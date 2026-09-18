use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type SocketSink =
    futures_util::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

#[derive(Clone, Debug)]
pub struct Event {
    pub method: String,
    pub params: Value,
    pub session_id: Option<String>,
}

#[derive(Clone)]
pub struct Client {
    sink: Arc<Mutex<SocketSink>>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>>,
    events: broadcast::Sender<Event>,
    next_id: Arc<AtomicU64>,
}

impl Client {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        let (socket, _) = connect_async(endpoint)
            .await
            .with_context(|| format!("failed to connect to CDP endpoint {endpoint}"))?;
        let (sink, mut stream) = socket.split();
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (events, _) = broadcast::channel(8192);

        let client = Self {
            sink: Arc::new(Mutex::new(sink)),
            pending: pending.clone(),
            events: events.clone(),
            next_id: Arc::new(AtomicU64::new(1)),
        };

        tokio::spawn(async move {
            while let Some(message) = stream.next().await {
                let Ok(Message::Text(text)) = message else {
                    continue;
                };
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                if let Some(id) = value.get("id").and_then(Value::as_u64) {
                    if let Some(sender) = pending.lock().await.remove(&id) {
                        let result = if let Some(error) = value.get("error") {
                            Err(anyhow!("CDP command failed: {error}"))
                        } else {
                            Ok(value.get("result").cloned().unwrap_or(Value::Null))
                        };
                        let _ = sender.send(result);
                    }
                    continue;
                }
                let Some(method) = value.get("method").and_then(Value::as_str) else {
                    continue;
                };
                let _ = events.send(Event {
                    method: method.to_owned(),
                    params: value.get("params").cloned().unwrap_or_else(|| json!({})),
                    session_id: value
                        .get("sessionId")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                });
            }

            let mut pending = pending.lock().await;
            for (_, sender) in pending.drain() {
                let _ = sender.send(Err(anyhow!("CDP connection closed")));
            }
            let _ = events.send(Event {
                method: "SinkSight.disconnected".to_owned(),
                params: Value::Null,
                session_id: None,
            });
        });

        Ok(client)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub async fn call(
        &self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(id, sender);

        let mut message = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        if let Some(session_id) = session_id {
            message["sessionId"] = Value::String(session_id.to_owned());
        }

        if let Err(error) = self
            .sink
            .lock()
            .await
            .send(Message::Text(message.to_string().into()))
            .await
        {
            self.pending.lock().await.remove(&id);
            return Err(error).context("failed to send CDP command");
        }

        receiver.await.context("CDP response channel closed")?
    }
}
