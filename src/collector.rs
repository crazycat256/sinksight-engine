use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::ValueEnum;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock, Semaphore};

use crate::analyze;
use crate::cdp::{Client, Event};
use crate::store::{CapturedScript, Store};

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum Mode {
    #[default]
    Dynamic,
    Stealth,
}

pub struct Config {
    pub devtools_active_port: PathBuf,
    pub output: PathBuf,
    pub mode: Mode,
    pub library_db: Option<Vec<u8>>,
    pub max_script_bytes: usize,
    pub analysis_concurrency: usize,
}

#[derive(Clone)]
struct Target {
    parent: Option<String>,
    target_type: String,
    url: String,
}

struct Runtime {
    store: Mutex<Store>,
    targets: RwLock<HashMap<String, Target>>,
    network_scripts: Mutex<HashMap<(String, String), (String, String)>>,
    library_db: Option<Vec<u8>>,
    max_script_bytes: usize,
    semaphore: Semaphore,
}

pub async fn run(config: Config) -> Result<()> {
    let runtime = Arc::new(Runtime {
        store: Mutex::new(Store::open(&config.output)?),
        targets: RwLock::new(HashMap::new()),
        network_scripts: Mutex::new(HashMap::new()),
        library_db: config.library_db,
        max_script_bytes: config.max_script_bytes,
        semaphore: Semaphore::new(config.analysis_concurrency.max(1)),
    });
    runtime.store.lock().await.export()?;

    loop {
        let endpoint = match endpoint_from_file(&config.devtools_active_port).await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                eprintln!("Waiting for Chromium: {error:#}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if let Err(error) = collect_connection(&endpoint, config.mode, runtime.clone()).await {
            eprintln!("CDP collection failed: {error:#}");
        }
        runtime.targets.write().await.clear();
        runtime.network_scripts.lock().await.clear();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn endpoint_from_file(path: &Path) -> Result<String> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("cannot read {}", path.display()))?;
    let mut lines = contents.lines();
    let port = lines.next().context("DevToolsActivePort has no port")?;
    let socket = lines
        .next()
        .context("DevToolsActivePort has no browser socket")?;
    if port.parse::<u16>().is_err() || !socket.starts_with('/') {
        bail!("invalid DevToolsActivePort contents");
    }
    Ok(format!("ws://127.0.0.1:{port}{socket}"))
}

async fn collect_connection(endpoint: &str, mode: Mode, runtime: Arc<Runtime>) -> Result<()> {
    let client = Client::connect(endpoint).await?;
    let mut events = client.subscribe();
    client
        .call(
            "Target.setAutoAttach",
            json!({"autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true}),
            None,
        )
        .await?;

    loop {
        let event = events.recv().await?;
        if event.method == "SinkSight.disconnected" {
            return Ok(());
        }
        dispatch(event, mode, client.clone(), runtime.clone()).await;
    }
}

async fn dispatch(event: Event, mode: Mode, client: Client, runtime: Arc<Runtime>) {
    match event.method.as_str() {
        "Target.attachedToTarget" => {
            let Some(session) = field(&event.params, "sessionId") else {
                return;
            };
            let info = &event.params["targetInfo"];
            let target = Target {
                parent: event.session_id,
                target_type: field(info, "type").unwrap_or_default(),
                url: field(info, "url").unwrap_or_default(),
            };
            runtime
                .targets
                .write()
                .await
                .insert(session.clone(), target.clone());
            tokio::spawn(async move {
                if let Err(error) =
                    configure_target(&client, &session, &target, mode, runtime).await
                {
                    eprintln!("Cannot configure target {}: {error:#}", target.url);
                }
            });
        }
        "Target.detachedFromTarget" => {
            if let Some(session) = field(&event.params, "sessionId") {
                runtime.targets.write().await.remove(&session);
            }
        }
        "Debugger.scriptParsed" if matches!(mode, Mode::Dynamic) => {
            let Some(session) = event.session_id else {
                return;
            };
            if event
                .params
                .pointer("/executionContextAuxData/isDefault")
                .and_then(Value::as_bool)
                == Some(false)
            {
                return;
            }
            let Some(script_id) = field(&event.params, "scriptId") else {
                return;
            };
            let script_url = field(&event.params, "url").unwrap_or_default();
            if ignored_url(&script_url) {
                return;
            }
            let page_url = page_url(&runtime, &session).await;
            tokio::spawn(async move {
                let result = client
                    .call(
                        "Debugger.getScriptSource",
                        json!({"scriptId": script_id}),
                        Some(&session),
                    )
                    .await;
                match result.and_then(|value| {
                    value["scriptSource"]
                        .as_str()
                        .map(str::to_owned)
                        .context("missing scriptSource")
                }) {
                    Ok(source) => process(runtime, source, script_url, page_url).await,
                    Err(error) => eprintln!("Cannot retrieve script source: {error:#}"),
                }
            });
        }
        "Network.responseReceived" => {
            if event.params["type"].as_str() != Some("Script") {
                return;
            }
            let Some(session) = event.session_id else {
                return;
            };
            let Some(request_id) = field(&event.params, "requestId") else {
                return;
            };
            let url = field(&event.params["response"], "url").unwrap_or_default();
            if ignored_url(&url) {
                return;
            }
            let page = page_url(&runtime, &session).await;
            runtime
                .network_scripts
                .lock()
                .await
                .insert((session, request_id), (url, page));
        }
        "Network.loadingFinished" => {
            let Some(session) = event.session_id else {
                return;
            };
            let Some(request_id) = field(&event.params, "requestId") else {
                return;
            };
            let metadata = runtime
                .network_scripts
                .lock()
                .await
                .remove(&(session.clone(), request_id.clone()));
            let Some((script_url, page_url)) = metadata else {
                return;
            };
            tokio::spawn(async move {
                let result = client
                    .call(
                        "Network.getResponseBody",
                        json!({"requestId": request_id}),
                        Some(&session),
                    )
                    .await;
                match result.and_then(decode_body) {
                    Ok(source) => process(runtime, source, script_url, page_url).await,
                    Err(error) => eprintln!("Cannot retrieve network script: {error:#}"),
                }
            });
        }
        _ => {}
    }
}

async fn configure_target(
    client: &Client,
    session: &str,
    target: &Target,
    mode: Mode,
    runtime: Arc<Runtime>,
) -> Result<()> {
    if !matches!(
        target.target_type.as_str(),
        "page" | "iframe" | "worker" | "shared_worker" | "service_worker" | "worklet"
    ) {
        return Ok(());
    }
    let _ = client
        .call(
            "Target.setAutoAttach",
            json!({"autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true}),
            Some(session),
        )
        .await;
    client
        .call("Network.enable", json!({}), Some(session))
        .await?;
    if matches!(mode, Mode::Dynamic) {
        client
            .call(
                "Debugger.enable",
                json!({"maxScriptsCacheSize": 1073741824_u64}),
                Some(session),
            )
            .await?;
        client
            .call(
                "Debugger.setSkipAllPauses",
                json!({"skip": true}),
                Some(session),
            )
            .await?;
        client
            .call(
                "Debugger.setPauseOnExceptions",
                json!({"state": "none"}),
                Some(session),
            )
            .await?;
    } else if matches!(target.target_type.as_str(), "page" | "iframe") {
        client.call("DOM.enable", json!({}), Some(session)).await?;
        let document = client
            .call(
                "DOM.getDocument",
                json!({"depth": -1, "pierce": true}),
                Some(session),
            )
            .await?;
        let page = target.url.clone();
        collect_dom_sources(&document["root"], &page, runtime).await;
    }
    Ok(())
}

async fn collect_dom_sources(root: &Value, page_url: &str, runtime: Arc<Runtime>) {
    let mut pending = vec![root];
    let mut sources = Vec::new();
    while let Some(node) = pending.pop() {
        if node["nodeName"].as_str() == Some("SCRIPT") {
            let has_source = attributes(node).iter().any(|(name, _)| name == "src");
            if !has_source {
                let text = node["children"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|child| child["nodeValue"].as_str())
                    .collect::<String>();
                if !text.is_empty() {
                    sources.push((text, "inline-script".to_owned()));
                }
            }
        }
        for (name, value) in attributes(node) {
            if name.starts_with("on") || value.trim_start().starts_with("javascript:") {
                sources.push((value, format!("inline-{name}")));
            }
        }
        if let Some(children) = node["children"].as_array() {
            pending.extend(children);
        }
        if let Some(shadow_roots) = node["shadowRoots"].as_array() {
            pending.extend(shadow_roots);
        }
        if let Some(content_document) = node.get("contentDocument") {
            pending.push(content_document);
        }
    }
    for (source, kind) in sources {
        process(runtime.clone(), source, kind, page_url.to_owned()).await;
    }
}

fn attributes(node: &Value) -> Vec<(String, String)> {
    node["attributes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .chunks_exact(2)
        .map(|pair| (pair[0].to_ascii_lowercase(), pair[1].to_owned()))
        .collect()
}

async fn page_url(runtime: &Runtime, session: &str) -> String {
    let targets = runtime.targets.read().await;
    let mut current = Some(session);
    let mut fallback = String::new();
    while let Some(id) = current {
        let Some(target) = targets.get(id) else {
            break;
        };
        if !target.url.is_empty() {
            fallback = target.url.clone();
        }
        if matches!(target.target_type.as_str(), "page" | "iframe") && !target.url.is_empty() {
            return target.url.clone();
        }
        current = target.parent.as_deref();
    }
    fallback
}

async fn process(runtime: Arc<Runtime>, source: String, script_url: String, page_url: String) {
    if source.trim().is_empty() || source.len() > runtime.max_script_bytes {
        return;
    }
    let Ok(_permit) = runtime.semaphore.acquire().await else {
        return;
    };
    let hash = format!("{:x}", Sha256::digest(source.as_bytes()));
    let result = analyze(&source, runtime.library_db.as_deref());
    let mut store = runtime.store.lock().await;
    match store.save(CapturedScript {
        hash: &hash,
        source: &source,
        script_url: &script_url,
        page_url: &page_url,
        result: &result,
    }) {
        Ok(true) => {
            if let Err(error) = store.export() {
                eprintln!("Cannot export findings: {error:#}");
            }
        }
        Ok(false) => {}
        Err(error) => eprintln!("Cannot store script: {error:#}"),
    }
}

fn field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn ignored_url(url: &str) -> bool {
    ["chrome:", "devtools:", "chrome-extension:", "extensions::"]
        .iter()
        .any(|prefix| url.starts_with(prefix))
}

fn decode_body(value: Value) -> Result<String> {
    let body = value["body"].as_str().context("missing response body")?;
    if value["base64Encoded"].as_bool() == Some(true) {
        let bytes = base64::engine::general_purpose::STANDARD.decode(body)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        Ok(body.to_owned())
    }
}
