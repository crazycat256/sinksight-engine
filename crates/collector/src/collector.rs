use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Mutex, Notify, RwLock, Semaphore};

use crate::cdp::{error_code, has_error_code, Client, Event};
use crate::store::{CapturedScript, Store};
use crate::worker::Pool;

#[derive(Clone, Copy, Debug, Default)]
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
    pub analysis_worker: PathBuf,
    pub verbose_source_errors: bool,
}

#[derive(Clone)]
struct Target {
    parent: Option<String>,
    target_type: String,
    url: String,
}

/// Script requests waiting for their body, keyed by `(session, request)`.
///
/// An entry is normally removed by `Network.loadingFinished`/`loadingFailed`,
/// but those events can be missed when the event stream lags or when a target
/// goes away without detaching, so the oldest entries are evicted once the map
/// grows past a bound rather than being kept for the life of the connection.
#[derive(Default)]
struct PendingBodies {
    entries: HashMap<(String, String), (String, String, u64)>,
    inserted: u64,
}

const MAX_PENDING_BODIES: usize = 4096;

impl PendingBodies {
    fn insert(&mut self, key: (String, String), script_url: String, page_url: String) {
        self.entries
            .insert(key, (script_url, page_url, self.inserted));
        self.inserted += 1;
        while self.entries.len() > MAX_PENDING_BODIES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, _, seq))| *seq)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    fn remove(&mut self, key: &(String, String)) -> Option<(String, String)> {
        self.entries
            .remove(key)
            .map(|(script_url, page_url, _)| (script_url, page_url))
    }

    fn retain_sessions_other_than(&mut self, session: &str) {
        self.entries
            .retain(|(target_session, _), _| target_session != session);
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SourceKind {
    Debugger,
    Network,
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debugger => formatter.write_str("Debugger.getScriptSource"),
            Self::Network => formatter.write_str("Network.getResponseBody"),
        }
    }
}

struct SourceFailures {
    verbose: bool,
    counts: Mutex<HashMap<(SourceKind, Option<i64>), usize>>,
}

impl SourceFailures {
    fn new(verbose: bool) -> Self {
        Self {
            verbose,
            counts: Mutex::new(HashMap::new()),
        }
    }

    async fn report(&self, kind: SourceKind, url: &str, error: &anyhow::Error) {
        let code = error_code(error);
        let count = {
            let mut counts = self.counts.lock().await;
            let count = counts.entry((kind, code)).or_default();
            *count += 1;
            *count
        };
        if self.verbose || count <= 10 {
            eprintln!("Cannot retrieve script source via {kind} for {url}: {error:#}");
        } else if count == 11 {
            eprintln!(
                "Suppressing further {kind} source errors with code {}; use --verbose-source-errors to show each one",
                code.map_or_else(|| "unknown".to_owned(), |code| code.to_string())
            );
        }
    }

    async fn summarize(&self) {
        let counts = {
            let mut counts = self.counts.lock().await;
            std::mem::take(&mut *counts)
        };
        if counts.is_empty() {
            return;
        }
        let mut counts = counts.into_iter().collect::<Vec<_>>();
        counts.sort_by_key(|((kind, code), _)| (format!("{kind}"), *code));
        for ((kind, code), count) in counts {
            eprintln!(
                "Source retrieval summary: {count} failure(s) via {kind}, code {}",
                code.map_or_else(|| "unknown".to_owned(), |code| code.to_string())
            );
        }
    }
}

async fn call_source_command(
    client: &Client,
    method: &str,
    params: Value,
    session: &str,
) -> Result<Value> {
    let result = client.call(method, params.clone(), Some(session)).await;
    if result
        .as_ref()
        .err()
        .is_some_and(|error| has_error_code(error, -32000))
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
        return client.call(method, params, Some(session)).await;
    }
    result
}

struct Runtime {
    store: Mutex<Store>,
    targets: RwLock<HashMap<String, Target>>,
    network_scripts: Mutex<PendingBodies>,
    analyzer: Pool,
    max_script_bytes: usize,
    semaphore: Semaphore,
    source_retrievals: Semaphore,
    source_failures: SourceFailures,
    analysis_gates: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    export_dirty: AtomicBool,
    export_notify: Notify,
}

pub async fn run(config: Config) -> Result<()> {
    let concurrency = config.analysis_concurrency.max(1);
    let analyzer = Pool::new(&config.analysis_worker, config.library_db, concurrency);
    let runtime = Arc::new(Runtime {
        store: Mutex::new(Store::open(&config.output)?),
        targets: RwLock::new(HashMap::new()),
        network_scripts: Mutex::new(PendingBodies::default()),
        analyzer,
        max_script_bytes: config.max_script_bytes,
        semaphore: Semaphore::new(concurrency),
        source_retrievals: Semaphore::new(concurrency.saturating_mul(2)),
        source_failures: SourceFailures::new(config.verbose_source_errors),
        analysis_gates: Mutex::new(HashMap::new()),
        export_dirty: AtomicBool::new(false),
        export_notify: Notify::new(),
    });
    runtime.store.lock().await.export()?;
    tokio::spawn(export_loop(runtime.clone()));

    let mut waiting_for_chromium = false;
    loop {
        let endpoint = match endpoint_from_file(&config.devtools_active_port).await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                if !waiting_for_chromium {
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                    {
                        eprintln!(
                            "Waiting for Chromium DevTools endpoint at {}",
                            config.devtools_active_port.display()
                        );
                    } else {
                        eprintln!("Cannot discover Chromium DevTools endpoint: {error:#}");
                    }
                    waiting_for_chromium = true;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        waiting_for_chromium = false;
        let ready_file = config.output.join("collector.ready");
        remove_ready_file(&ready_file).await;
        if let Err(error) =
            collect_connection(&endpoint, &ready_file, config.mode, runtime.clone()).await
        {
            if !is_connection_transition(&error) {
                eprintln!("CDP collection failed: {error:#}");
            }
        }
        eprintln!("Chromium DevTools connection closed; waiting for a new endpoint");
        runtime.source_failures.summarize().await;
        remove_ready_file(&ready_file).await;
        runtime.targets.write().await.clear();
        runtime.network_scripts.lock().await.clear();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn export_loop(runtime: Arc<Runtime>) {
    loop {
        runtime.export_notify.notified().await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        if !runtime.export_dirty.swap(false, Ordering::AcqRel) {
            continue;
        }
        if let Err(error) = runtime.store.lock().await.export() {
            eprintln!("Cannot export findings: {error:#}");
        }
    }
}

fn request_export(runtime: &Runtime) {
    runtime.export_dirty.store(true, Ordering::Release);
    runtime.export_notify.notify_one();
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

async fn collect_connection(
    endpoint: &str,
    ready_file: &Path,
    mode: Mode,
    runtime: Arc<Runtime>,
) -> Result<()> {
    let client = Client::connect(endpoint).await?;
    let mut events = client.subscribe();
    client
        .call(
            "Target.setAutoAttach",
            json!({"autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true}),
            None,
        )
        .await?;
    tokio::fs::write(ready_file, endpoint)
        .await
        .with_context(|| format!("cannot write {}", ready_file.display()))?;
    eprintln!("Attached to Chromium DevTools at {endpoint}");

    loop {
        let event = match events.recv().await {
            Ok(event) => event,
            // A burst of events can outrun the dispatcher. Losing the tail of
            // that burst costs a few scripts; tearing the session down would
            // cost every target we have attached to.
            Err(RecvError::Lagged(skipped)) => {
                eprintln!("Dropped {skipped} CDP events while catching up; collection continues");
                continue;
            }
            Err(error) => return Err(error).context("CDP event stream closed"),
        };
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
                    if !has_error_code(&error, -32001) {
                        eprintln!("Cannot configure target {}: {error:#}", target.url);
                    }
                }
            });
        }
        "Target.detachedFromTarget" => {
            if let Some(session) = field(&event.params, "sessionId") {
                runtime.targets.write().await.remove(&session);
                runtime
                    .network_scripts
                    .lock()
                    .await
                    .retain_sessions_other_than(&session);
            }
        }
        "Page.frameNavigated" => {
            let Some(session) = event.session_id else {
                return;
            };
            let frame = &event.params["frame"];
            if frame.get("parentId").is_none() {
                if let Some(url) = field(frame, "url") {
                    set_target_url(&runtime, &session, url).await;
                }
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
            if ignored_url(&page_url) {
                return;
            }
            tokio::spawn(async move {
                let Ok(permit) = runtime.source_retrievals.acquire().await else {
                    return;
                };
                let result = call_source_command(
                    &client,
                    "Debugger.getScriptSource",
                    json!({"scriptId": script_id}),
                    &session,
                )
                .await
                .and_then(|value| {
                    value["scriptSource"]
                        .as_str()
                        .map(str::to_owned)
                        .context("missing scriptSource")
                });
                drop(permit);
                match result {
                    Ok(source) => process(runtime, source, script_url, page_url).await,
                    Err(error) => {
                        runtime
                            .source_failures
                            .report(SourceKind::Debugger, &script_url, &error)
                            .await
                    }
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
            if ignored_url(&page) {
                return;
            }
            runtime
                .network_scripts
                .lock()
                .await
                .insert((session, request_id), url, page);
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
                let Ok(permit) = runtime.source_retrievals.acquire().await else {
                    return;
                };
                let result = call_source_command(
                    &client,
                    "Network.getResponseBody",
                    json!({"requestId": request_id}),
                    &session,
                )
                .await
                .and_then(decode_body);
                drop(permit);
                match result {
                    Ok(source) => process(runtime, source, script_url, page_url).await,
                    Err(error) => {
                        runtime
                            .source_failures
                            .report(SourceKind::Network, &script_url, &error)
                            .await
                    }
                }
            });
        }
        "Network.loadingFailed" => {
            let Some(session) = event.session_id else {
                return;
            };
            let Some(request_id) = field(&event.params, "requestId") else {
                return;
            };
            runtime
                .network_scripts
                .lock()
                .await
                .remove(&(session, request_id));
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
    if matches!(target.target_type.as_str(), "page" | "iframe") {
        client.call("Page.enable", json!({}), Some(session)).await?;
        let frame_tree = client
            .call("Page.getFrameTree", json!({}), Some(session))
            .await?;
        if let Some(url) = frame_tree
            .pointer("/frameTree/frame/url")
            .and_then(Value::as_str)
        {
            set_target_url(&runtime, session, url.to_owned()).await;
        }
    }
    client
        .call(
            "Network.enable",
            json!({
                "maxTotalBufferSize": 128 * 1024 * 1024,
                "maxResourceBufferSize": runtime.max_script_bytes,
                "enableDurableMessages": true
            }),
            Some(session),
        )
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

async fn set_target_url(runtime: &Runtime, session: &str, url: String) {
    if let Some(target) = runtime.targets.write().await.get_mut(session) {
        target.url = url;
    }
}

async fn process(runtime: Arc<Runtime>, source: String, script_url: String, page_url: String) {
    if ignored_url(&page_url) || source.trim().is_empty() || source.len() > runtime.max_script_bytes
    {
        return;
    }
    let hash = format!("{:x}", Sha256::digest(source.as_bytes()));
    let gate = analysis_gate(&runtime.analysis_gates, &hash).await;
    let _gate = gate.lock().await;

    // The same script is re-delivered on every page that loads it, so settle
    // deduplication before paying for an analysis.
    {
        let mut store = runtime.store.lock().await;
        match store.observe(&hash, &page_url, &script_url) {
            Ok(Some(true)) => {
                request_export(&runtime);
                return;
            }
            Ok(Some(false)) => return,
            Ok(None) => {}
            Err(error) => {
                eprintln!("Cannot record script observation: {error:#}");
                return;
            }
        }
    }

    let Ok(_permit) = runtime.semaphore.acquire().await else {
        return;
    };
    let result = match runtime.analyzer.analyze(&source).await {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Cannot analyze script {hash}: {error:#}");
            sinksight_analysis::AnalyzeResult {
                findings: Vec::new(),
                structural_hash: String::new(),
                library: None,
                analysis_error: Some(error.to_string()),
            }
        }
    };
    let mut store = runtime.store.lock().await;
    match store.save(CapturedScript {
        hash: &hash,
        source: &source,
        script_url: &script_url,
        page_url: &page_url,
        result: &result,
    }) {
        Ok(true) => request_export(&runtime),
        Ok(false) => {}
        Err(error) => eprintln!("Cannot store script: {error:#}"),
    }
}

async fn analysis_gate(
    gates: &Mutex<HashMap<String, Weak<Mutex<()>>>>,
    hash: &str,
) -> Arc<Mutex<()>> {
    let mut gates = gates.lock().await;
    gates.retain(|_, gate| gate.strong_count() != 0);
    if let Some(gate) = gates.get(hash).and_then(Weak::upgrade) {
        return gate;
    }

    let gate = Arc::new(Mutex::new(()));
    gates.insert(hash.to_owned(), Arc::downgrade(&gate));
    gate
}

fn field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn ignored_url(url: &str) -> bool {
    [
        "chrome:",
        "chrome-untrusted:",
        "devtools:",
        "chrome-extension:",
        "extensions::",
    ]
    .iter()
    .any(|prefix| url.starts_with(prefix))
}

fn is_connection_transition(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            )
        })
    })
}

async fn remove_ready_file(path: &Path) {
    if let Err(error) = tokio::fs::remove_file(path).await {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!("Cannot remove {}: {error}", path.display());
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn analysis_gate_is_shared_while_an_analysis_is_live() {
        let gates = Mutex::new(HashMap::new());

        let first = analysis_gate(&gates, "same-script").await;
        let second = analysis_gate(&gates, "same-script").await;
        let other = analysis_gate(&gates, "other-script").await;

        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &other));
        drop(first);
        drop(second);
        drop(other);

        let replacement = analysis_gate(&gates, "same-script").await;
        assert_eq!(Arc::strong_count(&replacement), 1);
    }
}
