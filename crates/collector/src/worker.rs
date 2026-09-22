use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::time::timeout;

use sinksight_analysis::{AnalyzeResult, Analyzer};

const MAX_RESULT_BYTES: usize = 64 * 1024 * 1024;
const MAX_LIBRARY_BYTES: usize = 1024 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;

/// A worker that never answers would otherwise hold its pool slot forever and,
/// once every slot is stuck, stall collection silently.
const ANALYSIS_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Pool {
    executable: Box<Path>,
    library_db: Option<Vec<u8>>,
    workers: Vec<Mutex<Option<Worker>>>,
    next: AtomicUsize,
}

impl Pool {
    pub fn new(executable: &Path, library_db: Option<Vec<u8>>, size: usize) -> Self {
        Self {
            executable: executable.into(),
            library_db,
            workers: (0..size.max(1)).map(|_| Mutex::new(None)).collect(),
            next: AtomicUsize::new(0),
        }
    }

    pub async fn analyze(&self, source: &str) -> Result<AnalyzeResult> {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        let mut slot = self.workers[index].lock().await;
        let mut last_error = None;
        for _ in 0..2 {
            if slot.is_none() {
                *slot = Some(Worker::start(&self.executable, self.library_db.as_deref()).await?);
            }
            let outcome = timeout(ANALYSIS_TIMEOUT, slot.as_mut().unwrap().analyze(source)).await;
            match outcome {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(error)) => {
                    last_error = Some(error);
                    // The frame stream is desynchronized, so the worker is gone.
                    kill(slot.take()).await;
                }
                Err(_) => {
                    kill(slot.take()).await;
                    // Retrying would just spend the same budget again.
                    bail!(
                        "analysis worker exceeded {} seconds",
                        ANALYSIS_TIMEOUT.as_secs()
                    );
                }
            }
        }
        Err(last_error.unwrap())
    }
}

async fn kill(worker: Option<Worker>) {
    if let Some(mut worker) = worker {
        let _ = worker.child.kill().await;
        let _ = worker.child.wait().await;
    }
}

struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Worker {
    async fn start(executable: &Path, library_db: Option<&[u8]>) -> Result<Self> {
        let mut child = Command::new(executable)
            .arg("analysis-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("cannot start analysis worker")?;
        let mut stdin = child.stdin.take().context("analysis worker has no stdin")?;
        let stdout = child
            .stdout
            .take()
            .context("analysis worker has no stdout")?;
        write_frame(&mut stdin, library_db.unwrap_or_default()).await?;
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }

    async fn analyze(&mut self, source: &str) -> Result<AnalyzeResult> {
        write_frame(&mut self.stdin, source.as_bytes()).await?;
        let bytes = read_frame(&mut self.stdout, MAX_RESULT_BYTES).await?;
        serde_json::from_slice(&bytes).context("analysis worker returned invalid JSON")
    }
}

pub async fn serve() -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let library_db = read_frame(&mut stdin, MAX_LIBRARY_BYTES).await?;
    let analyzer = Analyzer::new((!library_db.is_empty()).then_some(library_db.as_slice()))
        .map_err(anyhow::Error::msg)
        .context("invalid library database")?;

    loop {
        let source = match read_frame(&mut stdin, MAX_SOURCE_BYTES).await {
            Ok(source) => source,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof) =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        let source = std::str::from_utf8(&source).context("script source is not UTF-8")?;
        let result = analyzer.analyze(source);
        write_frame(&mut stdout, &serde_json::to_vec(&result)?).await?;
    }
}

async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<()> {
    writer.write_u64(bytes.len() as u64).await?;
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame(reader: &mut (impl AsyncRead + Unpin), limit: usize) -> Result<Vec<u8>> {
    let length = reader.read_u64().await?;
    let length = usize::try_from(length).context("frame is too large for this platform")?;
    if length > limit {
        bail!("frame exceeds the {limit}-byte limit");
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}
