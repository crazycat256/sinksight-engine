use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sinksight_collector::collector::{self, Config, Mode};
use sinksight_collector::worker::Pool;

#[derive(Parser)]
#[command(
    name = "sinksight",
    version,
    about = "Analyze JavaScript observed by Chromium"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Collect {
        #[arg(long)]
        devtools_active_port: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = ModeArgument::Dynamic)]
        mode: ModeArgument,
        #[arg(long)]
        library_db: Option<PathBuf>,
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        max_script_bytes: usize,
        #[arg(long, default_value_t = 4)]
        analysis_concurrency: usize,
        #[arg(long)]
        verbose_source_errors: bool,
    },
    Analyze {
        path: PathBuf,
        #[arg(long)]
        library_db: Option<PathBuf>,
    },
    #[command(hide = true)]
    AnalysisWorker,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArgument {
    Dynamic,
    Stealth,
}

impl From<ModeArgument> for Mode {
    fn from(value: ModeArgument) -> Self {
        match value {
            ModeArgument::Dynamic => Self::Dynamic,
            ModeArgument::Stealth => Self::Stealth,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Analyze { path, library_db } => {
            let source = tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("cannot read {}", path.display()))?;
            let library_db = read_optional(library_db).await?;
            let executable =
                std::env::current_exe().context("cannot locate sinksight executable")?;
            let analyzer = Pool::new(&executable, library_db, 1);
            println!(
                "{}",
                serde_json::to_string_pretty(&analyzer.analyze(&source).await?)?
            );
        }
        Command::Collect {
            devtools_active_port,
            output,
            mode,
            library_db,
            max_script_bytes,
            analysis_concurrency,
            verbose_source_errors,
        } => {
            let config = Config {
                devtools_active_port,
                output,
                mode: mode.into(),
                library_db: read_optional(library_db).await?,
                max_script_bytes,
                analysis_concurrency,
                analysis_worker: std::env::current_exe()
                    .context("cannot locate sinksight executable")?,
                verbose_source_errors,
            };
            tokio::select! {
                result = collector::run(config) => result?,
                result = tokio::signal::ctrl_c() => result.context("cannot listen for Ctrl-C")?,
            }
        }
        Command::AnalysisWorker => sinksight_collector::worker::serve().await?,
    }
    Ok(())
}

async fn read_optional(path: Option<PathBuf>) -> Result<Option<Vec<u8>>> {
    match path {
        Some(path) => {
            Ok(Some(tokio::fs::read(&path).await.with_context(|| {
                format!("cannot read {}", path.display())
            })?))
        }
        None => Ok(None),
    }
}
