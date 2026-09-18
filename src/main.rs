use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sinksight_engine::analyze;
use sinksight_engine::collector::{self, Config, Mode};

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
        #[arg(long, value_enum, default_value_t = Mode::Dynamic)]
        mode: Mode,
        #[arg(long)]
        library_db: Option<PathBuf>,
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        max_script_bytes: usize,
        #[arg(long, default_value_t = 4)]
        analysis_concurrency: usize,
    },
    Analyze {
        path: PathBuf,
        #[arg(long)]
        library_db: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Analyze { path, library_db } => {
            let source = tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("cannot read {}", path.display()))?;
            let library_db = read_optional(library_db).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&analyze(&source, library_db.as_deref()))?
            );
        }
        Command::Collect {
            devtools_active_port,
            output,
            mode,
            library_db,
            max_script_bytes,
            analysis_concurrency,
        } => {
            let config = Config {
                devtools_active_port,
                output,
                mode,
                library_db: read_optional(library_db).await?,
                max_script_bytes,
                analysis_concurrency,
            };
            tokio::select! {
                result = collector::run(config) => result?,
                result = tokio::signal::ctrl_c() => result.context("cannot listen for Ctrl-C")?,
            }
        }
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
