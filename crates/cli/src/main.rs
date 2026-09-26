use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sinksight_collector::collector::{self, Config, Mode};
use sinksight_collector::store::{finding_details, FindingDetails};
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
    /// Collect and analyze JavaScript from a running Chromium instance.
    Collect {
        /// Path to Chromium's DevToolsActivePort file.
        #[arg(long)]
        devtools_active_port: PathBuf,
        /// Directory in which SinkSight stores its database and exports.
        #[arg(long)]
        output: PathBuf,
        /// Collection mode. Stealth is less complete and should only be used when necessary.
        #[arg(long, value_enum, default_value_t = ModeArgument::Dynamic)]
        mode: ModeArgument,
        /// Optional SinkSight library database.
        #[arg(long)]
        library_db: Option<PathBuf>,
        /// Maximum source size that SinkSight captures, in bytes.
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_capture_bytes: usize,
        /// Maximum captured source size that SinkSight analyzes, in bytes.
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        max_analysis_bytes: usize,
        /// Number of analysis worker processes.
        #[arg(long, default_value_t = 4)]
        analysis_concurrency: usize,
        /// Print every source retrieval error instead of grouped samples.
        #[arg(long)]
        verbose_source_errors: bool,
    },
    /// Analyze one JavaScript file and print the result as JSON.
    Analyze {
        path: PathBuf,
        /// Optional SinkSight library database.
        #[arg(long)]
        library_db: Option<PathBuf>,
    },
    /// Show one stored finding with its origins and surrounding source.
    Finding {
        /// Finding ID from export/findings.csv.
        id: i64,
        /// SinkSight output directory containing metadata.db.
        #[arg(long)]
        output: PathBuf,
        /// Number of source characters to include before and after the finding.
        #[arg(long, default_value_t = 500)]
        context_chars: usize,
        /// Display every page and script URL instead of the first ten.
        #[arg(long)]
        all_urls: bool,
        /// Print structured JSON instead of the agent-oriented text format.
        #[arg(long)]
        json: bool,
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
            max_capture_bytes,
            max_analysis_bytes,
            analysis_concurrency,
            verbose_source_errors,
        } => {
            let config = Config {
                devtools_active_port,
                output,
                mode: mode.into(),
                library_db: read_optional(library_db).await?,
                max_capture_bytes,
                max_analysis_bytes,
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
        Command::Finding {
            id,
            output,
            context_chars,
            all_urls,
            json,
        } => {
            let Some(details) = finding_details(&output, id, context_chars)? else {
                bail!("finding {id} does not exist in {}", output.display());
            };
            if json {
                print_finding_json(&details, all_urls)?;
            } else {
                print_finding(&details, context_chars, all_urls);
            }
        }
        Command::AnalysisWorker => sinksight_collector::worker::serve().await?,
    }
    Ok(())
}

const DEFAULT_URL_LIMIT: usize = 10;

fn visible_urls(urls: &[String], all_urls: bool) -> (&[String], usize) {
    let visible = if all_urls {
        urls
    } else {
        &urls[..urls.len().min(DEFAULT_URL_LIMIT)]
    };
    (visible, urls.len() - visible.len())
}

fn print_url_section(title: &str, urls: &[String], all_urls: bool) {
    println!("{title} ({}):", urls.len());
    let (visible, omitted) = visible_urls(urls, all_urls);
    if visible.is_empty() {
        println!("  None");
    } else {
        for url in visible {
            println!("  {url}");
        }
        if omitted != 0 {
            println!("  And {omitted} others. Use --all-urls to display them.");
        }
    }
}

fn print_finding(details: &FindingDetails, context_chars: usize, all_urls: bool) {
    println!("Finding {}", details.id);
    println!("Sink: {}", details.detector);
    println!("Category: {}", details.category);
    println!("Location: {}", details.location);
    println!("File: {}", details.file);
    println!("Content SHA-256: {}", details.content_hash);
    if !details.structural_hash.is_empty() {
        println!("Structural hash: {}", details.structural_hash);
    }
    println!("Representative: {}", details.representative);
    println!("Family variants: {}", details.variant_count);
    println!("Snippet: {}", details.snippet);
    println!();
    print_url_section("Pages", &details.page_urls, all_urls);
    println!();
    print_url_section("Script URLs", &details.script_urls, all_urls);
    println!();
    println!(
        "Context ({context_chars} characters before and after; finding at characters {}..{}):",
        details.context.finding_start, details.context.finding_end
    );
    println!("{}", details.context.source);
}

fn print_finding_json(details: &FindingDetails, all_urls: bool) -> Result<()> {
    let (page_urls, omitted_pages) = visible_urls(&details.page_urls, all_urls);
    let (script_urls, omitted_scripts) = visible_urls(&details.script_urls, all_urls);
    let value = serde_json::json!({
        "id": details.id,
        "detector": details.detector,
        "category": details.category,
        "file": details.file,
        "location": details.location,
        "snippet": details.snippet,
        "structuralHash": details.structural_hash,
        "contentHash": details.content_hash,
        "representative": details.representative,
        "variantCount": details.variant_count,
        "pageUrls": {
            "items": page_urls,
            "total": details.page_urls.len(),
            "omitted": omitted_pages,
        },
        "scriptUrls": {
            "items": script_urls,
            "total": details.script_urls.len(),
            "omitted": omitted_scripts,
        },
        "context": details.context,
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
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
