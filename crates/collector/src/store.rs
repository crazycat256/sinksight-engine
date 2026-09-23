use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use csv::WriterBuilder;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use url::Url;

use sinksight_analysis::AnalyzeResult;

pub struct CapturedScript<'a> {
    pub hash: &'a str,
    pub source: &'a str,
    pub script_url: &'a str,
    pub page_url: &'a str,
    pub result: &'a AnalyzeResult,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportFinding {
    id: i64,
    file: String,
    location: String,
    detector: String,
    category: String,
    snippet: String,
    script_urls: Vec<String>,
    page_urls: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportScript {
    file: String,
    script_urls: Vec<String>,
    page_urls: Vec<String>,
    library: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis_error: Option<String>,
}

pub struct Store {
    output: PathBuf,
    connection: Connection,
}

impl Store {
    pub fn open(output: &Path) -> Result<Self> {
        fs::create_dir_all(output.join("scripts"))?;
        fs::create_dir_all(output.join("export"))?;
        let connection = Connection::open(output.join("metadata.db"))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS scripts (
                 hash TEXT PRIMARY KEY,
                 path TEXT NOT NULL,
                 source TEXT NOT NULL,
                 structural_hash TEXT NOT NULL,
                 library_json TEXT NOT NULL,
                 analysis_error TEXT,
                 captured_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS observations (
                 hash TEXT NOT NULL REFERENCES scripts(hash) ON DELETE CASCADE,
                 page_url TEXT NOT NULL,
                 script_url TEXT NOT NULL,
                 PRIMARY KEY (hash, page_url, script_url)
             );
             CREATE TABLE IF NOT EXISTS findings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 hash TEXT NOT NULL REFERENCES scripts(hash) ON DELETE CASCADE,
                 detector TEXT NOT NULL,
                 category TEXT NOT NULL,
                 start_line INTEGER NOT NULL,
                 start_column INTEGER NOT NULL,
                 end_line INTEGER NOT NULL,
                 end_column INTEGER NOT NULL,
                 snippet TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            output: output.to_owned(),
            connection,
        })
    }

    /// Records where an already-stored script was seen, without re-analyzing
    /// it. Returns `None` when the script is unknown, meaning the caller still
    /// has to analyze it and call [`Store::save`]. Otherwise returns whether
    /// this observation was new.
    pub fn observe(
        &mut self,
        hash: &str,
        page_url: &str,
        script_url: &str,
    ) -> Result<Option<bool>> {
        let known: Option<i64> = self
            .connection
            .query_row("SELECT 1 FROM scripts WHERE hash = ?1", [hash], |row| {
                row.get(0)
            })
            .optional()?;
        if known.is_none() {
            return Ok(None);
        }
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO observations (hash, page_url, script_url)
             VALUES (?1, ?2, ?3)",
            params![hash, page_url, script_url],
        )?;
        Ok(Some(inserted != 0))
    }

    pub fn save(&mut self, captured: CapturedScript<'_>) -> Result<bool> {
        // Two identical scripts can reach analysis concurrently, so the
        // caller's `observe` check does not make this one redundant.
        if let Some(inserted) =
            self.observe(captured.hash, captured.page_url, captured.script_url)?
        {
            return Ok(inserted);
        }

        let replaced: Option<(String, String)> = if captured.result.structural_hash.is_empty() {
            None
        } else {
            self.connection
                .query_row(
                    "SELECT hash, path FROM scripts
                     WHERE structural_hash = ?1
                     ORDER BY captured_at DESC LIMIT 1",
                    [&captured.result.structural_hash],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
        };
        let relative_path = replaced
            .as_ref()
            .map(|(_, path)| PathBuf::from(path))
            .unwrap_or_else(|| script_path(captured.script_url, captured.hash));
        let absolute_path = self.output.join(&relative_path);
        if let Some(parent) = absolute_path.parent() {
            fs::create_dir_all(parent)?;
        }
        atomic_write(&absolute_path, captured.source.as_bytes())?;

        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO scripts
             (hash, path, source, structural_hash, library_json, analysis_error, captured_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                captured.hash,
                path_string(&relative_path),
                captured.source,
                captured.result.structural_hash,
                serde_json::to_string(&captured.result.library)?,
                captured.result.analysis_error,
                unix_timestamp(),
            ],
        )?;
        if let Some((replaced_hash, _)) = &replaced {
            transaction.execute(
                "INSERT OR IGNORE INTO observations (hash, page_url, script_url)
                 SELECT ?1, page_url, script_url FROM observations WHERE hash = ?2",
                params![captured.hash, replaced_hash],
            )?;
            transaction.execute("DELETE FROM scripts WHERE hash = ?1", [replaced_hash])?;
        }
        transaction.execute(
            "INSERT OR IGNORE INTO observations (hash, page_url, script_url) VALUES (?1, ?2, ?3)",
            params![captured.hash, captured.page_url, captured.script_url],
        )?;
        for finding in &captured.result.findings {
            transaction.execute(
                "INSERT INTO findings
                 (hash, detector, category, start_line, start_column, end_line, end_column, snippet)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    captured.hash,
                    finding.detector_name,
                    format!("{:?}", finding.category).to_ascii_lowercase(),
                    finding.start_line,
                    finding.start_column,
                    finding.end_line,
                    finding.end_column,
                    finding.snippet,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(true)
    }

    pub fn export(&self) -> Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT f.id, s.hash, s.path,
                    f.detector, f.category, f.start_line, f.start_column,
                    f.end_line, f.end_column, f.snippet
             FROM findings f JOIN scripts s ON s.hash = f.hash
             ORDER BY s.path, f.start_line, f.start_column",
        )?;
        let mut rows = statement.query([])?;
        let mut findings = Vec::new();
        while let Some(row) = rows.next()? {
            let hash: String = row.get(1)?;
            let page_urls = self.page_urls(&hash)?;
            let start_line: u32 = row.get(5)?;
            let start_column: u32 = row.get(6)?;
            let end_line: u32 = row.get(7)?;
            let end_column: u32 = row.get(8)?;
            findings.push(ExportFinding {
                id: row.get(0)?,
                file: row.get(2)?,
                location: format!("L{start_line}:{start_column}-L{end_line}:{end_column}"),
                script_urls: self.script_urls(&hash)?,
                detector: row.get(3)?,
                category: row.get(4)?,
                snippet: row.get(9)?,
                page_urls,
            });
        }

        let mut csv = WriterBuilder::new().from_writer(Vec::new());
        csv.write_record([
            "id",
            "file",
            "location",
            "sink",
            "category",
            "snippet",
            "script_urls",
            "page_urls",
        ])?;
        for finding in &findings {
            csv.write_record([
                finding.id.to_string(),
                finding.file.clone(),
                finding.location.clone(),
                finding.detector.clone(),
                finding.category.clone(),
                finding.snippet.clone(),
                finding.script_urls.join(" "),
                finding.page_urls.join(" "),
            ])?;
        }
        let csv = csv.into_inner()?;
        atomic_write(&self.output.join("export/findings.csv"), &csv)?;
        atomic_write(
            &self.output.join("export/findings.json"),
            &(serde_json::to_vec_pretty(&findings)?),
        )?;

        let mut origins: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut statement = self
            .connection
            .prepare("SELECT hash, path FROM scripts ORDER BY path")?;
        let scripts = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for script in scripts {
            let (hash, path) = script?;
            origins.insert(path, self.page_urls(&hash)?);
        }
        atomic_write(
            &self.output.join("export/origins.json"),
            &(serde_json::to_vec_pretty(&origins)?),
        )?;

        let mut statement = self.connection.prepare(
            "SELECT hash, path, library_json, analysis_error FROM scripts ORDER BY path",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        let mut scripts = Vec::new();
        for row in rows {
            let (hash, file, library, analysis_error) = row?;
            scripts.push(ExportScript {
                file,
                script_urls: self.script_urls(&hash)?,
                page_urls: self.page_urls(&hash)?,
                library: serde_json::from_str(&library)?,
                analysis_error,
            });
        }
        atomic_write(
            &self.output.join("export/scripts.json"),
            &serde_json::to_vec_pretty(&scripts)?,
        )?;
        Ok(())
    }

    fn page_urls(&self, hash: &str) -> Result<Vec<String>> {
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT page_url FROM observations WHERE hash = ?1 ORDER BY page_url",
        )?;
        let page_urls = statement
            .query_map([hash], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()
            .map_err(Into::into);
        page_urls
    }

    fn script_urls(&self, hash: &str) -> Result<Vec<String>> {
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT script_url FROM observations
             WHERE hash = ?1 AND script_url != '' ORDER BY script_url",
        )?;
        let urls = statement
            .query_map([hash], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(urls)
    }
}

fn script_path(script_url: &str, hash: &str) -> PathBuf {
    let name = Url::parse(script_url)
        .ok()
        .and_then(|url| {
            url.path_segments()
                .and_then(Iterator::last)
                .map(sanitize_segment)
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "dynamic.js".to_owned());
    let name = if name.ends_with(".js") {
        name
    } else {
        format!("{name}.js")
    };
    PathBuf::from("scripts")
        .join(hash.get(..2).unwrap_or("00"))
        .join(format!("{hash}-{name}"))
}

fn sanitize_segment(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("")
    ));
    fs::write(&temporary, contents)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}
