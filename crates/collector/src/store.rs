use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use csv::WriterBuilder;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sinksight_analysis::AnalyzeResult;
type UrlIndex = BTreeMap<String, Vec<String>>;

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
    variant_count: usize,
    variants_with_different_findings: usize,
    variant_analysis_errors: usize,
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
        fs::create_dir_all(output.join("variants"))?;
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
                 captured_at INTEGER NOT NULL,
                 representative INTEGER NOT NULL DEFAULT 0
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
             );
             CREATE UNIQUE INDEX IF NOT EXISTS scripts_one_representative_per_family
             ON scripts(structural_hash)
             WHERE representative = 1 AND structural_hash <> '';",
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

        let representative = captured.result.structural_hash.is_empty()
            || !self.connection.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM scripts
                    WHERE structural_hash = ?1 AND representative = 1
                )",
                [&captured.result.structural_hash],
                |row| row.get(0),
            )?;
        let relative_path = variant_path(&captured.result.structural_hash, captured.hash);
        let absolute_path = self.output.join(&relative_path);
        if let Some(parent) = absolute_path.parent() {
            fs::create_dir_all(parent)?;
        }
        atomic_write(&absolute_path, captured.source.as_bytes())?;

        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO scripts
             (hash, path, source, structural_hash, library_json, analysis_error, captured_at,
              representative)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                captured.hash,
                path_string(&relative_path),
                captured.source,
                captured.result.structural_hash,
                serde_json::to_string(&captured.result.library)?,
                captured.result.analysis_error,
                unix_timestamp(),
                representative,
            ],
        )?;
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
        let (page_urls_by_family, script_urls_by_family) = self.observation_urls()?;
        let mut statement = self.connection.prepare(
            "SELECT f.id, s.structural_hash, s.hash, s.path,
                    f.detector, f.category, f.start_line, f.start_column,
                    f.end_line, f.end_column, f.snippet
             FROM findings f JOIN scripts s ON s.hash = f.hash
             WHERE s.representative = 1
             ORDER BY s.path, f.start_line, f.start_column",
        )?;
        let mut rows = statement.query([])?;
        let mut findings = Vec::new();
        while let Some(row) = rows.next()? {
            let structural_hash: String = row.get(1)?;
            let hash: String = row.get(2)?;
            let family = family_key(&structural_hash, &hash);
            let page_urls = page_urls_by_family
                .get(&family)
                .cloned()
                .unwrap_or_default();
            let start_line: u32 = row.get(6)?;
            let start_column: u32 = row.get(7)?;
            let end_line: u32 = row.get(8)?;
            let end_column: u32 = row.get(9)?;
            findings.push(ExportFinding {
                id: row.get(0)?,
                file: row.get(3)?,
                location: format!("L{start_line}:{start_column}-L{end_line}:{end_column}"),
                script_urls: script_urls_by_family
                    .get(&family)
                    .cloned()
                    .unwrap_or_default(),
                detector: row.get(4)?,
                category: row.get(5)?,
                snippet: row.get(10)?,
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
        let mut statement = self.connection.prepare(
            "SELECT hash, structural_hash, path FROM scripts
                 WHERE representative = 1 ORDER BY path",
        )?;
        let scripts = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for script in scripts {
            let (hash, structural_hash, path) = script?;
            let family = family_key(&structural_hash, &hash);
            origins.insert(
                path,
                page_urls_by_family
                    .get(&family)
                    .cloned()
                    .unwrap_or_default(),
            );
        }
        atomic_write(
            &self.output.join("export/origins.json"),
            &(serde_json::to_vec_pretty(&origins)?),
        )?;

        let family_stats = self.family_stats()?;
        let mut statement = self.connection.prepare(
            "SELECT hash, structural_hash, path, library_json, analysis_error
             FROM scripts WHERE representative = 1 ORDER BY path",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut scripts = Vec::new();
        for row in rows {
            let (hash, structural_hash, file, library, analysis_error) = row?;
            let family = family_key(&structural_hash, &hash);
            let stats = family_stats.get(&family).cloned().unwrap_or_default();
            scripts.push(ExportScript {
                file,
                script_urls: script_urls_by_family
                    .get(&family)
                    .cloned()
                    .unwrap_or_default(),
                page_urls: page_urls_by_family
                    .get(&family)
                    .cloned()
                    .unwrap_or_default(),
                variant_count: stats.variant_count,
                variants_with_different_findings: stats.variants_with_different_findings,
                variant_analysis_errors: stats.variant_analysis_errors,
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

    fn observation_urls(&self) -> Result<(UrlIndex, UrlIndex)> {
        let mut pages: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut scripts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut statement = self.connection.prepare(
            "SELECT s.hash, s.structural_hash, o.page_url, o.script_url
             FROM observations o JOIN scripts s ON s.hash = o.hash
             ORDER BY s.structural_hash, s.hash, o.page_url, o.script_url",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (hash, structural_hash, page_url, script_url) = row?;
            let family = family_key(&structural_hash, &hash);
            pages.entry(family.clone()).or_default().insert(page_url);
            if !script_url.is_empty() {
                scripts.entry(family).or_default().insert(script_url);
            }
        }
        Ok((
            pages
                .into_iter()
                .map(|(hash, urls)| (hash, urls.into_iter().collect()))
                .collect(),
            scripts
                .into_iter()
                .map(|(hash, urls)| (hash, urls.into_iter().collect()))
                .collect(),
        ))
    }

    fn family_stats(&self) -> Result<BTreeMap<String, FamilyStats>> {
        let mut findings: BTreeMap<String, BTreeMap<String, Vec<FindingSignature>>> =
            BTreeMap::new();
        let mut representatives = BTreeMap::new();
        let mut stats: BTreeMap<String, FamilyStats> = BTreeMap::new();
        let mut statement = self.connection.prepare(
            "SELECT s.hash, s.structural_hash, s.representative, s.analysis_error,
                    f.detector, f.category
             FROM scripts s LEFT JOIN findings f ON f.hash = s.hash
             ORDER BY s.hash, f.id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let hash: String = row.get(0)?;
            let structural_hash: String = row.get(1)?;
            let family = family_key(&structural_hash, &hash);
            let by_hash = findings.entry(family.clone()).or_default();
            let signatures = by_hash.entry(hash.clone()).or_default();
            let family_stats = stats.entry(family.clone()).or_default();
            if family_stats.seen_hashes.insert(hash.clone()) {
                family_stats.variant_count += 1;
                if row.get::<_, Option<String>>(3)?.is_some() {
                    family_stats.variant_analysis_errors += 1;
                }
            }
            if row.get::<_, bool>(2)? {
                representatives.insert(family, hash);
            }
            if let Some(detector) = row.get::<_, Option<String>>(4)? {
                signatures.push((detector, row.get(5)?));
            }
        }
        for (family, mut by_hash) in findings {
            let Some(representative) = representatives.get(&family) else {
                continue;
            };
            for signatures in by_hash.values_mut() {
                signatures.sort();
            }
            let representative_findings = by_hash.get(representative).cloned().unwrap_or_default();
            stats
                .entry(family)
                .or_default()
                .variants_with_different_findings = by_hash
                .iter()
                .filter(|(hash, variant_findings)| {
                    *hash != representative && **variant_findings != representative_findings
                })
                .count();
        }
        Ok(stats)
    }
}

#[derive(Clone, Default)]
struct FamilyStats {
    variant_count: usize,
    variants_with_different_findings: usize,
    variant_analysis_errors: usize,
    seen_hashes: BTreeSet<String>,
}

type FindingSignature = (String, String);

fn variant_path(structural_hash: &str, hash: &str) -> PathBuf {
    let family = if structural_hash.is_empty() {
        "unstructured"
    } else {
        structural_hash
    };
    PathBuf::from("variants")
        .join(family)
        .join(format!("{hash}.js"))
}

fn family_key(structural_hash: &str, hash: &str) -> String {
    if structural_hash.is_empty() {
        format!("unstructured:{hash}")
    } else {
        structural_hash.to_owned()
    }
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
