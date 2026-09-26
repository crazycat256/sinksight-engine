use std::fs;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sinksight_analysis::{analyze, Finding, FindingCategory};
use sinksight_collector::store::{finding_details, CapturedScript, Store};

fn content_hash(source: &str) -> String {
    format!("{:x}", Sha256::digest(source.as_bytes()))
}

#[test]
fn exports_raw_source_and_every_observed_url() {
    let output = tempfile::tempdir().unwrap();
    let source = "element.innerHTML = value;\n";
    let hash = content_hash(source);
    let result = analyze(source, None);
    let mut store = Store::open(output.path()).unwrap();

    for (script_url, page_url) in [
        ("https://cdn.example/a.js", "https://first.example/"),
        ("https://cdn.example/v2/a.js", "https://second.example/"),
    ] {
        store
            .save(CapturedScript {
                hash: &hash,
                source,
                script_url,
                page_url,
                result: &result,
            })
            .unwrap();
    }
    store.export().unwrap();

    let scripts: Value =
        serde_json::from_slice(&fs::read(output.path().join("export/scripts.json")).unwrap())
            .unwrap();
    let script = &scripts[0];
    assert_eq!(script["scriptUrls"].as_array().unwrap().len(), 2);
    assert_eq!(script["pageUrls"].as_array().unwrap().len(), 2);
    assert_eq!(script["variantCount"], 1);

    let file = script["file"].as_str().unwrap();
    assert_eq!(
        fs::read_to_string(output.path().join(file)).unwrap(),
        source
    );

    let csv = fs::read_to_string(output.path().join("export/findings.csv")).unwrap();
    assert_eq!(
        csv.lines().next().unwrap(),
        "id,file,location,sink,category,snippet"
    );
    assert!(!output.path().join("export/findings.json").exists());

    let details = finding_details(output.path(), 1, 8).unwrap().unwrap();
    assert_eq!(details.file, file);
    assert_eq!(details.page_urls.len(), 2);
    assert_eq!(details.script_urls.len(), 2);
    assert!(details.context.source.contains("element.innerHTML = value"));
    assert_eq!(
        details.context.source[details.context.finding_start..details.context.finding_end]
            .to_string(),
        "element.innerHTML = value"
    );
}

#[test]
fn preserves_variants_but_exports_only_the_first_representative() {
    let output = tempfile::tempdir().unwrap();
    let first = "window.state = { id: 1 }; element.innerHTML = value;\n";
    let second = "window.state = { id: 2 }; element.innerHTML = value;\n";
    let first_hash = content_hash(first);
    let second_hash = content_hash(second);
    let first_result = analyze(first, None);
    let mut second_result = analyze(second, None);
    assert_eq!(first_result.structural_hash, second_result.structural_hash);
    second_result.findings.push(Finding {
        detector_name: "variant-only".to_owned(),
        category: FindingCategory::Sink,
        start_offset: 0,
        end_offset: 1,
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 2,
        snippet: "variant".to_owned(),
    });

    let mut store = Store::open(output.path()).unwrap();
    store
        .save(CapturedScript {
            hash: &first_hash,
            source: first,
            script_url: "https://example.test/product/1.js",
            page_url: "https://example.test/product/1",
            result: &first_result,
        })
        .unwrap();
    drop(store);
    let mut store = Store::open(output.path()).unwrap();
    store
        .save(CapturedScript {
            hash: &second_hash,
            source: second,
            script_url: "https://example.test/product/2.js",
            page_url: "https://example.test/product/2",
            result: &second_result,
        })
        .unwrap();
    store.export().unwrap();

    let family = &first_result.structural_hash;
    assert_eq!(
        fs::read_to_string(
            output
                .path()
                .join("variants")
                .join(family)
                .join(format!("{first_hash}.js"))
        )
        .unwrap(),
        first
    );
    assert_eq!(
        fs::read_to_string(
            output
                .path()
                .join("variants")
                .join(family)
                .join(format!("{second_hash}.js"))
        )
        .unwrap(),
        second
    );

    let connection = rusqlite::Connection::open(output.path().join("metadata.db")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM scripts", [], |row| row
                .get::<_, u32>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM scripts WHERE representative = 1",
                [],
                |row| row.get::<_, u32>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM observations", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row
                .get::<_, usize>(0))
            .unwrap(),
        first_result.findings.len() + second_result.findings.len()
    );

    let scripts: Value =
        serde_json::from_slice(&fs::read(output.path().join("export/scripts.json")).unwrap())
            .unwrap();
    assert_eq!(scripts.as_array().unwrap().len(), 1);
    assert_eq!(scripts[0]["variantCount"], 2);
    assert_eq!(scripts[0]["variantsWithDifferentFindings"], 1);
    assert_eq!(scripts[0]["pageUrls"].as_array().unwrap().len(), 2);
    let representative = scripts[0]["file"].as_str().unwrap();
    assert!(representative.ends_with(&format!("/{first_hash}.js")));

    let csv = fs::read_to_string(output.path().join("export/findings.csv")).unwrap();
    assert_eq!(csv.lines().count(), first_result.findings.len() + 1);
    assert!(!output.path().join("export/findings.json").exists());
}

#[test]
fn finding_context_counts_characters_without_splitting_utf8() {
    let output = tempfile::tempdir().unwrap();
    let source = "const label = 'é🙂'; element.innerHTML = value;\n";
    let hash = content_hash(source);
    let result = analyze(source, None);
    let mut store = Store::open(output.path()).unwrap();
    store
        .save(CapturedScript {
            hash: &hash,
            source,
            script_url: "https://example.test/unicode.js",
            page_url: "https://example.test/",
            result: &result,
        })
        .unwrap();

    let details = finding_details(output.path(), 1, 3).unwrap().unwrap();
    assert_eq!(details.context.finding_start, 3);
    assert_eq!(
        details.context.source.chars().take(3).collect::<String>(),
        "'; "
    );
    let finding: String = details
        .context
        .source
        .chars()
        .skip(details.context.finding_start)
        .take(details.context.finding_end - details.context.finding_start)
        .collect();
    assert_eq!(finding, "element.innerHTML = value");
}
