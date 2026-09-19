use std::fs;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sinksight_engine::analyze;
use sinksight_engine::store::{CapturedScript, Store};

#[test]
fn deeply_nested_source_does_not_overflow_the_process_stack() {
    let depth = 20_000;
    let source = format!("{}location.href{};", "(".repeat(depth), ")".repeat(depth));

    let _ = analyze(&source, None);
}

#[test]
fn reports_partial_analysis_for_invalid_javascript() {
    let result = analyze("function broken( {", None);

    assert!(result.analysis_error.is_some());
}

#[test]
fn truncates_unicode_snippets_on_character_boundaries() {
    let source = format!("element.innerHTML = value + '{}';", "€".repeat(250));
    let result = analyze(&source, None);

    assert_eq!(result.findings.len(), 1);
    assert!(result.findings[0].snippet.chars().count() <= 200);
}

#[test]
fn exports_raw_source_and_every_observed_url() {
    let output = tempfile::tempdir().unwrap();
    let source = "element.innerHTML = value;\n";
    let hash = format!("{:x}", Sha256::digest(source.as_bytes()));
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

    let file = script["file"].as_str().unwrap();
    assert_eq!(
        fs::read_to_string(output.path().join(file)).unwrap(),
        source
    );

    let findings: Value =
        serde_json::from_slice(&fs::read(output.path().join("export/findings.json")).unwrap())
            .unwrap();
    assert_eq!(findings[0]["file"], file);
    assert_eq!(findings[0]["scriptUrls"].as_array().unwrap().len(), 2);
}
