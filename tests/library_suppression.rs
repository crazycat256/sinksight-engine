use sinksight_engine::analyze;
use sinksight_library_hash::{db, extract_hashes, parse_hash_bytes};

fn library_db(source: &str) -> Vec<u8> {
    let hashes = extract_hashes(source, Some(3)).unwrap();
    let function_hashes = hashes
        .functions
        .iter()
        .map(|function| (parse_hash_bytes(&function.hash).unwrap(), 0, 0))
        .collect();
    db::build_db(
        3,
        &[("known-library".to_owned(), vec!["1.0.0".to_owned()])],
        Vec::new(),
        function_hashes,
    )
}

#[test]
fn suppresses_findings_inside_known_functions_only() {
    let known = r#"
        function renderKnown(value) {
            const target = document.body;
            target.innerHTML = value;
            return target;
        }
    "#;
    let bundle = r#"
        function renderKnown(value) {
            const target = document.body;
            target.innerHTML = value;
            return target;
        }

        function renderBusiness(value) {
            const target = document.body;
            const rendered = value;
            target.innerHTML = rendered;
            return target;
        }
    "#;

    let result = analyze(bundle, Some(&library_db(known)));

    assert_eq!(result.library.unwrap().functions.len(), 1);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].snippet, "target.innerHTML = rendered");
}

#[test]
fn suppresses_a_known_function_even_when_its_hash_has_multiple_library_matches() {
    let known = r#"
        function render(value) {
            const target = document.body;
            target.innerHTML = value;
            return target;
        }
    "#;
    let hashes = extract_hashes(known, Some(3)).unwrap();
    let hash = parse_hash_bytes(&hashes.functions[0].hash).unwrap();
    let database = db::build_db(
        3,
        &[
            ("first-library".to_owned(), vec!["1.0.0".to_owned()]),
            ("second-library".to_owned(), vec!["2.0.0".to_owned()]),
        ],
        Vec::new(),
        vec![(hash, 0, 0), (hash, 1, 0)],
    );

    let result = analyze(known, Some(&database));

    assert_eq!(result.library.unwrap().functions[0].libs.len(), 2);
    assert!(result.findings.is_empty());
}
