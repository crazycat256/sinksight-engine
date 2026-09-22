use sinksight_analysis::analyze;

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
