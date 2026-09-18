mod common;
use common::count_detector;

const D: &str = "urlParams";

// new URLSearchParams

#[test]
fn ignores_new_url_search_params_with_no_arguments() {
    assert_eq!(count_detector("const p = new URLSearchParams();", D), 0);
    assert_eq!(count_detector("let i = new URLSearchParams();", D), 0);
    assert_eq!(count_detector("var p = new URLSearchParams();", D), 0);
    assert_eq!(count_detector("p = new URLSearchParams();", D), 0);
}

#[test]
fn detects_new_url_search_params_location_search() {
    assert_eq!(
        count_detector("const p = new URLSearchParams(location.search);", D),
        1
    );
}

#[test]
fn detects_new_url_search_params_with_variable_argument() {
    assert_eq!(
        count_detector("const p = new URLSearchParams(query);", D),
        1
    );
}

#[test]
fn ignores_new_url_search_params_with_static_string() {
    assert_eq!(
        count_detector(r#"const p = new URLSearchParams("a=1&b=2");"#, D),
        0
    );
}

#[test]
fn ignores_shadowed_url_search_params() {
    let code = r#"
        class URLSearchParams {}
        const p = new URLSearchParams();
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_new_url_search_params_window_location_search() {
    assert_eq!(
        count_detector("const p = new URLSearchParams(window.location.search);", D),
        1
    );
}

// new URL with location source

#[test]
fn detects_new_url_location_href() {
    assert_eq!(count_detector("const u = new URL(location.href);", D), 1);
}

#[test]
fn detects_new_url_document_url() {
    assert_eq!(count_detector("const u = new URL(document.URL);", D), 1);
}

#[test]
fn detects_new_url_window_location() {
    assert_eq!(count_detector("const u = new URL(window.location);", D), 1);
}

#[test]
fn detects_new_url_location() {
    assert_eq!(count_detector("const u = new URL(location);", D), 1);
}

#[test]
fn detects_new_url_document_document_uri() {
    assert_eq!(
        count_detector("const u = new URL(document.documentURI);", D),
        1
    );
}

#[test]
fn detects_new_url_document_base_uri() {
    assert_eq!(count_detector("const u = new URL(document.baseURI);", D), 1);
}

#[test]
fn detects_new_url_self_location_href() {
    assert_eq!(
        count_detector("const u = new URL(self.location.href);", D),
        1
    );
}

#[test]
fn ignores_new_url_with_static_string() {
    assert_eq!(
        count_detector(r#"const u = new URL("https://example.com");"#, D),
        0
    );
}

#[test]
fn ignores_new_url_with_non_location_variable() {
    assert_eq!(count_detector("const u = new URL(someVar);", D), 0);
}

#[test]
fn ignores_shadowed_url_constructor() {
    let code = r#"
        class URL { constructor(s) {} }
        const u = new URL(location.href);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

// Raw reads are NOT flagged

#[test]
fn ignores_raw_location_search_read() {
    assert_eq!(count_detector("const q = location.search;", D), 0);
}

#[test]
fn ignores_raw_location_hash_read() {
    assert_eq!(count_detector("const h = location.hash;", D), 0);
}

#[test]
fn ignores_raw_location_href_read() {
    assert_eq!(count_detector("const u = location.href;", D), 0);
}

#[test]
fn ignores_raw_document_url_read() {
    assert_eq!(count_detector("const u = document.URL;", D), 0);
}

#[test]
fn ignores_location_to_string() {
    assert_eq!(count_detector("const u = location.toString();", D), 0);
}

// Multiple parsers in same snippet

#[test]
fn detects_multiple_parser_usages() {
    let code = r#"
        const params = new URLSearchParams(location.search);
        const url = new URL(location.href);
    "#;
    assert_eq!(count_detector(code, D), 2);
}

// Realistic patterns

#[test]
fn detects_url_search_params_in_a_function_extracting_query_params() {
    let code = r#"
        function getParam(name) {
            const params = new URLSearchParams(window.location.search);
            return params.get(name);
        }
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_url_parser_used_to_extract_pathname() {
    let code = r#"
        function getPath() {
            const url = new URL(location.href);
            return url.pathname;
        }
    "#;
    assert_eq!(count_detector(code, D), 1);
}
