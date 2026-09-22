mod common;
use common::count_detector;

const D: &str = "documentReferrer";

#[test]
fn detects_document_referrer() {
    assert_eq!(count_detector("const r = document.referrer;", D), 1);
}

#[test]
fn detects_window_document_referrer() {
    assert_eq!(count_detector("const r = window.document.referrer;", D), 1);
}

#[test]
fn detects_document_referrer_in_concatenation() {
    assert_eq!(
        count_detector(r#"const url = "ref=" + document.referrer;"#, D),
        1
    );
}

#[test]
fn detects_document_referrer_in_template_literal() {
    assert_eq!(
        count_detector("const msg = `Referrer: ${document.referrer}`;", D),
        1
    );
}

#[test]
fn detects_document_referrer_as_function_argument() {
    assert_eq!(count_detector("track(document.referrer);", D), 1);
}

#[test]
fn ignores_non_document_referrer_property() {
    assert_eq!(count_detector("const r = myObj.referrer;", D), 0);
}

#[test]
fn ignores_document_title_different_property() {
    assert_eq!(count_detector("const t = document.title;", D), 0);
}

#[test]
fn still_matches_when_document_is_a_parameter_name() {
    let code = r#"
        function test(document) {
            const r = document.referrer;
        }
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_multiple_document_referrer_reads() {
    let code = r#"
        const a = document.referrer;
        fetch(document.referrer);
    "#;
    assert_eq!(count_detector(code, D), 2);
}

#[test]
fn detects_document_referrer_in_conditional() {
    let code = r#"
        if (document.referrer) {
            redirect(document.referrer);
        }
    "#;
    assert_eq!(count_detector(code, D), 2);
}
