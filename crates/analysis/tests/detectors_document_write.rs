mod common;
use common::count_detector;

const D: &str = "documentWrite";

#[test]
fn detects_dynamic_document_write() {
    assert_eq!(count_detector("document.write(payload)", D), 1);
}

#[test]
fn detects_dynamic_document_writeln() {
    assert_eq!(count_detector("document.writeln(payload)", D), 1);
}

#[test]
fn detects_dynamic_window_document_write() {
    assert_eq!(count_detector("window.document.write(payload)", D), 1);
}

#[test]
fn detects_nested_content_document_writeln() {
    assert_eq!(
        count_detector("iframe.contentDocument.writeln(payload)", D),
        1
    );
}

#[test]
fn ignores_static_document_write() {
    assert_eq!(count_detector("document.write('<p>safe</p>')", D), 0);
}

#[test]
fn ignores_static_template_literal() {
    assert_eq!(count_detector("document.write(`safe`)", D), 0);
}

#[test]
fn detects_dynamic_template_literal() {
    assert_eq!(count_detector("document.write(`safe ${payload}`)", D), 1);
}

#[test]
fn ignores_variable_resolving_to_static_string() {
    let code = r#"
        const part1 = "<script>";
        const part2 = "console.log('safe')";
        const part3 = "</script>";
        document.write(part1 + part2 + part3);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_document_write_through_const_alias() {
    let code = r#"
        const doc = document;
        doc.write(userInput);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_document_writeln_through_window_document_alias() {
    let code = r#"
        const doc = window.document;
        doc.writeln(userInput);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_document_write_through_iife_argument() {
    let code = r#"
        (function(d) {
            d.write(userInput);
        })(document);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_document_write_via_call() {
    assert_eq!(
        count_detector("document.write.call(document, userInput)", D),
        1
    );
}

#[test]
fn detects_document_write_via_call_on_const_alias() {
    let code = r#"
        const w = document.write;
        w.call(document, userInput);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_document_write_via_apply_with_array_literal() {
    let code = r#"
        const w = document.write;
        w.apply(document, [userInput]);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_document_write_call_with_static_argument() {
    assert_eq!(
        count_detector("document.write.call(document, '<p>safe</p>')", D),
        0
    );
}
