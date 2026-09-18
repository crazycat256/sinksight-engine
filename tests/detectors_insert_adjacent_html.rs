//! Port of `packages/vscode-ext/test/detectors/insertAdjacentHtml.test.ts`.

mod common;
use common::count_detector;

const D: &str = "insertAdjacentHtml";

#[test]
fn detects_dynamic_second_argument() {
    assert_eq!(
        count_detector("el.insertAdjacentHTML('beforeend', htmlPayload)", D),
        1
    );
}

#[test]
fn detects_dynamic_second_argument_with_window_document_element() {
    assert_eq!(
        count_detector(
            "window.document.body.insertAdjacentHTML('beforeend', htmlPayload)",
            D
        ),
        1
    );
}

#[test]
fn ignores_static_second_argument() {
    assert_eq!(
        count_detector("el.insertAdjacentHTML('beforeend', '<span>safe</span>')", D),
        0
    );
}

#[test]
fn ignores_constant_variable_passed_as_second_argument() {
    let code = r#"
        const position = 'beforeend';
        const safe = "<div>safe</div>";
        el.insertAdjacentHTML(position, safe);
    "#;
    assert_eq!(count_detector(code, D), 0);
}
