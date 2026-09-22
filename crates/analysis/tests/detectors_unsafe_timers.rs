mod common;
use common::count_detector;

const D: &str = "unsafeTimers";

#[test]
fn detects_string_like_dynamic_timeout_payload() {
    assert_eq!(count_detector("setTimeout('prefix:' + payload, 0)", D), 1);
}

#[test]
fn detects_string_like_dynamic_set_interval_payload() {
    assert_eq!(count_detector("setInterval('prefix:' + payload, 0)", D), 1);
}

#[test]
fn detects_string_like_dynamic_window_set_timeout_payload() {
    assert_eq!(
        count_detector("window.setTimeout('prefix:' + payload, 0)", D),
        1
    );
}

#[test]
fn detects_string_like_dynamic_window_set_interval_payload() {
    assert_eq!(
        count_detector("window.setInterval('prefix:' + payload, 0)", D),
        1
    );
}

#[test]
fn ignores_callback_timeout() {
    assert_eq!(count_detector("setTimeout(() => doWork(), 0)", D), 0);
}

#[test]
fn ignores_static_string_timeout_payload() {
    assert_eq!(count_detector("setTimeout('alert(1)', 0)", D), 0);
}

#[test]
fn ignores_resolved_static_string_payload() {
    let code = r#"
        const cmd = "alert(1)";
        setTimeout(cmd, 100);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_dynamic_string_payload() {
    let code = r#"
        const cmd = "alert(" + getUserInput() + ")";
        setTimeout(cmd, 100);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_dynamic_function_payload() {
    let code = r#"
        const fn = getDynamicFunction();
        setTimeout(fn, 100);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_arrow_function_with_dynamic_body() {
    let code = r#"
        setTimeout(() => {
            eval(getUserInput());
        }, 100);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_function_expression_with_dynamic_body() {
    let code = r#"
        setTimeout(function() {
            eval(getUserInput());
        }, 100);
    "#;
    assert_eq!(count_detector(code, D), 0);
}
