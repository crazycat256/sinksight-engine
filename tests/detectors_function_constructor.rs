//! Port of `packages/vscode-ext/test/detectors/functionConstructor.test.ts`.

mod common;
use common::count_detector;

const D: &str = "functionConstructor";

#[test]
fn detects_dynamic_new_function() {
    assert_eq!(count_detector("new Function(body)", D), 1);
}

#[test]
fn detects_dynamic_window_function() {
    assert_eq!(count_detector("new window.Function(body)", D), 1);
}

#[test]
fn detects_dynamic_function_call() {
    assert_eq!(count_detector("Function('x', payload)", D), 1);
}

#[test]
fn ignores_static_function_constructor() {
    assert_eq!(count_detector("Function('x', 'return x + 1')", D), 0);
}

#[test]
fn ignores_constant_variable_body() {
    let code = r#"
        const body = "return 42";
        new Function(body);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_dynamic_body_with_static_arguments() {
    let code = r#"
        const body = getDynamicBody();
        new Function("a", "b", body);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_dynamic_arguments_with_static_body() {
    let code = r#"
        const arg1 = getDynamicArg();
        new Function(arg1, "return 42");
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_multiple_arguments_with_static_body() {
    let code = r#"
        const arg1 = getDynamicArg1();
        const arg2 = getDynamicArg2();
        const arg3 = getDynamicArg3();
        const arg4 = getDynamicArg4();
        const code = "return 42";
        new Function(arg1, arg2, arg3, arg4, code);
    "#;
    assert_eq!(count_detector(code, D), 0);
}
