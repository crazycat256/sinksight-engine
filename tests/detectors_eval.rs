mod common;
use common::count_detector;

const D: &str = "eval";

#[test]
fn detects_dynamic_eval_argument() {
    assert_eq!(count_detector("eval(code)", D), 1);
}

#[test]
fn detects_dynamic_window_eval_argument() {
    assert_eq!(count_detector("window.eval(code)", D), 1);
}

#[test]
fn ignores_static_eval_argument() {
    assert_eq!(count_detector("eval('1+1')", D), 0);
}

#[test]
fn ignores_complex_static_expression() {
    let code = r#"
        const a = "1";
        const b = "+";
        const c = "1";
        eval(a + b + c);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_complex_dynamic_expression() {
    let code = r#"
        const a = "1";
        const b = getOperator();
        const c = `${a} ${b} 1`;
        eval(c);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_safe_dynamic_expression() {
    let code = r#"
        const a = "1";
        const b = "2";
        const c = a + b;
        eval(c);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_safe_expression_with_date() {
    let code = r#"
        const d = new Date();
        eval(d.toISOString());
    "#;
    assert_eq!(count_detector(code, D), 0);
}
