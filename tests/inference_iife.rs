//! Port of `packages/vscode-ext/test/inference/iife.test.ts`.

mod common;
use common::{with_identifier_usage, with_last_expr};
use sinksight_engine::inference::{infer_type, is_safe_expression};

fn assert_safe(code: &str) {
    with_last_expr(code, |ctx, expr, scope_id| {
        assert!(
            is_safe_expression(ctx, expr, scope_id),
            "expected safe: {code:?}"
        );
    });
}

fn assert_unsafe(code: &str) {
    with_last_expr(code, |ctx, expr, scope_id| {
        assert!(
            !is_safe_expression(ctx, expr, scope_id),
            "expected unsafe: {code:?}"
        );
    });
}

/// Port of the TS `getTypeInside` helper: finds the first *usage* of
/// `var_name` and returns its inferred type.
fn get_type_inside(code: &str, var_name: &str) -> String {
    with_identifier_usage(code, var_name, |ctx, expr, scope_id| {
        infer_type(ctx, expr, scope_id).to_string()
    })
}

/// Port of the TS `getSafetyInside` helper: finds the first *usage* of
/// `var_name` and returns whether it's safe.
fn get_safety_inside(code: &str, var_name: &str) -> bool {
    with_identifier_usage(code, var_name, |ctx, expr, scope_id| {
        is_safe_expression(ctx, expr, scope_id)
    })
}

// isSafeExpression: IIFE

#[test]
fn safe_iife_with_normal_function() {
    assert_safe(r#"(function(a) { return a; })("safe")"#);
}

#[test]
fn safe_iife_with_arrow_function() {
    assert_safe(r#"((a) => a)("safe")"#);
}

#[test]
fn unsafe_iife_with_normal_function() {
    assert_unsafe(r#"(function(a) { return a; })(unsafeVar)"#);
}

#[test]
fn safe_iife_with_undefined_behavior_if_argument_omitted() {
    assert_safe(r#"(function(a) { return a; })()"#);
}

#[test]
fn safe_iife_ignores_missing_arguments_correctly() {
    assert_safe(r#"(function(a, b) { return b; })("safe")"#);
}

#[test]
fn unsafe_iife_when_spread_operator_used_in_arguments() {
    assert_unsafe(r#"(function(a) { return a; })(...["safe"])"#);
}

#[test]
fn unsafe_if_iife_is_named() {
    assert_unsafe(r#"(function foo(a) { return a; })("safe")"#);
}

// inferType: IIFE arguments

#[test]
fn infers_window_type_from_argument() {
    assert_eq!(
        get_type_inside("(function(x) { x })(window)", "x"),
        "Window"
    );
}

#[test]
fn infers_location_type_from_argument() {
    assert_eq!(
        get_type_inside("(function(x) { x })(location)", "x"),
        "Location"
    );
}

#[test]
fn infers_document_type_from_argument() {
    assert_eq!(
        get_type_inside("(function(x) { x })(document)", "x"),
        "Document"
    );
}

#[test]
fn infers_object_type_from_argument() {
    assert_eq!(
        get_type_inside("(function(obj) { obj })({})", "obj"),
        "Object"
    );
}

#[test]
fn infers_number_type_from_argument() {
    assert_eq!(get_type_inside("((a) => { a })(42)", "a"), "number");
}

#[test]
fn infers_date_type_from_constructor_argument() {
    assert_eq!(
        get_type_inside("(function(date) { date })(new Date())", "date"),
        "Date"
    );
}

#[test]
fn infers_undefined_if_argument_is_missing() {
    assert_eq!(get_type_inside("(function(a) { a })()", "a"), "undefined");
}

#[test]
fn does_not_infer_type_for_non_iife_function_expression() {
    assert_eq!(get_type_inside("(function(a) { a })", "a"), "unknown");
}

#[test]
fn does_not_infer_type_for_non_iife_arrow_function() {
    assert_eq!(get_type_inside("((a) => { a })", "a"), "unknown");
}

#[test]
fn does_not_infer_type_if_a_spread_operator_is_used() {
    assert_eq!(
        get_type_inside("(function(a) { a })(...[window])", "a"),
        "unknown"
    );
}

#[test]
fn does_not_infer_type_if_the_iife_is_named() {
    assert_eq!(
        get_type_inside("(function named(a) { a })(window)", "a"),
        "unknown"
    );
}

// isSafeExpression: named function in closed scope

#[test]
fn named_function_safe_when_called_once_with_safe_literal_argument() {
    let code = r#"
        (function() {
            function g(x) { var _s = x; }
            g("safe");
        })();
    "#;
    assert!(get_safety_inside(code, "x"));
}

#[test]
fn named_function_unsafe_when_called_once_with_unsafe_argument() {
    let code = r#"
        (function() {
            function g(x) { var _s = x; }
            g(externalVar);
        })();
    "#;
    assert!(!get_safety_inside(code, "x"));
}

#[test]
fn named_function_safe_when_called_multiple_times_all_safe() {
    let code = r#"
        (function() {
            function g(x) { var _s = x; }
            g("hello");
            g("world");
        })();
    "#;
    assert!(get_safety_inside(code, "x"));
}

#[test]
fn named_function_unsafe_when_called_multiple_times_at_least_one_unsafe() {
    let code = r#"
        (function() {
            function g(x) { var _s = x; }
            g("safe");
            g(externalVar);
        })();
    "#;
    assert!(!get_safety_inside(code, "x"));
}

#[test]
fn named_function_safe_when_argument_is_missing() {
    let code = r#"
        (function() {
            function g(x) { var _s = x; }
            g();
        })();
    "#;
    assert!(get_safety_inside(code, "x"));
}

#[test]
fn named_function_unsafe_when_function_reference_escapes() {
    let code = r#"
        (function() {
            function g(x) { var _s = x; }
            setTimeout(g, 0);
        })();
    "#;
    assert!(!get_safety_inside(code, "x"));
}

#[test]
fn named_function_unsafe_when_spread_is_used_in_the_call() {
    let code = r#"
        (function() {
            function g(x) { var _s = x; }
            g(...["safe"]);
        })();
    "#;
    assert!(!get_safety_inside(code, "x"));
}

// inferType: named function in closed scope

#[test]
fn named_function_infers_string_type_when_called_with_string_literal() {
    let code = r#"
        (function() { function g(x) { x; } g("hello"); })()
    "#;
    assert_eq!(get_type_inside(code, "x"), "string");
}

#[test]
fn named_function_infers_number_type_when_called_with_numeric_literal() {
    let code = r#"
        (function() { function g(x) { x; } g(42); })()
    "#;
    assert_eq!(get_type_inside(code, "x"), "number");
}

#[test]
fn named_function_infers_window_type_when_called_with_window() {
    let code = r#"
        (function() { function g(x) { x; } g(window); })()
    "#;
    assert_eq!(get_type_inside(code, "x"), "Window");
}

#[test]
fn named_function_infers_string_type_when_all_call_sites_use_string_literals() {
    let code = r#"
        (function() { function g(x) { x; } g("a"); g("b"); })()
    "#;
    assert_eq!(get_type_inside(code, "x"), "string");
}

#[test]
fn named_function_returns_unknown_when_call_sites_use_different_types() {
    let code = r#"
        (function() { function g(x) { x; } g("str"); g(42); })()
    "#;
    assert_eq!(get_type_inside(code, "x"), "unknown");
}

#[test]
fn named_function_returns_unknown_when_function_reference_escapes() {
    let code = r#"
        (function() { function g(x) { x; } setTimeout(g, 0); })()
    "#;
    assert_eq!(get_type_inside(code, "x"), "unknown");
}
