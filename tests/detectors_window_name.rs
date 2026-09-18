//! Port of `packages/vscode-ext/test/detectors/windowName.test.ts`.

mod common;
use common::count_detector;

const D: &str = "windowName";

#[test]
fn detects_window_name_read() {
    assert_eq!(count_detector("const n = window.name;", D), 1);
}

#[test]
fn detects_self_name_read() {
    assert_eq!(count_detector("const n = self.name;", D), 1);
}

#[test]
fn detects_global_this_name_read() {
    assert_eq!(count_detector("const n = globalThis.name;", D), 1);
}

#[test]
fn ignores_window_name_write() {
    assert_eq!(count_detector(r#"window.name = "safe";"#, D), 0);
}

#[test]
fn ignores_self_name_write() {
    assert_eq!(count_detector(r#"self.name = "value";"#, D), 0);
}

#[test]
fn ignores_non_window_object_name() {
    assert_eq!(count_detector("const n = myObj.name;", D), 0);
}

#[test]
fn ignores_shadowed_window_binding() {
    let code = r#"
        const window = { name: "test" };
        const n = window.name;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_shadowed_self_binding() {
    let code = r#"
        const self = { name: "test" };
        const n = self.name;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_window_name_used_in_template_literal() {
    assert_eq!(count_detector("const msg = `Hello ${window.name}`;", D), 1);
}

#[test]
fn detects_window_name_used_as_function_argument() {
    assert_eq!(count_detector("doSomething(window.name);", D), 1);
}

#[test]
fn detects_window_name_in_concatenation() {
    assert_eq!(count_detector(r#"const s = "prefix" + window.name;"#, D), 1);
}

#[test]
fn detects_multiple_window_name_reads() {
    let code = r#"
        const a = window.name;
        const b = self.name;
    "#;
    assert_eq!(count_detector(code, D), 2);
}

// --- bare `name` ---

#[test]
fn detects_bare_name_read_when_no_local_binding() {
    assert_eq!(count_detector("const n = name;", D), 1);
}

#[test]
fn detects_bare_name_as_function_argument() {
    assert_eq!(count_detector("doSomething(name);", D), 1);
}

#[test]
fn detects_bare_name_in_template_literal() {
    assert_eq!(count_detector("const msg = `Hello ${name}`;", D), 1);
}

#[test]
fn ignores_bare_name_when_shadowed_by_local_variable() {
    let code = r#"
        const name = "safe";
        const n = name;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_bare_name_when_it_is_a_function_parameter() {
    let code = r#"
        function greet(name) {
            return "Hello " + name;
        }
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_bare_name_as_object_property_key() {
    assert_eq!(count_detector(r#"const obj = { name: "value" };"#, D), 0);
}

#[test]
fn ignores_bare_name_write() {
    assert_eq!(count_detector(r#"name = "safe";"#, D), 0);
}

#[test]
fn detects_bare_name_in_concatenation() {
    assert_eq!(count_detector(r#"const s = "prefix" + name;"#, D), 1);
}
