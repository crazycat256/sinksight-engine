mod common;
use common::count_detector;

const D: &str = "unsafeHtml";

#[test]
fn detects_dynamic_inner_html_assignment() {
    assert_eq!(count_detector("el.innerHTML = userInput", D), 1);
}

#[test]
fn detects_dynamic_outer_html_assignment() {
    assert_eq!(count_detector("el.outerHTML = userInput", D), 1);
}

#[test]
fn detects_dynamic_document_body_inner_html_assignment() {
    assert_eq!(count_detector("document.body.innerHTML = userInput", D), 1);
}

#[test]
fn ignores_static_html_assignment() {
    assert_eq!(count_detector("el.innerHTML = '<b>ok</b>'", D), 0);
}

#[test]
fn detects_computed_srcdoc_assignment() {
    assert_eq!(count_detector("frame['srcdoc'] = tpl", D), 1);
}

#[test]
fn ignores_concatenation_of_static_strings() {
    let code = r#"
        const a = "<div>";
        const b = "safe";
        const c = "</div>";
        el.innerHTML = a + b + c;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_template_literal_with_only_static_content() {
    let code = r#"
        const name = "World";
        el.innerHTML = `<h1>Hello, ${name}!</h1>`;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_concatenation_with_dynamic_variable() {
    let code = r#"
        const a = "<div>";
        const b = getUserInput();
        el.innerHTML = a + b;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_template_literal_with_dynamic_expression() {
    let code = r#"
        const name = getUserInput();
        el.innerHTML = `<h1>Hello, ${name}!</h1>`;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn resolves_variables_through_multiple_assignments() {
    let code = r#"
        const a = "safe";
        const b = a;
        const c = b;
        el.innerHTML = c;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_variable_reassigned_with_only_safe_values_let() {
    let code = r#"
        let a = "safe";
        a = "safe 2";
        el.innerHTML = a;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_variable_reassigned_with_dynamic_value_let() {
    let code = r#"
        let a = "safe";
        a = getUserInput();
        el.innerHTML = a;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_numeric_assignment() {
    let code = r#"
        el.innerHTML = 123;
        el.innerHTML = x * 1;
        el.innerHTML = Math.random();
        el.innerHTML = i++;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_ternary_operator_with_static_branches() {
    let code = r#"
        el.innerHTML = condition ? "<p>Yes</p>" : "<p>No</p>";
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_ternary_operator_with_dynamic_branch() {
    let code = r#"
        el.innerHTML = condition ? "<p>Yes</p>" : getUserInput();
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_multiple_assignments_with_final_static_value() {
    let code = r#"
        let a = "unsafe";
        a = "still unsafe";
        a = "safe";
        el.innerHTML = a;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_multiple_assignments_on_a_single_line_with_final_static_value() {
    let code = r#"
        a.innerHTML = b.innerHTML = c.innerHTML = "safe";
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_reassigned_variable_that_is_later_assigned_a_safe_value() {
    let code = r#"
        let a = getUserInput();
        a = "safe";
        el.innerHTML = a;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn still_detects_inner_html_self_assignment() {
    assert_eq!(count_detector("el.innerHTML = el.innerHTML", D), 1);
}

#[test]
fn detects_inner_html_from_new_array_of_dynamic_content() {
    assert_eq!(count_detector("el.innerHTML = new Array(userInput)", D), 1);
}

#[test]
fn ignores_inner_html_from_new_array_of_static_content() {
    assert_eq!(
        count_detector(r#"el.innerHTML = new Array("safe", "also safe")"#, D),
        0
    );
}

#[test]
fn detects_inner_html_from_dynamic_from_char_code() {
    assert_eq!(
        count_detector("el.innerHTML = String.fromCharCode(userInput)", D),
        1
    );
}

#[test]
fn ignores_inner_html_from_static_from_char_code() {
    assert_eq!(
        count_detector("el.innerHTML = String.fromCharCode(60, 98, 62)", D),
        0
    );
}

#[test]
fn detects_iframe_srcdoc_assignment() {
    let code = r#"
        const iframe = document.createElement("iframe");
        iframe.srcdoc = userInput;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_set_attribute_srcdoc() {
    let code = r#"
        const iframe = document.createElement("iframe");
        iframe.setAttribute("srcdoc", userInput);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_set_attribute_srcdoc_on_div() {
    let code = r#"
        const el = document.createElement("div");
        el.setAttribute("srcdoc", userInput);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_set_attribute_onclick() {
    assert_eq!(
        count_detector(r#"el.setAttribute("onclick", userInput)"#, D),
        1
    );
}

#[test]
fn detects_set_attribute_ns_onload() {
    let code = r#"
        el.setAttributeNS(null, "onload", userInput);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_onclick_property_assignment() {
    assert_eq!(count_detector("el.onclick = userInput", D), 0);
}

#[test]
fn ignores_srcdoc_assignment_on_div() {
    let code = r#"
        const el = document.createElement("div");
        el.srcdoc = userInput;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_inner_html_via_concatenated_property_name() {
    let code = r#"
        const el = document.createElement("div");
        el['inner' + 'HTML'] = userInput;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_inner_html_via_const_concatenated_property() {
    let code = r#"
        const el = document.createElement("div");
        const p = 'inner' + 'HTML';
        el[p] = userInput;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_inner_html_via_concatenated_const_variables() {
    let code = r#"
        const el = document.createElement("div");
        const a = 'inner';
        const b = 'HTML';
        el[a + b] = userInput;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_inner_html_after_both_branches_assign_safe() {
    let code = r#"
        let a = getUserInput();
        if (cond) {
            a = "<p>ok</p>";
        } else {
            a = "<p>also ok</p>";
        }
        el.innerHTML = a;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_inner_html_when_one_branch_stays_unsafe() {
    let code = r#"
        let a = getUserInput();
        if (cond) {
            a = "<p>ok</p>";
        }
        el.innerHTML = a;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_inner_html_after_iife_overwrites_with_safe() {
    let code = r#"
        let a = getUserInput();
        (function () {
            a = "<p>ok</p>";
        })();
        el.innerHTML = a;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_inner_html_after_finally_overwrites_with_safe() {
    let code = r#"
        let a = getUserInput();
        try {
            a = getUserInput();
        } finally {
            a = "<p>ok</p>";
        }
        el.innerHTML = a;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_inner_html_after_for_in_concatenates_unknown_values() {
    let code = r#"
        let html = "<table>";
        for (const key in data) {
            html += data[key];
        }
        el.innerHTML = html;
    "#;
    assert_eq!(count_detector(code, D), 1);
}
