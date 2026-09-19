mod common;
use common::count_detector;

const D: &str = "javascriptLinks";

// Assignments

#[test]
fn detects_dynamic_location_assignment() {
    assert_eq!(count_detector("location = target", D), 1);
}

#[test]
fn detects_dynamic_window_location_assignment() {
    assert_eq!(count_detector("window.location = target", D), 1);
}

#[test]
fn detects_dynamic_location_href_assignment() {
    assert_eq!(count_detector("location.href = target", D), 1);
}

#[test]
fn detects_dynamic_window_location_href_assignment() {
    assert_eq!(count_detector("window.location.href = target", D), 1);
}

#[test]
fn detects_dynamic_location_replace() {
    assert_eq!(count_detector("location.replace(target)", D), 1);
}

#[test]
fn ignores_assignment_to_local_location_variable() {
    let code = r#"
        function x(location, b) {
            location = b;
            location.replace(b);
            location.assign(b);
        }
        function x() {
            let location = "a";
            location = "b"
        }
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_dynamic_window_location_replace() {
    assert_eq!(count_detector("window.location.replace(target)", D), 1);
}

#[test]
fn detects_dynamic_href_assignment() {
    assert_eq!(count_detector("a.href = target", D), 1);
}

#[test]
fn detects_dynamic_set_attribute_on_href() {
    assert_eq!(count_detector("a.setAttribute('href', target)", D), 1);
}

#[test]
fn detects_dynamic_location_assign() {
    assert_eq!(count_detector("window.location.assign(target)", D), 1);
}

// Open methods

#[test]
fn detects_dynamic_open_call() {
    assert_eq!(count_detector("open(target)", D), 1);
}

#[test]
fn detects_window_in_iife_from_argument() {
    let code = r#"
        (function(a) {
            a.open(target);
        })(window);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_location_in_iife_from_argument() {
    let code = r#"
        (function(loc) {
            loc.assign(url);
        })(location);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_location_in_arrow_function_iife_from_argument() {
    let code = r#"
        ((loc) => {
            loc.replace(target);
        })(location);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_window_location_in_iife_from_argument() {
    let code = r#"
        (function(winLoc) {
            winLoc.assign(url);
        })(window.location);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_window_location_replace_in_iife_passing_window() {
    let code = r#"
        (function(win) {
            win.location.replace(url);
        })(window);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_local_variable_named_window_passed_to_iife() {
    let code = r#"
        const window = { open: function() {} };
        (function(a) {
            a.open(target);
        })(window);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_local_variable_named_location_passed_to_iife() {
    let code = r#"
        const location = { assign: function() {} };
        (function(loc) {
            loc.assign(url);
        })(location);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_window_open_call() {
    assert_eq!(count_detector("window.open(target)", D), 1);
}

#[test]
fn detects_open_call_with_window_open_specific_target_argument() {
    let code = r#"
        const obj = getObj();
        obj.open(target, "_blank");
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_open_call_with_window_open_specific_features_argument() {
    let code = r#"
        const obj = getObj();
        obj.open(target, "myWindow", "width=500,height=500");
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_open_call_on_xml_http_request() {
    let code = r#"
        const xhr = new XMLHttpRequest();
        xhr.open("GET", target);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_document_open_call() {
    assert_eq!(count_detector("document.open(target)", D), 0);
    assert_eq!(count_detector("window.document.open(target)", D), 0);
}

#[test]
fn ignores_open_call_on_unknown_object_without_specific_arguments() {
    let code = r#"
        const obj = getObj();
        obj.open(target);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_open_call_on_known_non_window_object() {
    let code = r#"
        const x = new SomeThing();
        x.open(unknown);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

// Javascript scheme prefix check

#[test]
fn detects_javascript_dynamic_expression() {
    assert_eq!(count_detector("a.href = 'javascript:' + payload", D), 1);
}

#[test]
fn ignores_safe_static_url_assignment() {
    assert_eq!(count_detector("a.href = 'https://example.com'", D), 0);
}

#[test]
fn ignores_javascript_void_0() {
    assert_eq!(count_detector("a.href = 'javascript:void(0)'", D), 0);
}

#[test]
fn ignores_constant_variable_holding_safe_url() {
    let code = r#"
        const url = "https://google.com";
        location.href = url;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

// URL objects

#[test]
fn ignores_to_string_on_url_object_initialized_with_safe_url() {
    let code = r#"
        const r = new URL(window.location.href);
        window.location.href = r.toString();
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_direct_assignment_of_url_object_initialized_with_safe_url() {
    let code = r#"
        const r = new URL(window.location.href);
        window.location.href = r;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_to_string_on_url_object_initialized_with_unknown_variable() {
    let code = r#"
        const r = new URL(userInput);
        window.location.href = r.toString();
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_assignment_of_url_object_initialized_with_unknown_variable() {
    let code = r#"
        const r = new URL(userInput);
        window.location.href = r;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_url_object_initialized_with_string_concatenation_of_safe_prefix() {
    let code = r#"
        const r = new URL("https://" + userInput);
        window.location.href = r.href;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_concatenated_constant_safe_url() {
    let code = r#"
        const domain = "https://";
        const site = "example.com";
        a.href = domain + site;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_unknown_identifier_in_concatenation_if_prefix_is_safe() {
    let code = r#"
        const domain = "https://";
        a.href = domain + unknownPart;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_binary_expression_with_safe_prefix_string_literal() {
    let code = r#"
        a.href = "https://" + unknownPart;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_variable_holding_static_javascript_string() {
    let code = r#"
        const script = "javascript:alert(1)";
        location.href = script;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_concatenation_forming_static_javascript_string() {
    let code = r#"
        const proto = "javascript:";
        const payload = "void(0)";
        location.href = proto + payload;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_template_literal_with_static_content() {
    assert_eq!(count_detector("location.href = `javascript:void(0)`", D), 0);
}

#[test]
fn ignores_string_cast_with_static_content() {
    assert_eq!(
        count_detector("location.href = String('javascript:void(0)')", D),
        0
    );
}

// Element safety checks

#[test]
fn ignores_src_assignment_on_confirmed_img_element() {
    let code = r#"
        const img = document.createElement("img");
        img.src = userInput;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_set_attribute_src_on_confirmed_img_element() {
    let code = r#"
        const s = "img";
        const img = document.createElement(s);
        img.setAttribute("src", userInput);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_href_assignment_on_confirmed_anchor_element() {
    let code = r#"
        const link = document.createElement("a");
        link.href = userInput;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_assignment_on_new_image_src_chained() {
    let code = r#"
        new Image().src = userInput;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_src_assignment_on_new_image() {
    let code = r#"
        const img = new Image();
        img.src = userInput;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_set_attribute_on_new_image() {
    let code = r#"
        const img = new Image(100, 100);
        img.setAttribute("src", userInput);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

// Primitive and null assignments

#[test]
fn ignores_assignment_of_numeric_literal_to_location() {
    assert_eq!(count_detector("e.location = .5", D), 0);
}

#[test]
fn ignores_assignment_of_null_to_src() {
    assert_eq!(count_detector("A.src = null", D), 0);
}

#[test]
fn ignores_assignment_of_boolean_to_href() {
    assert_eq!(count_detector("a.href = true", D), 0);
}

#[test]
fn ignores_assignment_of_undefined_to_location() {
    assert_eq!(count_detector("location = undefined", D), 0);
}

#[test]
fn ignores_src_assignment_of_negated_boolean() {
    assert_eq!(count_detector("e.src = !1", D), 0);
    assert_eq!(count_detector("e.src = !userControlled", D), 0);
}

#[test]
fn ignores_src_assignment_of_variable_holding_negated_boolean() {
    let code = r#"
        const disabled = !1;
        e.src = disabled;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_src_assignment_on_new_image_in_sequence_expression() {
    let code = r#"
        this.image = new Image(), this.image.src = o.localSrc;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_self_assignment_on_src() {
    assert_eq!(count_detector("n.src = n.src", D), 0);
}

#[test]
fn ignores_self_assignment_on_href() {
    assert_eq!(count_detector("a.href = a.href", D), 0);
}

#[test]
fn ignores_self_assignment_on_location() {
    assert_eq!(count_detector("location = location", D), 0);
}

#[test]
fn ignores_self_assigned_variable() {
    let code = r#"
        let a = "safe";
        a = a;
        window.location.assign(a);
    "#;
    assert_eq!(count_detector(code, D), 0);
}
