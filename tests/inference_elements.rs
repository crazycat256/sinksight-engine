//! Port of `packages/vscode-ext/test/inference/elements.test.ts`.

mod common;
use common::with_last_expr;
use sinksight_engine::inference::{infer_element_type, is_dangerous_attribute};

fn assert_element_type(code: &str, expected: Option<&str>) {
    with_last_expr(code, |ctx, expr, scope_id| {
        let ty = infer_element_type(ctx, expr, scope_id);
        assert_eq!(ty.as_deref(), expected, "for {code:?}");
    });
}

// inferElementType

#[test]
fn returns_none_for_non_element_expressions() {
    assert_element_type("42", None);
}

#[test]
fn returns_none_for_unknown_variables() {
    assert_element_type("someVar", None);
}

#[test]
fn infers_img_for_new_image() {
    assert_element_type("new Image()", Some("img"));
}

#[test]
fn infers_img_for_new_image_with_dimensions() {
    assert_element_type("new Image(100, 100)", Some("img"));
}

#[test]
fn infers_img_for_variable_holding_new_image() {
    assert_element_type("const img = new Image(); img", Some("img"));
}

#[test]
fn infers_audio_for_new_audio() {
    assert_element_type("new Audio()", Some("audio"));
}

#[test]
fn infers_option_for_new_option() {
    assert_element_type("new Option('text', 'value')", Some("option"));
}

#[test]
fn infers_tag_for_create_element_div() {
    assert_element_type("document.createElement('div')", Some("div"));
}

#[test]
fn infers_tag_for_create_element_script() {
    assert_element_type("document.createElement('script')", Some("script"));
}

#[test]
fn infers_tag_for_create_element_case_insensitive() {
    assert_element_type("document.createElement('IMG')", Some("img"));
}

#[test]
fn resolves_variable_tag_name() {
    let code = r#"
        const tag = "canvas";
        document.createElement(tag)
    "#;
    assert_element_type(code, Some("canvas"));
}

#[test]
fn returns_none_for_dynamic_tag_name() {
    assert_element_type("document.createElement(getTagName())", None);
}

#[test]
fn resolves_variable_holding_create_element_result() {
    let code = r#"
        const el = document.createElement("span");
        el
    "#;
    assert_element_type(code, Some("span"));
}

#[test]
fn infers_tag_for_create_element_ns_svg() {
    assert_element_type(
        r#"document.createElementNS("http://www.w3.org/2000/svg", "svg")"#,
        Some("svg"),
    );
}

#[test]
fn infers_tag_for_create_element_ns_circle() {
    assert_element_type(
        r#"document.createElementNS("http://www.w3.org/2000/svg", "circle")"#,
        Some("circle"),
    );
}

#[test]
fn infers_tag_for_create_element_ns_xhtml_namespace() {
    assert_element_type(
        r#"document.createElementNS("http://www.w3.org/1999/xhtml", "div")"#,
        Some("div"),
    );
}

#[test]
fn resolves_variable_tag_in_create_element_ns() {
    let code = r#"
        const tag = "rect";
        document.createElementNS("http://www.w3.org/2000/svg", tag)
    "#;
    assert_element_type(code, Some("rect"));
}

#[test]
fn returns_none_for_dynamic_tag_in_create_element_ns() {
    assert_element_type(
        r#"document.createElementNS("http://www.w3.org/2000/svg", getTag())"#,
        None,
    );
}

#[test]
fn resolves_variable_holding_create_element_ns_result() {
    let code = r#"
        const el = document.createElementNS("http://www.w3.org/2000/svg", "path");
        el
    "#;
    assert_element_type(code, Some("path"));
}

// isDangerousAttribute

#[test]
fn event_handlers_are_always_dangerous_on_any_element() {
    let events = [
        "onclick",
        "onload",
        "onerror",
        "onmouseover",
        "onfocus",
        "onsomethingthatdoesntexist",
    ];
    for ev in events {
        assert!(is_dangerous_attribute(Some("div"), ev));
        assert!(is_dangerous_attribute(Some("script"), ev));
        assert!(is_dangerous_attribute(None, ev));
    }
}

#[test]
fn src_attribute_dangerous_on_script() {
    assert!(is_dangerous_attribute(Some("script"), "src"));
}

#[test]
fn src_attribute_dangerous_on_iframe() {
    assert!(is_dangerous_attribute(Some("iframe"), "src"));
}

#[test]
fn src_attribute_dangerous_on_embed() {
    assert!(is_dangerous_attribute(Some("embed"), "src"));
}

#[test]
fn src_attribute_dangerous_on_object() {
    assert!(is_dangerous_attribute(Some("object"), "src"));
}

#[test]
fn src_attribute_not_dangerous_on_img() {
    assert!(!is_dangerous_attribute(Some("img"), "src"));
}

#[test]
fn src_attribute_not_dangerous_on_video() {
    assert!(!is_dangerous_attribute(Some("video"), "src"));
}

#[test]
fn src_attribute_not_dangerous_on_audio() {
    assert!(!is_dangerous_attribute(Some("audio"), "src"));
}

#[test]
fn src_attribute_dangerous_on_unknown_element() {
    assert!(is_dangerous_attribute(None, "src"));
}

#[test]
fn href_attribute_dangerous_on_a() {
    assert!(is_dangerous_attribute(Some("a"), "href"));
}

#[test]
fn href_attribute_dangerous_on_area() {
    assert!(is_dangerous_attribute(Some("area"), "href"));
}

#[test]
fn href_attribute_dangerous_on_base() {
    assert!(is_dangerous_attribute(Some("base"), "href"));
}

#[test]
fn href_attribute_dangerous_on_link() {
    assert!(is_dangerous_attribute(Some("link"), "href"));
}

#[test]
fn href_attribute_not_dangerous_on_div() {
    assert!(!is_dangerous_attribute(Some("div"), "href"));
}

#[test]
fn href_attribute_dangerous_on_unknown_element() {
    assert!(is_dangerous_attribute(None, "href"));
}

#[test]
fn data_attribute_dangerous_on_object() {
    assert!(is_dangerous_attribute(Some("object"), "data"));
}

#[test]
fn data_attribute_not_dangerous_on_div() {
    assert!(!is_dangerous_attribute(Some("div"), "data"));
}

#[test]
fn action_attribute_dangerous_on_form() {
    assert!(is_dangerous_attribute(Some("form"), "action"));
}

#[test]
fn action_attribute_not_dangerous_on_div() {
    assert!(!is_dangerous_attribute(Some("div"), "action"));
}

#[test]
fn formaction_attribute_dangerous_on_button() {
    assert!(is_dangerous_attribute(Some("button"), "formaction"));
}

#[test]
fn formaction_attribute_dangerous_on_input() {
    assert!(is_dangerous_attribute(Some("input"), "formaction"));
}

#[test]
fn srcdoc_attribute_dangerous_on_iframe() {
    assert!(is_dangerous_attribute(Some("iframe"), "srcdoc"));
}

#[test]
fn srcdoc_attribute_not_dangerous_on_div() {
    assert!(!is_dangerous_attribute(Some("div"), "srcdoc"));
}

#[test]
fn safe_attributes_are_not_dangerous_on_any_element() {
    let safe_attrs = ["class", "id", "style", "title", "alt", "width", "height"];
    for attr in safe_attrs {
        assert!(!is_dangerous_attribute(Some("div"), attr));
        assert!(!is_dangerous_attribute(Some("script"), attr));
        assert!(!is_dangerous_attribute(None, attr));
    }
}

#[test]
fn handles_mixed_case_attribute_names() {
    assert!(is_dangerous_attribute(Some("script"), "SRC"));
    assert!(is_dangerous_attribute(Some("a"), "HREF"));
    assert!(is_dangerous_attribute(Some("div"), "onClick"));
}

#[test]
fn handles_mixed_case_element_tags() {
    assert!(is_dangerous_attribute(Some("SCRIPT"), "src"));
    assert!(is_dangerous_attribute(Some("Script"), "src"));
}

#[test]
fn null_element_conservatively_flags_known_dangerous_attrs() {
    assert!(is_dangerous_attribute(None, "src"));
    assert!(is_dangerous_attribute(None, "href"));
    assert!(is_dangerous_attribute(None, "action"));
    assert!(is_dangerous_attribute(None, "formaction"));
    assert!(is_dangerous_attribute(None, "srcdoc"));
    assert!(is_dangerous_attribute(None, "data"));
}

#[test]
fn null_element_does_not_flag_clearly_safe_attrs() {
    assert!(!is_dangerous_attribute(None, "class"));
    assert!(!is_dangerous_attribute(None, "id"));
}
