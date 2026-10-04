mod common;
use common::count_detector;

const D: &str = "resourceUrl";

#[test]
fn detects_script_src_assignment() {
    let code = r#"
        const s = document.createElement("script");
        s.src = userInput;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_script_src_with_https_prefix() {
    let code = r#"
        const s = document.createElement("script");
        s.src = "https://" + userInput;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_static_script_src() {
    let code = r#"
        const s = document.createElement("script");
        s.src = "https://cdn.example/app.js";
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_script_set_attribute_src() {
    let code = r#"
        const s = document.createElement("script");
        s.setAttribute("src", userInput);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_object_data_assignment() {
    let code = r#"
        const obj = document.createElement("object");
        obj.data = userInput;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_embed_src_assignment() {
    let code = r#"
        const embed = document.createElement("embed");
        embed.src = userInput;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_unknown_element_src_as_resource() {
    assert_eq!(count_detector("el.src = userInput", D), 1);
}

#[test]
fn ignores_unknown_element_data_assignment() {
    assert_eq!(count_detector("el.data = userInput", D), 0);
}

#[test]
fn ignores_unknown_element_set_attribute_data() {
    assert_eq!(
        count_detector(r#"el.setAttribute("data", userInput)"#, D),
        0
    );
}

#[test]
fn ignores_img_src() {
    let code = r#"
        const img = document.createElement("img");
        img.src = userInput;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_iframe_src() {
    let code = r#"
        const frame = document.createElement("iframe");
        frame.src = userInput;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_anchor_href() {
    let code = r#"
        const a = document.createElement("a");
        a.href = userInput;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_self_assignment_on_src() {
    assert_eq!(count_detector("n.src = n.src", D), 0);
}

#[test]
fn ignores_numeric_src() {
    assert_eq!(count_detector("el.src = 1", D), 0);
}
