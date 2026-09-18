mod common;
use common::count_detector;

const D: &str = "createObjectUrl";

#[test]
fn detects_unknown_blob() {
    assert_eq!(count_detector("URL.createObjectURL(blob)", D), 1);
}

#[test]
fn detects_dynamic_blob_content() {
    let code = r#"
        const blob = new Blob([getUserInput()]);
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_dynamic_blob_and_text_html_type() {
    let code = r#"
        const blob = new Blob([getUserInput()], { type: "text/html" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_dynamic_blob_and_image_svg_xml_type() {
    let code = r#"
        const blob = new Blob([getUserInput()], { type: "image/svg+xml" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_dynamic_blob_and_application_xhtml_xml_type() {
    let code = r#"
        const blob = new Blob([getUserInput()], { type: "application/xhtml+xml" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_dynamic_blob_and_text_xml_type() {
    let code = r#"
        const blob = new Blob([getUserInput()], { type: "text/xml" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_dynamic_blob_and_application_xml_type() {
    let code = r#"
        const blob = new Blob([getUserInput()], { type: "application/xml" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_no_arguments() {
    assert_eq!(count_detector("URL.createObjectURL()", D), 1);
}

#[test]
fn detects_dynamic_blob_and_no_type_option() {
    let code = r#"
        const blob = new Blob([userInput]);
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_dynamic_blob_and_dynamic_type() {
    let code = r#"
        const blob = new Blob([data], { type: getMimeType() });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_dynamic_file_content_and_text_html_type() {
    let code = r#"
        const file = new File([getUserInput()], "page.html", { type: "text/html" });
        URL.createObjectURL(file);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_inline_dynamic_blob() {
    assert_eq!(
        count_detector(
            "URL.createObjectURL(new Blob([payload], { type: 'text/html' }))",
            D
        ),
        1
    );
}

#[test]
fn detects_empty_options_object() {
    let code = r#"
        const blob = new Blob([userInput], {});
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_static_blob_content() {
    let code = r#"
        const blob = new Blob(["<h1>Hello</h1>"]);
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_static_blob_content_and_text_html_type() {
    let code = r#"
        const blob = new Blob(["<h1>Hello</h1>"], { type: "text/html" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_blob_and_safe_mime_type_text_plain() {
    let code = r#"
        const blob = new Blob([getUserInput()], { type: "text/plain" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_blob_and_safe_mime_type_application_json() {
    let code = r#"
        const blob = new Blob([data], { type: "application/json" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_blob_and_safe_mime_type_application_octet_stream() {
    let code = r#"
        const blob = new Blob([data], { type: "application/octet-stream" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_blob_and_safe_mime_type_image_png() {
    let code = r#"
        const blob = new Blob([data], { type: "image/png" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_blob_and_safe_mime_type_template_literal_image_png() {
    let code = r#"
        const n = getUserInput();
        URL.createObjectURL(new Blob([n], { type: `image/png` }));
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_blob_and_safe_mime_type_image_jpeg() {
    let code = r#"
        const blob = new Blob([data], { type: "image/jpeg" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_blob_and_safe_mime_type_audio_mpeg() {
    let code = r#"
        const blob = new Blob([data], { type: "audio/mpeg" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_blob_and_safe_mime_type_video_mp4() {
    let code = r#"
        const blob = new Blob([data], { type: "video/mp4" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_blob_and_safe_mime_type_text_css() {
    let code = r#"
        const blob = new Blob([data], { type: "text/css" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_blob_and_safe_mime_type_application_pdf() {
    let code = r#"
        const blob = new Blob([data], { type: "application/pdf" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_dynamic_file_and_safe_mime_type() {
    let code = r#"
        const file = new File([data], "report.pdf", { type: "application/pdf" });
        URL.createObjectURL(file);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_type_variable_resolved_to_safe_string() {
    let code = r#"
        const mimeType = "text/plain";
        const blob = new Blob([data], { type: mimeType });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_revoke_object_url_calls() {
    assert_eq!(count_detector("URL.revokeObjectURL(url)", D), 0);
}

#[test]
fn ignores_unrelated_url_method_calls() {
    assert_eq!(count_detector("URL.canParse(url)", D), 0);
}

#[test]
fn ignores_create_object_url_on_non_url_objects() {
    let code = r#"
        const myLib = { createObjectURL: (b) => "url" };
        myLib.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_new_url_constructor() {
    assert_eq!(count_detector("new URL('https://example.com')", D), 0);
}

#[test]
fn detects_blob_constructed_from_template_literal() {
    let code = r#"
        const html = `<div>${getUserInput()}</div>`;
        const blob = new Blob([html], { type: "text/html" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_blob_built_from_concatenation() {
    let code = r#"
        const html = "<div>" + getUserInput() + "</div>";
        const blob = new Blob([html]);
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_blob_of_safe_concatenated_content() {
    let code = r#"
        const a = "Hello";
        const b = " World";
        const blob = new Blob([a + b], { type: "text/html" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_type_resolved_to_executable_mime() {
    let code = r#"
        const mimeType = "text/html";
        const blob = new Blob([data], { type: mimeType });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_computed_property_access_on_url() {
    assert_eq!(count_detector("URL['createObjectURL'](blob)", D), 1);
}

#[test]
fn detects_multiple_calls_independently() {
    let code = r#"
        URL.createObjectURL(blob1);
        URL.createObjectURL(new Blob(["safe"]));
        URL.createObjectURL(blob2);
    "#;
    assert_eq!(count_detector(code, D), 2);
}

#[test]
fn ignores_inline_safe_blob() {
    assert_eq!(
        count_detector(
            "URL.createObjectURL(new Blob(['hello'], { type: 'text/plain' }))",
            D
        ),
        0
    );
}

#[test]
fn detects_blob_with_spread_in_parts() {
    let code = r#"
        const parts = getHtmlParts();
        const blob = new Blob([...parts], { type: "text/html" });
        URL.createObjectURL(blob);
    "#;
    assert_eq!(count_detector(code, D), 1);
}
