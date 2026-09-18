//! Sink/input detectors. Walks `Semantic::nodes()` so each node already carries its `ScopeId`.

pub mod create_object_url;
pub mod document_referrer;
pub mod document_write;
pub mod eval;
pub mod function_constructor;
pub mod insert_adjacent_html;
pub mod javascript_links;
pub mod post_message;
pub mod unsafe_html;
pub mod unsafe_timers;
pub mod url_params;
pub mod window_name;

use oxc_ast::ast::Expression;
use oxc_ast::AstKind;
use oxc_span::Span;

use crate::ctx::{AnalysisCtx, RawMatch};

/// Walks every node recorded by semantic analysis and runs each detector
/// against the node kinds it's interested in, collecting all findings.
pub fn detect_all<'a>(ctx: &AnalysisCtx<'a>) -> Vec<RawMatch> {
    let mut out = Vec::new();

    for node in ctx.semantic.nodes().iter() {
        let scope_id = node.scope_id();
        match node.kind() {
            AstKind::AssignmentExpression(expr) => {
                unsafe_html::check(ctx, expr, scope_id, &mut out);
                javascript_links::check_assignment(ctx, expr, scope_id, &mut out);
                post_message::check_assignment(ctx, expr, scope_id, &mut out);
            }
            AstKind::CallExpression(expr) => {
                document_write::check(ctx, expr, scope_id, &mut out);
                insert_adjacent_html::check(ctx, expr, scope_id, &mut out);
                eval::check(ctx, expr, scope_id, &mut out);
                function_constructor::check_call(ctx, expr, scope_id, &mut out);
                unsafe_timers::check(ctx, expr, scope_id, &mut out);
                javascript_links::check_call(ctx, expr, scope_id, &mut out);
                create_object_url::check(ctx, expr, scope_id, &mut out);
                post_message::check_call(ctx, expr, scope_id, &mut out);
            }
            AstKind::NewExpression(expr) => {
                function_constructor::check_new(ctx, expr, scope_id, &mut out);
                url_params::check(ctx, expr, scope_id, &mut out);
            }
            AstKind::StaticMemberExpression(_) | AstKind::ComputedMemberExpression(_) => {
                let kind = node.kind();
                window_name::check_member(ctx, kind, node.id(), scope_id, &mut out);
                document_referrer::check(kind, &mut out);
            }
            AstKind::IdentifierReference(ident) => {
                window_name::check_identifier(ctx, ident, node.id(), scope_id, &mut out);
            }
            _ => {}
        }
    }

    out
}

/// Bridges the flattened `AstKind::StaticMemberExpression` /
/// `AstKind::ComputedMemberExpression` node kinds (as seen during the flat
/// [`detect_all`] walk) back to a `(property name, object, span)` triple,
/// unifying both member-access shapes the same way
/// [`oxc_ast::ast::MemberExpression::static_property_name`] does for an
/// already-typed `&MemberExpression`.
pub(crate) fn member_parts<'a>(kind: AstKind<'a>) -> Option<(&'a str, &'a Expression<'a>, Span)> {
    match kind {
        AstKind::StaticMemberExpression(m) => Some((m.property.name.as_str(), &m.object, m.span)),
        AstKind::ComputedMemberExpression(m) => {
            let name = m.static_property_name()?;
            Some((name.as_str(), &m.object, m.span))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use oxc_allocator::Allocator;
    use oxc_parser::{ParseOptions, Parser};
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;

    use crate::ctx::{AnalysisCtx, Category};

    use super::detect_all;

    /// Parses `source`, runs semantic analysis, and returns the detector
    /// names of every match found by [`detect_all`].
    fn run(source: &str) -> Vec<&'static str> {
        let allocator = Allocator::default();
        let source_type = SourceType::unambiguous();
        let options = ParseOptions {
            allow_return_outside_function: true,
            preserve_parens: false,
            ..ParseOptions::default()
        };
        let parser_ret = Parser::new(&allocator, source, source_type)
            .with_options(options)
            .parse();
        assert!(
            parser_ret.errors.is_empty(),
            "parse errors: {:?}",
            parser_ret.errors
        );

        let semantic_ret = SemanticBuilder::new().build(&parser_ret.program);
        assert!(
            semantic_ret.errors.is_empty(),
            "semantic errors: {:?}",
            semantic_ret.errors
        );

        let ctx = AnalysisCtx::new(source, &semantic_ret.semantic, &allocator);
        let mut names: Vec<&'static str> =
            detect_all(&ctx).into_iter().map(|m| m.detector).collect();
        names.sort_unstable();
        names
    }

    #[test]
    fn flags_unsafe_inner_html_assignment() {
        let names = run(r#"el.innerHTML = location.hash;"#);
        assert_eq!(names, vec!["unsafeHtml"]);
    }

    #[test]
    fn does_not_flag_static_inner_html_assignment() {
        let names = run(r#"el.innerHTML = "<b>static</b>";"#);
        assert!(names.is_empty(), "expected no matches, got {names:?}");
    }

    #[test]
    fn flags_document_write_with_dynamic_argument() {
        let names = run(r#"document.write(location.search);"#);
        assert_eq!(names, vec!["documentWrite"]);
    }

    #[test]
    fn flags_eval_with_dynamic_argument() {
        let names = run(r#"eval(userInput);"#);
        assert_eq!(names, vec!["eval"]);
    }

    #[test]
    fn does_not_flag_eval_with_static_argument() {
        let names = run(r#"eval("1 + 1");"#);
        assert!(names.is_empty(), "expected no matches, got {names:?}");
    }

    #[test]
    fn flags_function_constructor_with_dynamic_body() {
        let names = run(r#"new Function(userInput)();"#);
        assert_eq!(names, vec!["functionConstructor"]);
    }

    #[test]
    fn flags_settimeout_with_string_argument() {
        // A template literal is always string-typed, regardless of its
        // interpolations, so this exercises the "string but not provably
        // safe" branch of the detector (a bare `location.hash` MemberExpression
        // has no statically known type in the method registry, so it is not
        // flagged on its own).
        let names = run(r#"setTimeout(`${location.hash}`, 100);"#);
        assert_eq!(names, vec!["unsafeTimers"]);
    }

    #[test]
    fn does_not_flag_settimeout_with_function_argument() {
        let names = run(r#"setTimeout(() => doStuff(), 100);"#);
        assert!(names.is_empty(), "expected no matches, got {names:?}");
    }

    #[test]
    fn flags_window_name_read() {
        let names = run(r#"const value = window.name;"#);
        assert_eq!(names, vec!["windowName"]);
    }

    #[test]
    fn does_not_flag_window_name_write() {
        let names = run(r#"window.name = "safe";"#);
        assert!(names.is_empty(), "expected no matches, got {names:?}");
    }

    #[test]
    fn flags_insert_adjacent_html_with_dynamic_argument() {
        let names = run(r#"el.insertAdjacentHTML("beforeend", location.hash);"#);
        assert_eq!(names, vec!["insertAdjacentHtml"]);
    }

    #[test]
    fn flags_create_object_url_with_unresolvable_blob() {
        let names = run(r#"URL.createObjectURL(getBlob());"#);
        assert_eq!(names, vec!["createObjectUrl"]);
    }

    #[test]
    fn does_not_flag_create_object_url_with_safe_content_and_mime() {
        let names =
            run(r#"URL.createObjectURL(new Blob(["static text"], { type: "text/plain" }));"#);
        assert!(names.is_empty(), "expected no matches, got {names:?}");
    }

    #[test]
    fn flags_unchecked_post_message_handler() {
        let names =
            run(r#"window.addEventListener("message", function (e) { doStuff(e.data); });"#);
        assert_eq!(names, vec!["postMessage"]);
    }

    #[test]
    fn does_not_flag_post_message_handler_that_checks_origin() {
        let names = run(
            r#"window.addEventListener("message", function (e) { if (e.origin === "https://example.com") { doStuff(e.data); } });"#,
        );
        assert!(names.is_empty(), "expected no matches, got {names:?}");
    }

    #[test]
    fn flags_location_assignment_from_unresolvable_call() {
        let names = run(r#"location.href = getUserInput();"#);
        assert_eq!(names, vec!["javascriptLinks"]);
    }

    #[test]
    fn does_not_flag_location_assignment_from_location_search() {
        // `location.search` can never itself resolve to a `javascript:` URI
        // (it is a query string, always prefixed by `?`), so this is
        // intentionally not flagged.
        let names = run(r#"location.href = location.search;"#);
        assert!(names.is_empty(), "expected no matches, got {names:?}");
    }

    #[test]
    fn flags_document_referrer_read() {
        let names = run(r#"console.log(document.referrer);"#);
        assert_eq!(names, vec!["documentReferrer"]);
    }

    #[test]
    fn flags_url_search_params_without_static_arg() {
        let names = run(r#"const params = new URLSearchParams(location.search);"#);
        assert_eq!(names, vec!["urlParams"]);
    }

    #[test]
    fn does_not_flag_url_search_params_with_static_arg() {
        let names = run(r#"const params = new URLSearchParams("a=1");"#);
        assert!(names.is_empty(), "expected no matches, got {names:?}");
    }

    #[test]
    fn categorizes_sinks_and_inputs_correctly() {
        let allocator = Allocator::default();
        let source = r#"el.innerHTML = window.name;"#;
        let source_type = SourceType::unambiguous();
        let parser_ret = Parser::new(&allocator, source, source_type).parse();
        let semantic_ret = SemanticBuilder::new().build(&parser_ret.program);
        let ctx = AnalysisCtx::new(source, &semantic_ret.semantic, &allocator);
        let matches = detect_all(&ctx);

        let unsafe_html_match = matches
            .iter()
            .find(|m| m.detector == "unsafeHtml")
            .expect("unsafeHtml match");
        assert_eq!(unsafe_html_match.category, Category::Sink);

        let window_name_match = matches
            .iter()
            .find(|m| m.detector == "windowName")
            .expect("windowName match");
        assert_eq!(window_name_match.category, Category::Input);
    }
}
