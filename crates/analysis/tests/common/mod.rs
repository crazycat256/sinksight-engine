//! Shared helpers for the integration test suite.

#![allow(dead_code)]

use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Program, Statement};
use oxc_ast::AstKind;
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;

use sinksight_analysis::ctx::{Category, ScopeId};
use sinksight_analysis::{detect_all, AnalysisCtx};

/// Parses `source` (with the same parser options `analyze`/`detect_all` use),
/// runs semantic analysis, builds an [`AnalysisCtx`], and hands both it and
/// the parsed [`Program`] to `f`. Panics on any parse/semantic error.
pub fn with_ctx_and_program<R>(source: &str, f: impl FnOnce(&AnalysisCtx, &Program) -> R) -> R {
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
        "parse errors for {source:?}: {:?}",
        parser_ret.errors
    );

    let semantic_ret = SemanticBuilder::new().build(&parser_ret.program);
    assert!(
        semantic_ret.errors.is_empty(),
        "semantic errors for {source:?}: {:?}",
        semantic_ret.errors
    );

    let ctx = AnalysisCtx::new(source, &semantic_ret.semantic, &allocator);
    f(&ctx, &parser_ret.program)
}

/// Same as [`with_ctx_and_program`] but only exposes the [`AnalysisCtx`],
/// for callers (most detector tests) that only need `detect_all`.
pub fn with_ctx<R>(source: &str, f: impl FnOnce(&AnalysisCtx) -> R) -> R {
    with_ctx_and_program(source, |ctx, _program| f(ctx))
}

/// Runs `detect_all` and returns the sorted list of detector names that
/// fired.
pub fn detector_names(source: &str) -> Vec<&'static str> {
    with_ctx(source, |ctx| {
        let mut names: Vec<&'static str> =
            detect_all(ctx).into_iter().map(|m| m.detector).collect();
        names.sort_unstable();
        names
    })
}

/// Counts matches produced by a single named detector.
pub fn count_detector(source: &str, detector: &str) -> usize {
    with_ctx(source, |ctx| {
        detect_all(ctx)
            .into_iter()
            .filter(|m| m.detector == detector)
            .count()
    })
}

/// Returns the [`Category`] of the first match produced by `detector`, if
/// any.
pub fn category_for(source: &str, detector: &str) -> Option<Category> {
    with_ctx(source, |ctx| {
        detect_all(ctx)
            .into_iter()
            .find(|m| m.detector == detector)
            .map(|m| m.category)
    })
}

/// Total number of findings across every detector.
pub fn total_matches(source: &str) -> usize {
    with_ctx(source, |ctx| detect_all(ctx).len())
}

/// Finds the last top-level statement (which must be an `ExpressionStatement`)
/// and runs `f` with the analysis ctx, that statement's expression, and the
/// scope active at that point.
pub fn with_last_expr<R>(
    source: &str,
    f: impl FnOnce(&AnalysisCtx, &Expression, ScopeId) -> R,
) -> R {
    with_ctx_and_program(source, |ctx, program| {
        let last_stmt = program
            .body
            .last()
            .unwrap_or_else(|| panic!("no statements in {source:?}"));
        let Statement::ExpressionStatement(expr_stmt) = last_stmt else {
            panic!("last statement must be an expression statement, got {last_stmt:?}");
        };
        let scope_id = scope_id_for_expression_statement(ctx, expr_stmt.span);
        f(ctx, &expr_stmt.expression, scope_id)
    })
}

fn scope_id_for_expression_statement(ctx: &AnalysisCtx, span: oxc_span::Span) -> ScopeId {
    for node in ctx.semantic.nodes().iter() {
        if let AstKind::ExpressionStatement(stmt) = node.kind() {
            if stmt.span == span {
                return node.scope_id();
            }
        }
    }
    panic!("could not locate scope for expression statement at {span:?}");
}

/// Finds the first *usage* (not declaration) of `var_name` anywhere in the
/// program — i.e. the first `IdentifierReference` with that name — and hands
/// `f` the analysis ctx, the enclosing expression that reference is part of,
/// and the scope active at that point.
///
/// Oxc separates declarations (`BindingIdentifier`) from usages
/// (`IdentifierReference`) into distinct node kinds, but the target of an
/// assignment is an `IdentifierReference` too, so write-only references are
/// filtered out explicitly.
///
/// Only the small set of parent shapes exercised by these tests
/// (bare `x;` expression statements and `var y = x;` declarators) are
/// supported; anything else panics with a clear message.
pub fn with_identifier_usage<R>(
    source: &str,
    var_name: &str,
    f: impl FnOnce(&AnalysisCtx, &Expression, ScopeId) -> R,
) -> R {
    with_ctx(source, |ctx| {
        let nodes = ctx.semantic.nodes();
        let mut target: Option<(oxc_span::Span, ScopeId)> = None;
        for node in nodes.iter() {
            if let AstKind::IdentifierReference(ident) = node.kind() {
                let is_read = ident
                    .reference_id
                    .get()
                    .is_some_and(|rid| ctx.semantic.scoping().get_reference(rid).is_read());
                if ident.name.as_str() == var_name && is_read {
                    target = Some((ident.span, node.scope_id()));
                    break;
                }
            }
        }
        let Some((ident_span, scope_id)) = target else {
            panic!("no usage of `{var_name}` found in {source:?}");
        };

        for node in nodes.iter() {
            if let AstKind::IdentifierReference(ident) = node.kind() {
                if ident.span == ident_span {
                    let parent = nodes.kind(nodes.parent_id(node.id()));
                    let expr = match parent {
                        AstKind::ExpressionStatement(stmt) => &stmt.expression,
                        AstKind::VariableDeclarator(decl) => decl
                            .init
                            .as_ref()
                            .unwrap_or_else(|| panic!("declarator for `{var_name}` has no initializer")),
                        AstKind::ReturnStatement(ret) => ret
                            .argument
                            .as_ref()
                            .unwrap_or_else(|| panic!("return statement for `{var_name}` has no argument")),
                        other => panic!(
                            "unsupported parent node kind for identifier usage `{var_name}`: {other:?}"
                        ),
                    };
                    return f(ctx, expr, scope_id);
                }
            }
        }
        unreachable!("identifier span located above must be found again here");
    })
}
