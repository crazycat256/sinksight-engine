//!
//! Detects reads of `window.name`, which is attacker-controlled across
//! navigations: a malicious page can set `window.name` before navigating
//! the victim to the target page.
//!
//! Patterns detected:
//!  - `window.name` (read access)
//!  - `self.name` / `globalThis.name` (aliases for `window.name`)
//!  - `name` (bare global — only when no local binding shadows it)
//!
//! We do NOT flag writes (`window.name = ...`) since those are not inputs.
//! Flagged as **input** source.

use oxc_ast::ast::{AssignmentTarget, Expression, IdentifierReference};
use oxc_ast::AstKind;
use oxc_semantic::NodeId;

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::utils::assignment_target_span;

use super::member_parts;

pub fn check_member<'a>(
    ctx: &AnalysisCtx<'a>,
    kind: AstKind<'a>,
    node_id: NodeId,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    let Some((prop_name, object, span)) = member_parts(kind) else {
        return;
    };
    if prop_name != "name" {
        return;
    }
    let Expression::Identifier(obj_ident) = object else {
        return;
    };
    let obj_name = obj_ident.name.as_str();
    if !matches!(obj_name, "window" | "self" | "globalThis") {
        return;
    }
    if ctx
        .semantic
        .scoping()
        .find_binding(scope_id, obj_name.into())
        .is_some()
    {
        return;
    }

    if is_write_position(ctx, node_id, span) {
        return;
    }

    out.push(RawMatch {
        detector: "windowName",
        category: Category::Input,
        span,
    });
}

pub fn check_identifier<'a>(
    ctx: &AnalysisCtx<'a>,
    ident: &'a IdentifierReference<'a>,
    node_id: NodeId,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if ident.name != "name" {
        return;
    }
    // Only flag if there is no local/closer binding shadowing the global `name`.
    if ctx
        .semantic
        .scoping()
        .find_binding(scope_id, "name".into())
        .is_some()
    {
        return;
    }

    if is_write_position(ctx, node_id, ident.span) {
        return;
    }

    out.push(RawMatch {
        detector: "windowName",
        category: Category::Input,
        span: ident.span,
    });
}

fn is_write_position(ctx: &AnalysisCtx, node_id: NodeId, span: oxc_span::Span) -> bool {
    let nodes = ctx.semantic.nodes();
    let AstKind::AssignmentExpression(assign) = nodes.kind(nodes.parent_id(node_id)) else {
        return false;
    };
    assignment_target_span(&assign.left) == Some(span)
        || matches!(&assign.left, AssignmentTarget::AssignmentTargetIdentifier(id) if id.span == span)
}
