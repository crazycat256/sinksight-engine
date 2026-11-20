//!
//! Detects window `message` event listeners as attacker-controlled input sources.

use oxc_ast::ast::*;

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::infer_type;
use crate::utils::{
    assignment_target_object, is_property_named, resolved_assignment_property_name,
};

pub fn check_call<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    match &call.callee {
        Expression::Identifier(ident) => {
            if ident.name != "addEventListener" {
                return;
            }
            if ctx
                .semantic
                .scoping()
                .find_binding(scope_id, "addEventListener".into())
                .is_some()
            {
                return;
            }
        }
        callee => {
            let Some(member) = callee.get_member_expr() else {
                return;
            };
            if !is_property_named(member, &["addEventListener"]) {
                return;
            }
            if is_proven_non_window_message_target(ctx, member.object(), scope_id) {
                return;
            }
        }
    }

    let Some(Expression::StringLiteral(event_name)) =
        call.arguments.first().and_then(|a| a.as_expression())
    else {
        return;
    };
    if event_name.value != "message" {
        return;
    }

    let Some(_) = call.arguments.get(1).and_then(|a| a.as_expression()) else {
        return;
    };

    out.push(RawMatch {
        detector: "postMessage",
        category: Category::Input,
        span: call.span,
    });
}

pub fn check_assignment<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a AssignmentExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if let Some(prop_name) = resolved_assignment_property_name(ctx, &expr.left, scope_id) {
        if prop_name != "onmessage" {
            return;
        }
        let Some(obj) = assignment_target_object(&expr.left) else {
            return;
        };
        if is_proven_non_window_message_target(ctx, obj, scope_id) {
            return;
        }
    } else if let AssignmentTarget::AssignmentTargetIdentifier(id) = &expr.left {
        if id.name != "onmessage" {
            return;
        }
        if ctx
            .semantic
            .scoping()
            .find_binding(scope_id, "onmessage".into())
            .is_some()
        {
            return;
        }
    } else {
        return;
    }

    // Skip non-function values (null, undefined, literals, etc.) — these
    // can't be handlers at all, so they're not a `postMessage` sink.
    if is_definitely_not_a_handler(&expr.right) {
        return;
    }

    out.push(RawMatch {
        detector: "postMessage",
        category: Category::Input,
        span: expr.span,
    });
}

fn is_definitely_not_a_handler(expr: &Expression) -> bool {
    matches!(
        expr,
        Expression::NullLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
    ) || matches!(expr, Expression::Identifier(id) if id.name == "undefined")
}

const EXCLUDED_MESSAGE_TARGET_TYPES: &[&str] =
    &["Worker", "WebSocket", "BroadcastChannel", "MessagePort"];

fn is_proven_non_window_message_target<'a>(
    ctx: &AnalysisCtx<'a>,
    target: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    let ty = infer_type(ctx, target, scope_id);
    EXCLUDED_MESSAGE_TARGET_TYPES.contains(&ty.as_str())
}
