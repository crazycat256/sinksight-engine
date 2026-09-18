//! Port of `packages/vscode-ext/src/detectors/impl/unsafeTimers.ts`.

use oxc_ast::ast::{CallExpression, Expression};

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::{infer_type, is_safe_expression};
use crate::utils::{matches_callee_names, resolve_identifier};

const TIMER_NAMES: &[&str] = &["setTimeout", "setInterval"];

pub fn check<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if !is_timer_callee(ctx, &call.callee, scope_id) {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };

    // If it's an arrow function or function expression, it's safe.
    if matches!(
        first_arg,
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
    ) {
        return;
    }

    // For timers, we only care if the argument is a string (or could be
    // one). If it's definitely a function, it's safe. If it's unknown, we
    // assume it's a function to avoid massive false positives, UNLESS it's
    // string-typed (e.g. concatenation).
    let ty = infer_type(ctx, first_arg, scope_id);
    if ty == *"string" && !is_safe_expression(ctx, first_arg, scope_id) {
        out.push(RawMatch {
            detector: "unsafeTimers",
            category: Category::Sink,
            span: call.span,
        });
    }
}

fn is_timer_callee<'a>(
    ctx: &AnalysisCtx<'a>,
    callee: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    if matches_callee_names(callee, TIMER_NAMES) {
        return true;
    }
    let resolved = resolve_identifier(ctx, callee, scope_id);
    if !std::ptr::eq(resolved, callee) {
        return matches_callee_names(resolved, TIMER_NAMES);
    }
    false
}
