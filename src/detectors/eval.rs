//! Port of `packages/vscode-ext/src/detectors/impl/eval.ts`.

use oxc_ast::ast::{CallExpression, Expression};

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::is_safe_expression;
use crate::utils::{matches_callee_names, resolve_identifier};

pub fn check<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if !is_eval_callee(ctx, &call.callee, scope_id) || call.arguments.is_empty() {
        return;
    }
    let Some(first_arg) = call.arguments[0].as_expression() else {
        return;
    };
    if !is_safe_expression(ctx, first_arg, scope_id) {
        out.push(RawMatch {
            detector: "eval",
            category: Category::Sink,
            span: call.span,
        });
    }
}

fn is_eval_callee<'a>(
    ctx: &AnalysisCtx<'a>,
    callee: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    if matches_callee_names(callee, &["eval"]) {
        return true;
    }
    let resolved = resolve_identifier(ctx, callee, scope_id);
    if !std::ptr::eq(resolved, callee) {
        return matches_callee_names(resolved, &["eval"]);
    }
    false
}
