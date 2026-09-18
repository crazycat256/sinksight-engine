use oxc_ast::ast::{Argument, CallExpression, Expression, NewExpression};

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::is_safe_expression;
use crate::utils::matches_callee_names;

const FUNCTION_NAMES: &[&str] = &["Function"];

pub fn check_new<'a>(
    ctx: &AnalysisCtx<'a>,
    new_expr: &'a NewExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if is_function_reference(&new_expr.callee)
        && has_dynamic_function_arguments(ctx, &new_expr.arguments, scope_id)
    {
        out.push(RawMatch {
            detector: "functionConstructor",
            category: Category::Sink,
            span: new_expr.span,
        });
    }
}

pub fn check_call<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if is_function_reference(&call.callee)
        && has_dynamic_function_arguments(ctx, &call.arguments, scope_id)
    {
        out.push(RawMatch {
            detector: "functionConstructor",
            category: Category::Sink,
            span: call.span,
        });
    }
}

fn is_function_reference(callee: &Expression) -> bool {
    matches_callee_names(callee, FUNCTION_NAMES)
}

fn has_dynamic_function_arguments<'a>(
    ctx: &AnalysisCtx<'a>,
    args: &'a [Argument<'a>],
    scope_id: ScopeId,
) -> bool {
    let Some(body_arg) = args.last() else {
        return false;
    };
    match body_arg.as_expression() {
        Some(e) => !is_safe_expression(ctx, e, scope_id),
        None => true,
    }
}
