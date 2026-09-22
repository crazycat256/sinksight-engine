use oxc_ast::ast::CallExpression;

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::is_safe_expression;
use crate::utils::is_property_named;

pub fn check<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if !is_insert_adjacent_html_call(call) {
        return;
    }
    let Some(html_arg) = call.arguments.get(1).and_then(|a| a.as_expression()) else {
        return;
    };

    if !is_safe_expression(ctx, html_arg, scope_id) {
        out.push(RawMatch {
            detector: "insertAdjacentHtml",
            category: Category::Sink,
            span: call.span,
        });
    }
}

fn is_insert_adjacent_html_call(call: &CallExpression) -> bool {
    let Some(member) = call.callee.get_member_expr() else {
        return false;
    };
    is_property_named(member, &["insertAdjacentHTML"])
}
