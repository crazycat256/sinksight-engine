use oxc_ast::ast::CallExpression;

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::is_safe_expression;
use crate::utils::{is_document_object, is_property_named, resolve_identifier};

pub fn check<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if !is_document_write_call(ctx, call, scope_id) {
        return;
    }
    let has_unsafe_arg = call.arguments.iter().any(|arg| {
        arg.as_expression()
            .is_some_and(|e| !is_safe_expression(ctx, e, scope_id))
    });

    if has_unsafe_arg {
        out.push(RawMatch {
            detector: "documentWrite",
            category: Category::Sink,
            span: call.span,
        });
    }
}

fn is_document_write_call<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
) -> bool {
    let Some(member) = call.callee.get_member_expr() else {
        return false;
    };
    if !is_property_named(member, &["write", "writeln"]) {
        return false;
    }
    let object = resolve_identifier(ctx, member.object(), scope_id);
    is_document_object(object)
}
