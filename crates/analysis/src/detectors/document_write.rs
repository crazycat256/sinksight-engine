use oxc_ast::ast::{Argument, ArrayExpressionElement, CallExpression, Expression};

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
    if has_unsafe_write_payload(ctx, call, scope_id) {
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
    if is_property_named(member, &["write", "writeln"]) {
        let object = resolve_identifier(ctx, member.object(), scope_id);
        return is_document_object(object);
    }
    if is_property_named(member, &["call", "apply"]) {
        return is_document_write_function(ctx, member.object(), scope_id);
    }
    false
}

fn is_document_write_function<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    let resolved = resolve_identifier(ctx, expr, scope_id);
    let Some(member) = resolved.get_member_expr() else {
        return false;
    };
    is_property_named(member, &["write", "writeln"])
        && is_document_object(resolve_identifier(ctx, member.object(), scope_id))
}

fn has_unsafe_write_payload<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
) -> bool {
    let Some(member) = call.callee.get_member_expr() else {
        return write_args_unsafe(ctx, call.arguments.iter(), scope_id);
    };
    if is_property_named(member, &["call"]) {
        return write_args_unsafe(ctx, call.arguments.iter().skip(1), scope_id);
    }
    if is_property_named(member, &["apply"]) {
        let Some(arg_list) = call.arguments.get(1).and_then(|a| a.as_expression()) else {
            return false;
        };
        let resolved = resolve_identifier(ctx, arg_list, scope_id);
        if let Expression::ArrayExpression(arr) = resolved {
            return arr.elements.iter().any(|el| match el {
                ArrayExpressionElement::SpreadElement(spread) => {
                    !is_safe_expression(ctx, &spread.argument, scope_id)
                }
                ArrayExpressionElement::Elision(_) => false,
                _ => el
                    .as_expression()
                    .is_some_and(|e| !is_safe_expression(ctx, e, scope_id)),
            });
        }
        return !is_safe_expression(ctx, arg_list, scope_id);
    }
    write_args_unsafe(ctx, call.arguments.iter(), scope_id)
}

fn write_args_unsafe<'a, I>(ctx: &AnalysisCtx<'a>, args: I, scope_id: ScopeId) -> bool
where
    I: IntoIterator<Item = &'a Argument<'a>>,
{
    args.into_iter().any(|arg| {
        arg.as_expression()
            .is_some_and(|e| !is_safe_expression(ctx, e, scope_id))
    })
}
