//! Port of `packages/vscode-ext/src/detectors/impl/documentWrite.ts`.

use oxc_ast::ast::CallExpression;

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::is_safe_expression;
use crate::utils::{is_document_object, is_property_named};

pub fn check<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if !is_document_write_call(call) {
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

fn is_document_write_call(call: &CallExpression) -> bool {
    let Some(member) = call.callee.get_member_expr() else {
        return false;
    };
    if !is_document_object(member.object()) {
        return false;
    }
    is_property_named(member, &["write", "writeln"])
}
