//! Port of `packages/vscode-ext/src/detectors/impl/unsafeHtml.ts`.
//!
//! Detects assignment to `.innerHTML` / `.outerHTML` / `.srcdoc` with a
//! value that isn't provably safe from injection.

use oxc_ast::ast::AssignmentExpression;

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::is_safe_expression;
use crate::utils::assignment_target_property_name;

const HTML_PROPERTIES: &[&str] = &["innerHTML", "outerHTML", "srcdoc"];

pub fn check<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a AssignmentExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    let Some(prop_name) = assignment_target_property_name(&expr.left) else {
        return;
    };
    if !HTML_PROPERTIES.contains(&prop_name) {
        return;
    }

    if !is_safe_expression(ctx, &expr.right, scope_id) {
        out.push(RawMatch {
            detector: "unsafeHtml",
            category: Category::Sink,
            span: expr.span,
        });
    }
}
