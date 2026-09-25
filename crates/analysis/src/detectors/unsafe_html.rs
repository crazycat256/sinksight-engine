//! Detects HTML injection: `.innerHTML` / `.outerHTML`, `srcdoc`, and
//! `setAttribute` of `on*` / `srcdoc` with a value that isn't provably safe.

use oxc_ast::ast::{AssignmentExpression, CallExpression};

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::{
    attribute_sink_kind, could_be_attribute_sink, infer_element_type, is_safe_expression,
    AttributeSinkKind,
};
use crate::utils::{assignment_target_object, resolved_assignment_property_name};

use super::set_attribute_write;

const HTML_PROPERTIES: &[&str] = &["innerHTML", "outerHTML"];

pub fn check<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a AssignmentExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    let Some(prop_name) = resolved_assignment_property_name(ctx, &expr.left, scope_id) else {
        return;
    };
    if HTML_PROPERTIES.contains(&prop_name.as_str()) {
        if !is_safe_expression(ctx, &expr.right, scope_id) {
            out.push(RawMatch {
                detector: "unsafeHtml",
                category: Category::Sink,
                span: expr.span,
            });
        }
        return;
    }

    if !could_be_attribute_sink(&prop_name, AttributeSinkKind::HtmlInjection) {
        return;
    }
    let Some(obj) = assignment_target_object(&expr.left) else {
        return;
    };
    let tag = infer_element_type(ctx, obj, scope_id);
    if attribute_sink_kind(tag.as_deref(), &prop_name) != Some(AttributeSinkKind::HtmlInjection) {
        return;
    }
    if prop_name.to_lowercase().starts_with("on") {
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

pub fn check_call<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    let Some((object, name, value)) = set_attribute_write(call) else {
        return;
    };
    if !could_be_attribute_sink(name, AttributeSinkKind::HtmlInjection) {
        return;
    }
    let tag = infer_element_type(ctx, object, scope_id);
    if attribute_sink_kind(tag.as_deref(), name) != Some(AttributeSinkKind::HtmlInjection) {
        return;
    }
    if !is_safe_expression(ctx, value, scope_id) {
        out.push(RawMatch {
            detector: "unsafeHtml",
            category: Category::Sink,
            span: call.span,
        });
    }
}
