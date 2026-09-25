use std::collections::HashSet;

use oxc_ast::ast::*;

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::{attribute_sink_kind, infer_element_type, infer_type, AttributeSinkKind};
use crate::utils::{
    assignment_target_object, has_safe_url_prefix, is_browser_url_source, is_property_named,
    is_static_string_expression, matches_callee_names, resolve_identifier,
    resolved_assignment_property_name,
};

use super::{is_self_property_assignment, set_attribute_write};

const LOCATION_METHODS: &[&str] = &["assign", "replace"];
const OPEN_METHODS: &[&str] = &["open"];

pub fn check_assignment<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a AssignmentExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if is_location_navigation_assignment(ctx, expr, scope_id) {
        if is_suspicious_value(ctx, &expr.right, scope_id)
            && !is_self_property_assignment(&expr.left, &expr.right)
        {
            out.push(RawMatch {
                detector: "javascriptLinks",
                category: Category::Sink,
                span: expr.span,
            });
        }
        return;
    }

    let Some(prop_name) = resolved_assignment_property_name(ctx, &expr.left, scope_id) else {
        return;
    };
    let Some(obj) = assignment_target_object(&expr.left) else {
        return;
    };
    let tag = infer_element_type(ctx, obj, scope_id);
    if attribute_sink_kind(tag.as_deref(), &prop_name) != Some(AttributeSinkKind::JavascriptUri) {
        return;
    }
    if !is_suspicious_value(ctx, &expr.right, scope_id) {
        return;
    }
    if is_self_property_assignment(&expr.left, &expr.right) {
        return;
    }

    out.push(RawMatch {
        detector: "javascriptLinks",
        category: Category::Sink,
        span: expr.span,
    });
}

pub fn check_call<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if let Some((object, name, value)) = set_attribute_write(call) {
        let tag = infer_element_type(ctx, object, scope_id);
        if attribute_sink_kind(tag.as_deref(), name) == Some(AttributeSinkKind::JavascriptUri)
            && is_suspicious_value(ctx, value, scope_id)
        {
            out.push(RawMatch {
                detector: "javascriptLinks",
                category: Category::Sink,
                span: call.span,
            });
        }
        return;
    }

    let Some(first_arg_expr) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };

    if is_location_method_call(ctx, &call.callee, scope_id)
        && is_suspicious_value(ctx, first_arg_expr, scope_id)
    {
        out.push(RawMatch {
            detector: "javascriptLinks",
            category: Category::Sink,
            span: call.span,
        });
        return;
    }

    if is_open_call(ctx, call, scope_id) && is_suspicious_value(ctx, first_arg_expr, scope_id) {
        out.push(RawMatch {
            detector: "javascriptLinks",
            category: Category::Sink,
            span: call.span,
        });
    }
}

fn is_location_navigation_assignment<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a AssignmentExpression<'a>,
    scope_id: ScopeId,
) -> bool {
    if let AssignmentTarget::AssignmentTargetIdentifier(id) = &expr.left {
        return id.name == "location"
            && ctx
                .semantic
                .scoping()
                .find_binding(scope_id, "location".into())
                .is_none();
    }
    if resolved_assignment_property_name(ctx, &expr.left, scope_id).as_deref() != Some("location") {
        return false;
    }
    true
}

fn is_location_method_call<'a>(
    ctx: &AnalysisCtx<'a>,
    callee: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    let Some(member) = callee.get_member_expr() else {
        return false;
    };
    if !is_property_named(member, LOCATION_METHODS) {
        return false;
    }
    is_location_object(ctx, member.object(), scope_id)
}

fn is_open_call<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
) -> bool {
    let callee = &call.callee;
    if !matches_callee_names(callee, OPEN_METHODS) {
        return false;
    }

    if let Expression::Identifier(ident) = callee {
        return ctx
            .semantic
            .scoping()
            .find_binding(scope_id, ident.name)
            .is_none();
    }

    let Some(member) = callee.get_member_expr() else {
        return false;
    };
    let obj = member.object();

    let is_window_open = matches!(obj, Expression::Identifier(id) if id.name == "window")
        || infer_type(ctx, obj, scope_id) == *"Window";
    if is_window_open {
        return true;
    }

    if let Some(Expression::StringLiteral(second)) =
        call.arguments.get(1).and_then(|a| a.as_expression())
    {
        let val = second.value.to_lowercase();
        if matches!(val.as_str(), "_blank" | "_self" | "_parent" | "_top") {
            return true;
        }
    }
    if let Some(Expression::StringLiteral(third)) =
        call.arguments.get(2).and_then(|a| a.as_expression())
    {
        let val = third.value.to_lowercase();
        if val.contains("width=")
            || val.contains("height=")
            || val.contains("noopener")
            || val.contains("noreferrer")
        {
            return true;
        }
    }

    false
}

fn is_location_object<'a>(
    ctx: &AnalysisCtx<'a>,
    node: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    if infer_type(ctx, node, scope_id) == *"Location" {
        return true;
    }
    if let Some(member) = node.get_member_expr() {
        return is_location_object(ctx, member.object(), scope_id);
    }
    false
}

fn is_suspicious_value<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    if is_static_string_expression(ctx, expr, scope_id) {
        return false;
    }
    if has_safe_url_prefix(ctx, expr, scope_id) {
        return false;
    }
    if is_guaranteed_not_javascript_scheme(ctx, expr, scope_id, &mut HashSet::new()) {
        return false;
    }
    true
}

fn is_guaranteed_not_javascript_scheme<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<usize>,
) -> bool {
    let key = std::ptr::from_ref(expr) as usize;
    if !visited.insert(key) {
        return false;
    }

    if has_safe_url_prefix(ctx, expr, scope_id) {
        return true;
    }
    if is_browser_url_source(ctx, expr, scope_id) {
        return true;
    }

    let resolved = resolve_identifier(ctx, expr, scope_id);
    if matches!(resolved, Expression::UnaryExpression(_)) {
        return true;
    }
    if !std::ptr::eq(resolved, expr)
        && is_guaranteed_not_javascript_scheme(ctx, resolved, scope_id, visited)
    {
        return true;
    }

    if let Expression::NewExpression(new_expr) = resolved {
        if let Expression::Identifier(callee) = &new_expr.callee {
            if callee.name == "URL" {
                if let Some(arg1) = new_expr.arguments.first().and_then(|a| a.as_expression()) {
                    return is_guaranteed_not_javascript_scheme(ctx, arg1, scope_id, visited);
                }
            }
        }
    }

    if let Expression::CallExpression(call) = resolved {
        if let Some(member) = call.callee.get_member_expr() {
            if is_property_named(member, &["toString"])
                && infer_type(ctx, member.object(), scope_id) == *"URL"
                && is_guaranteed_not_javascript_scheme(ctx, member.object(), scope_id, visited)
            {
                return true;
            }
        }
    }

    if let Some(member) = resolved.get_member_expr() {
        if is_property_named(member, &["href", "toString"])
            && infer_type(ctx, member.object(), scope_id) == *"URL"
            && is_guaranteed_not_javascript_scheme(ctx, member.object(), scope_id, visited)
        {
            return true;
        }
    }

    false
}
