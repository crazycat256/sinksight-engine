//! Port of `packages/vscode-ext/src/detectors/impl/javascriptLinks.ts`.

use std::collections::HashSet;

use oxc_ast::ast::*;

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::{infer_element_type, infer_type};
use crate::utils::{
    assignment_target_object, assignment_target_property_name, has_safe_url_prefix,
    is_browser_url_source, is_property_named, is_static_string_expression, matches_callee_names,
    resolve_identifier,
};

const LINK_PROPERTIES: &[&str] = &["location", "href", "src"];
const LINK_ATTRIBUTE_NAMES: &[&str] = &["href", "src", "xlink:href"];
const LOCATION_METHODS: &[&str] = &["assign", "replace"];
const OPEN_METHODS: &[&str] = &["open"];

pub fn check_assignment<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a AssignmentExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    let right = &expr.right;

    let is_link_assignment = if let Some(prop_name) = assignment_target_property_name(&expr.left) {
        LINK_PROPERTIES.contains(&prop_name)
    } else if let AssignmentTarget::AssignmentTargetIdentifier(id) = &expr.left {
        LINK_PROPERTIES.contains(&id.name.as_str())
            && ctx
                .semantic
                .scoping()
                .find_binding(scope_id, &id.name)
                .is_none()
    } else {
        false
    };

    if !is_link_assignment || !is_suspicious_value(ctx, right, scope_id) {
        return;
    }

    if is_self_link_assignment(&expr.left, right) {
        return;
    }

    // Check if we are assigning to an image `src`.
    if let Some(prop_name) = assignment_target_property_name(&expr.left) {
        if prop_name == "src" {
            if let Some(obj) = assignment_target_object(&expr.left) {
                if infer_element_type(ctx, obj, scope_id).as_deref() == Some("img") {
                    return;
                }
            }
        }
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
    let callee = &call.callee;
    let first_arg = call.arguments.first();

    if is_set_attribute_call(callee) {
        if is_link_attribute_argument(first_arg) {
            if let Some(second_arg) = call.arguments.get(1).and_then(|a| a.as_expression()) {
                if is_suspicious_value(ctx, second_arg, scope_id) {
                    let is_safe_image_src = matches!(
                        first_arg.and_then(|a| a.as_expression()),
                        Some(Expression::StringLiteral(lit)) if lit.value == "src"
                    ) && callee.get_member_expr().is_some_and(|m| {
                        infer_element_type(ctx, m.object(), scope_id).as_deref() == Some("img")
                    });

                    if !is_safe_image_src {
                        out.push(RawMatch {
                            detector: "javascriptLinks",
                            category: Category::Sink,
                            span: call.span,
                        });
                    }
                }
            }
        }
        return;
    }

    let Some(first_arg_expr) = first_arg.and_then(|a| a.as_expression()) else {
        return;
    };

    if is_location_method_call(ctx, callee, scope_id)
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

    // 1. `open(...)` called without an object — assume it's `window.open`
    // unless it's a local variable.
    if let Expression::Identifier(ident) = callee {
        return ctx
            .semantic
            .scoping()
            .find_binding(scope_id, &ident.name)
            .is_none();
    }

    let Some(member) = callee.get_member_expr() else {
        return false;
    };
    let obj = member.object();

    // 2. `window.open(...)`
    let is_window_open = matches!(obj, Expression::Identifier(id) if id.name == "window")
        || infer_type(ctx, obj, scope_id) == *"Window";
    if is_window_open {
        return true;
    }

    // 3. `x.open(url, targetOrFeatures)` — check if the 2nd/3rd argument
    // looks like a `window.open` argument.
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

fn is_set_attribute_call(callee: &Expression) -> bool {
    callee
        .get_member_expr()
        .is_some_and(|m| is_property_named(m, &["setAttribute"]))
}

fn is_link_attribute_argument(arg: Option<&Argument>) -> bool {
    matches!(arg, Some(Argument::StringLiteral(lit)) if LINK_ATTRIBUTE_NAMES.contains(&lit.value.as_str()))
}

fn is_location_object<'a>(
    ctx: &AnalysisCtx<'a>,
    node: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    if infer_type(ctx, node, scope_id) == *"Location" {
        return true;
    }
    // Recurse through member chains (e.g. `frames[0].location`).
    if let Some(member) = node.get_member_expr() {
        return is_location_object(ctx, member.object(), scope_id);
    }
    false
}

fn is_self_link_assignment(left: &AssignmentTarget, right: &Expression) -> bool {
    if let AssignmentTarget::AssignmentTargetIdentifier(l) = left {
        if let Expression::Identifier(r) = right {
            return l.name == r.name;
        }
        return false;
    }

    let Some(left_prop) = assignment_target_property_name(left) else {
        return false;
    };
    let Some(left_obj) = assignment_target_object(left) else {
        return false;
    };
    let Some(right_member) = right.get_member_expr() else {
        return false;
    };
    let Some(right_prop) = right_member.static_property_name() else {
        return false;
    };

    left_prop == right_prop && expr_equivalent(left_obj, right_member.object())
}

/// Coarse approximation of Babel's `t.isNodesEquivalent` for the two shapes
/// this detector cares about: plain identifiers and member-expression
/// chains built from identifiers / `this`.
fn expr_equivalent(a: &Expression, b: &Expression) -> bool {
    match (a, b) {
        (Expression::Identifier(x), Expression::Identifier(y)) => x.name == y.name,
        (Expression::ThisExpression(_), Expression::ThisExpression(_)) => true,
        _ => match (a.get_member_expr(), b.get_member_expr()) {
            (Some(ma), Some(mb)) => match (ma.static_property_name(), mb.static_property_name()) {
                (Some(pa), Some(pb)) => pa == pb && expr_equivalent(ma.object(), mb.object()),
                _ => false,
            },
            _ => false,
        },
    }
}

/// A value is suspicious if it is NOT a static string expression (i.e. it
/// could contain user input) AND we can't otherwise prove it's not a
/// `javascript:` URI.
fn is_suspicious_value<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    if is_static_string_expression(ctx, expr, scope_id) {
        // Static: contains no user input. Even if it says
        // "javascript:alert(1)", the payload is fixed — not an injection.
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

    // Call expressions like `url.toString()`.
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

    // Member reads like `url.href`.
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
