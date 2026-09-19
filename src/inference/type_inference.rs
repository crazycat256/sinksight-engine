use std::collections::HashSet;

use oxc_ast::ast::*;
use oxc_ast::AstKind;
use oxc_span::GetSpan;

use crate::ctx::AnalysisCtx;
use crate::ctx::ScopeId;
use crate::utils::{is_unshadowed_global, resolve_identifier};

use super::elements::infer_element_type;
use super::method_registry::{
    get_constructor_type, get_discriminant_property, get_global_function, get_instance_method,
    get_instance_property, get_static_method,
};
use super::types::InferredType;

const MAX_INFER_DEPTH: u32 = 30;

/// Infer the runtime type of `expr`. Returns `"unknown"` when no
/// determination can be made.
pub fn infer_type<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> InferredType {
    infer_type_inner(ctx, expr, scope_id, &mut HashSet::new(), 0)
}

fn infer_type_inner<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
    depth: u32,
) -> InferredType {
    if depth > MAX_INFER_DEPTH {
        return InferredType::UNKNOWN;
    }
    let resolved = resolve_identifier(ctx, expr, scope_id);

    match resolved {
        Expression::NumericLiteral(_) => return InferredType::NUMBER,
        Expression::StringLiteral(_) => return InferredType::STRING,
        Expression::BooleanLiteral(_) => return InferredType::BOOLEAN,
        Expression::RegExpLiteral(_) => return InferredType::REGEXP,
        Expression::NullLiteral(_) => return InferredType::NULL,
        Expression::BigIntLiteral(_) => return InferredType::BIGINT,
        Expression::ArrayExpression(_) => return InferredType::ARRAY,
        Expression::ObjectExpression(_) => return InferredType::OBJECT,
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
            return InferredType::FUNCTION;
        }
        _ => {}
    }

    if let Expression::Identifier(ident) = resolved {
        let name = ident.name.as_str();
        let scoping = ctx.semantic.scoping();
        let has_binding = scoping.find_binding(scope_id, name).is_some();
        if name == "undefined" {
            return InferredType::UNDEFINED;
        }
        if (name == "window" || name == "globalThis") && !has_binding {
            return InferredType::WINDOW;
        }
        if name == "document" && !has_binding {
            return InferredType::DOCUMENT;
        }
        if name == "location" && !has_binding {
            return InferredType::LOCATION;
        }
    }

    if let Expression::NewExpression(new_expr) = resolved {
        if let Expression::Identifier(callee) = &new_expr.callee {
            if let Some(ctor_type) = get_constructor_type(callee.name.as_str()) {
                return ctor_type;
            }
            return InferredType::named(callee.name.to_string());
        }
        if let Some(member) = new_expr.callee.get_member_expr() {
            if let Some(prop) = member.static_property_name() {
                return InferredType::named(prop.to_string());
            }
        }
    }

    if let Expression::CallExpression(call) = resolved {
        let ty = infer_call_type(ctx, call, scope_id, visited, depth);
        if !ty.is_unknown() {
            return ty;
        }
    }

    if let Expression::BinaryExpression(bin) = resolved {
        return infer_binary_type(ctx, bin, scope_id, visited, depth);
    }

    if let Expression::UnaryExpression(unary) = resolved {
        match unary.operator {
            UnaryOperator::UnaryPlus | UnaryOperator::UnaryNegation | UnaryOperator::BitwiseNot => {
                return InferredType::NUMBER;
            }
            UnaryOperator::LogicalNot => return InferredType::BOOLEAN,
            UnaryOperator::Typeof => return InferredType::STRING,
            UnaryOperator::Void => return InferredType::UNDEFINED,
            _ => {}
        }
    }

    if matches!(resolved, Expression::UpdateExpression(_)) {
        return InferredType::NUMBER;
    }

    if let Some(member) = resolved.get_member_expr() {
        if let Some(prop_name) = (!member.is_computed())
            .then(|| member.static_property_name())
            .flatten()
        {
            if prop_name == "length" {
                let owner_type =
                    infer_type_inner(ctx, member.object(), scope_id, visited, depth + 1);
                const NUMERIC_LENGTH_TYPES: &[&str] =
                    &["string", "Array", "HTMLElement", "Function"];
                if NUMERIC_LENGTH_TYPES.contains(&owner_type.as_str()) {
                    return InferredType::NUMBER;
                }
            } else if prop_name == "size" {
                let owner_type =
                    infer_type_inner(ctx, member.object(), scope_id, visited, depth + 1);
                if owner_type == *"Map" || owner_type == *"Set" {
                    return InferredType::NUMBER;
                }
            } else if prop_name == "location" {
                return InferredType::LOCATION;
            } else if prop_name == "window" || prop_name == "defaultView" {
                return InferredType::WINDOW;
            } else if prop_name == "document" {
                return InferredType::DOCUMENT;
            } else {
                // A fresh visited set prevents an unrelated inference path
                // fresh Set for the owner-type lookup so it doesn't share
                // cycle-detection state with the outer identifier.
                let owner_type = infer_type_inner(
                    ctx,
                    member.object(),
                    scope_id,
                    &mut HashSet::new(),
                    depth + 1,
                );
                if !owner_type.is_unknown() {
                    if let Some(prop_type) = get_instance_property(owner_type.as_str(), prop_name) {
                        return prop_type;
                    }
                }
            }
        }
    }

    if matches!(resolved, Expression::TemplateLiteral(_)) {
        return InferredType::STRING;
    }

    if let Expression::ConditionalExpression(cond) = resolved {
        let consequent = infer_type_inner(ctx, &cond.consequent, scope_id, visited, depth + 1);
        let alternate = infer_type_inner(ctx, &cond.alternate, scope_id, visited, depth + 1);
        if consequent == alternate {
            return consequent;
        }
        return InferredType::UNKNOWN;
    }

    if let Expression::SequenceExpression(seq) = resolved {
        if let Some(last) = seq.expressions.last() {
            return infer_type_inner(ctx, last, scope_id, visited, depth + 1);
        }
    }

    if let Expression::LogicalExpression(logical) = resolved {
        let left_type = infer_type_inner(ctx, &logical.left, scope_id, visited, depth + 1);
        let right_type = infer_type_inner(ctx, &logical.right, scope_id, visited, depth + 1);
        if left_type == right_type {
            return left_type;
        }
    }

    if let Expression::AssignmentExpression(assign) = resolved {
        return infer_type_inner(ctx, &assign.right, scope_id, visited, depth + 1);
    }

    if infer_element_type(ctx, resolved, scope_id).is_some() {
        return InferredType::HTML_ELEMENT;
    }

    if let Expression::Identifier(ident) = expr {
        let usage_type = infer_type_from_property_usages(ctx, ident.name.as_str(), scope_id);
        if !usage_type.is_unknown() {
            return usage_type;
        }
    }

    InferredType::UNKNOWN
}

fn infer_call_type<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
    depth: u32,
) -> InferredType {
    let callee = &call.callee;

    if let Expression::Identifier(ident) = callee {
        if is_unshadowed_global(ctx, ident.name.as_str(), scope_id) {
            if ident.name == "Date" {
                return InferredType::STRING;
            }
            if let Some(desc) = get_global_function(ident.name.as_str()) {
                return desc.return_type.clone();
            }
        }
    }

    if let Some(member) = callee.get_member_expr() {
        if !member.is_computed() {
            let Some(method_name) = member.static_property_name() else {
                return InferredType::UNKNOWN;
            };
            let obj = member.object();

            if let Expression::Identifier(obj_ident) = obj {
                if is_unshadowed_global(ctx, obj_ident.name.as_str(), scope_id) {
                    if let Some(desc) = get_static_method(obj_ident.name.as_str(), method_name) {
                        return desc.return_type.clone();
                    }
                }
            }

            let owner_type = infer_type_inner(ctx, obj, scope_id, visited, depth + 1);
            if !owner_type.is_unknown() {
                if let Some(desc) = get_instance_method(owner_type.as_str(), method_name) {
                    return desc.return_type.clone();
                }
            }
            return infer_universal_method_return(method_name);
        }

        if let Some(method_name) = member.static_property_name() {
            let obj = member.object();
            let owner_type = infer_type_inner(ctx, obj, scope_id, visited, depth + 1);
            if !owner_type.is_unknown() {
                if let Some(desc) = get_instance_method(owner_type.as_str(), method_name) {
                    return desc.return_type.clone();
                }
            }
        }
    }

    InferredType::UNKNOWN
}

fn infer_universal_method_return(method_name: &str) -> InferredType {
    match method_name {
        "toString" | "toLocaleString" => InferredType::STRING,
        _ => InferredType::UNKNOWN,
    }
}

fn infer_binary_type<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a BinaryExpression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
    depth: u32,
) -> InferredType {
    let operator = expr.operator;

    const ARITHMETIC_BITWISE: &[BinaryOperator] = &[
        BinaryOperator::Subtraction,
        BinaryOperator::Multiplication,
        BinaryOperator::Division,
        BinaryOperator::Remainder,
        BinaryOperator::Exponential,
        BinaryOperator::BitwiseAnd,
        BinaryOperator::BitwiseOR,
        BinaryOperator::BitwiseXOR,
        BinaryOperator::ShiftLeft,
        BinaryOperator::ShiftRight,
        BinaryOperator::ShiftRightZeroFill,
    ];
    if ARITHMETIC_BITWISE.contains(&operator) {
        return InferredType::NUMBER;
    }

    if operator.is_equality()
        || operator.is_compare()
        || matches!(operator, BinaryOperator::In | BinaryOperator::Instanceof)
    {
        return InferredType::BOOLEAN;
    }

    if operator == BinaryOperator::Addition {
        let left_type = infer_type_inner(ctx, &expr.left, scope_id, visited, depth + 1);
        let right_type = infer_type_inner(ctx, &expr.right, scope_id, visited, depth + 1);
        if left_type == *"string" || right_type == *"string" {
            return InferredType::STRING;
        }
        if left_type == *"number" && right_type == *"number" {
            return InferredType::NUMBER;
        }
        if left_type == *"bigint" && right_type == *"bigint" {
            return InferredType::BIGINT;
        }
    }

    InferredType::UNKNOWN
}

/// Discriminant-property-based fallback: scan every reference to `name`
/// within its declared scope for member accesses whose property name is
/// registered as virtually unique to a single built-in class.
fn infer_type_from_property_usages(
    ctx: &AnalysisCtx,
    name: &str,
    scope_id: ScopeId,
) -> InferredType {
    let scoping = ctx.semantic.scoping();
    let nodes = ctx.semantic.nodes();
    let Some(symbol_id) = scoping.find_binding(scope_id, name) else {
        return InferredType::UNKNOWN;
    };

    for reference in scoping.get_resolved_references(symbol_id) {
        let ref_node_id = reference.node_id();
        let ref_span = nodes.kind(ref_node_id).span();
        let parent_id = nodes.parent_id(ref_node_id);
        // Only plain, non-computed
        // `name.property` accesses count (computed accesses like `name[x]`
        // are skipped, since `x` isn't necessarily a static property name).
        let prop_name = match nodes.kind(parent_id) {
            AstKind::StaticMemberExpression(m) if m.object.span() == ref_span => {
                Some(m.property.name.as_str())
            }
            _ => None,
        };
        if let Some(prop_name) = prop_name {
            if let Some(discriminant_type) = get_discriminant_property(prop_name) {
                return discriminant_type;
            }
        }
    }

    InferredType::UNKNOWN
}
