//! Conservative safety inference for expressions and assignments.
//!
//! Identifier uses are answered with intra-procedural reaching definitions
//! (see [`super::reaching`]): last write, if/else join, constant-condition
//! pruning, loops, switch, try/finally, IIFE execution, and return/break.
//! Uses of an outer binding inside a nested function stay flow-insensitive.

use std::collections::HashSet;

use oxc_ast::ast::*;
use oxc_ast::AstKind;

use crate::ctx::{AnalysisCtx, ScopeId};
use crate::inference::types::{is_safe_to_stringify, SafetyBehavior};
use crate::utils::{
    declarator_init, is_const_variable_binding, is_parameter_binding, is_unshadowed_global,
    is_variable_declarator_binding, resolve_identifier, resolve_iife_param,
    resolve_named_function_param, unwrap_expression,
};

use super::method_registry::{get_global_function, get_instance_method, get_static_method};
use super::reaching::identifier_use_is_safe;
use super::type_inference::infer_type;

/// Returns `true` when `expr` is provably safe from injection.
pub fn is_safe_expression<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    is_safe_expression_inner(ctx, expr, scope_id, &mut HashSet::new())
}

pub(crate) fn is_safe_expression_inner<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
    if let Expression::Identifier(ident) = expr {
        if let Some(safe) = identifier_use_is_safe(ctx, ident, scope_id, visited) {
            return safe;
        }
    }

    // Sequence/assignment must be peeled on the original node. `resolve_identifier`
    // would otherwise collapse `(a = "safe", a)` to the identifier `a` and fall
    // through to the flow-insensitive assignment scan.
    let unwrapped = unwrap_expression(expr);
    if let Expression::SequenceExpression(seq) = unwrapped {
        return seq
            .expressions
            .last()
            .is_some_and(|e| is_safe_expression_inner(ctx, e, scope_id, visited));
    }
    if let Expression::AssignmentExpression(assign) = unwrapped {
        return is_safe_expression_inner(ctx, &assign.right, scope_id, visited);
    }

    let resolved = resolve_identifier(ctx, expr, scope_id);

    // Template literals: safe only if every interpolation is safe. Must be
    // checked before the generic literal check since a `TemplateLiteral`
    // with no expressions is otherwise indistinguishable from a plain
    // string literal.
    if let Expression::TemplateLiteral(lit) = resolved {
        return lit
            .expressions
            .iter()
            .all(|e| is_safe_expression_inner(ctx, e, scope_id, visited));
    }

    if is_literal(resolved) {
        return true;
    }

    if let Expression::ObjectExpression(obj) = resolved {
        return obj.properties.iter().all(|prop| match prop {
            ObjectPropertyKind::SpreadProperty(spread) => {
                is_safe_expression_inner(ctx, &spread.argument, scope_id, visited)
            }
            ObjectPropertyKind::ObjectProperty(p) => match p.kind {
                PropertyKind::Get | PropertyKind::Set => false,
                PropertyKind::Init if p.method => true,
                PropertyKind::Init => is_safe_expression_inner(ctx, &p.value, scope_id, visited),
            },
        });
    }

    if let Expression::ArrayExpression(arr) = resolved {
        return arr.elements.iter().all(|el| match el {
            ArrayExpressionElement::SpreadElement(spread) => {
                is_safe_expression_inner(ctx, &spread.argument, scope_id, visited)
            }
            ArrayExpressionElement::Elision(_) => true,
            _ => match el.as_expression() {
                Some(e) => is_safe_expression_inner(ctx, e, scope_id, visited),
                None => true,
            },
        });
    }

    let ty = infer_type(ctx, resolved, scope_id);
    if is_safe_to_stringify(&ty) {
        return true;
    }

    if let Expression::BinaryExpression(bin) = resolved {
        if bin.operator == BinaryOperator::Addition {
            return is_safe_expression_inner(ctx, &bin.left, scope_id, visited)
                && is_safe_expression_inner(ctx, &bin.right, scope_id, visited);
        }
    }

    if let Expression::ConditionalExpression(cond) = resolved {
        return is_safe_expression_inner(ctx, &cond.consequent, scope_id, visited)
            && is_safe_expression_inner(ctx, &cond.alternate, scope_id, visited);
    }

    if let Expression::LogicalExpression(logical) = resolved {
        return is_safe_expression_inner(ctx, &logical.left, scope_id, visited)
            && is_safe_expression_inner(ctx, &logical.right, scope_id, visited);
    }

    if let Expression::SequenceExpression(seq) = resolved {
        if let Some(last) = seq.expressions.last() {
            return is_safe_expression_inner(ctx, last, scope_id, visited);
        }
    }

    if let Expression::AssignmentExpression(assign) = resolved {
        return is_safe_expression_inner(ctx, &assign.right, scope_id, visited);
    }

    if let Expression::CallExpression(call) = resolved {
        return is_call_safe(ctx, call, scope_id, visited);
    }

    if let Expression::NewExpression(new_expr) = resolved {
        if let Expression::Identifier(_) = &new_expr.callee {
            let ctor_type = infer_type(ctx, resolved, scope_id);
            // These types are not in SAFE_TO_STRINGIFY_TYPES because they echo
            // their constructor arguments: `new RegExp(x).toString()`,
            // `String(new Array(x))`, `"Error: " + x`, and `new URL("data:," + x)`
            // (an opaque path is not percent-encoded). They are safe exactly
            // when every argument is itself provably safe.
            if matches!(ctor_type.as_str(), "RegExp" | "Array" | "Error" | "URL") {
                return new_expr.arguments.iter().all(|a| match a.as_expression() {
                    Some(e) => is_safe_expression_inner(ctx, e, scope_id, visited),
                    None => true,
                });
            }
            return is_safe_to_stringify(&ctor_type);
        }
    }

    if let Expression::Identifier(ident) = resolved {
        return all_assignments_safe(ctx, ident.name.as_str(), scope_id, visited);
    }

    false
}

fn is_literal(expr: &Expression) -> bool {
    matches!(
        expr,
        Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::RegExpLiteral(_)
            | Expression::BigIntLiteral(_)
    )
}

// ---------------------------------------------------------------------------
// Non-constant variable safety
// ---------------------------------------------------------------------------

/// Flow-insensitive fallback: every initializer and plain assignment to
/// `name` must be safe. Used for nested-function uses of an outer binding,
/// where the closure may run at any time.
pub(crate) fn all_assignments_safe<'a>(
    ctx: &AnalysisCtx<'a>,
    name: &str,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
    // Prefixed key avoids collision with resolveIdentifier's visited
    // entries, which also use the bare variable name.
    let key = format!("$assign:{name}");
    if visited.contains(&key) {
        return false;
    }
    visited.insert(key);

    let scoping = ctx.semantic.scoping();
    let Some(symbol_id) = scoping.find_binding(scope_id, name.into()) else {
        return false;
    };

    // Parameters are inherently unsafe because we don't know what was
    // passed, unless we can resolve every possible call-site argument.
    if is_parameter_binding(ctx, symbol_id) {
        if let Some(resolution) = resolve_iife_param(ctx, symbol_id) {
            return match resolution.arg {
                Some(arg) => is_safe_expression_inner(ctx, arg, resolution.scope_id, visited),
                None => true, // missing argument -> undefined, safe
            };
        }
        if let Some(named) = resolve_named_function_param(ctx, symbol_id) {
            return named.args.iter().all(|arg| match arg {
                Some(e) => is_safe_expression_inner(ctx, e, named.scope_id, visited),
                None => true,
            });
        }
        return false;
    }

    if let Some(init) = declarator_init(ctx, symbol_id) {
        if !is_safe_expression_inner(ctx, init, scope_id, visited) {
            return false;
        }
    } else if !is_variable_declarator_binding(ctx, symbol_id) {
        // Not a var/let/const declarator (e.g. catch clause param, import,
        // hoisted function declaration) — assume unsafe.
        return false;
    }

    if is_const_variable_binding(ctx, symbol_id) {
        return true;
    }

    let nodes = ctx.semantic.nodes();
    for reference in scoping.get_resolved_references(symbol_id) {
        if !reference.is_write() {
            continue;
        }
        let parent_id = nodes.parent_id(reference.node_id());
        match nodes.kind(parent_id) {
            AstKind::AssignmentExpression(assign) if matches!(&assign.left, AssignmentTarget::AssignmentTargetIdentifier(l) if l.name == name) => {
                if !is_safe_expression_inner(ctx, &assign.right, scope_id, visited) {
                    return false;
                }
            }
            _ => {
                // Update expressions (`i++`), compound assignments, or any
                // other mutation pattern we can't prove safe.
                return false;
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Call expression safety
// ---------------------------------------------------------------------------

fn is_call_safe<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
    let callee = &call.callee;

    if let Expression::Identifier(ident) = callee {
        if !is_unshadowed_global(ctx, ident.name.as_str(), scope_id) {
            return false;
        }
        return is_global_call_safe(ctx, ident.name.as_str(), call, scope_id, visited);
    }

    if let Some(member) = callee.get_member_expr() {
        return is_method_call_safe(ctx, member, call, scope_id, visited);
    }

    // Immediately Invoked Function Expressions.
    if let Expression::ArrowFunctionExpression(f) = callee {
        let inner_scope_id = f.scope_id.get().unwrap_or(scope_id);
        if let Some(body_expr) = f.get_expression() {
            return is_safe_expression_inner(ctx, body_expr, inner_scope_id, visited);
        }
        return match &f.body {
            ArrowFunctionBody::FunctionBody(body) => {
                is_iife_body_safe(ctx, body, inner_scope_id, visited)
            }
            _ => false,
        };
    }
    if let Expression::FunctionExpression(f) = callee {
        let Some(body) = &f.body else { return false };
        let inner_scope_id = f.scope_id.get().unwrap_or(scope_id);
        return is_iife_body_safe(ctx, body, inner_scope_id, visited);
    }

    false
}

/// Very naive `return` statement collection for basic IIFE bodies: walks
/// nested blocks and `if` branches, treating an IIFE with no `return` as implicitly
/// returning `undefined` (safe).
fn is_iife_body_safe<'a>(
    ctx: &AnalysisCtx<'a>,
    body: &'a FunctionBody<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
    let mut all_safe = true;
    let mut has_return = false;
    for stmt in &body.statements {
        check_return(ctx, stmt, scope_id, visited, &mut has_return, &mut all_safe);
    }
    if has_return {
        all_safe
    } else {
        true
    }
}

fn check_return<'a>(
    ctx: &AnalysisCtx<'a>,
    stmt: &'a Statement<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
    has_return: &mut bool,
    all_safe: &mut bool,
) {
    match stmt {
        Statement::ReturnStatement(ret) => {
            *has_return = true;
            if let Some(arg) = &ret.argument {
                if !is_safe_expression_inner(ctx, arg, scope_id, visited) {
                    *all_safe = false;
                }
            }
        }
        Statement::BlockStatement(block) => {
            for inner in &block.body {
                check_return(ctx, inner, scope_id, visited, has_return, all_safe);
            }
        }
        Statement::IfStatement(if_stmt) => {
            check_return(
                ctx,
                &if_stmt.consequent,
                scope_id,
                visited,
                has_return,
                all_safe,
            );
            if let Some(alt) = &if_stmt.alternate {
                check_return(ctx, alt, scope_id, visited, has_return, all_safe);
            }
        }
        _ => {}
    }
}

fn is_global_call_safe<'a>(
    ctx: &AnalysisCtx<'a>,
    name: &str,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
    let Some(desc) = get_global_function(name) else {
        return false;
    };

    match desc.safety {
        SafetyBehavior::AlwaysSafe => true,
        SafetyBehavior::PreservesObject => {
            match call.arguments.first().and_then(|a| a.as_expression()) {
                Some(arg) => is_safe_expression_inner(ctx, arg, scope_id, visited),
                None => true, // e.g. String() with no args -> ""
            }
        }
        SafetyBehavior::PreservesAll => call.arguments.iter().all(|a| match a.as_expression() {
            Some(e) => is_safe_expression_inner(ctx, e, scope_id, visited),
            None => true,
        }),
        SafetyBehavior::Unsafe => false,
    }
}

fn is_method_call_safe<'a>(
    ctx: &AnalysisCtx<'a>,
    callee: &'a MemberExpression<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
    let Some(prop) = callee.static_property_name() else {
        return false;
    };
    let obj = callee.object();

    // Static methods: Math.floor(), JSON.stringify()... The receiver is a
    // well-known global, not a value we need to safety-check — only the
    // arguments matter.
    if let Expression::Identifier(obj_ident) = obj {
        if is_unshadowed_global(ctx, obj_ident.name.as_str(), scope_id) {
            if let Some(desc) = get_static_method(obj_ident.name.as_str(), prop) {
                return evaluate_static_method_safety(ctx, desc.safety, call, scope_id, visited);
            }
        }
    }

    // Infer the receiver independently before looking up the instance method.
    let owner_type = infer_type(ctx, obj, scope_id);
    if !owner_type.is_unknown() {
        if let Some(desc) = get_instance_method(owner_type.as_str(), prop) {
            return evaluate_method_safety(ctx, desc.safety, obj, call, scope_id, visited);
        }
    }

    // Fallback: universal methods like toString on a safe-to-stringify type,
    // or toString on an already-safe receiver (preserves safety).
    if prop == "toString" || prop == "toLocaleString" {
        if is_safe_to_stringify(&owner_type) {
            return true;
        }
        return is_safe_expression_inner(ctx, obj, scope_id, visited);
    }

    false
}

fn evaluate_method_safety<'a>(
    ctx: &AnalysisCtx<'a>,
    safety: SafetyBehavior,
    obj: &'a Expression<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
    match safety {
        SafetyBehavior::AlwaysSafe => true,
        SafetyBehavior::PreservesObject => is_safe_expression_inner(ctx, obj, scope_id, visited),
        SafetyBehavior::PreservesAll => {
            is_safe_expression_inner(ctx, obj, scope_id, visited)
                && call.arguments.iter().all(|a| match a.as_expression() {
                    Some(e) => is_safe_expression_inner(ctx, e, scope_id, visited),
                    None => true,
                })
        }
        SafetyBehavior::Unsafe => false,
    }
}

/// Safety evaluation for static methods (e.g. `Math.floor`, `JSON.stringify`).
/// The receiver is a well-known global — only the arguments need checking.
fn evaluate_static_method_safety<'a>(
    ctx: &AnalysisCtx<'a>,
    safety: SafetyBehavior,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
    match safety {
        SafetyBehavior::AlwaysSafe => true,
        SafetyBehavior::PreservesObject => {
            match call.arguments.first().and_then(|a| a.as_expression()) {
                Some(arg) => is_safe_expression_inner(ctx, arg, scope_id, visited),
                None => true,
            }
        }
        SafetyBehavior::PreservesAll => call.arguments.iter().all(|a| match a.as_expression() {
            Some(e) => is_safe_expression_inner(ctx, e, scope_id, visited),
            None => true,
        }),
        SafetyBehavior::Unsafe => false,
    }
}
