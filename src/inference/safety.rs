//! Port of `packages/vscode-ext/src/detectors/inference/safety.ts`.
//!
//! Simplification vs. the TS original: `allAssignmentsSafe` in TS first
//! tries a control-flow-sensitive backward scan (`isVariableSafeBackwards`)
//! over sibling statements/branches to narrow down the *specific* value a
//! variable holds at the use site, only falling back to "every possible
//! assignment must be safe" when that narrowing is inconclusive. Porting
//! that backward walk requires Babel-style "get previous sibling statement"
//! traversal, which has no cheap oxc equivalent (`AstNodes` has parent
//! pointers but no sibling index). We skip the narrowing step and always
//! use the "all assignments must be safe" fallback; this can never call an
//! actually-unsafe expression "safe" (the narrowing only ever *shortcuts*
//! the same fallback with a tighter, but consistent, answer), so it stays
//! sound at the cost of being slightly more conservative (more
//! false-"unsafe" verdicts) than the TS version in control-flow-narrowable
//! cases.

use std::collections::HashSet;

use oxc_ast::ast::*;
use oxc_ast::AstKind;

use crate::ctx::{AnalysisCtx, ScopeId};
use crate::inference::types::{is_safe_to_stringify, SafetyBehavior};
use crate::utils::{
    declarator_init, is_parameter_binding, is_variable_declarator_binding, resolve_identifier,
    resolve_iife_param, resolve_named_function_param,
};

use super::method_registry::{get_global_function, get_instance_method, get_static_method};
use super::type_inference::infer_type;

/// Returns `true` when `expr` is provably safe from injection.
pub fn is_safe_expression<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    is_safe_expression_inner(ctx, expr, scope_id, &mut HashSet::new())
}

fn is_safe_expression_inner<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
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
        if let Expression::Identifier(callee) = &new_expr.callee {
            // RegExp is not in SAFE_TO_STRINGIFY_TYPES because
            // `new RegExp(userInput).toString()` echoes the
            // attacker-controlled pattern; it's safe only when every
            // constructor argument is itself provably safe.
            if callee.name == "RegExp" {
                return new_expr.arguments.iter().all(|a| match a.as_expression() {
                    Some(e) => is_safe_expression_inner(ctx, e, scope_id, visited),
                    None => true,
                });
            }
            let ctor_type = infer_type(ctx, resolved, scope_id);
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

/// For a non-constant variable (e.g. `let`), checks whether every value it
/// can ever hold is safe: the initializer (if any) and every subsequent
/// plain assignment (`a = expr`). Returns `false` when the binding cannot
/// be found, is a parameter with no resolvable call-site argument, or any
/// value is not provably safe. Port of `allAssignmentsSafe` (see module
/// docs for the one intentional deviation: no backward flow narrowing).
fn all_assignments_safe<'a>(
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
    let Some(symbol_id) = scoping.find_binding(scope_id, name) else {
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
        return is_iife_body_safe(ctx, &f.body, inner_scope_id, visited);
    }
    if let Expression::FunctionExpression(f) = callee {
        let Some(body) = &f.body else { return false };
        let inner_scope_id = f.scope_id.get().unwrap_or(scope_id);
        return is_iife_body_safe(ctx, body, inner_scope_id, visited);
    }

    false
}

/// Very naive `return` statement collection for basic IIFE bodies: walks
/// nested blocks and `if` branches (matching the TS implementation's
/// `checkReturn`), treating an IIFE with no `return` at all as implicitly
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
        if let Some(desc) = get_static_method(obj_ident.name.as_str(), prop) {
            return evaluate_static_method_safety(ctx, desc.safety, call, scope_id, visited);
        }
    }

    // Instance methods: infer the receiver type (fresh visited set, mirrors
    // `infer_type`'s own top-level default), then look up the method.
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
