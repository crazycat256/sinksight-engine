//!
//! Detects `postMessage` event listeners where the handler does NOT verify
//! `event.origin` / `event.source`. An unchecked `message` listener is an
//! attacker-controlled input because any window can postMessage to the
//! target. Flagged as **input** source.

use oxc_ast::ast::*;
use oxc_ast::AstKind;
use oxc_semantic::SymbolId;

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::infer_type;
use crate::utils::{
    assignment_target_object, declarator_init, is_property_named, resolved_assignment_property_name,
};

pub fn check_call<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    match &call.callee {
        Expression::Identifier(ident) => {
            if ident.name != "addEventListener" {
                return;
            }
            if ctx
                .semantic
                .scoping()
                .find_binding(scope_id, "addEventListener")
                .is_some()
            {
                return;
            }
        }
        callee => {
            let Some(member) = callee.get_member_expr() else {
                return;
            };
            if !is_property_named(member, &["addEventListener"]) {
                return;
            }
            if is_proven_non_window_message_target(ctx, member.object(), scope_id) {
                return;
            }
        }
    }

    let Some(Expression::StringLiteral(event_name)) =
        call.arguments.first().and_then(|a| a.as_expression())
    else {
        return;
    };
    if event_name.value != "message" {
        return;
    }

    let Some(handler) = call.arguments.get(1).and_then(|a| a.as_expression()) else {
        return;
    };

    if is_unchecked_handler(ctx, handler, scope_id) {
        out.push(RawMatch {
            detector: "postMessage",
            category: Category::Input,
            span: call.span,
        });
    }
}

pub fn check_assignment<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a AssignmentExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if let Some(prop_name) = resolved_assignment_property_name(ctx, &expr.left, scope_id) {
        if prop_name != "onmessage" {
            return;
        }
        let Some(obj) = assignment_target_object(&expr.left) else {
            return;
        };
        if is_proven_non_window_message_target(ctx, obj, scope_id) {
            return;
        }
    } else if let AssignmentTarget::AssignmentTargetIdentifier(id) = &expr.left {
        if id.name != "onmessage" {
            return;
        }
        if ctx
            .semantic
            .scoping()
            .find_binding(scope_id, "onmessage")
            .is_some()
        {
            return;
        }
    } else {
        return;
    }

    // Skip non-function values (null, undefined, literals, etc.) — these
    // can't be handlers at all, so they're not a `postMessage` sink.
    if is_definitely_not_a_handler(&expr.right) {
        return;
    }

    if is_unchecked_handler(ctx, &expr.right, scope_id) {
        out.push(RawMatch {
            detector: "postMessage",
            category: Category::Input,
            span: expr.span,
        });
    }
}

fn is_definitely_not_a_handler(expr: &Expression) -> bool {
    matches!(
        expr,
        Expression::NullLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
    ) || matches!(expr, Expression::Identifier(id) if id.name == "undefined")
}

const EXCLUDED_MESSAGE_TARGET_TYPES: &[&str] =
    &["Worker", "WebSocket", "BroadcastChannel", "MessagePort"];

fn is_proven_non_window_message_target<'a>(
    ctx: &AnalysisCtx<'a>,
    target: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    let ty = infer_type(ctx, target, scope_id);
    EXCLUDED_MESSAGE_TARGET_TYPES.contains(&ty.as_str())
}

/// Returns `true` if the handler does NOT appear to check message origin.
fn is_unchecked_handler<'a>(
    ctx: &AnalysisCtx<'a>,
    handler: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    let Some(body) = extract_handler_body(ctx, handler, scope_id) else {
        return true;
    };
    let Some(event_param) = extract_event_param(ctx, handler, scope_id) else {
        return true;
    };
    !body_checks_origin(&body, event_param)
}

enum HandlerBody<'a> {
    Block(&'a FunctionBody<'a>),
    Expr(&'a Expression<'a>),
}

/// Resolves a symbol bound by either a named `function` declaration or a
/// `var`/`let`/`const` declarator initialized with a function/arrow, to the
/// `Function` node backing a `function` declaration (if any).
fn resolve_named_function<'a>(
    ctx: &AnalysisCtx<'a>,
    symbol_id: SymbolId,
) -> Option<&'a Function<'a>> {
    let nodes = ctx.semantic.nodes();
    let decl_id = ctx.semantic.scoping().symbol_declaration(symbol_id);
    match nodes.kind(decl_id) {
        AstKind::Function(f) => Some(f),
        AstKind::BindingIdentifier(_) => match nodes.kind(nodes.parent_id(decl_id)) {
            AstKind::Function(f) => Some(f),
            _ => None,
        },
        _ => None,
    }
}

fn arrow_or_function_body<'a>(expr: &'a Expression<'a>) -> Option<HandlerBody<'a>> {
    match expr {
        Expression::FunctionExpression(f) => f.body.as_deref().map(HandlerBody::Block),
        Expression::ArrowFunctionExpression(f) => match f.get_expression() {
            Some(body_expr) => Some(HandlerBody::Expr(body_expr)),
            None => Some(HandlerBody::Block(&f.body)),
        },
        _ => None,
    }
}

fn extract_handler_body<'a>(
    ctx: &AnalysisCtx<'a>,
    handler: &'a Expression<'a>,
    scope_id: ScopeId,
) -> Option<HandlerBody<'a>> {
    if let Some(body) = arrow_or_function_body(handler) {
        return Some(body);
    }
    let Expression::Identifier(ident) = handler else {
        return None;
    };
    let symbol_id = ctx.semantic.scoping().find_binding(scope_id, &ident.name)?;
    if let Some(f) = resolve_named_function(ctx, symbol_id) {
        return f.body.as_deref().map(HandlerBody::Block);
    }
    arrow_or_function_body(declarator_init(ctx, symbol_id)?)
}

fn first_param_name<'a>(params: &'a FormalParameters<'a>) -> Option<&'a str> {
    let first = params.items.first()?;
    match &first.pattern {
        BindingPattern::BindingIdentifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}

fn arrow_or_function_param<'a>(expr: &'a Expression<'a>) -> Option<&'a str> {
    match expr {
        Expression::FunctionExpression(f) => first_param_name(&f.params),
        Expression::ArrowFunctionExpression(f) => first_param_name(&f.params),
        _ => None,
    }
}

fn extract_event_param<'a>(
    ctx: &AnalysisCtx<'a>,
    handler: &'a Expression<'a>,
    scope_id: ScopeId,
) -> Option<&'a str> {
    if let Some(name) = arrow_or_function_param(handler) {
        return Some(name);
    }
    let Expression::Identifier(ident) = handler else {
        return None;
    };
    let symbol_id = ctx.semantic.scoping().find_binding(scope_id, &ident.name)?;
    if let Some(f) = resolve_named_function(ctx, symbol_id) {
        return first_param_name(&f.params);
    }
    arrow_or_function_param(declarator_init(ctx, symbol_id)?)
}

fn body_checks_origin(body: &HandlerBody, event_param: &str) -> bool {
    match body {
        HandlerBody::Block(fb) => fb
            .statements
            .iter()
            .any(|s| stmt_references_origin(s, event_param)),
        HandlerBody::Expr(e) => expr_references_origin(e, event_param),
    }
}

/// Checks statement-shaped branches for origin validation.
/// (the ones that only make sense for statements, not expressions).
fn stmt_references_origin(stmt: &Statement, event_param: &str) -> bool {
    match stmt {
        Statement::IfStatement(if_stmt) => {
            expr_references_origin(&if_stmt.test, event_param)
                || stmt_references_origin(&if_stmt.consequent, event_param)
                || if_stmt
                    .alternate
                    .as_ref()
                    .is_some_and(|alt| stmt_references_origin(alt, event_param))
        }
        Statement::SwitchStatement(sw) => {
            expression_references_origin(&sw.discriminant, event_param)
        }
        Statement::BlockStatement(block) => block
            .body
            .iter()
            .any(|s| stmt_references_origin(s, event_param)),
        Statement::ExpressionStatement(e) => expr_references_origin(&e.expression, event_param),
        Statement::ReturnStatement(r) => r
            .argument
            .as_ref()
            .is_some_and(|a| expr_references_origin(a, event_param)),
        Statement::VariableDeclaration(decl) => decl.declarations.iter().any(|d| {
            d.init
                .as_ref()
                .is_some_and(|i| expr_references_origin(i, event_param))
        }),
        _ => false,
    }
}

/// Checks expression-shaped nodes for origin validation:
/// the ternary-test shortcut, then the generic `expressionReferencesOrigin`
/// checks (which already subsume comparison-operator and
/// "call expression" shortcuts).
fn expr_references_origin(expr: &Expression, event_param: &str) -> bool {
    if let Expression::ConditionalExpression(cond) = expr {
        if expr_references_origin(&cond.test, event_param) {
            return true;
        }
    }
    expression_references_origin(expr, event_param)
}

/// Checks whether an expression is
/// `<eventParam>.origin` / `<eventParam>.source`, or contains such an
/// access through a logical/binary/call/unary wrapper.
fn expression_references_origin(expr: &Expression, event_param: &str) -> bool {
    if let Some(member) = expr.get_member_expr() {
        if matches!(member.object(), Expression::Identifier(id) if id.name == event_param)
            && is_property_named(member, &["origin", "source"])
        {
            return true;
        }
        if member.object().get_member_expr().is_some()
            && expression_references_origin(member.object(), event_param)
        {
            return true;
        }
    }

    match expr {
        Expression::LogicalExpression(l) => {
            expression_references_origin(&l.left, event_param)
                || expression_references_origin(&l.right, event_param)
        }
        Expression::BinaryExpression(b) => {
            expression_references_origin(&b.left, event_param)
                || expression_references_origin(&b.right, event_param)
        }
        Expression::CallExpression(call) => {
            call.arguments.iter().any(|a| {
                a.as_expression()
                    .is_some_and(|e| expression_references_origin(e, event_param))
            }) || call
                .callee
                .get_member_expr()
                .is_some_and(|m| expression_references_origin(m.object(), event_param))
        }
        Expression::UnaryExpression(u) => expression_references_origin(&u.argument, event_param),
        _ => false,
    }
}
