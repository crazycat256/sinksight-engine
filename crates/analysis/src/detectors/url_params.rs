//!
//! Detects URL-parsing constructs where the current page's URL is parsed,
//! giving the attacker access to query-string / fragment data:
//!
//!  - `new URLSearchParams(...)` with a non-static or absent argument
//!  - `new URL(...)` where the argument derives from `location.*` etc.
//!
//! Raw reads such as `location.search` or `document.URL` are intentionally
//! NOT flagged — only the explicit use in a parser is considered an input
//! source. Flagged as **input** source.

use oxc_ast::ast::{Argument, Expression, NewExpression};

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::utils::{is_browser_url_source, is_static_string_expression, resolve_identifier};

/// Whether the argument builds the parameters from scratch instead of parsing
/// something that could be the page URL: a constant string, or the record form
/// (`{ a: 1 }`) the constructor also accepts.
fn is_self_contained_init<'a>(
    ctx: &AnalysisCtx<'a>,
    arg: &'a Argument<'a>,
    scope_id: ScopeId,
) -> bool {
    let Some(expr) = arg.as_expression() else {
        return false;
    };
    is_static_string_expression(ctx, expr, scope_id)
        || matches!(
            resolve_identifier(ctx, expr, scope_id),
            Expression::ObjectExpression(_)
        )
}

pub fn check<'a>(
    ctx: &AnalysisCtx<'a>,
    new_expr: &'a NewExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    let Expression::Identifier(callee) = &new_expr.callee else {
        return;
    };
    let name = callee.name.as_str();

    if name == "URLSearchParams"
        && ctx
            .semantic
            .scoping()
            .find_binding(scope_id, "URLSearchParams".into())
            .is_none()
    {
        // `new URLSearchParams()` with no arguments creates an empty
        // object — it doesn't read `location.search` by default.
        if let Some(arg) = new_expr.arguments.first() {
            if !is_self_contained_init(ctx, arg, scope_id) {
                out.push(RawMatch {
                    detector: "urlParams",
                    category: Category::Input,
                    span: new_expr.span,
                });
            }
        }
        return;
    }

    if name == "URL"
        && ctx
            .semantic
            .scoping()
            .find_binding(scope_id, "URL".into())
            .is_none()
    {
        if let Some(arg) = new_expr.arguments.first().and_then(|a| a.as_expression()) {
            if is_browser_url_source(ctx, arg, scope_id) {
                out.push(RawMatch {
                    detector: "urlParams",
                    category: Category::Input,
                    span: new_expr.span,
                });
            }
        }
    }
}
