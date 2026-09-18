//! Port of `packages/vscode-ext/src/detectors/impl/urlParams.ts`.
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
use crate::utils::is_browser_url_source;

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
            .find_binding(scope_id, "URLSearchParams")
            .is_none()
    {
        // `new URLSearchParams()` with no arguments creates an empty
        // object — it doesn't read `location.search` by default.
        if let Some(arg) = new_expr.arguments.first() {
            if !matches!(arg, Argument::StringLiteral(_)) {
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
            .find_binding(scope_id, "URL")
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
