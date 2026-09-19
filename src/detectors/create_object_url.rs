use std::collections::HashSet;
use std::sync::LazyLock;

use oxc_ast::ast::{CallExpression, Expression, NewExpression, ObjectPropertyKind};

use crate::ctx::{AnalysisCtx, Category, RawMatch, ScopeId};
use crate::inference::is_safe_expression;
use crate::utils::{
    get_static_key_name, is_property_named, is_window_like, resolve_identifier, resolve_to_object,
};

/// MIME types that can lead to script execution when loaded via an object
/// URL. A Blob with one of these types can render HTML/SVG which may
/// contain inline scripts or event-handler attributes, resulting in XSS.
static EXECUTABLE_MIME_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "text/html",
        "text/xml",
        "application/xhtml+xml",
        "application/xml",
        "image/svg+xml",
    ])
});

pub fn check<'a>(
    ctx: &AnalysisCtx<'a>,
    call: &'a CallExpression<'a>,
    scope_id: ScopeId,
    out: &mut Vec<RawMatch>,
) {
    if !is_create_object_url_call(ctx, &call.callee, scope_id) {
        return;
    }

    let Some(blob_arg) = call.arguments.first() else {
        // No argument — still suspicious (runtime error, but pattern is wrong).
        out.push(RawMatch {
            detector: "createObjectUrl",
            category: Category::Sink,
            span: call.span,
        });
        return;
    };
    let Some(blob_arg) = blob_arg.as_expression() else {
        out.push(RawMatch {
            detector: "createObjectUrl",
            category: Category::Sink,
            span: call.span,
        });
        return;
    };

    let resolved = resolve_identifier(ctx, blob_arg, scope_id);

    if let Expression::NewExpression(new_expr) = resolved {
        if let Expression::Identifier(callee_ident) = &new_expr.callee {
            let ctor_name = callee_ident.name.as_str();
            if ctor_name == "Blob" || ctor_name == "File" {
                if is_blob_content_safe(ctx, new_expr, scope_id) {
                    return;
                }

                let mime_type = extract_blob_mime_type(ctx, new_expr, ctor_name, scope_id);
                if let Some(mime_type) = mime_type {
                    if !is_executable_mime(&mime_type) {
                        return;
                    }
                }

                out.push(RawMatch {
                    detector: "createObjectUrl",
                    category: Category::Sink,
                    span: call.span,
                });
                return;
            }
        }
    }

    // Cannot resolve to a known Blob/File constructor — flag as suspicious.
    out.push(RawMatch {
        detector: "createObjectUrl",
        category: Category::Sink,
        span: call.span,
    });
}

fn is_executable_mime(mime: &str) -> bool {
    let essence = mime
        .split(';')
        .next()
        .unwrap_or(mime)
        .trim()
        .to_ascii_lowercase();
    EXECUTABLE_MIME_TYPES.contains(essence.as_str())
}

fn is_create_object_url_call<'a>(
    ctx: &AnalysisCtx<'a>,
    callee: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    let Some(member) = callee.get_member_expr() else {
        return false;
    };
    if !is_property_named(member, &["createObjectURL"]) {
        return false;
    }
    is_url_constructor(ctx, member.object(), scope_id)
}

fn is_url_constructor<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    let resolved = resolve_identifier(ctx, expr, scope_id);
    if let Expression::Identifier(id) = resolved {
        return id.name == "URL";
    }
    let Some(member) = resolved.get_member_expr() else {
        return false;
    };
    if !is_property_named(member, &["URL"]) {
        return false;
    }
    let object = resolve_identifier(ctx, member.object(), scope_id);
    is_window_like(ctx, object, scope_id)
}

fn is_blob_content_safe<'a>(
    ctx: &AnalysisCtx<'a>,
    new_expr: &'a NewExpression<'a>,
    scope_id: ScopeId,
) -> bool {
    let Some(parts_arg) = new_expr.arguments.first() else {
        // No parts — `new Blob()` produces an empty blob, which is safe.
        return true;
    };
    match parts_arg.as_expression() {
        Some(e) => is_safe_expression(ctx, e, scope_id),
        None => false,
    }
}

fn extract_blob_mime_type<'a>(
    ctx: &AnalysisCtx<'a>,
    new_expr: &'a NewExpression<'a>,
    ctor_name: &str,
    scope_id: ScopeId,
) -> Option<String> {
    // Blob(parts, options) — options is at index 1.
    // File(parts, name, options) — options is at index 2.
    let options_index = if ctor_name == "File" { 2 } else { 1 };
    let options_arg = new_expr.arguments.get(options_index)?.as_expression()?;
    extract_type_property(ctx, options_arg, scope_id)
}

fn extract_type_property<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> Option<String> {
    let obj = resolve_to_object(ctx, expr, scope_id)?;

    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(op) = prop else {
            continue;
        };
        let Some(key_name) = get_static_key_name(op.computed, &op.key) else {
            continue;
        };
        if key_name != "type" {
            continue;
        }

        let val = resolve_identifier(ctx, &op.value, scope_id);
        if let Expression::StringLiteral(lit) = val {
            return Some(lit.value.to_string());
        }
        if let Expression::TemplateLiteral(lit) = val {
            if lit.quasis.len() == 1 {
                // `cooked`, not `raw`: an escape such as `text/\u0068tml`
                // denotes an executable MIME type just like `text/html` does.
                return lit.quasis.first()?.value.cooked.map(|a| a.to_string());
            }
        }
        // Non-static `type` value — cannot determine.
        return None;
    }

    // No `type` property found.
    None
}
