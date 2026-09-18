//! Port of `packages/vscode-ext/src/detectors/inference/elements.ts`.

use std::collections::HashSet;
use std::sync::LazyLock;

use oxc_ast::ast::Expression;

use crate::ctx::{AnalysisCtx, ScopeId};
use crate::utils::resolve_identifier;

use super::types::ElementTag;

/// Tries to infer the HTML tag name of an element expression. Returns the
/// lowercase tag (e.g. `"img"`, `"div"`) or `None` if unknown.
pub fn infer_element_type<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> Option<ElementTag> {
    let resolved = resolve_identifier(ctx, expr, scope_id);

    if let Expression::NewExpression(new_expr) = resolved {
        if let Expression::Identifier(callee) = &new_expr.callee {
            match callee.name.as_str() {
                "Image" => return Some("img".to_string()),
                "Audio" => return Some("audio".to_string()),
                "Option" => return Some("option".to_string()),
                _ => {}
            }
        }
    }

    if let Expression::CallExpression(call) = resolved {
        if let Some(member) = call.callee.get_member_expr() {
            let resolved_object = resolve_identifier(ctx, member.object(), scope_id);
            let is_document =
                matches!(resolved_object, Expression::Identifier(id) if id.name == "document");
            if is_document {
                let prop_name = (!member.is_computed())
                    .then(|| member.static_property_name())
                    .flatten();
                let tag_arg = match prop_name {
                    Some("createElement") => call.arguments.first(),
                    Some("createElementNS") => call.arguments.get(1),
                    _ => None,
                };
                if let Some(tag_arg) = tag_arg.and_then(|a| a.as_expression()) {
                    let target = resolve_identifier(ctx, tag_arg, scope_id);
                    if let Expression::StringLiteral(lit) = target {
                        return Some(lit.value.to_lowercase());
                    }
                }
            }
        }
    }

    None
}

/// For each attribute name, the set of element tags where that attribute can
/// lead to code execution or resource loading from an arbitrary URL when set
/// to a user-controlled value. `on*` event handlers are handled separately
/// (always dangerous).
static DANGEROUS_ATTR_ELEMENTS: LazyLock<Vec<(&'static str, HashSet<&'static str>)>> =
    LazyLock::new(|| {
        vec![
            (
                "src",
                HashSet::from(["script", "iframe", "embed", "object", "frame"]),
            ),
            ("href", HashSet::from(["a", "area", "base", "link"])),
            ("data", HashSet::from(["object"])),
            ("action", HashSet::from(["form"])),
            ("formaction", HashSet::from(["button", "input"])),
            ("srcdoc", HashSet::from(["iframe"])),
            ("ping", HashSet::from(["a", "area"])),
        ]
    });

static ALL_DANGEROUS_ATTR_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    DANGEROUS_ATTR_ELEMENTS
        .iter()
        .map(|(name, _)| *name)
        .collect()
});

/// Checks whether setting `attribute_name` to an arbitrary value is
/// dangerous on the given element type. If `element_tag` is `None`, we
/// cannot determine the element type, so we conservatively assume the worst
/// case.
pub fn is_dangerous_attribute(element_tag: Option<&str>, attribute_name: &str) -> bool {
    let lower_attr = attribute_name.to_lowercase();

    if lower_attr.starts_with("on") {
        return true;
    }

    let Some(element_tag) = element_tag else {
        return ALL_DANGEROUS_ATTR_NAMES.contains(lower_attr.as_str());
    };

    let lower_tag = element_tag.to_lowercase();
    match DANGEROUS_ATTR_ELEMENTS
        .iter()
        .find(|(name, _)| *name == lower_attr)
    {
        Some((_, tags)) => tags.contains(lower_tag.as_str()),
        None => false,
    }
}
