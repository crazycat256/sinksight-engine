//! Identifier resolution and shared AST helpers.

use std::collections::HashSet;

use oxc_ast::ast::*;
use oxc_ast::AstKind;
use oxc_semantic::{Reference, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::ctx::{AnalysisCtx, ScopeId};

/// Identifiers in this list are never treated as implicit-global candidates.
pub const KNOWN_GLOBALS: &[&str] = &[
    "window",
    "document",
    "console",
    "Math",
    "Object",
    "Array",
    "String",
    "Number",
    "Boolean",
    "RegExp",
    "setTimeout",
    "setInterval",
    "clearTimeout",
    "clearInterval",
    "eval",
    "undefined",
    "NaN",
    "Infinity",
    "global",
    "globalThis",
    "process",
    "module",
    "exports",
    "require",
    "HTMLElement",
    "Element",
    "Node",
    "Event",
    "JSON",
    "Promise",
    "Date",
    "Symbol",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
];

const MAX_RESOLVE_DEPTH: u32 = 30;

// ---------------------------------------------------------------------------
// Simple structural helpers (no scope needed)
// ---------------------------------------------------------------------------

/// Returns the static name of an object literal property key.
pub fn get_static_key_name<'a>(computed: bool, key: &PropertyKey<'a>) -> Option<&'a str> {
    if !computed {
        if let PropertyKey::StaticIdentifier(id) = key {
            return Some(id.name.as_str());
        }
    }
    if let PropertyKey::StringLiteral(lit) = key {
        return Some(lit.value.as_str());
    }
    None
}

/// Checks whether a member has one of the supplied static property names.
/// Oxc's [`MemberExpression::static_property_name`]
/// already unifies the "static identifier" and "computed string literal"
/// cases for us.
pub fn is_property_named(member: &MemberExpression, targets: &[&str]) -> bool {
    member
        .static_property_name()
        .is_some_and(|name| targets.contains(&name))
}

/// Same as [`is_property_named`] but for an `AssignmentTarget`'s member-like
/// variants (`a.b = x`, `a[b] = x`, `a.#b = x`), which oxc represents with a
/// separate enum from `Expression`'s member variants.
pub fn assignment_target_property_name<'a>(target: &'a AssignmentTarget<'a>) -> Option<&'a str> {
    match target {
        AssignmentTarget::StaticMemberExpression(m) => Some(m.property.name.as_str()),
        AssignmentTarget::ComputedMemberExpression(m) => {
            m.static_property_name().map(|a| a.as_str())
        }
        _ => None,
    }
}

/// Like [`assignment_target_property_name`], but also folds `el[key]` when
/// `key` is a constant string or a concatenation of constant strings.
pub fn resolved_assignment_property_name<'a>(
    ctx: &AnalysisCtx<'a>,
    target: &'a AssignmentTarget<'a>,
    scope_id: ScopeId,
) -> Option<String> {
    match target {
        AssignmentTarget::StaticMemberExpression(m) => Some(m.property.name.to_string()),
        AssignmentTarget::ComputedMemberExpression(m) => {
            if let Some(name) = m.static_property_name() {
                return Some(name.as_str().to_string());
            }
            fold_to_string_literal(ctx, &m.expression, scope_id, &mut HashSet::new())
        }
        _ => None,
    }
}

/// Returns the object expression of an assignment target's member-like
/// variants, or `None` for identifiers / destructuring patterns.
pub fn assignment_target_object<'a>(
    target: &'a AssignmentTarget<'a>,
) -> Option<&'a Expression<'a>> {
    match target {
        AssignmentTarget::StaticMemberExpression(m) => Some(&m.object),
        AssignmentTarget::ComputedMemberExpression(m) => Some(&m.object),
        AssignmentTarget::PrivateFieldExpression(m) => Some(&m.object),
        _ => None,
    }
}

/// Checks identifier and member-expression callees against known names. `callee` covers `Identifier`, member
/// expressions, and `super`,
/// since oxc's `Expression` already has a `Super` variant.
pub fn matches_callee_names(callee: &Expression, targets: &[&str]) -> bool {
    match callee {
        Expression::Identifier(ident) => targets.contains(&ident.name.as_str()),
        _ => callee
            .get_member_expr()
            .is_some_and(|m| is_property_named(m, targets)),
    }
}

/// Strips parentheses and TypeScript type-wrapper nodes.
/// oxc is normally parsed with `preserve_parens: false` (see
/// `sinksight_engine::parse`), so `ParenthesizedExpression` should not
/// appear in practice, but detectors may receive ASTs parsed elsewhere.
pub fn unwrap_expression<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    let mut current = expr;
    loop {
        current = match current {
            Expression::ParenthesizedExpression(e) => &e.expression,
            Expression::TSAsExpression(e) => &e.expression,
            Expression::TSSatisfiesExpression(e) => &e.expression,
            Expression::TSNonNullExpression(e) => &e.expression,
            Expression::TSTypeAssertion(e) => &e.expression,
            Expression::TSInstantiationExpression(e) => &e.expression,
            _ => return current,
        };
    }
}

/// Checks whether an expression denotes the global document object.
pub fn is_document_object(expr: &Expression) -> bool {
    match expr {
        Expression::Identifier(ident) => ident.name == "document",
        _ => match expr.get_member_expr() {
            Some(member) => {
                is_property_named(member, &["document", "contentDocument"])
                    || is_document_object(member.object())
            }
            None => false,
        },
    }
}

/// Checks whether an expression denotes an unshadowed window-like global. `scope_id` checks that the name is not
/// shadowed by a local binding.
pub fn is_window_like<'a>(ctx: &AnalysisCtx<'a>, expr: &Expression<'a>, scope_id: ScopeId) -> bool {
    match expr {
        Expression::Identifier(ident) => {
            let name = ident.name.as_str();
            matches!(
                name,
                "window" | "self" | "globalThis" | "top" | "parent" | "frames"
            ) && ctx
                .semantic
                .scoping()
                .find_binding(scope_id, name)
                .is_none()
        }
        _ => false,
    }
}

const LOCATION_PROPS: &[&str] = &["search", "hash", "href", "pathname"];
const DOCUMENT_URL_PROPS: &[&str] = &["URL", "documentURI", "baseURI"];

/// Checks whether an expression denotes the global location object.
pub fn is_global_location<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    match expr {
        Expression::Identifier(ident) if ident.name == "location" => ctx
            .semantic
            .scoping()
            .find_binding(scope_id, "location")
            .is_none(),
        _ => match expr.get_member_expr() {
            Some(member) if is_property_named(member, &["location"]) => {
                is_window_like(ctx, member.object(), scope_id)
            }
            _ => false,
        },
    }
}

/// Checks whether an expression reads from a browser-controlled URL source.
pub fn is_browser_url_source<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    if let Some(member) = expr.get_member_expr() {
        if is_property_named(member, LOCATION_PROPS)
            && is_global_location(ctx, member.object(), scope_id)
        {
            return true;
        }
        if is_property_named(member, DOCUMENT_URL_PROPS) && is_document_object(member.object()) {
            return true;
        }
        if is_property_named(member, &["location"])
            && is_window_like(ctx, member.object(), scope_id)
        {
            return true;
        }
    }
    if let Expression::Identifier(ident) = expr {
        if ident.name == "location" {
            return ctx
                .semantic
                .scoping()
                .find_binding(scope_id, "location")
                .is_none();
        }
    }
    false
}

/// Checks whether concatenation starts with a non-static value.
pub fn starts_with_variable(expr: &Expression) -> bool {
    let unwrapped = unwrap_expression_ref(expr);
    match unwrapped {
        Expression::StringLiteral(_) => false,
        Expression::TemplateLiteral(lit) => match lit.quasis.first() {
            None => true,
            Some(first) => first.value.raw.is_empty(),
        },
        Expression::BinaryExpression(bin) if bin.operator == BinaryOperator::Addition => {
            starts_with_variable(&bin.left)
        }
        _ => true,
    }
}

// `unwrap_expression` requires `&'a Expression<'a>` (arena-lifetime) so it
// can be used for resolution chains; this variant works on any borrow for
// call sites (like `starts_with_variable`) that only need to peek.
fn unwrap_expression_ref<'b>(expr: &'b Expression<'b>) -> &'b Expression<'b> {
    let mut current = expr;
    loop {
        current = match current {
            Expression::ParenthesizedExpression(e) => &e.expression,
            Expression::TSAsExpression(e) => &e.expression,
            Expression::TSSatisfiesExpression(e) => &e.expression,
            Expression::TSNonNullExpression(e) => &e.expression,
            Expression::TSTypeAssertion(e) => &e.expression,
            Expression::TSInstantiationExpression(e) => &e.expression,
            _ => return current,
        };
    }
}

/// Checks whether an expression has a statically safe URL prefix.
///
/// "Safe" means the leading literal already forces a non-`javascript`
/// scheme (or a relative URL) according to the WHATWG basic URL parser,
/// so the unknown remainder cannot turn the value into a `javascript:` URL.
pub fn has_safe_url_prefix<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    let Some(literal) = get_leading_literal_text(ctx, expr, scope_id) else {
        return false;
    };
    leading_url_cannot_be_javascript_scheme(&literal)
}

/// Returns `true` when `literal` is a URL prefix that cannot parse as the
/// `javascript` scheme, following the WHATWG basic URL parser:
/// <https://url.spec.whatwg.org/#basic-url-parser>
///
/// Steps applied to a *prefix* of the full input:
/// 1. Strip leading C0 controls and ASCII space (U+0000..=U+0020). Trailing
///    trim is skipped because the unknown remainder sits after this prefix.
/// 2. Remove every ASCII tab or newline (U+0009, U+000A, U+000D).
/// 3. Parse a scheme the same way the scheme start / scheme states do.
///
/// If the prefix is consumed entirely by step 1, the remainder chooses the
/// scheme. If a scheme is completed, it is `javascript` or it is not. If the
/// scheme is still being built, it can become `javascript` only when the
/// buffer is a prefix of that name. Any other first character falls through
/// to the no-scheme state (relative URL against the document base).
pub fn leading_url_cannot_be_javascript_scheme(literal: &str) -> bool {
    match parse_leading_url_scheme(literal) {
        LeadingScheme::Complete(scheme) => scheme != "javascript",
        LeadingScheme::Incomplete(buffer) => !"javascript".starts_with(&buffer),
        LeadingScheme::NoScheme => true,
        LeadingScheme::RemainderChoosesScheme => false,
    }
}

enum LeadingScheme {
    Complete(String),
    Incomplete(String),
    NoScheme,
    RemainderChoosesScheme,
}

fn parse_leading_url_scheme(literal: &str) -> LeadingScheme {
    let without_leading_c0_space = literal.trim_start_matches(|c: char| c as u32 <= 0x20);
    if without_leading_c0_space.is_empty() {
        return LeadingScheme::RemainderChoosesScheme;
    }

    let preprocessed: String = without_leading_c0_space
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    if preprocessed.is_empty() {
        return LeadingScheme::RemainderChoosesScheme;
    }

    let mut chars = preprocessed.chars();
    let Some(first) = chars.next() else {
        return LeadingScheme::RemainderChoosesScheme;
    };
    if !first.is_ascii_alphabetic() {
        return LeadingScheme::NoScheme;
    }

    let mut buffer = String::new();
    buffer.push(first.to_ascii_lowercase());
    for c in chars {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.') {
            buffer.push(c.to_ascii_lowercase());
            continue;
        }
        if c == ':' {
            return LeadingScheme::Complete(buffer);
        }
        return LeadingScheme::NoScheme;
    }
    LeadingScheme::Incomplete(buffer)
}

fn get_leading_literal_text<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> Option<String> {
    let unwrapped = unwrap_expression(expr);
    let resolved = resolve_identifier(ctx, unwrapped, scope_id);
    match resolved {
        Expression::StringLiteral(lit) => Some(lit.value.to_string()),
        Expression::TemplateLiteral(lit) => {
            let first = lit.quasis.first()?;
            let text = first
                .value
                .cooked
                .map(|a| a.to_string())
                .unwrap_or_default();
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        Expression::BinaryExpression(bin) if bin.operator == BinaryOperator::Addition => {
            get_leading_literal_text(ctx, &bin.left, scope_id)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// isStaticStringExpression
// ---------------------------------------------------------------------------

/// Checks whether an expression resolves to a static string.
pub fn is_static_string_expression<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> bool {
    is_static_string_expression_inner(ctx, expr, scope_id, &mut HashSet::new())
}

fn is_static_string_expression_inner<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
    let unwrapped = unwrap_expression(expr);
    let resolved = resolve_identifier_inner(ctx, unwrapped, scope_id, visited, 0);

    match resolved {
        Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::BigIntLiteral(_) => true,
        Expression::Identifier(ident) if ident.name == "undefined" => true,
        Expression::TemplateLiteral(lit) => lit
            .expressions
            .iter()
            .all(|e| is_static_string_expression_inner(ctx, e, scope_id, visited)),
        Expression::BinaryExpression(bin) if bin.operator == BinaryOperator::Addition => {
            is_static_string_expression_inner(ctx, &bin.left, scope_id, visited)
                && is_static_string_expression_inner(ctx, &bin.right, scope_id, visited)
        }
        Expression::ConditionalExpression(cond) => {
            is_static_string_expression_inner(ctx, &cond.consequent, scope_id, visited)
                && is_static_string_expression_inner(ctx, &cond.alternate, scope_id, visited)
        }
        Expression::LogicalExpression(logical) => {
            is_static_string_expression_inner(ctx, &logical.left, scope_id, visited)
                && is_static_string_expression_inner(ctx, &logical.right, scope_id, visited)
        }
        Expression::CallExpression(call) => {
            if let Expression::Identifier(callee) = &call.callee {
                if callee.name == "String" && call.arguments.len() == 1 {
                    if let Some(arg) = call.arguments[0].as_expression() {
                        return is_static_string_expression_inner(ctx, arg, scope_id, visited);
                    }
                }
            }
            if let Some(member) = call.callee.get_member_expr() {
                if is_property_named(member, &["concat"]) {
                    if !is_static_string_expression_inner(ctx, member.object(), scope_id, visited) {
                        return false;
                    }
                    return call.arguments.iter().all(|a| match a.as_expression() {
                        Some(e) => is_static_string_expression_inner(ctx, e, scope_id, visited),
                        None => false,
                    });
                }
            }
            false
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// resolve_identifier - the core constant-folding engine
// ---------------------------------------------------------------------------

/// Result of resolving an IIFE parameter to its call-site argument. Uses
/// A compact enum represents resolved, missing, and unresolved arguments.
/// `None` (the outer `Option`) plays the role of the "not an IIFE param"
/// `null`, while `arg: None` plays the role of the "missing argument"
/// (`undefined`) case.
pub struct ParamResolution<'a> {
    pub arg: Option<&'a Expression<'a>>,
    pub scope_id: ScopeId,
}

/// Result of resolving a named function's parameter across all of its
/// (non-escaping) call sites.
pub struct NamedParamResolution<'a> {
    pub args: Vec<Option<&'a Expression<'a>>>,
    pub scope_id: ScopeId,
}

/// Resolves an identifier to the expression that supplies its value.
pub fn resolve_identifier<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> &'a Expression<'a> {
    resolve_identifier_inner(ctx, expr, scope_id, &mut HashSet::new(), 0)
}

fn resolve_identifier_inner<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
    depth: u32,
) -> &'a Expression<'a> {
    if depth > MAX_RESOLVE_DEPTH {
        return expr;
    }

    if let Expression::AssignmentExpression(assign) = expr {
        return resolve_identifier_inner(ctx, &assign.right, scope_id, visited, depth + 1);
    }

    if let Expression::SequenceExpression(seq) = expr {
        if let Some(last) = seq.expressions.last() {
            return resolve_identifier_inner(ctx, last, scope_id, visited, depth + 1);
        }
    }

    if let Some(member) = expr.get_member_expr() {
        // Quick path: `obj.prop` where `obj` is a constant, "safe" object
        // literal whose relevant property was never (statically provably)
        // mutated.
        if let Expression::Identifier(obj_ident) = member.object() {
            if let Some(symbol_id) = ctx
                .semantic
                .scoping()
                .find_binding(scope_id, &obj_ident.name)
            {
                if let Some(Expression::ObjectExpression(obj)) = declarator_init(ctx, symbol_id) {
                    if is_safe_object_expression(obj)
                        && !ctx.semantic.scoping().symbol_is_mutated(symbol_id)
                    {
                        if let Some(mutated) = get_mutated_properties(ctx, symbol_id) {
                            if let Some(prop_name) =
                                resolved_member_property_name(ctx, member, scope_id)
                            {
                                if !mutated.contains(&prop_name) {
                                    if let Some(value) = find_object_property_value(obj, &prop_name)
                                    {
                                        return resolve_identifier_inner(
                                            ctx,
                                            value,
                                            scope_id,
                                            visited,
                                            depth + 1,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Generic fallback: resolve the object; if it becomes an object
        // literal, look the property straight up.
        let resolved_obj =
            resolve_identifier_inner(ctx, member.object(), scope_id, visited, depth + 1);
        if let Expression::ObjectExpression(obj) = resolved_obj {
            if let Some(prop_name) = resolved_member_property_name(ctx, member, scope_id) {
                if let Some(value) = find_object_property_value(obj, &prop_name) {
                    return resolve_identifier_inner(ctx, value, scope_id, visited, depth + 1);
                }
            }
        }

        // `this.prop` resolution: look for the first `this.prop = value`
        // assignment inside the enclosing scope's subtree.
        if matches!(member.object(), Expression::ThisExpression(_)) {
            if let Some(prop_name) = resolved_member_property_name(ctx, member, scope_id) {
                let key = format!("this.{prop_name}");
                if !visited.contains(&key) {
                    visited.insert(key);
                    if let Some(value) = resolve_this_property(ctx, scope_id, &prop_name) {
                        return resolve_identifier_inner(ctx, value, scope_id, visited, depth + 1);
                    }
                }
            }
        }
    }

    let Expression::Identifier(ident) = expr else {
        return expr;
    };
    let name = ident.name.as_str();
    if visited.contains(name) {
        return expr;
    }
    visited.insert(name.to_string());

    let scoping = ctx.semantic.scoping();
    let Some(symbol_id) = scoping.find_binding(scope_id, name) else {
        if !KNOWN_GLOBALS.contains(&name) {
            if let Some(value) = resolve_implicit_global(ctx, name) {
                return resolve_identifier_inner(ctx, value, scope_id, visited, depth + 1);
            }
        }
        return expr;
    };

    if let Some(resolution) = resolve_iife_param(ctx, symbol_id) {
        return match resolution.arg {
            Some(arg) => {
                resolve_identifier_inner(ctx, arg, resolution.scope_id, visited, depth + 1)
            }
            None => ctx.undefined_expr(),
        };
    }

    if let Some(named) = resolve_named_function_param(ctx, symbol_id) {
        if named.args.len() == 1 {
            return match named.args[0] {
                Some(arg) => resolve_identifier_inner(ctx, arg, named.scope_id, visited, depth + 1),
                None => ctx.undefined_expr(),
            };
        }
        if !named.args.is_empty() && named.args.iter().all(Option::is_none) {
            return ctx.undefined_expr();
        }
        if let Some(first) = named.args.iter().flatten().next() {
            let all_same_kind = named.args.iter().all(|a| match a {
                Some(e) => expr_kind_name(e) == expr_kind_name(first),
                None => false,
            });
            if all_same_kind {
                return resolve_identifier_inner(ctx, first, named.scope_id, visited, depth + 1);
            }
        }
    }

    let is_constant_ish = !scoping.symbol_is_mutated(symbol_id)
        || has_only_trivial_self_assignments(ctx, symbol_id, name);
    if is_constant_ish {
        if let Some(init) = declarator_init(ctx, symbol_id) {
            if let Expression::ObjectExpression(obj) = init {
                if !is_safe_object_expression(obj) {
                    return expr;
                }
                match get_mutated_properties(ctx, symbol_id) {
                    None => return expr,
                    Some(mutated) if !mutated.is_empty() => return expr,
                    Some(_) => {}
                }
            }
            return resolve_identifier_inner(ctx, init, scope_id, visited, depth + 1);
        }
    }

    expr
}

/// Coarse-grained "same AST node kind" comparison, used to decide whether
/// multiple call-site arguments can be treated as representative of a single
/// value for type-inference purposes.
fn expr_kind_name(expr: &Expression) -> &'static str {
    match expr {
        Expression::StringLiteral(_) => "StringLiteral",
        Expression::NumericLiteral(_) => "NumericLiteral",
        Expression::BooleanLiteral(_) => "BooleanLiteral",
        Expression::NullLiteral(_) => "NullLiteral",
        Expression::BigIntLiteral(_) => "BigIntLiteral",
        Expression::RegExpLiteral(_) => "RegExpLiteral",
        Expression::TemplateLiteral(_) => "TemplateLiteral",
        Expression::ArrayExpression(_) => "ArrayExpression",
        Expression::ObjectExpression(_) => "ObjectExpression",
        Expression::Identifier(_) => "Identifier",
        Expression::FunctionExpression(_) => "FunctionExpression",
        Expression::ArrowFunctionExpression(_) => "ArrowFunctionExpression",
        _ => "Other",
    }
}

/// Resolves `expr` and, if it resolves to an object literal, returns it.
pub fn resolve_to_object<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> Option<&'a ObjectExpression<'a>> {
    let resolved = resolve_identifier(ctx, expr, scope_id);
    if let Expression::ObjectExpression(obj) = resolved {
        return Some(obj);
    }
    if let Expression::Identifier(ident) = resolved {
        let symbol_id = ctx.semantic.scoping().find_binding(scope_id, &ident.name)?;
        if !ctx.semantic.scoping().symbol_is_mutated(symbol_id) {
            if let Some(Expression::ObjectExpression(obj)) = declarator_init(ctx, symbol_id) {
                return Some(obj);
            }
        }
    }
    None
}

fn find_object_property_value<'a>(
    obj: &'a ObjectExpression<'a>,
    prop_name: &str,
) -> Option<&'a Expression<'a>> {
    for prop in &obj.properties {
        if let ObjectPropertyKind::ObjectProperty(op) = prop {
            if let Some(key_name) = get_static_key_name(op.computed, &op.key) {
                if key_name == prop_name {
                    return Some(&op.value);
                }
            }
        }
    }
    None
}

/// Checks that an object has no spreads or getters/setters (regular
/// methods are fine since a function value can't itself become a string).
fn is_safe_object_expression(obj: &ObjectExpression) -> bool {
    obj.properties.iter().all(|prop| match prop {
        ObjectPropertyKind::SpreadProperty(_) => false,
        ObjectPropertyKind::ObjectProperty(p) => {
            !(matches!(p.kind, PropertyKind::Get | PropertyKind::Set))
        }
    })
}

/// Returns the initializer of a `VariableDeclarator`-bound symbol, or `None`
/// if the symbol isn't declared that way (e.g. it's a parameter, catch
/// clause binding, import, etc) or has no initializer.
pub(crate) fn declarator_init<'a>(
    ctx: &AnalysisCtx<'a>,
    symbol_id: SymbolId,
) -> Option<&'a Expression<'a>> {
    let scoping = ctx.semantic.scoping();
    let nodes = ctx.semantic.nodes();
    let node_id = scoping.symbol_declaration(symbol_id);
    match nodes.kind(node_id) {
        AstKind::VariableDeclarator(decl) => decl.init.as_ref(),
        _ => None,
    }
}

/// Whether `symbol_id` is bound by a `VariableDeclarator` (`var`/`let`/
/// `const x = ...`), regardless of whether it has an initializer.
pub(crate) fn is_variable_declarator_binding(ctx: &AnalysisCtx, symbol_id: SymbolId) -> bool {
    let scoping = ctx.semantic.scoping();
    let nodes = ctx.semantic.nodes();
    matches!(
        nodes.kind(scoping.symbol_declaration(symbol_id)),
        AstKind::VariableDeclarator(_)
    )
}

/// `const` bindings are never reassigned: a later write throws and does not
/// update the value that reaches uses.
pub(crate) fn is_const_variable_binding(ctx: &AnalysisCtx, symbol_id: SymbolId) -> bool {
    ctx.semantic
        .scoping()
        .symbol_flags(symbol_id)
        .is_const_variable()
}

/// Whether `symbol_id` is bound by a `FormalParameter`.
pub(crate) fn is_parameter_binding(ctx: &AnalysisCtx, symbol_id: SymbolId) -> bool {
    let scoping = ctx.semantic.scoping();
    let nodes = ctx.semantic.nodes();
    matches!(
        nodes.kind(scoping.symbol_declaration(symbol_id)),
        AstKind::FormalParameter(_)
    )
}

/// Returns properties that may have been mutated through a binding.
///
/// Returns `None` when mutation-safety cannot be established at all (the
/// binding should be treated as fully unsafe to read through), or
/// `Some(set)` of property names that are known to be mutated/escaped
/// somewhere in the program (an empty set means "provably never mutated").
///
/// Property-chain depth tracking is conservative and
/// preserved (`obj.a.b = x` invalidates everything), but the
/// "lambda passed to an opaque call escapes the object" check only looks at
/// the *direct* enclosing function of each reference, not the full ancestor
/// chain of nested closures. This trades a small amount of precision for
/// avoiding a potentially expensive unbounded walk; it never *under*-reports
/// mutation (i.e. it stays sound, at worst slightly more conservative).
fn get_mutated_properties(ctx: &AnalysisCtx, symbol_id: SymbolId) -> Option<HashSet<String>> {
    let scoping = ctx.semantic.scoping();
    let nodes = ctx.semantic.nodes();
    let mut mutated = HashSet::new();

    for reference in scoping.get_resolved_references(symbol_id) {
        let ref_node_id = reference.node_id();
        let ref_span = nodes.kind(ref_node_id).span();

        // Walk up through consecutive member-expression parents (obj.a.b...)
        // to find the outermost link in the chain, tracking depth.
        let mut current_id = ref_node_id;
        let mut current_span = ref_span;
        let mut depth = 0u32;
        loop {
            let parent_id = nodes.parent_id(current_id);
            match nodes.kind(parent_id) {
                AstKind::StaticMemberExpression(_)
                | AstKind::ComputedMemberExpression(_)
                | AstKind::PrivateFieldExpression(_) => {
                    depth += 1;
                    current_id = parent_id;
                    current_span = nodes.kind(parent_id).span();
                }
                _ => break,
            }
        }

        if depth == 0 {
            // Every reference to a trackable
            // binding must be the `object` of a `MemberExpression`, or the
            // whole binding is invalidated. This covers cases like `foo(obj)`
            // or `const b = obj` where the object itself escapes untracked,
            // not just closures passed to opaque calls.
            return None;
        }

        let parent_id = nodes.parent_id(current_id);
        let parent_kind = nodes.kind(parent_id);

        let prop_name_at_depth_1 = if depth == 1 {
            member_property_name_for_object_span(ctx, nodes, current_id, ref_span)
        } else {
            None
        };

        match parent_kind {
            AstKind::AssignmentExpression(assign)
                if assignment_target_span(&assign.left) == Some(current_span) =>
            {
                if depth > 1 {
                    return None;
                }
                match prop_name_at_depth_1 {
                    Some(name) if name != "__proto__" => {
                        mutated.insert(name);
                    }
                    _ => return None,
                }
            }
            AstKind::UpdateExpression(update)
                if simple_target_span(&update.argument) == Some(current_span) =>
            {
                if depth > 1 {
                    return None;
                }
                match prop_name_at_depth_1 {
                    Some(name) if name != "__proto__" => {
                        mutated.insert(name);
                    }
                    _ => return None,
                }
            }
            AstKind::UnaryExpression(unary)
                if unary.operator == UnaryOperator::Delete
                    && unary.argument.span() == current_span =>
            {
                if depth > 1 {
                    return None;
                }
                match prop_name_at_depth_1 {
                    Some(name) if name != "__proto__" => {
                        mutated.insert(name);
                    }
                    _ => return None,
                }
            }
            AstKind::CallExpression(call) => {
                if call.callee.span() == current_span {
                    // `obj.method()` — invalidate everything, we don't know
                    // what the method does to the receiver.
                    return None;
                }
                if call
                    .arguments
                    .iter()
                    .any(|a| a.as_expression().is_some_and(|e| e.span() == current_span))
                {
                    if depth > 1 {
                        return None;
                    }
                    match prop_name_at_depth_1 {
                        Some(name) => {
                            mutated.insert(name);
                        }
                        None => return None,
                    }
                }
            }
            AstKind::NewExpression(new_expr) => {
                if new_expr
                    .arguments
                    .iter()
                    .any(|a| a.as_expression().is_some_and(|e| e.span() == current_span))
                {
                    if depth > 1 {
                        return None;
                    }
                    match prop_name_at_depth_1 {
                        Some(name) => {
                            mutated.insert(name);
                        }
                        None => return None,
                    }
                }
            }
            _ => {
                if reference_escapes_into_opaque_call(nodes, ref_node_id) {
                    return None;
                }
            }
        }
    }

    Some(mutated)
}

pub(crate) fn assignment_target_span(target: &AssignmentTarget) -> Option<Span> {
    match target {
        AssignmentTarget::StaticMemberExpression(m) => Some(m.span),
        AssignmentTarget::ComputedMemberExpression(m) => Some(m.span),
        AssignmentTarget::PrivateFieldExpression(m) => Some(m.span),
        _ => None,
    }
}

fn simple_target_span(target: &SimpleAssignmentTarget) -> Option<Span> {
    match target {
        SimpleAssignmentTarget::StaticMemberExpression(m) => Some(m.span),
        SimpleAssignmentTarget::ComputedMemberExpression(m) => Some(m.span),
        SimpleAssignmentTarget::PrivateFieldExpression(m) => Some(m.span),
        _ => None,
    }
}

/// Property name of a member access, including `obj[ident]` and `obj[a + b]`
/// when the key folds to a constant string.
pub(crate) fn resolved_member_property_name<'a>(
    ctx: &AnalysisCtx<'a>,
    member: &'a MemberExpression<'a>,
    scope_id: ScopeId,
) -> Option<String> {
    if let Some(name) = member.static_property_name() {
        return Some(name.to_string());
    }
    let MemberExpression::ComputedMemberExpression(computed) = member else {
        return None;
    };
    fold_to_string_literal(ctx, &computed.expression, scope_id, &mut HashSet::new())
}

/// Folds `expr` to a constant string through identifier bindings and `+`.
/// Does not walk member expressions, so mutation analysis cannot re-enter
/// itself via a key like `obj[obj.a]`.
fn fold_to_string_literal<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> Option<String> {
    match unwrap_expression(expr) {
        Expression::StringLiteral(lit) => Some(lit.value.to_string()),
        Expression::TemplateLiteral(lit) if lit.expressions.is_empty() => lit
            .quasis
            .first()?
            .value
            .cooked
            .as_ref()
            .map(|atom| atom.to_string()),
        Expression::Identifier(ident) => {
            let name = ident.name.as_str();
            if !visited.insert(name.to_string()) {
                return None;
            }
            let result = (|| {
                let scoping = ctx.semantic.scoping();
                let symbol_id = scoping.find_binding(scope_id, name)?;
                let is_constant_ish = !scoping.symbol_is_mutated(symbol_id)
                    || has_only_trivial_self_assignments(ctx, symbol_id, name);
                if !is_constant_ish {
                    return None;
                }
                fold_to_string_literal(ctx, declarator_init(ctx, symbol_id)?, scope_id, visited)
            })();
            visited.remove(name);
            result
        }
        Expression::BinaryExpression(bin) if bin.operator == BinaryOperator::Addition => {
            let left = fold_to_string_literal(ctx, &bin.left, scope_id, visited)?;
            let right = fold_to_string_literal(ctx, &bin.right, scope_id, visited)?;
            Some(left + &right)
        }
        _ => None,
    }
}

/// Given the node id of the depth-1 member expression wrapping `ref_span`
/// (i.e. `obj.prop` where `obj` is at `ref_span`), returns `prop`'s name
/// if it is statically known or folds to a constant string.
fn member_property_name_for_object_span<'a>(
    ctx: &AnalysisCtx<'a>,
    nodes: &oxc_semantic::AstNodes<'a>,
    member_node_id: oxc_semantic::NodeId,
    _object_span: Span,
) -> Option<String> {
    match nodes.kind(member_node_id) {
        AstKind::StaticMemberExpression(m) => Some(m.property.name.to_string()),
        AstKind::ComputedMemberExpression(m) => {
            if let Some(name) = m.static_property_name() {
                return Some(name.as_str().to_string());
            }
            let scope_id = nodes.get_node(member_node_id).scope_id();
            fold_to_string_literal(ctx, &m.expression, scope_id, &mut HashSet::new())
        }
        _ => None,
    }
}

/// Determines whether a reference is read inside a closure that is
/// itself passed to an opaque call" escape check, but only for the direct
/// enclosing function (see [`get_mutated_properties`] doc comment).
fn reference_escapes_into_opaque_call(
    nodes: &oxc_semantic::AstNodes,
    ref_node_id: oxc_semantic::NodeId,
) -> bool {
    for ancestor_id in nodes.ancestor_ids(ref_node_id) {
        let (fn_span, is_function) = match nodes.kind(ancestor_id) {
            AstKind::Function(f) => (f.span, true),
            AstKind::ArrowFunctionExpression(f) => (f.span, true),
            AstKind::Program(_) => (Span::default(), false),
            _ => continue,
        };
        if !is_function {
            break;
        }
        let parent_id = nodes.parent_id(ancestor_id);
        let escapes = match nodes.kind(parent_id) {
            AstKind::CallExpression(call) => call
                .arguments
                .iter()
                .any(|a| a.as_expression().is_some_and(|e| e.span() == fn_span)),
            AstKind::NewExpression(new_expr) => new_expr
                .arguments
                .iter()
                .any(|a| a.as_expression().is_some_and(|e| e.span() == fn_span)),
            _ => false,
        };
        if escapes {
            return true;
        }
    }
    false
}

/// Checks whether a binding only has trivial self-assignments.
fn has_only_trivial_self_assignments(ctx: &AnalysisCtx, symbol_id: SymbolId, name: &str) -> bool {
    let scoping = ctx.semantic.scoping();
    let nodes = ctx.semantic.nodes();
    let mut has_any = false;
    for reference in scoping.get_resolved_references(symbol_id) {
        if !reference.is_write() {
            continue;
        }
        has_any = true;
        let parent_id = nodes.parent_id(reference.node_id());
        let is_trivial = matches!(
            nodes.kind(parent_id),
            AstKind::AssignmentExpression(assign)
                if assign.operator == AssignmentOperator::Assign
                    && matches!(&assign.left, AssignmentTarget::AssignmentTargetIdentifier(l) if l.name == name)
                    && matches!(&assign.right, Expression::Identifier(r) if r.name == name)
        );
        if !is_trivial {
            return false;
        }
    }
    has_any
}

/// Resolves an IIFE parameter to its call-site argument.
pub(crate) fn resolve_iife_param<'a>(
    ctx: &AnalysisCtx<'a>,
    symbol_id: SymbolId,
) -> Option<ParamResolution<'a>> {
    let scoping = ctx.semantic.scoping();
    if scoping.symbol_is_mutated(symbol_id) {
        return None;
    }
    let nodes = ctx.semantic.nodes();
    let decl_node_id = scoping.symbol_declaration(symbol_id);
    let AstKind::FormalParameter(param) = nodes.kind(decl_node_id) else {
        return None;
    };
    let params_node_id = nodes.parent_id(decl_node_id);
    let AstKind::FormalParameters(params) = nodes.kind(params_node_id) else {
        return None;
    };
    let fn_node_id = nodes.parent_id(params_node_id);
    let fn_span = match nodes.kind(fn_node_id) {
        AstKind::Function(f) => {
            if f.id.is_some() {
                return None;
            }
            f.span
        }
        AstKind::ArrowFunctionExpression(f) => f.span,
        _ => return None,
    };
    let call_node_id = nodes.parent_id(fn_node_id);
    let AstKind::CallExpression(call) = nodes.kind(call_node_id) else {
        return None;
    };
    if call.callee.span() != fn_span {
        return None;
    }
    if call
        .arguments
        .iter()
        .any(|a| matches!(a, Argument::SpreadElement(_)))
    {
        return None;
    }
    let param_index = params.items.iter().position(|p| p.span == param.span)?;
    let call_scope_id = nodes.get_node(call_node_id).scope_id();
    match call.arguments.get(param_index) {
        Some(arg) => Some(ParamResolution {
            arg: arg.as_expression(),
            scope_id: call_scope_id,
        }),
        None => Some(ParamResolution {
            arg: None,
            scope_id: call_scope_id,
        }),
    }
}

/// Resolves a named function parameter across its call sites.
pub(crate) fn resolve_named_function_param<'a>(
    ctx: &AnalysisCtx<'a>,
    symbol_id: SymbolId,
) -> Option<NamedParamResolution<'a>> {
    let scoping = ctx.semantic.scoping();
    let nodes = ctx.semantic.nodes();
    let decl_node_id = scoping.symbol_declaration(symbol_id);
    let AstKind::FormalParameter(param) = nodes.kind(decl_node_id) else {
        return None;
    };
    let params_node_id = nodes.parent_id(decl_node_id);
    let AstKind::FormalParameters(params) = nodes.kind(params_node_id) else {
        return None;
    };
    let fn_node_id = nodes.parent_id(params_node_id);
    let AstKind::Function(function) = nodes.kind(fn_node_id) else {
        return None;
    };
    let fn_id = function.id.as_ref()?;
    let fn_name = fn_id.name.as_str();

    let outer_scope_id = nodes.get_node(fn_node_id).scope_id();
    let fn_symbol_id = scoping.find_binding(outer_scope_id, fn_name)?;

    let refs: Vec<&Reference> = scoping
        .get_resolved_references(fn_symbol_id)
        .filter(|r| r.is_read())
        .collect();
    if refs.is_empty() {
        return None;
    }

    let param_index = params.items.iter().position(|p| p.span == param.span)?;

    let mut args = Vec::with_capacity(refs.len());
    let mut call_scope_id = outer_scope_id;
    for reference in refs {
        let ref_node_id = reference.node_id();
        let ref_span = nodes.kind(ref_node_id).span();
        let call_node_id = nodes.parent_id(ref_node_id);
        let AstKind::CallExpression(call) = nodes.kind(call_node_id) else {
            return None;
        };
        if call.callee.span() != ref_span {
            return None;
        }
        if call
            .arguments
            .iter()
            .any(|a| matches!(a, Argument::SpreadElement(_)))
        {
            return None;
        }
        args.push(
            call.arguments
                .get(param_index)
                .and_then(|a| a.as_expression()),
        );
        call_scope_id = nodes.get_node(call_node_id).scope_id();
    }

    Some(NamedParamResolution {
        args,
        scope_id: call_scope_id,
    })
}

/// Resolves an implicit global from its assignment.
///
/// Uses `Scoping::root_unresolved_references`, which already gives us
/// exactly the set of identifier references that could not be resolved to
/// any declared binding. No whole-program
/// re-scan required.
fn resolve_implicit_global<'a>(ctx: &AnalysisCtx<'a>, name: &str) -> Option<&'a Expression<'a>> {
    let scoping = ctx.semantic.scoping();
    let nodes = ctx.semantic.nodes();
    let mut found: Option<&'a Expression<'a>> = None;

    for (ref_name, ref_ids) in scoping.root_unresolved_references() {
        if *ref_name != name {
            continue;
        }
        for &ref_id in ref_ids.iter() {
            let reference = scoping.get_reference(ref_id);
            if !reference.is_write() {
                continue;
            }
            let node_id = reference.node_id();
            let parent_id = nodes.parent_id(node_id);
            if let AstKind::AssignmentExpression(assign) = nodes.kind(parent_id) {
                if let AssignmentTarget::AssignmentTargetIdentifier(target) = &assign.left {
                    if target.name == name {
                        if found.is_some() {
                            // Ambiguous: multiple implicit-global assignments.
                            return None;
                        }
                        found = Some(&assign.right);
                    }
                }
            }
        }
    }

    found
}

/// Resolves a value assigned through `this.prop`.
/// Scans every AST node for the first `this.prop = value` assignment that is
/// a descendant of the node that created `scope_id`.
fn resolve_this_property<'a>(
    ctx: &AnalysisCtx<'a>,
    scope_id: ScopeId,
    prop_name: &str,
) -> Option<&'a Expression<'a>> {
    let scoping = ctx.semantic.scoping();
    let nodes = ctx.semantic.nodes();
    let root_node_id = scoping.get_node_id(scope_id);

    for node in nodes.iter() {
        if let AstKind::AssignmentExpression(assign) = node.kind() {
            if let AssignmentTarget::StaticMemberExpression(member) = &assign.left {
                if matches!(member.object, Expression::ThisExpression(_))
                    && member.property.name == prop_name
                    && (root_node_id == node.id()
                        || nodes.ancestor_ids(node.id()).any(|id| id == root_node_id))
                {
                    return Some(&assign.right);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod url_scheme_tests {
    use super::leading_url_cannot_be_javascript_scheme;

    fn cannot_be_js(literal: &str) -> bool {
        leading_url_cannot_be_javascript_scheme(literal)
    }

    #[test]
    fn complete_https_scheme_cannot_be_javascript() {
        assert!(cannot_be_js("https://"));
        assert!(cannot_be_js("HTTPS://example.com/"));
        assert!(cannot_be_js("http:"));
        assert!(cannot_be_js("/relative/path"));
        assert!(cannot_be_js("//host/path"));
        assert!(cannot_be_js("?query"));
        assert!(cannot_be_js("#hash"));
        assert!(cannot_be_js("1javascript:"));
        assert!(cannot_be_js("http"));
        assert!(cannot_be_js("javascriptx:"));
        assert!(cannot_be_js("javascriptx"));
    }

    #[test]
    fn javascript_scheme_and_prefixes_can_still_be_javascript() {
        assert!(!cannot_be_js("javascript:"));
        assert!(!cannot_be_js("JAVASCRIPT:"));
        assert!(!cannot_be_js("javascript:alert(1)"));
        assert!(!cannot_be_js("java"));
        assert!(!cannot_be_js("j"));
        assert!(!cannot_be_js("javascript"));
    }

    #[test]
    fn leading_c0_and_space_are_stripped_before_scheme_parse() {
        assert!(!cannot_be_js(" "));
        assert!(!cannot_be_js("   "));
        assert!(!cannot_be_js("\n"));
        assert!(!cannot_be_js("\t"));
        assert!(!cannot_be_js("\u{0000}"));
        assert!(!cannot_be_js(" javascript:"));
        assert!(!cannot_be_js("  javascript:"));
        assert!(!cannot_be_js("\njavascript:"));
        assert!(!cannot_be_js("\tjavascript:"));
        assert!(!cannot_be_js("\u{000c}javascript:"));
        assert!(cannot_be_js(" https://"));
        assert!(cannot_be_js("\nhttps://example.com/"));
    }

    #[test]
    fn ascii_tab_and_newline_are_removed_from_the_whole_prefix() {
        assert!(!cannot_be_js("java\nscript:"));
        assert!(!cannot_be_js("java\tscript:"));
        assert!(!cannot_be_js("java\rscript:"));
        assert!(!cannot_be_js("java\r\nscript:alert(1)"));
        assert!(!cannot_be_js("JAVA\tSCRIPT:"));
        assert!(!cannot_be_js("javascript\t:"));
        assert!(cannot_be_js("ht\ntp://"));
        assert!(cannot_be_js("http\n:"));
    }

    #[test]
    fn interior_space_resets_to_relative_url() {
        assert!(cannot_be_js("java script:"));
        assert!(cannot_be_js("javascript :"));
    }
}
