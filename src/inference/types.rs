use std::collections::HashSet;
use std::sync::LazyLock;

/// All types that the inference engine can identify. Unlike JavaScript
/// (`InferredType = "string" | ... | (string & {})`), Rust has no
/// "open string enum" idiom, so this is a thin wrapper around `&'static str`
/// for well-known types plus an owned `String` fallback for constructor
/// names we don't otherwise recognize (e.g. `new Foo()` -> `"Foo"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InferredType {
    Known(&'static str),
    Named(String),
}

impl InferredType {
    pub const STRING: InferredType = InferredType::Known("string");
    pub const NUMBER: InferredType = InferredType::Known("number");
    pub const BOOLEAN: InferredType = InferredType::Known("boolean");
    pub const BIGINT: InferredType = InferredType::Known("bigint");
    pub const SYMBOL: InferredType = InferredType::Known("symbol");
    pub const UNDEFINED: InferredType = InferredType::Known("undefined");
    pub const NULL: InferredType = InferredType::Known("null");
    pub const HTML_ELEMENT: InferredType = InferredType::Known("HTMLElement");
    pub const DATE: InferredType = InferredType::Known("Date");
    pub const REGEXP: InferredType = InferredType::Known("RegExp");
    pub const ARRAY: InferredType = InferredType::Known("Array");
    pub const OBJECT: InferredType = InferredType::Known("Object");
    pub const FUNCTION: InferredType = InferredType::Known("Function");
    pub const ERROR: InferredType = InferredType::Known("Error");
    pub const MAP: InferredType = InferredType::Known("Map");
    pub const SET: InferredType = InferredType::Known("Set");
    pub const PROMISE: InferredType = InferredType::Known("Promise");
    pub const URL: InferredType = InferredType::Known("URL");
    pub const XML_HTTP_REQUEST: InferredType = InferredType::Known("XMLHttpRequest");
    pub const WINDOW: InferredType = InferredType::Known("Window");
    pub const DOCUMENT: InferredType = InferredType::Known("Document");
    pub const LOCATION: InferredType = InferredType::Known("Location");
    pub const UNKNOWN: InferredType = InferredType::Known("unknown");

    pub fn as_str(&self) -> &str {
        match self {
            InferredType::Known(s) => s,
            InferredType::Named(s) => s,
        }
    }

    pub fn named(name: impl Into<String>) -> InferredType {
        InferredType::Named(name.into())
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, InferredType::Known("unknown"))
    }
}

impl std::fmt::Display for InferredType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for InferredType {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for InferredType {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// HTML tag name (lowercase), e.g. `"div"`, `"script"`, `"img"`.
pub type ElementTag = String;

/// Types that are inherently safe when converted to a string. Their
/// `.toString()` or string concatenation can never produce executable HTML
/// or JavaScript.
pub static SAFE_TO_STRINGIFY_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "number",
        "boolean",
        "bigint",
        "undefined",
        "null",
        "Date",
        // RegExp is NOT here: `new RegExp(userInput).toString()` echoes the
        // attacker-controlled pattern.
        "Error",
        "URL",
        "Array",
        "Map",
        "Set",
        "Symbol",
    ])
});

pub fn is_safe_to_stringify(ty: &InferredType) -> bool {
    SAFE_TO_STRINGIFY_TYPES.contains(ty.as_str())
}

/// Describes how a method affects the safety of its return value relative
/// to its inputs (receiver + arguments).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyBehavior {
    /// The return type itself is always safe (e.g. returns number/boolean).
    AlwaysSafe,
    /// Safe if and only if the receiver (`this`) is safe.
    PreservesObject,
    /// Safe if receiver AND all string-like arguments are safe.
    PreservesAll,
    /// Cannot determine safety from inputs alone.
    Unsafe,
}

/// Metadata for a single method.
#[derive(Debug, Clone)]
pub struct MethodDescriptor {
    pub return_type: InferredType,
    pub safety: SafetyBehavior,
}
