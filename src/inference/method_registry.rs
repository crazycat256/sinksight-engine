//! Port of `packages/vscode-ext/src/detectors/inference/methodRegistry.ts`.
//!
//! NOTE: another agent may be working on a fuller/authoritative version of
//! this registry in parallel. This implementation exists so that
//! `type_inference.rs` / `safety.rs` / `elements.rs` compile and behave
//! correctly on their own; treat it as a placeholder to be reconciled if a
//! separate `method_registry.rs` lands.

use std::collections::HashMap;
use std::sync::LazyLock;

use super::types::{InferredType, MethodDescriptor, SafetyBehavior};

fn always(return_type: InferredType) -> MethodDescriptor {
    MethodDescriptor {
        return_type,
        safety: SafetyBehavior::AlwaysSafe,
    }
}

fn preserves_obj(return_type: InferredType) -> MethodDescriptor {
    MethodDescriptor {
        return_type,
        safety: SafetyBehavior::PreservesObject,
    }
}

fn preserves_all(return_type: InferredType) -> MethodDescriptor {
    MethodDescriptor {
        return_type,
        safety: SafetyBehavior::PreservesAll,
    }
}

fn unsafe_(return_type: InferredType) -> MethodDescriptor {
    MethodDescriptor {
        return_type,
        safety: SafetyBehavior::Unsafe,
    }
}

type MethodMap = HashMap<&'static str, MethodDescriptor>;

fn string_methods() -> MethodMap {
    HashMap::from([
        ("toLowerCase", preserves_obj(InferredType::STRING)),
        ("toUpperCase", preserves_obj(InferredType::STRING)),
        ("toLocaleLowerCase", preserves_obj(InferredType::STRING)),
        ("toLocaleUpperCase", preserves_obj(InferredType::STRING)),
        ("trim", preserves_obj(InferredType::STRING)),
        ("trimStart", preserves_obj(InferredType::STRING)),
        ("trimEnd", preserves_obj(InferredType::STRING)),
        ("trimLeft", preserves_obj(InferredType::STRING)),
        ("trimRight", preserves_obj(InferredType::STRING)),
        ("substring", preserves_obj(InferredType::STRING)),
        ("substr", preserves_obj(InferredType::STRING)),
        ("slice", preserves_obj(InferredType::STRING)),
        ("charAt", preserves_obj(InferredType::STRING)),
        ("at", preserves_obj(InferredType::STRING)),
        ("normalize", preserves_obj(InferredType::STRING)),
        ("repeat", preserves_obj(InferredType::STRING)),
        ("toString", preserves_obj(InferredType::STRING)),
        ("valueOf", preserves_obj(InferredType::STRING)),
        ("replace", preserves_all(InferredType::STRING)),
        ("replaceAll", preserves_all(InferredType::STRING)),
        ("concat", preserves_all(InferredType::STRING)),
        ("padStart", preserves_all(InferredType::STRING)),
        ("padEnd", preserves_all(InferredType::STRING)),
        ("indexOf", always(InferredType::NUMBER)),
        ("lastIndexOf", always(InferredType::NUMBER)),
        ("search", always(InferredType::NUMBER)),
        ("charCodeAt", always(InferredType::NUMBER)),
        ("codePointAt", always(InferredType::NUMBER)),
        ("localeCompare", always(InferredType::NUMBER)),
        ("length", always(InferredType::NUMBER)),
        ("includes", always(InferredType::BOOLEAN)),
        ("startsWith", always(InferredType::BOOLEAN)),
        ("endsWith", always(InferredType::BOOLEAN)),
        ("split", always(InferredType::ARRAY)),
        ("match", unsafe_(InferredType::UNKNOWN)),
        ("matchAll", unsafe_(InferredType::UNKNOWN)),
    ])
}

fn number_methods() -> MethodMap {
    HashMap::from([
        ("toFixed", always(InferredType::STRING)),
        ("toPrecision", always(InferredType::STRING)),
        ("toExponential", always(InferredType::STRING)),
        ("toString", always(InferredType::STRING)),
        ("valueOf", always(InferredType::NUMBER)),
        ("toLocaleString", always(InferredType::STRING)),
    ])
}

fn boolean_methods() -> MethodMap {
    HashMap::from([
        ("toString", always(InferredType::STRING)),
        ("valueOf", always(InferredType::BOOLEAN)),
    ])
}

fn bigint_methods() -> MethodMap {
    HashMap::from([
        ("toString", always(InferredType::STRING)),
        ("valueOf", always(InferredType::BIGINT)),
        ("toLocaleString", always(InferredType::STRING)),
    ])
}

fn date_methods() -> MethodMap {
    HashMap::from([
        ("getTime", always(InferredType::NUMBER)),
        ("getFullYear", always(InferredType::NUMBER)),
        ("getMonth", always(InferredType::NUMBER)),
        ("getDate", always(InferredType::NUMBER)),
        ("getDay", always(InferredType::NUMBER)),
        ("getHours", always(InferredType::NUMBER)),
        ("getMinutes", always(InferredType::NUMBER)),
        ("getSeconds", always(InferredType::NUMBER)),
        ("getMilliseconds", always(InferredType::NUMBER)),
        ("getTimezoneOffset", always(InferredType::NUMBER)),
        ("getUTCFullYear", always(InferredType::NUMBER)),
        ("getUTCMonth", always(InferredType::NUMBER)),
        ("getUTCDate", always(InferredType::NUMBER)),
        ("getUTCDay", always(InferredType::NUMBER)),
        ("getUTCHours", always(InferredType::NUMBER)),
        ("getUTCMinutes", always(InferredType::NUMBER)),
        ("getUTCSeconds", always(InferredType::NUMBER)),
        ("getUTCMilliseconds", always(InferredType::NUMBER)),
        ("valueOf", always(InferredType::NUMBER)),
        ("toISOString", always(InferredType::STRING)),
        ("toDateString", always(InferredType::STRING)),
        ("toTimeString", always(InferredType::STRING)),
        ("toLocaleString", always(InferredType::STRING)),
        ("toLocaleDateString", always(InferredType::STRING)),
        ("toLocaleTimeString", always(InferredType::STRING)),
        ("toUTCString", always(InferredType::STRING)),
        ("toJSON", always(InferredType::STRING)),
        ("toString", always(InferredType::STRING)),
    ])
}

fn regexp_methods() -> MethodMap {
    HashMap::from([
        ("test", always(InferredType::BOOLEAN)),
        ("toString", preserves_obj(InferredType::STRING)),
        ("exec", unsafe_(InferredType::UNKNOWN)),
    ])
}

fn array_methods() -> MethodMap {
    HashMap::from([
        ("join", preserves_all(InferredType::STRING)),
        ("toString", unsafe_(InferredType::STRING)),
        ("toLocaleString", unsafe_(InferredType::STRING)),
        ("push", always(InferredType::NUMBER)),
        ("unshift", always(InferredType::NUMBER)),
        ("indexOf", always(InferredType::NUMBER)),
        ("lastIndexOf", always(InferredType::NUMBER)),
        ("findIndex", always(InferredType::NUMBER)),
        ("includes", always(InferredType::BOOLEAN)),
        ("every", always(InferredType::BOOLEAN)),
        ("some", always(InferredType::BOOLEAN)),
        ("isArray", always(InferredType::BOOLEAN)),
        ("pop", unsafe_(InferredType::UNKNOWN)),
        ("shift", unsafe_(InferredType::UNKNOWN)),
        ("slice", unsafe_(InferredType::ARRAY)),
        ("splice", unsafe_(InferredType::ARRAY)),
        ("concat", unsafe_(InferredType::ARRAY)),
        ("filter", unsafe_(InferredType::ARRAY)),
        ("map", unsafe_(InferredType::ARRAY)),
        ("flat", unsafe_(InferredType::ARRAY)),
        ("flatMap", unsafe_(InferredType::ARRAY)),
        ("reverse", unsafe_(InferredType::ARRAY)),
        ("sort", unsafe_(InferredType::ARRAY)),
        ("fill", unsafe_(InferredType::ARRAY)),
        ("find", unsafe_(InferredType::UNKNOWN)),
        ("reduce", unsafe_(InferredType::UNKNOWN)),
        ("reduceRight", unsafe_(InferredType::UNKNOWN)),
        ("keys", unsafe_(InferredType::UNKNOWN)),
        ("values", unsafe_(InferredType::UNKNOWN)),
        ("entries", unsafe_(InferredType::UNKNOWN)),
        ("forEach", always(InferredType::UNDEFINED)),
    ])
}

fn error_methods() -> MethodMap {
    HashMap::from([("toString", always(InferredType::STRING))])
}

fn url_methods() -> MethodMap {
    HashMap::from([
        ("toString", always(InferredType::STRING)),
        ("toJSON", always(InferredType::STRING)),
    ])
}

fn map_methods() -> MethodMap {
    HashMap::from([
        ("get", unsafe_(InferredType::UNKNOWN)),
        ("has", always(InferredType::BOOLEAN)),
        ("set", unsafe_(InferredType::UNKNOWN)),
        ("delete", always(InferredType::BOOLEAN)),
        ("forEach", always(InferredType::UNDEFINED)),
        ("toString", always(InferredType::STRING)),
    ])
}

fn set_methods() -> MethodMap {
    HashMap::from([
        ("has", always(InferredType::BOOLEAN)),
        ("add", unsafe_(InferredType::UNKNOWN)),
        ("delete", always(InferredType::BOOLEAN)),
        ("forEach", always(InferredType::UNDEFINED)),
        ("toString", always(InferredType::STRING)),
    ])
}

fn promise_methods() -> MethodMap {
    HashMap::from([
        ("then", unsafe_(InferredType::PROMISE)),
        ("catch", unsafe_(InferredType::PROMISE)),
        ("finally", unsafe_(InferredType::PROMISE)),
        ("toString", always(InferredType::STRING)),
    ])
}

fn function_methods() -> MethodMap {
    HashMap::from([
        ("call", unsafe_(InferredType::UNKNOWN)),
        ("apply", unsafe_(InferredType::UNKNOWN)),
        ("bind", unsafe_(InferredType::FUNCTION)),
        ("toString", unsafe_(InferredType::STRING)),
    ])
}

fn object_methods() -> MethodMap {
    HashMap::from([
        ("toString", unsafe_(InferredType::STRING)),
        ("valueOf", unsafe_(InferredType::UNKNOWN)),
        ("hasOwnProperty", always(InferredType::BOOLEAN)),
        ("isPrototypeOf", always(InferredType::BOOLEAN)),
        ("propertyIsEnumerable", always(InferredType::BOOLEAN)),
        ("toLocaleString", unsafe_(InferredType::STRING)),
    ])
}

fn xhr_methods() -> MethodMap {
    HashMap::from([
        ("open", always(InferredType::UNDEFINED)),
        ("send", always(InferredType::UNDEFINED)),
        ("abort", always(InferredType::UNDEFINED)),
        ("setRequestHeader", always(InferredType::UNDEFINED)),
        ("getResponseHeader", unsafe_(InferredType::STRING)),
        ("getAllResponseHeaders", unsafe_(InferredType::STRING)),
        ("overrideMimeType", always(InferredType::UNDEFINED)),
    ])
}

fn response_methods() -> MethodMap {
    HashMap::from([
        ("json", unsafe_(InferredType::UNKNOWN)),
        ("text", unsafe_(InferredType::UNKNOWN)),
        ("blob", unsafe_(InferredType::UNKNOWN)),
        ("arrayBuffer", unsafe_(InferredType::UNKNOWN)),
        ("formData", unsafe_(InferredType::UNKNOWN)),
        ("clone", unsafe_(InferredType::UNKNOWN)),
        ("toString", always(InferredType::STRING)),
    ])
}

fn message_port_methods() -> MethodMap {
    HashMap::from([
        ("postMessage", always(InferredType::UNDEFINED)),
        ("start", always(InferredType::UNDEFINED)),
        ("close", always(InferredType::UNDEFINED)),
        ("toString", always(InferredType::STRING)),
        ("addEventListener", always(InferredType::UNDEFINED)),
        ("removeEventListener", always(InferredType::UNDEFINED)),
    ])
}

fn message_channel_methods() -> MethodMap {
    HashMap::from([("toString", always(InferredType::STRING))])
}

/// Map from inferred type name --> instance method descriptors.
pub static INSTANCE_METHODS: LazyLock<HashMap<&'static str, MethodMap>> = LazyLock::new(|| {
    HashMap::from([
        ("string", string_methods()),
        ("number", number_methods()),
        ("boolean", boolean_methods()),
        ("bigint", bigint_methods()),
        ("Date", date_methods()),
        ("RegExp", regexp_methods()),
        ("Array", array_methods()),
        ("Object", object_methods()),
        ("Error", error_methods()),
        ("URL", url_methods()),
        ("Map", map_methods()),
        ("Set", set_methods()),
        ("Promise", promise_methods()),
        ("Function", function_methods()),
        ("XMLHttpRequest", xhr_methods()),
        ("Response", response_methods()),
        ("MessagePort", message_port_methods()),
        ("MessageChannel", message_channel_methods()),
    ])
});

/// Owner type --> property name --> return type (non-method accessors).
pub static INSTANCE_PROPERTIES: LazyLock<
    HashMap<&'static str, HashMap<&'static str, InferredType>>,
> = LazyLock::new(|| {
    HashMap::from([
        (
            "MessageChannel",
            HashMap::from([
                ("port1", InferredType::named("MessagePort")),
                ("port2", InferredType::named("MessagePort")),
            ]),
        ),
        (
            "Response",
            HashMap::from([
                ("ok", InferredType::BOOLEAN),
                ("status", InferredType::NUMBER),
                ("statusText", InferredType::STRING),
                ("redirected", InferredType::BOOLEAN),
                ("bodyUsed", InferredType::BOOLEAN),
                ("url", InferredType::STRING),
                ("type", InferredType::STRING),
                ("headers", InferredType::UNKNOWN),
                ("body", InferredType::UNKNOWN),
            ]),
        ),
        (
            "XMLHttpRequest",
            HashMap::from([
                ("responseText", InferredType::UNKNOWN),
                ("responseXML", InferredType::UNKNOWN),
                ("response", InferredType::UNKNOWN),
                ("readyState", InferredType::NUMBER),
                ("status", InferredType::NUMBER),
                ("timeout", InferredType::NUMBER),
                ("withCredentials", InferredType::BOOLEAN),
                ("statusText", InferredType::STRING),
                ("responseType", InferredType::STRING),
                ("responseURL", InferredType::STRING),
            ]),
        ),
    ])
});

pub fn get_instance_property(owner_type: &str, prop_name: &str) -> Option<InferredType> {
    INSTANCE_PROPERTIES.get(owner_type)?.get(prop_name).cloned()
}

/// Maps a property/method *name* to the built-in type of the object that
/// owns it, for names virtually unique to a single built-in class.
pub static DISCRIMINANT_PROPERTIES: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        HashMap::from([
            ("port1", "MessageChannel"),
            ("port2", "MessageChannel"),
            ("responseText", "XMLHttpRequest"),
            ("responseXML", "XMLHttpRequest"),
            ("getAllResponseHeaders", "XMLHttpRequest"),
            ("searchParams", "URL"),
            ("dotAll", "RegExp"),
            ("getTime", "Date"),
            ("getFullYear", "Date"),
            ("getTimezoneOffset", "Date"),
            ("toISOString", "Date"),
            ("bodyUsed", "Response"),
        ])
    });

pub fn get_discriminant_property(prop_name: &str) -> Option<InferredType> {
    DISCRIMINANT_PROPERTIES
        .get(prop_name)
        .map(|s| InferredType::named(*s))
}

fn math_static() -> MethodMap {
    let names = [
        "abs", "ceil", "floor", "round", "trunc", "sign", "sqrt", "cbrt", "pow", "exp", "expm1",
        "log", "log2", "log10", "log1p", "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
        "sinh", "cosh", "tanh", "asinh", "acosh", "atanh", "hypot", "min", "max", "random",
        "fround", "clz32", "imul",
    ];
    names
        .into_iter()
        .map(|n| (n, always(InferredType::NUMBER)))
        .collect()
}

/// Global object name --> method name --> descriptor.
pub static STATIC_METHODS: LazyLock<HashMap<&'static str, MethodMap>> = LazyLock::new(|| {
    HashMap::from([
        ("Math", math_static()),
        (
            "Date",
            HashMap::from([
                ("now", always(InferredType::NUMBER)),
                ("parse", always(InferredType::NUMBER)),
                ("UTC", always(InferredType::NUMBER)),
            ]),
        ),
        (
            "Number",
            HashMap::from([
                ("isFinite", always(InferredType::BOOLEAN)),
                ("isInteger", always(InferredType::BOOLEAN)),
                ("isNaN", always(InferredType::BOOLEAN)),
                ("isSafeInteger", always(InferredType::BOOLEAN)),
                ("parseInt", always(InferredType::NUMBER)),
                ("parseFloat", always(InferredType::NUMBER)),
            ]),
        ),
        (
            "Object",
            HashMap::from([
                ("keys", always(InferredType::ARRAY)),
                ("values", unsafe_(InferredType::ARRAY)),
                ("entries", unsafe_(InferredType::ARRAY)),
                ("assign", unsafe_(InferredType::OBJECT)),
                ("create", unsafe_(InferredType::OBJECT)),
                ("freeze", unsafe_(InferredType::OBJECT)),
                ("seal", unsafe_(InferredType::OBJECT)),
                ("is", always(InferredType::BOOLEAN)),
                ("hasOwn", always(InferredType::BOOLEAN)),
                ("getPrototypeOf", unsafe_(InferredType::UNKNOWN)),
                ("defineProperty", unsafe_(InferredType::OBJECT)),
            ]),
        ),
        (
            "Array",
            HashMap::from([
                ("isArray", always(InferredType::BOOLEAN)),
                ("from", unsafe_(InferredType::ARRAY)),
                ("of", unsafe_(InferredType::ARRAY)),
            ]),
        ),
        (
            "JSON",
            HashMap::from([
                ("stringify", preserves_all(InferredType::STRING)),
                ("parse", preserves_all(InferredType::UNKNOWN)),
            ]),
        ),
        (
            "String",
            HashMap::from([
                ("fromCharCode", always(InferredType::STRING)),
                ("fromCodePoint", always(InferredType::STRING)),
            ]),
        ),
        (
            "Promise",
            HashMap::from([
                ("resolve", unsafe_(InferredType::PROMISE)),
                ("reject", unsafe_(InferredType::PROMISE)),
                ("all", unsafe_(InferredType::PROMISE)),
                ("allSettled", unsafe_(InferredType::PROMISE)),
                ("race", unsafe_(InferredType::PROMISE)),
                ("any", unsafe_(InferredType::PROMISE)),
            ]),
        ),
        (
            "Symbol",
            HashMap::from([
                ("for", always(InferredType::SYMBOL)),
                ("keyFor", unsafe_(InferredType::STRING)),
            ]),
        ),
    ])
});

/// Global function name --> descriptor.
pub static GLOBAL_FUNCTIONS: LazyLock<MethodMap> = LazyLock::new(|| {
    HashMap::from([
        ("parseInt", always(InferredType::NUMBER)),
        ("parseFloat", always(InferredType::NUMBER)),
        ("isNaN", always(InferredType::BOOLEAN)),
        ("isFinite", always(InferredType::BOOLEAN)),
        ("encodeURI", always(InferredType::STRING)),
        ("encodeURIComponent", always(InferredType::STRING)),
        ("decodeURI", unsafe_(InferredType::STRING)),
        ("decodeURIComponent", unsafe_(InferredType::STRING)),
        ("escape", always(InferredType::STRING)),
        ("unescape", unsafe_(InferredType::STRING)),
        ("String", preserves_obj(InferredType::STRING)),
        ("Number", always(InferredType::NUMBER)),
        ("Boolean", always(InferredType::BOOLEAN)),
        ("BigInt", always(InferredType::BIGINT)),
        ("Array", unsafe_(InferredType::ARRAY)),
    ])
});

/// `new Xxx()` --> inferred type.
pub static CONSTRUCTOR_TYPES: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        ("Date", "Date"),
        ("RegExp", "RegExp"),
        ("String", "string"),
        ("Number", "number"),
        ("Boolean", "boolean"),
        ("Array", "Array"),
        ("Object", "Object"),
        ("Map", "Map"),
        ("Set", "Set"),
        ("Error", "Error"),
        ("TypeError", "Error"),
        ("RangeError", "Error"),
        ("ReferenceError", "Error"),
        ("SyntaxError", "Error"),
        ("URIError", "Error"),
        ("EvalError", "Error"),
        ("URL", "URL"),
        ("Promise", "Promise"),
        ("Function", "Function"),
        ("Image", "HTMLElement"),
        ("WeakMap", "Map"),
        ("WeakSet", "Set"),
        ("XMLHttpRequest", "XMLHttpRequest"),
        ("Worker", "Worker"),
        ("WebSocket", "WebSocket"),
        ("BroadcastChannel", "BroadcastChannel"),
        ("MessageChannel", "MessageChannel"),
        ("MessagePort", "MessagePort"),
        ("Response", "Response"),
    ])
});

pub fn get_instance_method(
    owner_type: &str,
    method_name: &str,
) -> Option<&'static MethodDescriptor> {
    INSTANCE_METHODS.get(owner_type)?.get(method_name)
}

pub fn get_static_method(
    object_name: &str,
    method_name: &str,
) -> Option<&'static MethodDescriptor> {
    STATIC_METHODS.get(object_name)?.get(method_name)
}

pub fn get_global_function(name: &str) -> Option<&'static MethodDescriptor> {
    GLOBAL_FUNCTIONS.get(name)
}

pub fn get_constructor_type(name: &str) -> Option<InferredType> {
    CONSTRUCTOR_TYPES.get(name).map(|s| InferredType::named(*s))
}
