mod common;
use common::with_last_expr;
use sinksight_analysis::inference::infer_type;

fn assert_type(code: &str, expected: &str) {
    with_last_expr(code, |ctx, expr, scope_id| {
        let ty = infer_type(ctx, expr, scope_id);
        assert_eq!(ty.as_str(), expected, "for {code:?}");
    });
}

// Literals

#[test]
fn infers_number_literals() {
    for code in ["123", "0", "-1", "3.14", "0xff"] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_string_literals() {
    for code in ["('hello')", "(\"world\")"] {
        assert_type(code, "string");
    }
}

#[test]
fn infers_boolean_literals() {
    for code in ["true", "false"] {
        assert_type(code, "boolean");
    }
}

#[test]
fn infers_regexp_literals() {
    for code in ["/abc/", "/test/gi"] {
        assert_type(code, "RegExp");
    }
}

#[test]
fn infers_null() {
    assert_type("null", "null");
}

#[test]
fn infers_bigint() {
    for code in ["0n", "123n"] {
        assert_type(code, "bigint");
    }
}

#[test]
fn infers_array_literals() {
    for code in ["[]", "[1, 2, 3]"] {
        assert_type(code, "Array");
    }
}

#[test]
fn infers_object_literals() {
    for code in ["({})", "({ a: 1 })"] {
        assert_type(code, "Object");
    }
}

#[test]
fn infers_function_literals() {
    for code in ["(() => {})", "(function() {})"] {
        assert_type(code, "Function");
    }
}

// Template literals

#[test]
fn infers_string_for_template_literals() {
    for code in ["`hello`", "`hello ${42}`", "`${true} and ${false}`"] {
        assert_type(code, "string");
    }
}

#[test]
fn infers_initializer_type_after_self_assignment() {
    let code = r#"
        let a = "safe";
        a = a;
        a
    "#;
    assert_type(code, "string");
}

// Constructors (new Xxx)

#[test]
fn infers_new_date() {
    for code in ["new Date()", "new Date(2026, 0, 1)"] {
        assert_type(code, "Date");
    }
}

#[test]
fn infers_new_regexp() {
    for code in ["new RegExp('abc')", "new RegExp('test', 'gi')"] {
        assert_type(code, "RegExp");
    }
}

#[test]
fn infers_new_string() {
    assert_type("new String('x')", "string");
}

#[test]
fn infers_new_number() {
    assert_type("new Number(42)", "number");
}

#[test]
fn infers_new_boolean() {
    assert_type("new Boolean(true)", "boolean");
}

#[test]
fn infers_new_array() {
    for code in ["new Array()", "new Array(5)"] {
        assert_type(code, "Array");
    }
}

#[test]
fn infers_new_object() {
    assert_type("new Object()", "Object");
}

#[test]
fn infers_new_map() {
    assert_type("new Map()", "Map");
}

#[test]
fn infers_new_set() {
    assert_type("new Set()", "Set");
}

#[test]
fn infers_new_error() {
    for code in [
        "new Error('oops')",
        "new TypeError('bad')",
        "new RangeError('nope')",
    ] {
        assert_type(code, "Error");
    }
}

#[test]
fn infers_new_url() {
    assert_type("new URL('https://example.com')", "URL");
}

#[test]
fn infers_new_promise() {
    assert_type("new Promise(() => {})", "Promise");
}

#[test]
fn infers_new_function() {
    assert_type("new Function('return 1')", "Function");
}

#[test]
fn infers_new_image_as_html_element() {
    for code in ["new Image()", "new Image(100, 100)"] {
        assert_type(code, "HTMLElement");
    }
}

// Global function calls

#[test]
fn infers_number_for_global_number_functions() {
    for code in ["parseInt('42')", "parseFloat('3.14')", "Number('5')"] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_boolean_for_global_boolean_functions() {
    for code in ["Boolean(1)", "isNaN(x)", "isFinite(y)"] {
        assert_type(code, "boolean");
    }
}

#[test]
fn infers_string_for_global_string_functions() {
    for code in [
        "String(42)",
        "String(true)",
        "encodeURIComponent('test')",
        "encodeURI('http://example.com')",
        "Date()", // Date() without new returns a string
    ] {
        assert_type(code, "string");
    }
}

// Arithmetic & binary operators

#[test]
fn infers_number_for_arithmetic_operations() {
    for code in [
        "1 + 2", "x - y", "a * b", "10 / 2", "x % 3", "2 ** 10", "x & y", "a | b", "a ^ b",
        "x << 2", "x >> 1", "x >>> 0",
    ] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_boolean_for_comparison_operators() {
    for code in [
        "a === b",
        "x !== y",
        "x > 5",
        "y <= 10",
        "a == b",
        "a != b",
        "a < b",
        "a >= b",
        "'x' in obj",
        "x instanceof Array",
    ] {
        assert_type(code, "boolean");
    }
}

#[test]
fn infers_string_for_string_concatenation() {
    for code in [
        "'a' + 'b'",
        "'hello' + 42",
        "42 + 'hello'",
        "`prefix` + unknown",
    ] {
        assert_type(code, "string");
    }
}

// Unary expressions

#[test]
fn infers_number_for_numeric_unary_expressions() {
    for code in ["+x", "-x", "~x"] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_boolean_for_negation() {
    for code in ["!x", "!true"] {
        assert_type(code, "boolean");
    }
}

#[test]
fn infers_string_for_typeof() {
    for code in ["typeof x", "typeof 42"] {
        assert_type(code, "string");
    }
}

#[test]
fn infers_undefined_for_void() {
    for code in ["void 0", "void x"] {
        assert_type(code, "undefined");
    }
}

// Update expressions

#[test]
fn infers_number_for_update_expressions() {
    for code in ["i++", "++i", "i--", "--i"] {
        assert_type(code, "number");
    }
}

// Member expressions (properties)

#[test]
fn infers_number_for_length_on_known_receivers() {
    for code in ["[].length", "'hello'.length", "[1, 2, 3].length"] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_number_for_size_on_map_and_set() {
    for code in ["new Map().size", "new Set().size"] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_unknown_for_length_and_size_on_unknown_receiver() {
    for code in ["unknownObj.length", "unknownObj.size"] {
        assert_type(code, "unknown");
    }
}

// Typed instance properties (via INSTANCE_PROPERTIES registry)

#[test]
fn infers_message_port_for_message_channel_ports() {
    for code in ["new MessageChannel().port1", "new MessageChannel().port2"] {
        assert_type(code, "MessagePort");
    }
}

#[test]
fn infers_response_typed_properties() {
    assert_type("new Response().status", "number");
    for code in [
        "new Response().ok",
        "new Response().redirected",
        "new Response().bodyUsed",
    ] {
        assert_type(code, "boolean");
    }
    for code in ["new Response().url", "new Response().statusText"] {
        assert_type(code, "string");
    }
}

// Static method calls

#[test]
fn infers_number_for_math_methods() {
    for code in [
        "Math.random()",
        "Math.floor(3.7)",
        "Math.ceil(2.1)",
        "Math.round(4.5)",
        "Math.max(1, 2, 3)",
        "Math.min(1, 2)",
        "Math.abs(-5)",
        "Math.sqrt(16)",
        "Math.pow(2, 10)",
        "Math.trunc(3.9)",
    ] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_number_for_date_static_methods() {
    for code in ["Date.now()", "Date.parse('2026-01-01')"] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_boolean_for_number_static_methods() {
    for code in [
        "Number.isFinite(42)",
        "Number.isNaN(NaN)",
        "Number.isInteger(3)",
        "Number.isSafeInteger(42)",
    ] {
        assert_type(code, "boolean");
    }
}

#[test]
fn infers_number_for_number_parse_methods() {
    for code in ["Number.parseInt('42')", "Number.parseFloat('3.14')"] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_json_methods() {
    assert_type("JSON.stringify({ a: 1 })", "string");
    assert_type("JSON.parse('{}')", "unknown");
}

#[test]
fn infers_object_static_methods() {
    assert_type("Object.keys(obj)", "Array");
    assert_type("Object.is(a, b)", "boolean");
}

#[test]
fn infers_boolean_for_array_is_array() {
    assert_type("Array.isArray(x)", "boolean");
}

// Instance method calls

#[test]
fn infers_string_for_string_instance_methods() {
    for code in [
        "'hello'.toLowerCase()",
        "'hello'.toUpperCase()",
        "'hello'.trim()",
        "'hello'.trimStart()",
        "'hello'.trimEnd()",
        "'hello'.substring(0, 3)",
        "'hello'.slice(1)",
        "'hello'.charAt(0)",
        "'hello'.replace('h', 'H')",
        "'hello'.replaceAll('l', 'L')",
        "'hello'.concat(' world')",
        "'hello'.padStart(10, '*')",
        "'hello'.padEnd(10, '*')",
        "'hello'.repeat(3)",
        "'hello'.normalize()",
        "'hello'.toString()",
    ] {
        assert_type(code, "string");
    }
}

#[test]
fn infers_number_for_string_instance_methods() {
    for code in [
        "'hello'.indexOf('l')",
        "'hello'.lastIndexOf('l')",
        "'hello'.search(/l/)",
        "'hello'.charCodeAt(0)",
        "'hello'.codePointAt(0)",
    ] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_boolean_for_string_instance_methods() {
    for code in [
        "'hello'.includes('ell')",
        "'hello'.startsWith('hel')",
        "'hello'.endsWith('lo')",
    ] {
        assert_type(code, "boolean");
    }
}

#[test]
fn infers_string_for_number_instance_methods() {
    for code in [
        "(42).toFixed(2)",
        "(42).toPrecision(4)",
        "(42).toExponential()",
        "(42).toString()",
        "(42).toLocaleString()",
    ] {
        assert_type(code, "string");
    }
}

#[test]
fn infers_number_for_date_instance_methods() {
    for code in [
        "new Date().getTime()",
        "new Date().getFullYear()",
        "new Date().getMonth()",
        "new Date().getDate()",
        "new Date().getDay()",
        "new Date().getHours()",
        "new Date().getMinutes()",
        "new Date().getSeconds()",
        "new Date().getMilliseconds()",
        "new Date().valueOf()",
    ] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_string_for_date_instance_methods() {
    for code in [
        "new Date().toISOString()",
        "new Date().toDateString()",
        "new Date().toTimeString()",
        "new Date().toLocaleString()",
        "new Date().toLocaleDateString()",
        "new Date().toLocaleTimeString()",
        "new Date().toString()",
    ] {
        assert_type(code, "string");
    }
}

#[test]
fn infers_regexp_instance_methods() {
    assert_type("/test/.test('testing')", "boolean");
    assert_type("/test/.toString()", "string");
    assert_type("/test/.exec('testing')", "unknown");
}

#[test]
fn infers_undefined_for_message_port_methods() {
    for code in [
        "new MessageChannel().port1.postMessage('hi')",
        "new MessageChannel().port1.start()",
        "new MessageChannel().port1.close()",
    ] {
        assert_type(code, "undefined");
    }
}

#[test]
fn infers_unknown_for_response_body_methods() {
    for code in [
        "new Response().json()",
        "new Response().text()",
        "new Response().blob()",
        "new Response().arrayBuffer()",
        "new Response().formData()",
    ] {
        assert_type(code, "unknown");
    }
}

#[test]
fn infers_string_for_response_to_string() {
    assert_type("new Response().toString()", "string");
}

#[test]
fn infers_number_for_array_instance_methods() {
    for code in [
        "[].push(1)",
        "[].indexOf(1)",
        "[].lastIndexOf(1)",
        "[].findIndex(x => x === 1)",
    ] {
        assert_type(code, "number");
    }
}

#[test]
fn infers_boolean_for_array_instance_methods() {
    for code in [
        "[1,2].includes(1)",
        "[1,2].every(x => x > 0)",
        "[1,2].some(x => x > 0)",
    ] {
        assert_type(code, "boolean");
    }
}

#[test]
fn infers_string_for_array_join() {
    assert_type("[1,2,3].join(',')", "string");
}

// Variable resolution

#[test]
fn resolves_const_number() {
    assert_type("const x = 42; x", "number");
}

#[test]
fn resolves_const_string() {
    assert_type(r#"const s = "hello"; s"#, "string");
}

#[test]
fn resolves_chained_const() {
    assert_type("const a = 1; const b = a; b", "number");
}

#[test]
fn resolves_const_date() {
    assert_type("const d = new Date(); d", "Date");
}

#[test]
fn resolves_const_plus_arithmetic() {
    assert_type("const x = 10; const y = 20; x + y", "number");
}

#[test]
fn returns_unknown_for_non_constant_let() {
    assert_type(r#"let x = "safe"; x = getInput(); x"#, "unknown");
}

// Conditional / ternary

#[test]
fn returns_type_when_both_ternary_branches_match() {
    assert_type("true ? 1 : 2", "number");
}

#[test]
fn returns_unknown_when_ternary_branches_differ() {
    assert_type("true ? 1 : 'x'", "unknown");
}

// Logical expressions

#[test]
fn returns_type_when_both_logical_sides_match() {
    assert_type("1 || 2", "number");
}

#[test]
fn returns_unknown_when_logical_sides_differ() {
    assert_type("1 || 'x'", "unknown");
}

// Edge cases

#[test]
fn handles_sequence_expression() {
    assert_type("(1, 2, 'hello')", "string");
}

#[test]
fn handles_method_on_inferred_variable_type() {
    assert_type(r#"const s = "hello"; s.toUpperCase()"#, "string");
}

#[test]
fn handles_chained_method_calls() {
    assert_type(r#""hello".trim().toLowerCase()"#, "string");
}

#[test]
fn handles_computed_method_call_with_string_literal() {
    assert_type(r#""hello"["toLowerCase"]()"#, "string");
}

#[test]
fn handles_to_string_on_unknown() {
    assert_type("x.toString()", "string");
}

// Discriminant-property-usage-based inference

#[test]
fn infers_message_channel_when_port1_is_accessed() {
    assert_type(
        "const obj = createUnknownFactory(); obj.port1; obj",
        "MessageChannel",
    );
}

#[test]
fn infers_message_channel_when_port2_is_accessed() {
    assert_type(
        "const obj = createUnknownFactory(); obj.port2; obj",
        "MessageChannel",
    );
}

#[test]
fn infers_xml_http_request_when_response_text_is_accessed() {
    assert_type(
        "const obj = createXhr(); obj.responseText; obj",
        "XMLHttpRequest",
    );
}

#[test]
fn infers_xml_http_request_when_get_all_response_headers_is_called() {
    assert_type(
        "const obj = createXhr(); obj.getAllResponseHeaders(); obj",
        "XMLHttpRequest",
    );
}

#[test]
fn infers_regexp_when_dot_all_is_accessed() {
    assert_type("const obj = buildPattern(); obj.dotAll; obj", "RegExp");
}

#[test]
fn infers_date_when_get_time_is_called() {
    assert_type("const obj = getTimestamp(); obj.getTime(); obj", "Date");
}

#[test]
fn infers_date_when_to_iso_string_is_called() {
    assert_type("const obj = parseDate(raw); obj.toISOString(); obj", "Date");
}

#[test]
fn infers_url_when_search_params_is_accessed() {
    assert_type("const obj = parseUrl(input); obj.searchParams; obj", "URL");
}

#[test]
fn infers_response_when_body_used_is_accessed() {
    assert_type("const obj = getResponse(); obj.bodyUsed; obj", "Response");
}

#[test]
fn still_returns_unknown_when_no_discriminant_property_is_accessed() {
    assert_type(
        "const obj = createUnknownFactory(); obj.someRandomProp; obj",
        "unknown",
    );
}

#[test]
fn works_for_function_parameters_non_constant_bindings() {
    assert_type(
        "const ch = getChannel(); ch.port1.postMessage('x'); ch",
        "MessageChannel",
    );
}
