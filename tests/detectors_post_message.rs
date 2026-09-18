//! Port of `packages/vscode-ext/test/detectors/postMessage.test.ts`.

mod common;
use common::count_detector;

const D: &str = "postMessage";

// addEventListener("message", ...)

#[test]
fn detects_unchecked_inline_message_handler() {
    let code = r#"
        window.addEventListener("message", function(event) {
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_unchecked_inline_message_handler_without_window() {
    let code = r#"
        addEventListener("message", function(event) {
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_unchecked_arrow_message_handler() {
    let code = r#"
        window.addEventListener("message", (e) => {
            console.log(e.data);
        });
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_unchecked_arrow_message_handler_without_window() {
    let code = r#"
        addEventListener("message", (e) => {
            console.log(e.data);
        });
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_global_style_handler_without_window_when_origin_is_checked() {
    let code = r#"
        addEventListener("message", (event) => {
            if (event.origin !== "https://trusted.com") return;
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_shadowed_local_add_event_listener() {
    let code = r#"
        function addEventListener(name, handler) {
            return registerCustom(name, handler);
        }

        addEventListener("message", (event) => {
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_shadowed_local_onmessage_identifier_assignment() {
    let code = r#"
        function demo() {
            let onmessage;
            onmessage = (event) => {
                document.body.innerHTML = event.data;
            };
        }
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_handler_that_checks_event_origin_with_strict_eq() {
    let code = r#"
        window.addEventListener("message", function(event) {
            if (event.origin === "https://trusted.com") {
                document.body.innerHTML = event.data;
            }
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_handler_that_checks_event_origin_with_strict_neq() {
    let code = r#"
        window.addEventListener("message", function(event) {
            if (event.origin !== "https://trusted.com") return;
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_handler_that_checks_event_source() {
    let code = r#"
        window.addEventListener("message", function(event) {
            if (event.source === window.parent) {
                handleData(event.data);
            }
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_handler_with_origin_check_using_includes() {
    let code = r#"
        window.addEventListener("message", function(event) {
            if (allowedOrigins.includes(event.origin)) {
                handleData(event.data);
            }
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_handler_with_origin_check_using_starts_with() {
    let code = r#"
        window.addEventListener("message", function(event) {
            if (event.origin.startsWith("https://trusted")) {
                handleData(event.data);
            }
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_unchecked_handler_passed_by_reference() {
    let code = r#"
        function handleMessage(event) {
            document.body.innerHTML = event.data;
        }
        window.addEventListener("message", handleMessage);
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_handler_by_reference_that_checks_origin() {
    let code = r#"
        function handleMessage(event) {
            if (event.origin === "https://trusted.com") {
                document.body.innerHTML = event.data;
            }
        }
        window.addEventListener("message", handleMessage);
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_non_message_event_listener() {
    let code = r#"
        window.addEventListener("click", function(event) {
            console.log("clicked");
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_handler_with_no_parameters() {
    let code = r#"
        window.addEventListener("message", function() {
            doSomething();
        });
    "#;
    assert_eq!(count_detector(code, D), 1);
}

// onmessage assignment

#[test]
fn detects_unchecked_onmessage_assignment() {
    let code = r#"
        window.onmessage = function(event) {
            document.body.innerHTML = event.data;
        };
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_unchecked_bare_global_onmessage_assignment() {
    let code = r#"
        onmessage = function(event) {
            document.body.innerHTML = event.data;
        };
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_onmessage_with_origin_check() {
    let code = r#"
        window.onmessage = function(event) {
            if (event.origin === "https://trusted.com") {
                handleData(event.data);
            }
        };
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_checked_bare_global_onmessage_assignment() {
    let code = r#"
        onmessage = function(event) {
            if (event.origin !== "https://trusted.com") return;
            handleData(event.data);
        };
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn detects_unchecked_arrow_onmessage() {
    let code = r#"
        self.onmessage = (e) => {
            postMessage(e.data);
        };
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn detects_onmessage_with_reference_to_unchecked_function() {
    let code = r#"
        const handler = function(event) {
            eval(event.data);
        };
        window.onmessage = handler;
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_onmessage_with_reference_to_checked_function() {
    let code = r#"
        const handler = function(event) {
            if (event.origin === "https://example.com") {
                eval(event.data);
            }
        };
        window.onmessage = handler;
    "#;
    assert_eq!(count_detector(code, D), 0);
}

// Switch on origin

#[test]
fn ignores_handler_with_switch_on_event_origin() {
    let code = r#"
        window.addEventListener("message", function(event) {
            switch (event.origin) {
                case "https://a.com":
                    handleA(event.data);
                    break;
                case "https://b.com":
                    handleB(event.data);
                    break;
            }
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

// Logical expressions

#[test]
fn ignores_handler_with_logical_and_origin_check() {
    let code = r#"
        window.addEventListener("message", function(event) {
            if (event.origin === "https://trusted.com" && event.data) {
                handleData(event.data);
            }
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

// Destructured event parameter

#[test]
fn detects_handler_with_destructured_parameter() {
    let code = r#"
        window.addEventListener("message", function({ data }) {
            document.body.innerHTML = data;
        });
    "#;
    assert_eq!(count_detector(code, D), 1);
}

// Multiple listeners

#[test]
fn detects_multiple_unchecked_listeners_when_target_type_is_not_proven_safe() {
    let code = r#"
        window.addEventListener("message", (e) => {
            console.log(e.data);
        });
        document.addEventListener("message", (e) => {
            eval(e.data);
        });
    "#;
    assert_eq!(count_detector(code, D), 2);
}

#[test]
fn detects_only_unchecked_among_mixed_listeners() {
    let code = r#"
        window.addEventListener("message", (e) => {
            if (e.origin === "https://safe.com") handleData(e.data);
        });
        window.addEventListener("message", (e) => {
            eval(e.data);
        });
    "#;
    assert_eq!(count_detector(code, D), 1);
}

#[test]
fn ignores_onmessage_null_cleanup() {
    assert_eq!(count_detector("this.onmessage = null;", D), 0);
    assert_eq!(count_detector("window.onmessage = null;", D), 0);
}

#[test]
fn ignores_onmessage_undefined() {
    assert_eq!(count_detector("window.onmessage = undefined;", D), 0);
}

#[test]
fn ignores_onmessage_literal_value() {
    assert_eq!(count_detector("self.onmessage = 0;", D), 0);
}

#[test]
fn ignores_worker_message_listener() {
    let code = r#"
        const worker = new Worker("worker.js");
        worker.addEventListener("message", (event) => {
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_web_socket_message_listener() {
    let code = r#"
        const socket = new WebSocket("wss://example.com");
        socket.addEventListener("message", (event) => {
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_broadcast_channel_message_listener() {
    let code = r#"
        const channel = new BroadcastChannel("updates");
        channel.addEventListener("message", (event) => {
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_message_channel_port1_onmessage_assignment() {
    let code = r#"
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => {
            document.body.innerHTML = event.data;
        };
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_message_channel_port2_add_event_listener() {
    let code = r#"
        const channel = new MessageChannel();
        channel.port2.addEventListener("message", (event) => {
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_message_port_stored_in_a_variable() {
    let code = r#"
        const channel = new MessageChannel();
        const port = channel.port1;
        port.addEventListener("message", (event) => {
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_message_channel_port_aliases_resolved_from_assignments() {
    let code = r#"
        var pe = (M = new MessageChannel()).port2;
        M.port1.onmessage = fe;
        pe.onmessage = function(event) {
            document.body.innerHTML = event.data;
        };
    "#;
    assert_eq!(count_detector(code, D), 0);
}

#[test]
fn ignores_non_window_onmessage_assignments() {
    let code = r#"
        const socket = new WebSocket("wss://example.com");
        socket.onmessage = (event) => {
            document.body.innerHTML = event.data;
        };
    "#;
    assert_eq!(count_detector(code, D), 0);
}
