mod common;
use common::{category_for, count_detector, total_matches};
use sinksight_engine::ctx::Category;

#[test]
fn detects_unsafe_html_in_a_class_method_with_loops() {
    let code = r#"
        class TableRenderer {
            constructor(data) {
                this.data = data;
            }
            render() {
                let html = "<table>";
                for (let i = 0; i < this.data.length; i++) {
                    html += "<tr>";
                    for (let key in this.data[i]) {
                        // Unsafe concatenation
                        html += "<td>" + this.data[i][key] + "</td>";
                    }
                    html += "</tr>";
                }
                html += "</table>";
                document.getElementById("table-container").innerHTML = html;
            }
        }
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn ignores_safe_html_generation_using_dom_apis_and_safe_strings() {
    let code = r#"
        function buildSafeList(items) {
            const ul = document.createElement("ul");
            let safeHtml = "";
            items.forEach(item => {
                const li = document.createElement("li");
                li.textContent = item.name;
                ul.appendChild(li);

                // Safe string concatenation
                safeHtml += "<li class='item'>Safe</li>";
            });

            const container = document.querySelector(".container");
            container.innerHTML = safeHtml;
            container.appendChild(ul);
        }
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 0);
}

#[test]
fn detects_eval_hidden_in_a_deeply_nested_function() {
    let code = r#"
        const executePlugin = (pluginCode) => {
            function run() {
                const context = { window: null, document: null };
                return function() {
                    try {
                        // Dangerous eval
                        const result = eval(pluginCode);
                        return result;
                    } catch (e) {
                        console.error(e);
                    }
                }
            }
            return run()();
        };
    "#;
    assert_eq!(count_detector(code, "eval"), 1);
}

#[test]
fn ignores_eval_with_safe_static_string() {
    let code = r#"
        class MathEvaluator {
            static evaluate() {
                const expression = "2 + 2 * 3";
                // Safe eval because expression is static
                return eval(expression);
            }
        }
    "#;
    assert_eq!(count_detector(code, "eval"), 0);
}

#[test]
fn detects_unsafe_timers_with_dynamic_string_arguments() {
    let code = r#"
        function scheduleTask(taskName, delay) {
            // Unsafe because it's a string concatenation
            const command = "console.log('" + taskName + "')";

            setTimeout(command, delay);
            setInterval(command, delay * 2);
        }
    "#;
    assert_eq!(count_detector(code, "unsafeTimers"), 2);
}

#[test]
fn ignores_safe_timers_with_function_callbacks() {
    let code = r#"
        class TaskScheduler {
            schedule(callback, delay) {
                // Safe because callback is passed as a function, not a string
                setTimeout(callback, delay);
                setInterval(() => {
                    callback();
                }, delay * 2);
            }
        }
    "#;
    assert_eq!(count_detector(code, "unsafeTimers"), 0);
}

#[test]
fn detects_function_constructor_with_dynamic_body() {
    let code = r#"
        class ExpressionEvaluator {
            evaluate(expression, context) {
                const keys = Object.keys(context);
                const values = Object.values(context);

                // Unsafe Function constructor
                const fn = new Function(...keys, "return " + expression);
                return fn(...values);
            }
        }
    "#;
    assert_eq!(count_detector(code, "functionConstructor"), 1);
}

#[test]
fn ignores_function_constructor_with_safe_static_body() {
    let code = r#"
        function createSafeMultiplier(factor) {
            // Safe because the body is a static string
            const fn = new Function("a", "b", "return a * b");
            return fn(factor, 2);
        }
    "#;
    assert_eq!(count_detector(code, "functionConstructor"), 0);
}

#[test]
fn detects_javascript_links_in_dynamic_anchor_creation() {
    let code = r#"
        function createMenu(links) {
            const menu = document.createElement("nav");
            for (const link of links) {
                const a = document.createElement("a");
                a.textContent = link.label;

                if (link.isAction) {
                    // Unsafe javascript: link assignment
                    a.href = "javascript:" + link.action;
                } else {
                    // Safe because it has a safe prefix
                    a.href = "https://example.com/" + link.url;
                }

                menu.appendChild(a);
            }
            return menu;
        }
    "#;
    assert_eq!(count_detector(code, "javascriptLinks"), 1);
}

#[test]
fn ignores_string_concatenated_from_only_safe_parts() {
    let code = r#"
        const scheme = "https://";
        const domain = String("example.com");
        const port = 8080;
        const base = scheme.concat(domain, ":", port);
        function setLink(path) {
            const link = document.querySelector("a");
            const safePath = encodeURIComponent(path);
            link.outerHTML = `<a href="${base}/${safePath}">Click me</a>`;
            return link;
        }
    "#;
    assert_eq!(total_matches(code), 0);
}

#[test]
fn detects_string_concatenated_from_at_least_1_unsafe_part() {
    let code = r#"
        const scheme = getScheme(); // unknown value
        const domain = String("example.com");
        const port = 8080;
        const base = scheme.concat(domain, ":", port);
        function setLink(path) {
            const link = document.querySelector("a");
            const safePath = encodeURIComponent(path);
            link.outerHTML = `<a href="${base}/${safePath}">Click me</a>`;
            return link;
        }
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn ignores_javascript_link_concatenated_from_only_safe_parts() {
    let code = r#"
        const scheme = "javascript:";
        const action = String("void(0)");
        const payload = scheme.concat(action);
        function setLink() {
            const link = document.querySelector("a");
            link.href = payload;
            return link;
        }
    "#;
    assert_eq!(total_matches(code), 0);
}

#[test]
fn detects_javascript_link_concatenated_from_at_least_1_unsafe_part() {
    let code = r#"
        const scheme = "javascript:";
        const action = getAction(); // unknown value
        const payload = scheme.concat(action);
        function setLink() {
            const link = document.querySelector("a");
            link.href = payload;
            return link;
        }
    "#;
    assert_eq!(count_detector(code, "javascriptLinks"), 1);
}

#[test]
fn detects_document_write_with_dynamic_content() {
    let code = r#"
        function renderPage(userInput) {
            document.write("<h1>Hello " + userInput + "</h1>");
        }
    "#;
    assert_eq!(count_detector(code, "documentWrite"), 1);
}

#[test]
fn ignores_document_write_with_safe_static_content() {
    let code = r#"
        function renderHeader() {
            const title = "Welcome";
            document.write("<h1>" + title + "</h1>");
        }
    "#;
    assert_eq!(total_matches(code), 0);
}

#[test]
fn detects_insert_adjacent_html_with_dynamic_content() {
    let code = r#"
        class Widget {
            append(container, htmlContent) {
                container.insertAdjacentHTML('beforeend', htmlContent);
            }
        }
    "#;
    assert_eq!(count_detector(code, "insertAdjacentHtml"), 1);
}

#[test]
fn ignores_insert_adjacent_html_with_safe_static_content() {
    let code = r#"
        class Widget {
            append(container) {
                const template = "<div class='widget'></div>";
                container.insertAdjacentHTML('beforeend', template);
            }
        }
    "#;
    assert_eq!(total_matches(code), 0);
}

#[test]
fn ignores_static_iife_with_string_literal_argument() {
    let code = r#"
        (function (d, t, j, a) {
            s = d.createElement('script');
            s.src = t + j + a;
            d.body.appendChild(s);
            i = d.createElement('img');
            i.src = unknown;
        })(document, 'https://static.hotjar.com/c/hotjar-', '.js?sv=', 1);
    "#;
    assert_eq!(total_matches(code), 0);
}

#[test]
fn detects_iife_with_dynamic_argument_leading_to_unsafe_javascript_link() {
    let code = r#"
        const win = window;
        (function (w) {
            w.open(unknown);
        })(win);
    "#;
    assert_eq!(count_detector(code, "javascriptLinks"), 1);
}

#[test]
fn handles_chained_assignments_with_safe_implicit_globals() {
    let code = r#"
        (function(d) {
            a = b = d.createElement('script');
            b.src = 'https://safe.com';
        })(document);
    "#;
    assert_eq!(total_matches(code), 0);
}

#[test]
fn gracefully_handles_deeply_nested_iifes_passing_safe_arguments() {
    let code = r#"
        (function(doc) {
            (function(d, url) {
                const s = d.createElement('script');
                s.src = url;
            })(doc, 'https://safe-url.com');
        })(document);
    "#;
    assert_eq!(total_matches(code), 0);
}

#[test]
fn detects_unsafe_payload_mixed_with_logical_operators() {
    let code = r#"
        function render(input) {
            // If input is controlled, this is an XSS vector
            document.body.innerHTML = input || "<b>safe fallback</b>";
        }
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn detects_re_assigning_known_safe_variable_to_something_dangerous() {
    let code = r#"
        let safeHtml = "<b>Safe!</b>";
        safeHtml = getUnsafe(); // now it's tainted
        document.body.innerHTML = safeHtml;
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn handles_destructured_document_references_by_gracefully_failing_safe() {
    let code = r#"
        (function({createElement}, url) {
            const s = createElement('script');
            s.src = url;
        })(document, getUnknownUrl());
    "#;
    // Because destructuring parameters might not be statically tracked yet,
    // the tag is unknown and `src` is treated as a resource URL (worst case).
    assert_eq!(count_detector(code, "resourceUrl"), 1);
}

#[test]
fn handles_logical_and_assignment() {
    let code = r#"
        let html = "<b>initial</b>";
        html &&= getUnsafeData();
        document.body.insertAdjacentHTML('beforeend', html);
    "#;
    assert_eq!(count_detector(code, "insertAdjacentHtml"), 1);
}

#[test]
fn detects_eval_hidden_via_alias() {
    let code = r#"
        const myEval = eval;
        myEval(userInput);
    "#;
    assert_eq!(count_detector(code, "eval"), 1);
}

// Computed member keys built through string concatenation are not implemented.
#[test]
#[ignore = "computed member access via concatenated property name is not implemented"]
fn detects_eval_hidden_via_member_syntax_with_concatenation() {
    let code = r#"
        const prop = 'ev' + 'al';
        window[prop](userInput);
    "#;
    assert_eq!(count_detector(code, "eval"), 1);
}

#[test]
fn detects_settimeout_hidden_via_alias() {
    let code = r#"
        const myTimeout = setTimeout;
        myTimeout("console.log(" + userInput + ")", 1000);
    "#;
    assert_eq!(count_detector(code, "unsafeTimers"), 1);
}

// Same computed-property-name limitation as the eval alias case above, applied to `el[p] = userInput` where
// `p = 'inner' + 'HTML'`.
#[test]
#[ignore = "computed member access via concatenated property name is not implemented"]
fn detects_inner_html_with_concatenated_property_name() {
    let code = r#"
        const el = document.createElement("div");
        const p = 'inner' + 'HTML';
        el[p] = userInput;
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

// Detecting `document.write` reached via `Function.prototype.call`/`apply`
// is not implemented.
#[test]
#[ignore = "document.write via call()/apply() is not implemented"]
fn detects_document_write_via_function_apply_call() {
    let code = r#"
        const w = document.write;
        w.call(document, userInput);
    "#;
    assert_eq!(count_detector(code, "documentWrite"), 1);
}

// createObjectUrl complex cases

#[test]
fn detects_create_object_url_with_user_controlled_blob_content_in_a_class() {
    let code = r#"
        class FileUploader {
            preview(file) {
                const blob = new Blob([file.content], { type: "text/html" });
                const url = URL.createObjectURL(blob);
                document.querySelector("iframe").src = url;
            }
        }
    "#;
    assert_eq!(count_detector(code, "createObjectUrl"), 1);
}

#[test]
fn ignores_create_object_url_with_static_blob_in_a_helper_function() {
    let code = r#"
        function createDownload() {
            const csv = "name,age\nAlice,30\nBob,25";
            const blob = new Blob([csv], { type: "text/csv" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "export.csv";
            a.click();
        }
    "#;
    assert_eq!(count_detector(code, "createObjectUrl"), 0);
}

#[test]
fn detects_create_object_url_with_dynamic_content_but_no_mime_type() {
    let code = r#"
        function createPreview(htmlContent) {
            const blob = new Blob([htmlContent]);
            return URL.createObjectURL(blob);
        }
    "#;
    assert_eq!(count_detector(code, "createObjectUrl"), 1);
}

#[test]
fn ignores_create_object_url_with_dynamic_content_and_safe_mime_type() {
    let code = r#"
        function exportData(data) {
            const json = JSON.stringify(data);
            const blob = new Blob([json], { type: "application/json" });
            return URL.createObjectURL(blob);
        }
    "#;
    assert_eq!(count_detector(code, "createObjectUrl"), 0);
}

#[test]
fn detects_create_object_url_with_svg_mime_type_and_dynamic_content() {
    let code = r#"
        class SvgRenderer {
            render(svgContent) {
                const blob = new Blob([svgContent], { type: "image/svg+xml" });
                const url = URL.createObjectURL(blob);
                const img = document.createElement("img");
                img.src = url;
                return img;
            }
        }
    "#;
    assert_eq!(count_detector(code, "createObjectUrl"), 1);
}

#[test]
fn detects_create_object_url_with_unknown_variable_not_a_blob_constructor() {
    let code = r#"
        function previewFile(file) {
            // file could be anything — we can't prove it's safe
            const url = URL.createObjectURL(file);
            window.open(url);
        }
    "#;
    assert_eq!(count_detector(code, "createObjectUrl"), 1);
}

#[test]
fn ignores_create_object_url_with_safe_mime_type_resolved_from_a_variable() {
    let code = r#"
        function download(data) {
            const mime = "text/plain";
            const options = { type: mime };
            const blob = new Blob([data], options);
            return URL.createObjectURL(blob);
        }
    "#;
    assert_eq!(count_detector(code, "createObjectUrl"), 0);
}

#[test]
fn detects_create_object_url_when_mime_type_is_dynamic() {
    let code = r#"
        function createBlob(data, userMimeType) {
            const blob = new Blob([data], { type: userMimeType });
            return URL.createObjectURL(blob);
        }
    "#;
    assert_eq!(count_detector(code, "createObjectUrl"), 1);
}

// Input source complex cases

#[test]
fn detects_url_param_access_flowing_into_inner_html() {
    let code = r#"
        function renderSearch() {
            const params = new URLSearchParams(location.search);
            const query = params.get("q");
            document.getElementById("results").innerHTML = "<h1>" + query + "</h1>";
        }
    "#;
    assert!(count_detector(code, "urlParams") >= 1);
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn detects_unchecked_postmessage_handler_writing_to_dom() {
    let code = r#"
        window.addEventListener("message", function(event) {
            document.body.innerHTML = event.data.html;
        });
    "#;
    assert_eq!(count_detector(code, "postMessage"), 1);
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn does_not_flag_postmessage_with_thorough_origin_validation() {
    let code = r#"
        const ALLOWED = ["https://a.com", "https://b.com"];
        window.addEventListener("message", function(event) {
            if (!ALLOWED.includes(event.origin)) return;
            const { action, payload } = event.data;
            if (action === "render") {
                document.body.innerHTML = payload;
            }
        });
    "#;
    assert_eq!(count_detector(code, "postMessage"), 0);
}

#[test]
fn detects_window_name_used_in_eval() {
    let code = r#"
        function loadConfig() {
            const config = JSON.parse(window.name);
            eval(config.code);
        }
    "#;
    assert_eq!(count_detector(code, "windowName"), 1);
    assert_eq!(count_detector(code, "eval"), 1);
}

#[test]
fn detects_document_referrer_in_location_assignment() {
    let code = r#"
        function trackReferrer() {
            const ref = document.referrer;
            location.href = "javascript:" + ref;
        }
    "#;
    assert_eq!(count_detector(code, "documentReferrer"), 1);
    assert_eq!(count_detector(code, "javascriptLinks"), 1);
}

#[test]
fn detects_multiple_input_sources_in_a_single_function() {
    let code = r#"
        function gatherInputs() {
            const params = new URLSearchParams(location.search);
            const name = window.name;
            const ref = document.referrer;
            process(params, name, ref);
        }
    "#;
    assert_eq!(count_detector(code, "urlParams"), 1);
    assert_eq!(count_detector(code, "windowName"), 1);
    assert_eq!(count_detector(code, "documentReferrer"), 1);
}

#[test]
fn detects_input_sources_have_category_input() {
    let code = r#"
        const params = new URLSearchParams(location.search);
        document.body.innerHTML = params.get("q");
    "#;
    assert_eq!(category_for(code, "urlParams"), Some(Category::Input));
    assert_eq!(category_for(code, "unsafeHtml"), Some(Category::Sink));
}

#[test]
fn detects_usage_of_location_href_in_inner_html() {
    let code = r#"
        foo.innerHTML = location.href;
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn ignores_create_object_url_when_mimetype_is_text_css() {
    let code = r#"
        function C(e, t, r) {
            var n = r.css,
              o = r.sourceMap,
              i = void 0 === t.convertToAbsoluteUrls && o;
            (t.convertToAbsoluteUrls || i) && (n = p(n)), o && (n += "\n/*# sourceMappingURL=data:application/json;base64," + btoa(unescape(encodeURIComponent(JSON.stringify(o)))) + " */");
            var a = new Blob([n], {
                type: "text/css"
              }),
              s = e.href;
            e.href = URL.createObjectURL(a), s && URL.revokeObjectURL(s);
          }
    "#;
    assert_eq!(count_detector(code, "createObjectUrl"), 0);
}

#[test]
fn detects_json_deserialized_content_flowing_into_inner_html() {
    let code = r#"
        const urlParams = new URLSearchParams(location.search);
        const data = JSON.parse(urlParams.get("data"));
        document.getElementById("output").innerHTML = data.length;
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn detects_user_controlled_regex_in_inner_html_assignment() {
    let code = r#"
        function render(input) {
            const regex = new RegExp(input);
            document.body.innerHTML = regex.toString();
        }
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn ignores_static_regex_literal_used_with_to_string_in_inner_html() {
    let code = r#"
        const pattern = /safe-literal/gi;
        document.body.innerHTML = pattern.toString();
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 0);
}

#[test]
fn ignores_response_ok_and_status_used_in_inner_html() {
    let code = r#"
        const response = new Response();
        document.getElementById("status").innerHTML = response.ok;
        document.getElementById("code").innerHTML = response.status;
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 0);
}

#[test]
fn detects_response_text_result_flowing_into_inner_html() {
    let code = r#"
        fetch("/api").then(r => r.text()).then(html => {
            document.body.innerHTML = html;
        });
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn detects_xhr_response_text_from_opaque_factory_flowing_into_inner_html() {
    let code = r#"
        function loadAndRender(url) {
            const xhr = createXHR();
            xhr.open('GET', url, false);
            xhr.send();
            document.getElementById('output').innerHTML = xhr.responseText;
        }
    "#;
    assert_eq!(count_detector(code, "unsafeHtml"), 1);
}

#[test]
fn ignores_message_channel_port_listener_created_via_opaque_factory() {
    let code = r#"
        const channel = createChannel();
        channel.port1.addEventListener("message", function(event) {
            document.body.innerHTML = event.data;
        });
    "#;
    assert_eq!(count_detector(code, "postMessage"), 0);
}
