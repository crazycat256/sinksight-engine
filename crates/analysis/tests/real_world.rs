//! Downloads real-world minified libraries from a CDN, verifies their
//! integrity via SRI, and asserts the exact set of (detector, line, column)
//! findings `analyze` produces.
//!
//! Downloaded content is cached under `tests/fixtures/.cache/` (verified
//! against the pinned SRI hash on every read) so repeat runs and
//! network-restricted environments don't need to re-download anything once
//! the cache has been populated once.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use sha2::{Digest, Sha256};

use sinksight_analysis::analyze;

struct ExpectedFinding {
    detector: &'static str,
    line: u32,
    column: u32,
}

struct Target {
    name: &'static str,
    url: &'static str,
    sri: &'static str,
    expected_findings: &'static [ExpectedFinding],
}

macro_rules! ef {
    ($detector:literal, $line:literal, $column:literal) => {
        ExpectedFinding {
            detector: $detector,
            line: $line,
            column: $column,
        }
    };
}

const ALPINE: Target = Target {
    name: "alpine.min.js",
    url: "https://unpkg.com/alpinejs@3.13.5/dist/cdn.min.js",
    sri: "sha256-ygV4Me+b49juR+FAeAif0jgdx4ILS7f724WkkPW49ow=",
    expected_findings: &[ef!("unsafeHtml", 5, 30955)],
};

const ANGULAR: Target = Target {
    name: "angular.min.js",
    url: "https://unpkg.com/angular@1.8.3/angular.min.js",
    sri: "sha256-OW3BoD1swC6cUagCRuDbU8XI35vQcofjtRvOSinas1U=",
    expected_findings: &[
        ef!("functionConstructor", 253, 163),
        ef!("javascriptLinks", 51, 136),
        ef!("javascriptLinks", 127, 311),
        ef!("javascriptLinks", 172, 494),
        ef!("javascriptLinks", 173, 14),
        ef!("javascriptLinks", 206, 337),
        ef!("resourceUrl", 112, 67),
        ef!("unsafeHtml", 33, 283),
        ef!("unsafeHtml", 33, 435),
        ef!("unsafeHtml", 64, 38),
        ef!("unsafeHtml", 86, 391),
        ef!("unsafeHtml", 212, 168),
    ],
};

const BOOTSTRAP: Target = Target {
    name: "bootstrap.bundle.min.js",
    url: "https://unpkg.com/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js",
    sri: "sha256-CDOy6cOibCWEdsRiZuaHf8dSGGJRYuBGC+mjoJimHGw=",
    expected_findings: &[ef!("unsafeHtml", 6, 60036), ef!("unsafeHtml", 6, 60610)],
};

const D3: Target = Target {
    name: "d3.min.js",
    url: "https://unpkg.com/d3@7.9.0/dist/d3.min.js",
    sri: "sha256-8glLv2FBs1lyLE/kVOtsSw8OQswQzHr5IfwVj864ZTk=",
    expected_findings: &[
        ef!("functionConstructor", 2, 98202),
        ef!("unsafeHtml", 2, 19792),
        ef!("unsafeHtml", 2, 19873),
    ],
};

const ECHARTS: Target = Target {
    name: "echarts.js",
    url: "https://unpkg.com/echarts@5.5.1/dist/echarts.js",
    sri: "sha256-rUhV2kUT/gNqBo/w32+YBUuBscEeTKIc5SL9glB9AXs=",
    expected_findings: &[
        ef!("documentWrite", 72592, 14),
        ef!("documentWrite", 72602, 12),
        ef!("functionConstructor", 47512, 107),
        ef!("javascriptLinks", 16610, 8),
        ef!("javascriptLinks", 16612, 8),
        ef!("javascriptLinks", 72552, 10),
        ef!("unsafeHtml", 26754, 12),
        ef!("unsafeHtml", 73021, 8),
        ef!("unsafeHtml", 73033, 12),
        ef!("unsafeHtml", 73092, 8),
        ef!("unsafeHtml", 73093, 8),
        ef!("unsafeHtml", 74166, 10),
        ef!("unsafeHtml", 74183, 12),
    ],
};

const HTMX: Target = Target {
    name: "htmx.min.js",
    url: "https://unpkg.com/htmx.org@1.9.10/dist/htmx.min.js",
    sri: "sha256-s73PXHQYl6U2SLEgf/8EaaDWGQFCm6H26I+Y69hOZp4=",
    expected_findings: &[
        ef!("eval", 1, 5388),
        ef!("functionConstructor", 1, 14182),
        ef!("functionConstructor", 1, 24671),
        ef!("functionConstructor", 1, 35691),
        ef!("insertAdjacentHtml", 1, 46683),
        ef!("javascriptLinks", 1, 42808),
        ef!("postMessage", 1, 19697),
        ef!("unsafeHtml", 1, 29236),
        ef!("unsafeHtml", 1, 45022),
    ],
};

const JQUERY: Target = Target {
    name: "jquery.min.js",
    url: "https://unpkg.com/jquery@3.7.1/dist/jquery.min.js",
    sri: "sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=",
    expected_findings: &[
        ef!("javascriptLinks", 2, 72779),
        ef!("javascriptLinks", 2, 74660),
        ef!("javascriptLinks", 2, 82567),
        ef!("unsafeHtml", 2, 9983),
        ef!("unsafeHtml", 2, 36283),
        ef!("unsafeHtml", 2, 48682),
    ],
};

const LODASH: Target = Target {
    name: "lodash.min.js",
    url: "https://unpkg.com/lodash@4.17.21/lodash.min.js",
    sri: "sha256-qXBd/EfAdjOA2FGrGAG+b3YBn2tn5A6bhz+LSgYD96k=",
    expected_findings: &[ef!("functionConstructor", 105, 27)],
};

const MERMAID: Target = Target {
    name: "mermaid.js",
    url: "https://unpkg.com/mermaid@11.4.1/dist/mermaid.js",
    sri: "sha256-/S3+BiburO2wORBQIe1KsOor8bPJR0L2fetVlxkLQnM=",
    expected_findings: &[
        ef!("eval", 61643, 4),
        ef!("javascriptLinks", 11100, 10),
        ef!("javascriptLinks", 16864, 10),
        ef!("javascriptLinks", 66308, 10),
        ef!("javascriptLinks", 66314, 10),
        ef!("javascriptLinks", 66324, 10),
        ef!("javascriptLinks", 66340, 10),
        ef!("javascriptLinks", 67528, 12),
        ef!("javascriptLinks", 80624, 14),
        ef!("javascriptLinks", 81044, 14),
        ef!("resourceUrl", 11128, 10),
        ef!("resourceUrl", 17189, 10),
        ef!("resourceUrl", 35033, 16),
        ef!("resourceUrl", 35075, 16),
        ef!("resourceUrl", 35115, 16),
        ef!("resourceUrl", 35130, 16),
        ef!("unsafeHtml", 6460, 10),
        ef!("unsafeHtml", 21719, 8),
        ef!("unsafeHtml", 24032, 6),
        ef!("unsafeHtml", 24038, 6),
        ef!("unsafeHtml", 146951, 4),
        ef!("unsafeHtml", 147120, 8),
    ],
};

const MONACO: Target = Target {
    name: "monaco-editor.js",
    url: "https://unpkg.com/monaco-editor@0.52.2/min/vs/editor/editor.main.js",
    sri: "sha256-kLWIvAtiTiQFKlduG8qy6v/se8ZmiVGIhi7r2cl0V4I=",
    expected_findings: &[
        ef!("insertAdjacentHtml", 606, 88602),
        ef!("insertAdjacentHtml", 665, 12632),
        ef!("insertAdjacentHtml", 665, 12861),
        ef!("javascriptLinks", 6, 43947),
        ef!("javascriptLinks", 111, 147522),
        ef!("javascriptLinks", 120, 28742),
        ef!("javascriptLinks", 120, 29168),
        ef!("javascriptLinks", 121, 3098),
        ef!("javascriptLinks", 122, 94112),
        ef!("javascriptLinks", 122, 95032),
        ef!("javascriptLinks", 163, 54589),
        ef!("javascriptLinks", 216, 4960),
        ef!("javascriptLinks", 635, 3803),
        ef!("javascriptLinks", 722, 45517),
        ef!("javascriptLinks", 722, 99512),
        ef!("postMessage", 122, 4945),
        ef!("postMessage", 601, 35200),
        ef!("resourceUrl", 40, 10),
        ef!("resourceUrl", 42, 9),
        ef!("resourceUrl", 44, 33),
        ef!("resourceUrl", 46, 33),
        ef!("resourceUrl", 216, 4404),
        ef!("unsafeHtml", 6, 60204),
        ef!("unsafeHtml", 216, 4982),
        ef!("unsafeHtml", 234, 3975),
        ef!("unsafeHtml", 606, 80173),
        ef!("unsafeHtml", 606, 88576),
        ef!("unsafeHtml", 606, 88884),
        ef!("unsafeHtml", 616, 40649),
        ef!("unsafeHtml", 622, 26420),
        ef!("unsafeHtml", 623, 5309),
        ef!("unsafeHtml", 636, 24689),
        ef!("unsafeHtml", 721, 46642),
        ef!("urlParams", 601, 33837),
    ],
};

const PDF: Target = Target {
    name: "pdf.min.js",
    url: "https://unpkg.com/pdfjs-dist@5.4.624/build/pdf.min.mjs",
    sri: "sha256-XxF3F1eQ3PW1sKiIIF8TK+ppDDUZTkYTCZ1CGhZCPQs=",
    expected_findings: &[
        ef!("javascriptLinks", 28, 34526),
        ef!("javascriptLinks", 28, 34702),
        ef!("javascriptLinks", 28, 34854),
        ef!("javascriptLinks", 28, 35061),
        ef!("javascriptLinks", 28, 35211),
        ef!("javascriptLinks", 28, 35657),
        ef!("postMessage", 25, 124866),
        ef!("resourceUrl", 28, 71163),
    ],
};

const REACT_DOM: Target = Target {
    name: "react-dom.production.min.js",
    url: "https://unpkg.com/react-dom@18.2.0/umd/react-dom.production.min.js",
    sri: "sha256-IXWO0ITNDjfnNXIu5POVfqlgYoop36bDzhodR6LW5Pc=",
    expected_findings: &[
        ef!("resourceUrl", 181, 35),
        ef!("unsafeHtml", 220, 93),
        ef!("unsafeHtml", 220, 149),
    ],
};

const THREE: Target = Target {
    name: "three.core.js",
    url: "https://unpkg.com/three@0.183.1/build/three.core.js",
    sri: "sha256-an/INDeBhTTV4wzoyODOdiMMoiRURuokdEuz2IxDZYM=",
    expected_findings: &[ef!("resourceUrl", 44564, 2)],
};

const TYPESCRIPT: Target = Target {
    name: "typescript.js",
    url: "https://unpkg.com/typescript@5.9.3/lib/typescript.js",
    sri: "sha256-OukCySzETazhdcDmnhOksImfaYPGEh12uauN1XlednU=",
    expected_findings: &[],
};

const VUE: Target = Target {
    name: "vue.global.js",
    url: "https://unpkg.com/vue@3.4.21/dist/vue.global.js",
    sri: "sha256-JpdI604wSHrHzZo7nygsRBWsr0GzFzmtj91vqeY0M80=",
    expected_findings: &[
        ef!("functionConstructor", 14263, 6),
        ef!("functionConstructor", 16501, 19),
        ef!("unsafeHtml", 9660, 8),
        ef!("unsafeHtml", 16013, 6),
        ef!("unsafeHtml", 16016, 6),
    ],
};

fn cache_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/.cache")
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn verify_sri(content: &str, sri: &str) -> bool {
    let Some((algo, hash)) = sri.split_once('-') else {
        return false;
    };
    match algo {
        "sha256" => base64_encode(&Sha256::digest(content.as_bytes())) == hash,
        _ => false,
    }
}

/// Uses a verified cache entry when present, otherwise downloads and verifies it.
fn get_content(target: &Target) -> String {
    let cache_dir = cache_dir();
    let cached_path = cache_dir.join(target.name);

    if let Ok(content) = fs::read_to_string(&cached_path) {
        if verify_sri(&content, target.sri) {
            return content;
        }
        eprintln!(
            "Cache integrity mismatch for {}, re-downloading...",
            target.name
        );
    }

    eprintln!("Downloading {}...", target.name);
    let output = Command::new("curl")
        .args(["-sL", "--fail", "--max-time", "120", target.url])
        .output()
        .unwrap_or_else(|e| panic!("failed to invoke curl for {}: {e}", target.name));
    assert!(
        output.status.success(),
        "download failed for {} ({}): {}",
        target.name,
        target.url,
        String::from_utf8_lossy(&output.stderr)
    );
    let content = String::from_utf8(output.stdout)
        .unwrap_or_else(|e| panic!("non-UTF-8 response downloading {}: {e}", target.name));

    assert!(
        verify_sri(&content, target.sri),
        "SRI verification failed for {}",
        target.name
    );

    fs::create_dir_all(&cache_dir).unwrap_or_else(|e| panic!("failed to create cache dir: {e}"));
    fs::write(&cached_path, &content)
        .unwrap_or_else(|e| panic!("failed to write cache for {}: {e}", target.name));
    eprintln!("Cached {} ({} bytes)", target.name, content.len());

    content
}

fn run_target(target: &Target) {
    let content = get_content(target);
    let result = analyze(&content, None);

    let mut actual: Vec<(String, u32, u32)> = result
        .findings
        .iter()
        .map(|f| (f.detector_name.clone(), f.start_line, f.start_column))
        .collect();
    actual.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));

    let expected: Vec<(String, u32, u32)> = target
        .expected_findings
        .iter()
        .map(|f| (f.detector.to_string(), f.line, f.column))
        .collect();

    assert_eq!(actual, expected, "{} — findings mismatch", target.name);
}

#[test]
fn alpine_min_js() {
    run_target(&ALPINE);
}

#[test]
fn angular_min_js() {
    run_target(&ANGULAR);
}

#[test]
fn bootstrap_bundle_min_js() {
    run_target(&BOOTSTRAP);
}

#[test]
fn d3_min_js() {
    run_target(&D3);
}

#[test]
fn echarts_js() {
    run_target(&ECHARTS);
}

#[test]
fn htmx_min_js() {
    run_target(&HTMX);
}

#[test]
fn jquery_min_js() {
    run_target(&JQUERY);
}

#[test]
fn lodash_min_js() {
    run_target(&LODASH);
}

#[test]
fn mermaid_js() {
    run_target(&MERMAID);
}

#[test]
fn monaco_editor_js() {
    run_target(&MONACO);
}

#[test]
fn pdf_min_js() {
    run_target(&PDF);
}

#[test]
fn react_dom_production_min_js() {
    run_target(&REACT_DOM);
}

#[test]
fn three_core_js() {
    run_target(&THREE);
}

#[test]
fn typescript_js() {
    run_target(&TYPESCRIPT);
}

#[test]
fn vue_global_js() {
    run_target(&VUE);
}
