use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast::AstKind;
use oxc_ast_visit::{walk, Visit};
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::SemanticBuilder;
use oxc_span::{SourceType, Span};

use sinksight_library_hash::{check_script, load_db_handle, CheckResult, LoadedDb};

use crate::ctx::{AnalysisCtx, Category, RawMatch};
use crate::detectors::detect_all;

pub const MAX_SNIPPET: usize = 200;

pub struct Analyzer {
    library_db: Option<LoadedDb>,
}

impl Analyzer {
    pub fn new(library_db: Option<&[u8]>) -> Result<Self, String> {
        Ok(Self {
            library_db: library_db.map(load_db_handle).transpose()?,
        })
    }

    pub fn analyze(&self, source: &str) -> AnalyzeResult {
        #[cfg(not(target_family = "wasm"))]
        {
            return stacker::grow(64 * 1024 * 1024, || {
                analyze_with_handle(source, self.library_db.as_ref().map(LoadedDb::handle))
            });
        }

        #[cfg(target_family = "wasm")]
        {
            analyze_with_handle(source, self.library_db.as_ref().map(LoadedDb::handle))
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub detector_name: String,
    pub category: FindingCategory,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub snippet: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingCategory {
    Sink,
    Input,
}

impl From<Category> for FindingCategory {
    fn from(value: Category) -> Self {
        match value {
            Category::Sink => Self::Sink,
            Category::Input => Self::Input,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeResult {
    pub findings: Vec<Finding>,
    pub structural_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<LibraryCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryCheck {
    pub whole_file: Vec<LibraryMatchJson>,
    pub functions: Vec<FunctionMatchJson>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LibraryMatchJson {
    pub lib: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionMatchJson {
    pub libs: Vec<LibraryMatchJson>,
    pub function_name: Option<String>,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

impl From<&CheckResult> for LibraryCheck {
    fn from(value: &CheckResult) -> Self {
        Self {
            whole_file: value
                .whole_file
                .iter()
                .map(|m| LibraryMatchJson {
                    lib: m.lib.clone(),
                    version: m.version.clone(),
                })
                .collect(),
            functions: value
                .functions
                .iter()
                .map(|f| FunctionMatchJson {
                    libs: f
                        .libs
                        .iter()
                        .map(|m| LibraryMatchJson {
                            lib: m.lib.clone(),
                            version: m.version.clone(),
                        })
                        .collect(),
                    function_name: f.function_name.clone(),
                    start_line: f.start_line,
                    start_column: f.start_column,
                    end_line: f.end_line,
                    end_column: f.end_column,
                })
                .collect(),
        }
    }
}

struct LineIndex {
    line_starts: Vec<u32>,
}

impl LineIndex {
    fn new(source: &str) -> Self {
        let mut line_starts = vec![0u32];
        for (i, b) in source.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push((i + 1) as u32);
            }
        }
        Self { line_starts }
    }

    fn offset_to_line_col(&self, source: &str, offset: u32) -> (u32, u32) {
        let line_idx = self.line_starts.partition_point(|&start| start <= offset);
        let line = line_idx as u32;
        let line_start = self.line_starts[line_idx - 1] as usize;
        let col = source[line_start..offset as usize].chars().count() as u32;
        (line, col)
    }

    fn span_position(&self, source: &str, span: Span) -> (u32, u32, u32, u32) {
        let (start_line, start_column) = self.offset_to_line_col(source, span.start);
        let (end_line, end_column) = self.offset_to_line_col(source, span.end);
        (start_line, start_column, end_line, end_column)
    }
}

/// Analyze JavaScript source. Optional `library_db` is raw `.slhdb` bytes.
pub fn analyze(source: &str, library_db: Option<&[u8]>) -> AnalyzeResult {
    let analyzer = Analyzer::new(library_db).unwrap_or_else(|_| Analyzer { library_db: None });
    analyzer.analyze(source)
}

fn analyze_with_handle(source: &str, library_db: Option<u32>) -> AnalyzeResult {
    let allocator = Allocator::default();
    let source_type = SourceType::unambiguous();
    let options = ParseOptions {
        allow_return_outside_function: true,
        preserve_parens: false,
        ..ParseOptions::default()
    };

    let parser_ret = Parser::new(&allocator, source, source_type)
        .with_options(options)
        .parse();

    let mut analysis_errors: Vec<String> =
        parser_ret.errors.iter().map(ToString::to_string).collect();

    let structural_hash = structural_hash_of(&parser_ret.program);

    let semantic_ret = SemanticBuilder::new().build(&parser_ret.program);
    analysis_errors.extend(semantic_ret.errors.iter().map(ToString::to_string));
    let ctx = AnalysisCtx::new(source, &semantic_ret.semantic, &allocator);
    let raw_matches = detect_all(&ctx);

    let line_index = LineIndex::new(source);
    let mut findings: Vec<Finding> = raw_matches
        .into_iter()
        .map(|m| raw_match_to_finding(source, &line_index, m))
        .collect();

    let library = library_db.map(|handle| LibraryCheck::from(&check_script(handle, source)));

    if let Some(library) = &library {
        if !library.whole_file.is_empty() {
            findings.clear();
        } else if !library.functions.is_empty() {
            findings.retain(|finding| {
                !library
                    .functions
                    .iter()
                    .any(|function| function_contains_finding(function, finding))
            });
        }
    }

    AnalyzeResult {
        findings,
        structural_hash,
        library,
        analysis_error: (!analysis_errors.is_empty()).then(|| analysis_errors.join("\n")),
    }
}

fn function_contains_finding(function: &FunctionMatchJson, finding: &Finding) -> bool {
    let function_start = (function.start_line, function.start_column);
    let function_end = (function.end_line, function.end_column);
    let finding_start = (finding.start_line, finding.start_column);
    let finding_end = (finding.end_line, finding.end_column);
    finding_start >= function_start && finding_end <= function_end
}

fn raw_match_to_finding(source: &str, line_index: &LineIndex, m: RawMatch) -> Finding {
    let (start_line, start_column, end_line, end_column) = line_index.span_position(source, m.span);
    Finding {
        detector_name: m.detector.to_string(),
        category: m.category.into(),
        start_line,
        start_column,
        end_line,
        end_column,
        snippet: snippet_from_span(source, m.span),
    }
}

fn snippet_from_span(source: &str, span: Span) -> String {
    let start = span.start as usize;
    let end = (span.end as usize).min(source.len());
    if start >= end || start >= source.len() {
        return String::new();
    }
    let slice = &source[start..end];
    let compact: String = slice.split_whitespace().collect::<Vec<_>>().join(" ");
    compact.chars().take(MAX_SNIPPET).collect()
}

fn structural_hash_of(program: &Program<'_>) -> String {
    let mut parts: Vec<String> = Vec::new();
    StructuralHashVisitor { parts: &mut parts }.visit_program(program);
    let digest = Sha256::digest(parts.join(",").as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn strip_digits(name: &str) -> String {
    name.chars().filter(|c| !c.is_ascii_digit()).collect()
}

fn kind_type_name(kind: AstKind<'_>) -> String {
    let debug = kind.debug_name();
    debug.split('(').next().unwrap_or(&debug).to_string()
}

struct StructuralHashVisitor<'a> {
    parts: &'a mut Vec<String>,
}

impl<'a> Visit<'a> for StructuralHashVisitor<'_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        self.parts.push(kind_type_name(kind));

        match kind {
            AstKind::IdentifierName(id) => {
                self.parts.push(strip_digits(id.name.as_str()));
            }
            AstKind::BindingIdentifier(id) => {
                self.parts.push(strip_digits(id.name.as_str()));
            }
            AstKind::IdentifierReference(id) => {
                self.parts.push(strip_digits(id.name.as_str()));
            }
            AstKind::PrivateIdentifier(id) => {
                self.parts.push(strip_digits(id.name.as_str()));
            }
            AstKind::StaticMemberExpression(member) => {
                self.parts.push(strip_digits(member.property.name.as_str()));
            }
            _ => {}
        }
    }

    fn visit_object_expression(&mut self, expr: &ObjectExpression<'a>) {
        self.enter_node(AstKind::ObjectExpression(expr));

        let mut indexed: Vec<(String, usize)> = expr
            .properties
            .iter()
            .enumerate()
            .map(|(i, prop)| (property_sort_key(prop), i))
            .collect();
        indexed.sort_by(|a, b| a.0.cmp(&b.0));

        for (_, i) in indexed {
            walk::walk_object_property_kind(self, &expr.properties[i]);
        }

        self.leave_node(AstKind::ObjectExpression(expr));
    }
}

fn property_sort_key(prop: &ObjectPropertyKind<'_>) -> String {
    match prop {
        ObjectPropertyKind::ObjectProperty(p) => match &p.key {
            PropertyKey::StaticIdentifier(id) => id.name.to_string(),
            PropertyKey::StringLiteral(lit) => lit.value.to_string(),
            PropertyKey::NumericLiteral(lit) => lit
                .raw
                .map(|r| r.to_string())
                .unwrap_or_else(|| lit.value.to_string()),
            _ => String::new(),
        },
        ObjectPropertyKind::SpreadProperty(_) => String::new(),
    }
}
