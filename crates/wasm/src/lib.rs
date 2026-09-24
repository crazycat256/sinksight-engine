use serde::Serialize;
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use sinksight_analysis::{
    AnalyzeResult as Analysis, Analyzer, FindingCategory as AnalysisCategory,
};

#[wasm_bindgen]
pub struct Engine {
    inner: Analyzer,
}

#[wasm_bindgen]
impl Engine {
    /// `libraryDb` is the raw `.slhdb` bytes. Pass `undefined` to analyze without a library database.
    #[wasm_bindgen(constructor)]
    pub fn new(library_db: Option<Vec<u8>>) -> Result<Engine, JsValue> {
        Analyzer::new(library_db.as_deref())
            .map(|inner| Engine { inner })
            .map_err(|err| JsValue::from_str(&err))
    }

    pub fn analyze(&self, source: &str) -> AnalyzeResult {
        self.inner.analyze(source).into()
    }
}

#[derive(Serialize, Tsify)]
#[tsify(into_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeResult {
    pub findings: Vec<Finding>,
    pub structural_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<LibraryCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_error: Option<String>,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi)]
pub enum FindingCategory {
    Sink,
    Input,
}

#[derive(Serialize, Tsify)]
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

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct LibraryCheck {
    pub whole_file: Vec<LibraryMatch>,
    pub functions: Vec<FunctionMatch>,
}

#[derive(Serialize, Tsify)]
pub struct LibraryMatch {
    pub lib: String,
    pub version: String,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct FunctionMatch {
    pub libs: Vec<LibraryMatch>,
    pub function_name: Option<String>,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

impl From<Analysis> for AnalyzeResult {
    fn from(value: Analysis) -> Self {
        Self {
            findings: value.findings.into_iter().map(Into::into).collect(),
            structural_hash: value.structural_hash,
            library: value.library.map(Into::into),
            analysis_error: value.analysis_error,
        }
    }
}

impl From<sinksight_analysis::Finding> for Finding {
    fn from(value: sinksight_analysis::Finding) -> Self {
        Self {
            detector_name: value.detector_name,
            category: match value.category {
                AnalysisCategory::Sink => FindingCategory::Sink,
                AnalysisCategory::Input => FindingCategory::Input,
            },
            start_line: value.start_line,
            start_column: value.start_column,
            end_line: value.end_line,
            end_column: value.end_column,
            snippet: value.snippet,
        }
    }
}

impl From<sinksight_analysis::LibraryCheck> for LibraryCheck {
    fn from(value: sinksight_analysis::LibraryCheck) -> Self {
        Self {
            whole_file: value
                .whole_file
                .into_iter()
                .map(|m| LibraryMatch {
                    lib: m.lib,
                    version: m.version,
                })
                .collect(),
            functions: value
                .functions
                .into_iter()
                .map(|f| FunctionMatch {
                    libs: f
                        .libs
                        .into_iter()
                        .map(|m| LibraryMatch {
                            lib: m.lib,
                            version: m.version,
                        })
                        .collect(),
                    function_name: f.function_name,
                    start_line: f.start_line,
                    start_column: f.start_column,
                    end_line: f.end_line,
                    end_column: f.end_column,
                })
                .collect(),
        }
    }
}
