//! SinkSight analysis for DOM XSS sink and input detection.

pub mod analyze;
pub mod ctx;
pub mod detectors;
pub mod inference;
pub mod utils;

pub use analyze::{
    AnalyzeResult, Analyzer, Finding, FindingCategory, LibraryCheck, analyze, structural_hash,
};
pub use ctx::{AnalysisCtx, Category, RawMatch};
pub use detectors::detect_all;

pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
