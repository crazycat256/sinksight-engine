//! SinkSight analysis for DOM XSS sink and input detection.

pub mod analyze;
pub mod ctx;
pub mod detectors;
pub mod inference;
pub mod utils;

pub use analyze::{analyze, AnalyzeResult, Analyzer, Finding, FindingCategory, LibraryCheck};
pub use ctx::{AnalysisCtx, Category, RawMatch};
pub use detectors::detect_all;
