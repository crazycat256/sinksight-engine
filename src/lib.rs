//! SinkSight analysis engine for DOM XSS sink and input detection.

pub mod analyze;
pub mod cdp;
pub mod collector;
pub mod ctx;
pub mod detectors;
pub mod inference;
pub mod store;
pub mod utils;

pub use analyze::{analyze, AnalyzeResult, Finding, FindingCategory, LibraryCheck};
pub use ctx::{AnalysisCtx, Category, RawMatch};
pub use detectors::detect_all;
