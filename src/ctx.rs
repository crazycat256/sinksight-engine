//! Shared analysis context for detectors and inference.

use std::cell::Cell;

use oxc_allocator::{Allocator, Box as ArenaBox};
use oxc_ast::ast::{Expression, IdentifierReference};
use oxc_semantic::Semantic;
use oxc_span::{Atom, Span};

pub use oxc_semantic::{ScopeId, SymbolId};

pub struct AnalysisCtx<'a> {
    pub source: &'a str,
    pub semantic: &'a Semantic<'a>,
    pub allocator: &'a Allocator,
}

impl<'a> AnalysisCtx<'a> {
    pub fn new(source: &'a str, semantic: &'a Semantic<'a>, allocator: &'a Allocator) -> Self {
        Self {
            source,
            semantic,
            allocator,
        }
    }

    pub fn root_scope_id(&self) -> ScopeId {
        self.semantic.scoping().root_scope_id()
    }

    /// Synthetic `undefined` identifier (e.g. missing IIFE argument).
    pub fn undefined_expr(&self) -> &'a Expression<'a> {
        let ident = IdentifierReference {
            span: Span::new(0, 0),
            name: Atom::new_const("undefined"),
            reference_id: Cell::new(None),
        };
        self.allocator
            .alloc(Expression::Identifier(ArenaBox::new_in(
                ident,
                self.allocator,
            )))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RawMatch {
    pub detector: &'static str,
    pub category: Category,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Sink,
    Input,
}
