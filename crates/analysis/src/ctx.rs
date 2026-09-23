//! Shared analysis context for detectors and inference.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use oxc_allocator::{Allocator, Box as ArenaBox};
use oxc_ast::ast::{Expression, IdentifierReference};
use oxc_semantic::Semantic;
use oxc_span::{Atom, Span};

pub use oxc_semantic::{ScopeId, SymbolId};
const DEFAULT_INFERENCE_BUDGET: usize = 250_000;

pub struct AnalysisCtx<'a> {
    pub source: &'a str,
    pub semantic: &'a Semantic<'a>,
    pub allocator: &'a Allocator,
    inference_steps_remaining: Cell<usize>,
    inference_budget_exhausted: Cell<bool>,
    reaching_cache: RefCell<HashMap<(usize, u32, u32), bool>>,
}

impl<'a> AnalysisCtx<'a> {
    pub fn new(source: &'a str, semantic: &'a Semantic<'a>, allocator: &'a Allocator) -> Self {
        Self {
            source,
            semantic,
            allocator,
            inference_steps_remaining: Cell::new(DEFAULT_INFERENCE_BUDGET),
            inference_budget_exhausted: Cell::new(false),
            reaching_cache: RefCell::new(HashMap::new()),
        }
    }

    pub fn consume_inference_step(&self) -> bool {
        let remaining = self.inference_steps_remaining.get();
        if remaining == 0 {
            self.inference_budget_exhausted.set(true);
            return false;
        }
        self.inference_steps_remaining.set(remaining - 1);
        true
    }

    pub fn inference_budget_exhausted(&self) -> bool {
        self.inference_budget_exhausted.get()
    }

    pub fn cached_reaching_result(&self, key: (usize, u32, u32)) -> Option<bool> {
        self.reaching_cache.borrow().get(&key).copied()
    }

    pub fn cache_reaching_result(&self, key: (usize, u32, u32), result: bool) {
        self.reaching_cache.borrow_mut().insert(key, result);
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
