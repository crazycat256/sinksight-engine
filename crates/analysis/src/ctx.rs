//! Shared analysis context for detectors and inference.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use oxc_allocator::Allocator;
use oxc_ast::{ast::Expression, builder::AstBuilder};
use oxc_semantic::Semantic;
use oxc_span::Span;

pub use oxc_semantic::{ScopeId, SymbolId};
const DEFAULT_INFERENCE_BUDGET: usize = 250_000;

pub struct AnalysisCtx<'a> {
    pub source: &'a str,
    pub semantic: &'a Semantic<'a>,
    pub allocator: &'a Allocator,
    inference_steps_remaining: Cell<usize>,
    inference_budget_exhausted: Cell<bool>,
    reaching_cache: RefCell<HashMap<(usize, u32, u32), bool>>,
    mutated_properties_cache: RefCell<HashMap<SymbolId, Option<Rc<HashSet<String>>>>>,
    trivial_self_assignments_cache: RefCell<HashMap<SymbolId, bool>>,
    element_type_cache: RefCell<HashMap<SymbolId, Option<String>>>,
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
            mutated_properties_cache: RefCell::new(HashMap::new()),
            trivial_self_assignments_cache: RefCell::new(HashMap::new()),
            element_type_cache: RefCell::new(HashMap::new()),
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

    pub(crate) fn cached_mutated_properties(
        &self,
        symbol_id: SymbolId,
    ) -> Option<Option<Rc<HashSet<String>>>> {
        self.mutated_properties_cache
            .borrow()
            .get(&symbol_id)
            .cloned()
    }

    pub(crate) fn cache_mutated_properties(
        &self,
        symbol_id: SymbolId,
        properties: Option<Rc<HashSet<String>>>,
    ) {
        self.mutated_properties_cache
            .borrow_mut()
            .insert(symbol_id, properties);
    }

    pub(crate) fn cached_trivial_self_assignments(&self, symbol_id: SymbolId) -> Option<bool> {
        self.trivial_self_assignments_cache
            .borrow()
            .get(&symbol_id)
            .copied()
    }

    pub(crate) fn cache_trivial_self_assignments(&self, symbol_id: SymbolId, result: bool) {
        self.trivial_self_assignments_cache
            .borrow_mut()
            .insert(symbol_id, result);
    }

    pub(crate) fn cached_element_type(&self, symbol_id: SymbolId) -> Option<Option<String>> {
        self.element_type_cache.borrow().get(&symbol_id).cloned()
    }

    pub(crate) fn cache_element_type(&self, symbol_id: SymbolId, element_type: Option<String>) {
        self.element_type_cache
            .borrow_mut()
            .insert(symbol_id, element_type);
    }

    pub fn root_scope_id(&self) -> ScopeId {
        self.semantic.scoping().root_scope_id()
    }

    /// Synthetic `undefined` identifier (e.g. missing IIFE argument).
    pub fn undefined_expr(&self) -> &'a Expression<'a> {
        let builder = AstBuilder::new(self.allocator);
        self.allocator.alloc(Expression::new_identifier(
            Span::new(0, 0),
            "undefined",
            &builder,
        ))
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
