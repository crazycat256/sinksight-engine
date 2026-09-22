//! Intra-procedural reaching-definition facts for identifier safety.
//!
//! Walks the enclosing function (or program) in evaluation order and tracks
//! whether the last write that can reach a use is provably safe. Joins at
//! control-flow merges. Nested functions that write the binding poison every
//! same-function use; uses that occur *inside* a nested function stay
//! flow-insensitive (the closure may run at any time).

use std::collections::HashSet;

use oxc_ast::ast::*;
use oxc_ast::AstKind;
use oxc_ast_visit::{walk, Visit};
use oxc_semantic::{NodeId, ScopeFlags};
use oxc_span::{GetSpan, Span};

use crate::ctx::{AnalysisCtx, ScopeId, SymbolId};
use crate::utils::{
    is_const_variable_binding, is_parameter_binding, is_variable_declarator_binding,
    resolve_identifier, resolve_iife_param, resolve_named_function_param, unwrap_expression,
};

use super::safety::{all_assignments_safe, is_safe_expression_inner};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fact {
    Safe,
    Unsafe,
}

impl Fact {
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Safe, Self::Safe) => Self::Safe,
            _ => Self::Unsafe,
        }
    }

    fn is_safe(self) -> bool {
        matches!(self, Self::Safe)
    }
}

fn join_opt(a: Option<Fact>, b: Option<Fact>) -> Option<Fact> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.join(y)),
        (x, y) => x.or(y),
    }
}

#[derive(Clone, Debug)]
struct Outgoing {
    found: Option<Fact>,
    next: Option<Fact>,
    stops: Option<Fact>,
    breaks: Vec<(Option<String>, Fact)>,
    continues: Vec<(Option<String>, Fact)>,
}

impl Outgoing {
    fn empty() -> Self {
        Self {
            found: None,
            next: None,
            stops: None,
            breaks: Vec::new(),
            continues: Vec::new(),
        }
    }

    fn fallthrough(fact: Fact) -> Self {
        Self {
            next: Some(fact),
            ..Self::empty()
        }
    }

    fn found(fact: Fact) -> Self {
        Self {
            found: Some(fact),
            ..Self::empty()
        }
    }

    fn stop(fact: Fact) -> Self {
        Self {
            stops: Some(fact),
            ..Self::empty()
        }
    }

    fn brk(label: Option<String>, fact: Fact) -> Self {
        Self {
            breaks: vec![(label, fact)],
            ..Self::empty()
        }
    }

    fn cont(label: Option<String>, fact: Fact) -> Self {
        Self {
            continues: vec![(label, fact)],
            ..Self::empty()
        }
    }

    fn merge(&mut self, other: Self) {
        self.found = join_opt(self.found, other.found);
        self.next = join_opt(self.next, other.next);
        self.stops = join_opt(self.stops, other.stops);
        merge_jumps(&mut self.breaks, other.breaks);
        merge_jumps(&mut self.continues, other.continues);
    }
}

fn merge_jumps(into: &mut Vec<(Option<String>, Fact)>, extra: Vec<(Option<String>, Fact)>) {
    for (lab, fact) in extra {
        if let Some(existing) = into.iter_mut().find(|(l, _)| *l == lab) {
            existing.1 = existing.1.join(fact);
        } else {
            into.push((lab, fact));
        }
    }
}

fn take_matching(
    jumps: &mut Vec<(Option<String>, Fact)>,
    labels: &[String],
    unlabeled: bool,
) -> Option<Fact> {
    let mut acc = None;
    jumps.retain(|(lab, fact)| {
        let matched = match lab {
            None => unlabeled,
            Some(name) => labels.iter().any(|l| l == name),
        };
        if matched {
            acc = Some(acc.map_or(*fact, |a: Fact| a.join(*fact)));
            false
        } else {
            true
        }
    });
    acc
}

pub(super) fn identifier_use_is_safe<'a>(
    ctx: &AnalysisCtx<'a>,
    ident: &'a IdentifierReference<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> Option<bool> {
    let symbol_id = ident_symbol(ctx, ident, scope_id)?;
    if !is_variable_declarator_binding(ctx, symbol_id) && !is_parameter_binding(ctx, symbol_id) {
        return None;
    }

    let key = format!(
        "$reach:{}:{}:{}",
        symbol_id.index(),
        ident.span.start,
        ident.span.end
    );
    if visited.contains(&key) {
        return Some(false);
    }
    visited.insert(key.clone());
    let result = identifier_use_is_safe_after_guard(ctx, ident, symbol_id, scope_id, visited);
    visited.remove(&key);
    Some(result)
}

fn identifier_use_is_safe_after_guard<'a>(
    ctx: &AnalysisCtx<'a>,
    ident: &'a IdentifierReference<'a>,
    symbol_id: SymbolId,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> bool {
    if is_nested_use(ctx, ident.span, symbol_id) {
        return all_assignments_safe(ctx, ident.name.as_str(), scope_id, visited);
    }

    let decl_id = ctx.semantic.scoping().symbol_declaration(symbol_id);
    let Some(enclosing) = enclosing_callable(ctx, decl_id) else {
        return false;
    };
    let Some(stmts) = callable_statements(ctx, enclosing) else {
        return false;
    };

    if nested_closure_may_assign_unsafe(ctx, stmts, symbol_id, visited) {
        return false;
    }

    let initial = if is_parameter_binding(ctx, symbol_id) {
        param_initial_fact(ctx, symbol_id, visited)
    } else {
        Fact::Safe
    };

    let mut analyzer = Analyzer {
        ctx,
        symbol_id,
        use_span: ident.span,
        scope_id,
        visited,
        intermediate: None,
    };
    analyzer
        .exec_list(stmts, initial, true)
        .found
        .is_some_and(Fact::is_safe)
}

fn ident_symbol(
    ctx: &AnalysisCtx<'_>,
    ident: &IdentifierReference<'_>,
    scope_id: ScopeId,
) -> Option<SymbolId> {
    if let Some(rid) = ident.reference_id.get() {
        if let Some(symbol_id) = ctx.semantic.scoping().get_reference(rid).symbol_id() {
            return Some(symbol_id);
        }
    }
    ctx.semantic
        .scoping()
        .find_binding(scope_id, ident.name.as_str())
}

fn refers_to_symbol(
    ctx: &AnalysisCtx<'_>,
    ident: &IdentifierReference<'_>,
    symbol_id: SymbolId,
) -> bool {
    ident
        .reference_id
        .get()
        .and_then(|rid| ctx.semantic.scoping().get_reference(rid).symbol_id())
        == Some(symbol_id)
}

fn is_nested_use(ctx: &AnalysisCtx<'_>, use_span: Span, symbol_id: SymbolId) -> bool {
    let decl_id = ctx.semantic.scoping().symbol_declaration(symbol_id);
    let Some(use_id) = node_id_for_ident_span(ctx, use_span) else {
        return false;
    };
    let Some(use_fn) = enclosing_callable(ctx, use_id) else {
        return false;
    };
    let Some(decl_fn) = enclosing_callable(ctx, decl_id) else {
        return false;
    };
    use_fn != decl_fn
}

fn node_id_for_ident_span(ctx: &AnalysisCtx<'_>, span: Span) -> Option<NodeId> {
    ctx.semantic.nodes().iter().find_map(|node| {
        if let AstKind::IdentifierReference(ident) = node.kind() {
            if ident.span == span {
                return Some(node.id());
            }
        }
        None
    })
}

fn enclosing_callable(ctx: &AnalysisCtx<'_>, node_id: NodeId) -> Option<NodeId> {
    let nodes = ctx.semantic.nodes();
    std::iter::once(node_id)
        .chain(nodes.ancestor_ids(node_id))
        .find(|&id| {
            matches!(
                nodes.kind(id),
                AstKind::Function(_)
                    | AstKind::ArrowFunctionExpression(_)
                    | AstKind::Program(_)
                    | AstKind::StaticBlock(_)
                    | AstKind::Class(_)
            )
        })
}

fn callable_statements<'a>(ctx: &AnalysisCtx<'a>, node_id: NodeId) -> Option<&'a [Statement<'a>]> {
    match ctx.semantic.nodes().kind(node_id) {
        AstKind::Program(p) => Some(p.body.as_slice()),
        AstKind::Function(f) => f.body.as_ref().map(|b| b.statements.as_slice()),
        AstKind::ArrowFunctionExpression(a) => Some(a.body.statements.as_slice()),
        AstKind::StaticBlock(b) => Some(b.body.as_slice()),
        AstKind::Class(_) => None,
        _ => None,
    }
}

fn param_initial_fact(
    ctx: &AnalysisCtx<'_>,
    symbol_id: SymbolId,
    visited: &mut HashSet<String>,
) -> Fact {
    if let Some(resolution) = resolve_iife_param(ctx, symbol_id) {
        return match resolution.arg {
            Some(arg) => expr_fact(ctx, arg, resolution.scope_id, visited),
            None => Fact::Safe,
        };
    }
    if let Some(named) = resolve_named_function_param(ctx, symbol_id) {
        let mut fact = Fact::Safe;
        // A call site that omits the argument passes `undefined`, which is safe
        // and therefore cannot change the join.
        for e in named.args.iter().flatten() {
            fact = fact.join(expr_fact(ctx, e, named.scope_id, visited));
        }
        return fact;
    }
    Fact::Unsafe
}

fn expr_fact<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
    visited: &mut HashSet<String>,
) -> Fact {
    if is_safe_expression_inner(ctx, expr, scope_id, visited) {
        Fact::Safe
    } else {
        Fact::Unsafe
    }
}

fn nested_closure_may_assign_unsafe<'a>(
    ctx: &AnalysisCtx<'a>,
    stmts: &'a [Statement<'a>],
    symbol_id: SymbolId,
    visited: &mut HashSet<String>,
) -> bool {
    let mut scan = PoisonScan {
        ctx,
        symbol_id,
        visited,
        nested: 0,
        pending_iife: 0,
        poison: false,
    };
    for stmt in stmts {
        scan.visit_statement(stmt);
    }
    scan.poison
}

struct PoisonScan<'a, 'v> {
    ctx: &'a AnalysisCtx<'a>,
    symbol_id: SymbolId,
    visited: &'v mut HashSet<String>,
    nested: u32,
    pending_iife: u32,
    poison: bool,
}

impl PoisonScan<'_, '_> {
    fn consume_pending_iife(&mut self) -> bool {
        if self.pending_iife > 0 {
            self.pending_iife -= 1;
            true
        } else {
            false
        }
    }
}

impl<'a> Visit<'a> for PoisonScan<'a, '_> {
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        let skip = self.consume_pending_iife();
        if !skip {
            self.nested += 1;
        }
        walk::walk_function(self, func, flags);
        if !skip {
            self.nested -= 1;
        }
    }

    fn visit_arrow_function_expression(&mut self, func: &ArrowFunctionExpression<'a>) {
        let skip = self.consume_pending_iife();
        if !skip {
            self.nested += 1;
        }
        walk::walk_arrow_function_expression(self, func);
        if !skip {
            self.nested -= 1;
        }
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        let is_iife = iife_from_callee(&call.callee).is_some() || call_apply_iife(call).is_some();
        if is_iife {
            self.pending_iife += 1;
        }
        walk::walk_call_expression(self, call);
        if is_iife && self.pending_iife > 0 {
            self.pending_iife -= 1;
        }
    }

    fn visit_new_expression(&mut self, expr: &NewExpression<'a>) {
        let is_iife = iife_from_callee(&expr.callee).is_some();
        if is_iife {
            self.pending_iife += 1;
        }
        walk::walk_new_expression(self, expr);
        if is_iife && self.pending_iife > 0 {
            self.pending_iife -= 1;
        }
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        if self.nested > 0
            && !is_const_variable_binding(self.ctx, self.symbol_id)
            && assignment_target_writes_symbol(self.ctx, &assign.left, self.symbol_id)
            && (is_destructuring_target(&assign.left)
                || !is_safe_expression_inner(
                    self.ctx,
                    &assign.right,
                    self.ctx.root_scope_id(),
                    self.visited,
                ))
        {
            self.poison = true;
        }
        walk::walk_assignment_expression(self, assign);
    }

    fn visit_for_in_statement(&mut self, stmt: &ForInStatement<'a>) {
        if self.nested > 0
            && !is_const_variable_binding(self.ctx, self.symbol_id)
            && for_left_writes_symbol(self.ctx, &stmt.left, self.symbol_id)
        {
            self.poison = true;
        }
        walk::walk_for_in_statement(self, stmt);
    }

    fn visit_for_of_statement(&mut self, stmt: &ForOfStatement<'a>) {
        if self.nested > 0
            && !is_const_variable_binding(self.ctx, self.symbol_id)
            && for_left_writes_symbol(self.ctx, &stmt.left, self.symbol_id)
        {
            self.poison = true;
        }
        walk::walk_for_of_statement(self, stmt);
    }
}

struct Analyzer<'a, 'v> {
    ctx: &'a AnalysisCtx<'a>,
    symbol_id: SymbolId,
    use_span: Span,
    scope_id: ScopeId,
    visited: &'v mut HashSet<String>,
    /// Set while executing a `try` block: joins the fact after every statement
    /// so the handler can see values that only exist part-way through it.
    intermediate: Option<Fact>,
}

impl<'a, 'v> Analyzer<'a, 'v> {
    fn contains_use(&self, span: Span) -> bool {
        span.contains_inclusive(self.use_span)
    }

    fn refers(&self, ident: &IdentifierReference<'_>) -> bool {
        refers_to_symbol(self.ctx, ident, self.symbol_id)
    }

    fn expr_is_safe(&mut self, expr: &'a Expression<'a>, current: Fact) -> bool {
        let inner = unwrap_expression(expr);
        if let Expression::Identifier(id) = inner {
            if self.refers(id) {
                return current.is_safe();
            }
        }
        is_safe_expression_inner(self.ctx, expr, self.scope_id, self.visited)
    }

    fn fact_of(&mut self, expr: &'a Expression<'a>, current: Fact) -> Fact {
        if self.expr_is_safe(expr, current) {
            Fact::Safe
        } else {
            Fact::Unsafe
        }
    }

    fn exec_list(
        &mut self,
        stmts: &'a [Statement<'a>],
        mut fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        let mut acc = Outgoing::empty();
        for stmt in stmts {
            let probe = until_use && self.contains_use(stmt.span());
            let out = self.exec_stmt(stmt, fact, probe);
            if out.found.is_some() {
                acc.found = out.found;
                return acc;
            }
            acc.merge(Outgoing {
                found: None,
                next: None,
                stops: out.stops,
                breaks: out.breaks,
                continues: out.continues,
            });
            match out.next {
                Some(f) => {
                    fact = f;
                    if let Some(worst) = self.intermediate.as_mut() {
                        *worst = worst.join(fact);
                    }
                }
                None => return acc,
            }
        }
        acc.next = Some(fact);
        acc
    }

    fn exec_stmt(&mut self, stmt: &'a Statement<'a>, fact: Fact, until_use: bool) -> Outgoing {
        let (labels, inner) = peel_labels(stmt);
        let mut out = self.exec_stmt_inner(inner, fact, until_use, &labels);
        if !labels.is_empty() {
            if let Some(ex) = take_matching(&mut out.breaks, &labels, false) {
                out.next = join_opt(out.next, Some(ex));
            }
        }
        out
    }

    fn exec_stmt_inner(
        &mut self,
        stmt: &'a Statement<'a>,
        fact: Fact,
        until_use: bool,
        labels: &[String],
    ) -> Outgoing {
        match stmt {
            Statement::BlockStatement(block) => self.exec_list(&block.body, fact, until_use),
            Statement::EmptyStatement(_) | Statement::DebuggerStatement(_) => {
                Outgoing::fallthrough(fact)
            }
            Statement::ExpressionStatement(stmt) => {
                self.exec_expr(&stmt.expression, fact, until_use)
            }
            Statement::VariableDeclaration(decl) => {
                self.exec_var_decl(decl, fact, until_use, Fact::Safe)
            }
            Statement::FunctionDeclaration(_) => Outgoing::fallthrough(fact),
            Statement::ClassDeclaration(class) => self.exec_class(class, fact, until_use),
            Statement::IfStatement(if_stmt) => self.exec_if(if_stmt, fact, until_use),
            Statement::WhileStatement(w) => {
                self.exec_conditioned_loop(&w.test, &w.body, None, fact, until_use, labels, false)
            }
            Statement::DoWhileStatement(d) => self.exec_do_while(d, fact, until_use, labels),
            Statement::ForStatement(f) => self.exec_for(f, fact, until_use, labels),
            Statement::ForInStatement(f) => {
                self.exec_for_in_of(&f.left, &f.right, &f.body, fact, until_use, labels)
            }
            Statement::ForOfStatement(f) => {
                self.exec_for_in_of(&f.left, &f.right, &f.body, fact, until_use, labels)
            }
            Statement::SwitchStatement(s) => self.exec_switch(s, fact, until_use, labels),
            Statement::TryStatement(t) => self.exec_try(t, fact, until_use),
            Statement::ReturnStatement(r) => {
                self.exec_return_or_throw(r.argument.as_ref(), fact, until_use)
            }
            Statement::ThrowStatement(t) => {
                self.exec_return_or_throw(Some(&t.argument), fact, until_use)
            }
            Statement::BreakStatement(b) => {
                Outgoing::brk(b.label.as_ref().map(|l| l.name.to_string()), fact)
            }
            Statement::ContinueStatement(c) => {
                Outgoing::cont(c.label.as_ref().map(|l| l.name.to_string()), fact)
            }
            Statement::WithStatement(w) => {
                let obj_out = self.exec_expr(&w.object, fact, until_use);
                if obj_out.found.is_some() {
                    return obj_out;
                }
                let fact = obj_out.next.unwrap_or(fact);
                self.exec_stmt(&w.body, fact, until_use)
            }
            Statement::LabeledStatement(ls) => self.exec_stmt(&ls.body, fact, until_use),
            Statement::ExportNamedDeclaration(ex) => {
                if let Some(decl) = &ex.declaration {
                    self.exec_declaration(decl, fact, until_use)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
            Statement::ExportDefaultDeclaration(ex) => {
                self.exec_export_default(ex, fact, until_use)
            }
            _ => {
                if until_use && self.contains_use(stmt.span()) {
                    Outgoing::found(fact)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
        }
    }

    fn exec_declaration(
        &mut self,
        decl: &'a Declaration<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        match decl {
            Declaration::VariableDeclaration(v) => {
                self.exec_var_decl(v, fact, until_use, Fact::Safe)
            }
            Declaration::FunctionDeclaration(_) => Outgoing::fallthrough(fact),
            Declaration::ClassDeclaration(c) => self.exec_class(c, fact, until_use),
            _ => Outgoing::fallthrough(fact),
        }
    }

    fn exec_export_default(
        &mut self,
        ex: &'a ExportDefaultDeclaration<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        match &ex.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(_) => Outgoing::fallthrough(fact),
            ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                self.exec_class(c, fact, until_use)
            }
            other => {
                if let Some(expr) = other.as_expression() {
                    self.exec_expr(expr, fact, until_use)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
        }
    }

    fn exec_return_or_throw(
        &mut self,
        arg: Option<&'a Expression<'a>>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        if let Some(expr) = arg {
            let out = self.exec_expr(expr, fact, until_use);
            if out.found.is_some() {
                return out;
            }
            return Outgoing::stop(out.next.unwrap_or(fact));
        }
        Outgoing::stop(fact)
    }

    /// `no_init_fact` is the value a declarator without an initializer binds.
    /// That is `undefined` (safe) for a plain `var`/`let`, but for a
    /// `for (const x of xs)` head it is whatever `xs` yields.
    fn exec_var_decl(
        &mut self,
        decl: &'a VariableDeclaration<'a>,
        mut fact: Fact,
        until_use: bool,
        no_init_fact: Fact,
    ) -> Outgoing {
        for declarator in &decl.declarations {
            if let Some(init) = &declarator.init {
                let out = self.exec_expr(init, fact, until_use);
                if out.found.is_some() {
                    return out;
                }
                fact = out.next.unwrap_or(fact);
            }
            if binding_is_symbol(&declarator.id, self.symbol_id) {
                if binding_is_simple(&declarator.id) {
                    fact = match &declarator.init {
                        Some(init) => self.fact_of(init, fact),
                        None => no_init_fact,
                    };
                } else {
                    fact = Fact::Unsafe;
                }
            }
            if until_use && self.contains_use(declarator.span) {
                return Outgoing::found(fact);
            }
        }
        Outgoing::fallthrough(fact)
    }

    fn exec_if(&mut self, ifs: &'a IfStatement<'a>, fact: Fact, until_use: bool) -> Outgoing {
        let test_out = self.exec_expr(&ifs.test, fact, until_use);
        if test_out.found.is_some() {
            return test_out;
        }
        let fact = match test_out.next {
            Some(f) => f,
            None => return test_out,
        };
        let truth = static_truthiness(self.ctx, &ifs.test, self.scope_id);

        if until_use && self.contains_use(ifs.consequent.span()) {
            return self.exec_stmt(&ifs.consequent, fact, true);
        }
        if let Some(alt) = &ifs.alternate {
            if until_use && self.contains_use(alt.span()) {
                return self.exec_stmt(alt, fact, true);
            }
        }

        let run_then = truth != Some(false);
        let run_else = truth != Some(true);
        let mut out = Outgoing::empty();
        if run_then {
            out.merge(self.exec_stmt(&ifs.consequent, fact, false));
        }
        if run_else {
            if let Some(alt) = &ifs.alternate {
                out.merge(self.exec_stmt(alt, fact, false));
            } else {
                out.next = join_opt(out.next, Some(fact));
            }
        }
        out
    }

    /// Fact reaching the loop head on the second and later iterations, i.e.
    /// `enter` joined with whatever flows back over the loop's back edge. On a
    /// two-point lattice a single extra pass already reaches the fixpoint.
    fn loop_carried_entry(
        &mut self,
        test: Option<&'a Expression<'a>>,
        body: &'a Statement<'a>,
        update: Option<&'a Expression<'a>>,
        enter: Fact,
        labels: &[String],
    ) -> Fact {
        let mut body_out = self.exec_stmt(body, enter, false);
        let cont = take_matching(&mut body_out.continues, labels, true);
        let Some(mut after) = join_opt(body_out.next, cont) else {
            return enter;
        };
        if let Some(upd) = update {
            after = self.exec_expr(upd, after, false).next.unwrap_or(after);
        }
        if let Some(test) = test {
            after = self.exec_expr(test, after, false).next.unwrap_or(after);
        }
        enter.join(after)
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_conditioned_loop(
        &mut self,
        test: &'a Expression<'a>,
        body: &'a Statement<'a>,
        update: Option<&'a Expression<'a>>,
        fact: Fact,
        until_use: bool,
        labels: &[String],
        body_first: bool,
    ) -> Outgoing {
        let mut exits = Outgoing::empty();
        let mut enter = fact;

        if !body_first {
            let test_out = self.exec_expr(test, fact, until_use);
            if test_out.found.is_some() {
                return test_out;
            }
            enter = test_out.next.unwrap_or(fact);
            let truth = static_truthiness(self.ctx, test, self.scope_id);
            if truth != Some(true) {
                exits.next = Some(enter);
            }
            if truth == Some(false) {
                return exits;
            }
        }

        let loop_test = (!body_first).then_some(test);
        if until_use && self.contains_use(body.span()) {
            let probe_in = self.loop_carried_entry(loop_test, body, update, enter, labels);
            let out = self.exec_stmt(body, probe_in, true);
            if out.found.is_some() {
                return out;
            }
        }
        if let Some(upd) = update {
            if until_use && self.contains_use(upd.span()) {
                let probe_in = self.loop_carried_entry(loop_test, body, update, enter, labels);
                let body_out = self.exec_stmt(body, probe_in, false);
                let fact = body_out.next.unwrap_or(probe_in);
                return self.exec_expr(upd, fact, true);
            }
        }

        let mut body_in = enter;
        for _ in 0..2 {
            let mut body_out = self.exec_stmt(body, body_in, false);
            if let Some(ex) = take_matching(&mut body_out.breaks, labels, true) {
                exits.next = join_opt(exits.next, Some(ex));
            }
            let cont = take_matching(&mut body_out.continues, labels, true);
            exits.merge(Outgoing {
                found: body_out.found,
                next: None,
                stops: body_out.stops,
                breaks: body_out.breaks,
                continues: body_out.continues,
            });
            if exits.found.is_some() {
                return exits;
            }

            let mut after_body = join_opt(body_out.next, cont);
            if let Some(upd) = update {
                if let Some(f) = after_body {
                    let upd_out = self.exec_expr(upd, f, false);
                    after_body = upd_out.next;
                    exits.merge(Outgoing {
                        found: upd_out.found,
                        next: None,
                        stops: upd_out.stops,
                        breaks: upd_out.breaks,
                        continues: upd_out.continues,
                    });
                }
            }

            let Some(after_body) = after_body else {
                break;
            };

            let test_out = self.exec_expr(test, after_body, false);
            let after_test = test_out.next.unwrap_or(after_body);
            let truth = static_truthiness(self.ctx, test, self.scope_id);
            if truth != Some(true) {
                exits.next = join_opt(exits.next, Some(after_test));
            }
            if truth == Some(false) {
                break;
            }
            let joined = body_in.join(after_test);
            if joined == body_in {
                break;
            }
            body_in = joined;
        }
        exits
    }

    fn exec_do_while(
        &mut self,
        stmt: &'a DoWhileStatement<'a>,
        fact: Fact,
        until_use: bool,
        labels: &[String],
    ) -> Outgoing {
        if until_use && self.contains_use(stmt.body.span()) {
            // The first iteration runs unconditionally, so `fact` is a real
            // entry state and must be joined with the back edge.
            let probe_in =
                self.loop_carried_entry(Some(&stmt.test), &stmt.body, None, fact, labels);
            let out = self.exec_stmt(&stmt.body, probe_in, true);
            if out.found.is_some() {
                return out;
            }
        }
        self.exec_conditioned_loop(&stmt.test, &stmt.body, None, fact, false, labels, true)
    }

    fn exec_for(
        &mut self,
        stmt: &'a ForStatement<'a>,
        fact: Fact,
        until_use: bool,
        labels: &[String],
    ) -> Outgoing {
        let mut fact = fact;
        if let Some(init) = &stmt.init {
            let out = if let ForStatementInit::VariableDeclaration(decl) = init {
                self.exec_var_decl(decl, fact, until_use, Fact::Safe)
            } else if let Some(expr) = init.as_expression() {
                self.exec_expr(expr, fact, until_use)
            } else {
                Outgoing::fallthrough(fact)
            };
            if out.found.is_some() {
                return out;
            }
            fact = out.next.unwrap_or(fact);
        }

        let test = stmt.test.as_ref();
        let update = stmt.update.as_ref();
        match test {
            Some(test) => {
                self.exec_conditioned_loop(test, &stmt.body, update, fact, until_use, labels, false)
            }
            None => self.exec_conditioned_loop_always(&stmt.body, update, fact, until_use, labels),
        }
    }

    fn exec_conditioned_loop_always(
        &mut self,
        body: &'a Statement<'a>,
        update: Option<&'a Expression<'a>>,
        fact: Fact,
        until_use: bool,
        labels: &[String],
    ) -> Outgoing {
        if until_use && self.contains_use(body.span()) {
            let probe_in = self.loop_carried_entry(None, body, update, fact, labels);
            return self.exec_stmt(body, probe_in, true);
        }
        let mut exits = Outgoing::empty();
        let mut body_in = fact;
        for _ in 0..2 {
            let mut body_out = self.exec_stmt(body, body_in, false);
            if let Some(ex) = take_matching(&mut body_out.breaks, labels, true) {
                exits.next = join_opt(exits.next, Some(ex));
            }
            let cont = take_matching(&mut body_out.continues, labels, true);
            exits.merge(Outgoing {
                found: body_out.found,
                next: None,
                stops: body_out.stops,
                breaks: body_out.breaks,
                continues: body_out.continues,
            });
            if exits.found.is_some() {
                return exits;
            }
            let mut after = join_opt(body_out.next, cont);
            if let Some(upd) = update {
                if let Some(f) = after {
                    let upd_out = self.exec_expr(upd, f, false);
                    after = upd_out.next;
                }
            }
            let Some(after) = after else {
                break;
            };
            let joined = body_in.join(after);
            if joined == body_in {
                break;
            }
            body_in = joined;
        }
        exits
    }

    fn exec_for_in_of(
        &mut self,
        left: &'a ForStatementLeft<'a>,
        right: &'a Expression<'a>,
        body: &'a Statement<'a>,
        fact: Fact,
        until_use: bool,
        labels: &[String],
    ) -> Outgoing {
        let right_out = self.exec_expr(right, fact, until_use);
        if right_out.found.is_some() {
            return right_out;
        }
        let after_right = right_out.next.unwrap_or(fact);

        // Every iteration re-binds the loop variable to an element (for-of) or
        // a property name (for-in) of `right`, so that is the value reaching
        // uses in the body, not `undefined` and not the previous iteration's.
        let element_fact = self.fact_of(right, after_right);

        let left_out = if let ForStatementLeft::VariableDeclaration(decl) = left {
            self.exec_var_decl(decl, after_right, until_use, element_fact)
        } else if let Some(target) = left.as_assignment_target() {
            let mut out = self.exec_assignment_target(target, after_right, until_use);
            if out.found.is_none() {
                if let Some(f) = out.next.as_mut() {
                    if assignment_target_writes_symbol(self.ctx, target, self.symbol_id)
                        && !is_const_variable_binding(self.ctx, self.symbol_id)
                    {
                        *f = if is_destructuring_target(target) {
                            Fact::Unsafe
                        } else {
                            element_fact
                        };
                    }
                }
            }
            out
        } else {
            Outgoing::fallthrough(after_right)
        };
        if left_out.found.is_some() {
            return left_out;
        }
        let body_in = left_out.next.unwrap_or(after_right);

        let iters = static_iter_count(right);
        let mut exits = Outgoing::empty();
        if iters != Some(IterCount::OneOrMore) {
            exits.next = Some(after_right);
        }
        if iters == Some(IterCount::Zero) {
            return exits;
        }

        if until_use && self.contains_use(body.span()) {
            // A head that re-binds the symbol overwrites it on every iteration,
            // so nothing flows back over the loop's back edge.
            let rebinds = matches!(left, ForStatementLeft::VariableDeclaration(_))
                && for_left_writes_symbol(self.ctx, left, self.symbol_id);
            let probe_in = if rebinds {
                body_in
            } else {
                self.loop_carried_entry(None, body, None, body_in, labels)
            };
            return self.exec_stmt(body, probe_in, true);
        }

        let mut enter = body_in;
        let mut after_iter = None;
        for _ in 0..2 {
            let mut body_out = self.exec_stmt(body, enter, false);
            if let Some(ex) = take_matching(&mut body_out.breaks, labels, true) {
                exits.next = join_opt(exits.next, Some(ex));
            }
            let cont = take_matching(&mut body_out.continues, labels, true);
            exits.merge(Outgoing {
                found: body_out.found,
                next: None,
                stops: body_out.stops,
                breaks: body_out.breaks,
                continues: body_out.continues,
            });
            if exits.found.is_some() {
                return exits;
            }
            let after = join_opt(body_out.next, cont);
            after_iter = join_opt(after_iter, after);
            let Some(after) = after else {
                break;
            };
            let next_enter = after.join(body_in);
            if next_enter == enter {
                break;
            }
            enter = next_enter;
        }
        if iters != Some(IterCount::OneOrMore) {
            exits.next = join_opt(exits.next, Some(after_right));
        }
        if iters != Some(IterCount::Zero) {
            exits.next = join_opt(exits.next, after_iter);
        }
        exits
    }

    fn exec_switch(
        &mut self,
        sw: &'a SwitchStatement<'a>,
        fact: Fact,
        until_use: bool,
        labels: &[String],
    ) -> Outgoing {
        let disc_out = self.exec_expr(&sw.discriminant, fact, until_use);
        if disc_out.found.is_some() {
            return disc_out;
        }
        let mut fact = disc_out.next.unwrap_or(fact);

        let disc_key = static_literal_key(self.ctx, &sw.discriminant, self.scope_id);
        let mut default_idx = None;
        let mut matched_idx = None;
        let mut incomparable = disc_key.is_none();
        for (i, case) in sw.cases.iter().enumerate() {
            match &case.test {
                None => default_idx = Some(i),
                Some(test) => {
                    if until_use && self.contains_use(test.span()) {
                        return self.exec_expr(test, fact, true);
                    }
                    if let Some(ref dk) = disc_key {
                        match static_literal_key(self.ctx, test, self.scope_id) {
                            Some(tk) if tk == *dk && matched_idx.is_none() => {
                                matched_idx = Some(i);
                            }
                            None => incomparable = true,
                            Some(_) => {}
                        }
                    }
                }
            }
        }

        let possible: Vec<usize> = if let Some(idx) = matched_idx {
            for case in sw.cases.iter().take(idx + 1) {
                if let Some(test) = &case.test {
                    let out = self.exec_expr(test, fact, false);
                    fact = out.next.unwrap_or(fact);
                }
            }
            vec![idx]
        } else if !incomparable {
            if let Some(d) = default_idx {
                for case in &sw.cases {
                    if let Some(test) = &case.test {
                        let out = self.exec_expr(test, fact, false);
                        fact = out.next.unwrap_or(fact);
                    }
                }
                vec![d]
            } else {
                for case in &sw.cases {
                    if let Some(test) = &case.test {
                        let out = self.exec_expr(test, fact, false);
                        fact = out.next.unwrap_or(fact);
                    }
                }
                return Outgoing::fallthrough(fact);
            }
        } else {
            for case in &sw.cases {
                if let Some(test) = &case.test {
                    let out = self.exec_expr(test, fact, false);
                    if let Some(after) = out.next {
                        fact = fact.join(after);
                    }
                }
            }
            (0..sw.cases.len()).collect()
        };

        let mut merged = Outgoing::empty();
        if incomparable && default_idx.is_none() {
            merged.next = Some(fact);
        }

        let use_case = if until_use {
            sw.cases.iter().position(|c| self.contains_use(c.span()))
        } else {
            None
        };

        for start in possible {
            if let Some(use_idx) = use_case {
                if start > use_idx {
                    continue;
                }
            }
            merged.merge(self.exec_switch_from(&sw.cases, start, fact, until_use, labels));
        }
        merged
    }

    fn exec_switch_from(
        &mut self,
        cases: &'a [SwitchCase<'a>],
        start: usize,
        mut fact: Fact,
        until_use: bool,
        labels: &[String],
    ) -> Outgoing {
        let mut acc = Outgoing::empty();
        for case in cases.iter().skip(start) {
            let probe = until_use && self.contains_use(case.span);
            let mut out = self.exec_list(&case.consequent, fact, probe);
            if out.found.is_some() {
                return out;
            }
            if let Some(ex) = take_matching(&mut out.breaks, labels, true) {
                acc.next = join_opt(acc.next, Some(ex));
                acc.merge(Outgoing {
                    found: None,
                    next: None,
                    stops: out.stops,
                    breaks: out.breaks,
                    continues: out.continues,
                });
                return acc;
            }
            acc.merge(Outgoing {
                found: None,
                next: None,
                stops: out.stops,
                breaks: out.breaks,
                continues: out.continues,
            });
            match out.next {
                Some(f) => fact = f,
                None => return acc,
            }
        }
        acc.next = Some(fact);
        acc
    }

    fn exec_try(&mut self, stmt: &'a TryStatement<'a>, fact: Fact, until_use: bool) -> Outgoing {
        if until_use && self.contains_use(stmt.block.span) {
            return self.exec_list(&stmt.block.body, fact, true);
        }
        // An exception can be raised between any two statements of the block,
        // so the handler must see every value the symbol holds inside it, not
        // only the one that reaches the end.
        let outer = self.intermediate.replace(fact);
        let try_out = self.exec_list(&stmt.block.body, fact, false);
        let thrown = self.intermediate.take().unwrap_or(fact);
        self.intermediate = outer.map(|f| f.join(thrown));

        let mut tc = try_out;
        if let Some(handler) = &stmt.handler {
            if until_use && self.contains_use(handler.span) {
                let catch_in = join_opt(tc.next, Some(thrown)).unwrap_or(thrown);
                let catch_in = join_opt(Some(catch_in), tc.stops).unwrap_or(catch_in);
                return self.exec_list(&handler.body.body, catch_in, true);
            }
            let catch_in = join_opt(join_opt(tc.next, Some(thrown)), tc.stops).unwrap_or(thrown);
            let catch_out = self.exec_list(&handler.body.body, catch_in, false);
            let mut merged = Outgoing::empty();
            merged.found = join_opt(tc.found, catch_out.found);
            merged.next = join_opt(tc.next, catch_out.next);
            merged.stops = catch_out.stops;
            merge_jumps(&mut merged.breaks, tc.breaks);
            merge_jumps(&mut merged.breaks, catch_out.breaks);
            merge_jumps(&mut merged.continues, tc.continues);
            merge_jumps(&mut merged.continues, catch_out.continues);
            tc = merged;
        }

        if let Some(fin) = &stmt.finalizer {
            let mut fin_in = join_opt(tc.next, tc.stops);
            for (_, fact) in tc.breaks.iter().chain(tc.continues.iter()) {
                fin_in = join_opt(fin_in, Some(*fact));
            }
            // Without a handler the finalizer also runs on the exceptional
            // path; with one, `thrown` already went through `catch_in`.
            if stmt.handler.is_none() {
                fin_in = join_opt(fin_in, Some(thrown));
            }
            let fin_in = fin_in.unwrap_or(thrown);
            if until_use && self.contains_use(fin.span) {
                return self.exec_list(&fin.body, fin_in, true);
            }
            let fin_out = self.exec_list(&fin.body, fin_in, false);
            if fin_out.next.is_none() {
                return fin_out;
            }
            let f = fin_out.next.unwrap();
            return Outgoing {
                found: join_opt(tc.found, fin_out.found),
                next: tc.next.map(|_| f),
                stops: join_opt(tc.stops.map(|_| f), fin_out.stops),
                breaks: tc.breaks.into_iter().map(|(l, _)| (l, f)).collect(),
                continues: tc.continues.into_iter().map(|(l, _)| (l, f)).collect(),
            };
        }
        tc
    }

    fn exec_class(&mut self, class: &'a Class<'a>, mut fact: Fact, until_use: bool) -> Outgoing {
        if let Some(sup) = &class.super_class {
            let out = self.exec_expr(sup, fact, until_use);
            if out.found.is_some() {
                return out;
            }
            fact = out.next.unwrap_or(fact);
        }
        for element in &class.body.body {
            match element {
                ClassElement::StaticBlock(block) => {
                    let out = self.exec_list(&block.body, fact, until_use);
                    if out.found.is_some() {
                        return out;
                    }
                    fact = out.next.unwrap_or(fact);
                }
                ClassElement::PropertyDefinition(prop) => {
                    let out = self.exec_property_key(&prop.key, prop.computed, fact, until_use);
                    if out.found.is_some() {
                        return out;
                    }
                    fact = out.next.unwrap_or(fact);
                    if prop.r#static {
                        if let Some(value) = &prop.value {
                            let out = self.exec_expr(value, fact, until_use);
                            if out.found.is_some() {
                                return out;
                            }
                            fact = out.next.unwrap_or(fact);
                        }
                    }
                }
                ClassElement::MethodDefinition(method) => {
                    let out = self.exec_property_key(&method.key, method.computed, fact, until_use);
                    if out.found.is_some() {
                        return out;
                    }
                    fact = out.next.unwrap_or(fact);
                }
                ClassElement::AccessorProperty(prop) => {
                    let out = self.exec_property_key(&prop.key, prop.computed, fact, until_use);
                    if out.found.is_some() {
                        return out;
                    }
                    fact = out.next.unwrap_or(fact);
                    if prop.r#static {
                        if let Some(value) = &prop.value {
                            let out = self.exec_expr(value, fact, until_use);
                            if out.found.is_some() {
                                return out;
                            }
                            fact = out.next.unwrap_or(fact);
                        }
                    }
                }
                ClassElement::TSIndexSignature(_) => {}
            }
        }
        Outgoing::fallthrough(fact)
    }

    fn exec_property_key(
        &mut self,
        key: &'a PropertyKey<'a>,
        computed: bool,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        if computed {
            if let Some(expr) = key.as_expression() {
                return self.exec_expr(expr, fact, until_use);
            }
        }
        Outgoing::fallthrough(fact)
    }

    fn exec_expr(&mut self, expr: &'a Expression<'a>, fact: Fact, until_use: bool) -> Outgoing {
        let until_use = until_use && self.contains_use(expr.span());
        let expr = unwrap_expression(expr);
        match expr {
            Expression::Identifier(id) => {
                if until_use && id.span == self.use_span && self.refers(id) {
                    Outgoing::found(fact)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
            Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::RegExpLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::ThisExpression(_)
            | Expression::Super(_)
            | Expression::MetaProperty(_)
            | Expression::FunctionExpression(_)
            | Expression::ArrowFunctionExpression(_)
            | Expression::JSXElement(_)
            | Expression::JSXFragment(_) => Outgoing::fallthrough(fact),
            Expression::TemplateLiteral(lit) => {
                self.exec_expr_list(&lit.expressions, fact, until_use)
            }
            Expression::ArrayExpression(arr) => {
                let mut fact = fact;
                for el in &arr.elements {
                    let out = match el {
                        ArrayExpressionElement::SpreadElement(s) => {
                            self.exec_expr(&s.argument, fact, until_use)
                        }
                        ArrayExpressionElement::Elision(_) => Outgoing::fallthrough(fact),
                        other => {
                            if let Some(e) = other.as_expression() {
                                self.exec_expr(e, fact, until_use)
                            } else {
                                Outgoing::fallthrough(fact)
                            }
                        }
                    };
                    if out.found.is_some() {
                        return out;
                    }
                    fact = out.next.unwrap_or(fact);
                }
                Outgoing::fallthrough(fact)
            }
            Expression::ObjectExpression(obj) => self.exec_object(obj, fact, until_use),
            Expression::SequenceExpression(seq) => {
                self.exec_expr_list(&seq.expressions, fact, until_use)
            }
            Expression::UnaryExpression(u) => self.exec_expr(&u.argument, fact, until_use),
            Expression::UpdateExpression(u) => self.exec_update(u, fact, until_use),
            Expression::BinaryExpression(b) => {
                let left = self.exec_expr(&b.left, fact, until_use);
                if left.found.is_some() {
                    return left;
                }
                self.exec_expr(&b.right, left.next.unwrap_or(fact), until_use)
            }
            Expression::PrivateInExpression(p) => self.exec_expr(&p.right, fact, until_use),
            Expression::LogicalExpression(l) => self.exec_logical(l, fact, until_use),
            Expression::ConditionalExpression(c) => self.exec_conditional(c, fact, until_use),
            Expression::AssignmentExpression(a) => self.exec_assignment(a, fact, until_use),
            Expression::CallExpression(c) => self.exec_call(c, fact, until_use),
            Expression::NewExpression(n) => self.exec_new(n, fact, until_use),
            Expression::ComputedMemberExpression(_)
            | Expression::StaticMemberExpression(_)
            | Expression::PrivateFieldExpression(_) => {
                self.exec_member(expr.get_member_expr().unwrap(), fact, until_use)
            }
            Expression::ChainExpression(c) => self.exec_chain(c, fact, until_use),
            Expression::AwaitExpression(a) => self.exec_expr(&a.argument, fact, until_use),
            Expression::YieldExpression(y) => {
                if let Some(arg) = &y.argument {
                    self.exec_expr(arg, fact, until_use)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
            Expression::TaggedTemplateExpression(t) => {
                let tag = self.exec_expr(&t.tag, fact, until_use);
                if tag.found.is_some() {
                    return tag;
                }
                self.exec_expr_list(&t.quasi.expressions, tag.next.unwrap_or(fact), until_use)
            }
            Expression::ClassExpression(c) => self.exec_class(c, fact, until_use),
            Expression::ImportExpression(i) => {
                let src = self.exec_expr(&i.source, fact, until_use);
                if src.found.is_some() {
                    return src;
                }
                if let Some(opts) = &i.options {
                    self.exec_expr(opts, src.next.unwrap_or(fact), until_use)
                } else {
                    src
                }
            }
            Expression::V8IntrinsicExpression(v) => self.exec_args(&v.arguments, fact, until_use),
            Expression::ParenthesizedExpression(p) => {
                self.exec_expr(&p.expression, fact, until_use)
            }
            Expression::TSAsExpression(e) => self.exec_expr(&e.expression, fact, until_use),
            Expression::TSSatisfiesExpression(e) => self.exec_expr(&e.expression, fact, until_use),
            Expression::TSNonNullExpression(e) => self.exec_expr(&e.expression, fact, until_use),
            Expression::TSTypeAssertion(e) => self.exec_expr(&e.expression, fact, until_use),
            Expression::TSInstantiationExpression(e) => {
                self.exec_expr(&e.expression, fact, until_use)
            }
        }
    }

    fn exec_expr_list(
        &mut self,
        exprs: &'a [Expression<'a>],
        mut fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        for expr in exprs {
            let out = self.exec_expr(expr, fact, until_use);
            if out.found.is_some() {
                return out;
            }
            fact = out.next.unwrap_or(fact);
        }
        Outgoing::fallthrough(fact)
    }

    fn exec_object(
        &mut self,
        obj: &'a ObjectExpression<'a>,
        mut fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        for prop in &obj.properties {
            let out = match prop {
                ObjectPropertyKind::SpreadProperty(s) => {
                    self.exec_expr(&s.argument, fact, until_use)
                }
                ObjectPropertyKind::ObjectProperty(p) => {
                    let key_out = self.exec_property_key(&p.key, p.computed, fact, until_use);
                    if key_out.found.is_some() {
                        return key_out;
                    }
                    let fact = key_out.next.unwrap_or(fact);
                    if p.method || matches!(p.kind, PropertyKind::Get | PropertyKind::Set) {
                        Outgoing::fallthrough(fact)
                    } else {
                        self.exec_expr(&p.value, fact, until_use)
                    }
                }
            };
            if out.found.is_some() {
                return out;
            }
            fact = out.next.unwrap_or(fact);
        }
        Outgoing::fallthrough(fact)
    }

    fn exec_logical(
        &mut self,
        logical: &'a LogicalExpression<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        let left = self.exec_expr(&logical.left, fact, until_use);
        if left.found.is_some() {
            return left;
        }
        let after_left = left.next.unwrap_or(fact);
        let truth = static_truthiness(self.ctx, &logical.left, self.scope_id);
        let skip_right = match logical.operator {
            LogicalOperator::And => truth == Some(false),
            LogicalOperator::Or => truth == Some(true),
            LogicalOperator::Coalesce => {
                is_nullish_literal(self.ctx, &logical.left, self.scope_id) == Some(false)
            }
        };
        let force_right = match logical.operator {
            LogicalOperator::And => truth == Some(true),
            LogicalOperator::Or => truth == Some(false),
            LogicalOperator::Coalesce => {
                is_nullish_literal(self.ctx, &logical.left, self.scope_id) == Some(true)
            }
        };
        if skip_right {
            return Outgoing::fallthrough(after_left);
        }
        if until_use && self.contains_use(logical.right.span()) {
            return self.exec_expr(&logical.right, after_left, true);
        }
        let right = self.exec_expr(&logical.right, after_left, false);
        if force_right {
            return right;
        }
        let mut out = Outgoing::fallthrough(after_left);
        out.merge(right);
        out
    }

    fn exec_conditional(
        &mut self,
        cond: &'a ConditionalExpression<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        let test = self.exec_expr(&cond.test, fact, until_use);
        if test.found.is_some() {
            return test;
        }
        let fact = test.next.unwrap_or(fact);
        let truth = static_truthiness(self.ctx, &cond.test, self.scope_id);
        if until_use && self.contains_use(cond.consequent.span()) {
            return self.exec_expr(&cond.consequent, fact, true);
        }
        if until_use && self.contains_use(cond.alternate.span()) {
            return self.exec_expr(&cond.alternate, fact, true);
        }
        let run_then = truth != Some(false);
        let run_else = truth != Some(true);
        let mut out = Outgoing::empty();
        if run_then {
            out.merge(self.exec_expr(&cond.consequent, fact, false));
        }
        if run_else {
            out.merge(self.exec_expr(&cond.alternate, fact, false));
        }
        out
    }

    fn exec_assignment(
        &mut self,
        assign: &'a AssignmentExpression<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        let right = self.exec_expr(&assign.right, fact, until_use);
        if right.found.is_some() {
            return right;
        }
        let mut fact = right.next.unwrap_or(fact);
        let left = self.exec_assignment_target(&assign.left, fact, until_use);
        if left.found.is_some() {
            return left;
        }
        fact = left.next.unwrap_or(fact);

        if assignment_target_writes_symbol(self.ctx, &assign.left, self.symbol_id)
            && !is_const_variable_binding(self.ctx, self.symbol_id)
        {
            if is_destructuring_target(&assign.left) {
                fact = Fact::Unsafe;
            } else if assign.operator.is_assign() {
                fact = self.fact_of(&assign.right, fact);
            } else {
                fact = fact.join(self.fact_of(&assign.right, fact));
            }
        }
        Outgoing::fallthrough(fact)
    }

    fn exec_update(
        &mut self,
        upd: &'a UpdateExpression<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        let out = self.exec_simple_target(&upd.argument, fact, until_use);
        if out.found.is_some() {
            return out;
        }
        let mut fact = out.next.unwrap_or(fact);
        if simple_target_writes_symbol(self.ctx, &upd.argument, self.symbol_id)
            && !is_const_variable_binding(self.ctx, self.symbol_id)
        {
            fact = Fact::Safe;
        }
        Outgoing::fallthrough(fact)
    }

    fn exec_call(&mut self, call: &'a CallExpression<'a>, fact: Fact, until_use: bool) -> Outgoing {
        let callee_out = self.exec_expr(&call.callee, fact, until_use);
        if callee_out.found.is_some() {
            return callee_out;
        }
        let args_out = self.exec_args(&call.arguments, callee_out.next.unwrap_or(fact), until_use);
        if args_out.found.is_some() {
            return args_out;
        }
        let fact = args_out.next.unwrap_or(fact);
        if let Some(func) = iife_from_callee(&call.callee).or_else(|| call_apply_iife(call)) {
            return self.exec_iife(func, fact, until_use);
        }
        Outgoing::fallthrough(fact)
    }

    fn exec_new(
        &mut self,
        new_expr: &'a NewExpression<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        let callee_out = self.exec_expr(&new_expr.callee, fact, until_use);
        if callee_out.found.is_some() {
            return callee_out;
        }
        let args_out = self.exec_args(
            &new_expr.arguments,
            callee_out.next.unwrap_or(fact),
            until_use,
        );
        if args_out.found.is_some() {
            return args_out;
        }
        let fact = args_out.next.unwrap_or(fact);
        if let Some(func) = iife_from_callee(&new_expr.callee) {
            return self.exec_iife(func, fact, until_use);
        }
        Outgoing::fallthrough(fact)
    }

    fn exec_args(&mut self, args: &'a [Argument<'a>], mut fact: Fact, until_use: bool) -> Outgoing {
        for arg in args {
            let out = match arg {
                Argument::SpreadElement(s) => self.exec_expr(&s.argument, fact, until_use),
                other => {
                    if let Some(expr) = other.as_expression() {
                        self.exec_expr(expr, fact, until_use)
                    } else {
                        Outgoing::fallthrough(fact)
                    }
                }
            };
            if out.found.is_some() {
                return out;
            }
            fact = out.next.unwrap_or(fact);
        }
        Outgoing::fallthrough(fact)
    }

    fn exec_iife(&mut self, func: CalleeFn<'a>, fact: Fact, until_use: bool) -> Outgoing {
        let body = match func {
            CalleeFn::Fn(f) => match &f.body {
                Some(body) => body,
                None => return Outgoing::fallthrough(fact),
            },
            CalleeFn::Arrow(f) => &f.body,
        };
        let mut out = self.exec_list(&body.statements, fact, until_use);
        out.next = join_opt(out.next, out.stops);
        out.stops = None;
        out.breaks.clear();
        out.continues.clear();
        out
    }

    fn exec_member(
        &mut self,
        member: &'a MemberExpression<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        match member {
            MemberExpression::ComputedMemberExpression(m) => {
                let obj = self.exec_expr(&m.object, fact, until_use);
                if obj.found.is_some() {
                    return obj;
                }
                self.exec_expr(&m.expression, obj.next.unwrap_or(fact), until_use)
            }
            MemberExpression::StaticMemberExpression(m) => {
                self.exec_expr(&m.object, fact, until_use)
            }
            MemberExpression::PrivateFieldExpression(m) => {
                self.exec_expr(&m.object, fact, until_use)
            }
        }
    }

    fn exec_chain(
        &mut self,
        chain: &'a ChainExpression<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        match &chain.expression {
            ChainElement::CallExpression(call) => self.exec_call(call, fact, until_use),
            ChainElement::TSNonNullExpression(inner) => {
                self.exec_expr(&inner.expression, fact, until_use)
            }
            other => {
                if let Some(member) = other.as_member_expression() {
                    self.exec_member(member, fact, until_use)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
        }
    }

    fn exec_assignment_target(
        &mut self,
        target: &'a AssignmentTarget<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        match target {
            AssignmentTarget::AssignmentTargetIdentifier(id) => {
                if until_use && id.span == self.use_span && self.refers(id) {
                    Outgoing::found(fact)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
            AssignmentTarget::ComputedMemberExpression(m) => {
                let obj = self.exec_expr(&m.object, fact, until_use);
                if obj.found.is_some() {
                    return obj;
                }
                self.exec_expr(&m.expression, obj.next.unwrap_or(fact), until_use)
            }
            AssignmentTarget::StaticMemberExpression(m) => {
                self.exec_expr(&m.object, fact, until_use)
            }
            AssignmentTarget::PrivateFieldExpression(m) => {
                self.exec_expr(&m.object, fact, until_use)
            }
            AssignmentTarget::ArrayAssignmentTarget(arr) => {
                let mut fact = fact;
                for el in arr.elements.iter().flatten() {
                    let out = self.exec_maybe_default(el, fact, until_use);
                    if out.found.is_some() {
                        return out;
                    }
                    fact = out.next.unwrap_or(fact);
                }
                if let Some(rest) = &arr.rest {
                    return self.exec_assignment_target(&rest.target, fact, until_use);
                }
                Outgoing::fallthrough(fact)
            }
            AssignmentTarget::ObjectAssignmentTarget(obj) => {
                let mut fact = fact;
                for prop in &obj.properties {
                    let out = match prop {
                        AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(p) => {
                            if let Some(init) = &p.init {
                                self.exec_expr(init, fact, until_use)
                            } else {
                                Outgoing::fallthrough(fact)
                            }
                        }
                        AssignmentTargetProperty::AssignmentTargetPropertyProperty(p) => {
                            let key = self.exec_property_key(&p.name, p.computed, fact, until_use);
                            if key.found.is_some() {
                                return key;
                            }
                            self.exec_maybe_default(&p.binding, key.next.unwrap_or(fact), until_use)
                        }
                    };
                    if out.found.is_some() {
                        return out;
                    }
                    fact = out.next.unwrap_or(fact);
                }
                if let Some(rest) = &obj.rest {
                    return self.exec_assignment_target(&rest.target, fact, until_use);
                }
                Outgoing::fallthrough(fact)
            }
            other => {
                if let Some(expr) = other.get_expression() {
                    self.exec_expr(expr, fact, until_use)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
        }
    }

    fn exec_maybe_default(
        &mut self,
        target: &'a AssignmentTargetMaybeDefault<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        match target {
            AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(w) => {
                let init = self.exec_expr(&w.init, fact, until_use);
                if init.found.is_some() {
                    return init;
                }
                self.exec_assignment_target(&w.binding, init.next.unwrap_or(fact), until_use)
            }
            other => {
                if let Some(t) = other.as_assignment_target() {
                    self.exec_assignment_target(t, fact, until_use)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
        }
    }

    fn exec_simple_target(
        &mut self,
        target: &'a SimpleAssignmentTarget<'a>,
        fact: Fact,
        until_use: bool,
    ) -> Outgoing {
        match target {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(id) => {
                if until_use && id.span == self.use_span && self.refers(id) {
                    Outgoing::found(fact)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
            SimpleAssignmentTarget::ComputedMemberExpression(m) => {
                let obj = self.exec_expr(&m.object, fact, until_use);
                if obj.found.is_some() {
                    return obj;
                }
                self.exec_expr(&m.expression, obj.next.unwrap_or(fact), until_use)
            }
            SimpleAssignmentTarget::StaticMemberExpression(m) => {
                self.exec_expr(&m.object, fact, until_use)
            }
            SimpleAssignmentTarget::PrivateFieldExpression(m) => {
                self.exec_expr(&m.object, fact, until_use)
            }
            other => {
                if let Some(expr) = other.get_expression() {
                    self.exec_expr(expr, fact, until_use)
                } else {
                    Outgoing::fallthrough(fact)
                }
            }
        }
    }
}

fn peel_labels<'a>(stmt: &'a Statement<'a>) -> (Vec<String>, &'a Statement<'a>) {
    let mut labels = Vec::new();
    let mut cur = stmt;
    while let Statement::LabeledStatement(ls) = cur {
        labels.push(ls.label.name.to_string());
        cur = &ls.body;
    }
    (labels, cur)
}

fn binding_is_symbol(binding: &BindingPattern<'_>, symbol_id: SymbolId) -> bool {
    binding
        .get_binding_identifiers()
        .iter()
        .any(|id| id.symbol_id.get() == Some(symbol_id))
}

fn binding_is_simple(binding: &BindingPattern<'_>) -> bool {
    matches!(binding, BindingPattern::BindingIdentifier(_))
}

fn assignment_target_writes_symbol(
    ctx: &AnalysisCtx<'_>,
    target: &AssignmentTarget<'_>,
    symbol_id: SymbolId,
) -> bool {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => refers_to_symbol(ctx, id, symbol_id),
        AssignmentTarget::ArrayAssignmentTarget(arr) => {
            arr.elements
                .iter()
                .flatten()
                .any(|el| maybe_default_writes_symbol(ctx, el, symbol_id))
                || arr
                    .rest
                    .as_ref()
                    .is_some_and(|r| assignment_target_writes_symbol(ctx, &r.target, symbol_id))
        }
        AssignmentTarget::ObjectAssignmentTarget(obj) => {
            obj.properties.iter().any(|p| match p {
                AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(p) => {
                    refers_to_symbol(ctx, &p.binding, symbol_id)
                }
                AssignmentTargetProperty::AssignmentTargetPropertyProperty(p) => {
                    maybe_default_writes_symbol(ctx, &p.binding, symbol_id)
                }
            }) || obj
                .rest
                .as_ref()
                .is_some_and(|r| assignment_target_writes_symbol(ctx, &r.target, symbol_id))
        }
        _ => false,
    }
}

fn maybe_default_writes_symbol(
    ctx: &AnalysisCtx<'_>,
    target: &AssignmentTargetMaybeDefault<'_>,
    symbol_id: SymbolId,
) -> bool {
    match target {
        AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(w) => {
            assignment_target_writes_symbol(ctx, &w.binding, symbol_id)
        }
        other => other
            .as_assignment_target()
            .is_some_and(|t| assignment_target_writes_symbol(ctx, t, symbol_id)),
    }
}

fn is_destructuring_target(target: &AssignmentTarget<'_>) -> bool {
    matches!(
        target,
        AssignmentTarget::ArrayAssignmentTarget(_) | AssignmentTarget::ObjectAssignmentTarget(_)
    )
}

fn simple_target_writes_symbol(
    ctx: &AnalysisCtx<'_>,
    target: &SimpleAssignmentTarget<'_>,
    symbol_id: SymbolId,
) -> bool {
    match target {
        SimpleAssignmentTarget::AssignmentTargetIdentifier(id) => {
            refers_to_symbol(ctx, id, symbol_id)
        }
        _ => false,
    }
}

fn for_left_writes_symbol(
    ctx: &AnalysisCtx<'_>,
    left: &ForStatementLeft<'_>,
    symbol_id: SymbolId,
) -> bool {
    if let ForStatementLeft::VariableDeclaration(decl) = left {
        return decl
            .declarations
            .iter()
            .any(|d| binding_is_symbol(&d.id, symbol_id));
    }
    left.as_assignment_target()
        .is_some_and(|t| assignment_target_writes_symbol(ctx, t, symbol_id))
}

enum CalleeFn<'a> {
    Fn(&'a Function<'a>),
    Arrow(&'a ArrowFunctionExpression<'a>),
}

fn iife_from_callee<'a>(callee: &'a Expression<'a>) -> Option<CalleeFn<'a>> {
    let callee = unwrap_expression(callee);
    if let Expression::SequenceExpression(seq) = callee {
        return seq.expressions.last().and_then(iife_from_callee);
    }
    match callee {
        Expression::FunctionExpression(f) => Some(CalleeFn::Fn(f)),
        Expression::ArrowFunctionExpression(f) => Some(CalleeFn::Arrow(f)),
        _ => None,
    }
}

fn call_apply_iife<'a>(call: &'a CallExpression<'a>) -> Option<CalleeFn<'a>> {
    let member = unwrap_expression(&call.callee).get_member_expr()?;
    let prop = member.static_property_name()?;
    if prop != "call" && prop != "apply" {
        return None;
    }
    iife_from_callee(member.object())
}

fn static_truthiness<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> Option<bool> {
    let expr = unwrap_expression(expr);
    match expr {
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => {
            return static_truthiness(ctx, &u.argument, scope_id).map(|b| !b);
        }
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::Void => {
            return Some(false);
        }
        Expression::SequenceExpression(seq) => {
            return seq
                .expressions
                .last()
                .and_then(|e| static_truthiness(ctx, e, scope_id));
        }
        _ => {}
    }
    match resolve_identifier(ctx, expr, scope_id) {
        Expression::BooleanLiteral(b) => Some(b.value),
        Expression::NullLiteral(_) => Some(false),
        Expression::NumericLiteral(n) => Some(n.value != 0.0 && !n.value.is_nan()),
        Expression::BigIntLiteral(b) => Some(b.value.as_str() != "0"),
        Expression::StringLiteral(s) => Some(!s.value.is_empty()),
        Expression::TemplateLiteral(t) if t.expressions.is_empty() => Some(
            t.quasis
                .first()
                .and_then(|q| q.value.cooked.as_ref())
                .is_some_and(|c| !c.is_empty()),
        ),
        Expression::ArrayExpression(_)
        | Expression::ObjectExpression(_)
        | Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::ClassExpression(_)
        | Expression::RegExpLiteral(_) => Some(true),
        Expression::Identifier(id) if id.name == "undefined" || id.name == "NaN" => Some(false),
        Expression::Identifier(id) if id.name == "Infinity" => Some(true),
        resolved => {
            if std::ptr::eq(resolved, expr) {
                None
            } else {
                static_truthiness(ctx, resolved, scope_id)
            }
        }
    }
}

fn is_nullish_literal<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> Option<bool> {
    match resolve_identifier(ctx, unwrap_expression(expr), scope_id) {
        Expression::NullLiteral(_) => Some(true),
        Expression::Identifier(id) if id.name == "undefined" => Some(true),
        Expression::BooleanLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::ObjectExpression(_)
        | Expression::ArrayExpression(_) => Some(false),
        _ => None,
    }
}

#[derive(Clone, PartialEq, Eq)]
enum LiteralKey {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    BigInt(String),
    Undefined,
}

fn static_literal_key<'a>(
    ctx: &AnalysisCtx<'a>,
    expr: &'a Expression<'a>,
    scope_id: ScopeId,
) -> Option<LiteralKey> {
    match resolve_identifier(ctx, unwrap_expression(expr), scope_id) {
        Expression::NullLiteral(_) => Some(LiteralKey::Null),
        Expression::BooleanLiteral(b) => Some(LiteralKey::Bool(b.value)),
        Expression::NumericLiteral(n) => Some(LiteralKey::Num(n.value.to_bits())),
        Expression::StringLiteral(s) => Some(LiteralKey::Str(s.value.to_string())),
        Expression::BigIntLiteral(b) => Some(LiteralKey::BigInt(b.value.to_string())),
        Expression::Identifier(id) if id.name == "undefined" => Some(LiteralKey::Undefined),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IterCount {
    Zero,
    OneOrMore,
}

fn static_iter_count(expr: &Expression<'_>) -> Option<IterCount> {
    match unwrap_expression(expr) {
        Expression::ArrayExpression(arr) => {
            if arr
                .elements
                .iter()
                .any(|el| matches!(el, ArrayExpressionElement::SpreadElement(_)))
            {
                return None;
            }
            let n = arr
                .elements
                .iter()
                .filter(|el| !matches!(el, ArrayExpressionElement::Elision(_)))
                .count();
            if n == 0 {
                Some(IterCount::Zero)
            } else {
                Some(IterCount::OneOrMore)
            }
        }
        _ => None,
    }
}
