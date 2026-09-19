mod common;
use common::{with_identifier_usage, with_last_expr};
use sinksight_engine::inference::is_safe_expression;

fn assert_safe(code: &str) {
    with_last_expr(code, |ctx, expr, scope_id| {
        assert!(
            is_safe_expression(ctx, expr, scope_id),
            "expected safe: {code:?}"
        );
    });
}

fn assert_unsafe(code: &str) {
    with_last_expr(code, |ctx, expr, scope_id| {
        assert!(
            !is_safe_expression(ctx, expr, scope_id),
            "expected unsafe: {code:?}"
        );
    });
}

// Sequential writes

#[test]
fn unassigned_let_is_undefined_and_safe() {
    assert_safe("let a; a");
}

#[test]
fn unassigned_var_is_undefined_and_safe() {
    assert_safe("var a; a");
}

#[test]
fn later_unsafe_write_does_not_reach_earlier_capture() {
    let code = r#"
        let a = "safe";
        let b = a;
        a = getUserInput();
        b;
    "#;
    assert_safe(code);
}

#[test]
fn capture_of_then_unsafe_value_stays_unsafe_after_source_is_overwritten() {
    let code = r#"
        let a = getUserInput();
        let b = a;
        a = "safe";
        b;
    "#;
    assert_unsafe(code);
}

#[test]
fn copied_binding_is_safe_when_source_was_narrowed_first() {
    let code = r#"
        let b = getUserInput();
        b = "safe";
        let a = b;
        a;
    "#;
    assert_safe(code);
}

#[test]
fn block_assignment_reaches_use_after_the_block() {
    let code = r#"
        let a = getUserInput();
        {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn inner_let_does_not_shadow_outer_unsafe_binding() {
    let code = r#"
        let a = getUserInput();
        {
            let a = "safe";
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn sequence_applies_writes_before_the_used_value() {
    let code = r#"
        let a = getUserInput();
        (a = "safe", a);
    "#;
    assert_safe(code);
}

#[test]
fn sequence_keeps_last_write_when_it_is_unsafe() {
    let code = r#"
        let a = "safe";
        (a = "still safe", a = getUserInput(), a);
    "#;
    assert_unsafe(code);
}

#[test]
fn assignment_in_call_argument_reaches_later_use() {
    let code = r#"
        let a = getUserInput();
        foo(a = "safe");
        a;
    "#;
    assert_safe(code);
}

#[test]
fn assignment_in_computed_key_reaches_later_use() {
    let code = r#"
        let a = getUserInput();
        obj[a = "safe"] = 1;
        a;
    "#;
    assert_safe(code);
}

#[test]
fn assignment_in_array_literal_reaches_later_use() {
    let code = r#"
        let a = getUserInput();
        const xs = [a = "safe"];
        a;
    "#;
    assert_safe(code);
}

// Compound assignments and updates

#[test]
fn increment_makes_the_binding_a_safe_number() {
    let code = r#"
        let a = getUserInput();
        a++;
        a;
    "#;
    assert_safe(code);
}

#[test]
fn prefix_decrement_makes_the_binding_a_safe_number() {
    let code = r#"
        let a = getUserInput();
        --a;
        a;
    "#;
    assert_safe(code);
}

#[test]
fn plus_equals_safe_string_on_unsafe_value_stays_unsafe() {
    let code = r#"
        let a = getUserInput();
        a += "suffix";
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn plus_equals_unsafe_on_safe_value_becomes_unsafe() {
    let code = r#"
        let a = "<div>";
        a += getUserInput();
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn plus_equals_safe_on_safe_stays_safe() {
    let code = r#"
        let a = "<div>";
        a += "ok";
        a;
    "#;
    assert_safe(code);
}

#[test]
fn logical_or_equals_joins_when_lhs_safety_is_unknown() {
    let code = r#"
        let a = getUserInput();
        a ||= "safe";
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn destructuring_assignment_is_opaque() {
    let code = r#"
        let a = "safe";
        [a] = ["also safe"];
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn destructuring_declaration_is_opaque_even_from_a_safe_array() {
    let code = r#"
        let [a] = ["safe"];
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn object_destructuring_assignment_is_opaque() {
    let code = r#"
        let a = "safe";
        ({ a } = { a: "also safe" });
        a;
    "#;
    assert_unsafe(code);
}

// Constant conditions

#[test]
fn folds_negated_false() {
    let code = r#"
        let a = getUserInput();
        if (!false) {
            a = "safe";
        } else {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn folds_empty_string_as_falsy() {
    let code = r#"
        let a = getUserInput();
        if ("") {
            a = getUserInput();
        } else {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn folds_nonempty_string_as_truthy() {
    let code = r#"
        let a = getUserInput();
        if ("x") {
            a = "safe";
        } else {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn folds_null_as_falsy() {
    let code = r#"
        let a = getUserInput();
        if (null) {
            a = getUserInput();
        } else {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn folds_undefined_identifier_as_falsy() {
    let code = r#"
        let a = getUserInput();
        if (undefined) {
            a = getUserInput();
        } else {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn folds_void_zero_as_falsy() {
    let code = r#"
        let a = getUserInput();
        if (void 0) {
            a = getUserInput();
        } else {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn folds_array_literal_as_truthy() {
    let code = r#"
        let a = getUserInput();
        if ([]) {
            a = "safe";
        } else {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn folds_const_boolean_through_an_identifier() {
    let code = r#"
        const yes = true;
        let a = getUserInput();
        if (yes) {
            a = "safe";
        } else {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn folds_const_boolean_through_a_chain_of_consts() {
    let code = r#"
        const raw = !false;
        const yes = raw;
        let a = getUserInput();
        if (yes) {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn assignment_in_if_test_is_a_write() {
    let code = r#"
        let a = getUserInput();
        if (a = "safe") {}
        a;
    "#;
    assert_safe(code);
}

// Logical and ternary expressions

#[test]
fn truthy_and_runs_right_hand_assignment() {
    let code = r#"
        let a = getUserInput();
        true && (a = "safe");
        a;
    "#;
    assert_safe(code);
}

#[test]
fn falsy_and_skips_right_hand_assignment() {
    let code = r#"
        let a = "safe";
        false && (a = getUserInput());
        a;
    "#;
    assert_safe(code);
}

#[test]
fn truthy_or_skips_right_hand_assignment() {
    let code = r#"
        let a = "safe";
        true || (a = getUserInput());
        a;
    "#;
    assert_safe(code);
}

#[test]
fn falsy_or_runs_right_hand_assignment() {
    let code = r#"
        let a = getUserInput();
        false || (a = "safe");
        a;
    "#;
    assert_safe(code);
}

#[test]
fn nullish_coalesce_runs_right_when_left_is_null() {
    let code = r#"
        let a = getUserInput();
        null ?? (a = "safe");
        a;
    "#;
    assert_safe(code);
}

#[test]
fn nullish_coalesce_skips_right_when_left_is_a_string() {
    let code = r#"
        let a = "safe";
        "x" ?? (a = getUserInput());
        a;
    "#;
    assert_safe(code);
}

#[test]
fn unknown_and_joins_the_unsafe_right_hand_assignment() {
    let code = r#"
        let a = "safe";
        cond && (a = getUserInput());
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn ternary_constant_true_takes_consequent_write() {
    let code = r#"
        let a = getUserInput();
        true ? (a = "safe") : (a = getUserInput());
        a;
    "#;
    assert_safe(code);
}

#[test]
fn ternary_constant_false_takes_alternate_write() {
    let code = r#"
        let a = getUserInput();
        false ? (a = getUserInput()) : (a = "safe");
        a;
    "#;
    assert_safe(code);
}

#[test]
fn ternary_unknown_both_branches_safe() {
    let code = r#"
        let a = getUserInput();
        cond ? (a = "safe 1") : (a = "safe 2");
        a;
    "#;
    assert_safe(code);
}

#[test]
fn ternary_unknown_one_unsafe_branch() {
    let code = r#"
        let a = "safe";
        cond ? (a = "safe") : (a = getUserInput());
        a;
    "#;
    assert_unsafe(code);
}

// Nested if / return / throw

#[test]
fn diamond_of_four_safe_leaves() {
    let code = r#"
        let a = getUserInput();
        if (w) {
            if (x) a = "s1";
            else a = "s2";
        } else {
            if (y) a = "s3";
            else a = "s4";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn deep_nesting_one_unsafe_leaf_poisons_the_join() {
    let code = r#"
        let a = getUserInput();
        if (w) {
            if (x) a = "s1";
            else a = "s2";
        } else {
            if (y) a = "s3";
            else a = getUserInput();
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn throw_in_unknown_branch_then_safe_overwrite() {
    let code = r#"
        let a = getUserInput();
        if (condition) {
            throw new Error("stop");
        }
        a = "safe";
        a;
    "#;
    assert_safe(code);
}

#[test]
fn both_branches_return_so_the_use_is_unreachable() {
    let code = r#"
        let a = "safe";
        if (condition) {
            return;
        } else {
            return;
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn if_true_return_makes_following_unsafe_write_dead() {
    let code = r#"
        let a = "safe";
        if (true) {
            return;
        }
        a = getUserInput();
        a;
    "#;
    assert_unsafe(code);
}

// Loops

#[test]
fn while_true_break_after_safe_assign() {
    let code = r#"
        let a = getUserInput();
        while (true) {
            a = "safe";
            break;
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn while_true_if_true_break_skips_later_unsafe_write() {
    let code = r#"
        let a = getUserInput();
        while (true) {
            a = "safe";
            if (true) break;
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn do_while_false_still_applies_unsafe_body() {
    let code = r#"
        let a = "safe";
        do {
            a = getUserInput();
        } while (false);
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn do_while_unknown_that_always_assigns_safe() {
    let code = r#"
        let a = getUserInput();
        do {
            a = "safe";
        } while (condition);
        a;
    "#;
    assert_safe(code);
}

#[test]
fn for_init_write_is_visible_when_test_is_false() {
    let code = r#"
        let a = getUserInput();
        for (a = "safe"; false; a = getUserInput()) {}
        a;
    "#;
    assert_safe(code);
}

#[test]
fn for_update_does_not_run_when_test_is_false() {
    let code = r#"
        let a = "safe";
        for (a = "safe"; false; a = getUserInput()) {}
        a;
    "#;
    assert_safe(code);
}

#[test]
fn while_test_assignment_writes_before_a_false_body() {
    let code = r#"
        let a = "safe";
        while (a = getUserInput()) {
            break;
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn for_of_nonempty_array_always_runs_the_body() {
    let code = r#"
        let a = getUserInput();
        for (const x of ["item"]) {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn for_of_unknown_iterable_joins_zero_and_more_iterations() {
    let code = r#"
        let a = getUserInput();
        for (const x of items) {
            a = "safe";
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn for_in_that_assigns_the_loop_variable_to_the_tracked_binding() {
    let code = r#"
        let a = "safe";
        for (a in obj) {}
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn nested_loop_labeled_break_to_outer() {
    let code = r#"
        let a = getUserInput();
        outer: for (;;) {
            for (;;) {
                a = "safe";
                break outer;
                a = getUserInput();
            }
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn use_after_infinite_continue_loop_is_unreachable() {
    let code = r#"
        let a = getUserInput();
        while (true) {
            a = "safe";
            continue;
            a = getUserInput();
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn labeled_continue_reenters_after_safe_write_then_breaks() {
    let code = r#"
        let a = getUserInput();
        let once = true;
        loop: while (true) {
            a = "safe";
            if (once) {
                once = false;
                continue loop;
            }
            break;
        }
        a;
    "#;
    assert_safe(code);
}

// Switch

#[test]
fn switch_fallthrough_empty_case_reaches_safe_body() {
    let code = r#"
        let a = getUserInput();
        switch (1) {
            case 1:
            case 2:
                a = "safe";
                break;
            default:
                a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_fallthrough_overwrites_unsafe_with_safe() {
    let code = r#"
        let a = "safe";
        switch (1) {
            case 1:
                a = getUserInput();
            case 2:
                a = "safe";
                break;
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_fallthrough_without_later_overwrite_keeps_unsafe() {
    let code = r#"
        let a = "safe";
        switch (1) {
            case 1:
                a = getUserInput();
            case 2:
                break;
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn switch_static_miss_without_default_keeps_previous() {
    let code = r#"
        let a = "safe";
        switch (1) {
            case 2:
                a = getUserInput();
                break;
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_static_miss_takes_default() {
    let code = r#"
        let a = getUserInput();
        switch (1) {
            case 2:
                a = getUserInput();
                break;
            default:
                a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_break_inside_nested_if() {
    let code = r#"
        let a = getUserInput();
        switch (1) {
            case 1:
                a = "safe";
                if (true) break;
                a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_unknown_discriminant_with_unsafe_default() {
    let code = r#"
        let a = "safe";
        switch (x) {
            case 1:
                a = "safe";
                break;
            default:
                a = getUserInput();
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn switch_case_test_assignment_on_unknown_discriminant() {
    let code = r#"
        let a = "safe";
        switch (x) {
            case (a = getUserInput()):
                break;
            default:
                break;
        }
        a;
    "#;
    assert_unsafe(code);
}

// Try / catch / finally

#[test]
fn try_catch_joins_an_unassigned_catch_with_the_incoming_unsafe_value() {
    let code = r#"
        let a = getUserInput();
        try {
            a = "safe";
        } catch (e) {}
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn const_assignment_in_try_catch_keeps_the_initializer() {
    let code = r#"
        const a = "safe";
        try {
            a = getUserInput();
        } catch (e) {}
        a;
    "#;
    assert_safe(code);
}

#[test]
fn const_unsafe_initializer_is_not_sanitized_by_a_try_assignment() {
    let code = r#"
        const a = getUserInput();
        try {
            a = "safe";
        } catch (e) {}
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn try_and_catch_both_assign_safe() {
    let code = r#"
        let a = getUserInput();
        try {
            a = "safe 1";
        } catch (e) {
            a = "safe 2";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn catch_assigns_unsafe() {
    let code = r#"
        let a = "safe";
        try {
            a = "still safe";
        } catch (e) {
            a = getUserInput();
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn throw_then_catch_overwrites_with_safe() {
    let code = r#"
        let a = getUserInput();
        try {
            throw new Error("x");
            a = getUserInput();
        } catch (e) {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn finally_overwrites_try_and_catch() {
    let code = r#"
        let a = getUserInput();
        try {
            a = getUserInput();
        } catch (e) {
            a = getUserInput();
        } finally {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn finally_unsafe_wins_over_safe_try() {
    let code = r#"
        let a = "safe";
        try {
            a = "still safe";
        } finally {
            a = getUserInput();
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn use_after_try_that_always_returns_is_unreachable() {
    let code = r#"
        let a = "safe";
        try {
            return;
        } finally {
            a = "still safe";
        }
        a;
    "#;
    assert_unsafe(code);
}

// IIFE

#[test]
fn arrow_iife_reassignment_is_applied() {
    let code = r#"
        let a = getUserInput();
        (() => {
            a = "safe";
        })();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn bang_function_iife_reassignment_is_applied() {
    let code = r#"
        let a = getUserInput();
        !function () {
            a = "safe";
        }();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn void_function_iife_reassignment_is_applied() {
    let code = r#"
        let a = getUserInput();
        void function () {
            a = "safe";
        }();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn iife_call_method_reassignment_is_applied() {
    let code = r#"
        let a = getUserInput();
        (function () {
            a = "safe";
        }).call(null);
        a;
    "#;
    assert_safe(code);
}

#[test]
fn iife_apply_method_reassignment_is_applied() {
    let code = r#"
        let a = getUserInput();
        (function () {
            a = "safe";
        }).apply(null, []);
        a;
    "#;
    assert_safe(code);
}

#[test]
fn comma_callee_iife_reassignment_is_applied() {
    let code = r#"
        let a = getUserInput();
        (0, function () {
            a = "safe";
        })();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn nested_iife_reassignment_is_applied() {
    let code = r#"
        let a = getUserInput();
        (function () {
            (function () {
                a = "safe";
            })();
        })();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn iife_return_after_safe_write_still_commits_the_write() {
    let code = r#"
        let a = getUserInput();
        (function () {
            a = "safe";
            return;
            a = getUserInput();
        })();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn new_function_expression_runs_as_a_constructor_iife() {
    let code = r#"
        let a = getUserInput();
        new function () {
            a = "safe";
        };
        a;
    "#;
    assert_safe(code);
}

#[test]
fn iife_param_overwritten_before_copying_to_outer() {
    let code = r#"
        let result = getUserInput();
        (function (a) {
            a = "safe";
            result = a;
        })(getUserInput());
        result;
    "#;
    assert_safe(code);
}

// Closures / poison

#[test]
fn nested_function_that_only_assigns_safe_does_not_poison() {
    let code = r#"
        let a = getUserInput();
        a = "safe";
        function later() {
            a = "also safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn copy_of_a_binding_is_unsafe_when_a_nested_function_may_overwrite_the_source() {
    let code = r#"
        let a = "safe";
        let seen = a;
        function later() {
            a = getUserInput();
        }
        seen;
    "#;
    assert_unsafe(code);
}

#[test]
fn callback_passed_to_opaque_call_poisons_on_unsafe_write() {
    let code = r#"
        let a = "safe";
        foo(() => {
            a = getUserInput();
        });
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn callback_that_only_assigns_safe_does_not_poison() {
    let code = r#"
        let a = "safe";
        foo(() => {
            a = "still safe";
        });
        a;
    "#;
    assert_safe(code);
}

#[test]
fn unused_nested_function_does_not_run_sequentially_but_poisons() {
    let code = r#"
        let a = getUserInput();
        a = "safe";
        function f() {
            a = getUserInput();
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn iife_safe_write_is_undone_by_a_sibling_nested_unsafe_write() {
    let code = r#"
        let a = getUserInput();
        (function () {
            a = "safe";
        })();
        function f() {
            a = getUserInput();
        }
        a;
    "#;
    assert_unsafe(code);
}

// Class / with / labels

#[test]
fn class_static_block_assignment_runs_at_definition() {
    let code = r#"
        let a = getUserInput();
        class C {
            static {
                a = "safe";
            }
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn class_instance_field_does_not_run_at_definition() {
    let code = r#"
        let a = getUserInput();
        class C {
            x = (a = "safe");
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn static_field_initializer_runs_at_definition() {
    let code = r#"
        let a = getUserInput();
        class C {
            static x = (a = "safe");
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn double_label_break_exits_the_outer_block() {
    let code = r#"
        let a = getUserInput();
        foo: bar: {
            a = "safe";
            break foo;
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn with_statement_body_assignment_reaches_the_use() {
    let code = r#"
        let a = getUserInput();
        with (obj) {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

// Mixed / stress

#[test]
fn switch_inside_loop_with_labeled_break() {
    let code = r#"
        let a = getUserInput();
        outer: while (true) {
            switch (1) {
                case 1:
                    a = "safe";
                    break outer;
                default:
                    a = getUserInput();
            }
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn try_finally_inside_always_true_if() {
    let code = r#"
        let a = getUserInput();
        if (true) {
            try {
                a = getUserInput();
            } finally {
                a = "safe";
            }
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn iife_inside_safe_branch_of_constant_if() {
    let code = r#"
        let a = getUserInput();
        if (true) {
            (function () {
                a = "safe";
            })();
        } else {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn iife_inside_dead_branch_is_not_applied() {
    let code = r#"
        let a = "safe";
        if (false) {
            (function () {
                a = getUserInput();
            })();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn many_sequential_overwrites_last_safe_wins() {
    let code = r#"
        let a = getUserInput();
        a = getUserInput();
        a = "<div>";
        a = a;
        a = "final";
        a;
    "#;
    assert_safe(code);
}

#[test]
fn many_sequential_overwrites_last_unsafe_wins() {
    let code = r#"
        let a = "safe";
        a = "still";
        a = getUserInput();
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn opaque_call_does_not_by_itself_overwrite_a_local() {
    let code = r#"
        let a = "safe";
        foo(a);
        a;
    "#;
    assert_safe(code);
}

#[test]
fn assignment_through_comma_in_for_init() {
    let code = r#"
        let a = getUserInput();
        for (a = "safe", i = 0; false; ) {}
        a;
    "#;
    assert_safe(code);
}

#[test]
fn nested_try_finally_innermost_finally_wins() {
    let code = r#"
        let a = getUserInput();
        try {
            try {
                a = getUserInput();
            } finally {
                a = "mid";
            }
        } finally {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn loop_then_if_then_iife_then_switch() {
    let code = r#"
        let a = getUserInput();
        while (false) {
            a = getUserInput();
        }
        if (true) {
            (function () {
                a = "tmp";
            })();
        }
        switch (1) {
            case 1:
                a = "safe";
                break;
            default:
                a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn use_in_binary_expression_sees_last_write() {
    let code = r#"
        let a = getUserInput();
        a = "safe";
        a + "suffix";
    "#;
    assert_safe(code);
}

#[test]
fn use_in_binary_expression_sees_unsafe_write() {
    let code = r#"
        let a = "safe";
        a = getUserInput();
        a + "suffix";
    "#;
    assert_unsafe(code);
}

#[test]
fn string_call_preserves_reaching_fact() {
    let code = r#"
        let a = getUserInput();
        a = "safe";
        String(a);
    "#;
    assert_safe(code);
}

#[test]
fn template_interpolation_uses_reaching_fact() {
    let code = r#"
        let a = getUserInput();
        a = "safe";
        `${a}`;
    "#;
    assert_safe(code);
}

#[test]
fn two_bindings_refined_independently() {
    let code = r#"
        let a = getUserInput();
        let b = getUserInput();
        a = "safe";
        b;
    "#;
    assert_unsafe(code);
}

#[test]
fn two_bindings_both_narrowed() {
    let code = r#"
        let a = getUserInput();
        let b = getUserInput();
        a = "safe-a";
        b = "safe-b";
        a;
    "#;
    assert_safe(code);
}

#[test]
fn nested_sequence_keeps_the_innermost_last_write() {
    let code = r#"
        let a = getUserInput();
        ((a = "mid", a = "safe"), a);
    "#;
    assert_safe(code);
}

#[test]
fn assignment_expression_value_is_the_rhs() {
    let code = r#"
        let a = getUserInput();
        a = "safe";
    "#;
    assert_safe(code);
}

#[test]
fn iife_after_the_use_does_not_rewrite_the_use() {
    let code = r#"
        let a = "safe";
        a;
        (function () {
            a = getUserInput();
        })();
    "#;
    with_identifier_usage(code, "a", |ctx, expr, scope_id| {
        assert!(
            is_safe_expression(ctx, expr, scope_id),
            "expected the use before the IIFE to stay safe: {code:?}"
        );
    });
}

#[test]
fn function_declaration_in_a_dead_branch_still_poisons() {
    let code = r#"
        let a = "safe";
        if (false) {
            function later() {
                a = getUserInput();
            }
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn falsy_and_skips_an_iife_that_would_assign_unsafe() {
    let code = r#"
        let a = "safe";
        false && (function () {
            a = getUserInput();
        })();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn truthy_or_skips_an_iife_that_would_assign_unsafe() {
    let code = r#"
        let a = "safe";
        true || (function () {
            a = getUserInput();
        })();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn unknown_and_joins_an_iife_that_assigns_unsafe() {
    let code = r#"
        let a = "safe";
        unknown && (function () {
            a = getUserInput();
        })();
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn two_iifes_last_safe_write_wins() {
    let code = r#"
        let a = getUserInput();
        (function () {
            a = getUserInput();
        })();
        (function () {
            a = "safe";
        })();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn callback_inside_an_iife_still_poisons() {
    let code = r#"
        let a = "safe";
        (function () {
            foo(() => {
                a = getUserInput();
            });
        })();
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn class_method_that_assigns_unsafe_poisons() {
    let code = r#"
        let a = "safe";
        class C {
            m() {
                a = getUserInput();
            }
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn static_block_safe_write_is_undone_by_an_instance_method_poison() {
    let code = r#"
        let a = getUserInput();
        class C {
            static {
                a = "safe";
            }
            m() {
                a = getUserInput();
            }
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn generator_declaration_that_assigns_unsafe_poisons() {
    let code = r#"
        let a = "safe";
        function* later() {
            a = getUserInput();
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn arrow_expression_body_iife_reassignment_is_applied() {
    let code = r#"
        let a = getUserInput();
        (() => (a = "safe"))();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn optional_call_iife_reassignment_is_applied() {
    let code = r#"
        let a = getUserInput();
        (function () {
            a = "safe";
        })?.();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn iife_in_for_init_runs_before_a_false_test() {
    let code = r#"
        let a = getUserInput();
        for ((function () { a = "safe"; })(); false; ) {}
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_unknown_all_cases_and_default_assign_safe() {
    let code = r#"
        let a = getUserInput();
        switch (unknown) {
            case 1:
                a = "one";
                break;
            case 2:
                a = "two";
                break;
            default:
                a = "other";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_unknown_all_cases_safe_without_default_joins_the_miss() {
    let code = r#"
        let a = getUserInput();
        switch (unknown) {
            case 1:
                a = "one";
                break;
            case 2:
                a = "two";
                break;
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn switch_static_miss_still_runs_case_test_side_effects() {
    let code = r#"
        let a = getUserInput();
        switch (2) {
            case (a = "safe", 1):
                a = getUserInput();
                break;
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_true_matches_the_true_case() {
    let code = r#"
        let a = getUserInput();
        switch (true) {
            case false:
                a = getUserInput();
                break;
            case true:
                a = "safe";
                break;
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_fallthrough_across_three_cases_last_write_wins() {
    let code = r#"
        let a = getUserInput();
        switch (1) {
            case 1:
            case 2:
                a = "mid";
            case 3:
                a = "safe";
                break;
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_only_default_runs() {
    let code = r#"
        let a = getUserInput();
        switch (1) {
            default:
                a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_discriminant_assignment_is_a_write() {
    let code = r#"
        let a = getUserInput();
        switch (a = "safe") {
            default:
                break;
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn for_unknown_update_joins_an_unsafe_write() {
    let code = r#"
        let a = "safe";
        for (let i = 0; unknown; a = getUserInput()) {}
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn infinite_for_break_after_safe_assign() {
    let code = r#"
        let a = getUserInput();
        for (;;) {
            a = "safe";
            break;
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn for_of_empty_array_skips_the_body() {
    let code = r#"
        let a = "safe";
        for (const x of []) {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn for_of_break_skips_the_later_unsafe_write() {
    let code = r#"
        let a = getUserInput();
        for (const x of ["x", "y"]) {
            a = "safe";
            break;
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn for_in_unknown_object_joins_an_unsafe_body() {
    let code = r#"
        let a = "safe";
        for (const k in obj) {
            a = getUserInput();
            break;
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn labeled_block_break_skips_the_later_unsafe_write() {
    let code = r#"
        let a = getUserInput();
        L: {
            a = "safe";
            break L;
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn labeled_break_from_try_still_runs_finally() {
    let code = r#"
        let a = getUserInput();
        L: try {
            a = "from-try";
            break L;
            a = getUserInput();
        } finally {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn continue_in_try_still_runs_finally_before_the_next_iteration() {
    let code = r#"
        let a = getUserInput();
        for (const x of ["x"]) {
            try {
                a = "from-try";
                continue;
            } finally {
                a = "safe";
            }
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn if_zero_is_falsy() {
    let code = r#"
        let a = "safe";
        if (0) {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn if_nan_is_falsy() {
    let code = r#"
        let a = "safe";
        if (NaN) {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn if_infinity_is_truthy() {
    let code = r#"
        let a = getUserInput();
        if (Infinity) {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn if_empty_object_is_truthy() {
    let code = r#"
        let a = getUserInput();
        if ({}) {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn comma_in_if_test_applies_the_write_then_skips_the_body() {
    let code = r#"
        let a = getUserInput();
        if ((a = "safe", false)) {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn while_zero_skips_the_body() {
    let code = r#"
        let a = "safe";
        while (0) {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn while_unknown_joins_an_unsafe_body() {
    let code = r#"
        let a = "safe";
        while (unknown) {
            a = getUserInput();
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn while_test_assignment_to_unsafe_is_visible_after_the_loop() {
    let code = r#"
        let a = "safe";
        while (a = getUserInput()) {}
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn do_while_true_breaks_after_the_safe_write() {
    let code = r#"
        let a = getUserInput();
        do {
            a = "safe";
            break;
        } while (true);
        a;
    "#;
    assert_safe(code);
}

#[test]
fn if_else_if_else_every_branch_safe() {
    let code = r#"
        let a = getUserInput();
        if (unknown) {
            a = "one";
        } else if (unknown2) {
            a = "two";
        } else {
            a = "three";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn if_else_if_without_else_joins_the_incoming_unsafe_value() {
    let code = r#"
        let a = getUserInput();
        if (unknown) {
            a = "one";
        } else if (unknown2) {
            a = "two";
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn nested_try_outer_finally_wins() {
    let code = r#"
        let a = getUserInput();
        try {
            try {
                a = "inner";
            } finally {
                a = "inner-fin";
            }
        } finally {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn catch_unsafe_is_overwritten_by_finally() {
    let code = r#"
        let a = "safe";
        try {
        } catch (e) {
            a = getUserInput();
        } finally {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn unconditional_throw_takes_the_catch_write() {
    let code = r#"
        let a = getUserInput();
        try {
            throw 1;
            a = getUserInput();
        } catch (e) {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn try_switch_is_still_joined_with_an_unassigned_catch() {
    let code = r#"
        let a = getUserInput();
        try {
            switch (1) {
                case 1:
                    a = "safe";
                    break;
                default:
                    a = getUserInput();
            }
        } catch (e) {
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn folds_double_negation_through_a_const() {
    let code = r#"
        const raw = !!1;
        const yes = raw;
        let a = getUserInput();
        if (yes) {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn folds_negated_zero_through_a_const() {
    let code = r#"
        const yes = !0;
        let a = getUserInput();
        if (yes) {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn var_in_a_block_is_the_same_binding() {
    let code = r#"
        var a = getUserInput();
        {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn two_declarators_copy_then_source_is_narrowed() {
    let code = r#"
        let a = getUserInput(), b = a;
        a = "safe";
        b;
    "#;
    assert_unsafe(code);
}

#[test]
fn rest_assignment_is_opaque() {
    let code = r#"
        let a = "safe";
        [...a] = ["x"];
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn with_object_assignment_is_a_write() {
    let code = r#"
        let a = getUserInput();
        with (a = "safe") {}
        a;
    "#;
    assert_safe(code);
}

#[test]
fn for_loop_shadowed_let_does_not_overwrite_the_outer_binding() {
    let code = r#"
        let a = "safe";
        for (let a of [getUserInput()]) {}
        a;
    "#;
    assert_safe(code);
}

#[test]
fn while_true_continue_then_break_on_the_second_iteration_shape() {
    let code = r#"
        let a = getUserInput();
        while (true) {
            a = "safe";
            if (true) {
                break;
            }
            continue;
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn switch_inside_try_finally_overwrites_every_exit() {
    let code = r#"
        let a = getUserInput();
        try {
            switch (unknown) {
                case 1:
                    a = "one";
                    break;
                default:
                    a = "other";
            }
        } finally {
            a = "safe";
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn iife_then_dead_if_then_switch_default() {
    let code = r#"
        let a = getUserInput();
        (function () {
            a = "from-iife";
        })();
        if (false) {
            a = getUserInput();
        }
        switch ("k") {
            case "k":
                a = "safe";
                break;
            default:
                a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn diamond_join_then_loop_zero_iter_then_iife() {
    let code = r#"
        let a = getUserInput();
        if (unknown) {
            a = "left";
        } else {
            a = "right";
        }
        while (false) {
            a = getUserInput();
        }
        (function () {
            a = "safe";
        })();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn nested_labeled_for_continue_outer_skips_the_unsafe_write_after_the_inner_loop() {
    let code = r#"
        let a = getUserInput();
        outer: for (const x of ["x"]) {
            inner: for (const y of ["y"]) {
                a = "safe";
                continue outer;
                a = getUserInput();
            }
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn nested_labeled_for_continue_outer_finally_safe() {
    let code = r#"
        let a = getUserInput();
        outer: for (const x of ["x"]) {
            try {
                continue outer;
            } finally {
                a = "safe";
            }
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn many_nested_ifs_only_the_taken_path_matters() {
    let code = r#"
        let a = getUserInput();
        if (true) {
            if (true) {
                if (!false) {
                    if (1) {
                        a = "safe";
                    } else {
                        a = getUserInput();
                    }
                }
            }
        } else {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn sequence_in_for_update_runs_on_a_taken_iteration() {
    let code = r#"
        let a = "safe";
        for (let i = 0; i < 1; a = getUserInput(), i++) {
            i = 1;
        }
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn const_later_assignment_does_not_overwrite_a_safe_initializer() {
    let code = r#"
        const a = "safe";
        a = getUserInput();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn const_later_assignment_does_not_sanitize_an_unsafe_initializer() {
    let code = r#"
        const a = getUserInput();
        a = "safe";
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn const_increment_does_not_make_the_binding_a_safe_number() {
    let code = r#"
        const a = getUserInput();
        a++;
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn const_compound_assignment_does_not_join_into_the_binding() {
    let code = r#"
        const a = "safe";
        a += getUserInput();
        a;
    "#;
    assert_safe(code);
}

#[test]
fn for_of_into_an_outer_const_does_not_overwrite() {
    let code = r#"
        const a = "safe";
        for (a of [getUserInput()]) {}
        a;
    "#;
    assert_safe(code);
}

#[test]
fn iife_assignment_to_const_does_not_overwrite() {
    let code = r#"
        const a = getUserInput();
        (function () {
            a = "safe";
        })();
        a;
    "#;
    assert_unsafe(code);
}

#[test]
fn nested_function_assignment_to_outer_const_does_not_poison() {
    let code = r#"
        const a = "safe";
        function later() {
            a = getUserInput();
        }
        a;
    "#;
    assert_safe(code);
}

#[test]
fn nested_use_of_const_ignores_a_later_unsafe_write() {
    let code = r#"
        const a = "safe";
        function nested() {
            a;
        }
        a = getUserInput();
    "#;
    with_identifier_usage(code, "a", |ctx, expr, scope_id| {
        assert!(
            is_safe_expression(ctx, expr, scope_id),
            "expected nested use of const to stay at the initializer: {code:?}"
        );
    });
}
