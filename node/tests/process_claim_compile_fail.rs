//! Compile-time evidence that the process-claim reset is unobtainable
//! outside `stack-policy`'s own `#[cfg(test)]`.
//!
//! The UI fixture names both former import paths (`node::v11::…` and
//! `stack_policy::…`). A green run means neither path resolves — the seal
//! is the capability, not a single re-export.

#[test]
fn clear_process_stack_mode_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/clear_process_stack_mode_unobtainable.rs");
}
