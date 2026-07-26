//! Compile-time evidence that the process-claim reset is unobtainable
//! from a production `node` build (monotonic process claim).

#[test]
fn clear_process_stack_mode_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/clear_process_stack_mode_unobtainable.rs");
}
