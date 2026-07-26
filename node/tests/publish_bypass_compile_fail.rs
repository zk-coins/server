//! Compile-time evidence that `publish_applied_nullifier` cannot be driven
//! with a fabricated `AppliedTransition` (G3 proof-bypass sweep).

#[test]
fn publish_applied_nullifier_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/publish_applied_nullifier_unobtainable.rs");
}
