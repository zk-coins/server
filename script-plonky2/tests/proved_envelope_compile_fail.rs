//! Compile-time evidence that a hollow `ProvedPendingTransition` cannot be
//! minted outside the prove path (G3 capability token).
//!
//! Production constructors are only
//! `StateEngine::prove_pending_transition` /
//! `prove_pending_transition_detached`. The former public `from_parts`
//! assembler is private; the hollow mint is feature-gated (`test-utils`)
//! and is **not** enabled for this trybuild crate (depends on the library
//! without the feature).

#[test]
fn proved_pending_from_parts_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/proved_pending_from_parts_unobtainable.rs");
}
