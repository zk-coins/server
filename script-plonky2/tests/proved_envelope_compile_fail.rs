//! Compile-time evidence that a hollow `ProvedPendingTransition` cannot be
//! minted outside the prove path (G3 capability token).
//!
//! Production constructors are only
//! `StateEngine::prove_pending_transition` /
//! `prove_pending_transition_detached`. The former public `from_parts`
//! assembler is private; the hollow mint is `#[cfg(test)]` of the defining
//! crate only — this trybuild crate is a separate integration target and
//! never sees it (no Cargo feature can open the seam).

#[test]
fn proved_pending_from_parts_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/proved_pending_from_parts_unobtainable.rs");
}

#[test]
fn applied_transition_struct_literal_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/applied_transition_unobtainable.rs");
}

#[test]
fn receive_request_nav_rand_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/receive_request_nav_rand_unobtainable.rs");
}
