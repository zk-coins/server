//! Compile-time evidence that the legacy `Prover` type is deleted
//! (Stage 3 Runde 4 — not sealed, deleted). One UI file, one error.

#[test]
fn prover_type_is_deleted() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/prover_type_unobtainable.rs");
}
