//! Compile-time evidence that a broadcast-capable client cannot be
//! constructed without a [`LegacyBroadcastWitness`] (Defect 4 / P2-2).
//!
//! This harness depends on `esplora-bound` **without** the
//! `issue-legacy-broadcast-witness` feature (default features only), so it
//! models a crate that is not `node`: no mint path, and `connect(url)`
//! without a witness is a hard compile error.

#[test]
fn broadcast_client_cannot_be_constructed_without_witness() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/broadcast_client_requires_witness.rs");
}
