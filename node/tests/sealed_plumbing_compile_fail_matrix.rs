//! Single downstream compile-fail matrix for the sealed v1.1 plumbing surface.
//!
//! Raw publish / DB-write / adapter-mutation / scan-apply sinks are
//! `pub(crate)` on `node`. This integration target is a **separate crate**
//! that depends on `node` as a normal library dependency — the same edge a
//! downstream application, a `node` integration test, a dev-dependency
//! consumer, or a build-dependency consumer would use. Feature flags cannot
//! reopen the sinks (no Cargo feature exists for them).
//!
//! One matrix beats scattered trybuild files: every sealed sink is named in
//! one place, and widening any of them fails loudly here.
//!
//! Run: `cargo test -p node --test sealed_plumbing_compile_fail_matrix`

#[test]
fn sealed_plumbing_sinks_unobtainable_from_outside_node() {
    let t = trybuild::TestCases::new();
    // One UI crate enumerates every sealed sink; stderr pins the errors.
    t.compile_fail("tests/ui/sealed_plumbing_sinks_unobtainable.rs");
}
