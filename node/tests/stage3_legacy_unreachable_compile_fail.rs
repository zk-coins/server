//! Compile-time evidence for Stage-3 "not called is not unreachable":
//!
//! 1. `LegacyCommitmentScanCap` cannot be obtained (private field / test mint).
//! 2. Legacy `Prover` type is **deleted** (not sealed).
//! 3. Public free builders `build_circuit` / `prove_*` / `verify` are gone.
//!
//! **One UI file, one expected error** (B3) — partial weakenings cannot mask.
//! trybuild flattens this host package's direct deps into the UI crate.

#[test]
fn legacy_commitment_scan_cap_private_field_unobtainable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_commitment_scan_cap_private_field_unobtainable.rs");
}

#[test]
fn legacy_commitment_scan_cap_mint_unobtainable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_commitment_scan_cap_mint_unobtainable.rs");
}

#[test]
fn prover_type_is_deleted() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/prover_type_unobtainable.rs");
}

#[test]
fn legacy_build_circuit_is_unobtainable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_build_circuit_unobtainable.rs");
}

#[test]
fn legacy_prove_initial_is_unobtainable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_prove_initial_unobtainable.rs");
}

#[test]
fn legacy_prove_account_update_is_unobtainable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_prove_account_update_unobtainable.rs");
}

#[test]
fn legacy_verify_is_unobtainable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_verify_unobtainable.rs");
}

#[test]
fn legacy_commit_mint_is_unobtainable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_commit_mint_unobtainable.rs");
}

#[test]
fn legacy_receive_coin_into_is_unobtainable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_receive_coin_into_unobtainable.rs");
}

/// Runde 6 counter-probe: `import_account` → `state()` → `persist_account`
/// (and the legacy SQL sinks) are off the public positive list.
#[test]
fn legacy_import_and_mutate_state_is_unobtainable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_import_and_mutate_state_unobtainable.rs");
}
