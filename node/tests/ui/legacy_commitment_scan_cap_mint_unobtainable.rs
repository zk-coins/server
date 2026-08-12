// Compile-fail: mint_for_test is cfg(test) of the defining crate only.
// One expected error only (B3: one file, one expected error).

fn main() {
    let _ = node::legacy_commitment_scan::LegacyCommitmentScanCap::mint_for_test();
}
