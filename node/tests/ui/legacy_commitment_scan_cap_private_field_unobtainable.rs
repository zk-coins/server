// Compile-fail: LegacyCommitmentScanCap private field is unconstructible.
// One expected error only (B3: one file, one expected error).

fn main() {
    let _ = node::legacy_commitment_scan::LegacyCommitmentScanCap { _private: () };
}
