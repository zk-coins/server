// Compile-fail: a hollow `ProvedPendingTransition` cannot be assembled outside
// the prove path. Driven by trybuild (`tests/proved_envelope_compile_fail.rs`).
//
// This trybuild crate depends on `zkcoins-prover-plonky2` as a library:
//   - `from_parts` is private (prove-path only)
//   - `from_parts_for_test` does not exist outside the defining crate's
//     `#[cfg(test)]` (never set for dependency builds; no Cargo feature)

fn main() {
    // Intentional: former public hollow assembler is private.
    let _ = zkcoins_prover_plonky2::state_engine::ProvedPendingTransition::from_parts;
    // Intentional: test-only mint is cfg(test) of the defining crate only.
    let _ = zkcoins_prover_plonky2::state_engine::ProvedPendingTransition::from_parts_for_test;
}
