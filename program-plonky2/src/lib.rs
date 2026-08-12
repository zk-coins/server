//! zkCoins state-transition circuit, Plonky2 backend.
//!
//! This crate is the in-progress port of `program/` (SP1 + SHA256) to
//! Plonky2 + Poseidon over Goldilocks. See `SPEC.md` for the protocol
//! specification and `MIGRATION_RESEARCH.md` §6 for the porting plan.
//!
//! The crate currently exposes only the proof-system prelude
//! (field, hash config, recursion arity) so the toolchain can be
//! validated. Circuit gadgets, the monolithic state-transition
//! circuit, and host-side prover wiring will land in follow-up commits.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// Exclude the whole circuit-program crate from coverage instrumentation (see
// script-plonky2/src/lib.rs): justifiably excluded from the coverage floor, and
// instrumenting the circuit math makes an instrumented node build too slow.
#![cfg_attr(coverage_nightly, coverage(off))]

extern crate alloc;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

/// Native field. Goldilocks: `F = GF(2^64 - 2^32 + 1)`.
pub type F = GoldilocksField;

/// Recursion config. Poseidon over Goldilocks; quadratic extension (`D = 2`).
pub type C = PoseidonGoldilocksConfig;

/// Extension degree used for recursion FRI. Matches Plonky2's
/// `standard_recursion_config`.
pub const D: usize = 2;

// `clippy::chunks_exact_to_as_chunks` does not exist on the pinned
// nightly-2026-06-18; allowing an unknown lint fails under `-D warnings`.
// Keep only lints that this toolchain knows.
#[allow(clippy::needless_range_loop)]
pub mod circuit;
pub mod hash;
pub mod inputs;
pub mod merkle;
pub mod types;
pub mod u32_lib;

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;

    /// Toolchain smoke test: build a trivial circuit, prove it, verify it.
    /// Confirms the chosen `(F, C, D)` triple wires up end-to-end before any
    /// real gadget work begins.
    #[test]
    fn prelude_round_trips_a_proof() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        let z = builder.mul(x, y);
        builder.register_public_input(z);

        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(7)).unwrap();
        pw.set_target(y, F::from_canonical_u64(6)).unwrap();

        let data = builder.build::<C>();
        let proof = data.prove(pw).expect("prove failed");
        assert_eq!(proof.public_inputs[0], F::from_canonical_u64(42));
        data.verify(proof).expect("verify failed");
    }
}
