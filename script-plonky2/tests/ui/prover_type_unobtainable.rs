// Compile-fail: legacy Prover type is deleted from zkcoins-prover-plonky2.
// One expected error only.

fn main() {
    let _ = zkcoins_prover_plonky2::Prover;
}
