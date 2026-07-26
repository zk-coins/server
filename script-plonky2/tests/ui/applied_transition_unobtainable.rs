// Compile-fail: `AppliedTransition` is a capability — private fields, no
// public constructor, no struct-literal mint. Driven by trybuild.

fn main() {
    // Intentional: fields are private; struct literal must not compile.
    // Use `Default`-style placeholders that do not diverge (avoid unreachable_code).
    let proved = None::<zkcoins_prover_plonky2::prover_bridge::ProvedTransition>;
    let _ = zkcoins_prover_plonky2::state_engine::AppliedTransition {
        proved: proved.unwrap(),
        nullifier: ([0u8; 32], [0u8; 32]),
    };
}
