// Compile-fail: `begin_v1_mint` no longer accepts a caller-selected
// `V1ShadowMode`. The capability is the process stack claim, not a
// freely constructible enum value. Driven by trybuild
// (see `tests/v1_mint_boundary_compile_fail.rs`).

fn main() {
    // Intentional: three-argument form (engine, mode, request) must not
    // resolve — mode is not a parameter; callers cannot hand in `On`
    // while the flag is off.
    fn probe(
        engine: &zkcoins_prover::state_engine::StateEngine,
        req: zkcoins_prover::state_engine::MintRequest,
    ) {
        let _ = node::v1::begin_v1_mint(engine, node::v1::V1ShadowMode::On, req);
    }
    let _ = probe;
}
