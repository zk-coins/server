// Compile-fail: `begin_v11_mint` no longer accepts a caller-selected
// `V11ShadowMode`. The capability is the process stack claim, not a
// freely constructible enum value. Driven by trybuild
// (see `tests/v11_mint_boundary_compile_fail.rs`).

fn main() {
    // Intentional: three-argument form (engine, mode, request) must not
    // resolve — mode is not a parameter; callers cannot hand in `On`
    // while the flag is off.
    fn probe(
        engine: &zkcoins_prover::state_engine::StateEngine,
        req: zkcoins_prover::state_engine::MintRequest,
    ) {
        let _ = node::v11::begin_v11_mint(engine, node::v11::V11ShadowMode::On, req);
    }
    let _ = probe;
}
