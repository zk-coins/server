// Compile-fail: `begin_v11_send` does not accept a legacy
// `InCoinSourceWitness` (or any sources slice). Spend provenance on the
// v1.1 path is derived inside the engine as `InputAuthorization` /
// CoinHist — the wrong construct is unrepresentable. Driven by trybuild
// (see `tests/v11_provenance_boundary_compile_fail.rs`).

fn main() {
    // Intentional: three-argument form (engine, request, sources) must not
    // resolve — there is no sources parameter on the v1.1 send entry.
    fn probe(
        engine: &zkcoins_prover::state_engine::StateEngine,
        req: zkcoins_prover::state_engine::SendRequest,
        sources: &[Option<zkcoins_prover::InCoinSourceWitness>],
    ) {
        let _ = node::v11::begin_v11_send(engine, req, sources);
    }
    let _ = probe;
}
