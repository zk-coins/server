// Compile-fail: `publish_applied_nullifier` is not a public entry point on
// `node::v11`. Fabricated `AppliedTransition` cannot drive publish because
// the helper is gone and the type itself has private fields (proven in
// `zkcoins-prover-plonky2` trybuild). Driven by trybuild
// (`tests/publish_bypass_compile_fail.rs`).

fn main() {
    // Intentional: former public publish helper is not re-exported.
    let _ = node::v11::publish_applied_nullifier;
}
