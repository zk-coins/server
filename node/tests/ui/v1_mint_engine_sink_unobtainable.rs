// Compile-fail: the raw engine mint sink is module-private. Outside
// `v1::mint`, only `begin_v1_mint` (process-claim gated) may stage a
// mint/remint. Driven by trybuild (see `tests/v1_mint_boundary_compile_fail.rs`).

fn main() {
    // Intentional: `engine_begin_mint` is private to `v1::mint`.
    let _ = node::v1::mint::engine_begin_mint;
}
