// Compile-fail: the raw engine mint sink is module-private. Outside
// `v11::mint`, only `begin_v11_mint` (process-claim gated) may stage a
// mint/remint. Driven by trybuild (see `tests/v11_mint_boundary_compile_fail.rs`).

fn main() {
    // Intentional: `engine_begin_mint` is private to `v11::mint`.
    let _ = node::v11::mint::engine_begin_mint;
}
