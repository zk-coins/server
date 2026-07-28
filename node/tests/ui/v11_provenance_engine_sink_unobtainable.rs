// Compile-fail: the raw engine send sink is module-private. Outside
// `v11::provenance`, only `begin_v11_send` (process-claim gated, CoinHist
// provenance) may stage a spend. Driven by trybuild
// (see `tests/v11_provenance_boundary_compile_fail.rs`).

fn main() {
    // Intentional: `engine_begin_send` is private to `v11::provenance`.
    let _ = node::v11::provenance::engine_begin_send;
}
