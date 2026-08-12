// Compile-fail: the raw engine send sink is module-private. Outside
// `v1::provenance`, only `begin_v1_send` (process-claim gated, CoinHist
// provenance) may stage a spend. Driven by trybuild
// (see `tests/v1_provenance_boundary_compile_fail.rs`).

fn main() {
    // Intentional: `engine_begin_send` is private to `v1::provenance`.
    let _ = node::v1::provenance::engine_begin_send;
}
