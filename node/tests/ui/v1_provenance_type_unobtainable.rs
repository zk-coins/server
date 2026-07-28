// Compile-fail: `InCoinSourceWitness` is not re-exported on the v1.1
// surface. Downstream that depends only on `node` cannot name the legacy
// source-witness type through `node::v1`. Driven by trybuild
// (see `tests/v1_provenance_boundary_compile_fail.rs`).

fn main() {
    // Intentional: the legacy witness type is not on `node::v1`.
    let _ = std::any::type_name::<node::v1::InCoinSourceWitness>();
}
