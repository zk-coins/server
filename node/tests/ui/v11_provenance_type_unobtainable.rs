// Compile-fail: `InCoinSourceWitness` is not re-exported on the v1.1
// surface. Downstream that depends only on `node` cannot name the legacy
// source-witness type through `node::v11`. Driven by trybuild
// (see `tests/v11_provenance_boundary_compile_fail.rs`).

fn main() {
    // Intentional: the legacy witness type is not on `node::v11`.
    let _ = std::any::type_name::<node::v11::InCoinSourceWitness>();
}
