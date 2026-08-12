// Compile-fail: `node` does not depend on `esplora-client`, so the raw
// client type is not in scope. The sole owner is the `esplora-bound`
// facade package. This file is driven by trybuild (see
// `tests/esplora_boundary_compile_fail.rs`).

fn main() {
    // Intentional: naming the raw crate must not compile in the `node` package.
    let _ = ::esplora_client::Builder::new("http://127.0.0.1");
}
