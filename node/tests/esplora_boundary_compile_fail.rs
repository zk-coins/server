//! Compile-time evidence that a raw `esplora-client` handle is unobtainable
//! from the `node` package (Defect 4). The boundary is structural: `node`
//! depends on `esplora-bound`, not on `esplora-client`.

#[test]
fn raw_esplora_client_type_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/raw_esplora_client_unobtainable.rs");
}
