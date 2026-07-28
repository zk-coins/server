//! Compile-time evidence for the G9 provenance boundary:
//! - raw engine send sink is module-private;
//! - `begin_v11_send` does not accept a legacy `InCoinSourceWitness`;
//! - `InCoinSourceWitness` is not on the `node::v11` public surface.

#[test]
fn engine_begin_send_sink_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/v11_provenance_engine_sink_unobtainable.rs");
}

#[test]
fn begin_v11_send_sources_arg_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/v11_provenance_source_witness_unobtainable.rs");
}

#[test]
fn in_coin_source_witness_not_on_v11_surface() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/v11_provenance_type_unobtainable.rs");
}
