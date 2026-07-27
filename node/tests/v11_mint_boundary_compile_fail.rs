//! Compile-time evidence for the G7 mint boundary:
//! - raw engine mint sink is module-private;
//! - `begin_v11_mint` does not accept a caller-selected `V11ShadowMode`.

#[test]
fn engine_begin_mint_sink_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/v11_mint_engine_sink_unobtainable.rs");
}

#[test]
fn begin_v11_mint_mode_arg_is_unobtainable_by_compilation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/v11_mint_mode_arg_unobtainable.rs");
}
