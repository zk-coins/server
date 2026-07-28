// Compile-fail: prove_initial free function is no longer public.
// One expected error only.

fn main() {
    let _ = zkcoins_program::circuit::main::prove_initial;
}
