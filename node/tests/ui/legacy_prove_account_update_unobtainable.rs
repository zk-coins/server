// Compile-fail: prove_account_update free function is no longer public.
// One expected error only.

fn main() {
    let _ = zkcoins_program::circuit::main::prove_account_update;
}
