// Compile-fail: free verify for circuit::main is no longer public.
// One expected error only.

fn main() {
    let _ = zkcoins_program::circuit::main::verify;
}
