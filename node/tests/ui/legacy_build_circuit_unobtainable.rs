// Compile-fail: build_circuit is no longer public (deleted from API surface).
// One expected error only.

fn main() {
    let _ = zkcoins_program::circuit::main::build_circuit;
}
