// Compile-fail: a broadcast-capable client requires a LegacyBroadcastWitness.
// There is no un-witnessed constructor. Driven by trybuild (see
// `tests/broadcast_witness_compile_fail.rs`). This file is compiled as a
// consumer of `esplora-bound` without `issue-legacy-broadcast-witness`.

fn main() {
    // Intentional: connect without a witness must not compile.
    // The guarantee is the missing argument / wrong arity — not a string
    // search for "ensure_legacy_publisher_allowed".
    let _ = esplora_bound::EsploraBroadcastClient::connect("http://127.0.0.1");
}
