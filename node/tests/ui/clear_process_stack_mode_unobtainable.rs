// Compile-fail: production `node` must not re-export the process-claim
// reset. The claim is monotonic once set; only test builds that enable
// stack-policy's `test-support` feature (via [dev-dependencies]) may
// call `clear_process_stack_mode_for_test`. This file is driven by
// trybuild (see `tests/process_claim_compile_fail.rs`).

fn main() {
    // Intentional: the reset is cfg(test)-gated on the node surface and
    // feature-gated out of production stack-policy builds.
    node::v11::clear_process_stack_mode_for_test();
}
