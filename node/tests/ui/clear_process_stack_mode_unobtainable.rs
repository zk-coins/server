// Compile-fail: the process-claim reset is unreachable from every edge
// outside the defining crate's own `#[cfg(test)]`.
//
// Former mistake: only probing `node::v1::…` while the same capability
// remained public as `stack_policy::…` behind a `test-support` feature
// that any downstream could enable. The diagnostic even recommended that
// import. The seal is now the capability itself — `#[cfg(test)]` of
// `stack-policy` — not an import path. A Cargo feature cannot reopen it.
//
// Driven by trybuild (`tests/process_claim_compile_fail.rs`).

fn main() {
    // Intentional: node no longer re-exports the reset under any cfg.
    node::v1::clear_process_stack_mode_for_test();
    // Intentional: stack-policy only compiles the reset under its own
    // cfg(test); dependency builds (this trybuild UI crate) never see it.
    stack_policy::clear_process_stack_mode_for_test();
}
