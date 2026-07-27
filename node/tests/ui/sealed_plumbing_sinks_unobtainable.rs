// Compile-fail matrix: every raw durable / publish / mutation / scan-apply
// sink on `node::v11` is sealed (`pub(crate)`). This file is an external
// crate depending on `node` as a library — same reachability as any
// downstream, release or debug, feature-gated or not.
//
// Driven by trybuild (`tests/sealed_plumbing_compile_fail_matrix.rs`).

fn main() {
    // --- publish sinks ---
    // Former free-standing publish helper (already removed) + raw batch sink.
    let _ = node::v11::publish_applied_nullifier;
    let _ = node::v11::publish_v11_batch;
    let _ = node::v11::publish::publish_v11_batch;

    // --- database-write sinks ---
    let _ = node::v11::db_v11::persist_engine_snapshot;
    let _ = node::v11::db_v11::persist_engine_with_pending_members_ready;
    let _ = node::v11::db_v11::insert_pending_publish_members_ready;
    let _ = node::v11::db_v11::mark_pending_publish_constructed;
    let _ = node::v11::db_v11::mark_pending_publish_status;

    // --- adapter-mutation sinks ---
    let _ = node::v11::EngineAdapter::with_engine_mut;
    let _ = node::v11::EngineAdapter::restore_live;
    let _ = node::v11::EngineAdapter::set_tip_hash;
    let _ = node::v11::EngineAdapter::persist;
    let _ = node::v11::EngineAdapter::reload_from_db;
    let _ = node::v11::EngineAdapter::lock_writes;
    let _ = node::v11::EngineAdapter::snapshot_live;

    // --- scan-apply sinks (raw fold/replace; orchestration stays public) ---
    let _ = node::v11::fold_survivors_into_engine;
    let _ = node::v11::replace_engine_nflog_from_survivors;
    let _ = node::v11::scan::fold_survivors_into_engine;
    let _ = node::v11::scan::replace_engine_nflog_from_survivors;
}
