// Compile-fail matrix: every raw durable / publish / mutation / scan-apply
// sink on `node::v11` is sealed (`pub(crate)`). This file is an external
// crate depending on `node` as a library — same reachability as any
// downstream, release or debug, feature-gated or not.
//
// Beyond naming private wrappers, this matrix also proves **capability
// reachability**: inherent methods on whatever `connect_v11_publisher`
// returns, trait methods via UFCS, and free-standing construction of the
// argument types those methods take must all fail to compile.
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

    // Reachability probes below are typechecked as free-standing function
    // bodies (never invoked from main — avoids arity noise drowning the
    // real capability errors).
}

/// Inherent prepare / broadcast_commit / broadcast_reveal / publish on the
/// type returned by `connect_v11_publisher` must not resolve.
fn probe_inherent_methods_on_connect_return(publisher: &node::v11::V11Publisher) {
    let _ = publisher.prepare(&[]);
    let _ = publisher.broadcast_commit(loop {});
    let _ = publisher.broadcast_reveal(loop {});
    let _ = publisher.publish(&[]);
}

/// UFCS on the publisher trait must fail — trait is crate-private.
fn probe_trait_methods_via_ufcs(publisher: &node::v11::V11Publisher) {
    let _ = node::v11::NullifierBatchPublisher::publish_batch(publisher, &[]);
    let _ = node::v11::NullifierBatchPublisher::try_prepare(publisher, &[]);
    let _ = node::v11::NullifierBatchPublisher::broadcast_commit(publisher, loop {});
    let _ = node::v11::NullifierBatchPublisher::broadcast_reveal(publisher, loop {});
    let _ = node::v11::receive::NullifierBatchPublisher::publish_batch(publisher, &[]);
}

/// Free-standing `BatchMember` / `PreparedBatch` (and the foreign crate path)
/// must not be constructible from a crate that depends only on `node`.
fn probe_freestanding_batch_member_and_equivalents() {
    // Not re-exported on the v11 surface.
    let _ = node::v11::BatchMember {
        sig: loop {},
        build_tip: loop {},
    };
    let _ = node::v11::PreparedBatch {
        aggregate: loop {},
        payload: loop {},
        signed_commit: loop {},
        reveal_tx: loop {},
        commit_output: loop {},
        block_anchor: loop {},
        commit_vsize: loop {},
        reveal_vsize: loop {},
        commit_fee: loop {},
        reveal_fee: loop {},
    };
    // Not available through the publish submodule either.
    let _ = node::v11::publish::BatchMember {
        sig: loop {},
        build_tip: loop {},
    };
    // Foreign defining crate is not a direct dependency of a node-only consumer.
    let _ = ::zkcoins_prover_plonky2::publisher::BatchMember {
        sig: loop {},
        build_tip: loop {},
    };
    let _ = ::zkcoins_prover_plonky2::publisher::Publisher::connect(loop {});
}
