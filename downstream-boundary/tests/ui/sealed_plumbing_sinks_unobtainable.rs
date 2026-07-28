// Compile-fail matrix: every raw durable / publish / mutation / scan-apply
// sink on `node::v1` is sealed (`pub(crate)`). This file is an external
// crate depending on `node` as a library — same reachability as any
// downstream, release or debug, feature-gated or not.
//
// Beyond naming private wrappers, this matrix also proves **capability
// reachability** on whatever `connect_v1_publisher` actually returns
// (type derived from the connect expression — never a hardcoded facade
// name), trait methods via UFCS, free-standing construction of the
// argument types those methods take, coercion / Deref / AsRef reopenings,
// and a pin of the public API surface so future widening fails loudly.
//
// Driven by trybuild (`tests/sealed_plumbing_compile_fail_matrix.rs`)
// under the `downstream-boundary` package (node-only direct dependency).

/// Obtain a value whose type is whatever `connect_v1_publisher` returns.
///
/// Macro (not an `impl Trait` helper): an opaque return type would erase
/// inherent methods and the matrix would stay green even if connect
/// regressed to the raw foreign `Publisher`. Expansion keeps the concrete
/// type so the probe follows whatever connect actually returns.
/// Hardcoding `&V1Publisher` would pin a name, not the boundary.
macro_rules! publisher_from_connect {
    () => {
        match node::v1::connect_v1_publisher(loop {}) {
            Ok(p) => p,
            Err(_) => loop {},
        }
    };
}

fn main() {
    // --- publish sinks ---
    // Former free-standing publish helper (already removed) + raw batch sink.
    let _ = node::v1::publish_applied_nullifier;
    let _ = node::v1::publish_v1_batch;
    let _ = node::v1::publish::publish_v1_batch;

    // --- database-write sinks ---
    let _ = node::v1::db_v1::persist_engine_snapshot;
    let _ = node::v1::db_v1::persist_engine_with_pending_members_ready;
    let _ = node::v1::db_v1::insert_pending_publish_members_ready;
    let _ = node::v1::db_v1::mark_pending_publish_constructed;
    let _ = node::v1::db_v1::mark_pending_publish_status;

    // --- adapter-mutation sinks ---
    let _ = node::v1::EngineAdapter::with_engine_mut;
    let _ = node::v1::EngineAdapter::restore_live;
    let _ = node::v1::EngineAdapter::set_tip_hash;
    let _ = node::v1::EngineAdapter::persist;
    let _ = node::v1::EngineAdapter::reload_from_db;
    let _ = node::v1::EngineAdapter::lock_writes;
    let _ = node::v1::EngineAdapter::snapshot_live;

    // --- scan-apply sinks (raw fold/replace; orchestration stays public) ---
    let _ = node::v1::fold_survivors_into_engine;
    let _ = node::v1::replace_engine_nflog_from_survivors;
    let _ = node::v1::scan::fold_survivors_into_engine;
    let _ = node::v1::scan::replace_engine_nflog_from_survivors;

    // Reachability probes below are typechecked as free-standing function
    // bodies (never invoked from main — avoids arity noise drowning the
    // real capability errors).
}

/// Inherent prepare / broadcast_commit / broadcast_reveal / publish on the
/// type returned by `connect_v1_publisher` must not resolve.
///
/// Type is derived from the connect expression via `publisher_from_connect!`
/// — not a hardcoded `&V1Publisher`. If connect regresses to the raw
/// foreign `Publisher`, these four calls compile and the matrix fails.
fn probe_inherent_methods_on_connect_return() {
    let publisher = publisher_from_connect!();
    let _ = publisher.prepare(&[]);
    let _ = publisher.broadcast_commit(loop {});
    let _ = publisher.broadcast_reveal(loop {});
    let _ = publisher.publish(&[]);
}

/// UFCS on the publisher trait must fail — trait is crate-private.
fn probe_trait_methods_via_ufcs() {
    let publisher = publisher_from_connect!();
    let _ = node::v1::NullifierBatchPublisher::publish_batch(&publisher, &[]);
    let _ = node::v1::NullifierBatchPublisher::try_prepare(&publisher, &[]);
    let _ = node::v1::NullifierBatchPublisher::broadcast_commit(&publisher, loop {});
    let _ = node::v1::NullifierBatchPublisher::broadcast_reveal(&publisher, loop {});
    let _ = node::v1::receive::NullifierBatchPublisher::publish_batch(&publisher, &[]);
}

/// Free-standing `BatchMember` / `PreparedBatch` (and the foreign crate path)
/// must not be constructible from a crate that depends only on `node`.
fn probe_freestanding_batch_member_and_equivalents() {
    // Not re-exported on the v1 surface.
    let _ = node::v1::BatchMember {
        sig: loop {},
        build_tip: loop {},
    };
    let _ = node::v1::PreparedBatch {
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
    let _ = node::v1::publish::BatchMember {
        sig: loop {},
        build_tip: loop {},
    };
    // Foreign defining crate is not a direct dependency of this node-only
    // consumer. Use the Cargo package name (`zkcoins-prover` →
    // `zkcoins_prover`), not the path-directory name — a wrong name would
    // fail for the wrong reason and mask a real dep leak.
    let _ = ::zkcoins_prover::publisher::BatchMember {
        sig: loop {},
        build_tip: loop {},
    };
    let _ = ::zkcoins_prover::publisher::Publisher::connect(loop {});
}

/// Coercion / auto-deref / explicit Deref must not re-open foreign inherent
/// methods on the connect return type.
fn probe_coercion_and_deref() {
    let publisher = publisher_from_connect!();

    // Auto-deref through `&_`: foreign inherent methods must still fail.
    let _ = (&publisher).prepare(&[]);
    let _ = (&publisher).publish(&[]);

    // Explicit `Deref` bound — must not hold for the connect return type.
    // Adding `impl Deref<Target = Publisher>` (or any Deref) makes this
    // bound succeed and the matrix fails the compile_fail expectation.
    fn needs_deref<T: std::ops::Deref>(_t: &T) {}
    needs_deref(&publisher);

    // Explicit deref operator + method: same reopening if Target has prepare.
    let _ = (*&publisher).prepare(&[]);
    let _ = std::ops::Deref::deref(&publisher).prepare(&[]);
}

/// `AsRef` must not re-open foreign inherent methods.
fn probe_asref_does_not_open_foreign_methods() {
    let publisher = publisher_from_connect!();
    // Fully-qualified `AsRef::as_ref` — fails when no AsRef impl exists.
    // If `AsRef<Publisher>` (or any AsRef target with prepare) is added,
    // `as_ref` succeeds and the subsequent inherent calls compile → matrix
    // fails the compile_fail expectation.
    let exposed = std::convert::AsRef::as_ref(&publisher);
    let _ = exposed.prepare(&[]);
    let _ = exposed.broadcast_commit(loop {});
    let _ = exposed.broadcast_reveal(loop {});
    let _ = exposed.publish(&[]);
}

/// Public API surface pin: foreign types, re-export aliases, and extraction
/// helpers must not appear on the node public surface. Future widening of
/// these names fails here rather than silently shipping.
fn probe_public_api_surface_not_widened() {
    let publisher = publisher_from_connect!();

    // Facade field must stay private (no `publisher.inner` extraction).
    let _ = publisher.inner;

    // No inherent extraction / conversion helpers on the connect return type.
    let _ = publisher.into_inner();
    let _ = publisher.as_inner();
    let _ = publisher.inner();
    let _ = publisher.into_publisher();
    let _ = publisher.as_publisher();

    // Foreign publisher type and friends must not be re-exported on v1 /
    // publish (including under alias names other than the opaque facade).
    let _ = node::v1::Publisher;
    let _ = node::v1::publish::Publisher;
    let _ = node::v1::PublisherConfig;
    let _ = node::v1::publish::PublisherConfig;
    let _ = node::v1::PublishedBatch;
    let _ = node::v1::publish::PublishedBatch;
    let _ = node::v1::PreparedBatch;
    let _ = node::v1::publish::PreparedBatch;
    // BatchMember already probed via struct literal above; also pin the
    // bare path form so a future `pub use` / type alias is caught.
    let _ = node::v1::BatchMember;
    let _ = node::v1::publish::BatchMember;

    // No re-export of the foreign crate through the node package root.
    let _ = node::zkcoins_prover;
    let _ = node::v1::zkcoins_prover;
    let _ = node::v1::publish::zkcoins_prover;

    // Stage 3 Runde 4: legacy scan private field (cap unconstructible).
    // Prover type deleted — also unobtainable. Kept as extra sinks in this
    // multi-sink file (existing sealed_plumbing matrix). New Stage-3
    // one-file-one-error cases live under node/tests/ui.
    let _ = node::legacy_commitment_scan::LegacyCommitmentScanCap { _private: () };
}
