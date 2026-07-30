//! `SignTransition` — normative §3.2 / §7.5 wallet transition signature.
//!
//! Transport-free: no `axum`, no `tonic`. Cryptographic verification is
//! delegated to [`crate::v1::accept_wallet_transition_signature`] — this
//! module owns load, phase check, rehydrate, durable persist, handoff CAS
//! and wake ordering only.

use crate::job_dispatcher::JobNotifyMap;
use crate::job_store::{JobStatus, JobStore};
use crate::kernel::error::{KernelError, KernelErrorCode, KernelResult};
use crate::kernel::job_projection::project_job_row;
use crate::kernel::types::{Job, SignTransition};
use crate::v1::{
    self, PendingSignEntry, PendingSignMap, SignatureCheck, TransitionSignatureError, V1ShadowMode,
};

/// Dependencies for [`sign_transition`] — named so the call site stays
/// under clippy's argument limit and the three shared maps cannot be
/// reordered by accident.
pub(crate) struct SignTransitionDeps<'a> {
    pub store: &'a JobStore,
    pub pending_sign_map: &'a PendingSignMap,
    pub notify_map: &'a JobNotifyMap,
}

/// `SignTransition` (§7.8): verify a wallet S2C/BIP-340 signature against
/// the staged pending transition, persist the signed finalisation
/// capability, then hand off to a parked dispatcher.
///
/// # Ordering (security-critical)
///
/// 1. Load + phase check + rehydrate + verify
/// 2. Require a parked dispatcher notifier (**before** durable write)
/// 3. Install signature in-memory
/// 4. **Persist** signed capability under status-CAS (`awaiting_signature`)
/// 5. Handoff CAS (`try_signal_accept`) then `notify_one`
///
/// Persist before signal: a crash between signal and persist must not
/// leave SIGNALED with no durable signature. Absence of a notifier
/// refuses acceptance *before* persist so the wallet does not treat work
/// as done when nothing will finalise.
///
/// After a successful persist + CAS + wake, the result is projected from
/// the pre-loaded row — no second load. A post-success load failure must
/// not turn an irreversible accept into a client-visible error.
pub(crate) async fn sign_transition(
    deps: SignTransitionDeps<'_>,
    request: SignTransition,
) -> KernelResult<Job> {
    let SignTransitionDeps {
        store,
        pending_sign_map,
        notify_map,
    } = deps;
    let id = request.id.as_uuid();
    let submission = request.submission;

    let job = match store.load(id).await {
        Ok(Some(j)) => j,
        Ok(None) => return Err(KernelError::job_not_found()),
        Err(e) => {
            tracing::error!("JobStore::load failed in SignTransition: {}", e);
            return Err(KernelError::store_load_failed(e.to_string()));
        }
    };

    if job.status != JobStatus::AwaitingSignature {
        return Err(KernelError::wrong_phase(format!(
            "Job is in status `{}`, not `awaiting_signature`",
            job.status.as_str()
        )));
    }

    // Project **before** any durable write or handoff. Sign does not change
    // status or `response_body`, so the projected `Job` is the success
    // result. Doing this after signal would risk turning an irreversible
    // accept into a client-visible error on a corrupt payload (b2f).
    let projected = project_job_row(&job)?;

    // Prefer the in-memory map; after a restart rehydrate from the
    // persisted envelope under request_body.finalisation.
    let entry = match pending_sign_map.get(&id).map(|e| e.clone()) {
        Some(e) => e,
        None => match v1::rehydrate_pending_sign(&job.request_body) {
            Ok(Some(e)) => {
                pending_sign_map.insert(id, e.clone());
                e
            }
            Ok(None) => {
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "no PendingTransition staged for this job \
                     (awaiting_signature under v1.1 requires a staged entry)",
                    "SignTransition: missing staged pending while status is awaiting_signature",
                ));
            }
            Err(err) => {
                // Pre-split handler always surfaced rehydrate failures as
                // `internal_error` (corrupt/missing durable envelope), not
                // as a wallet-facing signature check. Preserve that.
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    err.message,
                    format!(
                        "SignTransition rehydrate_pending_sign failed at {:?}",
                        err.check
                    ),
                ));
            }
        },
    };

    // Normative path is always On; feature-disabled gating is transport-side
    // (HTTP `feature_disabled`). Crypto verify is reused, not reimplemented.
    let accepted = match v1::accept_wallet_transition_signature(
        V1ShadowMode::On,
        entry.network,
        &entry.pending,
        &submission,
    ) {
        Ok(sig) => sig,
        Err(err) => return Err(map_signature_error(err)),
    };

    // Require a parked dispatcher before durable write. Reporting
    // acceptance when nothing will finalise is worse than failing.
    let Some(notifier) = notify_map.get(&id).map(|e| e.value().clone()) else {
        return Err(KernelError::with_internal(
            KernelErrorCode::InternalError,
            "signature verified but no dispatcher is waiting to finalise this job; \
             refusing acceptance so the wallet does not treat the work as done",
            "SignTransition: job_notify_map has no entry for this job",
        ));
    };

    let mut entry = entry;
    if let Err(err) = entry.install_signature(accepted) {
        return Err(map_signature_error(err));
    }
    pending_sign_map.insert(id, entry.clone());

    let finalisation_value = encode_durable_finalisation(&entry)?;

    let mut merged = job.request_body.clone();
    let obj = match merged.as_object_mut() {
        Some(o) => o,
        None => {
            return Err(KernelError::corrupt_job_row(
                "jobs.request_body is not a JSON object (admit handlers enforce object shape)",
            ));
        }
    };
    obj.insert(v1::FINALISATION_BODY_KEY.to_string(), finalisation_value);
    // Drop legacy split keys if present (same cleanup as pre-split handler).
    obj.remove(v1::PENDING_SIGN_BODY_KEY);
    obj.remove("sign");

    match store
        .replace_request_body_if_status(id, JobStatus::AwaitingSignature, &merged)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            // Status moved (cancel / timeout / concurrent finalise). Write
            // did not hit — no event, no success.
            return Err(KernelError::wrong_phase(
                "signature verified but job is no longer awaiting_signature; \
                 status-qualified persist refused",
            ));
        }
        Err(e) => {
            tracing::error!(
                "Failed to persist durable finalisation signature in SignTransition: {}",
                e
            );
            return Err(KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to persist durable finalisation signature",
                e.to_string(),
            ));
        }
    }

    // Durable first, then CAS. If the dispatcher already timed out, refuse
    // acceptance even though the capability is signed.
    if !notifier.try_signal_accept() {
        return Err(KernelError::with_internal(
            KernelErrorCode::InternalError,
            "signature verified and persisted but the dispatcher is no longer waiting \
             to finalise this job (timed out or already signaled); refusing acceptance \
             so the wallet does not treat the work as done",
            "SignTransition: try_signal_accept lost handoff CAS after durable persist",
        ));
    }

    // Wake only after durable persist + successful CAS.
    notifier.commit_wake.notify_one();

    // Success is irreversible: return the pre-computed projection. No reload,
    // no second project (b2f: post-effect fallible work must not mask Ok).
    Ok(projected)
}

fn encode_durable_finalisation(entry: &PendingSignEntry) -> KernelResult<serde_json::Value> {
    let persist = match v1::DurableFinalisationPersist::from_entry(entry) {
        Ok(p) => p,
        Err(e) => {
            return Err(KernelError::with_internal(
                KernelErrorCode::InternalError,
                format!("encode durable finalisation: {e}"),
                "DurableFinalisationPersist::from_entry failed after install_signature",
            ));
        }
    };
    match serde_json::to_value(persist) {
        Ok(v) => Ok(v),
        Err(e) => Err(KernelError::with_internal(
            KernelErrorCode::InternalError,
            format!("encode durable finalisation: {e}"),
            "serde_json::to_value(DurableFinalisationPersist) failed",
        )),
    }
}

/// Map a v1 signature rejection onto the closed kernel error set.
///
/// Mirrors [`v1::sign_rejection`] machine codes; HTTP status/gRPC class
/// come from the error contract, not from inventing codes here.
pub(crate) fn map_signature_error(err: TransitionSignatureError) -> KernelError {
    match err.check {
        SignatureCheck::Encoding => {
            KernelError::new(KernelErrorCode::MalformedRequest, err.message)
        }
        SignatureCheck::S2cOpening => KernelError::new(KernelErrorCode::StaleMessage, err.message),
        SignatureCheck::Bip340 | SignatureCheck::PkMatch | SignatureCheck::PendingEnvelope => {
            KernelError::new(KernelErrorCode::InvalidSignature, err.message)
        }
        // Feature-disabled is an API-layer gate (`feature_disabled`), not a
        // kernel code. Domain always calls with V1ShadowMode::On; if this
        // arm is reached it is a programming error — fail closed as internal.
        SignatureCheck::ShadowFlag => KernelError::with_internal(
            KernelErrorCode::InternalError,
            err.message,
            "SignTransition received ShadowFlag under V1ShadowMode::On",
        ),
        SignatureCheck::LegacyCommitment => KernelError::wrong_phase(err.message),
    }
}

#[cfg(test)]
mod sign_tests {
    use super::*;
    use crate::job_dispatcher::JobNotifier;
    use crate::job_store::JobKind as StoreKind;
    use crate::kernel::types::{JobId, JobState};
    use crate::test_db::{setup_pool, SchemaScope};
    use crate::v1;
    use std::sync::Arc;

    async fn fresh_store() -> (Arc<JobStore>, SchemaScope) {
        let scope = setup_pool().await;
        (Arc::new(JobStore::new(scope.pool.clone())), scope)
    }

    fn empty_maps() -> (PendingSignMap, JobNotifyMap) {
        (
            Arc::new(dashmap::DashMap::new()),
            Arc::new(dashmap::DashMap::new()),
        )
    }

    async fn plant_awaiting(
        store: &JobStore,
        pending_sign_map: &PendingSignMap,
        with_durable: bool,
    ) -> (uuid::Uuid, v1::WalletSignSubmission) {
        let created = store
            .create(
                StoreKind::Send,
                &[0x51u8; 32],
                Some("k-sign-plant"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!("expected Fresh"),
        };
        let (entry, submission) = v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let advertised = v1::awaiting_signature_result_json(&entry);
        if with_durable {
            let persist = v1::DurableFinalisationPersist::from_entry(&entry).expect("encode");
            let mut body = serde_json::json!({});
            body.as_object_mut().unwrap().insert(
                v1::FINALISATION_BODY_KEY.to_string(),
                serde_json::to_value(&persist).unwrap(),
            );
            sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
                .bind(&body)
                .bind(id)
                .execute(store.pool())
                .await
                .expect("persist envelope");
        }
        store
            .set_awaiting_signature(id, 1, advertised)
            .await
            .expect("awaiting_signature");
        pending_sign_map.insert(id, entry);
        (id, submission)
    }

    #[tokio::test]
    async fn sign_accepts_and_persists_before_signal() {
        let (store, _db) = fresh_store().await;
        let (pending, notify) = empty_maps();
        let (id, submission) = plant_awaiting(store.as_ref(), &pending, true).await;
        let notifier = Arc::new(JobNotifier::new());
        notify.insert(id, Arc::clone(&notifier));

        let job = sign_transition(
            SignTransitionDeps {
                store: store.as_ref(),
                pending_sign_map: &pending,
                notify_map: &notify,
            },
            SignTransition {
                id: JobId(id),
                submission,
            },
        )
        .await
        .expect("sign ok");

        // Cause: still awaiting_signature (dispatcher finalise is later).
        assert!(
            matches!(job.state, JobState::AwaitingSignature { .. }),
            "sign does not flip status; got {:?}",
            job.state
        );
        // Handoff claimed SIGNALED.
        assert_eq!(
            notifier.handoff.load(std::sync::atomic::Ordering::SeqCst),
            crate::job_dispatcher::HANDOFF_SIGNALED
        );
        // Signature durable on the row.
        let row = store.load(id).await.expect("load").expect("row");
        let entry = v1::rehydrate_pending_sign(&row.request_body)
            .expect("rehydrate")
            .expect("finalisation present");
        assert!(
            entry.signature.is_some(),
            "persist-before-signal: signed capability must be durable after Ok"
        );
    }

    #[tokio::test]
    async fn sign_without_dispatcher_is_internal_error_and_does_not_persist() {
        let (store, _db) = fresh_store().await;
        let (pending, notify) = empty_maps();
        let (id, submission) = plant_awaiting(store.as_ref(), &pending, true).await;
        // No notify entry.

        let err = sign_transition(
            SignTransitionDeps {
                store: store.as_ref(),
                pending_sign_map: &pending,
                notify_map: &notify,
            },
            SignTransition {
                id: JobId(id),
                submission,
            },
        )
        .await
        .expect_err("no dispatcher");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        assert!(
            err.public_message.contains("no dispatcher"),
            "cause in message: {}",
            err.public_message
        );

        let row = store.load(id).await.expect("load").expect("row");
        let entry = v1::rehydrate_pending_sign(&row.request_body).ok().flatten();
        // Without durable envelope planted as signed — plant put unsigned
        // envelope only when with_durable; signature must still be absent.
        if let Some(e) = entry {
            assert!(
                e.signature.is_none(),
                "must not persist signature without a parked dispatcher"
            );
        }
    }

    #[tokio::test]
    async fn sign_wrong_phase_when_not_awaiting_signature() {
        let (store, _db) = fresh_store().await;
        let (pending, notify) = empty_maps();
        let created = store
            .create(
                StoreKind::Mint,
                &[0x52u8; 32],
                Some("k-sign-phase"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        let (_entry, submission) = v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let err = sign_transition(
            SignTransitionDeps {
                store: store.as_ref(),
                pending_sign_map: &pending,
                notify_map: &notify,
            },
            SignTransition {
                id: JobId(id),
                submission,
            },
        )
        .await
        .expect_err("queued");
        assert_eq!(err.code, KernelErrorCode::WrongPhase);
        assert!(
            err.public_message.contains("awaiting_signature"),
            "{}",
            err.public_message
        );
    }

    #[tokio::test]
    async fn sign_stale_message_maps_s2c_failure() {
        let (store, _db) = fresh_store().await;
        let (pending, notify) = empty_maps();
        let (id, mut submission) = plant_awaiting(store.as_ref(), &pending, true).await;
        notify.insert(id, Arc::new(JobNotifier::new()));
        // Corrupt s2c nonce → S2C opening fail → stale_message.
        submission.s2c_nonce = [0xEEu8; 32];

        let err = sign_transition(
            SignTransitionDeps {
                store: store.as_ref(),
                pending_sign_map: &pending,
                notify_map: &notify,
            },
            SignTransition {
                id: JobId(id),
                submission,
            },
        )
        .await
        .expect_err("stale");
        assert_eq!(
            err.code,
            KernelErrorCode::StaleMessage,
            "S2C failure must be stale_message, not generic err: {}",
            err.public_message
        );
    }

    #[tokio::test]
    async fn sign_invalid_signature_maps_bip340_failure() {
        let (store, _db) = fresh_store().await;
        let (pending, notify) = empty_maps();
        let (id, mut submission) = plant_awaiting(store.as_ref(), &pending, true).await;
        notify.insert(id, Arc::new(JobNotifier::new()));
        // Flip a byte in the s half so BIP-340 fails (S2C uses R + r_prime).
        submission.signature[63] ^= 0x01;

        let err = sign_transition(
            SignTransitionDeps {
                store: store.as_ref(),
                pending_sign_map: &pending,
                notify_map: &notify,
            },
            SignTransition {
                id: JobId(id),
                submission,
            },
        )
        .await
        .expect_err("bad sig");
        // Depending on which half fails, could be stale (R/s2c) or invalid.
        // Flipping s half (bytes 32..64) leaves R and r_prime intact → BIP-340.
        assert_eq!(
            err.code,
            KernelErrorCode::InvalidSignature,
            "BIP-340 failure must be invalid_signature: {}",
            err.public_message
        );
    }

    #[tokio::test]
    async fn sign_timed_out_handoff_persists_signature_but_refuses_acceptance() {
        let (store, _db) = fresh_store().await;
        let (pending, notify) = empty_maps();
        let (id, submission) = plant_awaiting(store.as_ref(), &pending, true).await;
        let notifier = Arc::new(JobNotifier::new());
        assert!(notifier.try_claim_timeout(), "simulate dispatcher timeout");
        notify.insert(id, Arc::clone(&notifier));

        let err = sign_transition(
            SignTransitionDeps {
                store: store.as_ref(),
                pending_sign_map: &pending,
                notify_map: &notify,
            },
            SignTransition {
                id: JobId(id),
                submission,
            },
        )
        .await
        .expect_err("handoff lost");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        assert!(
            err.public_message.contains("no longer waiting")
                || err.public_message.contains("timed out"),
            "{}",
            err.public_message
        );

        // Persist-before-signal: durable signature present even on refuse.
        let row = store.load(id).await.expect("load").expect("row");
        let entry = v1::rehydrate_pending_sign(&row.request_body)
            .expect("rehydrate")
            .expect("finalisation");
        assert!(
            entry.signature.is_some(),
            "signature must be durable when CAS refuses after persist"
        );
    }

    #[tokio::test]
    async fn sign_rehydrates_after_empty_map() {
        let (store, _db) = fresh_store().await;
        let (pending, notify) = empty_maps();
        let (id, submission) = plant_awaiting(store.as_ref(), &pending, true).await;
        pending.clear(); // simulated restart
        assert!(pending.get(&id).is_none());
        notify.insert(id, Arc::new(JobNotifier::new()));

        let job = sign_transition(
            SignTransitionDeps {
                store: store.as_ref(),
                pending_sign_map: &pending,
                notify_map: &notify,
            },
            SignTransition {
                id: JobId(id),
                submission,
            },
        )
        .await
        .expect("rehydrate + sign");
        assert!(matches!(job.state, JobState::AwaitingSignature { .. }));
        assert!(
            pending.get(&id).is_some(),
            "rehydrate must re-stage the pending entry"
        );
    }

    #[tokio::test]
    async fn sign_unknown_job_is_job_not_found() {
        let (store, _db) = fresh_store().await;
        let (pending, notify) = empty_maps();
        let (_entry, submission) = v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let err = sign_transition(
            SignTransitionDeps {
                store: store.as_ref(),
                pending_sign_map: &pending,
                notify_map: &notify,
            },
            SignTransition {
                id: JobId(uuid::Uuid::new_v4()),
                submission,
            },
        )
        .await
        .expect_err("missing");
        assert_eq!(err.code, KernelErrorCode::JobNotFound);
    }

    #[test]
    fn map_signature_error_causes_are_closed() {
        let cases = [
            (SignatureCheck::Encoding, KernelErrorCode::MalformedRequest),
            (SignatureCheck::S2cOpening, KernelErrorCode::StaleMessage),
            (SignatureCheck::Bip340, KernelErrorCode::InvalidSignature),
            (SignatureCheck::PkMatch, KernelErrorCode::InvalidSignature),
            (
                SignatureCheck::PendingEnvelope,
                KernelErrorCode::InvalidSignature,
            ),
            (
                SignatureCheck::LegacyCommitment,
                KernelErrorCode::WrongPhase,
            ),
            (SignatureCheck::ShadowFlag, KernelErrorCode::InternalError),
        ];
        for (check, want) in cases {
            let err = TransitionSignatureError {
                check,
                message: "m".into(),
            };
            assert_eq!(map_signature_error(err).code, want, "check={check:?}");
        }
    }
}
