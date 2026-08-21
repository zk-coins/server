//! `AttestBalance` — transport-free domain procedure (§5.7 / §7.5 / §7.8).
//!
//! The API layer has already verified the action-bound OwnershipProof
//! (§5.1 / §7.5). This module:
//!
//! 1. consumes the single-use `AttestBalanceChallenge` (nonce + chan_bind);
//! 2. admits a `kind = attest_balance` job under the same store path the
//!    HTTP handler used before the split.
//!
//! Cryptographic OwnershipProof verification, BIP-340, and `C_balance`
//! proving stay outside this module — verification at the HTTP edge,
//! proving in `v1::attest` / the dispatcher. No `axum`, no `tonic`.

use tokio::sync::mpsc;

use crate::job_dispatcher::JobEnvelope;
use crate::job_store::{self, CreateResult, JobKind as StoreKind, JobStore};
use crate::kernel::bootstrap::{ChallengeAction, ChallengeStore};
use crate::kernel::job_projection::project_job_row;
use crate::kernel::types::{ChanBind, Digest32, SubjectAddress};
use crate::kernel::{Job, KernelError, KernelErrorCode, KernelResult};

/// Ceiling pair for `AttestBalance` (§7.5).
///
/// Structural: both present or both absent. Mixed presence is not
/// representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttestCeiling {
    /// Omit both → node uses current `size_final`.
    NodeDefault,
    /// Client-supplied `nav_ceiling` (32-byte root) + `size_ceiling`.
    Explicit {
        nav_ceiling: Digest32,
        size_ceiling: u64,
    },
}

/// Already-authorised `AttestBalance` command (§7.8 `AttestRequest`).
///
/// No OwnershipProof fields — those are API-layer only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttestBalanceCommand {
    pub subject: SubjectAddress,
    pub asset_id: Digest32,
    pub ceiling: AttestCeiling,
    pub nonce: [u8; 32],
    pub chan_bind: ChanBind,
}

/// Dependencies for [`attest_balance`].
pub(crate) struct AttestBalanceDeps<'a> {
    pub challenges: &'a ChallengeStore,
    pub store: &'a JobStore,
    pub job_tx: &'a mpsc::Sender<JobEnvelope>,
    /// Precomputed `chan_bind` values for every authoritative public host
    /// (and onion key, if any). Empty → every redeem fails `ChanBindMismatch`.
    pub allowed_chan_binds: &'a [[u8; 32]],
    pub now: u64,
}

/// Persistable job body after a successful challenge consume (same shape
/// the dispatcher / `v1::prove_attestation_for_job` already understand).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct AttestJobBody {
    pub subject: [u8; 32],
    pub asset_id: [u8; 32],
    pub nav_ceiling: Option<[u8; 32]>,
    pub size_ceiling: Option<u64>,
}

impl AttestJobBody {
    pub(crate) fn from_command(cmd: &AttestBalanceCommand) -> Self {
        let (nav_ceiling, size_ceiling) = match cmd.ceiling {
            AttestCeiling::NodeDefault => (None, None),
            AttestCeiling::Explicit {
                nav_ceiling,
                size_ceiling,
            } => (Some(nav_ceiling.0), Some(size_ceiling)),
        };
        Self {
            subject: cmd.subject.0,
            asset_id: cmd.asset_id.0,
            nav_ceiling,
            size_ceiling,
        }
    }
}

/// `AttestBalance` (§7.8): consume the action-bound challenge, admit the job.
///
/// # Ordering
///
/// 1. Redeem challenge (atomic, action-bound) — irreversible on success
/// 2. Encode job body (infallible for a well-typed command)
/// 3. `JobStore::create` + dispatcher handoff
///
/// OwnershipProof verification is **not** performed here (API-layer gate).
pub(crate) async fn attest_balance(
    deps: AttestBalanceDeps<'_>,
    command: AttestBalanceCommand,
) -> KernelResult<Job> {
    let AttestBalanceDeps {
        challenges,
        store,
        job_tx,
        allowed_chan_binds,
        now,
    } = deps;

    challenges
        .redeem(
            ChallengeAction::AttestBalance,
            &command.nonce,
            &command.subject,
            &command.chan_bind,
            allowed_chan_binds,
            now,
        )
        .map_err(crate::kernel::bootstrap::ChallengeConsumeError::into_kernel_error)?;

    let body = AttestJobBody::from_command(&command);
    let request_value = serde_json::to_value(&body).map_err(|e| {
        KernelError::with_internal(
            KernelErrorCode::InternalError,
            "Failed to admit attestation job",
            format!("encode AttestJobBody: {e}"),
        )
    })?;

    let create_result = store
        .create(
            StoreKind::AttestBalance,
            &command.subject.0,
            None,
            request_value,
        )
        .await
        .map_err(|e| {
            tracing::error!("JobStore::create (attest_balance) failed: {}", e);
            KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to admit attestation job",
                e.to_string(),
            )
        })?;

    let job_row = match create_result {
        CreateResult::Fresh(j) | CreateResult::IdempotentReplay(j) => j,
        CreateResult::IdempotencyConflict => {
            // Attest admits without an Idempotency-Key; this arm is not
            // reachable for the current create call shape.
            return Err(KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to admit attestation job",
                "unexpected idempotency_conflict on attest admit",
            ));
        }
    };

    // Project before enqueue so a later load cannot turn a durable admit
    // into a client-visible error. Enqueue failure fails the row when the
    // CAS hits; the projected handle still names the public id.
    let projected = project_job_row(&job_row)?;

    if let Err(e) = job_tx
        .send(JobEnvelope {
            public_id: job_row.public_id,
        })
        .await
    {
        tracing::error!("attest job enqueue failed: {}", e);
        let err_body =
            crate::v1::encode_job_error("internal_error", format!("enqueue failed: {e}"));
        match store
            .fail(
                job_row.public_id,
                job_store::JobStatus::Queued,
                &err_body.to_string(),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::error!(
                    "attest admit: fail(queued) matched 0 rows for {}; \
                     not inventing success after enqueue loss",
                    job_row.public_id
                );
            }
            Err(store_err) => {
                tracing::error!(
                    "attest admit: fail after enqueue loss failed: {}",
                    store_err
                );
            }
        }
        return Err(KernelError::with_internal(
            KernelErrorCode::InternalError,
            "Failed to admit attestation job",
            format!("dispatcher enqueue failed: {e}"),
        ));
    }

    Ok(projected)
}

/// Issue an `AttestBalanceChallenge` (shared store entry point).
pub(crate) fn open_attest_balance_challenge(
    challenges: &ChallengeStore,
    subject: SubjectAddress,
    now: u64,
) -> crate::kernel::bootstrap::IssuedChallenge {
    challenges.issue(ChallengeAction::AttestBalance, subject, now)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::bootstrap::ChallengeConsumeError;
    use crate::kernel::types::JobKind;
    use crate::test_db::setup_pool;

    #[tokio::test]
    async fn attest_balance_consumes_challenge_and_admits_job() {
        let scope = setup_pool().await;
        let store = JobStore::new(scope.pool.clone());
        let challenges = ChallengeStore::new();
        let (tx, mut rx) = mpsc::channel(4);
        let now = 1_000u64;
        let subject = SubjectAddress([0x21u8; 32]);
        let issued = open_attest_balance_challenge(&challenges, subject, now);
        let allowed = [[0xAAu8; 32]];

        let job = attest_balance(
            AttestBalanceDeps {
                challenges: &challenges,
                store: &store,
                job_tx: &tx,
                allowed_chan_binds: &allowed,
                now,
            },
            AttestBalanceCommand {
                subject,
                asset_id: Digest32([0x22u8; 32]),
                ceiling: AttestCeiling::NodeDefault,
                nonce: issued.nonce,
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .await
        .expect("admit");

        assert_eq!(job.kind, JobKind::AttestBalance);
        let env = rx.try_recv().expect("dispatcher envelope");
        assert_eq!(env.public_id, job.id.as_uuid());

        // Challenge single-use.
        let err = challenges
            .redeem(
                ChallengeAction::AttestBalance,
                &issued.nonce,
                &subject,
                &ChanBind(allowed[0]),
                &allowed,
                now,
            )
            .expect_err("consumed");
        assert_eq!(err, ChallengeConsumeError::UnknownOrConsumed);
    }

    #[tokio::test]
    async fn attest_balance_rejects_wrong_chan_bind_with_cause() {
        let scope = setup_pool().await;
        let store = JobStore::new(scope.pool.clone());
        let challenges = ChallengeStore::new();
        let (tx, _rx) = mpsc::channel(1);
        let now = 2_000u64;
        let subject = SubjectAddress([0x31u8; 32]);
        let issued = open_attest_balance_challenge(&challenges, subject, now);
        let allowed = [[0x01u8; 32]];

        let err = attest_balance(
            AttestBalanceDeps {
                challenges: &challenges,
                store: &store,
                job_tx: &tx,
                allowed_chan_binds: &allowed,
                now,
            },
            AttestBalanceCommand {
                subject,
                asset_id: Digest32([0x32u8; 32]),
                ceiling: AttestCeiling::NodeDefault,
                nonce: issued.nonce,
                chan_bind: ChanBind([0xFFu8; 32]),
            },
        )
        .await
        .expect_err("wrong chan_bind");
        assert_eq!(err.code, KernelErrorCode::Unauthorized);
        assert!(
            err.public_message.contains("chan_bind"),
            "message must name chan_bind: {}",
            err.public_message
        );
    }

    #[tokio::test]
    async fn grant_action_challenge_cannot_authorise_attest_balance() {
        let scope = setup_pool().await;
        let store = JobStore::new(scope.pool.clone());
        let challenges = ChallengeStore::new();
        let (tx, _rx) = mpsc::channel(1);
        let now = 3_000u64;
        let subject = SubjectAddress([0x41u8; 32]);
        let grant_chal = challenges.issue(ChallengeAction::IssueViewGrant, subject, now);
        let allowed = [[0x00u8; 32]];

        let err = attest_balance(
            AttestBalanceDeps {
                challenges: &challenges,
                store: &store,
                job_tx: &tx,
                allowed_chan_binds: &allowed,
                now,
            },
            AttestBalanceCommand {
                subject,
                asset_id: Digest32([0x42u8; 32]),
                ceiling: AttestCeiling::NodeDefault,
                nonce: grant_chal.nonce,
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .await
        .expect_err("grant challenge");
        assert_eq!(err.code, KernelErrorCode::ChallengeExpired);
    }
}
