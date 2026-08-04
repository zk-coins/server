//! `SubmitTransition` — normative §7.5 / §7.8 transition admission.
//!
//! Transport-free: no `axum`, no `tonic`. Validates a closed
//! [`TransitionCommand`] (presence matrix + circuit bounds), admits a
//! job row under the same idempotency rules as legacy mint/send, and
//! hands the public id to the dispatcher.
//!
//! Legacy creator-signature / timestamp gates stay in `flow::*` and the
//! HTTP handlers — they are **not** part of this normative procedure.

use tokio::sync::mpsc;

// §7.5 delivery surface via the `jobs` re-export so the production call path
// keeps those symbols live (clippy unused_imports is the witness when this
// path is unwired — same class of gap as the publisher).
use super::{
    check_and_store_delivery_credentials, is_self_output, DeliveryCheckDeps, ProfileHighWaterStore,
};
use crate::job_dispatcher::JobEnvelope;
use crate::job_store::{self, CreateResult, JobStore};
use crate::kernel::bootstrap::BundleStore;
use crate::kernel::job_projection::project_job_row;
use crate::kernel::types::{Digest32, IdempotencyKey, Issuance, OutputTemplate, PublisherChoice};
use crate::kernel::{Job, KernelError, KernelErrorCode, KernelResult, TransitionCommand};
use crate::v1::DeliveryTargetStore;
use shared::spec_v1::ManifestClock;

/// §2.5 / §7.5 circuit bounds used at admit time (must match the sealed
/// circuit shape: `MAX_TX_INPUTS=8`, `MAX_TX_OUTPUTS=8`, `MAX_RX_COINS=4`).
pub(crate) const MAX_TX_INPUTS: usize = 8;
pub(crate) const MAX_TX_OUTPUTS: usize = 8;
pub(crate) const MAX_RX_COINS: usize = 4;

/// §7.5: Idempotency-Key is an opaque client string of at most 64 bytes.
pub(crate) const MAX_IDEMPOTENCY_KEY_BYTES: usize = 64;

/// §7.5 / §1.5: asset `name` MUST NOT exceed 255 bytes.
pub(crate) const MAX_ISSUANCE_NAME_BYTES: usize = 255;

/// Dependencies for [`admit_job`] (store + dispatcher only).
pub(crate) struct AdmitJobDeps<'a> {
    pub store: &'a JobStore,
    pub job_tx: &'a mpsc::Sender<JobEnvelope>,
}

/// Dependencies for [`submit_transition`] (admit + §7.5 delivery checks).
pub(crate) struct SubmitTransitionDeps<'a> {
    pub store: &'a JobStore,
    pub job_tx: &'a mpsc::Sender<JobEnvelope>,
    /// Active operational bundles (self-output leg of the §7.5 presence rule).
    pub bundles: &'a BundleStore,
    /// Verified delivery targets filled after credential checklists pass.
    pub delivery_targets: &'a DeliveryTargetStore,
    /// Relay-relative kind-0 high-water for profile freshness.
    pub profile_high_water: &'a ProfileHighWaterStore,
    /// Persisted `AccountState.owner` for the command subject, when known.
    pub subject_owner: Option<[u8; 32]>,
    /// Network pin for profile `zkcoins.network` checks.
    pub network: crate::kernel::chain::KernelNetwork,
    /// Injected wall clock for profile freshness windows and delivery TTL.
    ///
    /// [`ManifestClock::Unavailable`] is fail-closed at the credential check
    /// (profile age / store insert), not silently skipped.
    pub clock: ManifestClock,
}

/// Outcome of a successful admit (fresh row or same-key same-body replay).
///
/// Carries the **store row** so HTTP can project legacy wire fields
/// (`queued`, cached `response_body`) without a second load after the
/// irreversible create/commit.
#[derive(Debug, Clone)]
pub(crate) enum AdmitOutcome {
    /// Brand-new row; dispatcher was notified.
    Fresh(job_store::Job),
    /// Same idempotency key and equal admit body; no second enqueue.
    Replay(job_store::Job),
}

/// Failures of [`admit_job`]. Typed so HTTP can map the dispatcher
/// channel-down path to 503 without parsing message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmitError {
    /// Domain / store failure with a closed [`KernelErrorCode`].
    Domain(KernelError),
    /// Row was inserted but the admit channel refused the envelope;
    /// the row was CAS-failed from `queued` when the write hit.
    DispatcherUnavailable,
}

impl From<KernelError> for AdmitError {
    fn from(value: KernelError) -> Self {
        Self::Domain(value)
    }
}

impl AdmitError {
    pub(crate) fn into_kernel_error(self) -> KernelError {
        match self {
            Self::Domain(e) => e,
            Self::DispatcherUnavailable => KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Dispatcher unavailable",
                "admit channel send failed after job row insert",
            ),
        }
    }
}

/// Validate the closed presence / bounds matrix for a
/// [`TransitionCommand`] without touching the store.
///
/// # Errors
///
/// - [`KernelErrorCode::MalformedRequest`] — empty required list, empty
///   idempotency key, empty issuance name, issuance name over 255 bytes,
///   or other shape violations that are not pure upper bounds.
/// - [`KernelErrorCode::BoundsExceeded`] — when `input_coins`,
///   `output_templates`, or `fold_coin_ids` exceeds the §2.5 maximum.
///
/// Coin existence / spentness (`invalid_input_coin`) and balance
/// conservation (`insufficient_balance`) are **not** checked here —
/// they need ledger state during prove / a later store lookup. Publisher
/// profile resolution (`unknown_publisher`) is also deferred.
pub(crate) fn validate_transition_command(command: &TransitionCommand) -> KernelResult<()> {
    let common = command.common();
    validate_idempotency_key(&common.idempotency_key)?;

    match command {
        TransitionCommand::Mint {
            issuance,
            output_templates,
            ..
        } => {
            validate_issuance(issuance)?;
            validate_output_templates(output_templates)?;
        }
        TransitionCommand::Send {
            input_coins,
            output_templates,
            ..
        } => {
            validate_input_coins(input_coins)?;
            validate_output_templates(output_templates)?;
        }
        TransitionCommand::Receive { fold_coin_ids, .. } => {
            validate_fold_coin_ids(fold_coin_ids)?;
        }
    }
    Ok(())
}

fn validate_idempotency_key(key: &IdempotencyKey) -> KernelResult<()> {
    let raw = key.as_str();
    if raw.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "Idempotency-Key must be non-empty",
        ));
    }
    if raw.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!(
                "Idempotency-Key exceeds {MAX_IDEMPOTENCY_KEY_BYTES} bytes (got {})",
                raw.len()
            ),
        ));
    }
    Ok(())
}

fn validate_issuance(issuance: &Issuance) -> KernelResult<()> {
    let name = match issuance {
        Issuance::V1 { name, .. } | Issuance::V2 { name, .. } => name,
    };
    if name.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "issuance.name must be non-empty",
        ));
    }
    if name.len() > MAX_ISSUANCE_NAME_BYTES {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!(
                "issuance.name exceeds {MAX_ISSUANCE_NAME_BYTES} bytes (got {})",
                name.len()
            ),
        ));
    }
    Ok(())
}

fn validate_input_coins(coins: &[Digest32]) -> KernelResult<()> {
    if coins.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "kind=send requires input_coins with at least one coin identifier",
        ));
    }
    if coins.len() > MAX_TX_INPUTS {
        return Err(KernelError::new(
            KernelErrorCode::BoundsExceeded,
            format!(
                "input_coins length {} exceeds max_tx_inputs ({MAX_TX_INPUTS})",
                coins.len()
            ),
        ));
    }
    Ok(())
}

fn validate_output_templates(templates: &[OutputTemplate]) -> KernelResult<()> {
    if templates.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "output_templates must contain at least one template for this kind",
        ));
    }
    if templates.len() > MAX_TX_OUTPUTS {
        return Err(KernelError::new(
            KernelErrorCode::BoundsExceeded,
            format!(
                "output_templates length {} exceeds max_tx_outputs ({MAX_TX_OUTPUTS})",
                templates.len()
            ),
        ));
    }
    Ok(())
}

fn validate_fold_coin_ids(ids: &[Digest32]) -> KernelResult<()> {
    if ids.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "kind=receive requires fold_coin_ids with at least one coin identifier",
        ));
    }
    if ids.len() > MAX_RX_COINS {
        return Err(KernelError::new(
            KernelErrorCode::BoundsExceeded,
            format!(
                "fold_coin_ids length {} exceeds max_rx_coins ({MAX_RX_COINS})",
                ids.len()
            ),
        ));
    }
    Ok(())
}

/// Shared admit path: create (with body-aware idempotency) then, on a
/// fresh row, notify the dispatcher.
///
/// Used by normative [`submit_transition`] and by the legacy mint/send
/// HTTP handlers (which keep creator-signature validation outside).
///
/// # Ordering
///
/// 1. `JobStore::create` (generation lock + body compare in one tx)
/// 2. Project the row to a domain [`Job`] **before** any further fallible
///    work that could mask success on a replay / after irreversible admit
/// 3. On `Fresh` only: `job_tx.send` — if that fails, mark the row failed
///    from `queued` (CAS evaluated) and return `internal_error`
///
/// Replay never re-enqueues.
pub(crate) async fn admit_job(
    deps: AdmitJobDeps<'_>,
    kind: job_store::JobKind,
    account: &[u8; 32],
    idempotency_key: &str,
    request_body: serde_json::Value,
) -> Result<AdmitOutcome, AdmitError> {
    let AdmitJobDeps { store, job_tx } = deps;

    let create_result = match store
        .create(kind, account, Some(idempotency_key), request_body)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("JobStore::create failed in admit_job: {}", e);
            return Err(AdmitError::Domain(KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to admit job",
                e.to_string(),
            )));
        }
    };

    match create_result {
        CreateResult::IdempotencyConflict => Err(AdmitError::Domain(KernelError::new(
            KernelErrorCode::IdempotencyConflict,
            "Idempotency-Key was reused with a different request body",
        ))),
        CreateResult::IdempotentReplay(row) => Ok(AdmitOutcome::Replay(row)),
        CreateResult::Fresh(row) => {
            // A fresh `queued` row has no payload that can fail projection.
            // Enqueue next; if the channel is down, fail the row and surface
            // the error (same as the pre-split HTTP path).
            let public_id = row.public_id;
            if let Err(e) = job_tx.send(JobEnvelope { public_id }).await {
                tracing::error!("Job dispatcher channel send failed in admit_job: {}", e);
                match store
                    .fail(
                        public_id,
                        job_store::JobStatus::Queued,
                        "dispatcher unavailable",
                    )
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(
                            "admit_job enqueue-fail: fail(queued) matched 0 rows for job {} \
                             (concurrent advance); not inventing success",
                            public_id
                        );
                    }
                    Err(store_err) => {
                        tracing::error!(
                            "admit_job enqueue-fail: fail(queued) store error for job {}: {}",
                            public_id,
                            store_err
                        );
                    }
                }
                return Err(AdmitError::DispatcherUnavailable);
            }
            Ok(AdmitOutcome::Fresh(row))
        }
    }
}

/// Wire-edge §7.5 presence rule: every non-self mint/send output must carry
/// `delivery`. Runs **before** a job row exists; failure is
/// `malformed_request`. Self-output uses [`is_self_output`] (narrow: recipient
/// == subject == known owner **and** active operational bundle).
fn require_delivery_presence(
    command: &TransitionCommand,
    bundles: &BundleStore,
    subject_owner: Option<[u8; 32]>,
) -> KernelResult<()> {
    let (subject, templates) = match command {
        TransitionCommand::Mint {
            common,
            output_templates,
            ..
        }
        | TransitionCommand::Send {
            common,
            output_templates,
            ..
        } => (common.subject, output_templates.as_slice()),
        TransitionCommand::Receive { .. } => return Ok(()),
    };

    for (i, template) in templates.iter().enumerate() {
        if template.delivery.is_some() {
            continue;
        }
        if is_self_output(&template.recipient, &subject, subject_owner, bundles) {
            continue;
        }
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!(
                "output_templates[{i}].delivery is required for non-self outputs \
                 (kind ∈ {{send,mint}})"
            ),
        ));
    }
    Ok(())
}

/// `SubmitTransition` (§7.8): validate the closed command, admit, notify.
///
/// Mint, send, and receive share the admit path. Ordering:
/// 1. Shape / bounds ([`validate_transition_command`])
/// 2. §7.5 `delivery` presence ([`require_delivery_presence`] / [`is_self_output`])
///    — **before** a job row exists
/// 3. Both credential checklists + store fill
///    ([`check_and_store_delivery_credentials`]) — still before admit so
///    secrets never hit the job body; failures stay `malformed_request`
///    (no deferred delivery-time discovery). The filled
///    [`DeliveryTargetStore`] is what the prove/finalise mesh path reads.
/// 4. Admit + dispatcher handoff
///
/// A well-formed `kind=receive` creates a `jobs.kind = 'receive'` row and
/// enqueues the dispatcher. Clause-10 slot reconstitution and §2.3.3
/// prove/finalise remain on the dispatcher / `v1::receive` surface.
pub(crate) async fn submit_transition(
    deps: SubmitTransitionDeps<'_>,
    command: TransitionCommand,
) -> KernelResult<Job> {
    validate_transition_command(&command)?;

    // Wire-edge presence (kernel-only): missing delivery on a foreign output
    // never creates a job.
    require_delivery_presence(&command, deps.bundles, deps.subject_owner)?;

    // Credential checklists + verified store fill (kernel-only). Secrets are
    // discarded after a full pass; only {ivpk, op_pubkey, relays} (+ TTL)
    // remain for the prove/finalise delivery path.
    check_and_store_delivery_credentials(
        &command,
        &DeliveryCheckDeps {
            bundles: deps.bundles,
            delivery_targets: deps.delivery_targets,
            profile_high_water: deps.profile_high_water,
            subject_owner: deps.subject_owner,
            network: deps.network,
            clock: deps.clock,
        },
    )?;

    let common = command.common().clone();
    let account = common.subject.0;
    let idem_key = common.idempotency_key.as_str();

    let store_kind = match &command {
        TransitionCommand::Mint { .. } => job_store::JobKind::Mint,
        TransitionCommand::Send { .. } => job_store::JobKind::Send,
        TransitionCommand::Receive { .. } => job_store::JobKind::Receive,
    };
    let request_body = encode_normative_request_body(&command)?;

    let row = match admit_job(
        AdmitJobDeps {
            store: deps.store,
            job_tx: deps.job_tx,
        },
        store_kind,
        &account,
        idem_key,
        request_body,
    )
    .await
    {
        Ok(AdmitOutcome::Fresh(row) | AdmitOutcome::Replay(row)) => row,
        Err(e) => return Err(e.into_kernel_error()),
    };
    // Project only after admit+notify (or replay) so a projection failure
    // on a corrupt row is fail-closed — but a fresh queued admit always
    // projects. Replay of completed rows needs the stored response_body.
    project_job_row(&row)
}

/// Persistable JSON for a normative command (stable field set for
/// idempotency compares). Not the legacy mint/send DTO shape.
fn encode_normative_request_body(command: &TransitionCommand) -> KernelResult<serde_json::Value> {
    let common = command.common();
    let mut obj = serde_json::Map::new();
    obj.insert(
        "kind".to_string(),
        serde_json::Value::String(command.kind_str().to_string()),
    );
    obj.insert(
        "subject".to_string(),
        serde_json::Value::String(hex::encode(common.subject.0)),
    );
    obj.insert(
        "next_pubkey".to_string(),
        serde_json::Value::String(hex::encode(common.next_pubkey.0)),
    );
    obj.insert(
        "npk_rand".to_string(),
        serde_json::Value::String(hex::encode(common.npk_rand.0)),
    );
    match common.publisher {
        PublisherChoice::SelfPublish => {}
        PublisherChoice::FeeLessHandOff { publisher_pubkey } => {
            obj.insert(
                "publisher_pubkey".to_string(),
                serde_json::Value::String(hex::encode(publisher_pubkey.0)),
            );
        }
    }

    match command {
        TransitionCommand::Mint {
            issuance,
            output_templates,
            ..
        } => {
            obj.insert("issuance".to_string(), encode_issuance(issuance));
            obj.insert(
                "output_templates".to_string(),
                encode_output_templates(output_templates),
            );
        }
        TransitionCommand::Send {
            input_coins,
            output_templates,
            ..
        } => {
            obj.insert("input_coins".to_string(), encode_digest_list(input_coins));
            obj.insert(
                "output_templates".to_string(),
                encode_output_templates(output_templates),
            );
        }
        TransitionCommand::Receive { fold_coin_ids, .. } => {
            obj.insert(
                "fold_coin_ids".to_string(),
                encode_digest_list(fold_coin_ids),
            );
        }
    }

    Ok(serde_json::Value::Object(obj))
}

fn encode_issuance(issuance: &Issuance) -> serde_json::Value {
    match issuance {
        Issuance::V1 {
            name,
            decimals,
            amount,
            creator_pubkey,
        } => serde_json::json!({
            "name": name,
            "decimals": decimals,
            "issuance_version": 1u32,
            "amount": amount.to_string(),
            "creator_pubkey": hex::encode(creator_pubkey.0),
        }),
        Issuance::V2 {
            name,
            decimals,
            amount,
            cap_total,
            terms_salt,
            creator_pubkey,
        } => serde_json::json!({
            "name": name,
            "decimals": decimals,
            "issuance_version": 2u32,
            "amount": amount.to_string(),
            "cap_total": cap_total.to_string(),
            "terms_salt": hex::encode(terms_salt.0),
            "creator_pubkey": hex::encode(creator_pubkey.0),
        }),
    }
}

fn encode_output_templates(templates: &[OutputTemplate]) -> serde_json::Value {
    // Idempotency body: structural fields only. Delivery credentials are
    // **not** persisted here — after a successful checklist the store holds
    // only `{ivpk, op_pubkey, relays}` (+ TTL); `pk0` / `nk_commit` / `memo`
    // / signatures are discarded (§7.5 retention mandate).
    let items: Vec<serde_json::Value> = templates
        .iter()
        .map(|t| {
            serde_json::json!({
                "recipient": hex::encode(t.recipient.0),
                "asset_id": hex::encode(t.asset_id.0),
                "amount": t.amount.to_string(),
                "has_delivery": t.delivery.is_some(),
            })
        })
        .collect();
    serde_json::Value::Array(items)
}

fn encode_digest_list(ids: &[Digest32]) -> serde_json::Value {
    let items: Vec<serde_json::Value> = ids
        .iter()
        .map(|d| serde_json::Value::String(hex::encode(d.0)))
        .collect();
    serde_json::Value::Array(items)
}

/// Build a validated [`IdempotencyKey`] from a raw header/body string.
pub(crate) fn parse_idempotency_key(raw: &str) -> KernelResult<IdempotencyKey> {
    let key = IdempotencyKey::from_validated(raw.to_string());
    validate_idempotency_key(&key)?;
    Ok(key)
}

/// Test / caller helpers for constructing closed commands without
/// exposing open JSON builders in production paths.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use crate::kernel::types::{SubjectAddress, TransitionCommon, XOnlyKey};

    pub(crate) fn subject(seed: u8) -> SubjectAddress {
        SubjectAddress([seed; 32])
    }

    pub(crate) fn xonly(seed: u8) -> XOnlyKey {
        XOnlyKey([seed; 32])
    }

    pub(crate) fn digest(seed: u8) -> Digest32 {
        Digest32([seed; 32])
    }

    pub(crate) fn idem(key: &str) -> IdempotencyKey {
        IdempotencyKey::from_validated(key.to_string())
    }

    pub(crate) fn common_self(key: &str) -> TransitionCommon {
        TransitionCommon {
            subject: subject(0xA1),
            next_pubkey: xonly(0xB2),
            npk_rand: digest(0xC3),
            publisher: PublisherChoice::SelfPublish,
            idempotency_key: idem(key),
        }
    }

    /// Self-output template: recipient equals `common_self` subject `0xA1`.
    /// Delivery may be omitted when the test plants owner + active bundle.
    pub(crate) fn one_output() -> OutputTemplate {
        OutputTemplate {
            recipient: subject(0xA1),
            asset_id: digest(0xE5),
            amount: 1,
            delivery: None,
        }
    }

    /// Foreign (non-self) output without delivery — fails the presence rule.
    pub(crate) fn foreign_output() -> OutputTemplate {
        OutputTemplate {
            recipient: subject(0xD4),
            asset_id: digest(0xE5),
            amount: 1,
            delivery: None,
        }
    }

    pub(crate) fn mint_cmd(key: &str) -> TransitionCommand {
        TransitionCommand::Mint {
            common: common_self(key),
            issuance: Issuance::V1 {
                name: "tkn".to_string(),
                decimals: 8,
                amount: 100,
                creator_pubkey: xonly(0xD7),
            },
            output_templates: vec![one_output()],
        }
    }

    pub(crate) fn send_cmd(key: &str) -> TransitionCommand {
        TransitionCommand::Send {
            common: common_self(key),
            input_coins: vec![digest(0x11)],
            output_templates: vec![one_output()],
        }
    }

    pub(crate) fn receive_cmd(key: &str) -> TransitionCommand {
        TransitionCommand::Receive {
            common: common_self(key),
            fold_coin_ids: vec![digest(0x22)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::kernel::bootstrap::BundleStore;
    use crate::kernel::jobs::ProfileHighWaterStore;
    use crate::kernel::JobState;
    use crate::test_db::{setup_pool, SchemaScope};
    use crate::v1::DeliveryTargetStore;
    use shared::spec_v1::ManifestClock;
    use std::sync::Arc;

    async fn fresh_store() -> (Arc<JobStore>, SchemaScope) {
        let scope = setup_pool().await;
        (Arc::new(JobStore::new(scope.pool.clone())), scope)
    }

    fn plant_self_subject(bundles: &BundleStore) {
        use crate::kernel::bootstrap::OperationalBundle;
        let subj = subject(0xA1);
        let _ = bundles.install_for_test(
            &subj,
            OperationalBundle {
                ivk: [1; 32],
                ovk: [2; 32],
                op: [3; 32],
                nk: [4; 32],
                op_secret: [5; 32],
            },
        );
    }

    fn deps<'a>(
        store: &'a JobStore,
        job_tx: &'a mpsc::Sender<JobEnvelope>,
        bundles: &'a BundleStore,
        targets: &'a DeliveryTargetStore,
        hw: &'a ProfileHighWaterStore,
    ) -> SubmitTransitionDeps<'a> {
        SubmitTransitionDeps {
            store,
            job_tx,
            bundles,
            delivery_targets: targets,
            profile_high_water: hw,
            subject_owner: Some(subject(0xA1).0),
            network: crate::kernel::chain::KernelNetwork::Regtest,
            clock: ManifestClock::UnixSeconds(1_700_000_000),
        }
    }

    // ---- Presence / bounds matrix (unit; no store) ----

    #[test]
    fn mint_valid_ok() {
        validate_transition_command(&mint_cmd("k")).expect("mint ok");
    }

    #[test]
    fn send_valid_ok() {
        validate_transition_command(&send_cmd("k")).expect("send ok");
    }

    #[test]
    fn receive_valid_ok() {
        validate_transition_command(&receive_cmd("k")).expect("receive ok");
    }

    #[test]
    fn mint_empty_outputs_malformed() {
        let mut cmd = mint_cmd("k");
        if let TransitionCommand::Mint {
            output_templates, ..
        } = &mut cmd
        {
            output_templates.clear();
        }
        let err = validate_transition_command(&cmd).expect_err("empty outputs");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
    }

    #[test]
    fn mint_too_many_outputs_bounds() {
        let mut cmd = mint_cmd("k");
        if let TransitionCommand::Mint {
            output_templates, ..
        } = &mut cmd
        {
            *output_templates = (0..=MAX_TX_OUTPUTS).map(|_| one_output()).collect();
        }
        let err = validate_transition_command(&cmd).expect_err("too many outputs");
        assert_eq!(err.code, KernelErrorCode::BoundsExceeded);
    }

    #[test]
    fn mint_empty_issuance_name_malformed() {
        let mut cmd = mint_cmd("k");
        if let TransitionCommand::Mint { issuance, .. } = &mut cmd {
            *issuance = Issuance::V1 {
                name: String::new(),
                decimals: 8,
                amount: 1,
                creator_pubkey: xonly(0xD8),
            };
        }
        let err = validate_transition_command(&cmd).expect_err("empty name");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
    }

    #[test]
    fn mint_name_over_255_malformed() {
        let mut cmd = mint_cmd("k");
        if let TransitionCommand::Mint { issuance, .. } = &mut cmd {
            *issuance = Issuance::V1 {
                name: "x".repeat(MAX_ISSUANCE_NAME_BYTES + 1),
                decimals: 8,
                amount: 1,
                creator_pubkey: xonly(0xD9),
            };
        }
        let err = validate_transition_command(&cmd).expect_err("long name");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
    }

    #[test]
    fn send_empty_inputs_malformed() {
        let mut cmd = send_cmd("k");
        if let TransitionCommand::Send { input_coins, .. } = &mut cmd {
            input_coins.clear();
        }
        let err = validate_transition_command(&cmd).expect_err("empty inputs");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
    }

    #[test]
    fn send_too_many_inputs_bounds() {
        let mut cmd = send_cmd("k");
        if let TransitionCommand::Send { input_coins, .. } = &mut cmd {
            *input_coins = (0..=MAX_TX_INPUTS).map(|i| digest(i as u8)).collect();
        }
        let err = validate_transition_command(&cmd).expect_err("too many inputs");
        assert_eq!(err.code, KernelErrorCode::BoundsExceeded);
    }

    #[test]
    fn send_empty_outputs_malformed() {
        let mut cmd = send_cmd("k");
        if let TransitionCommand::Send {
            output_templates, ..
        } = &mut cmd
        {
            output_templates.clear();
        }
        let err = validate_transition_command(&cmd).expect_err("empty outs");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
    }

    #[test]
    fn send_too_many_outputs_bounds() {
        let mut cmd = send_cmd("k");
        if let TransitionCommand::Send {
            output_templates, ..
        } = &mut cmd
        {
            *output_templates = (0..=MAX_TX_OUTPUTS).map(|_| one_output()).collect();
        }
        let err = validate_transition_command(&cmd).expect_err("too many outs");
        assert_eq!(err.code, KernelErrorCode::BoundsExceeded);
    }

    #[test]
    fn receive_empty_fold_malformed() {
        let mut cmd = receive_cmd("k");
        if let TransitionCommand::Receive { fold_coin_ids, .. } = &mut cmd {
            fold_coin_ids.clear();
        }
        let err = validate_transition_command(&cmd).expect_err("empty fold");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
    }

    #[test]
    fn receive_too_many_fold_bounds() {
        let mut cmd = receive_cmd("k");
        if let TransitionCommand::Receive { fold_coin_ids, .. } = &mut cmd {
            *fold_coin_ids = (0..=MAX_RX_COINS).map(|i| digest(i as u8)).collect();
        }
        let err = validate_transition_command(&cmd).expect_err("too many fold");
        assert_eq!(err.code, KernelErrorCode::BoundsExceeded);
    }

    #[test]
    fn empty_idempotency_key_malformed() {
        let mut cmd = mint_cmd("");
        // fixtures allow empty string construction; validate must refuse.
        if let TransitionCommand::Mint { common, .. } = &mut cmd {
            common.idempotency_key = IdempotencyKey::from_validated(String::new());
        }
        let err = validate_transition_command(&cmd).expect_err("empty key");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
    }

    #[test]
    fn idempotency_key_over_64_malformed() {
        let long = "k".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1);
        let err = parse_idempotency_key(&long).expect_err("long key");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
    }

    // ---- Admit / idempotency (store; dispatcher is a channel drop) ----

    #[tokio::test]
    async fn submit_mint_fresh_then_same_body_replays() {
        let (store, _db) = fresh_store().await;
        let (tx, mut rx) = mpsc::channel::<JobEnvelope>(8);
        // Drain enqueue so the channel never fills.
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        let bundles = BundleStore::new();
        plant_self_subject(&bundles);
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let first = submit_transition(
            deps(store.as_ref(), &tx, &bundles, &targets, &hw),
            mint_cmd("idem-same"),
        )
        .await
        .expect("first");
        assert!(
            matches!(first.state, JobState::Accepted),
            "fresh mint is accepted, got {:?}",
            first.state
        );

        let second = submit_transition(
            deps(store.as_ref(), &tx, &bundles, &targets, &hw),
            mint_cmd("idem-same"),
        )
        .await
        .expect("replay");
        assert_eq!(second.id, first.id, "same key + same body → same job");
    }

    #[tokio::test]
    async fn submit_mint_same_key_different_body_is_idempotency_conflict() {
        let (store, _db) = fresh_store().await;
        let (tx, mut rx) = mpsc::channel::<JobEnvelope>(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        let bundles = BundleStore::new();
        plant_self_subject(&bundles);
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        submit_transition(
            deps(store.as_ref(), &tx, &bundles, &targets, &hw),
            mint_cmd("idem-diff"),
        )
        .await
        .expect("first");

        let mut other = mint_cmd("idem-diff");
        if let TransitionCommand::Mint { issuance, .. } = &mut other {
            *issuance = Issuance::V1 {
                name: "other".to_string(),
                decimals: 8,
                amount: 999,
                creator_pubkey: xonly(0xDA),
            };
        }
        let err = submit_transition(deps(store.as_ref(), &tx, &bundles, &targets, &hw), other)
            .await
            .expect_err("conflict");
        assert_eq!(
            err.code,
            KernelErrorCode::IdempotencyConflict,
            "cause must be idempotency_conflict, got {}",
            err.public_message
        );
    }

    #[tokio::test]
    async fn admit_ignores_stripped_finalisation_keys_on_replay() {
        // Same key after cancel stripped server keys must still replay
        // when the client body is unchanged — not false-conflict.
        let (store, _db) = fresh_store().await;
        let (tx, mut rx) = mpsc::channel::<JobEnvelope>(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        let body = serde_json::json!({
            "name": "tkn",
            "amount": 1u64,
            "decimals": 8,
        });
        let account = [0x77u8; 32];
        let key = "k-strip";

        let first = admit_job(
            AdmitJobDeps {
                store: store.as_ref(),
                job_tx: &tx,
            },
            job_store::JobKind::Mint,
            &account,
            key,
            body.clone(),
        )
        .await
        .expect("first");
        let AdmitOutcome::Fresh(job) = first else {
            panic!("expected Fresh");
        };
        let job_id = job.public_id;

        // Simulate post-admit server keys, then cancel strip.
        let mut with_server = body.clone();
        with_server.as_object_mut().expect("obj").insert(
            "finalisation".to_string(),
            serde_json::json!({"capability_bincode_hex": "dead"}),
        );
        with_server.as_object_mut().expect("obj").insert(
            "finalise_claim".to_string(),
            serde_json::json!({"owner": "x", "fence": 1}),
        );
        store
            .replace_request_body_if_status(job_id, job_store::JobStatus::Queued, &with_server)
            .await
            .expect("merge server keys");
        let cancelled = store.cancel(job_id).await.expect("cancel");
        assert!(cancelled, "cancel must hit queued row");

        let row = store.load(job_id).await.expect("load").expect("row");
        assert!(
            row.request_body.get("finalisation").is_none(),
            "cancel strips finalisation"
        );

        let second = admit_job(
            AdmitJobDeps {
                store: store.as_ref(),
                job_tx: &tx,
            },
            job_store::JobKind::Mint,
            &account,
            key,
            body,
        )
        .await
        .expect("replay after strip must not conflict");
        match second {
            AdmitOutcome::Replay(j) => assert_eq!(j.public_id, job_id),
            AdmitOutcome::Fresh(_) => panic!("must be Replay of the cancelled job, not Fresh"),
        }
    }

    /// A well-formed `kind=receive` must admit a job row (Accepted) and
    /// persist `jobs.kind = receive` — the property that was blocked when
    /// admission refused the kind outright.
    #[tokio::test]
    async fn submit_receive_admits_job_with_receive_kind() {
        let (store, _db) = fresh_store().await;
        let (tx, mut rx) = mpsc::channel::<JobEnvelope>(8);
        // Drain enqueue so the channel never fills; this test is admit-only.
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let job = submit_transition(
            deps(store.as_ref(), &tx, &bundles, &targets, &hw),
            receive_cmd("k-rx"),
        )
        .await
        .expect("valid receive must admit");
        assert!(
            matches!(job.state, JobState::Accepted),
            "fresh receive is accepted, got {:?}",
            job.state
        );
        assert_eq!(
            job.kind.as_str(),
            "receive",
            "projected kind must be the wire string receive"
        );

        let row = store
            .load(job.id.as_uuid())
            .await
            .expect("load")
            .expect("row after admit");
        assert_eq!(
            row.kind,
            job_store::JobKind::Receive,
            "store kind must be receive"
        );
        assert_eq!(
            row.request_body.get("kind").and_then(|v| v.as_str()),
            Some("receive"),
            "persisted body must echo kind=receive"
        );
        let folds = row
            .request_body
            .get("fold_coin_ids")
            .and_then(|v| v.as_array())
            .expect("fold_coin_ids array");
        assert_eq!(
            folds.len(),
            1,
            "fold_coin_ids from the command must survive encode"
        );
        assert_eq!(
            folds[0].as_str().expect("hex"),
            hex::encode(digest(0x22).0),
            "fold id must be the submitted coin identifier"
        );
    }

    /// Same-key / same-body receive replay returns the original job id.
    #[tokio::test]
    async fn submit_receive_same_body_replays() {
        let (store, _db) = fresh_store().await;
        let (tx, mut rx) = mpsc::channel::<JobEnvelope>(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let first = submit_transition(
            deps(store.as_ref(), &tx, &bundles, &targets, &hw),
            receive_cmd("idem-rx"),
        )
        .await
        .expect("first");
        let second = submit_transition(
            deps(store.as_ref(), &tx, &bundles, &targets, &hw),
            receive_cmd("idem-rx"),
        )
        .await
        .expect("replay");
        assert_eq!(second.id, first.id, "same key + same body → same job");
    }

    /// Full `submit_transition` path (not a direct unit call of the check
    /// helpers): missing `delivery` on a foreign output is rejected at the
    /// wire edge with `malformed_request` and **no** job row is created.
    ///
    /// This is the wiring witness — if presence is only unit-tested on the
    /// helper, a Submit in production could still skip the chain.
    #[tokio::test]
    async fn missing_delivery_on_foreign_output_no_job() {
        let (store, _db) = fresh_store().await;
        let (tx, mut rx) = mpsc::channel::<JobEnvelope>(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        let bundles = BundleStore::new();
        plant_self_subject(&bundles);
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let mut cmd = send_cmd("no-del");
        if let TransitionCommand::Send {
            output_templates, ..
        } = &mut cmd
        {
            *output_templates = vec![foreign_output()];
        }
        let err = submit_transition(deps(store.as_ref(), &tx, &bundles, &targets, &hw), cmd)
            .await
            .expect_err("foreign without delivery");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("delivery is required"),
            "{}",
            err.public_message
        );
        // Presence fails before admit: store must be empty for this subject.
        let account = subject(0xA1).0;
        let rows: (i64,) =
            sqlx::query_as("SELECT COUNT(*)::bigint FROM jobs WHERE account_address = $1")
                .bind(&account[..])
                .fetch_one(store.pool())
                .await
                .expect("count jobs");
        assert_eq!(rows.0, 0, "presence failure must not create a job row");
        assert!(
            targets.get(&subject(0xD4).0).is_none(),
            "target store stays empty when presence fails before checklist"
        );
    }

    #[test]
    fn job_kind_receive_as_str_from_db_str_round_trip() {
        // Mirrors `job_store_tests::job_kind_round_trip_covers_all_variants`
        // for the new variant (that list lives outside this workspace).
        let k = job_store::JobKind::Receive;
        assert_eq!(k.as_str(), "receive");
        assert_eq!(job_store::JobKind::from_db_str(k.as_str()), Some(k));
        assert_eq!(job_store::JobKind::from_db_str("receive"), Some(k));
    }

    #[tokio::test]
    async fn store_create_same_key_different_body_is_conflict_variant() {
        let (store, _db) = fresh_store().await;
        let account = [0x42u8; 32];
        let a = serde_json::json!({"amount": 1});
        let b = serde_json::json!({"amount": 2});
        match store
            .create(job_store::JobKind::Mint, &account, Some("k-c"), a)
            .await
            .expect("first")
        {
            CreateResult::Fresh(_) => {}
            other => panic!("expected Fresh, got {other:?}"),
        }
        match store
            .create(job_store::JobKind::Mint, &account, Some("k-c"), b)
            .await
            .expect("second")
        {
            CreateResult::IdempotencyConflict => {}
            other => panic!("expected IdempotencyConflict, got {other:?}"),
        }
    }
}
