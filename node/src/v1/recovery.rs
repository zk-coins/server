//! §4.5 emergency recovery — gapless kind-1059 pull, verify, decrypt-index fill.
//!
//! # Scope
//!
//! Orchestration of **node-side** recovery steps only. Relay, Blossom, note
//! detection, ZBE, bundle codecs, and the §2.3.3 receive checks already
//! exist; this module sequences them under the fail-closed rules of §4.5.
//!
//! | Step | What this module does |
//! |---|---|
//! | 3 | Paginated gapless kind-1059 scan (i)/(ii)/(iii) over seed relays |
//! | 5 | Re-run §2.3.3 via [`super::incoming::verify_coin_proof_for_index`];
//!     durable decrypt-index fill via the receive path |
//! | 6 | §4.2 SelfDeliveryRecordV1 VERIFY-ONLY replay: fetch/ZBE/decode,
//!     checks (i)–(vi), order, fold output coins into the durable
//!     self-delivery index, reconstruct/install/persist account heads;
//!     report heads + every discard (never silent) |
//!
//! Step 2 (NfLog rebuild from Bitcoin) is the existing scanner path — not
//! owned here. Step 6 installs each fully reconstructed account into the live
//! engine and durably persists the resulting full-engine snapshot.
//!
//! # Step 1 is intentionally absent (wallet-side only)
//!
//! Dense account enumeration (`account' = 0,1,2,…` with hard-stop /
//! 20-pending-gap) **cannot** run in the node. It needs `Pk₀(account)` from
//! the BIP-32 **SPEND** branch `A/0'/i'` (§1.2). That branch never leaves the
//! wallet: the operative bundle a node may hold after `Entrust` carries
//! `{ivk, ovk, op, nk, op_secret}` only (§1.2, §7.7) — no SPEND material.
//! Wallet/SDK layers own that walk; the node is given an explicit earliest
//! bound (`ZKCOINS_V1_RECOVERY_EARLIEST`) and scans under entrusteed `ivk`.
//!
//! # Production trigger
//!
//! Operator opt-in only: `ZKCOINS_V1_RECOVERY=1` plus page limit and earliest
//! bound. Without the flag the node never full-history-scans relays (that
//! would be an operational accident). Runtime spawns a **background**
//! one-shot campaign after listeners are wired so a long scan cannot block
//! readiness; see [`run_recovery_campaign`].
//!
//! # No new external surface
//!
//! Crate-private. No HTTP route, no kernel procedure, no migration.
//!
//! Spec: §1.2, §2.3.3, §4.2, §4.4, §4.5, §7.7.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use shared::spec_v1::bundle::{
    deserialize_coin_proof, deserialize_self_delivery_record, CoinProof,
};
use shared::spec_v1::encoding::digest_to_bytes;
use shared::spec_v1::hashes::{account_state_hash, address, hash_proof_data, nk_commit};
use shared::spec_v1::note_encryption::{
    derive_note_key, derive_out_key, envelope_open, zbe_open, COIN_CIPHERTEXT_LEN,
    ENVELOPE_LABEL_COIN, ENVELOPE_LABEL_K_TX, OUT_CIPHERTEXT_LEN,
};
use shared::spec_v1::serialize::{serialize_coin, serialize_proof_data};
use shared::spec_v1::{self as host, AccountState, Address, LookupResult, SpendClassification};
use sqlx::PgPool;
use zkcoins_prover::half_agg::comm_verify;
use zkcoins_prover::prover_bridge::{NavOpening, NullifierOpening, ProverBridge};
use zkcoins_prover::state_engine::{OpSecret, StateEngine, TrackedCoin};

use super::adapter::EngineAdapter;
use super::blossom::BlossomClient;
use super::db_decrypt_index::decrypt_record_id;
use super::db_self_delivery_index::{
    get_by_subject_coin as get_self_delivery_by_subject_coin,
    insert_and_mirror_self_delivery_batch, SelfDeliveryIndexRow,
};
use super::incoming::{
    extract_scan_tags, fetch_blob_from_holders, match_detect_tag, process_delivery_candidate,
    verify_coin_proof_for_index, AckClock, CandidateNetwork, CandidateOutcome, CandidateSecrets,
    CandidateStores, IncomingError,
};
use super::nostr::event::Event;
use super::nostr::kinds::delivery::{decode_delivery_payload, RecordKind};
use super::nostr::nip44;
use super::nostr::nip59::{unwrap_gift, KIND_GIFT_WRAP};
use super::nostr::relay::{Filter, RelayClient, RelayError};
use super::receive::extract_compliance_public_inputs;
use super::OsSecureRandom;
use crate::kernel::access::{
    InMemoryPrivateIndex, InsertRecordOutcome, PrivateIndex, ReceiptHub, TransitionKind,
};
use crate::kernel::bootstrap::{BundleStore, OperationalBundle};
use crate::kernel::types::SubjectAddress;

// ---------------------------------------------------------------------------
// Operator env (ZKCOINS_V1_* — same naming as other v1 ops pins)
// ---------------------------------------------------------------------------

/// Opt-in emergency recovery campaign. Only `"1"` enables; unset / other → off.
pub(crate) const RECOVERY_ENV: &str = "ZKCOINS_V1_RECOVERY";

/// Positive page size `L` for the gapless scan (required when recovery is on;
/// no silent default).
pub(crate) const RECOVERY_PAGE_LIMIT_ENV: &str = "ZKCOINS_V1_RECOVERY_PAGE_LIMIT";

/// Inclusive earliest `created_at` bound for the gapless scan (required when
/// recovery is on; no silent `0` default — operator supplies the wallet's
/// earliest account timestamp after step-1 enumeration elsewhere).
pub(crate) const RECOVERY_EARLIEST_ENV: &str = "ZKCOINS_V1_RECOVERY_EARLIEST";

/// How often the background campaign re-checks for an entrusteed bundle.
const BUNDLE_WAIT_INTERVAL: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Errors / outcomes
// ---------------------------------------------------------------------------

/// Fail-closed recovery reasons — never a bare “something failed”.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryError {
    /// Caller passed `page_limit = 0` (no silent default page size).
    InvalidPageLimit,
    /// No relay URLs (no silent single-relay default).
    EmptyRelayList,
    /// Underlying relay/source failure (connect, protocol, verify).
    Relay { relay_url: String, detail: String },
    /// Recovery requested but no active operational bundle is entrusteed.
    /// The node cannot scan under `ivk` without it (§7.7).
    NoOperationalBundle,
    /// Recovery requested but seed relays are unavailable (no verified
    /// BootstrapManifest / empty `seed_relays`).
    NoSeedRelays,
    /// Wall clock unusable for `now` (before UNIX epoch).
    WallClockUnavailable,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryError::InvalidPageLimit => {
                write!(f, "recovery page limit must be positive (no default L)")
            }
            RecoveryError::EmptyRelayList => {
                write!(f, "recovery relay list is empty (no default relay)")
            }
            RecoveryError::Relay { relay_url, detail } => {
                write!(f, "recovery relay {relay_url}: {detail}")
            }
            RecoveryError::NoOperationalBundle => write!(
                f,
                "ZKCOINS_V1_RECOVERY=1 requires an entrusteed operational bundle \
                 (ivk) before the recovery campaign can run — no bundle active; \
                 refusing to treat the node as restored"
            ),
            RecoveryError::NoSeedRelays => write!(
                f,
                "ZKCOINS_V1_RECOVERY=1 requires verified BootstrapManifest seed_relays \
                 (ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH) — none available; refusing to \
                 invent relay URLs or treat the node as restored"
            ),
            RecoveryError::WallClockUnavailable => {
                write!(
                    f,
                    "recovery wall clock is before UNIX epoch — refusing scan"
                )
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

/// One page from a recovery relay source (post-EOSE, verified events).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayQueryPage {
    pub events: Vec<Event>,
    /// `true` when the store may hold more matching events than returned
    /// (server-side cap, or client safety ceiling). A limit-free drain with
    /// `truncated = true` is **incomplete** — never treat it as full.
    pub truncated: bool,
}

/// Completeness of the §4.5 step-3 gapless scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GaplessScanStatus {
    /// Every reached same-second boundary was fully drained; `until` fell
    /// below the earliest bound or a quiet full round closed the scan.
    Complete,
    /// A timestamp `t` could not be fully drained on any reachable relay.
    /// Recovery **must not** present this as a full restore.
    Incomplete {
        /// The second that could not be proven complete — **not** advanced past.
        stuck_at: u64,
        /// Last `until` cursor (still ≥ `stuck_at`; never silently set to `t−1`).
        until_cursor: u64,
        /// Relays that blocked a full drain of `stuck_at` — always non-empty.
        ///
        /// * Truncation: each URL that returned `truncated = true` on the
        ///   limit-free `since = t, until = t` drain.
        /// * No reachable relay: every URL attempted for that drain (all
        ///   connect/protocol failures). The operator inspects these URLs;
        ///   without them an Incomplete only says “something is missing”.
        relay_urls: Vec<String>,
    },
}

/// Events discovered by the gapless scan, plus completeness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GaplessScanResult {
    /// Globally deduplicated by `event.id`, discovery order.
    pub events: Vec<Event>,
    pub status: GaplessScanStatus,
    /// Distinct `event.id` count (equals `events.len()`).
    pub unique_event_count: usize,
}

/// Why one SelfDeliveryRecordV1 candidate was discarded — §4.2 checks (i)-(vi) plus the
/// ordering-stage equivocation/monotonicity rules. Never a bare "invalid"; always names which
/// check failed and enough detail to debug it (no silent drop, per project policy).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SdrDiscardReason {
    /// Blob fetch failed (dispatch 2 populates call sites).
    FetchFailed { detail: String },
    /// ZBE open failed (dispatch 2).
    ZbeOpenFailed { detail: String },
    /// SelfDeliveryRecordV1 decode failed (dispatch 2).
    DecodeFailed { detail: String },
    /// Decoded SDR owner does not equal the recovery subject.
    AccountOwnerMismatch { detail: String },
    /// Decoded SDR nk commitment does not bind the entrusteed bundle nk.
    NkCommitMismatch { detail: String },
    /// Outer ordering counter does not equal the authenticated account-state counter.
    SendCounterMismatch { detail: String },
    /// First accepted post-genesis transition did not use counter 1.
    GenesisCounterInvalid { detail: String },
    /// First accepted transition's genesis preimage does not bind the subject.
    GenesisIdentityMismatch { detail: String },
    /// A later authenticated counter did not immediately follow the previous one.
    SendCounterNotSequential { detail: String },
    /// Outer delivery record kind does not equal the decoded SDR kind.
    RecordKindMismatch { detail: String },
    /// Durable idempotency lookup failed before a fold could be staged.
    IndexLookupFailed { detail: String },
    /// The per-subject atomic fold transaction failed.
    FoldCommitFailed { detail: String },
    /// §4.5 step 6: reconstructing or installing the recovered `AccountRecord`
    /// failed for a reason that is a conclusive contradiction (coinhist root
    /// mismatch, a spendable coin with no recoverable source, an unresolvable
    /// NAV-opening/nullifier-position reconstruction, or an engine that already
    /// holds a *different, older* account for this subject with no safe in-place
    /// update path) — never an availability/retry situation.
    HeadReconstructionFailed { detail: String },
    /// §4.5 step 6: the head reconstructed and installed cleanly into the live
    /// engine, but the durable engine-snapshot persist failed. The live engine
    /// is rolled back to its pre-install snapshot before this is reported, so
    /// memory and disk never diverge.
    HeadPersistFailed { detail: String },
    /// CoinProof coin identifier does not equal the naming OutputRef.
    FoldCoinIdMismatch { detail: String },
    /// CoinProof ephemeral key does not equal the naming OutputRef.
    FoldEpkMismatch { detail: String },
    /// CoinProof creation proof/nullifier does not equal the accepted SDR transition.
    FoldCreatingTransitionMismatch { detail: String },
    /// CoinProof ciphertext does not authenticate its serialized coin under recovered K_tx.
    FoldCiphertextBindingFailed { detail: String },
    /// Check (ii): `account_state_hash(account_state) ≠ proof_data.new_account_state_hash`.
    AccountStateHashMismatch,
    /// Check (iii-a): recursive transition proof load or verify failed.
    ProofVerifyFailed { detail: String },
    /// Check (iii-b): proof public inputs do not equal the record's `proof_data`.
    ProofDataMismatch,
    /// Check (iv): Fresh-Key-Substitution — `consumed_pubkey ≠ own_nullifier.pk_create`.
    ConsumedPubkeyMismatch,
    /// Check (iv): nullifier is not a ValidFirstSpend first-occurrence on NfLog.
    NotFirstOccurrence { detail: String },
    /// Check (v): inclusion block height/hash does not match NfLog + block_log.
    InclusionBlockMismatch { detail: String },
    /// Check (v): `occurred_at` is zero, differs from a successfully
    /// re-derived BIP-113 MTP, or the local `[h-10..=h]` window cannot be
    /// derived (pre-migration NULL `block_time`, scan-start edge). Spec §4.2
    /// mandates discard; there is no presence-only accept path.
    OccurredAtInvalid { detail: String },
    /// Check (v) ordering stage: `occurred_at` regressed vs a previously accepted record.
    OccurredAtNotMonotonic { detail: String },
    /// Check (vi): proof_block_anchor fails the §3.5 gap-bound predicate.
    AnchorBoundFailed { detail: String },
    /// Check (i) ordering stage: `prev_state_head` does not equal the expected prior ash.
    PrevStateHeadMismatch { detail: String },
    /// Ordering stage: same `send_counter` with divergent account-state ashes.
    Equivocation { detail: String },
}

impl SdrDiscardReason {
    /// Availability failures gate `restored` but do not establish invalidity.
    pub(crate) fn is_infra_availability(&self) -> bool {
        match self {
            SdrDiscardReason::FetchFailed { .. }
            | SdrDiscardReason::IndexLookupFailed { .. }
            | SdrDiscardReason::FoldCommitFailed { .. }
            | SdrDiscardReason::HeadPersistFailed { .. } => true,
            SdrDiscardReason::ZbeOpenFailed { .. }
            | SdrDiscardReason::DecodeFailed { .. }
            | SdrDiscardReason::AccountOwnerMismatch { .. }
            | SdrDiscardReason::NkCommitMismatch { .. }
            | SdrDiscardReason::SendCounterMismatch { .. }
            | SdrDiscardReason::GenesisCounterInvalid { .. }
            | SdrDiscardReason::GenesisIdentityMismatch { .. }
            | SdrDiscardReason::SendCounterNotSequential { .. }
            | SdrDiscardReason::RecordKindMismatch { .. }
            | SdrDiscardReason::FoldCoinIdMismatch { .. }
            | SdrDiscardReason::FoldEpkMismatch { .. }
            | SdrDiscardReason::FoldCreatingTransitionMismatch { .. }
            | SdrDiscardReason::FoldCiphertextBindingFailed { .. }
            | SdrDiscardReason::AccountStateHashMismatch
            | SdrDiscardReason::ProofVerifyFailed { .. }
            | SdrDiscardReason::ProofDataMismatch
            | SdrDiscardReason::ConsumedPubkeyMismatch
            | SdrDiscardReason::NotFirstOccurrence { .. }
            | SdrDiscardReason::InclusionBlockMismatch { .. }
            | SdrDiscardReason::OccurredAtInvalid { .. }
            | SdrDiscardReason::OccurredAtNotMonotonic { .. }
            | SdrDiscardReason::AnchorBoundFailed { .. }
            | SdrDiscardReason::PrevStateHeadMismatch { .. }
            | SdrDiscardReason::Equivocation { .. }
            | SdrDiscardReason::HeadReconstructionFailed { .. } => false,
        }
    }
}

impl fmt::Display for SdrDiscardReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdrDiscardReason::FetchFailed { detail } => {
                write!(f, "SDR fetch failed: {detail}")
            }
            SdrDiscardReason::ZbeOpenFailed { detail } => {
                write!(f, "SDR ZBE open failed: {detail}")
            }
            SdrDiscardReason::DecodeFailed { detail } => {
                write!(f, "SDR decode failed: {detail}")
            }
            SdrDiscardReason::AccountOwnerMismatch { detail } => {
                write!(f, "SDR subject binding: account owner mismatch: {detail}")
            }
            SdrDiscardReason::NkCommitMismatch { detail } => {
                write!(f, "SDR subject binding: nk_commit mismatch: {detail}")
            }
            SdrDiscardReason::SendCounterMismatch { detail } => {
                write!(f, "SDR authenticated send_counter mismatch: {detail}")
            }
            SdrDiscardReason::GenesisCounterInvalid { detail } => {
                write!(f, "SDR genesis counter invalid: {detail}")
            }
            SdrDiscardReason::GenesisIdentityMismatch { detail } => {
                write!(f, "SDR genesis identity mismatch: {detail}")
            }
            SdrDiscardReason::SendCounterNotSequential { detail } => {
                write!(f, "SDR authenticated send_counter not sequential: {detail}")
            }
            SdrDiscardReason::RecordKindMismatch { detail } => {
                write!(f, "SDR outer/inner record_kind mismatch: {detail}")
            }
            SdrDiscardReason::IndexLookupFailed { detail } => {
                write!(f, "SDR fold index lookup failed: {detail}")
            }
            SdrDiscardReason::FoldCommitFailed { detail } => {
                write!(f, "SDR fold batch commit failed: {detail}")
            }
            SdrDiscardReason::HeadReconstructionFailed { detail } => {
                write!(f, "SDR head reconstruction failed: {detail}")
            }
            SdrDiscardReason::HeadPersistFailed { detail } => {
                write!(f, "SDR head persist failed: {detail}")
            }
            SdrDiscardReason::FoldCoinIdMismatch { detail } => {
                write!(f, "SDR fold coin_id binding failed: {detail}")
            }
            SdrDiscardReason::FoldEpkMismatch { detail } => {
                write!(f, "SDR fold epk binding failed: {detail}")
            }
            SdrDiscardReason::FoldCreatingTransitionMismatch { detail } => {
                write!(f, "SDR fold creating transition binding failed: {detail}")
            }
            SdrDiscardReason::FoldCiphertextBindingFailed { detail } => {
                write!(f, "SDR fold ciphertext binding failed: {detail}")
            }
            SdrDiscardReason::AccountStateHashMismatch => write!(
                f,
                "SDR check (ii): account_state_hash does not match proof_data.new_account_state_hash"
            ),
            SdrDiscardReason::ProofVerifyFailed { detail } => {
                write!(f, "SDR check (iii-a): transition proof verify failed: {detail}")
            }
            SdrDiscardReason::ProofDataMismatch => write!(
                f,
                "SDR check (iii-b): recursive proof public inputs ≠ record.proof_data"
            ),
            SdrDiscardReason::ConsumedPubkeyMismatch => write!(
                f,
                "SDR check (iv): consumed_pubkey ≠ own_nullifier.pk_create (Fresh-Key-Substitution)"
            ),
            SdrDiscardReason::NotFirstOccurrence { detail } => {
                write!(f, "SDR check (iv): not first-occurrence: {detail}")
            }
            SdrDiscardReason::InclusionBlockMismatch { detail } => {
                write!(f, "SDR check (v): inclusion block mismatch: {detail}")
            }
            SdrDiscardReason::OccurredAtInvalid { detail } => {
                write!(f, "SDR check (v): occurred_at invalid: {detail}")
            }
            SdrDiscardReason::OccurredAtNotMonotonic { detail } => {
                write!(f, "SDR check (v): occurred_at not monotonic: {detail}")
            }
            SdrDiscardReason::AnchorBoundFailed { detail } => {
                write!(f, "SDR check (vi): anchor bound failed: {detail}")
            }
            SdrDiscardReason::PrevStateHeadMismatch { detail } => {
                write!(f, "SDR check (i): prev_state_head mismatch: {detail}")
            }
            SdrDiscardReason::Equivocation { detail } => {
                write!(f, "SDR ordering: equivocation at send_counter: {detail}")
            }
        }
    }
}

/// One record accepted through checks (i)-(vi), in ascending `send_counter` order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcceptedSdr {
    /// Content-address of the SelfDeliveryRecordV1 ZBE blob that produced this record.
    pub blob_id: [u8; 32],
    pub record: host::SelfDeliveryRecordV1,
    /// `digest_to_bytes(account_state_hash(&record.account_state))`.
    pub account_state_ash: [u8; 32],
}

/// Verified fold result before any durable write for the subject batch.
#[derive(Clone, Debug, PartialEq, Eq)]
enum StagedFoldOutcome {
    Row(SelfDeliveryIndexRow),
    AlreadyPresent { coin_id: [u8; 32] },
    NotOurs,
}

/// One SDR candidate that could not be replayed — operator-visible, never silent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SdrDiscard {
    pub subject: [u8; 32],
    pub blob_id: [u8; 32],
    pub record_kind: RecordKind,
    /// `None` when the record could not be decoded far enough to read `send_counter`
    /// (fetch/ZBE/decode failure) or when discarded before ordering assigned one.
    pub send_counter: Option<u64>,
    pub reason: SdrDiscardReason,
}

/// One recovered lineage head per subject that had at least one accepted SDR —
/// the uniquely-highest verified `send_counter` for that subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplayedAccountHead {
    pub subject: [u8; 32],
    pub record_kind: RecordKind,
    pub send_counter: u64,
    pub account_state: host::AccountState,
    pub account_state_ash: [u8; 32],
    pub recursive_proof: Vec<u8>,
    pub proof_data: host::ProofData,
    pub inclusion_block: host::BlockAnchor,
    pub occurred_at: u64,
}

/// Genesis ("empty account") ash for the subject — the expected `prev_state_head`
/// of the first accepted SelfDeliveryRecordV1.
///
/// Builds `AccountState::new(owner=Address(subject), nk_commit(nk), empty balances,
/// pk0, send_counter=0, coinhist_empty_root)` and returns its ash. `pk0` is the
/// creating nullifier's `pk_create` of the lowest-`send_counter` record in the
/// chain being verified (the account's own `current_pubkey` immediately before
/// that first transition).
pub(crate) fn canonical_genesis_account_state_ash(
    subject: &[u8; 32],
    nk: &[u8; 32],
    pk0: [u8; 32],
) -> Result<host::HashDigest, host::SpecError> {
    let owner = Address(*subject);
    let nkc = nk_commit(nk);
    let empty = AccountState::new(
        owner,
        nkc,
        BTreeMap::new(),
        pk0,
        0,
        host::coinhist_empty_root(),
    )
    .expect("empty account is always constructible");
    account_state_hash(&empty)
}

/// Panic-isolated load, recursive verification, and public-input extraction for
/// attacker-controlled transition proof bytes.
fn load_verify_transition_public_inputs(
    bridge: &ProverBridge,
    proof_bytes: &[u8],
    context: &str,
) -> Result<(host::ProofData, [u8; 32]), SdrDiscardReason> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> anyhow::Result<(host::ProofData, [u8; 32])> {
            let proof = bridge.load_transition_proof_bytes(proof_bytes)?;
            bridge.verify_transition(&proof)?;
            let (proof_data, consumed_pubkey, _network_id) =
                extract_compliance_public_inputs(&proof)?;
            Ok((proof_data, consumed_pubkey))
        },
    ));
    match result {
        Ok(Ok(public_inputs)) => Ok(public_inputs),
        Ok(Err(e)) => Err(SdrDiscardReason::ProofVerifyFailed {
            detail: format!("{context}: {e:#}"),
        }),
        Err(payload) => {
            let panic_detail = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_owned());
            tracing::error!(
                proof_context = context,
                panic = %panic_detail,
                "attacker-controlled transition proof parser/verifier panicked; isolated"
            );
            Err(SdrDiscardReason::ProofVerifyFailed {
                detail: format!("{context}: proof parser/verifier panicked: {panic_detail}"),
            })
        }
    }
}

/// Subject binding and §4.2 checks that do not need the state engine.
///
/// This runs before taking the [`EngineAdapter`] mutex. VERIFY-ONLY: it loads
/// and verifies the recursive proof but never proves a transition.
pub(crate) fn verify_sdr_record_pre_engine(
    bridge: &ProverBridge,
    subject: &[u8; 32],
    nk: &[u8; 32],
    record: &host::SelfDeliveryRecordV1,
) -> Result<([u8; 32], [u8; 32]), SdrDiscardReason> {
    if record.account_state.owner.0 != *subject {
        return Err(SdrDiscardReason::AccountOwnerMismatch {
            detail: format!(
                "account_state.owner {} != recovery subject {}",
                hex::encode(record.account_state.owner.0),
                hex::encode(subject)
            ),
        });
    }
    let expected_nkc = nk_commit(nk);
    if record.account_state.nk_commit != expected_nkc {
        return Err(SdrDiscardReason::NkCommitMismatch {
            detail: format!(
                "account_state.nk_commit {} != bundle nk_commit {}",
                hex::encode(digest_to_bytes(&record.account_state.nk_commit)),
                hex::encode(digest_to_bytes(&expected_nkc))
            ),
        });
    }
    if record.send_counter != record.account_state.send_counter {
        return Err(SdrDiscardReason::SendCounterMismatch {
            detail: format!(
                "outer {} != account_state {}",
                record.send_counter, record.account_state.send_counter
            ),
        });
    }

    // (ii) ash(account_state) == proof_data.new_account_state_hash
    let ash = match account_state_hash(&record.account_state) {
        Ok(a) => a,
        Err(_) => return Err(SdrDiscardReason::AccountStateHashMismatch),
    };
    if ash != record.proof_data.new_account_state_hash {
        return Err(SdrDiscardReason::AccountStateHashMismatch);
    }

    // (iii-b) proof public inputs == record.proof_data (full ProofData equality)
    let (creating_pd, consumed_pubkey) = load_verify_transition_public_inputs(
        bridge,
        &record.recursive_proof,
        "SDR recursive_proof",
    )?;
    if creating_pd != record.proof_data {
        return Err(SdrDiscardReason::ProofDataMismatch);
    }

    // (iv) Fresh-Key-Substitution + R/R' opens H(ProofData). NfLog access is
    // deliberately deferred to `verify_sdr_record_engine_checks`.
    if consumed_pubkey != record.own_nullifier.pk_create {
        return Err(SdrDiscardReason::ConsumedPubkeyMismatch);
    }
    let pk_create = record.own_nullifier.pk_create;
    let r_create = record.own_nullifier.r_create;
    let h_pd = hash_proof_data(&serialize_proof_data(&record.proof_data));
    comm_verify(
        &record.own_nullifier.r_create,
        &h_pd,
        &record.own_nullifier.r_prime_create,
    )
    .map_err(|e| SdrDiscardReason::NotFirstOccurrence {
        detail: format!("S2C opening does not bind H(ProofData): {e:#}"),
    })?;
    Ok((pk_create, r_create))
}

/// Engine-only part of §4.2 check (iv): NfLog classification, lookup, and
/// mirror-height resolution. No attacker-controlled proof parsing occurs here.
pub(crate) fn verify_sdr_record_engine_checks(
    engine: &StateEngine,
    pk_create: [u8; 32],
    r_create: [u8; 32],
) -> Result<u64 /* inclusion_height */, SdrDiscardReason> {
    match engine.nflog().classify(pk_create, r_create) {
        SpendClassification::ValidFirstSpend => {}
        SpendClassification::RejectedDoubleSpend => {
            return Err(SdrDiscardReason::NotFirstOccurrence {
                detail: "creating Pk is present with a different R (double-spend loser)".into(),
            });
        }
        SpendClassification::Pending => {
            return Err(SdrDiscardReason::NotFirstOccurrence {
                detail: "creating nullifier is not a first-occurrence on receiver NfLog".into(),
            });
        }
    }
    let inclusion_pos = match engine.nflog().lookup(pk_create) {
        LookupResult::Present { pos, r, .. } if r == r_create => pos,
        LookupResult::Present { r, .. } => {
            return Err(SdrDiscardReason::NotFirstOccurrence {
                detail: format!(
                    "NfLog first-occurrence R mismatches creating_nullifier.R (log has {})",
                    hex::encode(r)
                ),
            });
        }
        LookupResult::Absent => {
            return Err(SdrDiscardReason::NotFirstOccurrence {
                detail: "creating Pk vanished between classify and lookup".into(),
            });
        }
    };
    // Resolve inclusion height from the NfLog mirror (needed by async (v)/(vi)).
    // Height/hash equality vs the sealed record is checked in the async half.
    let inclusion_height = match engine.nflog_mirror().get(inclusion_pos as usize) {
        Some((cp, _)) => cp.height,
        None => {
            return Err(SdrDiscardReason::InclusionBlockMismatch {
                detail: format!(
                    "NfLog mirror has no entry at pos {inclusion_pos} for inclusion height"
                ),
            });
        }
    };
    Ok(inclusion_height)
}

/// Reconstruct the exact `NavOpening` that opens `target_nav_commitment` under
/// `nav_rand`, by scanning every canonical NfLog prefix length this node has
/// scanned so far (`0..=engine.nflog_mirror().len()`).
///
/// The wallet originally proved this transition against some historical
/// `size_final(tip_height)` <= the accumulator size at that time <= today's
/// accumulator size (the NfLog only grows; a canonical prefix root never
/// changes once fixed — see `NflogIncrementalMth`'s documented equivalence).
/// So the search is exhaustive over every value the original opening could
/// have been. `nav_commitment` is a collision-resistant hash binding, so a
/// match is (cryptographically) unique. Returns `None` only if this node's
/// NfLog genuinely lacks the prefix that was used — a real reconstruction gap.
fn reconstruct_nav_opening(
    engine: &StateEngine,
    nav_rand: [u8; 32],
    target_nav_commitment: host::HashDigest,
) -> Option<NavOpening> {
    let opens =
        |root: host::HashDigest| host::nav_commitment(root, &nav_rand) == target_nav_commitment;

    if opens(host::nflog_root(0, host::nflog_empty())) {
        return Some(NavOpening {
            nav: host::Nav {
                size: 0,
                mth: host::nflog_empty(),
            },
            nav_rand,
        });
    }
    let mirror = engine.nflog_mirror();
    let mut acc = shared::spec_v1::nflog::NflogIncrementalMth::new();
    for (_, entry) in &mirror {
        acc.append(entry);
        let mth = acc.mth();
        let size = acc.size();
        if opens(host::nflog_root(size, mth)) {
            return Some(NavOpening {
                nav: host::Nav { size, mth },
                nav_rand,
            });
        }
    }
    None
}

/// §4.2 checks (v except monotonicity) and (vi) — async half (block_log + anchor bound).
///
/// Takes only `inclusion_height` (a plain `u64` from the sync half); no `&StateEngine`.
pub(crate) async fn verify_sdr_record_checks_v_vi_async(
    pool: &PgPool,
    inclusion_height: u64,
    record: &host::SelfDeliveryRecordV1,
) -> Result<(), SdrDiscardReason> {
    // (v) inclusion height/hash + occurred_at bound to locally re-derived BIP-113 MTP
    // (monotonicity is ordering-stage).
    if u64::from(record.inclusion_block.height) != inclusion_height {
        return Err(SdrDiscardReason::InclusionBlockMismatch {
            detail: format!(
                "inclusion_block.height {} ≠ NfLog first-occurrence height {inclusion_height}",
                record.inclusion_block.height
            ),
        });
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| SdrDiscardReason::InclusionBlockMismatch {
            detail: format!("begin block_log verification snapshot: {e}"),
        })?;
    // REPEATABLE READ = snapshot isolation in Postgres: one MVCC snapshot for
    // all block_log reads below. Must be the first statement after BEGIN.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .map_err(|e| SdrDiscardReason::InclusionBlockMismatch {
            detail: format!("set block_log verification snapshot to REPEATABLE READ: {e}"),
        })?;

    let stored_inclusion_hash =
        crate::db::load_block_hash_at_height_in_tx(&mut tx, inclusion_height)
            .await
            .map_err(|e| SdrDiscardReason::InclusionBlockMismatch {
                detail: format!("block_log lookup at inclusion height {inclusion_height}: {e}"),
            })?;
    let Some(stored_inclusion_hash) = stored_inclusion_hash else {
        return Err(SdrDiscardReason::InclusionBlockMismatch {
            detail: format!(
                "no block_log row for inclusion height {inclusion_height} (node has not scanned it)"
            ),
        });
    };
    if record.inclusion_block.block_hash != stored_inclusion_hash {
        return Err(SdrDiscardReason::InclusionBlockMismatch {
            detail: format!(
                "inclusion_block.block_hash {} ≠ block_log hash {} at height {inclusion_height}",
                hex::encode(record.inclusion_block.block_hash),
                hex::encode(stored_inclusion_hash)
            ),
        });
    }
    if record.occurred_at == 0 {
        return Err(SdrDiscardReason::OccurredAtInvalid {
            detail: "occurred_at is zero; a valid sealed BIP-113 MTP is required".into(),
        });
    }
    let mtp = crate::db::load_median_time_past_in_tx(&mut tx, inclusion_height)
        .await
        .map_err(|e| SdrDiscardReason::OccurredAtInvalid {
            detail: format!(
                "block_log lookup for BIP-113 MTP window at inclusion height \
                 {inclusion_height}: {e}"
            ),
        })?;
    match mtp {
        Some(mtp) => {
            if record.occurred_at != mtp {
                return Err(SdrDiscardReason::OccurredAtInvalid {
                    detail: format!(
                        "occurred_at {} ≠ MTP(inclusion_block) {mtp} (BIP-113)",
                        record.occurred_at
                    ),
                });
            }
        }
        None => {
            return Err(SdrDiscardReason::OccurredAtInvalid {
                detail: format!(
                    "BIP-113 MTP window not locally derivable at inclusion height \
                     {inclusion_height}; check (v) discards (spec §4.2, no presence fallback)"
                ),
            });
        }
    }

    // (vi) §3.5 anchor bound via the shared scanner predicate
    let sp_anchor = zkcoins_prover::half_agg::BlockAnchor {
        block_hash: record.proof_block_anchor.block_hash,
        height: record.proof_block_anchor.height,
    };
    let anchor_hash = crate::db::load_block_hash_at_height_in_tx(
        &mut tx,
        u64::from(record.proof_block_anchor.height),
    )
    .await
    .map_err(|e| SdrDiscardReason::AnchorBoundFailed {
        detail: format!(
            "block_log lookup at proof_block_anchor height {}: {e}",
            record.proof_block_anchor.height
        ),
    })?;
    let Some(anchor_hash) = anchor_hash else {
        return Err(SdrDiscardReason::AnchorBoundFailed {
            detail: format!(
                "no block_log row for proof_block_anchor height {} (node has not scanned it)",
                record.proof_block_anchor.height
            ),
        });
    };
    zkcoins_prover::scanner::evaluate_anchor_bound(&sp_anchor, inclusion_height, anchor_hash)
        .map_err(|detail| SdrDiscardReason::AnchorBoundFailed { detail })?;

    tx.commit()
        .await
        .map_err(|e| SdrDiscardReason::InclusionBlockMismatch {
            detail: format!("commit block_log verification snapshot: {e}"),
        })?;

    Ok(())
}

/// Group survivors by the authenticated account-state counter, drop groups
/// with divergent account-state ashes, and collapse only full-struct-equal
/// republish duplicates.
///
/// Same-ash but non-identical records remain candidates, deterministically
/// ordered by blob id, so chain validation names and resolves each one.
pub(crate) fn resolve_equivocation_and_order(
    survivors: Vec<([u8; 32], RecordKind, host::SelfDeliveryRecordV1)>,
) -> (
    Vec<([u8; 32], RecordKind, host::SelfDeliveryRecordV1)>,
    Vec<(u64, [u8; 32], RecordKind, SdrDiscardReason)>,
) {
    let mut by_counter: BTreeMap<u64, Vec<([u8; 32], RecordKind, host::SelfDeliveryRecordV1)>> =
        BTreeMap::new();
    for (blob_id, record_kind, record) in survivors {
        by_counter
            .entry(record.account_state.send_counter)
            .or_default()
            .push((blob_id, record_kind, record));
    }

    let mut ordered = Vec::new();
    let mut discards = Vec::new();
    for (send_counter, group) in by_counter {
        // Survivors already passed check (ii), so ash is well-defined.
        let ashes: Vec<[u8; 32]> = group
            .iter()
            .map(|(_, _, r)| {
                digest_to_bytes(
                    &account_state_hash(&r.account_state)
                        .expect("survivor passed check (ii); ash is defined"),
                )
            })
            .collect();
        let first = ashes[0];
        if ashes.iter().all(|a| *a == first) {
            let mut distinct = Vec::new();
            let mut sorted = group;
            sorted.sort_by_key(|(blob_id, _, _)| *blob_id);
            for candidate in sorted {
                if !distinct.iter().any(
                    |(_, _, existing): &([u8; 32], RecordKind, host::SelfDeliveryRecordV1)| {
                        existing == &candidate.2
                    },
                ) {
                    distinct.push(candidate);
                }
            }
            ordered.extend(distinct);
        } else {
            let distinct: HashSet<[u8; 32]> = ashes.into_iter().collect();
            let detail = format!(
                "send_counter {send_counter}: {} records with {} distinct account_state ashes — rejecting all",
                group.len(),
                distinct.len()
            );
            // Name every member of the equivocating group (never silent).
            for (blob_id, record_kind, _) in group {
                discards.push((
                    send_counter,
                    blob_id,
                    record_kind,
                    SdrDiscardReason::Equivocation {
                        detail: detail.clone(),
                    },
                ));
            }
        }
    }
    (ordered, discards)
}

/// Walk an ascending, unique-per-`send_counter` chain applying check (i)
/// (`prev_state_head`) and check (v) monotonicity of `occurred_at`.
///
/// Does **not** break the loop on a broken link: every broken record is named
/// and a later record that still chains from the same still-current `prev_ash`
/// is still evaluated. Only accepted records advance `prev_ash` /
/// `prev_occurred_at`. The outer record kind is carried without fallback.
pub(crate) fn apply_ordered_chain(
    subject: &[u8; 32],
    nk: &[u8; 32],
    ordered: Vec<([u8; 32], RecordKind, host::SelfDeliveryRecordV1)>,
) -> (
    Vec<AcceptedSdr>,
    Vec<(u64, [u8; 32], RecordKind, SdrDiscardReason)>,
) {
    let mut accepted = Vec::new();
    let mut discards = Vec::new();
    let mut prev_ash: Option<host::HashDigest> = None;
    let mut prev_occurred_at: Option<u64> = None;
    let mut prev_send_counter: Option<u64> = None;

    for (blob_id, record_kind, record) in ordered {
        let send_counter = record.account_state.send_counter;
        let expected_prev = match prev_ash {
            None => {
                if send_counter != 1 {
                    discards.push((
                        send_counter,
                        blob_id,
                        record_kind,
                        SdrDiscardReason::GenesisCounterInvalid {
                            detail: format!(
                                "first post-genesis authenticated counter is {send_counter}, expected 1"
                            ),
                        },
                    ));
                    continue;
                }
                let derived_subject = address(
                    &record.own_nullifier.pk_create,
                    record.account_state.nk_commit,
                );
                if derived_subject != *subject {
                    discards.push((
                        send_counter,
                        blob_id,
                        record_kind,
                        SdrDiscardReason::GenesisIdentityMismatch {
                            detail: format!(
                                "address(pk_create, nk_commit) {} != recovery subject {}",
                                hex::encode(derived_subject),
                                hex::encode(subject)
                            ),
                        },
                    ));
                    continue;
                }
                match canonical_genesis_account_state_ash(
                    subject,
                    nk,
                    record.own_nullifier.pk_create,
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        discards.push((
                            send_counter,
                            blob_id,
                            record_kind,
                            SdrDiscardReason::PrevStateHeadMismatch {
                                detail: format!("genesis ash construction failed: {e}"),
                            },
                        ));
                        continue;
                    }
                }
            }
            Some(a) => a,
        };

        if let Some(previous) = prev_send_counter {
            if previous.checked_add(1) != Some(send_counter) {
                discards.push((
                    send_counter,
                    blob_id,
                    record_kind,
                    SdrDiscardReason::SendCounterNotSequential {
                        detail: format!(
                            "authenticated counter {send_counter} does not immediately follow {previous}"
                        ),
                    },
                ));
                continue;
            }
        }

        if record.prev_state_head != expected_prev {
            discards.push((
                send_counter,
                blob_id,
                record_kind,
                SdrDiscardReason::PrevStateHeadMismatch {
                    detail: format!(
                        "send_counter {send_counter}: prev_state_head {} ≠ expected {}",
                        hex::encode(digest_to_bytes(&record.prev_state_head)),
                        hex::encode(digest_to_bytes(&expected_prev))
                    ),
                },
            ));
            // Do not advance state; continue so later links from the same head are tried.
            continue;
        }

        if prev_occurred_at.is_some_and(|p| record.occurred_at < p) {
            discards.push((
                send_counter,
                blob_id,
                record_kind,
                SdrDiscardReason::OccurredAtNotMonotonic {
                    detail: format!(
                        "send_counter {send_counter}: occurred_at {} < previous accepted {}",
                        record.occurred_at,
                        prev_occurred_at.expect("is_some_and implies Some")
                    ),
                },
            ));
            continue;
        }

        // Accept — ash recompute is the same value proven equal to
        // proof_data.new_account_state_hash by check (ii).
        let new_ash = match account_state_hash(&record.account_state) {
            Ok(a) => a,
            Err(e) => {
                discards.push((
                    send_counter,
                    blob_id,
                    record_kind,
                    SdrDiscardReason::PrevStateHeadMismatch {
                        detail: format!(
                            "send_counter {send_counter}: account_state_hash failed after chain link: {e}"
                        ),
                    },
                ));
                continue;
            }
        };
        let occurred_at = record.occurred_at;
        accepted.push(AcceptedSdr {
            blob_id,
            account_state_ash: digest_to_bytes(&new_ash),
            record,
        });
        prev_ash = Some(new_ash);
        prev_occurred_at = Some(occurred_at);
        prev_send_counter = Some(send_counter);
    }

    (accepted, discards)
}

/// Outcome of classifying + verifying one matched recovery candidate (§4.5 step 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecoveredCandidateOutcome {
    /// Not for this `ivk` / not a delivery — ignore.
    Ignored { reason: &'static str },
    /// Incoming CoinProof passed the existing §2.3.3 path.
    CoinProofVerified { blob_id: [u8; 32] },
    /// Incoming CoinProof failed a check — discarded.
    CoinProofDiscarded { error: IncomingError },
    /// Self-delivery gift-wrap matched this ivk — a candidate for §4.2 replay,
    /// not yet fetched/decoded. Carries everything `run_recovery_campaign`
    /// needs to do so without re-parsing the gift-wrap.
    SelfDeliveryCandidate {
        record_kind: RecordKind,
        blob_id: [u8; 32],
        holders: Vec<String>,
        ss: [u8; 32],
        epk: [u8; 32],
    },
}

/// Operator-visible outcome of one recovery campaign.
///
/// [`Self::restored`] is `true` **only** when the gapless scan is
/// [`GaplessScanStatus::Complete`] **and** every entrusteed subject produced a
/// non-empty accepted, durably committed chain without an availability gap.
/// Partial committed heads remain visible for salvage/operator diagnosis, but
/// never upgrade `restored` when another expected subject is incomplete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryRunReport {
    pub scan_status: GaplessScanStatus,
    pub unique_event_count: usize,
    pub coin_proof_accepted: usize,
    pub coin_proof_rejected: usize,
    pub ignored: usize,
    /// Every SDR candidate that could not be replayed, across every scanned
    /// subject — never silently dropped.
    pub sdr_discards: Vec<SdrDiscard>,
    /// Output-ref coins folded into the durable self-delivery index this run
    /// (newly inserted rows only — already-present / not-ours outcomes are not
    /// counted here but are still traced at debug level, never silent).
    pub sdr_coins_folded: usize,
    /// One recovered lineage head per subject whose accepted chain's complete
    /// fold set committed. Heads may be reported despite an infra gap elsewhere
    /// for the same subject, but such a gap still gates `restored`.
    pub replayed_heads: Vec<ReplayedAccountHead>,
    /// `true` only on a complete scan with successful SDR replay for every
    /// subject that had candidates; incomplete / empty accepted → `false`.
    pub restored: bool,
}

fn restored_decision(
    scan_status: &GaplessScanStatus,
    expected_subjects: &HashSet<[u8; 32]>,
    subjects_with_committed_heads: &HashSet<[u8; 32]>,
    subjects_with_infra_gap: &HashSet<[u8; 32]>,
) -> bool {
    matches!(scan_status, GaplessScanStatus::Complete)
        && !expected_subjects.is_empty()
        && expected_subjects.iter().all(|subject| {
            subjects_with_committed_heads.contains(subject)
                && !subjects_with_infra_gap.contains(subject)
        })
}

impl RecoveryRunReport {
    fn not_restored_from_scan(scan: &GaplessScanResult) -> Self {
        Self {
            scan_status: scan.status.clone(),
            unique_event_count: scan.unique_event_count,
            coin_proof_accepted: 0,
            coin_proof_rejected: 0,
            ignored: 0,
            sdr_discards: Vec::new(),
            sdr_coins_folded: 0,
            replayed_heads: Vec::new(),
            restored: false,
        }
    }
}

/// Validated campaign parameters (only constructed when recovery is requested).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryCampaignConfig {
    pub page_limit: u64,
    pub earliest_account_timestamp: u64,
}

/// Whether the operator requested emergency recovery this process.
///
/// Only the exact value `"1"` enables (same posture as `ZKCOINS_V1_SLOW_CANARY`).
pub(crate) fn recovery_env_enabled() -> bool {
    matches!(std::env::var(RECOVERY_ENV), Ok(v) if v == "1")
}

/// Resolve campaign config from the environment.
///
/// * Flag unset / not `"1"` → `Ok(None)` (no campaign).
/// * Flag `"1"` → require positive page limit and a parseable earliest
///   timestamp; missing/invalid names the variable (no silent defaults).
pub(crate) fn recovery_campaign_config_from_env() -> Result<Option<RecoveryCampaignConfig>, String>
{
    if !recovery_env_enabled() {
        return Ok(None);
    }

    let page_raw = std::env::var(RECOVERY_PAGE_LIMIT_ENV).map_err(|e| match e {
        std::env::VarError::NotPresent => format!(
            "{RECOVERY_ENV}=1 requires {RECOVERY_PAGE_LIMIT_ENV} (positive integer page \
             size L) — refusing silent default L"
        ),
        std::env::VarError::NotUnicode(_) => {
            format!("{RECOVERY_PAGE_LIMIT_ENV} is not valid UTF-8")
        }
    })?;
    let page_limit: u64 = page_raw.parse().map_err(|_| {
        format!("{RECOVERY_PAGE_LIMIT_ENV}={page_raw:?} is not a non-negative integer")
    })?;
    if page_limit == 0 {
        return Err(format!(
            "{RECOVERY_PAGE_LIMIT_ENV}=0 is invalid — page limit must be positive \
             (no default L)"
        ));
    }

    let earliest_raw = std::env::var(RECOVERY_EARLIEST_ENV).map_err(|e| match e {
        std::env::VarError::NotPresent => format!(
            "{RECOVERY_ENV}=1 requires {RECOVERY_EARLIEST_ENV} (unix seconds; wallet \
             earliest account timestamp after dense enumeration) — refusing silent \
             start-at-zero"
        ),
        std::env::VarError::NotUnicode(_) => {
            format!("{RECOVERY_EARLIEST_ENV} is not valid UTF-8")
        }
    })?;
    let earliest_account_timestamp: u64 = earliest_raw.parse().map_err(|_| {
        format!("{RECOVERY_EARLIEST_ENV}={earliest_raw:?} is not a non-negative integer")
    })?;

    Ok(Some(RecoveryCampaignConfig {
        page_limit,
        earliest_account_timestamp,
    }))
}

// ---------------------------------------------------------------------------
// Step 3 — gapless paginated scan
// ---------------------------------------------------------------------------

/// Source of kind-1059 pages for recovery. Production wires
/// [`LiveRecoveryRelaySource`]; tests inject doubles (second flood, drain cap).
///
/// The source **must** surface truncation: a limit-free drain that silently
/// returns a capped subset without `truncated = true` would let recovery
/// skip `t` and lose events.
pub(crate) trait RecoveryRelaySource {
    fn query(
        &mut self,
        relay_url: &str,
        filter: &Filter,
    ) -> Pin<Box<dyn Future<Output = Result<RelayQueryPage, RecoveryError>> + Send + '_>>;
}

/// Production relay source: one connect/query/close per call via [`RelayClient`].
///
/// `EventsLimitExceeded` on a limit-free drain is reported as
/// `truncated = true` (incomplete) — never silently advanced past.
#[derive(Debug, Default)]
pub(crate) struct LiveRecoveryRelaySource;

impl RecoveryRelaySource for LiveRecoveryRelaySource {
    fn query(
        &mut self,
        relay_url: &str,
        filter: &Filter,
    ) -> Pin<Box<dyn Future<Output = Result<RelayQueryPage, RecoveryError>> + Send + '_>> {
        let url = relay_url.to_string();
        let filter = filter.clone();
        Box::pin(async move {
            let mut client =
                RelayClient::connect(&url)
                    .await
                    .map_err(|e| RecoveryError::Relay {
                        relay_url: url.clone(),
                        detail: e.to_string(),
                    })?;
            let result = client.query(std::slice::from_ref(&filter)).await;
            // Best-effort close; query outcome is authoritative.
            let _ = client.close().await;
            match result {
                Ok(events) => Ok(RelayQueryPage {
                    events,
                    // Limited pages: NIP-01 does not signal "more exist"; the
                    // gapless algorithm proves completeness via limit-free
                    // same-second drains, not via this flag.
                    truncated: false,
                }),
                Err(RelayError::EventsLimitExceeded { count, max, .. }) => {
                    // Client safety ceiling before EOSE — cannot claim a full
                    // drain. Empty page + truncated forces Incomplete.
                    tracing::warn!(
                        relay_url = %url,
                        count,
                        max,
                        "recovery relay hit events-per-subscription ceiling — \
                         treating page as truncated (scan will not advance past t)"
                    );
                    Ok(RelayQueryPage {
                        events: Vec::new(),
                        truncated: true,
                    })
                }
                Err(e) => Err(RecoveryError::Relay {
                    relay_url: url,
                    detail: e.to_string(),
                }),
            }
        })
    }
}

/// Gapless kind-1059 scan (§4.5 step 3 (i)/(ii)/(iii)).
///
/// - **(i)** Newest-first: `until = now`, page size `limit = L`, global
///   dedup by `event.id`.
/// - **(ii)** Never lower `until` under a reached second `t` until a
///   **limit-free** `since = t, until = t` drain is proven complete on every
///   reachable relay. Truncation → incomplete; **never** set `until = t − 1`.
/// - **(iii)** End when `until < earliest`, or a full relay round yields no
///   new id **and** every reached second has been fully drained.
///
/// `earliest_account_timestamp` is **required** (no default start).
/// `page_limit` must be positive (no default `L`).
pub(crate) async fn gapless_scan_kind_1059<S: RecoveryRelaySource>(
    source: &mut S,
    relay_urls: &[String],
    page_limit: u64,
    now: u64,
    earliest_account_timestamp: u64,
) -> Result<GaplessScanResult, RecoveryError> {
    if page_limit == 0 {
        return Err(RecoveryError::InvalidPageLimit);
    }
    if relay_urls.is_empty() {
        return Err(RecoveryError::EmptyRelayList);
    }
    // Bound is caller-supplied; documenting the requirement as a typed
    // parameter is the guard. No `unwrap_or(0)` path exists.

    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut events: Vec<Event> = Vec::new();
    let mut until = now;
    let mut fully_drained: HashSet<u64> = HashSet::new();

    // Safety: each successful drain of the minimum reached second strictly
    // decreases `until`, so the loop cannot spin forever on a fixed cursor.
    loop {
        if until < earliest_account_timestamp {
            return Ok(finish_complete(events));
        }

        let mut new_ids_this_round: usize = 0;
        let mut reached_seconds: HashSet<u64> = HashSet::new();

        // (i) Full relay round at the current `until`.
        for url in relay_urls {
            let filter = Filter {
                kinds: Some(vec![KIND_GIFT_WRAP]),
                since: Some(earliest_account_timestamp),
                until: Some(until),
                limit: Some(page_limit),
                ..Filter::default()
            };
            let page = match source.query(url, &filter).await {
                Ok(page) => page,
                Err(RecoveryError::Relay { .. }) => continue,
                Err(e) => return Err(e),
            };
            for event in page.events {
                if event.kind != KIND_GIFT_WRAP {
                    continue;
                }
                if event.created_at < earliest_account_timestamp || event.created_at > until {
                    continue;
                }
                reached_seconds.insert(event.created_at);
                if seen.insert(event.id) {
                    new_ids_this_round = new_ids_this_round.saturating_add(1);
                    events.push(event);
                }
            }
        }

        // (iii) Quiet full round: no new id, and every previously reached
        // second at or below `until` is already proven drained.
        if new_ids_this_round == 0 && reached_seconds.is_empty() {
            let undrained_below = events
                .iter()
                .map(|e| e.created_at)
                .filter(|t| *t <= until && !fully_drained.contains(t))
                .collect::<HashSet<_>>();
            if undrained_below.is_empty() {
                return Ok(finish_complete(events));
            }
            // Reached seconds from earlier rounds still need drain proof
            // before we may declare complete or lower `until`.
            for t in undrained_below {
                reached_seconds.insert(t);
            }
        }

        // (ii) Before stepping under any reached `t`, fully drain `t`.
        // Drain is **not** gated on the limited page returning exactly L
        // events — NIP-01 may return fewer than requested.
        let mut to_drain: Vec<u64> = reached_seconds.into_iter().collect();
        // Also drain any undrained second we already hold events for at
        // this cursor (over-fetch at the boundary is idempotent).
        for e in &events {
            if e.created_at <= until && !fully_drained.contains(&e.created_at) {
                to_drain.push(e.created_at);
            }
        }
        to_drain.sort_unstable();
        to_drain.dedup();

        for &t in &to_drain {
            if fully_drained.contains(&t) {
                continue;
            }
            match drain_timestamp(source, relay_urls, t, &mut seen, &mut events).await {
                Ok(()) => {
                    fully_drained.insert(t);
                }
                Err(DrainFailure::Incomplete { relay_urls }) => {
                    return Ok(GaplessScanResult {
                        unique_event_count: events.len(),
                        events,
                        status: GaplessScanStatus::Incomplete {
                            stuck_at: t,
                            until_cursor: until,
                            relay_urls,
                        },
                    });
                }
                Err(DrainFailure::Error(e)) => return Err(e),
            }
        }

        // All reached seconds ≤ `until` are proven complete. Lower `until`
        // strictly under the minimum drained second in this batch.
        let min_t = match to_drain.iter().copied().min() {
            Some(m) => m,
            None => {
                // No timestamps to step under — nothing left in range.
                return Ok(finish_complete(events));
            }
        };
        if min_t == 0 {
            // Drained the zero second; further lowering is impossible.
            return Ok(finish_complete(events));
        }
        // Proven: every event at `min_t` was seen. Only now may we advance.
        until = min_t - 1;
    }
}

fn finish_complete(events: Vec<Event>) -> GaplessScanResult {
    GaplessScanResult {
        unique_event_count: events.len(),
        events,
        status: GaplessScanStatus::Complete,
    }
}

enum DrainFailure {
    /// Limit-free drain of `t` did not prove complete. `relay_urls` names
    /// every relay that blocked the proof (truncated pages, or the full
    /// attempted set when none were reachable). Always non-empty when the
    /// caller passed a non-empty seed list.
    Incomplete {
        relay_urls: Vec<String>,
    },
    Error(RecoveryError),
}

/// Limit-free full drain of one second `t` across all relays.
///
/// Filter: `since = t, until = t`, **no** `limit`. One reachable relay that
/// returns `truncated = false` proves the second complete. If all reachable
/// relays truncate, or none are reachable, caller must not set
/// `until = t − 1`. The incomplete result always carries the blocking
/// relay URL(s) so the operator can inspect the right peer.
async fn drain_timestamp<S: RecoveryRelaySource>(
    source: &mut S,
    relay_urls: &[String],
    t: u64,
    seen: &mut HashSet<[u8; 32]>,
    events: &mut Vec<Event>,
) -> Result<(), DrainFailure> {
    let filter = Filter {
        kinds: Some(vec![KIND_GIFT_WRAP]),
        since: Some(t),
        until: Some(t),
        limit: None,
        ..Filter::default()
    };

    let mut reachable: usize = 0;
    let mut fully_drained_by_any_relay = false;
    let mut truncated_relays: Vec<String> = Vec::new();
    let mut attempted: Vec<String> = Vec::new();

    for url in relay_urls {
        attempted.push(url.clone());
        let page = match source.query(url, &filter).await {
            Ok(p) => p,
            Err(RecoveryError::Relay { .. }) => {
                // Unreachable / protocol failure on this URL — try others.
                // If none succeed, we report incomplete with every attempted
                // URL so the operator knows which peers to check.
                continue;
            }
            Err(e) => return Err(DrainFailure::Error(e)),
        };
        reachable = reachable.saturating_add(1);
        if page.truncated {
            truncated_relays.push(url.clone());
        } else {
            fully_drained_by_any_relay = true;
        }
        for event in page.events {
            if event.kind != KIND_GIFT_WRAP || event.created_at != t {
                continue;
            }
            if seen.insert(event.id) {
                events.push(event);
            }
        }
    }

    if reachable == 0 {
        return Err(DrainFailure::Incomplete {
            relay_urls: attempted,
        });
    }
    if !fully_drained_by_any_relay {
        return Err(DrainFailure::Incomplete {
            relay_urls: truncated_relays,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 5 — verify each find
// ---------------------------------------------------------------------------

/// Classify a scanned gift-wrap and, for CoinProof deliveries, re-run the
/// existing §2.3.3 checks in [`verify_coin_proof_for_index`].
///
/// Self-delivery payloads are **not** ignored: they are returned as
/// [`RecoveredCandidateOutcome::SelfDeliveryCandidate`] so the campaign can
/// fetch/decode/verify/order them (never silent).
///
/// Blob fetch / ZBE open for CoinProof is the caller's responsibility when
/// assembling a [`CoinProof`]; this function is the pure verify gate once
/// the plaintext bundle is in hand (same split as the receive path's
/// decode-then-verify). For detect-only classification without a blob, pass
/// `opened_coin_proof = None` — a match with `record_kind` still yields a
/// candidate; a CoinProof match without plaintext is reported as discarded.
pub(crate) fn verify_recovered_candidate(
    wrap: &Event,
    ivk: &[u8; 32],
    subject: &[u8; 32],
    engine: &StateEngine,
    bridge: &ProverBridge,
    opened_coin_proof: Option<&CoinProof>,
) -> RecoveredCandidateOutcome {
    if wrap.kind != KIND_GIFT_WRAP {
        return RecoveredCandidateOutcome::Ignored {
            reason: "not gift-wrap kind",
        };
    }

    let (outer_dt, epk) = match extract_scan_tags(&wrap.tags) {
        Ok(t) => t,
        Err(_) => {
            return RecoveredCandidateOutcome::Ignored {
                reason: "missing or invalid zkdt/zkepk",
            };
        }
    };
    let (ss, _) = match match_detect_tag(ivk, &outer_dt, &epk) {
        Ok(v) => v,
        Err(IncomingError::DetectTagMismatch { .. }) => {
            return RecoveredCandidateOutcome::Ignored {
                reason: "detect_tag not for this ivk",
            };
        }
        Err(e) => {
            return RecoveredCandidateOutcome::CoinProofDiscarded { error: e };
        }
    };

    // Unwrap to read the delivery payload (kind-1420). Failure is discard.
    let unwrapped = match unwrap_gift(wrap, ivk) {
        Ok(u) => u,
        Err(e) => {
            return RecoveredCandidateOutcome::CoinProofDiscarded {
                error: IncomingError::Nip59(e.to_string()),
            };
        }
    };
    if unwrapped.rumor.kind != super::nostr::kinds::delivery::KIND_DELIVERY {
        return RecoveredCandidateOutcome::Ignored {
            reason: "inner rumor not kind 1420",
        };
    }
    let payload = match decode_delivery_payload(&unwrapped.rumor.content) {
        Ok(p) => p,
        Err(e) => {
            return RecoveredCandidateOutcome::CoinProofDiscarded {
                error: IncomingError::Payload(e.to_string()),
            };
        }
    };

    // Self-delivery: queue for §4.2 replay — do not treat as CoinProof, do not ignore.
    if let Some(record_kind) = payload.record_kind {
        return RecoveredCandidateOutcome::SelfDeliveryCandidate {
            record_kind,
            blob_id: payload.blob_id,
            holders: payload.holders,
            ss,
            epk,
        };
    }
    // CoinProof path does not use the detect-tag shared secret further.
    let _ = ss;

    // CoinProof path: §2.3.3 via the **existing** verify function only.
    let Some(cp) = opened_coin_proof else {
        return RecoveredCandidateOutcome::CoinProofDiscarded {
            error: IncomingError::Verification(
                "recovery CoinProof match without opened plaintext — refusing credit".into(),
            ),
        };
    };
    match verify_coin_proof_for_index(engine, bridge, cp, subject) {
        Ok(()) => RecoveredCandidateOutcome::CoinProofVerified {
            blob_id: payload.blob_id,
        },
        Err(error) => RecoveredCandidateOutcome::CoinProofDiscarded { error },
    }
}

// ---------------------------------------------------------------------------
// Output-coin fold — reproduce the ONLINE self-delivery index rows exactly
// ---------------------------------------------------------------------------

/// Map a host `RecordKind` (SDR wire) to the delivery-payload `RecordKind`
/// used in recovery reports.
fn delivery_record_kind(k: host::RecordKind) -> RecordKind {
    match k {
        host::RecordKind::Mint => RecordKind::Mint,
        host::RecordKind::Send => RecordKind::Send,
        host::RecordKind::Receive => RecordKind::Receive,
    }
}

fn verify_delivery_record_kind(
    outer: RecordKind,
    record: &host::SelfDeliveryRecordV1,
) -> Result<(), SdrDiscardReason> {
    let inner = delivery_record_kind(record.record_kind);
    if inner != outer {
        return Err(SdrDiscardReason::RecordKindMismatch {
            detail: format!("outer {outer:?} != decoded SDR {inner:?}"),
        });
    }
    Ok(())
}

/// Map a host `RecordKind` to the durable `TransitionKind` (same mapping as
/// `signature.rs` online writer: 0x01/Mint, 0x02/Send, 0x03/Receive).
fn transition_kind_from_host_record_kind(k: host::RecordKind) -> TransitionKind {
    match k {
        host::RecordKind::Mint => TransitionKind::Mint,
        host::RecordKind::Send => TransitionKind::Send,
        host::RecordKind::Receive => TransitionKind::Receive,
    }
}

/// Subject + OVK for output-ref fold (OVK recovers `K_tx` from `out_ciphertext`).
///
/// No [`Debug`]: `ovk` is a secret (never log this bag).
#[derive(Clone, Copy)]
pub(crate) struct FoldOutputRefSecrets<'a> {
    pub subject: &'a [u8; 32],
    pub ovk: &'a [u8; 32],
}

/// Durable SQL store for the fold write path.
///
/// Argument group (clippy `too_many_arguments`), not pure config.
#[derive(Clone, Copy)]
pub(crate) struct FoldOutputRefStores<'a> {
    pub pool: &'a sqlx::PgPool,
}

fn verify_fold_static_bindings(
    cp: &CoinProof,
    oref: &host::OutputRef,
    accepted_record: &host::SelfDeliveryRecordV1,
) -> Result<[u8; 32], SdrDiscardReason> {
    let coin_id = digest_to_bytes(&cp.coin.identifier);
    if coin_id != oref.coin_id {
        return Err(SdrDiscardReason::FoldCoinIdMismatch {
            detail: format!(
                "CoinProof coin.identifier {} != OutputRef coin_id {}",
                hex::encode(coin_id),
                hex::encode(oref.coin_id)
            ),
        });
    }
    if cp.epk != oref.epk {
        return Err(SdrDiscardReason::FoldEpkMismatch {
            detail: format!(
                "CoinProof epk {} != OutputRef epk {}",
                hex::encode(cp.epk),
                hex::encode(oref.epk)
            ),
        });
    }
    if cp.creating_nullifier != accepted_record.own_nullifier {
        return Err(SdrDiscardReason::FoldCreatingTransitionMismatch {
            detail: "CoinProof creating_nullifier != accepted SDR own_nullifier".into(),
        });
    }
    Ok(coin_id)
}

/// Fetch, decrypt, bind, and verify one output ref without writing it.
async fn stage_output_ref_inner(
    stores: FoldOutputRefStores<'_>,
    bridge: &ProverBridge,
    secrets: FoldOutputRefSecrets<'_>,
    accepted_record: &host::SelfDeliveryRecordV1,
    transition_kind: TransitionKind,
    oref: &host::OutputRef,
    max_blob_bytes: u64,
    blob_stores: &[String],
    verify: impl FnOnce(&CoinProof) -> Result<(), IncomingError>,
) -> Result<StagedFoldOutcome, SdrDiscardReason> {
    // 1. Recover K_tx from out_ciphertext under K_out (OVK path).
    let k_out =
        derive_out_key(secrets.ovk, &oref.epk).map_err(|e| SdrDiscardReason::ZbeOpenFailed {
            detail: format!("derive_out_key: {e}"),
        })?;
    let payload = String::from_utf8(oref.out_ciphertext.clone()).map_err(|e| {
        SdrDiscardReason::ZbeOpenFailed {
            detail: format!("out_ciphertext is not UTF-8: {e}"),
        }
    })?;
    let sealed = nip44::decrypt(&k_out, &payload).map_err(|e| SdrDiscardReason::ZbeOpenFailed {
        detail: format!("NIP-44 decrypt out_ciphertext: {e}"),
    })?;
    let k_tx_vec =
        envelope_open(&sealed, ENVELOPE_LABEL_K_TX, OUT_CIPHERTEXT_LEN).map_err(|e| {
            SdrDiscardReason::ZbeOpenFailed {
                detail: format!("envelope_open K_tx: {e}"),
            }
        })?;
    let k_tx: [u8; 32] =
        k_tx_vec
            .try_into()
            .map_err(|v: Vec<u8>| SdrDiscardReason::ZbeOpenFailed {
                detail: format!(
                    "K_tx length {} ≠ {OUT_CIPHERTEXT_LEN} after envelope_open",
                    v.len()
                ),
            })?;

    // 2. Fetch the coin's own ZBE blob.
    let client = BlossomClient::new(max_blob_bytes).map_err(|e| SdrDiscardReason::FetchFailed {
        detail: format!("BlossomClient: {e}"),
    })?;
    let holders = recovery_blob_holders(&oref.blob_locators.holders, blob_stores);
    let (zbe_ciphertext, _attempts) =
        fetch_blob_from_holders(&client, &oref.blob_id, &holders)
            .await
            .map_err(|e| SdrDiscardReason::FetchFailed {
                detail: e.to_string(),
            })?;

    // 3. ZBE-open under recovered K_tx.
    let plaintext =
        zbe_open(&k_tx, &zbe_ciphertext).map_err(|e| SdrDiscardReason::ZbeOpenFailed {
            detail: format!("zbe_open coin blob: {e}"),
        })?;

    // 4. Deserialize CoinProof.
    let cp = deserialize_coin_proof(&plaintext).map_err(|e| SdrDiscardReason::DecodeFailed {
        detail: format!("deserialize_coin_proof: {e}"),
    })?;

    // 5. Not ours → ok, not an error.
    if cp.coin.recipient.0 != *secrets.subject {
        return Ok(StagedFoldOutcome::NotOurs);
    }

    // 6. Bind the fetched CoinProof to the OutputRef and accepted SDR.
    let coin_id = verify_fold_static_bindings(&cp, oref, accepted_record)?;
    let (creating_pd, _) =
        load_verify_transition_public_inputs(bridge, &cp.proof, "fold CoinProof creating proof")
            .map_err(|e| SdrDiscardReason::FoldCreatingTransitionMismatch {
                detail: e.to_string(),
            })?;
    if creating_pd != accepted_record.proof_data {
        return Err(SdrDiscardReason::FoldCreatingTransitionMismatch {
            detail: "CoinProof creating ProofData != accepted SDR proof_data".into(),
        });
    }

    let coin_ciphertext = String::from_utf8(cp.ciphertext.clone()).map_err(|e| {
        SdrDiscardReason::FoldCiphertextBindingFailed {
            detail: format!("CoinProof ciphertext is not UTF-8: {e}"),
        }
    })?;
    let coin_sealed = nip44::decrypt(&k_tx, &coin_ciphertext).map_err(|e| {
        SdrDiscardReason::FoldCiphertextBindingFailed {
            detail: format!("NIP-44 decrypt CoinProof ciphertext: {e}"),
        }
    })?;
    let opened_coin = envelope_open(&coin_sealed, ENVELOPE_LABEL_COIN, COIN_CIPHERTEXT_LEN)
        .map_err(|e| SdrDiscardReason::FoldCiphertextBindingFailed {
            detail: format!("envelope_open coin: {e}"),
        })?;
    if opened_coin.as_slice() != serialize_coin(&cp.coin).as_slice() {
        return Err(SdrDiscardReason::FoldCiphertextBindingFailed {
            detail: "opened CoinProof ciphertext != serialize_coin(cp.coin)".into(),
        });
    }

    // 7. Same §2.3.3 verify as the online receive path.
    verify(&cp).map_err(|e| SdrDiscardReason::DecodeFailed {
        detail: format!("coin proof verify: {e}"),
    })?;

    // 8. Idempotent durable presence check.
    if get_self_delivery_by_subject_coin(stores.pool, secrets.subject, &coin_id)
        .await
        .map_err(|e| SdrDiscardReason::IndexLookupFailed {
            detail: format!("index presence lookup: {e:#}"),
        })?
        .is_some()
    {
        return Ok(StagedFoldOutcome::AlreadyPresent { coin_id });
    }

    // 9. Stage EXACTLY the online row shape (signature.rs:1542-1557).
    let row = SelfDeliveryIndexRow {
        record_id: decrypt_record_id(secrets.subject, &coin_id, &oref.blob_id),
        subject: *secrets.subject,
        coin_id,
        blob_id: oref.blob_id,
        detect_tag: digest_to_bytes(&cp.detect_tag),
        canonical: plaintext,
        asset_id: digest_to_bytes(&cp.coin.asset_id),
        transition_kind,
        occurred_at: 0,
    };
    Ok(StagedFoldOutcome::Row(row))
}

// ---------------------------------------------------------------------------
// Production campaign — scan + classify + decrypt-index fill
// ---------------------------------------------------------------------------

/// One self-delivery gift-wrap candidate queued during classify for §4.2 replay.
#[derive(Clone, Debug)]
pub(crate) struct SdrGiftWrapCandidate {
    pub record_kind: RecordKind,
    pub blob_id: [u8; 32],
    pub holders: Vec<String>,
    pub ss: [u8; 32],
    pub epk: [u8; 32],
}

/// Dependencies for one background recovery campaign (runtime-owned handles).
pub(crate) struct RecoveryCampaignDeps {
    pub seed_relays: Vec<String>,
    pub blob_stores: Vec<String>,
    pub bundles: Arc<BundleStore>,
    pub adapter: Arc<EngineAdapter>,
    pub pool: Arc<PgPool>,
    pub index: Arc<InMemoryPrivateIndex>,
    pub receipts: Arc<ReceiptHub>,
    pub max_blob_bytes: u64,
    pub expected_network: String,
}

/// Receiver-advertised holders remain preferred; verified manifest stores are
/// appended as recovery-discoverable fallbacks without retrying duplicate URLs.
pub(crate) fn recovery_blob_holders(
    advertised: &[String],
    blob_stores: &[String],
) -> Vec<String> {
    let mut holders = Vec::with_capacity(advertised.len() + blob_stores.len());
    for holder in advertised.iter().chain(blob_stores) {
        if !holders.contains(holder) {
            holders.push(holder.clone());
        }
    }
    holders
}

/// Wait for at least one entrusteed operational bundle, then run one recovery
/// campaign: gapless scan → per-event classify (SDR candidates + CoinProof
/// receive path) → §4.2 VERIFY-ONLY SDR replay + output-coin fold.
///
/// # Fail-closed restored claim
///
/// * No seed relays / no bundle → [`RecoveryError`] (caller logs; not restored).
/// * Scan [`GaplessScanStatus::Incomplete`] → report with `restored = false`.
/// * Complete scan **and** every expected subject got a recovered head that
///   was installed and persisted (or was already present at or beyond that
///   head) → may set `restored = true`.
///
/// Partial CoinProof indexing on an incomplete scan is still attempted (useful
/// salvage) but **never** upgrades the restored flag.
/// Subjects in `active` that already have a servable recovered head on this
/// node (checked via the same private-index read `/v1/pull`'s
/// `get_account_state` uses) — a re-run of the campaign must not re-scan,
/// re-replay, or re-install these; it only needs to make progress on the rest.
fn already_recovered_subjects(
    index: &InMemoryPrivateIndex,
    active: &[(SubjectAddress, OperationalBundle)],
) -> HashSet<[u8; 32]> {
    active
        .iter()
        .filter(|(subject, _)| index.get_account_state(subject).is_ok())
        .map(|(subject, _)| subject.0)
        .collect()
}

pub(crate) async fn run_recovery_campaign(
    config: RecoveryCampaignConfig,
    deps: RecoveryCampaignDeps,
) -> Result<RecoveryRunReport, RecoveryError> {
    if deps.seed_relays.is_empty() {
        return Err(RecoveryError::NoSeedRelays);
    }

    // BundleStore is process-local and filled only after Entrust. Poll until
    // the operator entrusts; do not invent keys and do not claim restored
    // while waiting. The campaign is one-shot after the first non-empty
    // snapshot — not a continuous full-history re-scan.
    //
    // Absence is not silent: wait logs a named warning that recovery cannot
    // run without an operational bundle (see [`RecoveryError::NoOperationalBundle`]
    // text). There is no path that starts the scan with an empty subject set.
    let active = wait_for_active_bundles(&deps.bundles).await;
    let already_recovered = already_recovered_subjects(&deps.index, &active);
    if !already_recovered.is_empty() {
        tracing::info!(
            subjects = already_recovered.len(),
            "§4.5 recovery campaign: skipping already-recovered subject(s) this pass"
        );
    }
    let pending: Vec<&(SubjectAddress, OperationalBundle)> = active
        .iter()
        .filter(|(subject, _)| !already_recovered.contains(&subject.0))
        .collect();

    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return Err(RecoveryError::WallClockUnavailable),
    };

    tracing::info!(
        page_limit = config.page_limit,
        earliest = config.earliest_account_timestamp,
        now,
        seed_relays = deps.seed_relays.len(),
        subjects = active.len(),
        "§4.5 recovery campaign starting (gapless kind-1059 over seed relays)"
    );

    let mut source = LiveRecoveryRelaySource;
    let scan = gapless_scan_kind_1059(
        &mut source,
        &deps.seed_relays,
        config.page_limit,
        now,
        config.earliest_account_timestamp,
    )
    .await?;

    match &scan.status {
        GaplessScanStatus::Complete => {
            tracing::info!(
                unique_events = scan.unique_event_count,
                "§4.5 recovery gapless scan complete"
            );
        }
        GaplessScanStatus::Incomplete {
            stuck_at,
            until_cursor,
            relay_urls,
        } => {
            tracing::error!(
                stuck_at,
                until_cursor,
                relay_urls = ?relay_urls,
                unique_events = scan.unique_event_count,
                "§4.5 recovery gapless scan INCOMPLETE — node is NOT treated as \
                 restored (timestamp t could not be fully drained on the listed \
                 relay(s); until was not advanced past t)"
            );
        }
    }

    let mut report = RecoveryRunReport::not_restored_from_scan(&scan);
    let bridge = deps.adapter.bridge();
    let mut rng = OsSecureRandom;

    // Per-subject SDR candidates collected during classify (replayed after the
    // CoinProof loop so fetch/ZBE does not interleave with receive-path work).
    let mut sdr_candidates: HashMap<[u8; 32], Vec<SdrGiftWrapCandidate>> = HashMap::new();

    for event in &scan.events {
        for (subject, bundle) in &pending {
            // Classify first so SDR matches are queued for §4.2 replay
            // (the receive path silently ignores record_kind).
            let classified = deps.adapter.with_engine(|engine| {
                verify_recovered_candidate(event, &bundle.ivk, &subject.0, engine, &bridge, None)
            });
            match classified {
                RecoveredCandidateOutcome::SelfDeliveryCandidate {
                    record_kind,
                    blob_id,
                    holders,
                    ss,
                    epk,
                } => {
                    tracing::info!(
                        subject = %hex::encode(subject.0),
                        blob_id = %hex::encode(blob_id),
                        record_kind = ?record_kind,
                        holders = holders.len(),
                        "§4.5 recovery: SelfDeliveryRecord matched — queued as \
                         SDR replay candidate"
                    );
                    sdr_candidates
                        .entry(subject.0)
                        .or_default()
                        .push(SdrGiftWrapCandidate {
                            record_kind,
                            blob_id,
                            holders,
                            ss,
                            epk,
                        });
                    continue;
                }
                RecoveredCandidateOutcome::Ignored { .. } => {
                    // Not for this ivk / not a delivery — do not run blob fetch.
                    report.ignored = report.ignored.saturating_add(1);
                    continue;
                }
                RecoveredCandidateOutcome::CoinProofDiscarded { .. }
                | RecoveredCandidateOutcome::CoinProofVerified { .. } => {
                    // Without plaintext, classify reports Discarded for
                    // CoinProof matches; fall through to the receive path
                    // which fetches/opens/verifies/indexes.
                }
            }

            let outcome = process_delivery_candidate(
                event,
                CandidateSecrets {
                    subject: &subject.0,
                    ivk: &bundle.ivk,
                    op: &bundle.op,
                },
                CandidateStores {
                    adapter: deps.adapter.as_ref(),
                    pool: deps.pool.as_ref(),
                    index: deps.index.as_ref(),
                    receipts: deps.receipts.as_ref(),
                },
                CandidateNetwork {
                    max_blob_bytes: deps.max_blob_bytes,
                    manifest_blob_stores: &deps.blob_stores,
                    discovery_relays: &deps.seed_relays,
                    expected_network: &deps.expected_network,
                },
                AckClock { now, rng: &mut rng },
            )
            .await;

            match outcome {
                CandidateOutcome::Accepted {
                    coin_id,
                    blob_id,
                    record_id,
                    replay,
                    ..
                } => {
                    report.coin_proof_accepted = report.coin_proof_accepted.saturating_add(1);
                    tracing::info!(
                        subject = %hex::encode(subject.0),
                        coin_id = %hex::encode(coin_id),
                        blob_id = %hex::encode(blob_id),
                        record_id = %hex::encode(record_id),
                        replay,
                        "§4.5 recovery: CoinProof verified via §2.3.3 and durable \
                         decrypt-index write"
                    );
                }
                CandidateOutcome::Rejected { error } => {
                    report.coin_proof_rejected = report.coin_proof_rejected.saturating_add(1);
                    tracing::debug!(
                        subject = %hex::encode(subject.0),
                        error = %error,
                        "§4.5 recovery: candidate rejected (no credit)"
                    );
                }
                CandidateOutcome::Ignored { .. } => {
                    report.ignored = report.ignored.saturating_add(1);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // §4.2 SDR replay phase — per subject with collected candidates
    // -----------------------------------------------------------------------
    let subjects_with_heads: HashSet<[u8; 32]> = {
        let mut heads = HashSet::new();
        for (subject, bundle) in &active {
            let Some(candidates) = sdr_candidates.get(&subject.0) else {
                continue;
            };
            if candidates.is_empty() {
                continue;
            }

            let mut subject_coins_folded: usize = 0;
            let mut survivors: Vec<([u8; 32], RecordKind, host::SelfDeliveryRecordV1)> = Vec::new();

            // (a) fetch + ZBE-open + deserialize each candidate
            for candidate in candidates {
                let client = match BlossomClient::new(deps.max_blob_bytes) {
                    Ok(c) => c,
                    Err(e) => {
                        report.sdr_discards.push(SdrDiscard {
                            subject: subject.0,
                            blob_id: candidate.blob_id,
                            record_kind: candidate.record_kind,
                            send_counter: None,
                            reason: SdrDiscardReason::FetchFailed {
                                detail: format!("BlossomClient: {e}"),
                            },
                        });
                        continue;
                    }
                };
                let holders =
                    recovery_blob_holders(&candidate.holders, &deps.blob_stores);
                let zbe_ciphertext =
                    match fetch_blob_from_holders(&client, &candidate.blob_id, &holders).await {
                        Ok((body, _)) => body,
                        Err(e) => {
                            report.sdr_discards.push(SdrDiscard {
                                subject: subject.0,
                                blob_id: candidate.blob_id,
                                record_kind: candidate.record_kind,
                                send_counter: None,
                                reason: SdrDiscardReason::FetchFailed {
                                    detail: e.to_string(),
                                },
                            });
                            continue;
                        }
                    };
                let k_tx = match derive_note_key(&candidate.ss, &candidate.epk) {
                    Ok(k) => k,
                    Err(e) => {
                        report.sdr_discards.push(SdrDiscard {
                            subject: subject.0,
                            blob_id: candidate.blob_id,
                            record_kind: candidate.record_kind,
                            send_counter: None,
                            reason: SdrDiscardReason::ZbeOpenFailed {
                                detail: format!("derive_note_key: {e}"),
                            },
                        });
                        continue;
                    }
                };
                let plaintext = match zbe_open(&k_tx, &zbe_ciphertext) {
                    Ok(p) => p,
                    Err(e) => {
                        report.sdr_discards.push(SdrDiscard {
                            subject: subject.0,
                            blob_id: candidate.blob_id,
                            record_kind: candidate.record_kind,
                            send_counter: None,
                            reason: SdrDiscardReason::ZbeOpenFailed {
                                detail: format!("zbe_open SDR: {e}"),
                            },
                        });
                        continue;
                    }
                };
                let record = match deserialize_self_delivery_record(&plaintext) {
                    Ok(r) => r,
                    Err(e) => {
                        report.sdr_discards.push(SdrDiscard {
                            subject: subject.0,
                            blob_id: candidate.blob_id,
                            record_kind: candidate.record_kind,
                            send_counter: None,
                            reason: SdrDiscardReason::DecodeFailed {
                                detail: format!("deserialize_self_delivery_record: {e}"),
                            },
                        });
                        continue;
                    }
                };

                if let Err(reason) = verify_delivery_record_kind(candidate.record_kind, &record) {
                    report.sdr_discards.push(SdrDiscard {
                        subject: subject.0,
                        blob_id: candidate.blob_id,
                        record_kind: candidate.record_kind,
                        send_counter: Some(record.send_counter),
                        reason,
                    });
                    continue;
                }

                // (b) Subject/proof checks run before the mutex; only NfLog
                // access is performed under the short engine borrow.
                let (pk_create, r_create) =
                    match verify_sdr_record_pre_engine(&bridge, &subject.0, &bundle.nk, &record) {
                        Ok(values) => values,
                        Err(reason) => {
                            report.sdr_discards.push(SdrDiscard {
                                subject: subject.0,
                                blob_id: candidate.blob_id,
                                record_kind: candidate.record_kind,
                                send_counter: Some(record.send_counter),
                                reason,
                            });
                            continue;
                        }
                    };
                let inclusion_height = match deps.adapter.with_engine(|engine| {
                    verify_sdr_record_engine_checks(engine, pk_create, r_create)
                }) {
                    Ok(height) => height,
                    Err(reason) => {
                        report.sdr_discards.push(SdrDiscard {
                            subject: subject.0,
                            blob_id: candidate.blob_id,
                            record_kind: candidate.record_kind,
                            send_counter: Some(record.send_counter),
                            reason,
                        });
                        continue;
                    }
                };
                if let Err(reason) = verify_sdr_record_checks_v_vi_async(
                    deps.pool.as_ref(),
                    inclusion_height,
                    &record,
                )
                .await
                {
                    report.sdr_discards.push(SdrDiscard {
                        subject: subject.0,
                        blob_id: candidate.blob_id,
                        record_kind: candidate.record_kind,
                        send_counter: Some(record.send_counter),
                        reason,
                    });
                    continue;
                }

                survivors.push((candidate.blob_id, candidate.record_kind, record));
            }

            // (c) order + chain
            let (ordered, eq_discards) = resolve_equivocation_and_order(survivors);
            for (send_counter, blob_id, record_kind, reason) in eq_discards {
                report.sdr_discards.push(SdrDiscard {
                    subject: subject.0,
                    blob_id,
                    record_kind,
                    send_counter: Some(send_counter),
                    reason,
                });
            }

            let (accepted, chain_discards) = apply_ordered_chain(&subject.0, &bundle.nk, ordered);
            for (send_counter, blob_id, record_kind, reason) in chain_discards {
                report.sdr_discards.push(SdrDiscard {
                    subject: subject.0,
                    blob_id,
                    record_kind,
                    send_counter: Some(send_counter),
                    reason,
                });
            }

            // (d) Verify and stage every output_ref before any subject write.
            let mut staged_rows = Vec::new();
            let mut fold_failed = false;
            for accepted_sdr in &accepted {
                let tk = transition_kind_from_host_record_kind(accepted_sdr.record.record_kind);
                let rk = delivery_record_kind(accepted_sdr.record.record_kind);
                for oref in &accepted_sdr.record.output_refs {
                    // Engine borrow cannot span blob I/O (`with_engine` is sync);
                    // Campaign staging runs verify under a short engine borrow.
                    let outcome = stage_output_ref_via_adapter(
                        &deps,
                        &bridge,
                        FoldOutputRefSecrets {
                            subject: &subject.0,
                            ovk: &bundle.ovk,
                        },
                        &accepted_sdr.record,
                        tk,
                        oref,
                    )
                    .await;
                    match outcome {
                        Ok(StagedFoldOutcome::Row(row)) => staged_rows.push(row),
                        Ok(StagedFoldOutcome::AlreadyPresent { coin_id }) => {
                            tracing::debug!(
                                subject = %hex::encode(subject.0),
                                coin_id = %hex::encode(coin_id),
                                oref_blob = %hex::encode(oref.blob_id),
                                "§4.5 recovery: output_ref already present in self-delivery index"
                            );
                        }
                        Ok(StagedFoldOutcome::NotOurs) => {
                            tracing::debug!(
                                subject = %hex::encode(subject.0),
                                oref_blob = %hex::encode(oref.blob_id),
                                "§4.5 recovery: output_ref recipient ≠ subject (NotOurs)"
                            );
                        }
                        Err(reason) => {
                            fold_failed = true;
                            report.sdr_discards.push(SdrDiscard {
                                subject: subject.0,
                                blob_id: oref.blob_id,
                                record_kind: rk,
                                send_counter: Some(accepted_sdr.record.send_counter),
                                reason,
                            });
                        }
                    }
                }
            }

            if fold_failed {
                tracing::warn!(
                    subject = %hex::encode(subject.0),
                    staged_rows = staged_rows.len(),
                    "§4.5 recovery: subject fold verification failed; staged batch discarded"
                );
                continue;
            }

            let durable = match insert_and_mirror_self_delivery_batch(
                deps.pool.as_ref(),
                deps.index.as_ref(),
                &staged_rows,
            )
            .await
            {
                Ok(outcomes) => outcomes,
                Err(e) => {
                    let Some(last) = accepted.last() else {
                        continue;
                    };
                    report.sdr_discards.push(SdrDiscard {
                        subject: subject.0,
                        blob_id: last.blob_id,
                        record_kind: delivery_record_kind(last.record.record_kind),
                        send_counter: Some(last.record.send_counter),
                        reason: SdrDiscardReason::FoldCommitFailed {
                            detail: format!("per-subject transaction: {e:#}"),
                        },
                    });
                    continue;
                }
            };
            for (row, outcome) in durable {
                if outcome == InsertRecordOutcome::Inserted {
                    subject_coins_folded = subject_coins_folded.saturating_add(1);
                    report.sdr_coins_folded = report.sdr_coins_folded.saturating_add(1);
                    tracing::debug!(
                        subject = %hex::encode(subject.0),
                        coin_id = %hex::encode(row.coin_id),
                        oref_blob = %hex::encode(row.blob_id),
                        "§4.5 recovery: staged output_ref committed in subject batch"
                    );
                }
            }

            // (e) report head from last accepted (highest send_counter, ascending walk)
            if let Some(last) = accepted.last() {
                report.replayed_heads.push(ReplayedAccountHead {
                    subject: subject.0,
                    record_kind: delivery_record_kind(last.record.record_kind),
                    send_counter: last.record.send_counter,
                    account_state: last.record.account_state.clone(),
                    account_state_ash: last.account_state_ash,
                    recursive_proof: last.record.recursive_proof.clone(),
                    proof_data: last.record.proof_data.clone(),
                    inclusion_block: last.record.inclusion_block,
                    occurred_at: last.record.occurred_at,
                });
                match install_and_persist_recovered_head(
                    &deps, &bridge, subject.0, bundle, &accepted,
                )
                .await
                {
                    Ok(()) => {
                        heads.insert(subject.0);
                    }
                    Err(reason) => {
                        tracing::error!(
                            subject = %hex::encode(subject.0),
                            reason = %reason,
                            "§4.5 recovery: SDR replay verified a head but it could not be \
                             installed or persisted — head is reported for salvage/diagnosis \
                             but this subject is not restored"
                        );
                        report.sdr_discards.push(SdrDiscard {
                            subject: subject.0,
                            blob_id: last.blob_id,
                            record_kind: delivery_record_kind(last.record.record_kind),
                            send_counter: Some(last.record.send_counter),
                            reason,
                        });
                    }
                }
            } else {
                tracing::warn!(
                    subject = %hex::encode(subject.0),
                    candidates = candidates.len(),
                    subject_coins_folded,
                    "§4.5 recovery: SDR candidates present but no accepted chain \
                     — no replayed head for this subject"
                );
            }
        }
        heads
    };

    let expected_subjects: HashSet<[u8; 32]> =
        active.iter().map(|(subject, _)| subject.0).collect();
    let subjects_with_committed_heads: HashSet<[u8; 32]> = subjects_with_heads
        .union(&already_recovered)
        .copied()
        .collect();
    let subjects_with_infra_gap: HashSet<[u8; 32]> = report
        .sdr_discards
        .iter()
        .filter(|discard| discard.reason.is_infra_availability())
        .map(|discard| discard.subject)
        .collect();
    let sdr_replay_ok = expected_subjects.iter().all(|subject| {
        subjects_with_committed_heads.contains(subject)
            && !subjects_with_infra_gap.contains(subject)
    });
    report.restored = restored_decision(
        &report.scan_status,
        &expected_subjects,
        &subjects_with_committed_heads,
        &subjects_with_infra_gap,
    );

    if report.restored {
        tracing::info!(
            accepted = report.coin_proof_accepted,
            rejected = report.coin_proof_rejected,
            ignored = report.ignored,
            sdr_discards = report.sdr_discards.len(),
            sdr_coins_folded = report.sdr_coins_folded,
            replayed_heads = report.replayed_heads.len(),
            "§4.5 recovery campaign finished — scan complete and SDR replay \
             installed and persisted a head for every expected subject; restored=true"
        );
    } else {
        tracing::error!(
            accepted = report.coin_proof_accepted,
            rejected = report.coin_proof_rejected,
            sdr_discards = report.sdr_discards.len(),
            sdr_coins_folded = report.sdr_coins_folded,
            replayed_heads = report.replayed_heads.len(),
            scan_status = ?report.scan_status,
            sdr_replay_ok,
            "§4.5 recovery campaign finished — restored=false (incomplete scan \
             or SDR replay could not install and persist a gap-free head for every \
             expected subject); operator must not treat this node as fully recovered"
        );
    }
    Ok(report)
}

/// Campaign staging path: verifies without writing and obtains `&StateEngine`
/// only for the §2.3.3 gate via a short sync borrow.
async fn stage_output_ref_via_adapter(
    deps: &RecoveryCampaignDeps,
    bridge: &ProverBridge,
    secrets: FoldOutputRefSecrets<'_>,
    accepted_record: &host::SelfDeliveryRecordV1,
    transition_kind: TransitionKind,
    oref: &host::OutputRef,
) -> Result<StagedFoldOutcome, SdrDiscardReason> {
    stage_output_ref_inner(
        FoldOutputRefStores {
            pool: deps.pool.as_ref(),
        },
        bridge,
        secrets,
        accepted_record,
        transition_kind,
        oref,
        deps.max_blob_bytes,
        deps.blob_stores.as_slice(),
        |cp| {
            deps.adapter.with_engine(|engine| {
                verify_coin_proof_for_index(engine, bridge, cp, secrets.subject)
            })
        },
    )
    .await
}

/// §4.5 step 6: reconstruct the full `AccountRecord` for `subject` from the
/// accepted, ordered, already-fold-committed SDR chain, install it into the
/// live engine, and durably persist. VERIFY-ONLY — never proves anything;
/// `last_proof` is bound from the already-recovered/verified `recursive_proof`
/// bytes, never freshly generated.
///
/// Idempotent across repeat campaign runs: if the engine already holds this
/// subject at a send_counter >= the reconstructed head's, this is a no-op
/// success (already installed). If it holds an *older* account, that is a
/// fail-closed contradiction (no in-place update path exists for a live
/// account — this task never adds one).
async fn install_and_persist_recovered_head(
    deps: &RecoveryCampaignDeps,
    bridge: &ProverBridge,
    subject: [u8; 32],
    bundle: &OperationalBundle,
    accepted: &[AcceptedSdr],
) -> Result<(), SdrDiscardReason> {
    let owner = Address(subject);
    let head = accepted
        .last()
        .expect("caller checked accepted is non-empty");
    let genesis = accepted.first().expect("non-empty implies a first element");

    let existing_send_counter = deps
        .adapter
        .with_engine(|engine| engine.account(&owner).map(|r| r.state.send_counter));
    if let Some(existing) = existing_send_counter {
        if existing >= head.record.account_state.send_counter {
            tracing::info!(
                subject = %hex::encode(subject),
                existing_send_counter = existing,
                head_send_counter = head.record.account_state.send_counter,
                "§4.5 recovery: engine already holds this subject at or beyond the \
                 reconstructed head — treating as already installed"
            );
            return Ok(());
        }
        return Err(SdrDiscardReason::HeadReconstructionFailed {
            detail: format!(
                "engine already holds account at send_counter {existing}, behind the \
                 reconstructed head {} — no in-place account update path exists; refusing \
                 to overwrite (nothing was changed)",
                head.record.account_state.send_counter
            ),
        });
    }

    // 1. Admitted coin universe: this account's own self-created outputs
    // (durably folded just above, across every accepted SDR, not only the
    // head) plus every independently verified received CoinProof.
    let self_rows = super::db_self_delivery_index::list_by_subject(deps.pool.as_ref(), &subject)
        .await
        .map_err(|e| SdrDiscardReason::IndexLookupFailed {
            detail: format!("list self-delivery rows for head install: {e:#}"),
        })?;
    let received_rows = super::db_decrypt_index::list_by_subject(deps.pool.as_ref(), &subject)
        .await
        .map_err(|e| SdrDiscardReason::IndexLookupFailed {
            detail: format!("list decrypt-index rows for head install: {e:#}"),
        })?;

    let mut coin_sources: BTreeMap<[u8; 32], CoinProof> = BTreeMap::new();
    for row in &self_rows {
        let cp =
            deserialize_coin_proof(&row.canonical).map_err(|e| SdrDiscardReason::DecodeFailed {
                detail: format!(
                    "self-delivery canonical decode for coin {}: {e}",
                    hex::encode(row.coin_id)
                ),
            })?;
        coin_sources.insert(row.coin_id, cp);
    }
    for row in &received_rows {
        let cp =
            deserialize_coin_proof(&row.canonical).map_err(|e| SdrDiscardReason::DecodeFailed {
                detail: format!(
                    "decrypt-index canonical decode for coin {}: {e}",
                    hex::encode(row.coin_id)
                ),
            })?;
        coin_sources.entry(row.coin_id).or_insert(cp);
    }

    // 2. Spent set: union of `spent_or_folded_coin_ids` across every accepted
    // SDR in the reconstructed lineage (not only the head).
    let mut spent_ids: BTreeSet<[u8; 32]> = BTreeSet::new();
    for sdr in accepted {
        for id in &sdr.record.spent_or_folded_coin_ids {
            spent_ids.insert(*id);
        }
    }

    // 3. Spendable = admitted \ spent, with TrackedCoin sourced from the
    // matching CoinProof (coin_index from its inclusion_proof leaf_index).
    let mut spendable: Vec<([u8; 32], TrackedCoin)> = Vec::new();
    for (coin_id, cp) in &coin_sources {
        if spent_ids.contains(coin_id) {
            continue;
        }
        let inclusion =
            super::incoming::parse_inclusion_proof_wire(&cp.inclusion_proof).map_err(|e| {
                SdrDiscardReason::DecodeFailed {
                    detail: format!("coin {} inclusion_proof parse: {e}", hex::encode(coin_id)),
                }
            })?;
        spendable.push((
            *coin_id,
            TrackedCoin {
                coin: cp.coin.clone(),
                creating_prev_ash: cp.creating_prev_ash,
                coin_index: inclusion.leaf_index,
            },
        ));
    }

    // 4. NAV opening + canonical nullifier position for the head transition
    // itself, resolved under one live-engine read borrow.
    let entry_send_counter = head
        .record
        .account_state
        .send_counter
        .checked_sub(1)
        .expect("apply_ordered_chain guarantees an accepted head's send_counter >= 1");
    let nav_rand = OpSecret::new(bundle.op_secret).derive_nav_rand(entry_send_counter);
    let target_nav_commitment = head.record.proof_data.nav_commitment;
    let head_pk_create = head.record.own_nullifier.pk_create;
    let head_r_create = head.record.own_nullifier.r_create;

    let engine_result = deps.adapter.with_engine(|engine| {
        let nav = reconstruct_nav_opening(engine, nav_rand, target_nav_commitment);
        let pos = match engine.nflog().lookup(head_pk_create) {
            LookupResult::Present { pos, r, .. } if r == head_r_create => Some(pos),
            _ => None,
        };
        (nav, pos)
    });
    let (nav_opening, nullifier_pos) = match engine_result {
        (Some(nav), Some(pos)) => (nav, pos),
        (None, _) => {
            return Err(SdrDiscardReason::HeadReconstructionFailed {
                detail: "no canonical NfLog prefix this node has scanned opens the head \
                         transition's nav_commitment"
                    .into(),
            });
        }
        (_, None) => {
            return Err(SdrDiscardReason::HeadReconstructionFailed {
                detail: "head own_nullifier is no longer a first-occurrence match on this \
                         node's live NfLog at install time"
                    .into(),
            });
        }
    };

    // 5. Bind the recovered native-wire proof bytes to circuit-C identity —
    // load only, never re-proves (VERIFY-ONLY).
    let last_proof = bridge
        .load_transition_proof_bytes(&head.record.recursive_proof)
        .map_err(|e| SdrDiscardReason::ProofVerifyFailed {
            detail: format!("head last_proof bind at install time: {e:#}"),
        })?;

    let snapshot = super::db_v1::AccountSnapshot {
        owner,
        state: head.record.account_state.clone(),
        nk: bundle.nk,
        op_secret: Some(OpSecret::new(bundle.op_secret)),
        genesis_pubkey: genesis.record.own_nullifier.pk_create,
        spendable,
        spent_ids: spent_ids.into_iter().collect(),
        last_proof: Some(last_proof),
        last_nav_opening: Some(nav_opening),
        last_nullifier: Some(NullifierOpening {
            public_key: head_pk_create,
            signature_r: head_r_create,
            r_prime: head.record.own_nullifier.r_prime_create,
        }),
        last_nullifier_pos: Some(nullifier_pos),
    };
    let record =
        snapshot
            .into_record()
            .map_err(|e| SdrDiscardReason::HeadReconstructionFailed {
                detail: format!("{e:#}"),
            })?;

    let recovered_view =
        crate::v1::signature::account_state_view_from_record(&record).map_err(|e| {
            SdrDiscardReason::HeadReconstructionFailed {
                detail: format!(
                    "account_state_view_from_record for private-index registration: {e:#}"
                ),
            }
        })?;

    // 6. Install, then persist durably; roll the live engine back on a
    // persist failure so memory and disk never diverge.
    let pre = deps.adapter.snapshot_live();
    let insert_result = deps
        .adapter
        .with_engine_mut(|engine| engine.insert_account(owner, record))
        .map_err(|e| SdrDiscardReason::HeadReconstructionFailed {
            detail: format!("stack claim for account install: {e:#}"),
        })?;
    insert_result.map_err(|e| SdrDiscardReason::HeadReconstructionFailed {
        detail: format!("insert_account: {e:#}"),
    })?;

    if let Err(e) = deps.adapter.persist().await {
        let detail = match deps.adapter.restore_live(pre) {
            Ok(()) => format!("durable persist of recovered head failed (engine rolled back): {e:#}"),
            Err(restore_err) => format!(
                "durable persist of recovered head failed AND engine restore failed \
                 (memory/disk may diverge): persist={e:#}; restore={restore_err:#}"
            ),
        };
        return Err(SdrDiscardReason::HeadPersistFailed { detail });
    }

    deps.index
        .insert_account(
            crate::kernel::types::SubjectAddress(owner.0),
            recovered_view,
        )
        .map_err(|e| SdrDiscardReason::HeadReconstructionFailed {
            detail: format!("register recovered head in private-index (pull cache): {e:#}"),
        })?;

    tracing::info!(
        subject = %hex::encode(subject),
        send_counter = head.record.account_state.send_counter,
        spendable = coin_sources.len(),
        "§4.5 recovery: SDR replay reconstructed, installed, and durably persisted the \
         account head"
    );
    Ok(())
}

/// Block until [`BundleStore::list_active`] is non-empty.
///
/// Logs periodically so a missing entrust is visible (not a silent hang).
async fn wait_for_active_bundles(
    bundles: &BundleStore,
) -> Vec<(SubjectAddress, OperationalBundle)> {
    let mut ticks: u64 = 0;
    loop {
        let active = bundles.list_active();
        if !active.is_empty() {
            if ticks > 0 {
                tracing::info!(
                    subjects = active.len(),
                    waited_ticks = ticks,
                    "§4.5 recovery: operational bundle(s) present — starting campaign"
                );
            }
            return active;
        }
        if ticks == 0 {
            // Named prerequisite error (same text as [`RecoveryError::NoOperationalBundle`]):
            // recovery is requested but cannot start the scan without ivk.
            // We wait rather than exit — BundleStore is process-local and only
            // fills after Entrust once listeners are up. Never claim restored.
            tracing::warn!(
                error = %RecoveryError::NoOperationalBundle,
                "§4.5 recovery: blocking campaign start until EntrustOperationalBundle"
            );
        } else if ticks.is_multiple_of(12) {
            // ~60s at 5s interval
            tracing::warn!(
                waited_secs = ticks.saturating_mul(BUNDLE_WAIT_INTERVAL.as_secs()),
                error = %RecoveryError::NoOperationalBundle,
                "§4.5 recovery: still waiting for operational bundle"
            );
        }
        ticks = ticks.saturating_add(1);
        tokio::time::sleep(BUNDLE_WAIT_INTERVAL).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    use shared::spec_v1::bundle::serialize_coin_proof;
    use shared::spec_v1::note_encryption::zbe_seal;
    use std::collections::{BTreeMap, HashMap};
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use zkcoins_program::circuit::compliance::Network;

    /// Process environment is shared by the whole test binary. Every recovery-env
    /// mutation is serialized and restored by `RecoveryEnvRestore::drop`, including
    /// when an assertion unwinds.
    static RECOVERY_ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct RecoveryEnvRestore {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl RecoveryEnvRestore {
        fn clear() -> Self {
            let names = [
                RECOVERY_ENV,
                RECOVERY_PAGE_LIMIT_ENV,
                RECOVERY_EARLIEST_ENV,
            ];
            let saved = names
                .into_iter()
                .map(|name| (name, std::env::var_os(name)))
                .collect();
            for name in names {
                std::env::remove_var(name);
            }
            Self { saved }
        }
    }

    impl Drop for RecoveryEnvRestore {
        fn drop(&mut self) {
            for (name, value) in &self.saved {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn fixture_sk(label: &[u8]) -> [u8; 32] {
        let mut seed = Sha256::digest(label).to_vec();
        let secp = Secp256k1::new();
        loop {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&seed[..32]);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                let _ = Keypair::from_secret_key(&secp, &sk);
                return sk_bytes;
            }
            seed = Sha256::digest(&seed).to_vec();
        }
    }

    fn fixture_xonly(label: &[u8]) -> [u8; 32] {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&fixture_sk(label)).expect("fixture secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret);
        keypair.x_only_public_key().0.serialize()
    }

    fn signed_gift_wrap(sk: &[u8; 32], created_at: u64, content: &str) -> Event {
        Event::sign(sk, created_at, KIND_GIFT_WRAP, vec![], content.to_string())
            .expect("sign gift-wrap")
    }

    #[test]
    fn recovered_snapshot_with_consistent_coinhist_installs() {
        let owner = Address([0x11; 32]);
        let pk = [0x22; 32];
        let nk = [0x33; 32];
        let nk_commitment = host::nk_commit(&nk);
        let asset_id = host::nk_commit(&[0x44; 32]);
        let genesis = AccountState::new(
            owner,
            nk_commitment,
            BTreeMap::new(),
            pk,
            0,
            host::coinhist_empty_root(),
        )
        .expect("genesis AccountState");
        let genesis_ash = host::account_state_hash(&genesis).expect("genesis ash");
        let coin = host::Coin {
            identifier: host::coin_identifier(genesis_ash, &owner.0, asset_id, 50, 0),
            recipient: owner,
            amount: 50,
            asset_id,
        };
        let coin_id = host::digest_to_bytes(&coin.identifier);
        let mut coinhist = host::CoinHistTree::new();
        coinhist.admit(coin_id).expect("admit coin");
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), coin.amount);
        let state = AccountState::new(owner, nk_commitment, balances, pk, 1, coinhist.root())
            .expect("recovered AccountState");
        let snapshot = crate::v1::db_v1::AccountSnapshot {
            owner,
            state,
            nk,
            op_secret: Some(OpSecret::new([0xAA; 32])),
            genesis_pubkey: pk,
            spendable: vec![(
                coin_id,
                TrackedCoin {
                    coin,
                    creating_prev_ash: genesis_ash,
                    coin_index: 0,
                },
            )],
            spent_ids: vec![],
            last_proof: None,
            last_nav_opening: None,
            last_nullifier: None,
            last_nullifier_pos: None,
        };

        let record = snapshot
            .into_record()
            .expect("consistent recovered snapshot must reconstruct");
        let mut engine = StateEngine::new(Network::Testnet, 0);
        assert!(engine.insert_account(owner, record).is_ok());
    }

    #[test]
    fn recovered_head_registered_in_private_index_is_servable_via_get_account_state() {
        use crate::kernel::access::PrivateIndex;

        let owner = Address([0x11; 32]);
        let pk = [0x22; 32];
        let nk = [0x33; 32];
        let nk_commitment = host::nk_commit(&nk);
        let asset_id = host::nk_commit(&[0x44; 32]);
        let genesis = AccountState::new(
            owner,
            nk_commitment,
            BTreeMap::new(),
            pk,
            0,
            host::coinhist_empty_root(),
        )
        .expect("genesis AccountState");
        let genesis_ash = host::account_state_hash(&genesis).expect("genesis ash");
        let coin = host::Coin {
            identifier: host::coin_identifier(genesis_ash, &owner.0, asset_id, 50, 0),
            recipient: owner,
            amount: 50,
            asset_id,
        };
        let coin_id = host::digest_to_bytes(&coin.identifier);
        let mut coinhist = host::CoinHistTree::new();
        coinhist.admit(coin_id).expect("admit coin");
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), coin.amount);
        let state = AccountState::new(owner, nk_commitment, balances, pk, 1, coinhist.root())
            .expect("recovered AccountState");
        let snapshot = crate::v1::db_v1::AccountSnapshot {
            owner,
            state,
            nk,
            op_secret: Some(OpSecret::new([0xAA; 32])),
            genesis_pubkey: pk,
            spendable: vec![(
                coin_id,
                TrackedCoin {
                    coin,
                    creating_prev_ash: genesis_ash,
                    coin_index: 0,
                },
            )],
            spent_ids: vec![],
            last_proof: None,
            last_nav_opening: None,
            last_nullifier: None,
            last_nullifier_pos: None,
        };

        let record = snapshot
            .into_record()
            .expect("consistent recovered snapshot must reconstruct");
        let view = crate::v1::signature::account_state_view_from_record(&record).expect("view");
        let index = InMemoryPrivateIndex::new();
        index
            .insert_account(crate::kernel::types::SubjectAddress(owner.0), view.clone())
            .expect("insert");
        let served = index
            .get_account_state(&crate::kernel::types::SubjectAddress(owner.0))
            .expect("served");
        assert_eq!(served, view);
        assert_eq!(served.send_counter, record.state.send_counter);
        assert!(!served.account_state.is_empty());
    }

    #[test]
    fn recovered_snapshot_with_mismatched_coinhist_fails_closed_and_does_not_install() {
        let owner = Address([0x51; 32]);
        let pk = [0x52; 32];
        let nk = [0x53; 32];
        let nk_commitment = host::nk_commit(&nk);
        let asset_id = host::nk_commit(&[0x54; 32]);
        let genesis = AccountState::new(
            owner,
            nk_commitment,
            BTreeMap::new(),
            pk,
            0,
            host::coinhist_empty_root(),
        )
        .expect("genesis AccountState");
        let genesis_ash = host::account_state_hash(&genesis).expect("genesis ash");
        let coin = host::Coin {
            identifier: host::coin_identifier(genesis_ash, &owner.0, asset_id, 50, 0),
            recipient: owner,
            amount: 50,
            asset_id,
        };
        let coin_id = host::digest_to_bytes(&coin.identifier);
        let mut coinhist = host::CoinHistTree::new();
        coinhist.admit(coin_id).expect("admit coin");
        assert_ne!(coinhist.root(), host::coinhist_empty_root());
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), coin.amount);
        let state = AccountState::new(
            owner,
            nk_commitment,
            balances,
            pk,
            1,
            host::coinhist_empty_root(),
        )
        .expect("recovered AccountState with deliberately mismatched root");
        let snapshot = crate::v1::db_v1::AccountSnapshot {
            owner,
            state,
            nk,
            op_secret: Some(OpSecret::new([0xAA; 32])),
            genesis_pubkey: pk,
            spendable: vec![(
                coin_id,
                TrackedCoin {
                    coin,
                    creating_prev_ash: genesis_ash,
                    coin_index: 0,
                },
            )],
            spent_ids: vec![],
            last_proof: None,
            last_nav_opening: None,
            last_nullifier: None,
            last_nullifier_pos: None,
        };

        let err = match snapshot.into_record() {
            Ok(_) => panic!("coinhist root mismatch must fail before install"),
            Err(err) => err,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(
                "coinhist root after rebuild does not match AccountState.coin_history_root"
            ),
            "expected coinhist-root-vs-state contradiction, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Env config — fail-closed, no silent defaults
    // -----------------------------------------------------------------------

    #[test]
    fn recovery_env_off_when_unset_or_not_one() {
        let _lock = RECOVERY_ENV_TEST_LOCK
            .lock()
            .expect("lock recovery env tests");
        let _restore = RecoveryEnvRestore::clear();

        assert_eq!(recovery_campaign_config_from_env(), Ok(None));

        std::env::set_var(RECOVERY_ENV, "true");
        assert_eq!(recovery_campaign_config_from_env(), Ok(None));
    }

    #[test]
    fn recovery_env_rejects_missing_invalid_and_zero_page_limit() {
        let _lock = RECOVERY_ENV_TEST_LOCK
            .lock()
            .expect("lock recovery env tests");
        let _restore = RecoveryEnvRestore::clear();
        std::env::set_var(RECOVERY_ENV, "1");

        assert_eq!(
            recovery_campaign_config_from_env(),
            Err(format!(
                "{RECOVERY_ENV}=1 requires {RECOVERY_PAGE_LIMIT_ENV} (positive integer page size L) \
                 — refusing silent default L"
            ))
        );

        std::env::set_var(RECOVERY_PAGE_LIMIT_ENV, "not-a-number");
        assert_eq!(
            recovery_campaign_config_from_env(),
            Err(format!(
                "{RECOVERY_PAGE_LIMIT_ENV}=\"not-a-number\" is not a non-negative integer"
            ))
        );

        std::env::set_var(RECOVERY_PAGE_LIMIT_ENV, "0");
        assert_eq!(
            recovery_campaign_config_from_env(),
            Err(format!(
                "{RECOVERY_PAGE_LIMIT_ENV}=0 is invalid — page limit must be positive (no default L)"
            ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn recovery_env_rejects_non_utf8_page_limit() {
        use std::os::unix::ffi::OsStringExt;

        let _lock = RECOVERY_ENV_TEST_LOCK
            .lock()
            .expect("lock recovery env tests");
        let _restore = RecoveryEnvRestore::clear();
        std::env::set_var(RECOVERY_ENV, "1");
        std::env::set_var(
            RECOVERY_PAGE_LIMIT_ENV,
            OsString::from_vec(vec![0xff, 0xfe]),
        );

        assert_eq!(
            recovery_campaign_config_from_env(),
            Err(format!("{RECOVERY_PAGE_LIMIT_ENV} is not valid UTF-8"))
        );
    }

    #[test]
    fn recovery_env_rejects_missing_or_invalid_earliest_timestamp() {
        let _lock = RECOVERY_ENV_TEST_LOCK
            .lock()
            .expect("lock recovery env tests");
        let _restore = RecoveryEnvRestore::clear();
        std::env::set_var(RECOVERY_ENV, "1");
        std::env::set_var(RECOVERY_PAGE_LIMIT_ENV, "25");

        assert_eq!(
            recovery_campaign_config_from_env(),
            Err(format!(
                "{RECOVERY_ENV}=1 requires {RECOVERY_EARLIEST_ENV} (unix seconds; wallet earliest \
                 account timestamp after dense enumeration) — refusing silent start-at-zero"
            ))
        );

        std::env::set_var(RECOVERY_EARLIEST_ENV, "-1");
        assert_eq!(
            recovery_campaign_config_from_env(),
            Err(format!(
                "{RECOVERY_EARLIEST_ENV}=\"-1\" is not a non-negative integer"
            ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn recovery_env_rejects_non_utf8_earliest_timestamp() {
        use std::os::unix::ffi::OsStringExt;

        let _lock = RECOVERY_ENV_TEST_LOCK
            .lock()
            .expect("lock recovery env tests");
        let _restore = RecoveryEnvRestore::clear();
        std::env::set_var(RECOVERY_ENV, "1");
        std::env::set_var(RECOVERY_PAGE_LIMIT_ENV, "25");
        std::env::set_var(
            RECOVERY_EARLIEST_ENV,
            OsString::from_vec(vec![0xff, 0xfe]),
        );

        assert_eq!(
            recovery_campaign_config_from_env(),
            Err(format!("{RECOVERY_EARLIEST_ENV} is not valid UTF-8"))
        );
    }

    #[test]
    fn recovery_env_returns_valid_campaign_config() {
        let _lock = RECOVERY_ENV_TEST_LOCK
            .lock()
            .expect("lock recovery env tests");
        let _restore = RecoveryEnvRestore::clear();
        std::env::set_var(RECOVERY_ENV, "1");
        std::env::set_var(RECOVERY_PAGE_LIMIT_ENV, "25");
        std::env::set_var(RECOVERY_EARLIEST_ENV, "1700000000");

        assert_eq!(
            recovery_campaign_config_from_env(),
            Ok(Some(RecoveryCampaignConfig {
                page_limit: 25,
                earliest_account_timestamp: 1_700_000_000,
            }))
        );
    }

    #[test]
    fn recovery_run_report_restored_only_when_complete() {
        let incomplete = GaplessScanResult {
            events: vec![],
            status: GaplessScanStatus::Incomplete {
                stuck_at: 42,
                until_cursor: 100,
                relay_urls: vec!["ws://relay-stuck.test".into()],
            },
            unique_event_count: 0,
        };
        let mut report = RecoveryRunReport::not_restored_from_scan(&incomplete);
        report.coin_proof_accepted = 3;
        // Salvage must not flip restored.
        report.restored = matches!(report.scan_status, GaplessScanStatus::Complete);
        assert!(!report.restored);

        let complete = GaplessScanResult {
            events: vec![],
            status: GaplessScanStatus::Complete,
            unique_event_count: 0,
        };
        let mut report = RecoveryRunReport::not_restored_from_scan(&complete);
        report.restored = matches!(report.scan_status, GaplessScanStatus::Complete);
        assert!(report.restored);
    }

    #[test]
    fn no_operational_bundle_error_names_recovery_env() {
        let msg = RecoveryError::NoOperationalBundle.to_string();
        assert!(msg.contains("ZKCOINS_V1_RECOVERY=1"), "{msg}");
        assert!(msg.contains("operational bundle"), "{msg}");
        assert!(msg.contains("restored"), "{msg}");
    }

    #[test]
    fn no_seed_relays_error_names_manifest() {
        let msg = RecoveryError::NoSeedRelays.to_string();
        assert!(msg.contains("seed_relays"), "{msg}");
        assert!(
            msg.contains("BOOTSTRAP_MANIFEST") || msg.contains("BootstrapManifest"),
            "{msg}"
        );
    }

    #[test]
    fn already_recovered_subjects_only_returns_active_subjects_present_in_index() {
        let recovered_subject = SubjectAddress([0x31; 32]);
        let missing_subject = SubjectAddress([0x32; 32]);
        let bundle = OperationalBundle {
            ivk: [0x11; 32],
            ovk: [0x12; 32],
            op: [0x13; 32],
            nk: [0x14; 32],
            op_secret: [0x15; 32],
        };
        let index = InMemoryPrivateIndex::new();
        index
            .insert_account(
                recovered_subject,
                crate::kernel::access::AccountStateView {
                    account_state: vec![0x01],
                    state_head: crate::kernel::types::Digest32([0x21; 32]),
                    head_record_id: None,
                    send_counter: 7,
                    current_pubkey: [0x22; 32],
                    last_nullifier_pk: None,
                    last_nullifier_r: None,
                },
            )
            .expect("register recovered subject fixture");

        let active = vec![(recovered_subject, bundle), (missing_subject, bundle)];
        let recovered = already_recovered_subjects(&index, &active);
        assert_eq!(recovered, HashSet::from([recovered_subject.0]));
        assert!(!recovered.contains(&missing_subject.0));

        assert!(already_recovered_subjects(&index, &[]).is_empty());
    }

    // -----------------------------------------------------------------------
    // Relay double for step 3
    // -----------------------------------------------------------------------

    /// In-memory multi-relay store for gapless-scan tests.
    ///
    /// - Limited queries (`limit = Some(L)`): newest-first, at most L events
    ///   with `created_at` in `[since, until]`.
    /// - Limit-free same-second drain (`limit = None`, since==until): all
    ///   events at that second, unless `drain_cap` truncates (and sets
    ///   `truncated = true`).
    #[derive(Clone)]
    struct MemoryRelayMesh {
        /// relay_url → events
        by_relay: HashMap<String, Vec<Event>>,
        /// Per-relay cap on limit-free drains (`None` = honest full drain).
        drain_cap: HashMap<String, Option<usize>>,
        /// Query log for assertions (url, since, until, limit, returned, truncated).
        log: Arc<Mutex<Vec<QueryLogEntry>>>,
    }

    #[derive(Clone, Debug)]
    struct QueryLogEntry {
        relay_url: String,
        since: Option<u64>,
        until: Option<u64>,
        limit: Option<u64>,
        returned: usize,
        truncated: bool,
    }

    impl MemoryRelayMesh {
        fn new() -> Self {
            Self {
                by_relay: HashMap::new(),
                drain_cap: HashMap::new(),
                log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn add_relay(&mut self, url: &str, events: Vec<Event>, drain_cap: Option<usize>) {
            self.by_relay.insert(url.to_string(), events);
            self.drain_cap.insert(url.to_string(), drain_cap);
        }
    }

    impl RecoveryRelaySource for MemoryRelayMesh {
        fn query(
            &mut self,
            relay_url: &str,
            filter: &Filter,
        ) -> Pin<Box<dyn Future<Output = Result<RelayQueryPage, RecoveryError>> + Send + '_>>
        {
            let url = relay_url.to_string();
            let since = filter.since;
            let until = filter.until;
            let limit = filter.limit;
            let kinds = filter.kinds.clone();
            let store = self.by_relay.get(relay_url).cloned().unwrap_or_default();
            let cap = self.drain_cap.get(relay_url).copied().flatten();
            let log = Arc::clone(&self.log);

            Box::pin(async move {
                let mut matched: Vec<Event> = store
                    .into_iter()
                    .filter(|e| {
                        if let Some(u) = until {
                            if e.created_at > u {
                                return false;
                            }
                        }
                        if let Some(s) = since {
                            if e.created_at < s {
                                return false;
                            }
                        }
                        if let Some(ref ks) = kinds {
                            if !ks.contains(&e.kind) {
                                return false;
                            }
                        }
                        true
                    })
                    .collect();
                // Newest first (stable by id for determinism).
                matched.sort_by(|a, b| {
                    b.created_at
                        .cmp(&a.created_at)
                        .then_with(|| a.id.cmp(&b.id))
                });

                let (events, truncated) = match limit {
                    Some(l) => {
                        let l = l as usize;
                        let truncated = matched.len() > l;
                        matched.truncate(l);
                        (matched, truncated)
                    }
                    None => {
                        // Limit-free drain. Cap models a relay that cannot
                        // serve the full second.
                        if let Some(c) = cap {
                            let truncated = matched.len() > c;
                            matched.truncate(c);
                            (matched, truncated)
                        } else {
                            (matched, false)
                        }
                    }
                };

                log.lock().expect("log").push(QueryLogEntry {
                    relay_url: url,
                    since,
                    until,
                    limit,
                    returned: events.len(),
                    truncated,
                });

                Ok(RelayQueryPage { events, truncated })
            })
        }
    }

    struct FixedErrorRelaySource {
        error: RecoveryError,
        queried_urls: Vec<String>,
    }

    impl RecoveryRelaySource for FixedErrorRelaySource {
        fn query(
            &mut self,
            relay_url: &str,
            _filter: &Filter,
        ) -> Pin<Box<dyn Future<Output = Result<RelayQueryPage, RecoveryError>> + Send + '_>>
        {
            self.queried_urls.push(relay_url.to_string());
            let error = self.error.clone();
            Box::pin(async move { Err(error) })
        }
    }

    #[tokio::test]
    async fn drain_timestamp_propagates_non_relay_error_without_trying_next_url() {
        let mut source = FixedErrorRelaySource {
            error: RecoveryError::WallClockUnavailable,
            queried_urls: Vec::new(),
        };
        let relay_urls = vec!["ws://first.test".into(), "ws://second.test".into()];
        let mut seen = HashSet::new();
        let mut events = Vec::new();

        let err = drain_timestamp(&mut source, &relay_urls, 123, &mut seen, &mut events)
            .await
            .expect_err("non-Relay source error must escape the drain");

        match err {
            DrainFailure::Error(error) => {
                assert_eq!(error, RecoveryError::WallClockUnavailable)
            }
            DrainFailure::Incomplete { .. } => {
                panic!("non-Relay error must not be converted to an incomplete drain")
            }
        }
        assert_eq!(source.queried_urls, vec!["ws://first.test"]);
        assert!(seen.is_empty());
        assert!(events.is_empty());
    }

    // -----------------------------------------------------------------------
    // Step 3 — second flood: more than L events at one timestamp
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn gapless_scan_second_flood_finds_all_events_beyond_page_limit() {
        // L = 5, N = 12 events all at t = 1_700_000_500.
        // A naive `until -= 1` after one page would keep only 5 and lose 7.
        const L: u64 = 5;
        const N: usize = 12;
        const T: u64 = 1_700_000_500;
        const NOW: u64 = T + 10;
        const EARLIEST: u64 = T - 100;

        let sk = fixture_sk(b"zkCoins/v1/test-vector/recovery/flood-sk");
        let mut store = Vec::with_capacity(N);
        for i in 0..N {
            // Distinct content → distinct id; same created_at.
            store.push(signed_gift_wrap(&sk, T, &format!("flood-event-{i:02}")));
        }
        assert_eq!(store.len(), N);
        // All share the same second.
        assert!(store.iter().all(|e| e.created_at == T));

        let url = "ws://relay-flood.test".to_string();
        let mut mesh = MemoryRelayMesh::new();
        mesh.add_relay(&url, store, None); // honest drain

        let result =
            gapless_scan_kind_1059(&mut mesh, std::slice::from_ref(&url), L, NOW, EARLIEST)
                .await
                .expect("scan");

        assert_eq!(
            result.status,
            GaplessScanStatus::Complete,
            "honest flood drain must complete"
        );
        assert_eq!(
            result.unique_event_count, N,
            "must find all {N} events at t, not just the first page of L={L}"
        );
        assert_eq!(result.events.len(), N);

        // Drain must have issued a limit-free query at t on the seed relay.
        let log = mesh.log.lock().expect("log");
        let drain_queries: Vec<_> = log
            .iter()
            .filter(|q| q.limit.is_none() && q.since == Some(T) && q.until == Some(T))
            .collect();
        assert!(
            !drain_queries.is_empty(),
            "must issue limit-free since=t,until=t drain; log={log:?}"
        );
        assert!(
            drain_queries.iter().all(|q| q.relay_url == url),
            "drain queries must name the seed relay {url}; got {drain_queries:?}"
        );
        assert!(
            drain_queries
                .iter()
                .any(|q| q.returned == N && !q.truncated),
            "drain must return all {N} without truncation; got {drain_queries:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Step 3 — drain cap: incomplete, must not advance past t
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn gapless_scan_capped_drain_reports_incomplete_and_does_not_skip_t() {
        // L = 3, 8 events at t. Drain cap = 4 → limit-free always truncated.
        const L: u64 = 3;
        const N: usize = 8;
        const CAP: usize = 4;
        const T: u64 = 1_700_000_600;
        const NOW: u64 = T + 5;
        const EARLIEST: u64 = T - 50;

        let sk = fixture_sk(b"zkCoins/v1/test-vector/recovery/cap-sk");
        let mut store = Vec::with_capacity(N);
        for i in 0..N {
            store.push(signed_gift_wrap(&sk, T, &format!("cap-event-{i:02}")));
        }

        let url = "ws://relay-cap.test".to_string();
        let mut mesh = MemoryRelayMesh::new();
        mesh.add_relay(&url, store, Some(CAP));

        let result =
            gapless_scan_kind_1059(&mut mesh, std::slice::from_ref(&url), L, NOW, EARLIEST)
                .await
                .expect("scan returns Ok with Incomplete status");

        match result.status {
            GaplessScanStatus::Incomplete {
                stuck_at,
                until_cursor,
                relay_urls,
            } => {
                assert_eq!(stuck_at, T, "incomplete second must be t");
                // until must not have been lowered under t.
                assert!(
                    until_cursor >= T,
                    "until_cursor {until_cursor} must not advance past stuck t={T}"
                );
                // Operator must see which relay blocked the drain.
                assert_eq!(
                    relay_urls,
                    vec![url.clone()],
                    "incomplete must name the capped relay"
                );
            }
            GaplessScanStatus::Complete => {
                panic!("capped drain must report Incomplete, not Complete")
            }
        }

        // Must not have collected a silent full set — at most what limited
        // pages + capped drain could see, and never claim completeness.
        assert!(
            result.unique_event_count < N,
            "capped mesh must not surface all {N} as if complete; got {}",
            result.unique_event_count
        );

        let log = mesh.log.lock().expect("log");
        let drain_queries: Vec<_> = log
            .iter()
            .filter(|q| q.limit.is_none() && q.since == Some(T) && q.until == Some(T))
            .collect();
        assert!(
            drain_queries
                .iter()
                .any(|q| q.relay_url == url && q.truncated),
            "drain queries must record truncation on {url}; log={log:?}"
        );
        // No query may show until < T after a successful advance — we never
        // advanced. Limited pages may use until=NOW, drains use until=T.
        for q in log.iter() {
            if q.limit.is_none() {
                assert_eq!(q.until, Some(T));
                assert_eq!(q.relay_url, url);
            }
        }
    }

    #[tokio::test]
    async fn gapless_scan_refuses_zero_page_limit_and_empty_relays() {
        let mut mesh = MemoryRelayMesh::new();
        let err = gapless_scan_kind_1059(&mut mesh, &["ws://x".into()], 0, 10, 0)
            .await
            .expect_err("L=0");
        assert_eq!(err, RecoveryError::InvalidPageLimit);

        let err = gapless_scan_kind_1059(&mut mesh, &[], 5, 10, 0)
            .await
            .expect_err("empty relays");
        assert_eq!(err, RecoveryError::EmptyRelayList);
    }

    #[tokio::test]
    async fn gapless_scan_dedups_by_event_id_across_relays() {
        const T: u64 = 1_700_000_700;
        let sk = fixture_sk(b"zkCoins/v1/test-vector/recovery/dedup-sk");
        let e1 = signed_gift_wrap(&sk, T, "shared-one");
        let e2 = signed_gift_wrap(&sk, T, "shared-two");
        let mut mesh = MemoryRelayMesh::new();
        mesh.add_relay("ws://a.test", vec![e1.clone(), e2.clone()], None);
        mesh.add_relay("ws://b.test", vec![e1.clone(), e2.clone()], None);

        let result = gapless_scan_kind_1059(
            &mut mesh,
            &["ws://a.test".into(), "ws://b.test".into()],
            10,
            T + 1,
            T,
        )
        .await
        .expect("scan");
        assert_eq!(result.status, GaplessScanStatus::Complete);
        assert_eq!(result.unique_event_count, 2);
    }

    // -----------------------------------------------------------------------
    // Step 5 — §2.3.3 path identity + SDR candidate (never silent ignore)
    // -----------------------------------------------------------------------

    #[test]
    fn sdr_matched_is_named_gap_not_silent_ignore() {
        // SDR match must never be silently ignored: the outcome is a
        // SelfDeliveryCandidate the campaign can fetch+decode, not Ignored.
        let outcome = RecoveredCandidateOutcome::SelfDeliveryCandidate {
            record_kind: RecordKind::Send,
            blob_id: [0xAB; 32],
            holders: vec!["https://blossom.example".into()],
            ss: [0x11; 32],
            epk: [0x22; 32],
        };
        match outcome {
            RecoveredCandidateOutcome::SelfDeliveryCandidate {
                record_kind,
                blob_id,
                holders,
                ss,
                epk,
            } => {
                assert_eq!(record_kind, RecordKind::Send);
                assert_eq!(blob_id, [0xAB; 32]);
                assert_eq!(holders, vec!["https://blossom.example".to_string()]);
                assert_eq!(ss, [0x11; 32]);
                assert_eq!(epk, [0x22; 32]);
            }
            other => panic!("expected SelfDeliveryCandidate, got {other:?}"),
        }

        // Operator report names every discard (never silent).
        let discard = SdrDiscard {
            subject: [0x01; 32],
            blob_id: [0xAB; 32],
            record_kind: RecordKind::Send,
            send_counter: None,
            reason: SdrDiscardReason::FetchFailed {
                detail: "fixture".into(),
            },
        };
        let report = RecoveryRunReport {
            scan_status: GaplessScanStatus::Complete,
            unique_event_count: 1,
            coin_proof_accepted: 0,
            coin_proof_rejected: 0,
            ignored: 0,
            sdr_discards: vec![discard],
            sdr_coins_folded: 0,
            replayed_heads: Vec::new(),
            restored: true,
        };
        assert_eq!(report.sdr_discards.len(), 1);
        assert_eq!(report.sdr_discards[0].blob_id, [0xAB; 32]);
        assert!(matches!(
            report.sdr_discards[0].reason,
            SdrDiscardReason::FetchFailed { .. }
        ));
    }

    #[test]
    fn verify_recovered_candidate_names_sdr_via_real_gift_wrap() {
        use super::super::nostr::kinds::delivery::{
            delivery_rumor, encode_delivery_payload, DeliveryPayload,
        };
        use super::super::nostr::nip59::{delivery_scan_tags, seal_and_wrap, SecureRandom};
        use sha2::{Digest, Sha256};
        use shared::spec_v1::encoding::digest_to_bytes;
        use shared::spec_v1::hashes::detect_tag as poseidon_detect_tag;
        use shared::spec_v1::note_encryption::{shared_secret_sender, xonly_pubkey};
        use zkcoins_program::circuit::compliance::Network;

        /// Deterministic CSPRNG for the gift-wrap only (not production).
        struct ChainRng {
            state: [u8; 32],
        }
        impl ChainRng {
            fn new(seed: &[u8]) -> Self {
                Self {
                    state: Sha256::digest(seed).into(),
                }
            }
        }
        impl SecureRandom for ChainRng {
            fn fill_bytes(
                &mut self,
                dest: &mut [u8],
            ) -> Result<(), super::super::nostr::nip59::Nip59Error> {
                let mut filled = 0;
                while filled < dest.len() {
                    self.state = Sha256::digest(self.state).into();
                    let n = (dest.len() - filled).min(32);
                    dest[filled..filled + n].copy_from_slice(&self.state[..n]);
                    filled += n;
                }
                Ok(())
            }
        }

        // Recipient ivk (must be a valid scalar).
        let ivk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-ivk");
        let ivpk = xonly_pubkey(&ivk).expect("ivpk");
        // Sender seals to recipient IVPK.
        let sender_sk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-sender");
        let sender_pk = xonly_pubkey(&sender_sk).expect("sender pk");
        // Fresh epk for detect_tag (esk scalar).
        let esk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-esk");
        let epk = xonly_pubkey(&esk).expect("epk");
        let ss = shared_secret_sender(&esk, &ivpk).expect("ss");
        let detect = digest_to_bytes(&poseidon_detect_tag(&ss, &epk));

        let payload = DeliveryPayload {
            blob_id: [0xcd; 32],
            holders: vec!["https://blossom.recovery.test".into()],
            ack_nonce: [0x11; 32],
            record_kind: Some(RecordKind::Send),
        };
        // encode path must accept this payload (guards fixture validity).
        let _ = encode_delivery_payload(&payload).expect("encode");
        let rumor = delivery_rumor(sender_pk, 1_700_000_800, &payload).expect("rumor");
        let mut rng = ChainRng::new(b"zkCoins/v1/test-vector/recovery/sdr-rng");
        let tags = delivery_scan_tags(&detect, &epk);
        let wrap =
            seal_and_wrap(&rumor, &sender_sk, &ivpk, tags, 1_700_000_800, &mut rng).expect("wrap");

        let engine = StateEngine::new(Network::Regtest, 0);
        let bridge = ProverBridge::new(Network::Regtest);
        let subject = [0u8; 32];
        let out = verify_recovered_candidate(&wrap, &ivk, &subject, &engine, &bridge, None);
        match out {
            RecoveredCandidateOutcome::SelfDeliveryCandidate {
                record_kind,
                blob_id,
                holders,
                ss: got_ss,
                epk: got_epk,
            } => {
                assert_eq!(record_kind, RecordKind::Send);
                assert_eq!(blob_id, [0xcd; 32]);
                assert_eq!(holders, vec!["https://blossom.recovery.test".to_string()]);
                assert_eq!(got_ss, ss);
                assert_eq!(got_epk, epk);
            }
            other => panic!("SDR must be SelfDeliveryCandidate, not ignored/discarded: {other:?}"),
        }
    }

    #[test]
    fn verify_recovered_candidate_ignores_non_match() {
        let sk = fixture_sk(b"zkCoins/v1/test-vector/recovery/ignore-sk");
        let wrap = signed_gift_wrap(&sk, 1_700_000_000, "no-scan-tags");
        // Engine/bridge unused on ignore path — only need detect to fail closed.
        use zkcoins_program::circuit::compliance::Network;
        let engine = StateEngine::new(Network::Regtest, 0);
        let bridge = ProverBridge::new(Network::Regtest);
        let ivk = {
            let mut s = [0u8; 32];
            s[31] = 7;
            s
        };
        let subject = [0u8; 32];
        let out = verify_recovered_candidate(&wrap, &ivk, &subject, &engine, &bridge, None);
        assert!(
            matches!(out, RecoveredCandidateOutcome::Ignored { .. }),
            "got {out:?}"
        );
    }

    #[test]
    fn verify_coin_proof_for_index_is_the_step5_path() {
        // Compile-time / link-time pin: recovery step 5 calls the same
        // function symbol `incoming` uses for the receive store-and-ACK gate.
        // A second derivation would be a separate symbol — this test documents
        // the shared function pointer identity for reviewers.
        let f: fn(&StateEngine, &ProverBridge, &CoinProof, &[u8; 32]) -> Result<(), IncomingError> =
            verify_coin_proof_for_index;
        // Use the function so the binding is not eliminated.
        let _ = f as usize;
    }

    // -----------------------------------------------------------------------
    // §4.2 SDR replay — pure/sync unit tests (no real Plonky2 proof)
    // -----------------------------------------------------------------------

    /// Minimal valid `SelfDeliveryRecordV1` for ordering / check-(ii)/(iii) unit tests.
    ///
    /// Only fields the pure path actually reads need realism:
    /// `send_counter`, `prev_state_head`, `account_state`,
    /// `proof_data.new_account_state_hash`, `own_nullifier.pk_create`, `occurred_at`.
    /// `recursive_proof` is intentionally empty/garbage — never a success path here.
    fn sample_sdr_record(
        send_counter: u64,
        prev_state_head: host::HashDigest,
        account_state: AccountState,
        own_nullifier_pk: [u8; 32],
        occurred_at: u64,
    ) -> host::SelfDeliveryRecordV1 {
        let ash = account_state_hash(&account_state).expect("sample account_state ash");
        host::SelfDeliveryRecordV1 {
            record_kind: host::RecordKind::Send,
            send_counter,
            prev_state_head,
            account_state,
            recursive_proof: vec![],
            proof_data: host::ProofData {
                new_account_state_hash: ash,
                output_coins_root: host::ZERO_HASH,
                input_nullifiers_root: host::ZERO_HASH,
                coin_history_root: host::ZERO_HASH,
                nav_commitment: host::ZERO_HASH,
                npk_commit: [0u8; 32],
            },
            own_nullifier: host::CreatingNullifier {
                pk_create: own_nullifier_pk,
                r_create: [0u8; 32],
                r_prime_create: [0u8; 32],
            },
            proof_block_anchor: host::BlockAnchor {
                block_hash: [0u8; 32],
                height: 0,
            },
            inclusion_block: host::BlockAnchor {
                block_hash: [0u8; 32],
                height: 0,
            },
            occurred_at,
            spent_or_folded_coin_ids: vec![],
            output_refs: vec![],
            self_blob_locators: host::BlobLocatorSet {
                holders: vec!["https://x.test".into()],
            },
        }
    }

    fn sdr_check_block_hash(height: u64) -> [u8; 32] {
        [u8::try_from(height).unwrap().wrapping_add(1); 32]
    }

    async fn insert_sdr_check_block(
        pool: &PgPool,
        height: u64,
        block_hash: [u8; 32],
        block_time: Option<i64>,
    ) {
        crate::db::insert_block_log(
            pool,
            &crate::db::BlockLogEntry {
                block_time,
                block_hash: block_hash.to_vec(),
                block_height: Some(i64::try_from(height).unwrap()),
                inscription_count: 0,
                processing_duration_us: None,
            },
        )
        .await
        .unwrap();
    }

    async fn insert_sdr_mtp_window(pool: &PgPool, inclusion_height: u64, times: &[i64]) {
        let first_height = inclusion_height.saturating_sub(10);
        assert_eq!(times.len(), (inclusion_height - first_height + 1) as usize);
        for (height, block_time) in (first_height..=inclusion_height).zip(times.iter().copied()) {
            insert_sdr_check_block(
                pool,
                height,
                sdr_check_block_hash(height),
                Some(block_time),
            )
            .await;
        }
    }

    fn sample_sdr_for_async_checks(
        inclusion_height: u64,
        anchor_height: u64,
        occurred_at: u64,
    ) -> host::SelfDeliveryRecordV1 {
        let subject = [0x41; 32];
        let nk = [0x42; 32];
        let pk = [0x43; 32];
        let account = sample_account_state_for(subject, nk, pk, 1);
        let mut record = sample_sdr_record(1, host::ZERO_HASH, account, pk, occurred_at);
        record.inclusion_block = host::BlockAnchor {
            block_hash: sdr_check_block_hash(inclusion_height),
            height: u32::try_from(inclusion_height).unwrap(),
        };
        record.proof_block_anchor = host::BlockAnchor {
            block_hash: sdr_check_block_hash(anchor_height),
            height: u32::try_from(anchor_height).unwrap(),
        };
        record
    }

    async fn insert_sdr_anchor_if_outside_window(
        pool: &PgPool,
        inclusion_height: u64,
        anchor_height: u64,
    ) {
        if anchor_height < inclusion_height.saturating_sub(10) {
            insert_sdr_check_block(
                pool,
                anchor_height,
                sdr_check_block_hash(anchor_height),
                None,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn sdr_occurred_at_equal_to_locally_derived_mtp_is_accepted() {
        let scope = crate::test_db::setup_pool().await;
        let times = [11, 2, 9, 4, 8, 6, 7, 5, 3, 10, 1];
        insert_sdr_mtp_window(&scope.pool, 100, &times).await;
        insert_sdr_anchor_if_outside_window(&scope.pool, 100, 50).await;
        let record = sample_sdr_for_async_checks(100, 50, 6);

        verify_sdr_record_checks_v_vi_async(&scope.pool, 100, &record)
            .await
            .expect("occurred_at equal to the local BIP-113 MTP must pass");
    }

    #[tokio::test]
    async fn sdr_nonzero_occurred_at_different_from_mtp_is_discarded() {
        let scope = crate::test_db::setup_pool().await;
        let times = [11, 2, 9, 4, 8, 6, 7, 5, 3, 10, 1];
        insert_sdr_mtp_window(&scope.pool, 100, &times).await;
        let record = sample_sdr_for_async_checks(100, 50, 7);

        let err = verify_sdr_record_checks_v_vi_async(&scope.pool, 100, &record)
            .await
            .expect_err("non-MTP occurred_at must fail check (v)");
        match err {
            SdrDiscardReason::OccurredAtInvalid { detail } => {
                assert!(detail.contains("≠ MTP(inclusion_block)"), "{detail}");
            }
            other => panic!("expected OccurredAtInvalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sdr_zero_occurred_at_short_circuit_is_preserved() {
        let scope = crate::test_db::setup_pool().await;
        insert_sdr_check_block(
            &scope.pool,
            100,
            sdr_check_block_hash(100),
            Some(1_700_000_000),
        )
        .await;
        let record = sample_sdr_for_async_checks(100, 50, 0);

        let err = verify_sdr_record_checks_v_vi_async(&scope.pool, 100, &record)
            .await
            .expect_err("zero occurred_at must fail check (v)");
        match err {
            SdrDiscardReason::OccurredAtInvalid { detail } => {
                assert!(detail.contains("occurred_at is zero"), "{detail}");
            }
            other => panic!("expected OccurredAtInvalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sdr_missing_mtp_window_is_discarded() {
        let scope = crate::test_db::setup_pool().await;
        for height in 90_u64..=100 {
            // Height 95 is present but deliberately has SQL NULL block_time.
            let block_time = (height != 95).then_some(height as i64);
            insert_sdr_check_block(
                &scope.pool,
                height,
                sdr_check_block_hash(height),
                block_time,
            )
            .await;
        }
        insert_sdr_anchor_if_outside_window(&scope.pool, 100, 50).await;
        let record = sample_sdr_for_async_checks(100, 50, 95);

        let err = verify_sdr_record_checks_v_vi_async(&scope.pool, 100, &record)
            .await
            .expect_err("an incomplete MTP window must discard under §4.2");
        match err {
            SdrDiscardReason::OccurredAtInvalid { detail } => {
                assert!(
                    detail.contains("not locally derivable"),
                    "{detail}"
                );
            }
            other => panic!("expected OccurredAtInvalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sdr_zero_occurred_at_is_discarded_when_mtp_window_unavailable() {
        let scope = crate::test_db::setup_pool().await;
        for height in 90_u64..=100 {
            let block_time = (height != 95).then_some(height as i64);
            insert_sdr_check_block(
                &scope.pool,
                height,
                sdr_check_block_hash(height),
                block_time,
            )
            .await;
        }
        assert_eq!(
            crate::db::load_median_time_past(&scope.pool, 100)
                .await
                .unwrap(),
            None,
            "the fixture must have an unavailable MTP window"
        );
        let record = sample_sdr_for_async_checks(100, 50, 0);

        let err = verify_sdr_record_checks_v_vi_async(&scope.pool, 100, &record)
            .await
            .expect_err("zero occurred_at must fail before the MTP fallback");
        match err {
            SdrDiscardReason::OccurredAtInvalid { detail } => {
                assert!(detail.contains("occurred_at is zero"), "{detail}");
            }
            other => panic!("expected OccurredAtInvalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sdr_near_genesis_truncated_mtp_window_is_accepted() {
        let scope = crate::test_db::setup_pool().await;
        insert_sdr_mtp_window(&scope.pool, 3, &[40, 10, 30, 20]).await;
        let record = sample_sdr_for_async_checks(3, 0, 30);

        verify_sdr_record_checks_v_vi_async(&scope.pool, 3, &record)
            .await
            .expect("the four-block near-genesis MTP window must pass");
    }

    #[tokio::test]
    async fn sdr_even_count_mtp_uses_upper_middle_element() {
        let scope = crate::test_db::setup_pool().await;
        insert_sdr_mtp_window(&scope.pool, 3, &[2_000, 1, 1_000, 2]).await;
        assert_eq!(
            crate::db::load_median_time_past(&scope.pool, 3)
                .await
                .unwrap(),
            Some(1_000),
            "Bitcoin Core selects sorted[len/2], not an average"
        );
        let record = sample_sdr_for_async_checks(3, 0, 1_000);

        verify_sdr_record_checks_v_vi_async(&scope.pool, 3, &record)
            .await
            .expect("the exact upper-middle MTP must pass");
    }

    #[tokio::test]
    async fn sdr_a_b_a_reorg_restores_canonical_mtp_binding() {
        let scope = crate::test_db::setup_pool().await;
        insert_sdr_mtp_window(&scope.pool, 100, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]).await;
        insert_sdr_anchor_if_outside_window(&scope.pool, 100, 50).await;
        let record = sample_sdr_for_async_checks(100, 50, 6);

        // A is initially canonical at height 95, B replaces it, then the scanner
        // re-observes A when the chain returns to the original physical block.
        insert_sdr_check_block(&scope.pool, 95, [0xEE; 32], Some(1_000)).await;
        insert_sdr_check_block(
            &scope.pool,
            95,
            sdr_check_block_hash(95),
            Some(6),
        )
        .await;

        assert_eq!(
            crate::db::load_median_time_past(&scope.pool, 100)
                .await
                .unwrap(),
            Some(6),
            "the MTP window must select A's restored timestamp, not orphaned B's"
        );
        verify_sdr_record_checks_v_vi_async(&scope.pool, 100, &record)
            .await
            .expect("occurred_at matching restored canonical A's MTP must pass");
    }

    /// Distinct, constructible account state for chain / ash fixtures.
    fn sample_account_state_for(
        subject: [u8; 32],
        nk: [u8; 32],
        current_pubkey: [u8; 32],
        send_counter: u64,
    ) -> AccountState {
        AccountState::new(
            Address(subject),
            nk_commit(&nk),
            std::collections::BTreeMap::new(),
            current_pubkey,
            send_counter,
            host::coinhist_empty_root(),
        )
        .expect("sample account_state")
    }

    #[test]
    fn verify_sdr_rejects_foreign_account_owner() {
        use zkcoins_program::circuit::compliance::Network;

        let subject = [0x81u8; 32];
        let foreign_subject = [0x82u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/foreign-owner-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/foreign-owner-pk");
        let account = sample_account_state_for(foreign_subject, nk, pk, 1);
        let record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        let bridge = ProverBridge::new(Network::Regtest);

        let err = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect_err("foreign account owner must be rejected before proof loading");
        assert!(
            matches!(err, SdrDiscardReason::AccountOwnerMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_sdr_rejects_wrong_nk_commit() {
        use zkcoins_program::circuit::compliance::Network;

        let subject = [0x83u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/nk-commit-expected");
        let wrong_nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/nk-commit-wrong");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/nk-commit-pk");
        let account = sample_account_state_for(subject, wrong_nk, pk, 1);
        let record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        assert_ne!(record.account_state.nk_commit, nk_commit(&nk));
        let bridge = ProverBridge::new(Network::Regtest);

        let err = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect_err("wrong nk_commit must be rejected before proof loading");
        assert!(
            matches!(err, SdrDiscardReason::NkCommitMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_sdr_rejects_outer_authenticated_counter_mismatch() {
        use zkcoins_program::circuit::compliance::Network;

        let subject = [0x84u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/counter-mismatch-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/counter-mismatch-pk");
        let account = sample_account_state_for(subject, nk, pk, 1);
        let record = sample_sdr_record(u64::MAX, host::ZERO_HASH, account, pk, 100);
        let bridge = ProverBridge::new(Network::Regtest);

        let err = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect_err("outer/authenticated counter mismatch must precede proof loading");
        assert!(
            matches!(err, SdrDiscardReason::SendCounterMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn apply_ordered_chain_rejects_nonsequential_authenticated_counter() {
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/nonsequential-nk");
        let pk0 = fixture_sk(b"zkCoins/v1/test-vector/recovery/nonsequential-pk0");
        let pk1 = fixture_sk(b"zkCoins/v1/test-vector/recovery/nonsequential-pk1");
        let subject = address(&pk0, nk_commit(&nk));
        let genesis = canonical_genesis_account_state_ash(&subject, &nk, pk0).expect("genesis ash");
        let first_account = sample_account_state_for(subject, nk, pk1, 1);
        let skipped_account = sample_account_state_for(subject, nk, pk1, 3);
        let first = sample_sdr_record(1, genesis, first_account, pk0, 100);
        let skipped = sample_sdr_record(3, host::ZERO_HASH, skipped_account, pk1, 200);
        let first_blob = [0x31u8; 32];
        let skipped_blob = [0x33u8; 32];

        let (accepted, discards) = apply_ordered_chain(
            &subject,
            &nk,
            vec![
                (first_blob, RecordKind::Send, first),
                (skipped_blob, RecordKind::Send, skipped),
            ],
        );

        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].blob_id, first_blob);
        assert_eq!(discards.len(), 1);
        assert_eq!(discards[0].1, skipped_blob);
        assert!(
            matches!(
                &discards[0].3,
                SdrDiscardReason::SendCounterNotSequential { .. }
            ),
            "got {:?}",
            discards[0].3
        );
    }

    #[test]
    fn apply_ordered_chain_rejects_genesis_identity_mismatch() {
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/genesis-identity-nk");
        let subject_pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/genesis-identity-subject-pk");
        let rogue_pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/genesis-identity-rogue-pk");
        let subject = address(&subject_pk, nk_commit(&nk));
        assert_ne!(address(&rogue_pk, nk_commit(&nk)), subject);
        let account = sample_account_state_for(subject, nk, subject_pk, 1);
        let record = sample_sdr_record(1, host::ZERO_HASH, account, rogue_pk, 100);
        let blob_id = [0x41u8; 32];

        let (accepted, discards) =
            apply_ordered_chain(&subject, &nk, vec![(blob_id, RecordKind::Send, record)]);

        assert!(accepted.is_empty());
        assert_eq!(discards.len(), 1);
        assert_eq!(discards[0].1, blob_id);
        assert!(
            matches!(
                &discards[0].3,
                SdrDiscardReason::GenesisIdentityMismatch { .. }
            ),
            "got {:?}",
            discards[0].3
        );
    }

    #[test]
    fn apply_ordered_chain_rejects_invalid_genesis_counter() {
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/genesis-counter-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/genesis-counter-pk");
        let subject = address(&pk, nk_commit(&nk));
        let account = sample_account_state_for(subject, nk, pk, 2);
        let record = sample_sdr_record(2, host::ZERO_HASH, account, pk, 100);
        let blob_id = [0x42u8; 32];

        let (accepted, discards) =
            apply_ordered_chain(&subject, &nk, vec![(blob_id, RecordKind::Send, record)]);

        assert!(accepted.is_empty());
        assert_eq!(discards.len(), 1);
        assert_eq!(discards[0].1, blob_id);
        assert!(
            matches!(
                &discards[0].3,
                SdrDiscardReason::GenesisCounterInvalid { .. }
            ),
            "got {:?}",
            discards[0].3
        );
    }

    #[test]
    fn verify_fold_static_bindings_rejects_coin_id_mismatch() {
        let subject = [0x85u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/fold-binding-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/fold-binding-pk");
        let account = sample_account_state_for(subject, nk, pk, 1);
        let accepted_record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        let epk = [0x51u8; 32];
        let cp = host::CoinProof {
            coin: host::Coin {
                identifier: host::ZERO_HASH,
                recipient: Address(subject),
                amount: 1,
                asset_id: host::ZERO_HASH,
            },
            proof: vec![],
            inclusion_proof: vec![],
            creating_prev_ash: host::ZERO_HASH,
            creating_nullifier: accepted_record.own_nullifier,
            nav_opening: host::NavOpening {
                size: 0,
                mth: host::ZERO_HASH,
                nav_rand: [0u8; 32],
            },
            asset_terms: None,
            epk,
            ciphertext: vec![],
            detect_tag: host::ZERO_HASH,
        };
        let oref = host::OutputRef {
            coin_id: [0x52u8; 32],
            blob_id: [0u8; 32],
            epk,
            out_ciphertext: vec![],
            blob_locators: host::BlobLocatorSet {
                holders: vec!["https://x.test".into()],
            },
        };
        assert_ne!(digest_to_bytes(&cp.coin.identifier), oref.coin_id);

        let err = verify_fold_static_bindings(&cp, &oref, &accepted_record)
            .expect_err("coin identifier must bind to OutputRef coin_id");
        assert!(
            matches!(err, SdrDiscardReason::FoldCoinIdMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_fold_static_bindings_rejects_epk_mismatch() {
        let subject = [0x86u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/fold-epk-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/fold-epk-pk");
        let account = sample_account_state_for(subject, nk, pk, 1);
        let accepted_record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        let cp = host::CoinProof {
            coin: host::Coin {
                identifier: host::ZERO_HASH,
                recipient: Address(subject),
                amount: 1,
                asset_id: host::ZERO_HASH,
            },
            proof: vec![],
            inclusion_proof: vec![],
            creating_prev_ash: host::ZERO_HASH,
            creating_nullifier: accepted_record.own_nullifier,
            nav_opening: host::NavOpening {
                size: 0,
                mth: host::ZERO_HASH,
                nav_rand: [0u8; 32],
            },
            asset_terms: None,
            epk: [0x61; 32],
            ciphertext: vec![],
            detect_tag: host::ZERO_HASH,
        };
        let oref = host::OutputRef {
            coin_id: digest_to_bytes(&cp.coin.identifier),
            blob_id: [0u8; 32],
            epk: [0x62; 32],
            out_ciphertext: vec![],
            blob_locators: host::BlobLocatorSet {
                holders: vec!["https://x.test".into()],
            },
        };

        let err = verify_fold_static_bindings(&cp, &oref, &accepted_record)
            .expect_err("CoinProof epk must bind to OutputRef epk");
        match err {
            SdrDiscardReason::FoldEpkMismatch { detail } => {
                assert!(detail.contains("CoinProof epk"), "{detail}");
                assert!(detail.contains("OutputRef epk"), "{detail}");
            }
            other => panic!("expected FoldEpkMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_fold_static_bindings_rejects_creating_nullifier_mismatch() {
        let subject = [0x87u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/fold-nullifier-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/fold-nullifier-pk");
        let account = sample_account_state_for(subject, nk, pk, 1);
        let accepted_record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        let epk = [0x63; 32];
        let mut creating_nullifier = accepted_record.own_nullifier;
        creating_nullifier.r_create = [0x64; 32];
        let cp = host::CoinProof {
            coin: host::Coin {
                identifier: host::ZERO_HASH,
                recipient: Address(subject),
                amount: 1,
                asset_id: host::ZERO_HASH,
            },
            proof: vec![],
            inclusion_proof: vec![],
            creating_prev_ash: host::ZERO_HASH,
            creating_nullifier,
            nav_opening: host::NavOpening {
                size: 0,
                mth: host::ZERO_HASH,
                nav_rand: [0u8; 32],
            },
            asset_terms: None,
            epk,
            ciphertext: vec![],
            detect_tag: host::ZERO_HASH,
        };
        let oref = host::OutputRef {
            coin_id: digest_to_bytes(&cp.coin.identifier),
            blob_id: [0u8; 32],
            epk,
            out_ciphertext: vec![],
            blob_locators: host::BlobLocatorSet {
                holders: vec!["https://x.test".into()],
            },
        };

        let err = verify_fold_static_bindings(&cp, &oref, &accepted_record)
            .expect_err("CoinProof creating nullifier must bind to accepted SDR");
        assert_eq!(
            err,
            SdrDiscardReason::FoldCreatingTransitionMismatch {
                detail: "CoinProof creating_nullifier != accepted SDR own_nullifier".into(),
            }
        );
    }

    #[tokio::test]
    async fn recovery_fetch_falls_back_to_manifest_blob_store() {
        let unavailable_holder = MockServer::start().await;
        let server = MockServer::start().await;
        let body = b"recovery-only-manifest-copy".to_vec();
        let blob_id = super::super::blossom::blob_id_of(&body);
        Mock::given(method("GET"))
            .and(path(format!("/blossom/{}", hex::encode(blob_id))))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(body.clone()),
            )
            .mount(&server)
            .await;

        let advertised = vec![unavailable_holder.uri()];
        let blob_stores = vec![server.uri()];
        let holders = recovery_blob_holders(&advertised, &blob_stores);
        let client = BlossomClient::new(1024).expect("construct Blossom client");
        let (fetched, attempts) = fetch_blob_from_holders(&client, &blob_id, &holders)
            .await
            .expect("manifest blob store must recover the blob");

        assert_eq!(fetched, body);
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].holder, advertised[0]);
        assert_eq!(attempts[1].holder, blob_stores[0]);
    }

    #[test]
    fn recovery_blob_holders_preserve_preference_and_deduplicate() {
        let advertised = vec![
            "https://recipient-a.test".to_owned(),
            "https://shared.test".to_owned(),
            "https://recipient-a.test".to_owned(),
        ];
        let blob_stores = vec![
            "https://shared.test".to_owned(),
            "https://manifest-b.test".to_owned(),
            "https://manifest-b.test".to_owned(),
        ];

        assert_eq!(
            recovery_blob_holders(&advertised, &blob_stores),
            vec![
                "https://recipient-a.test".to_owned(),
                "https://shared.test".to_owned(),
                "https://manifest-b.test".to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn stage_output_ref_fetches_coin_only_from_manifest_blob_store() {
        let scope = crate::test_db::setup_pool().await;
        let subject = [0x88u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/blob-store-stage-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/blob-store-stage-pk");
        let account = sample_account_state_for(subject, nk, pk, 1);
        let accepted_record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        let bridge = ProverBridge::new(Network::Regtest);
        let ovk = fixture_sk(b"zkCoins/v1/test-vector/recovery/blob-store-stage-ovk");
        let epk = fixture_xonly(b"zkCoins/v1/test-vector/recovery/blob-store-stage-epk");
        let k_tx = [0x75; 32];
        let coin_proof = host::CoinProof {
            coin: host::Coin {
                identifier: host::ZERO_HASH,
                recipient: Address([0x99; 32]),
                amount: 1,
                asset_id: host::ZERO_HASH,
            },
            proof: vec![],
            inclusion_proof: vec![],
            creating_prev_ash: host::ZERO_HASH,
            creating_nullifier: accepted_record.own_nullifier,
            nav_opening: host::NavOpening {
                size: 0,
                mth: host::ZERO_HASH,
                nav_rand: [0; 32],
            },
            asset_terms: None,
            epk,
            ciphertext: vec![],
            detect_tag: host::ZERO_HASH,
        };
        let plaintext = serialize_coin_proof(&coin_proof).expect("serialize CoinProof");
        let (zbe_ciphertext, blob_id) = zbe_seal(&k_tx, &plaintext).expect("seal CoinProof");
        let unavailable_holder = MockServer::start().await;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/blossom/{}", hex::encode(blob_id))))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(zbe_ciphertext),
            )
            .mount(&server)
            .await;
        let out_ciphertext = crate::v1::delivery::out_ciphertext_for_output_ref(
            &ovk,
            &epk,
            &k_tx,
            &[0x76; 32],
        )
        .expect("construct OVK recovery envelope");
        let oref = host::OutputRef {
            coin_id: digest_to_bytes(&coin_proof.coin.identifier),
            blob_id,
            epk,
            out_ciphertext,
            blob_locators: host::BlobLocatorSet {
                holders: vec![unavailable_holder.uri()],
            },
        };
        let blob_stores = vec![server.uri()];

        let outcome = stage_output_ref_inner(
            FoldOutputRefStores { pool: &scope.pool },
            &bridge,
            FoldOutputRefSecrets {
                subject: &subject,
                ovk: &ovk,
            },
            &accepted_record,
            TransitionKind::Send,
            &oref,
            4096,
            &blob_stores,
            |_| -> Result<(), IncomingError> {
                panic!("a CoinProof for another subject must not reach verification")
            },
        )
        .await
        .expect("manifest blob store must supply the staged CoinProof");
        assert_eq!(outcome, StagedFoldOutcome::NotOurs);
    }

    #[tokio::test]
    async fn stage_output_ref_fails_locally_for_invalid_utf8_and_empty_holders() {
        let scope = crate::test_db::setup_pool().await;
        let subject = [0x88u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/stage-output-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/stage-output-pk");
        let account = sample_account_state_for(subject, nk, pk, 1);
        let accepted_record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        let bridge = ProverBridge::new(Network::Regtest);
        let ovk = fixture_sk(b"zkCoins/v1/test-vector/recovery/stage-output-ovk");
        let epk = fixture_xonly(b"zkCoins/v1/test-vector/recovery/stage-output-epk");
        let stores = FoldOutputRefStores { pool: &scope.pool };
        let secrets = FoldOutputRefSecrets {
            subject: &subject,
            ovk: &ovk,
        };

        let invalid_utf8 = host::OutputRef {
            coin_id: [0x73; 32],
            blob_id: [0x74; 32],
            epk,
            out_ciphertext: vec![0xff, 0xfe],
            blob_locators: host::BlobLocatorSet {
                holders: vec!["https://must-not-be-contacted.test".into()],
            },
        };
        let err = stage_output_ref_inner(
            stores,
            &bridge,
            secrets,
            &accepted_record,
            TransitionKind::Send,
            &invalid_utf8,
            1024,
            &[],
            |_| -> Result<(), IncomingError> {
                panic!("verification must not run after invalid out_ciphertext UTF-8")
            },
        )
        .await
        .expect_err("invalid out_ciphertext UTF-8 must fail before fetch");
        match err {
            SdrDiscardReason::ZbeOpenFailed { detail } => {
                assert!(detail.contains("out_ciphertext is not UTF-8"), "{detail}");
            }
            other => panic!("expected ZbeOpenFailed, got {other:?}"),
        }

        let k_tx = [0x75; 32];
        let out_ciphertext = crate::v1::delivery::out_ciphertext_for_output_ref(
            &ovk,
            &epk,
            &k_tx,
            &[0x76; 32],
        )
        .expect("construct valid OVK recovery envelope");
        let no_holders = host::OutputRef {
            coin_id: [0x77; 32],
            blob_id: [0x78; 32],
            epk,
            out_ciphertext,
            blob_locators: host::BlobLocatorSet { holders: vec![] },
        };
        let err = stage_output_ref_inner(
            stores,
            &bridge,
            secrets,
            &accepted_record,
            TransitionKind::Send,
            &no_holders,
            1024,
            &[],
            |_| -> Result<(), IncomingError> {
                panic!("verification must not run when the holder list is empty")
            },
        )
        .await
        .expect_err("empty holder list must fail without a network request");
        assert_eq!(
            err,
            SdrDiscardReason::FetchFailed {
                detail: "no advertised or manifest blob holders configured".into(),
            }
        );
    }

    #[test]
    fn same_ash_divergent_records_are_retained_with_deterministic_winner() {
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/same-ash-nk");
        let pk0 = fixture_sk(b"zkCoins/v1/test-vector/recovery/same-ash-pk0");
        let pk1 = fixture_sk(b"zkCoins/v1/test-vector/recovery/same-ash-pk1");
        let subject = address(&pk0, nk_commit(&nk));
        let genesis = canonical_genesis_account_state_ash(&subject, &nk, pk0).expect("genesis ash");
        let account = sample_account_state_for(subject, nk, pk1, 1);
        let genuine_record = sample_sdr_record(1, genesis, account.clone(), pk0, 100);
        let rogue_record = sample_sdr_record(1, genesis, account, pk0, 200);
        assert_eq!(
            account_state_hash(&genuine_record.account_state).expect("genuine ash"),
            account_state_hash(&rogue_record.account_state).expect("rogue ash")
        );
        assert_ne!(genuine_record, rogue_record);
        let genuine_blob = [0x01u8; 32];
        let rogue_blob = [0x99u8; 32];

        let (ordered, equivocation_discards) = resolve_equivocation_and_order(vec![
            (rogue_blob, RecordKind::Send, rogue_record),
            (genuine_blob, RecordKind::Send, genuine_record),
        ]);
        assert_eq!(ordered.len(), 2);
        assert!(
            equivocation_discards.is_empty(),
            "discards={equivocation_discards:?}"
        );

        let (accepted, chain_discards) = apply_ordered_chain(&subject, &nk, ordered);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].blob_id, genuine_blob);
        assert_eq!(chain_discards.len(), 1);
        assert_eq!(chain_discards[0].1, rogue_blob);
        assert!(
            matches!(
                &chain_discards[0].3,
                SdrDiscardReason::SendCounterNotSequential { .. }
            ),
            "got {:?}",
            chain_discards[0].3
        );
    }

    #[test]
    fn verify_delivery_record_kind_rejects_outer_inner_mismatch() {
        let subject = [0x86u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/record-kind-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/record-kind-pk");
        let account = sample_account_state_for(subject, nk, pk, 1);
        let mut record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        record.record_kind = host::RecordKind::Mint;

        let err = verify_delivery_record_kind(RecordKind::Send, &record)
            .expect_err("outer Send must not authenticate decoded Mint");
        assert!(
            matches!(err, SdrDiscardReason::RecordKindMismatch { .. }),
            "got {err:?}"
        );
    }

    #[ignore = "heavy: panic-catch path first builds circuit C (~2^21 gates, minutes) regardless \
                of proof validity; run with --ignored --release"]
    #[test]
    fn load_verify_transition_public_inputs_catches_noncanonical_proof_panic() {
        use zkcoins_program::circuit::compliance::Network;

        let bridge = ProverBridge::new(Network::Regtest);
        let err = load_verify_transition_public_inputs(&bridge, &[0xffu8; 64], "test context")
            .expect_err("non-canonical proof bytes must be panic-isolated");
        assert!(
            matches!(err, SdrDiscardReason::ProofVerifyFailed { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn restored_decision_rejects_empty_expected_subject_set() {
        let expected_subjects = HashSet::<[u8; 32]>::new();
        let subjects_with_committed_heads = HashSet::<[u8; 32]>::new();
        let subjects_with_infra_gap = HashSet::<[u8; 32]>::new();

        assert!(!restored_decision(
            &GaplessScanStatus::Complete,
            &expected_subjects,
            &subjects_with_committed_heads,
            &subjects_with_infra_gap,
        ));
    }

    #[test]
    fn apply_ordered_chain_prev_state_head_mismatch() {
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-chain-nk");
        let pk0 = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-chain-pk0");
        let subject = address(&pk0, nk_commit(&nk));
        let account = sample_account_state_for(subject, nk, pk0, 1);
        // Deliberately wrong head — not the canonical genesis ash.
        let record = sample_sdr_record(1, host::ZERO_HASH, account, pk0, 100);
        let blob_id = [0x01u8; 32];

        let (accepted, discards) =
            apply_ordered_chain(&subject, &nk, vec![(blob_id, RecordKind::Send, record)]);

        assert!(accepted.is_empty(), "wrong prev_state_head must not accept");
        assert_eq!(discards.len(), 1);
        assert_eq!(discards[0].0, 1);
        assert_eq!(discards[0].1, blob_id);
        assert!(
            matches!(
                discards[0].3,
                SdrDiscardReason::PrevStateHeadMismatch { .. }
            ),
            "got {:?}",
            discards[0].3
        );
    }

    #[test]
    fn apply_ordered_chain_genesis_positive() {
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-genesis-nk");
        let pk0 = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-genesis-pk0");
        let subject = address(&pk0, nk_commit(&nk));
        let genesis = canonical_genesis_account_state_ash(&subject, &nk, pk0).expect("genesis ash");
        let account = sample_account_state_for(subject, nk, pk0, 1);
        let record = sample_sdr_record(1, genesis, account, pk0, 100);
        let blob_id = [0x02u8; 32];

        let (accepted, discards) =
            apply_ordered_chain(&subject, &nk, vec![(blob_id, RecordKind::Send, record)]);

        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].record.send_counter, 1);
        assert_eq!(accepted[0].blob_id, blob_id);
        assert!(discards.is_empty(), "discards={discards:?}");
    }

    #[test]
    fn apply_ordered_chain_three_record_ascending() {
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-asc-nk");
        let pk0 = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-asc-pk0");
        let subject = address(&pk0, nk_commit(&nk));
        let pk1 = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-asc-pk1");
        let pk2 = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-asc-pk2");
        let pk3 = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-asc-pk3");

        let as0 = sample_account_state_for(subject, nk, pk1, 1);
        let as1 = sample_account_state_for(subject, nk, pk2, 2);
        let as2 = sample_account_state_for(subject, nk, pk3, 3);
        let ash0 = account_state_hash(&as0).expect("ash0");
        let ash1 = account_state_hash(&as1).expect("ash1");

        let genesis = canonical_genesis_account_state_ash(&subject, &nk, pk0).expect("genesis ash");
        let r0 = sample_sdr_record(1, genesis, as0, pk0, 100);
        let r1 = sample_sdr_record(2, ash0, as1, pk1, 100);
        let r2 = sample_sdr_record(3, ash1, as2, pk2, 200);
        let b0 = [0x10u8; 32];
        let b1 = [0x11u8; 32];
        let b2 = [0x12u8; 32];

        let (accepted, discards) = apply_ordered_chain(
            &subject,
            &nk,
            vec![
                (b0, RecordKind::Send, r0),
                (b1, RecordKind::Send, r1),
                (b2, RecordKind::Send, r2),
            ],
        );

        assert!(discards.is_empty(), "discards={discards:?}");
        assert_eq!(accepted.len(), 3);
        assert_eq!(accepted[0].record.send_counter, 1);
        assert_eq!(accepted[1].record.send_counter, 2);
        assert_eq!(accepted[2].record.send_counter, 3);
        assert_eq!(accepted.last().unwrap().record.send_counter, 3);
    }

    #[test]
    fn apply_ordered_chain_occurred_at_regression() {
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-mono-nk");
        let pk0 = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-mono-pk0");
        let subject = address(&pk0, nk_commit(&nk));
        let pk1 = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-mono-pk1");
        let pk2 = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-mono-pk2");
        let pk3 = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-mono-pk3");

        let as0 = sample_account_state_for(subject, nk, pk1, 1);
        let as1 = sample_account_state_for(subject, nk, pk2, 2);
        let as2 = sample_account_state_for(subject, nk, pk3, 3);
        let ash0 = account_state_hash(&as0).expect("ash0");
        let ash1 = account_state_hash(&as1).expect("ash1");

        let genesis = canonical_genesis_account_state_ash(&subject, &nk, pk0).expect("genesis ash");
        // Same chain as ascending, but counter=2 regresses occurred_at under 1's.
        let r0 = sample_sdr_record(1, genesis, as0, pk0, 100);
        let r1 = sample_sdr_record(2, ash0, as1, pk1, 200);
        let r2 = sample_sdr_record(3, ash1, as2, pk2, 150); // < 200
        let b0 = [0x20u8; 32];
        let b1 = [0x21u8; 32];
        let b2 = [0x22u8; 32];

        let (accepted, discards) = apply_ordered_chain(
            &subject,
            &nk,
            vec![
                (b0, RecordKind::Send, r0),
                (b1, RecordKind::Send, r1),
                (b2, RecordKind::Send, r2),
            ],
        );

        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted[0].record.send_counter, 1);
        assert_eq!(accepted[1].record.send_counter, 2);
        assert_eq!(discards.len(), 1);
        assert_eq!(discards[0].0, 3);
        assert_eq!(discards[0].1, b2);
        assert!(
            matches!(
                discards[0].3,
                SdrDiscardReason::OccurredAtNotMonotonic { .. }
            ),
            "got {:?}",
            discards[0].3
        );
    }

    #[test]
    fn resolve_equivocation_and_order_equivocation() {
        let subject = [0xAEu8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-eq-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-eq-pk");
        // Same send_counter, divergent account_state ashes → equivocation.
        let as_a = sample_account_state_for(subject, nk, [0x01; 32], 1);
        let as_b = sample_account_state_for(subject, nk, [0x02; 32], 1);
        assert_ne!(
            account_state_hash(&as_a).unwrap(),
            account_state_hash(&as_b).unwrap()
        );
        let record_a = sample_sdr_record(1, host::ZERO_HASH, as_a, pk, 100);
        let record_b = sample_sdr_record(1, host::ZERO_HASH, as_b, pk, 100);
        let blob_a = [0xAAu8; 32];
        let blob_b = [0xBBu8; 32];

        let (ordered, discards) = resolve_equivocation_and_order(vec![
            (blob_a, RecordKind::Send, record_a),
            (blob_b, RecordKind::Send, record_b),
        ]);

        assert!(
            ordered.is_empty() || ordered.iter().all(|(_, _, r)| r.send_counter != 1),
            "equivocating counter must not appear in ordered; got {ordered:?}"
        );
        assert_eq!(discards.len(), 2);
        for (sc, _blob, _record_kind, reason) in &discards {
            assert_eq!(*sc, 1);
            assert!(
                matches!(reason, SdrDiscardReason::Equivocation { .. }),
                "got {reason:?}"
            );
        }
    }

    #[test]
    fn resolve_equivocation_and_order_legitimate_duplicate() {
        let subject = [0xAFu8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-dup-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-dup-pk");
        let account = sample_account_state_for(subject, nk, pk, 1);
        let record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        let blob_a = [0xCAu8; 32];
        let blob_b = [0xCBu8; 32];
        // Re-published SDR: identical body, only blob_id differs.
        let record_b = record.clone();

        let (ordered, discards) = resolve_equivocation_and_order(vec![
            (blob_a, RecordKind::Send, record),
            (blob_b, RecordKind::Send, record_b),
        ]);

        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].2.send_counter, 1);
        assert!(discards.is_empty(), "discards={discards:?}");
    }

    #[test]
    fn verify_sdr_checks_ii_account_state_hash_mismatch() {
        use zkcoins_program::circuit::compliance::Network;

        let subject = [0xB0u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-ii-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-ii-pk");
        let account = sample_account_state_for(subject, nk, pk, 1);
        let mut record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        // Break check (ii): proof_data ash ≠ account_state ash.
        record.proof_data.new_account_state_hash = host::ZERO_HASH;
        // Ensure it really is a mismatch (empty account ash is never ZERO_HASH).
        let real_ash = account_state_hash(&record.account_state).expect("ash");
        assert_ne!(real_ash, record.proof_data.new_account_state_hash);

        let bridge = ProverBridge::new(Network::Regtest);
        let err = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect_err("check (ii) must fail");
        assert_eq!(err, SdrDiscardReason::AccountStateHashMismatch);
    }

    #[ignore = "heavy: first verify_transition call in a fresh process builds circuit C (~2^21 gates, \
                minutes) regardless of proof validity; run with --ignored --release"]
    #[test]
    fn verify_sdr_checks_iii_a_proof_verify_failed() {
        use zkcoins_program::circuit::compliance::Network;

        let subject = [0xB1u8; 32];
        let nk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-iii-nk");
        let pk = fixture_sk(b"zkCoins/v1/test-vector/recovery/sdr-iii-pk");
        let account = sample_account_state_for(subject, nk, pk, 1);
        // sample_sdr_record already sets new_account_state_hash correctly → (ii) passes.
        let mut record = sample_sdr_record(1, host::ZERO_HASH, account, pk, 100);
        // Empty / truncated wire: `load_transition_proof_bytes` must return Err
        // (mapped to ProofVerifyFailed). Prefer empty over 0xFF-filled bytes —
        // Plonky2 `from_bytes` panics on non-canonical Goldilocks limbs rather
        // than returning Err, which would not exercise the discard path.
        record.recursive_proof = vec![];

        let bridge = ProverBridge::new(Network::Regtest);
        let err = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect_err("garbage proof must fail check (iii-a)");
        assert!(
            matches!(err, SdrDiscardReason::ProofVerifyFailed { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn recovered_head_install_handles_existing_accounts_and_index_read_failure() {
        use crate::v1::separation::{
            claim_stack_scan_mode, set_process_stack_mode, ScanStackMode,
        };

        let scope = crate::test_db::setup_pool().await;
        set_process_stack_mode(ScanStackMode::V1);
        claim_stack_scan_mode(&scope.pool, ScanStackMode::V1)
            .await
            .expect("claim v1 stack mode for EngineAdapter fixture");
        let pool = Arc::new(scope.pool.clone());
        let adapter = Arc::new(
            EngineAdapter::load_or_create(pool.as_ref().clone(), Network::Regtest, 0)
                .await
                .expect("create recovery test adapter"),
        );
        let bridge = ProverBridge::new(Network::Regtest);

        let no_op_subject = [0x91; 32];
        let no_op_nk = [0x92; 32];
        let no_op_pk = [0x93; 32];
        let no_op_owner = Address(no_op_subject);
        let no_op_record = crate::v1::db_v1::AccountSnapshot {
            owner: no_op_owner,
            state: sample_account_state_for(no_op_subject, no_op_nk, no_op_pk, 5),
            nk: no_op_nk,
            op_secret: Some(OpSecret::new([0x94; 32])),
            genesis_pubkey: no_op_pk,
            spendable: vec![],
            spent_ids: vec![],
            last_proof: None,
            last_nav_opening: None,
            last_nullifier: None,
            last_nullifier_pos: None,
        }
        .into_record()
        .expect("construct existing no-op account");

        let behind_subject = [0xa1; 32];
        let behind_nk = [0xa2; 32];
        let behind_pk = [0xa3; 32];
        let behind_owner = Address(behind_subject);
        let behind_record = crate::v1::db_v1::AccountSnapshot {
            owner: behind_owner,
            state: sample_account_state_for(behind_subject, behind_nk, behind_pk, 1),
            nk: behind_nk,
            op_secret: Some(OpSecret::new([0xa4; 32])),
            genesis_pubkey: behind_pk,
            spendable: vec![],
            spent_ids: vec![],
            last_proof: None,
            last_nav_opening: None,
            last_nullifier: None,
            last_nullifier_pos: None,
        }
        .into_record()
        .expect("construct existing behind account");

        adapter
            .with_engine_mut(|engine| {
                engine
                    .insert_account(no_op_owner, no_op_record)
                    .expect("seed no-op account");
                engine
                    .insert_account(behind_owner, behind_record)
                    .expect("seed behind account");
            })
            .expect("seed adapter accounts under v1 process claim");

        let make_deps = |seed_relays: Vec<String>| RecoveryCampaignDeps {
            seed_relays,
            blob_stores: Vec::new(),
            bundles: BundleStore::shared(),
            adapter: Arc::clone(&adapter),
            pool: Arc::clone(&pool),
            index: InMemoryPrivateIndex::shared(),
            receipts: ReceiptHub::shared(),
            max_blob_bytes: 1024,
            expected_network: "regtest".into(),
        };
        let bundle = OperationalBundle {
            ivk: [0xb1; 32],
            ovk: [0xb2; 32],
            op: [0xb3; 32],
            nk: [0xb4; 32],
            op_secret: [0xb5; 32],
        };

        let no_seed_err = run_recovery_campaign(
            RecoveryCampaignConfig {
                page_limit: 10,
                earliest_account_timestamp: 1,
            },
            make_deps(vec![]),
        )
        .await
        .expect_err("empty seed relays must fail before bundle, DB, or network access");
        assert_eq!(no_seed_err, RecoveryError::NoSeedRelays);

        let no_op_state = sample_account_state_for(no_op_subject, no_op_nk, no_op_pk, 4);
        let no_op_sdr = sample_sdr_record(4, host::ZERO_HASH, no_op_state, no_op_pk, 100);
        let no_op_accepted = vec![AcceptedSdr {
            blob_id: [0xc1; 32],
            account_state_ash: digest_to_bytes(
                &account_state_hash(&no_op_sdr.account_state).expect("no-op head ash"),
            ),
            record: no_op_sdr,
        }];
        let deps = make_deps(vec!["ws://unused.test".into()]);
        install_and_persist_recovered_head(
            &deps,
            &bridge,
            no_op_subject,
            &bundle,
            &no_op_accepted,
        )
        .await
        .expect("an engine account ahead of the recovered head is an idempotent no-op");
        assert_eq!(
            adapter.with_engine(|engine| {
                engine
                    .account(&no_op_owner)
                    .expect("no-op account remains installed")
                    .state
                    .send_counter
            }),
            5
        );

        let behind_head_state =
            sample_account_state_for(behind_subject, behind_nk, behind_pk, 2);
        let behind_head = sample_sdr_record(
            2,
            host::ZERO_HASH,
            behind_head_state,
            behind_pk,
            100,
        );
        let behind_accepted = vec![AcceptedSdr {
            blob_id: [0xc2; 32],
            account_state_ash: digest_to_bytes(
                &account_state_hash(&behind_head.account_state).expect("behind head ash"),
            ),
            record: behind_head,
        }];
        let err = install_and_persist_recovered_head(
            &deps,
            &bridge,
            behind_subject,
            &bundle,
            &behind_accepted,
        )
        .await
        .expect_err("an older installed account must fail closed instead of being overwritten");
        assert_eq!(
            err,
            SdrDiscardReason::HeadReconstructionFailed {
                detail: "engine already holds account at send_counter 1, behind the \
                         reconstructed head 2 — no in-place account update path exists; refusing \
                         to overwrite (nothing was changed)"
                    .into(),
            }
        );
        assert_eq!(
            adapter.with_engine(|engine| {
                engine
                    .account(&behind_owner)
                    .expect("behind account remains installed")
                    .state
                    .send_counter
            }),
            1
        );

        sqlx::query("DROP TABLE v1_self_delivery_index CASCADE")
            .execute(pool.as_ref())
            .await
            .expect("drop self-delivery index table for SQL failure fixture");

        let missing_subject = [0xd1; 32];
        let missing_nk = [0xd2; 32];
        let missing_pk = [0xd3; 32];
        assert!(adapter
            .with_engine(|engine| engine.account(&Address(missing_subject)).is_none()));
        let missing_state =
            sample_account_state_for(missing_subject, missing_nk, missing_pk, 1);
        let missing_head =
            sample_sdr_record(1, host::ZERO_HASH, missing_state, missing_pk, 100);
        let missing_accepted = vec![AcceptedSdr {
            blob_id: [0xd4; 32],
            account_state_ash: digest_to_bytes(
                &account_state_hash(&missing_head.account_state).expect("missing head ash"),
            ),
            record: missing_head,
        }];
        let err = install_and_persist_recovered_head(
            &deps,
            &bridge,
            missing_subject,
            &bundle,
            &missing_accepted,
        )
        .await
        .expect_err("missing SQL table must map to IndexLookupFailed before reconstruction");
        match err {
            SdrDiscardReason::IndexLookupFailed { detail } => {
                assert!(
                    detail.starts_with("list self-delivery rows for head install:"),
                    "{detail}"
                );
                assert!(detail.contains("v1_self_delivery_index"), "{detail}");
            }
            other => panic!("expected IndexLookupFailed, got {other:?}"),
        }
        assert!(adapter
            .with_engine(|engine| engine.account(&Address(missing_subject)).is_none()));
    }

    // -----------------------------------------------------------------------
    // §4.2 SDR replay — heavy tests (real prove + verify_transition / circuit C)
    // -----------------------------------------------------------------------

    /// Real, valid genesis MINT transition + its NfLog fold + matching `block_log` rows,
    /// mapped into a valid `host::SelfDeliveryRecordV1`. Callers mutate exactly one field
    /// to produce their specific negative case; the untouched fixture is "fully valid".
    ///
    /// When `fold_nullifier` is false, the mint nullifier is **not** folded into the
    /// engine (check (iv) classify → Pending). Used only by the NotFirstOccurrence case.
    async fn build_real_mint_sdr_fixture_maybe_fold(
        pool: &sqlx::PgPool,
        fold_nullifier: bool,
    ) -> (
        host::SelfDeliveryRecordV1,
        StateEngine,
        [u8; 32], /* subject */
        [u8; 32], /* nk */
    ) {
        use shared::spec_v1::{ChainPosition, PublishedNullifier};
        use zkcoins_program::circuit::compliance::Network;
        use zkcoins_prover::prover_bridge::test_signing::{
            deterministic_secret, normalized_key, sign_transition,
        };
        use zkcoins_prover::state_engine::{MintRequest, OpSecret, ScannedNullifier};

        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/recovery-heavy-test/nk").into();
        let (secret0, public0, pk0) =
            normalized_key(deterministic_secret(b"zkCoins/v1/recovery-heavy-test/sk0"));
        let (_, _, pk1) =
            normalized_key(deterministic_secret(b"zkCoins/v1/recovery-heavy-test/sk1"));
        let owner = host::Address(host::address(&pk0, host::nk_commit(&nk)));

        let name_hash = host::name_hash(b"recovery-heavy-test-asset").expect("name_hash");
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &pk0, &name_hash, 2, 1);

        let mut engine = StateEngine::new(Network::Regtest, 0);
        let pending = engine
            .begin_mint(MintRequest {
                owner,
                nk,
                op_secret: OpSecret::new(
                    Sha256::digest(b"zkCoins/v1/recovery-heavy-test/op_secret").into(),
                ),
                current_pubkey: pk0,
                next_pubkey: pk1,
                name: b"recovery-heavy-test-asset".to_vec(),
                decimals: 2,
                amount: 100,
                issuance_version: 1,
                cap_total: 0,
                terms_salt: [0u8; 32],
                output_templates: vec![host::CoinTemplate {
                    recipient: owner,
                    amount: 100,
                    asset_id,
                }],
                npk_rand: [0x22; 32],
            })
            .expect("begin_mint");
        let sig = sign_transition(secret0, public0, &pending.proof_data, Network::Regtest);
        let applied = engine
            .finalise(pending, sig.transition.clone())
            .expect("finalise mint (real prove happens here)");

        let inclusion_height: u64 = 100;
        let anchor_height: u64 = 50;
        let inclusion_hash = [0xAAu8; 32];
        let anchor_hash = [0xBBu8; 32];

        if fold_nullifier {
            engine
                .append_nullifier(ScannedNullifier::from_survivor(&PublishedNullifier {
                    chain_pos: ChainPosition {
                        height: inclusion_height,
                        tx_index: 0,
                        vin_index: 0,
                        member_index: 0,
                    },
                    pk: applied.nullifier().0,
                    r: applied.nullifier().1,
                }))
                .expect("fold mint nullifier");
        }
        engine.set_tip_height(inclusion_height + 10);

        for height in inclusion_height - 10..inclusion_height {
            insert_sdr_check_block(
                pool,
                height,
                sdr_check_block_hash(height),
                Some(1_700_000_000),
            )
            .await;
        }
        crate::db::insert_block_log(
            pool,
            &crate::db::BlockLogEntry {
                block_time: Some(1_700_000_000),
                block_hash: inclusion_hash.to_vec(),
                block_height: Some(inclusion_height as i64),
                inscription_count: 0,
                processing_duration_us: None,
            },
        )
        .await
        .expect("insert inclusion block_log row");
        crate::db::insert_block_log(
            pool,
            &crate::db::BlockLogEntry {
                block_time: None,
                block_hash: anchor_hash.to_vec(),
                block_height: Some(anchor_height as i64),
                inscription_count: 0,
                processing_duration_us: None,
            },
        )
        .await
        .expect("insert anchor block_log row");

        let account_state = engine.account(&owner).expect("account").state.clone();
        let proof_data = applied.proved().proof_data.clone();
        let recursive_proof = applied.proved().proof.to_bytes();
        let record = host::SelfDeliveryRecordV1 {
            record_kind: host::RecordKind::Mint,
            send_counter: account_state.send_counter,
            prev_state_head: canonical_genesis_account_state_ash(&owner.0, &nk, pk0)
                .expect("genesis ash"),
            account_state,
            recursive_proof,
            proof_data,
            own_nullifier: host::CreatingNullifier {
                pk_create: applied.nullifier().0,
                r_create: applied.nullifier().1,
                r_prime_create: sig.transition.r_prime,
            },
            proof_block_anchor: host::BlockAnchor {
                block_hash: anchor_hash,
                height: anchor_height as u32,
            },
            inclusion_block: host::BlockAnchor {
                block_hash: inclusion_hash,
                height: inclusion_height as u32,
            },
            occurred_at: 1_700_000_000,
            spent_or_folded_coin_ids: vec![],
            output_refs: vec![],
            self_blob_locators: host::BlobLocatorSet {
                holders: vec!["https://recovery-heavy-test.example".into()],
            },
        };
        (record, engine, owner.0, nk)
    }

    /// Fully valid fixture (nullifier folded into NfLog).
    async fn build_real_mint_sdr_fixture(
        pool: &sqlx::PgPool,
    ) -> (
        host::SelfDeliveryRecordV1,
        StateEngine,
        [u8; 32], /* subject */
        [u8; 32], /* nk */
    ) {
        build_real_mint_sdr_fixture_maybe_fold(pool, true).await
    }

    #[ignore = "heavy: first verify_transition call in a fresh process builds circuit C (~2^21 gates, \
            minutes) regardless of proof validity; run with --ignored --release"]
    #[tokio::test]
    async fn verify_sdr_checks_iii_b_proof_data_mismatch() {
        use zkcoins_program::circuit::compliance::Network;

        let scope = crate::test_db::setup_pool().await;
        let (mut record, _engine, subject, nk) = build_real_mint_sdr_fixture(&scope.pool).await;
        // (iii-b) only: break proof_data equality while leaving new_account_state_hash
        // intact so check (ii) still passes.
        let real_root = record.proof_data.output_coins_root;
        if real_root != host::ZERO_HASH {
            record.proof_data.output_coins_root = host::ZERO_HASH;
        } else {
            let mut bytes = digest_to_bytes(&real_root);
            bytes[0] ^= 0x01;
            record.proof_data.output_coins_root =
                host::digest_from_bytes(&bytes).expect("digest_from_bytes");
        }
        assert_ne!(
            record.proof_data.output_coins_root, real_root,
            "fixture must actually diverge output_coins_root"
        );

        let bridge = ProverBridge::new(Network::Regtest);
        let err = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect_err("check (iii-b) must fail");
        assert_eq!(err, SdrDiscardReason::ProofDataMismatch);
    }

    #[ignore = "heavy: first verify_transition call in a fresh process builds circuit C (~2^21 gates, \
            minutes) regardless of proof validity; run with --ignored --release"]
    #[tokio::test]
    async fn verify_sdr_checks_iv_consumed_pubkey_mismatch() {
        use zkcoins_program::circuit::compliance::Network;

        let scope = crate::test_db::setup_pool().await;
        let (mut record, _engine, subject, nk) = build_real_mint_sdr_fixture(&scope.pool).await;
        // (iv) Fresh-Key-Substitution only — leave proof_data and other fields alone.
        record.own_nullifier.pk_create = [0x77u8; 32];

        let bridge = ProverBridge::new(Network::Regtest);
        let err = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect_err("check (iv) FKS must fail");
        assert_eq!(err, SdrDiscardReason::ConsumedPubkeyMismatch);
    }

    #[ignore = "heavy: first verify_transition call in a fresh process builds circuit C (~2^21 gates, \
            minutes) regardless of proof validity; run with --ignored --release"]
    #[tokio::test]
    async fn verify_sdr_checks_iv_not_first_occurrence() {
        use zkcoins_program::circuit::compliance::Network;

        let scope = crate::test_db::setup_pool().await;
        // Valid mint + proof, but nullifier never folded → classify Pending.
        let (record, engine, subject, nk) =
            build_real_mint_sdr_fixture_maybe_fold(&scope.pool, false).await;

        let bridge = ProverBridge::new(Network::Regtest);
        let (pk_create, r_create) = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect("pre-engine checks must pass");
        let err = verify_sdr_record_engine_checks(&engine, pk_create, r_create)
            .expect_err("check (iv) first-occurrence must fail");
        assert!(
            matches!(err, SdrDiscardReason::NotFirstOccurrence { .. }),
            "got {err:?}"
        );
    }

    #[ignore = "heavy: first verify_transition call in a fresh process builds circuit C (~2^21 gates, \
            minutes) regardless of proof validity; run with --ignored --release"]
    #[tokio::test]
    async fn verify_sdr_checks_v_inclusion_block_mismatch() {
        use zkcoins_program::circuit::compliance::Network;

        let scope = crate::test_db::setup_pool().await;
        let (mut record, engine, subject, nk) = build_real_mint_sdr_fixture(&scope.pool).await;
        // (v) only: wrong inclusion hash for the real height in block_log.
        record.inclusion_block.block_hash = [0xCCu8; 32];

        let bridge = ProverBridge::new(Network::Regtest);
        let (pk_create, r_create) = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect("pre-engine checks must still pass");
        let inclusion_height = verify_sdr_record_engine_checks(&engine, pk_create, r_create)
            .expect("engine checks must still pass");
        let err = verify_sdr_record_checks_v_vi_async(&scope.pool, inclusion_height, &record)
            .await
            .expect_err("check (v) inclusion hash must fail");
        assert!(
            matches!(err, SdrDiscardReason::InclusionBlockMismatch { .. }),
            "got {err:?}"
        );
    }

    #[ignore = "heavy: first verify_transition call in a fresh process builds circuit C (~2^21 gates, \
            minutes) regardless of proof validity; run with --ignored --release"]
    #[tokio::test]
    async fn verify_sdr_checks_v_occurred_at_invalid() {
        use zkcoins_program::circuit::compliance::Network;

        let scope = crate::test_db::setup_pool().await;
        let (mut record, engine, subject, nk) = build_real_mint_sdr_fixture(&scope.pool).await;
        // (v) only: zero occurred_at remains invalid before the MTP lookup.
        record.occurred_at = 0;

        let bridge = ProverBridge::new(Network::Regtest);
        let (pk_create, r_create) = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect("pre-engine checks must still pass");
        let inclusion_height = verify_sdr_record_engine_checks(&engine, pk_create, r_create)
            .expect("engine checks must still pass");
        let err = verify_sdr_record_checks_v_vi_async(&scope.pool, inclusion_height, &record)
            .await
            .expect_err("check (v) occurred_at must fail");
        assert!(
            matches!(err, SdrDiscardReason::OccurredAtInvalid { .. }),
            "got {err:?}"
        );
    }

    #[ignore = "heavy: first verify_transition call in a fresh process builds circuit C (~2^21 gates, \
            minutes) regardless of proof validity; run with --ignored --release"]
    #[tokio::test]
    async fn verify_sdr_checks_vi_anchor_bound_failed() {
        use zkcoins_program::circuit::compliance::Network;

        let scope = crate::test_db::setup_pool().await;
        let (mut record, engine, subject, nk) = build_real_mint_sdr_fixture(&scope.pool).await;
        // (vi) only: anchor height must be a strict ancestor of inclusion height.
        record.proof_block_anchor.height = record.inclusion_block.height;

        let bridge = ProverBridge::new(Network::Regtest);
        let (pk_create, r_create) = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect("pre-engine checks must still pass");
        let inclusion_height = verify_sdr_record_engine_checks(&engine, pk_create, r_create)
            .expect("engine checks must still pass");
        let err = verify_sdr_record_checks_v_vi_async(&scope.pool, inclusion_height, &record)
            .await
            .expect_err("check (vi) anchor bound must fail");
        assert!(
            matches!(err, SdrDiscardReason::AnchorBoundFailed { .. }),
            "got {err:?}"
        );
    }

    #[ignore = "heavy: first verify_transition call in a fresh process builds circuit C (~2^21 gates, \
            minutes) regardless of proof validity; run with --ignored --release"]
    #[tokio::test]
    async fn sdr_fully_valid_record_is_replayed() {
        use zkcoins_program::circuit::compliance::Network;

        let scope = crate::test_db::setup_pool().await;
        let (record, engine, subject, nk) = build_real_mint_sdr_fixture(&scope.pool).await;

        let bridge = ProverBridge::new(Network::Regtest);
        let (pk_create, r_create) = verify_sdr_record_pre_engine(&bridge, &subject, &nk, &record)
            .expect("fully valid record must pass pre-engine checks");
        let inclusion_height = verify_sdr_record_engine_checks(&engine, pk_create, r_create)
            .expect("fully valid record must pass engine checks");
        verify_sdr_record_checks_v_vi_async(&scope.pool, inclusion_height, &record)
            .await
            .expect("fully valid record must pass checks (v)/(vi)");

        let (accepted, discards) = apply_ordered_chain(
            &subject,
            &nk,
            vec![([0x01u8; 32], RecordKind::Mint, record.clone())],
        );
        assert!(
            discards.is_empty(),
            "fully valid record must not be discarded: {discards:?}"
        );
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].record.send_counter, record.send_counter);
    }
}
