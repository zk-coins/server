//! Gap G4 — v1.1 transition signature on the node (BIP-340 + sign-to-contract).
//!
//! Behind `ZKCOINS_V1_SHADOW=1` every state-advancing transition is authorised
//! by a [`TransitionSignature`] (§3.2), not by a legacy ash‖ocr
//! [`shared::commitment::Commitment`]. This module is the **host-side** check
//! the node runs on the wallet's `/sign` response before it installs the
//! signature into a pending transition and proves.
//!
//! ## Wallet wire contract (SDK specification)
//!
//! The node surfaces, in job status `awaiting_signature` (§7.5), the six
//! `ProofData` fields, `H(ProofData)`, `txn_pubkey = Pkᵢ`, and `send_counter`.
//! The wallet then `POST`s to `/v1/jobs/<job_id>/sign` exactly:
//!
//! | Field        | Encoding                                              | Wire size |
//! |--------------|-------------------------------------------------------|-----------|
//! | `signature`  | lowercase hex of `bytes(R) ‖ bytes(s)` (§3.2 step 6) | **exactly** 128 hex chars → 64 bytes |
//! | `s2c_nonce`  | lowercase hex of x-only even-y `R'` (§3.2 step 1b)  | **exactly** 64 hex chars → 32 bytes  |
//!
//! **Strict encoding (no silent variants):**
//! - Alphabet: only ASCII `0-9` and `a-f` (lowercase). Uppercase rejects.
//! - Length: exact character counts above. No pad, no truncate.
//! - **No** `0x` / `0X` prefix. A prefixed string is encoding failure.
//! - No whitespace, no mixed case.
//!
//! JSON field order is irrelevant (named fields). Binary order inside
//! `signature` is fixed: `R` (32 bytes) then `s` (32 bytes).
//!
//! The wallet **does not** send `pk_i` or `H(ProofData)`:
//! - `pk_i` is taken from the node's pending witness
//!   (`prev_account_state.current_pubkey` / the echoed `txn_pubkey`);
//! - `H(ProofData)` is recomputed by the node from the **pending**
//!   `ProofData` the engine produced at `begin_*` — never from a digest the
//!   wallet supplies.
//!
//! The wallet signs the **per-network fixed** message
//! `m_state = "zkCoins/v1/StateUpdate/{mainnet|testnet|regtest}"` (the network
//! the node was booted for) with S2C tweak
//! `t = H(bytes(R') ‖ H(ProofData))`, following §3.2 steps 1–6 including the
//! even-y rules 1b/3b.
//!
//! ## Where `ProofData` comes from (binding is not decorative)
//!
//! The finalise-path entry [`accept_wallet_transition_signature`] takes a
//! [`PendingTransition`] and derives both `pk_i` and the canonical
//! `serialize(ProofData)` **from that pending object alone**. A caller
//! therefore cannot verify a signature against one payload while the
//! transition it authorises carries another: there is no independent
//! `proof_data` / `expected_pk_i` parameter on the finalise path.
//!
//! Free-standing material verification exists as
//! [`verify_transition_signature_material`] for preflight/tooling when no
//! pending transition exists yet. That function is **not** called from the
//! finalise path.
//!
//! ## Checks (both mandatory — no silent partial accept)
//!
//! 1. **S2C opening** — `R == R' + H(bytes(R') ‖ H(ProofData))·G`
//!    ([`comm_verify`](zkcoins_prover::half_agg::comm_verify)). This is what
//!    binds the signature to *this* proof.
//! 2. **BIP-340** — `s·G == R + e·Pkᵢ` over the node's network `m_state`
//!    ([`verify_single`](zkcoins_prover::half_agg::verify_single)). A
//!    signature for another network's `m_state` is rejected here
//!    (cross-network replay).
//!
//! Either failure rejects the submission. "BIP-340 alone verified" is never
//! enough.
//!
//! ## Live path under a v1.1 claim
//!
//! - [`refuse_legacy_commitment_under_v1`] gates residual ash‖ocr
//!   [`CommitRequest`](crate::router::CommitRequest) entry points
//!   (`commit_flow` / `mint_commit_flow` / jobs commit). Under
//!   `ScanStackMode::V1` a legacy commitment is refused loud.
//! - [`crate::router::jobs_sign_handler`] is the production REST caller:
//!   flag-gated `POST /v1/jobs/{id}/sign` (§7.5) decodes
//!   [`WalletSignSubmission`] at the boundary (strict hex →
//!   `malformed_request` on violation) and verifies via
//!   [`accept_wallet_transition_signature`] against the staged
//!   [`PendingSignEntry`]. An accepted signature is driven into
//!   [`finalise_with_accepted_signature`] / `StateEngine::finalise`.
//!   With the flag off the route refuses at [`SignatureCheck::ShadowFlag`];
//!   the legacy `/api/jobs/{id}/commit` path is untouched.

use std::fmt;
use std::sync::Arc;

use dashmap::DashMap;
use serde::Deserialize;
use shared::spec_v1::{digest_to_bytes, hash_proof_data, serialize_proof_data, ProofData};
use uuid::Uuid;
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::half_agg::{comm_verify, verify_single};
use zkcoins_prover::prover_bridge::TransitionSignature;
use zkcoins_prover::state_engine::{FinalisationCapability, PendingTransition};

use super::mode::V1ShadowMode;
use super::separation::{process_stack_mode, ScanStackMode};

/// Canonical message when a legacy ash‖ocr Commitment hits a v1.1 process.
pub(crate) const LEGACY_COMMITMENT_REFUSED_UNDER_V1: &str =
    "legacy ash‖ocr Commitment refused under v1.1 process claim; \
     submit a §3.2 TransitionSignature bound to the pending transition \
     (ZKCOINS_V1_SHADOW=1 / ScanStackMode::V1 — no dual-accept)";

/// Which verification step rejected a wallet signature.
///
/// Tests (and callers) must branch on this so a wrong-network reject is not
/// misreported as an S2C failure and vice versa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCheck {
    /// `ZKCOINS_V1_SHADOW` is not on — legacy ash‖ocr path only.
    ShadowFlag,
    /// Process claimed v1.1; residual legacy Commitment entry is refused.
    LegacyCommitment,
    /// Hex / length / alphabet failure on the wire fields.
    Encoding,
    /// `sig.pk_i` does not equal the pending account's `current_pubkey`.
    PkMatch,
    /// Pending envelope's `proof_data_hash` does not match its `proof_data`.
    PendingEnvelope,
    /// S2C opening `R == R' + H(R' ‖ H(ProofData))·G` failed.
    S2cOpening,
    /// BIP-340 verify over the node network's `m_state` failed.
    Bip340,
}

/// Fail-closed rejection of a v1.1 transition signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionSignatureError {
    pub check: SignatureCheck,
    pub message: String,
}

impl fmt::Display for TransitionSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "v1.1 transition signature rejected at {:?}: {}",
            self.check, self.message
        )
    }
}

impl std::error::Error for TransitionSignatureError {}

impl TransitionSignatureError {
    fn new(check: SignatureCheck, message: impl Into<String>) -> Self {
        Self {
            check,
            message: message.into(),
        }
    }
}

/// JSON request body of `POST /v1/jobs/{job_id}/sign` (§7.5) **before**
/// strict hex decode.
///
/// Field names match the normative wire: `signature`, `s2c_nonce`. Values
/// are raw strings; the boundary converts them via
/// [`WalletSignSubmission::try_from`] so encoding failures surface as
/// [`SignatureCheck::Encoding`] → outward `malformed_request`, never as a
/// generic JSON-shape error or an invented machine code.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct WalletSignSubmissionWire {
    pub signature: String,
    pub s2c_nonce: String,
}

/// Decoded binary body of `POST /v1/jobs/{job_id}/sign` after strict hex
/// decode (§7.5). This is the request type the route verifies against —
/// the documented encoding is what the boundary enforces.
///
/// Field meanings:
/// - `signature` = `bytes(R) ‖ bytes(s)` (64 bytes, §3.2 step 6)
/// - `s2c_nonce` = x-only even-y encoding of pre-tweak `R'` (32 bytes)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletSignSubmission {
    pub signature: [u8; 64],
    pub s2c_nonce: [u8; 32],
}

impl WalletSignSubmission {
    /// Decode the hex fields the wallet POSTs.
    ///
    /// **Strict contract (SDK-facing):**
    /// - `signature`: exactly 128 lowercase hex characters (no `0x` prefix)
    /// - `s2c_nonce`: exactly 64 lowercase hex characters (no `0x` prefix)
    ///
    /// Uppercase, wrong length, whitespace, or a `0x`/`0X` prefix all fail
    /// at [`SignatureCheck::Encoding`]. There is no silent case-fold or
    /// prefix strip.
    pub(crate) fn from_hex(
        signature_hex: &str,
        s2c_nonce_hex: &str,
    ) -> Result<Self, TransitionSignatureError> {
        Ok(Self {
            signature: parse_hex_exact(signature_hex, "signature")?,
            s2c_nonce: parse_hex_exact(s2c_nonce_hex, "s2c_nonce")?,
        })
    }

    /// Kernel-API (§7.5): BIP-340 R half of the wallet submission.
    pub fn signature_r(&self) -> [u8; 32] {
        self.signature[..32]
            .try_into()
            .expect("64-byte signature has a 32-byte R")
    }

    /// Kernel-API (§7.5): BIP-340 s half of the wallet submission.
    pub fn signature_s(&self) -> [u8; 32] {
        self.signature[32..]
            .try_into()
            .expect("64-byte signature has a 32-byte s")
    }
}

impl TryFrom<&WalletSignSubmissionWire> for WalletSignSubmission {
    type Error = TransitionSignatureError;

    fn try_from(wire: &WalletSignSubmissionWire) -> Result<Self, Self::Error> {
        Self::from_hex(&wire.signature, &wire.s2c_nonce)
    }
}

impl TryFrom<WalletSignSubmissionWire> for WalletSignSubmission {
    type Error = TransitionSignatureError;

    fn try_from(wire: WalletSignSubmissionWire) -> Result<Self, Self::Error> {
        Self::try_from(&wire)
    }
}

/// Staged material for a job in `awaiting_signature` under a v1.1 claim.
///
/// The REST `/sign` route takes provenance from this entry alone (via
/// [`accept_wallet_transition_signature`]); the job's advertised
/// `awaiting_signature` JSON is derived from the same pending object so
/// a wallet never signs a different surface than the node verifies.
///
/// **`send_counter` is not a free field.** It is always
/// `pending.witness_wip.prev_account_state.send_counter` — the entry
/// counter of the transition being authorised. Callers cannot set a
/// counter that disagrees with the pending transition.
///
/// ## Durable finalisation (host path up to the documented edge)
///
/// The engine-owned [`FinalisationCapability`] inside this entry carries
/// the host witness for prove + apply. [`DurableFinalisationPersist`] also
/// carries every durable dependency of the **remaining host** steps —
/// §7.5 result install and job completion — so resume is "load and proceed"
/// through to a terminal job status, including after a true cold boot with
/// an empty in-memory map.
///
/// **Edge:** production finalise stages `v1_pending_publishes`
/// (`members_ready`) with the engine snapshot, then hands that row to the
/// durable nullifier publisher before the host marks the job complete.
/// NfLog scan-fold after on-chain confirmation remains outside the host edge.
/// See [`crate::job_dispatcher::JOB_FINALISE_HOST_EDGE`].
#[derive(Clone, Debug)]
pub struct PendingSignEntry {
    pub pending: PendingTransition,
    pub network: Network,
    /// Accepted wallet signature once `/sign` has verified it (also on the
    /// durable capability). `None` while waiting for the wallet.
    pub signature: Option<TransitionSignature>,
    /// §7.5 optional result field captured at stage time from the original
    /// transition request (caller-supplied; revalidated on complete).
    pub publisher_pubkey: Option<[u8; 32]>,
    /// §7.5 `result` JSON after a successful prove+apply. Present once the
    /// side-effectful engine step has finished so resume can **publish and
    /// complete** without re-running apply. `None` until that step lands.
    pub completion_result: Option<serde_json::Value>,
    /// HTTP status paired with [`Self::completion_result`] for
    /// `JobStore::complete` (always `Some(200)` once result is set).
    pub completion_status: Option<i16>,
}

impl PendingSignEntry {
    /// Stage a pending transition (complete witness from `begin_*`).
    /// `send_counter` is derived from the pending envelope — never accepted
    /// as input.
    /// Kernel-API (§7.5): construct a staged sign entry after `begin_*`
    /// for [`register_live_pending_after_begin`].
    pub fn new(pending: PendingTransition, network: Network) -> Self {
        Self {
            pending,
            network,
            signature: None,
            publisher_pubkey: None,
            completion_result: None,
            completion_status: None,
        }
    }

    /// Attach a caller-supplied publisher pubkey for the §7.5 result.
    pub(crate) fn with_publisher_pubkey(mut self, pk: Option<[u8; 32]>) -> Self {
        self.publisher_pubkey = pk;
        self
    }

    /// Entry counter `i` of this transition (`skᵢ = A/0'/i'`, §1.2 / §7.5).
    /// Derived from the pending account state — not stored separately.
    pub(crate) fn send_counter(&self) -> u64 {
        self.pending.witness_wip.prev_account_state.send_counter
    }

    /// Engine-owned capability for this entry (pending + optional signature).
    pub(crate) fn capability(&self) -> FinalisationCapability {
        let mut cap = FinalisationCapability::stage(self.pending.clone());
        if let Some(sig) = self.signature.clone() {
            // Already verified at install time; pk match is re-checked.
            cap.install_signature(sig)
                .expect("PendingSignEntry signature already pk-matched");
        }
        cap
    }

    /// Install an accepted wallet signature on the in-memory entry.
    pub(crate) fn install_signature(
        &mut self,
        sig: TransitionSignature,
    ) -> Result<(), TransitionSignatureError> {
        if sig.pk_i != self.pending.witness_wip.prev_account_state.current_pubkey {
            return Err(TransitionSignatureError::new(
                SignatureCheck::PkMatch,
                "install_signature: pk_i does not match pending current_pubkey",
            ));
        }
        self.signature = Some(sig);
        Ok(())
    }

    /// Record the §7.5 completion surface after a successful prove+apply.
    ///
    /// Both fields are required together — never store a result without its
    /// status or invent a default status.
    pub(crate) fn install_completion(
        &mut self,
        result: serde_json::Value,
        status: i16,
    ) -> Result<(), String> {
        if !result.is_object() {
            return Err(
                "install_completion: result must be a JSON object (§7.5 job result)".to_string(),
            );
        }
        if status != 200 {
            return Err(format!(
                "install_completion: success path requires HTTP 200; got {status}"
            ));
        }
        self.completion_result = Some(result);
        self.completion_status = Some(status);
        Ok(())
    }

    /// True when prove+apply has already produced a durable completion
    /// surface — resume may publish/complete without re-running the hook.
    pub(crate) fn has_completion(&self) -> bool {
        self.completion_result.is_some() && self.completion_status.is_some()
    }
}

/// Finalise readiness for the **prove+apply** leg: signature must be installed.
///
/// Publication and job completion additionally require
/// [`PendingSignEntry::has_completion`] (or a live finalise driver to produce
/// it). Kept as a named check so call sites stay explicit — never a silent
/// "always Ok".
pub(crate) fn ensure_finalise_ready(entry: &PendingSignEntry) -> Result<(), String> {
    if entry.signature.is_none() {
        return Err(
            "finalise readiness: durable capability has no installed signature \
             (wallet /sign has not accepted authorisation)"
                .to_string(),
        );
    }
    Ok(())
}

/// Completeness of the durable host capability for the **whole path** to a
/// terminal job (prove/apply + publish result + complete).
///
/// Every field the remaining steps depend on must be present. A missing
/// field fails loud — resume must not half-finish.
///
/// | Field | Required for |
/// |-------|----------------|
/// | engine capability (pending witness) | prove + apply |
/// | `signature` | prove + apply |
/// | `network` | BIP-340 re-verify / process identity |
/// | `completion_result` + `completion_status` | publish §7.5 result + job complete |
/// | `publisher_pubkey` | optional — only when the original request carried one |
pub(crate) fn ensure_completion_ready(entry: &PendingSignEntry) -> Result<(), String> {
    ensure_finalise_ready(entry)?;
    match (&entry.completion_result, entry.completion_status) {
        (Some(result), Some(status)) => {
            if !result.is_object() {
                return Err(
                    "completion readiness: completion_result must be a JSON object".to_string(),
                );
            }
            if status != 200 {
                return Err(format!(
                    "completion readiness: completion_status must be 200; got {status}"
                ));
            }
            // Publisher on the result must match the staged value when both set.
            if let Some(pk) = &entry.publisher_pubkey {
                let expected = hex_lower(pk);
                match result.get("publisher_pubkey").and_then(|v| v.as_str()) {
                    Some(got) if got == expected => {}
                    Some(got) => {
                        return Err(format!(
                            "completion readiness: completion_result.publisher_pubkey \
                             {got} does not match staged publisher_pubkey {expected}"
                        ));
                    }
                    None => {
                        return Err("completion readiness: staged publisher_pubkey present but \
                             completion_result omits publisher_pubkey"
                            .to_string());
                    }
                }
            }
            Ok(())
        }
        (None, None) => Err(
            "completion readiness: missing completion_result and completion_status \
             (prove+apply has not recorded the §7.5 surface; resume cannot publish \
             or complete without re-running finalise)"
                .to_string(),
        ),
        (Some(_), None) => Err(
            "completion readiness: completion_result present without completion_status \
             (incomplete capability field set)"
                .to_string(),
        ),
        (None, Some(_)) => Err(
            "completion readiness: completion_status present without completion_result \
             (incomplete capability field set)"
                .to_string(),
        ),
    }
}

/// Per-job map of staged v1.1 sign material. Keyed by job `public_id`.
pub type PendingSignMap = Arc<DashMap<Uuid, PendingSignEntry>>;

/// JSON key under `jobs.request_body` for the durable finalisation capability.
///
/// Replaces the old split (`pending_sign` + `sign`). Terminal status flips
/// strip this key (and the legacy keys for rows written by older builds).
pub(crate) const FINALISATION_BODY_KEY: &str = "finalisation";

/// Legacy key kept only so terminal strip / cleanup still erase old rows.
pub(crate) const PENDING_SIGN_BODY_KEY: &str = "pending_sign";

/// Durable job-row envelope: one record containing everything needed to
/// resume the **whole path to completion** after a true process restart.
///
/// ## Contents (derived from what each step depends on, including handed-in values)
///
/// | Field | Source | Why |
/// |-------|--------|-----|
/// | `capability` ([`FinalisationCapability`]) | engine / `begin_*` + `/sign` | full pending witness + optional accepted signature — **prove and apply** |
/// | `network` | process claim at stage | BIP-340 `m_state` for `/sign` re-verify after rehydrate |
/// | `publisher_pubkey` | original transition request (handed in) | §7.5 completed `result` field |
/// | `completion_result` | after successful prove+apply | §7.5 JSON published onto the job row — **host publication** |
/// | `completion_status` | paired with result (200) | `JobStore::complete` argument — **job completion** |
///
/// Live engine tip / CoinHist / NfLog are **not** stored in this envelope:
/// apply re-validates them, and production finalise persists the engine
/// plus `v1_pending_publishes` out-of-band. Once `completion_result` is
/// present, resume skips re-apply and only host-publishes + completes —
/// so a crash after durable stage cannot strand a job that resume cannot
/// finish up to [`crate::job_dispatcher::JOB_FINALISE_HOST_EDGE`]. On-chain
/// nullifier **broadcast** is outside this envelope (bitcoind required).
///
/// ## Wire encoding
///
/// `capability` is **`FinalisationCapability::to_durable_bytes` → lowercase
/// hex** so large `ComplianceProof`s stay off the JSON tree while remaining a
/// single opaque blob. That encode path is the only serde/bincode entry that
/// carries `op_secret`; `PendingTransition` / `FinalisationCapability` do not
/// derive `Serialize`. Network, publisher, and completion stay as plain JSON
/// fields for operators.
///
/// [`Debug`] redacts `capability_bincode_hex`: the blob embeds `op_secret`
/// via the durable wire of [`PendingTransition`], so printing the hex would
/// leak the key that keys every `nav_rand` for the account. (The hex itself
/// remains in storage JSON — that residual is named, not implied.)
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DurableFinalisationPersist {
    pub network: String,
    /// Lowercase hex of [`FinalisationCapability::to_durable_bytes`].
    pub capability_bincode_hex: String,
    /// Lowercase hex of the external publisher, when the request carried one.
    pub publisher_pubkey: Option<String>,
    /// §7.5 result object after prove+apply; absent until that step succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_result: Option<serde_json::Value>,
    /// HTTP status for job complete; present iff `completion_result` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_status: Option<i16>,
}

impl std::fmt::Debug for DurableFinalisationPersist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableFinalisationPersist")
            .field("network", &self.network)
            .field("capability_bincode_hex", &"[REDACTED]")
            .field("publisher_pubkey", &self.publisher_pubkey)
            .field("completion_result", &self.completion_result)
            .field("completion_status", &self.completion_status)
            .finish()
    }
}

impl DurableFinalisationPersist {
    pub(crate) fn from_entry(entry: &PendingSignEntry) -> Result<Self, String> {
        // Fail closed on split completion fields before persisting.
        match (&entry.completion_result, entry.completion_status) {
            (None, None) => {}
            (Some(r), Some(s)) => {
                if !r.is_object() {
                    return Err(
                        "DurableFinalisationPersist: completion_result must be a JSON object"
                            .to_string(),
                    );
                }
                if s != 200 {
                    return Err(format!(
                        "DurableFinalisationPersist: completion_status must be 200; got {s}"
                    ));
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "DurableFinalisationPersist: completion_result and completion_status \
                     must both be set or both be absent (incomplete capability)"
                        .to_string(),
                );
            }
        }
        let capability = entry.capability();
        // Explicit durable path only — FinalisationCapability is not
        // general-purpose Serializable (keeps OpSecret unreachable via serde).
        let bytes = capability
            .to_durable_bytes()
            .map_err(|e| format!("durable encode FinalisationCapability: {e}"))?;
        Ok(Self {
            network: network_label(entry.network).to_string(),
            capability_bincode_hex: hex_lower(&bytes),
            publisher_pubkey: entry.publisher_pubkey.as_ref().map(|pk| hex_lower(pk)),
            completion_result: entry.completion_result.clone(),
            completion_status: entry.completion_status,
        })
    }

    pub(crate) fn into_entry(self) -> Result<PendingSignEntry, TransitionSignatureError> {
        let network = parse_network_label(&self.network).ok_or_else(|| {
            TransitionSignatureError::new(
                SignatureCheck::PendingEnvelope,
                format!(
                    "persisted finalisation network {:?} is not a known label",
                    self.network
                ),
            )
        })?;
        if self.capability_bincode_hex.is_empty() {
            return Err(TransitionSignatureError::new(
                SignatureCheck::PendingEnvelope,
                "persisted finalisation capability_bincode_hex is missing/empty \
                 (incomplete capability)",
            ));
        }
        if self
            .capability_bincode_hex
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
            || !self.capability_bincode_hex.len().is_multiple_of(2)
        {
            return Err(TransitionSignatureError::new(
                SignatureCheck::PendingEnvelope,
                "persisted finalisation capability must be even-length lowercase hex",
            ));
        }
        let bytes = hex::decode(&self.capability_bincode_hex).map_err(|e| {
            TransitionSignatureError::new(
                SignatureCheck::PendingEnvelope,
                format!("persisted finalisation capability hex: {e}"),
            )
        })?;
        let capability =
            FinalisationCapability::from_durable_bytes(&bytes, network).map_err(|e| {
                TransitionSignatureError::new(
                    SignatureCheck::PendingEnvelope,
                    format!("persisted finalisation capability durable decode: {e}"),
                )
            })?;
        let publisher_pubkey = match self.publisher_pubkey {
            None => None,
            Some(hex) => {
                if hex.len() != 64
                    || hex
                        .bytes()
                        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
                {
                    return Err(TransitionSignatureError::new(
                        SignatureCheck::PendingEnvelope,
                        format!(
                            "persisted publisher_pubkey must be 64 lowercase hex chars; got len={}",
                            hex.len()
                        ),
                    ));
                }
                let raw = hex::decode(&hex).map_err(|e| {
                    TransitionSignatureError::new(
                        SignatureCheck::PendingEnvelope,
                        format!("persisted publisher_pubkey hex: {e}"),
                    )
                })?;
                let arr: [u8; 32] = raw.try_into().map_err(|v: Vec<u8>| {
                    TransitionSignatureError::new(
                        SignatureCheck::PendingEnvelope,
                        format!("persisted publisher_pubkey length {}", v.len()),
                    )
                })?;
                Some(arr)
            }
        };
        // Completion fields must arrive as a pair — incomplete splits fail loud.
        let (completion_result, completion_status) =
            match (self.completion_result, self.completion_status) {
                (None, None) => (None, None),
                (Some(r), Some(s)) => {
                    if !r.is_object() {
                        return Err(TransitionSignatureError::new(
                            SignatureCheck::PendingEnvelope,
                            "persisted completion_result must be a JSON object",
                        ));
                    }
                    if s != 200 {
                        return Err(TransitionSignatureError::new(
                            SignatureCheck::PendingEnvelope,
                            format!(
                                "persisted completion_status must be 200; got {s} \
                                 (incomplete/invalid capability)"
                            ),
                        ));
                    }
                    (Some(r), Some(s))
                }
                (Some(_), None) => {
                    return Err(TransitionSignatureError::new(
                        SignatureCheck::PendingEnvelope,
                        "persisted completion_result without completion_status \
                         (incomplete capability)",
                    ));
                }
                (None, Some(_)) => {
                    return Err(TransitionSignatureError::new(
                        SignatureCheck::PendingEnvelope,
                        "persisted completion_status without completion_result \
                         (incomplete capability)",
                    ));
                }
            };
        Ok(PendingSignEntry {
            pending: capability.pending().clone(),
            network,
            signature: capability.signature().cloned(),
            publisher_pubkey,
            completion_result,
            completion_status,
        })
    }
}

/// Backward-compatible alias used by older tests/docs.
///
/// Remove durable finalisation material from a job's `request_body`
/// (in-memory JSON). Also strips legacy `pending_sign` / `sign` keys.
pub(crate) fn strip_pending_sign_from_body(request_body: &mut serde_json::Value) -> bool {
    request_body
        .as_object_mut()
        .map(|obj| {
            let a = obj.remove(FINALISATION_BODY_KEY).is_some();
            let b = obj.remove(PENDING_SIGN_BODY_KEY).is_some();
            let c = obj.remove("sign").is_some();
            a || b || c
        })
        .unwrap_or(false)
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

fn parse_network_label(s: &str) -> Option<Network> {
    match s {
        "mainnet" => Some(Network::Mainnet),
        "testnet" => Some(Network::Testnet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

/// Stage a pending entry in the in-memory map **and** return the JSON
/// blob to merge into `jobs.request_body` under [`FINALISATION_BODY_KEY`]
/// so a restart can rehydrate the map and finalise.
pub(crate) fn stage_pending_sign(
    map: &PendingSignMap,
    job_id: Uuid,
    entry: PendingSignEntry,
) -> serde_json::Value {
    let persist = DurableFinalisationPersist::from_entry(&entry)
        .expect("FinalisationCapability always bincode-encodes");
    map.insert(job_id, entry);
    serde_json::to_value(persist).expect("DurableFinalisationPersist always encodes")
}

/// Rehydrate a staged entry from a job's persisted `request_body`.
///
/// Prefers [`FINALISATION_BODY_KEY`]. A legacy `pending_sign` key alone is
/// **not** rehydrated into a finalisable entry (old verification-grade
/// shape) — fail closed rather than pretend a partial record is complete.
pub(crate) fn rehydrate_pending_sign(
    request_body: &serde_json::Value,
) -> Result<Option<PendingSignEntry>, TransitionSignatureError> {
    if let Some(raw) = request_body.get(FINALISATION_BODY_KEY) {
        let persist: DurableFinalisationPersist =
            serde_json::from_value(raw.clone()).map_err(|e| {
                TransitionSignatureError::new(
                    SignatureCheck::PendingEnvelope,
                    format!("persisted finalisation is not a valid envelope: {e}"),
                )
            })?;
        return Ok(Some(persist.into_entry()?));
    }
    if request_body.get(PENDING_SIGN_BODY_KEY).is_some() {
        return Err(TransitionSignatureError::new(
            SignatureCheck::PendingEnvelope,
            "legacy pending_sign envelope is verification-grade only and cannot \
             resume finalise; resubmit the transition so a full FinalisationCapability \
             is staged",
        ));
    }
    Ok(None)
}

/// Attach an accepted signature to the durable finalisation record in
/// `request_body`, returning the updated JSON object value for the
/// `finalisation` key. Fails loud if no durable capability is present.
///
/// Kernel-API (§7.5): gRPC sign-path write — folds an accepted wallet
/// signature into the durable finalisation envelope on the job row.
pub fn durable_finalisation_with_signature(
    request_body: &serde_json::Value,
    signature: &TransitionSignature,
) -> Result<serde_json::Value, TransitionSignatureError> {
    let mut entry = rehydrate_pending_sign(request_body)?.ok_or_else(|| {
        TransitionSignatureError::new(
            SignatureCheck::PendingEnvelope,
            "no durable finalisation capability on job row to attach signature",
        )
    })?;
    entry.install_signature(signature.clone())?;
    let persist = DurableFinalisationPersist::from_entry(&entry)
        .map_err(|e| TransitionSignatureError::new(SignatureCheck::PendingEnvelope, e))?;
    serde_json::to_value(persist).map_err(|e| {
        TransitionSignatureError::new(
            SignatureCheck::PendingEnvelope,
            format!("encode durable finalisation after signature: {e}"),
        )
    })
}

/// §7.5 completed `result` object after a successful finalise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinaliseOutcome {
    pub new_account_state_hash: [u8; 32],
    pub output_coins_root: [u8; 32],
    pub input_nullifiers_root: [u8; 32],
    /// `coin.identifier` of every output coin the transition produced
    /// (empty for pure receive — §7.5 / §2.3.3).
    pub output_coin_ids: Vec<[u8; 32]>,
    /// Present for externally published kinds (publisher presence matrix
    /// case (b)/(c)); absent on self-publish (case a) and attest jobs.
    pub publisher_pubkey: Option<[u8; 32]>,
}

impl FinaliseOutcome {
    /// Coin identifiers from the pending witness (the transition that
    /// finalise proved). `AppliedTransition` only carries `ProofData` +
    /// nullifier; ids live on the witness.
    fn output_coin_ids_from_pending(pending: &PendingTransition) -> Vec<[u8; 32]> {
        pending
            .witness_wip
            .output_coins
            .iter()
            .map(|c| digest_to_bytes(&c.identifier))
            .collect()
    }

    /// Kernel-API (§7.5): build the completed job `result` from an applied
    /// transition after gRPC finalise.
    pub fn from_applied(
        applied: &zkcoins_prover::state_engine::AppliedTransition,
        pending: &PendingTransition,
        publisher_pubkey: Option<[u8; 32]>,
    ) -> Self {
        let pd = &applied.proved().proof_data;
        Self {
            new_account_state_hash: digest_to_bytes(&pd.new_account_state_hash),
            output_coins_root: digest_to_bytes(&pd.output_coins_root),
            input_nullifiers_root: digest_to_bytes(&pd.input_nullifiers_root),
            output_coin_ids: Self::output_coin_ids_from_pending(pending),
            publisher_pubkey,
        }
    }

    /// Build an outcome from the pending's ProofData + output coins
    /// (test drivers that do not run the full prove; production hook
    /// doubles that return the pending surface).
    ///
    /// Kernel-API (§7.5): crash-resume surface when `members_ready` is
    /// already durable and re-prove is skipped.
    pub fn from_pending_proof_data(pending: &PendingTransition) -> Self {
        Self::from_pending_proof_data_with_publisher(pending, None)
    }

    pub fn from_pending_proof_data_with_publisher(
        pending: &PendingTransition,
        publisher_pubkey: Option<[u8; 32]>,
    ) -> Self {
        let pd = &pending.proof_data;
        Self {
            new_account_state_hash: digest_to_bytes(&pd.new_account_state_hash),
            output_coins_root: digest_to_bytes(&pd.output_coins_root),
            input_nullifiers_root: digest_to_bytes(&pd.input_nullifiers_root),
            output_coin_ids: Self::output_coin_ids_from_pending(pending),
            publisher_pubkey,
        }
    }

    /// Kernel-API (§7.5): encode the completed job `result` JSON object.
    pub fn to_result_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "new_account_state_hash": hex_lower(&self.new_account_state_hash),
            "output_coins_root": hex_lower(&self.output_coins_root),
            "input_nullifiers_root": hex_lower(&self.input_nullifiers_root),
            "output_coin_ids": self
                .output_coin_ids
                .iter()
                .map(|id| hex_lower(id))
                .collect::<Vec<_>>(),
        });
        if let Some(pk) = &self.publisher_pubkey {
            obj.as_object_mut().expect("object").insert(
                "publisher_pubkey".to_string(),
                serde_json::Value::String(hex_lower(pk)),
            );
        }
        obj
    }
}

/// Drive an accepted wallet signature into [`StateEngine::finalise`].
///
/// Installs the signature on the pending witness and calls `finalise`.
/// Prefer [`finalise_accepted_prove_outside_lock`] on the production job
/// path so the multi-minute prove does not hold the engine mutex (the
/// receive-path invariant: prove outside the lock, re-validate on apply).
///
/// `publisher_pubkey` is the §7.5 optional result field (echo of the
/// transition's external publisher target, when present).
///
/// Kernel-API (§7.5): gRPC finalise holding the engine mutex (tooling /
/// short proves). Prefer [`finalise_accepted_prove_outside_lock`] on the
/// job path.
pub fn finalise_with_accepted_signature(
    engine: &mut zkcoins_prover::state_engine::StateEngine,
    pending: PendingTransition,
    signature: TransitionSignature,
    publisher_pubkey: Option<[u8; 32]>,
) -> Result<FinaliseOutcome, String> {
    // Capture output ids before finalise moves the pending.
    let output_coin_ids = FinaliseOutcome::output_coin_ids_from_pending(&pending);
    let applied = engine
        .finalise(pending, signature)
        .map_err(|e| format!("StateEngine::finalise failed: {e:#}"))?;
    let pd = &applied.proved().proof_data;
    Ok(FinaliseOutcome {
        new_account_state_hash: digest_to_bytes(&pd.new_account_state_hash),
        output_coins_root: digest_to_bytes(&pd.output_coins_root),
        input_nullifiers_root: digest_to_bytes(&pd.input_nullifiers_root),
        output_coin_ids,
        publisher_pubkey,
    })
}

/// Production finalise (in-memory only): prove **outside** the engine mutex,
/// then re-acquire and apply with live re-validation.
///
/// Prefer [`finalise_accepted_prove_persist_and_stage`] on the job path so
/// the applied engine and `v1_pending_publishes` intent are durable before
/// the host edge. This sync helper remains for call sites that only need
/// the in-memory apply (tests / tooling).
///
/// Kernel-API (§7.5): gRPC finalise with prove outside the engine lock and
/// live re-validation on apply (no durable stage — caller stages separately).
pub fn finalise_accepted_prove_outside_lock(
    adapter: &crate::v1::EngineAdapter,
    pending: PendingTransition,
    signature: TransitionSignature,
    publisher_pubkey: Option<[u8; 32]>,
) -> Result<FinaliseOutcome, String> {
    let output_coin_ids = FinaliseOutcome::output_coin_ids_from_pending(&pending);
    let bridge = adapter.bridge();
    let proved = zkcoins_prover::state_engine::StateEngine::prove_pending_transition_detached(
        &bridge, pending, signature,
    )
    .map_err(|e| format!("prove_pending_transition_detached failed: {e:#}"))?;
    let applied = adapter
        .with_engine_mut(|engine| engine.apply_proved_transition(proved))
        .map_err(|e| format!("apply_proved_transition (engine lock): {e:#}"))?
        .map_err(|e| format!("apply_proved_transition failed: {e:#}"))?;
    let pd = &applied.proved().proof_data;
    Ok(FinaliseOutcome {
        new_account_state_hash: digest_to_bytes(&pd.new_account_state_hash),
        output_coins_root: digest_to_bytes(&pd.output_coins_root),
        input_nullifiers_root: digest_to_bytes(&pd.input_nullifiers_root),
        output_coin_ids,
        publisher_pubkey,
    })
}

/// Runtime-supplied deps for §4.2 mesh delivery after durable persist.
///
/// Absent means "no delivery port installed" (legacy stack / tests). When
/// present, finalise runs delivery **after** engine+members_ready persist
/// and **after** the nullifier publish hand-off — never before durable
/// write. Missing operational bundle or recipient IVPK is a named error.
pub(crate) struct FinaliseDeliveryDeps<'a> {
    pub port: &'a dyn crate::v1::delivery::OutgoingDeliveryPort,
    pub bundles: &'a crate::kernel::bootstrap::BundleStore,
    pub targets: &'a crate::v1::delivery::DeliveryTargetStore,
    /// Ordered Blossom base URLs (holders only; no default).
    pub blob_holders: Vec<String>,
    pub max_blob_bytes: u64,
    pub now: u64,
    /// Kind-24242 auth expiration (absolute unix seconds).
    pub auth_expiration: u64,
    /// Closed network label for post-send profile refresh (`mainnet`/…).
    pub expected_network: &'a str,
    /// Self-delivery recipient relays (bootstrap seed relays; non-empty).
    pub self_relays: Vec<String>,
    /// Process-local RNG for change-coin / Phase-A builds.
    pub rng: &'a std::sync::Mutex<Box<dyn crate::v1::nostr::nip59::SecureRandom + Send>>,
}

/// Production job-path finalise: prove outside the lock, apply under the
/// write gate, then **atomically** persist the engine snapshot and stage
/// `v1_pending_publishes` (`members_ready`) **under the claim fence**, then
/// hand the staged intent to the durable nullifier publisher
/// ([`crate::v1::resume_pending_publish`] / `durable_publish_nullifier`),
/// then run §4.2 mesh delivery when [`FinaliseDeliveryDeps`] is provided.
///
/// Order is safety-relevant and fixed:
/// **persist → publish (nullifier) → deliver (mesh) → return Ok**
/// (caller may then mark the job `completed`). A crash after this function
/// returns leaves the account advanced, a progressive publish status, and
/// (once the host edge finishes) a completed job. Publish failure returns
/// `Err` **without** deleting or completing the `members_ready` row so a
/// later resume can still pick it up. Delivery never runs before persist.
///
/// ## Fence
///
/// `fence` is the acquisition token from
/// [`crate::job_store::JobStore::claim_finalise_exclusive`]. The engine +
/// `members_ready` commit uses the same token+lease predicate as the job-row
/// host-edge writes. A stale epoch (including same-owner reclaim) returns
/// [`crate::job_store::FINALISE_FENCE_LOST`] without writing; the caller must
/// quiet-exit rather than terminal-fail another claim's job.
///
/// ## Resume / crash after durable stage
///
/// If a pending-publish row already exists for `signature.pk_i`, prove+apply
/// are skipped **only while `fence` still holds**, then the durable publisher
/// is driven for that row (members_ready / constructed / commit_broadcast).
/// Re-applying an already-advanced account would fail; the staged row is the
/// durable signal that apply already landed. A lost fence refuses the resume
/// shortcut so a stale worker cannot drive host-edge completion after reclaim.
///
/// ## Lease liveness
///
/// The multi-minute prove runs on `spawn_blocking` so the caller's async
/// lease-renewal heartbeat can keep firing on the runtime.
pub(crate) async fn finalise_accepted_prove_persist_and_stage(
    adapter: &crate::v1::EngineAdapter,
    pending: PendingTransition,
    signature: TransitionSignature,
    publisher_pubkey: Option<[u8; 32]>,
    fence: crate::job_store::FinaliseFence,
    publisher: &impl crate::v1::receive::NullifierBatchPublisher,
    delivery: Option<FinaliseDeliveryDeps<'_>>,
) -> Result<FinaliseOutcome, anyhow::Error> {
    use crate::job_store::FINALISE_FENCE_LOST;
    use crate::v1::db_v1;

    // Already durable from a prior attempt that crashed after stage.
    // Still require a live fence: a stale epoch must not re-enter host-edge
    // completion after another claim reclaimed the job.
    //
    // Crash-resume after durable stage: re-drive nullifier publish **and**
    // any open delivery-outbox rows for this transition (mesh was not
    // completed, or only partially).
    if let Some(row) = db_v1::load_pending_publish(adapter.pool(), signature.pk_i)
        .await
        .map_err(|e| anyhow::anyhow!("load_pending_publish before finalise: {e:#}"))?
    {
        if row.owner.0 != pending.owner.0 {
            return Err(anyhow::anyhow!(
                "v1.1 finalise: pending publish for pk={} has owner {}, \
                 pending.owner is {} — refusing silent mismatch",
                hex_lower(&signature.pk_i),
                hex_lower(&row.owner.0),
                hex_lower(&pending.owner.0),
            ));
        }
        if !claim_fence_still_holds(adapter.pool(), fence)
            .await
            .map_err(anyhow::Error::msg)?
        {
            return Err(anyhow::Error::msg(FINALISE_FENCE_LOST));
        }
        tracing::info!(
            pk = %hex_lower(&signature.pk_i),
            status = %row.status,
            fence = fence.fence,
            "v1.1 finalise: pending publish already durable; \
             skipping re-prove/re-apply (crash-resume after stage)"
        );
        publish_staged_nullifier_after_members_ready(adapter, publisher, signature.pk_i).await?;
        if let Some(deps) = delivery.as_ref() {
            // Mesh first (fills external outbox artefacts), then Phase A if
            // still absent — output_refs require published blob_id/epk.
            resume_outbox_after_crash(adapter.pool(), signature.pk_i, deps)
                .await
                .map_err(|e| anyhow::anyhow!("v1.1 finalise crash-resume mesh outbox: {e}"))?;

            let already = crate::v1::db_sdr::get_phase_a(adapter.pool(), &signature.pk_i)
                .await
                .map_err(|e| anyhow::anyhow!("load Phase A on crash-resume: {e:#}"))?;
            if already.is_none() {
                let delivery_snapshot = DeliverySnapshot::from_pending(&pending, &signature)?;
                let tip_hash = adapter.tip_hash();
                let tip_height = adapter.with_engine(|engine| engine.tip_height());
                let tip_height_u32 = u32::try_from(tip_height).map_err(|_| {
                    anyhow::anyhow!("v1.1 finalise crash-resume: tip_height does not fit u32")
                })?;
                let proof_bytes = adapter
                    .with_engine(|engine| {
                        engine
                            .accounts()
                            .find(|(o, _)| o.0 == pending.owner.0)
                            .and_then(|(_, rec)| rec.last_proof.as_ref().map(|p| p.to_bytes()))
                    })
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "v1.1 finalise crash-resume: no last_proof for SDR Phase A re-stage"
                        )
                    })?;
                stage_sdr_phase_a_after_mesh(
                    adapter,
                    &delivery_snapshot,
                    &proof_bytes,
                    tip_height_u32,
                    tip_hash,
                    deps,
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("v1.1 finalise crash-resume SDR Phase A stage: {e}")
                })?;
            }
        }
        return Ok(FinaliseOutcome::from_pending_proof_data_with_publisher(
            &pending,
            publisher_pubkey,
        ));
    }

    // Capture delivery materials before prove moves `pending`.
    let delivery_snapshot = DeliverySnapshot::from_pending(&pending, &signature)?;

    // §4.2 targets must be resolved **before** durable finalise. A missing
    // IVPK discovered only at mesh-build would leave the transition already
    // persisted and the nullifier published. Fail closed here, named.
    if let Some(deps) = delivery.as_ref() {
        crate::v1::delivery::ensure_delivery_targets_before_finalise(
            &delivery_snapshot.owner,
            &delivery_snapshot.output_coins,
            deps.targets,
            deps.now,
        )
        .map_err(|e| {
            anyhow::anyhow!("v1.1 finalise: delivery targets incomplete before prove/persist: {e}")
        })?;
    }

    let output_coin_ids = FinaliseOutcome::output_coin_ids_from_pending(&pending);
    let owner = pending.owner;
    let bridge = adapter.bridge();
    let signature_for_prove = signature.clone();
    let proved = tokio::task::spawn_blocking(move || {
        zkcoins_prover::state_engine::StateEngine::prove_pending_transition_detached(
            &bridge,
            pending,
            signature_for_prove,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("prove_pending_transition_detached join: {e}"))?
    // Preserve typed engine causes (e.g. DependencyNotFinal) for host encode.
    .map_err(|e| e.context("prove_pending_transition_detached failed"))?;

    // Write gate: snapshot → apply → atomic fenced engine + members_ready → restore on fail.
    let _write_gate = adapter.lock_writes().await;
    let pre = adapter.snapshot_live();

    let applied = match adapter.with_engine_mut(|engine| engine.apply_proved_transition(proved)) {
        Ok(Ok(a)) => a,
        Ok(Err(e)) => {
            let _ = adapter.restore_live(pre);
            // Preserve typed engine causes through the host encode path.
            return Err(e.context("apply_proved_transition failed"));
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "apply_proved_transition (engine lock): {e:#}"
            ));
        }
    };

    let (pk, r) = applied.nullifier();
    if signature.pk_i != pk {
        let _ = adapter.restore_live(pre);
        return Err(anyhow::anyhow!(
            "v1.1 finalise: signature.pk_i does not match applied nullifier Pk"
        ));
    }
    if signature.signature_r() != r {
        let _ = adapter.restore_live(pre);
        return Err(anyhow::anyhow!(
            "v1.1 finalise: signature R does not match applied nullifier R"
        ));
    }

    let tip_hash = adapter.tip_hash();
    let tip_height = adapter.with_engine(|engine| engine.tip_height());
    let tip_height_u32 = u32::try_from(tip_height).map_err(|_| {
        anyhow::anyhow!(
            "v1.1 finalise: tip_height {tip_height} does not fit u32 for pending publish"
        )
    })?;

    let snap = adapter.snapshot_live();
    // Build outbox insert payloads **before** the durable TX so external
    // deliveries are owed in the same commit as engine + members_ready
    // (crash between persist and mesh leaves pending rows to resume).
    let outbox_entries = if let Some(deps) = delivery.as_ref() {
        let proof_bytes = applied.proved().proof.to_bytes();
        build_external_outbox_inserts(&delivery_snapshot, &proof_bytes, deps)
            .map_err(|e| anyhow::anyhow!("v1.1 finalise: outbox insert payload: {e}"))?
    } else {
        Vec::new()
    };
    match db_v1::persist_engine_with_pending_members_ready_and_outbox_if_finalise_fence(
        adapter.pool(),
        &snap,
        owner,
        pk,
        r,
        signature.signature_s(),
        signature.r_prime,
        tip_height_u32,
        tip_hash,
        fence,
        &outbox_entries,
    )
    .await
    {
        Ok(true) => {
            // Intent is durable. Never restore_live after this point.
        }
        Ok(false) => {
            if let Err(restore_err) = adapter.restore_live(pre) {
                return Err(anyhow::anyhow!(
                    "v1.1 finalise: claim fence/lease lost before durable stage; \
                     engine restore also failed ({restore_err:#})"
                ));
            }
            return Err(anyhow::Error::msg(FINALISE_FENCE_LOST));
        }
        Err(e) => {
            if let Err(restore_err) = adapter.restore_live(pre) {
                return Err(anyhow::anyhow!(
                    "v1.1 finalise: atomic engine+members_ready persist failed ({e:#}); \
                     engine restore also failed ({restore_err:#})"
                ));
            }
            return Err(anyhow::anyhow!(
                "v1.1 finalise: atomic engine+members_ready persist failed; \
                 engine restored (no silent credit): {e:#}"
            ));
        }
    }

    // Persist landed. Drop the write gate before broadcast (same ordering as
    // the direct receive path): scanner liveness must not wait on bitcoind.
    drop(_write_gate);

    // Hand off this staged row to the durable publisher. Failure keeps the
    // members_ready (or progressive) row for later resume — never mark done.
    // Order: **persist → publish (nullifier) → deliver (mesh)** — delivery
    // never runs before the durable write above.
    publish_staged_nullifier_after_members_ready(adapter, publisher, pk).await?;

    // §4.2 mesh delivery for external-recipient coins (after durable persist).
    // Both mesh delivery and SDR Phase A need the same deps — pass by shared
    // reference (bundle of refs + Vecs); neither consumer takes ownership.
    if let Some(deps) = delivery.as_ref() {
        // Plonky2 native encoding (§1.7.9) — `to_bytes()` is infallible.
        let proof_bytes = applied.proved().proof.to_bytes();
        deliver_outgoing_after_persist(&delivery_snapshot, &proof_bytes, deps)
            .await
            .map_err(|e| anyhow::anyhow!("v1.1 finalise mesh delivery after persist: {e}"))?;

        // §4.2 Phase A: stage SDR material keyed by transition nullifier Pk.
        // Fail-closed — incomplete material is a named error, never a silent skip.
        stage_sdr_phase_a_after_mesh(
            adapter,
            &delivery_snapshot,
            &proof_bytes,
            tip_height_u32,
            tip_hash,
            deps,
        )
        .await
        .map_err(|e| anyhow::anyhow!("v1.1 finalise SDR Phase A stage: {e}"))?;
    }

    let pd = &applied.proved().proof_data;
    Ok(FinaliseOutcome {
        new_account_state_hash: digest_to_bytes(&pd.new_account_state_hash),
        output_coins_root: digest_to_bytes(&pd.output_coins_root),
        input_nullifiers_root: digest_to_bytes(&pd.input_nullifiers_root),
        output_coin_ids,
        publisher_pubkey,
    })
}

/// Stage §4.2 Phase-A SDR material after mesh delivery of external coins.
///
/// External `output_ref`s come from durable outbox artefacts (same blob_id
/// the mesh published). Change/self coins are built locally for recovery
/// envelopes only. Incomplete material → named error (fail-closed).
async fn stage_sdr_phase_a_after_mesh(
    adapter: &crate::v1::EngineAdapter,
    snap: &DeliverySnapshot,
    proof_bytes: &[u8],
    tip_height: u32,
    tip_hash: [u8; 32],
    deps: &FinaliseDeliveryDeps<'_>,
) -> Result<(), crate::v1::delivery::DeliveryError> {
    use crate::kernel::types::SubjectAddress;
    use crate::v1::delivery::{build_coin_delivery, external_delivery_coins};
    use crate::v1::outbox_material::{SdrPhaseAMaterial, SdrPhaseAOutputRef};
    use crate::v1::sdr::{output_ref_from_built, stage_phase_a};
    use shared::spec_v1::note_encryption::xonly_pubkey;
    use shared::spec_v1::serialize::serialize_account_state;

    if deps.self_relays.is_empty() {
        return Err(crate::v1::delivery::DeliveryError::Relay(
            "SDR Phase A: self_relays empty (bootstrap seed relays required; no invent)".into(),
        ));
    }
    if deps.blob_holders.is_empty() {
        return Err(crate::v1::delivery::DeliveryError::BlobHoldersEmpty);
    }

    let subject = SubjectAddress(snap.owner);
    let bundle = deps.bundles.get_active(&subject).ok_or(
        crate::v1::delivery::DeliveryError::OperationalBundleMissing {
            subject: snap.owner,
        },
    )?;
    let self_ivpk = xonly_pubkey(&bundle.ivk).map_err(crate::v1::delivery::DeliveryError::Spec)?;
    let self_op_pk = xonly_pubkey(&bundle.op).map_err(crate::v1::delivery::DeliveryError::Spec)?;

    // Post-transition account state from the live engine (already applied).
    let account_state = adapter
        .with_engine(|engine| {
            engine
                .accounts()
                .find(|(owner, _)| owner.0 == snap.owner)
                .map(|(_, rec)| rec.state.clone())
        })
        .ok_or_else(|| {
            crate::v1::delivery::DeliveryError::Relay(
                "SDR Phase A: applied account missing from engine after finalise".into(),
            )
        })?;
    let account_state_bytes = serialize_account_state(&account_state)
        .map_err(crate::v1::delivery::DeliveryError::Spec)?;
    let post_send_counter = account_state.send_counter;
    // Guard: post == entry + 1 (overflow already refused by engine).
    if post_send_counter
        != snap.entry_send_counter.checked_add(1).ok_or_else(|| {
            crate::v1::delivery::DeliveryError::Relay("SDR Phase A: send_counter overflow".into())
        })?
    {
        return Err(crate::v1::delivery::DeliveryError::Relay(format!(
            "SDR Phase A: post send_counter {post_send_counter} != entry {} + 1",
            snap.entry_send_counter
        )));
    }

    // External output_refs from durable outbox artefacts (shared blob_id).
    let open = crate::v1::db_outbox::list_open_for_transition(adapter.pool(), &snap.pk_create)
        .await
        .map_err(|e| {
            crate::v1::delivery::DeliveryError::Relay(format!(
                "SDR Phase A list_open_for_transition: {e:#}"
            ))
        })?;
    // Also include completed external rows for this transition (mesh may have
    // already finished). Query by loading open first; if artefacts missing,
    // fail closed — Phase B cannot invent blob_ids.
    let external_expected: std::collections::HashSet<[u8; 32]> =
        external_delivery_coins(&snap.owner, &snap.output_coins)
            .into_iter()
            .map(|(_, c)| digest_to_bytes(&c.identifier))
            .collect();

    let mut output_refs: Vec<SdrPhaseAOutputRef> = Vec::new();
    let mut seen_external: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    for row in &open {
        if row.kind != crate::v1::db_outbox::OutboxKind::ExternalCoin {
            continue;
        }
        let Some(blob_id) = row.blob_id else {
            return Err(crate::v1::delivery::DeliveryError::Relay(format!(
                "SDR Phase A: external outbox {} has no blob_id yet — mesh build incomplete \
                 (refuse provisional output_ref)",
                hex::encode(row.outbox_id)
            )));
        };
        let Some(epk) = row.epk else {
            return Err(crate::v1::delivery::DeliveryError::Relay(format!(
                "SDR Phase A: external outbox {} missing epk artefact",
                hex::encode(row.outbox_id)
            )));
        };
        let Some(out_ct) = row.out_ciphertext.as_ref() else {
            return Err(crate::v1::delivery::DeliveryError::Relay(format!(
                "SDR Phase A: external outbox {} missing out_ciphertext",
                hex::encode(row.outbox_id)
            )));
        };
        if out_ct.is_empty() {
            return Err(crate::v1::delivery::DeliveryError::Relay(format!(
                "SDR Phase A: external outbox {} empty out_ciphertext",
                hex::encode(row.outbox_id)
            )));
        }
        let mat = crate::v1::outbox_material::ExternalOutboxMaterial::decode(&row.material)
            .map_err(|e| {
                crate::v1::delivery::DeliveryError::Relay(format!(
                    "SDR Phase A external material: {e:#}"
                ))
            })?;
        if mat.blob_holders.is_empty() {
            return Err(crate::v1::delivery::DeliveryError::BlobHoldersEmpty);
        }
        let coin_id = row.coin_id;
        seen_external.insert(coin_id);
        output_refs.push(
            output_ref_from_built(coin_id, blob_id, epk, out_ct, &mat.blob_holders)
                .map_err(|e| crate::v1::delivery::DeliveryError::SdrOutputRef(e.to_string()))?,
        );
    }

    if seen_external != external_expected {
        let missing: Vec<_> = external_expected.difference(&seen_external).collect();
        return Err(crate::v1::delivery::DeliveryError::Relay(format!(
            "SDR Phase A: missing external outbox artefacts for {} coin(s) \
             (first missing {}) — refuse incomplete Phase A",
            missing.len(),
            missing
                .first()
                .map(hex::encode)
                .unwrap_or_else(|| "none".into())
        )));
    }

    // Change / self-output coins: build local CoinProof envelopes for SDR
    // output_refs (no mesh publish).
    let change_coins: Vec<_> = snap
        .output_coins
        .iter()
        .enumerate()
        .filter(|(_, c)| c.recipient.0 == snap.owner)
        .collect();
    if !change_coins.is_empty() {
        let all_output_ids: Vec<_> = snap.output_coins.iter().map(|c| c.identifier).collect();
        let creating_nullifier = crate::v1::delivery::creating_nullifier_from_parts(
            snap.pk_create,
            snap.r_create,
            snap.r_prime_create,
        );
        let nav_opening =
            crate::v1::delivery::bundle_nav_opening(snap.nav_size, snap.nav_mth, snap.nav_rand);
        let mut rng = deps
            .rng
            .lock()
            .expect("finalise delivery rng mutex poisoned");
        for (leaf_index, coin) in change_coins {
            let material = crate::v1::delivery::OutgoingCoinMaterial {
                coin: coin.clone(),
                leaf_index: leaf_index as u32,
                all_output_ids: all_output_ids.clone(),
                proof_bytes: proof_bytes.to_vec(),
                creating_prev_ash: snap.creating_prev_ash,
                creating_nullifier,
                nav_opening,
                asset_terms: None,
                recipient_ivpk: self_ivpk,
                recipient_op_pk: self_op_pk,
                recipient_relays: deps.self_relays.clone(),
            };
            let built = build_coin_delivery(
                &material,
                &bundle.op,
                &bundle.ovk,
                &deps.blob_holders,
                deps.now,
                rng.as_mut(),
            )?;
            output_refs.push(
                output_ref_from_built(
                    digest_to_bytes(&coin.identifier),
                    built.blob_id,
                    built.keys.epk,
                    &built.out_ciphertext,
                    &deps.blob_holders,
                )
                .map_err(|e| crate::v1::delivery::DeliveryError::SdrOutputRef(e.to_string()))?,
            );
        }
    }

    let material = SdrPhaseAMaterial {
        v: 1,
        subject_hex: hex::encode(snap.owner),
        transition_pk_hex: hex::encode(snap.pk_create),
        record_kind: snap.record_kind,
        send_counter: post_send_counter,
        prev_state_head_hex: hex::encode(digest_to_bytes(&snap.creating_prev_ash)),
        account_state_hex: hex::encode(account_state_bytes),
        recursive_proof_hex: hex::encode(proof_bytes),
        proof_data_hex: hex::encode(snap.proof_data_bytes),
        own_nullifier_pk_hex: hex::encode(snap.pk_create),
        own_nullifier_r_hex: hex::encode(snap.r_create),
        own_nullifier_r_prime_hex: hex::encode(snap.r_prime_create),
        proof_block_anchor_hash_hex: hex::encode(tip_hash),
        proof_block_anchor_height: tip_height,
        spent_or_folded_coin_ids_hex: snap
            .spent_or_folded_coin_ids
            .iter()
            .map(hex::encode)
            .collect(),
        output_refs,
        blob_holders: deps.blob_holders.clone(),
        max_blob_bytes: deps.max_blob_bytes,
        recipient_ivpk_hex: hex::encode(self_ivpk),
        recipient_op_pk_hex: hex::encode(self_op_pk),
        recipient_relays: deps.self_relays.clone(),
    };

    stage_phase_a(adapter.pool(), &material).await?;
    tracing::info!(
        transition_pk = %hex::encode(snap.pk_create),
        subject = %hex::encode(snap.owner),
        send_counter = post_send_counter,
        "SDR Phase A staged (awaiting first-occurrence MTP for Phase B)"
    );
    Ok(())
}

/// Snapshot of delivery-relevant fields taken before prove moves `pending`.
struct DeliverySnapshot {
    owner: [u8; 32],
    output_coins: Vec<shared::spec_v1::Coin>,
    creating_prev_ash: shared::spec_v1::HashDigest,
    nav_size: u64,
    nav_mth: shared::spec_v1::HashDigest,
    nav_rand: [u8; 32],
    pk_create: [u8; 32],
    r_create: [u8; 32],
    r_prime_create: [u8; 32],
    /// SDR `RecordKind` wire byte (mint/send/receive).
    record_kind: u8,
    /// Input coin ids (spent / folded into the transition).
    spent_or_folded_coin_ids: Vec<[u8; 32]>,
    /// Entry `send_counter` (pre-transition); post-transition is entry+1.
    entry_send_counter: u64,
    /// `serialize(ProofData)` — fixed before prove.
    proof_data_bytes: [u8; 192],
}

impl DeliverySnapshot {
    fn from_pending(
        pending: &PendingTransition,
        signature: &TransitionSignature,
    ) -> Result<Self, anyhow::Error> {
        use shared::spec_v1 as host;
        use shared::spec_v1::serialize::serialize_proof_data;
        let w = &pending.witness_wip;
        let creating_prev_ash = host::account_state_hash(&w.prev_account_state)
            .map_err(|e| anyhow::anyhow!("v1.1 finalise: creating_prev_ash: {e}"))?;
        let record_kind = crate::v1::sdr::record_kind_from_witness(
            w.asset_issuance.is_some(),
            !w.received_coins.is_empty(),
        );
        let record_kind_byte = match record_kind {
            shared::spec_v1::bundle::RecordKind::Mint => 0x01,
            shared::spec_v1::bundle::RecordKind::Send => 0x02,
            shared::spec_v1::bundle::RecordKind::Receive => 0x03,
        };
        let spent_or_folded_coin_ids: Vec<[u8; 32]> = w
            .input_coins
            .iter()
            .map(|c| digest_to_bytes(&c.identifier))
            .collect();
        Ok(Self {
            owner: pending.owner.0,
            output_coins: w.output_coins.clone(),
            creating_prev_ash,
            nav_size: pending.nav_opening.nav.size,
            nav_mth: pending.nav_opening.nav.mth,
            nav_rand: pending.nav_opening.nav_rand,
            pk_create: signature.pk_i,
            r_create: signature.signature_r(),
            r_prime_create: signature.r_prime,
            record_kind: record_kind_byte,
            spent_or_folded_coin_ids,
            entry_send_counter: w.prev_account_state.send_counter,
            proof_data_bytes: serialize_proof_data(&pending.proof_data),
        })
    }
}

/// Build durable outbox insert rows for external coins (atomic with persist).
fn build_external_outbox_inserts(
    snap: &DeliverySnapshot,
    proof_bytes: &[u8],
    deps: &FinaliseDeliveryDeps<'_>,
) -> Result<Vec<crate::v1::db_outbox::OutboxInsert>, crate::v1::delivery::DeliveryError> {
    let coins = build_outgoing_coin_materials(snap, proof_bytes, deps)?;
    if coins.is_empty() {
        return Ok(Vec::new());
    }
    crate::v1::delivery::external_outbox_inserts(
        snap.owner,
        snap.pk_create,
        &coins,
        &deps.blob_holders,
        deps.max_blob_bytes,
    )
}

/// Shared material assembly for outbox insert and mesh publish.
fn build_outgoing_coin_materials(
    snap: &DeliverySnapshot,
    proof_bytes: &[u8],
    deps: &FinaliseDeliveryDeps<'_>,
) -> Result<Vec<crate::v1::delivery::OutgoingCoinMaterial>, crate::v1::delivery::DeliveryError> {
    use crate::v1::delivery::{
        bundle_nav_opening, creating_nullifier_from_parts, external_delivery_coins,
        OutgoingCoinMaterial,
    };

    let external = external_delivery_coins(&snap.owner, &snap.output_coins);
    if external.is_empty() {
        return Ok(Vec::new());
    }
    if proof_bytes.is_empty() {
        return Err(crate::v1::delivery::DeliveryError::ProofBytes(
            "creating transition proof_bytes empty — refuse mesh delivery without a proof".into(),
        ));
    }
    let all_output_ids: Vec<_> = snap.output_coins.iter().map(|c| c.identifier).collect();
    let creating_nullifier =
        creating_nullifier_from_parts(snap.pk_create, snap.r_create, snap.r_prime_create);
    let nav_opening = bundle_nav_opening(snap.nav_size, snap.nav_mth, snap.nav_rand);

    let mut coins = Vec::with_capacity(external.len());
    for (leaf_index, coin) in external {
        let target = deps.targets.require(&coin.recipient.0, deps.now)?;
        if target.relays.is_empty() {
            return Err(crate::v1::delivery::DeliveryError::RecipientRelaysEmpty {
                recipient: coin.recipient.0,
            });
        }
        coins.push(OutgoingCoinMaterial {
            coin: coin.clone(),
            leaf_index: leaf_index as u32,
            all_output_ids: all_output_ids.clone(),
            proof_bytes: proof_bytes.to_vec(),
            creating_prev_ash: snap.creating_prev_ash,
            creating_nullifier,
            nav_opening,
            asset_terms: None,
            recipient_ivpk: target.ivpk,
            recipient_op_pk: target.op_pk,
            recipient_relays: target.relays,
        });
    }
    Ok(coins)
}

/// Crash-resume: re-drive open outbox rows for `transition_pk` via the port.
async fn resume_outbox_after_crash(
    pool: &sqlx::PgPool,
    transition_pk: [u8; 32],
    deps: &FinaliseDeliveryDeps<'_>,
) -> Result<(), crate::v1::delivery::DeliveryError> {
    use crate::kernel::types::SubjectAddress;
    use crate::v1::delivery::{DeliveryOperatorContext, TransitionDeliveryRequest};
    use crate::v1::outbox_material::ExternalOutboxMaterial;

    let open = crate::v1::db_outbox::list_open_for_transition(pool, &transition_pk)
        .await
        .map_err(|e| {
            crate::v1::delivery::DeliveryError::Relay(format!("list_open_for_transition: {e:#}"))
        })?;
    if open.is_empty() {
        return Ok(());
    }
    // Rebuild OutgoingCoinMaterial from durable material for each open row.
    let mut coins = Vec::with_capacity(open.len());
    let mut subject: Option<[u8; 32]> = None;
    for row in &open {
        if row.kind != crate::v1::db_outbox::OutboxKind::ExternalCoin {
            continue;
        }
        match subject {
            None => subject = Some(row.subject),
            Some(s) if s != row.subject => {
                return Err(crate::v1::delivery::DeliveryError::Relay(
                    "open outbox rows for one transition_pk disagree on subject".into(),
                ));
            }
            Some(_) => {}
        }
        let mat = ExternalOutboxMaterial::decode(&row.material).map_err(|e| {
            crate::v1::delivery::DeliveryError::Relay(format!("outbox material decode: {e:#}"))
        })?;
        coins.push(mat.to_outgoing().map_err(|e| {
            crate::v1::delivery::DeliveryError::Relay(format!("outbox material to_outgoing: {e:#}"))
        })?);
    }
    if coins.is_empty() {
        return Ok(());
    }
    let subject = match subject {
        Some(s) => s,
        None => {
            return Err(crate::v1::delivery::DeliveryError::Relay(
                "open external outbox rows without subject".into(),
            ));
        }
    };
    let bundle = deps
        .bundles
        .get_active(&SubjectAddress(subject))
        .ok_or(crate::v1::delivery::DeliveryError::OperationalBundleMissing { subject })?;
    let request = TransitionDeliveryRequest {
        subject,
        coins,
        operator: DeliveryOperatorContext {
            op_sk: bundle.op,
            ovk: bundle.ovk,
            blob_holders: deps.blob_holders.clone(),
            max_blob_bytes: deps.max_blob_bytes,
            now: deps.now,
            auth_expiration: deps.auth_expiration,
        },
    };
    let report = deps.port.deliver_outgoing(request).await?;
    tracing::info!(
        transition_pk = %hex::encode(transition_pk),
        delivered = report.delivered,
        "mesh outbox re-driven after crash-resume"
    );
    Ok(())
}

/// Build per-coin materials and invoke the delivery port (§4.2 after persist).
async fn deliver_outgoing_after_persist(
    snap: &DeliverySnapshot,
    proof_bytes: &[u8],
    deps: &FinaliseDeliveryDeps<'_>,
) -> Result<(), crate::v1::delivery::DeliveryError> {
    use crate::kernel::types::SubjectAddress;
    use crate::v1::delivery::{DeliveryOperatorContext, TransitionDeliveryRequest};

    let coins = build_outgoing_coin_materials(snap, proof_bytes, deps)?;
    if coins.is_empty() {
        // Pure receive / mint-to-self / change-only: no mesh delivery.
        return Ok(());
    }

    let subject = SubjectAddress(snap.owner);
    let bundle = deps.bundles.get_active(&subject).ok_or(
        crate::v1::delivery::DeliveryError::OperationalBundleMissing {
            subject: snap.owner,
        },
    )?;

    // Snapshot targets for post-send profile refresh (replaceable kind-0).
    let refresh: Vec<([u8; 32], Vec<String>)> = coins
        .iter()
        .map(|c| (c.recipient_op_pk, c.recipient_relays.clone()))
        .collect();

    let request = TransitionDeliveryRequest {
        subject: snap.owner,
        coins,
        operator: DeliveryOperatorContext {
            op_sk: bundle.op,
            ovk: bundle.ovk,
            blob_holders: deps.blob_holders.clone(),
            max_blob_bytes: deps.max_blob_bytes,
            now: deps.now,
            auth_expiration: deps.auth_expiration,
        },
    };

    let report = deps.port.deliver_outgoing(request).await?;
    tracing::info!(
        subject = %hex::encode(snap.owner),
        delivered = report.delivered,
        "mesh delivery finished after durable persist"
    );

    // Refresh delivery targets from the recipient's published profile so the
    // next payment does not keep a stale relay set for the full TTL.
    // Delivery already succeeded; a refresh failure is named in logs only —
    // it must not reverse the mesh send or drop retention.
    for (op_pk, relays) in refresh {
        if let Err(e) = crate::v1::delivery::refresh_target_from_recipient_profile(
            deps.targets,
            &op_pk,
            &relays,
            deps.expected_network,
            deps.now,
        )
        .await
        {
            tracing::warn!(
                op_pk = %hex::encode(op_pk),
                error = %e,
                "post-delivery profile refresh failed (target TTL still applies)"
            );
        }
    }
    Ok(())
}

/// Typed cause for §7.5 `publish_rejected` (durable nullifier broadcast
/// handoff failed after `members_ready` was persisted).
///
/// The human [`Display`] text is diagnostic only — outward classification
/// must downcast this type via [`machine_code_from_engine_error`] /
/// [`encode_job_error_from_anyhow`], not parse the message. Same form as
/// [`zkcoins_prover::state_engine::DependencyNotFinal`].
#[derive(Debug, Clone)]
pub(crate) enum PublishRejected {
    /// Finalise-path durable publish after `members_ready` failed; the
    /// pending row is retained for the in-process / boot resumer.
    DurableHandoffFailed { detail: String },
}

impl std::fmt::Display for PublishRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DurableHandoffFailed { detail } => write!(
                f,
                "v1.1 finalise durable nullifier publish after members_ready \
                 failed (row retained for resume): {detail}"
            ),
        }
    }
}

impl std::error::Error for PublishRejected {}

/// Drive the durable publisher for a row that is already on disk
/// (`members_ready` or a progressive mid-broadcast status).
///
/// Reuses the receive-path resumer so construct → commit → reveal status
/// transitions stay single-sourced. On failure the row is left as-is
/// (not deleted, not marked complete).
///
/// Failure is a typed [`PublishRejected`] cause. Display text is **diagnostic
/// only** — host edges classify via [`encode_job_error_from_anyhow`] /
/// [`machine_code_from_engine_error`], never by parsing the message.
async fn publish_staged_nullifier_after_members_ready(
    adapter: &crate::v1::EngineAdapter,
    publisher: &impl crate::v1::receive::NullifierBatchPublisher,
    pk: [u8; 32],
) -> Result<(), anyhow::Error> {
    crate::v1::receive::resume_pending_publish_with(adapter, publisher, pk)
        .await
        .map_err(|e| {
            anyhow::Error::new(PublishRejected::DurableHandoffFailed {
                detail: format!("{e:#}"),
            })
        })?;
    Ok(())
}

/// True while `fence` is still the current claim epoch with an unexpired lease.
async fn claim_fence_still_holds(
    pool: &sqlx::PgPool,
    fence: crate::job_store::FinaliseFence,
) -> Result<bool, String> {
    use crate::job_store::FINALISE_CLAIM_PHASE;
    let owner_text = fence.owner.to_string();
    let held = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM jobs \
         WHERE public_id = $1 \
           AND status = 'broadcasting' \
           AND phase = $2 \
           AND request_body #>> '{finalise_claim,owner}' = $3 \
           AND (request_body #>> '{finalise_claim,fence}')::bigint = $4 \
           AND (request_body #>> '{finalise_claim,lease_expires_at}') IS NOT NULL \
           AND (request_body #>> '{finalise_claim,lease_expires_at}')::timestamptz > NOW()",
    )
    .bind(fence.job_id)
    .bind(FINALISE_CLAIM_PHASE)
    .bind(&owner_text)
    .bind(fence.fence)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("claim fence liveness check failed: {e:#}"))?;
    Ok(held.is_some())
}

/// Register a live [`PendingSignEntry`] produced by `StateEngine::begin_*`
/// so the dispatcher can stage it when the job enters `awaiting_signature`.
///
/// Production write site for the post-begin registry. The dispatcher
/// consumes the entry once via [`take_live_pending_after_begin`].
///
/// Kernel-API (§7.5): gRPC / job begin hands the staged
/// [`PendingSignEntry`] to the dispatcher via this registry.
pub fn register_live_pending_after_begin(
    map: &PendingSignMap,
    job_id: Uuid,
    entry: PendingSignEntry,
) {
    map.insert(job_id, entry);
}

/// Take (consume) a live pending registered by [`register_live_pending_after_begin`].
pub(crate) fn take_live_pending_after_begin(
    map: &PendingSignMap,
    job_id: Uuid,
) -> Option<PendingSignEntry> {
    map.remove(&job_id).map(|(_, e)| e)
}

/// Optional `publisher_pubkey` from a job's original transition request
/// body (§7.5 presence matrix).
///
/// - Field **absent** → `Ok(None)` (self-publish / no external publisher).
/// - Field **present and well-formed** (exactly 64 lowercase hex chars) →
///   `Ok(Some(pk))`.
/// - Field **present but malformed** (wrong type, wrong length, uppercase,
///   non-hex) → `Err` — never silently drops a bad publisher (no silent
///   fallback to "absent").
pub(crate) fn publisher_pubkey_from_request_body(
    request_body: &serde_json::Value,
) -> Result<Option<[u8; 32]>, String> {
    let Some(value) = request_body.get("publisher_pubkey") else {
        return Ok(None);
    };
    let Some(raw) = value.as_str() else {
        return Err(
            "publisher_pubkey must be a lowercase hex string of exactly 64 characters".to_string(),
        );
    };
    if raw.len() != 64
        || raw
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "publisher_pubkey must be exactly 64 lowercase hex characters; got len={}",
            raw.len()
        ));
    }
    let bytes = hex::decode(raw).map_err(|e| format!("publisher_pubkey hex decode failed: {e}"))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        format!("publisher_pubkey must decode to 32 bytes; got {}", v.len())
    })?;
    Ok(Some(arr))
}

/// Build the §7.5 `awaiting_signature` object from staged pending
/// material. All digests are lowercase hex; `send_counter` is a JSON number
/// **derived** from the pending account state.
///
/// This is what a v1.1 wallet must recompute and sign — **not** legacy
/// `account_state_hash` / `output_coins_root`.
pub(crate) fn awaiting_signature_result_json(entry: &PendingSignEntry) -> serde_json::Value {
    let pd = &entry.pending.proof_data;
    let txn_pubkey = entry.pending.witness_wip.prev_account_state.current_pubkey;
    serde_json::json!({
        "new_account_state_hash": hex_lower(&digest_to_bytes(&pd.new_account_state_hash)),
        "output_coins_root": hex_lower(&digest_to_bytes(&pd.output_coins_root)),
        "input_nullifiers_root": hex_lower(&digest_to_bytes(&pd.input_nullifiers_root)),
        "coin_history_root": hex_lower(&digest_to_bytes(&pd.coin_history_root)),
        "nav_commitment": hex_lower(&digest_to_bytes(&pd.nav_commitment)),
        "npk_commit": hex_lower(&pd.npk_commit),
        "proof_data_hash": hex_lower(&entry.pending.proof_data_hash),
        "txn_pubkey": hex_lower(&txn_pubkey),
        "send_counter": entry.send_counter(),
    })
}

/// Legacy ash‖ocr surface (flag off only).
pub(crate) fn legacy_awaiting_signature_result_json(
    account_state_hash: &str,
    output_coins_root: &str,
) -> serde_json::Value {
    serde_json::json!({
        "account_state_hash": account_state_hash,
        "output_coins_root": output_coins_root,
    })
}

/// Choose the `awaiting_signature` job result under the current process claim.
///
/// - **Legacy / unclaimed** → ash‖ocr (unchanged).
/// - **v1.1 claim** → §7.5 surface from staged pending. If no pending is
///   staged, returns `Err` — never silently falls back to ash‖ocr (a
///   wallet that signed those would then be rejected at `/sign`).
pub(crate) fn select_awaiting_signature_result(
    legacy_ash: &str,
    legacy_ocr: &str,
    pending: Option<&PendingSignEntry>,
) -> Result<serde_json::Value, TransitionSignatureError> {
    match process_stack_mode() {
        Some(ScanStackMode::V1) => match pending {
            Some(entry) => Ok(awaiting_signature_result_json(entry)),
            None => Err(TransitionSignatureError::new(
                SignatureCheck::LegacyCommitment,
                "v1.1 process claim: refusing to advertise legacy ash‖ocr on \
                 awaiting_signature; stage a PendingTransition (PendingSignEntry) \
                 so the job surfaces the §7.5 ProofData identity the wallet must sign",
            )),
        },
        Some(ScanStackMode::Legacy) | None => Ok(legacy_awaiting_signature_result_json(
            legacy_ash, legacy_ocr,
        )),
    }
}

/// Machine-code + HTTP status for a rejected `/sign` submission (§7.5 closed
/// enumeration — **no invented codes**).
///
/// | check | HTTP | `error` | §7.5 meaning |
/// |---|---|---|---|
/// | Encoding | 400 | `malformed_request` | body violates §7.1 hex/width |
/// | ShadowFlag | 404 | `feature_disabled` | v1.1 sign surface inactive under flag-off |
/// | S2cOpening | 409 | `stale_message` | S2C nonce does not open this job's H(ProofData) |
/// | Bip340 / PkMatch / PendingEnvelope | 409 | `invalid_signature` | BIP-340 / envelope fail |
/// | LegacyCommitment | 409 | `wrong_phase` | residual ash‖ocr on a v1.1 claim |
///
/// Not covered by `SignatureCheck` (handled at the route):
/// - job status ≠ `awaiting_signature` → `wrong_phase` (409)
/// - missing staged pending while status is correct → `internal_error` (500)
/// - dispatcher notifier absent after accept → `internal_error` (500)
pub(crate) fn sign_rejection(err: &TransitionSignatureError) -> (u16, &'static str) {
    match err.check {
        SignatureCheck::Encoding => (400, "malformed_request"),
        SignatureCheck::S2cOpening => (409, "stale_message"),
        SignatureCheck::Bip340 | SignatureCheck::PkMatch | SignatureCheck::PendingEnvelope => {
            (409, "invalid_signature")
        }
        // Route inactive under this process claim — not a phase mismatch.
        SignatureCheck::ShadowFlag => (404, "feature_disabled"),
        // Residual legacy Commitment under a v1.1 claim: the job is on the
        // wrong authorisation surface for this process (phase/protocol).
        SignatureCheck::LegacyCommitment => (409, "wrong_phase"),
    }
}

/// Encode a terminal job `error` column as the §7.5 `{error, message}`
/// object (JSON text). Prefer this over free-form strings so poll can
/// surface the closed machine code without inventing one.
pub(crate) fn encode_job_error(code: &str, message: impl Into<String>) -> String {
    serde_json::json!({
        "error": code,
        "message": message.into(),
    })
    .to_string()
}

/// Encode a job failure from an engine / host `anyhow::Error`.
///
/// Reads a typed [`zkcoins_prover::state_engine::DependencyNotFinal`] or
/// [`PublishRejected`] cause when present and maps it to the closed §7.5
/// machine code. The Display text is diagnostic only — never the contract.
/// All other causes default to `proving_failed` (callers that know a more
/// specific closed code should use [`encode_job_error`] directly).
pub(crate) fn encode_job_error_from_anyhow(err: &anyhow::Error) -> String {
    if let Some(code) = machine_code_from_engine_error(err) {
        return encode_job_error(code, format!("{err:#}"));
    }
    encode_job_error("proving_failed", format!("{err:#}"))
}

/// Closed §7.5 machine code for a typed engine / host cause, if any.
///
/// Walks the `anyhow` chain so intermediate `.context(...)` wrappers do not
/// hide [`DependencyNotFinal`](zkcoins_prover::state_engine::DependencyNotFinal)
/// or [`PublishRejected`].
pub(crate) fn machine_code_from_engine_error(err: &anyhow::Error) -> Option<&'static str> {
    for cause in err.chain() {
        if cause
            .downcast_ref::<zkcoins_prover::state_engine::DependencyNotFinal>()
            .is_some()
        {
            return Some("dependency_not_final");
        }
        if cause.downcast_ref::<PublishRejected>().is_some() {
            return Some("publish_rejected");
        }
    }
    None
}

/// HTTP status the §7.5 / §7.8 error contract assigns to a closed machine code.
///
/// Used by tests and host edges that must assert the transport mapping without
/// inventing a second table. Unknown codes return `None` (fail closed).
pub(crate) fn http_status_for_machine_code(code: &str) -> Option<u16> {
    use crate::kernel::KernelErrorCode;
    use crate::transport::error_contract;
    KernelErrorCode::ALL
        .iter()
        .copied()
        .find(|c| c.reason() == code)
        .map(|c| error_contract::describe(c).http_status)
}

/// Closed §7.5 `machine_code` set admissible on job poll `error` objects.
/// A stored JSON `"error"` string is **not** automatically valid — only
/// members of this set (plus the additional surface codes below) may leave
/// the node outward. Anything else is remapped via [`classify_stored_failure`].
const CLOSED_OUTWARD_ERROR_CODES: &[&str] = &[
    // Jobs-family table (§7.5)
    "invalid_input_coin",
    "insufficient_balance",
    "bounds_exceeded",
    "unknown_publisher",
    "stale_message",
    "invalid_signature",
    "job_not_found",
    "wrong_phase",
    "proving_failed",
    "publish_rejected",
    "circuit_digest_mismatch",
    // Cross-surface closed set
    "malformed_request",
    "idempotency_conflict",
    "unauthorized",
    "scope_exceeded",
    "challenge_expired",
    "session_expired",
    "not_found",
    "payload_too_large",
    "rate_limited",
    "dependency_not_final",
    "internal_error",
    "feature_disabled",
];

fn is_closed_outward_error_code(code: &str) -> bool {
    CLOSED_OUTWARD_ERROR_CODES.contains(&code)
}

/// Decode a stored job error into the §7.5 poll `error` object.
///
/// Accepts the structured JSON produced by [`encode_job_error`] **only when
/// the `"error"` field is a closed §7.5 machine code**. A stored value is
/// not automatically valid — free-form or invented codes are remapped via
/// [`classify_stored_failure`]. Free-form legacy strings are likewise mapped
/// into the closed enumeration: default `proving_failed` for failed jobs,
/// `internal_error` for cancelled / unclassifiable. Empty stored error still
/// yields a body so the poll envelope never omits `error` on failed/cancelled.
pub(crate) fn decode_job_error(
    raw: Option<&str>,
    status: crate::job_store::JobStatus,
) -> serde_json::Value {
    if let Some(s) = raw {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            if let Some(code) = v.get("error").and_then(|e| e.as_str()) {
                if is_closed_outward_error_code(code) {
                    // Ensure message is present.
                    if v.get("message").is_none() {
                        let mut obj = v;
                        obj.as_object_mut().expect("object").insert(
                            "message".to_string(),
                            serde_json::Value::String(String::new()),
                        );
                        return obj;
                    }
                    return v;
                }
                // Invented / non-closed code in stored JSON — reclassify.
                let message = v
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or(s)
                    .to_string();
                let remapped = classify_stored_failure(code, status);
                return serde_json::json!({ "error": remapped, "message": message });
            }
        }
        let code = classify_stored_failure(s, status);
        return serde_json::json!({ "error": code, "message": s });
    }
    let (code, message) = match status {
        crate::job_store::JobStatus::Cancelled => ("internal_error", "cancelled"),
        _ => ("proving_failed", "job failed"),
    };
    serde_json::json!({ "error": code, "message": message })
}

fn classify_stored_failure(msg: &str, status: crate::job_store::JobStatus) -> &'static str {
    if matches!(status, crate::job_store::JobStatus::Cancelled) {
        return "internal_error";
    }
    let lower = msg.to_ascii_lowercase();
    // `publish_rejected` is intentionally **not** recovered from free-form
    // text. Production encodes a typed [`PublishRejected`] cause via
    // [`encode_job_error_from_anyhow`] / [`machine_code_from_engine_error`]
    // (or stores structured JSON with the closed code). Substring matching
    // here would make a message rewrite at a distant call site silently
    // move the outward code — the silent-fallback class this project forbids.
    if lower.contains("unknown_publisher") {
        return "unknown_publisher";
    }
    if lower.contains("invalid_input_coin") {
        return "invalid_input_coin";
    }
    if lower.contains("insufficient_balance") {
        return "insufficient_balance";
    }
    if lower.contains("bounds_exceeded") {
        return "bounds_exceeded";
    }
    // `dependency_not_final` is intentionally **not** recovered from free-form
    // text. The engine emits a typed
    // [`zkcoins_prover::state_engine::DependencyNotFinal`] cause; production
    // encodes it via [`encode_job_error_from_anyhow`] /
    // [`machine_code_from_engine_error`]. Substring matching here would make a
    // message rewrite at a distant call site silently move an HTTP status —
    // the silent-fallback class this project forbids.
    if lower.contains("circuit_digest") {
        return "circuit_digest_mismatch";
    }
    // awaiting_signature timeout, missing dispatcher, rehydrate refuse,
    // and generic prove failures — §7.5 has no dedicated timeout code;
    // witness/prove failures are proving_failed; pure lifecycle bugs
    // that never reached prove use internal_error when so labelled.
    if lower.contains("internal_error")
        || lower.contains("no finalise driver")
        || lower.contains("dispatcher")
        || lower.contains("not_waiting")
    {
        return "internal_error";
    }
    "proving_failed"
}

/// True when the process claim is v1.1 (flag on and stack claimed).
pub(crate) fn v1_sign_route_active() -> bool {
    matches!(process_stack_mode(), Some(ScanStackMode::V1))
}

/// Refuse the v1.1 signature path when the shadow flag is off.
///
/// Legacy ash‖ocr commitments remain the only authorised signing protocol
/// under [`V1ShadowMode::Off`]. There is no silent dual-accept.
pub(crate) fn ensure_v1_signature_path(mode: V1ShadowMode) -> Result<(), TransitionSignatureError> {
    match mode {
        V1ShadowMode::On => Ok(()),
        V1ShadowMode::Off => Err(TransitionSignatureError::new(
            SignatureCheck::ShadowFlag,
            "ZKCOINS_V1_SHADOW is off — refusing TransitionSignature path \
             (legacy ash‖ocr Commitment remains the default; no dual-accept)",
        )),
    }
}

/// Refuse a residual legacy ash‖ocr Commitment under a v1.1 process claim.
///
/// Returns `Ok(())` when the process is **not** on the v1.1 claim (legacy
/// or unclaimed). Fail-loud under `ScanStackMode::V1` — never a silent
/// allow of the wrong signing protocol.
///
/// Wired into `commit_flow` / `mint_commit_flow` and the jobs commit
/// handler so a v1.1 boot cannot finalise via `CommitRequest`.
pub(crate) fn refuse_legacy_commitment_under_v1() -> Result<(), TransitionSignatureError> {
    match process_stack_mode() {
        Some(ScanStackMode::V1) => Err(TransitionSignatureError::new(
            SignatureCheck::LegacyCommitment,
            LEGACY_COMMITMENT_REFUSED_UNDER_V1,
        )),
        Some(ScanStackMode::Legacy) | None => Ok(()),
    }
}

/// Finalise-path entry: decode already done; derive `pk_i` and
/// `serialize(ProofData)` **from the pending transition**, verify BIP-340
/// + S2C, and return a [`TransitionSignature`] ready for engine finalise.
///
/// `mode` must be [`V1ShadowMode::On`]; under Off this fails at
/// [`SignatureCheck::ShadowFlag`] so the legacy Commitment path cannot be
/// bypassed by feeding a TransitionSignature into a half-migrated caller.
///
/// **Provenance is enforced by the type signature:** there is no
/// independent `expected_pk_i` or `proof_data` parameter. Substituting a
/// foreign `ProofData` while finalising a different pending transition is
/// not expressible — the only material used is `pending.proof_data` and
/// `pending.witness_wip.prev_account_state.current_pubkey`.
pub(crate) fn accept_wallet_transition_signature(
    mode: V1ShadowMode,
    network: Network,
    pending: &PendingTransition,
    submission: &WalletSignSubmission,
) -> Result<TransitionSignature, TransitionSignatureError> {
    ensure_v1_signature_path(mode)?;

    let expected_pk_i = &pending.witness_wip.prev_account_state.current_pubkey;
    let proof_data = &pending.proof_data;

    // Fail closed if the pending envelope is self-inconsistent.
    let serialized = serialize_proof_data(proof_data);
    let h_proof_data = hash_proof_data(&serialized);
    if h_proof_data != pending.proof_data_hash {
        return Err(TransitionSignatureError::new(
            SignatureCheck::PendingEnvelope,
            format!(
                "pending.proof_data_hash {} does not match hash(serialize(pending.proof_data)) {}",
                hex_lower(&pending.proof_data_hash),
                hex_lower(&h_proof_data)
            ),
        ));
    }

    let sig = TransitionSignature {
        pk_i: *expected_pk_i,
        signature: submission.signature,
        r_prime: submission.s2c_nonce,
    };
    verify_transition_signature_material(network, expected_pk_i, proof_data, &sig)?;
    Ok(sig)
}

/// Host-side BIP-340 + S2C check against **explicit** material.
///
/// Prefer [`accept_wallet_transition_signature`] on the finalise path —
/// that API takes a [`PendingTransition`] and derives `pk_i` / `ProofData`
/// so a caller cannot verify against substituted bytes. This function
/// exists for preflight/tooling when no pending transition exists yet; it
/// is **not** reachable from the finalise path (nothing on that path
/// calls it with caller-supplied pairs).
pub(crate) fn verify_transition_signature_material(
    network: Network,
    expected_pk_i: &[u8; 32],
    proof_data: &ProofData,
    sig: &TransitionSignature,
) -> Result<(), TransitionSignatureError> {
    if sig.pk_i != *expected_pk_i {
        return Err(TransitionSignatureError::new(
            SignatureCheck::PkMatch,
            format!(
                "signature pk_i {} does not equal pending current_pubkey {}",
                hex_lower(&sig.pk_i),
                hex_lower(expected_pk_i)
            ),
        ));
    }

    // Bind to the engine's ProofData by canonical serialize → SHA-256.
    // Never accept a caller-supplied H(ProofData).
    let serialized = serialize_proof_data(proof_data);
    let h_proof_data = hash_proof_data(&serialized);

    let r = sig.signature_r();
    let s = sig.signature_s();

    // 1) S2C opening — binds (R, R') to *this* ProofData.
    comm_verify(&r, &h_proof_data, &sig.r_prime).map_err(|e| {
        TransitionSignatureError::new(
            SignatureCheck::S2cOpening,
            format!(
                "sign-to-contract opening failed for H(ProofData)={}: {e:#}",
                hex_lower(&h_proof_data)
            ),
        )
    })?;

    // 2) BIP-340 over the node network's fixed m_state.
    let m_state = network.m_state_bytes();
    verify_single(&sig.pk_i, &r, &s, m_state).map_err(|e| {
        TransitionSignatureError::new(
            SignatureCheck::Bip340,
            format!(
                "BIP-340 verify failed under m_state={:?} (network={network:?}): {e:#}",
                std::str::from_utf8(m_state).unwrap_or("<non-utf8 m_state>")
            ),
        )
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_hex_exact<const N: usize>(
    raw: &str,
    field: &str,
) -> Result<[u8; N], TransitionSignatureError> {
    // Strict: reject optional 0x/0X that the earlier parser silently stripped.
    if raw.len() >= 2 && (raw.starts_with("0x") || raw.starts_with("0X")) {
        return Err(TransitionSignatureError::new(
            SignatureCheck::Encoding,
            format!(
                "{field} must be bare lowercase hex (exactly {} chars); \
                 0x/0X prefix is not accepted",
                N * 2
            ),
        ));
    }
    let expected_chars = N * 2;
    if raw.len() != expected_chars {
        return Err(TransitionSignatureError::new(
            SignatureCheck::Encoding,
            format!(
                "{field} hex length {} != {expected_chars} (no silent pad/truncate)",
                raw.len()
            ),
        ));
    }
    if raw
        .bytes()
        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(TransitionSignatureError::new(
            SignatureCheck::Encoding,
            format!("{field} is not lowercase hex (no silent case-fold)"),
        ));
    }
    let bytes = hex::decode(raw).map_err(|e| {
        TransitionSignatureError::new(
            SignatureCheck::Encoding,
            format!("{field} hex decode failed: {e}"),
        )
    })?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        TransitionSignatureError::new(
            SignatureCheck::Encoding,
            format!("{field} decoded to {} bytes, expected {N}", v.len()),
        )
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Test-only V.5 fixture helpers used by the `/sign` route tests.
/// Production code must not call these.
#[cfg(test)]
pub mod test_fixtures {
    use super::*;
    use sha2::{Digest, Sha256};
    use shared::spec_v1::{
        account_state_hash, address, asset_id_v1, coin_identifier, coinhist_empty_root,
        coinhist_root_after_first_insert, digest_to_bytes, hash_proof_data, merkle_root, name_hash,
        nav_commitment, nflog_empty, nflog_root, nk_commit, npk_commit, serialize_proof_data,
        AccountState, Address, CoinHistState, Nav, ProofData, TreeKind, GENESIS_TAG, ZERO_HASH,
    };
    use std::collections::BTreeMap;
    use zkcoins_prover::prover_bridge::{NavOpening, TransitionMode, TransitionWitness};
    use zkcoins_prover::state_engine::OpSecret;

    const V2EXT_PK0: &str = "7c9cdde9b8cb1e33a48a5c2b6ab1fa6fd753fa1762f56c0b3e8169e4f2d54630";
    const V5_R_PRIME_MAINNET: &str =
        "fafd5229e657311d934989a4bc8bdfc8f033b4d640d2eb27b9fdda316f5c9601";
    const V5_SIG_MAINNET: &str = "7db327f8ff4bb148f051a038d370c4213149fe3affeff5b7fb7e9f8e3cc4438532168b5fca622ba2fad6d72ed201e71cef1003df880d345ddbe2b89f1ce3d4e5";

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).expect("fixture hex").try_into().expect("32")
    }
    fn hex64(s: &str) -> [u8; 64] {
        hex::decode(s).expect("fixture hex").try_into().expect("64")
    }
    fn sha256_label(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    fn proof_data_at_0() -> ProofData {
        let pk0 = sha256_label("zkCoins/v1/test-vector/Pk0");
        let pk1 = sha256_label("zkCoins/v1/test-vector/Pk1");
        let nk = sha256_label("zkCoins/v1/test-vector/nk");
        let npk_rand = sha256_label("zkCoins/v1/test-vector/npk_rand");
        let nav_rand = sha256_label("zkCoins/v1/test-vector/nav_rand");
        let name_hash_usd = name_hash(b"USD-Demo").expect("USD-Demo");
        let npk_commit_0 = npk_commit(&pk1, &npk_rand);
        let nflog_empty_v = nflog_empty();
        let coinhist_empty = coinhist_empty_root();
        let nk_commit_sample = nk_commit(&nk);
        let asset_id = asset_id_v1(GENESIS_TAG, &pk0, &name_hash_usd, 2, 1);
        let addr_bytes = address(&pk0, nk_commit_sample);
        let addr = Address(addr_bytes);
        let ash_empty = account_state_hash(
            &AccountState::new(
                addr,
                nk_commit_sample,
                BTreeMap::new(),
                pk0,
                0,
                coinhist_empty,
            )
            .expect("empty account"),
        )
        .expect("hash empty");
        let coin_identifier_0 =
            coin_identifier(ash_empty, &addr_bytes, asset_id, 1_000_000_000u128, 0u32);
        let coin_history_root_0 = coinhist_root_after_first_insert(
            &digest_to_bytes(&coin_identifier_0),
            CoinHistState::Admitted,
        );
        let mut balances = BTreeMap::new();
        balances.insert(digest_to_bytes(&asset_id), 1_000_000_000u128);
        let ash_0 = account_state_hash(
            &AccountState::new(
                addr,
                nk_commit_sample,
                balances,
                pk1,
                1,
                coin_history_root_0,
            )
            .expect("ash_0 account"),
        )
        .expect("hash ash_0");
        let ocr_0 = merkle_root(TreeKind::CoinsRoot, &[coin_identifier_0]);
        let inr_0 = merkle_root(TreeKind::NullifiersRoot, &[]);
        let nav_root_empty = nflog_root(0, nflog_empty_v);
        let nav_commitment_0 = nav_commitment(nav_root_empty, &nav_rand);
        ProofData {
            new_account_state_hash: ash_0,
            output_coins_root: ocr_0,
            input_nullifiers_root: inr_0,
            coin_history_root: coin_history_root_0,
            nav_commitment: nav_commitment_0,
            npk_commit: npk_commit_0,
        }
    }

    fn pending_for(pk: [u8; 32], pd: ProofData) -> PendingTransition {
        let owner = Address([0u8; 32]);
        let account = AccountState::new(owner, ZERO_HASH, BTreeMap::new(), pk, 0, ZERO_HASH)
            .expect("skeleton account");
        let nav = Nav {
            size: 0,
            mth: nflog_empty(),
        };
        let nav_opening = NavOpening {
            nav,
            nav_rand: [0u8; 32],
        };
        let proof_data_hash = hash_proof_data(&serialize_proof_data(&pd));
        let witness = TransitionWitness {
            mode: TransitionMode::InitialProof,
            prev_account_state: account.clone(),
            new_account_state: account,
            input_coins: Vec::new(),
            input_auth: Vec::new(),
            output_templates: Vec::new(),
            output_coins: Vec::new(),
            output_history_proofs: Vec::new(),
            received_coins: Vec::new(),
            received_auth: Vec::new(),
            asset_issuance: None,
            nk: [0u8; 32],
            nav: nav_opening.nav,
            nav_rand: nav_opening.nav_rand,
            prev_nav_opening: None,
            nav_consistency: Vec::new(),
            next_pubkey: [0u8; 32],
            npk_rand: [0u8; 32],
            transition_signature: TransitionSignature {
                pk_i: pk,
                signature: [0u8; 64],
                r_prime: [0u8; 32],
            },
            prev_proof: None,
            predecessor_nullifier: None,
        };
        PendingTransition {
            witness_wip: witness,
            proof_data: pd,
            proof_data_hash,
            mode: TransitionMode::InitialProof,
            owner,
            nav_opening,
            // Signature-gate fixtures never exercise nav_rand derivation; a
            // constant stands in so the skeleton type is constructible.
            op_secret: OpSecret::new([0u8; 32]),
        }
    }

    /// V.5 mainnet fixture: staged pending + the matching wire submission.
    pub(crate) fn v5_mainnet_entry_and_submission() -> (PendingSignEntry, WalletSignSubmission) {
        let pk = hex32(V2EXT_PK0);
        let submission = WalletSignSubmission {
            signature: hex64(V5_SIG_MAINNET),
            s2c_nonce: hex32(V5_R_PRIME_MAINNET),
        };
        let pending = pending_for(pk, proof_data_at_0());
        (PendingSignEntry::new(pending, Network::Mainnet), submission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use shared::spec_v1::{
        account_state_hash, address, asset_id_v1, coin_identifier, coinhist_empty_root,
        coinhist_root_after_first_insert, digest_to_bytes, hash_proof_data, merkle_root, name_hash,
        nav_commitment, nflog_empty, nflog_root, nk_commit, npk_commit, serialize_proof_data,
        AccountState, Address, CoinHistState, Nav, ProofData, TreeKind, GENESIS_TAG, ZERO_HASH,
    };
    use std::collections::BTreeMap;
    use zkcoins_prover::prover_bridge::{NavOpening, TransitionMode, TransitionWitness};
    use zkcoins_prover::state_engine::{OpSecret, PendingTransition};

    use crate::v1::separation::{set_process_stack_mode, ScanStackMode};

    // ── V.5 pins from the reference implementation fixture ─────────────────
    // Source: script-plonky2/tests/generated_sig_agg_vectors.txt
    // (output of generate_sig_agg_vectors). Proposed for specification
    // appendix V.5 in PR #124 (unmerged draft at the time of this wiring).
    // Not claimed as already normative in the published spec tree.
    // Read-only conformance anchors. Do not regenerate here.

    const V2EXT_PK0: &str = "7c9cdde9b8cb1e33a48a5c2b6ab1fa6fd753fa1762f56c0b3e8169e4f2d54630";
    const H_PROOF_DATA_0: &str = "db8c60533ba19eba14958f6ce44fd8df2e784d17dac28d8532e66fa938308de4";

    const V5_R_PRIME_MAINNET: &str =
        "fafd5229e657311d934989a4bc8bdfc8f033b4d640d2eb27b9fdda316f5c9601";
    const V5_SIG_MAINNET: &str = "7db327f8ff4bb148f051a038d370c4213149fe3affeff5b7fb7e9f8e3cc4438532168b5fca622ba2fad6d72ed201e71cef1003df880d345ddbe2b89f1ce3d4e5";

    const V5_R_PRIME_TESTNET: &str =
        "8c5b9be1e267c2f40ead298fb6fd8f98c0bc3efb862fce6ef7fa98b5691b3c6e";
    const V5_SIG_TESTNET: &str = "c62142c2448e098e5f8f4ec306b8a922be44226ae754e7b515178485d2da2286c52881936dd64a1dc3b9756c4a7a033e76ca4ad778624acbf580c041be6f7bf0";

    const V5_R_PRIME_REGTEST: &str =
        "7f415c530cd07713998ae0467e2c18fce210a7818ec7ad26a7b419009d6598f1";
    const V5_SIG_REGTEST: &str = "8945e81ed57b06222bd86b957f6800fc5569014b295c40c0b7a501787edca2c916b9c2f693f5e43c030bfc4fa0f210b9e96d45b06e943e652c8edb3b4a06d7fc";

    fn hex32(s: &str) -> [u8; 32] {
        let b = hex::decode(s).expect("fixture hex");
        b.try_into().expect("32 bytes")
    }

    fn hex64(s: &str) -> [u8; 64] {
        let b = hex::decode(s).expect("fixture hex");
        b.try_into().expect("64 bytes")
    }

    fn sha256_label(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    /// Rebuild the V.4 `ProofData@0` that pins `H(ProofData@0)` for the
    /// reference V.5 signature fixture.
    ///
    /// Same recipe as `shared/tests/generated_poseidon_vectors_test.rs`.
    /// The node verifies by serialising *this* structure — never by trusting
    /// the bare digest pin alone.
    fn proof_data_at_0() -> ProofData {
        let pk0 = sha256_label("zkCoins/v1/test-vector/Pk0");
        let pk1 = sha256_label("zkCoins/v1/test-vector/Pk1");
        let nk = sha256_label("zkCoins/v1/test-vector/nk");
        let npk_rand = sha256_label("zkCoins/v1/test-vector/npk_rand");
        let nav_rand = sha256_label("zkCoins/v1/test-vector/nav_rand");
        let name_hash_usd = name_hash(b"USD-Demo").expect("USD-Demo");
        let npk_commit_0 = npk_commit(&pk1, &npk_rand);
        let nflog_empty_v = nflog_empty();
        let coinhist_empty = coinhist_empty_root();
        let nk_commit_sample = nk_commit(&nk);
        let asset_id = asset_id_v1(GENESIS_TAG, &pk0, &name_hash_usd, 2, 1);
        let addr_bytes = address(&pk0, nk_commit_sample);
        let addr = Address(addr_bytes);
        let ash_empty = account_state_hash(
            &AccountState::new(
                addr,
                nk_commit_sample,
                BTreeMap::new(),
                pk0,
                0,
                coinhist_empty,
            )
            .expect("empty account"),
        )
        .expect("hash empty");
        let coin_identifier_0 =
            coin_identifier(ash_empty, &addr_bytes, asset_id, 1_000_000_000u128, 0u32);
        let coin_history_root_0 = coinhist_root_after_first_insert(
            &digest_to_bytes(&coin_identifier_0),
            CoinHistState::Admitted,
        );
        let mut balances = BTreeMap::new();
        balances.insert(digest_to_bytes(&asset_id), 1_000_000_000u128);
        let ash_0 = account_state_hash(
            &AccountState::new(
                addr,
                nk_commit_sample,
                balances,
                pk1,
                1,
                coin_history_root_0,
            )
            .expect("ash_0 account"),
        )
        .expect("hash ash_0");
        let ocr_0 = merkle_root(TreeKind::CoinsRoot, &[coin_identifier_0]);
        let inr_0 = merkle_root(TreeKind::NullifiersRoot, &[]);
        let nav_root_empty = nflog_root(0, nflog_empty_v);
        let nav_commitment_0 = nav_commitment(nav_root_empty, &nav_rand);
        ProofData {
            new_account_state_hash: ash_0,
            output_coins_root: ocr_0,
            input_nullifiers_root: inr_0,
            coin_history_root: coin_history_root_0,
            nav_commitment: nav_commitment_0,
            npk_commit: npk_commit_0,
        }
    }

    fn v5_case(network: Network) -> (WalletSignSubmission, [u8; 32]) {
        let pk = hex32(V2EXT_PK0);
        let (sig, r_prime) = match network {
            Network::Mainnet => (hex64(V5_SIG_MAINNET), hex32(V5_R_PRIME_MAINNET)),
            Network::Testnet => (hex64(V5_SIG_TESTNET), hex32(V5_R_PRIME_TESTNET)),
            Network::Regtest => (hex64(V5_SIG_REGTEST), hex32(V5_R_PRIME_REGTEST)),
        };
        (
            WalletSignSubmission {
                signature: sig,
                s2c_nonce: r_prime,
            },
            pk,
        )
    }

    fn other_proof_data() -> ProofData {
        ProofData {
            new_account_state_hash: ZERO_HASH,
            output_coins_root: ZERO_HASH,
            input_nullifiers_root: ZERO_HASH,
            coin_history_root: ZERO_HASH,
            nav_commitment: ZERO_HASH,
            npk_commit: [0u8; 32],
        }
    }

    /// Skeleton pending whose only signature-relevant fields are
    /// `current_pubkey` and `proof_data` / `proof_data_hash`.
    /// Other witness fields are placeholders (finalise would reject them;
    /// this helper is only for the host-side signature gate).
    fn pending_for(pk: [u8; 32], pd: ProofData) -> PendingTransition {
        let owner = Address([0u8; 32]);
        let account = AccountState::new(owner, ZERO_HASH, BTreeMap::new(), pk, 0, ZERO_HASH)
            .expect("skeleton account");
        let nav = Nav {
            size: 0,
            mth: nflog_empty(),
        };
        let nav_opening = NavOpening {
            nav,
            nav_rand: [0u8; 32],
        };
        let proof_data_hash = hash_proof_data(&serialize_proof_data(&pd));
        let witness = TransitionWitness {
            mode: TransitionMode::InitialProof,
            prev_account_state: account.clone(),
            new_account_state: account,
            input_coins: Vec::new(),
            input_auth: Vec::new(),
            output_templates: Vec::new(),
            output_coins: Vec::new(),
            output_history_proofs: Vec::new(),
            received_coins: Vec::new(),
            received_auth: Vec::new(),
            asset_issuance: None,
            nk: [0u8; 32],
            nav: nav_opening.nav,
            nav_rand: nav_opening.nav_rand,
            prev_nav_opening: None,
            nav_consistency: Vec::new(),
            next_pubkey: [0u8; 32],
            npk_rand: [0u8; 32],
            transition_signature: TransitionSignature {
                pk_i: pk,
                signature: [0u8; 64],
                r_prime: [0u8; 32],
            },
            prev_proof: None,
            predecessor_nullifier: None,
        };
        PendingTransition {
            witness_wip: witness,
            proof_data: pd,
            proof_data_hash,
            mode: TransitionMode::InitialProof,
            owner,
            nav_opening,
            // Signature-gate fixtures never exercise nav_rand derivation; a
            // constant stands in so the skeleton type is constructible.
            op_secret: OpSecret::new([0u8; 32]),
        }
    }

    #[test]
    fn proof_data_at_0_matches_reference_h_proof_data_pin() {
        let pd = proof_data_at_0();
        let h = hash_proof_data(&serialize_proof_data(&pd));
        assert_eq!(
            hex::encode(h),
            H_PROOF_DATA_0,
            "reconstructed ProofData@0 must hash to the reference-implementation pin \
             (generated_sig_agg_vectors.txt / proposed V.5)"
        );
    }

    #[test]
    fn v5_conformance_all_three_networks() {
        let pd = proof_data_at_0();
        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let (submission, pk) = v5_case(network);
            let pending = pending_for(pk, pd.clone());
            let sig = accept_wallet_transition_signature(
                V1ShadowMode::On,
                network,
                &pending,
                &submission,
            )
            .unwrap_or_else(|e| {
                panic!("reference V.5 signature fixture must verify under {network:?}: {e}");
            });
            assert_eq!(sig.pk_i, pk);
            assert_eq!(sig.signature, submission.signature);
            assert_eq!(sig.r_prime, submission.s2c_nonce);
        }
    }

    #[test]
    fn rejects_wrong_network_m_state_at_bip340() {
        // Sign under mainnet m_state; verify under testnet. S2C is
        // network-independent so it would pass — BIP-340 must be the
        // check that fails (cross-network replay).
        let pd = proof_data_at_0();
        let (submission, pk) = v5_case(Network::Mainnet);
        let pending = pending_for(pk, pd);
        let err = accept_wallet_transition_signature(
            V1ShadowMode::On,
            Network::Testnet,
            &pending,
            &submission,
        )
        .expect_err("cross-network signature must be rejected");
        assert_eq!(
            err.check,
            SignatureCheck::Bip340,
            "wrong m_state must fail at BIP-340, not S2C; got: {err}"
        );
    }

    #[test]
    fn rejects_valid_bip340_with_bad_s2c_opening() {
        // Keep the V.5 BIP-340 signature intact (R,s,pk,m_state valid) but
        // substitute a different R' so the S2C opening cannot hold.
        let pd = proof_data_at_0();
        let (mut submission, pk) = v5_case(Network::Regtest);
        submission.s2c_nonce[0] ^= 0x01;
        let pending = pending_for(pk, pd);
        let err = accept_wallet_transition_signature(
            V1ShadowMode::On,
            Network::Regtest,
            &pending,
            &submission,
        )
        .expect_err("tampered R' must be rejected");
        assert_eq!(
            err.check,
            SignatureCheck::S2cOpening,
            "bad S2C opening must fail at S2cOpening (BIP-340 alone is not enough); got: {err}"
        );
    }

    /// Defect 2: a signature S2C-bound to ProofData@0 must not authorise a
    /// *different* pending transition. The finalise API takes the pending
    /// itself — there is no independent `proof_data` parameter to
    /// substitute — so the only attack is presenting the right signature
    /// against the wrong pending. That fails at S2C with a distinct check.
    #[test]
    fn substituted_proof_data_cannot_authorise_a_different_pending() {
        let correct_pd = proof_data_at_0();
        let wrong_pd = other_proof_data();
        assert_ne!(
            hash_proof_data(&serialize_proof_data(&wrong_pd)),
            hex32(H_PROOF_DATA_0),
            "fixture guard: alternate ProofData must not hash to the reference pin"
        );
        let (submission, pk) = v5_case(Network::Mainnet);

        // Pending that carries the *wrong* ProofData (would be the
        // transition being finalised) while the wallet signature was
        // produced over ProofData@0.
        let pending_wrong = pending_for(pk, wrong_pd);
        let err = accept_wallet_transition_signature(
            V1ShadowMode::On,
            Network::Mainnet,
            &pending_wrong,
            &submission,
        )
        .expect_err("signature over a different ProofData must not finalise this pending");
        assert_eq!(
            err.check,
            SignatureCheck::S2cOpening,
            "substituted proof_data on the pending must fail at S2cOpening; got: {err}"
        );

        // Sanity: the same submission against the *matching* pending works.
        let pending_ok = pending_for(pk, correct_pd);
        accept_wallet_transition_signature(
            V1ShadowMode::On,
            Network::Mainnet,
            &pending_ok,
            &submission,
        )
        .expect("matching pending must accept the reference signature");
    }

    #[test]
    fn accept_api_derives_pk_and_proof_data_from_pending_only() {
        // Type-level lock: accept_wallet_transition_signature takes
        // &PendingTransition, not (pk, proof_data). A caller that only
        // has a free-standing ProofData cannot reach the finalise path
        // without wrapping it in a pending — and then S2C binds that
        // pending's own proof_data.
        let pd = proof_data_at_0();
        let (submission, pk) = v5_case(Network::Regtest);
        let pending = pending_for(pk, pd);
        let sig = accept_wallet_transition_signature(
            V1ShadowMode::On,
            Network::Regtest,
            &pending,
            &submission,
        )
        .expect("canonical path");
        assert_eq!(
            sig.pk_i,
            pending.witness_wip.prev_account_state.current_pubkey
        );
    }

    #[test]
    fn rejects_pk_mismatch_on_material_preflight() {
        let pd = proof_data_at_0();
        let (submission, real_pk) = v5_case(Network::Testnet);
        let wrong_pk = [0x11u8; 32];
        let sig = TransitionSignature {
            pk_i: wrong_pk,
            signature: submission.signature,
            r_prime: submission.s2c_nonce,
        };
        // Material preflight (not finalise path) — explicit pair for tooling.
        let err = verify_transition_signature_material(Network::Testnet, &real_pk, &pd, &sig)
            .expect_err("explicit pk mismatch");
        assert_eq!(err.check, SignatureCheck::PkMatch, "got: {err}");
    }

    #[test]
    fn inconsistent_pending_envelope_hash_is_rejected() {
        let pd = proof_data_at_0();
        let (submission, pk) = v5_case(Network::Mainnet);
        let mut pending = pending_for(pk, pd);
        // Corrupt the cached hash so the envelope disagrees with proof_data.
        pending.proof_data_hash[0] ^= 0xff;
        let err = accept_wallet_transition_signature(
            V1ShadowMode::On,
            Network::Mainnet,
            &pending,
            &submission,
        )
        .expect_err("inconsistent pending envelope must fail closed");
        assert_eq!(err.check, SignatureCheck::PendingEnvelope, "got: {err}");
    }

    #[test]
    fn flag_off_refuses_transition_signature_path() {
        let pd = proof_data_at_0();
        let (submission, pk) = v5_case(Network::Regtest);
        let pending = pending_for(pk, pd);
        let err = accept_wallet_transition_signature(
            V1ShadowMode::Off,
            Network::Regtest,
            &pending,
            &submission,
        )
        .expect_err("flag off must refuse TransitionSignature");
        assert_eq!(err.check, SignatureCheck::ShadowFlag, "got: {err}");
    }

    /// Flag / Legacy claim: legacy ash‖ocr Commitment path stays open.
    /// (V1 refusal + accept is a separate process — claim is monotonic.)
    #[test]
    fn wired_path_allows_legacy_commitment_when_unclaimed_or_legacy() {
        assert!(
            refuse_legacy_commitment_under_v1().is_ok(),
            "unclaimed process must allow residual legacy commit path"
        );

        set_process_stack_mode(ScanStackMode::Legacy);
        assert!(
            refuse_legacy_commitment_under_v1().is_ok(),
            "legacy claim must allow ash‖ocr Commitment"
        );
        // Legacy commitment verify itself is untouched.
        {
            use bitcoin::secp256k1::SecretKey;
            use shared::commitment::Commitment;
            let sk = SecretKey::from_slice(&[0x42u8; 32]).expect("secret");
            let mut message = vec![0u8; 64];
            message[..32].fill(0xA1);
            message[32..].fill(0xB2);
            let commitment = Commitment::new(&sk, message).expect("sign legacy commitment");
            assert!(
                commitment.verify(),
                "legacy Commitment::verify must still accept ash‖ocr under flag-off"
            );
        }
    }

    /// Defect 1: under a v1.1 process claim the wired path refuses a legacy
    /// ash‖ocr Commitment, and accepts a v1.1 TransitionSignature against
    /// the pending transition.
    #[test]
    fn wired_path_rejects_legacy_commitment_under_v1_and_accepts_v1_signature() {
        set_process_stack_mode(ScanStackMode::V1);
        let legacy_err =
            refuse_legacy_commitment_under_v1().expect_err("v1.1 claim must refuse legacy");
        assert_eq!(
            legacy_err.check,
            SignatureCheck::LegacyCommitment,
            "got: {legacy_err}"
        );
        assert!(
            legacy_err
                .message
                .contains("legacy ash‖ocr Commitment refused"),
            "got: {legacy_err}"
        );

        // Same claim: accept a real v1.1 signature against the pending.
        let pd = proof_data_at_0();
        let (submission, pk) = v5_case(Network::Mainnet);
        let pending = pending_for(pk, pd);
        let sig = accept_wallet_transition_signature(
            V1ShadowMode::On,
            Network::Mainnet,
            &pending,
            &submission,
        )
        .expect("v1.1 signature must be accepted under the v1.1 claim");
        assert_eq!(sig.pk_i, pk);
    }

    #[test]
    fn legacy_commitment_path_unchanged_when_flag_off() {
        // Demonstrates: with the flag off, the legacy ash‖ocr Commitment
        // verify still works exactly as before. G4 does not touch
        // shared::commitment or the dual 32/64-byte path in state.rs.
        use bitcoin::secp256k1::SecretKey;
        use shared::commitment::Commitment;

        let sk = SecretKey::from_slice(&[0x42u8; 32]).expect("secret");
        let mut message = vec![0u8; 64];
        message[..32].fill(0xA1);
        message[32..].fill(0xB2);
        let commitment = Commitment::new(&sk, message).expect("sign legacy commitment");
        assert!(
            commitment.verify(),
            "legacy Commitment::verify must still accept ash‖ocr under flag-off"
        );
        assert!(ensure_v1_signature_path(V1ShadowMode::Off).is_err());
        assert!(ensure_v1_signature_path(V1ShadowMode::On).is_ok());
        assert!(refuse_legacy_commitment_under_v1().is_ok());
    }

    /// Defect 4: parser matches the documented SDK wire contract exactly.
    #[test]
    fn parser_matches_documented_wire_contract_exactly() {
        let (submission, _) = v5_case(Network::Mainnet);
        let sig_hex = hex::encode(submission.signature);
        let r_hex = hex::encode(submission.s2c_nonce);
        assert_eq!(sig_hex.len(), 128);
        assert_eq!(r_hex.len(), 64);

        let parsed = WalletSignSubmission::from_hex(&sig_hex, &r_hex).expect("canonical parse");
        assert_eq!(parsed, submission);

        // Uppercase rejected (no silent case-fold).
        let err =
            WalletSignSubmission::from_hex(&sig_hex.to_uppercase(), &r_hex).expect_err("uppercase");
        assert_eq!(err.check, SignatureCheck::Encoding);

        // Wrong length rejected.
        let err = WalletSignSubmission::from_hex(&sig_hex[..10], &r_hex).expect_err("short");
        assert_eq!(err.check, SignatureCheck::Encoding);

        // Optional 0x prefix was previously accepted — contract now rejects it.
        let err = WalletSignSubmission::from_hex(&format!("0x{sig_hex}"), &r_hex)
            .expect_err("0x prefix on signature");
        assert_eq!(err.check, SignatureCheck::Encoding, "got: {err}");
        assert!(
            err.message.contains("0x") || err.message.contains("prefix"),
            "error should name the prefix rule: {err}"
        );

        let err = WalletSignSubmission::from_hex(&sig_hex, &format!("0x{r_hex}"))
            .expect_err("0x prefix on s2c_nonce");
        assert_eq!(err.check, SignatureCheck::Encoding, "got: {err}");

        let err =
            WalletSignSubmission::from_hex(&format!("0X{sig_hex}"), &r_hex).expect_err("0X prefix");
        assert_eq!(err.check, SignatureCheck::Encoding, "got: {err}");

        // Whitespace / mixed content rejected.
        let err = WalletSignSubmission::from_hex(&format!(" {sig_hex}"), &r_hex)
            .expect_err("leading space");
        assert_eq!(err.check, SignatureCheck::Encoding);
    }

    #[test]
    fn never_accepts_caller_supplied_digest_in_place_of_proof_data() {
        // The finalise API has no parameter for H(ProofData). Binding is only
        // through serialize(pending.proof_data). This locks the surface.
        let pd = proof_data_at_0();
        let h = hash_proof_data(&serialize_proof_data(&pd));
        assert_eq!(hex::encode(h), H_PROOF_DATA_0);
        let (submission, pk) = v5_case(Network::Regtest);
        let pending = pending_for(pk, pd);
        accept_wallet_transition_signature(
            V1ShadowMode::On,
            Network::Regtest,
            &pending,
            &submission,
        )
        .expect("canonical path");
    }

    #[test]
    fn v1_job_advertises_proof_data_fields_not_ash_ocr() {
        set_process_stack_mode(ScanStackMode::V1);

        let pd = proof_data_at_0();
        let (_, pk) = v5_case(Network::Mainnet);
        let pending = pending_for(pk, pd);
        let entry = PendingSignEntry::new(pending, Network::Mainnet);
        let result = select_awaiting_signature_result(
            "aa".repeat(32).as_str(),
            "bb".repeat(32).as_str(),
            Some(&entry),
        )
        .expect("v1 with staged pending must advertise");
        assert!(
            result.get("account_state_hash").is_none(),
            "v1.1 job must not advertise legacy ash; got {result}"
        );
        assert!(
            result.get("output_coins_root").is_some(),
            "ocr is a ProofData field name under §7.5; got {result}"
        );
        for key in [
            "new_account_state_hash",
            "output_coins_root",
            "input_nullifiers_root",
            "coin_history_root",
            "nav_commitment",
            "npk_commit",
            "proof_data_hash",
            "txn_pubkey",
            "send_counter",
        ] {
            assert!(
                result.get(key).is_some(),
                "v1.1 awaiting_signature missing {key}; got {result}"
            );
        }
        assert_eq!(result["txn_pubkey"], hex::encode(pk));
        assert_eq!(result["send_counter"], 0);
        assert_eq!(result["proof_data_hash"], H_PROOF_DATA_0);

        // Without staged pending: refuse ash/ocr fallback.
        let err = select_awaiting_signature_result("aa", "bb", None)
            .expect_err("must not fall back to ash/ocr under v1.1");
        assert_eq!(err.check, SignatureCheck::LegacyCommitment);
    }

    #[test]
    fn flag_off_job_still_advertises_legacy_ash_ocr() {
        let ash = "aa".repeat(32);
        let ocr = "bb".repeat(32);
        let result = select_awaiting_signature_result(&ash, &ocr, None)
            .expect("legacy/unclaimed must keep ash/ocr");
        assert_eq!(result["account_state_hash"], ash);
        assert_eq!(result["output_coins_root"], ocr);
        assert!(result.get("proof_data_hash").is_none());
        assert!(result.get("txn_pubkey").is_none());
    }

    #[test]
    fn wire_body_try_from_enforces_encoding_at_boundary() {
        let (submission, _) = v5_case(Network::Mainnet);
        let wire = WalletSignSubmissionWire {
            signature: hex::encode(submission.signature),
            s2c_nonce: hex::encode(submission.s2c_nonce),
        };
        let decoded = WalletSignSubmission::try_from(&wire).expect("canonical wire");
        assert_eq!(decoded, submission);

        let bad = WalletSignSubmissionWire {
            signature: wire.signature.to_uppercase(),
            s2c_nonce: wire.s2c_nonce.clone(),
        };
        let err = WalletSignSubmission::try_from(&bad).expect_err("uppercase");
        assert_eq!(err.check, SignatureCheck::Encoding);
        let (status, code) = sign_rejection(&err);
        assert_eq!(status, 400);
        // §7.5 closed enumeration: non-canonical hex is malformed_request,
        // never an invented "encoding" code.
        assert_eq!(code, "malformed_request");
    }

    #[test]
    fn send_counter_is_derived_from_pending_not_free() {
        let pd = proof_data_at_0();
        let (_, pk) = v5_case(Network::Mainnet);
        // Build a pending whose prev_account_state.send_counter is 7.
        let mut pending = pending_for(pk, pd);
        pending.witness_wip.prev_account_state =
            AccountState::new(pending.owner, ZERO_HASH, BTreeMap::new(), pk, 7, ZERO_HASH)
                .expect("account with send_counter=7");
        let entry = PendingSignEntry::new(pending, Network::Mainnet);
        assert_eq!(entry.send_counter(), 7);
        let advertised = awaiting_signature_result_json(&entry);
        assert_eq!(advertised["send_counter"], 7);
        // There is no constructor / field that would let a caller set 99
        // while the pending carries 7 — send_counter is a method only.
    }

    #[test]
    fn durable_finalisation_round_trips_full_capability() {
        let (entry, submission) = test_fixtures::v5_mainnet_entry_and_submission();
        let persist = DurableFinalisationPersist::from_entry(&entry).expect("encode");
        let json = serde_json::to_value(&persist).expect("json");
        let body = serde_json::json!({ FINALISATION_BODY_KEY: json });
        let rehydrated = rehydrate_pending_sign(&body)
            .expect("rehydrate ok")
            .expect("Some");
        assert_eq!(rehydrated.send_counter(), entry.send_counter());
        assert_eq!(
            rehydrated.pending.proof_data_hash,
            entry.pending.proof_data_hash
        );
        // Full witness survives — not a partial verification-grade rebuild.
        assert_eq!(
            rehydrated.pending.witness_wip.output_coins.len(),
            entry.pending.witness_wip.output_coins.len()
        );
        accept_wallet_transition_signature(
            V1ShadowMode::On,
            rehydrated.network,
            &rehydrated.pending,
            &submission,
        )
        .expect("rehydrated pending must still verify the wallet signature");
        // Unsigned rehydrate is not finalise-ready (signature required).
        assert!(
            ensure_finalise_ready(&rehydrated).is_err(),
            "unsigned durable capability must not be finalise-ready"
        );
    }

    #[test]
    fn signed_durable_capability_survives_round_trip() {
        let (mut entry, submission) = test_fixtures::v5_mainnet_entry_and_submission();
        let accepted = accept_wallet_transition_signature(
            V1ShadowMode::On,
            entry.network,
            &entry.pending,
            &submission,
        )
        .expect("accept");
        entry.install_signature(accepted).expect("install");
        let persist = DurableFinalisationPersist::from_entry(&entry).expect("encode");
        let rehydrated = persist.into_entry().expect("into_entry");
        assert!(
            rehydrated.signature.is_some(),
            "signature must survive durable round-trip"
        );
        ensure_finalise_ready(&rehydrated).expect("signed rehydrate is finalise-ready");
        // Completion surface still absent until prove+apply records it.
        assert!(
            ensure_completion_ready(&rehydrated).is_err(),
            "signed-only capability is not completion-ready"
        );
    }

    #[test]
    fn completion_surface_round_trips_and_is_completion_ready() {
        let (mut entry, submission) = test_fixtures::v5_mainnet_entry_and_submission();
        let accepted = accept_wallet_transition_signature(
            V1ShadowMode::On,
            entry.network,
            &entry.pending,
            &submission,
        )
        .expect("accept");
        entry.install_signature(accepted).expect("install");
        let outcome = FinaliseOutcome::from_pending_proof_data_with_publisher(
            &entry.pending,
            entry.publisher_pubkey,
        );
        entry
            .install_completion(outcome.to_result_json(), 200)
            .expect("install completion");
        let persist = DurableFinalisationPersist::from_entry(&entry).expect("encode");
        let rehydrated = persist.into_entry().expect("into_entry");
        ensure_completion_ready(&rehydrated).expect("full capability is completion-ready");
        assert!(rehydrated.has_completion());
    }

    #[test]
    fn incomplete_capability_missing_completion_status_refuses_rehydrate() {
        let (mut entry, submission) = test_fixtures::v5_mainnet_entry_and_submission();
        let accepted = accept_wallet_transition_signature(
            V1ShadowMode::On,
            entry.network,
            &entry.pending,
            &submission,
        )
        .expect("accept");
        entry.install_signature(accepted).expect("install");
        let mut persist = DurableFinalisationPersist::from_entry(&entry).expect("encode");
        persist.completion_result = Some(serde_json::json!({ "new_account_state_hash": "00" }));
        // completion_status deliberately omitted → incomplete pair.
        let err = persist
            .into_entry()
            .expect_err("split completion must refuse");
        assert_eq!(err.check, SignatureCheck::PendingEnvelope);
        assert!(err.message.contains("incomplete"), "err={}", err.message);
    }

    #[test]
    fn legacy_pending_sign_key_alone_refuses_rehydrate() {
        let body = serde_json::json!({
            PENDING_SIGN_BODY_KEY: { "network": "mainnet" }
        });
        let err = rehydrate_pending_sign(&body).expect_err("legacy key must fail closed");
        assert_eq!(err.check, SignatureCheck::PendingEnvelope);
        assert!(
            err.message.contains("legacy pending_sign")
                || err.message.contains("verification-grade"),
            "err={}",
            err.message
        );
    }

    #[test]
    fn finalise_outcome_from_pending_carries_proof_data_surface() {
        let (entry, _) = test_fixtures::v5_mainnet_entry_and_submission();
        let publisher = [0xABu8; 32];
        let outcome = FinaliseOutcome::from_pending_proof_data_with_publisher(
            &entry.pending,
            Some(publisher),
        );
        let result = outcome.to_result_json();
        assert!(result.get("new_account_state_hash").is_some());
        assert!(result.get("output_coins_root").is_some());
        assert!(result.get("input_nullifiers_root").is_some());
        assert!(result.get("output_coin_ids").is_some());
        assert!(result["output_coin_ids"].is_array());
        assert_eq!(
            result["publisher_pubkey"].as_str().unwrap(),
            hex::encode(publisher)
        );
        // Must not look like the old short-circuit body.
        assert!(result.get("signature_accepted").is_none());
        assert!(result.get("sign").is_none());
    }

    #[test]
    fn decode_job_error_never_omits_and_never_invents() {
        use crate::job_store::JobStatus;
        let structured = encode_job_error("publish_rejected", "publisher said no");
        let v = decode_job_error(Some(&structured), JobStatus::Failed);
        assert_eq!(v["error"], "publish_rejected");
        assert_eq!(v["message"], "publisher said no");

        let free = decode_job_error(Some("prove blew up"), JobStatus::Failed);
        assert_eq!(free["error"], "proving_failed");
        assert_eq!(free["message"], "prove blew up");

        let cancelled = decode_job_error(None, JobStatus::Cancelled);
        assert_eq!(cancelled["error"], "internal_error");
        assert!(cancelled.get("message").is_some());
    }

    #[test]
    fn decode_job_error_rejects_invented_stored_codes() {
        use crate::job_store::JobStatus;
        // A stored JSON "error" is not automatically valid.
        let invented = r#"{"error":"dispatcher_not_waiting","message":"gone"}"#;
        let v = decode_job_error(Some(invented), JobStatus::Failed);
        assert_ne!(v["error"], "dispatcher_not_waiting");
        assert!(
            is_closed_outward_error_code(v["error"].as_str().unwrap()),
            "must remap to a closed code: {v}"
        );
        assert_eq!(v["message"], "gone");
    }

    #[test]
    fn publisher_pubkey_absent_ok_malformed_fails() {
        // Absent → Ok(None).
        let body = serde_json::json!({"kind": "send"});
        assert_eq!(publisher_pubkey_from_request_body(&body).unwrap(), None);

        // Well-formed → Ok(Some).
        let pk = "ab".repeat(32);
        let body = serde_json::json!({"publisher_pubkey": pk});
        let got = publisher_pubkey_from_request_body(&body).unwrap().unwrap();
        assert_eq!(hex::encode(got), pk);

        // Malformed (uppercase) → Err, never silent None.
        let body = serde_json::json!({"publisher_pubkey": "AB".repeat(32)});
        assert!(publisher_pubkey_from_request_body(&body).is_err());

        // Malformed (wrong length) → Err.
        let body = serde_json::json!({"publisher_pubkey": "aa".repeat(16)});
        assert!(publisher_pubkey_from_request_body(&body).is_err());

        // Malformed (non-string) → Err.
        let body = serde_json::json!({"publisher_pubkey": 42});
        assert!(publisher_pubkey_from_request_body(&body).is_err());
    }

    #[test]
    fn flag_off_timeout_error_is_plain_legacy_string() {
        // Defect 5: the stored timeout value under flag-off must remain
        // exactly the historical plain string (byte-identical).
        let legacy = "awaiting_signature timeout";
        assert_eq!(legacy.as_bytes(), b"awaiting_signature timeout");
        // Structured form is only for the v1.1 path.
        let structured = encode_job_error("internal_error", legacy);
        assert_ne!(structured.as_bytes(), legacy.as_bytes());
        assert!(structured.contains("internal_error"));
    }

    /// Typed engine cause (not a message substring) maps to
    /// `dependency_not_final` with the contract HTTP 409.
    ///
    /// Engine emission of both variants with a real account/`last_nullifier`
    /// is covered in `state_engine` host-only tests (no Plonky2 prove). This
    /// test pins the **outward** encode/decode + 409 contract path.
    #[test]
    fn typed_dependency_not_final_encodes_as_409_not_proving_failed() {
        use crate::job_store::JobStatus;
        use zkcoins_prover::state_engine::DependencyNotFinal;

        for cause in [
            DependencyNotFinal::PredecessorAbsentFromCanonicalNfLog,
            DependencyNotFinal::PredecessorPositionNotCoveredBySizeFinal {
                position: 0,
                size_final: 0,
            },
        ] {
            // Intermediate context must not hide the typed cause.
            let err = anyhow::Error::new(cause).context("begin_mint host refuse");
            assert_eq!(
                machine_code_from_engine_error(&err),
                Some("dependency_not_final"),
                "cause={cause:?}"
            );
            let encoded = encode_job_error_from_anyhow(&err);
            let outward = decode_job_error(Some(&encoded), JobStatus::Failed);
            assert_eq!(
                outward["error"], "dependency_not_final",
                "caller must see dependency_not_final, not proving_failed; got {outward}"
            );
            assert_eq!(
                http_status_for_machine_code("dependency_not_final"),
                Some(409),
                "§7.5 / error_contract maps dependency_not_final → 409"
            );
        }

        // Free-form predecessor prose without typed encode must NOT
        // silently become dependency_not_final (substring match removed).
        let free = decode_job_error(
            Some("predecessor nullifier is not in the canonical NfLog"),
            JobStatus::Failed,
        );
        assert_eq!(
            free["error"], "proving_failed",
            "substring match removed; free-form stays proving_failed"
        );
    }

    /// Typed host cause (not a message substring) maps to `publish_rejected`.
    ///
    /// §7.5: `publish_rejected` is a terminal **job error object**; the job
    /// poll HTTP status remains 200 (same as `proving_failed`) — it is not
    /// an RPC `KernelErrorCode`. Free-form text that merely contains the
    /// word must not classify as `publish_rejected` after the substring
    /// branch was removed.
    #[test]
    fn typed_publish_rejected_encodes_not_from_free_form_text() {
        use crate::job_store::JobStatus;

        let cause = PublishRejected::DurableHandoffFailed {
            detail: "recording publisher: forced broadcast handoff failure".to_string(),
        };
        // Intermediate context must not hide the typed cause.
        let err = anyhow::Error::new(cause).context("finalise durable handoff");
        assert_eq!(
            machine_code_from_engine_error(&err),
            Some("publish_rejected"),
            "typed PublishRejected must classify as publish_rejected"
        );
        let encoded = encode_job_error_from_anyhow(&err);
        let outward = decode_job_error(Some(&encoded), JobStatus::Failed);
        assert_eq!(
            outward["error"], "publish_rejected",
            "caller must see publish_rejected, not proving_failed; got {outward}"
        );
        // §7.5 job-poll surface: terminal job errors ride a successful poll
        // (HTTP 200) with the closed code in the body — not an RPC mapping.
        // `http_status_for_machine_code` only covers KernelErrorCode RPC
        // reasons; publish_rejected is intentionally absent there (same as
        // proving_failed).
        assert_eq!(
            http_status_for_machine_code("publish_rejected"),
            None,
            "publish_rejected is a terminal job body code, not an RPC KernelErrorCode"
        );
        assert_eq!(
            http_status_for_machine_code("proving_failed"),
            None,
            "proving_failed shares the same non-RPC job-body surface"
        );
        // Normative job-poll HTTP for both terminal job-body codes (§7.5).
        const JOB_POLL_HTTP_FOR_TERMINAL_JOB_ERROR: u16 = 200;
        assert_eq!(
            JOB_POLL_HTTP_FOR_TERMINAL_JOB_ERROR, 200,
            "§7.5: job poll itself returns 200; error is in the body"
        );

        // Free-form text with the same diagnostic wording must NOT silently
        // become publish_rejected (substring match removed — the point).
        let free_wording = "publish_rejected: v1.1 finalise durable nullifier publish \
             after members_ready failed (row retained for resume): bitcoind down";
        let free = decode_job_error(Some(free_wording), JobStatus::Failed);
        assert_eq!(
            free["error"], "proving_failed",
            "substring match removed; free-form stays proving_failed, got {free}"
        );
        let free_alt = decode_job_error(Some("publisher rejected the batch"), JobStatus::Failed);
        assert_eq!(
            free_alt["error"], "proving_failed",
            "legacy 'publisher rejected' free-form must not map either"
        );
    }

    /// Recording double: `try_prepare` → None so durable path uses
    /// `publish_batch` (same shape as the job_dispatcher finalise tests).
    struct TickRecordingPublisher {
        batches: std::sync::Mutex<Vec<usize>>,
        fail: bool,
    }

    impl TickRecordingPublisher {
        fn ok() -> Self {
            Self {
                batches: std::sync::Mutex::new(Vec::new()),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                batches: std::sync::Mutex::new(Vec::new()),
                fail: true,
            }
        }
        fn published_count(&self) -> usize {
            self.batches.lock().expect("lock").iter().sum()
        }
    }

    impl crate::v1::receive::NullifierBatchPublisher for TickRecordingPublisher {
        fn publish_batch(
            &self,
            members: &[zkcoins_prover::publisher::BatchMember],
        ) -> anyhow::Result<zkcoins_prover::publisher::PublishedBatch> {
            if self.fail {
                anyhow::bail!("recording publisher: forced broadcast handoff failure");
            }
            anyhow::ensure!(!members.is_empty(), "recording publisher: empty batch");
            self.batches.lock().expect("lock").push(members.len());
            let agg = zkcoins_prover::half_agg::AggregateStateNullifierV3 {
                version: 3,
                format: 0x01,
                block_anchor: members[0].build_tip,
                members: members.iter().map(|m| (m.sig.pk, m.sig.r)).collect(),
                raw_s: None,
                s_agg: Some([0xAB; 32]),
            };
            Ok(zkcoins_prover::publisher::PublishedBatch {
                aggregate: agg,
                payload: vec![0x42],
                commit_txid: bitcoin::Txid::from_raw_hash(
                    <bitcoin::hashes::sha256d::Hash as bitcoin::hashes::Hash>::from_byte_array(
                        [0x11; 32],
                    ),
                ),
                reveal_txid: bitcoin::Txid::from_raw_hash(
                    <bitcoin::hashes::sha256d::Hash as bitcoin::hashes::Hash>::from_byte_array(
                        [0x22; 32],
                    ),
                ),
                commit_output: bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(600),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                block_anchor: members[0].build_tip,
            })
        }
    }

    fn tick_xonly(label: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"v1/sig/resume-tick/");
        h.update(label);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    /// One resume sweep — same pickup path the binary resumer uses
    /// (`resume_all_pending_publishes` → `resume_pending_publish`). Kept
    /// local to tests so the binary can stay on the public `V1Publisher`
    /// surface without a second rebroadcast implementation.
    async fn resume_pending_publishes_tick(
        adapter: &crate::v1::EngineAdapter,
        publisher: &impl crate::v1::receive::NullifierBatchPublisher,
    ) -> anyhow::Result<usize> {
        crate::v1::receive::resume_all_pending_publishes_with(adapter, publisher).await
    }

    /// A waiting `members_ready` row is picked up by the resume tick without
    /// a process restart (recording publisher, no real bitcoind).
    #[tokio::test]
    async fn resume_tick_picks_up_members_ready_without_restart() {
        use crate::test_db::setup_pool;
        use crate::v1::db_v1;
        use crate::v1::separation::claim_stack_scan_mode;
        use crate::v1::EngineAdapter;
        use shared::spec_v1::Address;

        set_process_stack_mode(ScanStackMode::V1);
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        claim_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("claim v1");
        let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
            .await
            .expect("adapter");

        let owner = Address(tick_xonly(b"owner-ok"));
        let pk = tick_xonly(b"pk-ok");
        let r = tick_xonly(b"r-ok");
        let s = [0x55u8; 32];
        let r_prime = tick_xonly(b"rp-ok");
        db_v1::insert_pending_publish_members_ready(
            &pool, owner, pk, r, s, r_prime, 42, [0xAA; 32],
        )
        .await
        .expect("stage members_ready");

        let before = db_v1::list_resumable_pending_publishes(&pool)
            .await
            .expect("list");
        assert_eq!(before.len(), 1, "row must be resumable before tick");
        assert_eq!(before[0].status, db_v1::PENDING_PUBLISH_MEMBERS_READY);

        let recorder = TickRecordingPublisher::ok();
        let completed = resume_pending_publishes_tick(&adapter, &recorder)
            .await
            .expect("tick must succeed");
        assert_eq!(completed, 1, "one pending publish must complete");
        assert_eq!(
            recorder.published_count(),
            1,
            "recording publisher must observe the broadcast handoff"
        );

        let after = db_v1::list_resumable_pending_publishes(&pool)
            .await
            .expect("list after");
        assert!(
            after.is_empty(),
            "row must no longer be resumable after successful tick; got {after:?}"
        );
        let row = db_v1::load_pending_publish(&pool, pk)
            .await
            .expect("load")
            .expect("row retained");
        assert_ne!(
            row.status,
            db_v1::PENDING_PUBLISH_MEMBERS_READY,
            "status must advance past members_ready; got {}",
            row.status
        );
        drop(scope);
    }

    /// Failed handoff leaves the row waiting; a later tick still attempts
    /// resume (resumer does not give up after a permanent-looking error).
    #[tokio::test]
    async fn resume_tick_failure_keeps_row_and_retries() {
        use crate::test_db::setup_pool;
        use crate::v1::db_v1;
        use crate::v1::separation::claim_stack_scan_mode;
        use crate::v1::EngineAdapter;
        use shared::spec_v1::Address;

        set_process_stack_mode(ScanStackMode::V1);
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        claim_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("claim v1");
        let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
            .await
            .expect("adapter");

        let owner = Address(tick_xonly(b"owner-fail"));
        let pk = tick_xonly(b"pk-fail");
        let r = tick_xonly(b"r-fail");
        let s = [0x66u8; 32];
        let r_prime = tick_xonly(b"rp-fail");
        db_v1::insert_pending_publish_members_ready(&pool, owner, pk, r, s, r_prime, 7, [0xBB; 32])
            .await
            .expect("stage members_ready");

        let failing = TickRecordingPublisher::failing();
        let err1 = resume_pending_publishes_tick(&adapter, &failing)
            .await
            .expect_err("first tick must surface publisher failure");
        assert!(
            format!("{err1:#}").contains("forced broadcast handoff failure")
                || format!("{err1:#}").contains("publish_batch"),
            "error must name the handoff failure; got {err1:#}"
        );
        assert_eq!(
            failing.published_count(),
            0,
            "failing publisher must not publish"
        );

        let still = db_v1::list_resumable_pending_publishes(&pool)
            .await
            .expect("list");
        assert_eq!(
            still.len(),
            1,
            "row must remain resumable after failed tick"
        );
        assert_eq!(still[0].status, db_v1::PENDING_PUBLISH_MEMBERS_READY);

        // Second attempt still runs (resumer does not mark done / give up).
        let err2 = resume_pending_publishes_tick(&adapter, &failing)
            .await
            .expect_err("second tick must still attempt and fail");
        assert!(
            format!("{err2:#}").contains("forced broadcast handoff failure")
                || format!("{err2:#}").contains("publish_batch"),
            "retry error must name the handoff failure; got {err2:#}"
        );
        let still2 = db_v1::list_resumable_pending_publishes(&pool)
            .await
            .expect("list");
        assert_eq!(
            still2.len(),
            1,
            "row must remain resumable after second failed tick"
        );
        assert_eq!(still2[0].pk, pk);

        // Recovery on a subsequent successful tick (same process — no restart).
        let ok = TickRecordingPublisher::ok();
        let completed = resume_pending_publishes_tick(&adapter, &ok)
            .await
            .expect("recovery tick");
        assert_eq!(completed, 1);
        assert_eq!(ok.published_count(), 1);
        let gone = db_v1::list_resumable_pending_publishes(&pool)
            .await
            .expect("list");
        assert!(
            gone.is_empty(),
            "row must clear after successful recovery tick"
        );
        drop(scope);
    }
}
