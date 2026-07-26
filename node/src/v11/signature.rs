//! Gap G4 — v1.1 transition signature on the node (BIP-340 + sign-to-contract).
//!
//! Behind `ZKCOINS_V11_SHADOW=1` every state-advancing transition is authorised
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
//! - [`refuse_legacy_commitment_under_v11`] gates residual ash‖ocr
//!   [`CommitRequest`](crate::router::CommitRequest) entry points
//!   (`commit_flow` / `mint_commit_flow` / jobs commit). Under
//!   `ScanStackMode::V11` a legacy commitment is refused loud.
//! - Send / receive finalise must call
//!   [`accept_wallet_transition_signature`] with the engine's pending
//!   transition before installing the signature. REST `/sign` remains
//!   Stage 3; this module is the internal verification those paths use.

use std::fmt;

use shared::spec_v1::{hash_proof_data, serialize_proof_data, ProofData};
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::half_agg::{comm_verify, verify_single};
use zkcoins_prover::prover_bridge::TransitionSignature;
use zkcoins_prover::state_engine::PendingTransition;

use super::mode::V11ShadowMode;
use super::separation::{process_stack_mode, ScanStackMode};

/// Canonical message when a legacy ash‖ocr Commitment hits a v1.1 process.
pub const LEGACY_COMMITMENT_REFUSED_UNDER_V11: &str =
    "legacy ash‖ocr Commitment refused under v1.1 process claim; \
     submit a §3.2 TransitionSignature bound to the pending transition \
     (ZKCOINS_V11_SHADOW=1 / ScanStackMode::V11 — no dual-accept)";

/// Which verification step rejected a wallet signature.
///
/// Tests (and callers) must branch on this so a wrong-network reject is not
/// misreported as an S2C failure and vice versa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCheck {
    /// `ZKCOINS_V11_SHADOW` is not on — legacy ash‖ocr path only.
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

/// Binary body of `POST /v1/jobs/<job_id>/sign` after hex decode (§7.5).
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
    pub fn from_hex(
        signature_hex: &str,
        s2c_nonce_hex: &str,
    ) -> Result<Self, TransitionSignatureError> {
        Ok(Self {
            signature: parse_hex_exact(signature_hex, "signature")?,
            s2c_nonce: parse_hex_exact(s2c_nonce_hex, "s2c_nonce")?,
        })
    }

    pub fn signature_r(&self) -> [u8; 32] {
        self.signature[..32]
            .try_into()
            .expect("64-byte signature has a 32-byte R")
    }

    pub fn signature_s(&self) -> [u8; 32] {
        self.signature[32..]
            .try_into()
            .expect("64-byte signature has a 32-byte s")
    }
}

/// Refuse the v1.1 signature path when the shadow flag is off.
///
/// Legacy ash‖ocr commitments remain the only authorised signing protocol
/// under [`V11ShadowMode::Off`]. There is no silent dual-accept.
pub fn ensure_v11_signature_path(mode: V11ShadowMode) -> Result<(), TransitionSignatureError> {
    match mode {
        V11ShadowMode::On => Ok(()),
        V11ShadowMode::Off => Err(TransitionSignatureError::new(
            SignatureCheck::ShadowFlag,
            "ZKCOINS_V11_SHADOW is off — refusing TransitionSignature path \
             (legacy ash‖ocr Commitment remains the default; no dual-accept)",
        )),
    }
}

/// Refuse a residual legacy ash‖ocr Commitment under a v1.1 process claim.
///
/// Returns `Ok(())` when the process is **not** on the v1.1 claim (legacy
/// or unclaimed). Fail-loud under `ScanStackMode::V11` — never a silent
/// allow of the wrong signing protocol.
///
/// Wired into `commit_flow` / `mint_commit_flow` and the jobs commit
/// handler so a v1.1 boot cannot finalise via `CommitRequest`.
pub fn refuse_legacy_commitment_under_v11() -> Result<(), TransitionSignatureError> {
    match process_stack_mode() {
        Some(ScanStackMode::V11) => Err(TransitionSignatureError::new(
            SignatureCheck::LegacyCommitment,
            LEGACY_COMMITMENT_REFUSED_UNDER_V11,
        )),
        Some(ScanStackMode::Legacy) | None => Ok(()),
    }
}

/// Finalise-path entry: decode already done; derive `pk_i` and
/// `serialize(ProofData)` **from the pending transition**, verify BIP-340
/// + S2C, and return a [`TransitionSignature`] ready for engine finalise.
///
/// `mode` must be [`V11ShadowMode::On`]; under Off this fails at
/// [`SignatureCheck::ShadowFlag`] so the legacy Commitment path cannot be
/// bypassed by feeding a TransitionSignature into a half-migrated caller.
///
/// **Provenance is enforced by the type signature:** there is no
/// independent `expected_pk_i` or `proof_data` parameter. Substituting a
/// foreign `ProofData` while finalising a different pending transition is
/// not expressible — the only material used is `pending.proof_data` and
/// `pending.witness_wip.prev_account_state.current_pubkey`.
pub fn accept_wallet_transition_signature(
    mode: V11ShadowMode,
    network: Network,
    pending: &PendingTransition,
    submission: &WalletSignSubmission,
) -> Result<TransitionSignature, TransitionSignatureError> {
    ensure_v11_signature_path(mode)?;

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
pub fn verify_transition_signature_material(
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

#[cfg(test)]
mod tests {
    use super::*;
    use shared::spec_v1::{
        account_state_hash, address, asset_id_v1, coin_identifier, coinhist_empty_root,
        coinhist_root_after_first_insert, digest_to_bytes, hash_proof_data, merkle_root, name_hash,
        nav_commitment, nflog_empty, nflog_root, nk_commit, npk_commit, serialize_proof_data,
        AccountState, Address, CoinHistState, Nav, ProofData, TreeKind, GENESIS_TAG, ZERO_HASH,
    };
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use zkcoins_prover::prover_bridge::{NavOpening, TransitionMode, TransitionWitness};
    use zkcoins_prover::state_engine::PendingTransition;

    use crate::v11::separation::{
        clear_process_stack_mode_for_test, set_process_stack_mode, ScanStackMode,
    };

    // ── V.5 pins from the reference implementation fixture ─────────────────
    // Source: script-plonky2/tests/generated_sig_agg_vectors.txt
    // (output of generate_sig_agg_vectors). Proposed for specification
    // appendix V.5 in PR #124 (unmerged draft at the time of this wiring).
    // Not claimed as already normative in the published spec tree.
    // Read-only conformance anchors. Do not regenerate here.

    const V2EXT_PK0: &str =
        "7c9cdde9b8cb1e33a48a5c2b6ab1fa6fd753fa1762f56c0b3e8169e4f2d54630";
    const H_PROOF_DATA_0: &str =
        "db8c60533ba19eba14958f6ce44fd8df2e784d17dac28d8532e66fa938308de4";

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
                V11ShadowMode::On,
                network,
                &pending,
                &submission,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "reference V.5 signature fixture must verify under {network:?}: {e}"
                );
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
            V11ShadowMode::On,
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
            V11ShadowMode::On,
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
            V11ShadowMode::On,
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
            V11ShadowMode::On,
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
            V11ShadowMode::On,
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
            V11ShadowMode::On,
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
            V11ShadowMode::Off,
            Network::Regtest,
            &pending,
            &submission,
        )
        .expect_err("flag off must refuse TransitionSignature");
        assert_eq!(err.check, SignatureCheck::ShadowFlag, "got: {err}");
    }

    /// Defect 1: under a v1.1 process claim the wired path refuses a legacy
    /// ash‖ocr Commitment, and accepts a v1.1 TransitionSignature against
    /// the pending transition.
    #[test]
    fn wired_path_rejects_legacy_commitment_under_v11_and_accepts_v11_signature() {
        clear_process_stack_mode_for_test();

        // Flag / claim off: legacy commitment gate stays open; v1.1 accept
        // path is still gated by the shadow mode parameter.
        assert!(
            refuse_legacy_commitment_under_v11().is_ok(),
            "unclaimed process must allow residual legacy commit path"
        );

        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::Legacy);
        assert!(
            refuse_legacy_commitment_under_v11().is_ok(),
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
        clear_process_stack_mode_for_test();

        // v1.1 claim: refuse legacy commitment loud.
        set_process_stack_mode(ScanStackMode::V11);
        let legacy_err =
            refuse_legacy_commitment_under_v11().expect_err("v1.1 claim must refuse legacy");
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
            V11ShadowMode::On,
            Network::Mainnet,
            &pending,
            &submission,
        )
        .expect("v1.1 signature must be accepted under the v1.1 claim");
        assert_eq!(sig.pk_i, pk);

        clear_process_stack_mode_for_test();
    }

    #[test]
    fn legacy_commitment_path_unchanged_when_flag_off() {
        // Demonstrates: with the flag off, the legacy ash‖ocr Commitment
        // verify still works exactly as before. G4 does not touch
        // shared::commitment or the dual 32/64-byte path in state.rs.
        use bitcoin::secp256k1::SecretKey;
        use shared::commitment::Commitment;

        clear_process_stack_mode_for_test();
        let sk = SecretKey::from_slice(&[0x42u8; 32]).expect("secret");
        let mut message = vec![0u8; 64];
        message[..32].fill(0xA1);
        message[32..].fill(0xB2);
        let commitment = Commitment::new(&sk, message).expect("sign legacy commitment");
        assert!(
            commitment.verify(),
            "legacy Commitment::verify must still accept ash‖ocr under flag-off"
        );
        assert!(ensure_v11_signature_path(V11ShadowMode::Off).is_err());
        assert!(ensure_v11_signature_path(V11ShadowMode::On).is_ok());
        assert!(refuse_legacy_commitment_under_v11().is_ok());
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
        let err = WalletSignSubmission::from_hex(&sig_hex.to_uppercase(), &r_hex)
            .expect_err("uppercase");
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

        let err = WalletSignSubmission::from_hex(&format!("0X{sig_hex}"), &r_hex)
            .expect_err("0X prefix");
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
            V11ShadowMode::On,
            Network::Regtest,
            &pending,
            &submission,
        )
        .expect("canonical path");
    }
}
