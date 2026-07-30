//! `IssueViewGrant` — transport-free domain procedure (§5.2 / §7.5 / §7.8).
//!
//! Uses the **same** [`ChallengeStore`] as `AttestBalance`, under
//! [`ChallengeAction::IssueViewGrant`]. OwnershipProof verification is
//! API-layer only; this module consumes nonce/`chan_bind` and signs a
//! §5.2 view grant with the account's operational key `op`.
//!
//! ## What a grant unlocks today
//!
//! Reading procedures that honour a grant (`Pull`, `GetRecord`,
//! `GetCoinProof`, `SubscribeReceipts`) land in Block 7. Until then a
//! successfully issued grant **unlocks nothing** on this node: there is
//! no pull-session store and no scope interceptor. That is intentional
//! fail-closed — not an accidental full-account open.
//!
//! ## Scope / revocation
//!
//! - Scope shape and unbounded sentinels are taken from §5.1 / §5.2.
//! - Revocation is a node-local set (§5.2); no revocation API is wired in
//!   this block (reported as a GAP). Issued grants carry `expiry`.
//! - `scope_exceeded` (403) applies when a grant is **used** beyond its
//!   scope; use-time enforcement is Block 7. This module only **issues**.
//!
//! No `axum`, no `tonic`.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use shared::spec_v1::serialize::encode_bech32m;

use crate::kernel::bootstrap::{ChallengeAction, ChallengeStore};
use crate::kernel::types::{ChanBind, Digest32, SubjectAddress, XOnlyKey};
use crate::kernel::{KernelError, KernelErrorCode, KernelResult};

/// §5.2 grant version byte (currently always `0x01`).
pub(crate) const GRANT_VERSION: u8 = 0x01;

/// §5.2 `grant_message` domain tag.
pub(crate) const GRANT_MESSAGE_TAG: &str = "zkCoins/v1/Grant";

/// §7.5 `request_hash` tag for IssueGrant (API-layer OwnershipProof chal).
///
/// Used when the HTTP edge builds
/// `chal = H(domain ‖ nonce ‖ chan_bind ‖ subject ‖ expiry ‖ request_hash)`.
pub(crate) const ISSUE_GRANT_REQUEST_TAG: &str = "zkCoins/v1/IssueGrant";

/// Bech32m HRP for a serialised view grant (§5.2 / §1.7.7).
pub(crate) const GRANT_HRP: &str = "zkgrant";

/// Unbounded `not_after` sentinel: `2⁶³−1` (§5.1).
///
/// Spec: `not_after = 2⁶³−1` (`9223372036854775807`, i64::MAX as u64) means
/// no upper bound. JSON omission is normalised to this sentinel by the API
/// layer **before** the kernel sees the scope; the kernel encodes the value
/// as raw u64-be and does not rewrite `0` (a closed epoch window).
pub(crate) const SCOPE_NOT_AFTER_UNBOUNDED: u64 = 9_223_372_036_854_775_807;

// Lock the §5.1 bit-pattern: unbounded not_after is exactly i64::MAX as u64.
const _: () = assert!(SCOPE_NOT_AFTER_UNBOUNDED == i64::MAX as u64);

/// Closed asset-scope encoding for a view grant (§5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GrantAssetScope {
    /// `asset_ids = "*"` — discriminator byte `0x00`.
    All,
    /// Explicit list, **ascending** 32-byte ids — `0x01 ‖ u32-be count ‖ ids`.
    Selected(Vec<Digest32>),
}

/// Scope carried by an issued grant (and by IssueGrant requests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantScope {
    pub assets: GrantAssetScope,
    /// Lower time bound; `0` = unbounded below (§5.1).
    pub not_before: u64,
    /// Upper time bound; [`SCOPE_NOT_AFTER_UNBOUNDED`] = unbounded above.
    pub not_after: u64,
}

/// Already-authorised `IssueViewGrant` command (§7.8 `GrantRequest`).
///
/// No OwnershipProof / GrantProof fields — API-layer only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssueViewGrantCommand {
    pub subject: SubjectAddress,
    pub grantee_pk: XOnlyKey,
    pub scope: GrantScope,
    /// Grant-level expiry (unix seconds); independent of challenge expiry.
    pub expiry: u64,
    pub nonce: [u8; 32],
    pub chan_bind: ChanBind,
}

/// Dependencies for [`issue_view_grant`].
pub(crate) struct IssueViewGrantDeps<'a> {
    pub challenges: &'a ChallengeStore,
    pub allowed_chan_binds: &'a [[u8; 32]],
    pub now: u64,
    /// BIP-340 secret for the account's operational key `op`.
    ///
    /// `None` when the subject has not entrusted an operational bundle to
    /// this node (Block 8). The procedure then fails closed **before**
    /// consuming the challenge.
    pub op_sk: Option<&'a [u8; 32]>,
}

/// Result of a successful issue: Bech32m `zkgrant` string (§5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ViewGrantIssued {
    pub grant_bech32m: String,
    pub grant_id: [u8; 32],
}

/// Encode `asset_ids` as in `grant_message` / wire payload (§5.2).
pub(crate) fn encode_asset_ids(assets: &GrantAssetScope) -> KernelResult<Vec<u8>> {
    match assets {
        GrantAssetScope::All => Ok(vec![0x00]),
        GrantAssetScope::Selected(ids) => {
            if ids.is_empty() {
                return Err(KernelError::new(
                    KernelErrorCode::MalformedRequest,
                    "grant scope asset_ids list must be non-empty when not \"*\"",
                ));
            }
            // Ascending order is mandatory (§5.2).
            for w in ids.windows(2) {
                if w[0].0 >= w[1].0 {
                    return Err(KernelError::new(
                        KernelErrorCode::MalformedRequest,
                        "grant scope asset_ids must be strictly ascending",
                    ));
                }
            }
            let count = u32::try_from(ids.len()).map_err(|_| {
                KernelError::new(
                    KernelErrorCode::MalformedRequest,
                    "grant scope asset_ids count exceeds u32",
                )
            })?;
            let mut out = Vec::with_capacity(1 + 4 + ids.len() * 32);
            out.push(0x01);
            out.extend_from_slice(&count.to_be_bytes());
            for id in ids {
                out.extend_from_slice(&id.0);
            }
            Ok(out)
        }
    }
}

/// `request_hash = H("zkCoins/v1/IssueGrant" ‖ subject ‖ grantee_pk ‖
/// asset_ids ‖ not_before ‖ not_after ‖ expiry)` (§7.5).
///
/// The kernel does not verify OwnershipProof; the API layer forms this
/// digest before calling [`issue_view_grant`]. Exposed here so both edges
/// share one encoder (no second hash layout).
pub(crate) fn issue_grant_request_hash(
    subject: &SubjectAddress,
    grantee_pk: &XOnlyKey,
    scope: &GrantScope,
    expiry: u64,
) -> KernelResult<[u8; 32]> {
    let asset_enc = encode_asset_ids(&scope.assets)?;
    let mut pre =
        Vec::with_capacity(ISSUE_GRANT_REQUEST_TAG.len() + 32 + 32 + asset_enc.len() + 8 + 8 + 8);
    pre.extend_from_slice(ISSUE_GRANT_REQUEST_TAG.as_bytes());
    pre.extend_from_slice(&subject.0);
    pre.extend_from_slice(&grantee_pk.0);
    pre.extend_from_slice(&asset_enc);
    pre.extend_from_slice(&scope.not_before.to_be_bytes());
    pre.extend_from_slice(&scope.not_after.to_be_bytes());
    pre.extend_from_slice(&expiry.to_be_bytes());
    Ok(Sha256::digest(&pre).into())
}

/// Build the §5.2 payload prefix (version…nonce) and `grant_message`.
fn grant_prefix_and_message(
    subject: &SubjectAddress,
    grantee_pk: &XOnlyKey,
    scope: &GrantScope,
    expiry: u64,
    grant_nonce: &[u8; 16],
) -> KernelResult<(Vec<u8>, [u8; 32])> {
    let asset_enc = encode_asset_ids(&scope.assets)?;
    let mut prefix = Vec::with_capacity(1 + 32 + 32 + asset_enc.len() + 8 + 8 + 8 + 16);
    prefix.push(GRANT_VERSION);
    prefix.extend_from_slice(&subject.0);
    prefix.extend_from_slice(&grantee_pk.0);
    prefix.extend_from_slice(&asset_enc);
    prefix.extend_from_slice(&scope.not_before.to_be_bytes());
    prefix.extend_from_slice(&scope.not_after.to_be_bytes());
    prefix.extend_from_slice(&expiry.to_be_bytes());
    prefix.extend_from_slice(grant_nonce);

    let mut msg_pre = Vec::with_capacity(GRANT_MESSAGE_TAG.len() + prefix.len());
    msg_pre.extend_from_slice(GRANT_MESSAGE_TAG.as_bytes());
    msg_pre.extend_from_slice(&prefix);
    let grant_message: [u8; 32] = Sha256::digest(&msg_pre).into();
    Ok((prefix, grant_message))
}

/// Sign and Bech32m-encode a view grant (§5.2).
pub(crate) fn sign_view_grant(
    op_sk: &[u8; 32],
    subject: &SubjectAddress,
    grantee_pk: &XOnlyKey,
    scope: &GrantScope,
    expiry: u64,
    grant_nonce: &[u8; 16],
) -> KernelResult<ViewGrantIssued> {
    let (prefix, grant_message) =
        grant_prefix_and_message(subject, grantee_pk, scope, expiry, grant_nonce)?;
    let grant_id: [u8; 32] = Sha256::digest(grant_message).into();

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(op_sk).map_err(|e| {
        KernelError::with_internal(
            KernelErrorCode::InternalError,
            "Failed to issue view grant",
            format!("op secret key invalid: {e}"),
        )
    })?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let msg = Message::from_digest_slice(&grant_message).map_err(|e| {
        KernelError::with_internal(
            KernelErrorCode::InternalError,
            "Failed to issue view grant",
            format!("grant_message as BIP-340 message: {e}"),
        )
    })?;
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    let sig_bytes = sig.as_ref();

    let mut payload = prefix;
    payload.extend_from_slice(sig_bytes);

    let grant_bech32m = encode_bech32m(GRANT_HRP, &payload).map_err(|e| {
        let detail = match e {
            shared::spec_v1::SpecError::Bech32DecodeError(msg) => {
                format!("bech32m encode: {msg}")
            }
            other => format!("bech32m encode: {other}"),
        };
        KernelError::with_internal(
            KernelErrorCode::InternalError,
            "Failed to issue view grant",
            detail,
        )
    })?;

    Ok(ViewGrantIssued {
        grant_bech32m,
        grant_id,
    })
}

/// `IssueViewGrant` (§7.8): consume the action-bound challenge, sign the grant.
///
/// # Ordering
///
/// 1. Validate scope encoding (fallible, pure)
/// 2. Require `op_sk` present (fallible) — **before** consume
/// 3. Redeem challenge (atomic, irreversible)
/// 4. Sign + encode (key already validated shape; secp failure → internal)
///
/// A GrantProof must never reach this procedure: the API layer rejects it
/// with `401 unauthorized` (no-escalation, §5.1 / §7.5). This function has
/// no GrantProof parameter — structural, not order-dependent.
pub(crate) fn issue_view_grant(
    deps: IssueViewGrantDeps<'_>,
    command: IssueViewGrantCommand,
) -> KernelResult<ViewGrantIssued> {
    let IssueViewGrantDeps {
        challenges,
        allowed_chan_binds,
        now,
        op_sk,
    } = deps;

    // Pure validation first — do not burn the nonce on a malformed scope.
    // `issue_grant_request_hash` shares the asset-id encoding with
    // `grant_message` so a scope the API cannot hash is refused here too.
    let _request_hash = issue_grant_request_hash(
        &command.subject,
        &command.grantee_pk,
        &command.scope,
        command.expiry,
    )?;
    if command.expiry < now {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "grant expiry is already in the past",
        ));
    }

    let op_sk = match op_sk {
        Some(sk) => sk,
        None => {
            return Err(KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to issue view grant",
                "operational bundle (op signing key) not present for subject; \
                 EntrustOperationalBundle is required before IssueViewGrant",
            ));
        }
    };

    challenges
        .redeem(
            ChallengeAction::IssueViewGrant,
            &command.nonce,
            &command.subject,
            &command.chan_bind,
            allowed_chan_binds,
            now,
        )
        .map_err(crate::kernel::bootstrap::ChallengeConsumeError::into_kernel_error)?;

    // 16-byte grant nonce (independent of the 32-byte challenge nonce).
    let mut grant_nonce = [0u8; 16];
    let g = uuid::Uuid::new_v4();
    grant_nonce.copy_from_slice(g.as_bytes());

    sign_view_grant(
        op_sk,
        &command.subject,
        &command.grantee_pk,
        &command.scope,
        command.expiry,
        &grant_nonce,
    )
}

/// Typed cause: a GrantProof was presented where only OwnershipProof is
/// accepted (no-escalation). Downcastable; never derived from message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GrantProofRejected;

impl std::fmt::Display for GrantProofRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "GrantProof does not authorise this owner-only action \
             (AttestBalance / IssueViewGrant require OwnershipProof; no-escalation)",
        )
    }
}

impl std::error::Error for GrantProofRejected {}

impl GrantProofRejected {
    pub(crate) fn into_kernel_error(self) -> KernelError {
        KernelError::new(KernelErrorCode::Unauthorized, self.to_string())
    }
}

/// Closed capability proof kind for owner-only actions.
///
/// Exhaustive match makes GrantProof rejection **order-independent**: the
/// `Grant` arm always yields [`GrantProofRejected`], regardless of whether
/// challenge / signature checks would run first in another encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerOnlyCapability {
    Ownership,
    Grant,
}

/// Reject anything that is not an OwnershipProof for owner-only procedures.
pub(crate) fn require_ownership_capability(
    kind: OwnerOnlyCapability,
) -> Result<(), GrantProofRejected> {
    match kind {
        OwnerOnlyCapability::Ownership => Ok(()),
        OwnerOnlyCapability::Grant => Err(GrantProofRejected),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::bootstrap::{ChallengeConsumeError, ChallengeStore};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    fn sample_op_sk() -> [u8; 32] {
        [0x55u8; 32]
    }

    #[test]
    fn grant_proof_rejected_for_both_procedures_order_independent() {
        // Same closed match for both procedures — no check-order branch.
        let err = require_ownership_capability(OwnerOnlyCapability::Grant).expect_err("grant");
        assert_eq!(err, GrantProofRejected);
        assert_eq!(err.into_kernel_error().code, KernelErrorCode::Unauthorized);

        require_ownership_capability(OwnerOnlyCapability::Ownership).expect("ownership");
    }

    #[test]
    fn issue_view_grant_happy_path_consumes_challenge() {
        let store = ChallengeStore::new();
        let now = 1_700_000_000u64;
        let subject = SubjectAddress([0x10u8; 32]);
        let issued = store.issue(ChallengeAction::IssueViewGrant, subject, now);
        let allowed = [[0xABu8; 32]];
        let op = sample_op_sk();

        let out = issue_view_grant(
            IssueViewGrantDeps {
                challenges: &store,
                allowed_chan_binds: &allowed,
                now,
                op_sk: Some(&op),
            },
            IssueViewGrantCommand {
                subject,
                grantee_pk: XOnlyKey([0x20u8; 32]),
                scope: GrantScope {
                    assets: GrantAssetScope::All,
                    not_before: 0,
                    not_after: SCOPE_NOT_AFTER_UNBOUNDED,
                },
                expiry: now + 3600,
                nonce: issued.nonce,
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect("issue");

        assert!(
            out.grant_bech32m.starts_with("zkgrant1"),
            "HRP must be zkgrant: {}",
            out.grant_bech32m
        );
        // Challenge consumed.
        let err = store
            .redeem(
                ChallengeAction::IssueViewGrant,
                &issued.nonce,
                &subject,
                &ChanBind(allowed[0]),
                &allowed,
                now,
            )
            .expect_err("consumed");
        assert_eq!(err, ChallengeConsumeError::UnknownOrConsumed);
    }

    #[test]
    fn issue_view_grant_refuses_without_op_before_consume() {
        let store = ChallengeStore::new();
        let now = 100u64;
        let subject = SubjectAddress([0x11u8; 32]);
        let issued = store.issue(ChallengeAction::IssueViewGrant, subject, now);
        let allowed = [[0u8; 32]];

        let err = issue_view_grant(
            IssueViewGrantDeps {
                challenges: &store,
                allowed_chan_binds: &allowed,
                now,
                op_sk: None,
            },
            IssueViewGrantCommand {
                subject,
                grantee_pk: XOnlyKey([0x21u8; 32]),
                scope: GrantScope {
                    assets: GrantAssetScope::All,
                    not_before: 0,
                    not_after: SCOPE_NOT_AFTER_UNBOUNDED,
                },
                expiry: now + 10,
                nonce: issued.nonce,
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect_err("no op");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        // Challenge still live — refuse happened before consume.
        assert!(store.contains(ChallengeAction::IssueViewGrant, &issued.nonce));
    }

    #[test]
    fn attest_challenge_cannot_authorise_issue_view_grant() {
        let store = ChallengeStore::new();
        let now = 200u64;
        let subject = SubjectAddress([0x12u8; 32]);
        let attest = store.issue(ChallengeAction::AttestBalance, subject, now);
        let allowed = [[1u8; 32]];
        let op = sample_op_sk();

        let err = issue_view_grant(
            IssueViewGrantDeps {
                challenges: &store,
                allowed_chan_binds: &allowed,
                now,
                op_sk: Some(&op),
            },
            IssueViewGrantCommand {
                subject,
                grantee_pk: XOnlyKey([0x22u8; 32]),
                scope: GrantScope {
                    assets: GrantAssetScope::All,
                    not_before: 0,
                    not_after: SCOPE_NOT_AFTER_UNBOUNDED,
                },
                expiry: now + 10,
                nonce: attest.nonce,
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect_err("wrong action");
        assert_eq!(err.code, KernelErrorCode::ChallengeExpired);
    }

    #[test]
    fn wrong_chan_bind_rejected() {
        let store = ChallengeStore::new();
        let now = 300u64;
        let subject = SubjectAddress([0x13u8; 32]);
        let issued = store.issue(ChallengeAction::IssueViewGrant, subject, now);
        let allowed = [[2u8; 32]];
        let op = sample_op_sk();

        let err = issue_view_grant(
            IssueViewGrantDeps {
                challenges: &store,
                allowed_chan_binds: &allowed,
                now,
                op_sk: Some(&op),
            },
            IssueViewGrantCommand {
                subject,
                grantee_pk: XOnlyKey([0x23u8; 32]),
                scope: GrantScope {
                    assets: GrantAssetScope::All,
                    not_before: 0,
                    not_after: SCOPE_NOT_AFTER_UNBOUNDED,
                },
                expiry: now + 10,
                nonce: issued.nonce,
                chan_bind: ChanBind([0xFFu8; 32]),
            },
        )
        .expect_err("chan_bind");
        assert_eq!(err.code, KernelErrorCode::Unauthorized);
    }

    #[test]
    fn signed_grant_verifies_under_op_pubkey() {
        let op = sample_op_sk();
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&op).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();

        let subject = SubjectAddress([0x14u8; 32]);
        let grantee = XOnlyKey([0x24u8; 32]);
        let scope = GrantScope {
            assets: GrantAssetScope::Selected(vec![Digest32([0x01; 32]), Digest32([0x02; 32])]),
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let grant_nonce = [0x77u8; 16];
        let expiry = 1_800_000_000u64;

        let (_prefix, grant_message) =
            grant_prefix_and_message(&subject, &grantee, &scope, expiry, &grant_nonce).unwrap();
        let issued =
            sign_view_grant(&op, &subject, &grantee, &scope, expiry, &grant_nonce).unwrap();

        // Recompute message and verify the trailing 64 bytes of the payload.
        let data =
            shared::spec_v1::serialize::decode_bech32m(GRANT_HRP, &issued.grant_bech32m).unwrap();
        assert!(data.len() > 64);
        let sig = &data[data.len() - 64..];
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        // verify via zkcoins half_agg path used elsewhere
        let pk = xonly.serialize();
        zkcoins_prover::half_agg::verify_single(&pk, &r, &s, &grant_message)
            .expect("op signature must verify");
        let expected_id: [u8; 32] = Sha256::digest(grant_message).into();
        assert_eq!(issued.grant_id, expected_id);
    }

    #[test]
    fn asset_ids_must_be_strictly_ascending() {
        let err = encode_asset_ids(&GrantAssetScope::Selected(vec![
            Digest32([0x02; 32]),
            Digest32([0x01; 32]),
        ]))
        .expect_err("descending");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
    }

    #[test]
    fn request_hash_binds_scope_and_expiry() {
        let subject = SubjectAddress([1u8; 32]);
        let grantee = XOnlyKey([2u8; 32]);
        let scope = GrantScope {
            assets: GrantAssetScope::All,
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let h0 = issue_grant_request_hash(&subject, &grantee, &scope, 100).unwrap();
        let h1 = issue_grant_request_hash(&subject, &grantee, &scope, 101).unwrap();
        assert_ne!(h0, h1, "expiry must bind into request_hash");
    }

    #[test]
    fn unbounded_not_after_sentinel_is_spec_value() {
        assert_eq!(SCOPE_NOT_AFTER_UNBOUNDED, 9_223_372_036_854_775_807);
        assert_eq!(SCOPE_NOT_AFTER_UNBOUNDED, i64::MAX as u64);
        // Encoded into grant_message / request_hash as raw u64-be — no rewrite.
        let subject = SubjectAddress([1u8; 32]);
        let grantee = XOnlyKey([2u8; 32]);
        let scope = GrantScope {
            assets: GrantAssetScope::All,
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let h = issue_grant_request_hash(&subject, &grantee, &scope, 100).unwrap();
        let scope_closed = GrantScope {
            assets: GrantAssetScope::All,
            not_before: 0,
            not_after: 0, // closed epoch window, not unbounded
        };
        let h_closed = issue_grant_request_hash(&subject, &grantee, &scope_closed, 100).unwrap();
        assert_ne!(
            h, h_closed,
            "unbounded sentinel must not collide with not_after=0"
        );
    }
}
