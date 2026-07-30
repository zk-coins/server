//! `Publish` — transport-free publisher hand-off (§3.4 / §7.6 / §7.8).
//!
//! A policy or crypto rejection is a **successful** domain result
//! ([`PublishOutcome::Rejected`]), never a transport/`KernelError` failure.
//! That mirrors terminal job failures (`ProvingFailed` / `PublishRejected`
//! as successful `GetJob` answers): the network declined the inscription;
//! the RPC itself succeeded.
//!
//! Fee-coin delivery (presence matrix case (b), §3.8.1) is **not
//! representable** in the domain command. Any non-empty fee field is
//! rejected as `malformed_request` before an outcome is built — fail-closed,
//! never silently ignored. The closed reject-reason inventory still lists
//! the fee-related tokens so the wire vocabulary stays complete for the
//! deferred mechanism.
//!
//! Cryptographic BIP-340 verification is **delegated** to
//! [`zkcoins_prover::half_agg::verify_single`] — not reimplemented here.
//! Sign-to-contract opening is not checked publisher-side in v1 (no fee
//! `CoinProof` → no `H(ProofData)` source; §7.6).
//!
//! No `axum`, no `tonic`.

use zkcoins_program::circuit::compliance::Network as V1Network;
use zkcoins_prover::half_agg::verify_single;

use crate::kernel::chain::{validate_wire_vocabulary, KernelNetwork, WireEntry};
use crate::kernel::types::{Digest32, XOnlyKey};
use crate::kernel::{KernelError, KernelErrorCode, KernelResult};

/// §3.5 maximum gap between `block_anchor.height` and intended inclusion height.
///
/// Spec / publisher: `inclusion_height − block_anchor.height ≤ 100`.
pub(crate) const BLOCK_ANCHOR_MAX_GAP: u64 = 100;

/// Closed §7.6 reject-reason vocabulary.
///
/// Present on the wire **only** when the hand-off is well-formed and
/// `accepted == false`. The inventory length is the closed-set contract;
/// [`validate_closed_sets`] checks every wire token is non-empty and
/// pairwise distinct at process start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PublishRejectReason {
    InvalidSignature,
    InvalidS2cOpening,
    InvalidFeeCoinproof,
    FeeAddressMismatch,
    OcrMismatch,
    FeeTooLow,
    UnknownFeeAsset,
    Policy,
    AnchorStale,
}

impl PublishRejectReason {
    /// Every reason in §7.6 order. Length is the closed-set contract.
    pub(crate) const ALL: [PublishRejectReason; 9] = [
        Self::InvalidSignature,
        Self::InvalidS2cOpening,
        Self::InvalidFeeCoinproof,
        Self::FeeAddressMismatch,
        Self::OcrMismatch,
        Self::FeeTooLow,
        Self::UnknownFeeAsset,
        Self::Policy,
        Self::AnchorStale,
    ];

    /// Normative wire token for `PublishResult.reason`.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidS2cOpening => "invalid_s2c_opening",
            Self::InvalidFeeCoinproof => "invalid_fee_coinproof",
            Self::FeeAddressMismatch => "fee_address_mismatch",
            Self::OcrMismatch => "ocr_mismatch",
            Self::FeeTooLow => "fee_too_low",
            Self::UnknownFeeAsset => "unknown_fee_asset",
            Self::Policy => "policy",
            Self::AnchorStale => "anchor_stale",
        }
    }
}

/// Successful `Publish` result: accepted into a batch **or** typed rejection.
///
/// Unrepresentable combinations (`accepted` with `reason`, or `rejected`
/// with `batch_eta`) cannot be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PublishOutcome {
    Accepted { batch_eta: u64 },
    Rejected { reason: PublishRejectReason },
}

/// §3.5 block anchor carried by the hand-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PublishBlockAnchor {
    pub block_hash: Digest32,
    pub height: u32,
}

/// Decoded, fee-less publish command (§7.6 / §7.8).
///
/// Fee fields are **absent by construction**. Transport that observes any
/// non-empty `fee_blob_id` / `fee_epk` / `fee_blob_locators` must refuse
/// with `malformed_request` via [`refuse_v1_fee_fields`] before building
/// this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PublishCommand {
    pub public_key: XOnlyKey,
    pub r: XOnlyKey,
    pub s: Digest32,
    pub r_prime: XOnlyKey,
    pub block_anchor: PublishBlockAnchor,
}

/// Publisher policy for the v1 fee-less hand-off (presence matrix case (c)
/// and self-publish through this endpoint).
///
/// Closed decision set (§3.8 / §7.6): a publisher either **accepts** the
/// fee-less path or **declines** it. Decline is not consensus — it projects
/// to [`PublishRejectReason::Policy`] on a successful RPC (`accepted: false`).
/// Fee policy is not consensus; the reject-reason inventory stays separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PublishPolicy {
    /// Accept a well-formed, signature-valid, anchor-fresh fee-less hand-off.
    AcceptFeeLess { batch_eta_secs: u64 },
    /// Decline every fee-less hand-off with [`PublishRejectReason::Policy`].
    DeclineFeeLess,
}

impl PublishPolicy {
    /// Every fee-less policy arm. Length is the closed-set contract.
    ///
    /// Constructed in library code (not only under `cfg(test)`) so a dropped
    /// Spec case cannot hide behind dead-code silence. `batch_eta_secs` on
    /// the Accept arm is deployment configuration, not a wire token — the
    /// inventory only needs the arm to exist; the concrete eta is supplied
    /// at each call site.
    pub(crate) const ALL: [PublishPolicy; 2] = [
        Self::AcceptFeeLess { batch_eta_secs: 0 },
        Self::DeclineFeeLess,
    ];
}

/// Named configuration for [`publish`] (clippy `too_many_arguments` bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublishConfig {
    pub network: KernelNetwork,
    /// Live Bitcoin tip height used as the intended inclusion height for the
    /// §3.5 gap check. `None` means the process has no tip yet — the procedure
    /// fails closed as `internal_error` rather than inventing a height or
    /// skipping the bound.
    pub tip_height: Option<u64>,
    pub policy: PublishPolicy,
}

/// Refuse any non-empty fee delivery field in v1 (§3.8.1 / §7.6).
///
/// A partial set is also malformed. Empty-all is the only admissible shape.
pub(crate) fn refuse_v1_fee_fields(
    fee_blob_id: &[u8],
    fee_epk: &[u8],
    fee_blob_locators: &[u8],
) -> KernelResult<()> {
    if fee_blob_id.is_empty() && fee_epk.is_empty() && fee_blob_locators.is_empty() {
        return Ok(());
    }
    Err(KernelError::new(
        KernelErrorCode::MalformedRequest,
        "fee_blob_id, fee_epk, and fee_blob_locators must be absent in v1 \
         (fee-coin hand-off is deferred; presence matrix case (b) is not representable)",
    ))
}

/// `Publish` (§7.8): verify shape already checked, run §7.6 verification
/// order for the fee-less path, return a typed outcome.
///
/// # Outcome vs error
///
/// - **Shape / v1 fee presence** → `Err(malformed_request)` (caller must
///   refuse before this when fee bytes are non-empty).
/// - **Missing tip pin** → `Err(internal_error)` (no invented height).
/// - **Crypto / policy / anchor** → `Ok(Rejected { reason })`.
/// - **Accepted** → `Ok(Accepted { batch_eta })`.
///
/// A rejection is never an `Err`. The RPC layer maps `Ok(_)` to a
/// successful status and projects `accepted` / `reason` / `batch_eta`.
pub(crate) fn publish(
    config: PublishConfig,
    command: PublishCommand,
) -> KernelResult<PublishOutcome> {
    let PublishConfig {
        network,
        tip_height,
        policy,
    } = config;

    // 1. BIP-340 over the per-network fixed m_state (§7.6 step 1).
    let m_state = kernel_network_to_v1(network).m_state_bytes();
    if let Err(_e) = verify_single(&command.public_key.0, &command.r.0, &command.s.0, m_state) {
        return Ok(PublishOutcome::Rejected {
            reason: PublishRejectReason::InvalidSignature,
        });
    }

    // 2–3. Fee path deferred — command cannot carry fee fields.
    // S2C opening is not checked without a fee CoinProof (§7.6).

    // 4. block_anchor within §3.5 gap of intended inclusion (tip).
    let tip = match tip_height {
        Some(h) => h,
        None => {
            return Err(KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Publish requires a live Bitcoin tip for the block_anchor bound",
                "PublishConfig.tip_height is None — chain tip not installed on the façade",
            ));
        }
    };
    if !anchor_within_gap(command.block_anchor.height, tip) {
        return Ok(PublishOutcome::Rejected {
            reason: PublishRejectReason::AnchorStale,
        });
    }

    // 5. Publisher policy on the fee-less hand-off.
    match policy {
        PublishPolicy::DeclineFeeLess => Ok(PublishOutcome::Rejected {
            reason: PublishRejectReason::Policy,
        }),
        PublishPolicy::AcceptFeeLess { batch_eta_secs } => Ok(PublishOutcome::Accepted {
            batch_eta: batch_eta_secs,
        }),
    }
}

/// `block_anchor` is a strict ancestor of `inclusion_height` within gap ≤ 100.
fn anchor_within_gap(anchor_height: u32, inclusion_height: u64) -> bool {
    let anchor = u64::from(anchor_height);
    if inclusion_height <= anchor {
        return false;
    }
    inclusion_height - anchor <= BLOCK_ANCHOR_MAX_GAP
}

fn kernel_network_to_v1(network: KernelNetwork) -> V1Network {
    match network {
        KernelNetwork::Mainnet => V1Network::Mainnet,
        KernelNetwork::Testnet => V1Network::Testnet,
        KernelNetwork::Regtest => V1Network::Regtest,
    }
}

fn reject_reason_label(r: PublishRejectReason) -> &'static str {
    match r {
        PublishRejectReason::InvalidSignature => "InvalidSignature",
        PublishRejectReason::InvalidS2cOpening => "InvalidS2cOpening",
        PublishRejectReason::InvalidFeeCoinproof => "InvalidFeeCoinproof",
        PublishRejectReason::FeeAddressMismatch => "FeeAddressMismatch",
        PublishRejectReason::OcrMismatch => "OcrMismatch",
        PublishRejectReason::FeeTooLow => "FeeTooLow",
        PublishRejectReason::UnknownFeeAsset => "UnknownFeeAsset",
        PublishRejectReason::Policy => "Policy",
        PublishRejectReason::AnchorStale => "AnchorStale",
    }
}

/// Fail-closed check of the §7.6 `reason` vocabulary **and** the fee-less
/// policy decision set at process start.
pub(crate) fn validate_closed_sets() -> Result<(), String> {
    let reasons: [WireEntry; 9] = PublishRejectReason::ALL.map(|r| WireEntry {
        label: reject_reason_label(r),
        wire: r.as_str(),
    });
    validate_wire_vocabulary("PublishRejectReason", &reasons)?;

    // PublishPolicy is not a wire vocabulary (no tokens) — it is the closed
    // accept/decline decision for the fee-less hand-off (§3.8 / §7.6). Both
    // arms must be constructible here so the inventory cannot silently shrink.
    if PublishPolicy::ALL.len() != 2 {
        return Err(format!(
            "PublishPolicy inventory length {}, expected 2 (AcceptFeeLess, DeclineFeeLess)",
            PublishPolicy::ALL.len()
        ));
    }
    let mut saw_accept = false;
    let mut saw_decline = false;
    for p in PublishPolicy::ALL {
        match p {
            PublishPolicy::AcceptFeeLess { .. } => saw_accept = true,
            PublishPolicy::DeclineFeeLess => saw_decline = true,
        }
    }
    if !saw_accept || !saw_decline {
        return Err(
            "PublishPolicy::ALL must construct both AcceptFeeLess and DeclineFeeLess".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::spec_v1::{ProofData, ZERO_HASH};
    use zkcoins_prover::prover_bridge::test_signing::{
        deterministic_secret, normalized_key, sign_transition,
    };

    fn zero_pd() -> ProofData {
        ProofData {
            new_account_state_hash: ZERO_HASH,
            output_coins_root: ZERO_HASH,
            input_nullifiers_root: ZERO_HASH,
            coin_history_root: ZERO_HASH,
            nav_commitment: ZERO_HASH,
            npk_commit: [0u8; 32],
        }
    }

    fn signed_command(network: KernelNetwork) -> PublishCommand {
        let v1 = kernel_network_to_v1(network);
        let (secret, public, pk) =
            normalized_key(deterministic_secret(b"zkCoins/v1/block8/publish-test"));
        let signed = sign_transition(secret, public, &zero_pd(), v1);
        let sig = signed.transition.signature;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        PublishCommand {
            public_key: XOnlyKey(pk),
            r: XOnlyKey(r),
            s: Digest32(s),
            r_prime: XOnlyKey(signed.transition.r_prime),
            block_anchor: PublishBlockAnchor {
                block_hash: Digest32([0xABu8; 32]),
                height: 50,
            },
        }
    }

    fn accept_config(tip: u64) -> PublishConfig {
        PublishConfig {
            network: KernelNetwork::Regtest,
            tip_height: Some(tip),
            policy: PublishPolicy::AcceptFeeLess { batch_eta_secs: 30 },
        }
    }

    /// Property 1: a publish rejection is `Ok(Rejected)`, not `Err`.
    #[test]
    fn publish_rejection_is_successful_outcome_not_rpc_error() {
        let mut cmd = signed_command(KernelNetwork::Regtest);
        // Corrupt s → BIP-340 fails → typed rejection.
        cmd.s = Digest32([0xFFu8; 32]);
        let outcome = publish(accept_config(60), cmd).expect("rejection is Ok, not Err");
        match outcome {
            PublishOutcome::Rejected {
                reason: PublishRejectReason::InvalidSignature,
            } => {}
            other => panic!("expected Rejected(InvalidSignature), got {other:?}"),
        }
    }

    /// Property 2: closed reason inventory + start-edge uniqueness.
    #[test]
    fn reject_reason_inventory_is_closed_and_distinct() {
        assert_eq!(PublishRejectReason::ALL.len(), 9);
        validate_closed_sets().expect("inventory must pass start-edge check");
        let mut seen = std::collections::BTreeSet::new();
        for r in PublishRejectReason::ALL {
            assert!(!r.as_str().is_empty(), "{r:?} wire must be non-empty");
            assert!(
                seen.insert(r.as_str()),
                "duplicate wire token {}",
                r.as_str()
            );
        }
    }

    /// Closed fee-less policy set: Accept and Decline are both Spec arms.
    #[test]
    fn fee_less_policy_inventory_is_closed() {
        assert_eq!(PublishPolicy::ALL.len(), 2);
        validate_closed_sets().expect("policy inventory must pass start-edge check");
        let mut saw_accept = false;
        let mut saw_decline = false;
        for p in PublishPolicy::ALL {
            match p {
                PublishPolicy::AcceptFeeLess { .. } => saw_accept = true,
                PublishPolicy::DeclineFeeLess => saw_decline = true,
            }
        }
        assert!(saw_accept, "AcceptFeeLess must be in PublishPolicy::ALL");
        assert!(saw_decline, "DeclineFeeLess must be in PublishPolicy::ALL");
    }

    /// Property 3: any fee field present is malformed (fail-closed).
    #[test]
    fn fee_fields_fail_closed_when_set() {
        let cases: [(&[u8], &[u8], &[u8]); 4] = [
            (&[0u8; 32], &[], &[]),
            (&[], &[0u8; 32], &[]),
            (&[], &[], b"locators"),
            (&[1u8; 32], &[2u8; 32], b"x"),
        ];
        for (a, b, c) in cases {
            let err = refuse_v1_fee_fields(a, b, c).expect_err("fee field must be refused");
            assert_eq!(
                err.code,
                KernelErrorCode::MalformedRequest,
                "cause must be malformed_request, got {:?}",
                err.code
            );
            assert!(
                err.public_message.contains("fee_blob_id")
                    || err.public_message.contains("fee-coin")
                    || err.public_message.contains("fee_epk"),
                "message must name fee fields, got: {}",
                err.public_message
            );
        }
        refuse_v1_fee_fields(&[], &[], &[]).expect("all-empty is the only v1 shape");
    }

    #[test]
    fn policy_decline_is_rejected_not_error() {
        let cmd = signed_command(KernelNetwork::Regtest);
        let config = PublishConfig {
            network: KernelNetwork::Regtest,
            tip_height: Some(60),
            policy: PublishPolicy::DeclineFeeLess,
        };
        let outcome = publish(config, cmd).expect("Ok");
        assert_eq!(
            outcome,
            PublishOutcome::Rejected {
                reason: PublishRejectReason::Policy
            }
        );
    }

    #[test]
    fn anchor_stale_when_gap_exceeds_100() {
        let cmd = signed_command(KernelNetwork::Regtest);
        // anchor.height = 50; tip = 200 → gap 150 > 100.
        let outcome = publish(accept_config(200), cmd).expect("Ok");
        assert_eq!(
            outcome,
            PublishOutcome::Rejected {
                reason: PublishRejectReason::AnchorStale
            }
        );
    }

    #[test]
    fn accept_returns_batch_eta() {
        let cmd = signed_command(KernelNetwork::Regtest);
        let outcome = publish(accept_config(60), cmd).expect("Ok");
        assert_eq!(
            outcome,
            PublishOutcome::Accepted { batch_eta: 30 },
            "accepted outcome must carry batch_eta, not a free reason string"
        );
    }

    #[test]
    fn missing_tip_is_internal_error_not_invented_acceptance() {
        let cmd = signed_command(KernelNetwork::Regtest);
        let config = PublishConfig {
            network: KernelNetwork::Regtest,
            tip_height: None,
            policy: PublishPolicy::AcceptFeeLess { batch_eta_secs: 1 },
        };
        let err = publish(config, cmd).expect_err("no tip");
        assert_eq!(err.code, KernelErrorCode::InternalError);
    }

    #[test]
    fn wrong_network_m_state_is_invalid_signature() {
        // Sign under regtest; verify under mainnet.
        let cmd = signed_command(KernelNetwork::Regtest);
        let config = PublishConfig {
            network: KernelNetwork::Mainnet,
            tip_height: Some(60),
            policy: PublishPolicy::AcceptFeeLess { batch_eta_secs: 1 },
        };
        let outcome = publish(config, cmd).expect("Ok");
        assert_eq!(
            outcome,
            PublishOutcome::Rejected {
                reason: PublishRejectReason::InvalidSignature
            }
        );
    }

    #[test]
    fn validate_closed_sets_rejects_empty_and_duplicate_injections() {
        let empty = [WireEntry {
            label: "Policy",
            wire: "",
        }];
        let err = validate_wire_vocabulary("PublishRejectReason", &empty).expect_err("empty wire");
        assert!(err.contains("empty wire string"), "got: {err}");

        let dup = [
            WireEntry {
                label: "Policy",
                wire: "policy",
            },
            WireEntry {
                label: "AnchorStale",
                wire: "policy",
            },
        ];
        let err = validate_wire_vocabulary("PublishRejectReason", &dup).expect_err("dup");
        assert!(err.contains("duplicate wire string"), "got: {err}");
    }

    /// Property 6: SPEND-branch secrets must not appear as RPC field names.
    ///
    /// The operational bundle carries VIEW/op/nk/op_secret only. SPEND is
    /// `A/0'/i'` (`skᵢ`) and is never a kernel.v1 message field.
    #[test]
    fn no_spend_branch_secret_field_names_in_kernel_proto() {
        let proto = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../proto/kernel/v1/kernel.proto"
        ));
        // Field/token names that would let a SPEND-branch secret cross the
        // kernel boundary if present as a wire field.
        let forbidden = [
            "spend_sk",
            "spend_secret",
            "sk_i",
            "sk0",
            "sk_0",
            "master_secret",
            "bip32_seed",
            "mnemonic",
            "A_0",
            "spend_key",
        ];
        for token in forbidden {
            assert!(
                !proto.contains(token),
                "kernel.v1 proto must not carry SPEND-branch token {token:?}"
            );
        }
        // Operational bundle is intentional (VIEW/op/nk/op_secret), not SPEND.
        assert!(
            proto.contains("message EntrustRequest"),
            "EntrustRequest must exist (operational bundle, not SPEND)"
        );
        assert!(
            proto.contains("bytes bundle = 3"),
            "EntrustRequest.bundle carries the 161-byte operational bundle"
        );
    }
}
