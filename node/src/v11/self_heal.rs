//! v1.1 self-heal: digest baseline for `C` / `C_balance` and the canary
//! that replaces the legacy CMP/MMR recursion probe (Cutover Gap G5).
//!
//! # What the boot check compares
//!
//! Under `ZKCOINS_V11_SHADOW=1` the live digest blob is the tagged encoding
//! of the §3.6 boot pins `circuit_digest(C)` and `circuit_digest(C_balance)`
//! (see [`encode_v11_live_digest`]). The boot path compares that blob
//! byte-for-byte against `circuit_digest_meta` via the shared
//! [`crate::self_heal::heal_circuit_digest`] decision function. A mismatch
//! is always [`crate::self_heal::ResetDecision::Reset`] — never ignored.
//!
//! The pins are the protocol constants already mandatory for shadow boot
//! (`ZKCOINS_CIRCUIT_DIGEST_C` / `_C_BALANCE`). They deliberately avoid a
//! multi-minute Plonky2 circuit build at boot. Binary digests
//! ([`crate::v11::EngineAdapter::circuit_digests`]) remain available for
//! the slow path and for later Stage-3 prove-site cross-checks.
//!
//! # Boot canary (adoption boundary, no persisted digest)
//!
//! When no digest is stored yet, detector 2 probes whether a proof-bearing
//! v1.1 account still has the recursion preconditions the next
//! `AccountUpdate` needs:
//!
//! * a persisted `last_proof` (`ComplianceProof`)
//! * `last_nullifier` (predecessor nullifier opening)
//! * `last_nav_opening`
//! * the predecessor nullifier still present on the live NfLog at the
//!   recorded position with matching `R`
//! * the recorded NAV still equal to the live engine NfLog NAV
//!
//! Structural failure → [`CanaryOutcome::Stale`] → full reset.
//! All preconditions hold → [`CanaryOutcome::Compatible`].
//! No proof-bearing account → [`CanaryOutcome::NoSample`].
//!
//! # Edge: full re-prove is too slow for boot
//!
//! A genuine cyclic `prove_transition` (BIP-340 in-circuit AccountUpdate
//! with predecessor nullifier + NAV + `prev_proof`) requires the compliance
//! circuit build (multi-minute cold) plus a multi-second prove. That is
//! **not** run at boot.
//!
//! | Check | When | Cost | Establishes |
//! |---|---|---|---|
//! | Digest compare `C` + `C_balance` | every boot | O(1) | pins vs last recorded baseline |
//! | Structural canary (nullifier / NAV / openings) | no digest only | O(accounts) | recursion inputs still present and consistent |
//! | [`slow_canary_verify_transition`] | operator opt-in | circuit build + verify | live `C` still **accepts** a persisted proof |
//! | Full re-prove AccountUpdate | not automated here | circuit + prove | live `C` still **produces** a successor proof |
//!
//! ## Operator recovery / slow canary
//!
//! 1. **Digest mismatch at boot** — node resets v1.1 proof-dependent state
//!    (NfLog, accounts, pending publishes, legacy `accounts` rows) to empty
//!    genesis, stores the live pin digest, and re-inits the in-memory
//!    engine. Operator re-funds / re-mints as for any genesis wipe.
//! 2. **Slow verify canary** — set `ZKCOINS_V11_SLOW_CANARY=1` before boot.
//!    Runs `ProverBridge::verify_transition` on a persisted proof (pays the
//!    circuit build). Failure is loud: Stale → Reset.
//! 3. **Cannot determine** — a proof-bearing account missing nullifier or
//!    NAV openings is treated as **Stale** (fail-closed), never as fine.
//!
//! Flag off: this module is never consulted; legacy
//! [`crate::self_heal::heal_circuit_digest`] +
//! [`crate::account_node::AccountNode::canary_recursion`] stay byte-identical.

use shared::spec_v1::accumulator::LookupResult;
use shared::spec_v1::Nav;
use tracing::{info, warn};
use zkcoins_prover::prover_bridge::{ComplianceProof, NavOpening, NullifierOpening};

use crate::account_node::CanaryOutcome;

use super::adapter::EngineAdapter;

/// Magic prefix so a legacy bincode `HashOut` digest can never silently
/// equal a v1.1 pin encoding (different length and fixed tag).
pub const V11_DIGEST_TAG: &[u8; 4] = b"V11\0";

/// Total length of [`encode_v11_live_digest`]: tag + C + C_balance.
pub const V11_LIVE_DIGEST_LEN: usize = 4 + 32 + 32;

/// Encode the live v1.1 self-heal baseline: `V11\0 || C || C_balance`.
///
/// Both digests are the §1.7.1 32-byte forms (same as
/// `ProverBridge::circuit_digest_bytes` / `balance_circuit_digest_bytes`
/// and the §3.6 boot pins).
pub fn encode_v11_live_digest(c: &[u8; 32], c_balance: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(V11_LIVE_DIGEST_LEN);
    out.extend_from_slice(V11_DIGEST_TAG);
    out.extend_from_slice(c);
    out.extend_from_slice(c_balance);
    out
}

/// Decode a blob previously produced by [`encode_v11_live_digest`].
///
/// Returns `None` when the tag or length is wrong — callers that expect a
/// v1.1 baseline must treat `None` as "not a v1.1 digest" (which a live
/// pin encoding will not match → Reset). Never invents defaults.
pub fn decode_v11_live_digest(blob: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if blob.len() != V11_LIVE_DIGEST_LEN {
        return None;
    }
    if &blob[..4] != V11_DIGEST_TAG.as_slice() {
        return None;
    }
    let mut c = [0u8; 32];
    let mut c_balance = [0u8; 32];
    c.copy_from_slice(&blob[4..36]);
    c_balance.copy_from_slice(&blob[36..68]);
    Some((c, c_balance))
}

/// Structural inputs the next AccountUpdate recursion needs from a
/// persisted account (predecessor nullifier + NAV). Independent of the
/// proof blob so pure unit tests do not need a Plonky2 proof fixture.
#[derive(Clone, Debug)]
pub struct V11StructuralInputs<'a> {
    pub last_nullifier: Option<&'a NullifierOpening>,
    pub last_nullifier_pos: Option<u64>,
    pub last_nav_opening: Option<&'a NavOpening>,
}

/// Full canary sample: structural inputs plus the persisted proof (used
/// by the slow verify path).
#[derive(Clone, Debug)]
pub struct V11CanarySample<'a> {
    pub last_proof: &'a ComplianceProof,
    pub structural: V11StructuralInputs<'a>,
}

/// Live NfLog facts the structural canary needs (injected for pure tests).
#[derive(Clone, Debug)]
pub struct V11CanaryNflogView {
    pub nav: Nav,
    /// `(pos, r)` for a looked-up predecessor Pk, or `None` if absent.
    pub predecessor: Option<(u64, [u8; 32])>,
}

/// Pure structural canary.
///
/// * Missing nullifier or NAV opening while a proof exists → [`Stale`]
///   (inconsistent proof-dependent state; fail-closed).
/// * Predecessor absent / R or position mismatch → [`Stale`].
/// * Recorded NAV ≠ live NfLog NAV → [`Stale`].
/// * All checks pass → [`Compatible`].
///
/// Does **not** call Plonky2. Crypto acceptance of the proof is the slow
/// path ([`evaluate_v11_slow_canary`]).
pub fn evaluate_v11_structural_canary(
    inputs: &V11StructuralInputs<'_>,
    nflog: &V11CanaryNflogView,
) -> CanaryOutcome {
    let (Some(nf), Some(nav_open)) = (inputs.last_nullifier, inputs.last_nav_opening) else {
        // Proof without the recursion openings the next AccountUpdate needs.
        // "Cannot determine" is not fine — treat as stale so boot resets.
        warn!(
            "v1.1 self-heal canary: proof-bearing account is missing \
             last_nullifier and/or last_nav_opening; treating as Stale \
             (fail-closed — next AccountUpdate cannot recurse)"
        );
        return CanaryOutcome::Stale;
    };

    match nflog.predecessor {
        None => {
            warn!(
                "v1.1 self-heal canary: predecessor nullifier Pk not on live NfLog; Stale"
            );
            return CanaryOutcome::Stale;
        }
        Some((pos, r)) => {
            if r != nf.signature_r {
                warn!(
                    "v1.1 self-heal canary: predecessor nullifier R mismatch on NfLog; Stale"
                );
                return CanaryOutcome::Stale;
            }
            if let Some(recorded) = inputs.last_nullifier_pos {
                if recorded != pos {
                    warn!(
                        "v1.1 self-heal canary: predecessor nullifier position \
                         moved (recorded={recorded}, live={pos}); Stale"
                    );
                    return CanaryOutcome::Stale;
                }
            }
        }
    }

    if nav_open.nav != nflog.nav {
        warn!(
            "v1.1 self-heal canary: last_nav_opening does not match live NfLog NAV; Stale"
        );
        return CanaryOutcome::Stale;
    }

    CanaryOutcome::Compatible
}

/// Pure slow-canary combiner: structural must pass, then the injected
/// `verify_transition` result decides Compatible vs Stale.
///
/// `verify_ok == false` means the live circuit rejected the persisted proof
/// (or the cyclic verifier-data tail did not match). That is the property
/// the boot structural path cannot establish without a circuit build.
///
/// A test that would go red under a wrong change: flip `verify_ok` to
/// `true` while claiming Stale, or the reverse — the matrix is exhaustive.
pub fn evaluate_v11_slow_canary(
    inputs: &V11StructuralInputs<'_>,
    nflog: &V11CanaryNflogView,
    verify_ok: bool,
) -> CanaryOutcome {
    match evaluate_v11_structural_canary(inputs, nflog) {
        CanaryOutcome::Stale => CanaryOutcome::Stale,
        CanaryOutcome::NoSample => CanaryOutcome::NoSample,
        CanaryOutcome::Compatible => {
            if verify_ok {
                CanaryOutcome::Compatible
            } else {
                warn!(
                    "v1.1 self-heal slow canary: verify_transition rejected \
                     persisted ComplianceProof; Stale"
                );
                CanaryOutcome::Stale
            }
        }
    }
}

/// Boot-time structural canary over the live [`EngineAdapter`].
///
/// See module docs for the edge vs. full re-prove.
pub fn boot_canary(adapter: &EngineAdapter) -> CanaryOutcome {
    adapter.with_engine(|engine| {
        for (_owner, record) in engine.accounts() {
            if record.last_proof.is_none() {
                continue;
            }
            let inputs = V11StructuralInputs {
                last_nullifier: record.last_nullifier.as_ref(),
                last_nullifier_pos: record.last_nullifier_pos,
                last_nav_opening: record.last_nav_opening.as_ref(),
            };
            let predecessor = inputs.last_nullifier.and_then(|nf| {
                match engine.nflog().lookup(nf.public_key) {
                    LookupResult::Present { pos, r, .. } => Some((pos, r)),
                    LookupResult::Absent => None,
                }
            });
            let nflog = V11CanaryNflogView {
                nav: engine.nflog().nav(),
                predecessor,
            };
            // First proof-bearing account is decisive (legacy canary discipline).
            return evaluate_v11_structural_canary(&inputs, &nflog);
        }
        CanaryOutcome::NoSample
    })
}

/// Slow canary: structural checks + `ProverBridge::verify_transition`.
///
/// **Too expensive for default boot** (forces compliance circuit build).
/// Operator trigger: env `ZKCOINS_V11_SLOW_CANARY=1` (see main boot path)
/// or call this after an intentional warmup.
///
/// Establishes: the live `C` still **accepts** a persisted `ComplianceProof`
/// (including the cyclic verifier-data pin). Does **not** re-prove a
/// successor AccountUpdate — that remains a manual/ops procedure when
/// wall-time budgets allow (multi-minute cold prove).
pub fn slow_canary_verify_transition(adapter: &EngineAdapter) -> CanaryOutcome {
    let bridge = adapter.bridge();
    adapter.with_engine(|engine| {
        for (_owner, record) in engine.accounts() {
            let Some(proof) = record.last_proof.as_ref() else {
                continue;
            };
            let inputs = V11StructuralInputs {
                last_nullifier: record.last_nullifier.as_ref(),
                last_nullifier_pos: record.last_nullifier_pos,
                last_nav_opening: record.last_nav_opening.as_ref(),
            };
            let predecessor = inputs.last_nullifier.and_then(|nf| {
                match engine.nflog().lookup(nf.public_key) {
                    LookupResult::Present { pos, r, .. } => Some((pos, r)),
                    LookupResult::Absent => None,
                }
            });
            let nflog = V11CanaryNflogView {
                nav: engine.nflog().nav(),
                predecessor,
            };
            let verify_ok = bridge.verify_transition(proof).is_ok();
            return evaluate_v11_slow_canary(&inputs, &nflog, verify_ok);
        }
        CanaryOutcome::NoSample
    })
}

/// Whether the operator requested the slow verify canary this boot.
pub fn slow_canary_env_enabled() -> bool {
    matches!(std::env::var("ZKCOINS_V11_SLOW_CANARY"), Ok(v) if v == "1")
}

/// Build the canary closure outcome for the v1.1 heal path.
///
/// * Default: structural [`boot_canary`].
/// * `ZKCOINS_V11_SLOW_CANARY=1`: [`slow_canary_verify_transition`] instead
///   (loud about cost via log).
pub fn v11_canary_for_heal(adapter: &EngineAdapter) -> CanaryOutcome {
    if slow_canary_env_enabled() {
        info!(
            "v1.1 self-heal: ZKCOINS_V11_SLOW_CANARY=1 — running verify_transition \
             canary (compliance circuit build may take minutes on cold start)"
        );
        slow_canary_verify_transition(adapter)
    } else {
        boot_canary(adapter)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use shared::spec_v1::{digest_from_bytes, nflog_empty};

    fn nav_zero() -> Nav {
        Nav {
            size: 0,
            mth: nflog_empty(),
        }
    }

    fn nf(pk_byte: u8, r_byte: u8) -> NullifierOpening {
        NullifierOpening {
            public_key: [pk_byte; 32],
            signature_r: [r_byte; 32],
            r_prime: [0xAB; 32],
        }
    }

    fn nav_open(nav: Nav) -> NavOpening {
        NavOpening {
            nav,
            nav_rand: [0xCD; 32],
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let c = [0x11u8; 32];
        let b = [0x22u8; 32];
        let blob = encode_v11_live_digest(&c, &b);
        assert_eq!(blob.len(), V11_LIVE_DIGEST_LEN);
        assert_eq!(&blob[..4], V11_DIGEST_TAG);
        let (c2, b2) = decode_v11_live_digest(&blob).expect("decode");
        assert_eq!(c2, c);
        assert_eq!(b2, b);
    }

    #[test]
    fn decode_rejects_legacy_shaped_blob() {
        assert!(decode_v11_live_digest(b"not-a-v11-digest").is_none());
        assert!(decode_v11_live_digest(&[0u8; 32]).is_none());
        assert!(decode_v11_live_digest(&[]).is_none());
    }

    #[test]
    fn decode_rejects_wrong_tag_same_length() {
        let mut blob = encode_v11_live_digest(&[1u8; 32], &[2u8; 32]);
        blob[0] = b'X';
        assert!(decode_v11_live_digest(&blob).is_none());
    }

    #[test]
    fn encode_differs_when_either_digest_changes() {
        let base = encode_v11_live_digest(&[1u8; 32], &[2u8; 32]);
        let c_changed = encode_v11_live_digest(&[9u8; 32], &[2u8; 32]);
        let b_changed = encode_v11_live_digest(&[1u8; 32], &[9u8; 32]);
        assert_ne!(base, c_changed);
        assert_ne!(base, b_changed);
        assert_ne!(c_changed, b_changed);
    }

    #[test]
    fn structural_missing_openings_is_stale() {
        let nflog = V11CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((0, [1u8; 32])),
        };
        assert_eq!(
            evaluate_v11_structural_canary(
                &V11StructuralInputs {
                    last_nullifier: None,
                    last_nullifier_pos: None,
                    last_nav_opening: None,
                },
                &nflog
            ),
            CanaryOutcome::Stale
        );
        let nf = nf(1, 2);
        assert_eq!(
            evaluate_v11_structural_canary(
                &V11StructuralInputs {
                    last_nullifier: Some(&nf),
                    last_nullifier_pos: Some(0),
                    last_nav_opening: None,
                },
                &nflog
            ),
            CanaryOutcome::Stale
        );
    }

    #[test]
    fn structural_absent_predecessor_is_stale() {
        let nf = nf(1, 2);
        let nav = nav_open(nav_zero());
        let nflog = V11CanaryNflogView {
            nav: nav_zero(),
            predecessor: None,
        };
        assert_eq!(
            evaluate_v11_structural_canary(
                &V11StructuralInputs {
                    last_nullifier: Some(&nf),
                    last_nullifier_pos: Some(0),
                    last_nav_opening: Some(&nav),
                },
                &nflog
            ),
            CanaryOutcome::Stale
        );
    }

    #[test]
    fn structural_r_mismatch_is_stale() {
        let nf = nf(1, 2);
        let nav = nav_open(nav_zero());
        let nflog = V11CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((0, [0xFFu8; 32])),
        };
        assert_eq!(
            evaluate_v11_structural_canary(
                &V11StructuralInputs {
                    last_nullifier: Some(&nf),
                    last_nullifier_pos: Some(0),
                    last_nav_opening: Some(&nav),
                },
                &nflog
            ),
            CanaryOutcome::Stale
        );
    }

    #[test]
    fn structural_position_mismatch_is_stale() {
        let nf = nf(1, 2);
        let nav = nav_open(nav_zero());
        let nflog = V11CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((7, [2u8; 32])),
        };
        assert_eq!(
            evaluate_v11_structural_canary(
                &V11StructuralInputs {
                    last_nullifier: Some(&nf),
                    last_nullifier_pos: Some(0),
                    last_nav_opening: Some(&nav),
                },
                &nflog
            ),
            CanaryOutcome::Stale
        );
    }

    #[test]
    fn structural_nav_mismatch_is_stale() {
        let nf = nf(1, 2);
        let other = Nav {
            size: 3,
            mth: digest_from_bytes(&[0x55u8; 32]).expect("canonical limbs"),
        };
        let nav = nav_open(nav_zero());
        let nflog = V11CanaryNflogView {
            nav: other,
            predecessor: Some((0, [2u8; 32])),
        };
        assert_eq!(
            evaluate_v11_structural_canary(
                &V11StructuralInputs {
                    last_nullifier: Some(&nf),
                    last_nullifier_pos: Some(0),
                    last_nav_opening: Some(&nav),
                },
                &nflog
            ),
            CanaryOutcome::Stale
        );
    }

    #[test]
    fn structural_consistent_is_compatible() {
        let nf = nf(1, 2);
        let nav = nav_open(nav_zero());
        let nflog = V11CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((0, [2u8; 32])),
        };
        assert_eq!(
            evaluate_v11_structural_canary(
                &V11StructuralInputs {
                    last_nullifier: Some(&nf),
                    last_nullifier_pos: Some(0),
                    last_nav_opening: Some(&nav),
                },
                &nflog
            ),
            CanaryOutcome::Compatible
        );
    }

    /// Would go red if `verify_ok == false` were treated as Compatible.
    #[test]
    fn slow_canary_rejects_when_verify_fails() {
        let nf = nf(1, 2);
        let nav = nav_open(nav_zero());
        let inputs = V11StructuralInputs {
            last_nullifier: Some(&nf),
            last_nullifier_pos: Some(0),
            last_nav_opening: Some(&nav),
        };
        let nflog = V11CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((0, [2u8; 32])),
        };
        assert_eq!(
            evaluate_v11_slow_canary(&inputs, &nflog, false),
            CanaryOutcome::Stale,
            "circuit rejection must surface as Stale, not Compatible"
        );
    }

    #[test]
    fn slow_canary_accepts_when_verify_passes() {
        let nf = nf(1, 2);
        let nav = nav_open(nav_zero());
        let inputs = V11StructuralInputs {
            last_nullifier: Some(&nf),
            last_nullifier_pos: Some(0),
            last_nav_opening: Some(&nav),
        };
        let nflog = V11CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((0, [2u8; 32])),
        };
        assert_eq!(
            evaluate_v11_slow_canary(&inputs, &nflog, true),
            CanaryOutcome::Compatible
        );
    }

    #[test]
    fn slow_canary_stale_structural_short_circuits_verify() {
        // Even if verify_ok is true, missing openings stay Stale.
        let inputs = V11StructuralInputs {
            last_nullifier: None,
            last_nullifier_pos: None,
            last_nav_opening: None,
        };
        let nflog = V11CanaryNflogView {
            nav: nav_zero(),
            predecessor: None,
        };
        assert_eq!(
            evaluate_v11_slow_canary(&inputs, &nflog, true),
            CanaryOutcome::Stale
        );
    }
}
