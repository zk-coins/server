//! v1.1 self-heal: digest baseline for `C` / `C_balance` and the canary
//! that replaces the legacy CMP/MMR recursion probe (Cutover Gap G5).
//!
//! # What the boot check compares
//!
//! Under `ZKCOINS_V1_SHADOW=1` the **live** digest blob is the tagged
//! encoding of the circuits the node **just built** through
//! [`zkcoins_prover::prover_bridge::ProverBridge`] — not pins re-encoded
//! as themselves, and not an embedded text file that a developer must
//! remember to regenerate. See [`resolve_v1_live_digest`].
//!
//! Boot then:
//! 1. Registers the §3.6 env pins on the prover bridge.
//! 2. Forces construction of `C` and `C_balance`. At the moment each
//!    circuit finishes building, its digest is compared to the pin
//!    (§1.7.9). A mismatch **refuses** — not a warning, not a degrade.
//! 3. Uses the just-built digests as the self-heal baseline against
//!    `circuit_digest_meta` via [`crate::self_heal::heal_circuit_digest`].
//!
//! Construction is the identity check. If construction is lazy on other
//! paths, every proving entry point refuses until the pin check has
//! passed (see `ProverBridge::ensure_proving_identity`). "Cannot
//! determine the live digest" is a **refusal**, never a pass.
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
//! | Just-built `C`/`C_balance` vs §3.6 pins | first construction (boot via [`resolve_v1_live_digest`]) | circuit build | this process's real circuits match the network pins |
//! | Digest compare (just-built) vs DB | every boot after identity | O(1) | persisted state was produced under this circuit identity |
//! | Structural canary (nullifier / NAV / openings) | no digest only | O(accounts) | recursion inputs still present and consistent |
//! | [`slow_canary_verify_transition`] | operator opt-in | circuit build + verify | live `C` still **accepts** a persisted proof |
//! | Full re-prove AccountUpdate | not automated here | circuit + prove | live `C` still **produces** a successor proof |
//!
//! ## Operator recovery / slow canary
//!
//! 1. **Digest mismatch at boot** (DB vs binary embed) — node resets v1.1
//!    proof-dependent state (NfLog, accounts, pending publishes, legacy
//!    `accounts` rows) **and fails every non-terminal job** (stripping
//!    durable finalisation / cached completion so a wiped transition
//!    cannot later report `completed`), stores the live binary digest,
//!    and re-inits the in-memory engine. Operator re-funds / re-mints as
//!    for any genesis wipe.
//! 2. **Slow verify canary** — set `ZKCOINS_V1_SLOW_CANARY=1` before boot.
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
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::prover_bridge::{NavOpening, NullifierOpening, ProverBridge};

use crate::account_node::CanaryOutcome;

use super::adapter::EngineAdapter;

/// Magic prefix so a legacy bincode `HashOut` digest can never silently
/// equal a v1 pin encoding (different length and fixed tag).
///
/// Four bytes (`V1\0\0`): the historical `V11\0` tag was renamed with the
/// stack; length stays fixed so the layout remains `tag || C || C_balance`.
pub(crate) const V1_DIGEST_TAG: &[u8; 4] = b"V1\0\0";

/// Total length of [`encode_v1_live_digest`]: tag + C + C_balance.
pub(crate) const V1_LIVE_DIGEST_LEN: usize = 4 + 32 + 32;

/// Encode the live v1 self-heal baseline: `V1\0\0 || C || C_balance`.
///
/// Both digests are the §1.7.1 32-byte forms (same as
/// `ProverBridge::circuit_digest_bytes` / `balance_circuit_digest_bytes`
/// and the §3.6 boot pins). Production boot obtains these from the
/// **just-built** circuits via [`resolve_v1_live_digest`], not by
/// re-reading the pins alone or an embedded text file.
pub(crate) fn encode_v1_live_digest(c: &[u8; 32], c_balance: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(V1_LIVE_DIGEST_LEN);
    out.extend_from_slice(V1_DIGEST_TAG);
    out.extend_from_slice(c);
    out.extend_from_slice(c_balance);
    out
}

/// Resolve the live v1.1 self-heal digest from the circuits **just built**.
///
/// 1. Obtains the just-built `C` / `C_balance` digests (via
///    [`ProverBridge::require_live_identity`], after registering the §3.6
///    pins so construction refuses on mismatch).
/// 2. Cross-checks those digests against the pins again at this boundary.
/// 3. Returns [`encode_v1_live_digest`] of the **just-built** pair.
///
/// Returns `Err` when the digests cannot be determined or do not match
/// the pins. Callers **must abort boot** on `Err` — never treat either
/// case as "fine".
///
/// This is deliberately **not** `encode_v1_live_digest(pins…)` and not
/// an embedded generator artefact: only the digests of the circuits this
/// process constructed can establish §1.7.9.
///
/// # Single linear path (no production short-circuit)
///
/// The body is always `obtain_just_built → pin-check + encode(built)`.
/// A test-only override may substitute the **obtain** step with fabricated
/// digests; it never short-circuits the pin-check / encode tail and is
/// unreachable from the non-test production binary. Re-introducing
/// round-1's `return Ok(encode_v1_live_digest(pin_c, pin_c_balance))`
/// anywhere on this path turns a normal `cargo nextest` run red.
pub fn resolve_v1_live_digest(
    network: Network,
    pin_c: &[u8; 32],
    pin_c_balance: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let (built_c, built_b) = obtain_just_built_digests(network, pin_c, pin_c_balance)?;
    live_baseline_from_built_digests(&built_c, &built_b, pin_c, pin_c_balance, network)
}

/// Obtain the digests of the circuits this process just built.
///
/// Production always goes through [`ProverBridge`] (install pins, force
/// construction, return live digests). Under `cfg(test)` only, a thread-
/// local override may stand in for that build so unit tests stay cheap —
/// the override returns fabricated **built** digests; it does not encode
/// pins and does not live inside [`resolve_v1_live_digest`]'s control flow
/// as an early `Ok`.
fn obtain_just_built_digests(
    network: Network,
    pin_c: &[u8; 32],
    pin_c_balance: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), String> {
    #[cfg(test)]
    if let Some(pair) = test_built_digests_override() {
        return Ok(pair);
    }

    ProverBridge::install_network_pins(network, *pin_c, *pin_c_balance)
        .map_err(|e| e.to_string())?;
    ProverBridge::new(network)
        .require_live_identity()
        .map_err(|e| format!("cannot determine live circuit digest: {e}"))
}

/// Pin-check + encode the **built** pair (never the pins alone).
///
/// Shared tail of [`resolve_v1_live_digest`]. Encoding pins here under a
/// successful check is observationally equal today, but would green a
/// caller that never obtained built digests — so the encode arguments
/// stay the built pair.
fn live_baseline_from_built_digests(
    built_c: &[u8; 32],
    built_c_balance: &[u8; 32],
    pin_c: &[u8; 32],
    pin_c_balance: &[u8; 32],
    network: Network,
) -> Result<Vec<u8>, String> {
    zkcoins_prover::circuit_identity::require_live_digests_match_pins(
        built_c,
        built_c_balance,
        pin_c,
        pin_c_balance,
        network,
    )?;
    Ok(encode_v1_live_digest(built_c, built_c_balance))
}

#[cfg(test)]
thread_local! {
    /// Optional stand-in for ProverBridge's just-built digests.
    /// Only consulted by [`obtain_just_built_digests`] — never by an early
    /// return in [`resolve_v1_live_digest`].
    static TEST_BUILT_DIGESTS: std::cell::Cell<Option<([u8; 32], [u8; 32])>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn test_built_digests_override() -> Option<([u8; 32], [u8; 32])> {
    TEST_BUILT_DIGESTS.with(|c| c.get())
}

/// Install fabricated just-built digests for [`resolve_v1_live_digest`] tests.
///
/// Substitutes only the obtain step inside [`obtain_just_built_digests`];
/// pin-check + encode(built) still run through the production resolve path.
#[cfg(test)]
pub(crate) fn set_test_built_digests_override(built: Option<([u8; 32], [u8; 32])>) {
    TEST_BUILT_DIGESTS.with(|c| c.set(built));
}

/// Decode a blob previously produced by [`encode_v1_live_digest`].
///
/// Returns `None` when the tag or length is wrong — callers that expect a
/// v1.1 baseline must treat `None` as "not a v1.1 digest" (which a live
/// pin encoding will not match → Reset). Never invents defaults.
#[cfg(test)]
pub(crate) fn decode_v1_live_digest(blob: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if blob.len() != V1_LIVE_DIGEST_LEN {
        return None;
    }
    if &blob[..4] != V1_DIGEST_TAG.as_slice() {
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
pub(crate) struct V1StructuralInputs<'a> {
    pub last_nullifier: Option<&'a NullifierOpening>,
    pub last_nullifier_pos: Option<u64>,
    pub last_nav_opening: Option<&'a NavOpening>,
}

/// Live NfLog facts the structural canary needs (injected for pure tests).
#[derive(Clone, Debug)]
pub(crate) struct V1CanaryNflogView {
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
/// path ([`evaluate_v1_slow_canary`]).
pub(crate) fn evaluate_v1_structural_canary(
    inputs: &V1StructuralInputs<'_>,
    nflog: &V1CanaryNflogView,
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
pub(crate) fn evaluate_v1_slow_canary(
    inputs: &V1StructuralInputs<'_>,
    nflog: &V1CanaryNflogView,
    verify_ok: bool,
) -> CanaryOutcome {
    match evaluate_v1_structural_canary(inputs, nflog) {
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
pub(crate) fn boot_canary(adapter: &EngineAdapter) -> CanaryOutcome {
    adapter.with_engine(|engine| {
        for (_owner, record) in engine.accounts() {
            if record.last_proof.is_none() {
                continue;
            }
            let inputs = V1StructuralInputs {
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
            let nflog = V1CanaryNflogView {
                nav: engine.nflog().nav(),
                predecessor,
            };
            // First proof-bearing account is decisive (legacy canary discipline).
            return evaluate_v1_structural_canary(&inputs, &nflog);
        }
        CanaryOutcome::NoSample
    })
}

/// Slow canary: structural checks + `ProverBridge::verify_transition`.
///
/// **Too expensive for default boot** (forces compliance circuit build).
/// Operator trigger: env `ZKCOINS_V1_SLOW_CANARY=1` (see main boot path)
/// or call this after an intentional warmup.
///
/// Establishes: the live `C` still **accepts** a persisted `ComplianceProof`
/// (including the cyclic verifier-data pin). Does **not** re-prove a
/// successor AccountUpdate — that remains a manual/ops procedure when
/// wall-time budgets allow (multi-minute cold prove).
pub(crate) fn slow_canary_verify_transition(adapter: &EngineAdapter) -> CanaryOutcome {
    let bridge = adapter.bridge();
    adapter.with_engine(|engine| {
        for (_owner, record) in engine.accounts() {
            let Some(proof) = record.last_proof.as_ref() else {
                continue;
            };
            let inputs = V1StructuralInputs {
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
            let nflog = V1CanaryNflogView {
                nav: engine.nflog().nav(),
                predecessor,
            };
            let verify_ok = bridge.verify_transition(proof).is_ok();
            return evaluate_v1_slow_canary(&inputs, &nflog, verify_ok);
        }
        CanaryOutcome::NoSample
    })
}

/// Whether the operator requested the slow verify canary this boot.
pub(crate) fn slow_canary_env_enabled() -> bool {
    matches!(std::env::var("ZKCOINS_V1_SLOW_CANARY"), Ok(v) if v == "1")
}

/// Build the canary closure outcome for the v1.1 heal path.
///
/// * Default: structural [`boot_canary`].
/// * `ZKCOINS_V1_SLOW_CANARY=1`: [`slow_canary_verify_transition`] instead
///   (loud about cost via log).
pub fn v1_canary_for_heal(adapter: &EngineAdapter) -> CanaryOutcome {
    if slow_canary_env_enabled() {
        info!(
            "v1.1 self-heal: ZKCOINS_V1_SLOW_CANARY=1 — running verify_transition \
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
    use zkcoins_program::circuit::compliance::Network;

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
        let blob = encode_v1_live_digest(&c, &b);
        assert_eq!(blob.len(), V1_LIVE_DIGEST_LEN);
        assert_eq!(&blob[..4], V1_DIGEST_TAG);
        let (c2, b2) = decode_v1_live_digest(&blob).expect("decode");
        assert_eq!(c2, c);
        assert_eq!(b2, b);
    }

    #[test]
    fn decode_rejects_legacy_shaped_blob() {
        assert!(decode_v1_live_digest(b"not-a-v1-digest").is_none());
        assert!(decode_v1_live_digest(&[0u8; 32]).is_none());
        assert!(decode_v1_live_digest(&[]).is_none());
    }

    #[test]
    fn decode_rejects_wrong_tag_same_length() {
        let mut blob = encode_v1_live_digest(&[1u8; 32], &[2u8; 32]);
        blob[0] = b'X';
        assert!(decode_v1_live_digest(&blob).is_none());
    }

    #[test]
    fn encode_differs_when_either_digest_changes() {
        let base = encode_v1_live_digest(&[1u8; 32], &[2u8; 32]);
        let c_changed = encode_v1_live_digest(&[9u8; 32], &[2u8; 32]);
        let b_changed = encode_v1_live_digest(&[1u8; 32], &[9u8; 32]);
        assert_ne!(base, c_changed);
        assert_ne!(base, b_changed);
        assert_ne!(c_changed, b_changed);
    }

    #[test]
    fn structural_missing_openings_is_stale() {
        let nflog = V1CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((0, [1u8; 32])),
        };
        assert_eq!(
            evaluate_v1_structural_canary(
                &V1StructuralInputs {
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
            evaluate_v1_structural_canary(
                &V1StructuralInputs {
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
        let nflog = V1CanaryNflogView {
            nav: nav_zero(),
            predecessor: None,
        };
        assert_eq!(
            evaluate_v1_structural_canary(
                &V1StructuralInputs {
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
        let nflog = V1CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((0, [0xFFu8; 32])),
        };
        assert_eq!(
            evaluate_v1_structural_canary(
                &V1StructuralInputs {
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
        let nflog = V1CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((7, [2u8; 32])),
        };
        assert_eq!(
            evaluate_v1_structural_canary(
                &V1StructuralInputs {
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
        let nflog = V1CanaryNflogView {
            nav: other,
            predecessor: Some((0, [2u8; 32])),
        };
        assert_eq!(
            evaluate_v1_structural_canary(
                &V1StructuralInputs {
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
        let nflog = V1CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((0, [2u8; 32])),
        };
        assert_eq!(
            evaluate_v1_structural_canary(
                &V1StructuralInputs {
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
        let inputs = V1StructuralInputs {
            last_nullifier: Some(&nf),
            last_nullifier_pos: Some(0),
            last_nav_opening: Some(&nav),
        };
        let nflog = V1CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((0, [2u8; 32])),
        };
        assert_eq!(
            evaluate_v1_slow_canary(&inputs, &nflog, false),
            CanaryOutcome::Stale,
            "circuit rejection must surface as Stale, not Compatible"
        );
    }

    #[test]
    fn slow_canary_accepts_when_verify_passes() {
        let nf = nf(1, 2);
        let nav = nav_open(nav_zero());
        let inputs = V1StructuralInputs {
            last_nullifier: Some(&nf),
            last_nullifier_pos: Some(0),
            last_nav_opening: Some(&nav),
        };
        let nflog = V1CanaryNflogView {
            nav: nav_zero(),
            predecessor: Some((0, [2u8; 32])),
        };
        assert_eq!(
            evaluate_v1_slow_canary(&inputs, &nflog, true),
            CanaryOutcome::Compatible
        );
    }

    #[test]
    fn slow_canary_stale_structural_short_circuits_verify() {
        // Even if verify_ok is true, missing openings stay Stale.
        let inputs = V1StructuralInputs {
            last_nullifier: None,
            last_nullifier_pos: None,
            last_nav_opening: None,
        };
        let nflog = V1CanaryNflogView {
            nav: nav_zero(),
            predecessor: None,
        };
        assert_eq!(
            evaluate_v1_slow_canary(&inputs, &nflog, true),
            CanaryOutcome::Stale
        );
    }

    /// Drives the **public** [`resolve_v1_live_digest`] with fabricated
    /// just-built digests (override stands in only for
    /// [`obtain_just_built_digests`] / [`ProverBridge::require_live_identity`]).
    ///
    /// The resolve body is a single linear path: obtain → pin-check +
    /// encode(**built**). Round-1's
    /// `return Ok(encode_v1_live_digest(pin_c, pin_c_balance))` never
    /// consults built digests and would `Ok` any pin pair — this test
    /// goes **red** under that shortcut because it calls resolve itself
    /// with divergent pins (and the override no longer short-circuits
    /// past the production body).
    #[test]
    fn resolve_v1_live_digest_refuses_when_pins_differ_from_built() {
        let built_c = [0xAAu8; 32];
        let built_b = [0xBBu8; 32];
        let mut pin_c = built_c;
        pin_c[0] ^= 0xFF;
        assert_ne!(
            encode_v1_live_digest(&pin_c, &built_b),
            encode_v1_live_digest(&built_c, &built_b),
            "test oracle: pin encoding must differ from built encoding"
        );
        set_test_built_digests_override(Some((built_c, built_b)));
        let err = resolve_v1_live_digest(Network::Regtest, &pin_c, &built_b)
            .expect_err("built/pin divergence must refuse through resolve_v1_live_digest");
        set_test_built_digests_override(None);
        assert!(
            err.contains("do not match") || err.contains("Refusing"),
            "refusal must be loud via resolve_v1_live_digest: {err}"
        );
    }

    /// Happy path through [`resolve_v1_live_digest`]: when pins equal the
    /// just-built digests, the live baseline is `encode(built)`.
    #[test]
    fn resolve_v1_live_digest_returns_encoding_of_just_built_circuits() {
        let c = [0x11u8; 32];
        let b = [0x22u8; 32];
        set_test_built_digests_override(Some((c, b)));
        let live = resolve_v1_live_digest(Network::Regtest, &c, &b)
            .expect("matching pins must accept through resolve_v1_live_digest");
        set_test_built_digests_override(None);
        assert_eq!(
            live,
            encode_v1_live_digest(&c, &b),
            "live baseline must be encode(just-built)"
        );
        let (c2, b2) = decode_v1_live_digest(&live).expect("tagged blob");
        assert_eq!(c2, c);
        assert_eq!(b2, b);
    }

    /// Source guard: production code in this module must not encode pins as
    /// the live baseline. Complements the behavioural tests — a dual-path
    /// early `Ok(encode(pins))` on a production-only arm would otherwise
    /// be invisible to the override-driven tests.
    ///
    /// Scans non-comment lines of `self_heal.rs` up to the unit-test module
    /// for the exact round-1 anti-pattern.
    #[test]
    fn resolve_v1_live_digest_source_forbids_encode_pins_shortcut() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/v1/self_heal.rs");
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"));
        let prod = src
            .split("#[cfg(test)]\nmod unit_tests")
            .next()
            .expect("unit_tests module marker must exist in self_heal.rs");

        let mut code = String::new();
        for line in prod.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            // Drop trailing line comments; keep the code prefix.
            let code_part = match line.find("//") {
                Some(i) => &line[..i],
                None => line,
            };
            code.push_str(code_part);
            code.push('\n');
        }

        let forbidden = [
            "encode_v1_live_digest(pin_c, pin_c_balance)",
            "encode_v1_live_digest(&pin_c, &pin_c_balance)",
            "encode_v1_live_digest(*pin_c, *pin_c_balance)",
        ];
        for pat in forbidden {
            assert!(
                !code.contains(pat),
                "round-1 regression in production source: found `{pat}` — \
                 live baseline must be encode(just-built), never encode(pins)"
            );
        }
        assert!(
            code.contains("require_live_identity"),
            "production resolve path must obtain digests via ProverBridge::require_live_identity"
        );
        assert!(
            code.contains("live_baseline_from_built_digests"),
            "production resolve path must run the pin-check + encode(built) tail"
        );
        assert!(
            code.contains("encode_v1_live_digest(built_c, built_c_balance)"),
            "production encode must take the just-built pair, not the pins"
        );
    }

    /// Plonky2 circuit construction overflows the default test thread
    /// stack; spawn the body on a large stack.
    fn on_large_stack<F, R>(f: F) -> R
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        std::thread::Builder::new()
            .name("v1-digest-resolve".into())
            .stack_size(128 * 1024 * 1024)
            .spawn(f)
            .expect("spawn large-stack thread")
            .join()
            .expect("large-stack thread panicked")
    }

    /// Full [`ProverBridge`] wiring (no test override): real circuit build.
    /// Multi-minute; run with `--run-ignored` for end-to-end coverage of the
    /// obtain step. The ordinary run is already bound by the linear resolve
    /// path + source guard above.
    #[test]
    #[ignore = "multi-minute Plonky2 circuit build via ProverBridge"]
    fn resolve_v1_live_digest_via_real_prover_bridge_refuses_pin_mismatch() {
        on_large_stack(|| {
            // Ensure the override is off so we hit ProverBridge.
            set_test_built_digests_override(None);
            let network = Network::Testnet;
            let bridge = ProverBridge::new(network);
            let (built_c, built_b) = bridge
                .require_live_identity()
                .expect("unpinned ProverBridge build");
            let mut pin_c = built_c;
            pin_c[0] ^= 0xFF;
            let err = resolve_v1_live_digest(network, &pin_c, &built_b)
                .expect_err("real ProverBridge path must refuse pin mismatch");
            assert!(
                err.contains("do not match")
                    || err.contains("Refusing")
                    || err.contains("cannot determine")
                    || err.contains("does not match"),
                "refusal must be loud: {err}"
            );
        });
    }
}
