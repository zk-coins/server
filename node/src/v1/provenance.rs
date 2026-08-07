//! Gap G9 — source provenance: integrate the v1.1 mechanism, retire the
//! legacy one on the v1.1 path.
//!
//! ## Spec derivation (normative, `spec-v1.2` / `docs/specification.md`)
//!
//! Under v1.1 a coin's provenance is **not** a recursive source-ST proof
//! verified through a side aggregator. It is established in two places:
//!
//! ### Spend / input authenticity — §2.1 clause 2(b)(c) + clause 8
//!
//! > Then, for every `input_coins[j]`:
//! > (a) `input_coins[j].recipient` equals `prev_account_state.owner` …
//! > (b) `input_coins[j]` is included in the prior **coin-history SMT** …
//! > via `input_auth[j].history_path` against the root referenced in clause 1,
//! > and the circuit **MUST** check the authenticated leaf is exactly
//! > `H'_leaf(1)` (received-and-unspent …)
//! > (c) `input_coins[j].identifier` is recomputed in-circuit as
//! > `Hc("Coin", input_auth[j].creating_prev_ash ‖ … ‖ input_auth[j].coin_index)`
//! > … The per-input witness `input_auth[]` **MUST** therefore include each
//! > input coin's `creating_prev_ash` and its `coin_index`
//!
//! > **8. Coin-history update.** The per-account coin-history SMT is updated
//! > to mark spent inputs (`1 → 2`) … Each update is a **constrained two-root
//! > transition**, proven in-circuit over a witnessed sibling path …
//!
//! Host type: [`InputAuthorization`]
//! (`creating_prev_ash`, `coin_index`, `history_proof: CoinHistProof`).
//!
//! ### Receive / admission — §2.1 clause 10
//!
//! > **10. Received-coin admission (receive path).** For every
//! > `received_coins[j]` … the circuit **MUST** check, using `received_auth[j]`:
//! > (a) **Provenance proof.** `creating_proof` verifies under the circuit's
//! > **own** verifier data (cyclic recursion …)
//! > (b) **Coin binding** … recomputed … member of
//! > `creating_proof.ProofData.output_coins_root` …
//! > (c) **Cross-account conditional-NAV binding** …
//! > (d) **Admission binding — the creating transition's on-chain nullifier** …
//!
//! Host type: [`ReceivedAuthorization`] (creating proof + inclusion +
//! creating nullifier/S2C + NAV + CoinHist non-inclusion for admission).
//! The G3 surface [`ReceivedCoinSlot`] makes every clause-10 field
//! mandatory — no `Option` around the creating proof.
//!
//! ### What the legacy stack did (retired on the v1.1 path)
//!
//! Legacy spend provenance was `InCoinSourceWitness { source_proof,
//! source_inclusion, source_cmp }` fed into the outer ST circuit via the
//! **source aggregator** (`program-plonky2::circuit::source_aggregator`).
//! That construct has **no** counterpart in the v1.1 witness: the
//! compliance circuit verifies creating proofs on the receive path and
//! CoinHist membership on the spend path. There is no 1:1 aggregator
//! successor (cutover-plan §4.3).
//!
//! ## Call sites derived from the type `InCoinSourceWitness`
//!
//! Derived by following the type definition and every function signature
//! that names it (not by grepping a free string). Complete consumer set
//! in this worktree:
//!
//! | Location | Role |
//! |---|---|
//! | `program-plonky2::circuit::main::InCoinSourceWitness` | type definition |
//! | `main::prove_*_and_sources` / `set_per_slot_source_witnesses` | legacy prove core |
//! | `main::set_aggregator_proof_witness_from_sources` → `source_aggregator` | aggregator recursion |
//! | `script-plonky2::Prover::prove_*_and_sources` | re-export surface |
//! | `node::account_node::send_coins_inner` | **only production node construction** of `Some(InCoinSourceWitness{…})` |
//! | `node::account_node::canary_recursion` | all-`None` sources for a circuit-compat probe (not a user transition) |
//! | `program-plonky2` unit tests / `recursion_shape_probe` | legacy-only tests |
//!
//! No symbol under `node::v1` names `InCoinSourceWitness`. The v1.1
//! transition surface is [`TransitionWitness`] with `input_auth` /
//! `received_auth` only — the legacy witness type is **unrepresentable**
//! there (no field, no parameter, no constructor path).
//!
//! ## Boundary (process claim is the capability)
//!
//! - [`begin_v1_send`] is the **only** public orchestration entry that
//!   stages a v1.1 spend from the node. It consults the boot-time
//!   [`ScanStackMode::V1`] claim; the mode is **not** a parameter.
//! - The raw engine sink is module-private ([`engine_begin_send`]).
//! - Legacy residual `send_coins` / `InCoinSourceWitness` prove entries
//!   are removed; there is no dual-accept path back into source-aggregator.
//!
//! Full prove/finalise of a send (Plonky2) remains the heavy engine path
//! shared with G3 (`#[ignore]` e2e). Host `begin_send` witness construction
//! and CoinHist sequential paths are the G9 unit under test. Stage 3 swaps
//! the production REST call-site onto this path.

use anyhow::{bail, ensure, Context, Result};
use shared::spec_v1::{self as host, CoinHistState};
use zkcoins_prover::prover_bridge::InputAuthorization;
#[cfg(test)]
use zkcoins_prover::prover_bridge::ReceivedAuthorization;
use zkcoins_prover::state_engine::{PendingTransition, SendRequest, StateEngine};

use super::separation::{process_stack_mode, ScanStackMode};

/// Refusal when the process claim is not v1.1 — the CoinHist provenance
/// path is not dual-accepted on the legacy stack.
pub const V1_PROVENANCE_SHADOW_OFF: &str =
    "ZKCOINS_V1_SHADOW is off — refusing v1.1 CoinHist/creating-proof provenance path \
     (legacy InCoinSourceWitness send remains the default)";

/// Gate the v1.1 provenance / send path on the **process stack claim**.
///
/// | process claim | result |
/// |---|---|
/// | `Some(V1)` | allowed |
/// | `Some(Legacy)` | refuse ([`V1_PROVENANCE_SHADOW_OFF`]) |
/// | `None` | refuse (unclaimed — no silent fall-through) |
pub fn ensure_v1_provenance_path() -> Result<()> {
    match process_stack_mode() {
        Some(ScanStackMode::V1) => Ok(()),
        Some(ScanStackMode::Legacy) => bail!(V1_PROVENANCE_SHADOW_OFF),
        None => bail!(
            "v1.1 CoinHist/creating-proof provenance requires a process that claimed \
             ScanStackMode::V1 at boot (ZKCOINS_V1_SHADOW=1). Process claim is unset — \
             refusing (no silent fall-through to InCoinSourceWitness dual-accept)"
        ),
    }
}

/// Begin a §2.3.2 send through the v1.1 [`StateEngine`].
///
/// Requires a process claim of [`ScanStackMode::V1`]. The mode is **not**
/// a parameter — callers cannot hand in `On` while the flag is off.
///
/// Provenance for each spent input is **derived** inside the engine from
/// the account's CoinHist + [`TrackedCoin`](zkcoins_prover::state_engine::TrackedCoin)
/// metadata (`creating_prev_ash`, `coin_index`) into [`InputAuthorization`].
/// There is no parameter of type `InCoinSourceWitness` and no constructor
/// that accepts one: the wrong construct is unrepresentable on this path.
///
/// After the engine returns, this entry **re-checks** every input's
/// CoinHist opening so a regression that re-introduces empty/dummy
/// history proofs fails loud at the host boundary (not only in-circuit).
pub fn begin_v1_send(engine: &StateEngine, req: SendRequest) -> Result<PendingTransition> {
    ensure_v1_provenance_path()?;
    let pending = engine_begin_send(engine, req).context("v1.1 begin_send")?;
    assert_spend_provenance_is_coinhist(&pending)
        .context("v1.1 spend provenance boundary (CoinHist / InputAuthorization)")?;
    Ok(pending)
}

/// Raw `StateEngine::begin_send` sink.
///
/// **Module-private.** Possession of a path to this function is not exposed
/// outside `provenance` — the public orchestration entry is [`begin_v1_send`],
/// which obtains the process-stack capability first and re-asserts CoinHist
/// provenance. A compile-fail UI test pins that this symbol is unreachable
/// from outside the module.
fn engine_begin_send(engine: &StateEngine, req: SendRequest) -> Result<PendingTransition> {
    engine.begin_send(req)
}

/// Host boundary: every active input carries CoinHist leaf state
/// `Admitted` (clause 2(b)) plus a non-default `creating_prev_ash` /
/// `coin_index` binding (clause 2(c)). No other provenance mechanism is
/// accepted — and none is representable on the pending witness.
///
/// Sequential clause-8 intermediate roots are checked for multi-input
/// sends: input 0 opens the prior account `coin_history_root`; later
/// inputs **must not** open that same root (they open the post-spend
/// intermediate the engine staged). Full sequential replay lives in the
/// engine unit tests; this boundary refuses a flat "all open prior root"
/// regression without re-implementing the private SMT bit layout.
fn assert_spend_provenance_is_coinhist(pending: &PendingTransition) -> Result<()> {
    let w = &pending.witness_wip;
    ensure!(
        w.input_coins.len() == w.input_auth.len(),
        "input_coins / input_auth length mismatch (v1.1 InputAuthorization is mandatory per input)"
    );
    ensure!(
        !w.input_coins.is_empty(),
        "v1.1 send requires at least one input (empty transition has no spend provenance)"
    );

    let prior_root = w.prev_account_state.coin_history_root;
    for (index, (coin, auth)) in w.input_coins.iter().zip(w.input_auth.iter()).enumerate() {
        assert_input_authorization_shape(index, coin, auth)?;
        let id = host::digest_to_bytes(&coin.identifier);
        if index == 0 {
            ensure!(
                auth.history_proof.verify(&id, prior_root),
                "input[0]: history_proof must open the prior CoinHist root (clause 2(b))"
            );
        } else {
            // After a prior sequential spend the intermediate root moved;
            // opening the original prior root would mean the engine did not
            // stage clause-8 intermediates (or reused a single path).
            ensure!(
                !auth.history_proof.verify(&id, prior_root),
                "input[{index}]: history_proof must not open the pre-transition CoinHist root \
                 (sequential clause-8 intermediates required)"
            );
        }
    }

    // Receive slots on a pure send must be empty — creating-proof provenance
    // is a separate path (clause 10 / G3). A non-empty mix would still use
    // ReceivedAuthorization, never InCoinSourceWitness; pin emptiness so a
    // "send" entry cannot smuggle a half-built receive.
    ensure!(
        w.received_coins.is_empty() && w.received_auth.is_empty(),
        "begin_v1_send stages a pure send; received_* must be empty (use begin_receive / G3)"
    );

    Ok(())
}

fn assert_input_authorization_shape(
    index: usize,
    coin: &host::Coin,
    auth: &InputAuthorization,
) -> Result<()> {
    ensure!(
        auth.history_proof.state == CoinHistState::Admitted,
        "input[{index}]: CoinHist leaf must be Admitted (H'_leaf(1)); got {:?}",
        auth.history_proof.state
    );
    // creating_prev_ash enters the coin-identifier recompute (clause 2(c)).
    // The zero digest is not a legal prior ash for a real creating transition
    // in host practice; refuse it so a hollow auth cannot pass this boundary.
    ensure!(
        auth.creating_prev_ash != host::ZERO_HASH,
        "input[{index}]: creating_prev_ash must be the prior ash of the creating transition \
         (clause 2(c)); zero digest is not accepted as provenance"
    );
    let recomputed = host::coin_identifier(
        auth.creating_prev_ash,
        &coin.recipient.0,
        coin.asset_id,
        coin.amount,
        auth.coin_index,
    );
    ensure!(
        recomputed == coin.identifier,
        "input[{index}]: coin.identifier does not recompute from creating_prev_ash ‖ \
         recipient ‖ asset_id ‖ amount ‖ coin_index (clause 2(c))"
    );
    Ok(())
}

/// Host boundary for receive provenance (clause 10): every slot must carry
/// a creating proof and CoinHist non-inclusion. Used by tests and as the
/// dual of [`assert_spend_provenance_is_coinhist`]; the G3 receive path
/// already constructs [`ReceivedAuthorization`] without a source-witness
/// seam — this pins that property by type and value.
#[cfg(test)]
pub(crate) fn assert_receive_provenance_is_creating_proof(
    received_coins: &[host::Coin],
    received_auth: &[ReceivedAuthorization],
) -> Result<()> {
    ensure!(
        received_coins.len() == received_auth.len(),
        "received_coins / received_auth length mismatch"
    );
    ensure!(
        !received_coins.is_empty(),
        "receive provenance check requires at least one slot"
    );
    for (index, (coin, auth)) in received_coins.iter().zip(received_auth.iter()).enumerate() {
        // Creating proof is a required field of ReceivedAuthorization — its
        // presence is type-level. Pin that the host also filled a usable
        // output-inclusion and a non-zero creating_prev_ash (clause 10(b)).
        let _creating_proof = &auth.creating_proof;
        ensure!(
            auth.creating_prev_ash != host::ZERO_HASH,
            "received[{index}]: creating_prev_ash must bind the creating transition \
             (clause 10(b)); zero digest is not accepted"
        );
        ensure!(
            auth.history_proof.state == CoinHistState::Absent,
            "received[{index}]: admission requires CoinHist Absent (0→1); got {:?}",
            auth.history_proof.state
        );
        let recomputed = host::coin_identifier(
            auth.creating_prev_ash,
            &coin.recipient.0,
            coin.asset_id,
            coin.amount,
            auth.output_inclusion.leaf_index,
        );
        ensure!(
            recomputed == coin.identifier,
            "received[{index}]: coin.identifier does not recompute from creating proof \
             binding (clause 10(b))"
        );
    }
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::mode::V1ShadowMode;
    use crate::v1::separation::{
        claim_process_stack_from_shadow_mode, set_process_stack_mode, ScanStackMode,
    };
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::polynomial::PolynomialCoeffs;
    use plonky2::field::types::Field;
    use plonky2::fri::proof::FriProof;
    use plonky2::hash::merkle_tree::MerkleCap;
    use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};
    use sha2::{Digest, Sha256};
    use shared::spec_v1::{
        self as host, AccountState, Address, ChainPosition, Coin, CoinHistTree, CoinTemplate, Nav,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use zkcoins_program::circuit::compliance::Network;
    use zkcoins_prover::prover_bridge::test_signing::{deterministic_secret, normalized_key};
    use zkcoins_prover::prover_bridge::{
        ComplianceProof, NavOpening, NullifierOpening, OutputInclusionProof, TransitionMode,
    };
    use zkcoins_prover::state_engine::{AccountRecord, OpSecret, ScannedNullifier, TrackedCoin};

    fn host_dummy_last_proof() -> ComplianceProof {
        ProofWithPublicInputs {
            proof: Proof {
                wires_cap: MerkleCap(vec![]),
                plonk_zs_partial_products_cap: MerkleCap(vec![]),
                quotient_polys_cap: MerkleCap(vec![]),
                openings: OpeningSet {
                    constants: vec![],
                    plonk_sigmas: vec![],
                    wires: vec![],
                    plonk_zs: vec![],
                    plonk_zs_next: vec![],
                    partial_products: vec![],
                    quotient_polys: vec![],
                    lookup_zs: vec![],
                    lookup_zs_next: vec![],
                },
                opening_proof: FriProof {
                    commit_phase_merkle_caps: vec![],
                    query_round_proofs: vec![],
                    final_poly: PolynomialCoeffs::new(vec![]),
                    pow_witness: GoldilocksField::ZERO,
                },
            },
            public_inputs: vec![],
        }
    }

    fn with_v1_process_claim<R>(f: impl FnOnce() -> R) -> R {
        // Process claim is monotonic and un-clearable outside stack-policy's
        // own cfg(test). Rely on process-per-test isolation (nextest).
        claim_process_stack_from_shadow_mode(V1ShadowMode::On);
        f()
    }

    /// Deterministic operational secret for G9 provenance fixtures (A/4').
    /// Stored on the account so `begin_send` derives `nav_rand` rather than
    /// refusing a missing secret.
    fn g9_op_secret() -> OpSecret {
        OpSecret::new(Sha256::digest(b"zkCoins/v1/g9-provenance/op_secret").into())
    }

    /// Seeded account with two Admitted coins and a folded predecessor nullifier.
    fn seeded_spendable_engine() -> (StateEngine, Address, Vec<Coin>, [u8; 32]) {
        let mut engine = StateEngine::new(Network::Testnet, 0);
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/g9-provenance/nk").into();
        let op_secret = g9_op_secret();
        let (_, _, genesis_pubkey) =
            normalized_key(deterministic_secret(b"zkCoins/v1/g9-provenance/pk0"));
        let (_, _, current_pubkey) =
            normalized_key(deterministic_secret(b"zkCoins/v1/g9-provenance/pk1"));
        let owner = Address(host::address(&genesis_pubkey, host::nk_commit(&nk)));
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &genesis_pubkey, &[0x52; 32], 2, 1);
        let creating_state = AccountState::new(
            owner,
            host::nk_commit(&nk),
            BTreeMap::new(),
            genesis_pubkey,
            0,
            host::coinhist_empty_root(),
        )
        .unwrap();
        let creating_prev_ash = host::account_state_hash(&creating_state).unwrap();
        let coins = vec![
            Coin {
                identifier: host::coin_identifier(creating_prev_ash, &owner.0, asset_id, 40, 0),
                recipient: owner,
                amount: 40,
                asset_id,
            },
            Coin {
                identifier: host::coin_identifier(creating_prev_ash, &owner.0, asset_id, 60, 1),
                recipient: owner,
                amount: 60,
                asset_id,
            },
        ];
        let mut coinhist = CoinHistTree::new();
        let mut spendable = BTreeMap::new();
        for (index, coin) in coins.iter().enumerate() {
            let id = host::digest_to_bytes(&coin.identifier);
            coinhist.admit(id).unwrap();
            spendable.insert(
                id,
                TrackedCoin {
                    coin: coin.clone(),
                    creating_prev_ash,
                    coin_index: index as u32,
                },
            );
        }
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), 100);
        let state = AccountState::new(
            owner,
            host::nk_commit(&nk),
            balances,
            current_pubkey,
            1,
            coinhist.root(),
        )
        .unwrap();

        let predecessor_position = ChainPosition {
            height: 10,
            tx_index: 0,
            vin_index: 0,
            member_index: 0,
        };
        let predecessor_entry = host::NfLogEntry {
            pk: genesis_pubkey,
            r: [0x61; 32],
        };
        engine.set_tip_height(10);
        assert_eq!(
            engine
                .append_nullifier(ScannedNullifier::from_survivor(&host::PublishedNullifier {
                    chain_pos: predecessor_position,
                    pk: predecessor_entry.pk,
                    r: predecessor_entry.r,
                },))
                .unwrap(),
            0
        );
        engine.set_tip_height(15);
        engine
            .insert_account(
                owner,
                AccountRecord {
                    state,
                    coinhist,
                    nk,
                    op_secret: Some(op_secret),
                    genesis_pubkey,
                    spendable,
                    spent_ids: BTreeSet::new(),
                    last_proof: Some(host_dummy_last_proof()),
                    last_nav_opening: Some(NavOpening {
                        nav: Nav {
                            size: 0,
                            mth: host::nflog_empty(),
                        },
                        // Prior opening: derived from the account secret at
                        // the entry send_counter of the previous transition.
                        nav_rand: op_secret.derive_nav_rand(0),
                    }),
                    last_nullifier: Some(NullifierOpening {
                        public_key: predecessor_entry.pk,
                        signature_r: predecessor_entry.r,
                        r_prime: [0; 32],
                    }),
                    last_nullifier_pos: Some(0),
                },
            )
            .unwrap();

        let (_, _, next_pubkey) =
            normalized_key(deterministic_secret(b"zkCoins/v1/g9-provenance/pk2"));
        (engine, owner, coins, next_pubkey)
    }

    /// Flag-off / unclaimed: v1.1 provenance path is refused (no dual-accept).
    #[test]
    fn begin_v1_send_refuses_when_shadow_flag_off() {
        let (engine, owner, coins, next_pubkey) = seeded_spendable_engine();
        let req = SendRequest {
            owner,
            input_coin_ids: coins.iter().map(|c| c.identifier).collect(),
            output_templates: vec![CoinTemplate {
                recipient: Address([0x71; 32]),
                amount: 100,
                asset_id: coins[0].asset_id,
            }],
            next_pubkey,
            npk_rand: [0x73; 32],
        };

        let err = begin_v1_send(&engine, req.clone())
            .expect_err("unclaimed process must refuse v1.1 send");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ZKCOINS_V1_SHADOW") || msg.contains("ScanStackMode::V1"),
            "unexpected error: {msg}"
        );

        set_process_stack_mode(ScanStackMode::Legacy);
        let err = begin_v1_send(&engine, req).expect_err("legacy claim must refuse v1.1 send");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ZKCOINS_V1_SHADOW is off"),
            "unexpected error: {msg}"
        );
    }

    /// v1.1 send establishes spend provenance through CoinHist /
    /// `InputAuthorization` (clause 2(b)(c) + sequential clause 8) — not
    /// through `InCoinSourceWitness` / the source aggregator.
    #[test]
    fn v1_send_establishes_provenance_via_coinhist_input_auth() {
        with_v1_process_claim(|| {
            let (engine, owner, coins, next_pubkey) = seeded_spendable_engine();
            let prior_root = engine
                .account(&owner)
                .expect("account")
                .state
                .coin_history_root;

            let pending = begin_v1_send(
                &engine,
                SendRequest {
                    owner,
                    input_coin_ids: coins.iter().map(|c| c.identifier).collect(),
                    output_templates: vec![CoinTemplate {
                        recipient: Address([0x71; 32]),
                        amount: 100,
                        asset_id: coins[0].asset_id,
                    }],
                    next_pubkey,
                    npk_rand: [0x73; 32],
                },
            )
            .expect("flag-on begin_v1_send must succeed");

            assert_eq!(pending.mode, TransitionMode::AccountUpdateProof);
            assert_eq!(pending.witness_wip.input_auth.len(), 2);
            assert!(pending.witness_wip.received_auth.is_empty());
            assert!(pending.witness_wip.received_coins.is_empty());

            // First input opens the prior root at Admitted; second opens the
            // post-first-spend intermediate root (sequential clause 8).
            let first_id = host::digest_to_bytes(&coins[0].identifier);
            let second_id = host::digest_to_bytes(&coins[1].identifier);
            let first = &pending.witness_wip.input_auth[0];
            let second = &pending.witness_wip.input_auth[1];
            assert_eq!(first.history_proof.state, CoinHistState::Admitted);
            assert_eq!(second.history_proof.state, CoinHistState::Admitted);
            assert!(first.history_proof.verify(&first_id, prior_root));
            assert!(!second.history_proof.verify(&second_id, prior_root));

            // creating_prev_ash + coin_index recompute the identifiers
            // (clause 2(c)) — the CoinHist path's value/owner binding.
            for (i, (coin, auth)) in pending
                .witness_wip
                .input_coins
                .iter()
                .zip(pending.witness_wip.input_auth.iter())
                .enumerate()
            {
                let recomputed = host::coin_identifier(
                    auth.creating_prev_ash,
                    &coin.recipient.0,
                    coin.asset_id,
                    coin.amount,
                    auth.coin_index,
                );
                assert_eq!(
                    recomputed, coin.identifier,
                    "input[{i}] identifier recompute"
                );
                assert_ne!(auth.creating_prev_ash, host::ZERO_HASH);
            }

            // Boundary re-check is the same function the production entry runs.
            assert_spend_provenance_is_coinhist(&pending).expect("boundary must hold");
        });
    }

    /// Receive provenance is the creating proof + CoinHist admission
    /// (clause 10) — type-level and value-level. Complements G3's
    /// `ReceivedCoinSlot` (no `Option` around creating_proof).
    #[test]
    fn v1_receive_provenance_is_creating_proof_not_source_witness() {
        let owner = Address([0xB0; 32]);
        let asset_id = host::digest_from_bytes(&[0xAA; 32]).unwrap();
        let creating_prev_ash = host::digest_from_bytes(&[0xC1; 32]).unwrap();
        let coin = Coin {
            identifier: host::coin_identifier(creating_prev_ash, &owner.0, asset_id, 7, 0),
            recipient: owner,
            amount: 7,
            asset_id,
        };
        let auth = ReceivedAuthorization {
            creating_proof: host_dummy_last_proof(),
            output_inclusion: OutputInclusionProof {
                leaf_index: 0,
                depth: 1,
                siblings: vec![host::ZERO_HASH],
            },
            creating_prev_ash,
            creating_nullifier: NullifierOpening {
                public_key: [0x11; 32],
                signature_r: [0x22; 32],
                r_prime: [0x33; 32],
            },
            creating_nav_inclusion: vec![],
            pos_create: 0,
            creating_nav_opening: NavOpening {
                nav: Nav {
                    size: 0,
                    mth: host::nflog_empty(),
                },
                nav_rand: [0; 32],
            },
            creating_nav_consistency: vec![],
            history_proof: CoinHistTree::new().prove(host::digest_to_bytes(&coin.identifier)),
        };
        assert_eq!(auth.history_proof.state, CoinHistState::Absent);
        assert_receive_provenance_is_creating_proof(&[coin], &[auth]).expect("clause-10 shape");
    }

    /// Zero `creating_prev_ash` is not accepted as spend provenance.
    #[test]
    fn spend_provenance_refuses_zero_creating_prev_ash() {
        let owner = Address([0x01; 32]);
        let asset_id = host::digest_from_bytes(&[0x02; 32]).unwrap();
        let real_ash = host::digest_from_bytes(&[0x03; 32]).unwrap();
        let coin = Coin {
            identifier: host::coin_identifier(real_ash, &owner.0, asset_id, 1, 0),
            recipient: owner,
            amount: 1,
            asset_id,
        };
        let mut tree = CoinHistTree::new();
        let id = host::digest_to_bytes(&coin.identifier);
        tree.admit(id).unwrap();
        let auth = InputAuthorization {
            creating_prev_ash: host::ZERO_HASH,
            coin_index: 0,
            history_proof: tree.prove(id),
        };
        let err = assert_input_authorization_shape(0, &coin, &auth)
            .expect_err("zero creating_prev_ash must fail");
        assert!(
            format!("{err:#}").contains("creating_prev_ash"),
            "unexpected: {err:#}"
        );
    }

    #[test]
    fn ensure_v1_provenance_path_refuses_unclaimed_and_legacy() {
        assert!(
            ensure_v1_provenance_path().is_err(),
            "unclaimed must refuse"
        );
        set_process_stack_mode(ScanStackMode::Legacy);
        assert!(ensure_v1_provenance_path().is_err(), "legacy must refuse");
    }

    #[test]
    fn ensure_v1_provenance_path_allows_v1_claim() {
        set_process_stack_mode(ScanStackMode::V1);
        assert!(ensure_v1_provenance_path().is_ok());
    }

    /// Port of legacy `test_mint_single_invoice` (send side): one recipient
    /// template with full spend of inputs stages one recipient output and
    /// no change when amounts match.
    #[test]
    fn begin_v1_send_single_recipient_template_produces_one_output() {
        with_v1_process_claim(|| {
            let (engine, owner, coins, next_pubkey) = seeded_spendable_engine();
            let total: u128 = coins.iter().map(|c| c.amount).sum();
            let pending = begin_v1_send(
                &engine,
                SendRequest {
                    owner,
                    input_coin_ids: coins.iter().map(|c| c.identifier).collect(),
                    output_templates: vec![CoinTemplate {
                        recipient: Address([0x71; 32]),
                        amount: total,
                        asset_id: coins[0].asset_id,
                    }],
                    next_pubkey,
                    npk_rand: [0x73; 32],
                },
            )
            .expect("single-recipient full spend");
            assert_eq!(pending.witness_wip.output_templates.len(), 1);
            assert_eq!(pending.witness_wip.output_coins.len(), 1);
            assert_eq!(pending.witness_wip.output_coins[0].amount, total);
        });
    }

    /// Port of legacy `test_send_coins_rejects_too_many_invoices`:
    /// more than `MAX_TX_OUTPUTS` recipient templates is refused loud.
    #[test]
    fn begin_v1_send_rejects_too_many_output_templates() {
        use zkcoins_program::circuit::compliance::MAX_TX_OUTPUTS;
        with_v1_process_claim(|| {
            let (engine, owner, coins, next_pubkey) = seeded_spendable_engine();
            let templates: Vec<CoinTemplate> = (0..(MAX_TX_OUTPUTS + 1))
                .map(|i| CoinTemplate {
                    recipient: Address([i as u8; 32]),
                    amount: 1,
                    asset_id: coins[0].asset_id,
                })
                .collect();
            let err = begin_v1_send(
                &engine,
                SendRequest {
                    owner,
                    input_coin_ids: coins.iter().map(|c| c.identifier).collect(),
                    output_templates: templates,
                    next_pubkey,
                    npk_rand: [0x73; 32],
                },
            )
            .expect_err("over MAX_TX_OUTPUTS must refuse");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("too many output templates") || msg.contains("MAX_TX_OUTPUTS"),
                "unexpected error: {msg}"
            );
        });
    }

    /// Port of legacy `test_send_coins_rejects_too_many_coins_in_queue`:
    /// more than `MAX_TX_INPUTS` spendable inputs is refused loud.
    #[test]
    fn begin_v1_send_rejects_too_many_input_coins() {
        use zkcoins_program::circuit::compliance::MAX_TX_INPUTS;
        with_v1_process_claim(|| {
            let mut engine = StateEngine::new(Network::Testnet, 0);
            let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/g9-provenance/max-in/nk").into();
            let op_secret =
                OpSecret::new(Sha256::digest(b"zkCoins/v1/g9-provenance/max-in/op").into());
            let (_, _, genesis_pubkey) =
                normalized_key(deterministic_secret(b"zkCoins/v1/g9-provenance/max-in/pk0"));
            let (_, _, current_pubkey) =
                normalized_key(deterministic_secret(b"zkCoins/v1/g9-provenance/max-in/pk1"));
            let (_, _, next_pubkey) =
                normalized_key(deterministic_secret(b"zkCoins/v1/g9-provenance/max-in/pk2"));
            let owner = Address(host::address(&genesis_pubkey, host::nk_commit(&nk)));
            let asset_id = host::asset_id_v1(host::GENESIS_TAG, &genesis_pubkey, &[0x52; 32], 2, 1);
            let creating_state = AccountState::new(
                owner,
                host::nk_commit(&nk),
                BTreeMap::new(),
                genesis_pubkey,
                0,
                host::coinhist_empty_root(),
            )
            .unwrap();
            let creating_prev_ash = host::account_state_hash(&creating_state).unwrap();
            let n = MAX_TX_INPUTS + 1;
            let mut coinhist = CoinHistTree::new();
            let mut spendable = BTreeMap::new();
            let mut total = 0u128;
            let mut input_ids = Vec::with_capacity(n);
            for i in 0..n {
                let amount = 1u128;
                let coin = Coin {
                    identifier: host::coin_identifier(
                        creating_prev_ash,
                        &owner.0,
                        asset_id,
                        amount,
                        i as u32,
                    ),
                    recipient: owner,
                    amount,
                    asset_id,
                };
                let id = host::digest_to_bytes(&coin.identifier);
                coinhist.admit(id).unwrap();
                input_ids.push(coin.identifier);
                spendable.insert(
                    id,
                    TrackedCoin {
                        coin,
                        creating_prev_ash,
                        coin_index: i as u32,
                    },
                );
                total += amount;
            }
            let mut balances = BTreeMap::new();
            balances.insert(host::digest_to_bytes(&asset_id), total);
            let state = AccountState::new(
                owner,
                host::nk_commit(&nk),
                balances,
                current_pubkey,
                1,
                coinhist.root(),
            )
            .unwrap();
            let predecessor_position = ChainPosition {
                height: 10,
                tx_index: 0,
                vin_index: 0,
                member_index: 0,
            };
            engine.set_tip_height(10);
            assert_eq!(
                engine
                    .append_nullifier(ScannedNullifier::from_survivor(&host::PublishedNullifier {
                        chain_pos: predecessor_position,
                        pk: genesis_pubkey,
                        r: [0x61; 32],
                    },))
                    .unwrap(),
                0
            );
            engine.set_tip_height(15);
            engine
                .insert_account(
                    owner,
                    AccountRecord {
                        state,
                        coinhist,
                        nk,
                        op_secret: Some(op_secret),
                        genesis_pubkey,
                        spendable,
                        spent_ids: BTreeSet::new(),
                        last_proof: Some(host_dummy_last_proof()),
                        last_nav_opening: Some(NavOpening {
                            nav: Nav {
                                size: 0,
                                mth: host::nflog_empty(),
                            },
                            nav_rand: op_secret.derive_nav_rand(0),
                        }),
                        last_nullifier: Some(NullifierOpening {
                            public_key: genesis_pubkey,
                            signature_r: [0x61; 32],
                            r_prime: [0; 32],
                        }),
                        last_nullifier_pos: Some(0),
                    },
                )
                .unwrap();

            assert_eq!(input_ids.len(), n);
            let err = begin_v1_send(
                &engine,
                SendRequest {
                    owner,
                    input_coin_ids: input_ids,
                    output_templates: vec![CoinTemplate {
                        recipient: Address([0x99; 32]),
                        amount: 1,
                        asset_id,
                    }],
                    next_pubkey,
                    npk_rand: [0x73; 32],
                },
            )
            .expect_err("over MAX_TX_INPUTS must refuse");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("too many input coins") || msg.contains("MAX_TX_INPUTS"),
                "unexpected error: {msg}"
            );
        });
    }
}
