//! Gap G7 — re-mint into existing multi-asset accounts (flag-gated).
//!
//! ## Spec (v1.2 §6.5 + §2.1 clause 3)
//!
//! - **Token standard 1** (uncapped): the creator **MAY** mint any amount at
//!   any time. A follow-up mint on an account that already has a prior
//!   transition is an `AccountUpdateProof` carrying `asset_issuance`
//!   (§2.3.1 step 4). Circuit clause 3 runs the §6.5 (a)–(d) mint checks;
//!   conservation admits `Mint(a) = amount`.
//! - **Token standard 2** (capped): mint is **genesis-only**
//!   (`send_counter == 0` and `current_pubkey == Pk₀`, §6.5 clause (f)),
//!   with `amount ≤ cap_total` (clause (e)) and explicit non-self emission
//!   (clause (g)). A re-mint into a non-genesis account is unsatisfiable.
//!
//! ## Engine vs host
//!
//! Circuit `C` enforces the mint clauses in-circuit when a proof is built.
//! [`StateEngine::begin_mint`] preflights the unsatisfiable cases by name
//! so a non-conformant request is refused before any witness is staged.
//!
//! Investigation (this block): for token standard 1 the engine already
//! builds a conformant remint witness (`AccountUpdateProof` +
//! `asset_issuance` + balance credit). No circuit change is required. Token
//! standard 2 full emission (non-owner recipient on `MintRequest`) remains
//! out of scope here — the host refuses clause (g) rather than attempting
//! an unprovable self-credit.
//!
//! ## Flag gate
//!
//! Re-mint via the v1.1 engine is available only under
//! [`V11ShadowMode::On`]. With the flag off the legacy
//! [`crate::account_node::AccountNode::prepare_mint`] refusal
//! ("Re-mint into an existing asset account is not supported") stays the
//! default and is byte-identical. There is no dual-accept.
//!
//! ## Block edge
//!
//! Full prove/finalise of a remint (Plonky2) is not exercised here — that
//! is the heavy engine path shared with G3 receive e2e (`#[ignore]`).
//! Host `begin_mint` witness construction + balance arithmetic is the
//! G7 unit under test. Stage-3 will swap the production mint call-site
//! onto this path; until then legacy `/api/mint` still uses
//! `prepare_mint` (remint refused).

use anyhow::{bail, Result};
use zkcoins_prover::state_engine::{MintRequest, PendingTransition, StateEngine};

use super::mode::V11ShadowMode;

/// Refusal when the shadow flag is off — remint is not dual-accepted on
/// the legacy stack.
pub const V11_MINT_SHADOW_OFF: &str = "ZKCOINS_V11_SHADOW is off — refusing v1.1 mint/remint path \
     (legacy prepare_mint remains the default; remint stays refused there)";

/// Gate the v1.1 mint/remint path on the shadow flag.
///
/// `On` → allowed. `Off` → refuse. No silent fall-through to legacy.
pub fn ensure_v11_mint_path(mode: V11ShadowMode) -> Result<()> {
    match mode {
        V11ShadowMode::On => Ok(()),
        V11ShadowMode::Off => bail!(V11_MINT_SHADOW_OFF),
    }
}

/// Begin a mint or re-mint through the v1.1 [`StateEngine`].
///
/// Requires [`V11ShadowMode::On`]. Delegates to
/// [`StateEngine::begin_mint`], which already admits token-standard-1
/// re-issuance into an existing multi-asset account and refuses
/// non-conformant token-standard-2 requests naming the clause.
pub fn begin_v11_mint(
    engine: &StateEngine,
    mode: V11ShadowMode,
    req: MintRequest,
) -> Result<PendingTransition> {
    ensure_v11_mint_path(mode)?;
    engine.begin_mint(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v11::mode::V11ShadowMode;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::polynomial::PolynomialCoeffs;
    use plonky2::field::types::Field;
    use plonky2::fri::proof::FriProof;
    use plonky2::hash::merkle_tree::MerkleCap;
    use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};
    use sha2::{Digest, Sha256};
    use shared::spec_v1::{
        self as host, AccountState, Address, ChainPosition, Coin, CoinHistTree, Nav,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use zkcoins_program::circuit::compliance::Network;
    use zkcoins_prover::prover_bridge::test_signing::{deterministic_secret, normalized_key};
    use zkcoins_prover::prover_bridge::{
        ComplianceProof, NavOpening, NullifierOpening, TransitionMode,
    };
    use zkcoins_prover::state_engine::{
        AccountRecord, MintRequest, ScannedNullifier, StateEngine, TrackedCoin,
    };

    /// Host-only dummy recursion proof for `AccountRecord::last_proof`.
    /// Not cryptographically valid — sufficient for `begin_mint` host
    /// construction, which only clones it into the witness (prove is out of
    /// scope for G7; no circuit build). Same shape as the receive-path
    /// host-only dummy in `receive.rs`.
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

    fn std1_request() -> MintRequest {
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/g7-remint/nk").into();
        let (_, _, current_pubkey) =
            normalized_key(deterministic_secret(b"zkCoins/v1/g7-remint/pk0"));
        let (_, _, next_pubkey) =
            normalized_key(deterministic_secret(b"zkCoins/v1/g7-remint/pk1"));
        MintRequest {
            owner: Address(host::address(&current_pubkey, host::nk_commit(&nk))),
            nk,
            current_pubkey,
            next_pubkey,
            name: b"G7 Remint Asset".to_vec(),
            decimals: 2,
            amount: 100,
            issuance_version: 1,
            cap_total: 0,
            terms_salt: [0u8; 32],
            nav_rand: [0x11; 32],
            npk_rand: [0x22; 32],
        }
    }

    /// Flag-off: v1.1 mint path is refused (no dual-accept with legacy).
    ///
    /// Complements `prepare_mint_rejects_remint_into_existing_asset_account`
    /// in `account_node_tests`: that pins the legacy refusal string; this
    /// pins that the engine remint entry is unreachable with the flag off.
    #[test]
    fn begin_v11_mint_refuses_when_shadow_flag_off() {
        let engine = StateEngine::new(Network::Testnet, 0);
        let err = begin_v11_mint(&engine, V11ShadowMode::Off, std1_request())
            .expect_err("flag off must refuse v1.1 mint");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ZKCOINS_V11_SHADOW is off"),
            "unexpected error: {msg}"
        );
    }

    /// Flag-on conformant token-standard-1 re-mint: AccountUpdateProof,
    /// `asset_issuance` present, supply = prior + amount.
    #[test]
    fn v11_std1_remint_succeeds_and_updates_supply() {
        let mut engine = StateEngine::new(Network::Testnet, 0);
        let first = std1_request();
        let nk_commit = host::nk_commit(&first.nk);
        let name_hash = host::name_hash(&first.name).expect("name_hash");
        let asset_id = host::asset_id_v1(
            host::GENESIS_TAG,
            &first.current_pubkey,
            &name_hash,
            first.decimals,
            1,
        );
        let prior_amount: u128 = 100;
        let remint_amount: u128 = 55;

        // Fold predecessor via the public scan capability (private mirrors
        // are not reachable from the node crate).
        let predecessor_pk = first.current_pubkey;
        let predecessor_r = [0x71u8; 32];
        let predecessor_pos = ChainPosition {
            height: 10,
            tx_index: 0,
            vin_index: 0,
            member_index: 0,
        };
        engine.set_tip_height(10);
        let pos = engine
            .append_nullifier(ScannedNullifier::from_survivor(
                &shared::spec_v1::PublishedNullifier {
                    chain_pos: predecessor_pos,
                    pk: predecessor_pk,
                    r: predecessor_r,
                },
            ))
            .expect("fold predecessor");
        assert_eq!(pos, 0);
        engine.set_tip_height(15);

        let empty = AccountState::new(
            first.owner,
            nk_commit,
            BTreeMap::new(),
            first.current_pubkey,
            0,
            host::coinhist_empty_root(),
        )
        .expect("empty");
        let empty_ash = host::account_state_hash(&empty).expect("ash");
        let prior_coin = Coin {
            identifier: host::coin_identifier(
                empty_ash,
                &first.owner.0,
                asset_id,
                prior_amount,
                0,
            ),
            recipient: first.owner,
            amount: prior_amount,
            asset_id,
        };
        let mut coinhist = CoinHistTree::new();
        let prior_id = host::digest_to_bytes(&prior_coin.identifier);
        coinhist.admit(prior_id).expect("admit");
        let mut spendable = BTreeMap::new();
        spendable.insert(
            prior_id,
            TrackedCoin {
                coin: prior_coin,
                creating_prev_ash: empty_ash,
                coin_index: 0,
            },
        );
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), prior_amount);
        let state = AccountState::new(
            first.owner,
            nk_commit,
            balances,
            first.next_pubkey,
            1,
            coinhist.root(),
        )
        .expect("post-mint state");
        engine
            .insert_account(
                first.owner,
                AccountRecord {
                    state,
                    coinhist,
                    nk: first.nk,
                    genesis_pubkey: first.current_pubkey,
                    spendable,
                    spent_ids: BTreeSet::new(),
                    last_proof: Some(host_dummy_last_proof()),
                    last_nav_opening: Some(NavOpening {
                        nav: Nav {
                            size: 0,
                            mth: host::nflog_empty(),
                        },
                        nav_rand: [0; 32],
                    }),
                    last_nullifier: Some(NullifierOpening {
                        public_key: predecessor_pk,
                        signature_r: predecessor_r,
                        r_prime: [0; 32],
                    }),
                    last_nullifier_pos: Some(0),
                },
            )
            .expect("insert");

        let (_, _, remint_next) =
            normalized_key(deterministic_secret(b"zkCoins/v1/g7-remint/pk2"));
        let remint = MintRequest {
            owner: first.owner,
            nk: first.nk,
            current_pubkey: first.next_pubkey,
            next_pubkey: remint_next,
            name: first.name.clone(),
            decimals: first.decimals,
            amount: remint_amount,
            issuance_version: 1,
            cap_total: 0,
            terms_salt: [0u8; 32],
            nav_rand: [0x33; 32],
            npk_rand: [0x44; 32],
        };

        let pending = begin_v11_mint(&engine, V11ShadowMode::On, remint)
            .expect("flag-on std1 remint must succeed");

        assert_eq!(pending.mode, TransitionMode::AccountUpdateProof);
        let issuance = pending
            .witness_wip
            .asset_issuance
            .as_ref()
            .expect("remint must carry asset_issuance");
        assert_eq!(issuance.amount, remint_amount);
        assert_eq!(issuance.asset_id, asset_id);
        assert_eq!(
            pending
                .witness_wip
                .new_account_state
                .balances
                .get(&host::digest_to_bytes(&asset_id))
                .copied(),
            Some(prior_amount + remint_amount),
        );
        assert_eq!(pending.witness_wip.new_account_state.send_counter, 2);
    }

    /// Token-standard-2 amount over cap: refused naming §6.5 clause (e).
    #[test]
    fn v11_std2_remint_over_cap_refused_naming_clause_e() {
        let engine = StateEngine::new(Network::Testnet, 0);
        let mut req = std1_request();
        req.issuance_version = 2;
        req.amount = 101;
        req.cap_total = 100;
        req.terms_salt = [0x44; 32];

        let err = begin_v11_mint(&engine, V11ShadowMode::On, req)
            .expect_err("over-cap v2 mint must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("amount exceeds cap_total") && msg.contains("§6.5 clause (e)"),
            "unexpected error: {msg}"
        );
    }

    /// Token-standard-2 re-issuance into a non-genesis account: refused
    /// naming §6.5 clause (f) — even when amount ≤ cap.
    ///
    /// Host preflight only: clause (f) fires before `account_transition_context`,
    /// so `last_proof` is intentionally `None` (no circuit build).
    #[test]
    fn v11_std2_remint_non_genesis_refused_naming_clause_f() {
        let mut engine = StateEngine::new(Network::Testnet, 0);
        let base = std1_request();
        let nk_commit = host::nk_commit(&base.nk);
        let state = AccountState::new(
            base.owner,
            nk_commit,
            BTreeMap::new(),
            base.next_pubkey,
            1,
            host::coinhist_empty_root(),
        )
        .expect("post-genesis");
        engine
            .insert_account(
                base.owner,
                AccountRecord {
                    state,
                    coinhist: CoinHistTree::new(),
                    nk: base.nk,
                    genesis_pubkey: base.current_pubkey,
                    spendable: BTreeMap::new(),
                    spent_ids: BTreeSet::new(),
                    last_proof: None,
                    last_nav_opening: None,
                    last_nullifier: None,
                    last_nullifier_pos: None,
                },
            )
            .expect("insert");

        let mut req = base;
        req.issuance_version = 2;
        req.current_pubkey = req.next_pubkey;
        req.amount = 50;
        req.cap_total = 100;
        req.terms_salt = [0x44; 32];

        let err = begin_v11_mint(&engine, V11ShadowMode::On, req)
            .expect_err("v2 remint must fail at genesis binding");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("non-genesis account") && msg.contains("§6.5 clause (f)"),
            "unexpected error: {msg}"
        );
        assert!(
            !msg.contains("clause (e)"),
            "must not mask clause (f) as (e): {msg}"
        );
    }
}
