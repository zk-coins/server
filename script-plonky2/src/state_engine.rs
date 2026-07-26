//! In-memory zkCoins state-transition engine (P1-E.2).
//!
//! Wires host state primitives (`AccountState`, per-account `CoinHistTree`,
//! global `NfLogAccumulator`) to the P1-E.1 [`ProverBridge`] and drives the
//! §2.3 two-phase lifecycle (`request` → `awaiting_signature` → `finalise`)
//! for mint / send / receive.
//!
//! # Scope / non-scope
//!
//! - Purely in-memory: no DB, no I/O, no REST (those are P1-G).
//! - Fail-loud: every invalid state returns `Err`; checks are never skipped.
//! - **Receive path assumption:** [`StateEngine::begin_receive`] admits an
//!   already-verified received coin. The caller's node is responsible for
//!   decrypting the `CoinProof` bundle and re-verifying the creating proof /
//!   Bitcoin first-occurrence scan **before** calling `begin_receive`. Bundle
//!   decrypt and Bitcoin scan belong to P1-G.
//! - **Incoming-transition host checks:** [`StateEngine::verify_incoming_transition`]
//!   runs bridge verify + cyclic-tail pin and the canonical-NAV / `size_final`
//!   precondition (D.5 Caveat A). The Bitcoin first-occurrence anchor check for
//!   a foreign `(Pk, R)` needs the chain scanner and is **out of scope here**
//!   (P1-G).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{bail, ensure, Context, Result};
use shared::spec_v1::{
    self as host, AccountState, Address, ChainPosition, Coin, CoinHistTree, CoinTemplate,
    FoldOutcome, HashDigest, LookupResult, Nav, NfLogAccumulator, NfLogEntry, ProofData, TreeKind,
};
use zkcoins_program_plonky2::circuit::compliance::{
    Network, MAX_ACCOUNT_ASSETS, MAX_RX_COINS, MAX_TX_INPUTS, MAX_TX_OUTPUTS,
};

use crate::prover_bridge::{
    AssetIssuance, ComplianceProof, InputAuthorization, NavOpening, NullifierOpening,
    PredecessorNullifier, ProvedTransition, ProverBridge, ReceivedAuthorization, TransitionMode,
    TransitionSignature, TransitionWitness,
};

// ---------------------------------------------------------------------------
// Request types (wallet → engine)
// ---------------------------------------------------------------------------

/// §2.3.1 mint / issuance intent.
#[derive(Clone, Debug)]
pub struct MintRequest {
    pub owner: Address,
    /// Operational nullifier key (node operational bundle).
    pub nk: [u8; 32],
    /// Consumed spend key `Pkᵢ` (`Pk₀` for a genesis mint).
    pub current_pubkey: [u8; 32],
    /// Rotated spend key `Pkᵢ₊₁` folded into `new_account_state`.
    pub next_pubkey: [u8; 32],
    /// Human-readable asset name (hashed; never on-chain).
    pub name: Vec<u8>,
    pub decimals: u8,
    pub amount: u128,
    /// Token standard: `1` (default / uncapped) or `2` (capped).
    pub issuance_version: u8,
    /// Token-standard-2 supply cap; must be `0` for standard 1.
    pub cap_total: u128,
    /// Token-standard-2 terms salt; all-zero for standard 1.
    pub terms_salt: [u8; 32],
    pub nav_rand: [u8; 32],
    pub npk_rand: [u8; 32],
}

/// §2.3.2 send intent. Change outputs are computed by the engine.
#[derive(Clone, Debug)]
pub struct SendRequest {
    pub owner: Address,
    /// Identifiers of spendable coins the account owns (state-`1`).
    pub input_coin_ids: Vec<HashDigest>,
    /// Recipient output templates (before per-asset change).
    pub output_templates: Vec<CoinTemplate>,
    pub next_pubkey: [u8; 32],
    pub nav_rand: [u8; 32],
    pub npk_rand: [u8; 32],
}

/// §2.3.3 receive intent.
///
/// **Precondition (caller):** each entry of `received_coins` / `received_auth`
/// comes from a `CoinProof` the caller has already decrypted and fully
/// re-verified (creating proof + clause-10 host material). Bundle decrypt and
/// the Bitcoin first-occurrence scan are P1-G responsibilities — this engine
/// only folds the verified receipt into the account state.
#[derive(Clone, Debug)]
pub struct ReceiveRequest {
    pub owner: Address,
    /// Operational nullifier key. Required so a first receive can construct
    /// the canonical empty account for the `InitialProof` path.
    pub nk: [u8; 32],
    /// Consumed spend key `Pkᵢ` (`Pk₀` for a first-transition receive).
    pub current_pubkey: [u8; 32],
    pub received_coins: Vec<Coin>,
    pub received_auth: Vec<ReceivedAuthorization>,
    pub next_pubkey: [u8; 32],
    pub nav_rand: [u8; 32],
    pub npk_rand: [u8; 32],
}

// ---------------------------------------------------------------------------
// State model
// ---------------------------------------------------------------------------

/// Metadata needed to spend a state-`1` coin (clause-2 auth + history).
#[derive(Clone, Debug)]
pub struct TrackedCoin {
    pub coin: Coin,
    /// `prev_ash` of the transition that created this coin (clause 2 / 5).
    pub creating_prev_ash: HashDigest,
    /// Output index within the creating transition.
    pub coin_index: u32,
}

/// Per-account in-memory record.
pub struct AccountRecord {
    pub state: AccountState,
    pub coinhist: CoinHistTree,
    /// Account nullifier key (operational bundle).
    pub nk: [u8; 32],
    /// Address-bound genesis spend key `Pk₀`.
    pub genesis_pubkey: [u8; 32],
    /// Spendable (state-`1`) coins keyed by `digest_to_bytes(identifier)`.
    pub spendable: BTreeMap<[u8; 32], TrackedCoin>,
    /// Spent (state-`2`) coin ids retained so the coin-history SMT can be
    /// rebuilt without cloning `CoinHistTree`.
    pub spent_ids: BTreeSet<[u8; 32]>,
    /// Last compliance proof (required for `AccountUpdateProof`).
    pub last_proof: Option<ComplianceProof>,
    pub last_nav_opening: Option<NavOpening>,
    pub last_nullifier: Option<NullifierOpening>,
    pub last_nullifier_pos: Option<u64>,
}

/// Phase-1 output: witness ready for the wallet to sign (`awaiting_signature`).
#[derive(Clone, Debug)]
pub struct PendingTransition {
    /// Full `TransitionWitness` with a placeholder signature; `finalise`
    /// overwrites `transition_signature` before proving.
    pub witness_wip: TransitionWitness,
    pub proof_data: ProofData,
    pub proof_data_hash: [u8; 32],
    pub mode: TransitionMode,
    /// Account this transition advances.
    pub owner: Address,
    /// NAV opening used for this transition (stored on apply).
    pub nav_opening: NavOpening,
}

/// Phase-2 output after a successful prove + atomic state apply.
#[derive(Clone, Debug)]
pub struct AppliedTransition {
    pub proved: ProvedTransition,
    /// On-chain nullifier `(Pkᵢ, R)` extracted from the transition signature.
    pub nullifier: ([u8; 32], [u8; 32]),
}

/// In-memory state-transition engine.
pub struct StateEngine {
    bridge: ProverBridge,
    network: Network,
    accounts: HashMap<Address, AccountRecord>,
    activation_height: u64,
    nflog: NfLogAccumulator,
    /// Mirror of folded `NfLogEntry` values (for `size_final` NAV / inclusion
    /// / consistency proofs — the accumulator does not expose its log).
    nflog_entries: Vec<NfLogEntry>,
    /// Canonical positions parallel to `nflog_entries`. Retained so finalise
    /// can replay the accumulator transactionally before committing a fold.
    nflog_positions: Vec<ChainPosition>,
    tip_height: u64,
    /// Strictly-increasing fold ordinal at the current tip (as `tx_index`).
    fold_seq: u32,
}

struct StagedNfLog {
    accumulator: NfLogAccumulator,
    entries: Vec<NfLogEntry>,
    positions: Vec<ChainPosition>,
    fold_seq: u32,
    nullifier_pos: u64,
}

/// How the transition's own nullifier is recorded relative to the
/// **canonical** NfLog (§3.6: fold of what Bitcoin actually contains).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnNullifierCommit {
    /// Fold immediately at a synthetic local `(tip_height, fold_seq)` —
    /// used by mint/send until those paths are also deferred to the
    /// scanner. The synthetic position is **not** chain-canonical.
    SyntheticLocal,
    /// Do **not** touch the canonical NfLog. Account holds
    /// `last_nullifier = Some` / `last_nullifier_pos = None` until the
    /// scanner folds the confirmed on-chain survivor at its real
    /// `(height, tx_index, vin_index, member_index)`.
    DeferredToScanner,
}

impl StateEngine {
    /// Construct an empty engine for `network` with NfLog activation height.
    pub fn new(network: Network, activation_height: u64) -> Self {
        Self {
            bridge: ProverBridge::new(network),
            network,
            accounts: HashMap::new(),
            activation_height,
            nflog: NfLogAccumulator::new(activation_height),
            nflog_entries: Vec::new(),
            nflog_positions: Vec::new(),
            tip_height: 0,
            fold_seq: 0,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    /// Advance the Bitcoin tip used for `size_final` (scanner / tests).
    pub fn set_tip_height(&mut self, tip_height: u64) {
        self.tip_height = tip_height;
        self.fold_seq = 0;
    }

    pub fn account(&self, owner: &Address) -> Option<&AccountRecord> {
        self.accounts.get(owner)
    }

    pub fn nflog(&self) -> &NfLogAccumulator {
        &self.nflog
    }

    pub fn activation_height(&self) -> u64 {
        self.activation_height
    }

    pub fn fold_seq(&self) -> u32 {
        self.fold_seq
    }

    pub fn bridge(&self) -> &ProverBridge {
        &self.bridge
    }

    /// NfLog mirror in absolute position order: `(ChainPosition, entry)`.
    ///
    /// The sequence is the normative reconstruction input: reloading by
    /// folding these pairs in order yields a byte-identical NfLog root.
    pub fn nflog_mirror(&self) -> Vec<(ChainPosition, NfLogEntry)> {
        self.nflog_positions
            .iter()
            .copied()
            .zip(self.nflog_entries.iter().copied())
            .collect()
    }

    /// Iterate accounts currently held by the engine.
    pub fn accounts(&self) -> impl Iterator<Item = (&Address, &AccountRecord)> {
        self.accounts.iter()
    }

    /// Rebuild an engine from a complete persisted snapshot.
    ///
    /// Fails loud if:
    /// - NfLog positions are not a dense `0..n` sequence when folded,
    /// - any fold is duplicate / pre-activation,
    /// - account coinhist roots disagree with `AccountState`,
    /// - the rebuilt NfLog root disagrees with the source entries.
    ///
    /// Does **not** fall back to an empty engine on partial data.
    pub fn from_persisted(
        network: Network,
        activation_height: u64,
        tip_height: u64,
        fold_seq: u32,
        nflog: Vec<(ChainPosition, NfLogEntry)>,
        accounts: Vec<(Address, AccountRecord)>,
    ) -> Result<Self> {
        let mut engine = Self::new(network, activation_height);
        // Do not call `set_tip_height` here: it zeroes `fold_seq`.
        engine.tip_height = tip_height;
        engine.fold_seq = fold_seq;

        for (expected_pos, (chain_pos, entry)) in nflog.iter().copied().enumerate() {
            match engine
                .nflog
                .fold(chain_pos, entry.pk, entry.r)
                .context("from_persisted: NfLog fold failed")?
            {
                FoldOutcome::Appended(pos) => ensure!(
                    pos == expected_pos as u64,
                    "from_persisted: NfLog position gap or reorder at expected {expected_pos}, got {pos}"
                ),
                FoldOutcome::DuplicateIgnored => {
                    bail!("from_persisted: NfLog snapshot contains a duplicate Pk at position {expected_pos}")
                }
                FoldOutcome::BelowActivationHeight => {
                    bail!(
                        "from_persisted: NfLog snapshot entry at position {expected_pos} \
                         is below activation_height {activation_height}"
                    )
                }
            }
            engine.nflog_entries.push(entry);
            engine.nflog_positions.push(chain_pos);
        }

        ensure!(
            engine.nflog.nav().size == engine.nflog_entries.len() as u64,
            "from_persisted: NfLog size drifted from entry count"
        );
        ensure!(
            engine.nflog.nav().mth == host::nflog_mth(&engine.nflog_entries),
            "from_persisted: NfLog MTH disagrees with full-sequence recomputation"
        );

        for (owner, record) in accounts {
            engine.insert_account(owner, record)?;
        }
        Ok(engine)
    }

    /// Append a published nullifier at a known chain position (scanner / tests).
    ///
    /// Updates the live accumulator and its entry/position mirrors together.
    /// Fails loud on out-of-order positions, pre-activation folds, and
    /// first-occurrence duplicates (does not silently ignore duplicates —
    /// the scanner is expected to classify those before calling this).
    pub fn append_nullifier(
        &mut self,
        chain_pos: ChainPosition,
        pk: [u8; 32],
        r: [u8; 32],
    ) -> Result<u64> {
        let expected_pos = self.nflog_entries.len() as u64;
        match self
            .nflog
            .fold(chain_pos, pk, r)
            .context("append_nullifier: fold failed")?
        {
            FoldOutcome::Appended(pos) => {
                ensure!(
                    pos == expected_pos,
                    "append_nullifier: position mismatch expected {expected_pos}, got {pos}"
                );
                self.nflog_entries.push(NfLogEntry { pk, r });
                self.nflog_positions.push(chain_pos);
                Ok(pos)
            }
            FoldOutcome::DuplicateIgnored => {
                bail!("append_nullifier: Pk already present (first-occurrence would ignore)")
            }
            FoldOutcome::BelowActivationHeight => {
                bail!(
                    "append_nullifier: height {} is below activation_height {}",
                    chain_pos.height,
                    self.activation_height
                )
            }
        }
    }

    /// Insert a pre-built account (e.g. funded fixture for tests / recovery).
    ///
    /// Fails if `owner` is already present.
    pub fn insert_account(&mut self, owner: Address, record: AccountRecord) -> Result<()> {
        ensure!(
            record.state.owner == owner,
            "AccountRecord.owner does not match insert key"
        );
        ensure!(
            !self.accounts.contains_key(&owner),
            "account already present in the engine"
        );
        ensure!(
            record.coinhist.root() == record.state.coin_history_root,
            "coinhist root does not match AccountState.coin_history_root"
        );
        self.accounts.insert(owner, record);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // §2.3.1 Mint
    // -----------------------------------------------------------------------

    /// Phase 1 of token-standard-1 mint / issuance (§2.3.1): empty inputs,
    /// one self-output, `asset_issuance`, `nav = size_final`, six
    /// `ProofData` fields.
    ///
    /// Token-standard 2 is rejected until the request can name its mandatory
    /// explicit non-owner emission recipient. Producing the current self
    /// output would violate the frozen v2 constraints (no self-credit and no
    /// same-transition CoinHist admission), so this path fails loudly rather
    /// than constructing an unprovable witness.
    pub fn begin_mint(&self, req: MintRequest) -> Result<PendingTransition> {
        ensure!(
            matches!(req.issuance_version, 1 | 2),
            "unsupported issuance_version {}",
            req.issuance_version
        );
        if req.issuance_version == 2 {
            bail!(
                "token-standard-2 mint requires an explicit non-owner emission recipient; \
                 P1-E.2 MintRequest does not yet carry one"
            );
        }
        ensure!(req.amount > 0, "mint amount must be non-zero");
        ensure!(
            req.cap_total == 0,
            "token-standard-1 mint requires cap_total == 0"
        );
        ensure!(
            req.terms_salt == [0u8; 32],
            "token-standard-1 mint requires all-zero terms_salt"
        );

        let nk_commit = host::nk_commit(&req.nk);
        // For genesis, owner = H(Pk₀ ‖ nk_commit). For a follow-up mint the
        // address is still bound to Pk₀, not the rotated current_pubkey — the
        // request carries the durable owner identity.
        if let Some(existing) = self.accounts.get(&req.owner) {
            ensure!(existing.state.owner == req.owner, "account owner mismatch");
            ensure!(
                existing.nk == req.nk,
                "nk does not match the registered account"
            );
            ensure!(
                existing.state.current_pubkey == req.current_pubkey,
                "current_pubkey does not match the registered account"
            );
            ensure!(
                host::nk_commit(&req.nk) == existing.state.nk_commit,
                "nk does not open the registered nk_commit"
            );
        } else {
            let expected_owner = Address(host::address(&req.current_pubkey, nk_commit));
            ensure!(
                req.owner == expected_owner,
                "owner must equal H(current_pubkey ‖ nk_commit) for a genesis mint"
            );
        }

        let name_hash = host::name_hash(&req.name).context("name_hash")?;
        let creator_pubkey = match self.accounts.get(&req.owner) {
            Some(rec) => rec.genesis_pubkey,
            None => req.current_pubkey,
        };
        let asset_id = host::asset_id_v1(
            host::GENESIS_TAG,
            &creator_pubkey,
            &name_hash,
            req.decimals,
            1,
        );
        let terms_hash = host::terms_hash_v1(asset_id, 1);
        let issuance = AssetIssuance {
            asset_id,
            creator_pubkey,
            issuance_version: req.issuance_version,
            name_hash,
            decimals: req.decimals,
            amount: req.amount,
            terms_hash,
            cap_total: req.cap_total,
            terms_salt: req.terms_salt,
        };

        let (
            mode,
            prev_account_state,
            prev_proof,
            prev_nav_opening,
            predecessor_nullifier,
            nav_consistency,
            mut hist_leaves,
        ) = self.account_transition_context(&req.owner, &req.nk, req.current_pubkey)?;

        let prev_ash =
            host::account_state_hash(&prev_account_state).context("hash prev account state")?;
        let output_template = CoinTemplate {
            recipient: req.owner,
            amount: req.amount,
            asset_id,
        };
        let output_coin = Coin {
            identifier: host::coin_identifier(prev_ash, &req.owner.0, asset_id, req.amount, 0),
            recipient: req.owner,
            amount: req.amount,
            asset_id,
        };

        // History: admit self-output 0→1 (no inputs / receives).
        let output_id = host::digest_to_bytes(&output_coin.identifier);
        let output_history = {
            let hist = rebuild_coinhist(&hist_leaves)?;
            hist.non_inclusion(output_id)
                .context("self-output coin_id already present in coinhist")?
        };
        hist_leaves.insert(output_id, host::CoinHistState::Admitted);
        let new_hist = rebuild_coinhist(&hist_leaves)?;
        let new_root = new_hist.root();

        let mut new_balances = prev_account_state.balances.clone();
        credit_balance(&mut new_balances, asset_id, req.amount)?;
        let new_send = prev_account_state
            .send_counter
            .checked_add(1)
            .context("send_counter overflow")?;
        let new_account_state = AccountState::new(
            req.owner,
            prev_account_state.nk_commit,
            new_balances,
            req.next_pubkey,
            new_send,
            new_root,
        )
        .context("construct new AccountState after mint")?;

        let nav = self.size_final_nav()?;
        let nav_opening = NavOpening {
            nav,
            nav_rand: req.nav_rand,
        };
        let proof_data = compute_proof_data(
            &new_account_state,
            &[output_coin.clone()],
            &[],
            &req.nk,
            nav,
            &req.nav_rand,
            &req.next_pubkey,
            &req.npk_rand,
        )?;
        let proof_data_hash = host::hash_proof_data(&host::serialize_proof_data(&proof_data));

        let witness_wip = TransitionWitness {
            mode,
            prev_account_state,
            new_account_state,
            input_coins: Vec::new(),
            input_auth: Vec::new(),
            output_templates: vec![output_template],
            output_coins: vec![output_coin],
            output_history_proofs: vec![Some(output_history)],
            received_coins: Vec::new(),
            received_auth: Vec::new(),
            asset_issuance: Some(issuance),
            nk: req.nk,
            nav,
            nav_rand: req.nav_rand,
            prev_nav_opening,
            nav_consistency,
            next_pubkey: req.next_pubkey,
            npk_rand: req.npk_rand,
            transition_signature: placeholder_signature(req.current_pubkey),
            prev_proof,
            predecessor_nullifier,
        };

        Ok(PendingTransition {
            witness_wip,
            proof_data,
            proof_data_hash,
            mode,
            owner: req.owner,
            nav_opening,
        })
    }

    // -----------------------------------------------------------------------
    // §2.3.2 Send
    // -----------------------------------------------------------------------

    /// Phase 1 of send (§2.3.2): spend inputs, derive nullifiers, add
    /// per-asset change so `In(a)+Mint(a) == Out(a)`, `nav = size_final`.
    pub fn begin_send(&self, req: SendRequest) -> Result<PendingTransition> {
        let record = self
            .accounts
            .get(&req.owner)
            .context("send: account not found")?;
        ensure!(record.state.owner == req.owner, "account owner mismatch");
        ensure!(
            !req.input_coin_ids.is_empty(),
            "send requires at least one input coin"
        );
        ensure!(
            req.input_coin_ids.len() <= MAX_TX_INPUTS,
            "too many input coins: {} > {}",
            req.input_coin_ids.len(),
            MAX_TX_INPUTS
        );
        ensure!(
            req.output_templates.len() <= MAX_TX_OUTPUTS,
            "too many output templates: {} > {}",
            req.output_templates.len(),
            MAX_TX_OUTPUTS
        );

        // Resolve inputs and enforce conservation *before* any proving material
        // or predecessor wiring, so over-spend fails fast and loud.
        let mut input_coins = Vec::with_capacity(req.input_coin_ids.len());
        let mut in_by_asset: BTreeMap<[u8; 32], u128> = BTreeMap::new();
        let mut seen_inputs = BTreeSet::new();
        for coin_id in &req.input_coin_ids {
            let id_bytes = host::digest_to_bytes(coin_id);
            ensure!(seen_inputs.insert(id_bytes), "duplicate input coin_id");
            let tracked = record
                .spendable
                .get(&id_bytes)
                .context("input coin is not spendable on this account")?;
            ensure!(
                tracked.coin.identifier == *coin_id,
                "tracked coin identifier mismatch"
            );
            ensure!(
                tracked.coin.recipient == req.owner,
                "input coin recipient is not the spending account"
            );
            let asset_key = host::digest_to_bytes(&tracked.coin.asset_id);
            let entry = in_by_asset.entry(asset_key).or_insert(0);
            *entry = entry
                .checked_add(tracked.coin.amount)
                .context("In(a) amount overflow")?;
            input_coins.push(tracked.clone());
        }

        let mut out_by_asset: BTreeMap<[u8; 32], u128> = BTreeMap::new();
        for template in &req.output_templates {
            ensure!(
                template.amount > 0,
                "output template amount must be non-zero"
            );
            let asset_key = host::digest_to_bytes(&template.asset_id);
            let entry = out_by_asset.entry(asset_key).or_insert(0);
            *entry = entry
                .checked_add(template.amount)
                .context("Out(a) amount overflow")?;
        }

        // Per-asset change: amount = In(a) − Out(a) (no mint on send).
        let mut change_templates: Vec<CoinTemplate> = Vec::new();
        let all_assets: BTreeSet<[u8; 32]> = in_by_asset
            .keys()
            .chain(out_by_asset.keys())
            .copied()
            .collect();
        for asset_key in all_assets {
            let inn = match in_by_asset.get(&asset_key) {
                Some(&v) => v,
                None => 0,
            };
            let out = match out_by_asset.get(&asset_key) {
                Some(&v) => v,
                None => 0,
            };
            ensure!(
                inn >= out,
                "over-spend: outputs exceed inputs for an asset (In={inn}, Out={out})"
            );
            let change = inn - out;
            if change > 0 {
                let asset_id = host::digest_from_bytes(&asset_key)
                    .context("reconstruct asset_id from balance key")?;
                change_templates.push(CoinTemplate {
                    recipient: req.owner,
                    amount: change,
                    asset_id,
                });
            }
        }
        // Canonical order: caller recipient templates, then change by
        // ascending asset_id (change_templates already sorted via BTreeSet).
        let mut all_templates = req.output_templates.clone();
        all_templates.extend(change_templates);
        ensure!(
            all_templates.len() <= MAX_TX_OUTPUTS,
            "outputs including change exceed MAX_TX_OUTPUTS: {} > {}",
            all_templates.len(),
            MAX_TX_OUTPUTS
        );

        let (
            mode,
            prev_account_state,
            prev_proof,
            prev_nav_opening,
            predecessor_nullifier,
            nav_consistency,
            mut hist_leaves,
        ) = self.account_transition_context(&req.owner, &record.nk, record.state.current_pubkey)?;
        ensure!(
            matches!(mode, TransitionMode::AccountUpdateProof),
            "send requires a prior account transition (AccountUpdateProof)"
        );

        // Clause 8 consumes active history paths sequentially. Generate each
        // 1→2 opening against the current intermediate root, then apply the
        // spend immediately before constructing the next input's path.
        let mut hist_for_proofs = rebuild_coinhist(&hist_leaves)?;
        let mut input_auth = Vec::with_capacity(input_coins.len());
        let mut resolved_inputs = Vec::with_capacity(input_coins.len());
        for tracked in &input_coins {
            let id_bytes = host::digest_to_bytes(&tracked.coin.identifier);
            let history_proof = hist_for_proofs.prove(id_bytes);
            ensure!(
                history_proof.state == host::CoinHistState::Admitted,
                "input coin is not Admitted in coinhist"
            );
            ensure!(
                history_proof.verify(&id_bytes, hist_for_proofs.root()),
                "input history proof does not open the current sequential coin-history root"
            );
            input_auth.push(InputAuthorization {
                creating_prev_ash: tracked.creating_prev_ash,
                coin_index: tracked.coin_index,
                history_proof,
            });
            resolved_inputs.push(tracked.coin.clone());
            hist_for_proofs
                .spend(id_bytes)
                .context("apply sequential input spend to temporary coinhist")?;
            hist_leaves.insert(id_bytes, host::CoinHistState::Spent);
        }
        let input_coins = resolved_inputs;

        let prev_ash =
            host::account_state_hash(&prev_account_state).context("hash prev account state")?;
        let mut output_coins = Vec::with_capacity(all_templates.len());
        let mut output_history_proofs = Vec::with_capacity(all_templates.len());

        // Continue from the post-spend intermediate tree for self-output
        // admissions, matching the circuit's input → output slot order.
        for (index, template) in all_templates.iter().enumerate() {
            let coin = Coin {
                identifier: host::coin_identifier(
                    prev_ash,
                    &template.recipient.0,
                    template.asset_id,
                    template.amount,
                    index as u32,
                ),
                recipient: template.recipient,
                amount: template.amount,
                asset_id: template.asset_id,
            };
            let is_self = template.recipient == req.owner;
            if is_self {
                let id = host::digest_to_bytes(&coin.identifier);
                let proof = hist_for_proofs
                    .non_inclusion(id)
                    .context("self-output coin_id already present")?;
                ensure!(
                    proof.verify(&id, hist_for_proofs.root()),
                    "self-output history proof does not open the current sequential root"
                );
                output_history_proofs.push(Some(proof));
                hist_for_proofs
                    .admit(id)
                    .context("apply sequential self-output admission to temporary coinhist")?;
                hist_leaves.insert(id, host::CoinHistState::Admitted);
            } else {
                output_history_proofs.push(None);
            }
            output_coins.push(coin);
        }

        let new_hist = rebuild_coinhist(&hist_leaves)?;
        ensure!(
            hist_for_proofs.root() == new_hist.root(),
            "temporary sequential coinhist diverges from rebuilt final tree"
        );
        let new_root = new_hist.root();

        // balances: prev − In + Self (change / self-retained).
        let mut new_balances = prev_account_state.balances.clone();
        for coin in &input_coins {
            debit_balance(&mut new_balances, coin.asset_id, coin.amount)?;
        }
        for (template, coin) in all_templates.iter().zip(&output_coins) {
            if template.recipient == req.owner {
                credit_balance(&mut new_balances, coin.asset_id, coin.amount)?;
            }
        }
        let new_send = prev_account_state
            .send_counter
            .checked_add(1)
            .context("send_counter overflow")?;
        let new_account_state = AccountState::new(
            req.owner,
            prev_account_state.nk_commit,
            new_balances,
            req.next_pubkey,
            new_send,
            new_root,
        )
        .context("construct new AccountState after send")?;

        let nav = self.size_final_nav()?;
        let nav_opening = NavOpening {
            nav,
            nav_rand: req.nav_rand,
        };
        let proof_data = compute_proof_data(
            &new_account_state,
            &output_coins,
            &input_coins,
            &record.nk,
            nav,
            &req.nav_rand,
            &req.next_pubkey,
            &req.npk_rand,
        )?;
        let proof_data_hash = host::hash_proof_data(&host::serialize_proof_data(&proof_data));

        let witness_wip = TransitionWitness {
            mode,
            prev_account_state,
            new_account_state,
            input_coins,
            input_auth,
            output_templates: all_templates,
            output_coins,
            output_history_proofs,
            received_coins: Vec::new(),
            received_auth: Vec::new(),
            asset_issuance: None,
            nk: record.nk,
            nav,
            nav_rand: req.nav_rand,
            prev_nav_opening,
            nav_consistency,
            next_pubkey: req.next_pubkey,
            npk_rand: req.npk_rand,
            transition_signature: placeholder_signature(record.state.current_pubkey),
            prev_proof,
            predecessor_nullifier,
        };

        Ok(PendingTransition {
            witness_wip,
            proof_data,
            proof_data_hash,
            mode,
            owner: req.owner,
            nav_opening,
        })
    }

    // -----------------------------------------------------------------------
    // §2.3.3 Receive
    // -----------------------------------------------------------------------

    /// Phase 1 of receive (§2.3.3): admit already-verified received coins,
    /// clause-10 auth from the request, `nav = size_final`.
    ///
    /// See module docs for the pre-verified `CoinProof` assumption (P1-G).
    pub fn begin_receive(&self, req: ReceiveRequest) -> Result<PendingTransition> {
        ensure!(
            req.received_coins.len() == req.received_auth.len(),
            "received_coins / received_auth length mismatch"
        );
        ensure!(
            !req.received_coins.is_empty(),
            "receive requires at least one received coin"
        );
        ensure!(
            req.received_coins.len() <= MAX_RX_COINS,
            "too many received coins: {} > {}",
            req.received_coins.len(),
            MAX_RX_COINS
        );

        if let Some(record) = self.accounts.get(&req.owner) {
            ensure!(
                req.nk == record.nk,
                "receive: nk does not match the registered account"
            );
            ensure!(
                req.current_pubkey == record.state.current_pubkey,
                "receive: current_pubkey does not match the registered account"
            );
        } else {
            let expected_owner =
                Address(host::address(&req.current_pubkey, host::nk_commit(&req.nk)));
            ensure!(
                req.owner == expected_owner,
                "receive: owner must equal H(current_pubkey ‖ nk_commit) for an InitialProof"
            );
        }

        let (
            mode,
            prev_account_state,
            prev_proof,
            prev_nav_opening,
            predecessor_nullifier,
            nav_consistency,
            mut hist_leaves,
        ) = self.account_transition_context(&req.owner, &req.nk, req.current_pubkey)?;

        for coin in &req.received_coins {
            ensure!(
                coin.recipient == req.owner,
                "received coin recipient is not the receiving account"
            );
            ensure!(coin.amount > 0, "received coin amount must be non-zero");
        }

        // Clause 8 consumes active receipt paths sequentially. Generate each
        // 0→1 opening against the current intermediate root and admit it
        // before constructing the next receipt's path.
        let mut hist_for_proofs = rebuild_coinhist(&hist_leaves)?;
        let mut auth_with_history = Vec::with_capacity(req.received_auth.len());
        for (coin, mut auth) in req.received_coins.iter().zip(req.received_auth.into_iter()) {
            let id = host::digest_to_bytes(&coin.identifier);
            let proof = hist_for_proofs
                .non_inclusion(id)
                .context("received coin_id already present in coinhist")?;
            ensure!(
                proof.verify(&id, hist_for_proofs.root()),
                "received history proof does not open the current sequential coin-history root"
            );
            auth.history_proof = proof;
            auth_with_history.push(auth);
            hist_for_proofs
                .admit(id)
                .context("apply sequential receipt admission to temporary coinhist")?;
            hist_leaves.insert(id, host::CoinHistState::Admitted);
        }

        let new_hist = rebuild_coinhist(&hist_leaves)?;
        ensure!(
            hist_for_proofs.root() == new_hist.root(),
            "temporary sequential receive coinhist diverges from rebuilt final tree"
        );
        let new_root = new_hist.root();
        let mut new_balances = prev_account_state.balances.clone();
        for coin in &req.received_coins {
            credit_balance(&mut new_balances, coin.asset_id, coin.amount)?;
        }
        let new_send = prev_account_state
            .send_counter
            .checked_add(1)
            .context("send_counter overflow")?;
        let new_account_state = AccountState::new(
            req.owner,
            prev_account_state.nk_commit,
            new_balances,
            req.next_pubkey,
            new_send,
            new_root,
        )
        .context("construct new AccountState after receive")?;

        let nav = self.size_final_nav()?;
        let nav_opening = NavOpening {
            nav,
            nav_rand: req.nav_rand,
        };
        let proof_data = compute_proof_data(
            &new_account_state,
            &[],
            &[],
            &req.nk,
            nav,
            &req.nav_rand,
            &req.next_pubkey,
            &req.npk_rand,
        )?;
        let proof_data_hash = host::hash_proof_data(&host::serialize_proof_data(&proof_data));

        let witness_wip = TransitionWitness {
            mode,
            prev_account_state,
            new_account_state,
            input_coins: Vec::new(),
            input_auth: Vec::new(),
            output_templates: Vec::new(),
            output_coins: Vec::new(),
            output_history_proofs: Vec::new(),
            received_coins: req.received_coins,
            received_auth: auth_with_history,
            asset_issuance: None,
            nk: req.nk,
            nav,
            nav_rand: req.nav_rand,
            prev_nav_opening,
            nav_consistency,
            next_pubkey: req.next_pubkey,
            npk_rand: req.npk_rand,
            transition_signature: placeholder_signature(req.current_pubkey),
            prev_proof,
            predecessor_nullifier,
        };

        Ok(PendingTransition {
            witness_wip,
            proof_data,
            proof_data_hash,
            mode,
            owner: req.owner,
            nav_opening,
        })
    }

    // -----------------------------------------------------------------------
    // Phase 2: finalise
    // -----------------------------------------------------------------------

    /// Phase 2: install the wallet signature, prove via the bridge, then
    /// **atomically** apply the new account state / CoinHist / NfLog fold.
    /// On proving failure the engine state is left unchanged.
    ///
    /// Folds the own nullifier at a synthetic local position (mint/send path).
    /// Prefer [`Self::finalise_pending_chain_nullifier`] for receives so the
    /// canonical NfLog stays a pure function of Bitcoin.
    pub fn finalise(
        &mut self,
        pending: PendingTransition,
        signature: TransitionSignature,
    ) -> Result<AppliedTransition> {
        self.finalise_with_own_nullifier(pending, signature, OwnNullifierCommit::SyntheticLocal)
    }

    /// Prove + apply account/CoinHist **without** folding the own nullifier
    /// into the canonical NfLog.
    ///
    /// The receive path must use this: a published-but-unconfirmed nullifier
    /// is not part of the log defined by §3.6. The scanner folds it at the
    /// real chain position when it appears on Bitcoin. Until then the
    /// account records the nullifier opening with `last_nullifier_pos = None`
    /// (explicitly pending inclusion — not an accumulator entry).
    pub fn finalise_pending_chain_nullifier(
        &mut self,
        pending: PendingTransition,
        signature: TransitionSignature,
    ) -> Result<AppliedTransition> {
        self.finalise_with_own_nullifier(pending, signature, OwnNullifierCommit::DeferredToScanner)
    }

    fn finalise_with_own_nullifier(
        &mut self,
        mut pending: PendingTransition,
        signature: TransitionSignature,
        own_nullifier: OwnNullifierCommit,
    ) -> Result<AppliedTransition> {
        // Bind the mutable phase-1 envelope back to the witness before any
        // expensive proving or state staging.
        self.validate_pending_envelope(&pending)?;
        ensure!(
            signature.pk_i == pending.witness_wip.prev_account_state.current_pubkey,
            "signature pk_i does not equal prev_account_state.current_pubkey"
        );
        ensure!(
            pending.proof_data_hash
                == host::hash_proof_data(&host::serialize_proof_data(&pending.proof_data)),
            "pending proof_data_hash does not match proof_data"
        );

        pending.witness_wip.transition_signature = signature;
        let witness = pending.witness_wip;

        // Prove first — no state mutation yet.
        let proved = self
            .bridge
            .prove_transition(&witness)
            .context("finalise: prove_transition failed (state unchanged)")?;
        ensure!(
            proved.proof_data == pending.proof_data,
            "proved ProofData differs from pending ProofData"
        );

        let pk_i = witness.transition_signature.pk_i;
        let r = witness.transition_signature.signature_r();
        let nullifier_opening = NullifierOpening {
            public_key: pk_i,
            signature_r: r,
            r_prime: witness.transition_signature.r_prime,
        };

        // Apply atomically: if anything below fails after prove, we still
        // return Err — callers must not observe partial account/Nflog state.
        // Build the post-state, then swap in one go.
        let prev_ash = host::account_state_hash(&witness.prev_account_state)
            .context("hash prev account state for apply")?;

        let mut next_spendable: BTreeMap<[u8; 32], TrackedCoin>;
        let mut next_spent: BTreeSet<[u8; 32]>;
        let next_hist: CoinHistTree;
        let genesis_pubkey: [u8; 32];
        let nk = witness.nk;

        if let Some(existing) = self.accounts.get(&pending.owner) {
            next_spendable = existing.spendable.clone();
            next_spent = existing.spent_ids.clone();
            genesis_pubkey = existing.genesis_pubkey;
            // Start from a rebuilt tree so we re-validate the clause-8 path.
            let mut leaves = leaves_from_sets(&next_spendable, &next_spent);
            for coin in &witness.input_coins {
                let id = host::digest_to_bytes(&coin.identifier);
                ensure!(
                    next_spendable.remove(&id).is_some(),
                    "apply: spent input missing from spendable set"
                );
                ensure!(
                    leaves.get(&id) == Some(&host::CoinHistState::Admitted),
                    "apply: input not Admitted"
                );
                leaves.insert(id, host::CoinHistState::Spent);
                next_spent.insert(id);
            }
            for (index, (template, coin)) in witness
                .output_templates
                .iter()
                .zip(&witness.output_coins)
                .enumerate()
            {
                if template.recipient == pending.owner {
                    let id = host::digest_to_bytes(&coin.identifier);
                    ensure!(
                        !leaves.contains_key(&id),
                        "apply: self-output already in coinhist"
                    );
                    leaves.insert(id, host::CoinHistState::Admitted);
                    next_spendable.insert(
                        id,
                        TrackedCoin {
                            coin: coin.clone(),
                            creating_prev_ash: prev_ash,
                            coin_index: index as u32,
                        },
                    );
                }
            }
            for (index, coin) in witness.received_coins.iter().enumerate() {
                let id = host::digest_to_bytes(&coin.identifier);
                ensure!(
                    !leaves.contains_key(&id),
                    "apply: received coin already in coinhist"
                );
                leaves.insert(id, host::CoinHistState::Admitted);
                // Received coins use creating_prev_ash from auth when present.
                let creating_prev_ash = witness
                    .received_auth
                    .get(index)
                    .map(|a| a.creating_prev_ash)
                    .context("apply: missing received_auth for received coin")?;
                let coin_index = witness
                    .received_auth
                    .get(index)
                    .map(|a| a.output_inclusion.leaf_index)
                    .context("apply: missing output_inclusion for received coin")?;
                next_spendable.insert(
                    id,
                    TrackedCoin {
                        coin: coin.clone(),
                        creating_prev_ash,
                        coin_index,
                    },
                );
            }
            next_hist = rebuild_coinhist(&leaves)?;
        } else {
            // First transition: genesis mint or InitialProof receive.
            ensure!(
                matches!(pending.mode, TransitionMode::InitialProof),
                "missing account requires InitialProof mode"
            );
            ensure!(
                witness.input_coins.is_empty(),
                "InitialProof transition cannot spend inputs"
            );
            genesis_pubkey = witness.prev_account_state.current_pubkey;
            next_spendable = BTreeMap::new();
            next_spent = BTreeSet::new();
            let mut leaves = BTreeMap::new();
            for (index, (template, coin)) in witness
                .output_templates
                .iter()
                .zip(&witness.output_coins)
                .enumerate()
            {
                if template.recipient == pending.owner {
                    let id = host::digest_to_bytes(&coin.identifier);
                    leaves.insert(id, host::CoinHistState::Admitted);
                    next_spendable.insert(
                        id,
                        TrackedCoin {
                            coin: coin.clone(),
                            creating_prev_ash: prev_ash,
                            coin_index: index as u32,
                        },
                    );
                }
            }
            for (index, coin) in witness.received_coins.iter().enumerate() {
                let id = host::digest_to_bytes(&coin.identifier);
                ensure!(
                    !leaves.contains_key(&id),
                    "apply: received coin already in initial coinhist"
                );
                leaves.insert(id, host::CoinHistState::Admitted);
                let auth = witness
                    .received_auth
                    .get(index)
                    .context("apply: missing received_auth for initial received coin")?;
                next_spendable.insert(
                    id,
                    TrackedCoin {
                        coin: coin.clone(),
                        creating_prev_ash: auth.creating_prev_ash,
                        coin_index: auth.output_inclusion.leaf_index,
                    },
                );
            }
            next_hist = rebuild_coinhist(&leaves)?;
        }

        ensure!(
            next_hist.root() == witness.new_account_state.coin_history_root,
            "apply: coinhist root diverges from new_account_state"
        );

        // Own-nullifier commit: either stage a synthetic local fold (mint/send)
        // or leave the canonical NfLog untouched (receive → scanner).
        let (nullifier_pos, staged_fold) = match own_nullifier {
            OwnNullifierCommit::SyntheticLocal => {
                // Stage the complete accumulator and all of its engine-owned
                // mirrors. NfLogAccumulator::fold advances its private ordering
                // cursor even for DuplicateIgnored, so the live accumulator
                // must never be the object used for a fallible candidate fold.
                let staged = self.stage_nflog_append(pk_i, r)?;
                (Some(staged.nullifier_pos), Some(staged))
            }
            OwnNullifierCommit::DeferredToScanner => {
                // Refuse to invent a position. Caller must not observe this
                // nullifier in the accumulator until scan-fold.
                ensure!(
                    matches!(self.nflog.lookup(pk_i), LookupResult::Absent),
                    "apply: deferred nullifier Pk already present on canonical NfLog \
                     (double-spend / republish)"
                );
                (None, None)
            }
        };

        // All fallible checks are complete. Commit the account record and,
        // when synthetic, the staged NfLog state as one non-fallible section.
        let record = AccountRecord {
            state: witness.new_account_state.clone(),
            coinhist: next_hist,
            nk,
            genesis_pubkey,
            spendable: next_spendable,
            spent_ids: next_spent,
            last_proof: Some(proved.proof.clone()),
            last_nav_opening: Some(pending.nav_opening),
            last_nullifier: Some(nullifier_opening),
            last_nullifier_pos: nullifier_pos,
        };
        if let Some(staged) = staged_fold {
            self.nflog = staged.accumulator;
            self.nflog_entries = staged.entries;
            self.nflog_positions = staged.positions;
            self.fold_seq = staged.fold_seq;
        }
        self.accounts.insert(pending.owner, record);

        Ok(AppliedTransition {
            proved,
            nullifier: (pk_i, r),
        })
    }

    // -----------------------------------------------------------------------
    // Host acceptance (D.5 Caveat A)
    // -----------------------------------------------------------------------

    /// Node-side acceptance for an incoming proved transition:
    /// 1. bridge `verify_transition` (Plonky2 verify + cyclic-tail pin);
    /// 2. open `proof_data.nav_commitment` with `nav_opening`;
    /// 3. require the opened `(size, mth)` is **canonical** on this engine's
    ///    NfLog and `size ≤ size_final(tip_height)`.
    ///
    /// The Bitcoin first-occurrence anchor check for the transition's own
    /// `(Pkᵢ, R)` (or a creating nullifier) requires the scanner and is
    /// deferred to P1-G.
    pub fn verify_incoming_transition(
        &self,
        proved: &ProvedTransition,
        nav_opening: &NavOpening,
    ) -> Result<()> {
        let extracted_proof_data = self
            .bridge
            .verify_proved_transition_wrapper(proved)
            .context("incoming transition: wrapper/public-input mismatch")?;
        self.bridge
            .verify_transition(&proved.proof)
            .context("incoming transition: bridge verify failed")?;

        let expected_commit = host::nav_commitment(nav_opening.nav.root(), &nav_opening.nav_rand);
        ensure!(
            expected_commit == extracted_proof_data.nav_commitment,
            "incoming transition: nav_opening does not open proof_data.nav_commitment"
        );

        let size = nav_opening.nav.size;
        let mth = nav_opening.nav.mth;
        ensure!(
            self.nflog.is_canonical(size, mth),
            "incoming transition: nav (size, mth) is not canonical on this NfLog"
        );
        let size_final = self.nflog.size_final(self.tip_height);
        ensure!(
            size <= size_final,
            "incoming transition: nav.size {size} exceeds size_final {size_final}"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn validate_pending_envelope(&self, pending: &PendingTransition) -> Result<()> {
        let witness = &pending.witness_wip;
        ensure!(
            pending.owner == witness.prev_account_state.owner,
            "pending envelope owner differs from witness.prev_account_state.owner"
        );
        ensure!(
            pending.owner == witness.new_account_state.owner,
            "pending envelope owner differs from witness.new_account_state.owner"
        );
        ensure!(
            pending.mode == witness.mode,
            "pending envelope mode differs from witness.mode"
        );
        ensure!(
            pending.nav_opening
                == (NavOpening {
                    nav: witness.nav,
                    nav_rand: witness.nav_rand,
                }),
            "pending envelope nav_opening differs from witness nav/nav_rand"
        );

        match self.accounts.get(&pending.owner) {
            Some(record) => {
                ensure!(
                    matches!(pending.mode, TransitionMode::AccountUpdateProof),
                    "present account requires AccountUpdateProof mode"
                );
                ensure!(
                    record.state == witness.prev_account_state,
                    "stored account state differs from witness.prev_account_state"
                );
            }
            None => {
                ensure!(
                    matches!(pending.mode, TransitionMode::InitialProof),
                    "absent account requires InitialProof mode"
                );
            }
        }
        Ok(())
    }

    /// Rebuild the live accumulator from its exact canonical-position mirror,
    /// apply the candidate to the rebuilt value, and return a complete staged
    /// replacement. No field on `self` is mutated on any error.
    fn stage_nflog_append(&self, pk: [u8; 32], r: [u8; 32]) -> Result<StagedNfLog> {
        ensure!(
            self.nflog_entries.len() == self.nflog_positions.len(),
            "apply: NfLog entry/position mirrors have different lengths"
        );
        ensure!(
            self.nflog.nav().size == self.nflog_entries.len() as u64,
            "apply: NfLog entry mirror length drifted from accumulator"
        );
        ensure!(
            self.nflog.nav().mth == host::nflog_mth(&self.nflog_entries),
            "apply: NfLog entry mirror root drifted from accumulator"
        );

        let mut accumulator = NfLogAccumulator::new(self.activation_height);
        for (expected_pos, (chain_pos, entry)) in self
            .nflog_positions
            .iter()
            .copied()
            .zip(self.nflog_entries.iter().copied())
            .enumerate()
        {
            match accumulator
                .fold(chain_pos, entry.pk, entry.r)
                .context("apply: replay NfLog mirror")?
            {
                FoldOutcome::Appended(pos) => ensure!(
                    pos == expected_pos as u64,
                    "apply: replayed NfLog position mismatch"
                ),
                FoldOutcome::DuplicateIgnored => {
                    bail!("apply: replayed NfLog mirror contains a duplicate key")
                }
                FoldOutcome::BelowActivationHeight => {
                    bail!("apply: replayed NfLog mirror contains a pre-activation entry")
                }
            }
        }
        ensure!(
            accumulator.nav() == self.nflog.nav(),
            "apply: replayed NfLog differs from live accumulator"
        );
        ensure!(
            accumulator.size_final(self.tip_height) == self.nflog.size_final(self.tip_height),
            "apply: replayed NfLog final prefix differs from live accumulator"
        );

        let next_fold_seq = self
            .fold_seq
            .checked_add(1)
            .context("apply: fold_seq overflow")?;
        let chain_pos = ChainPosition {
            height: self.tip_height,
            tx_index: self.fold_seq,
            vin_index: 0,
            member_index: 0,
        };
        let nullifier_pos = match accumulator
            .fold(chain_pos, pk, r)
            .context("apply: staged NfLog fold failed")?
        {
            FoldOutcome::Appended(pos) => pos,
            FoldOutcome::DuplicateIgnored => {
                bail!("apply: nullifier Pk already present (double-spend / republish)")
            }
            FoldOutcome::BelowActivationHeight => {
                bail!("apply: fold height is below NfLog activation height")
            }
        };

        let mut entries = self.nflog_entries.clone();
        entries.push(NfLogEntry { pk, r });
        let mut positions = self.nflog_positions.clone();
        positions.push(chain_pos);
        ensure!(
            entries.len() as u64 == nullifier_pos + 1 && positions.len() == entries.len(),
            "apply: staged NfLog mirrors drifted from accumulator"
        );
        ensure!(
            accumulator.nav().mth == host::nflog_mth(&entries),
            "apply: staged NfLog mirror root mismatch"
        );

        Ok(StagedNfLog {
            accumulator,
            entries,
            positions,
            fold_seq: next_fold_seq,
            nullifier_pos,
        })
    }

    /// Shared setup for begin_*: mode, prev state, recursion material, and a
    /// mutable coinhist leaf map for sequential clause-8 updates.
    fn account_transition_context(
        &self,
        owner: &Address,
        nk: &[u8; 32],
        current_pubkey: [u8; 32],
    ) -> Result<(
        TransitionMode,
        AccountState,
        Option<ComplianceProof>,
        Option<NavOpening>,
        Option<PredecessorNullifier>,
        Vec<HashDigest>,
        BTreeMap<[u8; 32], host::CoinHistState>,
    )> {
        let nav = self.size_final_nav()?;

        if let Some(record) = self.accounts.get(owner) {
            ensure!(record.nk == *nk, "nk does not match registered account");
            ensure!(
                record.state.current_pubkey == current_pubkey,
                "current_pubkey does not match registered account"
            );
            let prev_proof = record
                .last_proof
                .clone()
                .context("AccountUpdateProof requires last_proof on the account")?;
            let prev_nav_opening = record
                .last_nav_opening
                .context("AccountUpdateProof requires last_nav_opening")?;
            let last_nf = record
                .last_nullifier
                .clone()
                .context("AccountUpdateProof requires last_nullifier")?;
            // Canonical position is what the chain-derived NfLog says (§3.6),
            // never a locally invented fold ordinal. A receive that has been
            // applied but not yet scan-folded has last_nullifier_pos = None
            // and must fail here until inclusion (fail-closed, no silent skip).
            let pos = match self.nflog.lookup(last_nf.public_key) {
                LookupResult::Present { pos, r, .. } => {
                    ensure!(
                        r == last_nf.signature_r,
                        "predecessor nullifier R on NfLog does not match account last_nullifier.R"
                    );
                    if let Some(cached) = record.last_nullifier_pos {
                        ensure!(
                            cached == pos,
                            "account last_nullifier_pos {cached} diverges from canonical \
                             NfLog position {pos} — refusing to prove on a stale cache"
                        );
                    }
                    pos
                }
                LookupResult::Absent => {
                    bail!(
                        "predecessor nullifier is not in the canonical NfLog \
                         (awaiting on-chain inclusion / scan-fold); refusing AccountUpdateProof"
                    );
                }
            };

            ensure!(
                pos < nav.size,
                "predecessor nullifier position {pos} is not covered by size_final nav.size {}",
                nav.size
            );
            // Inclusion path over the size_final prefix.
            let prefix = &self.nflog_entries[..nav.size as usize];
            let nav_inclusion = host::inclusion_path(pos, prefix)
                .context("predecessor nullifier inclusion path")?;
            let nav_consistency = host::consistency_proof(prev_nav_opening.nav.size, prefix)
                .context("nav consistency proof")?;

            let leaves = leaves_from_sets(&record.spendable, &record.spent_ids);
            Ok((
                TransitionMode::AccountUpdateProof,
                record.state.clone(),
                Some(prev_proof),
                Some(prev_nav_opening),
                Some(PredecessorNullifier {
                    nullifier: last_nf,
                    nav_inclusion,
                    position: pos,
                }),
                nav_consistency,
                leaves,
            ))
        } else {
            // Genesis / first transition: canonical empty account.
            let nk_commit = host::nk_commit(nk);
            let prev = AccountState::new(
                *owner,
                nk_commit,
                BTreeMap::new(),
                current_pubkey,
                0,
                host::coinhist_empty_root(),
            )
            .context("construct empty genesis AccountState")?;
            // InitialProof: empty consistency from 0 → nav.size (special-cased empty).
            ensure!(
                nav.size == 0
                    || host::consistency_proof(0, &self.nflog_entries[..nav.size as usize]).is_ok(),
                "initial nav consistency pre-check failed"
            );
            let nav_consistency = if nav.size == 0 {
                Vec::new()
            } else {
                // m == 0 ⇒ empty proof per validate_consistency_proof.
                Vec::new()
            };
            Ok((
                TransitionMode::InitialProof,
                prev,
                None,
                None,
                None,
                nav_consistency,
                BTreeMap::new(),
            ))
        }
    }

    /// `nav = size_final` at the current tip (§2.3.2 step 5 / §3.9).
    fn size_final_nav(&self) -> Result<Nav> {
        let size = self.nflog.size_final(self.tip_height);
        let full = self.nflog.nav();
        ensure!(
            size <= full.size,
            "size_final {size} exceeds accumulator size {}",
            full.size
        );
        if size == 0 {
            return Ok(Nav {
                size: 0,
                mth: host::nflog_empty(),
            });
        }
        if size == full.size {
            return Ok(full);
        }
        ensure!(
            self.nflog_entries.len() as u64 >= size,
            "nflog_entries shorter than size_final"
        );
        let mth = host::nflog_mth(&self.nflog_entries[..size as usize]);
        ensure!(
            self.nflog.is_canonical(size, mth),
            "computed size_final mth is not canonical"
        );
        Ok(Nav { size, mth })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn placeholder_signature(pk_i: [u8; 32]) -> TransitionSignature {
    TransitionSignature {
        pk_i,
        signature: [0u8; 64],
        r_prime: [0u8; 32],
    }
}

fn compute_proof_data(
    new_account_state: &AccountState,
    output_coins: &[Coin],
    input_coins: &[Coin],
    nk: &[u8; 32],
    nav: Nav,
    nav_rand: &[u8; 32],
    next_pubkey: &[u8; 32],
    npk_rand: &[u8; 32],
) -> Result<ProofData> {
    let output_ids: Vec<HashDigest> = output_coins.iter().map(|c| c.identifier).collect();
    let nullifiers: Vec<HashDigest> = input_coins
        .iter()
        .map(|c| host::nullifier(nk, c.identifier))
        .collect();
    Ok(ProofData {
        new_account_state_hash: host::account_state_hash(new_account_state)
            .context("hash new account state")?,
        output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &output_ids),
        input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &nullifiers),
        coin_history_root: new_account_state.coin_history_root,
        nav_commitment: host::nav_commitment(nav.root(), nav_rand),
        npk_commit: host::npk_commit(next_pubkey, npk_rand),
    })
}

fn leaves_from_sets(
    spendable: &BTreeMap<[u8; 32], TrackedCoin>,
    spent_ids: &BTreeSet<[u8; 32]>,
) -> BTreeMap<[u8; 32], host::CoinHistState> {
    let mut leaves = BTreeMap::new();
    for id in spent_ids {
        leaves.insert(*id, host::CoinHistState::Spent);
    }
    for id in spendable.keys() {
        leaves.insert(*id, host::CoinHistState::Admitted);
    }
    leaves
}

fn rebuild_coinhist(leaves: &BTreeMap<[u8; 32], host::CoinHistState>) -> Result<CoinHistTree> {
    let mut hist = CoinHistTree::new();
    for (&id, &state) in leaves {
        match state {
            host::CoinHistState::Admitted => {
                hist.admit(id).context("rebuild admit")?;
            }
            host::CoinHistState::Spent => {
                hist.admit(id).context("rebuild admit-before-spend")?;
                hist.spend(id).context("rebuild spend")?;
            }
            host::CoinHistState::Absent => {
                bail!("Absent must not appear in coinhist leaf map");
            }
        }
    }
    Ok(hist)
}

fn credit_balance(
    balances: &mut BTreeMap<[u8; 32], u128>,
    asset_id: HashDigest,
    amount: u128,
) -> Result<()> {
    ensure!(amount > 0, "credit amount must be non-zero");
    let key = host::digest_to_bytes(&asset_id);
    let entry = balances.entry(key).or_insert(0);
    *entry = entry
        .checked_add(amount)
        .context("balance credit overflow")?;
    ensure!(
        balances.len() <= MAX_ACCOUNT_ASSETS,
        "account balance count exceeds MAX_ACCOUNT_ASSETS"
    );
    Ok(())
}

fn debit_balance(
    balances: &mut BTreeMap<[u8; 32], u128>,
    asset_id: HashDigest,
    amount: u128,
) -> Result<()> {
    ensure!(amount > 0, "debit amount must be non-zero");
    let key = host::digest_to_bytes(&asset_id);
    let cur = balances
        .get(&key)
        .copied()
        .context("debit: asset not present in balances")?;
    ensure!(cur >= amount, "debit: insufficient balance");
    let next = cur - amount;
    if next == 0 {
        balances.remove(&key);
    } else {
        balances.insert(key, next);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover_bridge::test_signing::{
        base_proved_transition, deterministic_secret, normalized_key, sign_transition,
    };
    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use sha2::{Digest, Sha256};
    use zkcoins_program_plonky2::circuit::gadgets::curve_types::{AffinePoint, Secp256K1};

    /// Deterministic keys / coin construction matching `prover_bridge` fixtures.
    struct FundedFixture {
        owner: Address,
        nk: [u8; 32],
        asset_id: HashDigest,
        input_coin: Coin,
        /// Secret for the account's *current* spend key (post-mint = spend-key-1).
        spend_secret: Secp256K1Scalar,
        spend_public: AffinePoint<Secp256K1>,
        next_pubkey: [u8; 32],
        genesis_proof: ProvedTransition,
        genesis_nav_opening: NavOpening,
        genesis_nullifier: NullifierOpening,
    }

    fn build_funded_fixture(bridge: &ProverBridge) -> FundedFixture {
        // --- genesis mint witness (same pattern as prover_bridge::genesis_fixture) ---
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/compliance-chain/nk").into();
        let nk_commit = host::nk_commit(&nk);
        let (secret0, public0, pk0) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-0",
        ));
        let (_, _, pk1) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        let owner = Address(host::address(&pk0, nk_commit));
        let name_hash: [u8; 32] = Sha256::digest(b"Recursive Fixture Asset").into();
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &pk0, &name_hash, 2, 1);
        let issuance = AssetIssuance {
            asset_id,
            creator_pubkey: pk0,
            issuance_version: 1,
            name_hash,
            decimals: 2,
            amount: 100,
            terms_hash: host::terms_hash_v1(asset_id, 1),
            cap_total: 0,
            terms_salt: [0u8; 32],
        };
        let prev_account_state = AccountState::new(
            owner,
            nk_commit,
            BTreeMap::new(),
            pk0,
            0,
            host::coinhist_empty_root(),
        )
        .unwrap();
        let prev_ash = host::account_state_hash(&prev_account_state).unwrap();
        let output_template = CoinTemplate {
            recipient: owner,
            amount: 100,
            asset_id,
        };
        let output_coin = Coin {
            identifier: host::coin_identifier(prev_ash, &owner.0, asset_id, 100, 0),
            recipient: owner,
            amount: 100,
            asset_id,
        };
        let mut history = CoinHistTree::new();
        let output_history = history.prove(host::digest_to_bytes(&output_coin.identifier));
        history
            .admit(host::digest_to_bytes(&output_coin.identifier))
            .unwrap();
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), 100);
        let new_account_state =
            AccountState::new(owner, nk_commit, balances, pk1, 1, history.root()).unwrap();
        // Fresh-net mint: nav = size_final = empty.
        let nav_opening = NavOpening {
            nav: Nav {
                size: 0,
                mth: host::nflog_empty(),
            },
            nav_rand: [0x2bu8; 32],
        };
        let npk_rand = [0x4du8; 32];
        let proof_data = ProofData {
            new_account_state_hash: host::account_state_hash(&new_account_state).unwrap(),
            output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &[output_coin.identifier]),
            input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
            coin_history_root: new_account_state.coin_history_root,
            nav_commitment: host::nav_commitment(nav_opening.nav.root(), &nav_opening.nav_rand),
            npk_commit: host::npk_commit(&pk1, &npk_rand),
        };
        let signature = sign_transition(secret0, public0, &proof_data, Network::Testnet);
        let witness = TransitionWitness {
            mode: TransitionMode::InitialProof,
            prev_account_state,
            new_account_state: new_account_state.clone(),
            input_coins: Vec::new(),
            input_auth: Vec::new(),
            output_templates: vec![output_template],
            output_coins: vec![output_coin.clone()],
            output_history_proofs: vec![Some(output_history)],
            received_coins: Vec::new(),
            received_auth: Vec::new(),
            asset_issuance: Some(issuance),
            nk,
            nav: nav_opening.nav,
            nav_rand: nav_opening.nav_rand,
            prev_nav_opening: None,
            nav_consistency: Vec::new(),
            next_pubkey: pk1,
            npk_rand,
            transition_signature: signature.transition.clone(),
            prev_proof: None,
            predecessor_nullifier: None,
        };
        let genesis_proof = bridge
            .prove_transition(&witness)
            .expect("fixture genesis/mint proof");

        let (spend_secret, spend_public, pk1_check) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        assert_eq!(pk1_check, pk1);
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-2",
        ));

        FundedFixture {
            owner,
            nk,
            asset_id,
            input_coin: output_coin,
            spend_secret,
            spend_public,
            next_pubkey,
            genesis_proof,
            genesis_nav_opening: nav_opening,
            genesis_nullifier: NullifierOpening {
                public_key: signature.transition.pk_i,
                signature_r: signature.transition.signature_r(),
                r_prime: signature.transition.r_prime,
            },
        }
    }

    fn engine_with_funded_account(fixture: &FundedFixture) -> StateEngine {
        let mut engine = StateEngine::new(Network::Testnet, 0);
        // Fold the genesis nullifier at height 100, then tip past finality so
        // size_final covers it (predecessor dependency for the send).
        engine.set_tip_height(100);
        let genesis_position = ChainPosition {
            height: 100,
            tx_index: 0,
            vin_index: 0,
            member_index: 0,
        };
        let fold = engine
            .nflog
            .fold(
                genesis_position,
                fixture.genesis_nullifier.public_key,
                fixture.genesis_nullifier.signature_r,
            )
            .expect("fold genesis nullifier");
        let pos = match fold {
            FoldOutcome::Appended(p) => p,
            other => panic!("expected Appended, got {other:?}"),
        };
        engine.nflog_entries.push(NfLogEntry {
            pk: fixture.genesis_nullifier.public_key,
            r: fixture.genesis_nullifier.signature_r,
        });
        engine.nflog_positions.push(genesis_position);
        engine.fold_seq = 1;
        // tip ≥ height + 5 ⇒ size_final includes the entry.
        engine.set_tip_height(105);

        let mut coinhist = CoinHistTree::new();
        let id = host::digest_to_bytes(&fixture.input_coin.identifier);
        coinhist.admit(id).unwrap();
        let mut spendable = BTreeMap::new();
        let creating_prev_ash = {
            // prev_ash of the genesis mint (empty → minted state).
            let nk_commit = host::nk_commit(&fixture.nk);
            let (_s, _p, pk0) = normalized_key(deterministic_secret(
                b"zkCoins/v1/compliance-chain/spend-key-0",
            ));
            let empty = AccountState::new(
                fixture.owner,
                nk_commit,
                BTreeMap::new(),
                pk0,
                0,
                host::coinhist_empty_root(),
            )
            .unwrap();
            host::account_state_hash(&empty).unwrap()
        };
        spendable.insert(
            id,
            TrackedCoin {
                coin: fixture.input_coin.clone(),
                creating_prev_ash,
                coin_index: 0,
            },
        );
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&fixture.asset_id), 100);
        let (_s, _p, pk1) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        let state = AccountState::new(
            fixture.owner,
            host::nk_commit(&fixture.nk),
            balances,
            pk1,
            1,
            coinhist.root(),
        )
        .unwrap();
        let record = AccountRecord {
            state,
            coinhist,
            nk: fixture.nk,
            genesis_pubkey: {
                let (_s, _p, pk0) = normalized_key(deterministic_secret(
                    b"zkCoins/v1/compliance-chain/spend-key-0",
                ));
                pk0
            },
            spendable,
            spent_ids: BTreeSet::new(),
            last_proof: Some(fixture.genesis_proof.proof.clone()),
            last_nav_opening: Some(fixture.genesis_nav_opening),
            last_nullifier: Some(fixture.genesis_nullifier.clone()),
            last_nullifier_pos: Some(pos),
        };
        engine.insert_account(fixture.owner, record).unwrap();
        let _ = pos;
        engine
    }

    fn test_mint_request(issuance_version: u8) -> MintRequest {
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/state-engine/test-mint/nk").into();
        let (_, _, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/test-mint/pk0",
        ));
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/test-mint/pk1",
        ));
        MintRequest {
            owner: Address(host::address(&current_pubkey, host::nk_commit(&nk))),
            nk,
            current_pubkey,
            next_pubkey,
            name: b"State Engine Test Asset".to_vec(),
            decimals: 2,
            amount: 100,
            issuance_version,
            cap_total: if issuance_version == 2 { 100 } else { 0 },
            terms_salt: if issuance_version == 2 {
                [0x44; 32]
            } else {
                [0; 32]
            },
            nav_rand: [0x11; 32],
            npk_rand: [0x22; 32],
        }
    }

    fn dummy_received_auth(
        creating_proof: ComplianceProof,
        creating_prev_ash: HashDigest,
        leaf_index: u32,
    ) -> ReceivedAuthorization {
        let empty_nav = Nav {
            size: 0,
            mth: host::nflog_empty(),
        };
        ReceivedAuthorization {
            creating_proof,
            output_inclusion: crate::prover_bridge::OutputInclusionProof {
                leaf_index,
                depth: 0,
                siblings: Vec::new(),
            },
            creating_prev_ash,
            creating_nullifier: NullifierOpening {
                public_key: [0; 32],
                signature_r: [0; 32],
                r_prime: [0; 32],
            },
            creating_nav_inclusion: Vec::new(),
            pos_create: 0,
            creating_nav_opening: NavOpening {
                nav: empty_nav,
                nav_rand: [0; 32],
            },
            creating_nav_consistency: Vec::new(),
            history_proof: CoinHistTree::new().prove([0; 32]),
        }
    }

    #[test]
    fn begin_mint_rejects_token_standard_2_without_explicit_recipient() {
        let engine = StateEngine::new(Network::Testnet, 0);
        let err = engine
            .begin_mint(test_mint_request(2))
            .expect_err("v2 mint must fail loudly");
        assert!(
            format!("{err:#}").contains("explicit non-owner emission recipient"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn begin_receive_initial_proof_uses_sequential_history_roots() {
        let mut engine = StateEngine::new(Network::Testnet, 0);
        engine.set_tip_height(0);

        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/state-engine/initial-receive/nk").into();
        let (_, _, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/initial-receive/pk0",
        ));
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/initial-receive/pk1",
        ));
        let owner = Address(host::address(&current_pubkey, host::nk_commit(&nk)));
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &current_pubkey, &[0x31; 32], 2, 1);
        let initial_state = AccountState::new(
            owner,
            host::nk_commit(&nk),
            BTreeMap::new(),
            current_pubkey,
            0,
            host::coinhist_empty_root(),
        )
        .unwrap();
        let creating_prev_ash = host::account_state_hash(&initial_state).unwrap();
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
        let base = base_proved_transition(Network::Testnet);
        let auth = vec![
            dummy_received_auth(base.proof.clone(), creating_prev_ash, 0),
            dummy_received_auth(base.proof, creating_prev_ash, 1),
        ];

        let pending = engine
            .begin_receive(ReceiveRequest {
                owner,
                nk,
                current_pubkey,
                received_coins: coins.clone(),
                received_auth: auth,
                next_pubkey,
                nav_rand: [0x41; 32],
                npk_rand: [0x42; 32],
            })
            .expect("first-transition batched receive");
        assert_eq!(pending.mode, TransitionMode::InitialProof);
        assert!(pending.witness_wip.prev_proof.is_none());

        let first_id = host::digest_to_bytes(&coins[0].identifier);
        let second_id = host::digest_to_bytes(&coins[1].identifier);
        let first_proof = &pending.witness_wip.received_auth[0].history_proof;
        let second_proof = &pending.witness_wip.received_auth[1].history_proof;
        assert!(first_proof.verify(&first_id, host::coinhist_empty_root()));
        assert!(!second_proof.verify(&second_id, host::coinhist_empty_root()));
        let mut intermediate = CoinHistTree::new();
        intermediate.admit(first_id).unwrap();
        assert!(second_proof.verify(&second_id, intermediate.root()));
        intermediate.admit(second_id).unwrap();
        assert_eq!(
            intermediate.root(),
            pending.witness_wip.new_account_state.coin_history_root
        );
    }

    #[test]
    fn begin_send_multi_input_uses_sequential_history_roots() {
        let mut engine = StateEngine::new(Network::Testnet, 0);
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/state-engine/multi-send/nk").into();
        let (_, _, genesis_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/multi-send/pk0",
        ));
        let (_, _, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/multi-send/pk1",
        ));
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/multi-send/pk2",
        ));
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
        let predecessor_entry = NfLogEntry {
            pk: genesis_pubkey,
            r: [0x61; 32],
        };
        engine.set_tip_height(10);
        assert_eq!(
            engine
                .nflog
                .fold(
                    predecessor_position,
                    predecessor_entry.pk,
                    predecessor_entry.r,
                )
                .unwrap(),
            FoldOutcome::Appended(0)
        );
        engine.nflog_entries.push(predecessor_entry);
        engine.nflog_positions.push(predecessor_position);
        engine.set_tip_height(15);
        engine
            .insert_account(
                owner,
                AccountRecord {
                    state: state.clone(),
                    coinhist,
                    nk,
                    genesis_pubkey,
                    spendable,
                    spent_ids: BTreeSet::new(),
                    last_proof: Some(base_proved_transition(Network::Testnet).proof),
                    last_nav_opening: Some(NavOpening {
                        nav: Nav {
                            size: 0,
                            mth: host::nflog_empty(),
                        },
                        nav_rand: [0; 32],
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

        let pending = engine
            .begin_send(SendRequest {
                owner,
                input_coin_ids: coins.iter().map(|coin| coin.identifier).collect(),
                output_templates: vec![CoinTemplate {
                    recipient: Address([0x71; 32]),
                    amount: 100,
                    asset_id,
                }],
                next_pubkey,
                nav_rand: [0x72; 32],
                npk_rand: [0x73; 32],
            })
            .expect("multi-input begin_send");

        let first_id = host::digest_to_bytes(&coins[0].identifier);
        let second_id = host::digest_to_bytes(&coins[1].identifier);
        let first_proof = &pending.witness_wip.input_auth[0].history_proof;
        let second_proof = &pending.witness_wip.input_auth[1].history_proof;
        assert!(first_proof.verify(&first_id, state.coin_history_root));
        assert!(!second_proof.verify(&second_id, state.coin_history_root));
        let mut intermediate = rebuild_coinhist(&leaves_from_sets(
            &engine.account(&owner).unwrap().spendable,
            &BTreeSet::new(),
        ))
        .unwrap();
        intermediate.spend(first_id).unwrap();
        assert!(second_proof.verify(&second_id, intermediate.root()));
        intermediate.spend(second_id).unwrap();
        assert_eq!(
            intermediate.root(),
            pending.witness_wip.new_account_state.coin_history_root
        );
    }

    #[test]
    fn finalise_rejects_pending_envelope_mismatches_before_proving() {
        let engine = StateEngine::new(Network::Testnet, 0);
        let pending = engine
            .begin_mint(test_mint_request(1))
            .expect("begin token-standard-1 mint");
        let signature =
            placeholder_signature(pending.witness_wip.prev_account_state.current_pubkey);

        let mut wrong_owner = pending.clone();
        wrong_owner.owner = Address([0x91; 32]);
        let mut owner_engine = engine;
        let err = owner_engine
            .finalise(wrong_owner, signature.clone())
            .expect_err("wrong envelope owner must fail before proving");
        assert!(format!("{err:#}").contains("envelope owner"));

        let mut wrong_mode = pending.clone();
        wrong_mode.mode = TransitionMode::AccountUpdateProof;
        let mut mode_engine = StateEngine::new(Network::Testnet, 0);
        let err = mode_engine
            .finalise(wrong_mode, signature.clone())
            .expect_err("wrong envelope mode must fail before proving");
        assert!(format!("{err:#}").contains("envelope mode"));

        let mut stale_pending = pending.clone();
        stale_pending.mode = TransitionMode::AccountUpdateProof;
        stale_pending.witness_wip.mode = TransitionMode::AccountUpdateProof;
        let mut stale_state = stale_pending.witness_wip.prev_account_state.clone();
        stale_state.send_counter = 1;
        let stale_owner = stale_pending.owner;
        let mut stale_engine = StateEngine::new(Network::Testnet, 0);
        stale_engine
            .insert_account(
                stale_owner,
                AccountRecord {
                    state: stale_state,
                    coinhist: CoinHistTree::new(),
                    nk: stale_pending.witness_wip.nk,
                    genesis_pubkey: stale_pending.witness_wip.prev_account_state.current_pubkey,
                    spendable: BTreeMap::new(),
                    spent_ids: BTreeSet::new(),
                    last_proof: None,
                    last_nav_opening: None,
                    last_nullifier: None,
                    last_nullifier_pos: None,
                },
            )
            .unwrap();
        let err = stale_engine
            .finalise(stale_pending, signature.clone())
            .expect_err("stale witness prev_account_state must fail before proving");
        assert!(format!("{err:#}").contains("stored account state"));

        let mut wrong_nav = pending;
        wrong_nav.nav_opening.nav_rand[0] ^= 1;
        let mut nav_engine = StateEngine::new(Network::Testnet, 0);
        let err = nav_engine
            .finalise(wrong_nav, signature)
            .expect_err("wrong envelope NAV must fail before proving");
        assert!(format!("{err:#}").contains("envelope nav_opening"));
    }

    #[test]
    fn transactional_nflog_stage_leaves_engine_unchanged_on_duplicate() {
        let mut engine = StateEngine::new(Network::Testnet, 0);
        engine.set_tip_height(50);
        let position = ChainPosition {
            height: 50,
            tx_index: 0,
            vin_index: 0,
            member_index: 0,
        };
        let entry = NfLogEntry {
            pk: [0xa1; 32],
            r: [0xa2; 32],
        };
        assert_eq!(
            engine.nflog.fold(position, entry.pk, entry.r).unwrap(),
            FoldOutcome::Appended(0)
        );
        engine.nflog_entries.push(entry);
        engine.nflog_positions.push(position);
        engine.fold_seq = 1;

        let nav_before = engine.nflog.nav();
        let entries_before = engine.nflog_entries.clone();
        let positions_before = engine.nflog_positions.clone();
        let fold_seq_before = engine.fold_seq;
        let account_count_before = engine.accounts.len();

        let err = engine
            .stage_nflog_append(entry.pk, [0xff; 32])
            .err()
            .expect("duplicate staged fold must fail");
        assert!(format!("{err:#}").contains("already present"));
        assert_eq!(engine.nflog.nav(), nav_before);
        assert_eq!(engine.nflog_entries, entries_before);
        assert_eq!(engine.nflog_positions, positions_before);
        assert_eq!(engine.fold_seq, fold_seq_before);
        assert_eq!(engine.accounts.len(), account_count_before);

        let fresh = engine
            .stage_nflog_append([0xb1; 32], [0xb2; 32])
            .expect("a fresh fold at the same next position still stages");
        assert_eq!(fresh.nullifier_pos, 1);
        assert_eq!(engine.nflog.nav(), nav_before);
    }

    #[test]
    fn verify_incoming_rejects_forged_wrapper_proof_data_before_verify() {
        let engine = StateEngine::new(Network::Testnet, 0);
        let nav_opening = NavOpening {
            nav: Nav {
                size: 0,
                mth: host::nflog_empty(),
            },
            nav_rand: [0xc1; 32],
        };
        let mut proved = base_proved_transition(Network::Testnet);
        proved.proof_data.nav_commitment =
            host::nav_commitment(nav_opening.nav.root(), &nav_opening.nav_rand);

        let err = engine
            .verify_incoming_transition(&proved, &nav_opening)
            .expect_err("forged ProofData wrapper must not be trusted");
        let message = format!("{err:#}");
        assert!(
            message.contains("wrapper/public-input mismatch")
                && message.contains("proof_data differs"),
            "unexpected error: {message}"
        );
    }

    /// Fast: `begin_send` with outputs > inputs returns Err before proving.
    /// Conservation is checked before predecessor / last_proof wiring.
    #[test]
    fn begin_send_overspend_returns_err() {
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/state-engine/overspend/nk").into();
        let nk_commit = host::nk_commit(&nk);
        let (_s, _p, pk) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/overspend/pk",
        ));
        let owner = Address(host::address(&pk, nk_commit));
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &pk, &[7u8; 32], 2, 1);
        let empty = AccountState::new(
            owner,
            nk_commit,
            BTreeMap::new(),
            pk,
            0,
            host::coinhist_empty_root(),
        )
        .expect("empty");
        let empty_ash = host::account_state_hash(&empty).expect("ash");
        let coin = Coin {
            identifier: host::coin_identifier(empty_ash, &owner.0, asset_id, 50, 0),
            recipient: owner,
            amount: 50,
            asset_id,
        };
        let mut coinhist = CoinHistTree::new();
        let id = host::digest_to_bytes(&coin.identifier);
        coinhist.admit(id).expect("admit");
        let mut spendable = BTreeMap::new();
        spendable.insert(
            id,
            TrackedCoin {
                coin: coin.clone(),
                creating_prev_ash: empty_ash,
                coin_index: 0,
            },
        );
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), 50);
        let state =
            AccountState::new(owner, nk_commit, balances, pk, 1, coinhist.root()).expect("state");
        let record = AccountRecord {
            state,
            coinhist,
            nk,
            genesis_pubkey: pk,
            spendable,
            spent_ids: BTreeSet::new(),
            // No last_proof — overspend is checked first and must fail loud.
            last_proof: None,
            last_nav_opening: None,
            last_nullifier: None,
            last_nullifier_pos: None,
        };
        let mut engine = StateEngine::new(Network::Testnet, 0);
        engine.insert_account(owner, record).expect("insert");

        let err = engine
            .begin_send(SendRequest {
                owner,
                input_coin_ids: vec![coin.identifier],
                output_templates: vec![CoinTemplate {
                    recipient: Address([0x99u8; 32]),
                    amount: 51, // > 50
                    asset_id,
                }],
                next_pubkey: [0x55u8; 32],
                nav_rand: [0x11u8; 32],
                npk_rand: [0x22u8; 32],
            })
            .expect_err("overspend must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("over-spend"),
            "expected over-spend error, got: {msg}"
        );
    }

    /// End-to-end SEND through the engine (one engine `finalise` prove).
    ///
    /// Fixture setup proves a genesis mint once via the bridge so the account
    /// carries a genuine `last_proof`; the engine path under test is the send.
    #[test]
    #[ignore = "heavy: real Plonky2 prove (minutes); run with --ignored --release"]
    fn state_engine_send_end_to_end() {
        let bridge = ProverBridge::new(Network::Testnet);
        let fixture = build_funded_fixture(&bridge);
        let mut engine = engine_with_funded_account(&fixture);

        let external = Address([0x82u8; 32]);
        let pending = engine
            .begin_send(SendRequest {
                owner: fixture.owner,
                input_coin_ids: vec![fixture.input_coin.identifier],
                output_templates: vec![CoinTemplate {
                    recipient: external,
                    amount: 30,
                    asset_id: fixture.asset_id,
                }],
                next_pubkey: fixture.next_pubkey,
                nav_rand: [0x3cu8; 32],
                npk_rand: [0xa5u8; 32],
            })
            .expect("begin_send");

        // Expected ProofData: change 70 self + 30 external.
        assert_eq!(pending.mode, TransitionMode::AccountUpdateProof);
        assert_eq!(pending.witness_wip.input_coins.len(), 1);
        assert_eq!(pending.witness_wip.output_coins.len(), 2);
        // Canonical order: recipient templates first, then change.
        assert_eq!(pending.witness_wip.output_templates[0].recipient, external);
        assert_eq!(pending.witness_wip.output_templates[0].amount, 30);
        assert_eq!(
            pending.witness_wip.output_templates[1].recipient,
            fixture.owner
        );
        assert_eq!(pending.witness_wip.output_templates[1].amount, 70);

        let expected_pd = compute_proof_data(
            &pending.witness_wip.new_account_state,
            &pending.witness_wip.output_coins,
            &pending.witness_wip.input_coins,
            &fixture.nk,
            pending.nav_opening.nav,
            &pending.nav_opening.nav_rand,
            &fixture.next_pubkey,
            &pending.witness_wip.npk_rand,
        )
        .unwrap();
        assert_eq!(pending.proof_data, expected_pd);
        assert_eq!(
            pending.proof_data_hash,
            host::hash_proof_data(&host::serialize_proof_data(&expected_pd))
        );

        // size_final nav must cover the predecessor.
        assert_eq!(pending.nav_opening.nav.size, 1);
        assert!(engine
            .nflog
            .is_canonical(pending.nav_opening.nav.size, pending.nav_opening.nav.mth));

        let sig = sign_transition(
            fixture.spend_secret,
            fixture.spend_public,
            &pending.proof_data,
            Network::Testnet,
        );
        let applied = engine
            .finalise(pending, sig.transition)
            .expect("finalise send");

        // Account state: balance 70, send_counter 2, current_pubkey rotated.
        let rec = engine.account(&fixture.owner).expect("account present");
        assert_eq!(rec.state.send_counter, 2);
        assert_eq!(rec.state.current_pubkey, fixture.next_pubkey);
        assert_eq!(
            rec.state
                .balances
                .get(&host::digest_to_bytes(&fixture.asset_id)),
            Some(&70)
        );
        assert_eq!(rec.coinhist.root(), rec.state.coin_history_root);
        // Input spent, change admitted.
        let in_id = host::digest_to_bytes(&fixture.input_coin.identifier);
        assert!(rec.spent_ids.contains(&in_id));
        assert!(!rec.spendable.contains_key(&in_id));
        assert_eq!(rec.spendable.len(), 1);
        let change = rec.spendable.values().next().unwrap();
        assert_eq!(change.coin.amount, 70);
        assert_eq!(change.coin.recipient, fixture.owner);

        // Nullifier folded.
        assert_eq!(applied.nullifier.0, applied.proved.consumed_pubkey);
        assert_eq!(engine.nflog.nav().size, 2);
        assert_eq!(engine.nflog_entries.len(), 2);
        assert_eq!(engine.nflog_entries[1].pk, applied.nullifier.0);
        assert_eq!(engine.nflog_entries[1].r, applied.nullifier.1);

        // Host acceptance against the engine's own NfLog: the send's nav was
        // size_final=1 at prove time; after folding size grows, but the proved
        // nav remains a canonical prefix.
        engine
            .verify_incoming_transition(
                &applied.proved,
                &NavOpening {
                    nav: Nav {
                        size: 1,
                        mth: host::nflog_mth(&engine.nflog_entries[..1]),
                    },
                    // nav_rand from the send
                    nav_rand: [0x3cu8; 32],
                },
            )
            .expect("verify_incoming_transition on applied send");
    }
}
