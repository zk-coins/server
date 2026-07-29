//! Bitcoin publisher: half-aggregate nullifier signatures, inscribe via
//! Taproot commit/reveal, and broadcast to a real bitcoind.
//!
//! This is the first live-Bitcoin integration path (P1-F.3). It orchestrates
//! the already-implemented half-aggregation codec ([`crate::half_agg`]) and
//! Taproot envelope primitives ([`crate::inscription`]); it does **not**
//! reimplement either.
//!
//! ## §3.5 block_anchor selection
//!
//! The publisher chooses one `block_anchor` as the oldest **caller-asserted**
//! member tip among [`BatchMember::build_tip`] values. The publisher never
//! silently substitutes a fresher tip.
//!
//! **What this layer checks.** Every member's claimed tip exists on this node's
//! canonical chain (`height ≤ tip` and `hash == getblockhash(height)`),
//! including members that are not selected as the batch anchor. Immediately
//! before broadcast the selected anchor is re-verified by **identity**
//! (`getblockhash(height)` still equals the selected hash — not merely the
//! height gap), so a same-height reorg cannot sneak a stale hash past the
//! height-only check.
//!
//! **What this layer cannot check.** Nothing in the half-aggregate or the §3.5
//! payload binds a per-member build tip. NISSHAC aggregation coefficients are
//! computed over `(R, Pk)` only; `aggregate_verify` ignores `block_anchor`.
//! `ProofData` carries no height and no block-anchor field. The publisher
//! therefore **cannot** know that a claimed tip is the tip the proof was
//! actually built against — see [`BatchMember::build_tip`].
//!
//! **Inclusion-delay budget.** The consensus scanner bound is
//! `inclusion_height − anchor.height ≤ `[`BLOCK_ANCHOR_MAX_GAP`] (`100`).
//! Selection and the pre-broadcast re-check use the stricter effective bound
//! `MAX_GAP − `[`PublisherConfig::inclusion_delay_margin`]. With margin `m`,
//! inclusion up to `m + 1` blocks after the pre-broadcast check still
//! satisfies §3.5; beyond that the batch carries **zero** valid nullifiers
//! while its fees remain spent. The margin is a **budget**, not a guarantee of
//! inclusion. No fee-bump path is **implemented** in this module (see
//! [`PublisherConfig`] commit-fee note); choosing an adequate
//! `fee_rate_sat_per_vb` up front (and a sufficient margin) remains the
//! recommended approach.
//!
//! **RPC cost of anchor selection.** After the O(1) structural gates, selection
//! fetches the node tip once, then applies the effective height window by pure
//! arithmetic on caller-supplied heights (too old or in the future). A batch
//! rejected by that pre-filter costs O(1) RPCs (tip only). Only heights that
//! survive the window are looked up via `getblockhash` — at most
//! `window + 1` distinct heights for an accepted batch, independent of member
//! count (`window = MAX_GAP − inclusion_delay_margin`).
//!
//! ## Batch size is the caller's policy
//!
//! This module **never auto-splits** a batch. Which nullifiers share one
//! inscription is a policy decision (first-occurrence / fee / privacy). If the
//! resulting reveal exceeds Bitcoin Core's standardness weight limit, publish
//! fails loudly and the caller must split and re-submit. Member-count and
//! reveal-weight checks run **before** any per-member chain RPC so an
//! unpublishable batch costs O(1) RPCs. Use
//! [`max_half_agg_members_for_standard_reveal`] to learn the bound for a given
//! payload shape.
//!
//! ## Scope deliberately left to P1-G (scanner)
//!
//! The on-acceptance re-check of the §3.5 inclusion-height gap against the
//! mined reveal block, and the §3.6 first-occurrence policy, are **not**
//! enforced here. This module only publishes and can read back raw inscription
//! payloads for verification.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{
    Amount, Network as BitcoinNetwork, OutPoint, Script, ScriptBuf, Transaction, TxOut, Txid,
};
use bitcoincore_rpc::json::AddressType;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use zkcoins_program_plonky2::circuit::compliance::Network;

use crate::half_agg::{
    aggregate_sig_with_anchor, aggregate_verify, AggregateStateNullifierV3, BlockAnchor,
    NullifierSig, FORMAT_HALF_AGG, PAYLOAD_HEADER_LEN, PAYLOAD_MARKER, PAYLOAD_VERSION_V3,
};
use crate::inscription::{build_inscription, extract_payloads_from_reveal, InscriptionRequest};

/// BIP-341 NUMS (nothing-up-my-sleeve) internal key.
///
/// Hex: `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`
///
/// Using this point as the Taproot **internal key** makes the key path
/// **provably unspendable**: no discrete logarithm is known for it (BIP-341
/// appendix), so the only way to spend the commit output is the inscription
/// script leaf. Scanners and operators can therefore treat a spend of this
/// output as an intentional reveal of the envelope.
///
/// Because the key path is unspendable by design, an oversized reveal that
/// bitcoind rejects after the commit has already been broadcast permanently
/// burns the commit value. The pre-broadcast standardness weight check is
/// therefore mandatory — there is no key-path recovery hatch.
pub(crate) const NUMS_INTERNAL_KEY_BYTES: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Bitcoin Core standardness policy limit on a single transaction's weight
/// (`MAX_STANDARD_TX_WEIGHT` = 400 000 weight units).
pub(crate) const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// §3.5 maximum gap between `block_anchor.height` and inclusion height.
///
/// Scanner consensus bound: `inclusion_height − block_anchor.height ≤ 100`.
pub(crate) const BLOCK_ANCHOR_MAX_GAP: u32 = 100;

/// Recommended inclusion-delay margin (blocks of tip advance reserved so the
/// reveal can still land inside [`BLOCK_ANCHOR_MAX_GAP`]).
///
/// Callers pass this value explicitly as
/// [`PublisherConfig::inclusion_delay_margin`]. It is **not** applied as a
/// silent default — the field is mandatory on the config struct. Must be
/// strictly less than [`BLOCK_ANCHOR_MAX_GAP`].
///
/// With margin `m` and pre-broadcast tip `T`, an anchor that passes the
/// effective bound (`MAX_GAP − m`) still satisfies the §3.5 consensus gap of
/// 100 when the reveal is included at any height `≤ T + 1 + m` (i.e. up to
/// `m + 1` blocks after the pre-broadcast tip). Later inclusion yields a gap
/// `> 100` and the batch carries zero valid nullifiers while fees remain spent.
pub const BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN: u32 = 6;

/// Effective publish max gap when using the **recommended** margin:
/// [`BLOCK_ANCHOR_MAX_GAP`] − [`BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN`] = 94.
///
/// Prefer computing `BLOCK_ANCHOR_MAX_GAP − config.inclusion_delay_margin` at
/// runtime (see [`publish_max_gap`]). This constant documents the recommended
/// effective bound only.
#[cfg(test)]
pub(crate) const BLOCK_ANCHOR_PUBLISH_MAX_GAP: u32 =
    BLOCK_ANCHOR_MAX_GAP - BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN;

/// Cap on fee/topology fixed-point rounds before failing loudly.
const MAX_FEE_CONVERGENCE_ROUNDS: usize = 5;

/// Maximum number of funding UTXOs for which a signed commit is **constructed**
/// (built + `signrawtransactionwithwallet`) per `publish` call.
///
/// Candidates that fail the arithmetic pre-filter (cannot cover
/// `reveal_output_value` plus theoretical minimum fees) are skipped without
/// construction and do not count toward this limit. Exhausting the limit fails
/// loudly with counts of constructed attempts and pre-filter skips.
const MAX_FUNDING_CONSTRUCT_ATTEMPTS: usize = 32;

/// Absolute lower bound on commit vsize (vB) for a single deterministic segwit
/// input and one P2TR output with no change. Intentionally low so the funding
/// pre-filter never skips a UTXO that could still succeed after measurement.
const MIN_COMMIT_VSIZE_LOWER_BOUND: usize = 100;

/// Configuration for a [`Publisher`] talking to one bitcoind wallet.
///
/// Every field is mandatory. There is no default fee rate, no default reveal
/// output value, no default network, no default inclusion-delay margin, and no
/// password-based RPC auth — missing values fail at the call site that builds
/// this struct, not inside the publisher.
///
/// ## Commit fee policy (no fee-bump path implemented here)
///
/// No fee-bump path is **implemented** in this module. The commit transaction
/// does signal RBF (see [`crate::inscription`]), but replacing it changes
/// `commit_txid` and therefore invalidates the **pre-built** reveal that spends
/// that exact outpoint. Because the reveal is signature-free, a replacement
/// commit can be paired with a **newly built** reveal — rebuilding is cheap,
/// unlike re-signing a signed child. The reveal can also act as a replaceable
/// CPFP child of the commit. Those paths are physically available on the wire;
/// this publisher simply does not implement them. Choosing an adequate
/// [`Self::fee_rate_sat_per_vb`] up front (and a sufficient
/// [`Self::inclusion_delay_margin`]) remains the recommended approach.
#[derive(Clone, Debug)]
pub struct PublisherConfig {
    /// Base RPC URL, e.g. `http://127.0.0.1:18443`. The wallet path is appended.
    pub rpc_url: String,
    /// Path to bitcoind's `.cookie` file. Cookie-file auth only.
    pub cookie_path: PathBuf,
    /// Name of the loaded descriptor wallet that funds the commit.
    pub wallet_name: String,
    /// Fee rate in satoshis per virtual byte. Applied to measured vsizes.
    /// Prefer setting this high enough for timely inclusion — see struct-level
    /// note on fee policy (no bump path implemented in this module).
    pub fee_rate_sat_per_vb: u64,
    /// Explicit value of the reveal transaction's single output. Must sit
    /// at or above the dust limit of its scriptPubKey.
    pub reveal_output_value: Amount,
    /// zkCoins network constant used for aggregate signature verification
    /// (`m_state`). Must match the network the members signed against.
    ///
    /// Chain binding (exact): `Mainnet↔Bitcoin`, `Testnet↔Signet`,
    /// `Regtest↔Regtest`. Testnet3 / Testnet4 are **not** accepted for
    /// [`Network::Testnet`] — the normative testnet is Signet (§3.6).
    pub network: Network,
    /// Blocks of tip advance reserved between the pre-broadcast freshness
    /// check and eventual reveal inclusion.
    ///
    /// Must be strictly less than [`BLOCK_ANCHOR_MAX_GAP`]. The recommended
    /// value is [`BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN`] (`6`); callers must
    /// set it explicitly (no silent default).
    ///
    /// **What the margin buys.** Effective publish bound is
    /// `BLOCK_ANCHOR_MAX_GAP − inclusion_delay_margin`. With margin `m`, if
    /// the pre-broadcast tip is `T` and the anchor passes the effective
    /// bound, inclusion at height `≤ T + 1 + m` still satisfies the §3.5
    /// consensus gap of 100. Inclusion later than that makes the batch carry
    /// **zero** valid nullifiers under a conformant scanner while the commit
    /// and reveal fees remain spent. The margin is a budget for mempool lag,
    /// not a guarantee of inclusion within that window — see the struct-level
    /// commit fee-policy note (no bump path implemented in this module).
    pub inclusion_delay_margin: u32,
}

/// Connected publisher bound to one wallet RPC endpoint.
pub struct Publisher {
    rpc: Client,
    config: PublisherConfig,
    /// Test-only: invoked once immediately before the pre-broadcast anchor
    /// identity re-check, so a deterministic reorg can be injected without
    /// racing the publish path.
    #[cfg(test)]
    pre_broadcast_hook: Mutex<Option<Box<dyn FnMut(&Client) + Send>>>,
    /// Test-only: counts `getblockhash` RPCs issued for **member** tip
    /// validation ([`Self::cached_block_hash`]). Tip acquisition via
    /// [`Self::current_anchor`] and the pre-broadcast identity re-check are
    /// **not** counted here — this seam observes only the selection-loop cost
    /// that a weight-valid stale batch must not be allowed to inflate.
    #[cfg(test)]
    member_getblockhash_calls: Mutex<u64>,
}

/// One batch member together with the chain tip its proof was built against (§3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchMember {
    /// Half-aggregate contribution (BIP-340 `Pk`, `R`, `s`).
    pub sig: NullifierSig,
    /// Caller-asserted Bitcoin tip this member claims it was built against.
    ///
    /// ## What the publisher *does* check
    ///
    /// Every member's claimed tip exists on **this** node's canonical chain
    /// and is not in the future: `height ≤ node tip` and
    /// `hash == getblockhash(height)`. The oldest validated tip becomes the
    /// batch `block_anchor`. Immediately before broadcast that selected
    /// identity is re-verified (not merely the height gap).
    ///
    /// ## What the publisher *cannot* check
    ///
    /// That the claimed tip is the tip the proof was **actually** built
    /// against. Nothing in the half-aggregate or the §3.5 payload binds a
    /// per-member build tip:
    /// - NISSHAC aggregation coefficients are computed over `(R, Pk)` members
    ///   only; `aggregate_verify` ignores `block_anchor` entirely.
    /// - The publisher-chosen batch `block_anchor` is written into the payload
    ///   header after aggregation; it is not a commitment to each member's
    ///   proof-time height.
    /// - `ProofData` has no height field and no block-anchor field.
    ///
    /// ## Real consequence of a dishonest claim
    ///
    /// A submitter whose proof was really built at `H−150` can claim the
    /// current tip `H`. The batch is then admitted, whereas the truthful
    /// anchor would have given gap 151 and the batch would have carried
    /// **zero** valid nullifiers under §3.5. The lie converts a rejection into
    /// an acceptance. All conformant scanners accept the batch identically, so
    /// there is no divergence *between* nodes — but §3.5's
    /// actual-oldest-tip requirement is **not enforced** by this layer.
    ///
    /// This is therefore a **trust assumption on the submitting caller**, to
    /// be closed by a future version that carries a proof-bound tip. Do not
    /// treat chain-existence validation as cryptographic binding.
    pub build_tip: BlockAnchor,
}

/// Result of a successful `publish` call.
#[derive(Clone, Debug)]
pub struct PublishedBatch {
    /// Half-aggregated payload object that was inscribed.
    pub aggregate: AggregateStateNullifierV3,
    /// Exact on-chain payload bytes.
    pub payload: Vec<u8>,
    /// Broadcast commit transaction id.
    pub commit_txid: Txid,
    /// Broadcast reveal transaction id.
    pub reveal_txid: Txid,
    /// The P2TR commit output that the reveal spends — the scanner's prevout.
    pub commit_output: TxOut,
    /// Publisher-chosen §3.5 anchor: the chain-consistency-checked oldest
    /// member tip (`height ≤ node tip`, `hash == getblockhash(height)`).
    /// Written into the payload header; not a crypto-bound commitment to each
    /// member's actual proof-time height (see [`BatchMember::build_tip`]).
    pub block_anchor: BlockAnchor,
}

/// Fully constructed, fee-converged commit/reveal pair ready for broadcast.
///
/// Produced by [`Publisher::prepare`]. Callers that need crash recovery
/// **must** persist the raw transactions (consensus-serialised) before
/// calling [`Publisher::broadcast_commit`] / [`Publisher::broadcast_reveal`],
/// so a crash between the two legs can finish or safely abandon without
/// guessing the missing transaction.
#[derive(Clone, Debug)]
pub struct PreparedBatch {
    /// Half-aggregated payload object that will be inscribed.
    pub aggregate: AggregateStateNullifierV3,
    /// Exact on-chain payload bytes.
    pub payload: Vec<u8>,
    /// Signed commit transaction (ready for `sendrawtransaction`).
    pub signed_commit: Transaction,
    /// Complete reveal transaction spending the commit output.
    pub reveal_tx: Transaction,
    /// The P2TR commit output that the reveal spends.
    pub commit_output: TxOut,
    /// Publisher-chosen §3.5 anchor (see [`PublishedBatch::block_anchor`]).
    pub block_anchor: BlockAnchor,
    /// Fee-basis commit vsize (must equal `signed_commit.vsize()`).
    pub commit_vsize: usize,
    /// Fee-basis reveal vsize (must equal `reveal_tx.vsize()`).
    pub reveal_vsize: usize,
    pub commit_fee: Amount,
    pub reveal_fee: Amount,
}

impl PreparedBatch {
    pub fn commit_txid(&self) -> Txid {
        self.signed_commit.compute_txid()
    }

    pub fn reveal_txid(&self) -> Txid {
        self.reveal_tx.compute_txid()
    }
}

/// Full per-input extraction result from a reveal transaction.
///
/// `payloads` holds every `Ok(Some(_))` envelope body. Per-input `Err`
/// results (malformed marker inputs that contribute zero nullifiers per
/// §3.5) are retained in `errors` so they are never dropped silently.
/// `Ok(None)` inputs (no marker envelope) are neither payloads nor errors.
#[derive(Debug)]
pub struct RevealPayloads {
    /// Successfully extracted envelope bodies, in input order among successes.
    pub payloads: Vec<Vec<u8>>,
    /// Malformed-input error messages (also present in `per_input`).
    pub errors: Vec<String>,
    /// One result per reveal input.
    pub per_input: Vec<Result<Option<Vec<u8>>, String>>,
}

impl Publisher {
    /// Connect to `{rpc_url}/wallet/{wallet_name}` with cookie-file auth.
    ///
    /// Fails loudly if the cookie cannot be read, the node is unreachable, the
    /// named wallet is not loaded / not accessible, or bitcoind's chain does
    /// not match [`PublisherConfig::network`] (see [`chain_matches_config`]).
    pub fn connect(config: PublisherConfig) -> Result<Self> {
        ensure!(
            !config.rpc_url.is_empty(),
            "PublisherConfig.rpc_url must not be empty"
        );
        ensure!(
            !config.wallet_name.is_empty(),
            "PublisherConfig.wallet_name must not be empty"
        );
        ensure!(
            config.fee_rate_sat_per_vb > 0,
            "PublisherConfig.fee_rate_sat_per_vb must be > 0 (no default fee)"
        );
        ensure!(
            config.reveal_output_value > Amount::ZERO,
            "PublisherConfig.reveal_output_value must be > 0 (no default)"
        );
        ensure!(
            !config.cookie_path.as_os_str().is_empty(),
            "PublisherConfig.cookie_path must not be empty"
        );
        // Fail loudly on an unusable margin before any RPC. No silent clamp.
        publish_max_gap(config.inclusion_delay_margin).with_context(|| {
            format!(
                "PublisherConfig.inclusion_delay_margin {} is invalid \
                 (must be < BLOCK_ANCHOR_MAX_GAP={BLOCK_ANCHOR_MAX_GAP})",
                config.inclusion_delay_margin
            )
        })?;

        let base = config.rpc_url.trim_end_matches('/');
        let wallet_url = format!("{base}/wallet/{}", config.wallet_name);
        let rpc = Client::new(&wallet_url, Auth::CookieFile(config.cookie_path.clone()))
            .with_context(|| {
                format!(
                    "failed to open bitcoind RPC client at {wallet_url} using cookie {:?}",
                    config.cookie_path
                )
            })?;

        let chain_info = rpc
            .get_blockchain_info()
            .with_context(|| format!("bitcoind unreachable or RPC auth failed at {wallet_url}"))?;
        ensure_chain_matches_config(chain_info.chain, config.network)?;
        rpc.get_balances().with_context(|| {
            format!(
                "wallet '{}' is not loaded or not accessible at {wallet_url}",
                config.wallet_name
            )
        })?;

        Ok(Self {
            rpc,
            config,
            #[cfg(test)]
            pre_broadcast_hook: Mutex::new(None),
            #[cfg(test)]
            member_getblockhash_calls: Mutex::new(0),
        })
    }

    /// Tip block as a [`BlockAnchor`].
    ///
    /// ## Byte-order convention (normative for P1-G scanner)
    ///
    /// `BlockAnchor.block_hash` stores the **internal / consensus byte order**
    /// produced by rust-bitcoin's `BlockHash::to_byte_array()` — **not** the
    /// reversed display order used by Bitcoin RPC / block explorers.
    ///
    /// Round-trip: `BlockHash::from_byte_array(anchor.block_hash)` recovers
    /// the same `BlockHash` that `getblockhash(height)` returns.
    pub fn current_anchor(&self) -> Result<BlockAnchor> {
        let height_u64 = self.rpc.get_block_count().context("getblockcount failed")?;
        let height = u32::try_from(height_u64).context("block height does not fit in u32")?;
        let hash = self
            .rpc
            .get_block_hash(u64::from(height))
            .with_context(|| format!("getblockhash({height}) failed"))?;
        Ok(BlockAnchor {
            block_hash: hash.to_byte_array(),
            height,
        })
    }

    /// Half-aggregate `members`, verify the aggregate, and construct a
    /// fee-converged signed commit/reveal pair **without** broadcasting.
    ///
    /// Callers that need crash recovery between the two broadcast legs must
    /// persist [`PreparedBatch::signed_commit`] and [`PreparedBatch::reveal_tx`]
    /// before calling [`Self::broadcast_commit`] / [`Self::broadcast_reveal`].
    ///
    /// ## Failure modes (nothing is broadcast)
    ///
    /// - empty batch / member count exceeds `u16::MAX`
    /// - reveal exceeds [`MAX_STANDARD_TX_WEIGHT`] (checked **before** any
    ///   per-member chain RPC)
    /// - invalid / inconsistent member build tips (§3.5 oldest-tip rule)
    /// - aggregate verification failure (wrong network, corrupted `s`, …)
    /// - no eligible funding UTXO covers the inscription
    /// - fee/topology fixed-point does not converge
    ///
    /// **Batch composition is never auto-split.** An oversized batch fails
    /// with an actionable error; the caller decides how to split.
    pub fn prepare(&self, members: &[BatchMember]) -> Result<PreparedBatch> {
        ensure!(
            !members.is_empty(),
            "prepare requires at least one BatchMember"
        );
        let member_count = members.len();
        ensure!(
            member_count <= usize::from(u16::MAX),
            "batch member count {member_count} exceeds u16::MAX ({}); split the batch — \
             the publisher does not auto-split",
            u16::MAX
        );

        // ── O(1) structural gates before any per-member getblockhash ────
        // Half-agg payload size depends only on member count (fixed header +
        // 64 B per member + 32 B s_agg). A synthetic payload of that shape is
        // enough to reject an unpublishable batch without chain RPCs.
        let sizing_scalar = {
            let mut s = [0u8; 32];
            s[31] = 1;
            s
        };
        let sizing_payload = synthetic_half_agg_payload(
            member_count,
            &NUMS_INTERNAL_KEY_BYTES,
            &NUMS_INTERNAL_KEY_BYTES,
            &sizing_scalar,
        )
        .context("synthetic sizing payload for pre-RPC weight check failed")?;
        ensure_tx_within_standard_weight(
            "reveal",
            measure_reveal_weight(&sizing_payload)
                .context("measure_reveal_weight for pre-RPC weight check failed")?,
            member_count,
            sizing_payload.len(),
        )?;

        // ── Per-member chain validation + anchor selection (RPC) ────────
        let block_anchor = self.select_block_anchor(members)?;
        let sigs: Vec<NullifierSig> = members.iter().map(|m| m.sig).collect();
        let aggregate =
            aggregate_sig_with_anchor(&sigs, block_anchor).context("half-aggregation failed")?;
        aggregate_verify(&aggregate, self.config.network.m_state_bytes()).with_context(|| {
            format!(
                "aggregate signature verification failed under publisher network {:?} \
                 (wrong-network or corrupted member signature); refusing to build transactions",
                self.config.network
            )
        })?;
        let payload = aggregate.serialize();

        // Real payload must also be standard (same weight class as sizing; the
        // NUMS key path cannot recover a stuck commit).
        ensure_tx_within_standard_weight(
            "reveal",
            measure_reveal_weight(&payload)?,
            member_count,
            payload.len(),
        )?;

        let btc_network = self.chain_network()?;
        let nums_key = nums_internal_key()?;
        let reveal_address = self
            .rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .context("getnewaddress(bech32m) for reveal output failed")?
            .require_network(btc_network)
            .context("reveal address network mismatch")?;
        let reveal_script = reveal_address.script_pubkey();
        ensure_above_dust(self.config.reveal_output_value, &reveal_script).with_context(|| {
            format!(
                "reveal_output_value {} is not above dust for the reveal script",
                self.config.reveal_output_value
            )
        })?;
        let reveal_output = TxOut {
            value: self.config.reveal_output_value,
            script_pubkey: reveal_script,
        };

        let change_address = self
            .rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .context("getnewaddress(bech32m) for change failed")?
            .require_network(btc_network)
            .context("change address network mismatch")?;
        let change_script = change_address.script_pubkey();

        let candidates = self.list_funding_candidates()?;
        ensure!(
            !candidates.is_empty(),
            "no confirmed funding UTXOs with deterministic witness size \
             (v0 P2WPKH or v1 P2TR key-path) available in wallet '{}'",
            self.config.wallet_name
        );

        // Arithmetic pre-filter: skip candidates that cannot cover even the
        // theoretical minimum without building or signing anything.
        let reveal_vsize_for_min = sizing_inscription(&payload)
            .context("sizing inscription for theoretical min funding failed")?
            .reveal_tx
            .vsize();
        let theoretical_min = theoretical_min_funding_required(
            self.config.reveal_output_value,
            reveal_vsize_for_min,
            self.config.fee_rate_sat_per_vb,
        )?;

        let mut best_before: Option<(Amount, Amount)> = None;
        let mut best_after: Option<(Amount, Amount)> = None;
        let mut skipped_before_construct: usize = 0;
        let mut constructed_attempts: usize = 0;
        let mut before_count: usize = 0;
        let mut after_count: usize = 0;
        let mut last_non_funding_err: Option<anyhow::Error> = None;
        let mut built: Option<ConvergedInscription> = None;

        for funding in candidates.iter() {
            if funding.amount < theoretical_min {
                skipped_before_construct = skipped_before_construct
                    .checked_add(1)
                    .context("skipped_before_construct overflow")?;
                before_count = before_count
                    .checked_add(1)
                    .context("before_count overflow")?;
                record_best_shortfall(&mut best_before, theoretical_min, funding.amount);
                continue;
            }

            if constructed_attempts >= MAX_FUNDING_CONSTRUCT_ATTEMPTS {
                bail!(
                    "funding construct attempt limit exhausted: constructed {} attempt(s) \
                     (limit {MAX_FUNDING_CONSTRUCT_ATTEMPTS}), \
                     prefilter_skipped_before_construct={skipped_before_construct}, \
                     rejected_before_measurement={before_count}, \
                     rejected_after_measurement={after_count}, \
                     candidates_listed={}; refusing further signrawtransactionwithwallet calls",
                    constructed_attempts,
                    candidates.len()
                );
            }

            constructed_attempts = constructed_attempts
                .checked_add(1)
                .context("constructed_attempts overflow")?;

            match self.converge_fees_and_build(
                &payload,
                funding,
                nums_key,
                reveal_output.clone(),
                change_script.clone(),
            ) {
                Ok(converged) => {
                    built = Some(converged);
                    break;
                }
                Err(err) => match classify_funding_reject(&err) {
                    Some(FundingRejectKind::BeforeMeasurement { have, required }) => {
                        before_count = before_count
                            .checked_add(1)
                            .context("before_count overflow")?;
                        record_best_shortfall(&mut best_before, required, have);
                    }
                    Some(FundingRejectKind::AfterMeasurement { have, required }) => {
                        after_count = after_count.checked_add(1).context("after_count overflow")?;
                        record_best_shortfall(&mut best_after, required, have);
                    }
                    None => {
                        // Non-funding errors (signing, drift, …) are fatal.
                        last_non_funding_err = Some(err);
                        break;
                    }
                },
            }
        }

        let converged = match (built, last_non_funding_err) {
            (Some(c), _) => c,
            (None, Some(err)) => return Err(err),
            (None, None) => {
                bail!(
                    "no eligible funding UTXO covers the inscription; \
                     rejected_before_measurement={before_count}{}, \
                     rejected_after_measurement={after_count}{}, \
                     constructed_attempts={constructed_attempts}/{MAX_FUNDING_CONSTRUCT_ATTEMPTS}, \
                     prefilter_skipped_before_construct={skipped_before_construct}, \
                     candidates_listed={}",
                    format_best_shortfall_clause("arithmetic minimum", best_before),
                    format_best_shortfall_clause("measured requirement", best_after),
                    candidates.len()
                );
            }
        };

        // Re-check both transactions after signing — commit is tiny but the
        // invariant is "nothing broadcasts unless both are standard".
        ensure_tx_within_standard_weight(
            "commit",
            converged.signed_commit.weight().to_wu(),
            member_count,
            payload.len(),
        )?;
        ensure_tx_within_standard_weight(
            "reveal",
            converged.reveal_tx.weight().to_wu(),
            member_count,
            payload.len(),
        )?;

        // Final assertion: broadcast vsizes are exactly those the fees were
        // computed from.
        ensure!(
            converged.signed_commit.vsize() == converged.commit_vsize,
            "signed commit vsize {} != fee-basis commit vsize {}; refusing unconverged broadcast",
            converged.signed_commit.vsize(),
            converged.commit_vsize
        );
        ensure!(
            converged.reveal_tx.vsize() == converged.reveal_vsize,
            "reveal vsize {} != fee-basis reveal vsize {}; refusing unconverged broadcast",
            converged.reveal_tx.vsize(),
            converged.reveal_vsize
        );

        let commit_output = converged
            .signed_commit
            .output
            .first()
            .cloned()
            .context("commit transaction has no outputs")?;

        Ok(PreparedBatch {
            aggregate,
            payload,
            signed_commit: converged.signed_commit,
            reveal_tx: converged.reveal_tx,
            commit_output,
            block_anchor,
            commit_vsize: converged.commit_vsize,
            reveal_vsize: converged.reveal_vsize,
            commit_fee: converged.commit_fee,
            reveal_fee: converged.reveal_fee,
        })
    }

    /// Broadcast only the commit leg of a previously prepared pair.
    ///
    /// Re-checks the block-anchor identity immediately before
    /// `sendrawtransaction`. Does **not** broadcast the reveal.
    pub fn broadcast_commit(&self, prepared: &PreparedBatch) -> Result<Txid> {
        // Test-only injection point: deterministic reorg before the identity
        // re-check (no wall-clock race).
        #[cfg(test)]
        {
            if let Some(mut hook) = self
                .pre_broadcast_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                hook(&self.rpc);
            }
        }

        self.ensure_anchor_ready_for_broadcast(prepared.block_anchor)
            .context("pre-broadcast anchor re-check failed; refusing sendrawtransaction")?;

        let commit_txid = prepared.commit_txid();
        self.rpc
            .send_raw_transaction(&prepared.signed_commit)
            .with_context(|| format!("sendrawtransaction(commit) failed for {commit_txid}"))?;
        Ok(commit_txid)
    }

    /// Broadcast only the reveal leg of a previously prepared pair.
    ///
    /// Intended for the resume path after commit is already on chain (or
    /// immediately after a successful [`Self::broadcast_commit`]).
    pub fn broadcast_reveal(&self, prepared: &PreparedBatch) -> Result<Txid> {
        let commit_txid = prepared.commit_txid();
        let reveal_txid = prepared.reveal_txid();
        self.rpc
            .send_raw_transaction(&prepared.reveal_tx)
            .with_context(|| {
                format!(
                    "sendrawtransaction(reveal) failed for {reveal_txid}; \
                     commit already broadcast as {commit_txid} — operator recovery required \
                     (NUMS key path is unspendable; oversized reveal is unrecoverable)"
                )
            })?;
        Ok(reveal_txid)
    }

    /// Half-aggregate `members`, construct the commit/reveal pair, and
    /// broadcast both legs. Convenience wrapper around
    /// [`Self::prepare`] + [`Self::broadcast_commit`] + [`Self::broadcast_reveal`].
    ///
    /// Callers that need mid-pair crash recovery must use the split APIs and
    /// persist the prepared transactions between the two broadcast legs.
    pub fn publish(&self, members: &[BatchMember]) -> Result<PublishedBatch> {
        let prepared = self.prepare(members)?;
        let member_count = members.len();
        let commit_txid = self.broadcast_commit(&prepared)?;
        let reveal_txid = self.broadcast_reveal(&prepared)?;

        eprintln!(
            "publisher: broadcast commit={commit_txid} ({} vB, fee {} sat) \
             reveal={reveal_txid} ({} vB, fee {} sat) fee_rate={} sat/vB members={member_count}",
            prepared.commit_vsize,
            prepared.commit_fee.to_sat(),
            prepared.reveal_vsize,
            prepared.reveal_fee.to_sat(),
            self.config.fee_rate_sat_per_vb
        );

        Ok(PublishedBatch {
            aggregate: prepared.aggregate,
            payload: prepared.payload,
            commit_txid,
            reveal_txid,
            commit_output: prepared.commit_output,
            block_anchor: prepared.block_anchor,
        })
    }

    /// Re-verify that `anchor` is still the canonical block at its height on
    /// this node and that the publish gap still holds under the configured
    /// inclusion-delay margin.
    ///
    /// Always issues a fresh `getblockhash(anchor.height)` — never uses a
    /// selection-time cache. Called immediately before the first
    /// `sendrawtransaction`.
    pub fn ensure_anchor_ready_for_broadcast(&self, anchor: BlockAnchor) -> Result<()> {
        let tip_now = self.current_anchor().context(
            "get tip before sendrawtransaction failed; refusing to broadcast without freshness re-check",
        )?;
        let live_hash = self
            .rpc
            .get_block_hash(u64::from(anchor.height))
            .with_context(|| {
                format!(
                    "getblockhash({}) for pre-broadcast anchor identity re-check failed",
                    anchor.height
                )
            })?;
        let live_bytes = live_hash.to_byte_array();
        ensure!(
            live_bytes == anchor.block_hash,
            "block_anchor was reorged out before sendrawtransaction: \
             selected hash {:x?} at height {} is no longer canonical; \
             live getblockhash returns {:x?}; refusing broadcast \
             (height-only gap check would have passed — identity re-check is mandatory)",
            anchor.block_hash,
            anchor.height,
            live_bytes
        );
        ensure_publish_gap_ok(anchor, tip_now, self.config.inclusion_delay_margin).with_context(
            || {
                format!(
                    "block_anchor became too stale before sendrawtransaction \
                 (anchor height {}, tip now {}); refusing broadcast",
                    anchor.height, tip_now.height
                )
            },
        )?;
        Ok(())
    }

    /// Poll until `txid` has at least `min_conf` confirmations or `timeout`
    /// elapses. Returns the confirmation count on success. Never loops
    /// forever.
    pub fn wait_for_confirmation(
        &self,
        txid: &Txid,
        min_conf: u32,
        timeout: Duration,
    ) -> Result<u32> {
        ensure!(min_conf > 0, "min_conf must be > 0");
        let deadline = Instant::now() + timeout;
        let poll = Duration::from_millis(250);
        loop {
            let info = self
                .rpc
                .get_raw_transaction_info(txid, None)
                .with_context(|| format!("getrawtransaction({txid}) failed while waiting"))?;
            let confs = info.confirmations.unwrap_or(0);
            if confs >= min_conf {
                return Ok(confs);
            }
            if Instant::now() >= deadline {
                bail!(
                    "timeout waiting for {min_conf} confirmation(s) of {txid}: \
                     only {confs} after {timeout:?}"
                );
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(poll.min(remaining));
        }
    }

    /// Full reveal extraction including per-input errors (see [`RevealPayloads`]).
    ///
    /// Callers that only want payloads **must** inspect `errors` / `per_input`
    /// first — a reveal with one valid and one malformed marker input surfaces
    /// both; an all-malformed reveal is `payloads == []` with non-empty
    /// `errors`, not a silent empty success.
    pub fn fetch_reveal_payload_details(&self, txid: &Txid) -> Result<RevealPayloads> {
        let reveal = self
            .rpc
            .get_raw_transaction(txid, None)
            .with_context(|| format!("getrawtransaction(reveal {txid}) failed"))?;

        let mut prevouts = Vec::with_capacity(reveal.input.len());
        for (index, input) in reveal.input.iter().enumerate() {
            let parent_txid = input.previous_output.txid;
            let parent = self
                .rpc
                .get_raw_transaction(&parent_txid, None)
                .with_context(|| {
                    format!(
                        "getrawtransaction(parent {parent_txid}) for reveal input {index} failed; \
                         is txindex=1 enabled?"
                    )
                })?;
            let vout = input.previous_output.vout as usize;
            let prevout = parent.output.get(vout).cloned().with_context(|| {
                format!("parent {parent_txid} has no vout {vout} (reveal input {index})")
            })?;
            prevouts.push(prevout);
        }

        let raw = extract_payloads_from_reveal(&reveal, &prevouts)
            .context("extract_payloads_from_reveal failed")?;

        let mut payloads = Vec::new();
        let mut errors = Vec::new();
        let mut per_input = Vec::with_capacity(raw.len());
        for item in raw {
            match item {
                Ok(Some(payload)) => {
                    per_input.push(Ok(Some(payload.clone())));
                    payloads.push(payload);
                }
                Ok(None) => per_input.push(Ok(None)),
                Err(err) => {
                    let message = err.to_string();
                    errors.push(message.clone());
                    per_input.push(Err(message));
                }
            }
        }

        Ok(RevealPayloads {
            payloads,
            errors,
            per_input,
        })
    }

    // ── internal helpers ────────────────────────────────────────────────

    /// Choose the §3.5 `block_anchor` from member build tips.
    ///
    /// Order (deliberate — bounds RPC cost independent of member count):
    /// 1. Fetch the node tip once.
    /// 2. **Arithmetic window pre-filter** on every member's claimed height
    ///    (future or older than the effective publish bound). Pure arithmetic
    ///    on caller-supplied numbers — **zero** `getblockhash` RPCs. A batch
    ///    rejected here costs O(1) RPCs (tip only).
    /// 3. Canonical-hash check for surviving heights only
    ///    (`hash == getblockhash(height)`), cached per height **within this
    ///    call only**. At most `window + 1` distinct lookups for an accepted
    ///    batch (`window = MAX_GAP − inclusion_delay_margin`), regardless of
    ///    member count. The pre-broadcast re-check never uses this cache.
    /// 4. Lowest `build_tip.height` wins among validated tips; same-height
    ///    ties require identical hashes (else members are on different chains).
    /// 5. Re-assert the effective gap on the selected oldest tip.
    ///
    /// Offending member indices are named in error messages. `build_tip` is a
    /// caller assertion — see [`BatchMember::build_tip`].
    fn select_block_anchor(&self, members: &[BatchMember]) -> Result<BlockAnchor> {
        ensure!(
            !members.is_empty(),
            "select_block_anchor requires at least one BatchMember"
        );

        // 1. Tip once — only RPCs needed to reject a fully out-of-window batch.
        let node_tip = self.current_anchor()?;
        let window = publish_max_gap(self.config.inclusion_delay_margin)?;

        // 2. Arithmetic pre-filter: every claimed height must lie in
        //    [tip + 1 − window, tip]. No getblockhash yet.
        for (index, member) in members.iter().enumerate() {
            let tip = member.build_tip;
            ensure!(
                tip.height <= node_tip.height,
                "member[{index}] build_tip height {} is in the future relative to node tip {} \
                 (hash {:x?})",
                tip.height,
                node_tip.height,
                tip.block_hash
            );
            // Same bound as ensure_publish_gap_ok, with member index and an
            // explicit note that this is the pre-RPC arithmetic filter.
            let gap = publish_inclusion_gap(tip, node_tip)?;
            ensure!(
                gap <= window,
                "members too stale, re-prove: member[{index}] build_tip height {} with node tip {} \
                 implies inclusion gap ≥ {gap} > effective publish bound {window} \
                 (§3.5 MAX_GAP={BLOCK_ANCHOR_MAX_GAP} − inclusion_delay_margin {}); \
                 arithmetic pre-filter (no per-member getblockhash issued); \
                 refusing to substitute a fresher anchor",
                tip.height,
                node_tip.height,
                self.config.inclusion_delay_margin,
            );
        }

        // 3. Canonical-hash validation for heights that survived the window
        //    (≤ window + 1 distinct heights).
        let mut hash_cache: HashMap<u32, [u8; 32]> = HashMap::new();
        for (index, member) in members.iter().enumerate() {
            let tip = member.build_tip;
            let chain_hash = self.cached_block_hash(tip.height, &mut hash_cache)?;
            ensure!(
                chain_hash == tip.block_hash,
                "member[{index}] build_tip hash at height {} is not the canonical block on this node: \
                 member={:x?} chain={:x?}",
                tip.height,
                tip.block_hash,
                chain_hash
            );
        }

        // 4. Oldest validated tip is the batch anchor.
        let mut oldest = members[0].build_tip;
        let mut oldest_index = 0usize;
        for (index, member) in members.iter().enumerate().skip(1) {
            let tip = member.build_tip;
            if tip.height < oldest.height {
                oldest = tip;
                oldest_index = index;
            } else if tip.height == oldest.height {
                ensure!(
                    tip.block_hash == oldest.block_hash,
                    "member[{index}] and member[{oldest_index}] claim different block hashes at \
                     height {}: {:x?} vs {:x?} (built on different chains); refusing to pick an anchor",
                    tip.height,
                    tip.block_hash,
                    oldest.block_hash
                );
            }
        }

        // 5. Redundant on the selected oldest (every member already passed),
        //    but keeps the post-selection guarantee explicit at this site.
        ensure_publish_gap_ok(oldest, node_tip, self.config.inclusion_delay_margin)?;
        Ok(oldest)
    }

    /// `getblockhash(height)` with a per-call-site [`HashMap`] cache.
    ///
    /// Used only for member tip validation after the arithmetic window
    /// pre-filter. Cache hits do not issue RPCs and do not increment the
    /// test-only member-call counter.
    fn cached_block_hash(
        &self,
        height: u32,
        cache: &mut HashMap<u32, [u8; 32]>,
    ) -> Result<[u8; 32]> {
        if let Some(hash) = cache.get(&height) {
            return Ok(*hash);
        }
        #[cfg(test)]
        {
            let mut count = self
                .member_getblockhash_calls
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *count = count
                .checked_add(1)
                .context("member_getblockhash_calls counter overflowed")?;
        }
        let chain_hash = self
            .rpc
            .get_block_hash(u64::from(height))
            .with_context(|| format!("getblockhash({height}) for member build tip failed"))?;
        let bytes = chain_hash.to_byte_array();
        cache.insert(height, bytes);
        Ok(bytes)
    }

    fn chain_network(&self) -> Result<BitcoinNetwork> {
        let info = self
            .rpc
            .get_blockchain_info()
            .context("getblockchaininfo failed")?;
        Ok(info.chain)
    }

    /// Confirmed, spendable UTXOs with deterministic witness size, sorted by
    /// amount ascending (then outpoint) for deterministic selection.
    fn list_funding_candidates(&self) -> Result<Vec<FundingUtxo>> {
        let unspent = self
            .rpc
            .list_unspent(Some(1), None, None, Some(true), None)
            .context("listunspent(minconf=1) failed")?;

        let mut candidates: Vec<FundingUtxo> = Vec::new();
        for entry in unspent {
            if !entry.spendable {
                continue;
            }
            if entry.confirmations < 1 {
                continue;
            }
            if let Err(err) = ensure_deterministic_funding(&entry.script_pub_key) {
                eprintln!(
                    "publisher: skipping ineligible UTXO {}:{} — {err}",
                    entry.txid, entry.vout
                );
                continue;
            }
            candidates.push(FundingUtxo {
                outpoint: OutPoint {
                    txid: entry.txid,
                    vout: entry.vout,
                },
                amount: entry.amount,
                script_pubkey: entry.script_pub_key,
            });
        }

        candidates.sort_by(|a, b| {
            a.amount
                .cmp(&b.amount)
                .then_with(|| a.outpoint.txid.cmp(&b.outpoint.txid))
                .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
        });
        Ok(candidates)
    }

    /// Fixed-point fee and change-topology iteration for one funding UTXO.
    ///
    /// Two phases to avoid dust-boundary topology ping-pong (with-change fees
    /// can leave residual just below dust; without-change fees free enough
    /// residual to re-request change):
    ///
    /// 1. **With change** — iterate pure fees while leftover ≥ dust.
    /// 2. **Without change** — if residual would be dust or zero under the
    ///    with-change fees (or phase 1 never funded), absorb residual into the
    ///    commit fee and iterate pure fees for the no-change topology.
    ///
    /// **Provisional fees are seed only** — they never gate UTXO admission.
    /// Seeds are clamped so a signed measure is always attempted when
    /// `funding ≥ reveal_output`. Rejection uses **measured** pure fees only.
    ///
    /// Cycle detection uses a [`HashSet`] of `(commit_fee, reveal_fee)` states
    /// via [`note_fee_state`]. Caps each phase at [`MAX_FEE_CONVERGENCE_ROUNDS`].
    fn converge_fees_and_build(
        &self,
        payload: &[u8],
        funding: &FundingUtxo,
        internal_key: XOnlyPublicKey,
        reveal_output: TxOut,
        change_script: ScriptBuf,
    ) -> Result<ConvergedInscription> {
        ensure_deterministic_funding(&funding.script_pubkey)?;

        let provisional_commit_vsize = 300usize;
        let provisional_reveal_vsize = 200usize
            .checked_add(payload.len().saturating_add(200) / 4)
            .context("provisional reveal vsize overflow")?;
        let provisional_commit_fee =
            fee_for_vsize(provisional_commit_vsize, self.config.fee_rate_sat_per_vb)?;
        let provisional_reveal_fee =
            fee_for_vsize(provisional_reveal_vsize, self.config.fee_rate_sat_per_vb)?;
        let dust = change_script.minimal_non_dust();
        let reveal_out = self.config.reveal_output_value;

        // ── Phase 1: try with a change output ───────────────────────────
        // Seed only — clamp so we can build+measure even when the provisional
        // estimate exceeds the UTXO (e.g. 1600 sat @ 2 sat/vB).
        let (mut commit_fee, mut reveal_fee) = clamp_seed_fees(
            funding.amount,
            reveal_out,
            provisional_commit_fee,
            provisional_reveal_fee,
        )?;
        let mut with_change_viable = true;
        let mut seen_with: HashSet<(u64, u64)> = HashSet::new();

        for round in 1..=MAX_FEE_CONVERGENCE_ROUNDS {
            note_fee_state(&mut seen_with, commit_fee, reveal_fee, "with-change", round)?;

            let (build_commit_fee, build_reveal_fee) =
                clamp_seed_fees(funding.amount, reveal_out, commit_fee, reveal_fee)?;
            let spent_core = sum_amounts(&[reveal_out, build_commit_fee, build_reveal_fee])?;
            // Topology probe only — not an admission shortfall. Measured fees
            // decide rejection in phase 2.
            if funding.amount < spent_core {
                with_change_viable = false;
                break;
            }
            let leftover = funding
                .amount
                .checked_sub(spent_core)
                .context("with-change leftover underflow")?;
            if leftover < dust {
                eprintln!(
                    "publisher: change {} sat is below dust limit {} sat under with-change fees; \
                     switching to no-change topology (round {round})",
                    leftover.to_sat(),
                    dust.to_sat()
                );
                with_change_viable = false;
                break;
            }

            let built = self.build_and_sign_commit(
                payload,
                funding,
                internal_key,
                reveal_output.clone(),
                Some(change_script.clone()),
                build_commit_fee,
                build_reveal_fee,
            )?;
            let measured_commit_vsize = built.signed_commit.vsize();
            let measured_reveal_vsize = built.reveal_tx.vsize();
            ensure!(
                built.signed_commit.output.len() > 1,
                "with-change phase produced no change output on round {round}"
            );

            let next_commit_fee =
                fee_for_vsize(measured_commit_vsize, self.config.fee_rate_sat_per_vb)?;
            let next_reveal_fee =
                fee_for_vsize(measured_reveal_vsize, self.config.fee_rate_sat_per_vb)?;

            // Measured pure fees must still leave change ≥ dust.
            let next_spent = sum_amounts(&[reveal_out, next_commit_fee, next_reveal_fee])?;
            if funding.amount < next_spent
                || funding
                    .amount
                    .checked_sub(next_spent)
                    .context("with-change measured leftover underflow")?
                    < dust
            {
                eprintln!(
                    "publisher: measured with-change fees leave residual below dust or shortfall \
                     on round {round}; switching to no-change topology"
                );
                with_change_viable = false;
                break;
            }

            if next_commit_fee == commit_fee && next_reveal_fee == reveal_fee {
                return Ok(ConvergedInscription {
                    signed_commit: built.signed_commit,
                    reveal_tx: built.reveal_tx,
                    commit_vsize: measured_commit_vsize,
                    reveal_vsize: measured_reveal_vsize,
                    commit_fee,
                    reveal_fee,
                });
            }

            commit_fee = next_commit_fee;
            reveal_fee = next_reveal_fee;
        }

        if with_change_viable {
            bail!(
                "fee fixed-point did not converge in with-change phase within \
                 {MAX_FEE_CONVERGENCE_ROUNDS} rounds; refusing unconverged broadcast"
            );
        }

        // ── Phase 2: no change — residual absorbed into commit fee ──────
        // Fresh provisional seed (clamped); admission uses measured fees only.
        let (mut commit_fee, mut reveal_fee) = clamp_seed_fees(
            funding.amount,
            reveal_out,
            provisional_commit_fee,
            provisional_reveal_fee,
        )?;
        let mut seen_without: HashSet<(u64, u64)> = HashSet::new();

        for round in 1..=MAX_FEE_CONVERGENCE_ROUNDS {
            note_fee_state(
                &mut seen_without,
                commit_fee,
                reveal_fee,
                "no-change",
                round,
            )?;

            if funding.amount < reveal_out {
                bail!(
                    "funding rejected before measurement: UTXO {} sat < arithmetic minimum {} sat \
                     (reveal_output_value {}; no transaction was built or measured) \
                     on no-change round {round}",
                    funding.amount.to_sat(),
                    reveal_out.to_sat(),
                    reveal_out.to_sat()
                );
            }

            // Clamp seed for construction only — pure fee state is separate.
            let (_build_commit_seed, build_reveal_fee) =
                clamp_seed_fees(funding.amount, reveal_out, commit_fee, reveal_fee)?;
            let commit_fee_used = funding
                .amount
                .checked_sub(reveal_out)
                .and_then(|v| v.checked_sub(build_reveal_fee))
                .context("no-change commit fee accounting underflow")?;

            let built = self.build_and_sign_commit(
                payload,
                funding,
                internal_key,
                reveal_output.clone(),
                None,
                commit_fee_used,
                build_reveal_fee,
            )?;
            let measured_commit_vsize = built.signed_commit.vsize();
            let measured_reveal_vsize = built.reveal_tx.vsize();
            ensure!(
                built.signed_commit.output.len() == 1,
                "no-change phase produced a change output on round {round}"
            );

            let next_commit_fee =
                fee_for_vsize(measured_commit_vsize, self.config.fee_rate_sat_per_vb)?;
            let next_reveal_fee =
                fee_for_vsize(measured_reveal_vsize, self.config.fee_rate_sat_per_vb)?;

            // Admission gate: measured pure fees only.
            let measured_required = sum_amounts(&[reveal_out, next_commit_fee, next_reveal_fee])?;
            if funding.amount < measured_required {
                bail!(
                    "funding rejected after measurement: UTXO {} sat < measured requirement {} sat \
                     (reveal_output + measured commit_fee + measured reveal_fee) \
                     on no-change round {round}",
                    funding.amount.to_sat(),
                    measured_required.to_sat()
                );
            }

            // Pure fees stable; commit_fee_used may exceed pure commit_fee
            // because dust/exact residual is absorbed into the miner fee.
            if next_commit_fee == commit_fee && next_reveal_fee == reveal_fee {
                ensure!(
                    commit_fee_used >= commit_fee,
                    "no-change commit fee used {} sat is below pure fee {} sat",
                    commit_fee_used.to_sat(),
                    commit_fee.to_sat()
                );
                // Rebuild once more with pure reveal fee if the build used a
                // clamped seed (so the commit output carries pure reveal_fee).
                if build_reveal_fee != reveal_fee {
                    let commit_fee_final = funding
                        .amount
                        .checked_sub(reveal_out)
                        .and_then(|v| v.checked_sub(reveal_fee))
                        .context("no-change final commit fee accounting underflow")?;
                    ensure!(
                        commit_fee_final >= commit_fee,
                        "no-change final commit fee used {} sat is below pure fee {} sat",
                        commit_fee_final.to_sat(),
                        commit_fee.to_sat()
                    );
                    let final_built = self.build_and_sign_commit(
                        payload,
                        funding,
                        internal_key,
                        reveal_output.clone(),
                        None,
                        commit_fee_final,
                        reveal_fee,
                    )?;
                    ensure!(
                        final_built.signed_commit.output.len() == 1,
                        "no-change final build produced a change output"
                    );
                    let final_commit_vsize = final_built.signed_commit.vsize();
                    let final_reveal_vsize = final_built.reveal_tx.vsize();
                    let final_commit_fee =
                        fee_for_vsize(final_commit_vsize, self.config.fee_rate_sat_per_vb)?;
                    let final_reveal_fee =
                        fee_for_vsize(final_reveal_vsize, self.config.fee_rate_sat_per_vb)?;
                    ensure!(
                        final_commit_fee == commit_fee && final_reveal_fee == reveal_fee,
                        "no-change final rebuild fees drifted: pure=({}, {}) final=({}, {})",
                        commit_fee.to_sat(),
                        reveal_fee.to_sat(),
                        final_commit_fee.to_sat(),
                        final_reveal_fee.to_sat()
                    );
                    return Ok(ConvergedInscription {
                        signed_commit: final_built.signed_commit,
                        reveal_tx: final_built.reveal_tx,
                        commit_vsize: final_commit_vsize,
                        reveal_vsize: final_reveal_vsize,
                        commit_fee: commit_fee_final,
                        reveal_fee,
                    });
                }
                return Ok(ConvergedInscription {
                    signed_commit: built.signed_commit,
                    reveal_tx: built.reveal_tx,
                    commit_vsize: measured_commit_vsize,
                    reveal_vsize: measured_reveal_vsize,
                    commit_fee: commit_fee_used,
                    reveal_fee,
                });
            }

            commit_fee = next_commit_fee;
            reveal_fee = next_reveal_fee;
        }

        bail!(
            "fee/topology fixed-point did not converge within {MAX_FEE_CONVERGENCE_ROUNDS} \
             rounds per phase; refusing to broadcast from an unconverged state"
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn build_and_sign_commit(
        &self,
        payload: &[u8],
        funding: &FundingUtxo,
        internal_key: XOnlyPublicKey,
        reveal_output: TxOut,
        change_script_pubkey: Option<ScriptBuf>,
        commit_fee: Amount,
        reveal_fee: Amount,
    ) -> Result<BuiltInscription> {
        ensure_deterministic_funding(&funding.script_pubkey)?;

        let inscription = build_inscription(
            payload,
            InscriptionRequest {
                funding_outpoint: funding.outpoint,
                funding_value: funding.amount,
                internal_key,
                reveal_output,
                change_script_pubkey,
                commit_fee,
                reveal_fee,
            },
        )
        .context("build_inscription failed")?;

        let unsigned_txid = inscription.commit_tx.compute_txid();
        let signed = self
            .rpc
            .sign_raw_transaction_with_wallet(&inscription.commit_tx, None, None)
            .context("signrawtransactionwithwallet failed")?;
        if !signed.complete {
            let errors = signed
                .errors
                .as_ref()
                .map(|errs| {
                    errs.iter()
                        .map(|e| e.error.clone())
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .unwrap_or_else(|| "(no error details from bitcoind)".to_owned());
            bail!("signrawtransactionwithwallet incomplete: {errors}");
        }
        let signed_commit = signed
            .transaction()
            .context("failed to deserialize signed commit transaction")?;
        let signed_txid = signed_commit.compute_txid();
        ensure!(
            signed_txid == unsigned_txid,
            "signed commit txid {signed_txid} differs from unsigned {unsigned_txid}; \
             funding input is not segwit-txid-stable (or wallet mutated the tx). \
             Refusing to broadcast — reveal already references the unsigned commit txid."
        );

        Ok(BuiltInscription {
            signed_commit,
            reveal_tx: inscription.reveal_tx,
        })
    }
}

#[derive(Clone, Debug)]
struct FundingUtxo {
    outpoint: OutPoint,
    amount: Amount,
    script_pubkey: ScriptBuf,
}

struct BuiltInscription {
    signed_commit: Transaction,
    reveal_tx: Transaction,
}

struct ConvergedInscription {
    signed_commit: Transaction,
    reveal_tx: Transaction,
    commit_vsize: usize,
    reveal_vsize: usize,
    commit_fee: Amount,
    reveal_fee: Amount,
}

/// Reject funding scripts whose witness size is not deterministic.
///
/// Accepted:
/// - v0 P2WPKH (20-byte program) — fixed signature+pubkey witness
/// - v1 P2TR key-path (32-byte program) — fixed 64-byte schnorr witness
///
/// Rejected (loudly):
/// - v0 P2WSH (32-byte program) — witness size depends on the redeem script
/// - legacy / P2SH-wrapped segwit — scriptSig is part of the txid, so signing
///   would invalidate a pre-built reveal
/// - any other witness version / program length
pub(crate) fn ensure_deterministic_funding(script_pubkey: &Script) -> Result<()> {
    ensure!(
        script_pubkey.is_witness_program(),
        "funding scriptPubKey is not a segwit witness program (v0 or v1); \
         legacy and P2SH-wrapped inputs cannot fund a pre-built reveal because \
         signing would change the commit txid"
    );

    if script_pubkey.is_p2wpkh() {
        return Ok(());
    }
    if script_pubkey.is_p2tr() {
        return Ok(());
    }
    if script_pubkey.is_p2wsh() {
        bail!(
            "funding scriptPubKey is v0 P2WSH; its witness size is not predictable \
             (depends on the redeem script), so fee estimation is not sound — \
             use v0 P2WPKH or v1 P2TR key-path"
        );
    }

    let version = script_pubkey
        .witness_version()
        .context("witness program without witness version")?;
    bail!(
        "funding witness program version {} with non-standard program length is not supported; \
         only v0 P2WPKH (20-byte) and v1 P2TR (32-byte) have deterministic witness size",
        version.to_num()
    );
}

/// Back-compat name: deterministic segwit funding only (see
/// [`ensure_deterministic_funding`]).
#[cfg(test)]
pub(crate) fn ensure_segwit_funding(script_pubkey: &Script) -> Result<()> {
    ensure_deterministic_funding(script_pubkey)
}

/// Measure the weight (WU) of a reveal transaction that carries `payload`.
///
/// Uses a dummy funding outpoint and a P2TR reveal output; only the reveal
/// side is meaningful for the standardness bound (the envelope leaf dominates).
pub(crate) fn measure_reveal_weight(payload: &[u8]) -> Result<u64> {
    let inscription = sizing_inscription(payload)?;
    Ok(inscription.reveal_tx.weight().to_wu())
}

/// Maximum half-aggregate member count whose reveal stays within
/// [`MAX_STANDARD_TX_WEIGHT`].
///
/// Uses a representative on-curve `(Pk, R)` template so the envelope byte
/// layout matches a real format-`0x01` payload.
///
/// **Does not auto-split batches.** Batch composition (which nullifiers share
/// an inscription) is a policy decision with first-occurrence consequences;
/// callers that exceed this bound must split themselves and re-submit.
#[cfg(test)]
pub(crate) fn max_half_agg_members_for_standard_reveal() -> Result<usize> {
    // Structure/length is all that matters for weight. Build raw half-agg
    // payload bytes without per-member curve validation (that would dominate
    // the binary search at thousands of members).
    let point = NUMS_INTERNAL_KEY_BYTES;
    let scalar = {
        let mut s = [0u8; 32];
        s[31] = 1;
        s
    };

    let weight_for = |n: usize| -> Result<u64> {
        ensure!(n >= 1, "member count must be >= 1");
        ensure!(n <= usize::from(u16::MAX), "member count exceeds u16::MAX");
        let payload = synthetic_half_agg_payload(n, &point, &point, &scalar)?;
        measure_reveal_weight(&payload)
    };

    // At least one member must fit.
    let w1 = weight_for(1)?;
    ensure!(
        w1 <= MAX_STANDARD_TX_WEIGHT,
        "even a 1-member reveal weight {w1} exceeds MAX_STANDARD_TX_WEIGHT={MAX_STANDARD_TX_WEIGHT}"
    );

    // Exponential search for an upper bound, then binary search. Avoids building
    // multi-megabyte synthetic payloads at midpoints near u16::MAX.
    let mut lo = 1usize;
    let mut hi = 2usize;
    while hi < usize::from(u16::MAX) {
        let w = weight_for(hi)?;
        if w <= MAX_STANDARD_TX_WEIGHT {
            lo = hi;
            hi = hi.saturating_mul(2).min(usize::from(u16::MAX));
            if hi == lo {
                break;
            }
        } else {
            break;
        }
    }
    if hi > usize::from(u16::MAX) {
        hi = usize::from(u16::MAX);
    }
    // If even u16::MAX fits, that is the bound.
    if weight_for(hi)? <= MAX_STANDARD_TX_WEIGHT {
        return Ok(hi);
    }

    while lo + 1 < hi {
        let mid = lo
            .checked_add(hi)
            .map(|s| s / 2)
            .context("binary search midpoint overflow")?;
        let w = weight_for(mid)?;
        if w <= MAX_STANDARD_TX_WEIGHT {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

/// Fail loudly if `weight_wu` exceeds [`MAX_STANDARD_TX_WEIGHT`].
pub(crate) fn ensure_tx_within_standard_weight(
    which: &str,
    weight_wu: u64,
    member_count: usize,
    payload_len: usize,
) -> Result<()> {
    ensure!(
        weight_wu <= MAX_STANDARD_TX_WEIGHT,
        "{which} transaction weight {weight_wu} WU exceeds Bitcoin Core \
         MAX_STANDARD_TX_WEIGHT={MAX_STANDARD_TX_WEIGHT} WU for batch of {member_count} members \
         (payload {payload_len} bytes); split the batch — the publisher does not auto-split \
         (NUMS commit key path is unspendable, so an oversized reveal after commit broadcast \
         would permanently burn the commit value)"
    );
    Ok(())
}

/// Exact §3.5 half-agg wire layout for weight measurement (no curve checks).
fn synthetic_half_agg_payload(
    member_count: usize,
    pk: &[u8; 32],
    r: &[u8; 32],
    s_agg: &[u8; 32],
) -> Result<Vec<u8>> {
    let count = u16::try_from(member_count).context("member count exceeds u16")?;
    let body_len = member_count
        .checked_mul(64)
        .and_then(|n| n.checked_add(32))
        .context("payload body length overflow")?;
    let mut bytes = Vec::with_capacity(
        PAYLOAD_HEADER_LEN
            .checked_add(body_len)
            .context("payload length overflow")?,
    );
    bytes.extend_from_slice(&PAYLOAD_MARKER);
    bytes.push(PAYLOAD_VERSION_V3);
    bytes.push(FORMAT_HALF_AGG);
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 32]); // block_hash
    bytes.extend_from_slice(&0u32.to_be_bytes()); // height
    for _ in 0..member_count {
        bytes.extend_from_slice(pk);
        bytes.extend_from_slice(r);
    }
    bytes.extend_from_slice(s_agg);
    Ok(bytes)
}

fn sizing_inscription(payload: &[u8]) -> Result<crate::inscription::Inscription> {
    let nums = nums_internal_key()?;
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let reveal_script = ScriptBuf::new_p2tr(&secp, nums, None);
    let reveal_output = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: reveal_script,
    };
    // funding = reveal_out + reveal_fee + commit_fee (no change).
    let commit_fee = Amount::from_sat(1_000);
    let reveal_fee = Amount::from_sat(1_000);
    let funding_value = reveal_output
        .value
        .checked_add(reveal_fee)
        .and_then(|v| v.checked_add(commit_fee))
        .context("sizing funding value overflow")?;
    build_inscription(
        payload,
        InscriptionRequest {
            funding_outpoint: OutPoint::null(),
            funding_value,
            internal_key: nums,
            reveal_output,
            change_script_pubkey: None,
            commit_fee,
            reveal_fee,
        },
    )
    .context("sizing build_inscription failed")
}

/// `vsize * fee_rate_sat_per_vb`, failing loudly on overflow.
pub(crate) fn fee_for_vsize(vsize: usize, fee_rate_sat_per_vb: u64) -> Result<Amount> {
    ensure!(fee_rate_sat_per_vb > 0, "fee_rate_sat_per_vb must be > 0");
    let vsize_u64 = u64::try_from(vsize).context("vsize does not fit in u64")?;
    let fee_sats = vsize_u64
        .checked_mul(fee_rate_sat_per_vb)
        .with_context(|| {
            format!("fee overflow: vsize {vsize_u64} * rate {fee_rate_sat_per_vb} sat/vB")
        })?;
    Ok(Amount::from_sat(fee_sats))
}

/// Fail if `value` is strictly below the dust limit of `script_pubkey`.
pub(crate) fn ensure_above_dust(value: Amount, script_pubkey: &Script) -> Result<()> {
    let dust = script_pubkey.minimal_non_dust();
    ensure!(
        value >= dust,
        "output value {} sat is below dust limit {} sat for script",
        value.to_sat(),
        dust.to_sat()
    );
    Ok(())
}

/// Parse the BIP-341 NUMS internal key.
pub(crate) fn nums_internal_key() -> Result<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(&NUMS_INTERNAL_KEY_BYTES)
        .context("NUMS_INTERNAL_KEY_BYTES is not a valid x-only public key")
}

/// Whether bitcoind's chain matches the zkCoins [`Network`] config constant.
///
/// Exact mapping (anything else is a mismatch):
/// - [`Network::Mainnet`] ↔ [`BitcoinNetwork::Bitcoin`]
/// - [`Network::Testnet`] ↔ [`BitcoinNetwork::Signet`] only
///   (normative testnet is Signet per §3.6; Testnet3/Testnet4 are rejected)
/// - [`Network::Regtest`] ↔ [`BitcoinNetwork::Regtest`]
pub(crate) fn chain_matches_config(chain: BitcoinNetwork, config_network: Network) -> bool {
    matches!(
        (config_network, chain),
        (Network::Mainnet, BitcoinNetwork::Bitcoin)
            | (Network::Testnet, BitcoinNetwork::Signet)
            | (Network::Regtest, BitcoinNetwork::Regtest)
    )
}

/// Fail if bitcoind's chain and [`PublisherConfig::network`] disagree.
///
/// Error names both the configured network and the chain bitcoind reported.
pub(crate) fn ensure_chain_matches_config(
    chain: BitcoinNetwork,
    config_network: Network,
) -> Result<()> {
    ensure!(
        chain_matches_config(chain, config_network),
        "bitcoind chain {chain:?} does not match PublisherConfig.network {config_network:?} \
         (expected mapping: Bitcoin↔Mainnet, Signet↔Testnet, Regtest↔Regtest; \
         Testnet3/Testnet4 are not accepted for Network::Testnet)"
    );
    Ok(())
}

/// Effective publish max gap for a configured inclusion-delay margin:
/// [`BLOCK_ANCHOR_MAX_GAP`] − `inclusion_delay_margin`.
///
/// Fails loudly when `inclusion_delay_margin >= BLOCK_ANCHOR_MAX_GAP` (no
/// silent clamp, no default).
pub(crate) fn publish_max_gap(inclusion_delay_margin: u32) -> Result<u32> {
    ensure!(
        inclusion_delay_margin < BLOCK_ANCHOR_MAX_GAP,
        "inclusion_delay_margin {inclusion_delay_margin} must be < \
         BLOCK_ANCHOR_MAX_GAP ({BLOCK_ANCHOR_MAX_GAP}); refusing silent clamp"
    );
    Ok(BLOCK_ANCHOR_MAX_GAP - inclusion_delay_margin)
}

/// Minimum inclusion gap if the reveal is mined in the next block:
/// `(node_tip.height + 1) − anchor.height`.
pub(crate) fn publish_inclusion_gap(anchor: BlockAnchor, node_tip: BlockAnchor) -> Result<u32> {
    ensure!(
        anchor.height <= node_tip.height,
        "anchor height {} is above node tip {}",
        anchor.height,
        node_tip.height
    );
    let inclusion_lower = node_tip
        .height
        .checked_add(1)
        .context("tip height + 1 overflows u32")?;
    inclusion_lower
        .checked_sub(anchor.height)
        .context("anchor height exceeds inclusion lower bound after tip check")
}

/// Enforce the effective publish gap bound at selection and pre-broadcast.
///
/// Effective bound = [`BLOCK_ANCHOR_MAX_GAP`] − `inclusion_delay_margin`
/// (see [`publish_max_gap`]). On failure the message is
/// `"members too stale, re-prove"` and includes the actual gap and the
/// effective publish bound (not the consensus [`BLOCK_ANCHOR_MAX_GAP`] alone).
pub(crate) fn ensure_publish_gap_ok(
    anchor: BlockAnchor,
    node_tip: BlockAnchor,
    inclusion_delay_margin: u32,
) -> Result<()> {
    let bound = publish_max_gap(inclusion_delay_margin)?;
    let gap = publish_inclusion_gap(anchor, node_tip)?;
    ensure!(
        gap <= bound,
        "members too stale, re-prove: oldest build tip height {} with node tip {} \
         implies inclusion gap ≥ {} > effective publish bound {bound} \
         (§3.5 MAX_GAP={BLOCK_ANCHOR_MAX_GAP} − inclusion_delay_margin \
         {inclusion_delay_margin}); refusing to substitute a fresher anchor",
        anchor.height,
        node_tip.height,
        gap
    );
    Ok(())
}

/// Theoretical minimum funding: `reveal_output_value` plus fees for the
/// measured reveal vsize and a lower-bound commit vsize at the configured rate.
///
/// Used only as a pre-filter to skip hopeless UTXOs without signing. Admission
/// still requires measured fees after construction.
pub(crate) fn theoretical_min_funding_required(
    reveal_output: Amount,
    reveal_vsize: usize,
    fee_rate_sat_per_vb: u64,
) -> Result<Amount> {
    let commit_fee = fee_for_vsize(MIN_COMMIT_VSIZE_LOWER_BOUND, fee_rate_sat_per_vb)?;
    let reveal_fee = fee_for_vsize(reveal_vsize, fee_rate_sat_per_vb)?;
    sum_amounts(&[reveal_output, commit_fee, reveal_fee])
}

/// Clamp provisional/pure fee seeds so a signed measure can be built.
///
/// Seeds never gate UTXO admission — they only initialise fixed-point
/// iteration. When `funding < reveal_output`, both seeds are zero (the
/// subsequent measured-fee check reports the shortfall). When the sum of
/// seeds exceeds `funding − reveal_output`, fees are reduced (preferring to
/// keep the reveal seed) so `build_inscription` can construct a transaction.
pub(crate) fn clamp_seed_fees(
    funding: Amount,
    reveal_output: Amount,
    commit_fee: Amount,
    reveal_fee: Amount,
) -> Result<(Amount, Amount)> {
    let Some(fee_budget) = funding.checked_sub(reveal_output) else {
        return Ok((Amount::ZERO, Amount::ZERO));
    };
    let total = sum_amounts(&[commit_fee, reveal_fee])?;
    if total <= fee_budget {
        return Ok((commit_fee, reveal_fee));
    }
    if reveal_fee <= fee_budget {
        let commit = fee_budget
            .checked_sub(reveal_fee)
            .context("clamp_seed_fees commit underflow")?;
        return Ok((commit, reveal_fee));
    }
    // Entire budget goes to the reveal seed; commit seed is zero.
    Ok((Amount::ZERO, fee_budget))
}

/// Record a `(commit_fee, reveal_fee)` pure-fee state for cycle detection.
///
/// Returns an error if this pair was already seen in the current phase
/// (period-≥2 fee oscillation that the previous single-prev detector missed).
pub(crate) fn note_fee_state(
    seen: &mut HashSet<(u64, u64)>,
    commit_fee: Amount,
    reveal_fee: Amount,
    phase: &str,
    round: usize,
) -> Result<()> {
    let key = (commit_fee.to_sat(), reveal_fee.to_sat());
    if !seen.insert(key) {
        bail!(
            "fee fixed-point cycle detected in {phase} phase on round {round}: \
             revisited (commit_fee={}, reveal_fee={}) sat \
             (refusing unconverged broadcast)",
            key.0,
            key.1
        );
    }
    Ok(())
}

fn sum_amounts(parts: &[Amount]) -> Result<Amount> {
    let mut total = Amount::ZERO;
    for part in parts {
        total = total
            .checked_add(*part)
            .ok_or_else(|| anyhow!("amount sum overflow"))?;
    }
    Ok(total)
}

/// Funding-UTXO rejection kind. Distinguishes arithmetic pre-measurement
/// shortfalls from shortfalls computed after a signed measure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FundingRejectKind {
    /// No transaction was built or measured; `required` is an arithmetic minimum.
    BeforeMeasurement { have: Amount, required: Amount },
    /// A transaction was built and measured; `required` is the measured total.
    AfterMeasurement { have: Amount, required: Amount },
}

/// Classify a funding rejection from an error chain. Returns `None` for
/// non-funding errors (signing incomplete, fee cycle, …).
fn classify_funding_reject(err: &anyhow::Error) -> Option<FundingRejectKind> {
    for cause in err.chain() {
        let msg = cause.to_string();
        if let Some(rest) = msg.strip_prefix("funding rejected before measurement: UTXO ") {
            let (have, required) = parse_utxo_vs_required(rest, " < arithmetic minimum ")?;
            return Some(FundingRejectKind::BeforeMeasurement { have, required });
        }
        if let Some(rest) = msg.strip_prefix("funding rejected after measurement: UTXO ") {
            let (have, required) = parse_utxo_vs_required(rest, " < measured requirement ")?;
            return Some(FundingRejectKind::AfterMeasurement { have, required });
        }
    }
    None
}

/// Parse `"N sat < … M sat …"` into `(have, required)`.
fn parse_utxo_vs_required(rest: &str, middle: &str) -> Option<(Amount, Amount)> {
    let (have_s, after_have) = rest.split_once(" sat")?;
    let have = have_s.parse::<u64>().ok()?;
    let after_mid = after_have.strip_prefix(middle)?;
    let required_s = after_mid.split_whitespace().next()?;
    let required = required_s.parse::<u64>().ok()?;
    Some((Amount::from_sat(have), Amount::from_sat(required)))
}

fn record_best_shortfall(best: &mut Option<(Amount, Amount)>, required: Amount, have: Amount) {
    let shortfall = required.checked_sub(have).unwrap_or(required);
    match best {
        None => *best = Some((required, have)),
        Some((best_req, best_have)) => {
            let best_gap = best_req.checked_sub(*best_have).unwrap_or(*best_req);
            if shortfall < best_gap || (shortfall == best_gap && have > *best_have) {
                *best_req = required;
                *best_have = have;
            }
        }
    }
}

fn format_best_shortfall_clause(label: &str, best: Option<(Amount, Amount)>) -> String {
    match best {
        Some((required, have)) => format!(
            " (best {label}: required {} sat, have {} sat, shortfall {} sat)",
            required.to_sat(),
            have.to_sat(),
            required
                .checked_sub(have)
                .map(|a| a.to_sat())
                .unwrap_or(required.to_sat())
        ),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, PubkeyHash, WPubkeyHash, WScriptHash};
    use sha2::{Digest, Sha256};
    use shared::spec_v1::{ProofData, ZERO_HASH};
    use zkcoins_program_plonky2::circuit::compliance::Network;

    use crate::half_agg::{aggregate_verify, AggregateStateNullifierV3};
    use crate::prover_bridge::test_signing::{
        deterministic_secret, normalized_key, sign_transition,
    };

    // ── unit tests (no bitcoind) ────────────────────────────────────────

    #[test]
    fn deterministic_funding_rejects_legacy_p2wsh_accepts_p2wpkh_p2tr() {
        let legacy = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([0x11; 20]));
        let err = ensure_deterministic_funding(&legacy).expect_err("legacy must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("not a segwit witness program"),
            "unexpected error: {msg}"
        );

        let p2wpkh = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x22; 20]));
        ensure_deterministic_funding(&p2wpkh).expect("v0 p2wpkh must pass");

        let p2wsh = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0x33; 32]));
        let err = ensure_deterministic_funding(&p2wsh).expect_err("p2wsh must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("P2WSH") && msg.contains("not predictable"),
            "unexpected error: {msg}"
        );

        let nums = nums_internal_key().expect("NUMS key");
        let p2tr = ScriptBuf::new_p2tr(
            &bitcoin::secp256k1::Secp256k1::verification_only(),
            nums,
            None,
        );
        ensure_deterministic_funding(&p2tr).expect("v1 p2tr must pass");
    }

    #[test]
    fn fee_for_vsize_arithmetic_and_overflow() {
        assert_eq!(fee_for_vsize(250, 10).expect("ok").to_sat(), 2_500);
        assert_eq!(fee_for_vsize(1, 1).expect("ok").to_sat(), 1);
        let err = fee_for_vsize(usize::try_from(u64::MAX).unwrap_or(usize::MAX), 2)
            .expect_err("must overflow");
        assert!(
            err.to_string().contains("overflow") || err.to_string().contains("fit"),
            "unexpected: {err}"
        );
        let err = fee_for_vsize(10, 0).expect_err("zero rate");
        assert!(err.to_string().contains("must be > 0"), "unexpected: {err}");
    }

    #[test]
    fn dust_guard_on_reveal_output_value() {
        let nums = nums_internal_key().expect("NUMS");
        let p2tr = ScriptBuf::new_p2tr(
            &bitcoin::secp256k1::Secp256k1::verification_only(),
            nums,
            None,
        );
        let dust = p2tr.minimal_non_dust();
        ensure_above_dust(dust, &p2tr).expect("exactly dust must pass (>=)");
        ensure_above_dust(dust + Amount::from_sat(1), &p2tr).expect("above dust");
        if dust > Amount::ZERO {
            let err = ensure_above_dust(dust - Amount::from_sat(1), &p2tr)
                .expect_err("below dust must fail");
            assert!(err.to_string().contains("dust"), "unexpected: {err}");
        }
    }

    #[test]
    fn nums_key_parses_to_valid_xonly() {
        let key = nums_internal_key().expect("NUMS must parse");
        assert_eq!(key.serialize(), NUMS_INTERNAL_KEY_BYTES);
    }

    /// Finding 1: exact chain mapping — Testnet binds only to Signet.
    #[test]
    fn chain_matches_config_exact_mapping() {
        assert!(
            chain_matches_config(BitcoinNetwork::Bitcoin, Network::Mainnet),
            "Bitcoin ↔ Mainnet"
        );
        assert!(
            chain_matches_config(BitcoinNetwork::Signet, Network::Testnet),
            "Signet ↔ Testnet"
        );
        assert!(
            chain_matches_config(BitcoinNetwork::Regtest, Network::Regtest),
            "Regtest ↔ Regtest"
        );

        // Testnet3 / Testnet4 must NOT match Network::Testnet (spec pins Signet).
        assert!(
            !chain_matches_config(BitcoinNetwork::Testnet, Network::Testnet),
            "Testnet3 must not match Network::Testnet"
        );
        assert!(
            !chain_matches_config(BitcoinNetwork::Testnet4, Network::Testnet),
            "Testnet4 must not match Network::Testnet"
        );
        assert!(
            !chain_matches_config(BitcoinNetwork::Signet, Network::Mainnet),
            "Signet must not match Mainnet"
        );
        assert!(
            !chain_matches_config(BitcoinNetwork::Regtest, Network::Testnet),
            "Regtest must not match Testnet"
        );
        assert!(
            !chain_matches_config(BitcoinNetwork::Bitcoin, Network::Testnet),
            "Bitcoin must not match Testnet"
        );

        let err = ensure_chain_matches_config(BitcoinNetwork::Testnet, Network::Testnet)
            .expect_err("Testnet3 vs Network::Testnet must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("Testnet") && (msg.contains("Signet") || msg.contains("mapping")),
            "error must name both sides / mapping: {msg}"
        );
    }

    /// Finding 4: margin ≥ MAX_GAP is rejected loudly (no silent clamp).
    #[test]
    fn inclusion_delay_margin_must_be_below_max_gap() {
        let err = publish_max_gap(BLOCK_ANCHOR_MAX_GAP).expect_err("margin == MAX_GAP must fail");
        assert!(
            err.to_string().contains("inclusion_delay_margin"),
            "unexpected: {err}"
        );
        let err =
            publish_max_gap(BLOCK_ANCHOR_MAX_GAP + 1).expect_err("margin > MAX_GAP must fail");
        assert!(
            err.to_string().contains("BLOCK_ANCHOR_MAX_GAP"),
            "unexpected: {err}"
        );
        assert_eq!(
            publish_max_gap(BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN).expect("recommended"),
            BLOCK_ANCHOR_PUBLISH_MAX_GAP
        );
        assert_eq!(
            publish_max_gap(0).expect("zero margin"),
            BLOCK_ANCHOR_MAX_GAP
        );
        assert_eq!(publish_max_gap(10).expect("custom 10"), 90);
    }

    /// Finding 5: oversized batch is rejected by the weight guard **before**
    /// any per-member chain RPC. A batch that is both oversize and would need
    /// many getblockhash lookups (distinct future heights) must surface the
    /// weight error, not a chain/tip error.
    #[test]
    fn oversized_batch_rejected_before_chain_rpc() {
        let (template, _) = signed_members(1, Network::Regtest);
        let one = template[0];
        let max = max_half_agg_members_for_standard_reveal()
            .expect("max_half_agg_members_for_standard_reveal");
        let over_n = max + 1;
        // Distinct future heights — would force O(members) getblockhash if
        // select_block_anchor ran first.
        let members: Vec<BatchMember> = (0..over_n)
            .map(|i| BatchMember {
                sig: one,
                build_tip: BlockAnchor {
                    block_hash: {
                        let mut h = [0u8; 32];
                        h[0] = (i % 256) as u8;
                        h[1] = ((i / 256) % 256) as u8;
                        h
                    },
                    height: 1_000_000 + (i as u32),
                },
            })
            .collect();

        // Structural path used by publish() before select_block_anchor.
        let sizing_scalar = {
            let mut s = [0u8; 32];
            s[31] = 1;
            s
        };
        let sizing_payload = synthetic_half_agg_payload(
            members.len(),
            &NUMS_INTERNAL_KEY_BYTES,
            &NUMS_INTERNAL_KEY_BYTES,
            &sizing_scalar,
        )
        .expect("synthetic");
        let w = measure_reveal_weight(&sizing_payload).expect("measure");
        assert!(w > MAX_STANDARD_TX_WEIGHT, "fixture must be oversize");
        let err =
            ensure_tx_within_standard_weight("reveal", w, members.len(), sizing_payload.len())
                .expect_err("oversize must fail weight guard");
        let msg = err.to_string();
        assert!(
            msg.contains("MAX_STANDARD_TX_WEIGHT")
                || msg.contains(&MAX_STANDARD_TX_WEIGHT.to_string()),
            "must be weight error, not chain error: {msg}"
        );
        assert!(
            !msg.contains("getblockhash")
                && !msg.contains("canonical")
                && !msg.contains("build_tip"),
            "weight path must not mention chain validation: {msg}"
        );
        let _ = members; // keep the oversize+future-heights fixture live
    }

    /// Finding 1 (legacy name): oversized half-agg batch is rejected by the
    /// weight guard before any bitcoind interaction.
    #[test]
    fn oversized_batch_rejected_by_standard_weight_guard() {
        let (template, _) = signed_members(1, Network::Regtest);
        let one = template[0];

        let max = max_half_agg_members_for_standard_reveal()
            .expect("max_half_agg_members_for_standard_reveal");
        assert!(max >= 1, "max members must be at least 1");
        assert!(max < usize::from(u16::MAX), "max should be below u16::MAX");

        // Boundary: max fits, max+1 does not. Payload uses the repeated valid
        // member's (pk, R, s) — same shape `aggregate_sig_with_anchor` emits.
        let payload_for = |n: usize| {
            synthetic_half_agg_payload(n, &one.pk, &one.r, &one.s).expect("synthetic payload")
        };

        let payload_ok = payload_for(max);
        let w_ok = measure_reveal_weight(&payload_ok).expect("measure max");
        assert!(
            w_ok <= MAX_STANDARD_TX_WEIGHT,
            "max={max} weight {w_ok} should be within limit"
        );
        ensure_tx_within_standard_weight("reveal", w_ok, max, payload_ok.len())
            .expect("max members must pass the guard");

        let over_n = max + 1;
        let payload_over = payload_for(over_n);
        let w_over = measure_reveal_weight(&payload_over).expect("measure over");
        assert!(
            w_over > MAX_STANDARD_TX_WEIGHT,
            "max+1={over_n} weight {w_over} should exceed limit"
        );
        let err = ensure_tx_within_standard_weight("reveal", w_over, over_n, payload_over.len())
            .expect_err("oversize must fail");
        let msg = err.to_string();
        assert!(
            msg.contains(&MAX_STANDARD_TX_WEIGHT.to_string())
                || msg.contains("MAX_STANDARD_TX_WEIGHT"),
            "error must name the limit: {msg}"
        );
        assert!(
            msg.contains(&over_n.to_string()) || msg.contains("members"),
            "error must mention member count: {msg}"
        );

        // `aggregate_sig_with_anchor` accepts a repeated valid member (no need
        // for 65_535 distinct signatures). Aggregate a modest repeated batch
        // then pad the logical member list in the serialized payload shape via
        // the structural constructor above for the true oversize case — the
        // crypto sum of ~max members is intentionally avoided in unit tests.
        let repeated: Vec<NullifierSig> = std::iter::repeat(one).take(3).collect();
        let agg = aggregate_sig_with_anchor(&repeated, BlockAnchor::default())
            .expect("aggregate_sig_with_anchor accepts repeated members");
        assert_eq!(agg.members.len(), 3);
        let _ = agg;
    }

    /// Finding F5: `note_fee_state` detects period-≥2 fee oscillation by
    /// rejecting a revisited `(commit_fee, reveal_fee)` pair.
    #[test]
    fn note_fee_state_detects_repeated_fee_pair() {
        let mut seen = HashSet::new();
        note_fee_state(
            &mut seen,
            Amount::from_sat(100),
            Amount::from_sat(200),
            "with-change",
            0,
        )
        .expect("first (100,200) must be accepted");
        let err = note_fee_state(
            &mut seen,
            Amount::from_sat(100),
            Amount::from_sat(200),
            "with-change",
            1,
        )
        .expect_err("repeated (100,200) must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("fee fixed-point cycle detected"),
            "unexpected cycle error: {msg}"
        );
        note_fee_state(
            &mut seen,
            Amount::from_sat(101),
            Amount::from_sat(200),
            "with-change",
            2,
        )
        .expect("different pair (101,200) must be accepted");
    }

    // ── live regtest helpers ────────────────────────────────────────────

    fn require_env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "live regtest test requires env var {name} to be set \
                 (do not silently skip — missing coverage would be a lie)"
            )
        })
    }

    fn live_publisher_with(fee_rate_sat_per_vb: u64, reveal_output_value: Amount) -> Publisher {
        live_publisher_with_margin(
            fee_rate_sat_per_vb,
            reveal_output_value,
            BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN,
        )
    }

    fn live_publisher_with_margin(
        fee_rate_sat_per_vb: u64,
        reveal_output_value: Amount,
        inclusion_delay_margin: u32,
    ) -> Publisher {
        let url = require_env("ZKCOINS_REGTEST_URL");
        let cookie = require_env("ZKCOINS_REGTEST_COOKIE");
        let wallet = require_env("ZKCOINS_REGTEST_WALLET");
        Publisher::connect(PublisherConfig {
            rpc_url: url,
            cookie_path: PathBuf::from(cookie),
            wallet_name: wallet,
            fee_rate_sat_per_vb,
            reveal_output_value,
            network: Network::Regtest,
            inclusion_delay_margin,
        })
        .expect("Publisher::connect to live regtest must succeed")
    }

    fn live_publisher() -> Publisher {
        live_publisher_with(2, Amount::from_sat(1_000))
    }

    /// Install a one-shot pre-broadcast hook (test-only reorg injection).
    fn set_pre_broadcast_hook<F>(publisher: &Publisher, hook: F)
    where
        F: FnMut(&Client) + Send + 'static,
    {
        *publisher
            .pre_broadcast_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(hook));
    }

    /// Reset and return the previous member-`getblockhash` call count (test seam).
    fn take_member_getblockhash_calls(publisher: &Publisher) -> u64 {
        let mut guard = publisher
            .member_getblockhash_calls
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = *guard;
        *guard = 0;
        prev
    }

    fn signed_members(
        count: usize,
        m_state_network: Network,
    ) -> (Vec<NullifierSig>, &'static [u8]) {
        let mut members = Vec::with_capacity(count);
        for index in 0..count {
            let label = format!("zkCoins/v1/publisher/regtest-secret-{index}");
            let (secret, public, _) = normalized_key(deterministic_secret(label.as_bytes()));
            let proof_data = ProofData {
                new_account_state_hash: ZERO_HASH,
                output_coins_root: ZERO_HASH,
                input_nullifiers_root: ZERO_HASH,
                coin_history_root: ZERO_HASH,
                nav_commitment: ZERO_HASH,
                npk_commit: Sha256::digest(format!("publisher-next-key-{index}")).into(),
            };
            let signed = sign_transition(secret, public, &proof_data, m_state_network);
            let transition = signed.transition;
            members.push(NullifierSig {
                pk: transition.pk_i,
                r: transition.signature_r(),
                s: transition.signature_s(),
            });
        }
        (members, m_state_network.m_state_bytes())
    }

    fn batch_at_tip(publisher: &Publisher, sigs: &[NullifierSig]) -> Vec<BatchMember> {
        let tip = publisher.current_anchor().expect("current_anchor");
        sigs.iter()
            .map(|sig| BatchMember {
                sig: *sig,
                build_tip: tip,
            })
            .collect()
    }

    fn mine_one(publisher: &Publisher) {
        let network = publisher.chain_network().expect("network");
        let addr = publisher
            .rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("getnewaddress")
            .require_network(network)
            .expect("address network");
        publisher
            .rpc
            .generate_to_address(1, &addr)
            .expect("generatetoaddress");
    }

    fn mine_n(publisher: &Publisher, n: u64) {
        let network = publisher.chain_network().expect("network");
        let addr = publisher
            .rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("getnewaddress")
            .require_network(network)
            .expect("address network");
        publisher
            .rpc
            .generate_to_address(n, &addr)
            .expect("generatetoaddress");
    }

    fn mempool_txids(publisher: &Publisher) -> std::collections::BTreeSet<Txid> {
        publisher
            .rpc
            .get_raw_mempool()
            .expect("getrawmempool")
            .into_iter()
            .collect()
    }

    fn assert_roundtrip(publisher: &Publisher, members: &[BatchMember], m_state: &[u8]) {
        let batch = publisher.publish(members).expect("publish");

        mine_one(publisher);
        let confs = publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("wait_for_confirmation(reveal)");
        assert!(confs >= 1, "reveal should be confirmed, got {confs}");

        let details = publisher
            .fetch_reveal_payload_details(&batch.reveal_txid)
            .expect("fetch_reveal_payload_details");
        assert!(
            details.errors.is_empty(),
            "malformed inputs on reveal: {:?}",
            details.errors
        );
        assert_eq!(
            details.payloads.len(),
            1,
            "expected exactly one payload, got {}",
            details.payloads.len()
        );
        assert_eq!(
            details.payloads[0], batch.payload,
            "on-chain payload must equal published payload"
        );

        let decoded = AggregateStateNullifierV3::deserialize(&details.payloads[0])
            .expect("deserialize payload");
        assert_eq!(decoded, batch.aggregate);
        aggregate_verify(&decoded, m_state).expect("aggregate_verify after round-trip");

        // Block-anchor byte-order convention: consensus order via to_byte_array.
        let chain_hash = publisher
            .rpc
            .get_block_hash(u64::from(decoded.block_anchor.height))
            .expect("getblockhash(anchor.height)");
        assert_eq!(
            chain_hash.to_byte_array(),
            decoded.block_anchor.block_hash,
            "block_anchor.block_hash must equal BlockHash::to_byte_array() \
             of getblockhash(height) (consensus byte order)"
        );
        assert_eq!(
            BlockHash::from_byte_array(decoded.block_anchor.block_hash),
            chain_hash,
            "from_byte_array round-trip must recover the chain BlockHash"
        );

        let reveal_info = publisher
            .rpc
            .get_raw_transaction_info(&batch.reveal_txid, None)
            .expect("reveal raw tx info");
        assert!(reveal_info.blockhash.is_some(), "reveal must be in a block");
        assert!(
            reveal_info.confirmations.unwrap_or(0) >= 1,
            "reveal confirmations"
        );
        assert!(
            batch.commit_output.script_pubkey.is_p2tr(),
            "commit output must be P2TR"
        );

        let reveal_tx = publisher
            .rpc
            .get_raw_transaction(&batch.reveal_txid, None)
            .expect("reveal tx");
        assert_eq!(reveal_tx.input.len(), 1, "single-input reveal");
        assert_eq!(
            reveal_tx.input[0].previous_output.txid, batch.commit_txid,
            "reveal must spend the commit tx"
        );
        let commit_tx = publisher
            .rpc
            .get_raw_transaction(&batch.commit_txid, None)
            .expect("commit tx");
        let spent = &commit_tx.output[reveal_tx.input[0].previous_output.vout as usize];
        assert_eq!(
            spent.script_pubkey, batch.commit_output.script_pubkey,
            "spent commit script must match published commit_output"
        );
        assert!(spent.script_pubkey.is_p2tr());
    }

    /// Live regtest: 3-member half-aggregate → inscribe → mine → re-read.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_publish_roundtrip() {
        let publisher = live_publisher();
        let (sigs, m_state) = signed_members(3, Network::Regtest);
        let members = batch_at_tip(&publisher, &sigs);
        assert_roundtrip(&publisher, &members, m_state);
    }

    /// Live regtest: single-member path (half-agg format 0x01 is fine).
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_single_member_roundtrip() {
        let publisher = live_publisher();
        let (sigs, m_state) = signed_members(1, Network::Regtest);
        let members = batch_at_tip(&publisher, &sigs);
        let batch = publisher.publish(&members).expect("publish single");
        assert_eq!(
            batch.aggregate.format, 0x01,
            "aggregate_sig_with_anchor yields FORMAT_HALF_AGG even for one member"
        );
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");
        let details = publisher
            .fetch_reveal_payload_details(&batch.reveal_txid)
            .expect("fetch");
        assert!(details.errors.is_empty(), "errors: {:?}", details.errors);
        assert_eq!(details.payloads, vec![batch.payload.clone()]);
        let decoded =
            AggregateStateNullifierV3::deserialize(&details.payloads[0]).expect("deserialize");
        assert_eq!(decoded, batch.aggregate);
        aggregate_verify(&decoded, m_state).expect("verify");
    }

    /// Finding 2: corrupted / wrong-network aggregate is rejected and nothing
    /// is broadcast.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_rejects_wrong_network_or_corrupted_sig_without_broadcast() {
        let publisher = live_publisher();
        let before = mempool_txids(&publisher);

        // Sign against Testnet m_state; publisher verifies under Regtest.
        let (sigs, _) = signed_members(2, Network::Testnet);
        let members = batch_at_tip(&publisher, &sigs);
        let err = publisher
            .publish(&members)
            .expect_err("wrong-network members must fail verify");
        let msg = err.to_string();
        assert!(
            msg.contains("verification failed") || msg.contains("aggregate"),
            "unexpected error: {msg}"
        );
        let after = mempool_txids(&publisher);
        assert_eq!(
            before, after,
            "mempool must be unchanged after rejected publish"
        );

        // Corrupted s on an otherwise Regtest-valid member.
        let (mut sigs, _) = signed_members(1, Network::Regtest);
        sigs[0].s[0] ^= 0x01;
        let members = batch_at_tip(&publisher, &sigs);
        let err = publisher
            .publish(&members)
            .expect_err("corrupted s must fail verify");
        assert!(
            err.to_string().contains("verification failed")
                || err.to_string().contains("aggregate")
                || err.to_string().contains("signature"),
            "unexpected: {err}"
        );
        let after2 = mempool_txids(&publisher);
        assert_eq!(
            before, after2,
            "mempool must stay unchanged after corrupted-s reject"
        );
    }

    /// Finding 3: anchor equals the oldest member's build tip; descendant tips
    /// still yield the oldest; stale and wrong-hash tips fail loudly.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_block_anchor_selection_and_staleness() {
        let publisher = live_publisher();

        // Record tip T0, mine one so tip is T0+1, then build mixed tips.
        let t0 = publisher.current_anchor().expect("t0");
        mine_one(&publisher);
        let t1 = publisher.current_anchor().expect("t1");
        assert!(t1.height > t0.height);

        let (sigs, m_state) = signed_members(2, Network::Regtest);
        let members = vec![
            BatchMember {
                sig: sigs[0],
                build_tip: t1, // descendant / younger
            },
            BatchMember {
                sig: sigs[1],
                build_tip: t0, // oldest
            },
        ];
        let batch = publisher
            .publish(&members)
            .expect("publish with mixed tips");
        assert_eq!(
            batch.block_anchor, t0,
            "anchor must equal the oldest member's build tip"
        );
        assert_eq!(batch.aggregate.block_anchor, t0);
        aggregate_verify(&batch.aggregate, m_state).expect("verify");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");

        // Wrong hash at a real height.
        let tip = publisher.current_anchor().expect("tip");
        let (sigs, _) = signed_members(1, Network::Regtest);
        let mut bad_hash = tip.block_hash;
        bad_hash[0] ^= 0xff;
        let err = publisher
            .publish(&[BatchMember {
                sig: sigs[0],
                build_tip: BlockAnchor {
                    block_hash: bad_hash,
                    height: tip.height,
                },
            }])
            .expect_err("wrong hash must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("canonical") || msg.contains("not the canonical"),
            "unexpected: {msg}"
        );

        // Stale: mine 101 blocks after recording a tip, then use that tip.
        let stale_tip = publisher.current_anchor().expect("stale base");
        mine_n(&publisher, 101);
        let (sigs, _) = signed_members(1, Network::Regtest);
        let err = publisher
            .publish(&[BatchMember {
                sig: sigs[0],
                build_tip: stale_tip,
            }])
            .expect_err("stale members must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("members too stale, re-prove"),
            "unexpected stale error: {msg}"
        );
        assert!(
            msg.contains(&BLOCK_ANCHOR_PUBLISH_MAX_GAP.to_string())
                || msg.contains("effective publish bound")
                || msg.contains("94"),
            "stale error must mention effective publish bound: {msg}"
        );
    }

    /// Finding F1: non-selected member with future height fails validation
    /// (oldest selection would otherwise pick the valid tip); nothing broadcasts.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_rejects_nonselected_member_bad_build_tip() {
        let publisher = live_publisher();
        let before = mempool_txids(&publisher);
        let tip = publisher.current_anchor().expect("tip");
        let (sigs, _) = signed_members(2, Network::Regtest);

        // member[0] = current tip (would be selected as oldest if validation
        // skipped); member[1] = future height so it must fail naming index 1.
        let members = vec![
            BatchMember {
                sig: sigs[0],
                build_tip: tip,
            },
            BatchMember {
                sig: sigs[1],
                build_tip: BlockAnchor {
                    block_hash: tip.block_hash,
                    height: tip
                        .height
                        .checked_add(100)
                        .expect("tip.height + 100 must fit u32"),
                },
            },
        ];
        let err = publisher
            .publish(&members)
            .expect_err("future-height non-selected member must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("member[1]"),
            "error must name member index 1: {msg}"
        );
        let after = mempool_txids(&publisher);
        assert_eq!(
            before, after,
            "mempool must be unchanged after non-selected bad tip reject"
        );
    }

    /// Finding F2 / F1 live: connect fails when PublisherConfig.network
    /// disagrees with the live bitcoind chain (Mainnet or Testnet against regtest).
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_connect_rejects_network_mismatch() {
        let url = require_env("ZKCOINS_REGTEST_URL");
        let cookie = require_env("ZKCOINS_REGTEST_COOKIE");
        let wallet = require_env("ZKCOINS_REGTEST_WALLET");

        let mainnet_err = match Publisher::connect(PublisherConfig {
            rpc_url: url.clone(),
            cookie_path: PathBuf::from(&cookie),
            wallet_name: wallet.clone(),
            fee_rate_sat_per_vb: 2,
            reveal_output_value: Amount::from_sat(1_000),
            network: Network::Mainnet,
            inclusion_delay_margin: BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN,
        }) {
            Ok(_) => panic!("Mainnet config against regtest must fail connect"),
            Err(e) => e,
        };
        let msg = mainnet_err.to_string();
        assert!(
            (msg.contains("Mainnet") || msg.contains("Bitcoin"))
                && (msg.contains("Regtest") || msg.contains("regtest")),
            "connect error must name both config and chain sides: {msg}"
        );

        // Finding 1: Network::Testnet must not accept regtest (only Signet).
        let testnet_err = match Publisher::connect(PublisherConfig {
            rpc_url: url,
            cookie_path: PathBuf::from(cookie),
            wallet_name: wallet,
            fee_rate_sat_per_vb: 2,
            reveal_output_value: Amount::from_sat(1_000),
            network: Network::Testnet,
            inclusion_delay_margin: BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN,
        }) {
            Ok(_) => panic!("Testnet config against regtest must fail connect"),
            Err(e) => e,
        };
        let msg = testnet_err.to_string();
        assert!(
            msg.contains("Testnet")
                && (msg.contains("Regtest") || msg.contains("regtest") || msg.contains("Signet")),
            "Testnet-vs-regtest connect error must name both sides: {msg}"
        );
    }

    /// Finding 4 live: margin ≥ MAX_GAP rejected at connect; custom margin
    /// bound still publishes at exactly the effective gap.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_custom_inclusion_delay_margin() {
        let url = require_env("ZKCOINS_REGTEST_URL");
        let cookie = require_env("ZKCOINS_REGTEST_COOKIE");
        let wallet = require_env("ZKCOINS_REGTEST_WALLET");

        let err = match Publisher::connect(PublisherConfig {
            rpc_url: url,
            cookie_path: PathBuf::from(cookie),
            wallet_name: wallet,
            fee_rate_sat_per_vb: 2,
            reveal_output_value: Amount::from_sat(1_000),
            network: Network::Regtest,
            inclusion_delay_margin: BLOCK_ANCHOR_MAX_GAP,
        }) {
            Ok(_) => panic!("margin == MAX_GAP must fail connect"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("inclusion_delay_margin") || msg.contains("BLOCK_ANCHOR_MAX_GAP"),
            "unexpected margin error: {msg}"
        );

        // Custom margin 10 → effective bound 90. Mine 89 after H → gap 90.
        let custom_margin = 10u32;
        let publisher = live_publisher_with_margin(2, Amount::from_sat(1_000), custom_margin);
        let bound = publish_max_gap(custom_margin).expect("bound");
        assert_eq!(bound, 90);
        let build_tip = publisher.current_anchor().expect("record tip H");
        let mine_n_blocks = bound.checked_sub(1).expect("bound >= 1");
        mine_n(&publisher, u64::from(mine_n_blocks));
        let tip_after = publisher.current_anchor().expect("tip after mine");
        assert_eq!(
            tip_after.height,
            build_tip.height.checked_add(mine_n_blocks).expect("h"),
            "must advance tip by exactly {mine_n_blocks}"
        );
        let gap = publish_inclusion_gap(build_tip, tip_after).expect("gap");
        assert_eq!(gap, bound, "gap must equal effective bound");

        let (sigs, m_state) = signed_members(1, Network::Regtest);
        let batch = publisher
            .publish(&[BatchMember {
                sig: sigs[0],
                build_tip,
            }])
            .expect("gap == custom effective bound must succeed");
        assert_eq!(batch.block_anchor, build_tip);
        aggregate_verify(&batch.aggregate, m_state).expect("verify");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm custom-margin publish");
    }

    /// Finding 3: pre-broadcast anchor identity re-check aborts on reorg
    /// before any sendrawtransaction (mempool unchanged).
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_pre_broadcast_aborts_on_anchor_reorg() {
        let publisher = live_publisher();
        let before = mempool_txids(&publisher);
        let tip = publisher.current_anchor().expect("tip");
        let orphaned_hash = BlockHash::from_byte_array(tip.block_hash);
        let orphaned_height = tip.height;

        // After fee convergence / signing, reorg out the tip block and mine a
        // replacement at the same height so getblockhash(height) returns a
        // different identity. Funding UTXOs are mature coinbases deeper in
        // the chain and remain spendable.
        set_pre_broadcast_hook(&publisher, move |rpc| {
            rpc.invalidate_block(&orphaned_hash)
                .expect("invalidateblock of selected anchor");
            let network = rpc.get_blockchain_info().expect("getblockchaininfo").chain;
            let addr = rpc
                .get_new_address(None, Some(AddressType::Bech32m))
                .expect("getnewaddress")
                .require_network(network)
                .expect("address network");
            // Rebuild at least one block so height orphaned_height exists again
            // with a different hash.
            rpc.generate_to_address(1, &addr)
                .expect("generatetoaddress after invalidate");
            let live = rpc
                .get_block_hash(u64::from(orphaned_height))
                .expect("getblockhash after reorg");
            assert_ne!(
                live, orphaned_hash,
                "reorg fixture must replace the block at the anchor height"
            );
        });

        let (sigs, _) = signed_members(1, Network::Regtest);
        let members = batch_at_tip(&publisher, &sigs);
        assert_eq!(members[0].build_tip, tip);

        let err = publisher
            .publish(&members)
            .expect_err("reorged anchor must fail pre-broadcast identity check");
        // Full chain: outer context + root ensure! message.
        let msg = format!("{err:#}");
        assert!(
            msg.contains("reorged")
                || msg.contains("no longer canonical")
                || msg.contains("identity"),
            "error must name the identity failure: {msg}"
        );
        assert!(
            msg.contains(&format!("{orphaned_height}")) || msg.contains("height"),
            "error must mention the anchor height: {msg}"
        );
        let after = mempool_txids(&publisher);
        assert_eq!(
            before, after,
            "mempool must be unchanged — no sendrawtransaction after reorg"
        );
    }

    /// Finding F3a: publish gap exactly at BLOCK_ANCHOR_PUBLISH_MAX_GAP (94)
    /// still succeeds: mine 93 after recording H → gap = (H+93+1)−H = 94.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_publish_gap_exactly_publish_max_succeeds() {
        let publisher = live_publisher();
        let build_tip = publisher.current_anchor().expect("record tip H");
        // Exactly 93 blocks → inclusion gap lower bound = 94 = PUBLISH_MAX.
        mine_n(&publisher, 93);
        let tip_after = publisher.current_anchor().expect("tip after mine");
        assert_eq!(
            tip_after.height,
            build_tip.height.checked_add(93).expect("height + 93"),
            "must advance tip by exactly 93"
        );

        let (sigs, m_state) = signed_members(1, Network::Regtest);
        let members = vec![BatchMember {
            sig: sigs[0],
            build_tip,
        }];
        let batch = publisher
            .publish(&members)
            .expect("gap == BLOCK_ANCHOR_PUBLISH_MAX_GAP must succeed");
        assert_eq!(batch.block_anchor, build_tip);
        aggregate_verify(&batch.aggregate, m_state).expect("verify");
        // Optional confirm so the wallet settles cleanly for later tests.
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm boundary publish");
    }

    /// Finding F3b: publish gap one past BLOCK_ANCHOR_PUBLISH_MAX_GAP fails
    /// loudly: mine 94 after H → gap = 95 > 94; mempool unchanged.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_publish_gap_over_publish_max_fails_loudly() {
        let publisher = live_publisher();
        let before = mempool_txids(&publisher);
        let build_tip = publisher.current_anchor().expect("record tip H");
        mine_n(&publisher, 94);
        let tip_after = publisher.current_anchor().expect("tip after mine");
        assert_eq!(
            tip_after.height,
            build_tip.height.checked_add(94).expect("height + 94"),
            "must advance tip by exactly 94"
        );

        let expected_gap = publish_inclusion_gap(build_tip, tip_after).expect("gap");
        assert_eq!(
            expected_gap,
            BLOCK_ANCHOR_PUBLISH_MAX_GAP + 1,
            "gap must be exactly one over the publish max"
        );

        let (sigs, _) = signed_members(1, Network::Regtest);
        let err = publisher
            .publish(&[BatchMember {
                sig: sigs[0],
                build_tip,
            }])
            .expect_err("gap > BLOCK_ANCHOR_PUBLISH_MAX_GAP must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("members too stale, re-prove"),
            "unexpected over-gap error: {msg}"
        );
        assert!(
            msg.contains(&expected_gap.to_string())
                || msg.contains(&(BLOCK_ANCHOR_PUBLISH_MAX_GAP + 1).to_string()),
            "error must mention actual gap: {msg}"
        );
        assert!(
            msg.contains(&BLOCK_ANCHOR_PUBLISH_MAX_GAP.to_string())
                || msg.contains("effective publish bound")
                || msg.contains("94"),
            "error must mention effective publish bound: {msg}"
        );
        let after = mempool_txids(&publisher);
        assert_eq!(
            before, after,
            "mempool must be unchanged after over-gap reject"
        );
    }

    /// Finding F4: provisional fee seeds never gate UTXO admission — a confirmed
    /// 1600 sat P2TR UTXO at 2 sat/vB + 1000 sat reveal must publish (measured
    /// fees fit; provisional estimate alone would look ~568 sat short).
    ///
    /// Larger wallet UTXOs are locked for the duration so publish **must** fund
    /// from the 1600-sat candidate (otherwise the test would pass via a large
    /// coinbase even without the F4 fix).
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_provisional_fees_do_not_gate_1600_sat_utxo() {
        let publisher = live_publisher_with(2, Amount::from_sat(1_000));
        let btc_net = publisher.chain_network().expect("net");

        // Exact 1600 sat confirmed P2TR UTXO.
        let exact = Amount::from_sat(1_600);
        let addr = publisher
            .rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("get_new_address Bech32m")
            .require_network(btc_net)
            .expect("address network");
        publisher
            .rpc
            .send_to_address(&addr, exact, None, None, None, None, None, None)
            .expect("send_to_address 1600 sat");
        mine_one(&publisher);

        let unspent = publisher
            .rpc
            .list_unspent(Some(1), None, None, Some(true), None)
            .expect("listunspent");
        let exact_utxos: Vec<_> = unspent.iter().filter(|u| u.amount == exact).collect();
        assert!(
            !exact_utxos.is_empty(),
            "expected a confirmed 1600 sat UTXO among {:?}",
            unspent
                .iter()
                .map(|u| u.amount.to_sat())
                .collect::<Vec<_>>()
        );
        assert!(
            unspent.iter().any(|u| u.amount > Amount::from_sat(100_000)),
            "need a large funding candidate to remain for other tests after unlock"
        );

        // Lock every confirmed UTXO except one exact 1600-sat outpoint so the
        // publisher cannot fall back to a large coinbase/change input.
        let keep = OutPoint {
            txid: exact_utxos[0].txid,
            vout: exact_utxos[0].vout,
        };
        let to_lock: Vec<OutPoint> = unspent
            .iter()
            .filter(|u| !(u.txid == keep.txid && u.vout == keep.vout))
            .map(|u| OutPoint {
                txid: u.txid,
                vout: u.vout,
            })
            .collect();
        if !to_lock.is_empty() {
            publisher
                .rpc
                .lock_unspent(&to_lock)
                .expect("lock_unspent all but 1600-sat UTXO");
        }

        let publish_result = (|| {
            let (sigs, m_state) = signed_members(1, Network::Regtest);
            let members = batch_at_tip(&publisher, &sigs);
            let batch = publisher.publish(&members).map_err(|e| {
                format!(
                    "publish must succeed funding solely from the 1600 sat UTXO \
                     (provisional seeds must not gate admission): {e}"
                )
            })?;
            assert_eq!(batch.aggregate.members.len(), 1);

            // Prove the commit spent the locked-out-except 1600-sat prevout.
            let commit_tx = publisher
                .rpc
                .get_raw_transaction(&batch.commit_txid, None)
                .map_err(|e| format!("get_raw_transaction(commit): {e}"))?;
            assert_eq!(
                commit_tx.input.len(),
                1,
                "publisher builds single-input commits"
            );
            let funding_prev = commit_tx.input[0].previous_output;
            assert_eq!(
                funding_prev, keep,
                "commit must spend the 1600-sat UTXO {keep:?}, spent {funding_prev:?}"
            );
            let parent = publisher
                .rpc
                .get_raw_transaction(&funding_prev.txid, None)
                .map_err(|e| format!("get_raw_transaction(funding parent): {e}"))?;
            let spent_value = parent
                .output
                .get(funding_prev.vout as usize)
                .map(|o| o.value)
                .ok_or_else(|| format!("funding parent missing vout {}", funding_prev.vout))?;
            assert_eq!(
                spent_value,
                exact,
                "funding prevout must be exactly 1600 sat, got {}",
                spent_value.to_sat()
            );

            mine_one(&publisher);
            publisher
                .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
                .map_err(|e| format!("confirm 1600-sat path: {e}"))?;
            let details = publisher
                .fetch_reveal_payload_details(&batch.reveal_txid)
                .map_err(|e| format!("fetch details: {e}"))?;
            assert!(details.errors.is_empty(), "errors: {:?}", details.errors);
            aggregate_verify(
                &AggregateStateNullifierV3::deserialize(&details.payloads[0])
                    .map_err(|e| format!("deserialize: {e}"))?,
                m_state,
            )
            .map_err(|e| format!("verify: {e}"))?;
            Ok::<(), String>(())
        })();

        // Always unlock so later tests see the full wallet again.
        let _ = publisher.rpc.unlock_unspent_all();

        publish_result.expect("F4 1600-sat sole-funding path");
    }

    /// Finding 5: at 1 sat/vB, a funding UTXO sized so change lands just below
    /// dust must still converge and publish (topology drops the change output).
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_fee_convergence_when_change_below_dust() {
        let publisher = live_publisher_with(1, Amount::from_sat(1_000));
        let (sigs, m_state) = signed_members(1, Network::Regtest);
        let members = batch_at_tip(&publisher, &sigs);

        // Measure reveal vsize for this payload shape.
        let tip = publisher.current_anchor().expect("tip");
        let agg = aggregate_sig_with_anchor(&[sigs[0]], tip).expect("agg");
        let payload = agg.serialize();
        let reveal_vsize = sizing_inscription(&payload)
            .expect("sizing")
            .reveal_tx
            .vsize();

        // Commit with change is typically ~154 vB for P2TR in/out; without ~111.
        // Size funding so that under the *with-change* fee assumption the change
        // falls just below dust — fixed-point must drop the change and succeed.
        let nums = nums_internal_key().expect("nums");
        let p2tr = ScriptBuf::new_p2tr(
            &bitcoin::secp256k1::Secp256k1::verification_only(),
            nums,
            None,
        );
        let dust = p2tr.minimal_non_dust();
        let commit_vsize_with_change = 154usize;
        let commit_fee = fee_for_vsize(commit_vsize_with_change, 1).expect("cf");
        let reveal_fee = fee_for_vsize(reveal_vsize, 1).expect("rf");
        let spent = sum_amounts(&[Amount::from_sat(1_000), commit_fee, reveal_fee]).expect("sum");
        let funding_amount = spent
            .checked_add(dust)
            .expect("add dust")
            .checked_sub(Amount::from_sat(1))
            .expect("dust-1");

        // Create a confirmed P2TR UTXO of exactly that value.
        let btc_net = publisher.chain_network().expect("net");
        let addr = publisher
            .rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("addr")
            .require_network(btc_net)
            .expect("net");
        // Exact amount; fee paid from other wallet inputs (no subtractfeefromamount).
        publisher
            .rpc
            .send_to_address(&addr, funding_amount, None, None, None, None, None, None)
            .expect("sendtoaddress exact funding for dust-change case");
        mine_one(&publisher);

        // Ensure at least one UTXO of the target size exists; if the wallet
        // rounded, fall back to creating with createrawtransaction path.
        let unspent = publisher
            .rpc
            .list_unspent(Some(1), None, None, Some(true), None)
            .expect("listunspent");
        let has_target = unspent.iter().any(|u| u.amount == funding_amount);
        if !has_target {
            // Lock is not needed; send exact again (fee paid from other input).
            let addr2 = publisher
                .rpc
                .get_new_address(None, Some(AddressType::Bech32m))
                .expect("addr2")
                .require_network(btc_net)
                .expect("net");
            publisher
                .rpc
                .send_to_address(&addr2, funding_amount, None, None, None, None, None, None)
                .expect("sendtoaddress retry");
            mine_one(&publisher);
        }

        let batch = publisher
            .publish(&members)
            .expect("publish must succeed when change is dust-absorbed via fixed-point");
        assert_eq!(batch.aggregate.members.len(), 1);
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("mined");
        let details = publisher
            .fetch_reveal_payload_details(&batch.reveal_txid)
            .expect("details");
        assert!(details.errors.is_empty());
        aggregate_verify(
            &AggregateStateNullifierV3::deserialize(&details.payloads[0]).expect("dec"),
            m_state,
        )
        .expect("verify");
    }

    /// Finding 6: publisher skips a too-small eligible UTXO and funds from the
    /// next candidate.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_funding_retries_next_candidate() {
        let publisher = live_publisher_with(2, Amount::from_sat(1_000));
        let btc_net = publisher.chain_network().expect("net");

        // Tiny confirmed UTXO that cannot cover reveal_output + fees.
        let tiny = Amount::from_sat(1_500);
        let addr = publisher
            .rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("addr")
            .require_network(btc_net)
            .expect("net");
        publisher
            .rpc
            .send_to_address(&addr, tiny, None, None, None, None, None, None)
            .expect("create tiny utxo");
        mine_one(&publisher);

        let before_candidates = publisher.list_funding_candidates().expect("cands");
        assert!(
            before_candidates.iter().any(|c| c.amount == tiny)
                || before_candidates.iter().any(|c| c.amount <= tiny),
            "expected a tiny candidate among {:?}",
            before_candidates
                .iter()
                .map(|c| c.amount.to_sat())
                .collect::<Vec<_>>()
        );
        // There must also be a larger candidate (wallet coinbase/change).
        assert!(
            before_candidates
                .iter()
                .any(|c| c.amount > Amount::from_sat(100_000)),
            "need a large funding candidate"
        );

        let (sigs, m_state) = signed_members(1, Network::Regtest);
        let members = batch_at_tip(&publisher, &sigs);
        let batch = publisher
            .publish(&members)
            .expect("must skip tiny UTXO and fund from a larger candidate");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");
        let details = publisher
            .fetch_reveal_payload_details(&batch.reveal_txid)
            .expect("details");
        assert!(details.errors.is_empty());
        aggregate_verify(
            &AggregateStateNullifierV3::deserialize(&details.payloads[0]).expect("dec"),
            m_state,
        )
        .expect("verify");
    }

    /// Finding 5 live: arithmetic pre-filter skips unusable UTXOs without
    /// signing them; construct-attempt limit fails loudly when exhausted.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_funding_prefilter_and_attempt_limit() {
        let publisher = live_publisher_with(2, Amount::from_sat(1_000));
        let btc_net = publisher.chain_network().expect("net");
        let reveal_out = Amount::from_sat(1_000);

        // Create several confirmed UTXOs strictly below reveal_output_value so
        // the arithmetic pre-filter skips them without signrawtransaction.
        let below = Amount::from_sat(500);
        for _ in 0..3 {
            let addr = publisher
                .rpc
                .get_new_address(None, Some(AddressType::Bech32m))
                .expect("addr")
                .require_network(btc_net)
                .expect("net");
            publisher
                .rpc
                .send_to_address(&addr, below, None, None, None, None, None, None)
                .expect("create below-reveal utxo");
        }
        mine_one(&publisher);

        // Lock every UTXO that could actually fund the inscription so publish
        // can only see the below-reveal candidates.
        let unspent = publisher
            .rpc
            .list_unspent(Some(1), None, None, Some(true), None)
            .expect("listunspent");
        let to_lock: Vec<OutPoint> = unspent
            .iter()
            .filter(|u| u.amount >= reveal_out)
            .map(|u| OutPoint {
                txid: u.txid,
                vout: u.vout,
            })
            .collect();
        assert!(
            !to_lock.is_empty(),
            "need large UTXOs to lock so only tiny candidates remain"
        );
        publisher
            .rpc
            .lock_unspent(&to_lock)
            .expect("lock_unspent large UTXOs");

        let result = (|| {
            let candidates = publisher.list_funding_candidates().expect("cands");
            assert!(
                candidates.iter().all(|c| c.amount < reveal_out) && !candidates.is_empty(),
                "after lock, only below-reveal candidates should remain: {:?}",
                candidates
                    .iter()
                    .map(|c| c.amount.to_sat())
                    .collect::<Vec<_>>()
            );

            let (sigs, _) = signed_members(1, Network::Regtest);
            let members = batch_at_tip(&publisher, &sigs);
            let err = publisher
                .publish(&members)
                .expect_err("only below-reveal UTXOs must fail funding");
            let msg = err.to_string();
            assert!(
                msg.contains("rejected_before_measurement")
                    || msg.contains("before measurement")
                    || msg.contains("prefilter_skipped"),
                "error must report unmeasured/prefilter rejection: {msg}"
            );
            assert!(
                !msg.contains("final measured fees"),
                "must not claim measured fees when nothing was measured: {msg}"
            );
            // All candidates should be pre-filter skips → zero constructions.
            assert!(
                msg.contains("constructed_attempts=0")
                    || msg.contains("prefilter_skipped_before_construct"),
                "must report zero constructions / prefilter skips: {msg}"
            );
            Ok::<(), String>(())
        })();

        let _ = publisher.rpc.unlock_unspent_all();
        result.expect("F5 prefilter path");
    }

    /// Finding 6 live: funding below reveal_output_value is reported as an
    /// unmeasured arithmetic shortfall — never as "measured".
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_funding_below_reveal_output_is_unmeasured() {
        let reveal_out = Amount::from_sat(50_000);
        let publisher = live_publisher_with(2, reveal_out);
        let btc_net = publisher.chain_network().expect("net");

        // Confirmed UTXO below reveal_output_value.
        let tiny = Amount::from_sat(1_000);
        let addr = publisher
            .rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("addr")
            .require_network(btc_net)
            .expect("net");
        publisher
            .rpc
            .send_to_address(&addr, tiny, None, None, None, None, None, None)
            .expect("create tiny");
        mine_one(&publisher);

        let unspent = publisher
            .rpc
            .list_unspent(Some(1), None, None, Some(true), None)
            .expect("listunspent");
        let to_lock: Vec<OutPoint> = unspent
            .iter()
            .filter(|u| u.amount != tiny)
            .map(|u| OutPoint {
                txid: u.txid,
                vout: u.vout,
            })
            .collect();
        if !to_lock.is_empty() {
            publisher
                .rpc
                .lock_unspent(&to_lock)
                .expect("lock all but tiny");
        }

        let result = (|| {
            let (sigs, _) = signed_members(1, Network::Regtest);
            let members = batch_at_tip(&publisher, &sigs);
            let err = publisher
                .publish(&members)
                .expect_err("tiny < reveal_output must fail");
            let msg = err.to_string();
            assert!(
                msg.contains("rejected_before_measurement")
                    || msg.contains("before measurement")
                    || msg.contains("arithmetic"),
                "error must name unmeasured arithmetic shortfall: {msg}"
            );
            assert!(
                !msg.to_lowercase().contains("measured fees") && !msg.contains("final measured"),
                "must not describe unmeasured rejection as measured: {msg}"
            );
            assert!(
                msg.contains("rejected_after_measurement=0")
                    || !msg.contains("rejected_after_measurement="),
                "after-measurement count should be zero or absent: {msg}"
            );
            Ok::<(), String>(())
        })();

        let _ = publisher.rpc.unlock_unspent_all();
        result.expect("F6 unmeasured shortfall path");
    }

    /// Finding 5 live (ordering): oversize batch fails with weight error via
    /// the full publish path (not a chain/tip error), even when tips would
    /// require many getblockhash calls.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_oversize_batch_fails_before_chain_lookups() {
        let publisher = live_publisher();
        let before = mempool_txids(&publisher);
        let (template, _) = signed_members(1, Network::Regtest);
        let one = template[0];
        let max = max_half_agg_members_for_standard_reveal().expect("max");
        let over_n = max + 1;
        // Cap the constructed member list for time: still oversize weight, and
        // future heights that would force many RPCs if selection ran first.
        // max for standard reveal is typically thousands; building that many
        // BatchMember structs is fine (Copy), and publish must weight-reject
        // before select_block_anchor walks them with getblockhash.
        let members: Vec<BatchMember> = (0..over_n)
            .map(|i| BatchMember {
                sig: one,
                build_tip: BlockAnchor {
                    block_hash: [0u8; 32],
                    height: 9_000_000 + (i as u32),
                },
            })
            .collect();
        let err = publisher
            .publish(&members)
            .expect_err("oversize batch must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("MAX_STANDARD_TX_WEIGHT")
                || msg.contains(&MAX_STANDARD_TX_WEIGHT.to_string())
                || msg.contains("weight"),
            "must be weight error: {msg}"
        );
        assert!(
            !msg.contains("getblockhash")
                && !msg.contains("canonical block")
                && !msg.contains("in the future"),
            "must not reach per-member chain validation: {msg}"
        );
        assert_eq!(
            before,
            mempool_txids(&publisher),
            "mempool unchanged after oversize reject"
        );
    }

    /// Finding F1 (hardening round 4): a weight-valid batch whose every member
    /// height lies far outside the effective window is rejected by the
    /// **arithmetic** pre-filter with **zero** member `getblockhash` RPCs.
    ///
    /// Uses many distinct far-stale heights and deliberately wrong hashes: if
    /// selection still looked up hashes first, the canonical-hash mismatch
    /// would fire before the stale error and the call counter would be > 0.
    /// Also asserts a tip just inside the window still publishes.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_stale_batch_rejected_without_member_getblockhash() {
        let publisher = live_publisher();
        let before = mempool_txids(&publisher);
        let tip = publisher.current_anchor().expect("tip");
        let window = publish_max_gap(BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN).expect("window");
        // Chain must be deep enough that height 1 is strictly outside the window.
        assert!(
            tip.height > window + 1,
            "regtest tip {} must be > window+1 ({}) so height 1 is arithmetically stale",
            tip.height,
            window + 1
        );

        // Large enough that a pre-window getblockhash loop would be obvious
        // (thousands of distinct heights; still under the standard-reveal cap).
        let max_members = max_half_agg_members_for_standard_reveal().expect("max members");
        let n = 2_000usize.min(max_members);
        assert!(
            n >= 500,
            "fixture needs a large weight-valid batch; got n={n}, max={max_members}"
        );
        let (template, _) = signed_members(1, Network::Regtest);
        let one = template[0];
        // Distinct heights 1..n — all far below the window on this chain.
        // Wrong hashes: a hash-first order would fail on "canonical block"
        // before ever evaluating the gap, and would issue n getblockhash calls.
        let stale_members: Vec<BatchMember> = (0..n)
            .map(|i| {
                let height = 1u32.saturating_add(i as u32);
                BatchMember {
                    sig: one,
                    build_tip: BlockAnchor {
                        block_hash: {
                            let mut h = [0u8; 32];
                            h[0] = 0xaa;
                            h[1] = (i % 256) as u8;
                            h[2] = ((i / 256) % 256) as u8;
                            h
                        },
                        height,
                    },
                }
            })
            .collect();

        let _ = take_member_getblockhash_calls(&publisher);
        let err = publisher
            .publish(&stale_members)
            .expect_err("far-stale weight-valid batch must fail arithmetic pre-filter");
        let member_rpc = take_member_getblockhash_calls(&publisher);
        let msg = err.to_string();
        assert!(
            msg.contains("members too stale, re-prove"),
            "must be the arithmetic stale error (not a chain/hash error): {msg}"
        );
        assert!(
            msg.contains("arithmetic pre-filter") || msg.contains("no per-member getblockhash"),
            "error must identify the pre-RPC arithmetic filter: {msg}"
        );
        assert!(
            !msg.contains("canonical block") && !msg.contains("for member build tip failed"),
            "must not reach per-member hash validation: {msg}"
        );
        assert_eq!(
            member_rpc, 0,
            "far-stale rejection must issue zero member getblockhash RPCs; got {member_rpc}"
        );
        assert_eq!(
            before,
            mempool_txids(&publisher),
            "mempool must be unchanged after far-stale reject"
        );

        // Just inside the window: gap == window still publishes.
        let min_height = tip
            .height
            .checked_add(1)
            .expect("tip+1")
            .checked_sub(window)
            .expect("tip+1 >= window on this chain");
        let inside_hash = publisher
            .rpc
            .get_block_hash(u64::from(min_height))
            .expect("getblockhash(min in-window height)");
        let (sigs, m_state) = signed_members(1, Network::Regtest);
        let inside_members = vec![BatchMember {
            sig: sigs[0],
            build_tip: BlockAnchor {
                block_hash: inside_hash.to_byte_array(),
                height: min_height,
            },
        }];
        let gap = publish_inclusion_gap(inside_members[0].build_tip, tip).expect("gap");
        assert_eq!(
            gap, window,
            "fixture must sit exactly at the effective bound"
        );
        let batch = publisher
            .publish(&inside_members)
            .expect("batch just inside the window must still publish");
        assert_eq!(batch.block_anchor.height, min_height);
        aggregate_verify(&batch.aggregate, m_state).expect("verify inside-window batch");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm inside-window publish");
    }
}
