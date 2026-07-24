//! Bitcoin publisher: half-aggregate nullifier signatures, inscribe via
//! Taproot commit/reveal, and broadcast to a real bitcoind.
//!
//! This is the first live-Bitcoin integration path (P1-F.3). It orchestrates
//! the already-implemented half-aggregation codec ([`crate::half_agg`]) and
//! Taproot envelope primitives ([`crate::inscription`]); it does **not**
//! reimplement either.
//!
//! ## Scope deliberately left to P1-G (scanner)
//!
//! The §3.5 block-anchor / inclusion-height bound and the §3.6 first-occurrence
//! policy are **not** enforced here. This module only publishes and can
//! read back raw inscription payloads for verification.

use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{
    Amount, Network, OutPoint, Script, ScriptBuf, Transaction, TxOut, Txid,
};
use bitcoincore_rpc::json::AddressType;
use bitcoincore_rpc::{Auth, Client, RpcApi};

use crate::half_agg::{
    aggregate_sig_with_anchor, AggregateStateNullifierV3, BlockAnchor, NullifierSig,
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
pub const NUMS_INTERNAL_KEY_BYTES: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Configuration for a [`Publisher`] talking to one bitcoind wallet.
///
/// Every field is mandatory. There is no default fee rate, no default reveal
/// output value, and no password-based RPC auth — missing values fail at the
/// call site that builds this struct, not inside the publisher.
#[derive(Clone, Debug)]
pub struct PublisherConfig {
    /// Base RPC URL, e.g. `http://127.0.0.1:18443`. The wallet path is appended.
    pub rpc_url: String,
    /// Path to bitcoind's `.cookie` file. Cookie-file auth only.
    pub cookie_path: PathBuf,
    /// Name of the loaded descriptor wallet that funds the commit.
    pub wallet_name: String,
    /// Fee rate in satoshis per virtual byte. Applied to measured vsizes.
    pub fee_rate_sat_per_vb: u64,
    /// Explicit value of the reveal transaction's single output. Must sit
    /// strictly above the dust limit of its scriptPubKey.
    pub reveal_output_value: Amount,
}

/// Connected publisher bound to one wallet RPC endpoint.
pub struct Publisher {
    rpc: Client,
    config: PublisherConfig,
}

/// Result of a successful `publish` call.
#[derive(Clone, Debug)]
pub struct PublishedBatch {
    pub aggregate: AggregateStateNullifierV3,
    pub payload: Vec<u8>,
    pub commit_txid: Txid,
    pub reveal_txid: Txid,
    /// The P2TR commit output that the reveal spends — the scanner's prevout.
    pub commit_output: TxOut,
    pub block_anchor: BlockAnchor,
}

/// Full per-input extraction result from a reveal transaction.
///
/// `payloads` holds every `Ok(Some(_))` envelope body. Per-input `Err`
/// results (malformed marker inputs that contribute zero nullifiers per
/// §3.5) are retained in `errors` so they are never dropped silently.
/// `Ok(None)` inputs (no marker envelope) are neither payloads nor errors.
#[derive(Debug)]
pub struct RevealPayloads {
    pub payloads: Vec<Vec<u8>>,
    pub errors: Vec<String>,
    pub per_input: Vec<Result<Option<Vec<u8>>, String>>,
}

impl Publisher {
    /// Connect to `{rpc_url}/wallet/{wallet_name}` with cookie-file auth.
    ///
    /// Fails loudly if the cookie cannot be read, the node is unreachable, or
    /// the named wallet is not loaded / not accessible.
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

        let base = config.rpc_url.trim_end_matches('/');
        let wallet_url = format!("{base}/wallet/{}", config.wallet_name);
        let rpc = Client::new(&wallet_url, Auth::CookieFile(config.cookie_path.clone()))
            .with_context(|| {
                format!(
                    "failed to open bitcoind RPC client at {wallet_url} using cookie {:?}",
                    config.cookie_path
                )
            })?;

        rpc.get_blockchain_info().with_context(|| {
            format!("bitcoind unreachable or RPC auth failed at {wallet_url}")
        })?;
        rpc.get_balances().with_context(|| {
            format!(
                "wallet '{}' is not loaded or not accessible at {wallet_url}",
                config.wallet_name
            )
        })?;

        Ok(Self { rpc, config })
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
        let height_u64 = self
            .rpc
            .get_block_count()
            .context("getblockcount failed")?;
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

    /// Half-aggregate `members`, inscribe the payload, sign and broadcast
    /// commit then reveal to the connected bitcoind.
    pub fn publish(&self, members: &[NullifierSig]) -> Result<PublishedBatch> {
        ensure!(
            !members.is_empty(),
            "publish requires at least one NullifierSig member"
        );

        let block_anchor = self.current_anchor()?;
        let aggregate = aggregate_sig_with_anchor(members, block_anchor)
            .context("half-aggregation failed")?;
        let payload = aggregate.serialize();

        let network = self.chain_network()?;
        let nums_key = nums_internal_key()?;
        let reveal_address = self
            .rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .context("getnewaddress(bech32m) for reveal output failed")?
            .require_network(network)
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
            .require_network(network)
            .context("change address network mismatch")?;
        let change_script = change_address.script_pubkey();

        // Pass 1 — provisional fees large enough to build + sign + measure.
        // Over-estimate on purpose so the funding UTXO still covers pass 2.
        let provisional_commit_vsize = 300usize;
        let provisional_reveal_vsize = 200usize
            .checked_add(payload.len().saturating_add(200) / 4)
            .context("provisional reveal vsize overflow")?;
        let provisional_commit_fee =
            fee_for_vsize(provisional_commit_vsize, self.config.fee_rate_sat_per_vb)?;
        let provisional_reveal_fee =
            fee_for_vsize(provisional_reveal_vsize, self.config.fee_rate_sat_per_vb)?;

        let required_provisional = sum_amounts(&[
            self.config.reveal_output_value,
            provisional_commit_fee,
            provisional_reveal_fee,
        ])?;
        let funding = self.select_funding_utxo(required_provisional)?;

        let pass1 = self.build_and_sign_commit(
            &payload,
            &funding,
            nums_key,
            reveal_output.clone(),
            Some(change_script.clone()),
            provisional_commit_fee,
            provisional_reveal_fee,
        )?;
        let measured_commit_vsize = pass1.signed_commit.vsize();
        let measured_reveal_vsize = pass1.reveal_tx.vsize();

        let mut commit_fee =
            fee_for_vsize(measured_commit_vsize, self.config.fee_rate_sat_per_vb)?;
        let reveal_fee = fee_for_vsize(measured_reveal_vsize, self.config.fee_rate_sat_per_vb)?;

        // Change / dust absorption for the final fee numbers.
        let spent_core = sum_amounts(&[
            self.config.reveal_output_value,
            commit_fee,
            reveal_fee,
        ])?;
        ensure!(
            funding.amount >= spent_core,
            "funding UTXO {} sat is short of final required {} sat \
             (reveal_output + commit_fee + reveal_fee); shortfall {} sat",
            funding.amount.to_sat(),
            spent_core.to_sat(),
            spent_core
                .checked_sub(funding.amount)
                .map(|a| a.to_sat())
                .unwrap_or(u64::MAX)
        );
        let change_value = funding
            .amount
            .checked_sub(spent_core)
            .context("change subtraction underflow")?;
        let change_script_final = if change_value == Amount::ZERO {
            None
        } else {
            let dust = change_script.minimal_non_dust();
            if change_value < dust {
                // Absorb dust change into the commit fee so the remainder
                // pays the miner rather than creating a dust output.
                let absorbed = change_value;
                commit_fee = commit_fee
                    .checked_add(absorbed)
                    .context("commit fee + absorbed dust overflows")?;
                eprintln!(
                    "publisher: change {} sat is below dust limit {} sat; \
                     absorbed into commit fee (now {} sat)",
                    absorbed.to_sat(),
                    dust.to_sat(),
                    commit_fee.to_sat()
                );
                None
            } else {
                Some(change_script.clone())
            }
        };

        // Pass 2 — rebuild with measured fees and sign again.
        let pass2 = self.build_and_sign_commit(
            &payload,
            &funding,
            nums_key,
            reveal_output,
            change_script_final,
            commit_fee,
            reveal_fee,
        )?;

        ensure!(
            pass2.signed_commit.vsize() == measured_commit_vsize,
            "signed commit vsize drifted after fee rebuild: pass1={} vB, pass2={} vB \
             (fees were computed from pass1; refusing to broadcast under/over-paying tx)",
            measured_commit_vsize,
            pass2.signed_commit.vsize()
        );
        ensure!(
            pass2.reveal_tx.vsize() == measured_reveal_vsize,
            "reveal vsize drifted after fee rebuild: pass1={} vB, pass2={} vB \
             (fees were computed from pass1; refusing to broadcast)",
            measured_reveal_vsize,
            pass2.reveal_tx.vsize()
        );

        let commit_txid = pass2.signed_commit.compute_txid();
        let reveal_txid = pass2.reveal_tx.compute_txid();
        let commit_output = pass2
            .signed_commit
            .output
            .first()
            .cloned()
            .context("commit transaction has no outputs")?;

        self.rpc
            .send_raw_transaction(&pass2.signed_commit)
            .with_context(|| format!("sendrawtransaction(commit) failed for {commit_txid}"))?;

        self.rpc
            .send_raw_transaction(&pass2.reveal_tx)
            .with_context(|| {
                format!(
                    "sendrawtransaction(reveal) failed for {reveal_txid}; \
                     commit already broadcast as {commit_txid} — operator recovery required"
                )
            })?;

        eprintln!(
            "publisher: broadcast commit={commit_txid} ({} vB, fee {} sat) \
             reveal={reveal_txid} ({} vB, fee {} sat) fee_rate={} sat/vB",
            measured_commit_vsize,
            commit_fee.to_sat(),
            measured_reveal_vsize,
            reveal_fee.to_sat(),
            self.config.fee_rate_sat_per_vb
        );

        Ok(PublishedBatch {
            aggregate,
            payload,
            commit_txid,
            reveal_txid,
            commit_output,
            block_anchor,
        })
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

    /// Fetch a reveal transaction and extract every present zkCoins payload.
    ///
    /// Uses `getrawtransaction` on the reveal and each parent (requires
    /// `txindex=1`). Malformed per-input results are not returned inside the
    /// payload vector; call [`Self::fetch_reveal_payload_details`] to surface
    /// them.
    pub fn fetch_reveal_payloads(&self, txid: &Txid) -> Result<Vec<Vec<u8>>> {
        Ok(self.fetch_reveal_payload_details(txid)?.payloads)
    }

    /// Full reveal extraction including per-input errors (see [`RevealPayloads`]).
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

    fn chain_network(&self) -> Result<Network> {
        let info = self
            .rpc
            .get_blockchain_info()
            .context("getblockchaininfo failed")?;
        Ok(info.chain)
    }

    fn select_funding_utxo(&self, required: Amount) -> Result<FundingUtxo> {
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
            // HARD REQUIREMENT: segwit-only funding.
            if let Err(err) = ensure_segwit_funding(&entry.script_pub_key) {
                eprintln!(
                    "publisher: skipping non-segwit UTXO {}:{} — {err}",
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

        // Deterministic: smallest UTXO that covers `required`; ties broken by
        // outpoint (txid internal bytes, then vout).
        candidates.sort_by(|a, b| {
            a.amount
                .cmp(&b.amount)
                .then_with(|| a.outpoint.txid.cmp(&b.outpoint.txid))
                .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
        });

        for candidate in &candidates {
            if candidate.amount >= required {
                return Ok(candidate.clone());
            }
        }

        let best = candidates.last().map(|c| c.amount).unwrap_or(Amount::ZERO);
        bail!(
            "no confirmed segwit UTXO covers required {} sat; best available is {} sat \
             (shortfall {} sat, {} candidate(s) after segwit filter)",
            required.to_sat(),
            best.to_sat(),
            required
                .checked_sub(best)
                .map(|a| a.to_sat())
                .unwrap_or(required.to_sat()),
            candidates.len()
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
        ensure_segwit_funding(&funding.script_pubkey)?;

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

/// Reject non-witness-program funding scripts.
///
/// `build_inscription` returns a commit tx whose funding witness is empty and
/// a reveal that already references `commit_txid`. For a segwit input the
/// signature lives in the witness, so signing does not change the txid. For a
/// legacy input the scriptSig is part of the txid, so signing would
/// **invalidate the pre-built reveal**. Callers must not "fix" that by
/// rebuilding the reveal after signing — reject the input instead.
pub fn ensure_segwit_funding(script_pubkey: &Script) -> Result<()> {
    ensure!(
        script_pubkey.is_witness_program(),
        "funding scriptPubKey is not a segwit witness program (v0 or v1); \
         legacy inputs cannot fund a pre-built reveal because signing would \
         change the commit txid"
    );
    // Only v0 / v1 are accepted as "segwit funding" for this publisher.
    let version = script_pubkey
        .witness_version()
        .context("witness program without witness version")?;
    let v = version.to_num();
    ensure!(
        v == 0 || v == 1,
        "funding witness program version {v} is not v0 or v1"
    );
    Ok(())
}

/// `vsize * fee_rate_sat_per_vb`, failing loudly on overflow.
pub fn fee_for_vsize(vsize: usize, fee_rate_sat_per_vb: u64) -> Result<Amount> {
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
pub fn ensure_above_dust(value: Amount, script_pubkey: &Script) -> Result<()> {
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
pub fn nums_internal_key() -> Result<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(&NUMS_INTERNAL_KEY_BYTES)
        .context("NUMS_INTERNAL_KEY_BYTES is not a valid x-only public key")
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, PubkeyHash, WPubkeyHash, WScriptHash};
    use shared::spec_v1::{ProofData, ZERO_HASH};
    use sha2::{Digest, Sha256};
    use zkcoins_program_plonky2::circuit::compliance::Network;

    use crate::half_agg::{aggregate_verify, AggregateStateNullifierV3};
    use crate::prover_bridge::test_signing::{
        deterministic_secret, normalized_key, sign_transition,
    };

    // ── unit tests (no bitcoind) ────────────────────────────────────────

    #[test]
    fn segwit_only_funding_guard_rejects_legacy_accepts_v0_v1() {
        let legacy = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([0x11; 20]));
        let err = ensure_segwit_funding(&legacy).expect_err("legacy must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("not a segwit witness program"),
            "unexpected error: {msg}"
        );

        let p2wpkh = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x22; 20]));
        ensure_segwit_funding(&p2wpkh).expect("v0 p2wpkh must pass");

        let p2wsh = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0x33; 32]));
        ensure_segwit_funding(&p2wsh).expect("v0 p2wsh must pass");

        let nums = nums_internal_key().expect("NUMS key");
        let p2tr = ScriptBuf::new_p2tr(&bitcoin::secp256k1::Secp256k1::verification_only(), nums, None);
        ensure_segwit_funding(&p2tr).expect("v1 p2tr must pass");
    }

    #[test]
    fn fee_for_vsize_arithmetic_and_overflow() {
        assert_eq!(
            fee_for_vsize(250, 10).expect("ok").to_sat(),
            2_500
        );
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
        let p2tr = ScriptBuf::new_p2tr(&bitcoin::secp256k1::Secp256k1::verification_only(), nums, None);
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

    // ── live regtest helpers ────────────────────────────────────────────

    fn require_env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "live regtest test requires env var {name} to be set \
                 (do not silently skip — missing coverage would be a lie)"
            )
        })
    }

    fn live_publisher() -> Publisher {
        let url = require_env("ZKCOINS_REGTEST_URL");
        let cookie = require_env("ZKCOINS_REGTEST_COOKIE");
        let wallet = require_env("ZKCOINS_REGTEST_WALLET");
        Publisher::connect(PublisherConfig {
            rpc_url: url,
            cookie_path: PathBuf::from(cookie),
            wallet_name: wallet,
            fee_rate_sat_per_vb: 2,
            reveal_output_value: Amount::from_sat(1_000),
        })
        .expect("Publisher::connect to live regtest must succeed")
    }

    fn signed_members(count: usize, m_state_network: Network) -> (Vec<NullifierSig>, &'static [u8]) {
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

    fn assert_roundtrip(publisher: &Publisher, members: &[NullifierSig], m_state: &[u8]) {
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

        // Reveal is confirmed in a block; the spent commit output is P2TR.
        let reveal_info = publisher
            .rpc
            .get_raw_transaction_info(&batch.reveal_txid, None)
            .expect("reveal raw tx info");
        assert!(
            reveal_info.blockhash.is_some(),
            "reveal must be in a block"
        );
        assert!(
            reveal_info.confirmations.unwrap_or(0) >= 1,
            "reveal confirmations"
        );
        assert!(
            batch.commit_output.script_pubkey.is_p2tr(),
            "commit output must be P2TR"
        );

        // Confirm the reveal actually spent that P2TR commit output.
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
        let (members, m_state) = signed_members(3, Network::Regtest);
        assert_roundtrip(&publisher, &members, m_state);
    }

    /// Live regtest: single-member path (half-agg format 0x01 is fine).
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_single_member_roundtrip() {
        let publisher = live_publisher();
        let (members, m_state) = signed_members(1, Network::Regtest);
        let batch = publisher.publish(&members).expect("publish single");
        // Document actual format: aggregate_sig_with_anchor always emits 0x01.
        assert_eq!(
            batch.aggregate.format, 0x01,
            "aggregate_sig_with_anchor yields FORMAT_HALF_AGG even for one member"
        );
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");
        let payloads = publisher
            .fetch_reveal_payloads(&batch.reveal_txid)
            .expect("fetch");
        assert_eq!(payloads, vec![batch.payload.clone()]);
        let decoded =
            AggregateStateNullifierV3::deserialize(&payloads[0]).expect("deserialize");
        assert_eq!(decoded, batch.aggregate);
        aggregate_verify(&decoded, m_state).expect("verify");
    }
}
