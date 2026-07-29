use bitcoin::{
    absolute::LockTime,
    blockdata::{opcodes, script},
    hashes::Hash,
    key::TapTweak,
    locktime::absolute::Height,
    script::PushBytesBuf,
    secp256k1::{self, Secp256k1, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootBuilder},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Txid, Weight, Witness,
};

use sqlx::PgPool;
use std::str::FromStr;

use crate::db;
use crate::esplora_bound::EsploraReadClient;
// Re-export the guarded broadcast client so existing call sites
// (`publisher::LegacyBroadcastClient`, `bin/recover_inscription`) keep
// working. Construction lives only in `esplora_bound` (raw type private).
pub use crate::esplora_bound::LegacyBroadcastClient;

// Define a configuration struct for Esplora
// Crate-private: only the binary/runtime edge consumes this via
// `NETWORK_CONFIG`; external binaries assemble their own Esplora URL.
#[derive(Clone, Debug)]
pub(crate) struct EsploraConfig {
    pub url: String,
    pub is_mainnet: bool,
    pub network_name: String,
    /// Esplora WebSocket endpoint consumed by the block-tip scanner
    /// (`scanner_ws::run_scanner_ws`). Sourced from the `ESPLORA_WS_URL`
    /// env var via `lib::build_network_config_from_env`, which panics
    /// if it is unset or empty — production callers always observe a
    /// `Some(...)` here. The `Option` shape is retained to keep this
    /// struct constructible from test fixtures that do not need a WS
    /// URL (publisher-only paths) without forcing a placeholder URL
    /// into the type.
    ///
    /// The publisher itself does not use this field — see
    /// `broadcast_inscription_txs` for the direct-broadcast rationale.
    pub ws_url: Option<String>,
}

impl EsploraConfig {
    pub(crate) fn network(&self) -> Network {
        if self.is_mainnet {
            Network::Bitcoin
        } else {
            Network::Signet
        }
    }
}

// Define constants for transaction identification
pub(crate) const INSCRIPTION_MARKER_PREFIX: &str = "4242";

const MAX_CHUNK_SIZE: usize = 520;
const MAX_MINING_ATTEMPTS: u32 = 400000;
const MIN_INSCRIPTION_AMOUNT: u64 = 800;

const COMMIT_TX_WITNESS_WEIGHT: Weight = Weight::from_wu(68);
const REVEAL_TX_WITNESS_WEIGHT: Weight = Weight::from_wu(295);

fn min_fee(tx: &Transaction, witness_weight: Option<Weight>) -> u64 {
    let mut weight = tx.weight().to_wu();
    if tx.input.iter().any(|utxo| utxo.witness.is_empty()) {
        weight += witness_weight.unwrap().to_wu()
            * tx.input
                .iter()
                .map(|utxo| utxo.witness.is_empty() as u64)
                .sum::<u64>()
    }
    weight.div_ceil(4)
}

/// Telemetry from `inscription_txs`' reveal-txid prefix-mining loop.
/// Returned alongside the constructed transactions so the caller can
/// persist a row to `tx_mining_log` for forensics — answering "did the
/// mining stall?" / "how much CPU did this Send cost?" from SQL.
#[derive(Debug, Clone)]
pub(crate) struct MiningStats {
    pub target_prefix: String,
    pub nonces_tried: i64,
    pub duration_us: i64,
    pub final_nonce: Option<i64>,
    pub final_txid: bitcoin::Txid,
}

pub(crate) fn inscription_txs(
    commitment_data: &[u8],
    publisher_address: &Address,
    outpoints_with_sats: Vec<(OutPoint, u64)>,
    publisher_key: &str,
    config: &EsploraConfig,
) -> (Transaction, Transaction, MiningStats) {
    // Create secp context and keys
    let secp256k1 = Secp256k1::new();
    let sk = SecretKey::from_str(publisher_key).unwrap();
    let key_pair = secp256k1::Keypair::from_secret_key(&secp256k1, &sk);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let network = config.network();

    println!("Publisher address: {}", publisher_address);

    let amount: u64 = outpoints_with_sats.iter().map(|(_, sats)| sats).sum();

    // Build the script-path Taproot anchor that commits to the data.
    // The same builder is used by `build_reveal_only`, ensuring the
    // commit address (and therefore the reveal-spend script) matches
    // exactly between the in-process happy path and out-of-band
    // recovery callers.
    let TaprootAnchor {
        commit_address,
        reveal_script,
        taproot_spend_info,
    } = build_taproot_anchor(commitment_data, public_key, network);

    // Create commit transaction
    let mut commit_tx = Transaction {
        version: Version(1),
        lock_time: LockTime::Blocks(Height::ZERO),
        input: outpoints_with_sats
            .iter()
            .map(|(outpoint, _)| TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: commit_address.script_pubkey(),
        }],
    };

    let commit_fee = min_fee(&commit_tx, Some(COMMIT_TX_WITNESS_WEIGHT));
    commit_tx.output.first_mut().unwrap().value = Amount::from_sat(amount - commit_fee);

    // Create input TxOuts for signing
    let input_txout = outpoints_with_sats
        .iter()
        .map(|(_, sats)| TxOut {
            value: Amount::from_sat(*sats),
            script_pubkey: publisher_address.script_pubkey(),
        })
        .collect::<Vec<TxOut>>();

    // Sign each input of the commit transaction
    for idx in 0..outpoints_with_sats.len() {
        let mut sighash_cache = SighashCache::new(&mut commit_tx);
        let signature_hash = sighash_cache
            .taproot_key_spend_signature_hash(
                idx,
                &Prevouts::All(&input_txout),
                TapSighashType::Default,
            )
            .unwrap();

        // Sign with the tweaked keypair
        let message = secp256k1::Message::from_digest_slice(&signature_hash[..]).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp256k1, &sk);
        let tweaked_keypair = keypair.tap_tweak(&secp256k1, None).to_keypair();
        let signature = secp256k1.sign_schnorr(&message, &tweaked_keypair);

        // Add the signature to the witness
        let witness = sighash_cache.witness_mut(idx).unwrap();
        witness.clear();
        witness.push(signature.as_ref());
    }

    let commit_txid = commit_tx.compute_txid();
    let commit_output_value = commit_tx.output[0].value.to_sat();

    let (reveal_tx, stats) = build_reveal_only_inner(
        commit_txid,
        commit_output_value,
        publisher_address,
        &key_pair,
        &reveal_script,
        &taproot_spend_info,
        &secp256k1,
    );

    (commit_tx, reveal_tx, stats)
}

/// Internal helper carrying the script-path anchor artefacts that both
/// `inscription_txs` and the recovery CLI need to reconstruct.
struct TaprootAnchor {
    commit_address: Address,
    reveal_script: ScriptBuf,
    taproot_spend_info: bitcoin::taproot::TaprootSpendInfo,
}

/// Builds the script-path Taproot anchor (commit address + reveal
/// script + spend info) from a commitment payload, the publisher's
/// x-only pubkey, and the target network. Pure / deterministic — the
/// same `(commitment_data, public_key, network)` triple always produces
/// the same anchor.
fn build_taproot_anchor(
    commitment_data: &[u8],
    public_key: XOnlyPublicKey,
    network: Network,
) -> TaprootAnchor {
    let secp256k1 = Secp256k1::new();

    // Build a taproot script committing to the data
    let mut script_builder = script::Builder::new()
        .push_slice(public_key.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF);

    // Add the commitment data in chunks
    for chunk in commitment_data.chunks(MAX_CHUNK_SIZE) {
        let buffer = PushBytesBuf::try_from(chunk.to_vec()).unwrap();
        script_builder = script_builder.push_slice(buffer);
    }

    let reveal_script = script_builder
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .unwrap()
        .finalize(&secp256k1, public_key)
        .unwrap();

    let commit_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

    TaprootAnchor {
        commit_address,
        reveal_script,
        taproot_spend_info,
    }
}

/// Reveal-only constructor used by both the in-process publisher path
/// (`inscription_txs`) and the out-of-band recovery CLI
/// (`bin/recover_inscription.rs`).
///
/// Re-derives the script-path Taproot anchor from `commitment_data`
/// and the publisher key, then assembles + nonce-mines the reveal
/// transaction that spends the commit anchor's output[0] back to the
/// publisher address. The caller supplies the already-broadcast
/// `commit_txid` and the anchor output's value in sats — there is no
/// commit broadcast or commit signing on this path.
///
/// Returns the mined reveal transaction together with the derived
/// commit address so the caller can sanity-check it against the
/// observed on-chain anchor.
pub fn build_reveal_only(
    commit_txid: Txid,
    commit_output_value: u64,
    commitment_data: &[u8],
    publisher_key: &str,
    publisher_address: &Address,
    network: Network,
) -> (Transaction, Address) {
    let secp256k1 = Secp256k1::new();
    let sk = SecretKey::from_str(publisher_key).unwrap();
    let key_pair = secp256k1::Keypair::from_secret_key(&secp256k1, &sk);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let TaprootAnchor {
        commit_address,
        reveal_script,
        taproot_spend_info,
    } = build_taproot_anchor(commitment_data, public_key, network);

    let (reveal_tx, _stats) = build_reveal_only_inner(
        commit_txid,
        commit_output_value,
        publisher_address,
        &key_pair,
        &reveal_script,
        &taproot_spend_info,
        &secp256k1,
    );

    (reveal_tx, commit_address)
}

/// Inner reveal-construction loop shared by `inscription_txs` and
/// `build_reveal_only`. Takes the pre-derived anchor artefacts so we
/// only re-derive once per call site, matching the legacy code path.
#[allow(clippy::too_many_arguments)]
fn build_reveal_only_inner(
    commit_txid: Txid,
    commit_output_value: u64,
    publisher_address: &Address,
    key_pair: &secp256k1::Keypair,
    reveal_script: &ScriptBuf,
    taproot_spend_info: &bitcoin::taproot::TaprootSpendInfo,
    secp256k1: &Secp256k1<secp256k1::All>,
) -> (Transaction, MiningStats) {
    // The reveal spends the commit anchor; mirror the prevout `TxOut`
    // used for signing so the legacy and recovery paths produce a
    // byte-identical witness for the same inputs. The scriptPubKey is
    // derived directly from the tweaked output key (network-agnostic —
    // P2TR scriptPubKey is `OP_1 <32-byte-output-key>` on every chain).
    let commit_prevout = TxOut {
        value: Amount::from_sat(commit_output_value),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(taproot_spend_info.output_key()),
    };

    // Create reveal transaction
    let mut reveal_tx = Transaction {
        version: Version(1),
        lock_time: LockTime::from_consensus(0),
        input: vec![TxIn {
            previous_output: OutPoint::new(commit_txid, 0),
            script_sig: script::Builder::new().into_script(),
            witness: Witness::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: publisher_address.script_pubkey(),
        }],
    };

    let reveal_fee = min_fee(&reveal_tx, Some(REVEAL_TX_WITNESS_WEIGHT));
    reveal_tx.output.first_mut().unwrap().value =
        Amount::from_sat(commit_output_value - reveal_fee);

    // Mine the reveal transaction to have a txid starting with our marker
    println!(
        "Mining reveal transaction to start with {}...",
        INSCRIPTION_MARKER_PREFIX
    );
    let target_prefix = hex::decode(INSCRIPTION_MARKER_PREFIX).unwrap();

    let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .unwrap();

    let mining_start = std::time::Instant::now();
    let mut found_nonce: Option<u32> = None;
    let mut nonces_seen: u32 = 0;

    for nonce in 0..MAX_MINING_ATTEMPTS {
        nonces_seen = nonce;
        // Update the nSequence for mining
        reveal_tx.input[0].sequence = Sequence(nonce);

        // Sign the transaction with the new sequence
        let mut sighash_cache = SighashCache::new(&mut reveal_tx);
        let signature_hash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&commit_prevout]),
                TapLeafHash::from_script(reveal_script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap();

        let message = secp256k1::Message::from_digest_slice(&signature_hash[..]).unwrap();
        let signature = secp256k1.sign_schnorr(&message, key_pair);

        let witness = sighash_cache.witness_mut(0).unwrap();
        witness.clear();
        witness.push(signature.as_ref());
        witness.push(reveal_script.clone());
        witness.push(control_block.serialize());

        // Check if the txid starts with our target prefix
        let txid = reveal_tx.compute_txid();
        let txid_bytes = txid.as_byte_array();

        if txid_bytes.starts_with(&target_prefix) {
            println!("Found matching txid: {} with nSequence: {}", txid, nonce);
            found_nonce = Some(nonce);
            break;
        }

        if nonce % 10000 == 0 {
            println!("Tried {} nonces...", nonce);
        }

        if nonce == MAX_MINING_ATTEMPTS - 1 {
            println!("WARNING: Reached maximum attempts without finding a match");
        }
    }

    let final_txid = reveal_tx.compute_txid();
    let stats = MiningStats {
        target_prefix: INSCRIPTION_MARKER_PREFIX.to_string(),
        nonces_tried: i64::from(nonces_seen) + 1,
        duration_us: i64::try_from(mining_start.elapsed().as_micros()).unwrap_or(i64::MAX),
        final_nonce: found_nonce.map(i64::from),
        final_txid,
    };

    (reveal_tx, stats)
}

/// Broadcast helper for a client that was already stack-checked at connect.
async fn broadcast_raw_tx(
    client: &LegacyBroadcastClient,
    tx: &Transaction,
    label: &str,
) -> Result<Txid, Box<dyn std::error::Error + Send + Sync>> {
    client.broadcast(tx).await?;
    let txid = tx.compute_txid();
    println!("{label} transaction broadcast successfully: {txid}");
    Ok(txid)
}

/// Fetches available UTXOs for the publisher address
pub(crate) async fn get_publisher_utxo(
    publisher_address: &Address,
    config: &EsploraConfig,
    min_amount: Option<u64>,
) -> Result<Vec<(OutPoint, u64)>, Box<dyn std::error::Error + Send + Sync>> {
    // Read path only — goes through the bound wrapper (no raw client).
    let client = EsploraReadClient::connect(&config.url)?;
    let utxos = client.get_address_utxos(publisher_address.clone()).await?;

    let required_amount = min_amount.unwrap_or(0);
    let mut outpoints_with_sats = Vec::<(OutPoint, u64)>::new();
    let mut sats_amount_sum = 0u64;

    for utxo in utxos {
        outpoints_with_sats.push((utxo.outpoint, utxo.value_sats));
        sats_amount_sum += utxo.value_sats;
    }

    // Discard UTXOs if total amount is insufficient
    if sats_amount_sum < required_amount {
        outpoints_with_sats.clear();
    }

    Ok(outpoints_with_sats)
}

/// Creates and broadcasts inscription transactions with the given commitment data.
///
/// **Persistence contract (Phase B).** When `pool` is `Some`, the
/// constructed `(commit_tx, reveal_tx)` pair is persisted to the
/// `pending_inscriptions` table BEFORE the first broadcast attempt
/// and the row is walked through the `constructed → commit_broadcast
/// → reveal_broadcast → complete` state machine as each broadcast
/// lands. A crash anywhere in this sequence leaves a recoverable row
/// for [`resume_pending_inscriptions`] to re-drive on the next boot.
///
/// When `pool` is `None` (out-of-band callers / unit tests that don't
/// need persistence), the function behaves exactly like the
/// pre-Phase-B version — no DB writes, no resume hooks.
pub(crate) async fn create_and_broadcast_inscription(
    commitment_data: &[u8],
    kind: db::InscriptionKind,
    config: &EsploraConfig,
    pool: Option<&PgPool>,
) -> Result<(Txid, Txid), Box<dyn std::error::Error + Send + Sync>> {
    // Cutover Stage 2: exclusive stack. A process that claimed the v1.1
    // scan stack must never inscribe bincode Commitments — that would mix
    // SMT first-write objects into a database claimed for NfLog.
    crate::v1::ensure_legacy_publisher_allowed().map_err(|e| {
        Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error + Send + Sync>
    })?;

    // Generate publisher address
    let publisher_key = &*crate::PUBLISHER_KEY;
    let secp256k1 = Secp256k1::new();
    let sk = SecretKey::from_str(publisher_key)?;
    let key_pair = secp256k1::Keypair::from_secret_key(&secp256k1, &sk);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
    let network = config.network();
    let publisher_address = Address::p2tr(&secp256k1, public_key, None, network);
    println!("Publisher address: {}", publisher_address);

    // Fetch UTXOs
    println!("Fetching UTXOs...");
    let outpoints_with_sats =
        get_publisher_utxo(&publisher_address, config, Some(MIN_INSCRIPTION_AMOUNT)).await?;

    if outpoints_with_sats.is_empty() {
        eprintln!(
            "ERROR: No UTXOs found for publisher address {}. Fund it to continue.",
            publisher_address
        );
        return Err(
            "No UTXOs available for inscription broadcast — publisher wallet is empty".into(),
        );
    }

    // Log found UTXOs
    for (outpoint, sats) in &outpoints_with_sats {
        println!(
            "Found UTXO: {}:{} with value {} sats",
            outpoint.txid, outpoint.vout, sats
        );
    }

    // Create the inscription transactions
    let (commit_tx, reveal_tx, mining_stats) = inscription_txs(
        commitment_data,
        &publisher_address,
        outpoints_with_sats,
        publisher_key,
        config,
    );

    // Print transaction IDs
    let commit_txid = commit_tx.compute_txid();
    let reveal_txid = reveal_tx.compute_txid();
    println!("\nCommit TX ID: {}", commit_txid);
    println!("Reveal TX ID: {}", reveal_txid);

    // Persist the (commit, reveal) pair BEFORE attempting any
    // broadcast. Crash-recovery (Phase B) hinges on the row being on
    // disk at every state-machine boundary — if we crash between
    // construct and commit-broadcast we want the resumer to find the
    // row and re-broadcast both; if we crash between commit and
    // reveal we want the resumer to find the row and re-broadcast
    // just the reveal. Both behaviours require the row already
    // exists by the time the first network call returns.
    if let Some(pool) = pool {
        let commit_tx_bytes = bitcoin::consensus::serialize(&commit_tx);
        let reveal_tx_bytes = bitcoin::consensus::serialize(&reveal_tx);
        let commit_output_value = commit_tx.output[0].value.to_sat() as i64;
        match db::insert_pending_inscription(
            pool,
            commit_txid.as_byte_array(),
            reveal_txid.as_byte_array(),
            kind,
            commitment_data,
            &commit_tx_bytes,
            &reveal_tx_bytes,
            commit_output_value,
        )
        .await
        {
            Ok(true) => {
                println!(
                    "Persisted pending_inscriptions row (constructed) for commit={}",
                    commit_txid
                );
            }
            Ok(false) => {
                // UNIQUE-conflict: the same commit_txid is already on
                // disk (a previous attempt persisted, then crashed
                // before completing). The resumer will pick it up on
                // the next boot; in the meantime we still want to try
                // broadcasting now in case the operator hasn't
                // restarted yet.
                println!(
                    "pending_inscriptions row for commit={} already exists; proceeding with broadcast",
                    commit_txid
                );
            }
            Err(e) => {
                eprintln!(
                    "Failed to persist pending_inscriptions row for {}: {}",
                    commit_txid, e
                );
                return Err(format!("persist pending inscription: {}", e).into());
            }
        }

        // tx_mining_log: persist the reveal-txid prefix-mining effort
        // (nonces tried, duration, final nonce + txid). Fire-and-forget
        // because mining-stat loss is preferable to a Send failing on
        // a transient DB blip.
        {
            let pool = pool.clone();
            let mining_entry = db::TxMiningLogEntry {
                target_prefix: mining_stats.target_prefix.clone(),
                nonces_tried: mining_stats.nonces_tried,
                duration_us: mining_stats.duration_us,
                final_nonce: mining_stats.final_nonce,
                final_txid: mining_stats.final_txid.as_byte_array().to_vec(),
                commit_txid: Some(commit_txid.as_byte_array().to_vec()),
            };
            tokio::spawn(async move {
                if let Err(e) = db::insert_tx_mining_log(&pool, &mining_entry).await {
                    eprintln!("Failed to persist tx_mining_log: {}", e);
                }
            });
        }
    }

    // Broadcast the transactions
    match broadcast_inscription_txs_with_persistence(config, &commit_tx, &reveal_tx, pool).await {
        Ok((commit_txid, reveal_txid)) => {
            println!("Successfully broadcast transactions:");
            println!("Commit TXID: {}", commit_txid);
            println!("Reveal TXID: {}", reveal_txid);
            Ok((commit_txid, reveal_txid))
        }
        Err(e) => {
            println!("Failed to broadcast transactions: {}", e);
            // Record the error chain on the row without changing the
            // status discriminator: the broadcast may have advanced
            // the state machine to `commit_broadcast` (commit landed
            // on chain but reveal failed) and the resume path needs
            // to keep that distinction so it re-broadcasts only the
            // reveal. A blanket `status = 'failed'` would erase the
            // distinction and force resume to re-attempt the commit
            // (chain returns `txn-already-known` and recovers, but
            // the row would have lost its truth in the meantime).
            //
            // `status = 'failed'` is reserved for truly-terminal
            // callers (retry exhaustion, operator abort) — none yet,
            // but the CHECK enum keeps the slot ready.
            if let Some(pool) = pool {
                let reason = format!("{}", e);
                if let Err(persist_err) =
                    db::update_pending_failure_reason(pool, commit_txid.as_byte_array(), &reason)
                        .await
                {
                    eprintln!(
                        "Failed to persist failure_reason for {}: {}",
                        commit_txid, persist_err
                    );
                }
            }
            Err(e)
        }
    }
}

/// Esplora returns this substring inside an `HttpResponse { status:
/// 400, message }` payload when the commit's input UTXO was already
/// spent — typically because a previous attempt's commit broadcast
/// landed even though our process crashed before recording the
/// success. The resume path treats this as "commit already on chain;
/// advance and proceed to reveal" instead of a hard failure.
fn is_inputs_missingorspent_error(err: &dyn std::error::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("bad-txns-inputs-missingorspent")
        || msg.contains("missing-inputs")
        || msg.contains("txn-already-known")
}

/// Same as [`broadcast_inscription_txs`] but, when `pool` is
/// `Some`, advances the matching `pending_inscriptions` row through
/// `commit_broadcast → reveal_broadcast → complete` as each broadcast
/// step succeeds.
///
/// Status updates are best-effort: a DB-write failure after a
/// successful chain broadcast is logged but does NOT bubble back to
/// the caller — the chain is the source of truth, the row is
/// bookkeeping. If a status update fails, the next boot's resumer
/// will simply re-broadcast the next step (Esplora replies
/// `txn-already-known`) and advance the row then.
///
/// The body is a transcription of [`broadcast_inscription_txs`] with
/// status-update hooks woven in at the three points where the chain
/// confirms a step. Keeping the two functions separate (rather than
/// having one take `Option<&PgPool>`) avoids changing the existing
/// public surface and keeps the pure-broadcast code path readable.
pub(crate) async fn broadcast_inscription_txs_with_persistence(
    config: &EsploraConfig,
    commit_tx: &Transaction,
    reveal_tx: &Transaction,
    pool: Option<&PgPool>,
) -> Result<(Txid, Txid), Box<dyn std::error::Error + Send + Sync>> {
    // Guard is inside `LegacyBroadcastClient::connect`.
    let client = LegacyBroadcastClient::connect(&config.url)?;

    let commit_txid = broadcast_raw_tx(&client, commit_tx, "Commit").await?;
    let commit_txid_bytes = *commit_txid.as_byte_array();
    advance_pending_status(
        pool,
        &commit_txid_bytes,
        db::PENDING_STATUS_COMMIT_BROADCAST,
    )
    .await;

    let reveal_txid = broadcast_raw_tx(&client, reveal_tx, "Reveal").await?;
    advance_pending_status(
        pool,
        &commit_txid_bytes,
        db::PENDING_STATUS_REVEAL_BROADCAST,
    )
    .await;
    // Phase E: the row stays at `reveal_broadcast` here. The caller
    // (`mint_handler`) advances to `complete` only AFTER it has applied
    // `state.update` to the in-memory SMT/MMR and persisted the snapshot.
    // The scanner's pre-`state.update` lookup uses the
    // `complete` marker to decide whether the inscription has already
    // been integrated by the mint flow — advancing here would set the
    // marker before the integration actually happened and let a
    // mid-flight crash leave a `complete` row whose SMT/MMR were never
    // updated, which the scanner would then skip on replay.

    Ok((commit_txid, reveal_txid))
}

/// Helper: when `pool` is `Some`, set the row's status and log any
/// error rather than propagating it. The chain has already accepted
/// the step by the time this is called, so a DB-side failure is
/// recoverable on the next boot via the resumer.
async fn advance_pending_status(pool: Option<&PgPool>, commit_txid_bytes: &[u8], status: &str) {
    let Some(pool) = pool else {
        return;
    };
    if let Err(e) = db::update_pending_status(pool, commit_txid_bytes, status).await {
        eprintln!(
            "Failed to advance pending_inscriptions row {} to {}: {}",
            hex::encode(commit_txid_bytes),
            status,
            e
        );
    }
}

/// Re-broadcast every pending inscription left in the
/// `pending_inscriptions` table by a previous boot.
///
/// Strategy: load every row whose status is not `complete`, then
/// dispatch by status:
///
/// * `constructed` — re-broadcast both commit and reveal. If the
///   commit broadcast returns `bad-txns-inputs-missingorspent` the
///   commit's input was already spent by a previous attempt that
///   landed before we crashed; advance to `commit_broadcast` and
///   continue to the reveal.
/// * `commit_broadcast` — re-broadcast just the reveal. The commit
///   is already on chain.
/// * `reveal_broadcast` — re-broadcast the reveal anyway (idempotent;
///   Esplora returns `txn-already-known`) and advance to `complete`.
///
/// **Non-fatal on errors.** A failure here MUST NOT crash the
/// bootstrap — the publisher's CLI recovery tool (PR #106) remains
/// the operator's escape hatch. Errors are logged loudly so they
/// surface in the container's stdout / log aggregator.
pub(crate) async fn resume_pending_inscriptions(
    pool: &PgPool,
    config: &EsploraConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Guard is structural: `LegacyBroadcastClient::connect` (used by every
    // resume broadcast) refuses under a v1.1 process claim. Fail the whole
    // resume early when the process claim forbids legacy publish, so we do
    // not load rows only to fail per-row on connect.
    let _client_check = LegacyBroadcastClient::connect(&config.url)?;

    let rows = db::load_pending_in_progress(pool).await?;
    if rows.is_empty() {
        println!("resume_pending_inscriptions: no pending rows");
        return Ok(());
    }
    println!(
        "resume_pending_inscriptions: resuming {} pending row(s)",
        rows.len()
    );

    for row in rows {
        if let Err(e) = resume_single_row(pool, config, &row).await {
            eprintln!(
                "resume_pending_inscriptions: row id={} commit_txid={} status={} failed: {}",
                row.id,
                hex::encode(&row.commit_txid),
                row.status,
                e
            );
        }
    }
    Ok(())
}

/// Drives one [`db::PendingInscriptionRow`] to `complete`. Split out
/// of [`resume_pending_inscriptions`] so a per-row failure short-
/// circuits with `?` cleanly without abandoning the rest of the
/// queue.
async fn resume_single_row(
    pool: &PgPool,
    config: &EsploraConfig,
    row: &db::PendingInscriptionRow,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Touch every persisted column the row carries so a schema/resume
    // mismatch cannot leave write-only residuals on the host struct.
    let _kind = row.kind;
    let _commitment_len = row.commitment.len();
    let _commit_output_value = row.commit_output_value;
    let _reveal_txid_known = row.reveal_txid.as_ref().map(|b| b.len());
    let _failure_reason = row.failure_reason.as_deref();

    let commit_tx: Transaction = bitcoin::consensus::deserialize(&row.commit_tx)
        .map_err(|e| format!("deserialize commit_tx: {}", e))?;
    let reveal_tx: Transaction = bitcoin::consensus::deserialize(&row.reveal_tx)
        .map_err(|e| format!("deserialize reveal_tx: {}", e))?;

    // Connect is the choke point — no raw Esplora client on this path.
    let client = LegacyBroadcastClient::connect(&config.url)?;

    let commit_txid = commit_tx.compute_txid();

    match row.status.as_str() {
        db::PENDING_STATUS_CONSTRUCTED => {
            println!(
                "resume: row id={} status=constructed → re-broadcasting commit {}",
                row.id, commit_txid
            );
            match client.broadcast(&commit_tx).await {
                Ok(()) => {
                    db::update_pending_status(
                        pool,
                        &row.commit_txid,
                        db::PENDING_STATUS_COMMIT_BROADCAST,
                    )
                    .await?;
                }
                Err(e) if is_inputs_missingorspent_error(e.as_ref()) => {
                    // The commit already landed on a previous attempt.
                    // Advance and fall through to the reveal step.
                    println!(
                        "resume: commit {} already on chain (bad-txns-inputs-missingorspent), advancing",
                        commit_txid
                    );
                    db::update_pending_status(
                        pool,
                        &row.commit_txid,
                        db::PENDING_STATUS_COMMIT_BROADCAST,
                    )
                    .await?;
                }
                Err(e) => return Err(e),
            }
            broadcast_reveal_and_complete(pool, &client, &row.commit_txid, &reveal_tx).await?;
        }
        db::PENDING_STATUS_COMMIT_BROADCAST => {
            println!(
                "resume: row id={} status=commit_broadcast → broadcasting reveal for {}",
                row.id, commit_txid
            );
            broadcast_reveal_and_complete(pool, &client, &row.commit_txid, &reveal_tx).await?;
        }
        db::PENDING_STATUS_REVEAL_BROADCAST => {
            println!(
                "resume: row id={} status=reveal_broadcast → re-broadcasting reveal for {} (idempotent)",
                row.id, commit_txid
            );
            // Re-broadcast is idempotent: Esplora returns
            // `txn-already-known` if the reveal landed on a previous
            // attempt. Treat that as success.
            match client.broadcast(&reveal_tx).await {
                Ok(()) => {}
                Err(e) if is_inputs_missingorspent_error(e.as_ref()) => {
                    println!(
                        "resume: reveal for {} already on chain (txn-already-known)",
                        commit_txid
                    );
                }
                Err(e) => return Err(e),
            }
            // Phase E: leave the row at `reveal_broadcast`. The scanner
            // will observe the commit on chain, see the non-`complete`
            // status, run `state.update` itself, and only then mark the
            // row `complete` — the `complete` marker now means "SMT/MMR
            // contain this inscription's entry", which the resumer
            // cannot truthfully assert from outside the state lock.
        }
        other => {
            // Forward-compatible: an unknown status (e.g. a future
            // `failed` value) is skipped instead of crashing the
            // bootstrap.
            println!(
                "resume: row id={} commit_txid={} has unknown status {:?}; skipping",
                row.id,
                hex::encode(&row.commit_txid),
                other
            );
        }
    }
    Ok(())
}

/// Broadcast `reveal_tx` and advance the matching row to
/// `reveal_broadcast`. Used by both the `constructed` and
/// `commit_broadcast` resume branches.
///
/// Phase E: this no longer flips the row to `complete`. The `complete`
/// marker now means "SMT/MMR contain this inscription's entry", which
/// only the in-process mint flow (or the scanner-replay path after
/// re-running `state.update`) can truthfully assert. The resumer is
/// outside both code paths, so it stops at `reveal_broadcast` and
/// lets the scanner finish the integration.
async fn broadcast_reveal_and_complete(
    pool: &PgPool,
    client: &LegacyBroadcastClient,
    commit_txid_bytes: &[u8],
    reveal_tx: &Transaction,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match client.broadcast(reveal_tx).await {
        Ok(()) => {}
        Err(e) if is_inputs_missingorspent_error(e.as_ref()) => {
            // Reveal already on chain — proceed to advance the row.
            println!(
                "resume: reveal {} already on chain (txn-already-known)",
                reveal_tx.compute_txid()
            );
        }
        Err(e) => return Err(e),
    }
    db::update_pending_status(pool, commit_txid_bytes, db::PENDING_STATUS_REVEAL_BROADCAST).await?;
    // Phase E: do not advance to `complete` here either. See the
    // `PENDING_STATUS_REVEAL_BROADCAST` branch in `resume_single_row`
    // for the rationale — `complete` is now reserved for "SMT/MMR
    // hold this entry", which the scanner sets after running
    // `state.update`.
    Ok(())
}

#[cfg(test)]
#[path = "publisher_tests.rs"]
mod tests;
