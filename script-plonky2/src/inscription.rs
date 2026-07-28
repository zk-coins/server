//! Unit-level Taproot commit/reveal construction and §3.5 envelope extraction.
//!
//! This module deliberately does not sign the funding input, estimate fees,
//! broadcast transactions, enforce the block-anchor/inclusion-height bound, or
//! apply §3.6 first-occurrence rules. The caller supplies exact fees and signs
//! the commit transaction before broadcast. P1-F.3/P1-G own broadcast and
//! chain-scanning policy.

use anyhow::{anyhow, bail, ensure, Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::MAX_SCRIPT_ELEMENT_SIZE;
use bitcoin::opcodes;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::half_agg::PAYLOAD_MARKER;

const OP_FALSE_BYTE: u8 = 0x00;
const OP_PUSHDATA1_BYTE: u8 = 0x4c;
const OP_PUSHDATA2_BYTE: u8 = 0x4d;
const OP_PUSHDATA4_BYTE: u8 = 0x4e;
const OP_PUSHNUM_NEG1_BYTE: u8 = 0x4f;
const OP_PUSHNUM_1_BYTE: u8 = 0x51;
const OP_PUSHNUM_16_BYTE: u8 = 0x60;
const OP_IF_BYTE: u8 = 0x63;
const OP_ENDIF_BYTE: u8 = 0x68;

/// Exact transaction values and destinations for one inscription.
///
/// The commit output value is `reveal_output.value + reveal_fee`. The
/// remaining funding value, after `commit_fee`, becomes change when
/// `change_script_pubkey` is present. Without a change script, the values must
/// balance exactly.
#[derive(Clone, Debug)]
pub struct InscriptionRequest {
    pub funding_outpoint: OutPoint,
    pub funding_value: Amount,
    pub internal_key: XOnlyPublicKey,
    pub reveal_output: TxOut,
    pub change_script_pubkey: Option<ScriptBuf>,
    pub commit_fee: Amount,
    pub reveal_fee: Amount,
}

/// In-memory commit/reveal transactions for a script-path commitment.
///
/// `commit_tx` has an empty funding witness and must be signed by its caller.
/// `reveal_tx` is complete for this signature-free leaf: its first witness
/// element is a truthy stack value followed by the Tapscript and control block.
/// The leaf script and control block live only in `reveal_tx`'s witness —
/// intermediate Taproot builder state is not retained after construction.
#[derive(Clone, Debug)]
pub struct Inscription {
    pub commit_tx: Transaction,
    pub reveal_tx: Transaction,
}

/// Build the exact §3.5 envelope leaf.
///
/// The payload must already carry the `0x42 0x42` marker. Payload bytes are
/// split into pushes of at most 520 bytes. Every push uses the shortest legal
/// encoding, including the dedicated numeric opcode when the final chunk is a
/// one-byte script number.
pub fn build_envelope_script(payload: &[u8]) -> Result<ScriptBuf> {
    ensure!(
        payload.starts_with(&PAYLOAD_MARKER),
        "zkCoins payload must begin with marker 0x42 0x42"
    );

    let mut builder = Builder::new()
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF);
    for chunk in payload.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
        builder = push_minimal(builder, chunk)?;
    }
    Ok(builder.push_opcode(opcodes::all::OP_ENDIF).into_script())
}

/// Construct unsigned-funding commit and signature-free reveal transactions.
///
/// Fees are exact caller-supplied amounts; this function does no fee
/// estimation. The commit input remains unsigned because its previous
/// scriptPubKey/signing key are intentionally outside this unit-level API.
///
/// The envelope alone would leave an empty final stack after `OP_IF` consumes
/// `OP_FALSE`. The reveal therefore uses the §3.5 "optional script-required
/// stack elements" slot and supplies one truthy byte. No key or script-path
/// signature is required.
pub fn build_inscription(payload: &[u8], request: InscriptionRequest) -> Result<Inscription> {
    let leaf_script = build_envelope_script(payload)?;
    let secp = Secp256k1::verification_only();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf_script.clone())
        .context("failed to add inscription Tapscript leaf")?
        .finalize(&secp, request.internal_key)
        .map_err(|_| anyhow!("single-leaf Taproot tree was not finalizable"))?;

    let commit_value = request
        .reveal_output
        .value
        .checked_add(request.reveal_fee)
        .context("reveal output plus reveal fee overflows")?;
    let spent_by_commit = commit_value
        .checked_add(request.commit_fee)
        .context("commit value plus commit fee overflows")?;
    let change_value = request
        .funding_value
        .checked_sub(spent_by_commit)
        .context("funding value does not cover reveal output and explicit fees")?;

    let commit_prevout = TxOut {
        value: commit_value,
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
    };
    let mut commit_outputs = vec![commit_prevout.clone()];
    match (request.change_script_pubkey, change_value) {
        (Some(script_pubkey), value) if value != Amount::ZERO => {
            commit_outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }
        (Some(_), _) => {}
        (None, value) => ensure!(
            value == Amount::ZERO,
            "funding leaves change but no change scriptPubKey was supplied"
        ),
    }

    let commit_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: request.funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: commit_outputs,
    };

    let control_block = spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .context("single inscription leaf has no control block")?;
    let reveal_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(commit_tx.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::from_slice(&[
                &[0x01],
                leaf_script.as_bytes(),
                control_block.serialize().as_slice(),
            ]),
        }],
        output: vec![request.reveal_output],
    };

    Ok(Inscription {
        commit_tx,
        reveal_tx,
    })
}

/// Extract one result per transaction input under the §3.5 grammar.
///
/// `prevouts` must be aligned with `tx.input`. For each input:
///
/// - `Ok(Some(payload))` is the sole valid marker envelope;
/// - `Ok(None)` means key path, non-P2TR, or no marker envelope;
/// - `Err(_)` means a purported script-path/marker input is malformed and
///   contributes zero nullifiers.
///
/// The executed leaf is authenticated against the previous P2TR output with
/// its control block. Earlier witness stack elements are ignored, as is a
/// final BIP-341 annex beginning with `0x50`. This primitive returns raw bytes:
/// callers deserialize `AggregateStateNullifierV3` and P1-G applies the §3.5
/// block-anchor/inclusion bound and §3.6 first-occurrence policy.
pub fn extract_payloads_from_reveal(
    tx: &Transaction,
    prevouts: &[TxOut],
) -> Result<Vec<Result<Option<Vec<u8>>>>> {
    ensure!(
        tx.input.len() == prevouts.len(),
        "prevout count {} does not match transaction input count {}",
        prevouts.len(),
        tx.input.len()
    );
    Ok(tx
        .input
        .iter()
        .zip(prevouts)
        .map(|(input, prevout)| extract_payload_from_input(input, prevout))
        .collect())
}

/// Per-input form of [`extract_payloads_from_reveal`].
pub fn extract_payload_from_input(input: &TxIn, prevout: &TxOut) -> Result<Option<Vec<u8>>> {
    let output_key = match p2tr_output_key(&prevout.script_pubkey)? {
        Some(key) => key,
        None => return Ok(None),
    };
    let witness = input.witness.to_vec();
    let mut script_path_end = witness.len();
    if witness
        .last()
        .is_some_and(|element| element.first() == Some(&0x50))
    {
        script_path_end -= 1;
    }

    // A key-path witness is one signature element, optionally followed by an
    // annex (which was removed above).
    if script_path_end < 2 {
        return Ok(None);
    }

    let control_bytes = &witness[script_path_end - 1];
    let script_bytes = &witness[script_path_end - 2];
    let control_block =
        ControlBlock::decode(control_bytes).context("invalid Taproot control block")?;
    ensure!(
        control_block.leaf_version == LeafVersion::TapScript,
        "executed leaf is not Tapscript"
    );
    let script = Script::from_bytes(script_bytes);
    let secp = Secp256k1::verification_only();
    ensure!(
        control_block.verify_taproot_commitment(&secp, output_key, script),
        "control block does not commit the executed Tapscript to the prevout"
    );

    extract_envelope(script)
}

fn push_minimal(builder: Builder, data: &[u8]) -> Result<Builder> {
    match data {
        [] => Ok(builder.push_opcode(opcodes::OP_FALSE)),
        [0x81] => Ok(builder.push_opcode(opcodes::all::OP_PUSHNUM_NEG1)),
        [value @ 0x01..=0x10] => {
            let opcode = bitcoin::Opcode::from(OP_PUSHNUM_1_BYTE + *value - 1);
            Ok(builder.push_opcode(opcode))
        }
        _ => {
            let push = PushBytesBuf::try_from(data.to_vec())
                .map_err(|_| anyhow!("payload chunk exceeds Bitcoin push-data capacity"))?;
            Ok(builder.push_slice(push))
        }
    }
}

fn p2tr_output_key(script_pubkey: &Script) -> Result<Option<XOnlyPublicKey>> {
    if !script_pubkey.is_p2tr() {
        return Ok(None);
    }
    let key = XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..34])
        .context("P2TR output contains an invalid x-only output key")?;
    Ok(Some(key))
}

fn extract_envelope(script: &Script) -> Result<Option<Vec<u8>>> {
    let instructions = parse_instructions(script.as_bytes())?;
    let mut marker_envelopes = Vec::new();

    for start in 0..instructions.len().saturating_sub(1) {
        if instructions[start].opcode != OP_FALSE_BYTE
            || instructions[start + 1].opcode != OP_IF_BYTE
        {
            continue;
        }

        let mut payload = Vec::new();
        let mut well_formed = true;
        let mut terminated = false;
        for instruction in &instructions[start + 2..] {
            if instruction.opcode == OP_ENDIF_BYTE {
                terminated = true;
                break;
            }
            match &instruction.data {
                Some(data) => {
                    if !instruction.minimal || data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                        well_formed = false;
                    }
                    payload.extend_from_slice(data);
                }
                None => well_formed = false,
            }
        }

        if payload.starts_with(&PAYLOAD_MARKER) {
            marker_envelopes.push((payload, well_formed && terminated));
        }
    }

    match marker_envelopes.len() {
        0 => Ok(None),
        1 => {
            let (payload, valid) = marker_envelopes.pop().expect("length checked");
            ensure!(valid, "zkCoins envelope is malformed");
            Ok(Some(payload))
        }
        count => bail!(
            "executed Tapscript contains {count} zkCoins marker envelopes; input is nullifier-empty"
        ),
    }
}

#[derive(Debug)]
struct ParsedInstruction {
    opcode: u8,
    data: Option<Vec<u8>>,
    minimal: bool,
}

fn parse_instructions(script: &[u8]) -> Result<Vec<ParsedInstruction>> {
    let mut parsed = Vec::new();
    let mut cursor = 0usize;
    while cursor < script.len() {
        let opcode = script[cursor];
        cursor += 1;
        match opcode {
            OP_FALSE_BYTE => parsed.push(ParsedInstruction {
                opcode,
                data: Some(Vec::new()),
                minimal: true,
            }),
            0x01..=0x4b => {
                let length = usize::from(opcode);
                let data = take_push_data(script, &mut cursor, length)?;
                let minimal =
                    !(length == 1 && matches!(data[0], 0x01..=0x10 | OP_PUSHNUM_NEG1_BYTE));
                parsed.push(ParsedInstruction {
                    opcode,
                    data: Some(data),
                    minimal,
                });
            }
            OP_PUSHDATA1_BYTE => {
                let length = usize::from(take_length::<1>(script, &mut cursor)?[0]);
                parsed.push(ParsedInstruction {
                    opcode,
                    data: Some(take_push_data(script, &mut cursor, length)?),
                    minimal: length >= 0x4c,
                });
            }
            OP_PUSHDATA2_BYTE => {
                let length =
                    usize::from(u16::from_le_bytes(take_length::<2>(script, &mut cursor)?));
                parsed.push(ParsedInstruction {
                    opcode,
                    data: Some(take_push_data(script, &mut cursor, length)?),
                    minimal: length >= 0x100,
                });
            }
            OP_PUSHDATA4_BYTE => {
                let raw_length = u32::from_le_bytes(take_length::<4>(script, &mut cursor)?);
                let length =
                    usize::try_from(raw_length).context("push length does not fit usize")?;
                parsed.push(ParsedInstruction {
                    opcode,
                    data: Some(take_push_data(script, &mut cursor, length)?),
                    minimal: length >= 0x1_0000,
                });
            }
            OP_PUSHNUM_NEG1_BYTE => parsed.push(ParsedInstruction {
                opcode,
                data: Some(vec![0x81]),
                minimal: true,
            }),
            OP_PUSHNUM_1_BYTE..=OP_PUSHNUM_16_BYTE => parsed.push(ParsedInstruction {
                opcode,
                data: Some(vec![opcode - OP_PUSHNUM_1_BYTE + 1]),
                minimal: true,
            }),
            _ => parsed.push(ParsedInstruction {
                opcode,
                data: None,
                minimal: true,
            }),
        }
    }
    Ok(parsed)
}

fn take_length<const N: usize>(script: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .context("push-length cursor overflow")?;
    let bytes = script
        .get(*cursor..end)
        .context("truncated push-length opcode")?;
    *cursor = end;
    Ok(bytes.try_into().expect("checked fixed-length slice"))
}

fn take_push_data(script: &[u8], cursor: &mut usize, length: usize) -> Result<Vec<u8>> {
    let end = cursor
        .checked_add(length)
        .context("push-data cursor overflow")?;
    let data = script
        .get(*cursor..end)
        .context("truncated push data")?
        .to_vec();
    *cursor = end;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use bitcoin::{Txid, WPubkeyHash};
    use shared::spec_v1::{ProofData, ZERO_HASH};
    use zkcoins_program_plonky2::circuit::compliance::Network;

    use super::*;
    use crate::half_agg::{
        aggregate_sig_with_anchor, AggregateStateNullifierV3, BlockAnchor, NullifierSig,
    };
    use crate::prover_bridge::test_signing::{
        deterministic_secret, normalized_key, sign_transition,
    };

    fn xonly_key(byte: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[byte; 32]).expect("fixed secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret);
        XOnlyPublicKey::from_keypair(&keypair).0
    }

    fn aggregate_fixture() -> AggregateStateNullifierV3 {
        let (secret, public, _) =
            normalized_key(deterministic_secret(b"zkCoins/v1/inscription/member"));
        let proof_data = ProofData {
            new_account_state_hash: ZERO_HASH,
            output_coins_root: ZERO_HASH,
            input_nullifiers_root: ZERO_HASH,
            coin_history_root: ZERO_HASH,
            nav_commitment: ZERO_HASH,
            npk_commit: [0x23; 32],
        };
        let transition = sign_transition(secret, public, &proof_data, Network::Regtest).transition;
        aggregate_sig_with_anchor(
            &[NullifierSig {
                pk: transition.pk_i,
                r: transition.signature_r(),
                s: transition.signature_s(),
            }],
            BlockAnchor {
                block_hash: [0xa5; 32],
                height: 840_000,
            },
        )
        .expect("real signed member aggregates")
    }

    fn request() -> InscriptionRequest {
        InscriptionRequest {
            funding_outpoint: OutPoint::new(Txid::from_byte_array([0x11; 32]), 7),
            funding_value: Amount::from_sat(50_000),
            internal_key: xonly_key(3),
            reveal_output: TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new_p2tr(
                    &Secp256k1::verification_only(),
                    xonly_key(4),
                    None,
                ),
            },
            change_script_pubkey: Some(ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
                [0x33; 20],
            ))),
            commit_fee: Amount::from_sat(600),
            reveal_fee: Amount::from_sat(500),
        }
    }

    fn commit_script(script: ScriptBuf, annex: Option<Vec<u8>>) -> (Transaction, TxOut) {
        let secp = Secp256k1::verification_only();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .expect("test leaf")
            .finalize(&secp, xonly_key(3))
            .expect("single leaf finalizes");
        let control = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("test control block");
        let prevout = TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        };
        let mut witness =
            Witness::from_slice(&[&[0x01], script.as_bytes(), control.serialize().as_slice()]);
        if let Some(annex) = annex {
            witness.push(annex);
        }
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0x44; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness,
            }],
            output: vec![],
        };
        (tx, prevout)
    }

    fn one_result(tx: &Transaction, prevout: &TxOut) -> Result<Option<Vec<u8>>> {
        extract_payloads_from_reveal(tx, std::slice::from_ref(prevout))
            .expect("prevouts align")
            .pop()
            .expect("one input")
    }

    #[test]
    fn aggregate_commit_reveal_round_trip() {
        let aggregate = aggregate_fixture();
        let payload = aggregate.serialize();
        let inscription = build_inscription(&payload, request()).expect("inscription builds");
        let commit_prevout = inscription.commit_tx.output[0].clone();

        let extracted = one_result(&inscription.reveal_tx, &commit_prevout)
            .expect("valid envelope")
            .expect("marker payload");
        assert_eq!(extracted, payload);
        assert_eq!(
            AggregateStateNullifierV3::deserialize(&extracted).expect("payload deserializes"),
            aggregate
        );

        let witness = inscription.reveal_tx.input[0].witness.to_vec();
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[0], [0x01]);
        let leaf_script = ScriptBuf::from_bytes(witness[1].clone());
        let control = ControlBlock::decode(&witness[2]).expect("control block decodes");
        assert_eq!(control.leaf_version, LeafVersion::TapScript);
        // p2tr scriptPubKey: OP_1 (0x51) || OP_PUSHBYTES_32 (0x20) || x-only key
        let spk = commit_prevout.script_pubkey.as_bytes();
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x51);
        assert_eq!(spk[1], 0x20);
        let output_key =
            bitcoin::XOnlyPublicKey::from_slice(&spk[2..34]).expect("p2tr x-only key");
        assert!(control.verify_taproot_commitment(
            &Secp256k1::verification_only(),
            output_key,
            &leaf_script,
        ));
        assert_eq!(
            inscription.reveal_tx.input[0].previous_output,
            OutPoint::new(inscription.commit_tx.compute_txid(), 0)
        );
        assert_eq!(
            inscription
                .commit_tx
                .output
                .iter()
                .map(|output| output.value)
                .sum::<Amount>()
                + Amount::from_sat(600),
            Amount::from_sat(50_000)
        );
        assert_eq!(
            inscription.reveal_tx.output[0].value + Amount::from_sat(500),
            commit_prevout.value
        );
    }

    #[test]
    fn large_payload_uses_multiple_bounded_pushes_and_round_trips() {
        let mut payload = vec![0x42, 0x42];
        payload.extend((0..1_300).map(|index| (index % 251) as u8));
        let inscription = build_inscription(&payload, request()).expect("inscription builds");
        let extracted = one_result(&inscription.reveal_tx, &inscription.commit_tx.output[0])
            .expect("valid envelope")
            .expect("marker payload");
        assert_eq!(extracted, payload);

        let leaf_bytes = inscription.reveal_tx.input[0].witness.to_vec()[1].clone();
        let parsed = parse_instructions(&leaf_bytes).expect("script parses");
        let pushes: Vec<_> = parsed[2..parsed.len() - 1]
            .iter()
            .map(|instruction| {
                instruction
                    .data
                    .as_ref()
                    .expect("body contains only pushes")
            })
            .collect();
        assert!(pushes.len() > 1);
        assert!(pushes
            .iter()
            .all(|push| push.len() <= MAX_SCRIPT_ELEMENT_SIZE));
        assert!(parsed[2..parsed.len() - 1]
            .iter()
            .all(|instruction| instruction.minimal));
    }

    #[test]
    fn two_marker_envelopes_make_input_nullifier_empty() {
        let envelope = build_envelope_script(&[0x42, 0x42, 0x03]).expect("envelope");
        let mut bytes = envelope.clone().into_bytes();
        bytes.extend_from_slice(envelope.as_bytes());
        let (tx, prevout) = commit_script(ScriptBuf::from_bytes(bytes), None);
        assert!(one_result(&tx, &prevout).is_err());
    }

    #[test]
    fn non_minimal_push_makes_input_nullifier_empty() {
        let script = ScriptBuf::from_bytes(vec![
            OP_FALSE_BYTE,
            OP_IF_BYTE,
            OP_PUSHDATA1_BYTE,
            2,
            0x42,
            0x42,
            OP_ENDIF_BYTE,
        ]);
        let (tx, prevout) = commit_script(script, None);
        assert!(one_result(&tx, &prevout).is_err());
    }

    #[test]
    fn oversized_push_makes_input_nullifier_empty() {
        let mut bytes = vec![
            OP_FALSE_BYTE,
            OP_IF_BYTE,
            OP_PUSHDATA2_BYTE,
            0x09,
            0x02,
            0x42,
            0x42,
        ];
        bytes.resize(5 + 521, 0x17);
        bytes.push(OP_ENDIF_BYTE);
        let (tx, prevout) = commit_script(ScriptBuf::from_bytes(bytes), None);
        assert!(one_result(&tx, &prevout).is_err());
    }

    #[test]
    fn non_data_opcode_in_body_makes_input_nullifier_empty() {
        let script = ScriptBuf::from_bytes(vec![
            OP_FALSE_BYTE,
            OP_IF_BYTE,
            2,
            0x42,
            0x42,
            opcodes::all::OP_NOP.to_u8(),
            OP_ENDIF_BYTE,
        ]);
        let (tx, prevout) = commit_script(script, None);
        assert!(one_result(&tx, &prevout).is_err());
    }

    #[test]
    fn annex_is_ignored_while_real_envelope_extracts() {
        let payload = [0x42, 0x42, 0x03, 0x50, 0x42, 0x42];
        let script = build_envelope_script(&payload).expect("envelope");
        let (tx, prevout) = commit_script(script, Some(vec![0x50, 0x42, 0x42, 0xaa]));
        assert_eq!(
            one_result(&tx, &prevout)
                .expect("annex is ignored")
                .expect("payload exists"),
            payload
        );
    }

    #[test]
    fn key_path_input_contributes_nothing() {
        let prevout = TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly_key(9), None),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0x55; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&[[0x7a; 64]]),
            }],
            output: vec![],
        };
        assert_eq!(
            one_result(&tx, &prevout).expect("key path is ignored"),
            None
        );
    }
}
