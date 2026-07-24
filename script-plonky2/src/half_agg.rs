//! Host-side NISSHAC half-aggregation and version-3 nullifier payload codec.
//!
//! This module implements the protocol relations from spec v1.1 §§1.7.10
//! and 3.3, plus the exact `AggregateStateNullifierV3` bytes from §3.5.
//! It deliberately does not implement the Taproot envelope. The scanner is
//! also responsible for checking that `block_anchor` is a strict ancestor of
//! the inclusion block with a gap of at most 100 blocks.

use anyhow::{ensure, Context, Result};
use num::BigUint;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::Field;
use sha2::{Digest, Sha256};
use zkcoins_program_plonky2::circuit::gadgets::curve_types::{
    AffinePoint, Curve, CurveScalar, Secp256K1,
};

use crate::prover_bridge::{canonical_scalar, canonical_x_point, field_bytes, tagged_hash};

/// Prefix identifying a zkCoins inscription payload.
pub const PAYLOAD_MARKER: [u8; 2] = [0x42, 0x42];
/// The only accepted `AggregateStateNullifier` payload version.
pub const PAYLOAD_VERSION_V3: u8 = 0x03;
/// A raw, single-member nullifier payload.
pub const FORMAT_RAW: u8 = 0x00;
/// A NISSHAC half-aggregated nullifier payload.
pub const FORMAT_HALF_AGG: u8 = 0x01;
/// Marker, version, format, count, block hash, and block height.
pub const PAYLOAD_HEADER_LEN: usize = 42;

const HALF_AGG_DOMAIN: &[u8] = b"zkCoins/v1/HalfAgg";

/// Bitcoin tip metadata placed in a version-3 nullifier payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockAnchor {
    pub block_hash: [u8; 32],
    pub height: u32,
}

/// One ordinary BIP-340 signature supplied to the half-aggregator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NullifierSig {
    pub pk: [u8; 32],
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// Exact logical representation of the §3.5 inscription payload.
///
/// `members` stores `(Pk, R)` in inscription order. `format == 0x00`
/// requires exactly one member and `raw_s`; `format == 0x01` requires
/// `s_agg`. The scanner, rather than this byte codec, enforces the
/// `block_anchor` ancestor and inclusion-height-gap rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateStateNullifierV3 {
    pub version: u8,
    pub format: u8,
    pub block_anchor: BlockAnchor,
    pub members: Vec<([u8; 32], [u8; 32])>,
    pub raw_s: Option<[u8; 32]>,
    pub s_agg: Option<[u8; 32]>,
}

impl AggregateStateNullifierV3 {
    /// Serialize the exact §3.5 payload.
    ///
    /// This infallible signature is intentional for the wire API. A malformed
    /// in-memory value panics rather than emitting ambiguous or non-canonical
    /// bytes.
    pub fn serialize(&self) -> Vec<u8> {
        self.validate()
            .expect("refusing to serialize malformed AggregateStateNullifierV3");

        let count = u16::try_from(self.members.len()).expect("validated member count fits in u16");
        let body_len = match self.format {
            FORMAT_RAW => 96,
            FORMAT_HALF_AGG => self
                .members
                .len()
                .checked_mul(64)
                .and_then(|length| length.checked_add(32))
                .expect("validated payload length fits in usize"),
            _ => unreachable!("validate rejected an unknown format"),
        };
        let mut bytes = Vec::with_capacity(PAYLOAD_HEADER_LEN + body_len);
        bytes.extend_from_slice(&PAYLOAD_MARKER);
        bytes.push(self.version);
        bytes.push(self.format);
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&self.block_anchor.block_hash);
        bytes.extend_from_slice(&self.block_anchor.height.to_be_bytes());
        for (pk, r) in &self.members {
            bytes.extend_from_slice(pk);
            bytes.extend_from_slice(r);
        }
        match self.format {
            FORMAT_RAW => bytes.extend_from_slice(
                self.raw_s
                    .as_ref()
                    .expect("validate requires raw_s for raw payloads"),
            ),
            FORMAT_HALF_AGG => bytes.extend_from_slice(
                self.s_agg
                    .as_ref()
                    .expect("validate requires s_agg for aggregate payloads"),
            ),
            _ => unreachable!("validate rejected an unknown format"),
        }
        bytes
    }

    /// Parse one exact §3.5 payload, rejecting unknown values, malformed
    /// lengths, trailing bytes, and non-canonical curve encodings.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= PAYLOAD_HEADER_LEN,
            "AggregateStateNullifierV3 header is truncated"
        );
        ensure!(
            bytes[..2] == PAYLOAD_MARKER,
            "invalid AggregateStateNullifierV3 marker"
        );

        let version = bytes[2];
        ensure!(
            version == PAYLOAD_VERSION_V3,
            "unsupported AggregateStateNullifier version {version:#04x}"
        );
        let format = bytes[3];
        ensure!(
            matches!(format, FORMAT_RAW | FORMAT_HALF_AGG),
            "unsupported AggregateStateNullifierV3 format {format:#04x}"
        );
        let count = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));

        let expected_len = match format {
            FORMAT_RAW => {
                ensure!(
                    count == 1,
                    "raw AggregateStateNullifierV3 count must equal one"
                );
                PAYLOAD_HEADER_LEN + 96
            }
            FORMAT_HALF_AGG => PAYLOAD_HEADER_LEN
                .checked_add(
                    count
                        .checked_mul(64)
                        .context("AggregateStateNullifierV3 member length overflow")?,
                )
                .and_then(|length| length.checked_add(32))
                .context("AggregateStateNullifierV3 payload length overflow")?,
            _ => unreachable!("unknown formats were rejected"),
        };
        ensure!(
            bytes.len() == expected_len,
            "AggregateStateNullifierV3 length is {}, expected {expected_len}",
            bytes.len()
        );

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&bytes[6..38]);
        let height = u32::from_be_bytes(
            bytes[38..42]
                .try_into()
                .expect("validated header contains a four-byte height"),
        );
        let mut cursor = PAYLOAD_HEADER_LEN;
        let mut members = Vec::with_capacity(count);
        for index in 0..count {
            let pk = take_32(bytes, &mut cursor, "member public key")?;
            let r = take_32(bytes, &mut cursor, "member nonce")?;
            validate_member(&pk, &r, index)?;
            members.push((pk, r));
        }
        let scalar = take_32(bytes, &mut cursor, "payload scalar")?;
        canonical_scalar(&scalar, "AggregateStateNullifierV3 scalar")?;
        ensure!(
            cursor == bytes.len(),
            "AggregateStateNullifierV3 has trailing bytes"
        );

        let payload = Self {
            version,
            format,
            block_anchor: BlockAnchor { block_hash, height },
            members,
            raw_s: (format == FORMAT_RAW).then_some(scalar),
            s_agg: (format == FORMAT_HALF_AGG).then_some(scalar),
        };
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == PAYLOAD_VERSION_V3,
            "AggregateStateNullifier version must be 0x03"
        );
        ensure!(
            self.members.len() <= usize::from(u16::MAX),
            "AggregateStateNullifierV3 member count exceeds u16"
        );
        match self.format {
            FORMAT_RAW => {
                ensure!(
                    self.members.len() == 1,
                    "raw AggregateStateNullifierV3 count must equal one"
                );
                ensure!(
                    self.raw_s.is_some() && self.s_agg.is_none(),
                    "raw AggregateStateNullifierV3 requires only raw_s"
                );
            }
            FORMAT_HALF_AGG => {
                ensure!(
                    self.raw_s.is_none() && self.s_agg.is_some(),
                    "half-aggregate AggregateStateNullifierV3 requires only s_agg"
                );
            }
            _ => anyhow::bail!(
                "unsupported AggregateStateNullifierV3 format {:#04x}",
                self.format
            ),
        }
        for (index, (pk, r)) in self.members.iter().enumerate() {
            validate_member(pk, r, index)?;
        }
        let scalar = match self.format {
            FORMAT_RAW => self.raw_s.as_ref().expect("presence checked above"),
            FORMAT_HALF_AGG => self.s_agg.as_ref().expect("presence checked above"),
            _ => unreachable!("unknown formats were rejected"),
        };
        canonical_scalar(scalar, "AggregateStateNullifierV3 scalar")?;
        Ok(())
    }
}

/// Verify one ordinary BIP-340 signature over `m_state`.
pub fn verify_single(pk: &[u8; 32], r: &[u8; 32], s: &[u8; 32], m_state: &[u8]) -> Result<()> {
    let public_key = canonical_x_point(pk, "BIP-340 public key")?;
    let nonce = canonical_x_point(r, "BIP-340 nonce")?;
    let scalar = canonical_scalar(s, "BIP-340 signature scalar")?;
    let challenge = challenge_scalar(r, pk, m_state);

    let lhs = CurveScalar(scalar) * Secp256K1::GENERATOR_PROJECTIVE;
    let rhs = nonce + (CurveScalar(challenge) * public_key.to_projective()).to_affine();
    ensure!(lhs == rhs, "invalid BIP-340 signature");
    Ok(())
}

/// Half-aggregate signatures into a format-`0x01` payload object.
///
/// NISSHAC itself does not sign or commit the Bitcoin anchor, so this
/// convenience API uses `BlockAnchor::default()`. Publication code should use
/// [`aggregate_sig_with_anchor`] to install its chosen, scanner-checkable
/// anchor.
pub fn aggregate_sig(members: &[NullifierSig]) -> Result<AggregateStateNullifierV3> {
    aggregate_sig_with_anchor(members, BlockAnchor::default())
}

/// Half-aggregate signatures and attach the publisher's chosen block anchor.
pub fn aggregate_sig_with_anchor(
    members: &[NullifierSig],
    block_anchor: BlockAnchor,
) -> Result<AggregateStateNullifierV3> {
    ensure!(!members.is_empty(), "cannot half-aggregate zero signatures");
    ensure!(
        members.len() <= usize::from(u16::MAX),
        "half-aggregate member count exceeds u16"
    );

    for (index, member) in members.iter().enumerate() {
        validate_member(&member.pk, &member.r, index)?;
        canonical_scalar(&member.s, &format!("member {index} signature scalar"))?;
    }
    let coefficients = aggregation_coefficients(
        &members
            .iter()
            .map(|member| (member.pk, member.r))
            .collect::<Vec<_>>(),
    )?;
    let mut aggregate_scalar = Secp256K1Scalar::ZERO;
    for (member, coefficient) in members.iter().zip(coefficients) {
        let scalar = canonical_scalar(&member.s, "member signature scalar")?;
        aggregate_scalar += coefficient * scalar;
    }

    Ok(AggregateStateNullifierV3 {
        version: PAYLOAD_VERSION_V3,
        format: FORMAT_HALF_AGG,
        block_anchor,
        members: members.iter().map(|member| (member.pk, member.r)).collect(),
        raw_s: None,
        s_agg: Some(field_bytes(aggregate_scalar)),
    })
}

/// Verify the single NISSHAC multi-scalar relation for a half-aggregate.
pub fn aggregate_verify(agg: &AggregateStateNullifierV3, m_state: &[u8]) -> Result<()> {
    agg.validate()?;
    ensure!(
        agg.format == FORMAT_HALF_AGG,
        "AggregateVerify requires format 0x01"
    );
    ensure!(
        !agg.members.is_empty(),
        "AggregateVerify rejects an empty aggregate"
    );

    let aggregate_scalar = canonical_scalar(
        agg.s_agg
            .as_ref()
            .expect("aggregate payload validation requires s_agg"),
        "aggregate signature scalar",
    )?;
    let coefficients = aggregation_coefficients(&agg.members)?;
    let mut rhs = AffinePoint::<Secp256K1>::ZERO.to_projective();
    for (index, ((pk_bytes, r_bytes), coefficient)) in
        agg.members.iter().zip(coefficients).enumerate()
    {
        let public_key = canonical_x_point(pk_bytes, &format!("member {index} public key"))?;
        let nonce = canonical_x_point(r_bytes, &format!("member {index} nonce"))?;
        let challenge = challenge_scalar(r_bytes, pk_bytes, m_state);
        let signature_rhs =
            nonce + (CurveScalar(challenge) * public_key.to_projective()).to_affine();
        rhs = rhs + CurveScalar(coefficient) * signature_rhs;
    }

    let lhs = CurveScalar(aggregate_scalar) * Secp256K1::GENERATOR_PROJECTIVE;
    ensure!(lhs == rhs, "invalid NISSHAC half-aggregate");
    Ok(())
}

/// Return a retained commitment nonce by zero-based member index.
///
/// Invalid aggregate state or an out-of-range index fails loudly by panic,
/// matching this function's deliberately infallible return type.
pub fn comm_retrieve(agg: &AggregateStateNullifierV3, j: usize) -> [u8; 32] {
    agg.validate()
        .expect("CommRetrieve requires a valid AggregateStateNullifierV3");
    assert_eq!(
        agg.format, FORMAT_HALF_AGG,
        "CommRetrieve requires format 0x01"
    );
    agg.members[j].1
}

/// Verify the receiver's sign-to-contract opening.
///
/// The SHA-256 tweak is interpreted as an unreduced big-endian integer and
/// therefore must already be strictly smaller than the secp256k1 group order.
pub fn comm_verify(r: &[u8; 32], m_sc: &[u8; 32], r_prime: &[u8; 32]) -> Result<()> {
    let commitment = canonical_x_point(r, "S2C commitment R")?;
    let opening = canonical_x_point(r_prime, "S2C opening R'")?;

    let mut tweak_preimage = [0u8; 64];
    tweak_preimage[..32].copy_from_slice(r_prime);
    tweak_preimage[32..].copy_from_slice(m_sc);
    let tweak_bytes: [u8; 32] = Sha256::digest(tweak_preimage).into();
    let tweak_integer = BigUint::from_bytes_be(&tweak_bytes);
    ensure!(
        tweak_integer < Secp256K1Scalar::order(),
        "S2C tweak is not an unreduced canonical secp256k1 scalar"
    );
    let tweak = Secp256K1Scalar::from_noncanonical_biguint(tweak_integer);
    let opened = opening + (CurveScalar(tweak) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
    ensure!(!opened.to_affine().zero, "S2C opening produced infinity");
    ensure!(
        commitment.to_projective() == opened,
        "invalid sign-to-contract opening"
    );
    Ok(())
}

fn challenge_scalar(r: &[u8; 32], pk: &[u8; 32], m_state: &[u8]) -> Secp256K1Scalar {
    let mut preimage = Vec::with_capacity(64 + m_state.len());
    preimage.extend_from_slice(r);
    preimage.extend_from_slice(pk);
    preimage.extend_from_slice(m_state);
    Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&tagged_hash(
        b"BIP0340/challenge",
        &preimage,
    )))
}

fn aggregation_coefficients(members: &[([u8; 32], [u8; 32])]) -> Result<Vec<Secp256K1Scalar>> {
    ensure!(
        members.len() <= u32::MAX as usize,
        "half-aggregate member index exceeds u32"
    );
    let mut transcript = Vec::with_capacity(HALF_AGG_DOMAIN.len() + 64 * members.len());
    transcript.extend_from_slice(HALF_AGG_DOMAIN);
    for (pk, r) in members {
        transcript.extend_from_slice(r);
        transcript.extend_from_slice(pk);
    }
    let z: [u8; 32] = Sha256::digest(transcript).into();

    let mut coefficients = Vec::with_capacity(members.len());
    for index in 1..=members.len() {
        let mut preimage = [0u8; 36];
        preimage[..32].copy_from_slice(&z);
        preimage[32..].copy_from_slice(&(index as u32).to_be_bytes());
        let digest = Sha256::digest(preimage);
        coefficients.push(Secp256K1Scalar::from_noncanonical_biguint(
            BigUint::from_bytes_be(&digest),
        ));
    }
    Ok(coefficients)
}

fn validate_member(pk: &[u8; 32], r: &[u8; 32], index: usize) -> Result<()> {
    canonical_x_point(pk, &format!("member {index} public key"))?;
    canonical_x_point(r, &format!("member {index} nonce"))?;
    Ok(())
}

fn take_32(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<[u8; 32]> {
    let end = cursor
        .checked_add(32)
        .with_context(|| format!("{label} offset overflow"))?;
    let slice = bytes
        .get(*cursor..end)
        .with_context(|| format!("AggregateStateNullifierV3 truncated in {label}"))?;
    *cursor = end;
    Ok(slice
        .try_into()
        .expect("a checked 32-byte slice converts to an array"))
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use zkcoins_program_plonky2::circuit::compliance::Network;

    use super::*;
    use crate::prover_bridge::test_signing::{
        deterministic_secret, normalized_key, sign_transition,
    };
    use shared::spec_v1::{self as host, ProofData, ZERO_HASH};

    struct SignedMembers {
        members: Vec<NullifierSig>,
        openings: Vec<[u8; 32]>,
        messages_sc: Vec<[u8; 32]>,
    }

    fn hex_32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)
                .expect("fixture is valid hexadecimal");
        }
        bytes
    }

    fn signed_members(count: usize) -> SignedMembers {
        let mut members = Vec::with_capacity(count);
        let mut openings = Vec::with_capacity(count);
        let mut messages_sc = Vec::with_capacity(count);
        for index in 0..count {
            let label = format!("zkCoins/v1/half-agg/test-secret-{index}");
            let (secret, public, _) = normalized_key(deterministic_secret(label.as_bytes()));
            let proof_data = ProofData {
                new_account_state_hash: ZERO_HASH,
                output_coins_root: ZERO_HASH,
                input_nullifiers_root: ZERO_HASH,
                coin_history_root: ZERO_HASH,
                nav_commitment: ZERO_HASH,
                npk_commit: Sha256::digest(format!("next-key-{index}")).into(),
            };
            let signed = sign_transition(secret, public, &proof_data, Network::Testnet);
            let transition = signed.transition;
            let r = transition.signature_r();
            let s = transition.signature_s();
            members.push(NullifierSig {
                pk: transition.pk_i,
                r,
                s,
            });
            openings.push(transition.r_prime);
            messages_sc.push(host::hash_proof_data(&host::serialize_proof_data(
                &proof_data,
            )));
        }
        SignedMembers {
            members,
            openings,
            messages_sc,
        }
    }

    #[test]
    fn nisshac_completeness_for_one_two_and_three_members() {
        for count in [1, 2, 3] {
            let fixture = signed_members(count);
            for member in &fixture.members {
                verify_single(
                    &member.pk,
                    &member.r,
                    &member.s,
                    Network::Testnet.m_state_bytes(),
                )
                .expect("test signer must produce valid BIP-340 signatures");
            }
            let aggregate = aggregate_sig(&fixture.members).expect("aggregation succeeds");
            aggregate_verify(&aggregate, Network::Testnet.m_state_bytes())
                .expect("valid signatures must form a valid half-aggregate");
        }
    }

    #[test]
    fn nisshac_matches_the_normative_v8_fixture() {
        let members = [
            NullifierSig {
                pk: hex_32("e7f2a98e7b45e9424e3e0cb1d937a1698ebd339c6d8344906db979642cf20474"),
                r: hex_32("c41ff1a78f2006e5f5aa800efa84b2d2046d108dfa968909974ec37fcb87f6c4"),
                s: hex_32("748ae8e2fded9df9830cbaa8893484e753fdfd141cccc8b35a27ab5a870a83d2"),
            },
            NullifierSig {
                pk: hex_32("21799353e64a65ee4b1f414998c44878c56270cf8a81046cb3636e5ec31a3341"),
                r: hex_32("bd22b77069c75431ee3676bea7324a59e9b6466a62a9a3021f831e6ccf5d3220"),
                s: hex_32("caa0374d3cf77e1874298c98d3d3fe8b416f89d51823d6909c3e1cdbf91d3002"),
            },
        ];
        for member in &members {
            verify_single(
                &member.pk,
                &member.r,
                &member.s,
                Network::Testnet.m_state_bytes(),
            )
            .expect("normative V.8 signature must verify");
        }

        let aggregate = aggregate_sig(&members).expect("normative V.8 members aggregate");
        assert_eq!(
            aggregate.s_agg,
            Some(hex_32(
                "cfb0c36a8399589b5580ba41cafaf66b7d707443a202e4113f3635872ca58b78"
            ))
        );
        aggregate_verify(&aggregate, Network::Testnet.m_state_bytes())
            .expect("normative V.8 aggregate must verify");

        comm_verify(
            &members[0].r,
            &hex_32("bf50cc59a665bcdc2b5f0754dd754a73e37552a6b1b69eb9e42c07ddd1ae73e2"),
            &hex_32("5657f2e91dc3a2d248501a37dbe674d2cf8ed1a13c89b7710ca89aad3b9fe050"),
        )
        .expect("normative V.8 signer-one opening must verify");
        comm_verify(
            &members[1].r,
            &hex_32("85d06ebe2f0f5173af9ff8bdd2d4d594303a640d7b2f1c8819d5a48abfa4773d"),
            &hex_32("9c18a07c07be5225b688895f73daaffefdd62cbb49e1b854dd47f5aee1484193"),
        )
        .expect("normative V.8 signer-two opening must verify");
    }

    #[test]
    fn nisshac_rejects_tampering_and_noncanonical_members() {
        let fixture = signed_members(3);
        let aggregate = aggregate_sig(&fixture.members).expect("aggregation succeeds");

        let mut bad_scalar = aggregate.clone();
        bad_scalar.s_agg.as_mut().expect("aggregate scalar")[31] ^= 1;
        assert!(aggregate_verify(&bad_scalar, Network::Testnet.m_state_bytes()).is_err());

        let mut bad_r = aggregate.clone();
        bad_r.members[0].1 = aggregate.members[1].1;
        assert!(aggregate_verify(&bad_r, Network::Testnet.m_state_bytes()).is_err());

        let mut bad_pk = aggregate.clone();
        bad_pk.members[0].0 = aggregate.members[1].0;
        assert!(aggregate_verify(&bad_pk, Network::Testnet.m_state_bytes()).is_err());

        let mut noncanonical = aggregate.clone();
        noncanonical.members[0].0 = [0xff; 32];
        assert!(aggregate_verify(&noncanonical, Network::Testnet.m_state_bytes()).is_err());

        let mut off_curve = aggregate.clone();
        off_curve.members[0].1 = [0u8; 32];
        assert!(aggregate_verify(&off_curve, Network::Testnet.m_state_bytes()).is_err());

        let order_bytes = Secp256K1Scalar::order().to_bytes_be();
        let mut noncanonical_s = [0u8; 32];
        noncanonical_s[32 - order_bytes.len()..].copy_from_slice(&order_bytes);
        let mut bad_member = fixture.members[0];
        bad_member.s = noncanonical_s;
        assert!(aggregate_sig(&[bad_member]).is_err());
    }

    #[test]
    fn comm_verify_accepts_honest_opening_and_rejects_wrong_values() {
        let fixture = signed_members(2);
        let aggregate = aggregate_sig(&fixture.members).expect("aggregation succeeds");
        let r = comm_retrieve(&aggregate, 0);
        comm_verify(&r, &fixture.messages_sc[0], &fixture.openings[0])
            .expect("honest S2C opening must verify");

        let mut wrong_message = fixture.messages_sc[0];
        wrong_message[0] ^= 1;
        assert!(comm_verify(&r, &wrong_message, &fixture.openings[0]).is_err());
        assert!(comm_verify(&r, &fixture.messages_sc[0], &fixture.openings[1]).is_err());
    }

    #[test]
    fn payload_round_trips_raw_and_half_aggregate() {
        let fixture = signed_members(3);
        let anchor = BlockAnchor {
            block_hash: [0xa5; 32],
            height: 840_000,
        };
        let raw = AggregateStateNullifierV3 {
            version: PAYLOAD_VERSION_V3,
            format: FORMAT_RAW,
            block_anchor: anchor,
            members: vec![(fixture.members[0].pk, fixture.members[0].r)],
            raw_s: Some(fixture.members[0].s),
            s_agg: None,
        };
        assert_eq!(
            AggregateStateNullifierV3::deserialize(&raw.serialize()).expect("raw payload parses"),
            raw
        );

        let aggregate =
            aggregate_sig_with_anchor(&fixture.members, anchor).expect("aggregate payload builds");
        assert_eq!(
            AggregateStateNullifierV3::deserialize(&aggregate.serialize())
                .expect("aggregate payload parses"),
            aggregate
        );
    }

    #[test]
    fn payload_parser_rejects_every_malformed_shape() {
        let fixture = signed_members(3);
        let aggregate = aggregate_sig(&fixture.members).expect("aggregation succeeds");
        let encoded = aggregate.serialize();

        let mut bad_marker = encoded.clone();
        bad_marker[0] ^= 1;
        assert!(AggregateStateNullifierV3::deserialize(&bad_marker).is_err());

        let mut bad_version = encoded.clone();
        bad_version[2] = 0x02;
        assert!(AggregateStateNullifierV3::deserialize(&bad_version).is_err());

        let mut bad_format = encoded.clone();
        bad_format[3] = 0x02;
        assert!(AggregateStateNullifierV3::deserialize(&bad_format).is_err());

        let mut count_overrun = encoded.clone();
        count_overrun[4..6].copy_from_slice(&4u16.to_be_bytes());
        assert!(AggregateStateNullifierV3::deserialize(&count_overrun).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(AggregateStateNullifierV3::deserialize(&trailing).is_err());

        let truncated = &encoded[..encoded.len() - 33];
        assert!(AggregateStateNullifierV3::deserialize(truncated).is_err());

        let raw = AggregateStateNullifierV3 {
            version: PAYLOAD_VERSION_V3,
            format: FORMAT_RAW,
            block_anchor: BlockAnchor::default(),
            members: vec![(fixture.members[0].pk, fixture.members[0].r)],
            raw_s: Some(fixture.members[0].s),
            s_agg: None,
        };
        let mut raw_bad_count = raw.serialize();
        raw_bad_count[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert!(AggregateStateNullifierV3::deserialize(&raw_bad_count).is_err());
    }

    #[test]
    fn payload_size_report_at_required_batch_sizes() {
        let fixture = signed_members(1);
        let base = aggregate_sig(&fixture.members).expect("aggregation succeeds");
        for count in [1usize, 10, 100] {
            let mut aggregate = base.clone();
            aggregate.members = vec![base.members[0]; count];
            let length = aggregate.serialize().len();
            println!("half_agg payload bytes at k={count}: {length}");
            assert_eq!(length, PAYLOAD_HEADER_LEN + 64 * count + 32);
        }
    }
}
