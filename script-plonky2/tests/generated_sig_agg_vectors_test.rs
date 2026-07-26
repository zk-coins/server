//! Generates `script-plonky2/tests/generated_sig_agg_vectors.txt`.
//!
//! Fills the two long-form `<REGEN>` slots that no earlier generator produces:
//! - **V.5** transition signature — BIP-340 + S2C over `H(ProofData@0)` with
//!   the V.2-ext keys (curve-valid). Emitted for **all three** networks
//!   (the fixture does not pin a single `m_state`). Values are the **reference
//!   implementation's output** (this generator), proposed for specification
//!   appendix V.5 in PR #124 — an unmerged draft, not a published-spec pin.
//! - **V.6** aggregate scalar `s_agg` — Σⱼ aⱼ·sⱼ mod n over the **V.8**
//!   two-signer member set (`m = 2` layout in V.6; V.8 is the only fully
//!   pinned two-member signing/aggregation fixture).
//!
//! Nonce rule: the V.8 fixture rule (deterministic test-vector nonce rule)
//! so the vectors are reproducible. Production nonces remain signer-private.
//!
//! Values are **computed**, never hand-copied. Self-checks:
//! - each V.5 signature verifies under BIP-340 (`verify_single`) and opens
//!   under `comm_verify` against `H(ProofData@0)`;
//! - V.6 `s_agg` is produced by `aggregate_sig` and passes `aggregate_verify`;
//! - the V.8 nonce-rule signer recomputes the pinned V.8 rows bit-for-bit
//!   before those members feed `s_agg`.
//!
//! Re-run:
//! `cargo test -p zkcoins-prover-plonky2 --test generated_sig_agg_vectors_test generate_sig_agg_vectors -- --nocapture`
//!
//! Lives under `tests/` (not `src/`) so the generator is never part of the
//! library. Helpers that mirror `prover_bridge`'s `pub(crate)` encoding
//! utilities are local copies — the production API is not widened for tests.

use std::fs;
use std::path::PathBuf;

use num::BigUint;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField};
use sha2::{Digest, Sha256};
use zkcoins_program_plonky2::circuit::compliance::Network;
use zkcoins_program_plonky2::circuit::gadgets::curve_types::{
    AffinePoint, Curve, CurveScalar, Secp256K1,
};
use zkcoins_prover_plonky2::half_agg::{
    aggregate_sig, aggregate_sig_with_anchor, aggregate_verify, comm_verify, verify_single,
    BlockAnchor, NullifierSig,
};

// ── Local copies of prover_bridge `pub(crate)` helpers (test-only) ───────────
// Identical semantics to the production encoding helpers; kept here so this
// integration test does not force those internals into the public API.

fn field_bytes<FF: PrimeField>(value: FF) -> [u8; 32] {
    let encoded = value.to_canonical_biguint().to_bytes_be();
    assert!(encoded.len() <= 32);
    let mut bytes = [0u8; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    bytes
}

fn is_odd<FF: PrimeField>(value: FF) -> bool {
    (&value.to_canonical_biguint() & BigUint::from(1u8)) == BigUint::from(1u8)
}

fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut preimage = Vec::with_capacity(64 + message.len());
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(message);
    Sha256::digest(preimage).into()
}

fn assert_canonical_scalar(bytes: &[u8; 32], label: &str) {
    let integer = BigUint::from_bytes_be(bytes);
    assert!(
        integer < Secp256K1Scalar::order(),
        "{label} is not a canonical secp256k1 scalar"
    );
}

// ── V.2-ext keys (spec V.2-ext table; BIP-32 hardened, curve-valid) ──────────
const V2EXT_SK0_HEX: &str = "4a8e3a83404f1aa99e89af57179dcf033820b816c0d78ac94fcb322d6ee85649";
const V2EXT_PK0_HEX: &str = "7c9cdde9b8cb1e33a48a5c2b6ab1fa6fd753fa1762f56c0b3e8169e4f2d54630";

// ── V.4 pin: H(ProofData@0) from shared/tests/generated_poseidon_vectors.txt ─
const H_PROOF_DATA_0_HEX: &str = "db8c60533ba19eba14958f6ce44fd8df2e784d17dac28d8532e66fa938308de4";

// ── V.8 synthetic signing fixture (spec V.8; testnet m_state) ───────────────
const V8_SK_SIG_1_HEX: &str = "22f508c0a93b29fa87ca8d9abcec996f01620656cd7a7e4ab5418b2e76beccf4";
const V8_D_1_HEX: &str = "22f508c0a93b29fa87ca8d9abcec996f01620656cd7a7e4ab5418b2e76beccf4";
const V8_PK_1_HEX: &str = "e7f2a98e7b45e9424e3e0cb1d937a1698ebd339c6d8344906db979642cf20474";
const V8_M_SC_1_HEX: &str = "bf50cc59a665bcdc2b5f0754dd754a73e37552a6b1b69eb9e42c07ddd1ae73e2";
const V8_R_PRIME_1_HEX: &str = "5657f2e91dc3a2d248501a37dbe674d2cf8ed1a13c89b7710ca89aad3b9fe050";
const V8_R_1_HEX: &str = "c41ff1a78f2006e5f5aa800efa84b2d2046d108dfa968909974ec37fcb87f6c4";
const V8_S_1_HEX: &str = "748ae8e2fded9df9830cbaa8893484e753fdfd141cccc8b35a27ab5a870a83d2";

const V8_SK_SIG_2_HEX: &str = "86b75c297fd9a0af472d06fbf889f7e4667c9e42b7d7efc8b1ca7e66b95462c0";
const V8_D_2_HEX: &str = "7948a3d680265f50b8d2f9040776081a54323ea3f770b0730e07e02616e1de81";
const V8_PK_2_HEX: &str = "21799353e64a65ee4b1f414998c44878c56270cf8a81046cb3636e5ec31a3341";
const V8_M_SC_2_HEX: &str = "85d06ebe2f0f5173af9ff8bdd2d4d594303a640d7b2f1c8819d5a48abfa4773d";
const V8_R_PRIME_2_HEX: &str = "9c18a07c07be5225b688895f73daaffefdd62cbb49e1b854dd47f5aee1484193";
const V8_R_2_HEX: &str = "bd22b77069c75431ee3676bea7324a59e9b6466a62a9a3021f831e6ccf5d3220";
const V8_S_2_HEX: &str = "caa0374d3cf77e1874298c98d3d3fe8b416f89d51823d6909c3e1cdbf91d3002";

const V8_S_AGG_HEX: &str = "cfb0c36a8399589b5580ba41cafaf66b7d707443a202e4113f3635872ca58b78";

struct SignedOpening {
    pk: [u8; 32],
    r_prime: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    signature: [u8; 64],
}

fn hex_32(value: &str) -> [u8; 32] {
    assert_eq!(
        value.len(),
        64,
        "expected 64 hex chars, got {} for {value}",
        value.len()
    );
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)
            .unwrap_or_else(|e| panic!("invalid hex in fixture {value}: {e}"));
    }
    bytes
}

fn hex64_of(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn scalar_from_be32(bytes: &[u8; 32]) -> Secp256K1Scalar {
    let integer = BigUint::from_bytes_be(bytes);
    // Fail loud if the fixture scalar is non-canonical (not merely reduce).
    assert!(
        integer < Secp256K1Scalar::order(),
        "scalar fixture is not a canonical secp256k1 scalar"
    );
    Secp256K1Scalar::from_noncanonical_biguint(integer)
}

fn scalar_mod_n_from_be32(bytes: &[u8; 32]) -> Secp256K1Scalar {
    // BIP-340 / V.8: int(·) mod n — from_noncanonical_biguint reduces.
    Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(bytes))
}

/// BIP-340 key normalisation: even-y public key, matching secret `d`.
fn bip340_normalise(
    secret: Secp256K1Scalar,
) -> (Secp256K1Scalar, AffinePoint<Secp256K1>, [u8; 32]) {
    let mut d = secret;
    let mut public = (CurveScalar(d) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
    if is_odd(public.y) {
        d = -d;
        public = -public;
    }
    assert!(!is_odd(public.y), "BIP-340 public key must have even y");
    (d, public, field_bytes(public.x))
}

/// V.8 fixture nonce rule (test-vector only, not production-normative).
///
/// ```text
/// masked   = d XOR int(tagged_hash("BIP0340/aux", 0x00×32))
/// rand_ctr = tagged_hash("BIP0340/nonce", masked ‖ Pk ‖ m_state ‖ u32-be(ctr))
/// k'       = int(rand_ctr) mod n
/// ```
/// starting at `ctr = 0`, incrementing on every §3.2 step-3b redraw and on
/// `k' = 0`. Step 1b even-y normalisation of `R'` is applied after each draw.
fn sign_s2c_v8_nonce(
    d: Secp256K1Scalar,
    pk_bytes: &[u8; 32],
    m_sc: &[u8; 32],
    m_state: &[u8],
) -> SignedOpening {
    let d_bytes = field_bytes(d);
    let aux = tagged_hash(b"BIP0340/aux", &[0u8; 32]);
    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = d_bytes[i] ^ aux[i];
    }

    // Bound the redraw loop; honest draws terminate in ~2 expected attempts.
    for ctr in 0u32..10_000 {
        let mut nonce_preimage = Vec::with_capacity(32 + 32 + m_state.len() + 4);
        nonce_preimage.extend_from_slice(&masked);
        nonce_preimage.extend_from_slice(pk_bytes);
        nonce_preimage.extend_from_slice(m_state);
        nonce_preimage.extend_from_slice(&ctr.to_be_bytes());
        let rand_ctr = tagged_hash(b"BIP0340/nonce", &nonce_preimage);
        let mut k_prime = scalar_mod_n_from_be32(&rand_ctr);
        if k_prime.is_zero() {
            continue;
        }

        let mut r_prime = (CurveScalar(k_prime) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
        // §3.2 step 1b: even-y normalise R'.
        if is_odd(r_prime.y) {
            k_prime = -k_prime;
            r_prime = -r_prime;
        }
        let r_prime_bytes = field_bytes(r_prime.x);

        let mut tweak_preimage = [0u8; 64];
        tweak_preimage[..32].copy_from_slice(&r_prime_bytes);
        tweak_preimage[32..].copy_from_slice(m_sc);
        let tweak_bytes: [u8; 32] = Sha256::digest(tweak_preimage).into();
        let tweak_integer = BigUint::from_bytes_be(&tweak_bytes);
        // §3.2 step 3b: t must be an unreduced canonical scalar.
        if tweak_integer >= Secp256K1Scalar::order() {
            continue;
        }
        let tweak = Secp256K1Scalar::from_noncanonical_biguint(tweak_integer);
        let r = (r_prime + (CurveScalar(tweak) * Secp256K1::GENERATOR_PROJECTIVE).to_affine())
            .to_affine();
        if r.zero || is_odd(r.y) {
            continue;
        }
        let rx_bytes = field_bytes(r.x);

        let mut challenge_preimage = Vec::with_capacity(64 + m_state.len());
        challenge_preimage.extend_from_slice(&rx_bytes);
        challenge_preimage.extend_from_slice(pk_bytes);
        challenge_preimage.extend_from_slice(m_state);
        let e = scalar_mod_n_from_be32(&tagged_hash(b"BIP0340/challenge", &challenge_preimage));
        let s = k_prime + tweak + e * d;
        if s.is_zero() {
            continue;
        }
        let s_bytes = field_bytes(s);
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&rx_bytes);
        signature[32..].copy_from_slice(&s_bytes);
        return SignedOpening {
            pk: *pk_bytes,
            r_prime: r_prime_bytes,
            r: rx_bytes,
            s: s_bytes,
            signature,
        };
    }
    panic!("V.8 nonce-rule signer exhausted redraw budget without a valid signature");
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

#[test]
fn generate_sig_agg_vectors() {
    // ── Sanity: V.8 nonce-rule signer recomputes the pinned fixture ─────────
    let (d1, _, pk1) = bip340_normalise(scalar_from_be32(&hex_32(V8_SK_SIG_1_HEX)));
    assert_eq!(
        field_bytes(d1),
        hex_32(V8_D_1_HEX),
        "V.8 signer-1 d mismatch"
    );
    assert_eq!(pk1, hex_32(V8_PK_1_HEX), "V.8 signer-1 Pk mismatch");
    let m_sc_1 = hex_32(V8_M_SC_1_HEX);
    let signed1 = sign_s2c_v8_nonce(d1, &pk1, &m_sc_1, Network::Testnet.m_state_bytes());
    assert_eq!(
        signed1.r_prime,
        hex_32(V8_R_PRIME_1_HEX),
        "V.8 R'_1 mismatch"
    );
    assert_eq!(signed1.r, hex_32(V8_R_1_HEX), "V.8 R_1 mismatch");
    assert_eq!(signed1.s, hex_32(V8_S_1_HEX), "V.8 s_1 mismatch");

    let (d2, _, pk2) = bip340_normalise(scalar_from_be32(&hex_32(V8_SK_SIG_2_HEX)));
    assert_eq!(
        field_bytes(d2),
        hex_32(V8_D_2_HEX),
        "V.8 signer-2 d mismatch"
    );
    assert_eq!(pk2, hex_32(V8_PK_2_HEX), "V.8 signer-2 Pk mismatch");
    let m_sc_2 = hex_32(V8_M_SC_2_HEX);
    let signed2 = sign_s2c_v8_nonce(d2, &pk2, &m_sc_2, Network::Testnet.m_state_bytes());
    assert_eq!(
        signed2.r_prime,
        hex_32(V8_R_PRIME_2_HEX),
        "V.8 R'_2 mismatch"
    );
    assert_eq!(signed2.r, hex_32(V8_R_2_HEX), "V.8 R_2 mismatch");
    assert_eq!(signed2.s, hex_32(V8_S_2_HEX), "V.8 s_2 mismatch");

    // ── V.6: s_agg over the V.8 two-signer member set via aggregate_sig ─────
    // s_agg depends only on members' (pk, R, s) — NOT on block_anchor
    // (aggregate_sig_with_anchor stores the anchor but never folds it into
    // the coefficient transcript or the scalar sum; see half_agg.rs).
    let members = [
        NullifierSig {
            pk: signed1.pk,
            r: signed1.r,
            s: signed1.s,
        },
        NullifierSig {
            pk: signed2.pk,
            r: signed2.r,
            s: signed2.s,
        },
    ];
    for member in &members {
        verify_single(
            &member.pk,
            &member.r,
            &member.s,
            Network::Testnet.m_state_bytes(),
        )
        .expect("V.8 recomputed member must BIP-340-verify under testnet m_state");
    }
    comm_verify(&signed1.r, &m_sc_1, &signed1.r_prime)
        .expect("V.8 signer-1 S2C opening must verify");
    comm_verify(&signed2.r, &m_sc_2, &signed2.r_prime)
        .expect("V.8 signer-2 S2C opening must verify");

    let aggregate = aggregate_sig(&members).expect("V.8 members must half-aggregate");
    let s_agg = aggregate
        .s_agg
        .expect("half-aggregate payload must carry s_agg");
    assert_eq!(
        s_agg,
        hex_32(V8_S_AGG_HEX),
        "computed s_agg must match the V.8 pin (and thus fill V.6)"
    );
    aggregate_verify(&aggregate, Network::Testnet.m_state_bytes())
        .expect("V.6/V.8 s_agg must aggregate_verify under testnet m_state");

    // Confirm anchor independence: same members + non-default anchor → same s_agg.
    let with_anchor = aggregate_sig_with_anchor(
        &members,
        BlockAnchor {
            block_hash: [0xa5; 32],
            height: 840_000,
        },
    )
    .expect("aggregate with anchor");
    assert_eq!(
        with_anchor.s_agg.expect("s_agg present"),
        s_agg,
        "s_agg must be independent of block_anchor"
    );

    // ── V.5: V.2-ext sk₀ / Pk₀ over H(ProofData@0), all three networks ─────
    let h_proof_data_0 = hex_32(H_PROOF_DATA_0_HEX);
    let (d0, _, pk0) = bip340_normalise(scalar_from_be32(&hex_32(V2EXT_SK0_HEX)));
    assert_eq!(
        pk0,
        hex_32(V2EXT_PK0_HEX),
        "V.2-ext Pk₀ must match the pinned x-only public key"
    );
    // The secret used for signing is the BIP-340-normalised d, not raw sk₀.
    // (pk₀ lift / BIP-340 validity is covered by verify_single below.)
    assert_canonical_scalar(&field_bytes(d0), "V.2-ext d0");

    let networks = [Network::Mainnet, Network::Testnet, Network::Regtest];
    let mut v5_openings: Vec<(Network, SignedOpening)> = Vec::with_capacity(3);
    for network in networks {
        let signed = sign_s2c_v8_nonce(d0, &pk0, &h_proof_data_0, network.m_state_bytes());
        verify_single(&signed.pk, &signed.r, &signed.s, network.m_state_bytes()).unwrap_or_else(
            |e| {
                panic!(
                    "V.5 signature must BIP-340-verify under {}: {e}",
                    network_label(network)
                )
            },
        );
        comm_verify(&signed.r, &h_proof_data_0, &signed.r_prime).unwrap_or_else(|e| {
            panic!(
                "V.5 S2C opening must verify under {}: {e}",
                network_label(network)
            )
        });
        assert_eq!(signed.pk, pk0, "signature must be under V.2-ext Pk₀");
        v5_openings.push((network, signed));
    }

    // ── Emit ───────────────────────────────────────────────────────────────
    let mut lines: Vec<String> = Vec::new();
    lines.push("# generated_sig_agg_vectors.txt — V.5 signature + V.6 s_agg".into());
    lines.push("# Computed by script-plonky2 generate_sig_agg_vectors; never hand-edit.".into());
    lines.push("#".into());
    lines.push(
        "# V.5 inputs (reference-implementation output; proposed for V.5 in PR #124 draft):"
            .into(),
    );
    lines.push("#   sk/Pk = V.2-ext sk₀/Pk₀ (BIP-340-normalised d used for signing)".into());
    lines.push("#   H(ProofData@0) = V.4 pin from generated_poseidon_vectors.txt".into());
    lines
        .push("#   nonce rule = V.8 fixture rule (deterministic; not production-normative)".into());
    lines.push(
        "#   networks = mainnet | testnet | regtest (V.5 does not pin a single m_state)".into(),
    );
    lines.push("#".into());
    lines.push("# V.6 inputs:".into());
    lines.push("#   member set = V.8 two-signer fixture (m = 2; V.6 layout reuses it)".into());
    lines.push("#   s_agg is independent of block_anchor (anchor is payload metadata only)".into());
    lines.push("#".into());

    lines.push(format!("v2ext_pk0 = {}", hex64_of(&pk0)));
    lines.push(format!("h_proof_data_0 = {}", hex64_of(&h_proof_data_0)));

    for (network, signed) in &v5_openings {
        let label = network_label(*network);
        lines.push(format!(
            "v5_r_prime_{label} = {}",
            hex64_of(&signed.r_prime)
        ));
        lines.push(format!(
            "v5_signature_{label} = {}",
            hex64_of(&signed.signature)
        ));
        println!("v5_signature_{label} = {}", hex64_of(&signed.signature));
        println!("v5_r_prime_{label}   = {}", hex64_of(&signed.r_prime));
    }

    lines.push(format!("v6_s_agg = {}", hex64_of(&s_agg)));
    println!("v6_s_agg = {}", hex64_of(&s_agg));

    // Also emit the V.8 recomputed intermediates that feed s_agg (documentation).
    lines.push(format!("v8_pk_1 = {}", hex64_of(&signed1.pk)));
    lines.push(format!("v8_r_1 = {}", hex64_of(&signed1.r)));
    lines.push(format!("v8_s_1 = {}", hex64_of(&signed1.s)));
    lines.push(format!("v8_pk_2 = {}", hex64_of(&signed2.pk)));
    lines.push(format!("v8_r_2 = {}", hex64_of(&signed2.r)));
    lines.push(format!("v8_s_2 = {}", hex64_of(&signed2.s)));

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("generated_sig_agg_vectors.txt");
    fs::create_dir_all(path.parent().expect("tests/ parent")).expect("create tests/");
    let body = lines.join("\n") + "\n";
    fs::write(&path, &body).expect("write generated_sig_agg_vectors.txt");
    println!("wrote {}", path.display());
}
