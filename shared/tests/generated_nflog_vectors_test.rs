//! Generates `shared/tests/generated_nflog_vectors.txt` from the live
//! nullifier-log primitives (V.11 hand-listed smoke set).
//!
//! Values are **computed**, never hand-copied. Re-run with `cargo test -p shared`
//! to refresh the file.
//!
//! Line format (fixed for this generator):
//! - Scalars: `mth@n = 0x<64 hex>`, `nav_root@n = 0x<64 hex>`
//! - Paths:   `inclusion@p,n = 0x…,0x…` (comma-separated digests, production
//!            PATH order; empty path ⇒ empty RHS after `= `)
//! - Paths:   `consistency@m,n = 0x…,0x…` (same comma-separated form)
//!
//! `nflog_empty` is intentionally **not** emitted — V.4 / the Poseidon generator
//! already pins it.

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use shared::spec_v1::{
    consistency_proof, digest_to_bytes, inclusion_path, nflog_mth, nflog_root, verify_consistency,
    verify_inclusion, NfLogEntry,
};

/// V.8 signer-1 / signer-2 `(Pk_j, R_j)` — fully pinned (SHA-256 / BIP-340), no `<REGEN>`.
const V8_PK_1: &str = "e7f2a98e7b45e9424e3e0cb1d937a1698ebd339c6d8344906db979642cf20474";
const V8_R_1: &str = "c41ff1a78f2006e5f5aa800efa84b2d2046d108dfa968909974ec37fcb87f6c4";
const V8_PK_2: &str = "21799353e64a65ee4b1f414998c44878c56270cf8a81046cb3636e5ec31a3341";
const V8_R_2: &str = "bd22b77069c75431ee3676bea7324a59e9b6466a62a9a3021f831e6ccf5d3220";

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_digest(d: &shared::spec_v1::HashDigest) -> String {
    hex32(&digest_to_bytes(d))
}

fn parse_hex32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).unwrap_or_else(|e| {
        panic!("V.8 fixture hex decode failed for {hex_str}: {e}");
    });
    <[u8; 32]>::try_from(bytes.as_slice()).unwrap_or_else(|_| {
        panic!(
            "V.8 fixture must be 32 bytes, got {} for {hex_str}",
            bytes.len()
        );
    })
}

/// Normative V.11 sample-leaf sequence for the hand-listed smoke set.
///
/// - positions 0, 1: V.8 fixture `(Pk_j, R_j)`
/// - positions `p ≥ 2`: `Pk = SHA-256("zkCoins/v1/test-vector/nflog/pk" ‖ u8(p))`,
///   `R = SHA-256("zkCoins/v1/test-vector/nflog/r" ‖ u8(p))`
fn sample_entries(n: usize) -> Vec<NfLogEntry> {
    assert!(
        n <= 9,
        "V.11 hand-listed smoke set only covers n ≤ 9 (got {n})"
    );
    let mut out = Vec::with_capacity(n);
    for p in 0..n {
        let entry = if p == 0 {
            NfLogEntry {
                pk: parse_hex32(V8_PK_1),
                r: parse_hex32(V8_R_1),
            }
        } else if p == 1 {
            NfLogEntry {
                pk: parse_hex32(V8_PK_2),
                r: parse_hex32(V8_R_2),
            }
        } else {
            let p_u8 = u8::try_from(p).unwrap_or_else(|_| {
                panic!("smoke-set position {p} must fit in u8");
            });
            let mut pk_pre = b"zkCoins/v1/test-vector/nflog/pk".to_vec();
            pk_pre.push(p_u8);
            let mut r_pre = b"zkCoins/v1/test-vector/nflog/r".to_vec();
            r_pre.push(p_u8);
            NfLogEntry {
                pk: Sha256::digest(&pk_pre).into(),
                r: Sha256::digest(&r_pre).into(),
            }
        };
        out.push(entry);
    }
    out
}

fn format_path(path: &[shared::spec_v1::HashDigest]) -> String {
    path.iter().map(hex_digest).collect::<Vec<_>>().join(",")
}

#[test]
fn generate_nflog_vectors_file() {
    const MAX_N: usize = 9;
    let entries = sample_entries(MAX_N);

    let mth_ns: &[usize] = &[1, 2, 3, 4, 5, 7, 8, 9];
    let inclusion_pairs: &[(u64, usize)] = &[
        (0, 3),
        (1, 3),
        (2, 3),
        (0, 4),
        (1, 4),
        (3, 4),
        (0, 5),
        (2, 5),
        (4, 5),
        (0, 8),
        (3, 8),
        (7, 8),
    ];
    let consistency_pairs: &[(u64, usize)] = &[(1, 2), (3, 4), (5, 8), (7, 8), (8, 9)];

    // Precompute mth@n for every n used below.
    let mut mth_by_n: [Option<shared::spec_v1::HashDigest>; MAX_N + 1] = [None; MAX_N + 1];
    for &n in mth_ns {
        let mth = nflog_mth(&entries[..n]);
        mth_by_n[n] = Some(mth);
    }
    // Consistency also needs mth@m for m not necessarily in mth_ns alone (all are).
    for &(m, n) in consistency_pairs {
        let m_us = m as usize;
        if mth_by_n[m_us].is_none() {
            mth_by_n[m_us] = Some(nflog_mth(&entries[..m_us]));
        }
        if mth_by_n[n].is_none() {
            mth_by_n[n] = Some(nflog_mth(&entries[..n]));
        }
    }

    let mut lines: Vec<String> = Vec::new();

    // --- mth@n / nav_root@n ---
    for &n in mth_ns {
        let mth = mth_by_n[n].unwrap_or_else(|| panic!("mth@{n} missing"));
        let nav = nflog_root(n as u64, mth);
        lines.push(format!("mth@{n} = {}", hex_digest(&mth)));
        lines.push(format!("nav_root@{n} = {}", hex_digest(&nav)));
    }

    // --- inclusion@(p,n) with self-check ---
    for &(p, n) in inclusion_pairs {
        let slice = &entries[..n];
        let path = inclusion_path(p, slice).unwrap_or_else(|e| {
            panic!("inclusion_path({p}, n={n}) failed: {e:?}");
        });
        let leaf = shared::spec_v1::nflog_leaf_hash(p, &slice[p as usize]);
        let mth = mth_by_n[n].unwrap_or_else(|| panic!("mth@{n} missing for inclusion"));
        assert!(
            verify_inclusion(leaf, p, &path, n as u64, mth),
            "self-check: inclusion@({p},{n}) does not verify against mth@{n}"
        );
        lines.push(format!("inclusion@{p},{n} = {}", format_path(&path)));
    }

    // --- consistency@(m,n) with self-check ---
    for &(m, n) in consistency_pairs {
        let slice = &entries[..n];
        let proof = consistency_proof(m, slice).unwrap_or_else(|e| {
            panic!("consistency_proof(m={m}, n={n}) failed: {e:?}");
        });
        let mth_a = mth_by_n[m as usize].unwrap_or_else(|| panic!("mth@{m} missing"));
        let mth_b = mth_by_n[n].unwrap_or_else(|| panic!("mth@{n} missing"));
        assert!(
            verify_consistency(m, mth_a, n as u64, mth_b, &proof),
            "self-check: consistency@({m},{n}) does not verify against mth@{m} / mth@{n}"
        );
        lines.push(format!("consistency@{m},{n} = {}", format_path(&proof)));
    }

    lines.push(String::new()); // trailing newline

    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/generated_nflog_vectors.txt"
    ));
    fs::write(&path, lines.join("\n")).expect("write generated_nflog_vectors.txt");

    let written = fs::read_to_string(&path).expect("read back vectors file");
    for &n in mth_ns {
        let label = format!("mth@{n}");
        assert!(
            written.contains(&label),
            "generated file missing label {label}"
        );
        let label = format!("nav_root@{n}");
        assert!(
            written.contains(&label),
            "generated file missing label {label}"
        );
    }
    for &(p, n) in inclusion_pairs {
        let label = format!("inclusion@{p},{n}");
        assert!(
            written.contains(&label),
            "generated file missing label {label}"
        );
    }
    for &(m, n) in consistency_pairs {
        let label = format!("consistency@{m},{n}");
        assert!(
            written.contains(&label),
            "generated file missing label {label}"
        );
    }
    // Must not re-pin nflog_empty here.
    assert!(
        !written.contains("nflog_empty"),
        "V.11 smoke generator must not emit nflog_empty (owned by V.4 / Poseidon generator)"
    );
}
