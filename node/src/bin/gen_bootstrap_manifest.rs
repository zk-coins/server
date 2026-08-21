//! Generate a signed §4.3 BootstrapManifestV1 (BMF1) artifact.
//!
//! Produces the same wire encoding and BIP-340 signature domain that the
//! node verification path expects (`shared::spec_v1::bootstrap_manifest`
//! + `node` BMF1 loader under `ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH`).
//!
//! ## Secret material (never on argv)
//!
//! Supply the network bootstrap **secret** via exactly one of:
//!
//! - `ZKCOINS_BOOTSTRAP_PRIVKEY` — 64 lowercase hex chars (32 bytes)
//! - `ZKCOINS_BOOTSTRAP_PRIVKEY_FILE` — path to a file whose contents are
//!   that hex (optional surrounding whitespace is trimmed)
//!
//! The secret is never printed, logged, or written into the artifact
//! path. argv never accepts a secret.
//!
//! ## Fail-closed
//!
//! `--bootstrap-pubkey` (or `ZKCOINS_BOOTSTRAP_PUBKEY`) must equal the
//! x-only public key derived from the secret. A mismatch aborts **before**
//! any bytes are written to `--output`.
//!
//! ```sh
//! cargo build --release -p node --bin gen_bootstrap_manifest
//!
//! export ZKCOINS_BOOTSTRAP_PRIVKEY_FILE=./bootstrap.priv   # 64 hex, mode 0600
//! export ZKCOINS_BOOTSTRAP_PUBKEY=…                        # 64 hex x-only
//!
//! ./target/release/gen_bootstrap_manifest \
//!   --output ./bootstrap.bmf1 \
//!   --network regtest \
//!   --bootstrap-pubkey "$ZKCOINS_BOOTSTRAP_PUBKEY" \
//!   --seed-relay 'ws://nostr-relay:8080/' \
//!   --blob-store 'http://127.0.0.1:8080/' \
//!   --operator-id '<64-hex-op-pubkey>' \
//!   --issued-at 1700000000 \
//!   --expires-at 2000000000
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use shared::spec_v1::{
    sign_and_serialize_bootstrap_manifest, BootstrapManifestBody, SignBootstrapManifest,
    BOOTSTRAP_PROTOCOL_VERSION,
};

/// Env: 64 lowercase hex secret (32 bytes). Mutually exclusive with the file form.
const PRIVKEY_ENV: &str = "ZKCOINS_BOOTSTRAP_PRIVKEY";
/// Env: path to a file containing the hex secret.
const PRIVKEY_FILE_ENV: &str = "ZKCOINS_BOOTSTRAP_PRIVKEY_FILE";
/// Env fallback for the public pin when `--bootstrap-pubkey` is omitted.
const PUBKEY_ENV: &str = "ZKCOINS_BOOTSTRAP_PUBKEY";

#[derive(Debug)]
struct CliArgs {
    output: PathBuf,
    network: String,
    bootstrap_pubkey: [u8; 32],
    seed_relays: Vec<String>,
    blob_stores: Vec<String>,
    operator_ids: Vec<[u8; 32]>,
    issued_at: u64,
    expires_at: u64,
}

fn print_usage(program: &str) {
    eprintln!(
        "usage: {program} \\
    --output <path> \\
    --network <mainnet|testnet|regtest> \\
    --bootstrap-pubkey <64-hex-xonly>   (or env {PUBKEY_ENV}) \\
    --seed-relay <url>                  (repeatable, ≥1) \\
    --blob-store <url>                  (repeatable, ≥1) \\
    --operator-id <64-hex-xonly>        (repeatable, ≥1) \\
    --issued-at <unix-seconds> \\
    --expires-at <unix-seconds>

env (secret — never pass on argv):
  {PRIVKEY_ENV}         64 lowercase hex secp256k1 secret, OR
  {PRIVKEY_FILE_ENV}    path to a file whose contents are that hex

env (public pin, optional if --bootstrap-pubkey is set):
  {PUBKEY_ENV}          64 lowercase hex BIP-340 x-only

Writes a BMF1 frame that verifies under the pin. Refuses to write when the
secret does not derive to --bootstrap-pubkey / {PUBKEY_ENV}.
"
    );
}

fn parse_hex_32(raw: &str, label: &str) -> Result<[u8; 32], String> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "{label} must be exactly 64 hex characters, got {} chars",
            trimmed.len()
        ));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!(
            "{label} must be 64 lowercase hex characters (no 0x, no uppercase)"
        ));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(trimmed, &mut out)
        .map_err(|e| format!("{label} is not valid hex: {e}"))?;
    Ok(out)
}

fn take_value<I: Iterator<Item = String>>(iter: &mut I, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("flag `{flag}` requires a value"))
}

fn parse_args(argv: Vec<String>) -> Result<CliArgs, String> {
    let mut iter = argv.into_iter();
    let program = iter
        .next()
        .unwrap_or_else(|| "gen_bootstrap_manifest".into());

    let mut output: Option<PathBuf> = None;
    let mut network: Option<String> = None;
    let mut bootstrap_pubkey_cli: Option<String> = None;
    let mut seed_relays: Vec<String> = Vec::new();
    let mut blob_stores: Vec<String> = Vec::new();
    let mut operator_ids: Vec<[u8; 32]> = Vec::new();
    let mut issued_at: Option<u64> = None;
    let mut expires_at: Option<u64> = None;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--output" => {
                output = Some(PathBuf::from(take_value(&mut iter, "--output")?));
            }
            "--network" => {
                network = Some(take_value(&mut iter, "--network")?);
            }
            "--bootstrap-pubkey" => {
                bootstrap_pubkey_cli = Some(take_value(&mut iter, "--bootstrap-pubkey")?);
            }
            "--seed-relay" => {
                seed_relays.push(take_value(&mut iter, "--seed-relay")?);
            }
            "--blob-store" => {
                blob_stores.push(take_value(&mut iter, "--blob-store")?);
            }
            "--operator-id" => {
                let raw = take_value(&mut iter, "--operator-id")?;
                operator_ids.push(parse_hex_32(&raw, "--operator-id")?);
            }
            "--issued-at" => {
                let raw = take_value(&mut iter, "--issued-at")?;
                issued_at = Some(
                    raw.parse::<u64>()
                        .map_err(|e| format!("--issued-at must be a u64 unix timestamp: {e}"))?,
                );
            }
            "--expires-at" => {
                let raw = take_value(&mut iter, "--expires-at")?;
                expires_at = Some(
                    raw.parse::<u64>()
                        .map_err(|e| format!("--expires-at must be a u64 unix timestamp: {e}"))?,
                );
            }
            "-h" | "--help" => {
                print_usage(&program);
                return Err(String::new());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let output = output.ok_or_else(|| "--output is required".to_string())?;
    let network = network.ok_or_else(|| "--network is required".to_string())?;
    match network.as_str() {
        "mainnet" | "testnet" | "regtest" => {}
        other => {
            return Err(format!(
                "--network={other:?} is not supported; expected mainnet|testnet|regtest"
            ));
        }
    }
    if seed_relays.is_empty() {
        return Err("at least one --seed-relay is required".to_string());
    }
    if blob_stores.is_empty() {
        return Err("at least one --blob-store is required".to_string());
    }
    if operator_ids.is_empty() {
        return Err("at least one --operator-id is required".to_string());
    }
    let issued_at = issued_at.ok_or_else(|| "--issued-at is required".to_string())?;
    let expires_at = expires_at.ok_or_else(|| "--expires-at is required".to_string())?;

    let bootstrap_pubkey_raw = match bootstrap_pubkey_cli {
        Some(v) => v,
        None => match std::env::var(PUBKEY_ENV) {
            Ok(v) if !v.trim().is_empty() => v,
            Ok(_) => {
                return Err(format!(
                    "--bootstrap-pubkey is required (or set non-empty {PUBKEY_ENV})"
                ));
            }
            Err(std::env::VarError::NotPresent) => {
                return Err(format!(
                    "--bootstrap-pubkey is required (or set {PUBKEY_ENV})"
                ));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!("{PUBKEY_ENV} is not valid UTF-8"));
            }
        },
    };
    let bootstrap_pubkey = parse_hex_32(&bootstrap_pubkey_raw, "--bootstrap-pubkey / pubkey env")?;

    Ok(CliArgs {
        output,
        network,
        bootstrap_pubkey,
        seed_relays,
        blob_stores,
        operator_ids,
        issued_at,
        expires_at,
    })
}

/// Load the bootstrap secret from env or file. Never returns key material
/// inside the `Err` string.
fn load_secret_key() -> Result<[u8; 32], String> {
    let from_env = match std::env::var(PRIVKEY_ENV) {
        Ok(v) => Some(v),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{PRIVKEY_ENV} is not valid UTF-8"));
        }
    };
    let from_file = match std::env::var(PRIVKEY_FILE_ENV) {
        Ok(v) => Some(v),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{PRIVKEY_FILE_ENV} is not valid UTF-8"));
        }
    };

    match (from_env, from_file) {
        (None, None) => Err(format!(
            "set exactly one of {PRIVKEY_ENV} or {PRIVKEY_FILE_ENV} \
             (bootstrap secret must not be passed on argv)"
        )),
        (Some(_), Some(_)) => Err(format!(
            "set exactly one of {PRIVKEY_ENV} or {PRIVKEY_FILE_ENV}, not both"
        )),
        (Some(hex_raw), None) => parse_hex_32(&hex_raw, PRIVKEY_ENV),
        (None, Some(path_raw)) => {
            let path = path_raw.trim();
            if path.is_empty() {
                return Err(format!("{PRIVKEY_FILE_ENV} is set but empty"));
            }
            let contents = fs::read_to_string(path).map_err(|e| {
                format!("{PRIVKEY_FILE_ENV}={path:?} is not readable: {e} — refusing to sign")
            })?;
            parse_hex_32(&contents, PRIVKEY_FILE_ENV)
        }
    }
}

/// Build BMF1 bytes from CLI fields + secret. Pure enough for unit tests.
fn build_artifact(args: &CliArgs, secret_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let body = BootstrapManifestBody {
        network: args.network.clone(),
        protocol_version: BOOTSTRAP_PROTOCOL_VERSION.to_string(),
        seed_relays: args.seed_relays.clone(),
        blob_stores: args.blob_stores.clone(),
        operator_ids: args.operator_ids.clone(),
        issued_at: args.issued_at,
        expires_at: args.expires_at,
    };
    sign_and_serialize_bootstrap_manifest(
        body,
        SignBootstrapManifest {
            secret_key,
            expected_bootstrap_pubkey: &args.bootstrap_pubkey,
        },
    )
    .map_err(|e| e.to_string())
}

/// Write `bytes` to `output` via a same-directory temp file + rename.
/// On any error before rename completes, the destination is left untouched
/// (or absent). The temp file is removed on failure.
fn write_atomic(output: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create parent dir {}: {e}", parent.display()))?;
    }
    let file_name = output
        .file_name()
        .ok_or_else(|| format!("--output {} has no file name", output.display()))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(".tmp");
    let tmp_path = parent.join(tmp_name);

    // Scope so the file handle is closed before rename.
    {
        let mut f = fs::File::create(&tmp_path)
            .map_err(|e| format!("create temp {}: {e}", tmp_path.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("write temp {}: {e}", tmp_path.display()))?;
        f.sync_all()
            .map_err(|e| format!("sync temp {}: {e}", tmp_path.display()))?;
    }

    fs::rename(&tmp_path, output).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("rename {} → {}: {e}", tmp_path.display(), output.display())
    })?;
    Ok(())
}

fn run(argv: Vec<String>) -> Result<(), String> {
    let args = parse_args(argv)?;
    // Load + sign before touching the output path so a key mismatch never
    // creates or truncates the destination.
    let secret = load_secret_key()?;
    let bytes = build_artifact(&args, &secret)?;
    write_atomic(&args.output, &bytes)?;
    // Success line: path + byte length only. Never print keys or sig hex.
    eprintln!(
        "gen_bootstrap_manifest: wrote {} bytes to {}",
        bytes.len(),
        args.output.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run(std::env::args().collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) if msg.is_empty() => ExitCode::SUCCESS, // --help
        Err(msg) => {
            eprintln!("gen_bootstrap_manifest: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    use shared::spec_v1::{
        deserialize_bootstrap_manifest, verify_bootstrap_manifest, ManifestClock,
        VerifyBootstrapManifest, BMF1_MAGIC,
    };
    use std::sync::Mutex;

    /// Process-global env mutations must be serialised across tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn fixture_sk(label: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut seed = Sha256::digest(label).to_vec();
        let secp = Secp256k1::new();
        loop {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&seed[..32]);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                let kp = Keypair::from_secret_key(&secp, &sk);
                let (xonly, _) = kp.x_only_public_key();
                return (sk_bytes, xonly.serialize());
            }
            seed = Sha256::digest(&seed).to_vec();
        }
    }

    fn sample_args(pk: [u8; 32], output: PathBuf) -> CliArgs {
        CliArgs {
            output,
            network: "regtest".to_string(),
            bootstrap_pubkey: pk,
            seed_relays: vec!["wss://relay.example".to_string()],
            blob_stores: vec!["https://blob.example".to_string()],
            operator_ids: vec![[0x42; 32]],
            issued_at: 1_000,
            expires_at: 2_000_000_000,
        }
    }

    #[test]
    fn build_artifact_verifies_under_pin() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/gen-bootstrap-manifest");
        let args = sample_args(pk, PathBuf::from("/tmp/unused.bmf1"));
        let bytes = build_artifact(&args, &sk).expect("build");
        assert_eq!(&bytes[..4], BMF1_MAGIC.as_slice());
        let m = deserialize_bootstrap_manifest(&bytes).expect("de");
        verify_bootstrap_manifest(
            &m,
            VerifyBootstrapManifest {
                pinned_bootstrap_pubkey: &pk,
                expected_network: "regtest",
                expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
                clock: ManifestClock::UnixSeconds(1_500),
            },
        )
        .expect("verify");
    }

    #[test]
    fn wrong_secret_refuses_and_writes_nothing() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (sk_wrong, _pk_wrong) =
            fixture_sk(b"zkCoins/v1/test-vector/gen-bootstrap-manifest-WRONG");
        let (_sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/gen-bootstrap-manifest");
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("must-not-exist.bmf1");

        // Key mismatch is detected in build_artifact — no write attempted.
        let args = sample_args(pk, out.clone());
        let err = build_artifact(&args, &sk_wrong).expect_err("mismatch");
        assert!(
            err.contains("does not match")
                || err.contains("PubkeyMismatch")
                || err.contains("refusing"),
            "unexpected error: {err}"
        );
        assert!(!out.exists(), "output must not be created on key mismatch");

        // End-to-end through run(): env secret + CLI pin mismatch.
        // Save/restore so parallel package tests do not inherit our secret.
        let saved_priv = std::env::var_os(PRIVKEY_ENV);
        let saved_file = std::env::var_os(PRIVKEY_FILE_ENV);
        std::env::set_var(PRIVKEY_ENV, hex::encode(sk_wrong));
        std::env::remove_var(PRIVKEY_FILE_ENV);
        let argv = vec![
            "gen_bootstrap_manifest".into(),
            "--output".into(),
            out.to_string_lossy().into_owned(),
            "--network".into(),
            "regtest".into(),
            "--bootstrap-pubkey".into(),
            hex::encode(pk),
            "--seed-relay".into(),
            "wss://relay.example".into(),
            "--blob-store".into(),
            "https://blob.example".into(),
            "--operator-id".into(),
            hex::encode([0x42u8; 32]),
            "--issued-at".into(),
            "1000".into(),
            "--expires-at".into(),
            "2000000000".into(),
        ];
        let run_result = run(argv);
        match saved_priv {
            Some(v) => std::env::set_var(PRIVKEY_ENV, v),
            None => std::env::remove_var(PRIVKEY_ENV),
        }
        match saved_file {
            Some(v) => std::env::set_var(PRIVKEY_FILE_ENV, v),
            None => std::env::remove_var(PRIVKEY_FILE_ENV),
        }
        let err = run_result.expect_err("run must fail");
        assert!(
            err.contains("does not match") || err.contains("refusing"),
            "unexpected run error: {err}"
        );
        assert!(!out.exists(), "run must not create output on key mismatch");
    }

    #[test]
    fn tampered_byte_fails_verify() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/gen-bootstrap-manifest");
        let args = sample_args(pk, PathBuf::from("/tmp/unused.bmf1"));
        let mut bytes = build_artifact(&args, &sk).expect("build");
        // Flip a body byte (after magic+version, before sig).
        let idx = 10;
        bytes[idx] ^= 0x01;
        let m = match deserialize_bootstrap_manifest(&bytes) {
            Ok(m) => m,
            Err(_) => return, // codec rejection is also a valid fail-closed outcome
        };
        let err = verify_bootstrap_manifest(
            &m,
            VerifyBootstrapManifest {
                pinned_bootstrap_pubkey: &pk,
                expected_network: "regtest",
                expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
                clock: ManifestClock::Unavailable,
            },
        )
        .expect_err("tamper");
        let msg = err.to_string();
        assert!(
            msg.contains("signature") || msg.contains("network") || msg.contains("invalid"),
            "unexpected reject: {msg}"
        );
    }

    #[test]
    fn network_label_mismatch_rejected() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/gen-bootstrap-manifest");
        let mut args = sample_args(pk, PathBuf::from("/tmp/unused.bmf1"));
        args.network = "regtest".to_string();
        let bytes = build_artifact(&args, &sk).expect("build");
        let m = deserialize_bootstrap_manifest(&bytes).expect("de");
        let err = verify_bootstrap_manifest(
            &m,
            VerifyBootstrapManifest {
                pinned_bootstrap_pubkey: &pk,
                expected_network: "testnet", // pin says testnet; artifact is regtest
                expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
                clock: ManifestClock::Unavailable,
            },
        )
        .expect_err("network");
        assert!(
            err.to_string().contains("network"),
            "expected network mismatch, got {err}"
        );
    }

    #[test]
    fn write_atomic_roundtrip() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/gen-bootstrap-manifest");
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("bootstrap.bmf1");
        let args = sample_args(pk, out.clone());
        let bytes = build_artifact(&args, &sk).expect("build");
        write_atomic(&out, &bytes).expect("write");
        let back = fs::read(&out).expect("read");
        assert_eq!(back, bytes);
        assert!(!dir.path().join(".bootstrap.bmf1.tmp").exists());
    }
}
