//! Prüfender Bootstrap-Manifest-Loader (§4.3 / §7.7).
//!
//! ## Betriebskonfiguration
//!
//! `ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH` — Dateipfad zu einem BMF1-Artefakt.
//!
//! | Variable | Start |
//! |---|---|
//! | fehlt | Store leer; exclusive v1-Boot bricht später bei `ChainIdentity`-Install ab |
//! | gesetzt, Datei fehlt / unlesbar / ungültig | **Startabbruch** mit Variable + Grund |
//! | gesetzt, gültig unter gepinntem `bootstrap_pubkey` | verifiziertes Manifest im Store |
//!
//! Kein Default-Manifest, keine eingebauten Relay-URLs, kein „dev mode“,
//! der die Prüfung überspringt. Signieren gehört nicht hierher — nur
//! Verifizieren unter dem eingefrorenen Netzwerkparameter-Pin.
//!
//! Speicherklasse: process-lokal wie [`super::bundle::BundleStore`] /
//! [`super::challenges::ChallengeStore`]. Unverifizierte Bytes werden
//! **nie** gehalten.
//!
//! No `axum`, no `tonic`.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use shared::spec_v1::bootstrap_manifest::{
    deserialize, manifest_id, verify_bootstrap_manifest, BootstrapManifestV1, ManifestClock,
    VerifyBootstrapManifest, BOOTSTRAP_PROTOCOL_VERSION,
};
use shared::spec_v1::SpecError;

/// Env: filesystem path to a signed BMF1 bootstrap manifest.
///
/// Named `ZKCOINS_V1_*` like the other v1-stack operational path/env pins
/// (`ZKCOINS_V1_BITCOIND_COOKIE_PATH`, …): optional at boot, but if present
/// the artifact must fully verify. Not `ZKCOINS_BOOTSTRAP_PUBKEY` (that is
/// the §3.6 parameter pin, not a file path).
pub(crate) const BOOTSTRAP_MANIFEST_PATH_ENV: &str = "ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH";

/// Fully verified bootstrap manifest + content-addressed id.
///
/// Constructed only after BIP-340 verification under the pinned key.
/// Unverified bytes never reach this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedBootstrapManifest {
    manifest: BootstrapManifestV1,
    manifest_id: [u8; 32],
}

impl VerifiedBootstrapManifest {
    pub(crate) fn manifest(&self) -> &BootstrapManifestV1 {
        &self.manifest
    }

    pub(crate) fn manifest_id(&self) -> [u8; 32] {
        self.manifest_id
    }

    pub(crate) fn network(&self) -> &str {
        &self.manifest.network
    }

    pub(crate) fn protocol_version(&self) -> &str {
        &self.manifest.protocol_version
    }

    pub(crate) fn seed_relays(&self) -> &[String] {
        &self.manifest.seed_relays
    }

    pub(crate) fn blob_stores(&self) -> &[String] {
        &self.manifest.blob_stores
    }

    pub(crate) fn operator_ids(&self) -> &[[u8; 32]] {
        &self.manifest.operator_ids
    }

    pub(crate) fn issued_at(&self) -> u64 {
        self.manifest.issued_at
    }

    pub(crate) fn expires_at(&self) -> u64 {
        self.manifest.expires_at
    }

    pub(crate) fn manifest_sig(&self) -> &[u8; 64] {
        &self.manifest.manifest_sig
    }
}

/// Process-local store for the optional verified bootstrap manifest.
#[derive(Debug, Default)]
pub(crate) struct ManifestStore {
    loaded: Option<VerifiedBootstrapManifest>,
}

impl ManifestStore {
    pub(crate) fn new() -> Self {
        Self { loaded: None }
    }

    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    pub(crate) fn from_verified(verified: VerifiedBootstrapManifest) -> Self {
        Self {
            loaded: Some(verified),
        }
    }

    pub(crate) fn shared_from_verified(verified: VerifiedBootstrapManifest) -> Arc<Self> {
        Arc::new(Self::from_verified(verified))
    }

    /// The verified manifest, if one was installed at boot.
    pub(crate) fn get(&self) -> Option<&VerifiedBootstrapManifest> {
        self.loaded.as_ref()
    }

    /// Whether a verified manifest is held.
    pub(crate) fn is_loaded(&self) -> bool {
        self.loaded.is_some()
    }
}

/// Fail-loud load / verify errors for the boot edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ManifestLoadError {
    /// Env var present but empty / whitespace-only.
    EmptyPath,
    /// Path does not exist or is unreadable.
    Io { path: PathBuf, detail: String },
    /// Bytes present but codec / trust-anchor checks failed.
    Invalid { path: PathBuf, cause: SpecError },
}

impl fmt::Display for ManifestLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => write!(
                f,
                "{BOOTSTRAP_MANIFEST_PATH_ENV} is set but empty — refusing to start \
                 (no silent default path)"
            ),
            Self::Io { path, detail } => write!(
                f,
                "{BOOTSTRAP_MANIFEST_PATH_ENV}={path:?} is not readable: {detail} — \
                 refusing to start (configured manifest must load)"
            ),
            Self::Invalid { path, cause } => write!(
                f,
                "{BOOTSTRAP_MANIFEST_PATH_ENV}={path:?} rejected: {cause} — \
                 refusing to start (no half-loaded manifest)"
            ),
        }
    }
}

impl std::error::Error for ManifestLoadError {}

/// Inputs for [`load_bootstrap_manifest`] (destructured at the call site).
#[derive(Debug, Clone, Copy)]
pub(crate) struct LoadBootstrapManifestConfig<'a> {
    /// Raw value of [`BOOTSTRAP_MANIFEST_PATH_ENV`], or `None` if unset.
    pub path_env: Option<&'a str>,
    /// Pinned `bootstrap_pubkey` from the frozen network parameter set.
    pub pinned_bootstrap_pubkey: &'a [u8; 32],
    /// Bare network label (`mainnet` | `testnet` | `regtest`).
    pub expected_network: &'a str,
    /// Wall clock for expiry; see [`ManifestClock`].
    pub clock: ManifestClock,
}

/// Load, decode, and verify a bootstrap manifest from the operation config.
///
/// * `path_env == None` → `Ok(None)` (node has no manifest).
/// * `path_env == Some(...)` → must fully succeed or return [`ManifestLoadError`].
pub(crate) fn load_bootstrap_manifest(
    LoadBootstrapManifestConfig {
        path_env,
        pinned_bootstrap_pubkey,
        expected_network,
        clock,
    }: LoadBootstrapManifestConfig<'_>,
) -> Result<Option<VerifiedBootstrapManifest>, ManifestLoadError> {
    let Some(raw) = path_env else {
        return Ok(None);
    };
    let path = raw.trim();
    if path.is_empty() {
        return Err(ManifestLoadError::EmptyPath);
    }
    let path = Path::new(path);
    let bytes = std::fs::read(path).map_err(|e| ManifestLoadError::Io {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    let verified = verify_manifest_bytes(
        &bytes,
        path,
        pinned_bootstrap_pubkey,
        expected_network,
        clock,
    )?;
    Ok(Some(verified))
}

/// Decode + trust-anchor verify over already-read bytes (tests / pure path).
pub(crate) fn verify_manifest_bytes(
    bytes: &[u8],
    path: &Path,
    pinned_bootstrap_pubkey: &[u8; 32],
    expected_network: &str,
    clock: ManifestClock,
) -> Result<VerifiedBootstrapManifest, ManifestLoadError> {
    let manifest = deserialize(bytes).map_err(|cause| ManifestLoadError::Invalid {
        path: path.to_path_buf(),
        cause,
    })?;
    verify_bootstrap_manifest(
        &manifest,
        VerifyBootstrapManifest {
            pinned_bootstrap_pubkey,
            expected_network,
            expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
            clock,
        },
    )
    .map_err(|cause| ManifestLoadError::Invalid {
        path: path.to_path_buf(),
        cause,
    })?;
    let id = manifest_id(&manifest).map_err(|cause| ManifestLoadError::Invalid {
        path: path.to_path_buf(),
        cause,
    })?;
    Ok(VerifiedBootstrapManifest {
        manifest,
        manifest_id: id,
    })
}

/// Read [`BOOTSTRAP_MANIFEST_PATH_ENV`] from the process environment.
///
/// `None` when unset. Non-UTF-8 is returned as `Some` empty so the load
/// path can fail loud via [`ManifestLoadError::EmptyPath`] / IO — callers
/// that need a distinct non-UTF-8 signal should use `std::env::var` directly.
pub(crate) fn bootstrap_manifest_path_from_env() -> Result<Option<String>, ManifestLoadError> {
    match std::env::var(BOOTSTRAP_MANIFEST_PATH_ENV) {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(ManifestLoadError::Io {
            path: PathBuf::from("<non-utf8>"),
            detail: format!("{BOOTSTRAP_MANIFEST_PATH_ENV} is not valid UTF-8"),
        }),
        Ok(v) => Ok(Some(v)),
    }
}

/// Boot helper: optional path from env + pins → shared store.
///
/// When the env var is absent the store is empty. When present the
/// artifact must verify under `pinned_bootstrap_pubkey` or the process
/// must not start.
pub(crate) fn load_manifest_store(
    LoadBootstrapManifestConfig {
        path_env,
        pinned_bootstrap_pubkey,
        expected_network,
        clock,
    }: LoadBootstrapManifestConfig<'_>,
) -> Result<Arc<ManifestStore>, ManifestLoadError> {
    match load_bootstrap_manifest(LoadBootstrapManifestConfig {
        path_env,
        pinned_bootstrap_pubkey,
        expected_network,
        clock,
    })? {
        None => Ok(ManifestStore::shared()),
        Some(v) => Ok(ManifestStore::shared_from_verified(v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    use shared::spec_v1::bootstrap_manifest::{bootstrap_message, serialize, BMF1_MAGIC};
    use std::io::Write;

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

    fn signed_bytes(network: &str, sk: &[u8; 32]) -> Vec<u8> {
        let mut m = BootstrapManifestV1 {
            network: network.to_string(),
            protocol_version: "v1".to_string(),
            seed_relays: vec!["wss://relay.example".to_string()],
            blob_stores: vec!["https://blob.example".to_string()],
            operator_ids: vec![[0x42; 32]],
            issued_at: 1_000,
            expires_at: 2_000_000_000,
            manifest_sig: [0u8; 64],
        };
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(sk).unwrap();
        let kp = Keypair::from_secret_key(&secp, &secret);
        let msg = bootstrap_message(&m).unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp);
        m.manifest_sig = *sig.as_ref();
        serialize(&m).unwrap()
    }

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp");
        f.write_all(bytes).expect("write");
        f
    }

    #[test]
    fn missing_path_env_is_ok_empty_store() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let _ = sk;
        let store = load_manifest_store(LoadBootstrapManifestConfig {
            path_env: None,
            pinned_bootstrap_pubkey: &pk,
            expected_network: "regtest",
            clock: ManifestClock::Unavailable,
        })
        .expect("unset");
        assert!(!store.is_loaded());
        assert!(store.get().is_none());
    }

    #[test]
    fn set_path_missing_file_aborts() {
        let (_sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let err = load_bootstrap_manifest(LoadBootstrapManifestConfig {
            path_env: Some("/no/such/bootstrap/manifest.bmf1"),
            pinned_bootstrap_pubkey: &pk,
            expected_network: "regtest",
            clock: ManifestClock::Unavailable,
        })
        .expect_err("missing file");
        match err {
            ManifestLoadError::Io { ref path, .. } => {
                assert!(path.ends_with("manifest.bmf1"));
            }
            other => panic!("expected Io, got {other:?}"),
        }
        assert!(
            err.to_string().contains(BOOTSTRAP_MANIFEST_PATH_ENV),
            "message must name the env var: {err}"
        );
    }

    #[test]
    fn set_path_invalid_aborts_with_cause() {
        let (_sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let f = write_temp(b"not-a-manifest");
        let err = load_bootstrap_manifest(LoadBootstrapManifestConfig {
            path_env: Some(f.path().to_str().unwrap()),
            pinned_bootstrap_pubkey: &pk,
            expected_network: "regtest",
            clock: ManifestClock::Unavailable,
        })
        .expect_err("invalid");
        match err {
            ManifestLoadError::Invalid { ref cause, .. } => {
                assert!(
                    matches!(cause, SpecError::BootstrapMagicInvalid { .. })
                        || matches!(cause, SpecError::BootstrapTruncated { .. }),
                    "cause={cause:?}"
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert!(err.to_string().contains(BOOTSTRAP_MANIFEST_PATH_ENV));
    }

    #[test]
    fn set_path_valid_installs_verified() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let bytes = signed_bytes("regtest", &sk);
        let f = write_temp(&bytes);
        let store = load_manifest_store(LoadBootstrapManifestConfig {
            path_env: Some(f.path().to_str().unwrap()),
            pinned_bootstrap_pubkey: &pk,
            expected_network: "regtest",
            clock: ManifestClock::UnixSeconds(1_500),
        })
        .expect("valid");
        let v = store.get().expect("loaded");
        assert_eq!(v.network(), "regtest");
        assert_eq!(v.manifest_id(), manifest_id(v.manifest()).unwrap());
        assert_eq!(&v.manifest_sig()[..], &bytes[bytes.len() - 64..]);
        // Magic present on original bytes; store never holds raw unverified.
        assert_eq!(&bytes[..4], BMF1_MAGIC.as_slice());
    }

    #[test]
    fn empty_path_string_is_error() {
        let (_sk, pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let err = load_bootstrap_manifest(LoadBootstrapManifestConfig {
            path_env: Some("   "),
            pinned_bootstrap_pubkey: &pk,
            expected_network: "regtest",
            clock: ManifestClock::Unavailable,
        })
        .expect_err("empty");
        assert_eq!(err, ManifestLoadError::EmptyPath);
    }

    #[test]
    fn foreign_signature_rejected_at_load() {
        let (sk, _pk) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey");
        let (_sk_o, pk_other) = fixture_sk(b"zkCoins/v1/test-vector/bootstrap-pubkey-OTHER");
        let bytes = signed_bytes("regtest", &sk);
        let f = write_temp(&bytes);
        let err = load_bootstrap_manifest(LoadBootstrapManifestConfig {
            path_env: Some(f.path().to_str().unwrap()),
            pinned_bootstrap_pubkey: &pk_other,
            expected_network: "regtest",
            clock: ManifestClock::Unavailable,
        })
        .expect_err("foreign");
        match err {
            ManifestLoadError::Invalid { cause, .. } => {
                assert_eq!(cause, SpecError::BootstrapSignatureInvalid);
            }
            other => panic!("expected Invalid/sig, got {other:?}"),
        }
    }
}
