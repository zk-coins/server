//! Node-side Esplora boundary: re-exports the `esplora-bound` facade and
//! applies the legacy-publisher stack gate on broadcast construction.
//!
//! ## Why a separate package
//!
//! `esplora-client` is **not** a dependency of the `node` package. The
//! raw `AsyncClient` / `Builder` types are therefore unobtainable here
//! (compile error if named) — the boundary is structural, not a
//! recursive string search of production sources.
//!
//! The `esplora-bound` package owns the raw crate and exports only
//! [`EsploraReadClient`] and [`EsploraBroadcastClient`] with private
//! inner fields. This module wraps broadcast construction with
//! [`ensure_legacy_publisher_allowed`] so a v1.1 process claim still
//! refuses legacy commitment broadcast before any Esplora I/O.

use crate::v11::ensure_legacy_publisher_allowed;

// Read path: no stack gate (reads are not a publish path).
pub use esplora_bound::{AddressUtxo, BlockStatusView, EsploraReadClient};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Broadcast-capable Esplora client for **legacy** commitment inscriptions.
///
/// Construction always runs [`ensure_legacy_publisher_allowed`]. Possessing
/// a value of this type means the stack check passed at connect time.
pub struct LegacyBroadcastClient {
    inner: esplora_bound::EsploraBroadcastClient,
}

impl std::fmt::Debug for LegacyBroadcastClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LegacyBroadcastClient { /* inner private */ }")
    }
}

impl LegacyBroadcastClient {
    /// Build a broadcast-capable client after the legacy stack check.
    ///
    /// Fails loud under a v1.1 process claim **before** any Esplora I/O.
    pub fn connect(url: &str) -> Result<Self, BoxError> {
        ensure_legacy_publisher_allowed().map_err(|e| {
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())) as BoxError
        })?;
        let inner = esplora_bound::EsploraBroadcastClient::connect(url)?;
        Ok(Self { inner })
    }

    pub async fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<(), BoxError> {
        self.inner.broadcast(tx).await
    }

    pub async fn get_tx(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<Option<bitcoin::Transaction>, BoxError> {
        self.inner.get_tx(txid).await
    }
}

#[cfg(test)]
mod boundary_tests {
    /// `node` must not list `esplora-client` as a direct dependency — the
    /// raw types are only reachable through the `esplora-bound` facade.
    /// Evidence that a raw client is unobtainable is a **compile** failure
    /// (see `tests/ui/raw_esplora_client_unobtainable.rs` + trybuild), not
    /// a recursive string search of production sources.
    #[test]
    fn node_cargo_toml_does_not_depend_on_esplora_client() {
        let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
        // Direct dependency line (not a comment). Facade package is allowed.
        for line in manifest.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            assert!(
                !trimmed.starts_with("esplora-client"),
                "node must not depend on esplora-client directly (use esplora-bound); found: {trimmed}"
            );
        }
        assert!(
            manifest.contains("esplora-bound"),
            "node must depend on the esplora-bound facade package"
        );
    }
}
