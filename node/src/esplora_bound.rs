//! Node-side Esplora boundary: re-exports the `esplora-bound` facade.
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
//! inner fields. Broadcast construction runs the process-stack legacy
//! policy **inside** the facade constructor (`stack-policy`), so a v1.1
//! process claim refuses legacy commitment broadcast before any Esplora
//! I/O — including when `node` code calls the facade directly.

// Read path: no stack gate (reads are not a publish path).
pub use esplora_bound::{AddressUtxo, BlockStatusView, EsploraReadClient};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Broadcast-capable Esplora client for **legacy** commitment inscriptions.
///
/// Thin node-side alias over [`esplora_bound::EsploraBroadcastClient`].
/// Construction delegates to the facade, which always runs
/// [`stack_policy::ensure_legacy_publisher_allowed`] before any Esplora I/O.
/// Possessing a value of this type means the stack check passed at connect
/// time.
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
    /// The check lives inside the facade constructor; there is no witness
    /// to forge and no path that skips the policy.
    pub fn connect(url: &str) -> Result<Self, BoxError> {
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
    use stack_policy::{
        set_process_stack_mode, ScanStackMode,
        STACK_SEPARATION_REFUSAL,
    };

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
        assert!(
            manifest.contains("stack-policy"),
            "node must depend on the stack-policy crate (shared process claim)"
        );
        assert!(
            !manifest.contains("issue-legacy-broadcast-witness"),
            "witness feature must be gone; policy is co-located with construction"
        );
    }

    /// Even a `node`-internal caller that bypasses
    /// [`LegacyBroadcastClient`] and hits the facade directly cannot obtain
    /// a broadcast-capable client without the policy check passing.
    #[test]
    fn node_internal_facade_connect_refuses_under_v1_claim() {
        set_process_stack_mode(ScanStackMode::V1);
        let err = esplora_bound::EsploraBroadcastClient::connect("http://127.0.0.1:1")
            .expect_err("node-internal facade connect must refuse under v1");
        let msg = err.to_string();
        assert!(
            msg.contains(STACK_SEPARATION_REFUSAL) || msg.contains("v1.1"),
            "got: {msg}"
        );
    }

    /// Wrapper and facade agree: legacy claim allows construction.
    #[test]
    fn node_wrapper_and_facade_allow_under_legacy_claim() {
        set_process_stack_mode(ScanStackMode::Legacy);
        super::LegacyBroadcastClient::connect("http://127.0.0.1:1")
            .expect("wrapper under legacy");
        esplora_bound::EsploraBroadcastClient::connect("http://127.0.0.1:1")
            .expect("facade under legacy");
    }
}
