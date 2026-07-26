//! Sole workspace owner of the `esplora-client` crate.
//!
//! ## Compiler-enforced boundary
//!
//! Downstream packages (notably `node`) depend on **this** crate, not on
//! `esplora-client`. The raw `AsyncClient` / `Builder` types are never
//! re-exported, and both wrappers keep the raw handle in a **private**
//! field with no `into_inner` / `as_raw` / public field. A raw client is
//! therefore unobtainable from `node` because the type is not in scope —
//! not because of a string-search convention.
//!
//! Callers only see [`EsploraReadClient`] (reads) and
//! [`EsploraBroadcastClient`] (broadcast + get_tx).
//!
//! ## Broadcast capability = co-located process-stack policy
//!
//! [`EsploraBroadcastClient::connect`] runs
//! [`stack_policy::ensure_legacy_publisher_allowed`] **inside** this
//! constructor before any Esplora I/O. There is no witness typestate and
//! no feature-gated mint path: every construction of a broadcast-capable
//! facade, from any crate including `node`, executes the same check.
//! Possession of a returned client is therefore evidence that the process
//! claim allowed legacy publish at construction time.

use bitcoin::{Address, BlockHash, OutPoint, Transaction, Txid};
use esplora_client::{
    r#async::DefaultSleeper, AsyncClient as RawAsyncClient, Builder as RawBuilder,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Read-only Esplora HTTP surface used by the legacy scanner, readiness
/// probe, and UTXO fetch.
pub struct EsploraReadClient {
    inner: RawAsyncClient<DefaultSleeper>,
}

impl std::fmt::Debug for EsploraReadClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EsploraReadClient { /* inner private */ }")
    }
}

/// Subset of Esplora block status the scanner needs (no raw type leak).
#[derive(Clone, Debug)]
pub struct BlockStatusView {
    pub height: Option<u32>,
    pub next_best: Option<BlockHash>,
}

/// One confirmed UTXO as returned by Esplora `GET /address/:addr/utxo`.
#[derive(Clone, Debug)]
pub struct AddressUtxo {
    pub outpoint: OutPoint,
    pub value_sats: u64,
}

impl EsploraReadClient {
    /// Build a read client from an Esplora base URL.
    pub fn connect(url: &str) -> Result<Self, BoxError> {
        let builder = RawBuilder::new(url);
        let inner = RawAsyncClient::<DefaultSleeper>::from_builder(builder)?;
        Ok(Self { inner })
    }

    pub async fn get_tip_hash(&self) -> Result<BlockHash, BoxError> {
        Ok(self.inner.get_tip_hash().await?)
    }

    pub async fn get_height(&self) -> Result<u32, BoxError> {
        Ok(self.inner.get_height().await?)
    }

    pub async fn get_block_txids(&self, block_hash: BlockHash) -> Result<Vec<Txid>, BoxError> {
        Ok(self.inner.get_block_txids(block_hash).await?)
    }

    pub async fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, BoxError> {
        Ok(self.inner.get_tx(txid).await?)
    }

    pub async fn get_block_status(&self, block_hash: &BlockHash) -> Result<BlockStatusView, BoxError> {
        let s = self.inner.get_block_status(block_hash).await?;
        Ok(BlockStatusView {
            height: s.height,
            next_best: s.next_best,
        })
    }

    pub async fn get_address_utxos(&self, address: Address) -> Result<Vec<AddressUtxo>, BoxError> {
        let utxos = self.inner.get_address_utxo(address).await?;
        Ok(utxos
            .into_iter()
            .map(|u| AddressUtxo {
                outpoint: OutPoint::new(u.txid, u.vout),
                value_sats: u.value.to_sat(),
            })
            .collect())
    }
}

/// Broadcast-capable Esplora client (raw I/O only).
///
/// Construction always runs the process-stack legacy-publisher policy
/// ([`stack_policy::ensure_legacy_publisher_allowed`]) before building the
/// inner client. Stack policy is co-located with construction so a caller
/// inside `node` cannot obtain a broadcast-capable client without the check.
/// This type hides the raw `esplora-client` handle.
pub struct EsploraBroadcastClient {
    inner: RawAsyncClient<DefaultSleeper>,
}

impl std::fmt::Debug for EsploraBroadcastClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EsploraBroadcastClient { /* inner private */ }")
    }
}

impl EsploraBroadcastClient {
    /// Build a broadcast-capable client from an Esplora base URL.
    ///
    /// Runs [`stack_policy::ensure_legacy_publisher_allowed`] first. Fails
    /// loud under a v1.1 process claim **before** any Esplora I/O. There is
    /// no un-checked constructor and no witness to forge or forget.
    pub fn connect(url: &str) -> Result<Self, BoxError> {
        stack_policy::ensure_legacy_publisher_allowed()?;
        let builder = RawBuilder::new(url);
        let inner = RawAsyncClient::<DefaultSleeper>::from_builder(builder)?;
        Ok(Self { inner })
    }

    pub async fn broadcast(&self, tx: &Transaction) -> Result<(), BoxError> {
        self.inner.broadcast(tx).await.map_err(|e| e.into())
    }

    pub async fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, BoxError> {
        self.inner.get_tx(txid).await.map_err(|e| e.into())
    }
}

#[cfg(test)]
mod policy_construction_tests {
    use super::*;
    use stack_policy::{
        clear_process_stack_mode_for_test, set_process_stack_mode, ScanStackMode,
        STACK_SEPARATION_REFUSAL,
    };

    /// A broadcast-capable client cannot be obtained under a v1.1 process
    /// claim — the policy check is inside `connect`, not a caller-side
    /// witness.
    #[test]
    fn broadcast_connect_refuses_under_v11_process_claim() {
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);
        let err = EsploraBroadcastClient::connect("http://127.0.0.1:1")
            .expect_err("v11 claim must block broadcast construction");
        let msg = err.to_string();
        assert!(
            msg.contains(STACK_SEPARATION_REFUSAL) || msg.contains("v1.1"),
            "got: {msg}"
        );
        clear_process_stack_mode_for_test();
    }

    /// Policy pass (legacy claim) allows construction; no stack-separation
    /// error is returned. Client build itself only needs a parseable URL.
    #[test]
    fn broadcast_connect_succeeds_under_legacy_process_claim() {
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::Legacy);
        let client = EsploraBroadcastClient::connect("http://127.0.0.1:1")
            .expect("legacy claim must allow broadcast construction");
        // Touch Debug so the private-inner formatting path is covered.
        let _ = format!("{client:?}");
        clear_process_stack_mode_for_test();
    }

    /// Unclaimed process (pre-boot / unit-test default) still allows legacy
    /// broadcast construction — same rule as the policy function.
    #[test]
    fn broadcast_connect_allowed_when_process_unclaimed() {
        clear_process_stack_mode_for_test();
        EsploraBroadcastClient::connect("http://127.0.0.1:1")
            .expect("unclaimed process allows legacy broadcast construction");
        clear_process_stack_mode_for_test();
    }
}
