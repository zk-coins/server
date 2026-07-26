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
//! [`EsploraBroadcastClient`] (broadcast + get_tx). Stack policy for the
//! legacy publisher (v1.1 exclusive claim) is enforced by the `node`
//! wrapper around [`EsploraBroadcastClient`] — this crate stays free of
//! process-global stack state.

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
/// Stack policy (legacy publisher under a v1.1 process claim) is enforced
/// by the `node` package's [`LegacyBroadcastClient`](../node) wrapper —
/// this type only hides the raw `esplora-client` handle.
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
    pub fn connect(url: &str) -> Result<Self, BoxError> {
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
