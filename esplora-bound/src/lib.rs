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
//! ## Broadcast capability = witness typestate
//!
//! [`EsploraBroadcastClient::connect`] requires a [`LegacyBroadcastWitness`].
//! The witness has a private field, so it cannot be forged outside this
//! crate. Minting is available only under the
//! `issue-legacy-broadcast-witness` feature (enabled solely by the `node`
//! package). The sole production issuer is
//! `node::v11::ensure_legacy_publisher_allowed`, which mints only after the
//! process claim check succeeds. Possession of a broadcast-capable client
//! is therefore evidence that a witness was supplied at construction; in
//! the workspace, that witness is issued only on the claim-check path.

use bitcoin::{Address, BlockHash, OutPoint, Transaction, Txid};
use esplora_client::{
    r#async::DefaultSleeper, AsyncClient as RawAsyncClient, Builder as RawBuilder,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Proof that the legacy-publisher process claim was checked.
///
/// Private field: values cannot be constructed with struct-literal syntax
/// from any other crate. The only mint path is [`LegacyBroadcastWitness::issue`],
/// gated behind the `issue-legacy-broadcast-witness` feature so workspace
/// crates other than `node` cannot obtain a witness at all.
///
/// `node::v11::ensure_legacy_publisher_allowed` is the sole caller of
/// [`issue`](LegacyBroadcastWitness::issue) after the claim check passes.
#[derive(Clone, Copy, Debug)]
pub struct LegacyBroadcastWitness {
    _private: (),
}

#[cfg(feature = "issue-legacy-broadcast-witness")]
impl LegacyBroadcastWitness {
    /// Mint a witness after the process claim check has succeeded.
    ///
    /// Available only when the `issue-legacy-broadcast-witness` feature is
    /// enabled. The `node` package is the sole workspace consumer of that
    /// feature; its claim-check function is the sole production caller.
    pub const fn issue() -> Self {
        Self { _private: () }
    }
}

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
/// Construction requires a [`LegacyBroadcastWitness`]. Stack policy (legacy
/// publisher under a v1.1 process claim) is enforced by the `node` package,
/// which is the sole issuer of that witness after the claim check. This
/// type hides the raw `esplora-client` handle and refuses un-witnessed
/// construction at compile time.
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
    /// Requires a [`LegacyBroadcastWitness`]. There is no un-witnessed
    /// constructor: `connect(url)` without a witness is a compile error.
    /// Possession of a returned client therefore implies a witness was
    /// supplied; the `node` package issues witnesses only from the
    /// claim-check path.
    pub fn connect(url: &str, _witness: LegacyBroadcastWitness) -> Result<Self, BoxError> {
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
