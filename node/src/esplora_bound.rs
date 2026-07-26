//! Sole production boundary for the `esplora-client` crate.
//!
//! ## Why this module exists
//!
//! `esplora-client` is a package dependency of `node`, but **no production
//! module outside this file may import it**. All construction of the raw
//! `AsyncClient` lives here; callers only see [`EsploraReadClient`] (reads)
//! and [`LegacyBroadcastClient`] (legacy commitment broadcast, stack-gated).
//!
//! What makes a raw client unobtainable from production code:
//!
//! 1. The raw `AsyncClient` / `Builder` types are never re-exported.
//! 2. Both wrappers keep the raw handle in a **private** field with no
//!    `into_inner` / `as_raw` / public field.
//! 3. A unit test walks production sources and fails if any file other
//!    than this module mentions `esplora_client` / `EsploraBuilder` /
//!    `AsyncClient` construction patterns.
//!
//! A future caller that wants Esplora I/O must go through one of the
//! wrappers (or extend this module). Convention alone was not enough —
//! see the round-5 review: as long as the raw type is reachable, the
//! wrapper is optional.

use bitcoin::{Address, BlockHash, OutPoint, Transaction, Txid};
use esplora_client::{
    r#async::DefaultSleeper, AsyncClient as RawAsyncClient, Builder as RawBuilder,
};

use crate::v11::ensure_legacy_publisher_allowed;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Read-only Esplora HTTP surface used by the legacy scanner, readiness
/// probe, and UTXO fetch. Construction does **not** run the legacy
/// publisher stack check (reads are not a publish path).
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

/// Broadcast-capable Esplora client for **legacy** commitment inscriptions.
///
/// Construction always runs [`ensure_legacy_publisher_allowed`]. Possessing
/// a value of this type means the stack check passed at connect time.
pub struct LegacyBroadcastClient {
    inner: RawAsyncClient<DefaultSleeper>,
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
mod boundary_tests {
    use std::fs;
    use std::path::PathBuf;

    /// Production sources (excluding this module) must not import or
    /// construct the raw `esplora_client` types. The boundary is this file.
    #[test]
    fn production_sources_do_not_import_raw_esplora_client() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let src = manifest_dir.join("src");
        let mut offenders: Vec<String> = Vec::new();
        visit_rs(&src, &mut |path, contents| {
            // This module is the only allowed owner.
            if path.ends_with("esplora_bound.rs") {
                return;
            }
            // Integration tests under tests/ are outside src/.
            let forbidden = [
                "use esplora_client",
                "esplora_client::",
                "EsploraBuilder",
                "EsploraAsyncClient",
            ];
            for needle in forbidden {
                if contents.contains(needle) {
                    offenders.push(format!("{}: contains `{needle}`", path.display()));
                }
            }
        });
        assert!(
            offenders.is_empty(),
            "raw esplora_client must stay confined to esplora_bound.rs:\n{}",
            offenders.join("\n")
        );
    }

    fn visit_rs(dir: &std::path::Path, f: &mut impl FnMut(&std::path::Path, &str)) {
        let entries = fs::read_dir(dir).expect("read src");
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                // Skip generated / non-source if any.
                visit_rs(&path, f);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let contents = fs::read_to_string(&path).expect("read rs");
                f(&path, &contents);
            }
        }
    }
}
