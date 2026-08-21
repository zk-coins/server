//! Node → [`StateEngine`] adapter (Cutover Stages 1–2).
//!
//! Owns a mutex-protected in-memory engine and the Postgres pool used to
//! snapshot / reload it. Stage 2 folds NfLog survivors through this
//! adapter (`scan` / `main::run_v1_scan_loop`). Wallet signing and
//! prove-path REST remain Stage 3.
//!
//! ## Write serialisation (receive ↔ scanner)
//!
//! Receive and scanner each take a pre-mutation snapshot, mutate memory,
//! release the engine mutex, await durable persist, and may later restore
//! their snapshot on persist failure. Without a shared gate those restores
//! race: a scanner persist failure can roll back a receive that already
//! committed (or vice versa).
//!
//! [`Self::lock_writes`] is an async mutex held for the full
//! snapshot → mutate → persist → optional-restore critical section. Only
//! one participant may occupy that window at a time; that is what enforces
//! the ordering.

use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use sqlx::PgPool;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::prover_bridge::ProverBridge;
use zkcoins_prover::state_engine::StateEngine;

use super::db_v1::{self, CatalogInscription, EngineSnapshot};
use super::mode::{network_label, v1_boot_pins_from_env, V1_BOOT_CONFIG_ERROR};
use super::separation::require_v1_process_for_nflog_write;

/// In-memory engine plus the tip block hash the StateEngine does not yet
/// carry (Stage 1: hash lives on the adapter / snapshot so equal-height
/// forks stay distinguishable across persist/reload), and the inscription
/// catalog written at fold time (same durable transaction as NfLog).
struct LiveEngine {
    engine: StateEngine,
    tip_hash: [u8; 32],
    catalog: Vec<CatalogInscription>,
}

/// Identity fingerprints for restart tests:
/// `(nflog_nav_root_bytes, sorted (owner, coinhist_root_bytes))`.
#[cfg(test)]
type IdentityRoots = ([u8; 32], Vec<([u8; 32], [u8; 32])>);

/// Flag-gated handle: node process ↔ v1.1 StateEngine + shadow persistence.
pub struct EngineAdapter {
    live: Mutex<LiveEngine>,
    /// Serialises snapshot→mutate→persist→restore across receive and scanner.
    write_gate: AsyncMutex<()>,
    pool: PgPool,
    network: Network,
    activation_height: u64,
}

impl EngineAdapter {
    /// Load from Postgres, or create an empty engine when the v1 tables are
    /// empty. Fails loud if meta is present but inconsistent with the caller's
    /// pins (network / activation height), or if meta is missing while data
    /// rows remain (see [`db_v1::load_engine_snapshot`]).
    pub async fn load_or_create(
        pool: PgPool,
        network: Network,
        activation_height: u64,
    ) -> Result<Self> {
        match db_v1::load_engine_snapshot(&pool)
            .await
            .context("EngineAdapter: load snapshot")?
        {
            None => {
                let engine = StateEngine::new(network, activation_height);
                let adapter = Self {
                    live: Mutex::new(LiveEngine {
                        engine,
                        tip_hash: [0u8; 32],
                        catalog: Vec::new(),
                    }),
                    write_gate: AsyncMutex::new(()),
                    pool,
                    network,
                    activation_height,
                };
                // Persist the empty genesis snapshot so a subsequent boot
                // sees meta and can detect pin mismatches.
                adapter.persist().await?;
                Ok(adapter)
            }
            Some(snap) => {
                if snap.network != network {
                    bail!(
                        "EngineAdapter: persisted network={} but boot pin is {}; \
                         refusing to start (no silent network switch)",
                        network_label(snap.network),
                        network_label(network)
                    );
                }
                if snap.activation_height != activation_height {
                    bail!(
                        "EngineAdapter: persisted activation_height={} but boot pin is {}; \
                         refusing to start (activation_height is consensus-critical)",
                        snap.activation_height,
                        activation_height
                    );
                }
                let tip_hash = snap.tip_hash;
                let catalog = snap.inscriptions.clone();
                let engine = snap
                    .into_engine()
                    .context("EngineAdapter: reconstruct StateEngine from snapshot")?;
                Ok(Self {
                    live: Mutex::new(LiveEngine {
                        engine,
                        tip_hash,
                        catalog,
                    }),
                    write_gate: AsyncMutex::new(()),
                    pool,
                    network,
                    activation_height,
                })
            }
        }
    }

    /// Bootstrap from env pins (`ZKCOINS_NETWORK`, `ZKCOINS_ACTIVATION_HEIGHT`,
    /// published params identity, …).
    ///
    /// Call only when `ZKCOINS_V1_SHADOW=1`. Missing env vars fail with
    /// [`V1_BOOT_CONFIG_ERROR`] — never fall back to legacy pins.
    pub async fn load_or_create_from_env(pool: PgPool) -> Result<Self> {
        let pins = v1_boot_pins_from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
        // Re-surface the canonical message if either pin was empty after trim.
        if network_label(pins.network).is_empty() {
            bail!("{V1_BOOT_CONFIG_ERROR}");
        }
        Self::load_or_create(pool, pins.network, pins.activation_height).await
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn activation_height(&self) -> u64 {
        self.activation_height
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.live
            .lock()
            .expect("EngineAdapter mutex poisoned")
            .tip_hash
    }

    /// Acquire the exclusive write gate that serialises receive and scanner
    /// snapshot→mutate→persist→restore critical sections.
    ///
    /// Hold for the entire window that ends either with a durable commit or
    /// with a restore of the pre-mutation snapshot. Releasing earlier re-opens
    /// the cross-participant rollback race.
    ///
    /// **Crate-private.** Downstream code must not assemble mutate+persist
    /// windows; use receive / scan orchestration entry points.
    pub(crate) async fn lock_writes(&self) -> AsyncMutexGuard<'_, ()> {
        self.write_gate.lock().await
    }

    /// Update the tip block hash (height remains on the engine via
    /// `set_tip_height`). Together they form the reorg-detectable cursor.
    ///
    /// Requires an exclusive v1.1 process claim — same capability as
    /// NfLog mutation so a legacy / unset process cannot move the cursor.
    ///
    /// **Crate-private mutation sink.** Tip moves only through scan apply
    /// (and crate-internal receive/test setup).
    pub(crate) fn set_tip_hash(&self, tip_hash: [u8; 32]) -> Result<()> {
        require_v1_process_for_nflog_write()
            .context("EngineAdapter::set_tip_hash: stack claim required")?;
        self.live
            .lock()
            .expect("EngineAdapter mutex poisoned")
            .tip_hash = tip_hash;
        Ok(())
    }

    pub fn bridge(&self) -> ProverBridge {
        // ProverBridge is a cheap Copy handle; the circuit cache is process-global.
        ProverBridge::new(self.network)
    }

    /// Borrow the live engine under the adapter mutex (read-only).
    pub fn with_engine<R>(&self, f: impl FnOnce(&StateEngine) -> R) -> R {
        let guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        f(&guard.engine)
    }

    /// Mutate the in-memory engine. Requires an exclusive v1.1 process claim
    /// ([`require_v1_process_for_nflog_write`]) — unguarded NfLog mutation
    /// under a legacy / unset claim is refused.
    ///
    /// Callers that also persist **must** restore via [`Self::restore_live`]
    /// if the durable write fails (see [`super::scan::apply_forward_scan`]);
    /// this method alone does not open a DB transaction. Hold
    /// [`Self::lock_writes`] across the mutate+persist+restore window.
    ///
    /// **Crate-private mutation sink.** External crates cannot assemble
    /// engine mutations; use receive / scan orchestration.
    pub(crate) fn with_engine_mut<R>(&self, f: impl FnOnce(&mut StateEngine) -> R) -> Result<R> {
        require_v1_process_for_nflog_write()
            .context("EngineAdapter::with_engine_mut: stack claim required")?;
        let mut guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        Ok(f(&mut guard.engine))
    }

    /// Snapshot the live engine + tip hash (for rollback if a later persist fails).
    ///
    /// **Crate-private** — paired with sealed restore/persist sinks so a
    /// downstream cannot roll its own mutate window.
    pub(crate) fn snapshot_live(&self) -> EngineSnapshot {
        let guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        EngineSnapshot::from_engine_with_tip_hash(
            &guard.engine,
            guard.tip_hash,
            guard.catalog.clone(),
        )
    }

    /// Read-only clone of the in-memory inscription catalog.
    pub(crate) fn catalog_snapshot(&self) -> Vec<CatalogInscription> {
        self.live
            .lock()
            .expect("EngineAdapter mutex poisoned")
            .catalog
            .clone()
    }

    /// Replace the full catalog (reorg / full-replace apply).
    pub(crate) fn replace_catalog(&self, catalog: Vec<CatalogInscription>) -> Result<()> {
        require_v1_process_for_nflog_write()
            .context("EngineAdapter::replace_catalog: stack claim required")?;
        let mut guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        guard.catalog = catalog;
        Ok(())
    }

    /// Append newly accepted inscriptions (forward scan). Refuses duplicate
    /// triple keys so a re-scan cannot double-insert.
    pub(crate) fn append_catalog(&self, new: &[CatalogInscription]) -> Result<()> {
        require_v1_process_for_nflog_write()
            .context("EngineAdapter::append_catalog: stack claim required")?;
        let mut guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        for ins in new {
            let key = ins.cursor_key();
            if guard.catalog.iter().any(|e| e.cursor_key() == key) {
                bail!(
                    "EngineAdapter::append_catalog: inscription at \
                     ({},{},{}) already present — refusing silent overwrite",
                    ins.height,
                    ins.tx_index,
                    ins.vin_index
                );
            }
            guard.catalog.push(ins.clone());
        }
        // Keep stream order: (height, tx_index, vin_index).
        guard
            .catalog
            .sort_by_key(|e| (e.height, e.tx_index, e.vin_index));
        Ok(())
    }

    /// Replace the live engine from a previously taken [`Self::snapshot_live`].
    ///
    /// Requires an exclusive v1.1 process claim. Rollback after a failed
    /// fold is still a live-engine mutation and must not run under a
    /// legacy / unset process.
    ///
    /// **Crate-private mutation sink.**
    pub(crate) fn restore_live(&self, snap: EngineSnapshot) -> Result<()> {
        require_v1_process_for_nflog_write()
            .context("EngineAdapter::restore_live: stack claim required")?;
        if snap.network != self.network {
            bail!(
                "EngineAdapter::restore_live: network pin mismatch ({} vs {})",
                network_label(snap.network),
                network_label(self.network)
            );
        }
        if snap.activation_height != self.activation_height {
            bail!(
                "EngineAdapter::restore_live: activation_height pin mismatch ({} vs {})",
                snap.activation_height,
                self.activation_height
            );
        }
        let tip_hash = snap.tip_hash;
        let catalog = snap.inscriptions.clone();
        let engine = snap
            .into_engine()
            .context("EngineAdapter::restore_live reconstruct")?;
        let mut guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        guard.engine = engine;
        guard.tip_hash = tip_hash;
        guard.catalog = catalog;
        Ok(())
    }

    /// Snapshot the live engine and write it atomically to Postgres.
    ///
    /// NfLog, accounts, and the inscription catalog share one transaction
    /// (`clear_all` + `write_all`) so a failed fold cannot leave catalog
    /// rows without a matching NfLog tip (or the reverse).
    ///
    /// **Crate-private durable-write sink.** Downstream durable writes go
    /// through receive / scan orchestration only.
    pub(crate) async fn persist(&self) -> Result<()> {
        let snap = {
            let guard = self.live.lock().expect("EngineAdapter mutex poisoned");
            EngineSnapshot::from_engine_with_tip_hash(
                &guard.engine,
                guard.tip_hash,
                guard.catalog.clone(),
            )
        };
        db_v1::persist_engine_snapshot(&self.pool, &snap)
            .await
            .context("EngineAdapter::persist")
    }

    /// Drop the in-memory engine and rebuild it from Postgres.
    ///
    /// Used by restart-identity tests and by a future reorg/self-heal path.
    /// Requires an exclusive v1.1 process claim — reloading replaces the
    /// live engine the same way a fold does.
    ///
    /// **Crate-private mutation sink.**
    ///
    /// Production boots reconstruct via [`Self::load_or_create`]; this path
    /// is for in-process restart-identity (crate tests) and future self-heal.
    #[allow(dead_code)] // exercised by crate tests; not on the production boot path
    pub(crate) async fn reload_from_db(&self) -> Result<()> {
        require_v1_process_for_nflog_write()
            .context("EngineAdapter::reload_from_db: stack claim required")?;
        let snap = db_v1::load_engine_snapshot(&self.pool)
            .await
            .context("EngineAdapter::reload_from_db load")?
            .context(
                "EngineAdapter::reload_from_db: v1 tables are empty — \
                 cannot reload (no silent re-init to empty engine)",
            )?;
        if snap.network != self.network {
            bail!(
                "EngineAdapter::reload_from_db: network pin mismatch ({} vs {})",
                network_label(snap.network),
                network_label(self.network)
            );
        }
        if snap.activation_height != self.activation_height {
            bail!(
                "EngineAdapter::reload_from_db: activation_height pin mismatch ({} vs {})",
                snap.activation_height,
                self.activation_height
            );
        }
        let tip_hash = snap.tip_hash;
        let catalog = snap.inscriptions.clone();
        let engine = snap
            .into_engine()
            .context("EngineAdapter::reload_from_db reconstruct")?;
        let mut guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        guard.engine = engine;
        guard.tip_hash = tip_hash;
        guard.catalog = catalog;
        Ok(())
    }

    /// Identity fingerprints used by restart-identity tests:
    /// `(nflog_nav_root_bytes, sorted (owner, coinhist_root_bytes))`.
    #[cfg(test)]
    pub(crate) fn identity_roots(&self) -> IdentityRoots {
        self.with_engine(|engine| {
            let nav = engine.nflog().nav();
            let nflog_root = shared::spec_v1::digest_to_bytes(&nav.root());
            let mut accounts: Vec<([u8; 32], [u8; 32])> = engine
                .accounts()
                .map(|(owner, record)| {
                    (
                        owner.0,
                        shared::spec_v1::digest_to_bytes(&record.coinhist.root()),
                    )
                })
                .collect();
            accounts.sort_by_key(|a| a.0);
            (nflog_root, accounts)
        })
    }

    /// After a v1.1 self-heal Reset the durable tables are empty but this
    /// process still holds the pre-reset in-memory engine. Replace it with
    /// a fresh empty engine and persist so the next restart sees a consistent
    /// genesis snapshot (meta present, no accounts / NfLog entries).
    ///
    /// Requires an exclusive v1.1 process claim — same capability as any
    /// live-engine mutation. Fails loud if the claim is missing.
    pub async fn reinit_after_self_heal_reset(&self) -> Result<()> {
        require_v1_process_for_nflog_write()
            .context("EngineAdapter::reinit_after_self_heal_reset: stack claim required")?;
        {
            let mut guard = self.live.lock().expect("EngineAdapter mutex poisoned");
            guard.engine = StateEngine::new(self.network, self.activation_height);
            guard.tip_hash = [0u8; 32];
            guard.catalog.clear();
        }
        self.persist()
            .await
            .context("EngineAdapter::reinit_after_self_heal_reset persist")
    }
}
