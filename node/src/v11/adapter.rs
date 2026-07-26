//! Node → [`StateEngine`] adapter (Cutover Stages 1–2).
//!
//! Owns a mutex-protected in-memory engine and the Postgres pool used to
//! snapshot / reload it. Stage 2 folds NfLog survivors through this
//! adapter (`scan` / `main::run_v11_scan_loop`). Wallet signing and
//! prove-path REST remain Stage 3.

use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use sqlx::PgPool;
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::prover_bridge::ProverBridge;
use zkcoins_prover::state_engine::StateEngine;

use super::db_v11::{self, EngineSnapshot};
use super::mode::{network_label, v11_boot_pins_from_env, V11_BOOT_CONFIG_ERROR};
use super::separation::require_v11_process_for_nflog_write;

/// In-memory engine plus the tip block hash the StateEngine does not yet
/// carry (Stage 1: hash lives on the adapter / snapshot so equal-height
/// forks stay distinguishable across persist/reload).
struct LiveEngine {
    engine: StateEngine,
    tip_hash: [u8; 32],
}

/// Flag-gated handle: node process ↔ v1.1 StateEngine + shadow persistence.
pub struct EngineAdapter {
    live: Mutex<LiveEngine>,
    pool: PgPool,
    network: Network,
    activation_height: u64,
}

impl EngineAdapter {
    /// Load from Postgres, or create an empty engine when the v11 tables are
    /// empty. Fails loud if meta is present but inconsistent with the caller's
    /// pins (network / activation height), or if meta is missing while data
    /// rows remain (see [`db_v11::load_engine_snapshot`]).
    pub async fn load_or_create(
        pool: PgPool,
        network: Network,
        activation_height: u64,
    ) -> Result<Self> {
        match db_v11::load_engine_snapshot(&pool)
            .await
            .context("EngineAdapter: load snapshot")?
        {
            None => {
                let engine = StateEngine::new(network, activation_height);
                let adapter = Self {
                    live: Mutex::new(LiveEngine {
                        engine,
                        tip_hash: [0u8; 32],
                    }),
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
                let engine = snap
                    .into_engine()
                    .context("EngineAdapter: reconstruct StateEngine from snapshot")?;
                Ok(Self {
                    live: Mutex::new(LiveEngine { engine, tip_hash }),
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
    /// Call only when `ZKCOINS_V11_SHADOW=1`. Missing env vars fail with
    /// [`V11_BOOT_CONFIG_ERROR`] — never fall back to legacy pins.
    pub async fn load_or_create_from_env(pool: PgPool) -> Result<Self> {
        let pins = v11_boot_pins_from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
        // Re-surface the canonical message if either pin was empty after trim.
        if network_label(pins.network).is_empty() {
            bail!("{V11_BOOT_CONFIG_ERROR}");
        }
        Self::load_or_create(pool, pins.network, pins.activation_height).await
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn activation_height(&self) -> u64 {
        self.activation_height
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.live
            .lock()
            .expect("EngineAdapter mutex poisoned")
            .tip_hash
    }

    /// Update the tip block hash (height remains on the engine via
    /// `set_tip_height`). Together they form the reorg-detectable cursor.
    ///
    /// Requires an exclusive v1.1 process claim — same capability as
    /// NfLog mutation so a legacy / unset process cannot move the cursor.
    pub fn set_tip_hash(&self, tip_hash: [u8; 32]) -> Result<()> {
        require_v11_process_for_nflog_write()
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

    /// §1.7.1 digests for `C` and `C_balance` (both pinned per network).
    pub fn circuit_digests(&self) -> ([u8; 32], [u8; 32]) {
        let bridge = self.bridge();
        (
            bridge.circuit_digest_bytes(),
            bridge.balance_circuit_digest_bytes(),
        )
    }

    pub fn with_engine<R>(&self, f: impl FnOnce(&StateEngine) -> R) -> R {
        let guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        f(&guard.engine)
    }

    /// Mutate the in-memory engine. Requires an exclusive v1.1 process claim
    /// ([`require_v11_process_for_nflog_write`]) — the public surface must not
    /// allow unguarded NfLog mutation under a legacy / unset claim.
    ///
    /// Callers that also persist **must** restore via [`Self::restore_live`]
    /// if the durable write fails (see [`super::scan::apply_forward_scan`]);
    /// this method alone does not open a DB transaction.
    pub fn with_engine_mut<R>(&self, f: impl FnOnce(&mut StateEngine) -> R) -> Result<R> {
        require_v11_process_for_nflog_write()
            .context("EngineAdapter::with_engine_mut: stack claim required")?;
        let mut guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        Ok(f(&mut guard.engine))
    }

    /// Snapshot the live engine + tip hash (for rollback if a later persist fails).
    pub fn snapshot_live(&self) -> EngineSnapshot {
        let guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        EngineSnapshot::from_engine_with_tip_hash(&guard.engine, guard.tip_hash)
    }

    /// Replace the live engine from a previously taken [`Self::snapshot_live`].
    ///
    /// Requires an exclusive v1.1 process claim. Rollback after a failed
    /// fold is still a live-engine mutation and must not run under a
    /// legacy / unset process.
    pub fn restore_live(&self, snap: EngineSnapshot) -> Result<()> {
        require_v11_process_for_nflog_write()
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
        let engine = snap
            .into_engine()
            .context("EngineAdapter::restore_live reconstruct")?;
        let mut guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        guard.engine = engine;
        guard.tip_hash = tip_hash;
        Ok(())
    }

    /// Snapshot the live engine and write it atomically to Postgres.
    pub async fn persist(&self) -> Result<()> {
        let snap = {
            let guard = self.live.lock().expect("EngineAdapter mutex poisoned");
            EngineSnapshot::from_engine_with_tip_hash(&guard.engine, guard.tip_hash)
        };
        db_v11::persist_engine_snapshot(&self.pool, &snap)
            .await
            .context("EngineAdapter::persist")
    }

    /// Drop the in-memory engine and rebuild it from Postgres.
    ///
    /// Used by restart-identity tests and by a future reorg/self-heal path.
    /// Requires an exclusive v1.1 process claim — reloading replaces the
    /// live engine the same way a fold does.
    pub async fn reload_from_db(&self) -> Result<()> {
        require_v11_process_for_nflog_write()
            .context("EngineAdapter::reload_from_db: stack claim required")?;
        let snap = db_v11::load_engine_snapshot(&self.pool)
            .await
            .context("EngineAdapter::reload_from_db load")?
            .context(
                "EngineAdapter::reload_from_db: v11 tables are empty — \
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
        let engine = snap
            .into_engine()
            .context("EngineAdapter::reload_from_db reconstruct")?;
        let mut guard = self.live.lock().expect("EngineAdapter mutex poisoned");
        guard.engine = engine;
        guard.tip_hash = tip_hash;
        Ok(())
    }

    /// Identity fingerprints used by restart-identity tests:
    /// `(nflog_nav_root_bytes, sorted (owner, coinhist_root_bytes))`.
    pub fn identity_roots(&self) -> ([u8; 32], Vec<([u8; 32], [u8; 32])>) {
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
            accounts.sort_by(|a, b| a.0.cmp(&b.0));
            (nflog_root, accounts)
        })
    }
}
