//! Process-global lifecycle for the host-wide proving lease.
//!
//! The lease serialises the memory-heavy prover across processes. It follows
//! actual circuit residency: acquisition precedes every fresh circuit build,
//! and release happens only after the idle TTL and after every resident slot
//! has either been evicted or proved to contain no circuit memory.

use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const LEASE_PATH_ENV: &str = "ZKCOINS_PROVER_LEASE_PATH";
const IDLE_TTL_SECS_ENV: &str = "ZKCOINS_PROVER_IDLE_TTL_SECS";
const LEASE_TIMEOUT_SECS_ENV: &str = "ZKCOINS_PROVER_LEASE_TIMEOUT_SECS";
const DEFAULT_IDLE_TTL_SECS: u64 = 30;
const DEFAULT_LEASE_TIMEOUT_SECS: u64 = 1800;
const REAPER_INTERVAL: Duration = Duration::from_secs(2);
const LEASE_POLL_INTERVAL: Duration = Duration::from_millis(100);

struct LeaseState {
    // Closing the fd releases flock even if the process crashes.
    _file: File,
}

struct LeaseManager {
    lease: Option<LeaseState>,
    last_active: Option<Instant>,
}

impl LeaseManager {
    const fn new() -> Self {
        Self {
            lease: None,
            last_active: None,
        }
    }
}

static MANAGER: Mutex<LeaseManager> = Mutex::new(LeaseManager::new());

// Linux flock locks independent open-file descriptions, even inside one
// process. Serialising open + poll prevents two first-build threads from each
// opening the lease file and then waiting forever on the other process-local fd.
// This is deliberately not MANAGER: note_active and the reaper must remain
// responsive during the potentially 30-minute cross-process poll.
static ACQUISITION: Mutex<()> = Mutex::new(());
static REAPER_STARTED: OnceLock<Result<(), String>> = OnceLock::new();

fn lock_manager() -> std::sync::MutexGuard<'static, LeaseManager> {
    // No MANAGER guard spans fallible work or a circuit build, so recovering
    // the inner value cannot expose a half-written state. Recovery also stops
    // an unrelated thread panic from cascading into the lease reaper.
    MANAGER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Acquire the host-wide flock once for this process.
///
/// The slow poll is serialised by [`ACQUISITION`] but never holds [`MANAGER`].
/// A second first-build thread rechecks the process state after acquiring that
/// serialiser, so it cannot open a second fd after another thread succeeded.
pub(crate) fn acquire_host_lease() -> Result<()> {
    {
        let mut manager = lock_manager();
        if manager.lease.is_some() {
            manager.last_active = Some(Instant::now());
            return Ok(());
        }
    }

    // Poison carries no data here: ACQUISITION is only a serialisation token,
    // so a prior owner's unwind cannot leave state that needs reconstruction.
    let _acquisition = ACQUISITION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    {
        let mut manager = lock_manager();
        if manager.lease.is_some() {
            manager.last_active = Some(Instant::now());
            return Ok(());
        }
    }

    let (file, path) = open_lease_file()?;
    let timeout_secs = env_secs(LEASE_TIMEOUT_SECS_ENV, DEFAULT_LEASE_TIMEOUT_SECS)?;
    acquire_exclusive_with_timeout(&file, &path, timeout_secs)?;

    // Start the only observer that can release an otherwise empty lease before
    // publishing the fd in MANAGER. If thread creation fails, `file` drops here
    // and flock is released instead of becoming a process-lifetime leak.
    ensure_reaper_started()?;

    let mut manager = lock_manager();
    manager.lease = Some(LeaseState { _file: file });
    manager.last_active = Some(Instant::now());
    Ok(())
}

/// Record circuit use without waiting behind cross-process flock polling.
pub(crate) fn note_active() {
    lock_manager().last_active = Some(Instant::now());
}

/// Boot-time path validation: open an existing lease file read-only, or create
/// it on a writable mount. This deliberately does not acquire the flock.
pub(crate) fn ensure_lease_path_ready() -> Result<()> {
    let (file, _) = open_lease_file()?;
    drop(file);
    Ok(())
}

fn lease_path_from_env() -> Result<PathBuf> {
    let value = std::env::var_os(LEASE_PATH_ENV).ok_or_else(|| {
        anyhow::anyhow!(
            "{LEASE_PATH_ENV} must be set for circuit construction; refusing to build without a host-wide lease"
        )
    })?;
    if value.is_empty() {
        bail!(
            "{LEASE_PATH_ENV} must be non-empty for circuit construction; refusing to build without a host-wide lease"
        );
    }
    Ok(PathBuf::from(value))
}

/// Read-first makes an existing lease usable through the secondary node's
/// read-only shared-volume mount. Only `NotFound` permits the explicit create
/// attempt used by the primary node; every other open error fails immediately.
fn open_lease_file() -> Result<(File, PathBuf)> {
    let path = lease_path_from_env()?;
    match OpenOptions::new().read(true).open(&path) {
        Ok(file) => Ok((file, path)),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&path)
                .with_context(|| {
                    format!(
                        "create proving lease file {} after it was not found; \
                         {LEASE_PATH_ENV} must point into a writable directory, or the primary \
                         node must boot first and create the file for a read-only secondary mount",
                        path.display()
                    )
                })?;
            Ok((file, path))
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "open existing proving lease file {} from {LEASE_PATH_ENV}",
                path.display()
            )
        }),
    }
}

fn env_secs(name: &'static str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => value.parse::<u64>().with_context(|| {
            format!("{name}={value:?} must be a non-negative integer number of seconds")
        }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{name} must contain valid UTF-8 integer seconds")
        }
    }
}

fn acquire_exclusive_with_timeout(file: &File, path: &Path, timeout_secs: u64) -> Result<()> {
    let timeout = Duration::from_secs(timeout_secs);
    let started = Instant::now();
    loop {
        match fs2::FileExt::try_lock_exclusive(file) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                let elapsed = started.elapsed();
                if elapsed >= timeout {
                    bail!(
                        "timed out after {timeout_secs}s waiting for host-wide proving lease {}; \
                         another prover process still owns the exclusive lease",
                        path.display()
                    );
                }
                std::thread::sleep(std::cmp::min(
                    LEASE_POLL_INTERVAL,
                    timeout.saturating_sub(elapsed),
                ));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("acquire exclusive host-wide proving lease {}", path.display())
                });
            }
        }
    }
}

/// Start the idle observer before a circuit build can begin.
pub(crate) fn ensure_reaper_started() -> Result<()> {
    if let Some(started) = REAPER_STARTED.get() {
        return started
            .as_ref()
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!(error.clone()));
    }

    let idle_ttl_secs = env_secs(IDLE_TTL_SECS_ENV, DEFAULT_IDLE_TTL_SECS)?;
    match REAPER_STARTED.get_or_init(|| {
        std::thread::Builder::new()
            .name("zkcoins-prover-reaper".to_owned())
            .spawn(move || reaper_loop(idle_ttl_secs))
            .map(|_| ())
            .map_err(|error| format!("spawn prover lease reaper thread: {error}"))
    }) {
        Ok(()) => Ok(()),
        Err(error) => bail!("{error}"),
    }
}

fn idle_ttl_elapsed(secs_since_active: u64, idle_ttl_secs: u64) -> bool {
    secs_since_active >= idle_ttl_secs
}

/// Run one idle-reaper tick behind an unwind boundary. The eviction callback
/// is injected so tests can exercise panic isolation with a lightweight
/// stand-in; production passes the unchanged six-slot eviction operation.
/// A panic may poison `MANAGER`, but the following tick recovers it through
/// [`lock_manager`] and remains able to release the lease.
fn reaper_tick(idle_ttl_secs: u64, try_evict_all_unreferenced: impl FnOnce() -> bool) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut manager = lock_manager();
        if manager.lease.is_none() {
            return;
        }
        let secs_since_active = manager
            .last_active
            .map(|last_active| last_active.elapsed().as_secs())
            .unwrap_or(0);
        if !idle_ttl_elapsed(secs_since_active, idle_ttl_secs) {
            return;
        }

        // Keep MANAGER only across the six short slot inspections so no cache
        // hit or new builder can race between the all-empty decision and flock
        // release. Builders never take MANAGER while holding a slot lock, and
        // no slot lock spans construction, so this lock order cannot deadlock.
        if try_evict_all_unreferenced() {
            manager.lease = None;
            manager.last_active = None;
        }
    }));

    if let Err(payload) = result {
        let description = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("non-string panic payload");
        eprintln!("zkcoins prover reaper tick panicked; continuing: {description}");
    }
}

fn reaper_loop(idle_ttl_secs: u64) {
    loop {
        std::thread::sleep(REAPER_INTERVAL);
        reaper_tick(
            idle_ttl_secs,
            crate::prover_bridge::try_evict_all_unreferenced,
        );
    }
}

#[cfg(test)]
mod prover_lease_tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    use super::*;

    static TEST_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct RemoveTestFile(PathBuf);

    impl Drop for RemoveTestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    struct RestoreEnv {
        name: &'static str,
        value: Option<std::ffi::OsString>,
    }

    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            match self.value.take() {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    fn unique_test_path(label: &str) -> PathBuf {
        let sequence = TEST_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "zkcoins-{label}-{}-{sequence}.lease",
            std::process::id()
        ))
    }

    fn clear_process_lease() {
        let mut manager = lock_manager();
        manager.lease = None;
        manager.last_active = None;
    }

    #[test]
    fn prover_lease_idle_ttl_boundary() {
        assert!(!idle_ttl_elapsed(29, 30));
        assert!(idle_ttl_elapsed(30, 30));
        assert!(idle_ttl_elapsed(31, 30));
    }

    #[test]
    fn reaper_recovers_after_one_panicking_tick_and_releases_on_the_next() {
        let _env_lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        clear_process_lease();
        let path = unique_test_path("reaper-panic-recovery");
        let _cleanup = RemoveTestFile(path.clone());
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("create stand-in lease file");
        {
            let mut manager = lock_manager();
            manager.lease = Some(LeaseState { _file: file });
            manager.last_active = Some(Instant::now());
        }

        // Call the same caught tick used by `reaper_loop` directly: this avoids
        // an infinite test thread and the production two-second sleep while
        // still panicking with MANAGER held, which also covers poison recovery.
        reaper_tick(0, || panic!("injected one-tick eviction failure"));
        assert!(
            lock_manager().lease.is_some(),
            "a failed tick must leave the lease owned"
        );

        reaper_tick(0, || true);
        let manager = lock_manager();
        assert!(
            manager.lease.is_none(),
            "the next clean tick must release the lease"
        );
        assert!(manager.last_active.is_none());
    }

    #[test]
    fn flock_is_mutually_exclusive_across_independent_fds() {
        let path = unique_test_path("flock-mutuality");
        let _cleanup = RemoveTestFile(path.clone());
        let first = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("create first independent lease fd");
        let second = OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("open second independent lease fd");

        fs2::FileExt::try_lock_exclusive(&first).expect("first fd takes exclusive flock");
        let blocked = fs2::FileExt::try_lock_exclusive(&second)
            .expect_err("second fd must not take flock while first fd holds it");
        assert_eq!(blocked.kind(), ErrorKind::WouldBlock);

        fs2::FileExt::unlock(&first).expect("release first fd flock");
        fs2::FileExt::try_lock_exclusive(&second)
            .expect("second fd takes flock after first releases it");
        fs2::FileExt::unlock(&second).expect("release second fd flock");
    }

    #[test]
    fn prover_lease_acquire_fails_closed_when_path_is_missing() {
        let _env_lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        clear_process_lease();
        let _restore_path = RestoreEnv {
            name: LEASE_PATH_ENV,
            value: std::env::var_os(LEASE_PATH_ENV),
        };
        std::env::remove_var(LEASE_PATH_ENV);

        let error = acquire_host_lease()
            .expect_err("acquire must fail when ZKCOINS_PROVER_LEASE_PATH is missing");
        assert!(error.to_string().contains(LEASE_PATH_ENV));
    }

    #[test]
    fn prover_lease_poll_does_not_hold_manager() {
        let _env_lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        clear_process_lease();
        let path = unique_test_path("manager-responsive");
        let _cleanup = RemoveTestFile(path.clone());
        let owner = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("create external lease owner");
        fs2::FileExt::try_lock_exclusive(&owner).expect("external fd owns flock");

        let _restore_path = RestoreEnv {
            name: LEASE_PATH_ENV,
            value: std::env::var_os(LEASE_PATH_ENV),
        };
        let _restore_timeout = RestoreEnv {
            name: LEASE_TIMEOUT_SECS_ENV,
            value: std::env::var_os(LEASE_TIMEOUT_SECS_ENV),
        };
        std::env::set_var(LEASE_PATH_ENV, &path);
        std::env::set_var(LEASE_TIMEOUT_SECS_ENV, "1");

        let acquiring = std::thread::spawn(acquire_host_lease);
        let wait_started = Instant::now();
        loop {
            match ACQUISITION.try_lock() {
                Err(std::sync::TryLockError::WouldBlock) => break,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    drop(poisoned.into_inner());
                    break;
                }
                Ok(guard) => drop(guard),
            }
            assert!(
                wait_started.elapsed() < Duration::from_secs(1),
                "acquire thread never entered its serialised flock poll"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            note_active();
            done_tx.send(()).expect("report note_active completion");
        });
        done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("note_active must not wait behind the blocking flock poll");

        let error = acquiring
            .join()
            .expect("acquire test thread must not panic")
            .expect_err("external flock owner must force acquisition timeout");
        assert!(error.to_string().contains("timed out"));
        fs2::FileExt::unlock(&owner).expect("release external test flock");
        clear_process_lease();
    }
}
