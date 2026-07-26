//! Shared-Postgres test infrastructure (Optimisation B from
//! zk-coins/node#181).
//!
//! ## Why this exists
//!
//! Before this module, every Postgres-touching test in the node crate
//! spun its own `postgres:17` container via `testcontainers_modules::
//! postgres::Postgres::default().with_tag("17").start()`. Container
//! boot is ~3 s wall on the M3 Ultra runner — multiplied across
//! ~220 DB-touching tests under `--test-threads=1` that is ~11 min
//! of pure container-spawn overhead per CI run.
//!
//! ## What changes
//!
//! - One `postgres:17` container is reused across the entire test
//!   run via testcontainers' `ReuseDirective::Always` + a stable
//!   container name (`zkcoins-test-shared-pg`). `cargo nextest`
//!   spawns one process per test, so a process-local `OnceCell`
//!   does NOT actually share state across tests — it would degrade
//!   to one container per test. The reuse flag tells testcontainers
//!   to look up the named container on the daemon and attach to it
//!   if present, only starting a fresh one when nothing matches.
//!   The container outlives every test binary in the run and is
//!   torn down by the CI's post-test `docker rm -f
//!   zkcoins-test-shared-pg` cleanup step.
//! - Each call to [`setup_pool`] creates a fresh, UUID-named schema
//!   in that shared container, runs the full migration suite scoped
//!   to that schema (via a per-pool `SET search_path` `after_connect`
//!   hook), and hands back a [`SchemaScope`] holding the pool.
//! - When the scope is dropped, the schema is removed **synchronously
//!   on a dedicated thread** (not a detached tokio task). Under
//!   nextest the process exits immediately after the test function
//!   returns; a `tokio::spawn` cleanup never runs and leftover
//!   `t_*` schemas accumulate until catalog pressure stalls the
//!   suite. Blocking cleanup + an orphan purge at attach fix that.
//!
//! ## Migration SQL precondition
//!
//! `search_path`-based schema isolation only works if no migration
//! SQL hardcodes a schema name. As of issue #181 a
//! `grep -E 'public\.|CREATE SCHEMA|SET search_path' node/migrations/`
//! returns empty — every CREATE/ALTER targets an unqualified table
//! name, so it lands in whichever schema is first on `search_path`.
//! New migrations MUST preserve this property.
//!
//! ## Cross-process attach-or-create race (issue #181 Opt A)
//!
//! `testcontainers` 0.27 does NOT atomicise the lookup-or-create
//! path behind `with_reuse(ReuseDirective::Always)`. The flow is:
//! `GET /containers/<name>/json` → on 404, `POST /containers/create`
//! → `POST /containers/<id>/start`. Two processes racing this
//! sequence both observe 404, both POST `create`, the Docker daemon
//! serialises the `create` calls and returns 409 Conflict to every
//! loser because the second `create` collides on the requested name.
//! At `--test-threads=1` this is dormant (one process at a time);
//! at `--test-threads=8` (the post-#181 default) it deterministically
//! breaks 6+/8 nextest processes on every cold-cache run.
//!
//! Workaround: a process-shared exclusive file lock around the
//! `testcontainers` call in [`init_shared_pg`]. The lock file lives
//! under `$TMPDIR` (falls back to `/tmp`) so every test process on
//! the same host serialises through the same inode. Acquisition is
//! **bounded** ([`LOCK_WAIT_SECS`]): if another process holds the
//! lock past that deadline we fail loud with a concrete remediation
//! message instead of hanging the suite forever.
//!
//! ## Orphan schema purge
//!
//! Live tests set `application_name = zkcoins-test:<schema>` on every
//! pool connection. Purge only drops `t_*` schemas that have **no**
//! backend advertising that name — so concurrent nextest workers keep
//! their in-use schemas. Leftovers from killed processes (no backend)
//! are removed automatically at the next attach.
//!
//! ## No polling
//!
//! `OnceCell::get_or_init` is event-driven; the first caller spawns
//! the container, every subsequent caller awaits the same future.
//! Per the repo's "No polling — events only" rule (CONTRIBUTING.md)
//! there is no readiness poll loop. The cross-process file lock uses
//! `try_lock_exclusive` with a deadline (bounded wait, fail-loud).

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};
use std::sync::Arc;
use std::time::{Duration, Instant};
use testcontainers::core::ReuseDirective;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::OnceCell;

/// Stable name the shared Postgres container is registered under on
/// the local Docker daemon. The `with_reuse(ReuseDirective::Always)`
/// lookup matches on this name plus the image config, so every
/// `cargo nextest` test process attaches to the same container.
const SHARED_PG_CONTAINER_NAME: &str = "zkcoins-test-shared-pg";

/// How long a process may wait for the cross-process attach-or-create
/// lock before failing loud. Covers one cold container create (~3 s)
/// plus headroom for a peer mid-purge; anything longer almost always
/// means a wedged Docker daemon or a dead holder.
const LOCK_WAIT_SECS: u64 = 120;

/// How long `init_shared_pg` may spend on container start/attach +
/// first admin connect + orphan purge before failing loud.
const CONTAINER_READY_SECS: u64 = 90;

/// Cap simultaneous connections per test pool. Under nextest with
/// `--test-threads=8`, eight processes × this budget must stay under
/// Postgres `max_connections` (default 100) with room for admin
/// cleanup connections.
const TEST_POOL_MAX_CONNECTIONS: u32 = 5;

/// If this many orphan `t_*` schemas remain after a purge pass, fail
/// loud — the catalog is too far gone for reliable concurrent DDL.
const ORPHAN_HARD_LIMIT: i64 = 500;

/// Lazily-initialised, process-wide (per test binary) Postgres
/// container. `Arc` wrapping lets [`SchemaScope::Drop`] capture a
/// cheap clone of `base_url` without borrowing from the `OnceCell`.
static SHARED_PG: OnceCell<Arc<SharedPg>> = OnceCell::const_new();

/// Single shared Postgres container plus the admin base URL.
///
/// The container handle is retained for the lifetime of the test
/// binary so the daemon does not garbage-collect it before the last
/// test finishes. `_container` is intentionally underscored — nothing
/// else reads it.
pub(crate) struct SharedPg {
    _container: ContainerAsync<Postgres>,
    pub base_url: String,
}

/// A per-test schema scoped against [`SHARED_PG`].
///
/// The held `pool` only ever sees the per-test schema (via the
/// `after_connect` hook that sets `search_path`), so test queries
/// never need to qualify table names. When the scope is dropped,
/// the schema is removed on a blocking path — see the module docs.
pub struct SchemaScope {
    pub pool: PgPool,
    schema: String,
    base_url: String,
}

impl SchemaScope {
    /// Name of the isolated per-test schema (`t_<uuid_simple>`).
    /// Exposed so a small number of introspection tests can scope
    /// their `information_schema` queries to the right schema
    /// (otherwise they would see the always-empty `public`).
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Admin base URL for the shared container (`postgres://...
    /// /postgres`, no `search_path` set). Exposed for the two
    /// `db_tests::connect_and_migrate_*` error-path tests that need
    /// to feed a URL into the real `db::connect_and_migrate` while
    /// still landing inside this test's isolated schema. Callers
    /// should append `?options=-c%20search_path%3D<schema>` to
    /// constrain the resulting pool.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for SchemaScope {
    fn drop(&mut self) {
        let schema = self.schema.clone();
        let base = self.base_url.clone();
        // Blocking cleanup on a dedicated OS thread with its own
        // current-thread runtime. nextest exits the process the moment
        // the test returns, so a `tokio::spawn` on the test runtime is
        // never polled. Joining the thread keeps orphan `t_*` schemas
        // from accumulating across the suite.
        //
        // Intentionally do **not** call `pool.close()` here: the test
        // is still inside `#[tokio::test]`'s runtime when locals drop,
        // and `PgPool::close` on a foreign runtime waits for connection
        // tasks owned by the test runtime — which is blocked joining
        // this thread → deadlock (suite stalls at 0% CPU). DROP SCHEMA
        // CASCADE terminates backends still holding the schema; the
        // pool handle is dropped with `SchemaScope` afterwards.
        let join = std::thread::Builder::new()
            .name("zkcoins-test-schema-drop".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                // Hard ceiling so a wedged cleanup cannot freeze nextest.
                // Orphan purge at the next attach is the backstop.
                let _ = rt.block_on(async move {
                    tokio::time::timeout(
                        Duration::from_secs(20),
                        drop_schema_best_effort(&base, &schema),
                    )
                    .await
                });
            });
        if let Ok(handle) = join {
            let _ = handle.join();
        }
    }
}

/// Start (or reuse) the shared Postgres container, create a fresh
/// per-test schema, run all migrations scoped to that schema, and
/// return a [`SchemaScope`] whose `pool` field is a `PgPool` whose
/// every connection has `search_path` pinned to the schema.
///
/// Drop the returned scope at the end of the test to surrender the
/// schema. Tests that wrap the pool in `Arc` should keep the scope
/// alive (`let scope = setup_pool().await; let pool =
/// Arc::new(scope.pool.clone());`) — `PgPool::clone` is cheap
/// (it is `Arc`-backed internally).
pub async fn setup_pool() -> SchemaScope {
    let pg = SHARED_PG.get_or_init(init_shared_pg).await.clone();

    let schema = format!("t_{}", uuid::Uuid::new_v4().simple());
    let app_name = application_name_for_schema(&schema);

    // CREATE SCHEMA via an admin pool (search_path = public) so we
    // do not depend on the chicken-and-egg state of the per-test
    // pool's `after_connect` hook. Advertise the test application_name
    // on the admin connection *before* CREATE SCHEMA so a concurrent
    // orphan purge cannot drop the schema in the window before the
    // per-test pool connects.
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(30))
        .after_connect({
            let app = app_name.clone();
            move |conn, _meta| {
                let app = app.clone();
                Box::pin(async move {
                    conn.execute(format!("SET application_name TO '{app}'").as_str())
                        .await?;
                    Ok(())
                })
            }
        })
        .connect(&pg.base_url)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "connect admin pool for schema create failed: {e}\n\
                 shared container `{SHARED_PG_CONTAINER_NAME}` may be wedged. \
                 Fix: `docker rm -f {SHARED_PG_CONTAINER_NAME}` then re-run."
            )
        });
    admin
        .execute(format!("CREATE SCHEMA \"{schema}\"").as_str())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "create per-test schema `{schema}` failed: {e}\n\
                 If the shared Postgres catalog is bloated with leftover \
                 `t_*` schemas, run: \
                 `docker rm -f {SHARED_PG_CONTAINER_NAME}` and re-run the suite."
            )
        });
    // Keep `admin` open until the per-test pool has connected (below)
    // so the application_name lease remains visible to purge.

    // Per-test pool: every connection sets search_path to the
    // isolated schema and advertises `application_name` so orphan
    // purge never drops an in-use schema. The migration runner below
    // picks up the same `after_connect` hook, so all `CREATE TABLE`
    // statements land in `<schema>` instead of `public`.
    let schema_for_hook = schema.clone();
    let app_name_for_hook = app_name.clone();
    let pool = PgPoolOptions::new()
        .max_connections(TEST_POOL_MAX_CONNECTIONS)
        .acquire_timeout(Duration::from_secs(60))
        .after_connect(move |conn, _meta| {
            let s = schema_for_hook.clone();
            let app = app_name_for_hook.clone();
            Box::pin(async move {
                // application_name is a literal identifier for purge;
                // schema names are `t_` + 32 hex so this is injection-safe.
                conn.execute(
                    format!("SET application_name TO '{app}'; SET search_path TO \"{s}\", public")
                        .as_str(),
                )
                .await?;
                Ok(())
            })
        })
        .connect(&pg.base_url)
        .await
        .expect("connect per-test pool");

    // Per-test pool now holds the application_name lease; admin can go.
    admin.close().await;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations in per-test schema");

    SchemaScope {
        pool,
        schema,
        base_url: pg.base_url.clone(),
    }
}

/// Boot OR attach to the shared container. Called via
/// `OnceCell::get_or_init` so concurrent callers within one process
/// await the same future. Across processes (the nextest default),
/// `ReuseDirective::Always` + the stable container name make
/// testcontainers attach to the already-running container instead
/// of spawning a new one.
///
/// The `testcontainers` 0.27 attach-or-create path is NOT atomic
/// (see module docs); under `--test-threads=8` (issue #181 Opt A),
/// concurrent test processes race to look up the named container.
/// Wrapping the call in a process-shared exclusive file lock with a
/// **bounded wait** serialises the race and fails loud if the lock
/// cannot be obtained.
async fn init_shared_pg() -> Arc<SharedPg> {
    let lock_path = std::env::temp_dir().join("zkcoins-test-pg.lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap_or_else(|e| {
            panic!(
                "open shared-pg lock file {}: {e}\n\
                 Fix: ensure $TMPDIR is writable.",
                lock_path.display()
            )
        });

    acquire_shared_pg_lock(&lock_file, &lock_path);

    // Bound the whole attach/create + readiness path so a wedged
    // Docker daemon cannot hang nextest indefinitely.
    let ready = tokio::time::timeout(Duration::from_secs(CONTAINER_READY_SECS), async {
        let container = Postgres::default()
            .with_tag("17")
            .with_container_name(SHARED_PG_CONTAINER_NAME)
            .with_reuse(ReuseDirective::Always)
            .start()
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "start or attach to shared postgres:17 container \
                     `{SHARED_PG_CONTAINER_NAME}` failed: {e}\n\
                     Fix: `docker rm -f {SHARED_PG_CONTAINER_NAME}` \
                     then re-run. Ensure Docker is running."
                )
            });
        let host = container
            .get_host()
            .await
            .expect("shared postgres get_host");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("shared postgres get_host_port_ipv4");
        let base_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

        // Fail loud if the container is up but Postgres is not
        // answering protocol-correctly (partial boot / catalog wedge).
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&base_url)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "shared postgres at {base_url} did not accept connections: {e}\n\
                     Fix: `docker rm -f {SHARED_PG_CONTAINER_NAME}` then re-run."
                )
            });

        // Purge leftover `t_*` schemas from previous nextest runs
        // whose process-exit skipped Drop. Only drops schemas with
        // no live backend advertising the test application_name.
        purge_orphan_test_schemas(&admin).await;
        admin.close().await;

        Arc::new(SharedPg {
            _container: container,
            base_url,
        })
    })
    .await;

    // Release the lock before interpreting the timeout result so a
    // panic/timeout cannot leave the exclusive lock held.
    drop(lock_file);

    match ready {
        Ok(pg) => pg,
        Err(_) => panic!(
            "shared postgres init exceeded {CONTAINER_READY_SECS}s \
             (container start/attach + admin connect + orphan purge).\n\
             Fix: `docker rm -f {SHARED_PG_CONTAINER_NAME}` and \
             `rm -f {}`, ensure Docker is healthy, then re-run.",
            lock_path.display()
        ),
    }
}

/// Bounded exclusive flock. Uses `try_lock_exclusive` + short sleeps
/// up to [`LOCK_WAIT_SECS`], then panics with remediation steps.
/// (Unbounded `lock_exclusive` is what made interrupted suite runs
/// appear as a permanent hang for the next operator.)
fn acquire_shared_pg_lock(lock_file: &std::fs::File, lock_path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(LOCK_WAIT_SECS);
    loop {
        match fs2::FileExt::try_lock_exclusive(lock_file) {
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    panic!(
                        "timed out after {LOCK_WAIT_SECS}s waiting for exclusive lock on {}.\n\
                         Another test process is stuck inside shared-Postgres \
                         attach-or-create, or a dead holder left the lock wedged.\n\
                         Fix:\n\
                         1. `docker rm -f {SHARED_PG_CONTAINER_NAME}`\n\
                         2. `rm -f {}`\n\
                         3. kill stray `target/debug/deps/node-*` / `cargo-nextest` processes\n\
                         4. re-run the suite",
                        lock_path.display(),
                        lock_path.display()
                    );
                }
                // Short yield only — not a readiness poll of Postgres.
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!(
                "acquire shared-pg lock on {}: {e}\n\
                 Fix: `rm -f {}` and re-run.",
                lock_path.display(),
                lock_path.display()
            ),
        }
    }
}

fn application_name_for_schema(schema: &str) -> String {
    format!("zkcoins-test:{schema}")
}

/// Drop every idle test schema (no backend with matching
/// `application_name`). Safe under concurrent nextest workers because
/// live pools advertise the lease on every connection.
async fn purge_orphan_test_schemas(admin: &PgPool) {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT n.nspname \
         FROM pg_namespace n \
         WHERE n.nspname LIKE 't\\_%' ESCAPE '\\' \
           AND NOT EXISTS ( \
             SELECT 1 FROM pg_stat_activity a \
             WHERE a.datname = current_database() \
               AND a.application_name = 'zkcoins-test:' || n.nspname \
           ) \
         ORDER BY n.nspname",
    )
    .fetch_all(admin)
    .await
    .unwrap_or_else(|e| {
        panic!(
            "listing orphan test schemas failed: {e}\n\
             Fix: `docker rm -f {SHARED_PG_CONTAINER_NAME}` then re-run."
        )
    });

    if rows.is_empty() {
        return;
    }

    eprintln!(
        "test_db: purging {} orphan t_* schema(s) from shared postgres",
        rows.len()
    );
    for (name,) in rows {
        if !is_test_schema_name(&name) {
            panic!("refusing to drop unexpected schema name `{name}` during orphan purge");
        }
        drop_schema_best_effort_on(admin, &name).await;
    }

    let remaining: (i64,) = sqlx::query_as(
        "SELECT count(*)::bigint FROM pg_namespace WHERE nspname LIKE 't\\_%' ESCAPE '\\'",
    )
    .fetch_one(admin)
    .await
    .unwrap_or_else(|e| panic!("counting remaining test schemas failed: {e}"));

    if remaining.0 > ORPHAN_HARD_LIMIT {
        panic!(
            "shared postgres still has {} t_* schemas after orphan purge \
             (limit {ORPHAN_HARD_LIMIT}). Catalog is too bloated for a reliable suite.\n\
             Fix: `docker rm -f {SHARED_PG_CONTAINER_NAME}` then re-run.",
            remaining.0
        );
    }
}

fn is_test_schema_name(name: &str) -> bool {
    // `t_` + 32 hex chars from `Uuid::simple()`.
    let rest = match name.strip_prefix("t_") {
        Some(r) => r,
        None => return false,
    };
    rest.len() == 32 && rest.chars().all(|c| c.is_ascii_hexdigit())
}

async fn drop_schema_best_effort(base_url: &str, schema: &str) {
    // Bounded connect so a wedged server cannot hang Drop (and thus
    // nextest) forever. `connect_timeout` is a libpq/sqlx URL option.
    let url = if base_url.contains('?') {
        format!("{base_url}&connect_timeout=5")
    } else {
        format!("{base_url}?connect_timeout=5")
    };
    let admin = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&url)
        .await
    {
        Ok(p) => p,
        Err(_) => return,
    };
    drop_schema_best_effort_on(&admin, schema).await;
    admin.close().await;
}

async fn drop_schema_best_effort_on(admin: &PgPool, schema: &str) {
    // Terminate backends still holding the per-test pool (same
    // application_name lease) *before* DROP SCHEMA. Otherwise
    // CASCADE waits for those connections while SchemaScope::Drop
    // joins this cleanup — classic deadlock under nextest.
    let app = application_name_for_schema(schema);
    let _ = admin
        .execute(
            format!(
                "SELECT pg_terminate_backend(pid) \
                 FROM pg_stat_activity \
                 WHERE datname = current_database() \
                   AND pid <> pg_backend_pid() \
                   AND application_name = '{app}'"
            )
            .as_str(),
        )
        .await;
    let _ = admin
        .execute(format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE").as_str())
        .await;
}
