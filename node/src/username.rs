use serde::{Deserialize, Serialize};
use shared::Address;
use sqlx::PgPool;
use std::collections::HashMap;

use crate::db;
use zkcoins_program::hash::digest_from_bytes;
#[cfg(all(test, feature = "username-claim"))]
use zkcoins_program::hash::digest_to_bytes;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct UsernameStore {
    usernames: HashMap<String, Address>,
}

impl UsernameStore {
    /// Test-only after PR-A3 — the production bootstrap calls
    /// `load_from_pg`. Kept because every store-touching test
    /// constructs a known-empty store via `new()`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Test-only sync helper: insert a `(normalized_name, address)`
    /// pair directly into the in-memory map, bypassing both the
    /// validation rules and the Postgres round-trip. Production code
    /// must go through `claim` so the SQL `ON CONFLICT DO NOTHING`
    /// boundary catches races; tests that just need a pre-populated
    /// store (for handler smoke tests, concurrent-read tests, etc.)
    /// use this to avoid bringing up a testcontainer per test.
    #[cfg(test)]
    pub(crate) fn insert_for_test(&mut self, normalized_name: &str, address: Address) {
        self.usernames.insert(normalized_name.to_string(), address);
    }

    /// Validate `username` against the public charset rules. Pulled
    /// out of `claim` so the same checks can run at the SQL boundary
    /// without a duplicate copy of the rules, and so the
    /// `claim_username` handler can normalise the value once at entry
    /// — the Schnorr signature hash and the persisted name then agree
    /// on the exact byte string, ruling out a case-mismatch squat.
    ///
    /// Returns the normalized (lowercased) name on success.
    #[cfg(feature = "username-claim")]
    pub(crate) fn validate(username: &str) -> Result<String, &'static str> {
        let normalized = username.to_lowercase();
        if normalized.is_empty() || normalized.len() > 64 {
            return Err("Username must be 1-64 characters");
        }
        if !normalized
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err("Username may only contain a-z, 0-9, -, _, .");
        }
        Ok(normalized)
    }

    /// Synchronous pre-flight check against the in-memory mirror. The
    /// claim handler runs this under a short `std::sync::Mutex` guard,
    /// then drops the guard before the DB round-trip — so concurrent
    /// `resolve` / `get_username` reads never observe a blank store
    /// while a claim is mid-flight (the bug the previous `mem::take`
    /// approach surfaced).
    ///
    /// Returns a 4xx-shaped validation message on collision. The
    /// dedicated `&'static str` return — rather than the broader
    /// `ClaimUsernameError` — keeps the handler's error mapping a flat
    /// `Result<(), &'static str>` with no unreachable `Db` arm; that
    /// would otherwise read as dead code under the 100 % coverage gate.
    #[cfg(feature = "username-claim")]
    pub(crate) fn precheck(&self, normalized: &str, address: &Address) -> Result<(), &'static str> {
        if self.usernames.contains_key(normalized) {
            return Err("Username already taken");
        }
        if self.usernames.values().any(|a| a == address) {
            return Err("Address already has a username");
        }
        Ok(())
    }

    /// In-memory commit that runs after the DB `ON CONFLICT DO NOTHING`
    /// has reported `rows_affected == 1`. Held under the same short
    /// sync guard as `precheck` would be — no `.await` inside, no
    /// `mem::take`, the store is never observable as empty.
    #[cfg(feature = "username-claim")]
    pub(crate) fn commit_after_db(&mut self, normalized: String, address: Address) {
        self.usernames.insert(normalized, address);
    }

    /// Claim `username` for `address`, persisting to Postgres
    /// atomically via `db::claim_username`'s `ON CONFLICT DO NOTHING`
    /// path. On success the in-memory mirror is updated too so
    /// subsequent `resolve` / `get_username` calls don't have to
    /// round-trip to the database.
    ///
    /// The "address already has a username" check is enforced at the
    /// in-memory level only — the database schema permits multiple
    /// names per address by design (a future product change might
    /// allow aliasing) and the application-level rule is the
    /// authoritative one for the MVP.
    ///
    /// This convenience wrapper composes `validate` + `precheck` +
    /// `db::claim_username` + `commit_after_db` so the unit tests can
    /// drive the full pipeline in one call. The production
    /// `claim_username_handler` calls the steps directly because it
    /// must not hold a `std::sync::Mutex` guard across the async DB
    /// round-trip.
    // Test-only convenience wrapper (production uses the handler +
    // `db::claim_username` steps without holding the mutex across await).
    #[cfg(all(test, feature = "username-claim"))]
    pub(crate) async fn claim(
        &mut self,
        pool: &PgPool,
        username: &str,
        address: Address,
    ) -> Result<(), ClaimUsernameError> {
        let normalized = Self::validate(username).map_err(ClaimUsernameError::Validation)?;
        self.precheck(&normalized, &address)
            .map_err(ClaimUsernameError::Validation)?;

        let addr_bytes = digest_to_bytes(&address);
        let inserted = db::claim_username(pool, &normalized, &addr_bytes).await?;
        if !inserted {
            // The SQL layer caught a race against another process /
            // worker that claimed the name between the in-memory check
            // above and this insert. Surface as the same string the
            // in-memory check would have produced.
            return Err(ClaimUsernameError::Validation("Username already taken"));
        }

        self.commit_after_db(normalized, address);
        Ok(())
    }

    pub(crate) fn resolve(&self, username: &str) -> Option<Address> {
        self.usernames.get(&username.to_lowercase()).copied()
    }

    #[cfg(test)]
    pub(crate) fn get_username(&self, address: &Address) -> Option<&str> {
        self.usernames
            .iter()
            .find(|(_, a)| *a == address)
            .map(|(name, _)| name.as_str())
    }

    /// Rebuild a `UsernameStore` from the `usernames` table.
    ///
    /// The full table is read into memory at boot so subsequent
    /// `resolve` / `get_username` calls — the hot read path — answer
    /// locally. The table is small (one row per registered user) and
    /// only grows through the `claim_username` endpoint, so the memory
    /// footprint is bounded.
    pub async fn load_from_pg(pool: &PgPool) -> Result<Self, LoadUsernameStoreError> {
        let rows = db::load_all_usernames(pool).await?;
        let mut usernames: HashMap<String, Address> = HashMap::with_capacity(rows.len());
        for (name, addr_bytes) in rows {
            let addr_arr: [u8; 32] = addr_bytes
                .as_slice()
                .try_into()
                .map_err(|_| LoadUsernameStoreError::BadAddressLength(addr_bytes.len()))?;
            usernames.insert(name, digest_from_bytes(&addr_arr));
        }
        Ok(UsernameStore { usernames })
    }
}

/// Error type for `UsernameStore::claim`. Wraps the validation error
/// strings (returned to the API caller as a 4xx body) and any database
/// error from the underlying `db::claim_username` upsert.
///
/// Test-only: production claim path does not use this enum.
#[cfg(all(test, feature = "username-claim"))]
#[derive(Debug)]
pub(crate) enum ClaimUsernameError {
    /// Caller-fixable input rejection (charset, length, duplicate).
    Validation(&'static str),
    /// The Postgres `INSERT ... ON CONFLICT DO NOTHING` failed for a
    /// reason other than a name conflict (connect, transaction).
    Db(sqlx::Error),
}

#[cfg(all(test, feature = "username-claim"))]
impl std::fmt::Display for ClaimUsernameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimUsernameError::Validation(s) => write!(f, "{}", s),
            ClaimUsernameError::Db(e) => write!(f, "database error: {}", e),
        }
    }
}

#[cfg(all(test, feature = "username-claim"))]
impl std::error::Error for ClaimUsernameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClaimUsernameError::Validation(_) => None,
            ClaimUsernameError::Db(e) => Some(e),
        }
    }
}

#[cfg(all(test, feature = "username-claim"))]
impl From<sqlx::Error> for ClaimUsernameError {
    fn from(e: sqlx::Error) -> Self {
        ClaimUsernameError::Db(e)
    }
}

/// Error type for `UsernameStore::load_from_pg`. Same split as
/// `state::LoadStateError` and `account_node::LoadAccountNodeError`
/// — bootstrap callers branch on these.
#[derive(Debug)]
pub enum LoadUsernameStoreError {
    /// The Postgres call itself failed (connect, query, decode).
    Db(sqlx::Error),
    /// A row's `address` column was not the expected 32 bytes.
    BadAddressLength(usize),
}

impl std::fmt::Display for LoadUsernameStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadUsernameStoreError::Db(e) => write!(f, "database error: {}", e),
            LoadUsernameStoreError::BadAddressLength(n) => write!(
                f,
                "usernames.address has unexpected length {} (expected 32)",
                n
            ),
        }
    }
}

impl std::error::Error for LoadUsernameStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadUsernameStoreError::Db(e) => Some(e),
            LoadUsernameStoreError::BadAddressLength(_) => None,
        }
    }
}

impl From<sqlx::Error> for LoadUsernameStoreError {
    fn from(e: sqlx::Error) -> Self {
        LoadUsernameStoreError::Db(e)
    }
}

#[cfg(test)]
#[path = "username_tests.rs"]
mod tests;
