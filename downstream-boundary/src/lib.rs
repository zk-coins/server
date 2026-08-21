//! Downstream-only edge used by the sealed plumbing compile-fail matrix.
//!
//! Production code does not depend on this crate. It exists so trybuild
//! generates a fixture whose sole library dependency is `node` — the same
//! edge a real consumer of the `node` package would have.
