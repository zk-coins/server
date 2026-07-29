//! Generated `kernel.v1` types and gRPC service stubs.
//!
//! This crate contains **only** `tonic`/`prost` output from
//! `proto/kernel/v1/kernel.proto` plus re-exports. No business logic,
//! no node state, no validation beyond what prost generates.
//!
//! Normative contract: `docs/specification.md` §7.8 (tag `spec-v1.2`).

// Generated code trips several clippy lints; silence them at the crate
// root rather than fighting the generator.
#![allow(clippy::all)]
#![allow(missing_docs)]

tonic::include_proto!("kernel.v1");
