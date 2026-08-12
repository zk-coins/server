//! Transport adapters and shared error contract.
//!
//! Visibility is `pub(crate)`. HTTP SSE projections for jobs currently live
//! in `router` (byte-stable with existing pure helpers); gRPC conversion
//! for StreamJob/CancelJob lives under `grpc/`.

pub(crate) mod error_contract;
pub(crate) mod grpc;
