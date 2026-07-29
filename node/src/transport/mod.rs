//! Transport adapters and shared error contract.
//!
//! Block 1 only introduces the total error mapping. HTTP/gRPC adapter
//! modules land with later blocks. Visibility is `pub(crate)`.

pub(crate) mod error_contract;

pub(crate) use error_contract::{describe, ErrorDescriptor, GrpcStatusCode, ERROR_INFO_DOMAIN};
