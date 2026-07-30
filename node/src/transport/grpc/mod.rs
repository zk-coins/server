//! gRPC transport adapters (Block 2–3: job procedures + SignTransition).
//!
//! Domain types in, proto / `tonic::Status` shapes out. Kernel never imports
//! these modules.

pub(crate) mod convert;
pub(crate) mod errors;

pub(crate) use convert::{job_event_to_proto, job_to_proto, parse_sign_request};
pub(crate) use errors::kernel_error_to_status;
