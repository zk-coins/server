//! gRPC transport adapters (Block 2: StreamJob / CancelJob error + event map).
//!
//! Domain types in, proto / `tonic::Status` shapes out. Kernel never imports
//! these modules.

pub(crate) mod convert;
pub(crate) mod errors;

pub(crate) use convert::{job_event_to_proto, job_to_proto};
pub(crate) use errors::kernel_error_to_status;
