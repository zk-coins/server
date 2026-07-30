//! gRPC transport adapters (Block 2–4: jobs + SignTransition + SubmitTransition).
//!
//! Domain types in, proto / `tonic::Status` shapes out. Kernel never imports
//! these modules.

pub(crate) mod convert;
pub(crate) mod errors;

pub(crate) use convert::{
    job_event_to_proto, job_to_proto, parse_attest_request, parse_grant_request,
    parse_sign_request, parse_transition_request,
};
pub(crate) use errors::kernel_error_to_status;
