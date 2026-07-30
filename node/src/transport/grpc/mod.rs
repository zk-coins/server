//! gRPC transport adapters (Block 2–4: jobs + SignTransition + SubmitTransition).
//!
//! Domain types in, proto / `tonic::Status` shapes out. Kernel never imports
//! these modules.

pub(crate) mod convert;
pub(crate) mod errors;

pub(crate) use convert::{
    account_state_to_proto, accumulator_tip_to_proto, coin_proof_blob_to_proto, job_event_to_proto,
    job_to_proto, kernel_info_to_proto, nullifier_path_to_proto, parse_attest_request,
    parse_coin_proof_request, parse_grant_request, parse_list_inscriptions_request,
    parse_nullifier_path_request, parse_pull_request, parse_record_request,
    parse_session_authority, parse_session_bound, parse_sign_request, parse_transition_request,
    pull_result_to_proto, record_blob_to_proto,
};
pub(crate) use errors::kernel_error_to_status;
