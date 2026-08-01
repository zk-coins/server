//! gRPC transport adapters (Block 2–4: jobs + SignTransition + SubmitTransition;
//! Block 8: Publish / Entrust / Revoke).
//!
//! Domain types in, proto / `tonic::Status` shapes out. Kernel never imports
//! these modules.

pub(crate) mod convert;
pub(crate) mod errors;

pub(crate) use convert::{
    account_state_to_proto, accumulator_tip_to_proto, coin_proof_blob_to_proto,
    entrust_result_to_proto, inscription_to_proto, job_event_to_proto, job_to_proto,
    kernel_info_to_proto, nullifier_path_to_proto, parse_attest_request, parse_coin_proof_request,
    parse_entrust_request, parse_grant_request, parse_list_inscriptions_request,
    parse_nullifier_path_request, parse_publish_request, parse_pull_request, parse_record_request,
    parse_revoke_request, parse_session_authority, parse_session_bound, parse_sign_request,
    parse_transition_request, publish_outcome_to_proto, pull_result_to_proto, receipt_to_proto,
    record_blob_to_proto, revoke_result_to_proto,
};
pub(crate) use errors::kernel_error_to_status;
