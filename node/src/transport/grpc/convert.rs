//! Domain `Job` / `JobEvent` → `kernel.v1` proto messages.
//!
//! Conversion is fail-closed: a domain job that cannot be projected into a
//! **complete** proto `Job` (required digests for `awaiting_signature` /
//! `completed`) yields `KernelError::internal_error` rather than an `Ok`
//! with empty optional fields that pretend the payload is absent.

use crate::kernel::error::{KernelError, KernelResult};
use crate::kernel::types::{Job, JobEvent, JobKind, JobPayload, JobState};
use crate::v1;
use kernel_proto::{
    AwaitingSignature as ProtoAwaitingSignature, Job as ProtoJob, JobError as ProtoJobError,
    JobEvent as ProtoJobEvent, JobResult as ProtoJobResult,
};

/// Map a domain event to `kernel.v1.JobEvent`.
pub(crate) fn job_event_to_proto(event: &JobEvent) -> KernelResult<ProtoJobEvent> {
    Ok(ProtoJobEvent {
        event: event.kind.as_v1_str().to_string(),
        job: Some(job_to_proto(&event.job)?),
    })
}

/// Map a domain job to a complete proto `Job`.
///
/// Required payload fields are decoded from the store's free JSON:
/// - `awaiting_signature` → full §7.5 surface (hex digests + `send_counter`)
/// - `completed` → §7.5 `JobResult` (mint/send digests + ids, or attest-only)
/// - terminal `error` → closed machine code via [`v1::decode_job_error`]
///
/// A half-decodable payload is `Err`, never a half-filled `Ok`.
pub(crate) fn job_to_proto(job: &Job) -> KernelResult<ProtoJob> {
    let status = job.normative_status().as_v1_str().to_string();
    let phase = if job.state.is_terminal() {
        String::new()
    } else {
        job.phase.clone()
    };
    let progress = v1_progress_fraction(job.progress);

    let (awaiting_signature, result, error) = match &job.state {
        JobState::AwaitingSignature { payload, .. } => {
            (Some(decode_awaiting_signature(payload)?), None, None)
        }
        JobState::Completed { result } => (None, Some(decode_job_result(job.kind, result)?), None),
        JobState::Failed { error } => (
            None,
            None,
            Some(proto_job_error(error.as_deref(), /*cancelled*/ false)?),
        ),
        JobState::Cancelled { error } => (
            None,
            None,
            Some(proto_job_error(error.as_deref(), /*cancelled*/ true)?),
        ),
        JobState::Accepted | JobState::Proving | JobState::Publishing => (None, None, None),
    };

    Ok(ProtoJob {
        job_id: job.id.as_uuid().to_string(),
        kind: job.kind.as_str().to_string(),
        status,
        phase,
        progress,
        awaiting_signature,
        result,
        error,
    })
}

fn v1_progress_fraction(progress: i16) -> f32 {
    // Store holds 0–100; §7.5 wire is float in [0, 1].
    (progress as f32) / 100.0
}

fn proto_job_error(raw: Option<&str>, cancelled: bool) -> KernelResult<ProtoJobError> {
    let status = if cancelled {
        crate::job_store::JobStatus::Cancelled
    } else {
        crate::job_store::JobStatus::Failed
    };
    // `decode_job_error` always returns a closed {error, message} object.
    let v = v1::decode_job_error(raw, status);
    let error = match v.get("error").and_then(|e| e.as_str()) {
        Some(code) => code.to_string(),
        None => {
            return Err(KernelError::corrupt_job_row(
                "decode_job_error returned object without error field",
            ));
        }
    };
    let message = match v.get("message").and_then(|m| m.as_str()) {
        Some(m) => m.to_string(),
        None => {
            return Err(KernelError::corrupt_job_row(
                "decode_job_error returned object without message field",
            ));
        }
    };
    Ok(ProtoJobError { error, message })
}

/// §7.5 `awaiting_signature` surface → proto (all digests required).
fn decode_awaiting_signature(payload: &JobPayload) -> KernelResult<ProtoAwaitingSignature> {
    let obj = payload.0.as_object().ok_or_else(|| {
        KernelError::corrupt_job_row("awaiting_signature payload is not a JSON object")
    })?;
    Ok(ProtoAwaitingSignature {
        new_account_state_hash: require_hex_bytes(obj, "new_account_state_hash", 32)?,
        output_coins_root: require_hex_bytes(obj, "output_coins_root", 32)?,
        input_nullifiers_root: require_hex_bytes(obj, "input_nullifiers_root", 32)?,
        coin_history_root: require_hex_bytes(obj, "coin_history_root", 32)?,
        nav_commitment: require_hex_bytes(obj, "nav_commitment", 32)?,
        npk_commit: require_hex_bytes(obj, "npk_commit", 32)?,
        proof_data_hash: require_hex_bytes(obj, "proof_data_hash", 32)?,
        txn_pubkey: require_hex_bytes(obj, "txn_pubkey", 32)?,
        send_counter: require_u64(obj, "send_counter")?,
    })
}

/// §7.5 completed `result` → proto.
///
/// - `attest_balance`: only `attestation` is required; digest fields empty.
/// - mint / send: the three digests + `output_coin_ids` are required;
///   `publisher_pubkey` may be empty (self-publish); `attestation` empty.
fn decode_job_result(kind: JobKind, payload: &JobPayload) -> KernelResult<ProtoJobResult> {
    let obj = payload
        .0
        .as_object()
        .ok_or_else(|| KernelError::corrupt_job_row("completed result is not a JSON object"))?;

    match kind {
        JobKind::AttestBalance => {
            let attestation = require_hex_bytes_unbounded(obj, "attestation")?;
            Ok(ProtoJobResult {
                new_account_state_hash: Vec::new(),
                output_coins_root: Vec::new(),
                input_nullifiers_root: Vec::new(),
                output_coin_ids: Vec::new(),
                publisher_pubkey: Vec::new(),
                attestation,
            })
        }
        JobKind::Mint | JobKind::Send => {
            let output_coin_ids = require_hex_bytes_array(obj, "output_coin_ids", 32)?;
            let publisher_pubkey = optional_hex_bytes(obj, "publisher_pubkey", 32)?;
            Ok(ProtoJobResult {
                new_account_state_hash: require_hex_bytes(obj, "new_account_state_hash", 32)?,
                output_coins_root: require_hex_bytes(obj, "output_coins_root", 32)?,
                input_nullifiers_root: require_hex_bytes(obj, "input_nullifiers_root", 32)?,
                output_coin_ids,
                publisher_pubkey,
                attestation: Vec::new(),
            })
        }
    }
}

fn require_hex_bytes(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    expected_len: usize,
) -> KernelResult<Vec<u8>> {
    let raw = match obj.get(key).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return Err(KernelError::corrupt_job_row(format!(
                "job payload missing required hex field `{key}`"
            )));
        }
    };
    decode_hex_exact(raw, key, expected_len)
}

/// Hex field present and non-empty, length not fixed (attestation blob).
fn require_hex_bytes_unbounded(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> KernelResult<Vec<u8>> {
    let raw = match obj.get(key).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return Err(KernelError::corrupt_job_row(format!(
                "job payload missing required hex field `{key}`"
            )));
        }
    };
    if raw.is_empty() {
        return Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` is empty hex"
        )));
    }
    if raw.bytes().any(|b| !b.is_ascii_hexdigit()) {
        return Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` is not hex"
        )));
    }
    hex::decode(raw).map_err(|e| {
        KernelError::corrupt_job_row(format!("job payload field `{key}` hex decode failed: {e}"))
    })
}

/// Optional fixed-width hex: absent → empty bytes (self-publish statement).
/// Present but malformed → error (never silently drop).
fn optional_hex_bytes(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    expected_len: usize,
) -> KernelResult<Vec<u8>> {
    match obj.get(key) {
        None => Ok(Vec::new()),
        Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(v) => {
            let raw = match v.as_str() {
                Some(s) => s,
                None => {
                    return Err(KernelError::corrupt_job_row(format!(
                        "job payload field `{key}` is not a string"
                    )));
                }
            };
            if raw.is_empty() {
                return Ok(Vec::new());
            }
            decode_hex_exact(raw, key, expected_len)
        }
    }
}

fn require_hex_bytes_array(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    expected_len: usize,
) -> KernelResult<Vec<Vec<u8>>> {
    let arr = match obj.get(key).and_then(|v| v.as_array()) {
        Some(a) => a,
        None => {
            return Err(KernelError::corrupt_job_row(format!(
                "job payload missing required array field `{key}`"
            )));
        }
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let raw = match item.as_str() {
            Some(s) => s,
            None => {
                return Err(KernelError::corrupt_job_row(format!(
                    "job payload `{key}[{i}]` is not a hex string"
                )));
            }
        };
        out.push(decode_hex_exact(raw, &format!("{key}[{i}]"), expected_len)?);
    }
    Ok(out)
}

fn require_u64(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> KernelResult<u64> {
    match obj.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_u64().ok_or_else(|| {
            KernelError::corrupt_job_row(format!(
                "job payload field `{key}` is not a non-negative integer"
            ))
        }),
        Some(_) => Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` is not a number"
        ))),
        None => Err(KernelError::corrupt_job_row(format!(
            "job payload missing required field `{key}`"
        ))),
    }
}

fn decode_hex_exact(raw: &str, key: &str, expected_len: usize) -> KernelResult<Vec<u8>> {
    if raw.len() != expected_len * 2 {
        return Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` must be {} hex chars ({} bytes); got len {}",
            expected_len * 2,
            expected_len,
            raw.len()
        )));
    }
    if raw
        .bytes()
        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b) && !(b'A'..=b'F').contains(&b))
    {
        return Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` is not hex"
        )));
    }
    let bytes = hex::decode(raw).map_err(|e| {
        KernelError::corrupt_job_row(format!("job payload field `{key}` hex decode failed: {e}"))
    })?;
    if bytes.len() != expected_len {
        return Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` decoded to {} bytes, expected {expected_len}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::error::KernelErrorCode;
    use crate::kernel::types::{
        JobEventKind, JobId, JobKind, JobPayload, JobState, NormativeJobStatus,
    };
    use uuid::Uuid;

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn sample_awaiting_payload() -> JobPayload {
        JobPayload(serde_json::json!({
            "new_account_state_hash": hex32(0x11),
            "output_coins_root": hex32(0x22),
            "input_nullifiers_root": hex32(0x33),
            "coin_history_root": hex32(0x44),
            "nav_commitment": hex32(0x55),
            "npk_commit": hex32(0x66),
            "proof_data_hash": hex32(0x77),
            "txn_pubkey": hex32(0x88),
            "send_counter": 3u64,
        }))
    }

    fn sample_completed_payload() -> JobPayload {
        JobPayload(serde_json::json!({
            "new_account_state_hash": hex32(0xa1),
            "output_coins_root": hex32(0xa2),
            "input_nullifiers_root": hex32(0xa3),
            "output_coin_ids": [hex32(0xb1)],
        }))
    }

    fn sample_completed() -> Job {
        Job {
            id: JobId(Uuid::from_u128(1)),
            kind: JobKind::Mint,
            phase: "completed".to_string(),
            progress: 100,
            state: JobState::Completed {
                result: sample_completed_payload(),
            },
        }
    }

    #[test]
    fn complete_event_maps_event_name_status_and_result() {
        let job = sample_completed();
        let ev = JobEvent {
            kind: JobEventKind::Complete,
            job,
        };
        let proto = job_event_to_proto(&ev).expect("complete is well-formed");
        assert_eq!(proto.event, "complete");
        let j = proto.job.expect("job");
        assert_eq!(j.status, "completed");
        assert_eq!(j.kind, "mint");
        assert!(j.phase.is_empty(), "terminal phase absent");
        assert!((j.progress - 1.0).abs() < f32::EPSILON);
        assert!(j.error.is_none());
        let result = j.result.expect("result required on completed");
        assert_eq!(result.new_account_state_hash, vec![0xa1; 32]);
        assert_eq!(result.output_coin_ids.len(), 1);
        assert_eq!(result.output_coin_ids[0], vec![0xb1; 32]);
        assert!(result.publisher_pubkey.is_empty());
        assert!(result.attestation.is_empty());
    }

    #[test]
    fn failed_event_carries_job_error() {
        let job = Job {
            id: JobId(Uuid::from_u128(2)),
            kind: JobKind::Send,
            phase: "failed".to_string(),
            progress: 40,
            state: JobState::Failed {
                error: Some(v1::encode_job_error("proving_failed", "witness")),
            },
        };
        let ev = JobEvent {
            kind: JobEventKind::Error,
            job,
        };
        let proto = job_event_to_proto(&ev).expect("failed");
        assert_eq!(proto.event, "error");
        let err = proto.job.unwrap().error.unwrap();
        assert_eq!(err.error, "proving_failed");
        assert_eq!(err.message, "witness");
    }

    #[test]
    fn phase_event_uses_accepted_alias() {
        let job = Job {
            id: JobId(Uuid::from_u128(3)),
            kind: JobKind::Mint,
            phase: "queued".to_string(),
            progress: 0,
            state: JobState::Accepted,
        };
        assert_eq!(job.normative_status(), NormativeJobStatus::Accepted);
        let proto = job_to_proto(&job).expect("accepted");
        assert_eq!(proto.status, "accepted");
        assert_eq!(proto.phase, "queued");
        assert!(proto.result.is_none());
        assert!(proto.awaiting_signature.is_none());
        assert!(proto.error.is_none());
    }

    #[test]
    fn awaiting_signature_decodes_full_surface() {
        let job = Job {
            id: JobId(Uuid::from_u128(4)),
            kind: JobKind::Send,
            phase: "awaiting_signature".to_string(),
            progress: 50,
            state: JobState::AwaitingSignature {
                payload: sample_awaiting_payload(),
                proof_id: Some(9),
            },
        };
        let proto = job_to_proto(&job).expect("awaiting");
        assert_eq!(proto.status, "awaiting_signature");
        let ash = proto.awaiting_signature.expect("payload");
        assert_eq!(ash.new_account_state_hash, vec![0x11; 32]);
        assert_eq!(ash.send_counter, 3);
        assert!(proto.result.is_none());
    }

    #[test]
    fn legacy_ash_ocr_awaiting_signature_is_internal_error() {
        // Legacy surface is not a complete §7.8 AwaitingSignature — refuse.
        let job = Job {
            id: JobId(Uuid::from_u128(5)),
            kind: JobKind::Send,
            phase: "awaiting_signature".to_string(),
            progress: 50,
            state: JobState::AwaitingSignature {
                payload: JobPayload(serde_json::json!({
                    "account_state_hash": hex32(0xaa),
                    "output_coins_root": hex32(0xbb),
                })),
                proof_id: Some(1),
            },
        };
        let err = job_to_proto(&job).expect_err("legacy ash‖ocr is incomplete");
        assert_eq!(err.code, KernelErrorCode::InternalError);
    }

    #[test]
    fn completed_without_digests_is_internal_error() {
        // Full mint/send completed surface except one required digest — so the
        // error detail names that field specifically, not whichever happens to
        // be validated first among several absences.
        let job = Job {
            id: JobId(Uuid::from_u128(6)),
            kind: JobKind::Mint,
            phase: "completed".to_string(),
            progress: 100,
            state: JobState::Completed {
                result: JobPayload(serde_json::json!({
                    "output_coins_root": hex32(0xa2),
                    "input_nullifiers_root": hex32(0xa3),
                    "output_coin_ids": [hex32(0xb1)],
                    // deliberately omit `new_account_state_hash`
                })),
            },
        };
        let err = job_to_proto(&job).expect_err("half result");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        let detail = &err.internal_context.expect("ctx").detail;
        assert!(detail.contains("new_account_state_hash"), "detail={detail}");
    }

    #[test]
    fn attest_completed_requires_only_attestation() {
        let job = Job {
            id: JobId(Uuid::from_u128(7)),
            kind: JobKind::AttestBalance,
            phase: "completed".to_string(),
            progress: 100,
            state: JobState::Completed {
                result: JobPayload(serde_json::json!({
                    "attestation": hex::encode([0xCDu8; 16]),
                })),
            },
        };
        let proto = job_to_proto(&job).expect("attest");
        let result = proto.result.expect("result");
        assert_eq!(result.attestation, vec![0xCD; 16]);
        assert!(result.new_account_state_hash.is_empty());
        assert!(result.output_coin_ids.is_empty());
    }
}
