//! `kernel.v1` gRPC service skeleton (§7.8).
//!
//! Binds a tonic server on `KERNEL_GRPC_ADDR` (required, no default) and
//! implements every `service Kernel` procedure. Procedures whose node-side
//! Fachlogik is **not** yet a faithful §7.8 mapping return
//! `Status::unimplemented("<Name>: not yet implemented")` — never an
//! invented `Ok(...)` payload.
//!
//! The existing HTTP router is untouched; this is an additive internal
//! surface only (Kernel/API split is a later step).
//!
//! Mapping status is documented in `docs/kernel-rpc-mapping.md` and in the
//! implementer report for this change. Today **0 of 20** procedures are
//! wired: the five REST handlers that look closest (`GetJob`, `StreamJob`,
//! `SignTransition`, `CancelJob`, `AttestBalance`) only *approximately*
//! match §7.8 (HTTP/JSON shapes, OwnershipProof still on the node, no
//! typed Job→proto mapper). Wiring them half-correctly would ship silent
//! wrong `Ok` values — forbidden.

use std::net::SocketAddr;
use std::pin::Pin;

use futures_util::Stream;
use kernel_proto::kernel_server::{Kernel, KernelServer};
use kernel_proto::{
    AccountStateRequest, AccountStateResult, AccumulatorTip, AttestRequest, Challenge,
    CoinProofBlob, CoinProofRequest, EntrustRequest, EntrustResult, GetAccumulatorRequest,
    GetInfoRequest, GrantRequest, GrantResult, Info, Inscription, Job, JobEvent, JobHandle,
    JobRequest, ListInscriptionsRequest, NullifierPath, NullifierPathRequest, PublishRequest,
    PublishResult, PullChallengeRequest, PullRequest, PullResult, Receipt, RecordBlob,
    RecordRequest, RevokeRequest, RevokeResult, SignRequest, SubscribeReceiptsRequest,
    TransitionRequest,
};
use tonic::{Request, Response, Status};

/// Environment variable that selects the kernel gRPC listen address.
///
/// Required and non-empty. There is **no** default host or port — a missing
/// or blank value is a hard start failure (same fail-loud posture as
/// `DATABASE_URL` / `PUBLISHER_KEY`).
pub const KERNEL_GRPC_ADDR_ENV: &str = "KERNEL_GRPC_ADDR";

/// Failure starting the kernel gRPC listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelGrpcStartError {
    /// `KERNEL_GRPC_ADDR` is unset, empty, or whitespace-only.
    MissingAddr,
    /// `KERNEL_GRPC_ADDR` is set but is not a valid `SocketAddr`.
    InvalidAddr(String),
    /// Transport / bind / serve failure (message only — transport error
    /// is not `Clone`).
    Serve(String),
}

impl std::fmt::Display for KernelGrpcStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelGrpcStartError::MissingAddr => write!(
                f,
                "{KERNEL_GRPC_ADDR_ENV} env var must be set to a bind address \
                 (e.g. `127.0.0.1:50051`) — no default host or port exists"
            ),
            KernelGrpcStartError::InvalidAddr(raw) => write!(
                f,
                "{KERNEL_GRPC_ADDR_ENV} is not a valid socket address: {raw:?}"
            ),
            KernelGrpcStartError::Serve(msg) => {
                write!(f, "kernel gRPC serve failed: {msg}")
            }
        }
    }
}

impl std::error::Error for KernelGrpcStartError {}

/// Read and parse `KERNEL_GRPC_ADDR`. No default.
pub fn kernel_grpc_addr_from_env() -> Result<SocketAddr, KernelGrpcStartError> {
    let raw = std::env::var(KERNEL_GRPC_ADDR_ENV).map_err(|_| KernelGrpcStartError::MissingAddr)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(KernelGrpcStartError::MissingAddr);
    }
    trimmed
        .parse::<SocketAddr>()
        .map_err(|_| KernelGrpcStartError::InvalidAddr(raw))
}

/// Bind and serve `kernel.v1` on `addr` (runs until the process exits).
pub async fn serve_kernel_grpc(addr: SocketAddr) -> Result<(), KernelGrpcStartError> {
    let service = KernelService;
    tracing::info!(%addr, "kernel.v1 gRPC listening");
    tonic::transport::Server::builder()
        .add_service(KernelServer::new(service))
        .serve(addr)
        .await
        .map_err(|e| KernelGrpcStartError::Serve(e.to_string()))
}

/// Read `KERNEL_GRPC_ADDR` and serve. Fail-loud if the env var is missing
/// or not a bindable socket address.
pub async fn start_kernel_grpc() -> Result<(), KernelGrpcStartError> {
    let addr = kernel_grpc_addr_from_env()?;
    serve_kernel_grpc(addr).await
}

/// Honest `kernel.v1` implementation: every procedure is currently
/// `unimplemented` (see module docs). Holds no state — state wiring is
/// a later step once each procedure has a faithful §7.8 mapping.
#[derive(Debug, Default, Clone)]
struct KernelService;

fn not_yet(procedure: &'static str) -> Status {
    Status::unimplemented(format!("{procedure}: not yet implemented"))
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl Kernel for KernelService {
    async fn get_info(&self, _request: Request<GetInfoRequest>) -> Result<Response<Info>, Status> {
        Err(not_yet("GetInfo"))
    }

    async fn get_accumulator(
        &self,
        _request: Request<GetAccumulatorRequest>,
    ) -> Result<Response<AccumulatorTip>, Status> {
        Err(not_yet("GetAccumulator"))
    }

    type ListInscriptionsStream = BoxStream<Inscription>;

    async fn list_inscriptions(
        &self,
        _request: Request<ListInscriptionsRequest>,
    ) -> Result<Response<Self::ListInscriptionsStream>, Status> {
        Err(not_yet("ListInscriptions"))
    }

    async fn get_nullifier_path(
        &self,
        _request: Request<NullifierPathRequest>,
    ) -> Result<Response<NullifierPath>, Status> {
        Err(not_yet("GetNullifierPath"))
    }

    async fn submit_transition(
        &self,
        _request: Request<TransitionRequest>,
    ) -> Result<Response<JobHandle>, Status> {
        Err(not_yet("SubmitTransition"))
    }

    async fn get_job(&self, _request: Request<JobRequest>) -> Result<Response<Job>, Status> {
        Err(not_yet("GetJob"))
    }

    type StreamJobStream = BoxStream<JobEvent>;

    async fn stream_job(
        &self,
        _request: Request<JobRequest>,
    ) -> Result<Response<Self::StreamJobStream>, Status> {
        Err(not_yet("StreamJob"))
    }

    async fn sign_transition(
        &self,
        _request: Request<SignRequest>,
    ) -> Result<Response<Job>, Status> {
        Err(not_yet("SignTransition"))
    }

    async fn cancel_job(&self, _request: Request<JobRequest>) -> Result<Response<Job>, Status> {
        Err(not_yet("CancelJob"))
    }

    async fn open_pull_challenge(
        &self,
        _request: Request<PullChallengeRequest>,
    ) -> Result<Response<Challenge>, Status> {
        Err(not_yet("OpenPullChallenge"))
    }

    async fn pull(&self, _request: Request<PullRequest>) -> Result<Response<PullResult>, Status> {
        Err(not_yet("Pull"))
    }

    async fn get_record(
        &self,
        _request: Request<RecordRequest>,
    ) -> Result<Response<RecordBlob>, Status> {
        Err(not_yet("GetRecord"))
    }

    async fn get_coin_proof(
        &self,
        _request: Request<CoinProofRequest>,
    ) -> Result<Response<CoinProofBlob>, Status> {
        Err(not_yet("GetCoinProof"))
    }

    async fn get_account_state(
        &self,
        _request: Request<AccountStateRequest>,
    ) -> Result<Response<AccountStateResult>, Status> {
        Err(not_yet("GetAccountState"))
    }

    type SubscribeReceiptsStream = BoxStream<Receipt>;

    async fn subscribe_receipts(
        &self,
        _request: Request<SubscribeReceiptsRequest>,
    ) -> Result<Response<Self::SubscribeReceiptsStream>, Status> {
        Err(not_yet("SubscribeReceipts"))
    }

    async fn publish(
        &self,
        _request: Request<PublishRequest>,
    ) -> Result<Response<PublishResult>, Status> {
        Err(not_yet("Publish"))
    }

    async fn entrust_operational_bundle(
        &self,
        _request: Request<EntrustRequest>,
    ) -> Result<Response<EntrustResult>, Status> {
        Err(not_yet("EntrustOperationalBundle"))
    }

    async fn revoke_operational_bundle(
        &self,
        _request: Request<RevokeRequest>,
    ) -> Result<Response<RevokeResult>, Status> {
        Err(not_yet("RevokeOperationalBundle"))
    }

    async fn attest_balance(
        &self,
        _request: Request<AttestRequest>,
    ) -> Result<Response<JobHandle>, Status> {
        Err(not_yet("AttestBalance"))
    }

    async fn issue_view_grant(
        &self,
        _request: Request<GrantRequest>,
    ) -> Result<Response<GrantResult>, Status> {
        Err(not_yet("IssueViewGrant"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;
    use tonic::Code;

    /// Serialise env mutations: `KERNEL_GRPC_ADDR` is process-wide and
    /// tests run under `--test-threads=8`.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn missing_kernel_grpc_addr_is_missing_addr() {
        let _guard = env_lock();
        // Save / restore so we do not leak into other tests in this binary.
        let previous = std::env::var_os(KERNEL_GRPC_ADDR_ENV);
        std::env::remove_var(KERNEL_GRPC_ADDR_ENV);

        let err = kernel_grpc_addr_from_env().expect_err("unset must fail");
        assert_eq!(
            err,
            KernelGrpcStartError::MissingAddr,
            "error cause must be MissingAddr, got {err:?}"
        );

        // Empty / whitespace-only is the same class of failure (no default).
        std::env::set_var(KERNEL_GRPC_ADDR_ENV, "   ");
        let err = kernel_grpc_addr_from_env().expect_err("blank must fail");
        assert_eq!(err, KernelGrpcStartError::MissingAddr);

        match previous {
            Some(v) => std::env::set_var(KERNEL_GRPC_ADDR_ENV, v),
            None => std::env::remove_var(KERNEL_GRPC_ADDR_ENV),
        }
    }

    #[test]
    fn invalid_kernel_grpc_addr_is_invalid_addr() {
        let _guard = env_lock();
        let previous = std::env::var_os(KERNEL_GRPC_ADDR_ENV);
        std::env::set_var(KERNEL_GRPC_ADDR_ENV, "not-a-socket-addr");

        let err = kernel_grpc_addr_from_env().expect_err("garbage must fail");
        match err {
            KernelGrpcStartError::InvalidAddr(raw) => {
                assert_eq!(raw, "not-a-socket-addr");
            }
            other => panic!("expected InvalidAddr, got {other:?}"),
        }

        match previous {
            Some(v) => std::env::set_var(KERNEL_GRPC_ADDR_ENV, v),
            None => std::env::remove_var(KERNEL_GRPC_ADDR_ENV),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_kernel_grpc_fails_with_missing_addr_cause() {
        let _guard = env_lock();
        let previous = std::env::var_os(KERNEL_GRPC_ADDR_ENV);
        std::env::remove_var(KERNEL_GRPC_ADDR_ENV);

        let err = start_kernel_grpc()
            .await
            .expect_err("start without KERNEL_GRPC_ADDR must fail");
        assert_eq!(
            err,
            KernelGrpcStartError::MissingAddr,
            "assertion is on the error *cause*, not only Display"
        );

        match previous {
            Some(v) => std::env::set_var(KERNEL_GRPC_ADDR_ENV, v),
            None => std::env::remove_var(KERNEL_GRPC_ADDR_ENV),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_kernel_grpc_binds_configured_address() {
        // Ephemeral port: probe → drop → rebind (same shape as runtime_tests).
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe");
        let addr = probe.local_addr().expect("probe addr");
        drop(probe);

        let handle = tokio::spawn(async move { serve_kernel_grpc(addr).await });

        let mut last_err = None;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            match tokio::net::TcpStream::connect(addr).await {
                Ok(_) => {
                    handle.abort();
                    let _ = handle.await;
                    return;
                }
                Err(e) => last_err = Some(e),
            }
        }
        handle.abort();
        let _ = handle.await;
        panic!("kernel gRPC did not accept TCP on {addr} within timeout; last_err={last_err:?}");
    }

    /// Every procedure of `service Kernel` must name itself in an
    /// `Unimplemented` status. No invented `Ok` payloads.
    #[tokio::test]
    async fn every_procedure_is_unimplemented_with_its_name() {
        let svc = KernelService;

        // No `Debug` bound on `T`: streaming RPCs return `Response<dyn Stream…>`,
        // which is not `Debug`. `Result::expect_err` would force that bound via
        // its panic formatting — a plain `match` does not.
        async fn expect_unimplemented<T>(name: &'static str, result: Result<T, Status>) {
            let status = match result {
                Ok(_) => panic!("{name} must not return Ok"),
                Err(status) => status,
            };
            assert_eq!(
                status.code(),
                Code::Unimplemented,
                "{name}: expected Code::Unimplemented, got {:?}",
                status.code()
            );
            let msg = status.message();
            assert!(
                msg.contains(name),
                "{name}: status message must name the procedure, got {msg:?}"
            );
            assert!(
                msg.contains("not yet implemented"),
                "{name}: status message must say not yet implemented, got {msg:?}"
            );
        }

        // Empty Default bodies: we only assert the status code / message,
        // never a successful payload. Avoids inventing field values.
        expect_unimplemented(
            "GetInfo",
            svc.get_info(Request::new(GetInfoRequest::default())).await,
        )
        .await;
        expect_unimplemented(
            "GetAccumulator",
            svc.get_accumulator(Request::new(GetAccumulatorRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "ListInscriptions",
            svc.list_inscriptions(Request::new(ListInscriptionsRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "GetNullifierPath",
            svc.get_nullifier_path(Request::new(NullifierPathRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "SubmitTransition",
            svc.submit_transition(Request::new(TransitionRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "GetJob",
            svc.get_job(Request::new(JobRequest::default())).await,
        )
        .await;
        expect_unimplemented(
            "StreamJob",
            svc.stream_job(Request::new(JobRequest::default())).await,
        )
        .await;
        expect_unimplemented(
            "SignTransition",
            svc.sign_transition(Request::new(SignRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "CancelJob",
            svc.cancel_job(Request::new(JobRequest::default())).await,
        )
        .await;
        expect_unimplemented(
            "OpenPullChallenge",
            svc.open_pull_challenge(Request::new(PullChallengeRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented("Pull", svc.pull(Request::new(PullRequest::default())).await).await;
        expect_unimplemented(
            "GetRecord",
            svc.get_record(Request::new(RecordRequest::default())).await,
        )
        .await;
        expect_unimplemented(
            "GetCoinProof",
            svc.get_coin_proof(Request::new(CoinProofRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "GetAccountState",
            svc.get_account_state(Request::new(AccountStateRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "SubscribeReceipts",
            svc.subscribe_receipts(Request::new(SubscribeReceiptsRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "Publish",
            svc.publish(Request::new(PublishRequest::default())).await,
        )
        .await;
        expect_unimplemented(
            "EntrustOperationalBundle",
            svc.entrust_operational_bundle(Request::new(EntrustRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "RevokeOperationalBundle",
            svc.revoke_operational_bundle(Request::new(RevokeRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "AttestBalance",
            svc.attest_balance(Request::new(AttestRequest::default()))
                .await,
        )
        .await;
        expect_unimplemented(
            "IssueViewGrant",
            svc.issue_view_grant(Request::new(GrantRequest::default()))
                .await,
        )
        .await;
    }
}
