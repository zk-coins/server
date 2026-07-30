//! `kernel.v1` gRPC service (§7.8).
//!
//! Binds a tonic server on a configured address and implements every
//! `service Kernel` procedure. Procedures whose node-side Fachlogik is
//! **not** yet a faithful §7.8 mapping return
//! `Status::unimplemented("<Name>: not yet implemented")` — never an
//! invented `Ok(...)` payload.
//!
//! Wired today (Block 4–5): `GetJob`, `StreamJob`, `CancelJob`,
//! `SignTransition`, `SubmitTransition`, `AttestBalance`, `IssueViewGrant`.
//! These call the transport-neutral domain façade and map through
//! `transport/grpc/` converters + the shared error contract.
//!
//! The existing HTTP router is untouched; this is an additive internal
//! surface only (Kernel/API split is a later step).

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::Stream;
use futures_util::StreamExt;
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
use uuid::Uuid;

use crate::job_dispatcher::JobEnvelope;
use crate::job_store::JobStore;
use crate::kernel::{
    CancelPolicy, JobId, JobRequest as DomainJobRequest, KernelError, KernelErrorCode,
    KernelService as DomainKernel,
};
use crate::transport::grpc::{
    job_event_to_proto, job_to_proto, kernel_error_to_status, parse_attest_request,
    parse_grant_request, parse_sign_request, parse_transition_request,
};
use crate::v1::PendingSignMap;
use tokio::sync::mpsc;

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

/// Bind and serve with an explicit domain façade (shared store + hub).
///
/// Used by `start_rest_node` so gRPC and REST/dispatcher share one
/// notify map. There is **no** pool-only public entry that fabricates a
/// fresh empty notify map — a gRPC server without the dispatcher's hub
/// would accept `StreamJob` and never emit phase events.
///
/// Domain types stay crate-private; the only production boot path is
/// `start_rest_node` (binary) after `kernel_grpc_addr_from_env`.
pub(crate) async fn serve_kernel_grpc_with_domain(
    addr: SocketAddr,
    domain: DomainKernel,
    job_tx: mpsc::Sender<JobEnvelope>,
) -> Result<(), KernelGrpcStartError> {
    let service = GrpcKernelService::new(domain, job_tx);
    tracing::info!(%addr, "kernel.v1 gRPC listening");
    tonic::transport::Server::builder()
        .add_service(KernelServer::new(service))
        .serve(addr)
        .await
        .map_err(|e| KernelGrpcStartError::Serve(e.to_string()))
}

/// gRPC adapter over the transport-neutral domain façade.
///
/// Constructed only with a real [`DomainKernel`] (store + event hub) and
/// the same admit channel REST uses. No `Default` — an empty service
/// would invent a silent no-data edge.
#[derive(Clone)]
struct GrpcKernelService {
    domain: DomainKernel,
    job_tx: mpsc::Sender<JobEnvelope>,
}

impl GrpcKernelService {
    fn new(domain: DomainKernel, job_tx: mpsc::Sender<JobEnvelope>) -> Self {
        Self { domain, job_tx }
    }
}

fn not_yet(procedure: &'static str) -> Status {
    Status::unimplemented(format!("{procedure}: not yet implemented"))
}

/// Parse proto `JobRequest.job_id` into a domain request.
///
/// Empty / non-UUID → `malformed_request` (never a silent nil UUID).
/// Returns a domain error; callers map through [`map_domain_err`] so the
/// parse path never stamps a transport status itself.
fn parse_job_request(req: kernel_proto::JobRequest) -> Result<DomainJobRequest, KernelError> {
    let raw = req.job_id.trim();
    if raw.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "job_id is required",
        ));
    }
    let id = Uuid::parse_str(raw).map_err(|_| {
        KernelError::new(KernelErrorCode::MalformedRequest, "job_id must be a UUID")
    })?;
    Ok(DomainJobRequest { id: JobId(id) })
}

fn map_domain_err(err: KernelError) -> Status {
    if err.code == KernelErrorCode::InternalError {
        if let Some(ctx) = &err.internal_context {
            tracing::error!("kernel gRPC internal_error: {}", ctx.detail);
        }
    }
    kernel_error_to_status(&err)
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl Kernel for GrpcKernelService {
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
        request: Request<TransitionRequest>,
    ) -> Result<Response<JobHandle>, Status> {
        let cmd = parse_transition_request(request.into_inner()).map_err(map_domain_err)?;
        let job = self
            .domain
            .submit_transition(&self.job_tx, cmd)
            .await
            .map_err(map_domain_err)?;
        Ok(Response::new(JobHandle {
            job_id: job.id.as_uuid().to_string(),
            // §7.5 / §7.8: success status is `accepted` (store row is `queued`).
            status: job.normative_status().as_v1_str().to_string(),
        }))
    }

    async fn get_job(&self, request: Request<JobRequest>) -> Result<Response<Job>, Status> {
        let req = parse_job_request(request.into_inner()).map_err(map_domain_err)?;
        let job = self.domain.get_job(req).await.map_err(map_domain_err)?;
        let proto = job_to_proto(&job).map_err(map_domain_err)?;
        Ok(Response::new(proto))
    }

    type StreamJobStream = BoxStream<JobEvent>;

    async fn stream_job(
        &self,
        request: Request<JobRequest>,
    ) -> Result<Response<Self::StreamJobStream>, Status> {
        let req = parse_job_request(request.into_inner()).map_err(map_domain_err)?;
        let domain_stream = self.domain.stream_job(req).await.map_err(map_domain_err)?;

        let stream = async_stream::stream! {
            let mut domain_stream = domain_stream;
            while let Some(item) = domain_stream.next().await {
                match item {
                    Ok(ev) => match job_event_to_proto(&ev) {
                        Ok(proto) => {
                            let terminal = ev.job.state.is_terminal();
                            yield Ok(proto);
                            if terminal {
                                return;
                            }
                        }
                        Err(e) => {
                            yield Err(map_domain_err(e));
                            return;
                        }
                    },
                    Err(e) => {
                        yield Err(map_domain_err(e));
                        return;
                    }
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }

    async fn sign_transition(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<Job>, Status> {
        // API-edge feature gate (same surface as HTTP `feature_disabled`):
        // not a KernelErrorCode. Refuse before domain so a legacy stack
        // never sees a missing-staging `internal_error` for a surface that
        // is simply off. Unimplemented + flag name distinguishes this from
        // unwired procedures (`"<Name>: not yet implemented"`).
        if !crate::v1::v1_sign_route_active() {
            return Err(Status::unimplemented(
                "SignTransition: disabled — requires ZKCOINS_V1_SHADOW=1 / \
                 ScanStackMode::V1 (surface inactive in this configuration; \
                 not an unimplemented procedure)",
            ));
        }
        // Width / UUID checks at the transport edge (64 / 32 bytes).
        let req = parse_sign_request(request.into_inner()).map_err(map_domain_err)?;
        let job = self
            .domain
            .sign_transition(req)
            .await
            .map_err(map_domain_err)?;
        let proto = job_to_proto(&job).map_err(map_domain_err)?;
        Ok(Response::new(proto))
    }

    async fn cancel_job(&self, request: Request<JobRequest>) -> Result<Response<Job>, Status> {
        let req = parse_job_request(request.into_inner()).map_err(map_domain_err)?;
        // §7.8 CancelJob uses the normative not-yet-published policy.
        let job = self
            .domain
            .cancel_job(req, CancelPolicy::NotYetPublished)
            .await
            .map_err(map_domain_err)?;
        let proto = job_to_proto(&job).map_err(map_domain_err)?;
        Ok(Response::new(proto))
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
        request: Request<AttestRequest>,
    ) -> Result<Response<JobHandle>, Status> {
        // OwnershipProof is API-layer only — this message carries none.
        let command = parse_attest_request(request.into_inner()).map_err(map_domain_err)?;
        let hosts = crate::v1::public_hosts_from_env();
        let allowed: Vec<[u8; 32]> = hosts
            .iter()
            .map(|h| crate::v1::attest::chan_bind_for_host(h))
            .collect();
        let now = crate::v1::unix_now();
        let job = self
            .domain
            .attest_balance(&self.job_tx, &allowed, now, command)
            .await
            .map_err(map_domain_err)?;
        Ok(Response::new(JobHandle {
            job_id: job.id.as_uuid().to_string(),
            status: job.normative_status().as_v1_str().to_string(),
        }))
    }

    async fn issue_view_grant(
        &self,
        request: Request<GrantRequest>,
    ) -> Result<Response<GrantResult>, Status> {
        // OwnershipProof is API-layer only — this message carries none.
        // op signing key is not loaded until Entrust (Block 8); missing
        // bundle fails closed inside the domain before challenge consume.
        let command = parse_grant_request(request.into_inner()).map_err(map_domain_err)?;
        let hosts = crate::v1::public_hosts_from_env();
        let allowed: Vec<[u8; 32]> = hosts
            .iter()
            .map(|h| crate::v1::attest::chan_bind_for_host(h))
            .collect();
        let now = crate::v1::unix_now();
        let issued = self
            .domain
            .issue_view_grant(&allowed, now, None, command)
            .map_err(map_domain_err)?;
        Ok(Response::new(GrantResult {
            grant: issued.grant_bech32m,
        }))
    }
}

/// Build a domain façade from store + notify map + pending-sign map +
/// shared challenge store (production / tests). Sign and stream share
/// the dispatcher's maps; challenges are shared with HTTP AppState.
pub(crate) fn domain_from_parts(
    job_store: Arc<JobStore>,
    notify_map: crate::job_dispatcher::JobNotifyMap,
    pending_sign_map: PendingSignMap,
    challenges: Arc<crate::kernel::bootstrap::ChallengeStore>,
) -> DomainKernel {
    DomainKernel::from_parts(job_store, notify_map, pending_sign_map, challenges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job_store::{CreateResult, JobKind as StoreKind, JobStore};
    use crate::test_db::{setup_pool, SchemaScope};
    use futures_util::StreamExt;
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

    async fn test_domain() -> (DomainKernel, SchemaScope) {
        let scope = setup_pool().await;
        let store = Arc::new(JobStore::new(scope.pool.clone()));
        (
            DomainKernel::from_parts(
                store,
                Arc::new(dashmap::DashMap::new()),
                Arc::new(dashmap::DashMap::new()),
                crate::kernel::bootstrap::ChallengeStore::shared(),
            ),
            scope,
        )
    }

    fn grpc_svc(domain: DomainKernel) -> GrpcKernelService {
        let (job_tx, _rx) = mpsc::channel::<JobEnvelope>(8);
        GrpcKernelService::new(domain, job_tx)
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
    async fn serve_kernel_grpc_with_domain_binds_configured_address() {
        // Ephemeral port: probe → drop → rebind (same shape as runtime_tests).
        // Uses the domain-façade path only — there is no pool-only serve
        // that invents an empty notify map.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe");
        let addr = probe.local_addr().expect("probe addr");
        drop(probe);

        let (domain, _scope) = test_domain().await;
        let (job_tx, _rx) = mpsc::channel::<JobEnvelope>(8);
        let handle =
            tokio::spawn(async move { serve_kernel_grpc_with_domain(addr, domain, job_tx).await });

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

    /// Procedures that are not yet faithfully mapped must name themselves
    /// in an `Unimplemented` status. No invented `Ok` payloads.
    #[tokio::test]
    async fn unmapped_procedures_are_unimplemented_with_their_name() {
        let (domain, _scope) = test_domain().await;
        let svc = grpc_svc(domain);

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
        // SubmitTransition is wired: empty body fails closed as
        // malformed_request (InvalidArgument), not unimplemented.
        {
            let err = svc
                .submit_transition(Request::new(TransitionRequest::default()))
                .await
                .expect_err("empty TransitionRequest must fail closed");
            assert_ne!(
                err.code(),
                Code::Unimplemented,
                "SubmitTransition is wired; empty body is malformed, not unimplemented"
            );
            assert_eq!(err.code(), Code::InvalidArgument);
        }
        // SignTransition is wired **and active** under V1: empty request
        // fails at the width/UUID boundary as malformed_request, not as
        // the feature gate (Unimplemented) and not as "not yet implemented".
        // Process claim is monotonic; nextest isolates per test.
        {
            crate::v1::set_process_stack_mode(crate::v1::ScanStackMode::V1);
            let err = svc
                .sign_transition(Request::new(SignRequest::default()))
                .await
                .expect_err("empty SignRequest must fail closed");
            assert_ne!(
                err.code(),
                Code::Unimplemented,
                "SignTransition is wired and active; empty body is malformed, not unimplemented"
            );
            assert_eq!(err.code(), Code::InvalidArgument);
        }
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
        // AttestBalance / IssueViewGrant are wired (Block 5): empty body
        // fails closed as malformed_request (InvalidArgument), not
        // unimplemented. OwnershipProof fields are absent from the proto.
        {
            let err = svc
                .attest_balance(Request::new(AttestRequest::default()))
                .await
                .expect_err("empty AttestRequest must fail closed");
            assert_ne!(
                err.code(),
                Code::Unimplemented,
                "AttestBalance is wired; empty body is malformed, not unimplemented"
            );
            assert_eq!(err.code(), Code::InvalidArgument);
        }
        {
            let err = svc
                .issue_view_grant(Request::new(GrantRequest::default()))
                .await
                .expect_err("empty GrantRequest must fail closed");
            assert_ne!(
                err.code(),
                Code::Unimplemented,
                "IssueViewGrant is wired; empty body is malformed, not unimplemented"
            );
            assert_eq!(err.code(), Code::InvalidArgument);
        }
    }

    /// Names that must not appear as field/type tokens on the kernel gRPC
    /// surface (API verifies OwnershipProof; kernel receives proven identity).
    const FORBIDDEN_OWNERSHIP_PROOF_TOKENS: &[&str] = &[
        "ownership_proof",
        "OwnershipProof",
        "grant_proof",
        "GrantProof",
    ];

    /// Strip proto3 `// …` line comments. This is the only comment form present
    /// in `proto/kernel/v1/kernel.proto` (no `/* … */` block comments).
    ///
    /// Line structure is preserved so 1-based line numbers still match the
    /// original source after stripping trailing comment text per line.
    fn strip_proto3_line_comments(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        for line in src.lines() {
            match line.find("//") {
                Some(idx) => out.push_str(&line[..idx]),
                None => out.push_str(line),
            }
            out.push('\n');
        }
        out
    }

    /// First forbidden token in `proto` after stripping `//` comments, with
    /// 1-based line number and the comment-free line text.
    fn find_ownership_proof_field_in_proto(proto: &str) -> Option<(&'static str, usize, String)> {
        let stripped = strip_proto3_line_comments(proto);
        for (i, line) in stripped.lines().enumerate() {
            for &token in FORBIDDEN_OWNERSHIP_PROOF_TOKENS {
                if line.contains(token) {
                    return Some((token, i + 1, line.to_string()));
                }
            }
        }
        None
    }

    /// Check that `proto` declares neither OwnershipProof nor GrantProof fields.
    ///
    /// Comments are ignored: only the comment-free text is scanned. On failure
    /// the error states the violated rule and the hit location.
    fn check_kernel_proto_has_no_ownership_proof_fields(proto: &str) -> Result<(), String> {
        match find_ownership_proof_field_in_proto(proto) {
            None => Ok(()),
            Some((token, line, text)) => {
                let trimmed = text.trim();
                let rule = if token == "ownership_proof" || token == "OwnershipProof" {
                    "kernel.proto must not carry OwnershipProof fields on AttestRequest/GrantRequest"
                } else if token == "grant_proof" || token == "GrantProof" {
                    "kernel.proto must not carry GrantProof fields on AttestRequest/GrantRequest"
                } else {
                    panic!(
                        "FORBIDDEN_OWNERSHIP_PROOF_TOKENS and rule mapping out of sync: {token}"
                    );
                };
                Err(format!(
                    "{rule} (found `{token}` at line {line}: {trimmed})"
                ))
            }
        }
    }

    /// gRPC `AttestRequest` / `GrantRequest` carry no OwnershipProof fields
    /// (API-layer gate). This pins the proto surface so a regression that
    /// re-introduces ownership_proof / grant_proof on the kernel messages
    /// is visible as a compile or field-presence failure.
    #[test]
    fn grpc_attest_and_grant_requests_have_no_ownership_proof_fields() {
        // Field inventory from the generated prost types / Default shape.
        // If someone adds an ownership_proof field, these bindings fail to
        // compile or the default struct gains a non-empty field name below.
        let attest = AttestRequest {
            subject: String::new(),
            asset_id: vec![],
            nav_ceiling: vec![],
            size_ceiling: 0,
            nonce: vec![],
            chan_bind: vec![],
        };
        let grant = GrantRequest {
            subject: String::new(),
            grantee_pk: vec![],
            scope: None,
            expiry: 0,
            nonce: vec![],
            chan_bind: vec![],
        };
        // Reflective check against the normative proto source text: the
        // checked-in kernel.proto must not declare ownership_proof / grant_proof
        // (comment documentation of the rule is not a violation).
        let proto = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../proto/kernel/v1/kernel.proto"
        ));
        if let Err(msg) = check_kernel_proto_has_no_ownership_proof_fields(proto) {
            panic!("{msg}");
        }
        // Touch the structs so field renames/additions force this test to update.
        assert!(attest.nonce.is_empty());
        assert!(grant.nonce.is_empty());
        assert!(attest.chan_bind.is_empty());
        assert!(grant.chan_bind.is_empty());
    }

    /// The checker must fail closed on a real field declaration — not only
    /// stay green on the checked-in proto.
    #[test]
    fn ownership_proof_field_declaration_is_detected() {
        let dirty = r#"
message AttestRequest {
  string subject = 1;
  bytes ownership_proof = 9;
}
"#;
        let err = match check_kernel_proto_has_no_ownership_proof_fields(dirty) {
            Ok(()) => panic!("declared ownership_proof field must be reported as a violation"),
            Err(msg) => msg,
        };
        assert!(
            err.contains("ownership_proof"),
            "error must name the forbidden token: {err}"
        );
        assert!(
            err.contains(
                "kernel.proto must not carry OwnershipProof fields on AttestRequest/GrantRequest"
            ),
            "error must keep the OwnershipProof rule wording: {err}"
        );
        assert!(
            err.contains("line "),
            "error must include a line location: {err}"
        );
    }

    /// Names that appear only in `//` comments document the rule; they are
    /// not field declarations and must not trip the checker.
    #[test]
    fn ownership_proof_name_only_in_comment_is_clean() {
        let comment_only = r#"
// API layer has already verified the action-bound OwnershipProof (§5.1 / §7.5);
// kernel trusts the caller. No ownership_proof / grant_proof / GrantProof fields.
message AttestRequest {
  string subject = 1;                       // OwnershipProof stays at the API edge
  bytes nonce = 5;
}
message GrantRequest {
  string subject = 1;                       // GrantProof is also API-only
}
"#;
        if let Err(msg) = check_kernel_proto_has_no_ownership_proof_fields(comment_only) {
            panic!("names only in // comments must be treated as clean: {msg}");
        }
    }

    /// Flag/claim off: SignTransition is refused at the gRPC edge with
    /// `Unimplemented` naming `ZKCOINS_V1_SHADOW` — never a domain call
    /// (no job mutation). Distinct from unwired procedures' "not yet
    /// implemented" wording.
    #[tokio::test]
    async fn sign_transition_flag_off_is_unimplemented_naming_flag_without_domain() {
        // Default process claim is unset → `v1_sign_route_active()` is false
        // (nextest process isolation; do not claim V1 in this test).
        let scope = setup_pool().await;
        let store = Arc::new(JobStore::new(scope.pool.clone()));
        let created = store
            .create(
                StoreKind::Send,
                &[0x51u8; 32],
                Some("grpc-sign-flag-off"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            CreateResult::Fresh(j) => j.public_id,
            _ => panic!("fresh"),
        };
        store
            .set_awaiting_signature(
                id,
                1,
                serde_json::json!({
                    "account_state_hash": "aa".repeat(32),
                    "output_coins_root": "bb".repeat(32),
                }),
            )
            .await
            .expect("awaiting_signature");
        let before = store.load(id).await.expect("load").expect("row");
        assert_eq!(
            before.status,
            crate::job_store::JobStatus::AwaitingSignature
        );

        let domain = DomainKernel::from_parts(
            Arc::clone(&store),
            Arc::new(dashmap::DashMap::new()),
            Arc::new(dashmap::DashMap::new()),
            crate::kernel::bootstrap::ChallengeStore::shared(),
        );
        let svc = grpc_svc(domain);

        // Well-formed widths so a missing gate would reach the domain and
        // mutate or fail on staging — not the width check.
        let err = svc
            .sign_transition(Request::new(SignRequest {
                job_id: id.to_string(),
                signature: vec![0u8; 64],
                s2c_nonce: vec![0u8; 32],
            }))
            .await
            .expect_err("flag-off SignTransition must refuse");

        assert_eq!(
            err.code(),
            Code::Unimplemented,
            "disabled surface uses Unimplemented (not a domain KernelError); got {:?}",
            err.code()
        );
        let msg = err.message();
        assert!(
            msg.contains("ZKCOINS_V1_SHADOW"),
            "message must name the feature flag, got {msg:?}"
        );
        assert!(
            msg.contains("disabled") || msg.contains("inactive"),
            "message must state the surface is off, got {msg:?}"
        );
        assert!(
            !msg.contains("not yet implemented"),
            "must distinguish disabled from unwired procedures, got {msg:?}"
        );

        // Domain not entered: row still awaiting_signature, body untouched.
        let after = store.load(id).await.expect("load").expect("row");
        assert_eq!(
            after.status,
            crate::job_store::JobStatus::AwaitingSignature,
            "flag-off gate must not touch the job"
        );
        assert_eq!(
            after.phase, before.phase,
            "flag-off gate must not rewrite phase"
        );
        assert_eq!(
            after.request_body, before.request_body,
            "flag-off gate must not rewrite request_body (no durable sign install)"
        );
        assert_eq!(after.error, before.error);
    }

    #[tokio::test]
    async fn get_job_returns_complete_proving_snapshot() {
        let scope = setup_pool().await;
        let store = Arc::new(JobStore::new(scope.pool.clone()));
        let created = store
            .create(
                StoreKind::Mint,
                &[0xA1u8; 32],
                Some("grpc-get-job"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            CreateResult::Fresh(j) => j.public_id,
            _ => panic!("fresh"),
        };
        store
            .set_status(
                id,
                crate::job_store::JobStatus::Queued,
                crate::job_store::JobStatus::Proving,
                "proving_circuit",
            )
            .await
            .expect("proving");
        let domain = DomainKernel::from_parts(
            Arc::clone(&store),
            Arc::new(dashmap::DashMap::new()),
            Arc::new(dashmap::DashMap::new()),
            crate::kernel::bootstrap::ChallengeStore::shared(),
        );
        let svc = grpc_svc(domain);
        let resp = svc
            .get_job(Request::new(JobRequest {
                job_id: id.to_string(),
            }))
            .await
            .expect("GetJob Ok");
        let job = resp.into_inner();
        assert_eq!(job.job_id, id.to_string());
        assert_eq!(job.kind, "mint");
        assert_eq!(job.status, "proving");
        assert_eq!(job.phase, "proving_circuit");
        assert!(job.result.is_none());
        assert!(job.awaiting_signature.is_none());
        assert!(job.error.is_none());
        assert!((job.progress - 0.0).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn get_job_unknown_is_not_found_with_error_info_reason() {
        let (domain, _scope) = test_domain().await;
        let svc = grpc_svc(domain);
        let missing = Uuid::new_v4();
        let status = match svc
            .get_job(Request::new(JobRequest {
                job_id: missing.to_string(),
            }))
            .await
        {
            Ok(_) => panic!("unknown job must not return Ok"),
            Err(s) => s,
        };
        assert_eq!(status.code(), Code::NotFound);
        assert_eq!(status.message(), "Job not found");
        assert_eq!(
            status
                .metadata()
                .get("error-reason")
                .expect("error-reason")
                .to_str()
                .expect("str"),
            "job_not_found"
        );
        assert_eq!(
            status
                .metadata()
                .get("error-domain")
                .expect("error-domain")
                .to_str()
                .expect("str"),
            crate::transport::error_contract::ERROR_INFO_DOMAIN
        );
        assert_eq!(
            status
                .metadata()
                .get("error-http-status")
                .expect("http")
                .to_str()
                .expect("str"),
            "404"
        );
    }

    #[tokio::test]
    async fn stream_job_emits_complete_snapshot_for_terminal_cancelled() {
        let scope = setup_pool().await;
        let store = Arc::new(JobStore::new(scope.pool.clone()));
        let created = store
            .create(
                StoreKind::Send,
                &[0xA2u8; 32],
                Some("grpc-stream-job"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            CreateResult::Fresh(j) => j.public_id,
            _ => panic!("fresh"),
        };
        assert!(store.cancel(id).await.expect("cancel"));

        let domain = DomainKernel::from_parts(
            Arc::clone(&store),
            Arc::new(dashmap::DashMap::new()),
            Arc::new(dashmap::DashMap::new()),
            crate::kernel::bootstrap::ChallengeStore::shared(),
        );
        let svc = grpc_svc(domain);
        let resp = svc
            .stream_job(Request::new(JobRequest {
                job_id: id.to_string(),
            }))
            .await
            .expect("StreamJob open");
        let mut stream = resp.into_inner();
        let first = stream.next().await.expect("one frame").expect("Ok frame");
        assert_eq!(first.event, "error"); // cancelled → Error kind
        let job = first.job.expect("job on event");
        assert_eq!(job.job_id, id.to_string());
        assert_eq!(job.status, "cancelled");
        assert_eq!(job.kind, "send");
        let err = job.error.expect("cancelled carries JobError");
        assert_eq!(err.error, "internal_error");
        assert!(job.result.is_none());
        assert!(job.awaiting_signature.is_none());
        // Terminal stream ends after the snapshot.
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn cancel_job_returns_complete_cancelled_job() {
        let scope = setup_pool().await;
        let store = Arc::new(JobStore::new(scope.pool.clone()));
        let created = store
            .create(
                StoreKind::Mint,
                &[0xA3u8; 32],
                Some("grpc-cancel-job"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            CreateResult::Fresh(j) => j.public_id,
            _ => panic!("fresh"),
        };
        store
            .set_status(
                id,
                crate::job_store::JobStatus::Queued,
                crate::job_store::JobStatus::Proving,
                "proving",
            )
            .await
            .expect("proving");

        let domain = DomainKernel::from_parts(
            Arc::clone(&store),
            Arc::new(dashmap::DashMap::new()),
            Arc::new(dashmap::DashMap::new()),
            crate::kernel::bootstrap::ChallengeStore::shared(),
        );
        let svc = grpc_svc(domain);
        let resp = svc
            .cancel_job(Request::new(JobRequest {
                job_id: id.to_string(),
            }))
            .await
            .expect("CancelJob Ok under NotYetPublished");
        let job = resp.into_inner();
        assert_eq!(job.job_id, id.to_string());
        assert_eq!(job.status, "cancelled");
        assert_eq!(job.kind, "mint");
        let err = job.error.expect("JobError on cancelled");
        assert_eq!(err.error, "internal_error");
        assert!(job.phase.is_empty(), "terminal phase empty");
        assert!(job.result.is_none());
        assert!(job.awaiting_signature.is_none());
    }

    #[tokio::test]
    async fn empty_job_id_is_malformed_request() {
        let (domain, _scope) = test_domain().await;
        let svc = grpc_svc(domain);
        let status = match svc
            .get_job(Request::new(JobRequest {
                job_id: String::new(),
            }))
            .await
        {
            Ok(_) => panic!("empty job_id must not Ok"),
            Err(s) => s,
        };
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "job_id is required");
        assert_eq!(
            status
                .metadata()
                .get("error-reason")
                .expect("reason")
                .to_str()
                .expect("str"),
            "malformed_request"
        );
        assert_eq!(
            status
                .metadata()
                .get("error-http-status")
                .expect("http")
                .to_str()
                .expect("str"),
            "400"
        );
        assert_eq!(
            status
                .metadata()
                .get("error-domain")
                .expect("domain")
                .to_str()
                .expect("str"),
            crate::transport::error_contract::ERROR_INFO_DOMAIN
        );
    }

    #[tokio::test]
    async fn non_uuid_job_id_is_malformed_request() {
        let (domain, _scope) = test_domain().await;
        let svc = grpc_svc(domain);
        let status = match svc
            .get_job(Request::new(JobRequest {
                job_id: "not-a-uuid".to_string(),
            }))
            .await
        {
            Ok(_) => panic!("non-UUID job_id must not Ok"),
            Err(s) => s,
        };
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "job_id must be a UUID");
        assert_eq!(
            status
                .metadata()
                .get("error-reason")
                .expect("reason")
                .to_str()
                .expect("str"),
            "malformed_request"
        );
        assert_eq!(
            status
                .metadata()
                .get("error-http-status")
                .expect("http")
                .to_str()
                .expect("str"),
            "400"
        );
        assert_eq!(
            status
                .metadata()
                .get("error-domain")
                .expect("domain")
                .to_str()
                .expect("str"),
            crate::transport::error_contract::ERROR_INFO_DOMAIN
        );
    }
}
