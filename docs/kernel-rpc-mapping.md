# Kernel-RPC-Abbildung: §7.5 REST → §7.8 `kernel.v1`

Normative Quellen:

- REST: `docs/specification.md` §7.5 / §7.6 / §7.7 (tag `spec-v1.2`)
- Kernel: `docs/specification.md` §7.8 + `proto/kernel/v1/kernel.proto`
- Code-Stand: Worktree `node` (Branch `feat/v1-spec-rebuild`)

Spalte **gRPC verdrahtet?** meint die `tonic`-Implementierung in
`node/src/kernel_rpc.rs` über die transportneutrale Domain-Fassade
(`node/src/kernel/`). „Ja“ = Domain-Aufruf + Proto-Mapping, kein
`Status::unimplemented`. „Nein“ nennt die **konkret fehlende**
Voraussetzung für eine ehrliche Verdrahtung.

Boot: gRPC startet **nur** aus `start_rest_node` via
`serve_kernel_grpc_with_domain` mit **geteiltem** Job-Store + Notify-Map
(Dispatcher). Es gibt keinen pool-only-Public-Boot mit leerer Map.

## Abbildungstabelle

| §7.5 / §7.6 / §7.7 REST | Kernel-Prozedur (§7.8) | Kind | gRPC verdrahtet? | REST / Engine im node |
|---|---|---|---|---|
| `GET /` | — (API-lokal; §7.5) | — | — | ja: `router.rs` `root_handler` — Form weicht ab (legacy endpoint map) |
| `GET /health` | — (API-lokal; §7.5) | — | — | ja: `router.rs` `health_handler` |
| `GET /health/ready` | `GetInfo` (Teilfeld `ready` / `ready_reason`) | unary | **teilweise** — Domain-`GetInfo` + closed `reason`-Mapping existieren; Produktion setzt `ChainIdentity = None` → fail-closed `Internal` (kein erfundener Infra-Pin). REST-JSON ist eigenes Shape | teilweise: `ready_handler` |
| `GET /v1/info` | `GetInfo` | unary | **teilweise** — Domain-Projektion vorhanden; Produktion ohne `ChainIdentity` → fail-closed. §7.5-Route noch Legacy `/api/info` | Legacy: `info_handler` (`/api/info`) |
| `GET /v1/chain/accumulator` | `GetAccumulator` | unary | **ja** — `kernel_rpc::get_accumulator` → live NfLog tip via `ChainView` | intern: `state_engine` tip/nflog, `shared` accumulator |
| `GET /v1/chain/inscriptions` | `ListInscriptions` | server-stream | **nein** — fehlt ein beim Falten geschriebener **Inschriften-Katalog** mit Reveal-Txid und §3.5-Format; NfLog speichert beides nicht. Proto-`txid`/`format` sind nicht-optional → Abwesenheit nicht darstellbar. gRPC: `Unimplemented` mit dieser Voraussetzung in der Meldung | Legacy 410: `get_inscription_handler` |
| `GET /v1/chain/nullifier/<pubkey>` | `GetNullifierPath` | unary | **ja** — Path-B present/absent gegen live Index; Fehler nie als `present: false` | intern: `accumulator::lookup`, `nflog::inclusion_path` |
| `POST /v1/tx` | `SubmitTransition` | unary | **ja** — Domain-Admit + gRPC-Request-Mapping (mint/send/receive) | Legacy-Admit: `jobs_mint_handler` / `jobs_send_handler`; Engine: `begin_v1_mint` / `begin_v1_send` / `execute_v1_receive` |
| `GET /v1/jobs/<id>` | `GetJob` | unary | **ja** — `kernel_rpc::get_job` → `DomainKernel::get_job` → `job_to_proto` | ja: `get_job_v1_handler`; Store `JobStore::load` |
| `GET /v1/jobs/<id>/stream` | `StreamJob` | server-stream | **ja** — `kernel_rpc::stream_job` → `DomainKernel::stream_job` / `JobEventHub` → `job_event_to_proto` (live nur mit shared Notify-Map) | ja: `stream_job_v1_handler` |
| `POST /v1/jobs/<id>/sign` | `SignTransition` | unary | **ja** — `kernel_rpc::sign_transition` → `DomainKernel::sign_transition` → `job_to_proto` (Width 64/32 am gRPC-Rand). **Feature-Gate am gRPC-Rand** (vor Domäne): bei inaktivem V1-Claim (`!v1_sign_route_active()`) `Status::unimplemented` mit Meldung, die `ZKCOINS_V1_SHADOW` / `ScanStackMode::V1` nennt und **nicht** den Text `not yet implemented` der unverdrahteten Prozeduren — analog HTTP `feature_disabled` (kein `KernelErrorCode`) | ja: `jobs_sign_handler` → Flag-Gate `feature_disabled` / 404 → `kernel/jobs/sign`; `accept_wallet_transition_signature` |
| `POST /v1/jobs/<id>/cancel` | `CancelJob` | unary | **ja** — `kernel_rpc::cancel_job` → `DomainKernel::cancel_job` (`CancelPolicy::NotYetPublished`) → `job_to_proto` | ja: `jobs_cancel_v1_handler` |
| `POST /v1/pull/challenge` | `OpenPullChallenge` | unary | **ja** — Domain `open_pull_challenge` / `ChallengeStore::issue_pull` (Pull) bzw. `issue` (AttestBalance / IssueViewGrant / Entrust / Revoke). Action-Set: `""`/`pull`, `attest_balance`, `issue_grant`, `entrust`, `revoke` | **nicht vorhanden** (gRPC only heute) |
| `POST /v1/pull` | `Pull` | unary | **ja** — Domain-Pull (Challenge-Consume + Session-Issue); Authority via Metadata `x-zkcoins-session-authority` (Proto-GAP) | **nicht vorhanden** |
| `GET /v1/record/<record_id>` | `GetRecord` | unary | **ja** — session-gated Domain; Index process-local/leer bis Katalog | **nicht vorhanden** |
| `GET /v1/proof/<coin_id>` | `GetCoinProof` | unary | **ja** — session-gated Domain | Legacy 410: `get_proof_handler` |
| `GET /v1/account/state` | `GetAccountState` | unary | **ja** — ownership-only via `ActiveSession::require_ownership` (enum-Diskriminante) | Engine: `state_engine::account` |
| `GET /v1/receipts/stream` | `SubscribeReceipts` | server-stream | **nein** — fehlt ein **Receive/Decrypt-Index-Writer**, der nach dauerhaftem Persist (§4.8) verifizierte Credits veröffentlicht (§4.9). Ohne Writer darf kein Abonnement angenommen werden (kein leerer Stream). Domain-Fan-out existiert bewusst nicht. gRPC: `Unimplemented` mit dieser Voraussetzung | **nicht vorhanden** |
| `POST /v1/publish/spendrecord` (§7.6) | `Publish` | unary | **ja** — `kernel_rpc::publish` → `DomainKernel::publish` / `kernel::publish::publish` mit `PublishPolicy` (AcceptFeeLess / DeclineFeeLess). Fee-Felder fail-closed am Transport-Rand; abgelehnter Publish ist erfolgreiche RPC mit `accepted: false` + closed `reason`, kein Transport-Fehler | intern: `v1::publish::publish_v1_batch` (crate-private self-publish); kein §7.6-REST-Endpoint |
| `POST /v1/bootstrap/challenge` (§7.7) | `OpenPullChallenge` (`action` = entrust/revoke) | unary | **ja** — `entrust`/`revoke` am `OpenPullChallenge`-Rand: Domain `ChallengeStore::issue` mit `ChallengeAction::Entrust` / `Revoke` (eigene Nonce-Maps) | **nicht vorhanden** |
| `POST /v1/bootstrap/entrust` (§7.7) | `EntrustOperationalBundle` | unary | **ja** — `kernel_rpc::entrust_operational_bundle` → `DomainKernel::entrust_operational_bundle` / `bootstrap::entrust_operational_bundle` (Challenge-Consume + Bundle-Persist, Layout 161 Bytes) | **nicht vorhanden** (gRPC only heute; BundleStore process-local) |
| `POST /v1/bootstrap/revoke` (§7.7) | `RevokeOperationalBundle` | unary | **ja** — `kernel_rpc::revoke_operational_bundle` → `DomainKernel::revoke_operational_bundle` / `bootstrap::revoke_operational_bundle` (einmaliger Nonce-Consume, Active→Revoked) | **nicht vorhanden** |
| `POST /v1/attest/balance/challenge` | `OpenPullChallenge` (`action` = `attest_balance`) | unary | **ja** — siehe `OpenPullChallenge` | ja: `attest_balance_challenge_handler` |
| `POST /v1/attest/balance` | `AttestBalance` | unary | **ja** — Domain-Attest-Fassade + Proto-Mapping | ja: `attest_balance_handler`; `issue_attest_challenge` / `prove_attestation_for_job` |
| `POST /v1/grants/challenge` | `OpenPullChallenge` (`action` = `issue_grant`) | unary | **ja** — siehe `OpenPullChallenge` | **nicht vorhanden** (gRPC only heute) |
| `POST /v1/grants` | `IssueViewGrant` | unary | **ja** — Domain-Grant (ohne `op_sk` fail-closed vor Challenge-Consume) | **nicht vorhanden** (gRPC only heute) |

## Blossom (§7.4) — kein Kernel-RPC in §7.8

Die REST-Keys `blossom_get` / `blossom_head` / `blossom_upload` / `blossom_delete` (§7.5 closed endpoint map) laufen über die Blossom-Ebene, nicht über `service Kernel`. Im node: **nicht vorhanden**.

## Zählung: Kernel-Prozeduren

20 Prozeduren in `service Kernel`.

| Kriterium | Prozeduren | Zahl |
|---|---|---|
| **gRPC verdrahtet** (Domain + Proto, kein `unimplemented` auf dem Happy-Path) | `GetJob`, `StreamJob`, `CancelJob`, `SignTransition`, `SubmitTransition`, `AttestBalance`, `IssueViewGrant`, `GetInfo`, `GetAccumulator`, `GetNullifierPath`, `OpenPullChallenge`, `Pull`, `GetRecord`, `GetCoinProof`, `GetAccountState`, `Publish`, `EntrustOperationalBundle`, `RevokeOperationalBundle` | **18** |
| gRPC `Unimplemented` mit benannter Voraussetzung | `ListInscriptions` (Inschriften-Katalog), `SubscribeReceipts` (Credit-Writer nach Persist) | **2** |

**Kurzfassung:** **18 von 20** Kernel-Prozeduren sind gRPC-verdrahtet. Block 8 verdrahtete `Publish`, `EntrustOperationalBundle` und `RevokeOperationalBundle`. `ListInscriptions` und `SubscribeReceipts` bleiben `Unimplemented` mit benannter Voraussetzung (Inschriften-Katalog bzw. Credit-Writer nach §4.8-Persist). Writer-Vertrag: `kernel::access::receipts`. `OpenPullChallenge` deckt auch `entrust`/`revoke` ab (Challenge-Maps getrennt pro Action). `SignTransition` hat zusätzlich ein **API-Rand-Feature-Gate**: bei inaktivem V1-Claim `Unimplemented` mit `ZKCOINS_V1_SHADOW` in der Meldung (ohne `not yet implemented`) — nicht dasselbe wie unverdrahtet. Server-Boot nur über `start_rest_node` + shared Hub + pending-sign-Map — kein stummer pool-only-Stream-Pfad.

## API-lokale Endpunkte (explizit ohne Kernel)

| REST | Grund |
|---|---|
| `GET /` | §7.5: Listing, API-lokal |
| `GET /health` | §7.5: Liveness, API-lokal |

`GET /health/ready` ist **nicht** rein API-lokal: §7.8 mappt Readiness über `GetInfo.ready` / `ready_reason`.
