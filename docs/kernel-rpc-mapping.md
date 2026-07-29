# Kernel-RPC-Abbildung: §7.5 REST → §7.8 `kernel.v1`

Normative Quellen:

- REST: `docs/specification.md` §7.5 / §7.6 / §7.7 (tag `spec-v1.2`)
- Kernel: `docs/specification.md` §7.8 + `proto/kernel/v1/kernel.proto`
- Code-Stand: Worktree `node` (Branch `feat/v1-spec-rebuild`, Block 2)

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
| `GET /health/ready` | `GetInfo` (Teilfeld `ready` / `ready_reason`) | unary | **nein** — fehlt Domain-`GetInfo` + closed `reason`-Mapping; REST-JSON ist eigenes Shape | teilweise: `ready_handler` |
| `GET /v1/info` | `GetInfo` | unary | **nein** — fehlt Domain-Projektion (`circuit_digests`, `features`, `bootstrap`) und §7.5-Route | Legacy: `info_handler` (`/api/info`) |
| `GET /v1/chain/accumulator` | `GetAccumulator` | unary | **nein** — fehlt öffentlicher Tip-Endpoint + Domain-Read über `StateEngine`/`nflog` | intern: `state_engine` tip/nflog, `shared` accumulator |
| `GET /v1/chain/inscriptions` | `ListInscriptions` | server-stream | **nein** — fehlt paginierte Triple-Cursor-Liste + Domain-Stream | Legacy 410: `get_inscription_handler` |
| `GET /v1/chain/nullifier/<pubkey>` | `GetNullifierPath` | unary | **nein** — fehlt Domain-Path-B-Fassade über Acc/NfLog | intern: `accumulator::lookup`, `nflog::inclusion_path` |
| `POST /v1/tx` | `SubmitTransition` | unary | **nein** — fehlt unified Admit-Domain + gRPC-Request-Mapping (mint/send/receive) | Legacy-Admit: `jobs_mint_handler` / `jobs_send_handler`; Engine: `begin_v1_mint` / `begin_v1_send` / `execute_v1_receive` |
| `GET /v1/jobs/<id>` | `GetJob` | unary | **ja** — `kernel_rpc::get_job` → `DomainKernel::get_job` → `job_to_proto` | ja: `get_job_v1_handler`; Store `JobStore::load` |
| `GET /v1/jobs/<id>/stream` | `StreamJob` | server-stream | **ja** — `kernel_rpc::stream_job` → `DomainKernel::stream_job` / `JobEventHub` → `job_event_to_proto` (live nur mit shared Notify-Map) | ja: `stream_job_v1_handler` |
| `POST /v1/jobs/<id>/sign` | `SignTransition` | unary | **nein** — fehlt Domain-Sign-Fassade + Proto-`SignRequest`-Mapping (REST/Wallet-Sign existiert) | ja: `jobs_sign_handler`; `accept_wallet_transition_signature` |
| `POST /v1/jobs/<id>/cancel` | `CancelJob` | unary | **ja** — `kernel_rpc::cancel_job` → `DomainKernel::cancel_job` (`CancelPolicy::NotYetPublished`) → `job_to_proto` | ja: `jobs_cancel_v1_handler` |
| `POST /v1/pull/challenge` | `OpenPullChallenge` | unary | **nein** — fehlt Challenge-Domain + generisches OpenPull | **nicht vorhanden** |
| `POST /v1/pull` | `Pull` | unary | **nein** — fehlt Pull-Domain | **nicht vorhanden** |
| `GET /v1/record/<record_id>` | `GetRecord` | unary | **nein** — fehlt Record-Lookup-Domain | **nicht vorhanden** |
| `GET /v1/proof/<coin_id>` | `GetCoinProof` | unary | **nein** — fehlt session-gated proof Domain (§7.5) | Legacy 410: `get_proof_handler` |
| `GET /v1/account/state` | `GetAccountState` | unary | **nein** — fehlt ownership-gated Domain über Engine-Accounts | Engine: `state_engine::account` |
| `GET /v1/receipts/stream` | `SubscribeReceipts` | server-stream | **nein** — fehlt Receipt-Hub/Domain-Stream | **nicht vorhanden** |
| `POST /v1/publish/spendrecord` (§7.6) | `Publish` | unary | **nein** — fehlt permissionless SpendRecord-Hand-off Domain | intern: `publish_v1_batch` (crate-private self-publish) |
| `POST /v1/bootstrap/challenge` (§7.7) | `OpenPullChallenge` (`action` = entrust/revoke) | unary | **nein** — siehe `OpenPullChallenge` | **nicht vorhanden** |
| `POST /v1/bootstrap/entrust` (§7.7) | `EntrustOperationalBundle` | unary | **nein** — fehlt Bundle-Persistenz-Domain unter §7.7 | intern Tests/Account-Rows, kein Endpoint |
| `POST /v1/bootstrap/revoke` (§7.7) | `RevokeOperationalBundle` | unary | **nein** — fehlt Revoke-Domain | **nicht vorhanden** |
| `POST /v1/attest/balance/challenge` | `OpenPullChallenge` (`action` = `attest_balance`) | unary | **nein** — generisches OpenPull fehlt; attest-Challenge nur REST | ja: `attest_balance_challenge_handler` |
| `POST /v1/attest/balance` | `AttestBalance` | unary | **nein** — fehlt Domain-Attest-Fassade + Proto-Mapping (REST/Engine vorhanden) | ja: `attest_balance_handler`; `issue_attest_challenge` / `prove_attestation_for_job` |
| `POST /v1/grants/challenge` | `OpenPullChallenge` (`action` = `issue_grant`) | unary | **nein** — siehe `OpenPullChallenge` | **nicht vorhanden** |
| `POST /v1/grants` | `IssueViewGrant` | unary | **nein** — fehlt Grant-Domain | **nicht vorhanden** |

## Blossom (§7.4) — kein Kernel-RPC in §7.8

Die REST-Keys `blossom_get` / `blossom_head` / `blossom_upload` / `blossom_delete` (§7.5 closed endpoint map) laufen über die Blossom-Ebene, nicht über `service Kernel`. Im node: **nicht vorhanden**.

## Zählung: Kernel-Prozeduren

20 Prozeduren in `service Kernel`.

| Kriterium | Prozeduren | Zahl |
|---|---|---|
| **gRPC verdrahtet** (Domain + Proto, kein `unimplemented`) | `GetJob`, `StreamJob`, `CancelJob` | **3** |
| REST/Engine vorhanden, gRPC noch `unimplemented` | `SignTransition`, `AttestBalance` (+ teilweise `GetInfo` / `OpenPullChallenge` nur attest) | **2+** |
| Weder gRPC noch passende §7.5-Surface | Rest der 20 | **15** (inkl. nur-interne Bausteine) |

**Kurzfassung:** **3 von 20** Kernel-Prozeduren sind gRPC-verdrahtet (`GetJob`, `StreamJob`, `CancelJob`). Die übrigen 17 antworten ehrlich mit `Status::unimplemented("<Name>: not yet implemented")`. Server-Boot nur über `start_rest_node` + shared Hub — kein stummer pool-only-Stream-Pfad.

## API-lokale Endpunkte (explizit ohne Kernel)

| REST | Grund |
|---|---|
| `GET /` | §7.5: Listing, API-lokal |
| `GET /health` | §7.5: Liveness, API-lokal |

`GET /health/ready` ist **nicht** rein API-lokal: §7.8 mappt Readiness über `GetInfo.ready` / `ready_reason`.
