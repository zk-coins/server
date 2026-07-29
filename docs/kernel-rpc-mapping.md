# Kernel-RPC-Abbildung: §7.5 REST → §7.8 `kernel.v1`

Normative Quellen:

- REST: `docs/specification.md` §7.5 / §7.6 / §7.7 (tag `spec-v1.2`)
- Kernel: `docs/specification.md` §7.8 + `proto/kernel/v1/kernel.proto`
- Code-Stand: Worktree `node-kernel` (detached `b16ad44`)

Spalte **im node heute vorhanden?** nennt nur belegbare Stellen
(`Datei:Zeile`) oder „nicht vorhanden“. Eine gRPC-Server-Oberfläche
existiert im node **nicht** (kein `.proto` vor diesem PR, kein `tonic`/
`prost`). „Vorhanden“ meint die **interne Logik / REST-Handler**, die
eine spätere Kernel-Prozedur speisen könnte.

## Abbildungstabelle

| §7.5 / §7.6 / §7.7 REST | Kernel-Prozedur (§7.8) | Kind | Im node heute vorhanden? |
|---|---|---|---|
| `GET /` | — (API-lokal, kein Kernel-Aufruf; §7.5) | — | ja: `node/src/router.rs:3527` `root_handler`, Route `router.rs:3966` — **Form weicht ab** (legacy endpoint map, nicht die §7.5 closed keys) |
| `GET /health` | — (API-lokal, Liveness; §7.5) | — | ja: `node/src/router.rs:3327` `health_handler`, Route `router.rs:3967` |
| `GET /health/ready` | `GetInfo` (Teilfeld `ready` / `ready_reason`) | unary | teilweise: `node/src/router.rs:3145` `ready_handler` — eigenes JSON `{ready, failures, status, prover}`, **nicht** das §7.5 `{ready, reason?}` mit closed `reason` |
| `GET /v1/info` | `GetInfo` | unary | **nicht vorhanden** als `/v1/info`. Legacy: `node/src/router.rs:3352` `info_handler` (`/api/info`) — anderes Shape (`capabilities`, kein `circuit_digests` / `features` / `bootstrap`) |
| `GET /v1/chain/accumulator` | `GetAccumulator` | unary | **nicht vorhanden** als Route. Intern: `script-plonky2/src/state_engine.rs:639` `tip_height`, `state_engine.rs:653` `nflog()`, `shared/src/spec_v1/accumulator.rs` — kein öffentlicher Tip-Endpoint |
| `GET /v1/chain/inscriptions` | `ListInscriptions` | server-stream | **nicht vorhanden** (paginierte Triple-Cursor-Liste). Legacy 410: `node/src/router.rs:2991` `get_inscription_handler` (`GET /api/inscriptions/:txid`) |
| `GET /v1/chain/nullifier/<pubkey>` | `GetNullifierPath` | unary | **nicht vorhanden** als Route. Intern Path-B: `shared/src/spec_v1/accumulator.rs:189` `lookup`, `shared/src/spec_v1/nflog.rs:200` `inclusion_path` |
| `POST /v1/tx` | `SubmitTransition` | unary | **nicht vorhanden** als unified `/v1/tx`. Legacy-Admit: `node/src/router.rs:1230` `jobs_mint_handler` (`/api/jobs/mint`), `router.rs:1293` `jobs_send_handler` (`/api/jobs/send`). Engine: `node/src/v1/mint.rs:99` `begin_v1_mint`, `node/src/v1/provenance.rs:161` `begin_v1_send`, `node/src/v1/receive.rs:990` `execute_v1_receive` — **kein** REST-Receive-Admit unter `/v1/tx` |
| `GET /v1/jobs/<id>` | `GetJob` | unary | ja: `node/src/router.rs:2246` `get_job_v1_handler`, Route `router.rs:3994`; Store `node/src/job_store.rs:500` `load` |
| `GET /v1/jobs/<id>/stream` | `StreamJob` | server-stream | ja: `node/src/router.rs:2517` `stream_job_v1_handler`, Route `router.rs:3996` |
| `POST /v1/jobs/<id>/sign` | `SignTransition` | unary | ja: `node/src/router.rs:1794` `jobs_sign_handler`, Route `router.rs:3995`; Verify `node/src/v1/signature.rs:1482` `accept_wallet_transition_signature` |
| `POST /v1/jobs/<id>/cancel` | `CancelJob` | unary | ja: `node/src/router.rs:2419` `jobs_cancel_v1_handler`, Route `router.rs:3997` |
| `POST /v1/pull/challenge` | `OpenPullChallenge` | unary | **nicht vorhanden** |
| `POST /v1/pull` | `Pull` | unary | **nicht vorhanden** |
| `GET /v1/record/<record_id>` | `GetRecord` | unary | **nicht vorhanden** |
| `GET /v1/proof/<coin_id>` | `GetCoinProof` | unary | **nicht vorhanden** als §7.5 session-gated proof. Legacy 410: `node/src/router.rs:1111` `get_proof_handler` (`/api/proof/:id`, Status 410 in `router.rs:1123`) |
| `GET /v1/account/state` | `GetAccountState` | unary | **nicht vorhanden**. Engine hat Accounts: `script-plonky2/src/state_engine.rs:649` `account` — kein ownership-gated REST/RPC |
| `GET /v1/receipts/stream` | `SubscribeReceipts` | server-stream | **nicht vorhanden** |
| `POST /v1/publish/spendrecord` (§7.6) | `Publish` | unary | **nicht vorhanden** als hand-off REST. Intern: `node/src/v1/publish.rs:199` `publish_v1_batch` (crate-private, self-publish/resume — kein permissionless SpendRecord-Hand-off) |
| `POST /v1/bootstrap/challenge` (§7.7) | `OpenPullChallenge` (`action` = `entrust`/`revoke`) | unary | **nicht vorhanden** |
| `POST /v1/bootstrap/entrust` (§7.7) | `EntrustOperationalBundle` | unary | **nicht vorhanden** (Bundle-Persistenz intern in Account-Rows / Tests, z. B. `node/src/v1/tests.rs` — kein §7.7 Endpoint) |
| `POST /v1/bootstrap/revoke` (§7.7) | `RevokeOperationalBundle` | unary | **nicht vorhanden** |
| `POST /v1/attest/balance/challenge` | `OpenPullChallenge` (`action` = `attest_balance`) | unary | ja (attest-spezifisch, nicht generisches OpenPull): `node/src/router.rs:2109` `attest_balance_challenge_handler`, Route `router.rs:3999–4001`; `node/src/v1/attest.rs:446` `issue_attest_challenge` |
| `POST /v1/attest/balance` | `AttestBalance` | unary | ja: `node/src/router.rs:2139` `attest_balance_handler`, Route `router.rs:4003`; Auth `node/src/v1/attest.rs:479` `authorise_attest_balance`; Prove `node/src/v1/attest.rs:1047` `prove_attestation_for_job` |
| `POST /v1/grants/challenge` | `OpenPullChallenge` (`action` = `issue_grant`) | unary | **nicht vorhanden** |
| `POST /v1/grants` | `IssueViewGrant` | unary | **nicht vorhanden** |

## Blossom (§7.4) — kein Kernel-RPC in §7.8

Die REST-Keys `blossom_get` / `blossom_head` / `blossom_upload` / `blossom_delete` (§7.5 closed endpoint map) laufen über die Blossom-Ebene, nicht über `service Kernel`. Im node: **nicht vorhanden**.

## Zählung: Kernel-Prozeduren mit node-Entsprechung

20 Prozeduren in `service Kernel`.

| Kriterium | Prozeduren | Zahl |
|---|---|---|
| Handler/Route unter §7.5-Pfad (oder eng verwandt) **funktional vorhanden** | `GetJob`, `StreamJob`, `SignTransition`, `CancelJob`, `AttestBalance` | **5** |
| Teilweise / nur Legacy-REST oder nur interne Engine ohne passende Surface | `GetInfo`, `GetAccumulator`, `GetNullifierPath`, `SubmitTransition`, `OpenPullChallenge` (nur attest-challenge), `Publish` | **6** |
| Nicht vorhanden | `ListInscriptions`, `Pull`, `GetRecord`, `GetCoinProof`, `GetAccountState`, `SubscribeReceipts`, `EntrustOperationalBundle`, `RevokeOperationalBundle`, `IssueViewGrant` | **9** |

**Kurzfassung für den Bericht:** **5 von 20** Prozeduren haben heute eine belastbare Handler-Entsprechung unter einem §7.5-ähnlichen Pfad; **11 von 20**, wenn man interne Engine-/Legacy-Bausteine als „teilweise Entsprechung“ mitzählt. Eine gRPC-Implementierung von `kernel.v1` gibt es **nicht**.

## API-lokale Endpunkte (explizit ohne Kernel)

| REST | Grund |
|---|---|
| `GET /` | §7.5: Listing, API-lokal |
| `GET /health` | §7.5: Liveness, API-lokal |

`GET /health/ready` ist **nicht** rein API-lokal: §7.8 mappt Readiness über `GetInfo.ready` / `ready_reason`.
