//! Structural smoke test for the generated OpenAPI 3.x document.
//!
//! Unlike `api_remote`, this suite does not touch the network and does
//! not need a running node. It calls [`node::openapi::openapi_json`]
//! directly — the same code path that backs `GET /openapi.json` — and
//! asserts the shape of the resulting document.
//!
//! The point is to catch drift between the handler annotations and the
//! wire contract before the build ships:
//!
//!   - every always-on `/api/*` route is listed under `paths`
//!   - the request and response envelopes the wallet app depends on
//!     (`SendCoinResponse`, `LnurlErrorResponse`) appear under
//!     `components.schemas`
//!   - `InfoResponse` carries the `username_domain` field — its
//!     absence in an earlier Zod-driven mirror is what motivated the
//!     switch to annotation-driven generation in the first place
//!   - the static Swagger UI page served at `/docs` references the
//!     bundled `swagger-ui-bundle.js` and `swagger-ui.css` assets via
//!     same-origin relative URLs, with no `https://` references and no
//!     `servers(...)` block in the spec — both would couple the
//!     document to a specific deployment host
//!
//! Read by: `cargo test -p node --test openapi_smoke` (CI, both the
//! slim PR job and the full release job).

use serde_json::Value;

/// Parse the cached spec once per test process. Each test calls this
/// at its top so a parse failure surfaces as the failing test's panic
/// instead of a shared lazy-static initialisation error.
fn parse_spec() -> Value {
    let json = node::openapi::openapi_json();
    serde_json::from_str::<Value>(json)
        .expect("openapi_json() must return a serialisable OpenAPI document")
}

#[test]
fn spec_is_valid_openapi_3_x() {
    let v = parse_spec();
    let version = v["openapi"]
        .as_str()
        .expect("`openapi` field must be a string");
    assert!(
        version.starts_with("3."),
        "expected OpenAPI 3.x, got `{version}`"
    );
}

#[test]
fn spec_paths_is_non_empty() {
    let v = parse_spec();
    let paths = v["paths"]
        .as_object()
        .expect("`paths` must be a JSON object");
    assert!(
        !paths.is_empty(),
        "`paths` must list at least one annotated handler"
    );
}

#[test]
fn spec_lists_every_always_on_route() {
    let v = parse_spec();
    let paths = v["paths"]
        .as_object()
        .expect("`paths` must be a JSON object");

    // Every always-on (non-feature-gated) route on the wire surface
    // that the wallet app talks to, plus the operational endpoints
    // load balancers and Kuma monitors depend on. Feature-gated routes
    // (`/api/address`, `/api/username/claim`, the LNURL pair) are not
    // checked here because the default build does not enable them and
    // the document must reflect the running binary.
    let required = [
        "/",
        "/health",
        "/health/ready",
        "/health/publisher",
        "/api/info",
        "/api/balance",
        "/api/history",
        "/api/history/{id}",
        "/api/jobs/mint",
        "/api/jobs/send",
        "/api/jobs/{job_id}",
        "/api/jobs/{job_id}/stream",
        "/api/jobs/{job_id}/commit",
        "/api/jobs/{job_id}/cancel",
        "/api/receive",
        "/api/proof/{id}",
        "/api/inscriptions/{txid}",
        "/api/username/resolve/{username}",
    ];

    for path in required {
        assert!(
            paths.contains_key(path),
            "spec is missing the always-on path `{path}` — \
             handler annotation is probably missing from `ApiDoc::paths(...)`"
        );
    }
}

#[test]
fn spec_registers_critical_schemas() {
    let v = parse_spec();
    let schemas = v["components"]["schemas"]
        .as_object()
        .expect("`components.schemas` must be a JSON object");

    // `LnurlErrorResponse` is the LUD-style error envelope returned
    // by the username and LNURL endpoints. It is distinct from
    // `SendCoinResponse` (the zkCoins-style envelope used by the coin
    // endpoints) and the Zod mirror previously declared them as one
    // — that bug is what this assertion guards against.
    assert!(
        schemas.contains_key("LnurlErrorResponse"),
        "`LnurlErrorResponse` must be registered separately from `SendCoinResponse`"
    );

    // `SendCoinResponse` is the canonical zkCoins envelope: every
    // coin endpoint uses it for both 2xx and 4xx/5xx bodies. Missing
    // here means the spec cannot describe any non-200 response on
    // those endpoints.
    assert!(
        schemas.contains_key("SendCoinResponse"),
        "`SendCoinResponse` must be registered under components.schemas"
    );

    // Stage 3 Runde 6 closed unauthenticated `/api/history` (410 Gone).
    // Only the error envelope remains in the OpenAPI schema — list/detail
    // success bodies (`HistoryResponse` / `HistoryItem` / `TxDetail`) are
    // gone with the handlers.
    assert!(
        schemas.contains_key("HistoryErrorResponse"),
        "`HistoryErrorResponse` must be registered under components.schemas — \
         closed `/api/history` still documents its 410 body"
    );
    for gone in ["HistoryResponse", "HistoryItem", "TxDetail"] {
        assert!(
            !schemas.contains_key(gone),
            "`{gone}` must NOT remain registered after Stage 3 closed history"
        );
    }

    // `ReadyResponse` is what Kuma + load balancers consume to gate
    // traffic on `/health/ready`. Missing here means a deploy that
    // changes the readiness shape ships without anyone noticing the
    // monitor contract broke.
    assert!(
        schemas.contains_key("ReadyResponse"),
        "`ReadyResponse` must be registered under components.schemas — \
         readiness probes consume this shape"
    );
}

#[test]
fn info_response_carries_username_domain() {
    // Drift guard: `username_domain` was missing from the previous
    // Zod-driven attempt and only surfaced under review. The whole
    // point of generating the spec from the Rust type is that this
    // field cannot go missing without removing it from `InfoResponse`
    // itself, which would break the wallet app.
    let v = parse_spec();
    let info = &v["components"]["schemas"]["InfoResponse"];
    let properties = info["properties"]
        .as_object()
        .expect("`InfoResponse.properties` must be a JSON object");
    assert!(
        properties.contains_key("username_domain"),
        "`InfoResponse` is missing the `username_domain` property — \
         did someone drop the field from the Rust struct?"
    );
}

#[test]
fn info_response_carries_typed_bitcoin_network() {
    // Drift guard for the typed `bitcoin_network` enum: the wallet/SDK
    // switch behaviour on the lowercase `mainnet`/`mutinynet` identifier
    // rather than the free-text `network` label, so the property must
    // exist and the `BitcoinNetwork` schema must be registered.
    let v = parse_spec();
    let properties = v["components"]["schemas"]["InfoResponse"]["properties"]
        .as_object()
        .expect("`InfoResponse.properties` must be a JSON object");
    assert!(
        properties.contains_key("bitcoin_network"),
        "`InfoResponse` is missing the `bitcoin_network` property — \
         did someone drop the field from the Rust struct?"
    );

    let schemas = v["components"]["schemas"]
        .as_object()
        .expect("`components.schemas` must be a JSON object");
    assert!(
        schemas.contains_key("BitcoinNetwork"),
        "`BitcoinNetwork` must be registered under components.schemas — \
         clients depend on the typed network enum"
    );
}

#[test]
fn docs_html_loads_bundled_swagger_ui_assets() {
    let html = node::openapi::DOCS_HTML;
    // Same-origin relative URLs served by `swagger_asset_handler` from
    // the binary-bundled `utoipa-swagger-ui` `vendored` snapshot. A
    // leading `https://` here would re-introduce the CDN dependency
    // the bundled-assets refactor was supposed to remove.
    assert!(
        html.contains("/docs/swagger-ui-bundle.js"),
        "`DOCS_HTML` must load the Swagger UI JS bundle from the same-origin `/docs/` path"
    );
    assert!(
        html.contains("/docs/swagger-ui.css"),
        "`DOCS_HTML` must load the Swagger UI stylesheet from the same-origin `/docs/` path"
    );
    assert!(
        html.contains("url: '/openapi.json'"),
        "`DOCS_HTML` must point Swagger UI at the relative `/openapi.json` URL"
    );
}

#[test]
fn docs_html_has_no_external_urls() {
    // The whole point of the bundling refactor: zero CDN dependencies
    // in the docs page so the node ships a self-contained binary.
    let html = node::openapi::DOCS_HTML;
    assert!(
        !html.contains("http://"),
        "`DOCS_HTML` must not reference any external `http://` URL"
    );
    assert!(
        !html.contains("https://"),
        "`DOCS_HTML` must not reference any external `https://` URL — \
         Swagger UI assets are bundled into the binary"
    );
}

#[test]
fn spec_has_no_hardcoded_servers_block() {
    // The previous shape pinned `servers(...)` to the hosted DFX
    // deployments, which leaks DFX infrastructure into every
    // self-hoster's binary and confuses Swagger UI's "Try it out"
    // panel. Per OpenAPI 3.x, omitting `servers` (or leaving it empty)
    // means "same host as the document was fetched from" — exactly
    // the self-host-friendly default we want.
    let v = parse_spec();
    match v.get("servers") {
        None => {}
        Some(serde_json::Value::Array(arr)) => {
            for entry in arr {
                let url = entry["url"].as_str().unwrap_or("");
                assert!(
                    !url.starts_with("http://") && !url.starts_with("https://"),
                    "spec.servers must not hardcode an absolute URL, got `{url}`"
                );
            }
        }
        Some(other) => panic!("spec.servers must be absent or an array, got {other}"),
    }
}
