//! OpenAPI 3.x spec for the zkCoins node REST API.
//!
//! The spec is generated at compile time from `#[utoipa::path]`
//! annotations on the handlers in [`crate::router`] and `ToSchema`
//! impls on the request / response types. There is no separately
//! maintained YAML or JSON — drift between the wire format and the
//! documentation is structurally impossible because the same Rust
//! type drives both serde and the schema.
//!
//! Four routes are wired in [`crate::router::create_router`]:
//!
//! - `GET /openapi.json` — returns the generated spec as JSON. The
//!   serialised bytes are produced once at first call into
//!   [`openapi_json`] and cached in a process-wide `OnceLock<String>`;
//!   subsequent calls return the same slice without re-serialising.
//! - `GET /docs` — serves a static HTML page that boots Swagger UI
//!   from two same-origin assets:
//!   - `GET /docs/swagger-ui.css`
//!   - `GET /docs/swagger-ui-bundle.js`
//!
//! The asset bytes are bundled into the binary via the
//! `utoipa-swagger-ui` crate's `vendored` feature, so the page works
//! offline, behind any reverse proxy that preserves path ordering, and
//! has no runtime CDN dependency. The `axum` feature of
//! `utoipa-swagger-ui` is deliberately disabled because it requires
//! axum 0.8; we hit the framework-agnostic [`utoipa_swagger_ui::serve`]
//! entrypoint from our own axum 0.7 handler instead.
//!
//! Feature-gated handlers are conditionally registered via
//! `#[cfg(feature = "...")]` on both the `paths(...)` list and the
//! handler's own annotation, so the spec describes exactly the routes
//! that exist in the running binary — not a superset.

use std::sync::{Arc, OnceLock};

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use utoipa::OpenApi;
use utoipa_swagger_ui::Config;

use crate::db::{InscriptionKind, InscriptionSummary};
use crate::job_store::JobStatus;
use crate::router::{
    BalanceResponse, BitcoinNetwork, Capabilities, CommitRequest, HistoryErrorResponse,
    InfoResponse, JobErrorResponse, JobStatusResponse, LnurlErrorResponse, MintRequest,
    PublisherHealthErrorResponse, PublisherHealthResponse, ReadyResponse, RootEndpoints,
    RootResponse, SendCoinRequest, SendCoinResponse, UsernameResponse,
};

#[cfg(feature = "address-list")]
use crate::router::AddressesResponse;
#[cfg(feature = "username-claim")]
use crate::router::ClaimUsernameRequest;
#[cfg(feature = "lnurl")]
use crate::router::LnurlpResponse;

/// Static Swagger UI HTML page served at `GET /docs`. References two
/// same-origin assets (`/docs/swagger-ui.css`, `/docs/swagger-ui-bundle.js`)
/// served from the bundled `utoipa-swagger-ui` `vendored` snapshot, and
/// points the renderer at the relative `/openapi.json` URL so the page
/// works behind any reverse proxy that preserves path ordering. No
/// external URLs — verified by the `openapi_smoke` suite.
pub const DOCS_HTML: &str = concat!(
    "<!DOCTYPE html>\n",
    "<html lang=\"en\">\n",
    "<head>\n",
    "<meta charset=\"UTF-8\">\n",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
    "<title>zkCoins API</title>\n",
    "<link rel=\"stylesheet\" href=\"/docs/swagger-ui.css\">\n",
    "</head>\n",
    "<body>\n",
    "<div id=\"swagger-ui\"></div>\n",
    "<script src=\"/docs/swagger-ui-bundle.js\" charset=\"UTF-8\"></script>\n",
    "<script>\n",
    "window.onload = function() {\n",
    "  window.ui = SwaggerUIBundle({\n",
    "    url: '/openapi.json',\n",
    "    dom_id: '#swagger-ui',\n",
    "    deepLinking: true,\n",
    "    presets: [SwaggerUIBundle.presets.apis],\n",
    "  });\n",
    "};\n",
    "</script>\n",
    "</body>\n",
    "</html>\n",
);

/// Compile-time root of the OpenAPI 3.x spec. The `#[openapi]`
/// attribute lists every handler whose `#[utoipa::path]` annotation
/// should appear under `paths`, plus every type registered under
/// `components.schemas`. Feature-gated handlers and feature-only
/// schemas are conditionally listed below.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "zkCoins API",
        description = "REST API of the zkCoins node (Shielded CSV on Bitcoin). \
                       This spec is generated from the handler annotations in the \
                       running binary, so it describes the exact wire contract this \
                       node serves. Interactive Swagger UI: `/docs`.",
        license(name = "MIT"),
    ),
    // No `servers(...)` block: per OpenAPI 3.x, the document then
    // applies to the host it was fetched from, so each self-hoster's
    // node automatically advertises its own URL instead of pointing at
    // the hosted DFX deployments.
    paths(
        crate::router::root_handler,
        crate::router::health_handler,
        crate::router::ready_handler,
        crate::router::publisher_health_handler,
        crate::router::info_handler,
        crate::router::get_balance_handler,
        crate::router::get_history_handler,
        crate::router::get_history_item_handler,
        crate::router::jobs_mint_handler,
        crate::router::jobs_send_handler,
        crate::router::jobs_commit_handler,
        crate::router::jobs_cancel_handler,
        crate::router::get_job_handler,
        crate::router::stream_job_handler,
        crate::router::receive_coin_handler,
        crate::router::get_proof_handler,
        crate::router::get_inscription_handler,
        crate::router::resolve_username_handler,
    ),
    components(schemas(
        RootResponse,
        RootEndpoints,
        ReadyResponse,
        PublisherHealthResponse,
        PublisherHealthErrorResponse,
        InfoResponse,
        BitcoinNetwork,
        Capabilities,
        BalanceResponse,
        HistoryErrorResponse,
        SendCoinRequest,
        SendCoinResponse,
        MintRequest,
        CommitRequest,
        JobStatus,
        JobStatusResponse,
        JobErrorResponse,
        UsernameResponse,
        LnurlErrorResponse,
        InscriptionSummary,
        InscriptionKind,
    )),
)]
pub(crate) struct ApiDoc;

/// Feature-gated path additions and schema registrations. Implemented
/// as a thin compile-time-conditional extension of [`ApiDoc`] so the
/// always-on derive above stays readable and the gated handlers carry
/// their own `paths(...)` entries next to the feature flag that
/// controls them.
#[cfg(feature = "address-list")]
#[derive(OpenApi)]
#[openapi(
    paths(crate::router::get_address_handler),
    components(schemas(AddressesResponse))
)]
struct AddressListDoc;

#[cfg(feature = "username-claim")]
#[derive(OpenApi)]
#[openapi(
    paths(crate::router::claim_username_handler),
    components(schemas(ClaimUsernameRequest))
)]
struct UsernameClaimDoc;

#[cfg(feature = "lnurl")]
#[derive(OpenApi)]
#[openapi(
    paths(crate::router::lnurlp_handler, crate::router::lnurl_callback_handler,),
    components(schemas(LnurlpResponse))
)]
struct LnurlDoc;

/// Build the complete OpenAPI document for this binary, merging in
/// every feature-gated sub-doc that the build enables.
pub(crate) fn build_openapi() -> utoipa::openapi::OpenApi {
    #[allow(unused_mut)]
    let mut doc = ApiDoc::openapi();
    #[cfg(feature = "address-list")]
    doc.merge(AddressListDoc::openapi());
    #[cfg(feature = "username-claim")]
    doc.merge(UsernameClaimDoc::openapi());
    #[cfg(feature = "lnurl")]
    doc.merge(LnurlDoc::openapi());
    doc
}

/// Cached JSON serialisation of [`build_openapi`]. Populated on first
/// access and reused for every subsequent `GET /openapi.json` so we
/// pay the serde cost once per process, not per request.
fn cached_openapi_json() -> &'static str {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE.get_or_init(|| {
        build_openapi()
            .to_json()
            .expect("OpenApi::to_json is infallible for a #[derive(OpenApi)] document")
    })
}

/// Re-export for callers that want the raw JSON string (e.g. the
/// integration smoke test) without going through the HTTP handler.
pub fn openapi_json() -> &'static str {
    cached_openapi_json()
}

/// `GET /openapi.json` — return the cached OpenAPI 3.x document.
pub(crate) async fn openapi_json_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        cached_openapi_json(),
    )
}

/// `GET /docs` — return the static Swagger UI page.
pub(crate) async fn docs_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DOCS_HTML,
    )
}

/// Shared [`utoipa_swagger_ui::Config`] used to look up bundled assets.
/// The path argument matches the spec URL embedded in [`DOCS_HTML`] so
/// Swagger UI itself loads `/openapi.json` (this struct does not gate
/// asset lookup — `serve()` keys solely off the relative file name).
pub(crate) fn swagger_ui_config() -> Arc<Config<'static>> {
    static CONFIG: OnceLock<Arc<Config<'static>>> = OnceLock::new();
    CONFIG
        .get_or_init(|| Arc::new(Config::from("/openapi.json")))
        .clone()
}

/// `GET /docs/{file}` — serve a single Swagger UI asset (CSS, JS, font,
/// map) bundled into the binary by the `utoipa-swagger-ui` `vendored`
/// feature. Returns 404 for unknown files.
///
/// `utoipa_swagger_ui::serve` returns `Err` in two situations
/// (see `utoipa-swagger-ui-9.0.2/src/lib.rs::serve`): when the
/// `swagger-initializer.js` bundle is not valid UTF-8, and when the
/// oauth config formatter fails. The first is impossible because the
/// `vendored` feature bakes in a known-good UTF-8 bundle at compile
/// time, and the second is impossible because [`swagger_ui_config`]
/// builds a [`Config`] without an oauth section. `expect()` is
/// therefore correct here: a panic would only fire if either
/// invariant were violated by a future upstream change, and the
/// readiness probe would surface that within minutes.
pub(crate) async fn swagger_asset_handler(Path(file): Path<String>) -> Response {
    match utoipa_swagger_ui::serve(&file, swagger_ui_config())
        .expect("utoipa-swagger-ui::serve cannot error for our bundled, no-oauth config")
    {
        Some(asset) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, asset.content_type)],
            asset.bytes.to_vec(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// Foreign types like `bitcoin::secp256k1::PublicKey` cannot derive
// `ToSchema` here (orphan rule). Each use site overrides the schema
// with `#[schema(value_type = String)]` so the spec describes the
// hex-encoded wire form instead of the in-process representation.

#[cfg(test)]
#[path = "openapi_tests.rs"]
mod tests;
