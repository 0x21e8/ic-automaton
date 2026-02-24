/// Certified HTTP handler for the canister's browser UI and JSON API.
///
/// Every route that is served as a query response is covered by an
/// IC-certified Merkle tree (v2 certificate header).  Write routes
/// (`POST /api/conversation`, …) carry an
/// `upgrade: true` flag so the IC boundary nodes automatically retry them as
/// update calls, which go through `handle_http_request_update`.
///
/// # Route map
///
/// | Method | Path                          | Kind        |
/// |--------|-------------------------------|-------------|
/// | GET    | `/`                           | query       |
/// | GET    | `/index.html`                 | query       |
/// | GET    | `/styles.css`                 | query       |
/// | GET    | `/app.js`                     | query       |
/// | GET    | `/api/snapshot`               | query       |
/// | GET    | `/api/wallet/balance`         | query       |
/// | GET    | `/api/wallet/balance/sync-config` | query   |
/// | GET    | `/api/evm/config`             | query       |
/// | GET    | `/api/inference/config`       | query       |
/// | POST   | `/api/conversation`           | update      |
use crate::storage::stable;
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};
#[cfg(target_arch = "wasm32")]
use ic_http_certification::utils::add_v2_certificate_header;
use ic_http_certification::{
    DefaultCelBuilder, DefaultResponseCertification, HttpCertification, HttpCertificationPath,
    HttpCertificationTree, HttpCertificationTreeEntry, HttpRequest, HttpResponse,
    HttpUpdateRequest, HttpUpdateResponse, Method, StatusCode, CERTIFICATE_EXPRESSION_HEADER_NAME,
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;

const HEADER_CONTENT_TYPE: &str = "Content-Type";
const HEADER_CACHE_CONTROL: &str = "Cache-Control";
const CONTENT_TYPE_HTML: &str = "text/html; charset=utf-8";
const CONTENT_TYPE_CSS: &str = "text/css; charset=utf-8";
const CONTENT_TYPE_JS: &str = "application/javascript; charset=utf-8";
const CONTENT_TYPE_JSON: &str = "application/json; charset=utf-8";
const CACHE_NO_STORE: &str = "no-store";
const DEFAULT_SNAPSHOT_LIMIT: usize = 25;
const UI_INDEX_HTML: &str = include_str!("ui_index.html");
const UI_STYLES_CSS: &str = include_str!("ui_styles.css");
const UI_APP_JS: &str = include_str!("ui_app.js");

// ── Certification types ──────────────────────────────────────────────────────

/// Log priority levels for HTTP-layer diagnostics.
#[derive(Clone, Copy, Debug, LogPriorityLevels)]
enum HttpLogPriority {
    #[log_level(capacity = 1000, name = "HTTP_INFO")]
    Info,
    #[log_level(capacity = 500, name = "HTTP_WARN")]
    Warn,
    #[log_level(capacity = 200, name = "HTTP_ERROR")]
    Error,
}

impl GetLogFilter for HttpLogPriority {
    fn get_log_filter() -> LogFilter {
        LogFilter::ShowAll
    }
}

/// A fully-certified HTTP route: pairs a pre-built `HttpCertification` proof
/// with the base response body so that `render_certified_response` can attach
/// the v2 certificate header without recomputing the Merkle witness each time.
#[derive(Clone)]
struct CertifiedRoute {
    method: Method,
    request_path: &'static str,
    cert_path: HttpCertificationPath<'static>,
    #[cfg(target_arch = "wasm32")]
    expr_path: Vec<String>,
    certification: HttpCertification,
    base_response: HttpResponse<'static>,
}

/// Thread-local snapshot of the certification tree and all registered routes.
/// Rebuilt by `init_certification` on every `init` / `post_upgrade` call and
/// whenever a write route mutates state that is reflected in a GET response.
#[derive(Clone)]
struct HttpCertificationState {
    tree: HttpCertificationTree,
    routes: Vec<CertifiedRoute>,
    fallback_not_found: CertifiedRoute,
}

// ── API types ────────────────────────────────────────────────────────────────

/// Parsed body for `POST /api/conversation` — identifies the conversation by
/// sender address.
#[derive(Clone, Debug, Deserialize)]
struct ConversationLookupRequest {
    sender: String,
}

/// JSON body returned when `POST /api/conversation` cannot find the requested
/// sender.
#[derive(Clone, Debug, Serialize)]
struct ConversationLookupError {
    ok: bool,
    error: String,
}

/// Serialisable snapshot of EVM configuration fields served by
/// `GET /api/evm/config`.
#[derive(Clone, Debug, Serialize)]
struct EvmConfigView {
    automaton_address: Option<String>,
    inbox_contract_address: Option<String>,
    usdc_address: Option<String>,
    chain_id: u64,
    rpc_url: String,
}

fn evm_config_view() -> EvmConfigView {
    let route = stable::evm_route_state_view();
    EvmConfigView {
        automaton_address: route.automaton_evm_address,
        inbox_contract_address: route.inbox_contract_address,
        usdc_address: stable::get_discovered_usdc_address(),
        chain_id: route.chain_id,
        rpc_url: stable::get_evm_rpc_url(),
    }
}

// ── Route handlers ───────────────────────────────────────────────────────────

// Per-canister thread-local state holding the live certification tree.
thread_local! {
    static HTTP_STATE: RefCell<Option<HttpCertificationState>> = const { RefCell::new(None) };
}

/// Builds a fresh `HttpCertificationState` from current stable storage,
/// commits the Merkle root hash as certified data, and stores the state in
/// the thread-local slot.  Must be called from `init`, `post_upgrade`, and
/// after any write route that changes a GET-served payload.
pub fn init_certification() {
    let state = build_certification_state();
    set_tree_as_certified_data(&state.tree);
    HTTP_STATE.with(|slot| {
        *slot.borrow_mut() = Some(state);
    });
}

/// Handles `http_request` query calls.
///
/// Routes that exist in the certification tree are served with a v2 certificate
/// header.  Upgrade routes return `upgrade: true` so the boundary node retries
/// as `http_request_update`.  Unknown paths fall back to the certified 404
/// wildcard route.
pub fn handle_http_request(request: HttpRequest<'_>) -> HttpResponse<'static> {
    ensure_initialized();

    let path = match request.get_path() {
        Ok(path) => path,
        Err(error) => {
            log!(
                HttpLogPriority::Warn,
                "http_request malformed url={} err={}",
                request.url(),
                error
            );
            return HttpResponse::bad_request(
                br#"{"ok":false,"error":"malformed request url"}"#.as_slice(),
                vec![
                    (
                        HEADER_CONTENT_TYPE.to_string(),
                        CONTENT_TYPE_JSON.to_string(),
                    ),
                    (HEADER_CACHE_CONTROL.to_string(), CACHE_NO_STORE.to_string()),
                ],
            )
            .build();
        }
    };

    HTTP_STATE.with(|slot| {
        let state = slot.borrow();
        let state = state
            .as_ref()
            .expect("http certification state must be initialized");
        if let Some(route) = state
            .routes
            .iter()
            .find(|route| route.method == *request.method() && route.request_path == path)
        {
            return render_certified_response(state, route, &path);
        }
        render_certified_response(state, &state.fallback_not_found, &path)
    })
}

/// Handles `http_request_update` calls — the mutable side of the HTTP
/// interface.  Each arm dispatches to the appropriate storage operation and
/// calls `init_certification` when a state change affects a GET-served route.
pub fn handle_http_request_update(request: HttpUpdateRequest<'_>) -> HttpUpdateResponse<'static> {
    let path = match request.get_path() {
        Ok(path) => path,
        Err(_) => {
            return HttpResponse::bad_request(
                br#"{"ok":false,"error":"malformed request url"}"#.as_slice(),
                vec![
                    (
                        HEADER_CONTENT_TYPE.to_string(),
                        CONTENT_TYPE_JSON.to_string(),
                    ),
                    (HEADER_CACHE_CONTROL.to_string(), CACHE_NO_STORE.to_string()),
                ],
            )
            .build_update();
        }
    };

    match (request.method(), path.as_str()) {
        (&Method::GET, "/api/snapshot") => {
            let snapshot = stable::observability_snapshot(DEFAULT_SNAPSHOT_LIMIT);
            json_update_response(StatusCode::OK, &snapshot)
        }
        (&Method::GET, "/api/wallet/balance") => {
            let telemetry = stable::wallet_balance_telemetry_view();
            json_update_response(StatusCode::OK, &telemetry)
        }
        (&Method::GET, "/api/wallet/balance/sync-config") => {
            let config = stable::wallet_balance_sync_config_view();
            json_update_response(StatusCode::OK, &config)
        }
        (&Method::POST, "/api/conversation") => {
            match parse_conversation_lookup_request(request.body()) {
                Ok(payload) => match stable::get_conversation_log(&payload.sender) {
                    Some(log) => json_update_response(StatusCode::OK, &log),
                    None => json_update_response(
                        StatusCode::NOT_FOUND,
                        &ConversationLookupError {
                            ok: false,
                            error: format!("conversation not found for sender {}", payload.sender),
                        },
                    ),
                },
                Err(error) => json_update_response(
                    StatusCode::BAD_REQUEST,
                    &ConversationLookupError { ok: false, error },
                ),
            }
        }
        (&Method::GET, "/api/evm/config") => {
            let config = evm_config_view();
            json_update_response(StatusCode::OK, &config)
        }
        (&Method::GET, "/api/inference/config") => {
            let config = stable::inference_config_view();
            json_update_response(StatusCode::OK, &config)
        }
        _ => HttpResponse::not_found(
            br#"{"ok":false,"error":"not found"}"#.as_slice(),
            vec![
                (
                    HEADER_CONTENT_TYPE.to_string(),
                    CONTENT_TYPE_JSON.to_string(),
                ),
                (HEADER_CACHE_CONTROL.to_string(), CACHE_NO_STORE.to_string()),
            ],
        )
        .build_update(),
    }
}

/// Lazily initialises the certification state if not yet present.
/// Used as a safety net in `handle_http_request`; in production the explicit
/// `init_certification` call in `init`/`post_upgrade` should always pre-populate
/// the state.
fn ensure_initialized() {
    HTTP_STATE.with(|slot| {
        if slot.borrow().is_none() {
            let state = build_certification_state();
            set_tree_as_certified_data(&state.tree);
            *slot.borrow_mut() = Some(state);
        }
    });
}

// ── UI serving ───────────────────────────────────────────────────────────────

/// Constructs the full `HttpCertificationState` by reading current stable
/// storage values and building certified routes for all static assets and API
/// endpoints.  Inserts each route into a fresh `HttpCertificationTree`.
fn build_certification_state() -> HttpCertificationState {
    let snapshot = stable::observability_snapshot(DEFAULT_SNAPSHOT_LIMIT);
    let wallet_balance = stable::wallet_balance_telemetry_view();
    let wallet_sync_config = stable::wallet_balance_sync_config_view();
    let evm_config = evm_config_view();
    let inference_config = stable::inference_config_view();

    let mut tree = HttpCertificationTree::default();
    let routes = vec![
        static_asset_route(
            Method::GET,
            "/",
            "/",
            UI_INDEX_HTML.as_bytes(),
            CONTENT_TYPE_HTML,
        ),
        static_asset_route(
            Method::GET,
            "/index.html",
            "/index.html",
            UI_INDEX_HTML.as_bytes(),
            CONTENT_TYPE_HTML,
        ),
        static_asset_route(
            Method::GET,
            "/styles.css",
            "/styles.css",
            UI_STYLES_CSS.as_bytes(),
            CONTENT_TYPE_CSS,
        ),
        static_asset_route(
            Method::GET,
            "/app.js",
            "/app.js",
            UI_APP_JS.as_bytes(),
            CONTENT_TYPE_JS,
        ),
        json_route(Method::GET, "/api/snapshot", &snapshot),
        json_route(Method::GET, "/api/wallet/balance", &wallet_balance),
        json_route(
            Method::GET,
            "/api/wallet/balance/sync-config",
            &wallet_sync_config,
        ),
        json_route(Method::GET, "/api/evm/config", &evm_config),
        json_route(Method::GET, "/api/inference/config", &inference_config),
        upgrade_route(Method::POST, "/api/conversation"),
    ];
    for route in &routes {
        let entry = HttpCertificationTreeEntry::new(&route.cert_path, route.certification);
        tree.insert(&entry);
    }

    let fallback_not_found = not_found_route();
    let fallback_entry = HttpCertificationTreeEntry::new(
        &fallback_not_found.cert_path,
        fallback_not_found.certification,
    );
    tree.insert(&fallback_entry);

    HttpCertificationState {
        tree,
        routes,
        fallback_not_found,
    }
}

/// Builds a `CertifiedRoute` for a static file asset (HTML, CSS, JS).
fn static_asset_route(
    method: Method,
    request_path: &'static str,
    cert_path: &'static str,
    body: &[u8],
    content_type: &'static str,
) -> CertifiedRoute {
    let base_response = HttpResponse::ok(
        body.to_vec(),
        vec![
            (HEADER_CONTENT_TYPE.to_string(), content_type.to_string()),
            (HEADER_CACHE_CONTROL.to_string(), CACHE_NO_STORE.to_string()),
        ],
    )
    .build();

    certified_route(
        method,
        request_path,
        HttpCertificationPath::exact(cert_path),
        base_response,
    )
}

/// Serialises `payload` to JSON and builds a certified GET route for
/// `request_path`.  On serialization failure a 500 response with a static
/// error JSON body is used so callers reliably detect the failure path.
fn json_route<T: Serialize>(
    method: Method,
    request_path: &'static str,
    payload: &T,
) -> CertifiedRoute {
    let base_response = match serde_json::to_vec(payload) {
        Ok(body) => HttpResponse::ok(
            body,
            vec![
                (
                    HEADER_CONTENT_TYPE.to_string(),
                    CONTENT_TYPE_JSON.to_string(),
                ),
                (HEADER_CACHE_CONTROL.to_string(), CACHE_NO_STORE.to_string()),
            ],
        )
        .build(),
        Err(error) => {
            log!(
                HttpLogPriority::Error,
                "http_json_serialize_error route={} err={}",
                request_path,
                error
            );
            HttpResponse::internal_server_error(
                br#"{"ok":false,"error":"serialization failed"}"#.as_slice(),
                vec![
                    (
                        HEADER_CONTENT_TYPE.to_string(),
                        CONTENT_TYPE_JSON.to_string(),
                    ),
                    (HEADER_CACHE_CONTROL.to_string(), CACHE_NO_STORE.to_string()),
                ],
            )
            .build()
        }
    };

    certified_route(
        method,
        request_path,
        HttpCertificationPath::exact(request_path),
        base_response,
    )
}

/// Builds a certified route that signals `upgrade: true` to the boundary
/// node, causing it to retry the request as an update call.
fn upgrade_route(method: Method, request_path: &'static str) -> CertifiedRoute {
    let base_response = HttpResponse::ok(
        br#"{"upgrade":true}"#.as_slice(),
        vec![
            (
                HEADER_CONTENT_TYPE.to_string(),
                CONTENT_TYPE_JSON.to_string(),
            ),
            (HEADER_CACHE_CONTROL.to_string(), CACHE_NO_STORE.to_string()),
        ],
    )
    .with_upgrade(true)
    .build();

    certified_route(
        method,
        request_path,
        HttpCertificationPath::exact(request_path),
        base_response,
    )
}

/// Builds the certified wildcard 404 fallback route that covers all paths not
/// explicitly registered in the tree.
fn not_found_route() -> CertifiedRoute {
    let base_response = HttpResponse::not_found(
        br#"404 Not Found"#.as_slice(),
        vec![
            (
                HEADER_CONTENT_TYPE.to_string(),
                "text/plain; charset=utf-8".to_string(),
            ),
            (HEADER_CACHE_CONTROL.to_string(), CACHE_NO_STORE.to_string()),
        ],
    )
    .build();

    certified_route(
        Method::GET,
        "__wildcard_not_found__",
        HttpCertificationPath::wildcard("/"),
        base_response,
    )
}

/// Core builder: attaches the CEL expression header to `base_response`,
/// computes the `HttpCertification` proof, and packages everything into a
/// `CertifiedRoute`.
fn certified_route(
    method: Method,
    request_path: &'static str,
    cert_path: HttpCertificationPath<'static>,
    mut base_response: HttpResponse<'static>,
) -> CertifiedRoute {
    let cel_expr = DefaultCelBuilder::response_only_certification()
        .with_response_certification(DefaultResponseCertification::response_header_exclusions(
            vec![],
        ))
        .build();
    base_response.add_header((
        CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(),
        cel_expr.to_string(),
    ));
    let certification = HttpCertification::response_only(&cel_expr, &base_response, None)
        .expect("response-only certification should succeed");
    #[cfg(target_arch = "wasm32")]
    let expr_path = cert_path.to_expr_path();

    CertifiedRoute {
        method,
        request_path,
        cert_path,
        #[cfg(target_arch = "wasm32")]
        expr_path,
        certification,
        base_response,
    }
}

/// Clones the pre-built base response and — on wasm32 — attaches the IC v2
/// certificate header using the data certificate and a Merkle witness for
/// `request_path`.
fn render_certified_response(
    state: &HttpCertificationState,
    route: &CertifiedRoute,
    request_path: &str,
) -> HttpResponse<'static> {
    #[cfg(target_arch = "wasm32")]
    let mut response = route.base_response.clone();
    #[cfg(not(target_arch = "wasm32"))]
    let response = route.base_response.clone();

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (state, route, request_path);
    }

    #[cfg(target_arch = "wasm32")]
    {
        if let Some(data_certificate) = ic_cdk::api::data_certificate() {
            let entry = HttpCertificationTreeEntry::new(&route.cert_path, route.certification);
            match state.tree.witness(&entry, request_path) {
                Ok(witness) => {
                    add_v2_certificate_header(
                        &data_certificate,
                        &mut response,
                        &witness,
                        &route.expr_path,
                    );
                }
                Err(error) => {
                    log!(
                        HttpLogPriority::Error,
                        "http_witness_error request_path={} err={}",
                        request_path,
                        error
                    );
                }
            }
        } else {
            log!(
                HttpLogPriority::Warn,
                "http_data_certificate_missing request_path={}",
                request_path
            );
        }
    }
    response
}

/// Serialises `payload` to JSON and wraps it in an `HttpUpdateResponse` with
/// the given status code.  Falls back to a 500 plain-error body on
/// serialization failure.
fn json_update_response<T: Serialize>(
    status_code: StatusCode,
    payload: &T,
) -> HttpUpdateResponse<'static> {
    match serde_json::to_vec(payload) {
        Ok(body) => HttpResponse::builder()
            .with_status_code(status_code)
            .with_body(body)
            .with_headers(vec![
                (
                    HEADER_CONTENT_TYPE.to_string(),
                    CONTENT_TYPE_JSON.to_string(),
                ),
                (HEADER_CACHE_CONTROL.to_string(), CACHE_NO_STORE.to_string()),
            ])
            .build_update(),
        Err(error) => {
            log!(
                HttpLogPriority::Error,
                "http_json_serialize_error err={}",
                error
            );
            HttpResponse::internal_server_error(
                br#"{"ok":false,"error":"serialization failed"}"#.as_slice(),
                vec![
                    (
                        HEADER_CONTENT_TYPE.to_string(),
                        CONTENT_TYPE_JSON.to_string(),
                    ),
                    (HEADER_CACHE_CONTROL.to_string(), CACHE_NO_STORE.to_string()),
                ],
            )
            .build_update()
        }
    }
}

/// Parses the `POST /api/conversation` request body and trims the sender field.
fn parse_conversation_lookup_request(body: &[u8]) -> Result<ConversationLookupRequest, String> {
    if body.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err("conversation lookup body cannot be empty".to_string());
    }

    let payload = serde_json::from_slice::<ConversationLookupRequest>(body)
        .map_err(|error| format!("invalid conversation lookup payload: {error}"))?;
    let sender = payload.sender.trim();
    if sender.is_empty() {
        return Err("sender cannot be empty".to_string());
    }

    Ok(ConversationLookupRequest {
        sender: sender.to_string(),
    })
}

/// Commits the Merkle root hash of `tree` as the canister's certified data.
/// No-op in native/test builds where the IC certified data API is unavailable.
fn set_tree_as_certified_data(tree: &HttpCertificationTree) {
    #[cfg(target_arch = "wasm32")]
    {
        let root_hash = tree.root_hash();
        ic_cdk::api::certified_data_set(&root_hash);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = tree;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn find_header<'a>(response: &'a HttpResponse<'_>, name: &str) -> Option<&'a str> {
        response
            .headers()
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn serves_root_asset_with_expected_headers() {
        init_certification();

        let request = HttpRequest::get("/").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert!(std::str::from_utf8(response.body())
            .expect("root body should be utf8")
            .contains("AUTOMATON"));
        assert_eq!(
            find_header(&response, HEADER_CONTENT_TYPE),
            Some(CONTENT_TYPE_HTML)
        );
    }

    #[test]
    fn serves_app_asset_with_history_and_config_commands_wired() {
        init_certification();

        let request = HttpRequest::get("/app.js").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(
            find_header(&response, HEADER_CONTENT_TYPE),
            Some(CONTENT_TYPE_JS)
        );

        let body = std::str::from_utf8(response.body()).expect("app.js body should be utf8");
        assert!(
            body.contains("Past messages and automaton responses"),
            "help output should mention the history command"
        );
        assert!(
            body.contains("Configuration overview"),
            "help output should mention the config command"
        );
        assert!(
            body.contains("case \"history\""),
            "command dispatcher should route the history command"
        );
        assert!(
            body.contains("case \"config\""),
            "command dispatcher should route the config command"
        );
        assert!(
            body.contains("LIVE STATUS VIEW"),
            "status command should open a live status view"
        );
    }

    #[test]
    fn api_snapshot_query_path_returns_certified_json() {
        init_certification();

        let request = HttpRequest::get("/api/snapshot").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), None);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("snapshot body should decode as json");
        assert!(body.get("runtime").is_some());
    }

    #[test]
    fn get_wallet_balance_route_is_certified_query() {
        init_certification();

        let request = HttpRequest::get("/api/wallet/balance").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), None);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("wallet balance body should decode as json");
        assert!(body.get("status").is_some());
    }

    #[test]
    fn get_wallet_balance_sync_config_route_is_certified_query() {
        init_certification();

        let request = HttpRequest::get("/api/wallet/balance/sync-config").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), None);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("wallet sync config body should decode as json");
        assert!(body.get("enabled").is_some());
    }

    #[test]
    fn get_evm_config_route_is_certified_query() {
        init_certification();

        let request = HttpRequest::get("/api/evm/config").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), None);
        let body =
            serde_json::from_slice::<Value>(response.body()).expect("evm config should decode");
        assert!(body.get("chain_id").is_some());
    }

    #[test]
    fn get_evm_config_returns_expected_fields() {
        stable::init_storage();
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("automaton address should store");
        stable::set_inbox_contract_address(Some(
            "0x2222222222222222222222222222222222222222".to_string(),
        ))
        .expect("inbox contract should store");
        stable::set_evm_chain_id(31337).expect("chain id should store");
        init_certification();

        let request = HttpRequest::get("/api/evm/config").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = serde_json::from_slice::<serde_json::Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(
            body.get("automaton_address")
                .and_then(serde_json::Value::as_str),
            Some("0x1111111111111111111111111111111111111111")
        );
        assert_eq!(
            body.get("inbox_contract_address")
                .and_then(serde_json::Value::as_str),
            Some("0x2222222222222222222222222222222222222222")
        );
        assert_eq!(
            body.get("chain_id").and_then(serde_json::Value::as_u64),
            Some(31337)
        );
        assert!(body
            .get("rpc_url")
            .and_then(serde_json::Value::as_str)
            .is_some());
    }

    #[test]
    fn wallet_balance_routes_return_safe_non_secret_views() {
        init_certification();
        stable::init_storage();
        stable::set_wallet_balance_snapshot(crate::domain::types::WalletBalanceSnapshot {
            eth_balance_wei_hex: Some("0x1".to_string()),
            usdc_balance_raw_hex: Some("0x2a".to_string()),
            usdc_decimals: 6,
            usdc_contract_address: Some("0x3333333333333333333333333333333333333333".to_string()),
            last_synced_at_ns: Some(1),
            last_synced_block: Some(123),
            last_error: Some("rpc timeout".to_string()),
        });
        stable::set_wallet_balance_bootstrap_pending(true);
        stable::set_wallet_balance_sync_config(crate::domain::types::WalletBalanceSyncConfig {
            enabled: true,
            normal_interval_secs: 300,
            low_cycles_interval_secs: 900,
            freshness_window_secs: 600,
            max_response_bytes: 256,
            discover_usdc_via_inbox: true,
        })
        .expect("wallet sync config should persist");

        let telemetry_response =
            handle_http_request_update(HttpRequest::get("/api/wallet/balance").build_update());
        assert_eq!(telemetry_response.status_code(), StatusCode::OK);
        let telemetry = serde_json::from_slice::<Value>(telemetry_response.body())
            .expect("telemetry body should decode as json");
        assert_eq!(
            telemetry.get("eth_balance_wei_hex").and_then(Value::as_str),
            Some("0x1")
        );
        assert_eq!(
            telemetry
                .get("usdc_balance_raw_hex")
                .and_then(Value::as_str),
            Some("0x2a")
        );
        assert_eq!(
            telemetry.get("status").and_then(Value::as_str),
            Some("Error")
        );
        assert_eq!(
            telemetry.get("bootstrap_pending").and_then(Value::as_bool),
            Some(true)
        );
        assert!(telemetry.get("ecdsa_key_name").is_none());
        assert!(telemetry.get("evm_rpc_url").is_none());
        assert!(telemetry.get("openrouter_api_key").is_none());

        let config_response = handle_http_request_update(
            HttpRequest::get("/api/wallet/balance/sync-config").build_update(),
        );
        assert_eq!(config_response.status_code(), StatusCode::OK);
        let config = serde_json::from_slice::<Value>(config_response.body())
            .expect("config body should decode as json");
        assert_eq!(
            config.get("normal_interval_secs").and_then(Value::as_u64),
            Some(300)
        );
        assert_eq!(
            config
                .get("low_cycles_interval_secs")
                .and_then(Value::as_u64),
            Some(900)
        );
        assert_eq!(
            config.get("freshness_window_secs").and_then(Value::as_u64),
            Some(600)
        );
        assert!(config.get("ecdsa_key_name").is_none());
        assert!(config.get("evm_rpc_url").is_none());
        assert!(config.get("openrouter_api_key").is_none());
    }

    #[test]
    fn unknown_paths_render_not_found_response() {
        init_certification();

        let request = HttpRequest::get("/no-such-path").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn get_inference_config_route_is_certified_query() {
        init_certification();

        let request = HttpRequest::get("/api/inference/config").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), None);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("inference config body should decode as json");
        assert!(body.get("provider").is_some());
    }

    #[test]
    fn post_inference_config_route_is_not_upgradable() {
        init_certification();

        let request = HttpRequest::post("/api/inference/config").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(response.upgrade(), None);
    }

    #[test]
    fn post_inbox_route_is_not_upgradable() {
        init_certification();

        let request = HttpRequest::post("/api/inbox").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(response.upgrade(), None);
    }

    #[test]
    fn post_conversation_route_is_upgradable() {
        init_certification();

        let request = HttpRequest::post("/api/conversation").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), Some(true));
    }

    #[test]
    fn conversation_lookup_returns_conversation_log() {
        init_certification();
        stable::init_storage();
        stable::append_conversation_entry(
            "0xAbCd00000000000000000000000000000000Ef12",
            crate::domain::types::ConversationEntry {
                inbox_message_id: "inbox:1".to_string(),
                sender_body: "hello".to_string(),
                agent_reply: "hi".to_string(),
                turn_id: "turn-1".to_string(),
                timestamp_ns: 1,
            },
        );

        let request: HttpUpdateRequest = HttpRequest::post("/api/conversation")
            .with_headers(vec![(
                "content-type".to_string(),
                CONTENT_TYPE_JSON.to_string(),
            )])
            .with_body(br#"{"sender":"0xabcd00000000000000000000000000000000ef12"}"#.to_vec())
            .build_update();
        let response = handle_http_request_update(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(
            body.get("sender").and_then(Value::as_str),
            Some("0xabcd00000000000000000000000000000000ef12")
        );
        assert_eq!(
            body.get("entries")
                .and_then(Value::as_array)
                .map(|entries| entries.len()),
            Some(1)
        );
    }

    #[test]
    fn post_inbox_update_route_returns_not_found() {
        init_certification();

        let request: HttpUpdateRequest = HttpRequest::post("/api/inbox")
            .with_headers(vec![(
                "content-type".to_string(),
                CONTENT_TYPE_JSON.to_string(),
            )])
            .with_body(br#"{"message":"legacy path"}"#.to_vec())
            .build_update();
        let response = handle_http_request_update(request);

        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(body.get("ok"), Some(&Value::Bool(false)));
        assert_eq!(body.get("error").and_then(Value::as_str), Some("not found"));
    }

    #[test]
    fn post_inference_config_update_returns_not_found() {
        init_certification();

        let request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
            .with_headers(vec![(
                "content-type".to_string(),
                CONTENT_TYPE_JSON.to_string(),
            )])
            .with_body(br#"{"provider":"openrouter"}"#.to_vec())
            .build_update();
        let response = handle_http_request_update(request);

        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(body.get("ok"), Some(&Value::Bool(false)));
        assert_eq!(body.get("error").and_then(Value::as_str), Some("not found"));
    }
}
