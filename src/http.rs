use crate::domain::types::InferenceConfigView;
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

#[derive(Clone)]
struct HttpCertificationState {
    tree: HttpCertificationTree,
    routes: Vec<CertifiedRoute>,
    fallback_not_found: CertifiedRoute,
}

#[derive(Clone, Debug, Serialize)]
struct InboxPostSuccess {
    ok: bool,
    id: String,
}

#[derive(Clone, Debug, Serialize)]
struct InboxPostError {
    ok: bool,
    error: String,
}

#[derive(Clone, Debug, Serialize)]
struct InferenceConfigError {
    ok: bool,
    error: String,
}

#[derive(Clone, Debug, Serialize)]
struct InferenceConfigSuccess {
    ok: bool,
    config: InferenceConfigView,
}

#[derive(Clone, Debug, Deserialize)]
struct ConversationLookupRequest {
    sender: String,
}

#[derive(Clone, Debug, Serialize)]
struct ConversationLookupError {
    ok: bool,
    error: String,
}

#[derive(Clone, Debug, Deserialize)]
struct InferenceConfigUpdateRequest {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    key_action: Option<OpenRouterKeyAction>,
    #[serde(default)]
    api_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OpenRouterKeyAction {
    Keep,
    Set,
    Clear,
}

#[derive(Clone, Debug, Serialize)]
struct EvmConfigView {
    automaton_address: Option<String>,
    inbox_contract_address: Option<String>,
    usdc_address: Option<String>,
    chain_id: u64,
    rpc_url: String,
}

#[derive(Clone, Debug, Deserialize)]
struct InboxPostRequest {
    message: String,
}

thread_local! {
    static HTTP_STATE: RefCell<Option<HttpCertificationState>> = const { RefCell::new(None) };
}

pub fn init_certification() {
    let state = build_certification_state();
    set_tree_as_certified_data(&state.tree);
    HTTP_STATE.with(|slot| {
        *slot.borrow_mut() = Some(state);
    });
}

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

pub fn handle_http_request_update(request: HttpUpdateRequest<'_>) -> HttpUpdateResponse<'static> {
    let path = match request.get_path() {
        Ok(path) => path,
        Err(_) => {
            return json_update_response(
                StatusCode::BAD_REQUEST,
                &InboxPostError {
                    ok: false,
                    error: "malformed request url".to_string(),
                },
            );
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
        (&Method::POST, "/api/inbox") => {
            let payload = parse_inbox_post_request(request.body());
            match payload {
                Ok(body) => {
                    let caller = ic_cdk::api::msg_caller().to_text();
                    match stable::post_inbox_message(body.message, caller) {
                        Ok(id) => {
                            log!(HttpLogPriority::Info, "http_inbox_posted id={}", id);
                            json_update_response(StatusCode::OK, &InboxPostSuccess { ok: true, id })
                        }
                        Err(error) => {
                            log!(
                                HttpLogPriority::Warn,
                                "http_inbox_post_rejected err={}",
                                error
                            );
                            json_update_response(
                                StatusCode::BAD_REQUEST,
                                &InboxPostError { ok: false, error },
                            )
                        }
                    }
                }
                Err(error) => {
                    log!(
                        HttpLogPriority::Warn,
                        "http_inbox_parse_error err={}",
                        error
                    );
                    json_update_response(
                        StatusCode::BAD_REQUEST,
                        &InboxPostError { ok: false, error },
                    )
                }
            }
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
            let route = stable::evm_route_state_view();
            let config = EvmConfigView {
                automaton_address: route.automaton_evm_address,
                inbox_contract_address: route.inbox_contract_address,
                usdc_address: stable::get_discovered_usdc_address(),
                chain_id: route.chain_id,
                rpc_url: stable::get_evm_rpc_url(),
            };
            json_update_response(StatusCode::OK, &config)
        }
        (&Method::GET, "/api/inference/config") => {
            let config = stable::inference_config_view();
            json_update_response(StatusCode::OK, &config)
        }
        (&Method::POST, "/api/inference/config") => {
            match parse_inference_config_request(request.body()) {
                Ok(payload) => match apply_inference_config_update(payload) {
                    Ok(_) => json_update_response(
                        StatusCode::OK,
                        &InferenceConfigSuccess {
                            ok: true,
                            config: stable::inference_config_view(),
                        },
                    ),
                    Err(error) => {
                        log!(
                            HttpLogPriority::Warn,
                            "http_inference_config_update_rejected err={}",
                            error
                        );
                        json_update_response(
                            StatusCode::BAD_REQUEST,
                            &InferenceConfigError { ok: false, error },
                        )
                    }
                },
                Err(error) => {
                    log!(
                        HttpLogPriority::Warn,
                        "http_inference_config_parse_rejected err={}",
                        error.error
                    );
                    json_update_response(StatusCode::BAD_REQUEST, &error)
                }
            }
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

fn ensure_initialized() {
    HTTP_STATE.with(|slot| {
        if slot.borrow().is_none() {
            let state = build_certification_state();
            set_tree_as_certified_data(&state.tree);
            *slot.borrow_mut() = Some(state);
        }
    });
}

fn build_certification_state() -> HttpCertificationState {
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
        upgrade_route(Method::GET, "/api/snapshot"),
        upgrade_route(Method::GET, "/api/wallet/balance"),
        upgrade_route(Method::GET, "/api/wallet/balance/sync-config"),
        upgrade_route(Method::GET, "/api/evm/config"),
        upgrade_route(Method::GET, "/api/inference/config"),
        upgrade_route(Method::POST, "/api/inference/config"),
        upgrade_route(Method::POST, "/api/conversation"),
        upgrade_route(Method::POST, "/api/inbox"),
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

fn parse_inbox_post_request(body: &[u8]) -> Result<InboxPostRequest, String> {
    if body.is_empty() {
        return Err("message body cannot be empty".to_string());
    }

    if let Ok(parsed) = serde_json::from_slice::<InboxPostRequest>(body) {
        return Ok(parsed);
    }

    let as_text = std::str::from_utf8(body).map_err(|_| "request body is not valid utf-8")?;
    let message = as_text.trim();
    if message.is_empty() {
        return Err("message body cannot be empty".to_string());
    }

    Ok(InboxPostRequest {
        message: message.to_string(),
    })
}

fn parse_inference_config_request(
    body: &[u8],
) -> Result<InferenceConfigUpdateRequest, InferenceConfigError> {
    if body.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(InferenceConfigError {
            ok: false,
            error: "inference config body cannot be empty".to_string(),
        });
    }

    serde_json::from_slice::<InferenceConfigUpdateRequest>(body).map_err(|error| {
        InferenceConfigError {
            ok: false,
            error: format!("invalid inference config payload: {error}"),
        }
    })
}

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

fn apply_inference_config_update(
    payload: InferenceConfigUpdateRequest,
) -> Result<InferenceConfigView, String> {
    let current_config = stable::inference_config_view();
    let current_provider = current_config.provider.clone();
    let openrouter_has_api_key = current_config.openrouter_has_api_key;
    let requested_provider = payload
        .provider
        .as_ref()
        .map(|raw| parse_inference_provider(raw))
        .transpose()?;

    if let Some(provider) = requested_provider.as_ref() {
        stable::set_inference_provider(provider.clone());
    }

    if let Some(raw_model) = payload.model {
        let model = raw_model.trim();
        if !model.is_empty() {
            let target_provider = requested_provider
                .clone()
                .unwrap_or_else(|| current_provider.clone());
            if target_provider == crate::domain::types::InferenceProvider::OpenRouter
                && is_ic_llm_model_alias(model)
            {
                return Err(format!(
                    "openrouter model id is invalid: {model}. use a provider model id like openai/gpt-4o-mini"
                ));
            }
            stable::set_inference_model(model.to_string())?;
        } else {
            return Err("inference model cannot be empty".to_string());
        }
    }

    let provider = requested_provider.unwrap_or(current_provider);
    match payload.key_action.unwrap_or(OpenRouterKeyAction::Keep) {
        OpenRouterKeyAction::Keep => {
            if provider == crate::domain::types::InferenceProvider::OpenRouter
                && !openrouter_has_api_key
            {
                return Err(
                    "openrouter api key is not configured; set key_action to set".to_string(),
                );
            }
        }
        OpenRouterKeyAction::Set => {
            if provider != crate::domain::types::InferenceProvider::OpenRouter {
                return Err("key action set requires openrouter provider".to_string());
            }
            let trimmed_key = payload.api_key.unwrap_or_default().trim().to_string();
            if trimmed_key.is_empty() {
                return Err("api key cannot be empty when action is set".to_string());
            }
            stable::set_openrouter_api_key(Some(trimmed_key));
        }
        OpenRouterKeyAction::Clear => {
            if provider != crate::domain::types::InferenceProvider::OpenRouter {
                return Err("key action clear requires openrouter provider".to_string());
            }
            stable::set_openrouter_api_key(None);
        }
    }

    Ok(stable::inference_config_view())
}

fn parse_inference_provider(raw: &str) -> Result<crate::domain::types::InferenceProvider, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "llm_canister" | "llm-canister" | "ic_llm" | "icllm" | "mock" => {
            Ok(crate::domain::types::InferenceProvider::IcLlm)
        }
        "openrouter" => Ok(crate::domain::types::InferenceProvider::OpenRouter),
        unsupported => Err(format!("unsupported inference provider: {unsupported}")),
    }
}

fn is_ic_llm_model_alias(model: &str) -> bool {
    matches!(
        model.trim().to_ascii_lowercase().as_str(),
        "llama3.1:8b" | "qwen3:32b" | "llama4-scout"
    )
}

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
    fn api_snapshot_query_path_requests_upgrade() {
        init_certification();

        let request = HttpRequest::get("/api/snapshot").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), Some(true));
    }

    #[test]
    fn get_wallet_balance_route_is_upgradable() {
        init_certification();

        let request = HttpRequest::get("/api/wallet/balance").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), Some(true));
    }

    #[test]
    fn get_wallet_balance_sync_config_route_is_upgradable() {
        init_certification();

        let request = HttpRequest::get("/api/wallet/balance/sync-config").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), Some(true));
    }

    #[test]
    fn get_evm_config_route_is_upgradable() {
        init_certification();

        let request = HttpRequest::get("/api/evm/config").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), Some(true));
    }

    #[test]
    fn get_evm_config_returns_expected_fields() {
        init_certification();
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

        let request: HttpUpdateRequest = HttpRequest::get("/api/evm/config").build_update();
        let response = handle_http_request_update(request);

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
    fn get_inference_config_route_is_upgradable() {
        init_certification();

        let request = HttpRequest::get("/api/inference/config").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), Some(true));
    }

    #[test]
    fn post_inference_config_route_is_upgradable() {
        init_certification();

        let request = HttpRequest::post("/api/inference/config").build();
        let response = handle_http_request(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.upgrade(), Some(true));
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
    fn inference_config_update_rejects_invalid_provider() {
        init_certification();

        let request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
            .with_headers(vec![(
                "content-type".to_string(),
                CONTENT_TYPE_JSON.to_string(),
            )])
            .with_body(br#"{"provider":"bad-provider"}"#.to_vec())
            .build_update();
        let response = handle_http_request_update(request);

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(body.get("ok"), Some(&Value::Bool(false)));
        assert_eq!(
            body.get("error").and_then(Value::as_str),
            Some("unsupported inference provider: bad-provider")
        );
    }

    #[test]
    fn inference_config_update_rejects_empty_body() {
        init_certification();

        let request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
            .with_headers(vec![(
                "content-type".to_string(),
                CONTENT_TYPE_JSON.to_string(),
            )])
            .with_body(b"   ".to_vec())
            .build_update();
        let response = handle_http_request_update(request);

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(body.get("ok"), Some(&Value::Bool(false)));
        assert_eq!(
            body.get("error").and_then(Value::as_str),
            Some("inference config body cannot be empty")
        );
    }

    #[test]
    fn inference_config_update_rejects_openrouter_key_action_without_provider() {
        init_certification();
        stable::init_storage();
        stable::set_inference_provider(crate::domain::types::InferenceProvider::IcLlm);

        let request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
            .with_headers(vec![(
                "content-type".to_string(),
                CONTENT_TYPE_JSON.to_string(),
            )])
            .with_body(
                br#"{"key_action":"set","api_key":"test-key","model":"llama3.1:8b"}"#.to_vec(),
            )
            .build_update();
        let response = handle_http_request_update(request);

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(
            body.get("error").and_then(Value::as_str),
            Some("key action set requires openrouter provider")
        );
    }

    #[test]
    fn inference_config_update_rejects_openrouter_keep_without_api_key() {
        init_certification();
        stable::init_storage();
        stable::set_inference_provider(crate::domain::types::InferenceProvider::IcLlm);
        stable::set_openrouter_api_key(None);

        let request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
            .with_headers(vec![(
                "content-type".to_string(),
                CONTENT_TYPE_JSON.to_string(),
            )])
            .with_body(
                br#"{"provider":"openrouter","model":"openai/gpt-4o-mini","key_action":"keep"}"#
                    .to_vec(),
            )
            .build_update();
        let response = handle_http_request_update(request);

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(
            body.get("error").and_then(Value::as_str),
            Some("openrouter api key is not configured; set key_action to set")
        );
    }

    #[test]
    fn inference_config_update_rejects_ic_llm_model_alias_for_openrouter() {
        init_certification();
        stable::init_storage();
        stable::set_openrouter_api_key(Some("test-key".to_string()));

        let request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
            .with_headers(vec![(
                "content-type".to_string(),
                CONTENT_TYPE_JSON.to_string(),
            )])
            .with_body(
                br#"{"provider":"openrouter","model":"qwen3:32b","key_action":"keep"}"#.to_vec(),
            )
            .build_update();
        let response = handle_http_request_update(request);

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(
            body.get("error").and_then(Value::as_str),
            Some(
                "openrouter model id is invalid: qwen3:32b. use a provider model id like openai/gpt-4o-mini"
            )
        );
    }

    #[test]
    fn inference_config_update_payload_rejects_invalid_json() {
        init_certification();

        let request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
            .with_headers(vec![(
                "content-type".to_string(),
                CONTENT_TYPE_JSON.to_string(),
            )])
            .with_body(br#"{"provider": "openrouter", "key_action": "set"}"#.to_vec())
            .build_update();
        let response = handle_http_request_update(request);

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(body.get("ok"), Some(&Value::Bool(false)));
        assert_eq!(
            body.get("error")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "api key cannot be empty when action is set"
        );
    }

    #[test]
    fn inference_config_update_reflects_viewed_state() {
        stable::init_storage();
        stable::set_inference_provider(crate::domain::types::InferenceProvider::IcLlm);
        stable::set_inference_model("llama3.1:8b".to_string()).expect("model should set");
        stable::set_openrouter_api_key(Some("test-key".to_string()));

        let request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
            .with_headers(vec![(
                "content-type".to_string(),
                CONTENT_TYPE_JSON.to_string(),
            )])
            .with_body(
                br#"{"provider":"openrouter","model":"openai/gpt-4o-mini","key_action":"keep"}"#
                    .to_vec(),
            )
            .build_update();
        let response = handle_http_request_update(request);

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = serde_json::from_slice::<Value>(response.body())
            .expect("response should decode as json");
        assert_eq!(body.get("ok"), Some(&Value::Bool(true)));
        let config = body.get("config").unwrap_or(&Value::Null);
        assert_eq!(
            config.get("provider"),
            Some(&Value::String("OpenRouter".to_string()))
        );
        assert_eq!(
            config.get("model"),
            Some(&Value::String("openai/gpt-4o-mini".to_string()))
        );
        assert!(config
            .get("openrouter_has_api_key")
            .and_then(Value::as_bool)
            .unwrap_or(false));
        assert!(config.get("openrouter_api_key").is_none());
    }
}
