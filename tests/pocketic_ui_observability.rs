#![cfg(feature = "pocketic_tests")]

use std::path::Path;

use candid::{decode_one, encode_args, CandidType, Principal};
use ic_http_certification::{HttpRequest, HttpResponse, HttpUpdateRequest, HttpUpdateResponse};
use pocket_ic::PocketIc;
use serde::Deserialize;
use serde_json::Value;

const WASM_PATHS: &[&str] = &[
    "target/wasm32-unknown-unknown/release/backend.wasm",
    "target/wasm32-unknown-unknown/release/deps/backend.wasm",
];

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct SnapshotEnvelope {
    runtime: Value,
    scheduler: Value,
    inbox_stats: Value,
    inbox_messages: Vec<Value>,
    recent_turns: Vec<Value>,
    recent_transitions: Vec<Value>,
    recent_jobs: Vec<Value>,
}

fn assert_wasm_artifact_present() -> Vec<u8> {
    for path in WASM_PATHS {
        if Path::new(path).exists() {
            return std::fs::read(path).unwrap_or_else(|error| {
                panic!("cannot read PocketIC test artifact {path}: {error}");
            });
        }
    }
    panic!(
        "build artifact not found at any expected path ({:?}); run `icp build` before PocketIC tests",
        WASM_PATHS
    );
}

fn with_backend_canister() -> (PocketIc, Principal) {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    let wasm = assert_wasm_artifact_present();

    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    (pic, canister_id)
}

fn call_query<T>(pic: &PocketIc, canister_id: Principal, method: &str, payload: Vec<u8>) -> T
where
    T: for<'de> Deserialize<'de> + CandidType,
{
    let response = pic
        .query_call(canister_id, Principal::anonymous(), method, payload)
        .unwrap_or_else(|error| panic!("query call {method} failed: {error:?}"));
    decode_one(&response)
        .unwrap_or_else(|error| panic!("failed decoding {method} response: {error:?}"))
}

fn call_http_update<'a>(
    pic: &PocketIc,
    canister_id: Principal,
    request: HttpUpdateRequest<'a>,
) -> HttpUpdateResponse<'a> {
    let payload = encode_args((request,))
        .unwrap_or_else(|error| panic!("failed to encode http_request_update args: {error}"));
    let response = pic
        .update_call(
            canister_id,
            Principal::anonymous(),
            "http_request_update",
            payload,
        )
        .unwrap_or_else(|error| panic!("http update call failed: {error:?}"));
    decode_one(&response)
        .unwrap_or_else(|error| panic!("failed decoding http_request_update response: {error:?}"))
}

fn parse_json_response(response: &HttpUpdateResponse<'_>, context: &str) -> Value {
    serde_json::from_slice(response.body())
        .unwrap_or_else(|error| panic!("{context} should return json: {error}"))
}

#[test]
fn serves_certified_root_and_supports_ui_observability_flow() {
    let (pic, canister_id) = with_backend_canister();

    let root_request = HttpRequest::get("/").build();
    let root_payload = encode_args((root_request,))
        .unwrap_or_else(|error| panic!("failed to encode http_request args: {error}"));
    let root_response: HttpResponse = call_query(&pic, canister_id, "http_request", root_payload);

    assert_eq!(root_response.status_code().as_u16(), 200);
    let root_body = String::from_utf8_lossy(root_response.body());
    assert!(
        root_body.contains("Autonomous Automaton"),
        "root html should contain the UI title"
    );
    assert!(
        root_response
            .headers()
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("IC-Certificate")),
        "root response should be certified"
    );

    let post_payload = serde_json::to_vec(&serde_json::json!({
        "message": "hello from pocketic ui flow"
    }))
    .expect("failed to serialize inbox body");
    let post_request: HttpUpdateRequest = HttpRequest::post("/api/inbox")
        .with_headers(vec![(
            "content-type".to_string(),
            "application/json".to_string(),
        )])
        .with_body(post_payload)
        .build_update();
    let post_response = call_http_update(&pic, canister_id, post_request);
    assert_eq!(post_response.status_code().as_u16(), 200);

    let post_json: Value =
        serde_json::from_slice(post_response.body()).expect("post /api/inbox should return json");
    let posted_id = post_json
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        posted_id.starts_with("inbox:"),
        "post /api/inbox should return an inbox id"
    );

    let snapshot_request: HttpUpdateRequest = HttpRequest::get("/api/snapshot").build_update();
    let snapshot_response = call_http_update(&pic, canister_id, snapshot_request);
    assert_eq!(snapshot_response.status_code().as_u16(), 200);

    let snapshot: SnapshotEnvelope = serde_json::from_slice(snapshot_response.body())
        .expect("snapshot should decode to structured json");
    let total_messages = snapshot
        .inbox_stats
        .get("total_messages")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    assert!(
        total_messages >= 1,
        "snapshot should include at least one inbox message after posting"
    );
    assert!(
        snapshot
            .inbox_messages
            .iter()
            .any(|msg| msg.get("id").and_then(Value::as_str) == Some(posted_id)),
        "snapshot should include the posted message id"
    );
}

#[test]
fn supports_inference_config_http_flow() {
    let (pic, canister_id) = with_backend_canister();

    let initial_response = call_http_update(
        &pic,
        canister_id,
        HttpRequest::get("/api/inference/config").build_update(),
    );
    assert_eq!(initial_response.status_code().as_u16(), 200);
    let initial_json = parse_json_response(&initial_response, "GET /api/inference/config");
    assert_eq!(
        initial_json
            .get("provider")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "Mock"
    );
    assert!(initial_json.get("openrouter_api_key").is_none());
    assert_eq!(
        initial_json.get("openrouter_has_api_key"),
        Some(&Value::Bool(false))
    );

    let set_request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
        .with_headers(vec![(
            "content-type".to_string(),
            "application/json".to_string(),
        )])
        .with_body(
            serde_json::json!({
                "provider": "openrouter",
                "model": "qwen3:32b",
                "key_action": "set",
                "api_key": "test-key",
            })
            .to_string()
            .into_bytes(),
        )
        .build_update();
    let set_response = call_http_update(&pic, canister_id, set_request);
    assert_eq!(set_response.status_code().as_u16(), 200);
    let set_json = parse_json_response(&set_response, "POST /api/inference/config set");
    assert_eq!(set_json.get("ok"), Some(&Value::Bool(true)));
    let set_config = &set_json["config"];
    assert_eq!(
        set_config.get("provider").and_then(Value::as_str),
        Some("OpenRouter")
    );
    assert_eq!(
        set_config.get("model").and_then(Value::as_str),
        Some("qwen3:32b")
    );
    assert_eq!(
        set_config
            .get("openrouter_has_api_key")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(set_config.get("openrouter_api_key").is_none());

    let reread_response = call_http_update(
        &pic,
        canister_id,
        HttpRequest::get("/api/inference/config").build_update(),
    );
    assert_eq!(reread_response.status_code().as_u16(), 200);
    let reread_json = parse_json_response(&reread_response, "GET /api/inference/config");
    assert_eq!(
        reread_json.get("provider").and_then(Value::as_str),
        Some("OpenRouter")
    );
    assert_eq!(
        reread_json
            .get("openrouter_has_api_key")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(reread_json.get("openrouter_api_key").is_none());

    let clear_request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
        .with_headers(vec![(
            "content-type".to_string(),
            "application/json".to_string(),
        )])
        .with_body(
            serde_json::json!({
                "provider": "llm_canister",
                "model": "llama3.1:8b",
                "key_action": "clear",
            })
            .to_string()
            .into_bytes(),
        )
        .build_update();
    let clear_response = call_http_update(&pic, canister_id, clear_request);
    assert_eq!(clear_response.status_code().as_u16(), 200);
    let clear_json = parse_json_response(&clear_response, "POST /api/inference/config clear");
    let clear_config = &clear_json["config"];
    assert_eq!(
        clear_config.get("provider").and_then(Value::as_str),
        Some("IcLlm")
    );
    assert_eq!(
        clear_config.get("model").and_then(Value::as_str),
        Some("llama3.1:8b")
    );
    assert_eq!(
        clear_config
            .get("openrouter_has_api_key")
            .and_then(Value::as_bool),
        Some(false)
    );
}
