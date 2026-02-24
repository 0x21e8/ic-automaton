#![cfg(feature = "pocketic_tests")]

use std::path::Path;
use std::time::Duration;

use alloy_primitives::keccak256;
use candid::{decode_one, encode_args, CandidType, Principal};
use ic_http_certification::{HttpRequest, HttpResponse, HttpUpdateRequest, HttpUpdateResponse};
use pocket_ic::common::rest::{
    CanisterHttpReply, CanisterHttpRequest, CanisterHttpResponse, MockCanisterHttpResponse,
};
use pocket_ic::PocketIc;
use serde::Deserialize;
use serde_json::{json, Value};

const WASM_PATHS: &[&str] = &[
    "target/wasm32-unknown-unknown/release/backend.wasm",
    "target/wasm32-unknown-unknown/release/deps/backend.wasm",
];
const INBOX_MESSAGE_QUEUED_EVENT_SIGNATURE: &str =
    "MessageQueued(address,uint64,address,string,uint256,uint256)";

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct SnapshotEnvelope {
    runtime: Value,
    scheduler: Value,
    storage_growth: Value,
    cycles: Value,
    inbox_stats: Value,
    inbox_messages: Vec<Value>,
    outbox_stats: Value,
    outbox_messages: Vec<Value>,
    prompt_layers: Vec<Value>,
    conversation_summaries: Vec<Value>,
    recent_turns: Vec<Value>,
    recent_transitions: Vec<Value>,
    recent_jobs: Vec<Value>,
}

#[derive(CandidType, Clone, Debug)]
struct InitArgs {
    ecdsa_key_name: String,
    inbox_contract_address: Option<String>,
    evm_chain_id: Option<u64>,
}

#[derive(CandidType, Clone, Copy, Debug)]
enum InferenceProvider {
    IcLlm,
}

#[allow(dead_code)]
#[derive(CandidType, Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum TaskKind {
    AgentTurn,
    PollInbox,
    CheckCycles,
    TopUpCycles,
    Reconcile,
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum JobStatus {
    Pending,
    InFlight,
    Succeeded,
    Failed,
    TimedOut,
    Skipped,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
struct ObservedJob {
    kind: TaskKind,
    status: JobStatus,
    created_at_ns: u64,
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
    let init_args = encode_args((InitArgs {
        ecdsa_key_name: "dfx_test_key".to_string(),
        inbox_contract_address: None,
        evm_chain_id: None,
    },))
    .expect("failed to encode init args");

    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, init_args, None);
    set_inference_provider(&pic, canister_id, InferenceProvider::IcLlm);
    set_inference_model(&pic, canister_id, "deterministic-local");

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

fn call_update<T>(pic: &PocketIc, canister_id: Principal, method: &str, payload: Vec<u8>) -> T
where
    T: for<'de> Deserialize<'de> + CandidType,
{
    let response = pic
        .update_call(canister_id, Principal::anonymous(), method, payload)
        .unwrap_or_else(|error| panic!("update call {method} failed: {error:?}"));
    decode_one(&response)
        .unwrap_or_else(|error| panic!("failed decoding {method} response: {error:?}"))
}

fn set_evm_rpc_url(pic: &PocketIc, canister_id: Principal, url: &str) {
    let payload = encode_args((url.to_string(),)).expect("failed to encode set_evm_rpc_url");
    let result: Result<String, String> = call_update(pic, canister_id, "set_evm_rpc_url", payload);
    assert!(result.is_ok(), "set_evm_rpc_url failed: {result:?}");
}

fn set_automaton_evm_address_admin(pic: &PocketIc, canister_id: Principal, address: &str) {
    let payload = encode_args((Some(address.to_string()),))
        .expect("failed to encode set_automaton_evm_address_admin");
    let result: Result<Option<String>, String> =
        call_update(pic, canister_id, "set_automaton_evm_address_admin", payload);
    assert!(
        result.is_ok(),
        "set_automaton_evm_address_admin failed: {result:?}"
    );
}

fn set_inbox_contract_address_admin(pic: &PocketIc, canister_id: Principal, address: &str) {
    let payload = encode_args((Some(address.to_string()),))
        .expect("failed to encode set_inbox_contract_address_admin");
    let result: Result<Option<String>, String> = call_update(
        pic,
        canister_id,
        "set_inbox_contract_address_admin",
        payload,
    );
    assert!(
        result.is_ok(),
        "set_inbox_contract_address_admin failed: {result:?}"
    );
}

fn set_inference_provider(pic: &PocketIc, canister_id: Principal, provider: InferenceProvider) {
    let payload = encode_args((provider,)).expect("failed to encode set_inference_provider");
    let _: String = call_update(pic, canister_id, "set_inference_provider", payload);
}

fn set_inference_model(pic: &PocketIc, canister_id: Principal, model: &str) {
    let payload = encode_args((model.to_string(),)).expect("failed to encode set_inference_model");
    let result: Result<String, String> =
        call_update(pic, canister_id, "set_inference_model", payload);
    assert!(result.is_ok(), "set_inference_model failed: {result:?}");
}

fn set_task_interval_secs(pic: &PocketIc, canister_id: Principal, kind: TaskKind, interval: u64) {
    let payload = encode_args((kind, interval)).expect("failed to encode set_task_interval_secs");
    let result: Result<String, String> =
        call_update(pic, canister_id, "set_task_interval_secs", payload);
    assert!(result.is_ok(), "set_task_interval_secs failed: {result:?}");
}

fn list_scheduler_jobs(pic: &PocketIc, canister_id: Principal) -> Vec<ObservedJob> {
    call_query(
        pic,
        canister_id,
        "list_scheduler_jobs",
        encode_args((200u32,)).expect("failed to encode list_scheduler_jobs"),
    )
}

fn latest_poll_job(jobs: &[ObservedJob]) -> Option<&ObservedJob> {
    jobs.iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .max_by_key(|job| job.created_at_ns)
}

fn response_word_from_address(address: &str) -> String {
    let suffix = address.trim_start_matches("0x").to_ascii_lowercase();
    format!("0x{suffix:0>64}")
}

fn response_word_from_quantity(quantity_hex: &str) -> String {
    let suffix = quantity_hex.trim_start_matches("0x").to_ascii_lowercase();
    format!("0x{suffix:0>64}")
}

fn message_queued_topic0() -> String {
    let hash = keccak256(INBOX_MESSAGE_QUEUED_EVENT_SIGNATURE.as_bytes());
    format!("0x{}", hex::encode(hash.as_slice()))
}

fn address_to_topic(address: &str) -> String {
    let normalized = address.trim().to_ascii_lowercase();
    let without_prefix = normalized.trim_start_matches("0x");
    format!("0x{:0>64}", without_prefix)
}

fn encode_u256_word(value: u128) -> String {
    format!("{value:064x}")
}

fn encode_message_queued_payload(
    sender: &str,
    message: &str,
    usdc_amount: u128,
    eth_amount: u128,
) -> String {
    let sender = sender.trim().to_ascii_lowercase();
    let sender_hex = sender.trim_start_matches("0x");
    assert_eq!(sender_hex.len(), 40, "sender must be a 20-byte hex address");

    let message_hex = hex::encode(message.as_bytes());
    let padded_message_hex = if message_hex.len().is_multiple_of(64) {
        message_hex.clone()
    } else {
        let padding = "0".repeat(64 - (message_hex.len() % 64));
        format!("{message_hex}{padding}")
    };

    format!(
        "0x{:0>64}{}{}{}{}{}",
        sender_hex,
        encode_u256_word(128),
        encode_u256_word(usdc_amount),
        encode_u256_word(eth_amount),
        encode_u256_word(message.len() as u128),
        padded_message_hex,
    )
}

fn rpc_log(
    block_number: u64,
    log_index: u64,
    tx_hash: &str,
    contract_address: &str,
    topic1: &str,
    data: &str,
) -> Value {
    json!({
        "address": contract_address,
        "topics": [message_queued_topic0(), topic1],
        "data": data,
        "blockNumber": format!("0x{block_number:x}"),
        "logIndex": format!("0x{log_index:x}"),
        "transactionHash": tx_hash,
    })
}

fn wallet_sync_rpc_response(
    request: &CanisterHttpRequest,
    latest_block: u64,
    logs: &[Value],
) -> CanisterHttpResponse {
    let request_json: Value = serde_json::from_slice(&request.body)
        .unwrap_or_else(|error| panic!("failed to parse canister http request body: {error}"));
    let method = request_json
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let response = match method {
        "eth_blockNumber" => json!({
            "jsonrpc":"2.0",
            "id":1,
            "result": format!("0x{latest_block:x}"),
        }),
        "eth_getLogs" => json!({
            "jsonrpc":"2.0",
            "id":1,
            "result":logs,
        }),
        "eth_getBalance" => json!({
            "jsonrpc":"2.0",
            "id":1,
            "result":"0x64",
        }),
        "eth_call" => {
            let calldata = request_json
                .get("params")
                .and_then(Value::as_array)
                .and_then(|params| params.first())
                .and_then(|tx| tx.get("data"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let result = if calldata.len() <= 10 {
                response_word_from_address("0x3333333333333333333333333333333333333333")
            } else {
                response_word_from_quantity("0x2a")
            };
            json!({
                "jsonrpc":"2.0",
                "id":1,
                "result":result,
            })
        }
        unsupported => panic!("unsupported canister http method in test: {unsupported}"),
    };

    CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&response)
            .unwrap_or_else(|error| panic!("failed to encode rpc response: {error}")),
    })
}

fn flush_wallet_sync_http(pic: &PocketIc) {
    for _ in 0..20 {
        let pending_http = pic.get_canister_http();
        if pending_http.is_empty() {
            pic.tick();
            continue;
        }
        for request in pending_http {
            pic.mock_canister_http_response(MockCanisterHttpResponse {
                subnet_id: request.subnet_id,
                request_id: request.request_id,
                response: wallet_sync_rpc_response(&request, 10, &[]),
                additional_responses: vec![],
            });
        }
        pic.tick();
    }
}

fn drive_due_poll_inbox_with_logs(pic: &PocketIc, canister_id: Principal, logs: &[Value]) {
    let before_poll_jobs = list_scheduler_jobs(pic, canister_id)
        .into_iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .count();

    pic.advance_time(Duration::from_secs(31));
    pic.tick();

    for _ in 0..36 {
        let pending_http = pic.get_canister_http();
        if !pending_http.is_empty() {
            for request in pending_http {
                pic.mock_canister_http_response(MockCanisterHttpResponse {
                    subnet_id: request.subnet_id,
                    request_id: request.request_id,
                    response: wallet_sync_rpc_response(&request, 10, logs),
                    additional_responses: vec![],
                });
            }
        }

        pic.tick();

        let jobs = list_scheduler_jobs(pic, canister_id);
        let poll_jobs = jobs
            .iter()
            .filter(|job| job.kind == TaskKind::PollInbox)
            .count();
        let latest_terminal = latest_poll_job(&jobs)
            .map(|job| {
                matches!(
                    job.status,
                    JobStatus::Succeeded
                        | JobStatus::Failed
                        | JobStatus::TimedOut
                        | JobStatus::Skipped
                )
            })
            .unwrap_or(false);
        if poll_jobs > before_poll_jobs && latest_terminal && pic.get_canister_http().is_empty() {
            return;
        }
    }

    panic!("poll inbox did not complete with mocked http responses");
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
fn serves_certified_root_and_supports_ui_observability_continuation_flow() {
    let (pic, canister_id) = with_backend_canister();
    set_task_interval_secs(&pic, canister_id, TaskKind::AgentTurn, 30);
    set_task_interval_secs(&pic, canister_id, TaskKind::PollInbox, 30);
    set_evm_rpc_url(&pic, canister_id, "https://mainnet.base.org");
    let automaton_address = "0x1111111111111111111111111111111111111111";
    let inbox_contract_address = "0x2222222222222222222222222222222222222222";
    set_automaton_evm_address_admin(&pic, canister_id, automaton_address);
    set_inbox_contract_address_admin(&pic, canister_id, inbox_contract_address);

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
        root_body.contains("Prompt Layers"),
        "root html should expose prompt layer panel"
    );
    assert!(
        root_body.contains("Conversations"),
        "root html should expose conversation panel"
    );
    assert!(
        root_response
            .headers()
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("IC-Certificate")),
        "root response should be certified"
    );

    let post_request: HttpUpdateRequest = HttpRequest::post("/api/inbox")
        .with_headers(vec![(
            "content-type".to_string(),
            "application/json".to_string(),
        )])
        .with_body(br#"{"message":"hello from pocketic ui flow"}"#.to_vec())
        .build_update();
    let post_response = call_http_update(&pic, canister_id, post_request);
    assert_eq!(post_response.status_code().as_u16(), 404);

    let post_json: Value =
        serde_json::from_slice(post_response.body()).expect("post /api/inbox should return json");
    assert_eq!(post_json.get("ok"), Some(&Value::Bool(false)));
    assert_eq!(
        post_json.get("error").and_then(Value::as_str),
        Some("not found")
    );

    let topic1 = address_to_topic(automaton_address);
    let payload = encode_message_queued_payload(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "hello from pocketic ui flow",
        0,
        0,
    );
    let logs = vec![rpc_log(
        2,
        0,
        "0x1111111111111111111111111111111111111111111111111111111111111111",
        inbox_contract_address,
        &topic1,
        &payload,
    )];
    drive_due_poll_inbox_with_logs(&pic, canister_id, &logs);

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
    let tracked_entries = snapshot
        .storage_growth
        .get("tracked_entry_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let cycle_total = snapshot
        .cycles
        .get("total_cycles")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let cycle_liquid = snapshot
        .cycles
        .get("liquid_cycles")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    assert!(
        cycle_total >= cycle_liquid,
        "cycle telemetry should include total and liquid balances"
    );
    assert!(
        total_messages >= 1,
        "snapshot should include at least one inbox message after posting"
    );
    assert!(
        tracked_entries >= 1,
        "snapshot should expose tracked storage entry trend metrics"
    );
    assert!(
        snapshot.inbox_messages.iter().any(|msg| {
            msg.get("body")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .contains("hello from pocketic ui flow")
        }),
        "snapshot should include the polled inbox message"
    );
    assert_eq!(
        snapshot.prompt_layers.len(),
        10,
        "snapshot should include all prompt layers"
    );

    for _ in 0..6 {
        pic.advance_time(Duration::from_secs(31));
        pic.tick();
        flush_wallet_sync_http(&pic);
    }

    let after_turn_response = call_http_update(
        &pic,
        canister_id,
        HttpRequest::get("/api/snapshot").build_update(),
    );
    assert_eq!(after_turn_response.status_code().as_u16(), 200);
    let after_turn_snapshot: SnapshotEnvelope = serde_json::from_slice(after_turn_response.body())
        .expect("post-turn snapshot should decode");
    let outbox_total = after_turn_snapshot
        .outbox_stats
        .get("total_messages")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    assert!(outbox_total >= 1, "snapshot should include outbox replies");
    assert!(
        after_turn_snapshot.outbox_messages.iter().any(|msg| msg
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .starts_with("outbox:")),
        "snapshot should include at least one outbox record id"
    );
    assert!(
        after_turn_snapshot.outbox_messages.iter().any(|msg| {
            msg.get("body")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .contains("deterministic continuation")
        }),
        "outbox body should reflect continuation-stage model response after tool execution"
    );
    assert!(
        !after_turn_snapshot.conversation_summaries.is_empty(),
        "snapshot should include conversation summaries after agent replies"
    );

    let sender = after_turn_snapshot
        .conversation_summaries
        .first()
        .and_then(|entry| entry.get("sender"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    assert!(
        sender.starts_with("2vxsx-fae") || sender.starts_with("0x"),
        "conversation sender should be present"
    );

    let conversation_request: HttpUpdateRequest = HttpRequest::post("/api/conversation")
        .with_headers(vec![(
            "content-type".to_string(),
            "application/json".to_string(),
        )])
        .with_body(
            serde_json::json!({
                "sender": sender,
            })
            .to_string()
            .into_bytes(),
        )
        .build_update();
    let conversation_response = call_http_update(&pic, canister_id, conversation_request);
    assert_eq!(conversation_response.status_code().as_u16(), 200);
    let conversation_json: Value = serde_json::from_slice(conversation_response.body())
        .expect("conversation endpoint should return json");
    assert_eq!(
        conversation_json
            .get("entries")
            .and_then(Value::as_array)
            .map(|entries| !entries.is_empty()),
        Some(true),
        "conversation endpoint should return at least one exchange"
    );
}

#[test]
fn inference_config_http_route_is_read_only() {
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
        "IcLlm"
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
                "model": "openai/gpt-4o-mini",
                "key_action": "set",
                "api_key": "test-key",
            })
            .to_string()
            .into_bytes(),
        )
        .build_update();
    let set_response = call_http_update(&pic, canister_id, set_request);
    assert_eq!(set_response.status_code().as_u16(), 404);
    let set_json = parse_json_response(&set_response, "POST /api/inference/config set");
    assert_eq!(set_json.get("ok"), Some(&Value::Bool(false)));
    assert_eq!(
        set_json.get("error").and_then(Value::as_str),
        Some("not found")
    );

    let invalid_request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
        .with_headers(vec![(
            "content-type".to_string(),
            "application/json".to_string(),
        )])
        .with_body(
            serde_json::json!({
                "provider": "bad-provider",
            })
            .to_string()
            .into_bytes(),
        )
        .build_update();
    let invalid_response = call_http_update(&pic, canister_id, invalid_request);
    assert_eq!(invalid_response.status_code().as_u16(), 404);
    let invalid_json = parse_json_response(&invalid_response, "POST /api/inference/config invalid");
    assert_eq!(invalid_json.get("ok"), Some(&Value::Bool(false)));
    assert_eq!(
        invalid_json
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "not found"
    );

    let reread_response = call_http_update(
        &pic,
        canister_id,
        HttpRequest::get("/api/inference/config").build_update(),
    );
    assert_eq!(reread_response.status_code().as_u16(), 200);
    let reread_json = parse_json_response(&reread_response, "GET /api/inference/config");
    assert_eq!(
        reread_json.get("provider").and_then(Value::as_str),
        Some("IcLlm")
    );
    assert_eq!(
        reread_json
            .get("openrouter_has_api_key")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(reread_json.get("openrouter_api_key").is_none());

    let clear_openrouter_request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
        .with_headers(vec![(
            "content-type".to_string(),
            "application/json".to_string(),
        )])
        .with_body(
            serde_json::json!({
                "provider": "openrouter",
                "key_action": "clear",
                "model": "openai/gpt-4o-mini",
            })
            .to_string()
            .into_bytes(),
        )
        .build_update();
    let clear_openrouter_response = call_http_update(&pic, canister_id, clear_openrouter_request);
    assert_eq!(clear_openrouter_response.status_code().as_u16(), 404);
    let clear_openrouter_json = parse_json_response(
        &clear_openrouter_response,
        "POST /api/inference/config clear openrouter",
    );
    assert_eq!(
        clear_openrouter_json.get("error").and_then(Value::as_str),
        Some("not found")
    );

    let switch_request: HttpUpdateRequest = HttpRequest::post("/api/inference/config")
        .with_headers(vec![(
            "content-type".to_string(),
            "application/json".to_string(),
        )])
        .with_body(
            serde_json::json!({
                "provider": "llm_canister",
                "model": "llama3.1:8b",
            })
            .to_string()
            .into_bytes(),
        )
        .build_update();
    let switch_response = call_http_update(&pic, canister_id, switch_request);
    assert_eq!(switch_response.status_code().as_u16(), 404);
    let switch_json = parse_json_response(
        &switch_response,
        "POST /api/inference/config switch provider",
    );
    assert_eq!(
        switch_json.get("error").and_then(Value::as_str),
        Some("not found")
    );
}
