#![cfg(feature = "pocketic_tests")]

use std::path::Path;
use std::time::Duration;

use candid::{decode_one, encode_args, CandidType, Principal};
use ic_http_certification::{HttpRequest, HttpUpdateRequest, HttpUpdateResponse};
use pocket_ic::common::rest::{
    CanisterHttpReject, CanisterHttpReply, CanisterHttpRequest, CanisterHttpResponse,
    MockCanisterHttpResponse,
};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const WASM_PATHS: &[&str] = &[
    "target/wasm32-unknown-unknown/release/backend.wasm",
    "target/wasm32-unknown-unknown/release/deps/backend.wasm",
];

const AUTOMATON_ADDRESS: &str = "0x1111111111111111111111111111111111111111";
const INBOX_CONTRACT_ADDRESS: &str = "0x2222222222222222222222222222222222222222";
const USDC_CONTRACT_ADDRESS: &str = "0x3333333333333333333333333333333333333333";
const ETH_BALANCE_WEI_HEX: &str = "0x64";
const USDC_BALANCE_RAW_HEX: &str = "0x2a";

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct InitArgs {
    ecdsa_key_name: String,
    inbox_contract_address: Option<String>,
    evm_chain_id: Option<u64>,
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
enum InferenceProvider {
    IcLlm,
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
enum TaskKind {
    AgentTurn,
    PollInbox,
    CheckCycles,
    Reconcile,
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
enum JobStatus {
    Pending,
    InFlight,
    Succeeded,
    Failed,
    TimedOut,
    Skipped,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct ObservedJob {
    id: String,
    kind: TaskKind,
    status: JobStatus,
    created_at_ns: u64,
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Default)]
enum WalletBalanceStatus {
    #[default]
    Unknown,
    Fresh,
    Stale,
    Error,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct WalletBalanceTelemetryView {
    eth_balance_wei_hex: Option<String>,
    usdc_balance_raw_hex: Option<String>,
    usdc_decimals: u8,
    usdc_contract_address: Option<String>,
    last_synced_at_ns: Option<u64>,
    last_synced_block: Option<u64>,
    last_error: Option<String>,
    age_secs: Option<u64>,
    freshness_window_secs: u64,
    is_stale: bool,
    status: WalletBalanceStatus,
    bootstrap_pending: bool,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct WalletBalanceSyncConfigView {
    enabled: bool,
    normal_interval_secs: u64,
    low_cycles_interval_secs: u64,
    freshness_window_secs: u64,
    max_response_bytes: u64,
    discover_usdc_via_inbox: bool,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct OutboxStats {
    total_messages: u64,
}

#[derive(Clone, Copy, Debug)]
enum WalletRpcMode {
    Success,
    FailWalletSync,
    RejectOversizedUntilTuned,
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
        evm_chain_id: Some(8453),
    },))
    .expect("failed to encode init args");

    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, init_args, None);
    set_inference_provider(&pic, canister_id, InferenceProvider::IcLlm);
    set_inference_model(&pic, canister_id, "deterministic-local");

    (pic, canister_id)
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

fn set_task_enabled(pic: &PocketIc, canister_id: Principal, kind: TaskKind, enabled: bool) {
    let payload = encode_args((kind, enabled)).expect("failed to encode set_task_enabled");
    let _: String = call_update(pic, canister_id, "set_task_enabled", payload);
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

fn set_evm_rpc_url(pic: &PocketIc, canister_id: Principal, url: &str) {
    let payload = encode_args((url.to_string(),)).expect("failed to encode set_evm_rpc_url");
    let result: Result<String, String> = call_update(pic, canister_id, "set_evm_rpc_url", payload);
    assert!(result.is_ok(), "set_evm_rpc_url failed: {result:?}");
}

fn set_automaton_evm_address_admin(pic: &PocketIc, canister_id: Principal, address: &str) {
    let payload = encode_args((Some(address.to_string()),)).expect("failed to encode address");
    let result: Result<Option<String>, String> =
        call_update(pic, canister_id, "set_automaton_evm_address_admin", payload);
    assert!(
        result.is_ok(),
        "set_automaton_evm_address_admin failed: {result:?}"
    );
}

fn set_inbox_contract_address_admin(pic: &PocketIc, canister_id: Principal, address: &str) {
    let payload = encode_args((Some(address.to_string()),)).expect("failed to encode address");
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

fn post_inbox_message(pic: &PocketIc, canister_id: Principal, message: &str) {
    let payload = encode_args((message.to_string(),)).expect("failed to encode post_inbox_message");
    let result: Result<String, String> =
        call_update(pic, canister_id, "post_inbox_message", payload);
    assert!(result.is_ok(), "post_inbox_message failed: {result:?}");
}

fn list_scheduler_jobs(pic: &PocketIc, canister_id: Principal) -> Vec<ObservedJob> {
    call_query(
        pic,
        canister_id,
        "list_scheduler_jobs",
        encode_args((200u32,)).expect("failed to encode list_scheduler_jobs"),
    )
}

fn get_outbox_stats(pic: &PocketIc, canister_id: Principal) -> OutboxStats {
    call_query(
        pic,
        canister_id,
        "get_outbox_stats",
        encode_args(()).expect("failed to encode get_outbox_stats"),
    )
}

fn get_wallet_balance_telemetry(
    pic: &PocketIc,
    canister_id: Principal,
) -> WalletBalanceTelemetryView {
    call_query(
        pic,
        canister_id,
        "get_wallet_balance_telemetry",
        encode_args(()).expect("failed to encode get_wallet_balance_telemetry"),
    )
}

fn get_wallet_balance_sync_config(
    pic: &PocketIc,
    canister_id: Principal,
) -> WalletBalanceSyncConfigView {
    call_query(
        pic,
        canister_id,
        "get_wallet_balance_sync_config",
        encode_args(()).expect("failed to encode get_wallet_balance_sync_config"),
    )
}

fn configure_task_set(
    pic: &PocketIc,
    canister_id: Principal,
    enable_agent_turn: bool,
    enable_poll_inbox: bool,
    interval_secs: u64,
) {
    for kind in [
        TaskKind::AgentTurn,
        TaskKind::PollInbox,
        TaskKind::CheckCycles,
        TaskKind::Reconcile,
    ] {
        set_task_enabled(pic, canister_id, kind, false);
        set_task_interval_secs(pic, canister_id, kind, interval_secs);
    }
    set_task_enabled(pic, canister_id, TaskKind::AgentTurn, enable_agent_turn);
    set_task_enabled(pic, canister_id, TaskKind::PollInbox, enable_poll_inbox);
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

fn decode_rpc_request(request: &CanisterHttpRequest) -> (String, Value) {
    let body: Value = serde_json::from_slice(&request.body)
        .unwrap_or_else(|error| panic!("failed to decode canister http request: {error}"));
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    (method, body)
}

fn wallet_rpc_response(
    request: &CanisterHttpRequest,
    mode: WalletRpcMode,
    latest_block: u64,
) -> CanisterHttpResponse {
    let (method, body) = decode_rpc_request(request);
    let max_response_bytes = request.max_response_bytes.unwrap_or_default();

    let fail_wallet_sync = matches!(mode, WalletRpcMode::FailWalletSync)
        && matches!(method.as_str(), "eth_getBalance" | "eth_call");
    if fail_wallet_sync {
        return CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 500,
            headers: vec![],
            body: b"{}".to_vec(),
        });
    }

    let reject_oversized = matches!(mode, WalletRpcMode::RejectOversizedUntilTuned)
        && matches!(method.as_str(), "eth_getBalance" | "eth_call")
        && max_response_bytes <= 256;
    if reject_oversized {
        return CanisterHttpResponse::CanisterHttpReject(CanisterHttpReject {
            reject_code: 1,
            message: "Http body exceeds size limit of 256 bytes.".to_string(),
        });
    }

    let response_body = match method.as_str() {
        "eth_blockNumber" => json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{latest_block:x}"),
        }),
        "eth_getLogs" => json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [],
        }),
        "eth_getBalance" => json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": ETH_BALANCE_WEI_HEX,
        }),
        "eth_call" => {
            let calldata = body
                .get("params")
                .and_then(Value::as_array)
                .and_then(|params| params.first())
                .and_then(|first| first.get("data"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let result = if calldata.len() <= 10 {
                response_word_from_address(USDC_CONTRACT_ADDRESS)
            } else {
                response_word_from_quantity(USDC_BALANCE_RAW_HEX)
            };
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": result,
            })
        }
        unsupported => panic!("unsupported canister http method in wallet test: {unsupported}"),
    };

    CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&response_body)
            .unwrap_or_else(|error| panic!("failed to encode mock rpc response: {error}")),
    })
}

fn drive_due_poll_inbox_with_wallet_rpc_mocks(
    pic: &PocketIc,
    canister_id: Principal,
    mode: WalletRpcMode,
) {
    let before_poll_jobs = list_scheduler_jobs(pic, canister_id)
        .into_iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .count();

    pic.tick();

    for _ in 0..36 {
        let pending_http = pic.get_canister_http();
        if !pending_http.is_empty() {
            for request in pending_http {
                pic.mock_canister_http_response(MockCanisterHttpResponse {
                    subnet_id: request.subnet_id,
                    request_id: request.request_id,
                    response: wallet_rpc_response(&request, mode, 10),
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

    panic!("poll inbox did not complete with wallet rpc mocks within expected ticks");
}

fn advance_and_run_due_poll_inbox(pic: &PocketIc, canister_id: Principal, mode: WalletRpcMode) {
    pic.advance_time(Duration::from_secs(31));
    drive_due_poll_inbox_with_wallet_rpc_mocks(pic, canister_id, mode);
}

fn wait_for_outbox_messages(pic: &PocketIc, canister_id: Principal, at_least: u64) {
    for _ in 0..20 {
        if get_outbox_stats(pic, canister_id).total_messages >= at_least {
            return;
        }
        pic.advance_time(Duration::from_secs(31));
        pic.tick();
    }

    panic!("outbox did not reach expected count {at_least}");
}

#[test]
fn bootstrap_gate_blocks_first_inference_until_wallet_sync_succeeds() {
    let (pic, canister_id) = with_backend_canister();
    configure_task_set(&pic, canister_id, true, true, 30);
    set_evm_rpc_url(&pic, canister_id, "https://mainnet.base.org");
    set_automaton_evm_address_admin(&pic, canister_id, AUTOMATON_ADDRESS);
    set_inbox_contract_address_admin(&pic, canister_id, INBOX_CONTRACT_ADDRESS);
    post_inbox_message(
        &pic,
        canister_id,
        "bootstrap gate must block agent turn before first wallet sync",
    );

    advance_and_run_due_poll_inbox(&pic, canister_id, WalletRpcMode::FailWalletSync);

    let failed_sync = get_wallet_balance_telemetry(&pic, canister_id);
    assert!(failed_sync.bootstrap_pending);
    assert!(failed_sync.last_synced_at_ns.is_none());
    assert!(failed_sync.last_error.is_some());
    assert_eq!(get_outbox_stats(&pic, canister_id).total_messages, 0);

    advance_and_run_due_poll_inbox(&pic, canister_id, WalletRpcMode::Success);

    let synced = get_wallet_balance_telemetry(&pic, canister_id);
    assert!(!synced.bootstrap_pending);
    assert!(synced.last_synced_at_ns.is_some());
    assert_eq!(synced.last_error, None);
    assert_eq!(
        synced.eth_balance_wei_hex.as_deref(),
        Some(ETH_BALANCE_WEI_HEX)
    );
    assert_eq!(
        synced.usdc_contract_address.as_deref(),
        Some(USDC_CONTRACT_ADDRESS)
    );

    set_task_enabled(&pic, canister_id, TaskKind::PollInbox, false);
    wait_for_outbox_messages(&pic, canister_id, 1);
}

#[test]
fn wallet_sync_refreshes_on_due_window_transitions_to_stale_and_degrades_non_fatally() {
    let (pic, canister_id) = with_backend_canister();
    configure_task_set(&pic, canister_id, false, true, 30);
    set_evm_rpc_url(&pic, canister_id, "https://mainnet.base.org");
    set_automaton_evm_address_admin(&pic, canister_id, AUTOMATON_ADDRESS);
    set_inbox_contract_address_admin(&pic, canister_id, INBOX_CONTRACT_ADDRESS);

    let config = get_wallet_balance_sync_config(&pic, canister_id);
    assert!(config.enabled);
    assert_eq!(config.normal_interval_secs, 300);
    assert_eq!(config.freshness_window_secs, 600);

    advance_and_run_due_poll_inbox(&pic, canister_id, WalletRpcMode::Success);
    let first = get_wallet_balance_telemetry(&pic, canister_id);
    let first_synced_at = first
        .last_synced_at_ns
        .expect("first sync should set last_synced_at_ns");
    assert_eq!(first.status, WalletBalanceStatus::Fresh);

    pic.advance_time(Duration::from_secs(120));
    drive_due_poll_inbox_with_wallet_rpc_mocks(&pic, canister_id, WalletRpcMode::Success);
    let before_due = get_wallet_balance_telemetry(&pic, canister_id);
    assert_eq!(before_due.last_synced_at_ns, Some(first_synced_at));

    pic.advance_time(Duration::from_secs(301));
    drive_due_poll_inbox_with_wallet_rpc_mocks(&pic, canister_id, WalletRpcMode::Success);
    let refreshed = get_wallet_balance_telemetry(&pic, canister_id);
    let refreshed_synced_at = refreshed
        .last_synced_at_ns
        .expect("refreshed sync should set last_synced_at_ns");
    assert!(refreshed_synced_at > first_synced_at);
    assert_eq!(
        refreshed.eth_balance_wei_hex.as_deref(),
        Some(ETH_BALANCE_WEI_HEX)
    );
    assert_eq!(
        refreshed.usdc_balance_raw_hex.as_deref(),
        Some(USDC_BALANCE_RAW_HEX)
    );

    set_task_enabled(&pic, canister_id, TaskKind::PollInbox, false);
    pic.advance_time(Duration::from_secs(620));
    pic.tick();
    let stale = get_wallet_balance_telemetry(&pic, canister_id);
    assert!(stale.is_stale);
    assert_eq!(stale.status, WalletBalanceStatus::Stale);

    set_task_enabled(&pic, canister_id, TaskKind::PollInbox, true);
    pic.advance_time(Duration::from_secs(31));
    drive_due_poll_inbox_with_wallet_rpc_mocks(&pic, canister_id, WalletRpcMode::FailWalletSync);

    let degraded = get_wallet_balance_telemetry(&pic, canister_id);
    assert_eq!(degraded.last_synced_at_ns, Some(refreshed_synced_at));
    assert_eq!(
        degraded.eth_balance_wei_hex.as_deref(),
        Some(ETH_BALANCE_WEI_HEX)
    );
    assert_eq!(
        degraded.usdc_balance_raw_hex.as_deref(),
        Some(USDC_BALANCE_RAW_HEX)
    );
    assert!(degraded
        .last_error
        .as_deref()
        .unwrap_or_default()
        .contains("evm rpc returned status 500"));
    assert_eq!(degraded.status, WalletBalanceStatus::Error);

    let jobs = list_scheduler_jobs(&pic, canister_id);
    let latest =
        latest_poll_job(&jobs).expect("latest poll job should be present after failure cycle");
    assert_eq!(latest.status, JobStatus::Succeeded);
}

#[test]
fn wallet_sync_oversized_outcall_tunes_response_limit_and_recovers_without_manual_reset() {
    let (pic, canister_id) = with_backend_canister();
    configure_task_set(&pic, canister_id, false, true, 30);
    set_evm_rpc_url(&pic, canister_id, "https://mainnet.base.org");
    set_automaton_evm_address_admin(&pic, canister_id, AUTOMATON_ADDRESS);
    set_inbox_contract_address_admin(&pic, canister_id, INBOX_CONTRACT_ADDRESS);

    let before = get_wallet_balance_sync_config(&pic, canister_id);
    assert_eq!(before.max_response_bytes, 256);

    advance_and_run_due_poll_inbox(&pic, canister_id, WalletRpcMode::RejectOversizedUntilTuned);

    let after = get_wallet_balance_sync_config(&pic, canister_id);
    assert_eq!(after.max_response_bytes, 512);

    let synced = get_wallet_balance_telemetry(&pic, canister_id);
    assert!(!synced.bootstrap_pending);
    assert_eq!(synced.last_error, None);
    assert_eq!(synced.status, WalletBalanceStatus::Fresh);
    assert_eq!(
        synced.eth_balance_wei_hex.as_deref(),
        Some(ETH_BALANCE_WEI_HEX)
    );
    assert_eq!(
        synced.usdc_balance_raw_hex.as_deref(),
        Some(USDC_BALANCE_RAW_HEX)
    );
    assert_eq!(
        synced.usdc_contract_address.as_deref(),
        Some(USDC_CONTRACT_ADDRESS)
    );

    let jobs = list_scheduler_jobs(&pic, canister_id);
    let latest =
        latest_poll_job(&jobs).expect("latest poll job should be present after recovery cycle");
    assert_eq!(latest.status, JobStatus::Succeeded);
    let failed_poll_jobs = jobs
        .iter()
        .filter(|job| job.kind == TaskKind::PollInbox && job.status == JobStatus::Failed)
        .count();
    assert_eq!(failed_poll_jobs, 0);

    pic.advance_time(Duration::from_secs(301));
    drive_due_poll_inbox_with_wallet_rpc_mocks(
        &pic,
        canister_id,
        WalletRpcMode::RejectOversizedUntilTuned,
    );
    let stable_config = get_wallet_balance_sync_config(&pic, canister_id);
    assert_eq!(
        stable_config.max_response_bytes, 512,
        "response limit should stay tuned without additional manual intervention"
    );
}

#[test]
fn wallet_balance_http_views_expose_safe_non_secret_fields() {
    let (pic, canister_id) = with_backend_canister();
    configure_task_set(&pic, canister_id, false, true, 30);
    set_evm_rpc_url(&pic, canister_id, "https://mainnet.base.org");
    set_automaton_evm_address_admin(&pic, canister_id, AUTOMATON_ADDRESS);
    set_inbox_contract_address_admin(&pic, canister_id, INBOX_CONTRACT_ADDRESS);

    advance_and_run_due_poll_inbox(&pic, canister_id, WalletRpcMode::Success);

    let telemetry_response = call_http_update(
        &pic,
        canister_id,
        HttpRequest::get("/api/wallet/balance").build_update(),
    );
    assert_eq!(telemetry_response.status_code().as_u16(), 200);
    let telemetry: Value = serde_json::from_slice(telemetry_response.body())
        .expect("wallet balance telemetry route should return json");
    assert_eq!(
        telemetry.get("eth_balance_wei_hex").and_then(Value::as_str),
        Some(ETH_BALANCE_WEI_HEX)
    );
    assert_eq!(
        telemetry
            .get("usdc_contract_address")
            .and_then(Value::as_str),
        Some(USDC_CONTRACT_ADDRESS)
    );
    assert!(telemetry.get("ecdsa_key_name").is_none());
    assert!(telemetry.get("evm_rpc_url").is_none());
    assert!(telemetry.get("openrouter_api_key").is_none());

    let config_response = call_http_update(
        &pic,
        canister_id,
        HttpRequest::get("/api/wallet/balance/sync-config").build_update(),
    );
    assert_eq!(config_response.status_code().as_u16(), 200);
    let config: Value = serde_json::from_slice(config_response.body())
        .expect("wallet balance sync config route should return json");
    assert_eq!(
        config.get("normal_interval_secs").and_then(Value::as_u64),
        Some(300)
    );
    assert_eq!(
        config
            .get("discover_usdc_via_inbox")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(config.get("ecdsa_key_name").is_none());
    assert!(config.get("evm_rpc_url").is_none());
    assert!(config.get("openrouter_api_key").is_none());
}
