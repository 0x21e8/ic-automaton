#![cfg(feature = "pocketic_tests")]

use std::path::Path;
use std::time::Duration;

use alloy_primitives::keccak256;
use candid::{decode_one, encode_args, CandidType, Principal};
use pocket_ic::common::rest::{
    CanisterHttpReply, CanisterHttpRequest, CanisterHttpResponse, MockCanisterHttpResponse,
};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const WASM_PATHS: &[&str] = &[
    "target/wasm32-unknown-unknown/release/backend.wasm",
    "target/wasm32-unknown-unknown/release/deps/backend.wasm",
];
const INBOX_MESSAGE_QUEUED_EVENT_SIGNATURE: &str =
    "MessageQueued(address,uint64,address,string,uint256,uint256)";

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct InitArgs {
    ecdsa_key_name: String,
    inbox_contract_address: Option<String>,
    evm_chain_id: Option<u64>,
    evm_rpc_url: Option<String>,
    evm_confirmation_depth: Option<u64>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct RetentionConfig {
    jobs_max_age_secs: u64,
    jobs_max_records: u64,
    dedupe_max_age_secs: u64,
    turns_max_age_secs: u64,
    transitions_max_age_secs: u64,
    tools_max_age_secs: u64,
    inbox_max_age_secs: u64,
    outbox_max_age_secs: u64,
    maintenance_batch_size: u32,
    maintenance_interval_secs: u64,
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

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct EvmRouteStateView {
    chain_id: u64,
    automaton_evm_address: Option<String>,
    inbox_contract_address: Option<String>,
    automaton_address_topic: Option<String>,
    next_block: u64,
    next_log_index: u64,
    confirmation_depth: u64,
    last_poll_at_ns: u64,
    consecutive_empty_polls: u32,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct InboxStats {
    total_messages: u64,
    pending_count: u64,
    staged_count: u64,
    consumed_count: u64,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
enum InboxMessageStatus {
    Pending,
    Staged,
    Consumed,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct InboxMessage {
    id: String,
    seq: u64,
    body: String,
    posted_by: String,
    status: InboxMessageStatus,
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
    with_backend_canister_with_init(InitArgs {
        ecdsa_key_name: "dfx_test_key".to_string(),
        inbox_contract_address: None,
        evm_chain_id: Some(8453),
        evm_rpc_url: None,
        evm_confirmation_depth: None,
    })
}

fn with_backend_canister_with_init(init: InitArgs) -> (PocketIc, Principal) {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    let wasm = assert_wasm_artifact_present();
    let init_args = encode_args((init,)).expect("failed to encode init args");

    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, init_args, None);

    (pic, canister_id)
}

#[test]
fn init_args_apply_confirmation_depth_and_chain_for_evm_route_state() {
    let (pic, canister_id) = with_backend_canister_with_init(InitArgs {
        ecdsa_key_name: "dfx_test_key".to_string(),
        inbox_contract_address: Some("0x2222222222222222222222222222222222222222".to_string()),
        evm_chain_id: Some(31_337),
        evm_rpc_url: Some("http://127.0.0.1:18545".to_string()),
        evm_confirmation_depth: Some(0),
    });

    let route = get_evm_route_state_view(&pic, canister_id);
    assert_eq!(route.chain_id, 31_337);
    assert_eq!(route.confirmation_depth, 0);
    assert_eq!(
        route.inbox_contract_address.as_deref().unwrap_or_default(),
        "0x2222222222222222222222222222222222222222"
    );
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

fn set_task_enabled(pic: &PocketIc, canister_id: Principal, kind: TaskKind, enabled: bool) {
    let payload = encode_args((kind, enabled)).expect("failed to encode set_task_enabled args");
    let _: String = call_update(pic, canister_id, "set_task_enabled", payload);
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
    let payload =
        encode_args((Some(address.to_string()),)).expect("failed to encode automaton address");
    let result: Result<Option<String>, String> =
        call_update(pic, canister_id, "set_automaton_evm_address_admin", payload);
    assert!(result.is_ok(), "set_automaton_evm_address_admin failed");
}

fn set_inbox_contract_address_admin(pic: &PocketIc, canister_id: Principal, address: &str) {
    let payload =
        encode_args((Some(address.to_string()),)).expect("failed to encode inbox address");
    let result: Result<Option<String>, String> = call_update(
        pic,
        canister_id,
        "set_inbox_contract_address_admin",
        payload,
    );
    assert!(result.is_ok(), "set_inbox_contract_address_admin failed");
}

fn configure_only_poll_inbox(pic: &PocketIc, canister_id: Principal, interval_secs: u64) {
    for kind in [
        TaskKind::AgentTurn,
        TaskKind::PollInbox,
        TaskKind::CheckCycles,
        TaskKind::Reconcile,
    ] {
        set_task_enabled(pic, canister_id, kind, false);
        set_task_interval_secs(pic, canister_id, kind, interval_secs);
    }
    set_task_enabled(pic, canister_id, TaskKind::PollInbox, true);
}

fn set_retention_config(pic: &PocketIc, canister_id: Principal, config: RetentionConfig) {
    let payload = encode_args((config,)).expect("failed to encode set_retention_config args");
    let result: Result<RetentionConfig, String> =
        call_update(pic, canister_id, "set_retention_config", payload);
    assert!(result.is_ok(), "set_retention_config failed: {result:?}");
}

fn list_scheduler_jobs(pic: &PocketIc, canister_id: Principal) -> Vec<ObservedJob> {
    call_query(
        pic,
        canister_id,
        "list_scheduler_jobs",
        encode_args((200u32,)).expect("failed to encode list_scheduler_jobs"),
    )
}

fn get_inbox_stats(pic: &PocketIc, canister_id: Principal) -> InboxStats {
    call_query(
        pic,
        canister_id,
        "get_inbox_stats",
        encode_args(()).expect("failed to encode get_inbox_stats"),
    )
}

fn list_inbox_messages(pic: &PocketIc, canister_id: Principal) -> Vec<InboxMessage> {
    call_query(
        pic,
        canister_id,
        "list_inbox_messages",
        encode_args((50u32,)).expect("failed to encode list_inbox_messages"),
    )
}

fn get_evm_route_state_view(pic: &PocketIc, canister_id: Principal) -> EvmRouteStateView {
    call_query(
        pic,
        canister_id,
        "get_evm_route_state_view",
        encode_args(()).expect("failed to encode get_evm_route_state_view"),
    )
}

fn latest_poll_job(jobs: &[ObservedJob]) -> Option<&ObservedJob> {
    jobs.iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .max_by_key(|job| job.created_at_ns)
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

fn make_tx_hash(id: u64) -> String {
    format!("0x{id:064x}")
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
    assert!(
        sender_hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit()),
        "sender address must be hex"
    );

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

fn rpc_response_body_for_request(
    request: &CanisterHttpRequest,
    latest_block: u64,
    logs: &[Value],
) -> Vec<u8> {
    let request_json: Value = serde_json::from_slice(&request.body)
        .unwrap_or_else(|error| panic!("failed to decode canister http request body: {error}"));
    let method = request_json
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let response = match method {
        "eth_blockNumber" => json!({
            "jsonrpc":"2.0",
            "id":1,
            "result": format!("0x{latest_block:x}")
        }),
        "eth_getLogs" => json!({
            "jsonrpc":"2.0",
            "id":1,
            "result": logs
        }),
        "eth_getBalance" => json!({
            "jsonrpc":"2.0",
            "id":1,
            "result":"0x0"
        }),
        "eth_call" => json!({
            "jsonrpc":"2.0",
            "id":1,
            "result":"0x0000000000000000000000000000000000000000000000000000000000000000"
        }),
        unsupported => {
            panic!("unsupported canister http method in test: {unsupported}");
        }
    };
    serde_json::to_vec(&response).expect("failed to encode mock canister http response")
}

fn drive_poll_inbox_with_http_mocks(
    pic: &PocketIc,
    canister_id: Principal,
    latest_block: u64,
    logs: &[Value],
) {
    let before_poll_jobs = list_scheduler_jobs(pic, canister_id)
        .into_iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .count();

    pic.tick();

    for _ in 0..24 {
        let pending_http = pic.get_canister_http();
        if !pending_http.is_empty() {
            for request in pending_http {
                let body = rpc_response_body_for_request(&request, latest_block, logs);
                pic.mock_canister_http_response(MockCanisterHttpResponse {
                    subnet_id: request.subnet_id,
                    request_id: request.request_id,
                    response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                        status: 200,
                        headers: vec![],
                        body,
                    }),
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
        let pending_after_tick = pic.get_canister_http();
        let terminal = latest_poll_job(&jobs)
            .map(|job| matches!(job.status, JobStatus::Succeeded | JobStatus::Failed))
            .unwrap_or(false);
        if poll_jobs > before_poll_jobs && terminal && pending_after_tick.is_empty() {
            return;
        }
    }

    panic!("poll inbox did not finish with mocked http responses in expected ticks");
}

fn configure_route_for_polling(pic: &PocketIc, canister_id: Principal) -> (String, String, String) {
    let automaton_address = "0x1111111111111111111111111111111111111111".to_string();
    let contract_address = "0x2222222222222222222222222222222222222222".to_string();
    let automaton_topic = address_to_topic(&automaton_address);

    set_evm_rpc_url(pic, canister_id, "https://mainnet.base.org");
    set_automaton_evm_address_admin(pic, canister_id, &automaton_address);
    set_inbox_contract_address_admin(pic, canister_id, &contract_address);
    configure_only_poll_inbox(pic, canister_id, 30);

    (automaton_address, contract_address, automaton_topic)
}

#[test]
fn poll_inbox_ignores_route_mismatch_and_accepts_match_without_registration() {
    let (pic, canister_id) = with_backend_canister();
    let (_automaton, contract_address, automaton_topic) =
        configure_route_for_polling(&pic, canister_id);
    let other_topic = address_to_topic("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let other_contract = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let matched_sender = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    let matched_message = "who are you?";

    let logs = vec![
        rpc_log(
            0,
            0,
            &make_tx_hash(1),
            &contract_address,
            &other_topic,
            "0xdeadbeef",
        ),
        rpc_log(
            0,
            1,
            &make_tx_hash(2),
            other_contract,
            &automaton_topic,
            "0xfeedface",
        ),
        rpc_log(
            0,
            2,
            &make_tx_hash(3),
            &contract_address,
            &automaton_topic,
            &encode_message_queued_payload(matched_sender, matched_message, 0, 500_000_000_000_000),
        ),
    ];

    pic.advance_time(Duration::from_secs(31));
    drive_poll_inbox_with_http_mocks(&pic, canister_id, 2, &logs);

    let stats = get_inbox_stats(&pic, canister_id);
    assert_eq!(
        stats.total_messages, 1,
        "only route-matched logs should be ingested"
    );
    let messages = list_inbox_messages(&pic, canister_id);
    assert_eq!(messages.len(), 1, "exactly one message should be staged");
    assert_eq!(
        messages[0].body, matched_message,
        "staged inbox body should contain decoded MessageQueued.message"
    );
    assert_eq!(
        messages[0].posted_by, matched_sender,
        "staged inbox sender should contain decoded MessageQueued.sender"
    );
}

#[test]
fn poll_inbox_dedupes_duplicate_tx_hash_and_log_index() {
    let (pic, canister_id) = with_backend_canister();
    let (_automaton, contract_address, automaton_topic) =
        configure_route_for_polling(&pic, canister_id);
    let duplicate_tx = make_tx_hash(42);

    let first_logs = vec![rpc_log(
        0,
        7,
        &duplicate_tx,
        &contract_address,
        &automaton_topic,
        &encode_message_queued_payload(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "duplicate-1",
            0,
            500_000_000_000_000,
        ),
    )];
    pic.advance_time(Duration::from_secs(31));
    drive_poll_inbox_with_http_mocks(&pic, canister_id, 2, &first_logs);

    let after_first = get_inbox_stats(&pic, canister_id);
    assert_eq!(after_first.total_messages, 1);

    let duplicate_logs = vec![rpc_log(
        1,
        7,
        &duplicate_tx,
        &contract_address,
        &automaton_topic,
        &encode_message_queued_payload(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "duplicate-2",
            0,
            500_000_000_000_000,
        ),
    )];
    pic.advance_time(Duration::from_secs(31));
    drive_poll_inbox_with_http_mocks(&pic, canister_id, 3, &duplicate_logs);

    let after_second = get_inbox_stats(&pic, canister_id);
    assert_eq!(
        after_second.total_messages, 1,
        "duplicate tx_hash/log_index should be skipped on re-poll"
    );
}

#[test]
fn poll_inbox_empty_poll_backoff_skips_rpc_until_due_then_resumes() {
    let (pic, canister_id) = with_backend_canister();
    let (_automaton, _contract_address, _automaton_topic) =
        configure_route_for_polling(&pic, canister_id);

    pic.advance_time(Duration::from_secs(31));
    drive_poll_inbox_with_http_mocks(&pic, canister_id, 2, &[]);

    let after_first = get_evm_route_state_view(&pic, canister_id);
    assert_eq!(after_first.consecutive_empty_polls, 1);
    assert!(after_first.last_poll_at_ns > 0);

    pic.advance_time(Duration::from_secs(31));
    pic.tick();
    pic.tick();
    assert!(
        pic.get_canister_http().is_empty(),
        "backoff window should skip rpc outcalls"
    );

    let after_skip = get_evm_route_state_view(&pic, canister_id);
    assert_eq!(after_skip.last_poll_at_ns, after_first.last_poll_at_ns);
    assert_eq!(after_skip.consecutive_empty_polls, 1);

    pic.advance_time(Duration::from_secs(31));
    drive_poll_inbox_with_http_mocks(&pic, canister_id, 3, &[]);

    let after_resume = get_evm_route_state_view(&pic, canister_id);
    assert!(
        after_resume.last_poll_at_ns > after_first.last_poll_at_ns,
        "rpc polling should resume once backoff due window is reached"
    );
    assert_eq!(after_resume.consecutive_empty_polls, 2);
}

#[test]
fn poll_inbox_stages_default_and_override_pricing_payload_variants() {
    let (pic, canister_id) = with_backend_canister();
    let (_automaton, contract_address, automaton_topic) =
        configure_route_for_polling(&pic, canister_id);

    let default_message = "default pricing";
    let override_message = "override pricing";
    let logs = vec![
        rpc_log(
            0,
            0,
            &make_tx_hash(70),
            &contract_address,
            &automaton_topic,
            &encode_message_queued_payload(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                default_message,
                1_000_000,
                500_000_000_000_000,
            ),
        ),
        rpc_log(
            0,
            1,
            &make_tx_hash(71),
            &contract_address,
            &automaton_topic,
            &encode_message_queued_payload(
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                override_message,
                3_000_000,
                2_000_000_000_000_000,
            ),
        ),
    ];

    pic.advance_time(Duration::from_secs(31));
    drive_poll_inbox_with_http_mocks(&pic, canister_id, 2, &logs);

    let stats = get_inbox_stats(&pic, canister_id);
    assert_eq!(stats.total_messages, 2);

    let bodies = list_inbox_messages(&pic, canister_id)
        .into_iter()
        .map(|message| message.body)
        .collect::<Vec<_>>();
    assert!(
        bodies.iter().any(|body| body == default_message),
        "default-pricing payload should decode into staged inbox message body"
    );
    assert!(
        bodies.iter().any(|body| body == override_message),
        "override-pricing payload should decode into staged inbox message body"
    );
}

#[test]
fn poll_inbox_handles_high_volume_burst_with_retention_active() {
    let (pic, canister_id) = with_backend_canister();
    let (_automaton, contract_address, automaton_topic) =
        configure_route_for_polling(&pic, canister_id);
    set_retention_config(
        &pic,
        canister_id,
        RetentionConfig {
            jobs_max_age_secs: 2,
            jobs_max_records: 64,
            dedupe_max_age_secs: 2,
            turns_max_age_secs: 7 * 24 * 60 * 60,
            transitions_max_age_secs: 7 * 24 * 60 * 60,
            tools_max_age_secs: 7 * 24 * 60 * 60,
            inbox_max_age_secs: 14 * 24 * 60 * 60,
            outbox_max_age_secs: 14 * 24 * 60 * 60,
            maintenance_batch_size: 128,
            maintenance_interval_secs: 1,
        },
    );

    let burst_logs = (0..12u64)
        .map(|idx| {
            rpc_log(
                0,
                idx,
                &make_tx_hash(1_000 + idx),
                &contract_address,
                &automaton_topic,
                &encode_message_queued_payload(
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    &format!("phase3-burst-message-{idx:03}"),
                    0,
                    500_000_000_000_000,
                ),
            )
        })
        .collect::<Vec<_>>();

    pic.advance_time(Duration::from_secs(31));
    drive_poll_inbox_with_http_mocks(&pic, canister_id, 5, &burst_logs);

    for step in 0..30u64 {
        pic.advance_time(Duration::from_secs(31));
        drive_poll_inbox_with_http_mocks(&pic, canister_id, 6 + step, &[]);
    }

    let jobs = list_scheduler_jobs(&pic, canister_id);
    let poll_jobs = jobs
        .iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .collect::<Vec<_>>();
    assert!(
        poll_jobs.len() <= 80,
        "retention should bound high-volume poll job history"
    );
    assert!(
        latest_poll_job(&jobs)
            .map(|job| job.status == JobStatus::Succeeded)
            .unwrap_or(false),
        "polling should keep succeeding under sustained high-volume scheduling"
    );

    let stats = get_inbox_stats(&pic, canister_id);
    assert_eq!(
        stats.total_messages, 12,
        "all burst logs should be ingested exactly once"
    );
}
