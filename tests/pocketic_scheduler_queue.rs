#![cfg(feature = "pocketic_tests")]

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

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

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
enum TaskKind {
    AgentTurn,
    PollInbox,
    CheckCycles,
    Reconcile,
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
enum InferenceProvider {
    IcLlm,
    OpenRouter,
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

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
enum TaskLane {
    Mutating,
    ReadOnly,
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
enum SurvivalTier {
    Normal,
    LowCycles,
    Critical,
    OutOfCycles,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct ObservedJob {
    id: String,
    kind: TaskKind,
    lane: TaskLane,
    dedupe_key: String,
    priority: u8,
    created_at_ns: u64,
    scheduled_for_ns: u64,
    started_at_ns: Option<u64>,
    finished_at_ns: Option<u64>,
    status: JobStatus,
    attempts: u32,
    max_attempts: u32,
    last_error: Option<String>,
}

#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
struct SchedulerLease {
    lane: TaskLane,
    job_id: String,
    acquired_at_ns: u64,
    expires_at_ns: u64,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct SchedulerRuntime {
    enabled: bool,
    paused_reason: Option<String>,
    low_cycles_mode: bool,
    survival_tier: SurvivalTier,
    survival_tier_recovery_checks: u32,
    next_job_seq: u64,
    active_mutating_lease: Option<SchedulerLease>,
    last_tick_started_ns: u64,
    last_tick_finished_ns: u64,
    last_tick_error: Option<String>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct InitArgs {
    ecdsa_key_name: String,
    inbox_contract_address: Option<String>,
    evm_chain_id: Option<u64>,
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

fn non_controller_principal() -> Principal {
    Principal::self_authenticating(b"non-controller-scheduler-queue")
}

fn call_update_as<T>(
    pic: &PocketIc,
    canister_id: Principal,
    caller: Principal,
    method: &str,
    payload: Vec<u8>,
) -> T
where
    T: for<'de> Deserialize<'de> + CandidType,
{
    let response = pic
        .update_call(canister_id, caller, method, payload)
        .unwrap_or_else(|error| panic!("update call {method} failed: {error:?}"));
    decode_one(&response)
        .unwrap_or_else(|error| panic!("failed decoding {method} response: {error:?}"))
}

fn call_update<T>(pic: &PocketIc, canister_id: Principal, method: &str, payload: Vec<u8>) -> T
where
    T: for<'de> Deserialize<'de> + CandidType,
{
    call_update_as(pic, canister_id, Principal::anonymous(), method, payload)
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
    let payload = encode_args((kind, enabled)).unwrap_or_else(|error| {
        panic!("failed to encode set_task_enabled args: {error}");
    });
    let _: String = call_update(pic, canister_id, "set_task_enabled", payload);
}

fn set_task_interval_secs(
    pic: &PocketIc,
    canister_id: Principal,
    kind: TaskKind,
    interval_secs: u64,
) {
    let payload = encode_args((kind, interval_secs)).unwrap_or_else(|error| {
        panic!("failed to encode set_task_interval_secs args: {error}");
    });
    let result: Result<String, String> =
        call_update(pic, canister_id, "set_task_interval_secs", payload);
    assert!(result.is_ok(), "set_task_interval_secs failed: {result:?}");
}

fn set_scheduler_low_cycles_mode(pic: &PocketIc, canister_id: Principal, enabled: bool) {
    let payload = encode_args((enabled,)).unwrap_or_else(|error| {
        panic!("failed to encode set_scheduler_low_cycles_mode args: {error}");
    });
    let _: String = call_update(pic, canister_id, "set_scheduler_low_cycles_mode", payload);
}

fn set_inference_provider(pic: &PocketIc, canister_id: Principal, provider: InferenceProvider) {
    let payload = encode_args((provider,)).unwrap_or_else(|error| {
        panic!("failed to encode set_inference_provider args: {error}");
    });
    let _: String = call_update(pic, canister_id, "set_inference_provider", payload);
}

fn set_inference_model(pic: &PocketIc, canister_id: Principal, model: &str) {
    let payload = encode_args((model.to_string(),)).unwrap_or_else(|error| {
        panic!("failed to encode set_inference_model args: {error}");
    });
    let result: Result<String, String> =
        call_update(pic, canister_id, "set_inference_model", payload);
    assert!(result.is_ok(), "set_inference_model failed: {result:?}");
}

fn set_openrouter_api_key(pic: &PocketIc, canister_id: Principal, api_key: Option<String>) {
    let payload = encode_args((api_key,)).unwrap_or_else(|error| {
        panic!("failed to encode set_openrouter_api_key args: {error}");
    });
    let _: String = call_update(pic, canister_id, "set_openrouter_api_key", payload);
}

fn set_evm_rpc_url(pic: &PocketIc, canister_id: Principal, url: &str) {
    let payload = encode_args((url.to_string(),)).expect("failed to encode set_evm_rpc_url args");
    let result: Result<String, String> = call_update(pic, canister_id, "set_evm_rpc_url", payload);
    assert!(result.is_ok(), "set_evm_rpc_url failed: {result:?}");
}

fn set_automaton_evm_address_admin(pic: &PocketIc, canister_id: Principal, address: &str) {
    let payload = encode_args((Some(address.to_string()),))
        .expect("failed to encode set_automaton_evm_address_admin args");
    let result: Result<Option<String>, String> =
        call_update(pic, canister_id, "set_automaton_evm_address_admin", payload);
    assert!(
        result.is_ok(),
        "set_automaton_evm_address_admin failed: {result:?}"
    );
}

fn set_inbox_contract_address_admin(pic: &PocketIc, canister_id: Principal, address: &str) {
    let payload = encode_args((Some(address.to_string()),))
        .expect("failed to encode set_inbox_contract_address_admin args");
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

fn set_retention_config(pic: &PocketIc, canister_id: Principal, config: RetentionConfig) {
    let payload = encode_args((config,)).expect("failed to encode set_retention_config args");
    let result: Result<RetentionConfig, String> =
        call_update(pic, canister_id, "set_retention_config", payload);
    assert!(result.is_ok(), "set_retention_config failed: {result:?}");
}

fn list_scheduler_jobs(pic: &PocketIc, canister_id: Principal) -> Vec<ObservedJob> {
    let payload = encode_args((200u32,)).unwrap_or_else(|error| {
        panic!("failed to encode list_scheduler_jobs args: {error}");
    });
    call_query(pic, canister_id, "list_scheduler_jobs", payload)
}

fn get_scheduler_view(pic: &PocketIc, canister_id: Principal) -> SchedulerRuntime {
    call_query(
        pic,
        canister_id,
        "get_scheduler_view",
        encode_args(()).expect("failed to encode empty args"),
    )
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

fn configure_only_agent_turn(pic: &PocketIc, canister_id: Principal, interval_secs: u64) {
    for kind in [
        TaskKind::AgentTurn,
        TaskKind::PollInbox,
        TaskKind::CheckCycles,
        TaskKind::Reconcile,
    ] {
        set_task_enabled(pic, canister_id, kind, false);
        set_task_interval_secs(pic, canister_id, kind, interval_secs);
    }
    set_task_enabled(pic, canister_id, TaskKind::AgentTurn, true);
}

fn assert_single_slot_poll_inbox_job(counted_jobs: &[ObservedJob]) -> String {
    let poll_jobs = counted_jobs
        .iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .collect::<Vec<_>>();

    assert!(
        !poll_jobs.is_empty(),
        "expected at least one poll-inbox job"
    );
    assert_eq!(
        poll_jobs.len(),
        1,
        "expected one poll-inbox job for the slot"
    );

    poll_jobs[0].dedupe_key.clone()
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

fn wallet_sync_rpc_response(request: &CanisterHttpRequest) -> CanisterHttpResponse {
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
            "result":"0xa",
        }),
        "eth_getLogs" => json!({
            "jsonrpc":"2.0",
            "id":1,
            "result":[],
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

fn drive_poll_inbox_with_wallet_sync_mocks(pic: &PocketIc, canister_id: Principal) {
    let before_poll_jobs = list_scheduler_jobs(pic, canister_id)
        .into_iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .count();

    pic.tick();

    for _ in 0..30 {
        let pending_http = pic.get_canister_http();
        if !pending_http.is_empty() {
            for request in pending_http {
                pic.mock_canister_http_response(MockCanisterHttpResponse {
                    subnet_id: request.subnet_id,
                    request_id: request.request_id,
                    response: wallet_sync_rpc_response(&request),
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
        let terminal = latest_poll_job(&jobs)
            .map(|job| matches!(job.status, JobStatus::Succeeded | JobStatus::Failed))
            .unwrap_or(false);
        if poll_jobs > before_poll_jobs && terminal && pic.get_canister_http().is_empty() {
            return;
        }
    }

    panic!("poll inbox did not complete with wallet sync mocks in expected ticks");
}

#[cfg(feature = "pocketic_tests")]
#[test]
fn placeholder_concurrent_ticks_still_serialized() {
    let (pic, canister_id) = with_backend_canister();
    configure_only_poll_inbox(&pic, canister_id, 60);
    pic.advance_time(Duration::from_secs(61));

    pic.tick();
    let first_jobs = list_scheduler_jobs(&pic, canister_id);
    assert_eq!(first_jobs.len(), 1);
    let first_slot_dedupe = assert_single_slot_poll_inbox_job(&first_jobs);
    assert_eq!(
        first_jobs
            .iter()
            .filter(|job| job.status == JobStatus::InFlight)
            .count(),
        0
    );

    pic.tick();
    let second_jobs = list_scheduler_jobs(&pic, canister_id);
    let second_slot_dedupe = assert_single_slot_poll_inbox_job(&second_jobs);
    assert_eq!(
        first_slot_dedupe, second_slot_dedupe,
        "duplicate timer ticks should not create a second poll-inbox slot job"
    );
    assert!(
        second_jobs.len() <= 1,
        "scheduler should not dispatch concurrent mutating jobs"
    );

    let active_mutating_lease_present = get_scheduler_view(&pic, canister_id)
        .active_mutating_lease
        .is_some();
    assert!(
        !active_mutating_lease_present,
        "scheduler lease should be released after tick processing"
    );
}

#[cfg(feature = "pocketic_tests")]
#[test]
fn placeholder_duplicate_ticks_are_idempotent_for_single_slot() {
    let (pic, canister_id) = with_backend_canister();
    configure_only_poll_inbox(&pic, canister_id, 60);
    pic.advance_time(Duration::from_secs(61));

    pic.tick();
    pic.tick();
    let jobs = list_scheduler_jobs(&pic, canister_id);

    let poll_dedupe_keys = jobs
        .iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .map(|job| job.dedupe_key.clone())
        .collect::<HashSet<_>>();
    assert_eq!(
        poll_dedupe_keys.len(),
        1,
        "tick duplicates should map to one dedupe key"
    );
    assert_eq!(
        jobs.iter()
            .filter(|job| job.kind == TaskKind::PollInbox)
            .count(),
        1,
        "duplicate ticks should not create extra poll-inbox jobs"
    );
}

#[cfg(feature = "pocketic_tests")]
#[test]
fn placeholder_post_upgrade_rearms_timer() {
    let (pic, canister_id) = with_backend_canister();
    configure_only_poll_inbox(&pic, canister_id, 60);
    pic.advance_time(Duration::from_secs(61));

    pic.tick();
    let pre_upgrade_job_count = list_scheduler_jobs(&pic, canister_id)
        .into_iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .count();
    assert!(
        pre_upgrade_job_count > 0,
        "expected a poll-inbox job before upgrade"
    );

    let wasm = assert_wasm_artifact_present();
    let _ = pic.upgrade_canister(canister_id, wasm, vec![], None);

    set_task_interval_secs(&pic, canister_id, TaskKind::PollInbox, 60);
    pic.advance_time(Duration::from_secs(61));
    pic.tick();

    let post_upgrade_job_count = list_scheduler_jobs(&pic, canister_id)
        .into_iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .count();
    assert!(
        post_upgrade_job_count > pre_upgrade_job_count,
        "upgrade should preserve scheduler scheduling and re-arm timer callbacks"
    );
}

#[cfg(feature = "pocketic_tests")]
#[test]
fn placeholder_low_cycles_mode_suppresses_non_essential_jobs() {
    let (pic, canister_id) = with_backend_canister();

    for kind in [
        TaskKind::AgentTurn,
        TaskKind::PollInbox,
        TaskKind::CheckCycles,
        TaskKind::Reconcile,
    ] {
        set_task_enabled(&pic, canister_id, kind, false);
        set_task_interval_secs(&pic, canister_id, kind, 60);
    }

    set_task_enabled(&pic, canister_id, TaskKind::PollInbox, true);
    set_task_enabled(&pic, canister_id, TaskKind::CheckCycles, true);
    set_task_enabled(&pic, canister_id, TaskKind::Reconcile, true);

    set_scheduler_low_cycles_mode(&pic, canister_id, true);
    pic.advance_time(Duration::from_secs(61));
    pic.tick();

    let jobs = list_scheduler_jobs(&pic, canister_id);
    let jobs_by_kind = jobs
        .iter()
        .filter(|job| job.kind == TaskKind::PollInbox || job.kind == TaskKind::CheckCycles)
        .count();
    let reconcile_jobs = jobs
        .iter()
        .filter(|job| job.kind == TaskKind::Reconcile)
        .count();

    assert!(
        jobs_by_kind >= 1,
        "low cycles mode should still process essential tasks"
    );
    assert_eq!(
        reconcile_jobs, 0,
        "low cycles mode should skip non-essential tasks"
    );
}

#[cfg(feature = "pocketic_tests")]
#[test]
fn placeholder_agent_turn_lease_ttl_covers_longer_continuation_runtime() {
    let (pic, canister_id) = with_backend_canister();

    configure_only_poll_inbox(&pic, canister_id, 60);
    set_evm_rpc_url(&pic, canister_id, "https://mainnet.base.org");
    set_automaton_evm_address_admin(
        &pic,
        canister_id,
        "0x1111111111111111111111111111111111111111",
    );
    set_inbox_contract_address_admin(
        &pic,
        canister_id,
        "0x2222222222222222222222222222222222222222",
    );
    pic.advance_time(Duration::from_secs(61));
    drive_poll_inbox_with_wallet_sync_mocks(&pic, canister_id);

    configure_only_agent_turn(&pic, canister_id, 60);
    set_inference_provider(&pic, canister_id, InferenceProvider::OpenRouter);
    set_openrouter_api_key(&pic, canister_id, Some("test-api-key".to_string()));
    pic.advance_time(Duration::from_secs(61));

    pic.tick();

    let runtime = get_scheduler_view(&pic, canister_id);
    let lease = runtime
        .active_mutating_lease
        .expect("agent turn should keep a mutating lease while awaiting async work");
    let ttl_ns = lease.expires_at_ns.saturating_sub(lease.acquired_at_ns);
    assert_eq!(
        ttl_ns, 240_000_000_000,
        "agent-turn lease ttl regression: expected 240 seconds"
    );
    assert_eq!(lease.lane, TaskLane::Mutating);
}

#[cfg(feature = "pocketic_tests")]
#[test]
fn non_controller_cannot_mutate_scheduler_control_plane() {
    let (pic, canister_id) = with_backend_canister();
    let outsider = non_controller_principal();

    let set_enabled_payload = encode_args((TaskKind::PollInbox, false))
        .unwrap_or_else(|error| panic!("failed to encode payload: {error}"));
    let set_enabled_result = pic.update_call(
        canister_id,
        outsider,
        "set_task_enabled",
        set_enabled_payload,
    );
    assert!(
        set_enabled_result.is_err(),
        "set_task_enabled should reject non-controller callers"
    );

    let set_interval_payload = encode_args((TaskKind::PollInbox, 30u64))
        .unwrap_or_else(|error| panic!("failed to encode payload: {error}"));
    let set_interval_result: Result<String, String> = call_update_as(
        &pic,
        canister_id,
        outsider,
        "set_task_interval_secs",
        set_interval_payload,
    );
    assert_eq!(
        set_interval_result,
        Err("caller is not a controller".to_string()),
        "set_task_interval_secs should enforce controller authorization"
    );

    let low_cycles_payload =
        encode_args((true,)).unwrap_or_else(|error| panic!("failed to encode payload: {error}"));
    let low_cycles_result = pic.update_call(
        canister_id,
        outsider,
        "set_scheduler_low_cycles_mode",
        low_cycles_payload,
    );
    assert!(
        low_cycles_result.is_err(),
        "set_scheduler_low_cycles_mode should reject non-controller callers"
    );
}

#[cfg(feature = "pocketic_tests")]
#[test]
fn high_volume_poll_inbox_history_stays_bounded_with_active_retention() {
    let (pic, canister_id) = with_backend_canister();
    configure_only_poll_inbox(&pic, canister_id, 1);
    set_retention_config(
        &pic,
        canister_id,
        RetentionConfig {
            jobs_max_age_secs: 2,
            jobs_max_records: 48,
            dedupe_max_age_secs: 2,
            turns_max_age_secs: 7 * 24 * 60 * 60,
            transitions_max_age_secs: 7 * 24 * 60 * 60,
            tools_max_age_secs: 7 * 24 * 60 * 60,
            inbox_max_age_secs: 14 * 24 * 60 * 60,
            outbox_max_age_secs: 14 * 24 * 60 * 60,
            maintenance_batch_size: 96,
            maintenance_interval_secs: 1,
        },
    );

    for _ in 0..180 {
        pic.advance_time(Duration::from_secs(2));
        pic.tick();
    }

    let runtime = get_scheduler_view(&pic, canister_id);
    assert!(
        runtime.next_job_seq >= 10,
        "scheduler should continue producing jobs under sustained load"
    );
    assert!(
        runtime.last_tick_error.is_none(),
        "scheduler tick should remain healthy under sustained retention activity"
    );

    let jobs = list_scheduler_jobs(&pic, canister_id);
    let poll_jobs = jobs
        .iter()
        .filter(|job| job.kind == TaskKind::PollInbox)
        .collect::<Vec<_>>();
    assert!(
        !poll_jobs.is_empty(),
        "poll-inbox jobs should remain queryable after retention compaction"
    );
    assert!(
        poll_jobs.len() <= 60,
        "retention should keep historical job volume bounded"
    );
    assert!(
        poll_jobs.iter().any(|job| {
            matches!(
                job.status,
                JobStatus::Succeeded | JobStatus::Skipped | JobStatus::TimedOut
            )
        }),
        "scheduler should continue reaching terminal job states while retention runs"
    );
}
