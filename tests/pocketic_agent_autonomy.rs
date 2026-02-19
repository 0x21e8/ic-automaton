#![cfg(feature = "pocketic_tests")]

use std::path::Path;
use std::time::Duration;

use candid::{decode_one, encode_args, CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

const WASM_PATH: &str = "target/wasm32-unknown-unknown/release/backend.wasm";

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
enum TaskKind {
    AgentTurn,
    PollInbox,
    CheckCycles,
    Reconcile,
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
enum TaskLane {
    Mutating,
    ReadOnly,
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

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
enum AgentState {
    Bootstrapping,
    Idle,
    LoadingContext,
    Inferring,
    ExecutingActions,
    Persisting,
    Sleeping,
    Faulted,
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
enum InferenceProvider {
    Mock,
    IcLlm,
    OpenRouter,
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

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct RuntimeView {
    state: AgentState,
    turn_in_flight: bool,
    loop_enabled: bool,
    turn_counter: u64,
    last_turn_id: Option<String>,
    last_error: Option<String>,
    soul: String,
    evm_chain_id: u64,
    evm_next_block: u64,
    evm_next_log_index: u64,
    last_transition_at_ns: u64,
    inference_provider: InferenceProvider,
    inference_model: String,
}

fn assert_wasm_artifact_present() -> Vec<u8> {
    if !Path::new(WASM_PATH).exists() {
        panic!("build artifact not found at {WASM_PATH}; run `icp build` before PocketIC tests");
    }
    std::fs::read(WASM_PATH).unwrap_or_else(|error| {
        panic!("cannot read PocketIC test artifact {WASM_PATH}: {error}");
    })
}

fn with_backend_canister() -> (PocketIc, Principal) {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    let wasm = assert_wasm_artifact_present();

    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

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

fn set_loop_enabled(pic: &PocketIc, canister_id: Principal, enabled: bool) {
    let payload = encode_args((enabled,)).unwrap_or_else(|error| {
        panic!("failed to encode set_loop_enabled args: {error}");
    });
    let _: String = call_update(pic, canister_id, "set_loop_enabled", payload);
}

fn set_inference_provider(pic: &PocketIc, canister_id: Principal, provider: InferenceProvider) {
    let payload = encode_args((provider,)).unwrap_or_else(|error| {
        panic!("failed to encode set_inference_provider args: {error}");
    });
    let _: String = call_update(pic, canister_id, "set_inference_provider", payload);
}

fn list_scheduler_jobs(pic: &PocketIc, canister_id: Principal) -> Vec<ObservedJob> {
    let payload = encode_args((200u32,)).unwrap_or_else(|error| {
        panic!("failed to encode list_scheduler_jobs args: {error}");
    });
    call_query(pic, canister_id, "list_scheduler_jobs", payload)
}

fn get_runtime_view(pic: &PocketIc, canister_id: Principal) -> RuntimeView {
    call_query(
        pic,
        canister_id,
        "get_runtime_view",
        encode_args(()).expect("failed to encode empty args"),
    )
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

#[test]
fn loop_disabled_agent_turn_is_counted_as_successful_skip() {
    let (pic, canister_id) = with_backend_canister();
    configure_only_agent_turn(&pic, canister_id, 60);
    set_loop_enabled(&pic, canister_id, false);

    pic.advance_time(Duration::from_secs(61));
    pic.tick();

    let jobs = list_scheduler_jobs(&pic, canister_id);
    let agent_jobs = jobs
        .iter()
        .filter(|job| job.kind == TaskKind::AgentTurn)
        .collect::<Vec<_>>();
    assert!(
        !agent_jobs.is_empty(),
        "expected an agent-turn scheduled job to be materialized"
    );
    assert!(
        agent_jobs
            .iter()
            .all(|job| job.status == JobStatus::Succeeded && job.last_error.is_none()),
        "disabled loop should not be marked as failed"
    );

    let runtime = get_runtime_view(&pic, canister_id);
    assert!(!runtime.loop_enabled);
    assert_ne!(
        runtime.state,
        AgentState::Faulted,
        "disabled loop skip must not transition runtime to faulted"
    );
}

#[test]
fn agent_turn_self_recovers_after_transient_inference_failure() {
    let (pic, canister_id) = with_backend_canister();
    configure_only_agent_turn(&pic, canister_id, 60);

    set_inference_provider(&pic, canister_id, InferenceProvider::IcLlm);
    pic.advance_time(Duration::from_secs(61));
    pic.tick();

    let after_failure = get_runtime_view(&pic, canister_id);
    assert_eq!(
        after_failure.state,
        AgentState::Faulted,
        "failed inference turn should set runtime faulted"
    );
    assert!(
        after_failure.last_error.is_some(),
        "faulted state must preserve error context"
    );

    set_inference_provider(&pic, canister_id, InferenceProvider::Mock);
    pic.advance_time(Duration::from_secs(61));
    pic.tick();

    let after_recovery = get_runtime_view(&pic, canister_id);
    assert_eq!(
        after_recovery.state,
        AgentState::Sleeping,
        "next tick should autonomously recover from faulted state"
    );
    assert!(
        after_recovery.last_error.is_none(),
        "successful recovery turn should clear runtime error"
    );

    let jobs = list_scheduler_jobs(&pic, canister_id);
    let failed_count = jobs
        .iter()
        .filter(|job| job.kind == TaskKind::AgentTurn && job.status == JobStatus::Failed)
        .count();
    let succeeded_count = jobs
        .iter()
        .filter(|job| job.kind == TaskKind::AgentTurn && job.status == JobStatus::Succeeded)
        .count();

    assert!(failed_count >= 1, "expected at least one failed agent turn");
    assert!(
        succeeded_count >= 1,
        "expected a successful recovery agent turn"
    );
}
