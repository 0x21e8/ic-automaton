use std::collections::HashSet;
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
    next_job_seq: u64,
    active_mutating_lease: Option<SchedulerLease>,
    last_tick_started_ns: u64,
    last_tick_finished_ns: u64,
    last_tick_error: Option<String>,
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

fn set_scheduler_low_cycles_mode(pic: &PocketIc, canister_id: Principal, enabled: bool) {
    let payload = encode_args((enabled,)).unwrap_or_else(|error| {
        panic!("failed to encode set_scheduler_low_cycles_mode args: {error}");
    });
    let _: String = call_update(pic, canister_id, "set_scheduler_low_cycles_mode", payload);
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

#[cfg(not(feature = "pocketic_tests"))]
#[test]
#[ignore = "Enable feature `pocketic_tests` and add a PocketIC runtime dependency to run"]
fn placeholder_concurrent_ticks_still_serialized() {
    let _wasm = assert_wasm_artifact_present();
}

#[cfg(not(feature = "pocketic_tests"))]
#[test]
#[ignore = "Enable feature `pocketic_tests` and add a PocketIC runtime dependency to run"]
fn placeholder_duplicate_ticks_are_idempotent_for_single_slot() {
    let _wasm = assert_wasm_artifact_present();
}

#[cfg(not(feature = "pocketic_tests"))]
#[test]
#[ignore = "Enable feature `pocketic_tests` and add a PocketIC runtime dependency to run"]
fn placeholder_post_upgrade_rearms_timer() {
    let _wasm = assert_wasm_artifact_present();
}

#[cfg(not(feature = "pocketic_tests"))]
#[test]
#[ignore = "Enable feature `pocketic_tests` and add a PocketIC runtime dependency to run"]
fn placeholder_low_cycles_mode_suppresses_non_essential_jobs() {
    let _wasm = assert_wasm_artifact_present();
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
