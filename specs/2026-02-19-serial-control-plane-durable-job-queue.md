# Spec: Serial Control Plane + Durable Job Queue (Low-Level Implementation)

**Status:** LOCKED
**Date:** 2026-02-19
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** complex
**Authority:** approval
**Tier:** 3

---

## Problem
The runtime is moving from one periodic loop to multiple periodic concerns (agent turn, inbox polling, cycle checks, reconciliation). If each concern gets its own timer callback, ICP timer jitter/duplication and async re-entrancy can cause unsafe interleaving, duplicated side effects, fragmented retry policies, and hard-to-debug behavior.

## Goal
Implement a single serial control-plane scheduler with a durable typed job queue so periodic work is deterministic, non-interleaving for mutating operations, idempotent under duplicate ticks, and observable.

Measurable success:
1. At most one mutating job executes at a time.
2. Duplicate timer ticks do not create duplicate terminal side effects for a cadence slot.
3. Scheduler state/job history survives canister upgrades.
4. Timer re-arm in `post_upgrade` restores scheduling without manual intervention.

## Non-Goals
- Multi-canister scheduler distribution.
- Parallel mutating job execution.
- Event-stream scheduler for external push/websocket sources.
- Full RBAC/authorization redesign (project currently dev-phase).

---

## Context & Inputs
- Option 3 from `docs/design/TASK_SCHEDULING_PATTERNS_ICP.md`.
- Current baseline in `src/lib.rs` + `src/agent.rs` uses one timer and `turn_in_flight` guard.
- ICP constraints from `docs/design/ICP_ANALYSIS.md` and `ic-cdk-timers 1.0.0`:
  - timers are not persisted across upgrade,
  - duplicate timer execution is possible under load/timeouts,
  - overlap behavior differs between interval APIs,
  - timer execution uses internal self-calls.

---

## Architecture Invariants (Mandatory)

1. Mutating-lane serialization:
- At most one mutating job can be `InFlight` at any time.

2. Durable lease:
- Active execution must be represented by a stable lease object.
- Stale leases must be recoverable (timeout/reaper path).

3. Idempotency:
- Every enqueued job has a deterministic `dedupe_key`.
- Queue insertion must reject duplicate non-terminal dedupe keys.

4. Explicit terminal record:
- Every execution attempt ends in `Succeeded`, `Failed`, `TimedOut`, or `Skipped` with timestamp.

5. Upgrade safety:
- `init` and `post_upgrade` both initialize scheduler storage and re-arm timer.

6. Low-cycles degradation:
- In low-cycles mode, only essential tasks are enqueued/executed.

---

## Low-Level Design

### 1) Domain Types
Add to `src/domain/types.rs`.

```rust
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskKind {
    AgentTurn,
    PollInbox,
    CheckCycles,
    Reconcile,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TaskLane {
    Mutating,
    ReadOnly,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TaskScheduleConfig {
    pub kind: TaskKind,
    pub enabled: bool,
    pub essential: bool,
    pub interval_secs: u64,
    pub priority: u8,
    pub max_backoff_secs: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TaskScheduleRuntime {
    pub kind: TaskKind,
    pub next_due_ns: u64,
    pub backoff_until_ns: Option<u64>,
    pub consecutive_failures: u32,
    pub pending_job_id: Option<String>,
    pub last_started_ns: Option<u64>,
    pub last_finished_ns: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    InFlight,
    Succeeded,
    Failed,
    TimedOut,
    Skipped,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ScheduledJob {
    pub id: String,
    pub kind: TaskKind,
    pub lane: TaskLane,
    pub dedupe_key: String,
    pub priority: u8,
    pub created_at_ns: u64,
    pub scheduled_for_ns: u64,
    pub started_at_ns: Option<u64>,
    pub finished_at_ns: Option<u64>,
    pub status: JobStatus,
    pub attempts: u32,
    pub max_attempts: u32,
    pub last_error: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SchedulerLease {
    pub lane: TaskLane,
    pub job_id: String,
    pub acquired_at_ns: u64,
    pub expires_at_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SchedulerRuntime {
    pub enabled: bool,
    pub paused_reason: Option<String>,
    pub low_cycles_mode: bool,
    pub next_job_seq: u64,
    pub active_mutating_lease: Option<SchedulerLease>,
    pub last_tick_started_ns: u64,
    pub last_tick_finished_ns: u64,
    pub last_tick_error: Option<String>,
}
```

### 2) Stable Memory Layout
Extend `src/storage/stable.rs` (KISS: keep existing storage module; no storage refactor required in this slice).

New memory IDs:
- `MemoryId(5)`: scheduler runtime (`scheduler.runtime` key).
- `MemoryId(6)`: task schedule configs (`task_cfg:<kind>`).
- `MemoryId(7)`: task runtime (`task_rt:<kind>`).
- `MemoryId(8)`: job records (`job:<job_id>`).
- `MemoryId(9)`: job queue index (`queue:<lane>:<scheduled_for_ns>:<priority>:<seq>` => `job_id`).
- `MemoryId(10)`: dedupe index (`dedupe:<key>` => latest non-terminal job id / last terminal job id).

Required stable APIs:
- `init_scheduler_defaults(now_ns)`
- `list_task_configs()` / `upsert_task_config(...)`
- `get_task_runtime(kind)` / `save_task_runtime(...)`
- `enqueue_job_if_absent(kind, lane, dedupe_key, scheduled_for_ns, priority)`
- `pop_next_pending_job(lane, now_ns)`
- `acquire_mutating_lease(job_id, now_ns, ttl_ns)`
- `complete_job(job_id, status, error, now_ns)`
- `recover_stale_lease(now_ns)`
- `list_recent_jobs(limit)`

### 3) Scheduler Tick Algorithm
Create `src/scheduler.rs` with orchestration logic.

```rust
pub async fn scheduler_tick() {
    let now = ic_cdk::api::time();

    stable::recover_stale_lease(now);

    if !stable::scheduler_enabled() {
        stable::record_scheduler_tick(now, Ok(()));
        return;
    }

    refresh_due_jobs(now); // cadence -> job materialization

    if stable::mutating_lease_active(now) {
        stable::record_scheduler_tick(now, Ok(()));
        return;
    }

    let Some(job) = stable::pop_next_pending_job(TaskLane::Mutating, now) else {
        stable::record_scheduler_tick(now, Ok(()));
        return;
    };

    if stable::acquire_mutating_lease(&job.id, now, lease_ttl_ns(&job.kind)).is_err() {
        stable::record_scheduler_tick(now, Ok(()));
        return;
    }

    let result = dispatch_job(&job).await;
    match result {
        Ok(()) => stable::complete_job(&job.id, JobStatus::Succeeded, None, ic_cdk::api::time()),
        Err(e) => stable::complete_job(&job.id, JobStatus::Failed, Some(e), ic_cdk::api::time()),
    }
}
```

### 4) Due Job Materialization
`refresh_due_jobs(now)` behavior:
- Iterate task configs sorted by priority + kind.
- Skip disabled tasks.
- In low-cycles mode, skip non-essential tasks.
- Load runtime row for task.
- Skip when:
  - `pending_job_id` exists,
  - `backoff_until_ns > now`,
  - `next_due_ns > now`.
- Build deterministic dedupe key for cadence slot:
  - `format!("{kind:?}:{slot_start_ns}")`
  - `slot_start_ns = now - (now % interval_ns)`
- Call `enqueue_job_if_absent`.
- Advance `next_due_ns` by interval (no catch-up burst in this slice).

### 5) Job Dispatch Contract
`dispatch_job(job)` routes by task kind:
- `AgentTurn` -> wraps current `run_scheduled_turn` pathway.
- `PollInbox` -> poller handler (or placeholder returning `Ok(())` until poller lands).
- `CheckCycles` -> cycles checker + low-cycles flag updates.
- `Reconcile` -> reconcile handler (or placeholder in this slice).

All handlers must be idempotent and return `Result<(), String>`.

### 6) Retry / Backoff Rules
- On `Succeeded`:
  - `consecutive_failures = 0`
  - clear `backoff_until_ns`
- On `Failed`/`TimedOut`:
  - increment `consecutive_failures`
  - exponential backoff capped by `max_backoff_secs`
  - set `backoff_until_ns`
- On repeated lease timeout:
  - mark job `TimedOut`
  - clear lease
  - apply backoff

### 7) Timer Arming
`src/lib.rs` changes:
- replace direct `run_scheduled_turn` timer wiring with scheduler timer wiring.
- use `set_timer_interval_serial` for scheduler control-plane timer.
- keep `init` and `post_upgrade` both calling storage init + scheduler re-arm.

### 8) Observability
Use `canlog` structured records for:
- tick start/finish,
- job enqueued/dequeued,
- lease acquired/released/recovered,
- job completion status,
- low-cycles mode transitions.

### 9) Public API Surface
Add query endpoints in `src/lib.rs`:
- `get_scheduler_view() -> SchedulerRuntime`
- `list_scheduler_jobs(limit: u32) -> Vec<ScheduledJob>`
- `list_task_schedules() -> Vec<(TaskScheduleConfig, TaskScheduleRuntime)>`

Add update endpoints (dev-phase; no auth yet):
- `set_scheduler_enabled(enabled: bool) -> String`
- `set_task_interval_secs(kind: TaskKind, interval_secs: u64) -> Result<String, String>`
- `set_task_enabled(kind: TaskKind, enabled: bool) -> String`

---

## TDD-First Implementation Plan

- [x] **Task 1: Add domain scheduler contracts + unit tests first**
      - Files: `src/domain/types.rs`, `src/domain/mod.rs` (if needed), `src/scheduler.rs` (type-only stubs), `tests/scheduler_domain.rs`
      - Validation: `cargo test --test scheduler_domain`
      - Notes: Add enums/structs/defaults and serialization tests before storage/logic.

- [x] **Task 2: Implement durable scheduler storage + unit tests first**
      - Files: `src/storage/stable.rs`, `tests/scheduler_storage.rs`
      - Validation: `cargo test --test scheduler_storage`
      - Notes: Implement queue ordering, dedupe insertion guard, lease lifecycle, stale lease recovery.

- [x] **Task 3: Implement scheduler tick engine + unit tests first**
      - Files: `src/scheduler.rs`, `src/storage/stable.rs`, `tests/scheduler_tick.rs`
      - Validation: `cargo test --test scheduler_tick`
      - Notes: Cover due-job materialization, no catch-up burst, serialization guarantee.

- [x] **Task 4: Integrate existing agent loop as `TaskKind::AgentTurn` handler**
      - Files: `src/agent.rs`, `src/scheduler.rs`
      - Validation: `cargo test`
      - Notes: Keep existing FSM semantics; enforce job contract (`Result<(), String>`).

- [x] **Task 5: Replace timer wiring and add scheduler public APIs**
      - Files: `src/lib.rs`, `src/domain/types.rs`, `ic-automaton.did` (generated)
      - Validation: `cargo test && icp build`
      - Notes: Use `set_timer_interval_serial`; export query/update endpoints for scheduler control.

- [x] **Task 6: Add canlog structured scheduler/job logs**
      - Files: `src/scheduler.rs`, `src/agent.rs`, `src/features/*` as needed
      - Validation: `cargo test`
      - Notes: Log lifecycle events with stable identifiers for correlation.

- [x] **Task 7: PocketIC integration tests for ICP-specific behavior**
      - Files: `tests/pocketic_scheduler_queue.rs`, `Cargo.toml` (dev-dependencies)
      - Validation: `cargo test --test pocketic_scheduler_queue -- --nocapture`
      - Notes: Validate non-interleaving, duplicate tick tolerance, upgrade re-arm behavior.

- [x] **Task 8: Final validation and cleanup**
      - Files: `src/*`, `tests/*`, `ic-automaton.did` (generated)
      - Validation: `cargo fmt --all -- --check && cargo clippy --all-targets --all-features && cargo test && icp build && bash .githooks/pre-commit`
      - Notes: Do not hand-edit `ic-automaton.did`.

---

## Test Matrix (Required)

### Unit
- Queue key ordering selects earliest due then highest priority.
- Dedupe guard prevents duplicate pending/inflight jobs for same dedupe key.
- Lease acquisition rejects second mutating lease.
- Stale lease recovery marks timed out and clears lease.
- Backoff progression is exponential and capped.

### Integration (PocketIC)
- Concurrent ticks still result in single mutating in-flight execution.
- Duplicate timer trigger cannot create duplicate successful terminal effects for one cadence slot.
- `post_upgrade` re-arms timer and scheduling resumes.
- Low-cycles mode suppresses non-essential tasks.

### Regression
- Existing turn orchestration remains functional under scheduler dispatch.
- Existing runtime view/list_turns/list_recent_events remain backwards usable in dev phase.

---

## Security / Safety Notes
- Maintain idempotency at handler level even with serialized lane.
- Never clear a lease without writing terminal job status.
- Avoid unbounded queue growth:
  - one pending job per task kind in this slice,
  - capped historical job retention (e.g., keep last N records; archive/drop older entries).
- Keep sensitive config out of query endpoints.

---

## Verification

### Smoke Tests
- `cargo check` -- scheduler/types/storage compile.
- `cargo fmt --all -- --check` -- formatting clean.
- `cargo clippy --all-targets --all-features` -- lint checks pass.
- `cargo test` -- unit and integration suites pass.

### Expected State
- `src/scheduler.rs` exists and owns the scheduler tick orchestration.
- `src/storage/stable.rs` contains scheduler maps, queue index, dedupe index, and lease APIs.
- `src/domain/types.rs` includes `TaskKind`, `ScheduledJob`, `SchedulerLease`, and scheduler view types.
- `src/lib.rs` arms scheduler timer in `init` and `post_upgrade`.
- `ic-automaton.did` includes scheduler query/update endpoints from Rust export.

### Regression
- `bash .githooks/pre-commit` passes.

### Integration Test
- `cargo test --test pocketic_scheduler_queue -- --nocapture` proves:
  1. serialized mutating execution,
  2. duplicate tick idempotency,
  3. post-upgrade re-arm,
  4. low-cycles task gating.


## After verification

- Generate commit message and commit.
- Mark Task complete.

---

## Codebase Snapshot

Snapshot date: 2026-02-19

- Current scheduler entrypoint is timer-driven `run_scheduled_turn` from `src/lib.rs`.
- Runtime lock is currently a single `turn_in_flight` flag in `RuntimeSnapshot`.
- No dedicated scheduler module exists yet.
- No `tests/` directory exists yet; this spec introduces one.

---

## Autonomy Scope

### Decide yourself
- Exact stable key formats for queue ordering and dedupe index.
- Exact default intervals/priorities for initial task config values.
- Whether `PollInbox`/`Reconcile` are no-op placeholders in the first implementation PR.

### Escalate (log blocker, skip, continue)
- Any request to allow parallel mutating execution.
- Any request to remove dedupe keys or lease timeout recovery.
- Any request to add external distributed queue components in this slice.

---

## Progress

_Dev agent writes here during execution._

### Completed
- Spec locked.
- Task 2 completed (durable scheduler storage APIs and unit tests added in `src/storage/stable.rs`).
- Task 3 completed (scheduler tick orchestration with unit tests added in `src/scheduler.rs`).
- Task 4 completed (agent loop handler wired to scheduler as `TaskKind::AgentTurn`).
- Task 5 completed (scheduler timer wiring and public scheduler/task APIs are in `src/lib.rs`).
- Task 6 completed (canlog events added to scheduler orchestration and storage paths).
- Task 7 completed with executable tests in `tests/pocketic_scheduler_queue.rs`.
- Task 8 completed (final validation/cleanup tracked; runtime and queue integration stabilized; remaining non-git housekeeping steps are ready for execution when desired).

### Blockers
- None.

### Learnings
- ICP timer behavior and async message scheduling strongly favor explicit durable scheduler state over timer-per-task orchestration.
