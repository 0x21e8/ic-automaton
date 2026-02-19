# ICP Automaton Task Scheduling Patterns

## Objective
Select a scheduling model for periodic automaton work (agent loop, inbox/message polling, cycle-balance checks, reconciliation, health pings) that:
- supports different cadences per task,
- prevents unsafe interleaving of critical calls,
- stays reliable under ICP runtime constraints,
- remains simple enough to evolve.

This document compares three options:
1. Many independent timers (one timer per task type)
2. One unified scheduler with typed tasks
3. A stronger ICP-native pattern (serial control-plane scheduler + durable job queue)

## Current Baseline In This Repo
Current code arms one timer in `src/lib.rs` and runs one orchestrated turn (`run_scheduled_turn`) from `src/agent.rs`. A `turn_in_flight` flag in stable state avoids overlapping turns.

This baseline is already close to a unified control plane, but new periodic concerns are coming and need an explicit scheduling design.

## ICP Runtime Constraints That Drive The Design
These constraints are decisive (not optional design preferences):
- No persistent process/thread: execution is message-driven.
- `await` yields control; other messages may run before continuation.
- Timers from `ic-cdk-timers` are not persisted across upgrade; re-arm in `post_upgrade`.
- `set_timer_interval` can trigger overlapping invocations; callbacks must be idempotent.
- `set_timer_interval_serial` skips overlapping invocations for that timer, but stable-state leases are still needed for hard safety guarantees.
- Under load/timeouts, duplicate timer execution can happen; dedupe/idempotency is required.
- Timer execution uses internal self-calls, so timer-heavy designs add call overhead and cycle cost.

Implication: "Do not interleave calls" cannot rely on timer API behavior alone. It needs explicit runtime guards in stable state.

## Option 1: Many Independent Timers
### Shape
Each task owns its own interval timer.

```rust
fn arm_timers() {
    ic_cdk_timers::set_timer_interval(Duration::from_secs(30), || async {
        run_agent_loop().await;
    });

    ic_cdk_timers::set_timer_interval(Duration::from_secs(15), || async {
        poll_inbox().await;
    });

    ic_cdk_timers::set_timer_interval(Duration::from_secs(60), || async {
        check_cycles_balance().await;
    });
}
```

### Advantages
- Very simple to add the first few tasks.
- Each task can have an independent cadence with minimal framework code.
- Local reasoning per task is straightforward at small scale.

### Disadvantages
- Hard to prevent cross-task interleaving without adding a global lock protocol.
- Easy to create hidden race-like behavior around shared state/cursors.
- Backoff, retries, logging, and observability get duplicated across task handlers.
- More timers means more internal scheduling/self-call overhead and potential timer storms.
- Failure handling becomes fragmented (each timer invents its own behavior).

### Safety Notes
If this option is used, add at least:
- one global execution lease in stable state,
- per-task idempotency keys,
- consistent retry/backoff policy,
- explicit low-cycles degradation policy.

At that point, complexity converges toward a unified scheduler anyway.

## Option 2: Unified Task System (Single Scheduler)
### Shape
One scheduler tick checks typed task definitions and dispatches due work.

```rust
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum TaskKind { AgentTurn, PollInbox, CheckCycles, Reconcile }

struct TaskRuntime {
    next_due_ns: u64,
    backoff_until_ns: u64,
    last_error: Option<String>,
}

async fn scheduler_tick() -> Result<(), String> {
    if stable::scheduler_has_inflight() {
        return Ok(());
    }

    let now = ic_cdk::api::time();
    if let Some(task) = stable::pick_next_due_task(now) {
        let run_id = stable::acquire_scheduler_lease(task, now)?;
        let result = run_task(task).await;
        stable::finish_scheduler_run(run_id, task, result, now);
    }
    Ok(())
}

fn arm_scheduler() {
    ic_cdk_timers::set_timer_interval_serial(Duration::from_secs(1), async || {
        let _ = scheduler_tick().await;
    });
}
```

### Advantages
- Single place for non-interleaving enforcement.
- Uniform retries, backoff, jitter, and observability.
- Easier to reason about invariants and upgrade re-arming.
- Better extensibility as task count grows.
- Easier to test deterministically (one scheduler state machine).

### Disadvantages
- More upfront framework code than independent timers.
- One scheduler bug can affect all periodic work.
- Potential head-of-line blocking unless prioritization and budget limits are explicit.

### Safety Notes
- Keep scheduler lease in stable memory.
- Make task handlers idempotent even with serialization.
- Use bounded per-tick work and priority rules to avoid starvation.

## Option 3 (Recommended): Serial Control Plane + Durable Job Queue
This is a stronger pattern than either extreme for ICP.

### Shape
- Keep one serial scheduler timer (`set_timer_interval_serial`) as control plane.
- Maintain durable per-task cadence metadata (`next_due_ns`, backoff, health).
- Scheduler enqueues concrete jobs (with dedupe keys) into a durable queue.
- A single worker lease executes one mutating job at a time.
- Cheap read-only probes may run with a separate read lane later, but writes remain serialized.

```rust
enum Lane { ReadOnly, Mutating }

struct Job {
    id: String,
    kind: TaskKind,
    lane: Lane,
    dedupe_key: String,
    scheduled_at_ns: u64,
}

async fn scheduler_tick() -> Result<(), String> {
    let now = ic_cdk::api::time();
    refresh_due_jobs(now); // derives jobs from cadence metadata

    if stable::mutating_lane_busy() {
        return Ok(());
    }

    if let Some(job) = stable::pop_next_job(Lane::Mutating, now) {
        let lease = stable::acquire_lane_lease(Lane::Mutating, &job.id, now)?;
        let result = execute_job(job.clone()).await;
        stable::complete_job(lease, job, result, now);
    }
    Ok(())
}
```

### Why this is better on ICP
- Enforces non-interleaving as a first-class invariant.
- Survives timer jitter/duplicates because queue + dedupe is explicit.
- Cleanly separates policy (cadence/priority) from execution (jobs).
- Supports future extensibility without multiplying timers.
- Maps well to stable-memory-first architecture and audit requirements.

### Main tradeoff
- Slightly more design work now, but less operational risk and less accidental complexity later.

## Comparison Across Decision Dimensions
| Dimension | Many timers | Unified scheduler | Serial control plane + durable queue |
|---|---|---|---|
| Simplicity (initial) | High | Medium | Medium |
| Simplicity (at 6+ tasks) | Low | Medium/High | High |
| Extensibility | Low/Medium | High | High |
| Safety (non-interleaving) | Low by default | High | Very high |
| Safety (duplicate execution) | Low/Medium | Medium/High | High |
| Observability consistency | Low | High | High |
| Failure isolation | Medium | Medium | High (explicit retries + queue state) |
| Cycle efficiency at scale | Medium/Low | Medium/High | High |
| Testability | Medium | High | High |

## Recommendation
Adopt Option 3: serial control-plane scheduler with a durable typed job queue.

### Hard Invariants
- At most one mutating job executes at any time.
- Every job has an idempotency key.
- Every completion writes a terminal run record (success/failure/timeout).
- Timer setup is re-armed in both `init` and `post_upgrade`.
- On low cycles, scheduler degrades to essential tasks only.

## Minimal Migration Path From Current Code
1. Keep current `run_scheduled_turn` as `TaskKind::AgentTurn` handler.
2. Introduce `TaskKind::CheckCycles` and `TaskKind::PollInbox` as queued jobs.
3. Replace direct timer-per-task additions with cadence metadata entries.
4. Add a query endpoint for scheduler diagnostics (next due, inflight, last errors).
5. Add PocketIC tests for:
   - no overlapping mutating jobs,
   - duplicate timer tick tolerance,
   - upgrade + timer re-arm behavior,
   - low-cycles degradation mode.

## Implementation Notes For This Repo
- Use `canlog` for structured scheduler/job lifecycle logs.
- Keep scheduler state in stable structures (same persistence approach as runtime snapshot/turn logs).
- Keep task handlers side-effect-safe and idempotent; serialization reduces risk but is not a substitute for idempotency.

## References Reviewed
- `docs/design/ICP_ANALYSIS.md` (Section 2: Agent Loop and Heartbeat patterns, plus runtime gap analysis)
- `src/lib.rs` (current timer arming and upgrade re-arm behavior)
- `src/agent.rs` (current single-turn orchestration and `turn_in_flight` guard usage)
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ic-cdk-timers-1.0.0/src/lib.rs` and `.../global_timer.rs` (timer overlap/duplicate behavior and internal self-call execution model)
