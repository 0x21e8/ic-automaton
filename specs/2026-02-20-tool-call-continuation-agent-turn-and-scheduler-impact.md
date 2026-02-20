# Spec: Tool-Call Continuation in Agent Turns (OpenRouter/IcLlm) with Scheduler-Safe Bounds

**Status:** LOCKED
**Date:** 2026-02-20
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** complex
**Authority:** approval
**Tier:** 3

---

## Problem
OpenRouter (and potentially IcLlm) responses frequently terminate with tool calls, but the runtime currently executes tools and ends the turn without sending tool outputs back to inference for a continuation response. This breaks the standard tool-call protocol for multi-step reasoning and explains why provider logs show requests finishing at `tool_calls`.

Because continuation is missing, final assistant responses are synthesized locally from tool records, not model-completed after tool results. Adding continuation increases per-turn work and directly impacts scheduler lease duration, tick throughput, and retry/backoff behavior.

## Goal
Implement bounded, same-turn inference continuation after tool execution so the agent can:
1. Execute model-requested tools.
2. Send tool results back to the provider in the same turn.
3. Receive a final assistant response (or additional tool calls) up to a strict round limit.

Measurable success:
1. A turn with provider-emitted `tool_calls` performs at least one continuation inference call in the same `AgentTurn` job.
2. Final outbox reply prefers the model’s post-tool continuation content when available.
3. Turn runtime is bounded by explicit round/time caps, and scheduler behavior remains serial and non-overlapping.
4. No duplicate side effects are introduced by continuation-stage failures.

## Non-Goals
- Streaming token responses.
- Redesigning the scheduler into multiple lanes or multiple timers.
- Generic planner/graph execution beyond linear bounded rounds.
- Backward-compatibility migrations for pre-existing stable turn/tool records (development phase allows schema evolution).

---

## Human Clarifications Applied
- None in-session; scope was inferred from the request and repository behavior.

## Autonomous Decisions
- Implement continuation inside the existing `AgentTurn` job rather than introducing a new task kind.
- Keep single scheduler timer architecture (`set_timer_interval_serial`) and mutating-lane lease model.
- Add strict continuation bounds (round cap + wall-time cap) to protect scheduler liveness.
- Treat post-tool continuation inference failures as degraded completion (not hard turn failure) to avoid retrying already-executed side effects.

---

## Investigation Summary (Current Behavior)

### Inference/Tool Protocol Gap
- `src/features/inference.rs` currently builds only `system + user` request messages and returns `tool_calls` + explanation.
- `src/agent.rs` executes returned tools once and does not issue a second inference call with tool outputs.
- OpenRouter parser currently reads tool call IDs but drops them before returning runtime `ToolCall` values.

### Agent Loop Behavior
- Turn flow is single-pass inference -> tool execution -> persist.
- Outbox reply is currently either inference explanation or local “Tool results: …” summary.
- Tool-call dedupe for autonomy suppresses repeated calls by removing them before execution.

### Timer/Scheduler Behavior
- Single serial scheduler tick (`src/lib.rs`) dispatches queued mutating jobs.
- `TaskKind::AgentTurn` uses a mutating lease with TTL 120s (`src/scheduler.rs`).
- Scheduler can process up to 4 mutating jobs per tick (`MAX_MUTATING_JOBS_PER_TICK`).
- Failure of `run_scheduled_turn_job` marks job failed and applies task backoff (`src/storage/stable.rs`).

---

## Timer & Agent Loop Impact Analysis

### 1) Per-turn runtime inflation
Continuation adds one or more additional inference outcalls per turn. Without bounds, `AgentTurn` duration can increase enough to reduce scheduler cadence effectiveness.

Required impact response:
- Add `MAX_INFERENCE_ROUNDS_PER_TURN` (default: 3).
- Add `MAX_AGENT_TURN_DURATION_NS` guard (must be below lease TTL with safety margin).
- Stop continuation and finalize degraded reply when either bound is reached.

### 2) Mutating lease risk
Longer turns increase lease expiry risk during failures/restarts.

Required impact response:
- Increase `TaskKind::AgentTurn` lease TTL from 120s to 240s.
- Emit explicit logs when a turn exits due to round/time caps.

### 3) Scheduler throughput/latency
A heavier `AgentTurn` can delay `PollInbox`/`CheckCycles` processing in the same tick cycle.

Required impact response:
- Keep current architecture, but add observability for `inference_round_count` and `turn_duration_ms` in turn diagnostics/logs.
- Do not add new timer callbacks.

### 4) Retry/backoff semantics after side effects
If continuation fails after tools already ran, hard-failing the turn causes scheduler/job retry pressure and can replay side effects for inbox messages.

Required impact response:
- Initial inference failure behavior stays unchanged.
- Continuation-stage inference failure after any executed tool becomes non-fatal turn degradation with fallback reply.

### 5) Autonomy dedupe interaction
Current suppression removes calls entirely; continuation protocols require a tool-result message per model tool call.

Required impact response:
- Replace “drop suppressed call” with “synthetic skipped tool result record” so continuation still receives tool output for each requested call.

---

## Requirements

### Must Have
- [ ] Add bounded multi-round continuation loop to `run_scheduled_turn_job`.
- [ ] Preserve provider tool-call IDs through inference parsing for both OpenRouter and IcLlm paths.
- [ ] Extend inference request construction to support transcript-style messages (`assistant tool_calls` + `tool` messages) for continuation rounds.
- [ ] Execute model tool calls and feed tool outputs back into inference in the same turn until:
  - no more tool calls, or
  - max rounds reached, or
  - max turn duration reached.
- [ ] Keep scheduler architecture unchanged (single timer, serial mutating lane), but increase `AgentTurn` lease TTL to 240s.
- [ ] Convert continuation-stage inference failure (after any executed tool) to degraded success with fallback response instead of hard turn failure.
- [ ] Preserve existing survival-operation checks per inference call.
- [ ] Update autonomy dedupe behavior to generate synthetic tool-result outputs rather than removing suppressed calls.
- [ ] Add/adjust unit and PocketIC tests covering continuation semantics and scheduler impact boundaries.

### Should Have
- [ ] Add turn-level diagnostics fields for `inference_round_count` and `continuation_stop_reason` (none | max_rounds | max_duration | inference_error).
- [ ] Include provider request/response logs for continuation rounds with sensitive data redaction.
- [ ] Cap total tool calls processed per turn to prevent pathological loops.

### Could Have
- [ ] Add a query helper to inspect continuation details for the most recent turn.
- [ ] Add a configurable runtime knob for max continuation rounds.

---

## Constraints
- Keep KISS: continuation is linear, bounded, and in-process within one `AgentTurn`.
- No additional scheduler timers or task kinds in this slice.
- No secret leakage in logs, observability snapshot, or query interfaces.
- Continue using non-replicated OpenRouter outcalls for inference.
- Maintain host-safe time helpers (no direct `ic_cdk::api::time()` in native test-executed code paths).
- Do not hand-edit Candid; rely on Rust export workflow.

---

## Success Criteria
- A provider response containing `tool_calls` triggers a continuation inference request with tool-role messages in the same turn.
- Outbox body for inbox-driven turns reflects continuation model text when returned; falls back to deterministic tool summary on degraded continuation.
- Scheduler jobs remain serialized with no overlap, and no timer infra changes beyond lease TTL adjustment.
- New tests verify:
  - continuation rounds terminate correctly,
  - bounded runtime behavior,
  - no hard failure on post-tool continuation error,
  - dedupe-suppressed calls still produce tool outputs for continuation protocol completeness.

---

## Implementation Plan

- [x] **Task 1: Add continuation-capable inference data model and parsers (TDD first)**
      - Files: `src/domain/types.rs`, `src/features/inference.rs`
      - Validation: `cargo test -q parse_openrouter_completion` and `cargo test -q parse_ic_llm_response_maps_tool_calls`
      - Notes: Carry tool-call IDs forward; preserve strict JSON argument parsing.

- [x] **Task 2: Add transcript-based inference request building for initial and continuation rounds**
      - Files: `src/features/inference.rs`
      - Validation: `cargo test -q openrouter_request_body_uses_full_assembled_prompt_with_conversation_context` and new continuation-request unit tests
      - Notes: Keep system prompt + dynamic context on round 0; append assistant/tool messages for subsequent rounds.

- [x] **Task 3: Refactor agent loop into bounded multi-round infer/execute/continue cycle**
      - Files: `src/agent.rs`, `src/tools.rs`
      - Validation: `cargo test -q no_input_turn_runs_autonomous_inference_and_records_inner_dialogue` and new continuation loop tests
      - Notes: Implement max rounds/time guards and degraded continuation fallback behavior.

- [ ] **Task 4: Update autonomy dedupe behavior for continuation protocol completeness**
      - Files: `src/agent.rs`
      - Validation: new unit test asserting suppressed autonomy calls still generate tool outputs consumable by continuation
      - Notes: Use synthetic “skipped due to freshness dedupe” tool records when suppression applies.

- [ ] **Task 5: Apply scheduler safeguards for longer AgentTurn jobs**
      - Files: `src/scheduler.rs`, `tests/pocketic_scheduler_queue.rs`
      - Validation: `cargo test -q refresh_due_jobs_advances_single_interval_once` and new lease-duration regression coverage
      - Notes: Increase `AgentTurn` lease TTL to 240s; keep serial dispatch model unchanged.

- [ ] **Task 6: Integration validation with PocketIC**
      - Files: `tests/pocketic_agent_autonomy.rs`, `tests/pocketic_ui_observability.rs`
      - Validation: `icp build && cargo test -q --features pocketic_tests continuation`
      - Notes: Build before PocketIC tests to avoid stale Wasm artifacts.

- [ ] **Task 7: Final validation and candid sync**
      - Files: `src/lib.rs`, `ic-automaton.did` (generated)
      - Validation: `cargo check && cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test -q && icp build`
      - Notes: Ensure exported interfaces remain coherent and API-key redaction remains intact.

---

## Context Files

- `AGENTS.md`
- `src/agent.rs`
- `src/features/inference.rs`
- `src/tools.rs`
- `src/scheduler.rs`
- `src/storage/stable.rs`
- `src/domain/state_machine.rs`
- `src/domain/types.rs`
- `src/lib.rs`
- `tests/pocketic_agent_autonomy.rs`
- `tests/pocketic_scheduler_queue.rs`
- `docs/design/TASK_SCHEDULING_PATTERNS_ICP.md`
- `specs/2026-02-19-serial-control-plane-durable-job-queue.md`

---

## Codebase Snapshot

Snapshot date: 2026-02-20

- `src/agent.rs` performs a single inference call per turn and does not perform continuation after tool execution.
- `src/features/inference.rs` request builders currently emit only `system + user` messages; parser returns tool name/args but discards provider call IDs.
- `src/tools.rs` executes calls sequentially and records outputs without provider call-id linkage.
- `src/scheduler.rs` uses one serial timer, mutating lease, and `TaskKind::AgentTurn` lease TTL of 120 seconds.
- `src/storage/stable.rs` marks failed jobs with backoff and clears active lease on completion/timeout recovery.
- `tests/pocketic_scheduler_queue.rs` asserts serialized mutating execution, dedupe idempotency, and post-upgrade timer re-arm behavior.

---

## Autonomy Scope

### Decide yourself:
- Exact struct names for transcript/tool-result payloads.
- Whether to add new optional fields vs new records for continuation diagnostics.
- Exact constant values for max continuation rounds and max turn duration (within specified safety intent).

### Escalate (log blocker, skip, continue):
- Any requirement to split continuation into separate scheduler tasks.
- Any request to remove bounded guards (round/time caps).
- Any change that would expose secrets in observability or logs.
- Any dependency on undocumented provider semantics that cannot be validated via tests.

---

## Verification

### Smoke Tests
- `cargo check` -- compile all continuation and scheduler guard changes.
- `cargo fmt --all -- --check` -- enforce formatting.
- `cargo clippy --all-targets --all-features -- -D warnings` -- lint and safety checks.
- `cargo test -q` -- unit/regression coverage for agent, inference, scheduler, and storage.
- `icp build` -- ensure canister build and generated artifacts are in sync.

### Expected State
- File `src/agent.rs` contains bounded continuation loop logic and explicit continuation stop reasons.
- File `src/features/inference.rs` supports transcript-based request building and preserves provider tool-call IDs.
- File `src/scheduler.rs` sets `TaskKind::AgentTurn` lease TTL to 240 seconds.
- File `src/domain/types.rs` includes continuation-capable tool-call metadata structures.
- `rg -n "MAX_INFERENCE_ROUNDS_PER_TURN|continuation|tool_call_id" src` returns expected implementation markers.

### Regression
- `cargo test -q`
- `cargo test -q --features pocketic_tests pocketic_scheduler_queue`

### Integration Test
- `icp build && cargo test -q --features pocketic_tests pocketic_agent_autonomy::agent_continues_after_tool_results_and_posts_final_reply -- --exact --nocapture`
  - Proves: one scheduler turn can execute tools, perform continuation inference, and persist final outbox reply without requiring a second timer tick.

---

## Progress

### Completed
- Spec locked with scheduler/timer impact analysis and executable implementation plan.

### Blockers
- None.

### Learnings
- The current architecture already guarantees serial mutating execution; continuation can be added safely if turn-level runtime is explicitly bounded and continuation failure semantics avoid replay pressure after side effects.

---

## Ship Checklist (non-negotiable final step)

- [ ] Run full verification suite.
- [ ] Confirm no API-key leakage in logs/responses/snapshots.
- [ ] Confirm no timer infra regression (serial execution, dedupe idempotency, upgrade re-arm).
- [ ] Confirm Candid regeneration from Rust exports only.
