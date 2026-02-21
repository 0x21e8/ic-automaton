# Spec: Recovery Policy Consolidation and Typed Outcall Error Taxonomy

**Status:** LOCKED
**Date:** 2026-02-21
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** complex
**Authority:** approval
**Tier:** 3

---

## Problem
Recovery behavior is currently spread across multiple layers with different mechanisms: survival-operation backoff, scheduler task backoff, FSM fault recovery, and feature-local string-matched recovery paths. Recent wallet-sync size auto-recovery improved resilience but added another custom policy branch.

This fragmentation increases drift risk, makes failures harder to reason about, and can produce inconsistent observability and retry semantics across inference, EVM poll, wallet sync, and tool execution paths.

## Goal
Define and implement a single, typed recovery architecture so all operational failures follow a consistent policy pipeline:
1. Classify failures into typed categories.
2. Apply one centralized recovery policy (retry/backoff/tune/fail).
3. Persist and expose coherent recovery telemetry.

Measurable success:
1. No string-fragile policy branching in scheduler/features for core recovery decisions.
2. Wallet sync, EVM poll, and inference use shared recovery policy primitives.
3. Recovery outcomes are visible through structured state/logging with bounded, testable behavior.

## Non-Goals
- Replacing current scheduler queue architecture.
- Rewriting all feature adapters in one step.
- Introducing new external services or infrastructure.
- Changing business logic of agent goals/prompts.

---

## Autonomous Decisions
- Treat this as an architectural consolidation (approval authority, Tier 3).
- Propose incremental migration with compatibility shims to reduce risk.
- Keep existing behavior guarantees (autonomous self-heal, non-fatal transient degradation) while consolidating policy.
- Preserve current persisted config surfaces and only extend where needed.

---

## Findings (Current State)
- Survival-operation gating/backoff exists and is generic:
  - `src/storage/stable.rs` (`can_run_survival_operation`, `record_survival_operation_failure`, `record_survival_operation_success`).
- Scheduler task backoff/lease recovery is separate:
  - `src/storage/stable.rs` (`complete_job`, `recover_stale_lease`).
- Wallet sync size recovery is custom and string-based:
  - `src/scheduler.rs` (`wallet_sync_error_suggests_response_limit_increase`, `maybe_increase_wallet_sync_max_response_bytes`).
- Transport layers emit free-form error strings:
  - `src/features/evm.rs`, `src/features/inference.rs`.
- Retry/attempt metadata exists (`ScheduledJob.max_attempts`) but is not authoritative policy:
  - `src/domain/types.rs`, `src/storage/stable.rs`.

---

## Requirements

### Must Have
- [ ] Introduce a typed recovery/error model for outcall and operation failures (shared domain type).
- [ ] Define one policy engine that maps typed failure + operation context to action:
      `Skip`, `RetryImmediate`, `Backoff`, `TuneResponseLimit`, `EscalateFault`.
- [ ] Remove policy-critical string matching from scheduler/feature logic, preserving only adapter-level error translation.
- [ ] Unify response-size adaptive tuning policy across wallet sync and other eligible outcalls.
- [ ] Align survival-operation accounting and task-level outcomes with policy decisions (single semantic source).
- [ ] Add structured observability for recovery actions (action chosen, reason, bounds, before/after values).
- [ ] Add migration-safe defaults and bounds so existing deployments can recover without manual intervention.
- [ ] Add integration coverage for real recovery paths (size-limit, transient transport, configuration errors).

### Should Have
- [ ] Make `ScheduledJob.max_attempts` either enforced or removed/deprecated to eliminate semantic ambiguity.
- [ ] Separate configured vs effective adaptive runtime limits for response-byte caps.
- [ ] Add a small query view exposing recent recovery events and active adaptive overrides.

### Could Have
- [ ] Add common helper macros/functions for consistent canlog recovery event emission.
- [ ] Add policy simulation unit harness to validate future policy tweaks without full integration tests.

---

## Constraints
- Keep KISS: consolidate policy flow, do not redesign scheduler lanes.
- Preserve current autonomy invariant: transient failures must self-heal without operator resets.
- Keep runtime-safe bounds for all adaptive tuning.
- Avoid secret leakage in errors/logs/telemetry.
- Keep host-safe time behavior in tests.
- Preserve generated Candid workflow (`ic_cdk::export_candid!()`).

---

## Success Criteria
- Recovery decisions are traceable to one policy component with typed inputs.
- Wallet sync bootstrap can recover from size-limit failures without bespoke branch logic.
- Equivalent transient failures in inference/EVM/wallet domains produce consistent policy semantics.
- Observability clearly distinguishes classification, policy action, and resulting state changes.
- Verification suite passes with new and regression tests.

---

## Implementation Plan

- [x] **Task 1: Define shared recovery domain model and policy engine**
      - Files: `src/domain/types.rs`, `src/domain/recovery_policy.rs` (new), `src/domain/mod.rs`
      - Validation: `cargo test --lib domain::types::tests:: recovery_policy::tests::`
      - Notes: Add typed failure taxonomy and pure policy mapping from failure + context to action.

- [ ] **Task 2: Translate feature-layer errors into typed failures**
      - Files: `src/features/evm.rs`, `src/features/inference.rs`, `src/features/http_fetch.rs` (if touched)
      - Validation: `cargo test --lib features::evm::tests:: features::inference::tests::`
      - Dependencies: Task 1
      - Notes: Keep adapters responsible for classification input, not policy decisions.

- [ ] **Task 3: Consolidate scheduler/storage execution semantics**
      - Files: `src/scheduler.rs`, `src/storage/stable.rs`, `src/domain/types.rs`
      - Validation: `cargo test --lib scheduler::tests:: storage::stable::tests::`
      - Dependencies: Task 1, Task 2
      - Notes: Replace bespoke wallet-sync policy branch, unify backoff/tuning accounting, and resolve `max_attempts` semantics (enforce or deprecate).

- [ ] **Task 4: Integration coverage, observability, and final validation**
      - Files: `tests/pocketic_wallet_balance_sync.rs`, `tests/pocketic_agent_autonomy.rs`, `tests/pocketic_evm_polling.rs`, `src/http.rs` (if adding recovery view)
      - Validation: `icp build && cargo test --features pocketic_tests --test pocketic_wallet_balance_sync -- --nocapture && cargo fmt --all -- --check && cargo clippy --all-targets --all-features && cargo test && icp build`
      - Dependencies: Task 1, Task 2, Task 3
      - Notes: Add oversized-response integration case and verify unified policy behavior end-to-end.

---

## Context Files

- `AGENTS.md`
- `src/scheduler.rs`
- `src/storage/stable.rs`
- `src/domain/types.rs`
- `src/domain/state_machine.rs`
- `src/features/evm.rs`
- `src/features/inference.rs`
- `src/tools.rs`
- `tests/pocketic_wallet_balance_sync.rs`
- `tests/pocketic_agent_autonomy.rs`
- `tests/pocketic_evm_polling.rs`
- `docs/design/CYCLES_SURVIVAL_MODE_AND_HTTPS_OUTCALL_COST_CONTROL.md`

---

## Codebase Snapshot

Snapshot date: 2026-02-21

- Recovery mechanisms currently exist in parallel:
  - survival-operation backoff: `src/storage/stable.rs`
  - scheduler job backoff/lease timeout: `src/storage/stable.rs`, `src/scheduler.rs`
  - FSM self-heal from `Faulted` on `TimerTick`: `src/domain/state_machine.rs`, `src/agent.rs`
  - wallet-sync size auto-tuning (custom): `src/scheduler.rs`
- Core outcall layers still expose string-heavy errors:
  - `src/features/evm.rs`, `src/features/inference.rs`
- Integration tests validate many degradation flows but do not yet provide an end-to-end oversized-reply policy test with typed classification:
  - `tests/pocketic_wallet_balance_sync.rs`

---

## Autonomy Scope

### Decide yourself:
- Exact typed error enum naming and module boundaries.
- Whether to keep policy engine in `domain/` vs `scheduler/` as long as it remains pure and reusable.
- Whether to enforce or deprecate `max_attempts`, provided semantics are explicit and tested.
- Exact telemetry payload shape for recovery events.

### Escalate (log blocker, skip, continue):
- Any proposed change that alters economic safety policy (cycles reserve floor, survival tier thresholds).
- Any migration that could break existing stable data decoding.
- Any widening of public API surface that exposes sensitive internals.

---

## Verification

### Smoke Tests
- `cargo fmt --all -- --check` -- formatting and syntax integrity.
- `cargo clippy --all-targets --all-features` -- lint and correctness checks.
- `cargo test --lib scheduler::tests::` -- scheduler recovery/backoff behavior.
- `cargo test --lib features::evm::tests:: features::inference::tests::` -- adapter translation and outcall behavior.
- `icp build` -- canister build and generated artifacts remain healthy.

### Expected State
- `rg -n "Recovery|FailureKind|PolicyAction|recover" src/domain src/scheduler.rs src/storage/stable.rs` shows one typed policy path.
- `rg -n "max_response_bytes" src/scheduler.rs src/storage/stable.rs src/features/evm.rs` shows consolidated bounds and policy wiring (no duplicated policy constants).
- `rg -n "max_attempts" src/domain/types.rs src/storage/stable.rs src/scheduler.rs` shows explicit enforced or deprecated semantics.

### Regression
- `bash .githooks/pre-commit` passes.

### Integration Test
- `icp build && cargo test --features pocketic_tests --test pocketic_wallet_balance_sync -- --nocapture`
  - asserts bootstrap exits under size-limit failure via unified policy path,
  - asserts typed classification and policy action are observable,
  - asserts no manual reset is required.

---

## Progress

_Dev agent writes here during execution._

### Completed
- Spec locked.
- Task 1 complete: added typed recovery domain model, added pure recovery policy engine, and validated with targeted unit tests plus strict repo checks (`bash .githooks/pre-commit`, `cargo test`).

### Blockers
- None.

### Learnings
- Current recovery behavior is functionally robust but policy-fragmented; consolidation should prioritize typed classification and single-decision ownership before widening feature scope.

---

## Ship Checklist (non-negotiable final step)

- [ ] Run full verification suite.
- [ ] Confirm no secret-bearing error payloads are exposed in queries/logs.
- [ ] Confirm stable-state migration safety for any new typed recovery fields.
- [ ] Confirm Candid remains generated from Rust exports.
