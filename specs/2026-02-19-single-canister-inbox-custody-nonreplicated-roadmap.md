# Spec: Single-Canister Automaton v1.1 (Inbox-Custody + Non-Replicated Outcalls)

**Status:** LOCKED (revised)
**Date:** 2026-02-20
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** complex
**Authority:** approval
**Tier:** 3

---

## Supersedes

This spec is the execution source of truth and supersedes implementation guidance in:
- `specs/2026-02-18-ic-automaton-v1-state-machine-skeleton.md`
- `specs/2026-02-18-inference-provider-ic-llm-then-openrouter.md`
- `specs/2026-02-18-evm-inbox-paid-events-http-outcalls-anvil-foundry-e2e.md`
- `specs/2026-02-19-autonomous-usdc-lock-flow-base-to-icp.md`

---

## Problem

The current roadmap is directionally correct but drifts from the current repository reality in several critical places (scheduler role boundaries, tests presence, and inbox ingestion wiring). It also does not yet define a concrete shared-Inbox strategy for many automatons that controls HTTPS outcall spend.

## Goal

Define one consistent, executable v1.1 plan where:
1. Runtime remains single-canister for this project.
2. `InboxContract` is the USDC custody point.
3. Inference and EVM polling use non-replicated outcalls with compensating controls.
4. Inbox ingestion is route-aware so only messages for this automaton are processed.
5. Polling is cost-aware and minimizes unnecessary outcalls in idle/no-message periods.

## Non-Goals

- Multi-canister decomposition for this automaton in v1.1.
- Guaranteed zero empty polls without a push/relay architecture.
- Multi-provider RPC quorum/consensus in v1.1.
- Backward-compat upgrade migration guarantees (reinstall/wipe is acceptable in development).

---

## Human Decisions Applied (Locked)

- USDC custody is in `InboxContract` (not treasury-forwarding on send).
- EVM and inference outcalls are non-replicated in this phase.
- Runtime architecture for this project remains single-canister.
- Shared `InboxContract` across many automatons is allowed if routing isolation is enforced at event schema and poll filters.

---

## Architecture Invariants (Mandatory)

### 1) Single canister runtime (this repo)
- Agent loop, scheduler, EVM polling, and bridge workflow run in one canister for v1.1.
- No separate bridge canister for this repo in v1.1.

### 2) Inbox custody
- `InboxContract` holds custodial USDC balance used by autonomous sweep/reconcile.
- Message payment path must not transfer USDC out of `InboxContract` during ingestion.

### 3) Outcall trust mode and controls
- Use non-replicated outcalls (`is_replicated: Some(false)`) for inference and EVM JSON-RPC.
- Enforce strict allowlists (chain, contract, topic set), bounded range, bounded response bytes, and idempotent ingest.

### 4) Scheduler role separation
- `PollInbox` owns external inbox ingestion (EVM polling + staging).
- `AgentTurn` consumes staged inputs and must not perform external inbox polling directly.

### 5) Shared Inbox routing isolation
- Contract events must include an indexed routing key (automaton key) so polling can filter server-side.
- Canister must persist one route binding and ignore non-matching logs defensively even if RPC filtering is wrong.

### 6) Cost minimization invariant
- Base strategy is to reduce outcall frequency first (adaptive cadence/backoff), then reduce payload size.
- No unfiltered `eth_getLogs` calls against shared Inbox in production mode.

---

## Shared Inbox Viability (Many Automatons)

Using one `InboxContract` for many automatons is viable.

Required contract/event shape:
- `event MessageQueued(bytes32 indexed automaton_key, uint64 indexed nonce, ...payload...)`
- `automaton_key` must be deterministic and unique per automaton (for example keccak256 of configured principal/text identity).
- `nonce` must be monotonic per `automaton_key`.

Required poll pattern per automaton:
- `eth_getLogs` with `address = InboxContract` and topics filter including:
  - topic0 = `MessageQueued` signature
  - topic1 = local `automaton_key`
- This ensures RPC node pre-filters and the automaton does not download other automatons' events.

Hard truth on empty polls:
- In pure pull mode, an automaton cannot be guaranteed to avoid all empty polls.
- To approach near-zero empty polls, use adaptive poll interval and optional nonce-head check.
- True zero-empty-poll behavior requires push/relay architecture (out of v1.1 scope).

---

## Requirements

### Must Have
- [ ] Align spec with current code reality and remove stale assumptions.
- [ ] Keep canonical runtime/config/job state in stable structures.
- [ ] Ensure `InboxContract.sendMessage(...)` preserves custody in contract.
- [ ] Add `InboxContract.bridgeLockUsdcToIcp(...)` with `BRIDGER_ROLE` and `UsdcLockSubmitted` event.
- [ ] Add route-binding config in canister runtime (for example `inbox_automaton_key`, `inbox_contract_address`, `chain_id`).
- [ ] Persist route-aware EVM cursor semantics:
  - `chain_id`
  - `contract_address`
  - `automaton_key_topic`
  - `next_block`
  - `next_log_index`
  - `confirmation_depth`
  - `last_poll_at_ns`
  - `consecutive_empty_polls`
- [ ] Use idempotency key `(tx_hash, log_index)` for ingest dedupe.
- [ ] `PollInbox` executes EVM polling and stages only route-matching messages.
- [ ] `AgentTurn` consumes staged inbox input only (no direct EVM poll path).
- [ ] Add adaptive polling backoff for empty polls (example: 30s -> 60s -> 120s -> 300s max), reset on hit.
- [ ] Keep loop alive on poll failures; persist structured error and retry on cadence.
- [ ] Implement autonomous sweep/reconcile from `InboxContract` custody.
- [ ] Add explicit bridge job state machine and terminal reconciliation outcomes.
- [ ] Expose admin-only controls for runtime config and bridge pause/resume/reconcile.
- [ ] Do not expose user endpoint that directly triggers a sweep.
- [ ] Keep candid generated from Rust export (`ic_cdk::export_candid!()`).
- [ ] Maintain unit + PocketIC integration coverage for ingestion, dedupe, and cadence backoff.

### Should Have
- [ ] Add lightweight nonce-head optimization if contract exposes `latestNonce(automaton_key)` to skip `eth_getLogs` when unchanged.
- [ ] Emit `canlog` entries for poll window, filter parameters, empty-poll backoff state, and ingest decisions.
- [ ] Add safe diagnostics query for route binding + cursor + poll backoff state.

### Could Have
- [ ] Add capped dead-letter queue for malformed logs.
- [ ] Add v1.2 design note for shared poller canister (single outcall fan-out to many automatons).

---

## Constraints

- Keep solution KISS and single-canister for this repo in v1.1.
- Do not hand-edit `ic-automaton.did`.
- Keep secrets update-only; never leak in query responses/log payloads.
- Use PocketIC for integration tests.
- Use `icp-cli` for build/deploy/test loops.
- Follow TDD and keep tests green incrementally.

---

## Success Criteria

- Route-matching events are ingested; non-matching events are ignored.
- No duplicate ingestion for `(tx_hash, log_index)` across retries/restarts.
- `AgentTurn` works from staged input and no longer performs direct inbox EVM polling.
- Idle periods show reduced outcall count via adaptive poll backoff.
- USDC remains in `InboxContract` after message ingestion and is sweepable later.
- One autonomous sweep reaches terminal `Settled` or `Failed` with auditable transitions.
- Validation gates pass: fmt, clippy, tests, `icp build`.

---

## Implementation Plan

- [ ] **Task 1: Correct orchestrator boundaries (PollInbox vs AgentTurn)**
      - Files: `src/scheduler.rs`, `src/agent.rs`, `src/storage/stable.rs`
      - Validation: `cargo test scheduler::tests --lib && cargo test agent::tests --lib`
      - Notes: Move EVM ingress to `PollInbox`; keep `AgentTurn` pure consumer of staged input.

- [ ] **Task 2: Add route-binding and route-aware cursor model**
      - Files: `src/domain/types.rs`, `src/storage/stable.rs`, `src/lib.rs`
      - Validation: `cargo test`
      - Notes: Add config + admin setters; expose safe query view.

- [ ] **Task 3: Tighten EVM poll filters + idempotency ingest**
      - Files: `src/features/evm.rs`, `src/scheduler.rs`, `src/storage/stable.rs`
      - Validation: `cargo test`
      - Notes: Filter by contract + topics; ingest only validated route matches.

- [ ] **Task 4: Empty-poll adaptive cadence and recovery reset**
      - Files: `src/scheduler.rs`, `src/storage/stable.rs`, `src/domain/types.rs`
      - Validation: `cargo test scheduler::tests --lib`
      - Notes: Backoff on empty polls; reset immediately on event hit.

- [ ] **Task 5: Contract custody + event schema updates**
      - Files: `evm/src/Inbox.sol`, `evm/test/Inbox.t.sol` (if/when `evm/` is introduced in this repo)
      - Validation: `cd evm && forge test`
      - Notes: Add indexed `automaton_key` + nonce event fields and custody-preserving flow.

- [ ] **Task 6: Bridge sweep/reconcile and admin control plane**
      - Files: `src/features/signer.rs`, `src/agent.rs`, `src/lib.rs`, `src/domain/types.rs`
      - Validation: `cargo test && icp build`
      - Notes: Timer-driven only; no user-triggered sweep endpoint.

- [ ] **Task 7: PocketIC integration and outcall-economy assertions**
      - Files: `tests/pocketic_agent_autonomy.rs`, `tests/pocketic_scheduler_queue.rs`, `tests/` (new as needed)
      - Validation: `cargo test --features pocketic_tests`
      - Notes: Add cases for route mismatch ignore, duplicate log dedupe, empty-poll backoff behavior.

---

## Context Files

- `AGENTS.md`
- `docs/design/CYCLES_SURVIVAL_MODE_AND_HTTPS_OUTCALL_COST_CONTROL.md`
- `src/lib.rs`
- `src/agent.rs`
- `src/scheduler.rs`
- `src/domain/types.rs`
- `src/storage/stable.rs`
- `src/features/evm.rs`
- `tests/pocketic_agent_autonomy.rs`
- `tests/pocketic_scheduler_queue.rs`

---

## Codebase Snapshot

Snapshot date: 2026-02-20

- Single canister runtime exists with `scheduler_tick` and `run_scheduled_turn_job`.
- `HttpEvmPoller` exists and already uses non-replicated outcalls.
- `PollInbox` currently stages canister-local inbox messages; `AgentTurn` currently still performs EVM polling directly.
- PocketIC tests are present under `tests/`.
- No `evm/` Solidity project is currently checked into this repository snapshot.

---

## Autonomy Scope

### Decide yourself

- Exact Rust type shapes for route binding and cursor extensions.
- Exact empty-poll backoff curve values within bounded limits.
- Internal adapter boundaries for EVM RPC and bridge clients.

### Escalate (log blocker, skip, continue)

- Any proposal to move custody out of `InboxContract`.
- Any proposal to make sweep user-triggerable.
- Any proposal to disable route filtering and accept unfiltered shared-Inbox scans.
- Any proposal to switch to replicated outcalls in this phase.

---

## Verification

### Smoke Tests

- `cargo check` -- Rust canister compiles.
- `cargo fmt --all -- --check` -- formatting is clean.
- `cargo clippy --all-targets --all-features` -- lint checks pass.
- `cargo test` -- unit/integration suites pass.
- `icp build` -- canister build and candid generation pass.

### Expected State

- `src/scheduler.rs` contains inbox EVM ingestion in `TaskKind::PollInbox` path.
- `src/agent.rs` no longer performs direct EVM inbox polling in turn path.
- `src/domain/types.rs` contains route-binding/cursor fields for filtered inbox ingest.
- `src/storage/stable.rs` persists route-aware cursor and empty-poll counters.
- `ic-automaton.did` is generated from Rust export and includes new admin/query endpoints.

### Regression

- `bash .githooks/pre-commit` passes.

### Integration Test

- `cargo test --features pocketic_tests --test pocketic_agent_autonomy` proves route-aware inbox ingestion and staged consumption.
- `cargo test --features pocketic_tests --test pocketic_scheduler_queue` proves poll dedupe/backoff behavior.

---

## Progress

_Dev agent writes here during execution._

### Completed

- Spec revised to align with current repo and shared-Inbox routing/outcall constraints.

### Blockers

- None.

### Learnings

- Shared Inbox is feasible, but strict route-topic filtering plus adaptive cadence is mandatory to control outcall cost.

---

## Ship Checklist (non-negotiable final step)

- [ ] Verification suite completed locally with green results.
- [ ] Confirm no secret leakage in queries/logs.
- [ ] Confirm `InboxContract` custody semantics are preserved.
- [ ] Confirm no user-triggered sweep endpoint exists.
- [ ] Confirm candid was regenerated from Rust export, not hand-edited.
- [ ] Confirm shared-Inbox polling uses route-topic filter (no unfiltered `eth_getLogs`).
