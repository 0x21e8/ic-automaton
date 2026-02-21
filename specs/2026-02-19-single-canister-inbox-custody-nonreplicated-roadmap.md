# Spec: Single-Canister Automaton v1.2 (Shared Inbox Forwarding + Non-Replicated Outcalls)

**Status:** LOCKED (revised)
**Date:** 2026-02-21
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

The roadmap still assumes inbox custody/sweep behavior and automaton key routing that no longer matches the target model. We now need one shared `InboxContract` for many automatons, with EVM-address identity, direct forwarding of paid assets, per-automaton minimum pricing, and no registration step.

## Goal

Define one consistent, executable v1.2 plan where:
1. Runtime remains single-canister for this project.
2. One shared `InboxContract` serves many automatons.
3. The automaton identifier is its EVM address.
4. On each accepted payment, `InboxContract` forwards USDC and ETH to the automaton EVM address.
5. Minimum message cost is per automaton (`1 USDC` and `0.0005 ETH` defaults when unset), settable by that automaton.
6. Automatons do not register with `InboxContract`.
7. Inference and EVM polling remain non-replicated with strict compensating controls.

## Non-Goals

- Multi-canister decomposition for this automaton in v1.2.
- Guaranteed zero empty polls without a push/relay architecture.
- Multi-provider RPC quorum/consensus in v1.2.
- Backward-compat upgrade migration guarantees (reinstall/wipe is acceptable in development).

---

## Human Decisions Applied (Locked)

- One `InboxContract` is shared across many automatons.
- Automaton identity on EVM is its EVM address.
- Payment flow forwards both USDC and ETH to the target automaton EVM address on accepted payment.
- `InboxContract` keeps per-automaton minimum pricing with defaults of `1 USDC` and `0.0005 ETH` when unset.
- The respective automaton is allowed to set/update its own minimum price.
- No automaton registration flow is required.
- EVM and inference outcalls are non-replicated in this phase.
- Runtime architecture for this project remains single-canister.

---

## Architecture Invariants (Mandatory)

### 1) Single canister runtime (this repo)
- Agent loop, scheduler, and EVM polling run in one canister for v1.2.
- No separate bridge/sweep canister for this repo in v1.2.

### 2) Shared Inbox with address routing
- `InboxContract` emits routeable events keyed by indexed automaton EVM address.
- Canister persists one route binding (`automaton_evm_address`) and ignores non-matching logs defensively even if RPC filtering is wrong.

### 3) Forwarding semantics
- Accepted message payments must forward both USDC and ETH to the automaton EVM address in the same payment flow.
- `InboxContract` is not the long-lived custody point for message funds in this model.

### 4) Per-automaton min-price semantics
- `InboxContract` stores per-automaton min message costs for USDC and ETH.
- If no per-automaton value exists, defaults are `1 USDC` and `0.0005 ETH`.
- Only the respective automaton identity is allowed to set/update its own min price.

### 5) No registration requirement
- Automatons do not have to pre-register in `InboxContract`.
- Message processing and min-price lookup work for any automaton address; unset pricing falls back to defaults.

### 6) Outcall trust mode and controls
- Use non-replicated outcalls (`is_replicated: Some(false)`) for inference and EVM JSON-RPC.
- Enforce strict allowlists (chain, contract, topic set), bounded range, bounded response bytes, and idempotent ingest.

### 7) Scheduler role separation
- `PollInbox` owns external inbox ingestion (EVM polling + staging).
- `AgentTurn` consumes staged inputs and must not perform external inbox polling directly.

### 8) Cost minimization invariant
- Base strategy is to reduce outcall frequency first (adaptive cadence/backoff), then reduce payload size.
- No unfiltered `eth_getLogs` calls against shared Inbox in production mode.

---

## Shared Inbox Viability (Many Automatons)

Using one `InboxContract` for many automatons is viable.

Required contract/event shape:
- `event MessageQueued(address indexed automaton, uint64 indexed nonce, ...payload...)`
- `automaton` is the target automaton EVM address and the canonical route key.
- `nonce` is monotonic per `automaton`.

Required payment rules:
- Contract computes required minimums using per-automaton map and defaults if unset.
- Contract rejects underfunded messages.
- On accepted payment, contract forwards USDC and ETH to `automaton`.

Required poll pattern per automaton:
- `eth_getLogs` with `address = InboxContract`, `topic0 = MessageQueued` signature, and `topic1 = local automaton_evm_address`.
- This ensures RPC node pre-filters and the automaton does not download other automatons' events.

Hard truth on empty polls:
- In pure pull mode, an automaton cannot be guaranteed to avoid all empty polls.
- To approach near-zero empty polls, use adaptive poll interval and optional nonce-head check.
- True zero-empty-poll behavior requires push/relay architecture (out of v1.2 scope).

---

## Requirements

### Must Have
- [ ] Align spec with current code reality and remove stale custody/registration assumptions.
- [ ] Keep canonical runtime/config/job state in stable structures.
- [ ] Update contract model so message acceptance forwards USDC and ETH to automaton EVM address.
- [ ] Add per-automaton min-price map for USDC and ETH in `InboxContract`.
- [ ] Enforce defaults when unset: `1 USDC` and `0.0005 ETH`.
- [ ] Allow the respective automaton to set/update its own min-price values.
- [ ] Keep canister route binding config using `automaton_evm_address`, `inbox_contract_address`, and `chain_id`.
- [ ] Persist route-aware EVM cursor semantics with `chain_id`, `contract_address`, `automaton_address_topic`, `next_block`, `next_log_index`, `confirmation_depth`, `last_poll_at_ns`, and `consecutive_empty_polls`.
- [ ] Use idempotency key `(tx_hash, log_index)` for ingest dedupe.
- [ ] `PollInbox` executes EVM polling and stages only route-matching messages.
- [ ] `AgentTurn` consumes staged inbox input only (no direct EVM poll path).
- [ ] Add adaptive polling backoff for empty polls (example: 30s -> 60s -> 120s -> 300s max), reset on hit.
- [ ] Keep loop alive on poll failures; persist structured error and retry on cadence.
- [ ] Do not require automaton registration for payment ingest or routing.
- [ ] Expose admin-only controls for runtime config and pause/resume of poll jobs.
- [ ] Enforce controller authorization (or equivalent admin policy) on mutating runtime/scheduler config endpoints.
- [ ] Keep candid generated from Rust export (`ic_cdk::export_candid!()`).
- [ ] Maintain unit + PocketIC integration coverage for routing, dedupe, pricing defaults/overrides, and no-registration behavior.
- [ ] Add a deterministic Anvil-backed E2E test path for EVM polling behavior.

### Should Have
- [ ] Add lightweight nonce-head optimization if contract exposes `latestNonce(automaton)` to skip `eth_getLogs` when unchanged.
- [ ] Emit `canlog` entries for poll window, filter parameters, empty-poll backoff state, ingest decisions, and effective min-price source (default vs override).
- [ ] Add safe diagnostics query for route binding + cursor + poll backoff state.

### Could Have
- [ ] Add capped dead-letter queue for malformed logs.
- [ ] Add v1.3 design note for shared poller canister (single outcall fan-out to many automatons).

---

## Constraints

- Keep solution KISS and single-canister for this repo in v1.2.
- Do not hand-edit `ic-automaton.did`.
- Keep secrets update-only; never leak in query responses/log payloads.
- Contract changes are an external dependency unless an `evm/` workspace is added to this repo.
- Use PocketIC for integration tests.
- Use `icp-cli` for build/deploy/test loops.
- Follow TDD and keep tests green incrementally.

---

## Success Criteria

- Route-matching events are ingested; non-matching events are ignored.
- No duplicate ingestion for `(tx_hash, log_index)` across retries/restarts.
- `AgentTurn` works from staged input and no longer performs direct inbox EVM polling.
- Idle periods show reduced outcall count via adaptive poll backoff.
- Accepted message payments forward both USDC and ETH to the automaton EVM address.
- Unset automaton pricing uses default thresholds; automaton override pricing is enforceable immediately.
- No registration transaction or API call is required before an automaton can receive/process paid messages.
- Validation gates pass: fmt, clippy, tests, `icp build`.

---

## Implementation Plan

- [ ] **Task 1: Preserve and harden orchestrator boundaries (PollInbox vs AgentTurn)**
      - Files: `src/scheduler.rs`, `src/agent.rs`, `src/storage/stable.rs`, `tests/pocketic_agent_autonomy.rs`
      - Validation: `cargo test scheduler::tests --lib && cargo test agent::tests --lib`
      - Notes: Keep EVM ingress in `PollInbox`; keep `AgentTurn` a staged-input consumer only; add regression assertions so this boundary cannot drift.

- [x] **Task 2: Add EVM-address route-binding and route-aware cursor model**
      - Files: `src/domain/types.rs`, `src/storage/stable.rs`, `src/lib.rs`
      - Validation: `cargo test`
      - Notes: Add config + admin setters; expose safe query view.

- [x] **Task 3: Contract payment forwarding + min-price map/defaults**
      - Files: `evm/src/Inbox.sol`, `evm/test/Inbox.t.sol` (if/when `evm/` is introduced in this repo)
      - Validation: `cd evm && forge test`
      - Notes: Event must use indexed automaton address; accepted payments forward USDC and ETH; no registration gate.

- [x] **Task 4: Tighten EVM poll filters + idempotency ingest + backoff**
      - Files: `src/features/evm.rs`, `src/scheduler.rs`, `src/storage/stable.rs`, `src/domain/types.rs`
      - Validation: `cargo test`
      - Notes: Filter by contract + automaton-address topic; ingest only validated route matches; update poller event signature/topic handling to match the finalized contract ABI.

- [x] **Task 5: Enforce admin authorization on mutable control-plane endpoints**
      - Files: `src/lib.rs`, `tests/pocketic_agent_autonomy.rs`, `tests/pocketic_scheduler_queue.rs`
      - Validation: `cargo test`
      - Notes: Controller-only controls should cover scheduler/runtime/inference/RPC config mutation endpoints while preserving intended public ingress endpoints.

- [ ] **Task 6: PocketIC integration and outcall-economy assertions**
      - Files: `tests/pocketic_agent_autonomy.rs`, `tests/pocketic_scheduler_queue.rs`, `tests/` (new as needed)
      - Validation: `cargo test --features pocketic_tests`
      - Notes: Add cases for route mismatch ignore, duplicate log dedupe, empty-poll backoff behavior, default pricing, override pricing, and no-registration flow.

- [ ] **Task 7: Anvil-backed E2E polling coverage**
      - Files: `src/features/evm.rs`, `Cargo.toml` (or `tests/` if implemented as integration test)
      - Validation: `cargo test --features anvil_e2e --lib http_evm_poller_e2e_against_anvil -- --nocapture`
      - Notes: Run against a local Anvil process and verify real JSON-RPC polling path end-to-end (not host stub), with stable setup/teardown and clear skip/ignore behavior when feature is disabled.

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

Snapshot date: 2026-02-21

- Single canister runtime exists with `scheduler_tick` and `run_scheduled_turn_job`.
- `HttpEvmPoller` exists and already uses non-replicated outcalls.
- `PollInbox` performs EVM polling when `evm_rpc_url`, `inbox_contract_address`, and `evm_address` are configured, then stages inbox messages.
- `AgentTurn` currently consumes staged inbox input and does not perform direct EVM polling (it still writes the unchanged cursor back at turn end).
- `HttpEvmPoller` currently filters by topic0 `MessageQueued(address,address,string)` plus topic1 local `evm_address`.
- `EvmPollCursor` currently stores only `chain_id`, `next_block`, and `next_log_index`.
- Mutating control-plane updates in `src/lib.rs` are currently callable without controller checks (except `update_prompt_layer_admin`).
- PocketIC tests currently cover scheduler dedupe/lease/low-cycles and staged-input flow, but not route-mismatch filtering, `(tx_hash, log_index)` dedupe, or empty-poll backoff.
- PocketIC tests are present under `tests/`.
- No `evm/` Solidity project is currently checked into this repository snapshot.

---

## Autonomy Scope

### Decide yourself

- Exact Rust type shapes for address route binding and cursor extensions.
- Exact empty-poll backoff curve values within bounded limits.
- Internal adapter boundaries for EVM RPC clients.

### Escalate (log blocker, skip, continue)

- Any proposal to reintroduce custody/sweep semantics for message payments.
- Any proposal to require automaton registration before message processing.
- Any proposal to disable route filtering and accept unfiltered shared-Inbox scans.
- Any proposal to switch to replicated outcalls in this phase.
- Any proposal to change default min-price constants away from `1 USDC` and `0.0005 ETH`.
- If `evm/` is still absent, whether to add a local Foundry workspace here or execute contract changes in an external contract repository.

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
- `src/domain/types.rs` contains EVM-address route-binding/cursor fields for filtered inbox ingest.
- `src/storage/stable.rs` persists route-aware cursor and empty-poll counters.
- `src/lib.rs` enforces admin authorization for mutating control-plane endpoints.
- `ic-automaton.did` is generated from Rust export and includes new admin/query endpoints.
- `evm/src/Inbox.sol` (when present) enforces default and per-automaton min pricing and forwarding semantics.

### Regression

- `bash .githooks/pre-commit` passes.

### Integration Test

- `cargo test --features pocketic_tests --test pocketic_agent_autonomy` proves route-aware inbox ingestion and staged consumption.
- `cargo test --features pocketic_tests --test pocketic_scheduler_queue` proves queue dedupe/lease behavior and explicit empty-poll backoff assertions.
- `cargo test --features anvil_e2e --lib http_evm_poller_e2e_against_anvil -- --nocapture` proves Anvil-backed EVM polling E2E behavior.
- `cd evm && forge test` (when `evm/` exists) proves forwarding, default min-price, override min-price, and no-registration contract behavior.

---

## Progress

_Dev agent writes here during execution._

### Completed

- Spec revised to align with shared-inbox EVM-address routing, forwarding semantics, per-automaton min pricing, and no-registration requirements.
- Task 2 complete: route-aware cursor fields, controller-gated route config setters, and safe route-state query view implemented with passing validation.
- Task 3 complete: added `evm/` Foundry workspace with `Inbox.sol` forwarding logic, per-automaton min-price defaults/overrides, and passing Forge tests for forwarding and no-registration behavior.
- Task 4 complete: updated poller ABI/topic handling and route validation, added `(tx_hash, log_index)` ingest idempotency, and implemented adaptive empty-poll backoff with passing unit/integration validation.
- Task 5 complete: added controller authorization checks for mutable runtime/scheduler/inference/RPC control-plane endpoints and PocketIC coverage for non-controller rejection with public inbox ingress preserved.

### Blockers

- None.

### Learnings

- Shared Inbox remains viable with strict route-topic filtering and adaptive cadence.
- Forward-on-payment semantics simplify canister custody/reconcile surface area for inbox message funds.

---

## Ship Checklist (non-negotiable final step)

- [ ] Verification suite completed locally with green results.
- [ ] Confirm no secret leakage in queries/logs.
- [ ] Confirm no user-triggered registration prerequisite exists.
- [ ] Confirm default min prices are exactly `1 USDC` and `0.0005 ETH` when unset.
- [ ] Confirm automaton-specific min-price updates are restricted to the respective automaton.
- [ ] Confirm accepted message payment forwards USDC and ETH to automaton EVM address.
- [ ] Confirm candid was regenerated from Rust export, not hand-edited.
- [ ] Confirm shared-Inbox polling uses route-topic filter (no unfiltered `eth_getLogs`).
