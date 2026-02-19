# Spec: Single-Canister Automaton v1.1 (Inbox-Custody + Non-Replicated Outcalls)

**Status:** LOCKED
**Date:** 2026-02-19
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

Current specs define overlapping behavior with contradictions around USDC custody, trust mode for outcalls, and component boundaries. This creates implementation risk (drift, broken bridge assumptions, inconsistent security posture).

## Goal

Define one consistent, extendable, executable plan for v1.1 where:
1. The architecture is single-canister.
2. `InboxContract` is the on-chain USDC custody point.
3. Inference and EVM HTTP paths use non-replicated outcalls.
4. The system supports autonomous inbox ingestion and autonomous USDC sweep/reconcile.

## Non-Goals

- Multi-canister decomposition in v1.1.
- Multi-provider RPC failover in v1.1.
- Streaming inference responses.
- Backward-compat upgrade migration guarantees (reinstall/wipe is acceptable in development).

---

## Human Decisions Applied (Locked)

- USDC custody is in `InboxContract` (not a treasury-forwarding send path).
- EVM and inference HTTP outcalls are non-replicated for this phase.
- Runtime architecture is a single canister.

---

## Architecture Invariants (Mandatory)

### 1) Single canister
- Agent loop, EVM polling, inference selection, bridge sweep, and reconciliation run inside one canister.
- No separate `BridgeAutomaton` canister in v1.1.

### 2) Inbox custody
- `InboxContract` must hold custodial USDC balance used by autonomous sweeps.
- Message payment path must not transfer USDC away from `InboxContract` at ingestion time.

### 3) Outcall trust mode
- Use non-replicated outcalls (`is_replicated: Some(false)`) for:
  - inference provider HTTP calls,
  - EVM JSON-RPC polling (`eth_blockNumber`, `eth_getLogs`, receipt/status polling).
- Apply compensating controls:
  - confirmation depth before ingestion/finality,
  - strict allowlists (chain, contract, token, topics),
  - idempotency keys and replay safety,
  - bounded ranges, response size, and timeouts.

### 4) FSM-driven execution
- Main agent turn progression is event-driven via explicit transition function.
- Bridge jobs use explicit `SweepState` transitions with idempotent retry/reconcile semantics.
- No direct state mutation bypassing transition handlers in orchestrator code.

---

## Requirements

### Must Have
- [ ] Unify runtime terminology and flow on `run_scheduled_turn` (single orchestrator entrypoint).
- [ ] Keep canonical runtime/config/job state in stable structures.
- [ ] Ensure `InboxContract.sendMessage(...)` preserves USDC custody in contract.
- [ ] Add `InboxContract.bridgeLockUsdcToIcp(...)` with `BRIDGER_ROLE` and `UsdcLockSubmitted` event.
- [ ] Implement non-replicated `RpcEvmPoller` with bounded log windows and strict validation.
- [ ] Persist EVM cursor with clear semantics:
  - `chain_id`
  - `contract_address`
  - `next_block`
  - `next_log_index` (within `next_block`; reset when block increments)
  - `confirmation_depth`
  - `last_poll_at_ns`
- [ ] Define and enforce one idempotency key for inbox-event ingest: `(tx_hash, log_index)`.
- [ ] Convert validated inbox events into bounded turn input batches.
- [ ] Keep loop alive on poll failures; persist structured error and retry on cadence.
- [ ] Implement autonomous sweep policy from `InboxContract` custody to OneSec registration and reconciliation.
- [ ] Add bridge job model with explicit transitions:
  - `Idle -> FeesChecked -> TxSubmitted -> TxConfirmed -> BridgeAccepted -> IcpPending -> Settled`
  - any active state -> `Failed` on non-retryable error/TTL
- [ ] Expose admin-only controls:
  - `set_config`
  - `pause_bridge`
  - `resume_bridge`
  - `force_reconcile`
- [ ] Do not expose any user endpoint that directly triggers a sweep.
- [ ] Maintain generated candid workflow (`ic_cdk::export_candid!()`; no manual `.did` edits).
- [ ] Add unit + PocketIC integration tests, plus Anvil/Foundry-assisted E2E.

### Should Have
- [ ] Use `canlog` structured logs for state transitions, poll windows, and bridge job lifecycle.
- [ ] Add deterministic test abstractions for time/id generation.
- [ ] Add query endpoints for non-secret diagnostics:
  - active provider and model,
  - EVM cursor and cadence,
  - bridge job summaries (without secrets).

### Could Have
- [ ] Add lightweight replay/projection status endpoint for operational debugging.
- [ ] Add capped dead-letter queue for malformed EVM logs.

---

## Constraints

- Keep solution KISS and single-canister.
- Do not hand-edit `ic-automaton.did`.
- Keep RPC/API secrets update-only and never returned in query responses.
- Use PocketIC for canister integration tests.
- Use `icp-cli` for build/deploy/test loops.
- Follow TDD and keep tests green incrementally.

---

## Success Criteria

- ETH and USDC message submissions emit parseable inbox events.
- USDC remains in `InboxContract` after message ingestion and is sweepable later.
- Polling is periodic (not every turn), deterministic, and idempotent across retries.
- Inference and EVM polling execute using non-replicated outcalls.
- One autonomous sweep can reach terminal `Settled` or `Failed` with auditable transitions.
- No duplicate ingestion of already-processed inbox logs.
- Full validation gates pass: fmt, clippy, tests, build, and E2E script.

---

## Implementation Plan

- [ ] **Task 1: Align contract semantics with custody + bridge lock**
      - Files: `evm/src/Inbox.sol`, `evm/src/mocks/MockUSDC.sol`, `evm/test/Inbox.t.sol`
      - Validation: `cd evm && forge test`
      - Notes: Remove treasury-forwarding assumption in message ingest path; custody remains in contract.

- [ ] **Task 2: Define unified domain/state models (agent + bridge)**
      - Files: `src/domain/types.rs`, `src/domain/state_machine.rs`
      - Validation: `cargo test`
      - Notes: Standardize event/state names used by orchestrator and specs.

- [ ] **Task 3: Extend stable storage for cursor/cadence/bridge jobs**
      - Files: `src/storage/stable.rs`
      - Validation: `cargo test`
      - Notes: Canonical persistence for cursor semantics and bridge job lifecycle.

- [ ] **Task 4: Implement RPC EVM poller (non-replicated) with validation/idempotency**
      - Files: `src/features/evm.rs`, `src/agent.rs`
      - Validation: `cargo test`
      - Notes: Enforce allowlists, bounded ranges, confirmation depth, and dedupe key.

- [ ] **Task 5: Implement autonomous sweep/reconcile pipeline in single canister**
      - Files: `src/features/signer.rs`, `src/agent.rs`, `src/lib.rs`
      - Validation: `cargo test`
      - Notes: No public trigger; timer-driven only; OneSec calls wrapped in typed adapters/ports.

- [ ] **Task 6: Wire admin APIs + candid export**
      - Files: `src/lib.rs`, `ic-automaton.did` (generated output only)
      - Validation: `icp build`
      - Notes: Admin-only controls and safe query views.

- [ ] **Task 7: Add unit and PocketIC integration coverage**
      - Files: `tests/` (new), `src/features/inference.rs`, `src/features/evm.rs`, `src/agent.rs`
      - Validation: `cargo test`
      - Notes: Include malformed log, duplicate log, reorg-depth, transient RPC failure, and bridge retry/backoff cases.

- [ ] **Task 8: Add Anvil/Foundry/PocketIC end-to-end orchestration**
      - Files: `scripts/run-e2e-inbox-bridge.sh`, `tests/e2e_inbox_bridge.rs`, `evm/script/DeployInbox.s.sol`, `evm/script/SeedInboxMessages.s.sol`
      - Validation: `./scripts/run-e2e-inbox-bridge.sh`
      - Notes: Proves full path from paid inbox event to autonomous sweep and reconciliation.

---

## Context Files

- `AGENTS.md`
- `docs/design/ICP_ANALYSIS.md`
- `src/lib.rs`
- `src/agent.rs`
- `src/domain/types.rs`
- `src/domain/state_machine.rs`
- `src/storage/stable.rs`
- `src/features/inference.rs`
- `src/features/evm.rs`
- `src/features/signer.rs`
- `icp.yaml`

---

## Codebase Snapshot

Snapshot date: 2026-02-19

- Single canister Rust code exists under `src/` with timer-driven `run_scheduled_turn`.
- Inference provider selection exists (`Mock`, `IcLlm`, `OpenRouter`) with non-replicated OpenRouter support.
- Current EVM path is mock-only (`MockEvmPoller`), no Foundry project checked in yet.
- No `tests/` directory is present currently; test expansion is part of this spec.

---

## Autonomy Scope

### Decide yourself

- Exact Rust type layouts and module decomposition.
- Concrete polling defaults and rate limits.
- Internal adapter boundaries for OneSec and EVM RPC.

### Escalate (log blocker, skip, continue)

- Any proposal to split bridge into another canister.
- Any proposal to move USDC custody out of `InboxContract`.
- Any proposal to make sweep user-triggerable.
- Any proposal to switch outcalls to replicated mode in this phase.

---

## Verification

### Smoke Tests

- `cd evm && forge build` -- Solidity contracts compile.
- `cd evm && forge test` -- custody + lock path behavior is correct.
- `cargo check` -- Rust canister compiles.
- `cargo fmt --all -- --check` -- formatting is clean.
- `cargo clippy --all-targets --all-features` -- lint checks pass.
- `cargo test` -- unit/integration suites pass.
- `icp build` -- canister build and candid generation pass.

### Expected State

- `evm/src/Inbox.sol` defines both `sendMessage` and `bridgeLockUsdcToIcp`.
- `src/features/evm.rs` contains RPC poller and mock poller.
- `src/domain/types.rs` includes bridge config, bridge job, and cursor fields with `confirmation_depth`.
- `src/lib.rs` exports admin-only bridge controls and safe query views.
- `ic-automaton.did` is generated from Rust export and includes new endpoints.

### Regression

- `bash .githooks/pre-commit` passes.

### Integration Test

- `./scripts/run-e2e-inbox-bridge.sh` executes:
  1. Start Anvil.
  2. Deploy `Inbox` + `MockUSDC`.
  3. Submit paid inbox messages (ETH + USDC).
  4. Run PocketIC tests that poll logs via non-replicated outcall path.
  5. Verify exactly-once inbox ingestion and cursor advancement.
  6. Verify autonomous sweep path uses `bridgeLockUsdcToIcp`.
  7. Verify reconciliation reaches terminal state without duplicate settlement.

---

## Progress

_Dev agent writes here during execution._

### Completed

- Spec locked.

### Blockers

- None.

### Learnings

- Single-canister autonomy remains feasible while keeping extension points via adapters and typed state.

---

## Ship Checklist (non-negotiable final step)

- [ ] Verification suite completed locally with green results.
- [ ] Confirm no secret leakage in queries/logs.
- [ ] Confirm `InboxContract` custody semantics are preserved.
- [ ] Confirm no user-triggered sweep endpoint exists.
- [ ] Confirm candid was regenerated from Rust export, not hand-edited.
