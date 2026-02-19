# Spec: ICP Automaton v1 Explicit State Machine Skeleton

**Status:** LOCKED
**Date:** 2026-02-18
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** complex
**Authority:** approval
**Tier:** 3

---

## Problem
The first implementation slice must establish an explicit state-machine core, durable persistence, and a runnable single-turn loop with mocked feature adapters.

## Goal
Deliver a buildable/tested canister skeleton where one agent turn runs through an explicit FSM and persists state safely:
1. Canonical state in stable structures.

## Non-Goals
- Social relay support.
- Conway API integration.
- Real HTTP outcalls, SIWE, x402 settlement, or ERC-8004 writes.
- Child canister spawning and governance flows.
- Backward-compat migration work (dev phase allows reinstall/wipe).

---

## Human Clarifications Applied
- Memory scope: episodic memory only for v1.
- Soul mutability: mutable via controlled update endpoint in v1.
- Feature scope: inference + signer + skills loader/store only.
- Loop done criteria: one full turn path (input -> infer -> execute mocked actions -> persist -> state transition).

---

## Autonomous Decisions
- Use an explicit pure transition function (`State x Event -> Transition`) and keep side effects outside it.
- Make stable memory the source of truth for correctness-critical runtime state and episodic event history.
- Use `ic-rusqlite` as a projection/query layer for richer filtering and reporting.
- Require replay from stable event log into SQL projection to keep recovery simple after schema changes.
- Follow TDD: write state machine and loop tests before implementation tasks.

---

## State Machine Contract (Mandatory)

### States
- `Bootstrapping`
- `Idle`
- `LoadingContext`
- `Inferring`
- `ExecutingActions`
- `Persisting`
- `Sleeping`
- `Faulted`

### Events
- `InitCompleted`
- `WakeRequested { reason }`
- `ContextLoaded`
- `InferenceCompleted`
- `ActionsCompleted`
- `PersistCompleted`
- `SleepRequested`
- `TurnFailed { reason }`
- `ResetFault`

### Transition Rules
- Only legal transitions are encoded in one pure function.
- Illegal transition attempts return an explicit error and are audit-logged.
- `run_agent_turn` must progress by dispatching events, not mutating state directly.
- At most one turn can be in flight (`turn_lock` guard in stable runtime state).

---

## Persistence Design (Stable vs SQL)

### Stable Structures (Canonical)
- `RuntimeSnapshot` (`StableCell`):
  - current FSM state
  - `turn_lock`
  - loop enabled/disabled
  - last turn id
  - last error
- `ConfigKV` (`StableBTreeMap<String, String>`):
  - soul text/version
  - system config keys
  - protected-key write policy
- `SkillStore` (`StableBTreeMap<String, SkillRecord>`):
  - installed skills, enabled flags, metadata, instructions
- `EpisodicLog` (`StableLog` or ULID-keyed `StableBTreeMap`):
  - append-only turn envelopes and transition events
  - canonical memory history for replay

Why canonical in stable structures:
- must survive upgrades deterministically
- simple KV/log access fits runtime control path
- avoids coupling critical correctness to SQL schema evolution


---

## Requirements

### Must Have
- [ ] Implement FSM domain module with typed states/events, legal transitions, and transition errors.
- [ ] Implement `run_agent_turn` orchestrator that advances by dispatching FSM events.
- [ ] Implement stable canonical stores for runtime snapshot, soul/config KV, skills store, and episodic memory log.
- [ ] Implement feature modules with explicit ports + two adapters each:
  - inference: `MockInferenceAdapter`, `StubInferenceAdapter`
  - signer: `MockSignerAdapter`, `StubSignerAdapter`
  - skills: stable store + loader, with mock loader source
- [ ] Implement timer wiring with `ic-cdk-timers` in `init` and `post_upgrade`.
- [ ] Expose controlled soul update endpoint with guardrails + audit event.
- [ ] Generate Candid from Rust (`ic_cdk::export_candid!()`); do not hand-edit `.did`.
- [ ] Add unit and PocketIC integration tests covering FSM legality and one full mocked turn.

### Should Have
- [ ] Deterministic test abstractions for clock/id generation.
- [ ] Explicit protected-key list for config writes (`soul` allowed via dedicated API only).

### Could Have
- [ ] Manual test wake endpoint with optional inline input.
- [ ] Small query endpoint for projection replay status.

---

## Constraints
- Keep architecture KISS and single-canister for v1.
- No Social/Conway modules in this scope.
- No direct edits to `ic-automaton.did`; use candid export/generation flow.
- Follow TDD and maintain broad unit + integration coverage.
- Integration tests should use PocketIC.
- Since this is development phase, canister reinstall and stable memory wipe are acceptable.

---

## Success Criteria
- FSM legality is enforced in tests (illegal transitions rejected and logged).
- One `run_agent_turn` call performs the full mocked turn path and ends in a valid terminal state.
- Soul persists across calls and is retrievable after update.
- Episodic memory appends at least one turn envelope and one transition event per turn.
- SQL projection is populated and queryable after turn execution.
- Replay from stable episodic log can rebuild SQL projection.

---

## Implementation Plan

- [ ] **Task 1:** Add domain model and explicit FSM (TDD first)
      - Files: `src/domain/mod.rs`, `src/domain/state_machine.rs`, `src/domain/types.rs`, `tests/state_machine.rs`
      - Validation: `cargo test --test state_machine`
      - Notes: Pure transition function only; no storage/integration logic here.

- [ ] **Task 2:** Implement canonical stable persistence
      - Files: `src/storage/mod.rs`, `src/storage/stable_runtime.rs`, `src/storage/stable_skills.rs`, `src/storage/stable_memory.rs`, `tests/stable_storage.rs`
      - Validation: `cargo test --test stable_storage`
      - Notes: Include protected config key policy and dedicated soul write path.

- [ ] **Task 3:** Implement feature modules with explicit mock/stub adapters
      - Files: `src/features/mod.rs`, `src/features/inference.rs`, `src/features/signer.rs`, `src/features/skills.rs`, `tests/features_mocks.rs`
      - Validation: `cargo test --test features_mocks`
      - Notes: No generic `integrations` bucket; one explicit module per feature.

- [ ] **Task 4:** Implement loop orchestrator and canister API surface
      - Files: `src/agent/mod.rs`, `src/agent/loop.rs`, `src/lib.rs`
      - Validation: `cargo test --test agent_loop_mocked`
      - Notes: `run_agent_turn` must dispatch events through FSM and persist both stable + SQL layers.

- [ ] **Task 5:** Timer wiring, upgrade hooks, and PocketIC integration coverage
      - Files: `src/lib.rs`, `tests/pocketic_agent_loop.rs`
      - Validation: `cargo test --test pocketic_agent_loop`
      - Notes: Re-arm timers in `post_upgrade`; assert turn execution + persistence via public endpoints.

- [ ] **Task 6:** Candid generation workflow alignment
      - Files: `src/lib.rs`, `scripts/generate-candid.sh` (if missing), `ic-automaton.did` (generated output only)
      - Validation: `./scripts/generate-candid.sh ic-automaton.did`
      - Notes: Add `ic_cdk::export_candid!()` and keep `.did` generated, not manually edited.

---

## Context Files

Files the dev agent should read before starting:
- `docs/design/ICP_ANALYSIS.md`
- `AGENTS.md`
- `Cargo.toml`
- `src/lib.rs`
- `icp.yaml`

---

## Codebase Snapshot

Snapshot date: 2026-02-18

- `Cargo.toml`
```toml
[package]
name = "backend"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
candid = "0.10"
ic-cdk = "0.19"
```

- `src/lib.rs`
```rust
#[ic_cdk::query]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}
```

- `ic-automaton.did`
```did
service : {
  greet : (name : text) -> (text) query
}
```

- `AGENTS.md` highlights in effect:
  - TDD and extensive unit + integration testing required.
  - PocketIC required for integration tests.
  - Candid must be generated from Rust export; no manual `.did` edits.

---

## Autonomy Scope

### Decide yourself:
- Concrete Rust type names and module internals.
- Specific deterministic mock payloads for inference/signer/skills.
- Exact test case decomposition for unit and PocketIC suites.

### Escalate (log blocker, skip, continue):
- Any proposal to add Social/Conway in this v1.
- Any change that removes explicit FSM-driven flow.
- Any shift of canonical runtime/soul/episodic data away from stable structures.
- Any manual edit workflow for `ic-automaton.did`.

---

## Verification

### Smoke Tests
- `cargo check` -- compiles the new module graph.
- `cargo test --test state_machine` -- proves legal/illegal transition handling.
- `cargo test --test agent_loop_mocked` -- proves one full mocked turn path.
- `cargo test --test pocketic_agent_loop` -- proves integration behavior in PocketIC.
- `icp build` -- proves canister build and candid export integration.

### Expected State
- File `src/domain/state_machine.rs` exists and is >400 bytes.
- File `src/storage/stable_memory.rs` exists and is >300 bytes.
- File `src/features/inference.rs` exists and is >250 bytes.
- File `src/features/signer.rs` exists and is >250 bytes.
- File `src/features/skills.rs` exists and is >250 bytes.
- `rg "enum AgentState|enum AgentEvent|fn transition" src/domain/state_machine.rs` returns matches.
- `rg "soul" src/storage/stable_runtime.rs src/storage/stable_memory.rs src/features/skills.rs` returns matches.
- `rg "CREATE TABLE IF NOT EXISTS turn_projection" src/storage/sql_projection.rs` returns a match.
- `rg "export_candid|ic_cdk::export_candid!" src/lib.rs` returns a match.

### Regression
- `cargo test` -- all unit/integration tests pass after feature addition.

### Integration Test
- `cargo test --test pocketic_agent_loop -- --nocapture`:
  - initializes canister
  - triggers one wake/turn
  - verifies resulting FSM state is valid
  - verifies episodic memory persisted
  - verifies soul update endpoint persists and is retrievable

