# Spec: Inference Provider Abstraction (ic_llm First, OpenRouter Optional)

**Status:** LOCKED
**Date:** 2026-02-18
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** moderate
**Authority:** approval
**Tier:** 2

---

## Problem
The agent loop currently hardcodes `MockInferenceAdapter`, so no real LLM inference path exists. We need production inference while preserving deterministic control flow and clear failure handling in the FSM runtime.

## Goal
Add a provider-based inference layer where:
1. `ic_llm` is the default production backend.
2. OpenRouter can be used through direct non-replicated HTTPS outcalls.
3. The scheduler/turn FSM remains unchanged except for adapter selection and error propagation.

## Non-Goals
- Streaming token responses.
- Multi-model routing and automatic retries across providers.
- Prompt optimization and advanced memory retrieval changes.
- Financial/settlement-grade use of non-replicated responses.

---

## Human Clarifications Applied
- Initial backend choice: implement `ic_llm` first.
- OpenRouter direct outcall path is required as an optional provider.

---

## Autonomous Decisions
- Keep one `InferenceAdapter` trait and add provider-specific adapters behind it.
- Store provider config in stable state so provider selection survives upgrades/restarts.
- Keep tool-policy enforcement in existing execution path; inference output remains advisory input.

---

## Requirements

### Must Have
- [ ] Add an inference provider config model persisted in stable storage (`Mock | IcLlm | OpenRouter`).
- [ ] Implement `IcLlmInferenceAdapter` as first production backend.
- [ ] Implement `OpenRouterInferenceAdapter` using HTTPS outcall with `is_replicated: Some(false)`.
- [ ] Parse model responses into existing `ToolCall` objects; reject malformed tool call payloads safely.
- [ ] Route adapter selection from runtime config in `run_scheduled_turn`.
- [ ] Add update/query endpoints to configure and inspect provider/model (without exposing secrets).
- [ ] Preserve existing FSM semantics (`TurnFailed` on inference errors).
- [ ] Add unit tests for adapter selection, response parsing, and inference failure handling.
- [ ] Add PocketIC integration coverage for one full turn with production adapter path mocked/stubbed deterministically.

### Should Have
- [ ] Structured logging with `canlog` for inference request lifecycle and failures.
- [ ] Request/response size limits and explicit timeout/cost guardrails for OpenRouter outcalls.
- [ ] Config validation for provider-specific required fields.

### Could Have
- [ ] A simple health endpoint (`check_inference_provider`) that performs a minimal no-tool dry run.

---

## Constraints
- Keep design KISS and compatible with current single-canister runtime.
- Do not relax tool-policy checks based on inference provider.
- Do not leak API keys in logs, query responses, or turn records.
- Use non-replicated HTTP mode only for inference where single-replica trust is acceptable.
- Keep Candid generated from Rust exports (`ic_cdk::export_candid!()`).

---

## Success Criteria
- Runtime can switch inference provider via update call and persist that choice.
- A scheduled turn reaches `ExecutingActions`/`Persisting` using `ic_llm` path.
- OpenRouter adapter can complete inference via non-replicated outcall and parse tool calls.
- Inference errors deterministically move turn to `Faulted` with clear error message.
- All validation gates pass: `cargo check`, `cargo fmt --check`, `cargo clippy`, tests, `icp build`.

---

## Implementation Plan

- [ ] **Task 1: Add inference provider config domain + persistence (TDD first)**
      - Files: `src/domain/types.rs`, `src/storage/stable.rs`, `src/lib.rs`
      - Validation: `cargo test`
      - Notes: Add provider enum and config struct; add guarded update/query methods for provider + model + optional OpenRouter key storage.

- [ ] **Task 2: Refactor inference module to support multiple adapters**
      - Files: `src/features/inference.rs`, `src/features/mod.rs`, `src/agent.rs`
      - Validation: `cargo test`
      - Notes: Keep `InferenceAdapter` trait; add provider factory/selector called by turn loop.

- [ ] **Task 3: Implement `ic_llm` adapter**
      - Files: `Cargo.toml`, `src/features/inference.rs`
      - Validation: `cargo check`
      - Notes: Map `InferenceInput` to provider request, parse output into `InferenceOutput` with safe defaults.

- [ ] **Task 4: Implement OpenRouter non-replicated HTTPS adapter**
      - Files: `src/features/inference.rs`
      - Validation: `cargo test`
      - Notes: Use `ic_cdk::management_canister::http_request::{http_request, HttpRequestArgs}` with `is_replicated: Some(false)` and strict `max_response_bytes`.

- [ ] **Task 5: Add tests for parsing, selection, and failure semantics**
      - Files: `src/features/inference.rs`, `src/agent.rs` (and/or new test modules under `src/`)
      - Validation: `cargo test`
      - Notes: Include malformed JSON, no-tool response, provider misconfiguration, and HTTP failure cases.

- [ ] **Task 6: Integration and build validation**
      - Files: `src/lib.rs`, `ic-automaton.did` (generated only)
      - Validation: `cargo check && cargo fmt --check && cargo clippy --all-targets --all-features && cargo test && icp build`
      - Notes: Ensure candid export includes new endpoints and canister still initializes and runs timer loop.

---

## Context Files

- `AGENTS.md`
- `docs/design/ICP_ANALYSIS.md`
- `src/agent.rs`
- `src/features/inference.rs`
- `src/storage/stable.rs`
- `src/domain/types.rs`
- `src/lib.rs`

---

## Codebase Snapshot

Snapshot date: 2026-02-18

- `src/features/inference.rs` currently exposes only mock/stub adapters and no HTTP/integration-backed inference.
- `src/agent.rs` currently calls `MockInferenceAdapter::infer(...)` directly in scheduled turns.
- `Cargo.toml` currently has no `ic-llm` dependency.

---

## Autonomy Scope

### Decide yourself:
- Exact names for config fields and update/query methods.
- Response parsing structs for provider outputs.
- Internal adapter-factory organization and test module layout.

### Escalate (log blocker, skip, continue):
- Any change that requires broad FSM redesign.
- Any decision to remove OpenRouter support from this scope.
- Any requirement to expose secrets through query interfaces.

---

## Verification

### Smoke Tests
- `cargo check` -- compile all new adapters and config paths.
- `cargo fmt --all -- --check` -- formatting compliance.
- `cargo clippy --all-targets --all-features` -- lint cleanliness.
- `cargo test` -- unit and integration behavior checks.
- `icp build` -- canister build + candid generation flow.

### Expected State
- File `src/features/inference.rs` contains `IcLlmInferenceAdapter` and `OpenRouterInferenceAdapter`.
- File `src/domain/types.rs` contains provider enum/config types.
- `get_runtime_view` or dedicated query exposes active provider (no secret value leakage).
- Generated `ic-automaton.did` includes new configuration endpoints.

### Regression
- `bash .githooks/pre-commit` passes.

### Integration Test
- Execute a PocketIC test scenario that sets provider to `IcLlm` (or deterministic stub behind same adapter path), runs one scheduled turn, and verifies:
  - turn transitions through `Inferring` to post-inference state,
  - tool calls are persisted when present,
  - errors route to `Faulted` with stored `last_error`.

---

## Progress

_Dev agent writes here during execution._

### Completed
- Spec locked.

### Blockers
- None.

### Learnings
- `ic-cdk 0.19` management-canister HTTP API supports `HttpRequestArgs { is_replicated: Option<bool> }`, enabling non-replicated OpenRouter inference outcalls.

---

## Ship Checklist (non-negotiable final step)

- [ ] Run verification suite (smoke + regression + integration).
- [ ] Confirm no secret leakage in query responses/logs.
- [ ] Confirm Candid regenerated from Rust export, not manually edited.

