# Spec: OpenRouter Latency Controls and Inference Backoff Hardening

**Status:** LOCKED
**Date:** 2026-02-20
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** moderate
**Authority:** approval
**Tier:** 2

---

## Problem
OpenRouter inference outcalls are exposed to replica-side HTTPS outcall time limits (currently effectively 30s request timeout in replica adapter defaults), while the canister currently sends full prompt assembly and does not bound generation length. Timeout/transient outcall failures can cause unstable turn behavior because inference success/failure bookkeeping does not cleanly distinguish completed inference from deferred/skipped inference.

## Goal
Implement bounded-latency OpenRouter inference and resilient timeout behavior so that:
1. OpenRouter requests are explicitly constrained for latency (`max_tokens` cap + compact prompt path).
2. Timeout/transient outcall failures are handled as controlled deferrals with survival backoff.
3. Inference backoff state is not accidentally cleared by deferred/skip outcomes.

## Non-Goals
- Changing IC replica timeout values or HTTPS outcall adapter config.
- Streaming responses, multi-provider orchestration, or broad inference architecture redesign.
- Introducing new external providers or changing custody/scheduling architecture.

---

## Human Clarifications Applied
- Scope is restricted to change 2 (latency controls) and change 3 (resilience/backoff behavior).

---

## Autonomous Decisions
- Add OpenRouter output-token cap as explicit runtime config (instead of hardcoded constant) to permit post-deploy tuning without code edits.
- Use compact prompt assembly for OpenRouter by default to reduce prompt size and response latency risk.
- Introduce explicit inference outcome disposition (`Completed` vs `Deferred`) so survival success resets occur only on real completion.

---

## Requirements

### Must Have
- [ ] Add OpenRouter latency config field `openrouter_max_output_tokens` to runtime state with safe default (initial target: 256).
- [ ] Validate `openrouter_max_output_tokens` (`> 0`, bounded upper limit) and persist it in stable storage.
- [ ] Include `max_tokens` in OpenRouter request body using `openrouter_max_output_tokens`.
- [ ] Build OpenRouter system prompt using compact assembly path to reduce request size/latency.
- [ ] Classify OpenRouter timeout/transient outcall errors as deferred inference outcomes (not hard turn failures).
- [ ] Record survival inference failure backoff for timeout/transient deferrals.
- [ ] Prevent `record_survival_operation_success(Inference)` from running for deferred/skip outcomes.
- [ ] Keep hard failures for non-transient categories (e.g., malformed response parse, invalid config, persistent non-2xx provider errors where deferral is not intended).
- [ ] Add unit tests for:
  - latency request body constraints (`max_tokens`, compact prompt path),
  - transient error classification,
  - inference backoff bookkeeping correctness (no accidental reset on deferred).

### Should Have
- [ ] Extend safe inference config view and HTTP config route to expose `openrouter_max_output_tokens` (without exposing secrets).
- [ ] Add targeted PocketIC integration coverage that demonstrates autonomous turn continuity under OpenRouter timeout/transient failure.
- [ ] Add canlog lines that differentiate `inference_deferred_transient_timeout` from hard inference failures.

### Could Have
- [ ] Add optional low-latency model preset helper for OpenRouter config (e.g., preset to a known fast model ID), while keeping manual model override available.

---

## Constraints
- Preserve KISS: no scheduler redesign, no new operation classes.
- Keep non-replicated OpenRouter outcall mode (`is_replicated: Some(false)`).
- Do not leak OpenRouter API key via logs/query/API views.
- Respect host-safe time guidance in all new tests/helpers.
- Preserve Candid generation flow from Rust exports; do not hand-edit `ic-automaton.did`.

---

## Success Criteria
- OpenRouter request payload includes explicit `max_tokens` cap and compact prompt assembly.
- Under simulated timeout/transient outcall failure, agent turn remains operational (controlled defer path) and inference survival backoff increments.
- Deferred inference outcomes do not trigger survival success reset.
- Existing inference/provider tests remain green, and new tests lock in regression protection.
- Validation gates pass: format, clippy, unit tests, `icp build`, and selected PocketIC flow.

---

## Implementation Plan

- [ ] **Task 1: Add OpenRouter latency config to runtime + persistence (TDD first)**
      - Files: `src/domain/types.rs`, `src/storage/stable.rs`, `src/lib.rs`
      - Validation: `cargo test --lib domain::types::tests:: storage::stable::tests::`
      - Notes: Add default value and setter/getter path; include strict bounds validation.

- [ ] **Task 2: Expose safe config surface for latency knob**
      - Files: `src/domain/types.rs`, `src/http.rs`, `src/ui_app.js` (if HTTP UI config flow is included), `tests/pocketic_ui_observability.rs` (if UI route payload changes)
      - Validation: `cargo test --lib http::tests::`
      - Notes: Expose only non-secret fields; keep backward-compatible request parsing where practical.

- [ ] **Task 3: Enforce OpenRouter latency controls in request assembly**
      - Files: `src/features/inference.rs`, `src/prompt.rs` (only if helper reuse needed)
      - Validation: `cargo test --lib features::inference::tests::`
      - Notes: Add `max_tokens`; use compact prompt assembly for OpenRouter request body.

- [ ] **Task 4: Harden inference outcome semantics + transient timeout deferral**
      - Files: `src/features/inference.rs`, `src/agent.rs` (only if turn reply handling needs disposition awareness), `src/storage/stable.rs` (if helper methods are added)
      - Validation: `cargo test --lib features::inference::tests:: scheduler::tests::`
      - Notes: Introduce explicit inference disposition; record failure backoff for transient timeout and avoid success reset for deferred results.

- [ ] **Task 5: Add integration coverage for continuity under OpenRouter transient failure**
      - Files: `tests/pocketic_agent_autonomy.rs`
      - Validation: `icp build && cargo test --features pocketic_tests --test pocketic_agent_autonomy -- --nocapture`
      - Notes: Assert autonomous loop continuity and survival backoff behavior when OpenRouter outcall transiently fails.

- [ ] **Task 6: Full validation**
      - Files: `src/features/inference.rs`, `src/domain/types.rs`, `src/storage/stable.rs`, `src/http.rs`, `tests/pocketic_agent_autonomy.rs`, `tests/pocketic_ui_observability.rs` (if touched)
      - Validation: `cargo fmt --all -- --check && cargo clippy --all-targets --all-features && cargo test && icp build`
      - Dependencies: Task 1, Task 2, Task 3, Task 4, Task 5

---

## Context Files

- `AGENTS.md`
- `docs/design/CYCLES_SURVIVAL_MODE_AND_HTTPS_OUTCALL_COST_CONTROL.md`
- `src/features/inference.rs`
- `src/storage/stable.rs`
- `src/domain/types.rs`
- `src/http.rs`
- `src/agent.rs`
- `tests/pocketic_agent_autonomy.rs`
- `tests/pocketic_ui_observability.rs`

---

## Codebase Snapshot

Snapshot date: 2026-02-20

- `src/features/inference.rs` currently:
  - builds OpenRouter request body without `max_tokens`,
  - uses full prompt assembly for OpenRouter,
  - records survival failure only for low-cycles paths,
  - records survival success generically on `Ok(...)` outcomes.
- `src/domain/types.rs` currently has OpenRouter runtime fields for base URL and response size cap, but no output-token cap.
- `src/storage/stable.rs` currently persists provider/model/OpenRouter key/base URL and survival backoff runtime state.
- `src/http.rs` currently supports inference config updates for provider/model/key actions and key presence semantics.

---

## Autonomy Scope

### Decide yourself:
- Exact cap bounds for `openrouter_max_output_tokens` (recommended default 256; upper bound chosen conservatively).
- Exact transient timeout classification heuristics from IC/OpenRouter error strings/reject patterns.
- Final naming for inference disposition enum/flags.
- Whether UI wiring for the new knob is included in this change or deferred (as long as HTTP/Candid surfaces remain coherent).

### Escalate (log blocker, skip, continue):
- Any need to alter scheduler architecture beyond inference disposition/backoff accounting.
- Any requirement to add new external dependencies/services.
- Any ambiguity around exposing additional secret-bearing config fields.

---

## Verification

### Smoke Tests
- `cargo fmt --all -- --check` -- formatting unchanged and valid.
- `cargo clippy --all-targets --all-features` -- lint and correctness checks pass.
- `cargo test --lib features::inference::tests::` -- inference request shaping and timeout/backoff behavior is covered.
- `cargo test --lib http::tests::` -- inference config HTTP contract remains valid.
- `icp build` -- canister build path and generated artifacts remain healthy.

### Expected State
- `rg -n "openrouter_max_output_tokens" src/domain/types.rs src/storage/stable.rs src/http.rs` returns matches in runtime model and config path.
- `rg -n "\"max_tokens\"|assemble_system_prompt_compact" src/features/inference.rs` returns OpenRouter request body control points.
- `rg -n "Deferred|deferred|survival_operation_failure" src/features/inference.rs` returns deferred outcome and backoff handling paths.
- `rg -n "survival_operation_success" src/features/inference.rs` confirms success reset is gated to completed inference only.

### Regression
- `bash .githooks/pre-commit` passes.

### Integration Test
- `icp build && cargo test --features pocketic_tests --test pocketic_agent_autonomy -- --nocapture` passes with assertions that an OpenRouter transient timeout path:
  - does not require manual reset to continue scheduled operation,
  - activates inference survival backoff,
  - preserves autonomous loop continuity.

---

## Progress

_Dev agent writes here during execution._

### Completed
- Spec locked.

### Blockers
- None.

### Learnings
- IC HTTPS outcall adapter defaults currently include `http_request_timeout_secs = 30` and `http_connect_timeout_secs = 2`, so canister-side request shaping/backoff is required for latency resilience.

---

## Ship Checklist (non-negotiable final step)

- [ ] Run verification suite (smoke + regression + integration).
- [ ] Confirm no API key leakage in query/API responses/logs.
- [ ] Confirm Candid is generated from Rust exports and not hand-edited.
