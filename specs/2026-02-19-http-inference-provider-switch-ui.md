# Spec: HTTP Inference Provider Switch + UI Controls

**Status:** LOCKED
**Date:** 2026-02-19
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** moderate
**Authority:** approval
**Tier:** 2

---

## Problem

Inference provider configuration is currently exposed via Candid update/query methods, but the canister HTTP API used by the frontend does not provide inference config routes, and the UI has no controls for provider/model/key management. As a result, operators cannot switch between the llm_canister (mock) path and OpenRouter directly from the frontend.

## Goal

Ship a canister-served configuration surface that allows inference provider management from the UI:
1. Add an HTTP endpoint to read and update inference provider settings.
2. Support switching between `llm_canister (mock)` and `openrouter`.
3. For OpenRouter, support model selection and API key updates.
4. Keep secrets protected (no API key exposure in query responses/logs/UI snapshots).

## Non-Goals

- Redesigning inference adapters or changing inference execution semantics.
- Adding authentication/RBAC in this slice.
- Introducing new frontend frameworks or a build pipeline.
- Adding multi-provider routing, retries, or fallback orchestration.

---

## Human Clarifications Applied

- UI option `llm_canister (mock)` maps to runtime provider `IcLlm`.
- OpenRouter model selection uses a dropdown with an optional custom override.
- OpenRouter API key changes are explicit-only (no implicit update/clear from empty fields).

---

## Autonomous Decisions

- Add HTTP config routes at `/api/inference/config`:
- `GET /api/inference/config` for current safe-to-display config.
- `POST /api/inference/config` for config updates.
- Keep provider choices in the UI to two options requested by product: `llm_canister (mock)` and `openrouter`.
- Map `llm_canister (mock)` to runtime `InferenceProvider::IcLlm`.
- Model control behavior:
- show dropdown presets;
- allow explicit custom model override input.
- Key mutation behavior:
- update key only when explicitly requested;
- clear key only when explicitly requested.
- Reuse existing stable config setters/getters where possible and avoid duplicating persistence logic.
- Keep endpoint unauthenticated for now to match current development-phase UI/write-path posture.

---

## Requirements

### Must Have
- [ ] Add canister HTTP API route `GET /api/inference/config` returning safe inference config (`provider`, `model`, `openrouter_base_url`, `openrouter_has_api_key`, `openrouter_max_response_bytes`).
- [ ] Add canister HTTP API route `POST /api/inference/config` that supports:
- [ ] switching provider between `llm_canister (mock)` and `openrouter`;
- [ ] setting OpenRouter model via dropdown value or explicit custom override value;
- [ ] setting or clearing OpenRouter API key only through explicit action fields in payload.
- [ ] Enforce validation errors with clear JSON error responses for malformed payloads and invalid provider/model values.
- [ ] Ensure API key is never returned in JSON responses.
- [ ] Ensure API key is never emitted in logs.
- [ ] Add a dedicated "Inference" panel/form in the canister-served UI with:
- [ ] provider selector,
- [ ] OpenRouter model dropdown + optional custom override input,
- [ ] OpenRouter API key password input,
- [ ] explicit key action controls (`keep` / `set` / `clear`) with save/apply action and user-visible status.
- [ ] UI loads and displays current config on boot.
- [ ] UI conditionally shows/enables OpenRouter-specific fields when OpenRouter is selected.
- [ ] Successful save refreshes local UI state and reflects persisted config.
- [ ] Add unit tests for HTTP config request parsing/validation/response shaping.
- [ ] Add integration coverage (PocketIC) proving endpoint behavior and persistence across calls.

### Should Have
- [ ] Add a "clear API key" UI action (explicit empty/clear submission path).
- [ ] Disable submit while request is in flight to prevent duplicate submissions.
- [ ] Keep inference config panel consistent with existing visual token/component system.

### Could Have
- [ ] Surface a lightweight "active provider" badge in the Runtime panel.
- [ ] Show a "last updated" timestamp for inference config actions in UI state text.

---

## Constraints

- Keep implementation KISS and localized to HTTP + UI layers and existing storage helpers.
- Do not hand-edit `ic-automaton.did`; rely on Rust candid export flow.
- Preserve existing scheduler/autonomy behavior.
- Do not expose secret key material via query payloads, snapshot payloads, or logs.
- Follow current canister-served frontend approach (plain HTML/CSS/JS, no bundler).

---

## Success Criteria

- UI user can switch provider between `llm_canister (mock)` and `openrouter` without using Candid calls manually.
- UI user can set OpenRouter model from dropdown or explicit custom override from the Inference panel.
- UI user can set or clear OpenRouter API key only through explicit key actions.
- `GET /api/inference/config` reflects saved provider/model and boolean key-presence state.
- API key value is never returned by any HTTP response.
- Invalid payloads return deterministic JSON validation errors.
- All validation gates pass (`fmt`, `clippy`, tests, build).

---

## Implementation Plan

- [ ] **Task 1: Add HTTP inference config DTOs and route handlers (TDD first)**
      - Files: `src/http.rs`, `src/domain/types.rs` (if dedicated HTTP DTOs are added)
      - Validation: `cargo test --lib http`
      - Notes: Implement `GET/POST /api/inference/config` in `handle_http_request_update`.

- [ ] **Task 2: Wire route handlers to stable inference config persistence**
      - Files: `src/http.rs`, `src/storage/stable.rs` (only if missing helper APIs), `src/lib.rs` (if exports/refs needed)
      - Validation: `cargo test`
      - Notes: Reuse `set_inference_provider`, `set_inference_model`, `set_openrouter_api_key`, `inference_config_view`.

- [ ] **Task 3: Add frontend inference settings panel and API wiring**
      - Files: `src/ui_index.html`, `src/ui_app.js`, `src/ui_styles.css`
      - Validation: `rg -n \"inference|/api/inference/config|openrouter\" src/ui_index.html src/ui_app.js src/ui_styles.css`
      - Notes: Keep component styling consistent with existing UI direction and responsive layout.

- [ ] **Task 4: Add endpoint + UI integration tests with PocketIC**
      - Files: `tests/pocketic_ui_observability.rs` (extend) or `tests/pocketic_ui_inference_config.rs` (new), `src/http.rs` tests
      - Validation: `icp build && cargo test --features pocketic_tests --test pocketic_ui_observability`
      - Notes: Validate save + fetch roundtrip, provider switch behavior, and API key non-disclosure.

- [ ] **Task 5: Full validation + hooks**
      - Files: changed files above
      - Validation: `cargo fmt --all -- --check && cargo clippy --all-targets --all-features && cargo test && icp build && bash .githooks/pre-commit`
      - Dependencies: Task 1, Task 2, Task 3, Task 4

---

## Context Files

Files the dev agent should read before starting:
- `AGENTS.md`
- `src/http.rs`
- `src/ui_index.html`
- `src/ui_app.js`
- `src/ui_styles.css`
- `src/lib.rs`
- `src/storage/stable.rs`
- `src/domain/types.rs`
- `src/features/inference.rs`
- `specs/2026-02-18-inference-provider-ic-llm-then-openrouter.md`
- `specs/2026-02-19-certified-on-canister-observability-ui.md`

---

## Codebase Snapshot

Snapshot date: 2026-02-19

- Inference config persistence and Candid methods already exist (`set_inference_provider`, `set_inference_model`, `set_openrouter_api_key`, `get_inference_config`).
- HTTP API currently supports only `/api/snapshot` and `/api/inbox`; there is no inference-config HTTP route.
- UI currently supports observability polling and inbox message posting only; no inference settings controls exist.
- Runtime inference layer already supports `Mock`, `IcLlm`, and `OpenRouter` providers.

---

## Autonomy Scope

### Decide yourself:
- Exact HTTP payload schema shape for update requests.
- Exact UI copy/layout for inference controls within existing design language.
- Whether to extend existing PocketIC UI test or add a dedicated test file.

### Escalate (log blocker, skip, continue):
- Any requirement to expose raw OpenRouter API key through query/UI.
- Any requirement to introduce auth/permissions for config writes in this same slice.
- Any proposal to broaden scope into inference-engine redesign.

---

## Verification

### Smoke Tests
- `cargo check` -- project compiles with new HTTP/UI inference config paths.
- `cargo fmt --all -- --check` -- formatting compliance.
- `cargo clippy --all-targets --all-features` -- lint compliance.
- `cargo test` -- unit/integration tests pass.
- `icp build` -- canister build and candid generation still pass.

### Expected State
- `src/http.rs` contains route handlers for `GET /api/inference/config` and `POST /api/inference/config`.
- `src/ui_index.html` contains inference settings form controls.
- `src/ui_app.js` calls `/api/inference/config` for load and save flows.
- No response type includes raw OpenRouter API key value (only presence boolean).
- `ic-automaton.did` is regenerated from Rust exports and not manually edited.

### Regression
- `bash .githooks/pre-commit` passes.

### Integration Test
- `icp build && cargo test --features pocketic_tests --test pocketic_ui_observability` proves:
- canister serves UI assets,
- inference config endpoint accepts provider/model/key updates,
- subsequent config reads reflect persisted updates while keeping API key hidden.

---

## Progress

_Dev agent writes here during execution._

### Completed
- Spec locked.

### Blockers
- None.

### Learnings
- Existing backend inference config persistence is already implemented; this feature is primarily an HTTP API + frontend exposure gap.

---

## Ship Checklist (non-negotiable final step)

- [ ] Run verification suite (smoke + regression + integration).
- [ ] Confirm no secret leakage in HTTP responses/logs.
- [ ] Confirm UI can switch providers and persist OpenRouter model/key state.
