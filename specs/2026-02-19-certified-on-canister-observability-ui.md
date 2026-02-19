# Spec: Certified On-Canister Observability UI

**Status:** LOCKED
**Date:** 2026-02-19
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** moderate
**Authority:** approval
**Tier:** 2

---

## Problem

The automaton currently exposes only Candid methods, so there is no direct, human-facing interface that conveys "what the automaton is thinking and doing." This makes operability and storytelling weak despite the runtime already collecting useful inbox, turn, transition, and scheduler data.

## Goal

Serve a minimal, modern UI directly from the canister with certified HTTP responses, and make it actionable + observable:
1. A user can open `/` and use the UI without any external hosting.
2. A user can post a message to the automaton inbox from the UI.
3. A user can view live runtime activity (state, turns, transitions, jobs, inbox status) from the UI.
4. Core UI assets are certified using `ic-http-certification`.

## Non-Goals

- Building a full admin console or RBAC system.
- Replacing existing Candid APIs with HTTP JSON APIs.
- Real-time push/WebSocket streaming.
- Rich analytics, search, or long-term log archival UX.

---

## Autonomous Decisions

- Use `ic-http-certification` for static UI asset certification (`/`, `/app.js`, `/styles.css`) served by canister HTTP entrypoints.
- Keep the frontend buildless (plain HTML/CSS/JS files embedded/served by Rust) to stay KISS and avoid adding a JS build pipeline.
- Reuse existing Candid endpoints for core data and add one compact snapshot query for UI hydration to reduce round trips.
- Poll for observability updates on a short interval (default: 2 seconds), with graceful degradation on transient query failures.
- Keep UI publicly readable in this development phase; no auth gating is introduced in this feature slice.

---

## Design System And Visual Direction

### Creative Direction

- Theme: "Living machine on decentralized substrate" with an operational, cinematic control-room feel.
- Tone: calm, technical, and alive; avoid toy-like UI and default dashboard boilerplate.
- Visual hierarchy: identity first (automaton), then current state, then event stream and controls.

### Typography

- Use a distinctive sans + mono pairing (example target: `Space Grotesk` for UI, `IBM Plex Mono` for logs/data).
- Avoid default-only font stacks (`Arial`, plain system defaults) as primary identity type.
- Use mono face for IDs, timestamps, job keys, and event payload snippets.

### Color, Surface, And Atmosphere

- Define CSS variables for semantic tokens in `:root`:
- [ ] base background
- [ ] elevated panel surface
- [ ] primary text
- [ ] muted text
- [ ] accent signal (automation active)
- [ ] warning/error state
- [ ] border and focus ring
- Use layered background treatment (subtle gradient/noise/grid), not flat single-color canvas.
- Maintain accessible contrast for all body text and status badges.

### Components

- Compose UI from reusable primitives:
- [ ] shell/frame
- [ ] panel/card
- [ ] status badge
- [ ] timeline row
- [ ] message composer
- [ ] key-value stat tile
- Ensure component styling is token-driven (no one-off hardcoded colors scattered through stylesheet).

### Motion And Interaction

- Include meaningful but minimal motion:
- [ ] initial reveal/stagger for primary panels
- [ ] soft live-update pulse for new events
- Respect reduced-motion preferences via `@media (prefers-reduced-motion: reduce)`.
- Keep motion functional (state change communication), not decorative noise.

### Responsive And Accessibility

- Desktop and mobile layouts must be first-class; no horizontal overflow at common widths.
- Minimum touch target size for composer actions on mobile.
- Keyboard focus visibility for actionable controls.
- Status states must not rely on color alone (icon/text label pairing).

---

## Requirements

### Must Have
- [ ] Implement certified HTTP asset serving with `ic-http-certification`.
- [ ] Add canister HTTP handlers for serving UI assets (`http_request`, and `http_request_update` if required by certification flow/gateway compatibility).
- [ ] Ensure certification state is initialized/rebuilt in both `init` and `post_upgrade`.
- [ ] Add a UI-oriented query method returning structured observability snapshot data (runtime, scheduler view, recent turns, recent transitions, recent jobs, inbox stats/messages).
- [ ] Provide a minimal modern UI that reflects project identity ("autonomous automaton on decentralized substrate").
- [ ] Implement a small token-based design system in CSS variables and use it across all UI components.
- [ ] Apply a non-default typography pairing (sans + mono) aligned with the technical/operational theme.
- [ ] UI includes message composer that calls `post_inbox_message`.
- [ ] UI includes live activity panel for runtime state and soul.
- [ ] UI includes live activity panel for scheduler health and recent jobs.
- [ ] UI includes live activity panel for recent transitions/turns ("thinking and doing").
- [ ] UI includes live activity panel for inbox stats and recent messages.
- [ ] Add failure states in UI (network/query/update error visibility, retry behavior).
- [ ] Include reduced-motion safe animations and meaningful state-change cues.
- [ ] Ensure responsive layout and keyboard-visible focus for interactive controls.
- [ ] Add unit tests for HTTP route handling + certification setup and for the snapshot query shape.
- [ ] Add PocketIC integration test covering end-to-end UI support primitives (asset serving + posting + observable state changes).

### Should Have
- [ ] Stable, typed DTOs for UI responses (avoid stringly typed parsing in frontend).
- [ ] Basic filter/scope controls in UI feed (e.g., limit selector and source toggles).
- [ ] Relative timestamps in UI for log readability.

### Could Have
- [ ] Lightweight "copy as JSON" for diagnostics from each panel.
- [ ] Auto-scroll toggle for newest-first event feed.

---

## Constraints

- Use `icp-cli` workflow for build/deploy/test loops.
- Keep Candid generated from Rust (`ic_cdk::export_candid!()`); do not hand-edit `ic-automaton.did`.
- Preserve current scheduler/autonomy behavior; UI work must be read-only except explicit inbox post action.
- Keep implementation minimal and maintainable (no SPA framework or bundler introduced in this slice).
- Keep style system centralized and token-based; avoid ad hoc inline styling.
- Follow ICP security best practices:
- [ ] certified HTTP responses for static assets
- [ ] no secret material surfaced in UI snapshot/query payloads
- [ ] bounded response sizes/limits for lists returned to UI

---

## Success Criteria

- Opening canister root path serves the UI from the canister itself.
- UI assets are certified and verifiable through IC HTTP certification headers/witness path.
- Posting a message from UI successfully writes to inbox (`post_inbox_message`) and appears in UI refresh.
- UI shows recent operational history that maps to agent activity (turns, transitions, scheduler jobs) without requiring manual Candid calls.
- UI style is driven by explicit design tokens and reusable component classes (no one-off visual drift).
- UI is visually distinct from a default template (expressive typography, atmospheric background, clear identity framing).
- UI remains usable on mobile and with reduced-motion preferences.
- All relevant tests pass, including PocketIC integration coverage for this feature.

---

## Implementation Plan

- [ ] **Task 1: Add HTTP certification and asset service module**
      - Files: `Cargo.toml`, `src/http.rs` (new), `src/lib.rs`
      - Validation: `cargo check`
      - Notes: Introduce `ic-http-certification` and a small asset registry + certified response builder for static files.

- [ ] **Task 2: Add UI static assets (buildless frontend)**
      - Files: `src/ui_index.html` (new), `src/ui_styles.css` (new), `src/ui_app.js` (new)
      - Validation: `rg -n "post_inbox_message|get_observability_snapshot|list_recent" src/ui_index.html src/ui_app.js`
      - Notes: Keep UX intentional/minimal, responsive on desktop/mobile, no framework dependency.

- [ ] **Task 3: Implement design-system tokens and component primitives**
      - Files: `src/ui_styles.css`, `src/ui_index.html`
      - Validation: `rg -n -- "--color-|--font-|prefers-reduced-motion|panel|timeline|badge" src/ui_styles.css`
      - Notes: Enforce tokenized color/type/spacing and reusable component classes; include reduced-motion behavior.

- [ ] **Task 4: Add UI snapshot API for efficient hydration**
      - Files: `src/domain/types.rs`, `src/lib.rs`, `src/storage/stable.rs` (if helper accessors are needed)
      - Validation: `cargo test`
      - Notes: Add typed structs with bounded limits and no secret fields.

- [ ] **Task 5: Wire init/upgrade lifecycle for certification**
      - Files: `src/lib.rs`, `src/http.rs`
      - Validation: `cargo test`
      - Notes: Ensure certification tree/data is initialized in `init` and `post_upgrade`.

- [ ] **Task 6: Add unit tests for HTTP and snapshot behavior**
      - Files: `src/http.rs`, `src/lib.rs` (tests module or dedicated unit test modules)
      - Validation: `cargo test`
      - Notes: Cover route correctness, content type, and deterministic snapshot schema behavior.

- [ ] **Task 7: Add PocketIC integration test for canister-served UI flow**
      - Files: `tests/pocketic_ui_observability.rs` (new)
      - Validation: `icp build && cargo test --features pocketic_tests --test pocketic_ui_observability`
      - Notes: Verify asset serving primitives + message post + observable updates via query methods.

- [ ] **Task 8: Final validation and candid generation**
      - Files: `ic-automaton.did` (generated), changed source files above
      - Validation: `bash .githooks/pre-commit`
      - Dependencies: Task 1, Task 2, Task 3, Task 4, Task 5, Task 6, Task 7

---

## Context Files

- `AGENTS.md`
- `src/lib.rs`
- `src/http.rs` (new)
- `src/domain/types.rs`
- `src/storage/stable.rs`
- `src/scheduler.rs`
- `tests/pocketic_agent_autonomy.rs`
- `tests/pocketic_scheduler_queue.rs`
- `Cargo.toml`
- `icp.yaml`

---

## Codebase Snapshot

Snapshot date: 2026-02-19

- Canister already has inbox write path (`post_inbox_message`) and multiple observability queries (`list_recent_events`, `list_turns`, `list_scheduler_jobs`, `get_runtime_view`, `get_scheduler_view`, `get_inbox_stats`).
- Scheduler and storage already persist structured runtime/job/message state and use `canlog` logging.
- No canister HTTP endpoint exists yet for serving UI assets.
- No frontend/UI asset files currently exist in the repository.
- Existing PocketIC tests cover scheduler and autonomy behavior, but not HTTP asset serving/UI flow.

---

## Autonomy Scope

### Decide yourself

- Exact UI layout, typography, and visual treatment within "minimal modern" direction.
- Internal module boundaries for HTTP/certification helpers.
- Snapshot payload shape and list limits, as long as it remains typed, bounded, and non-sensitive.

### Escalate (log blocker, skip, continue)

- Any requirement to expose privileged/admin-only mutation from UI.
- Any requirement to move UI hosting off-canister.
- Any requirement to introduce external analytics, trackers, or third-party frontend runtime dependencies.

---

## Verification

### Smoke Tests

- `cargo check` -- code compiles with new HTTP/certification and UI modules.
- `cargo fmt --all -- --check` -- formatting remains clean.
- `cargo clippy --all-targets --all-features` -- lint/static checks pass.
- `cargo test` -- unit tests pass (including new HTTP/snapshot tests).
- `icp build` -- canister builds and candid generation succeeds.

### Expected State

- `Cargo.toml` includes `ic-http-certification` dependency.
- File `src/http.rs` exists and defines canister HTTP handling for UI assets.
- Files `src/ui_index.html`, `src/ui_styles.css`, and `src/ui_app.js` exist.
- `src/ui_styles.css` defines shared design tokens (type/color/spacing/motion) and component classes used by the UI.
- `src/lib.rs` exports the HTTP handler(s) and UI snapshot query endpoint.
- `ic-automaton.did` includes the new query/update methods introduced for UI/certified HTTP support.

### Regression

- `bash .githooks/pre-commit` passes.

### Integration Test

- `icp build && cargo test --features pocketic_tests --test pocketic_ui_observability` passes and proves:
- [ ] canister serves UI assets over HTTP path(s)
- [ ] UI backend primitives can post inbox messages
- [ ] observability snapshot reflects newly posted/processed state over time
