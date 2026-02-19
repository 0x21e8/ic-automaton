# Spec: Temporary Open Canister Inbox For Agent Loop

**Status:** LOCKED
**Date:** 2026-02-19
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** simple
**Authority:** approval
**Tier:** 2

---

## Problem
Before implementing the EVM inbox contract path, there is no simple end-to-end way to inject external user messages into the canister and validate that scheduled runtime work can feed those messages into the agent loop.

## Goal
Ship a temporary, canister-local inbox where any caller can post a message, and periodic runtime work ingests pending inbox messages into the existing agent turn path.

Measurable success:
1. Anonymous and authenticated callers can submit inbox messages through a public update method.
2. Scheduled `PollInbox` jobs ingest posted messages in bounded batches and mark them processed idempotently.
3. A scheduled `AgentTurn` can consume staged inbox input and record turn artifacts without requiring EVM events.

## Non-Goals
- EVM inbox contract integration.
- Message payment, authz, anti-spam/rate limiting, or quotas.
- Backward-compat migration guarantees for temporary schema.
- Full production inbox design.

---

## Human Clarifications Applied
- This is explicitly temporary and exists only to test the loop before EVM contract work.
- Inbox posting is intentionally open to everyone (no authentication gate).
- Keep implementation plan concise (2 tasks).

---

## Requirements

### Must Have
- [ ] Add public update endpoint to post inbox messages without caller authorization checks.
- [ ] Persist inbox messages in stable memory with deterministic ordering and processed state.
- [ ] Implement `PollInbox` job behavior that moves pending messages into an agent-consumable staging area in bounded batches.
- [ ] Ensure each message is staged/processed at most once under duplicate scheduler ticks.
- [ ] Update `AgentTurn` input path to consume staged inbox messages and proceed through normal inference/tool flow.
- [ ] Add unit tests for storage/idempotency and PocketIC integration coverage for end-to-end scheduler behavior.

### Should Have
- [ ] Add query endpoint(s) for recent posted messages and pending counts for debugging.
- [ ] Add structured `canlog` events for post, stage, and consume operations.

### Could Have
- [ ] Add lightweight truncation/retention policy for old processed messages.

---

## Constraints
- Keep changes KISS and local to the canister.
- Do not hand-edit `ic-automaton.did`; rely on candid export flow.
- Use scheduler lanes and existing runtime patterns (no parallel mutating execution).
- Preserve autonomous behavior: transient poll/turn failures must not require manual reset.

---

## Success Criteria
- Posting messages via canister API works for anonymous callers.
- `PollInbox` cadence produces `Succeeded` jobs and stages messages exactly once per message id.
- `AgentTurn` processes staged inbox input and records non-empty turn input summaries when messages exist.
- Existing scheduler/autonomy tests remain green, plus new inbox-focused tests pass.

---

## Implementation Plan

- [ ] **Task 1: Implement temporary open canister inbox storage + API (TDD first)**
      - Files: `src/domain/types.rs`, `src/storage/stable.rs`, `src/lib.rs`, `tests/` (new inbox unit/integration test files)
      - Validation: `cargo test inbox --lib`
      - Notes: Add stable message model, open post endpoint, and message listing/debug queries.

- [ ] **Task 2: Wire scheduler PollInbox ingestion into AgentTurn and validate end-to-end**
      - Files: `src/scheduler.rs`, `src/agent.rs`, `src/storage/stable.rs`, `tests/pocketic_agent_autonomy.rs` (or `tests/pocketic_inbox_polling.rs`)
      - Validation: `cargo test --test pocketic_agent_autonomy --features pocketic_tests`
      - Dependencies: Task 1

---

## Context Files

- `AGENTS.md`
- `src/lib.rs`
- `src/scheduler.rs`
- `src/agent.rs`
- `src/storage/stable.rs`
- `src/domain/types.rs`
- `tests/pocketic_agent_autonomy.rs`
- `tests/pocketic_scheduler_queue.rs`

---

## Codebase Snapshot

Snapshot date: 2026-02-19

- `TaskKind::PollInbox` exists but currently dispatches to a placeholder no-op path in `src/scheduler.rs`.
- `run_scheduled_turn_job` currently derives turn input from `MockEvmPoller` output in `src/agent.rs`.
- Scheduler queue/idempotency primitives already exist in `src/storage/stable.rs` and are covered by queue-focused tests.
- No canister-local public inbox message model/API exists yet.

---

## Autonomy Scope

### Decide yourself
- Exact stable keys and record shapes for temporary inbox state.
- Batch size default for each PollInbox run.
- Whether inbox integration reuses current turn input summary fields or introduces a dedicated summary label.

### Escalate (log blocker, skip, continue)
- Any decision that changes the "no authentication" requirement.
- Any change that introduces new external integrations (EVM/HTTP) in this temporary slice.

---

## Verification

### Smoke Tests
- `cargo test scheduler::tests --lib` -- scheduler core still passes with PollInbox behavior in place.
- `cargo test agent::tests --lib` -- agent loop behavior remains stable with staged inbox input path.

### Expected State
- `src/lib.rs` exports a public update method for posting inbox messages.
- `src/storage/stable.rs` contains stable inbox persistence helpers for post/list/stage/mark-processed flows.
- `src/scheduler.rs` no longer treats `TaskKind::PollInbox` as unconditional no-op.

### Regression
- `cargo test` passes.

### Integration Test
- `cargo test --test pocketic_agent_autonomy --features pocketic_tests` proves: post message -> scheduler PollInbox tick -> AgentTurn consumes staged message -> successful job/turn artifacts.

---

## Progress

_Dev agent writes here during execution._

### Completed
(none yet)

### Blockers
(none yet)

### Learnings
(none yet)
