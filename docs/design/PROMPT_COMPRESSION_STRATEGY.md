# Prompt Compression Strategy

**Date:** 2026-02-22  
**Status:** Design proposal  
**Scope:** Reduce inference payload size and latency risk by compressing prompt assembly and dynamic context while preserving safety, autonomy, and operational truth.

## Problem

The current prompt pipeline has unbounded payload growth paths that can materially increase inference latency/cost and outcall failure risk.

Primary pressure points:

1. OpenRouter still uses full prompt assembly instead of compact assembly.
2. `InferenceInput.input` can include concatenated full inbox bodies.
3. Layer 10 dynamic context can grow with staged messages, conversation history, and memory entries.
4. No explicit total assembled prompt budget is enforced before provider dispatch.

This is especially risky for autonomous operation, where the canister must self-heal and continue without manual intervention.

## Goals

1. Bound prompt size deterministically before inference calls.
2. Preserve immutable safety/precedence semantics.
3. Keep enough context for high-quality autonomous decisions.
4. Reduce OpenRouter request size and timeout risk.
5. Keep implementation simple and testable (KISS).

## Non-Goals

1. Redesign prompt layer architecture.
2. Remove conversation memory from the agent.
3. Change safety precedence or mutable-layer governance.
4. Introduce a new inference provider.

## Current State (Code-Grounded)

### System prompt assembly paths

1. Full assembly (Layers 0-10): `src/prompt.rs` via `assemble_system_prompt`.
2. Compact assembly (Layers 0, 1, 5, 10): `src/prompt.rs` via `assemble_system_prompt_compact`.
3. IcLlm currently uses compact: `src/features/inference.rs`.
4. OpenRouter currently uses full: `src/features/inference.rs`.

### Measured static size

Approximation method: `approx_tokens ~= chars / 4`.

1. Full static layers (0-9, no Layer 10): ~6,339 chars (~1,585 tokens).
2. Compact static layers (0,1,5, no Layer 10): ~1,955 chars (~489 tokens).
3. Static delta: ~4,384 chars (~1,096 tokens) saved by compact mode.

### Key dynamic growth vectors

1. `InferenceInput.input` can embed all staged inbox bodies as a single concatenated string.
2. Layer 10 pending obligations currently list every staged message with preview.
3. Layer 10 conversation context includes per-sender history entries.
4. Layer 10 memory section includes raw facts and rollups.
5. Enabled skill instructions are appended verbatim into Layer 5.

### Spec/code drift to resolve

A prior locked spec states OpenRouter should use compact prompt assembly by default, but code currently still uses full assembly.

## Constraints and Invariants

1. Layers 0-5 remain immutable and highest-precedence.
2. Mutable layer updates stay constrained to layers 6-9.
3. Prompt injection defenses remain intact.
4. Runtime behavior must remain autonomous; no manual operator dependency.
5. Host-safe time/testing guidance remains unchanged.

## Design

### Core approach

Introduce deterministic prompt budgeting with strict truncation order and provider-aware defaults.

Principles:

1. Compress highest-volume duplicated content first.
2. Keep safety-critical instructions intact.
3. Prefer structured summaries over raw payload duplication.
4. Fail safe: if over budget, trim context sections by priority instead of sending oversized prompts.

### Compression Plan (Phased)

#### Phase 1: Immediate high-impact reductions

1. Switch OpenRouter to compact system prompt assembly.
2. Replace `InferenceInput.input` inbox payload from full concatenated message bodies to a compact envelope (counts/senders/ids and optional tiny preview budget).
3. Add unit tests locking the new OpenRouter compact behavior.

Expected impact:

1. Remove ~1,096 static tokens from every OpenRouter request.
2. Eliminate worst-case duplication of large inbox bodies between `input.input` and Layer 10.

#### Phase 2: Layer 10 deterministic budgeter

Add a Layer 10 compressor/budgeter that enforces fixed caps:

1. Max staged obligations included in detail.
2. Max conversation senders and entries per sender by provider.
3. Max memory facts and rollups included.
4. Max chars per section and max chars total for Layer 10.

Truncation order (least harmful first):

1. Drop memory rollups beyond cap.
2. Drop older memory facts beyond cap.
3. Reduce conversation entries per sender.
4. Reduce number of conversation senders.
5. Replace per-message pending obligations with aggregate summary only.

Expected impact:

1. Predictable upper bound for prompt context.
2. Lower outcall timeout/transport pressure under inbox spikes.

#### Phase 3: Skill and mutable-layer containment

1. Cap rendered active skill instruction bytes in Layer 5.
2. Enforce a total assembled prompt char budget before dispatch.
3. Keep current per-layer mutable cap, but enforce aggregate request-safe cap at assembly time.

Expected impact:

1. Prevent runaway prompt growth from enabled skills/mutable edits.
2. Make prompt size behavior stable over long autonomous runs.

## Provider Profiles

Use provider-specific targets (initial defaults):

1. IcLlm: compact prompt + tighter Layer 10 budget.
2. OpenRouter: compact prompt + moderate Layer 10 budget.

Implementation note: profile-based caps should be constants first; runtime tunables can be added later only if needed.

## Proposed Data and API Behavior Changes

1. No Candid interface changes required for Phase 1/2.
2. No storage schema changes required for Phase 1/2.
3. Internal behavior change: inference requests become compact/budgeted deterministically.

## Validation Plan

### Unit tests

1. OpenRouter request uses compact assembled prompt.
2. `InferenceInput.input` no longer contains full concatenated inbox bodies.
3. Layer 10 budgeter caps sender count, entries per sender, memory items, and total length.
4. Safety/precedence sections remain present after compression.

### Integration tests (PocketIC)

1. Large staged inbox batch does not produce oversized request payload behavior regressions.
2. Autonomous turn remains functional and produces valid tool actions/replies under compressed context.

### Smoke checks

1. `cargo test --lib prompt::tests::`
2. `cargo test --lib features::inference::tests::`
3. `cargo test --lib agent::tests::`
4. `icp build`
5. `cargo test --features pocketic_tests`

## Rollout

1. Land Phase 1 first (smallest diff, highest ROI).
2. Land Phase 2 with test-locked budgets.
3. Land Phase 3 only if prompted by measured drift.

## Risks and Mitigations

1. Risk: Over-compression removes decision-critical context.
   Mitigation: deterministic section priority and targeted tests for autonomy behavior.
2. Risk: Behavior drift from changing `InferenceInput.input`.
   Mitigation: keep minimal envelope semantics stable (`inbox`, `autonomy_tick`, etc.) and lock tests.
3. Risk: Silent spec/code mismatch recurrence.
   Mitigation: explicit tests for provider prompt profile selection.

## Acceptance Criteria

1. OpenRouter path uses compact prompt assembly by default.
2. Prompt request size is bounded by explicit caps and deterministic truncation.
3. All existing safety precedence guarantees remain intact.
4. No autonomy regression in scheduler-driven turns.
5. Unit + integration tests cover the new compression invariants.
