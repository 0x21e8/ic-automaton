# Inner Monologue Natural Flow Implementation Plan

## Scope

Make `peek` output read like coherent human thought flow while preserving operational truth and existing observability guarantees.

## Requirements

1. `peek` output should read like a coherent human thought flow, not logs.
2. It should stay interesting: clear tension/choice/result, not flat status text.
3. Keep operational truth: no fabricated actions, no loss of diagnostics.
4. Preserve autonomy constraints and existing safety policy behavior.
5. Keep storage bounds and deterministic testability intact.

## Chosen Shape

1. Build a narrative composer in `src/agent.rs` and feed it structured turn events.
2. Add explicit voice guidance in prompt policy so model-generated text aligns.
3. Keep existing machine fields (`tool_call_count`, `continuation_stop_reason`, `error`) as the audit channel.
4. Do not add schema/API complexity yet (no dual-channel fields in v1).

## Implementation Plan (TDD-first)

### Slice 1: Lock Style Contract with Tests

1. Add tests in `src/agent.rs` around a new renderer API (e.g. `render_inner_dialogue_narrative(...)`) before implementation.
2. Replace brittle phrase checks currently tied to `goal:` / `why:` with intent-based assertions.
3. Add negative assertions that final text does not contain raw labels like `goal:`, `why:`, `inference:`.

### Slice 2: Structured Beats + Narrative Rendering

1. In `src/agent.rs`, replace direct string appends with structured beat collection.
2. Render beats into short paragraphs: context -> decision -> action/result -> next step.
3. Keep factual details (counts, stop reasons, errors), but phrase naturally.
4. Keep tool summary truthful by reusing existing tool summarization.

### Slice 3: Prompt-Level Voice Alignment

1. Add an "Inner Dialogue Voice" subsection to system policy in `src/prompt.rs`.
2. Place it where both full and compact prompt paths receive it (Layer 5).
3. Guidance should enforce first-person reflective tone, causal flow, concise language, and concrete claims.
4. Ensure it does not conflict with safety/operations policy layers.

### Slice 4: UI/Doc Alignment

1. Keep UI rendering unchanged unless readability issues remain (`src/ui_app.js` renders `inner_dialogue` verbatim).
2. Update spec examples in terminal UI docs to match the new narrative style contract.

## Acceptance Criteria

1. `peek` entries read as 1-3 coherent paragraphs per turn with clear flow.
2. No raw label prefixes (`goal:`, `why:`, `inference:`) in stored `inner_dialogue`.
3. Stop/degrade reasons remain visible in natural language.
4. Tool outcomes remain explicitly stated and truthful.
5. Existing turn metadata semantics remain unchanged.
6. `inner_dialogue` remains within storage truncation bounds.

## Validation Plan

1. `cargo test --lib agent::tests::`
2. `cargo test --lib features::inference::tests::`
3. `icp build` (before PocketIC integration tests)
4. `cargo test --features pocketic_tests`
5. Manual `peek` review of latest 5 turns in local UI.

## Commit Plan

1. Commit 1: tests + style contract assertions.
2. Commit 2: narrative composer implementation.
3. Commit 3: prompt voice guidance + docs update.
