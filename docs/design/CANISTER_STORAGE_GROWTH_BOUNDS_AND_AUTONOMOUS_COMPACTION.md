# Canister Storage Growth Bounds and Autonomous Compaction

**Date:** 2026-02-21  
**Status:** Design proposal  
**Scope:** Identify where canister state can grow unbounded, classify bounded vs unbounded memory surfaces, propose practical fixes (with tradeoffs), and define autonomous summarization/compaction tasks.

## Why this matters

The automaton must survive without human operations. Unbounded storage growth creates two existential risks:

1. Storage-cycle burn grows continuously.
2. Message execution can hit instruction/stable-memory access limits before raw storage limits.

The design must prioritize autonomous, incremental self-maintenance over manual cleanup.

## External constraints and best practices (research)

- ICP canister stable memory is capped at up to **500 GiB** (subnet capacity dependent), and storage is charged continuously per GiB-second.
  - Source: https://internetcomputer.org/docs/building-apps/canister-management/storage
- Storage pricing baseline currently documented as **127,000 cycles per GiB-second** on 13-node subnets (scaled for larger subnets).
  - Source: https://internetcomputer.org/docs/building-apps/canister-management/storage
  - Source: https://internetcomputer.org/docs/building-apps/essentials/gas-cost
- Per-message execution limits are strict (including instruction limits and stable-memory access/write limits per message), so full-map scans and large single-message maintenance jobs do not scale.
  - Source: https://internetcomputer.org/docs/building-apps/canister-management/resource-limits
  - Source: https://internetcomputer.org/docs/references/execution-errors
- ICP best practices explicitly recommend paginating large query responses and limiting per-call resource usage.
  - Source: https://internetcomputer.org/docs/building-apps/best-practices/general
- HTTPS outcalls should set `max_response_bytes` conservatively; cost is based on reserved max bytes, not actual body size.
  - Source: https://internetcomputer.org/docs/building-apps/network-features/using-http/https-outcalls/overview
  - Source: https://internetcomputer.org/docs/building-apps/security/https-outcalls
- Stable structures are the right primitive for large persistent state and avoid pre/post-upgrade serialization bottlenecks.
  - Source: https://internetcomputer.org/docs/building-apps/developer-tools/cdks/rust/stable-structures
  - Source: https://docs.rs/crate/ic-stable-structures/latest

## Current storage inventory (code-grounded)

Primary definitions are in `src/storage/stable.rs`.

| MemoryId | Map | Current role | Bounded today? | Growth pressure |
|---|---|---|---|---|
| 0 | `RUNTIME_MAP` | runtime snapshot + misc runtime KV | Mixed | Some keys bounded; dynamic prefixes are unbounded |
| 1 | `TRANSITION_MAP` | transition history | No | Append-only forever |
| 2 | `TURN_MAP` | turn history | No | Append-only forever |
| 3 | `TOOL_MAP` | tool records per turn | No | Append-only forever |
| 4 | `SKILL_MAP` | skills by name | Practically yes | Small unless skill sprawl |
| 5 | `SCHEDULER_RUNTIME_MAP` | scheduler runtime singleton | Yes | Single key |
| 6 | `TASK_CONFIG_MAP` | task configs by `TaskKind` | Yes | Fixed key cardinality |
| 7 | `TASK_RUNTIME_MAP` | task runtime by `TaskKind` | Yes | Fixed key cardinality |
| 8 | `JOB_MAP` | historical scheduled jobs | No | Continuous append |
| 9 | `JOB_QUEUE_MAP` | pending queue index | Burst-bounded | Backlog spikes |
| 10 | `DEDUPE_MAP` | dedupe index for jobs | No | Continuous append |
| 11 | `INBOX_MAP` | all inbox messages + status | No | External-input driven, retained forever |
| 12 | `INBOX_PENDING_QUEUE_MAP` | pending inbox queue | Burst-bounded | Backlog spikes |
| 13 | `INBOX_STAGED_QUEUE_MAP` | staged inbox queue | Burst-bounded | Processing lag spikes |
| 14 | `OUTBOX_MAP` | all outbox messages | No | Retained forever |
| 15 | `SURVIVAL_OPERATION_RUNTIME_MAP` | survival operation backoff state | Yes | Fixed small set |
| 16 | `MEMORY_FACTS_MAP` | memory facts KV | Intended bounded, currently bypassable | Growth if many distinct keys |
| 17 | `HTTP_DOMAIN_ALLOWLIST_MAP` | allowed domains | Yes | Small |
| 18 | `PROMPT_LAYER_MAP` | mutable prompt layers | Yes | Fixed layer IDs |
| 19 | `CONVERSATION_MAP` | per-sender conversation history | Yes | Explicit sender+entry caps |

### Important bounded surfaces already in place

- Conversation caps are explicit and enforced:
  - max entries/sender: 20
  - max senders: 200
  - sender/reply truncation: 500 chars
  - (`src/storage/stable.rs`)
- Prompt layers are fixed to mutable IDs only (`src/storage/stable.rs`, `src/prompt.rs`).
- Task config/runtime are bounded by fixed `TaskKind` set (`src/domain/types.rs`).
- Cycle burn sample window is time and count bounded (`CYCLES_BURN_MAX_SAMPLES = 450`).

## High-risk unbounded growth paths

### 1) Scheduler history and dedupe index

- `JOB_MAP` is append-only historical storage (`enqueue_job_if_absent`, `complete_job`, no pruning path).
- `DEDUPE_MAP` stores slot-based dedupe keys and is never pruned.
- Baseline scheduler cadence (`TaskKind::default_interval_secs`):
  - `AgentTurn`: 30s
  - `PollInbox`: 30s
  - `CheckCycles`: 60s
  - `Reconcile`: 300s
- Baseline jobs/day (if enabled):  
  `2880 + 2880 + 1440 + 288 = 7488/day`

Even without user traffic, this guarantees indefinite growth in `JOB_MAP` and `DEDUPE_MAP`.

### 2) Turn/transition/tool histories

- `TRANSITION_MAP`, `TURN_MAP`, `TOOL_MAP` continuously append and are never pruned.
- `TurnRecord.inner_dialogue` has no explicit persisted size cap (`src/domain/types.rs`, `src/agent.rs`).
- Tool records are bounded in count per turn (`MAX_TOOL_CALLS_PER_TURN = 12`) but not tightly bounded in `args_json`/`output` length globally.

### 3) Inbox/outbox persistence

- `INBOX_MAP` retains pending/staged/consumed forever.
- `OUTBOX_MAP` retains forever.
- `post_inbox_message` only validates non-empty body; no maximum body size.
- EVM decode fallback stores raw event envelope JSON, which can be large (`src/scheduler.rs`).

### 4) Runtime map dynamic keys

- `evm.ingest:*` keys via `try_mark_evm_event_ingested` (never pruned).
- `autonomy.tool_success.*` fingerprints via `record_autonomy_tool_success` (never pruned).

### 5) Memory facts cap bypass

- Tool path (`remember_fact_tool`) enforces `MAX_MEMORY_FACTS = 500`.
- Agent path (`persist_eth_balance_from_tool_calls` -> `upsert_memory_fact` -> `stable::set_memory_fact`) bypasses cardinality guard for new keys.
- Result: conceptually “bounded memory” can still expand in key cardinality.

## Growth impacts beyond raw bytes

The first failures likely happen before 500 GiB:

1. **Query/update hot paths degrade** from full-map scans + sort + truncate:
   - `list_inbox_messages`, `list_outbox_messages`, `list_recent_jobs`, `list_all_memory_facts`, `list_memory_facts_by_prefix`.
2. **Instruction/stable-access limits per message** can fail large scans/compaction attempts.
3. **Storage-cycle burden** rises monotonically.
4. **High-watermark stickiness**:
   - ICP stable memory API exposes grow/read/write, not shrink primitives.
   - Inference: once the canister memory grows, “logical delete” alone should not be relied on to reduce allocated memory watermark.
   - Source: https://internetcomputer.org/docs/references/ic-interface-spec

## Design goals

1. Keep autonomous operation safe as data scales.
2. Bound all growth-critical surfaces by policy, not hope.
3. Keep maintenance incremental and resumable (never giant one-shot maintenance calls).
4. Preserve enough history for debugging/governance while controlling cost.
5. Prefer simple, low-risk changes first (KISS).

## Proposed fixes and tradeoffs

## A) Enforce input and record size bounds (Immediate)

### Changes

- Add explicit max size validation for inbound inbox message body.
- Cap stored fallback EVM envelope body size; keep hash + metadata when truncated.
- Cap persisted `inner_dialogue` length.
- Cap `ToolCallRecord.args_json` and `ToolCallRecord.output` persisted length.

### Merit

- Fastest way to stop worst-case single-entry blowups.
- Reduces DoS-by-large-payload risk and protects instruction budget.

### Tradeoff

- Some fidelity loss in long outputs/logs.
- Requires careful truncation strategy to preserve debugging value (prefix + suffix + hash).

## B) Stop full-map scans for “recent N” endpoints (Immediate)

### Changes

- Replace full collect+sort where key order already carries recency:
  - `INBOX_MAP`: iterate reverse by seq key.
  - `OUTBOX_MAP`: iterate reverse by seq key.
  - `JOB_MAP`: iterate reverse by monotonic job seq key.
- Introduce cursor-based pagination endpoints for large listings.

### Merit

- Large performance gain and better resilience under growth.
- Aligns with ICP best practice to paginate.

### Tradeoff

- API shape changes for clients.
- Cursor semantics must be deterministic and test-covered.

## C) Add retention policies for append-only histories (High priority)

### Changes

- Define retention config (runtime-tunable):
  - Jobs: keep `N` days or `N` records.
  - Dedupe slot keys: keep `N` days.
  - Turn/transition/tool history: keep short hot window + summarized cold history.
  - Inbox/outbox raw message retention windows.
- Add autonomous pruning tasks with fixed per-run budgets and checkpoints.

### Merit

- Converts guaranteed unbounded growth into controlled growth.
- Predictable storage-cycle slope.

### Tradeoff

- Raw forensic depth drops unless summary artifacts are added.
- More maintenance code and migration tests required.

## D) Fix memory-facts cardinality guard globally (High priority)

### Changes

- Centralize all writes through a bounded upsert helper (used by tools and agent internals).
- Enforce key/value byte limits and max fact count uniformly.
- Add deterministic eviction policy when full (e.g., oldest-updated or namespace quotas).

### Merit

- Eliminates policy bypass and hidden unbounded growth.

### Tradeoff

- Potential eviction of rarely-used but valuable facts unless ranking is tuned.

## E) Summarization-first retention (High leverage)

### Changes

- Before deleting raw data windows, produce compact summaries:
  - conversation/session summaries,
  - turn window summaries (actions, outcomes, errors),
  - memory fact rollups (e.g., balance trends, recurring signals).
- Store summaries in dedicated bounded maps with clear schema.

### Merit

- Keeps strategic memory while controlling storage.
- Better for autonomous continuity than hard-delete-only retention.

### Tradeoff

- Summaries can be lossy or wrong; must include provenance window and confidence.
- Requires prompt discipline so summaries do not overwrite critical exact facts.

## Proposed autonomous maintenance tasks

Add maintenance tasks as first-class scheduler tasks (or one `StorageMaintenance` task with internal sub-steps and cursors).

## Task 1: `PruneJobHistory`

- Scope: `JOB_MAP`, `DEDUPE_MAP`.
- Trigger: hourly.
- Work budget: max `K` deletes/update (e.g., 200).
- Policy: keep recent `N` days and/or `M` newest.
- Cursor: persist last scanned key.

## Task 2: `PruneTurnHistory`

- Scope: `TRANSITION_MAP`, `TURN_MAP`, `TOOL_MAP`.
- Trigger: hourly/daily depending on load.
- Policy:
  - Keep full detail for short hot window (e.g., 7 days).
  - For older ranges, retain summaries and drop raw records.
- Link integrity: prune tools only after associated turn is summarized or pruned.

## Task 3: `CompactInboxOutbox`

- Scope: `INBOX_MAP`, `OUTBOX_MAP`, queue maps.
- Policy:
  - Keep pending/staged always.
  - Keep consumed/sent raw bodies for short window.
  - Replace older windows with sender/session summary records.
- Guardrail: never remove records required by active conversation window.

## Task 4: `PruneRuntimeDedupeKeys`

- Scope: dynamic keys in `RUNTIME_MAP`:
  - `evm.ingest:*`
  - `autonomy.tool_success.*`
- Policy:
  - TTL bound aligned with duplicate-suppression windows and replay safety.
  - Use key namespace and timestamp payload to support pruning.

## Task 5: `MemoryFactCompactor`

- Scope: `MEMORY_FACTS_MAP`.
- Policy:
  - Enforce hard cap.
  - Prefer keep by freshness + strategic namespace priority.
  - Summarize low-priority stale facts into rollups.

## Session and memory summarization design

## Summary object families

1. `SessionSummary` (per sender, per time bucket)
   - Window start/end
   - Message count
   - Main intents/topics
   - Open obligations
   - Last actionable state
2. `TurnWindowSummary` (global, per hour/day)
   - Turns attempted/succeeded/failed
   - Tool success/failure distribution
   - Key errors and repeated failure signatures
3. `MemoryRollup` (per namespace)
   - Source keys aggregated
   - Aggregation timestamp
   - Canonical condensed value
   - Provenance pointer(s)

## Summarization safety rules

- Summaries are additive first; delete raw data only after summary persisted.
- Every summary carries provenance window and source count.
- Keep critical exact facts exempt from summarization (e.g., latest balances, addresses, config).
- Never let summarization calls exceed fixed instruction/memory budgets; use checkpointed batches.

## Suggested retention defaults (starting point)

These are starting values to tune with telemetry:

- Jobs: keep 14 days raw.
- Dedupe keys: keep 3-7 days.
- Turn/transition/tool raw: keep 7 days + daily summaries for 90 days.
- Inbox consumed/outbox sent raw: keep 14 days + per-sender session summaries for 180 days.
- Runtime dedupe fingerprints: keep 24h (or matched to duplicate window policy).
- Memory facts: hard cap 500 (already intended), with per-namespace quotas.

## Implementation roadmap (KISS, phased)

Use the checklist below as an implementation tracker. Mark each item complete when the "done when" condition is true.

## Phase 0 checklist: Safety rails (small, immediate)

- [x] **P0.1 Add inbox payload cap and truncation policy**
  - Code refs: `src/storage/stable.rs:1495`, `src/http.rs:577`, `src/scheduler.rs:312`.
  - Scope: enforce max body bytes/chars for all inbox ingress paths (public update, `/api/inbox`, EVM ingest fallback).
  - Done when: oversize payload tests pass and inbox stores bounded body content only.

- [x] **P0.2 Cap persisted per-turn text surfaces**
  - Code refs: `src/agent.rs:336`, `src/storage/stable.rs:1412`, `src/storage/stable.rs:1449`.
  - Scope: bound `inner_dialogue`, `ToolCallRecord.args_json`, and `ToolCallRecord.output` before persistence.
  - Done when: serialized turn/tool records have deterministic size ceilings and truncation is test-covered.

- [x] **P0.3 Remove full-scan "recent N" query paths**
  - Code refs: `src/storage/stable.rs:1529`, `src/storage/stable.rs:1788`, `src/storage/stable.rs:2239`, `src/storage/stable.rs:1421`, `src/storage/stable.rs:1435`.
  - Scope: replace collect+sort patterns with key-order reverse iteration where possible.
  - Done when: list endpoints return same ordering semantics without full-map materialization.

- [x] **P0.4 Close memory-facts cardinality bypass**
  - Code refs: `src/tools.rs:526`, `src/agent.rs:282`, `src/storage/stable.rs:949`, `src/storage/stable.rs:967`, `src/storage/stable.rs:971`.
  - Scope: central bounded upsert used by both tool and agent-internal memory writes.
  - Done when: max fact count policy cannot be bypassed via any code path.

- [x] **P0.5 Add storage-growth observability**
  - Code refs: `src/storage/stable.rs:1722`, `src/domain/types.rs:507`, `src/http.rs:182`, `src/lib.rs:205`.
  - Scope: expose per-map counts and retention/summarization progress metrics in observability output.
  - Done when: `/api/snapshot` and candid query snapshot include growth metrics needed for tuning.

- [x] **P0.6 Add canbench pilot for read-path hotspots**
  - Code refs: `src/storage/stable.rs:1529`, `src/storage/stable.rs:1788`, `src/storage/stable.rs:2239`.
  - Scope: add `canbench-rs` harness and baseline benchmarks for inbox/outbox/job listing paths.
  - Done when: baseline metrics are persisted and future runs detect instruction/memory regressions.

## Phase 1 checklist: Retention primitives

- [x] **P1.1 Add retention config model**
  - Code refs: `src/domain/types.rs:868`, `src/storage/stable.rs:545`, `src/lib.rs:205`.
  - Scope: add explicit retention config (age/count limits) for jobs, dedupe, turns, transitions, tools, inbox/outbox.
  - Done when: config is persisted, queryable, and updateable by controller endpoints.

- [x] **P1.2 Add maintenance runtime checkpoint state**
  - Code refs: `src/storage/stable.rs` (new map alongside existing memory IDs), `src/domain/types.rs` (new runtime structs).
  - Scope: persist cursors and last-run metadata for incremental prune scans.
  - Done when: maintenance can resume from checkpoints across ticks/upgrades.

- [x] **P1.3 Implement `JOB_MAP` and `DEDUPE_MAP` pruning first**
  - Code refs: `src/storage/stable.rs:1921`, `src/storage/stable.rs:2110`, `src/storage/stable.rs:2239`, `src/storage/stable.rs:2288`.
  - Scope: prune terminal old jobs and expired dedupe keys with bounded deletes per run.
  - Done when: retention policy keeps map size bounded under long-running scheduler operation.

- [x] **P1.4 Integrate one bounded maintenance scheduler lane**
  - Code refs: `src/domain/types.rs:629`, `src/scheduler.rs:691`, `src/scheduler.rs:84`, `src/storage/stable.rs:1921`.
  - Scope: add maintenance task scheduling with fixed work budget and low priority.
  - Done when: maintenance runs automatically without starving core mutating tasks.

- [x] **P1.5 Add idempotency and safety invariants for pruning**
  - Code refs: `src/storage/stable.rs:2110`, `src/storage/stable.rs:1808`, `src/storage/stable.rs:1872`.
  - Scope: ensure prune operations are retry-safe and never touch pending/staged inbox or in-flight-linked records.
  - Done when: repeated execution cannot corrupt queues or break turn execution assumptions.

- [x] **P1.6 Add canbench coverage for prune batch complexity**
  - Code refs: `src/storage/stable.rs:1921`, `src/storage/stable.rs:2110`.
  - Scope: benchmark prune operations at multiple dataset sizes and batch sizes.
  - Done when: benchmark results show cost scales with configured batch budget, not total map size.

## Phase 2 checklist: Summarization

- [x] **P2.1 Define summary schemas**
  - Code refs: `src/domain/types.rs` (add `SessionSummary`, `TurnWindowSummary`, `MemoryRollup` types).
  - Scope: stable schemas with provenance fields (window bounds, source count, generated_at_ns).
  - Done when: schemas are candid-exported and serialization-tested.

- [x] **P2.2 Add bounded summary stores**
  - Code refs: `src/storage/stable.rs` (new stable maps and helpers), `src/lib.rs` (query endpoints).
  - Scope: introduce dedicated maps for summaries with explicit retention/cap policy.
  - Done when: summary maps are queryable and bounded independently of raw logs.

- [x] **P2.3 Implement inbox/outbox summarize-then-prune**
  - Code refs: `src/storage/stable.rs:1495`, `src/storage/stable.rs:1788`, `src/storage/stable.rs:1808`, `src/storage/stable.rs:1872`.
  - Scope: summarize consumed/sent windows before raw deletion; never prune pending/staged.
  - Done when: old raw windows are removed only after durable summary write succeeds.

- [x] **P2.4 Implement turn/transition/tool summarize-then-prune**
  - Code refs: `src/storage/stable.rs:1412`, `src/storage/stable.rs:1421`, `src/storage/stable.rs:1435`, `src/storage/stable.rs:1449`.
  - Scope: aggregate old turn windows; preserve link integrity between turn and tool records.
  - Done when: old turn/tool volumes flatten while recent debug window remains intact.

- [x] **P2.5 Add summary consumption rules in context builder**
  - Code refs: `src/agent.rs:481`, `src/agent.rs:620`, `src/storage/stable.rs:971`.
  - Scope: define when dynamic context reads raw facts versus rollups.
  - Done when: prompt context remains useful under aggressive raw-retention limits.

- [x] **P2.6 Add canbench coverage for summarize-then-prune**
  - Code refs: `src/storage/stable.rs:1495`, `src/storage/stable.rs:1412`, `src/storage/stable.rs:1788`.
  - Scope: benchmark summary creation and prune steps separately using scoped measurements.
  - Done when: summarization and prune phases stay within bounded per-run instruction/memory envelopes.

## Phase 3 checklist: Hardening and tuning

- [x] **P3.1 Add high-volume PocketIC scenarios**
  - Code refs: `tests/pocketic_scheduler_queue.rs`, `tests/pocketic_agent_autonomy.rs`, `tests/pocketic_evm_polling.rs`.
  - Scope: sustained runs with heavy inbox/job/turn volumes and active maintenance.
  - Done when: scheduler keeps making forward progress and retention bounds are respected.

- [x] **P3.2 Add synthetic stress harness for oversized and burst payloads**
  - Code refs: `src/storage/stable.rs`, `src/http.rs`, `src/scheduler.rs`.
  - Scope: verify rejection/truncation and resilience under burst ingress.
  - Done when: no panic/timeouts and bounded-state guarantees hold.

- [x] **P3.3 Tune defaults from telemetry**
  - Code refs: `src/storage/stable.rs`, `src/domain/types.rs`.
  - Scope: adjust retention windows, batch sizes, and maintenance cadence from observed growth slopes.
  - Done when: growth slope stabilizes in long-run soak tests.

- [x] **P3.4 Add operator-visible storage pressure signals**
  - Code refs: `src/storage/stable.rs`, `src/domain/types.rs`, `src/http.rs`, `src/lib.rs`, `tests/pocketic_ui_observability.rs`.
  - Scope: expose "near-limit" warnings and trend fields in observability APIs.
  - Done when: monitoring can alert before instruction/storage risk thresholds.

- [x] **P3.5 Gate CI with canbench regression thresholds**
  - Code refs: `.github/workflows/canbench-regression.yml`, `ci/check_canbench_regression.py`, `canbench.yml`, `canbench_results.yml`.
  - Scope: run canbench in CI with tolerance-based checks against persisted baselines.
  - Done when: PRs fail on significant instruction/memory regressions in targeted storage-critical benchmarks.

## Useful implementation context for coding agents

- Ordering assumptions currently relied upon:
  - Inbox order: `inbox:{seq:020}` keys (`src/storage/stable.rs:1499`).
  - Outbox order: `outbox:{seq:020}` keys (`src/storage/stable.rs:1766`).
  - Job order: `job:{seq}:{scheduled_for}` keys (`src/storage/stable.rs:1953`).
- Scheduler throughput limits:
  - `MAX_MUTATING_JOBS_PER_TICK = 4` (`src/scheduler.rs:25`).
  - `POLL_INBOX_STAGE_BATCH_SIZE = 50` (`src/scheduler.rs:22`).
- Turn execution guardrails already present:
  - `MAX_INFERENCE_ROUNDS_PER_TURN = 3` (`src/agent.rs:23`).
  - `MAX_AGENT_TURN_DURATION_NS = 90s` (`src/agent.rs:24`).
  - `MAX_TOOL_CALLS_PER_TURN = 12` (`src/agent.rs:25`).
- Existing bounded examples worth reusing:
  - conversation caps (`src/storage/stable.rs:470`).
  - cycle sample cap (`src/storage/stable.rs:1627`).
- Benchmarking strategy:
  - Use `canbench` for deterministic instruction/memory regression checks on storage-critical functions.
  - Keep PocketIC for scheduler/timer/outcall realism; do not replace integration tests with canbench.

## Testing strategy

- Unit tests:
  - size-cap enforcement and truncation behavior.
  - retention cutoff boundary correctness.
  - summarize-then-prune invariants.
  - pagination cursor monotonicity.
- PocketIC integration tests:
  - sustained scheduler operation under high history volume.
  - maintenance tasks progress incrementally without starvation.
  - no regression in autonomy loop under concurrent ingestion.
- Stress tests:
  - large inbox payload attempts rejected/truncated as designed.
  - list/query endpoints remain bounded in execution behavior.

## Risks and mitigations

- Risk: Over-pruning harms debugging.
  - Mitigation: summary-first retention + explicit hot window.
- Risk: Maintenance jobs contend with critical jobs.
  - Mitigation: low-priority scheduling + strict per-run budgets + suspend in low-cycles tier.
- Risk: Summary drift or hallucinated compression.
  - Mitigation: deterministic summary fields where possible, provenance metadata, and conservative deletion gates.

## Open decisions for implementation

1. Should retention be count-based, age-based, or hybrid per map?
2. Which memory namespaces are “critical exact facts” exempt from summarization?
3. How much raw inbox/outbox history is required for debugging vs cost envelope?
4. Should maintenance be a single task with sub-cursors or separate `TaskKind`s?

## Recommended first execution slice

Implement **Phase 0** first, then ship **Job/Dedupe retention (Phase 1 subset)**.  
This yields immediate risk reduction with minimal architectural complexity and no product-behavior ambiguity.
