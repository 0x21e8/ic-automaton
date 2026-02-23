# Hybrid Experimenter vs Full Autonomic Runtime

**Date:** 2026-02-22  
**Status:** Exploratory design  
**Scope:** Present and discuss design-space options 2 and 3 for automaton self-knowledge, capability learning, and autonomous expansion.

---

## Context

The current codebase already has a strong autonomy substrate:

- Timer-driven scheduler with task cadence, dedupe, and lease control (`src/scheduler.rs`, `src/storage/stable.rs`)
- Recovery/backoff and survival-tier gating (`src/domain/recovery_policy.rs`, `src/storage/stable.rs`)
- Structured tool execution records (`ToolCallRecord`) and job runtime telemetry (`src/domain/types.rs`)
- Layered prompt system with mutable policy layers 6-9 (`src/prompt.rs`, `src/tools.rs`)
- Stable-memory state with runtime config surfaces and admin update APIs (`src/lib.rs`, `src/storage/stable.rs`)

The remaining design question is how much autonomy to put above this substrate.

---

## Option 2: Hybrid Experimenter Runtime

### Summary

Add a typed, system-owned capability learning loop on top of the existing scheduler + tool runtime. Keep planning flexible, but keep learning and safety enforcement deterministic and stateful.

### Why this is a good fit now

- Reuses most existing primitives
- Bounded complexity and cycle spend
- Stronger guarantees than prompt-only self-improvement
- Fast path to practical autonomous adaptation

### Core Components

1. Capability Registry (typed stable state)
- One row per capability (for example: `evm_read.eth_getBalance`, `send_eth`, `http_fetch.domain:X`)
- Tracks:
  - preconditions
  - expected effects
  - risk tier
  - confidence score
  - failure streak
  - `last_verified_ns`
  - `next_probe_ns`

2. Evidence Pipeline (from real outcomes)
- Inputs:
  - tool outcomes (`ToolCallRecord`)
  - scheduler job outcomes and recovery decisions
- Outputs:
  - confidence updates
  - capability promotion/demotion
  - probe scheduling updates

3. Probe Scheduler
- Runs low-risk verification probes periodically
- Uses existing scheduling/retry mechanisms
- Initial low-churn approach: implement probe execution under `TaskKind::Reconcile`, then split into a dedicated task if needed

4. Execution Gate
- Before executing a tool call, check capability confidence + risk policy
- If blocked:
  - skip action
  - record reason
  - schedule probe/retry

### Control Loop

1. Observe: ingest tool/job outcomes.
2. Update: recompute confidence and failure streaks.
3. Decide: enable, degrade, or quarantine capabilities.
4. Probe: execute due low-risk probes.
5. Plan/Act: allow only policy-compliant capabilities.

### Strengths

- Deterministic learning state survives upgrades
- Bounded by existing recovery/backoff controls
- Better at avoiding repeated useless actions
- Compatible with current layered-prompt model

### Weaknesses

- Discovery is limited to declared capability surface
- Still depends on model reasoning quality for goal selection
- Requires adding and maintaining typed capability schemas

---

## Option 3: Full Autonomic Runtime

### Summary

Evolve Option 2 into a runtime that not only verifies known capabilities, but also discovers new strategies/opportunities and reallocates effort dynamically to maximize survival and income.

### Added Components Beyond Option 2

1. Strategy Portfolio Manager
- Maintains multiple candidate strategies with explicit expected value, risk, and cost models
- Allocates execution budget across strategies based on observed returns

2. Opportunity Harvester
- Continuously gathers candidate opportunities from inbox, chain data, and allowlisted HTTP sources
- Converts raw signals into testable hypotheses

3. Experiment Manager
- Runs bounded experiments with explicit budget caps and stop conditions
- Promotes successful experiments to reusable capabilities

4. Governance and Rollback Layer
- Hard budget envelopes by operation class
- Quarantine and rollback for strategies with high loss/failure
- Explicit kill-switch semantics for high-risk autonomy branches

### Control Loop

1. Sense: gather opportunities and system state.
2. Hypothesize: generate candidate value-creating actions.
3. Allocate: assign budget by expected value/risk.
4. Execute: run bounded experiments or known strategies.
5. Learn: update portfolio weights and capability graph.
6. Recover: quarantine failing strategies and rebalance.

### Strengths

- Highest upside for autonomous income generation
- Better long-horizon adaptation to changing environments
- More resilient to single-strategy failure

### Weaknesses

- Much larger policy/governance surface
- Higher cycle burn risk without tight budget controls
- Harder observability and debugging
- More failure modes from interaction effects across subsystems

---

## Option 2 vs Option 3

| Dimension | Option 2: Hybrid Experimenter | Option 3: Full Autonomic |
|---|---|---|
| Time to value | Fast | Slow |
| Implementation complexity | Moderate | High |
| New failure surface | Moderate | High |
| Cost control difficulty | Moderate | High |
| Discovery power | Limited-to-moderate | High |
| Governance burden | Moderate | Very high |
| Fit for current codebase | Strong | Partial (needs significant extension) |

---

## How to Navigate the Design Space

Treat this as a staged progression with hard gates:

1. Land Option 2 fully first.
- Typed capability registry
- Evidence-driven confidence updates
- Probe scheduling
- Tool execution gating

2. Only move toward Option 3 when Option 2 is stable.
- Stable means:
  - low repeated-failure loops
  - predictable budget behavior
  - confidence metrics match observed outcomes

3. Introduce Option 3 in bounded slices.
- First portfolio management over existing capabilities
- Then opportunity harvesting
- Then bounded experimentation
- Keep rollback and budget envelopes mandatory at each step

---

## Personality Adaptation Across Different Automatons (Without Code Changes)

For multiple instantiated automatons, personality can be set by runtime data, not binaries:

1. Identity/persona label
- `soul` value (`update_soul`)

2. Behavioral policy style
- Prompt layers 6-9 content (`update_prompt_layer_admin` or `update_prompt_layer` tool)

3. Operational tempo and risk posture
- Task intervals and enablement (`set_task_interval_secs`, `set_task_enabled`)
- Survival mode toggles (`set_scheduler_low_cycles_mode`)

4. Cognitive/cost profile
- Inference provider/model configuration

5. Environment specialization
- Init args per canister install (`ecdsa_key_name`, `evm_chain_id`, `evm_rpc_url`, allowlist domains, etc.)

This creates a "persona pack" per automaton instance:

- `identity`: soul
- `policy`: layer 6-9 text
- `tempo`: scheduler cadence
- `risk`: enabled tasks + low-cycles settings
- `cognition`: provider/model
- `environment`: chain + RPC + domains

No code changes are required to vary these parameters across instances.

---

## Recommendation

Adopt Option 2 as the active architecture and treat Option 3 as a gated expansion path.

Reason:
- It matches the current codebase architecture with minimal structural churn.
- It materially improves self-knowledge and learning quality now.
- It preserves a clear migration path to full autonomy after governance and budget controls are proven.
