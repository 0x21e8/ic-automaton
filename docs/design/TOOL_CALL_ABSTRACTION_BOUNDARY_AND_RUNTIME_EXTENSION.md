# Tool Call Abstraction Boundary and Runtime Extension

**Date:** 2026-02-19  
**Status:** Draft design  
**Scope:** Define what is a tool call vs skill vs internal runtime subsystem, with ICP-specific runtime extension constraints.

## Problem

The codebase already has:
- runtime tool execution (`src/tools.rs`)
- persisted skill metadata (`src/features/skills.rs`, `src/storage/stable.rs`)
- inference-emitted tool calls (`src/features/inference.rs`)

But there is no explicit architecture contract for:
- what capabilities should be model-invoked tools,
- what should stay as skills/instructions,
- what should stay internal runtime logic,
- how new tools can be introduced at runtime on ICP.

Without this boundary, capability sprawl and security regressions are likely.

## Current Baseline (Repo)

- Tool calls are executed by `ToolManager` with a compile-time string match (`sign_message`, `broadcast_transaction`, `record_signal`) and per-tool policy in memory (`src/tools.rs`).
- Skills are persisted as `SkillRecord` rows (`name`, `description`, `instructions`, `enabled`, `mutable`) in stable memory (`src/domain/types.rs`, `src/storage/stable.rs`), with one default skill installed at init (`src/features/skills.rs`).
- Agent turns consume inferred tool calls and persist tool call records per turn (`src/agent.rs`, `src/storage/stable.rs`).
- Scheduler survival classes (`Inference`, `EvmPoll`, `EvmBroadcast`, `ThresholdSign`) already exist and gate expensive operations (`src/scheduler.rs`, `src/storage/stable.rs`).

## Working Definitions

- Tool call: A bounded executable capability the model can request at runtime and the canister may execute.
- Skill: Reusable instruction/policy that shapes planning and tool-choice behavior; not an executable side-effect surface by itself.
- Internal runtime subsystem: Non-negotiable kernel behavior that should not depend on model discretion (state transitions, memory lifecycle, safety checks).

## Decision Framework

Classify each capability with this order:
1. Is it safety-critical, required every turn, or part of deterministic kernel flow?
2. Does it require user/model discretion to decide when/how to run?
3. Can it be strictly typed, bounded, auditable, and policy-gated?

Rules:
- If answer to (1) is yes -> internal runtime subsystem.
- Else if (2) and (3) are yes -> tool call.
- Skills only express policy/workflow about when to use internal capability and tools.

## Capability Classification (Requested Areas)

| Capability | Default Classification | Why | Notes |
|---|---|---|---|
| Inter-canister calls | Tool calls (typed domain tools), not raw generic call | Caller/callee/method/cycles are high-impact and must be policy-gated/audited | Do not expose `call_canister(method,args)` to the model. Expose narrow tools (for example `send_outbox_message`, `fetch_peer_card`, `submit_signed_tx`). |
| Storage/retrieval of memory | Internal subsystem by default | Context loading and persistence are core runtime invariants | Optional explicit tools (`remember_fact`, `forget_fact`) only for user-visible memory intent; keep automatic memory indexing/retrieval internal. |
| HTTP calls | Tool calls for domain connectors; internal for provider plumbing | External I/O should be bounded and explicit | Inference-provider HTTP (OpenRouter adapter) is runtime plumbing, not a model-selectable tool. External business HTTP should be toolized per endpoint/domain class. |
| Web search | Tool call + skill policy | Querying current web state is discretionary and non-deterministic | Skill defines search policy (freshness/citation thresholds); tool performs execution and returns normalized results. |

## Tool vs Skill Contract

### Tool contract (must have)
- Stable `name` + semantic version.
- Strict JSON schema for args/result.
- Side-effect class: `ReadOnly` or `Mutating`.
- Idempotency contract and dedupe key strategy.
- Cycle/time budget envelope.
- Policy gates: enabled, allowed states, per-turn budget, approval requirement.
- Full execution record persisted (request summary, result, error, timing, cycle estimate).

### Skill contract (must have)
- Plain-language planning constraints and workflow guidance.
- Allowed/forbidden tool sets by name.
- Trigger heuristics (when to retrieve memory, when to web search, when to avoid expensive tools).
- Non-authoritative: cannot bypass tool policy or state machine rules.

## ICP Runtime Extension: What Is Actually Possible

### Constraint
New native Rust/Wasm tool executors are not hot-pluggable without Wasm upgrade. On ICP, code changes still require `install_code` and controller authority.

### What can be added at runtime without parent canister upgrade
1. New instances of precompiled generic tool adapters (recommended):
   - Example: add a new allowed HTTP connector entry or inter-canister endpoint entry from stable config.
   - Requires a declarative tool registry in stable memory.
2. New capabilities through an external tool-gateway canister:
   - Parent canister calls gateway via inter-canister API.
   - Gateway can evolve independently.
3. Skill changes:
   - Prompt/instruction/policy updates via stable `SkillRecord`.

### What still requires upgrade
- Any new executor logic not expressible by existing generic adapters.
- Any new safety-critical policy mechanism missing in current kernel.

## Recommended Architecture (KISS)

### 1) Introduce a persistent `ToolSpec` registry
- Store in stable memory.
- Include: `name`, `kind`, `version`, `arg_schema`, `result_schema`, `trust_class`, `budget`, `policy`, `routing`.
- Keep executor code compile-time, but bindings runtime-configurable.

### 2) Add `trust_class` to each tool
- `ConsensusRequired` for financially or governance-relevant reads/writes.
- `BestEffort` for non-deterministic or low-stakes retrieval (for example web search draft context).
- Tie this to replicated/non-replicated outcall policy and admission controls.

### 3) Split execution layers
- Planner layer: model + skills produces candidate tool calls.
- Policy layer: validates tool availability, schema, budget, approval, state constraints.
- Executor layer: performs tool execution and returns normalized result.
- Persistence layer: appends full audit record.

### 4) Keep memory lifecycle internal
- `LoadingContext` and `Persisting` remain runtime-owned.
- Optional memory tools are additive and narrow, not replacement for internal memory pipeline.

## Security and Reliability Guardrails

- Never expose generic raw inter-canister or raw HTTP tool surfaces to the model.
- Require per-tool and per-operation cycle admission checks.
- Add explicit allowlists:
  - inter-canister principals + methods
  - HTTP domains + paths
- Enforce result-size caps and timeout budgets.
- Keep tool execution side effects idempotent or compensatable.
- Require manual approval mode for high-risk tools (fund transfer, signing, upgrades).

## Proposed Data Model Changes

1. Add persistent tool registry (new stable map):
- `ToolSpecRecord { name, kind, version, enabled, mutable, policy_json, schema_json, routing_json }`

2. Extend tool call records:
- add `started_at_ns`, `finished_at_ns`, `latency_ms`, `estimated_cycles`, `trust_class`, `idempotency_key`.

3. Extend skill records:
- add `required_tools`, `forbidden_tools`, `priority`, `updated_at_ns`, `source`.

## What Is Missing Today

- No persistent tool registry or tool versioning.
- No schema validation for inferred `args_json` before execution.
- No explicit trust class attached to tool executions.
- No generic runtime path to add connector-style tools without code edits.
- No approval workflow for sensitive tools.
- No explicit coupling between skills and allowed tool subsets.

## Clarifications Needed (Before Implementation)

1. Should web search outputs ever be allowed to directly trigger mutating tools (sign/broadcast), or only inform drafts that need a second confirmation step?
2. Which operations require consensus-grade data (`replicated`) vs best-effort data (`non-replicated`)?
3. Who can create/modify tool specs and skills in production (controller only, governance, role-based principal list)?
4. Do you want one generic `http_connector` tool with strict allowlists, or one tool per domain capability?
5. Should memory writes from model-issued tools be immediately committed, or staged and reviewed by policy before commit?
6. Is an external tool-gateway canister acceptable for runtime extensibility, or must all capabilities remain single-canister?
7. Do you want backward-incompatible simplification now (given dev-phase tolerance), or staged migration with temporary compatibility shims?

## Implementation Order (Suggested)

1. Formalize classification policy and add `ToolSpecRecord` + migrations.
2. Add schema validation + trust class + richer tool execution records.
3. Refactor existing tools (`sign_message`, `broadcast_transaction`, `record_signal`) onto registry-backed dispatch.
4. Add first connector-style tool (for example `web_search`) under strict read-only policy.
5. Add skill-to-tool policy enforcement (`required_tools`/`forbidden_tools`).
6. Evaluate external tool-gateway canister for runtime extension beyond precompiled adapters.

## Research References

### External references
- ICP Rust inter-canister calls: https://internetcomputer.org/docs/building-apps/developer-tools/cdks/rust/intercanister
- ICP interface spec (`http_request`, management methods): https://internetcomputer.org/docs/references/ic-interface-spec
- ICP cycles formula for HTTPS outcalls: https://internetcomputer.org/docs/references/cycles-cost-formulas/#https-outcalls
- `ic-stable-structures` crate docs: https://docs.rs/ic-stable-structures/latest/ic_stable_structures/
- OpenAI tools/function calling guides: https://platform.openai.com/docs/guides/tools and https://platform.openai.com/docs/guides/function-calling
- OpenAI skills guide: https://platform.openai.com/docs/guides/skills
- Model Context Protocol tool specification: https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- Anthropic tool use overview: https://docs.anthropic.com/en/docs/agents-and-tools/tool-use/overview

### Codebase references
- `src/tools.rs`
- `src/features/skills.rs`
- `src/features/inference.rs`
- `src/agent.rs`
- `src/scheduler.rs`
- `src/storage/stable.rs`
- `src/domain/types.rs`
