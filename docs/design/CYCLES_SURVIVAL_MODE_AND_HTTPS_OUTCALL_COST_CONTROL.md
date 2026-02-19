# Cycles Survival Mode and HTTPS Outcall Cost Control

**Date:** 2026-02-19  
**Status:** Draft design for implementation planning  
**Scope:** Runtime behavior under low/insufficient cycles, scheduler policy, and HTTPS outcall cost efficiency

## Problem Statement

The canister currently re-enters inference while cycle balance is insufficient and faults repeatedly on scheduled turns.

Observed live errors:
- `openrouter http outcall failed: insufficient liquid cycles balance, available: 1756780967, required: 42838411000`
- This repeats on consecutive `AgentTurn` jobs while state stays `Faulted`.

Current behavior creates a failure loop:
1. `AgentTurn` runs on cadence.
2. Inference tries HTTPS outcall.
3. Outcall fails for insufficient liquid cycles.
4. Turn faults.
5. Next tick retries the same expensive action.

This violates the autonomy requirement that runtime should self-heal and continue safe scheduled operation without operator resets.

## Current Code Baseline (What Exists Today)

- Scheduler cadence:
  - `AgentTurn`: 30s (`src/domain/types.rs`)
  - `PollInbox`: 30s
  - `CheckCycles`: 60s
  - `Reconcile`: 300s
- `CheckCycles` dispatch is currently a no-op (`src/scheduler.rs`).
- Inference uses `ic_cdk::management_canister::http_request` with:
  - `is_replicated: Some(false)` (correct for LLM-style nondeterministic responses)
  - `max_response_bytes: Some(snapshot.openrouter_max_response_bytes)`
- Default OpenRouter `max_response_bytes`: `64 * 1024` (`src/domain/types.rs`).
- Low-cycles mode exists in scheduler runtime but is not driven by cycle-aware policy.

## Scope Correction: This Must Be Multi-Operation, Not Inference-Only

The immediate live failure is on inference, but your point is correct: the survival policy must cover *all* expensive operation classes.

Important distinction in the current codebase:
- Today, EVM polling and signing are still mock adapters (`MockEvmPoller`, `MockSignerAdapter`).
- So currently observed insufficient-cycles failures come from inference HTTPS outcalls.

However, roadmap/spec context already includes future expensive paths:
- EVM JSON-RPC polling (`eth_blockNumber`, `eth_getLogs`, receipt polling),
- threshold signing (`sign_with_ecdsa` / possibly schnorr),
- EVM transaction submission workflows (which combine signing + one or more outcalls).

Conclusion:
- The design should be generalized now as a cycle admission controller for operation classes, not a one-off inference fix.

## Deep Investigation: How Cycles Work and Why This Fails

## 1) Balance vs Liquid Balance vs Reserved Cycles

On IC, a canister can show a non-zero cycle balance while still being unable to spend cycles for an operation if liquid cycles are too low.

- `canister_balance128`: total cycles balance.
- `canister_liquid_cycle_balance128`: spendable cycles after reservations.
- Reserved cycles can grow under resource reservation and reduce liquid balance.

Implication:
- Guarding only on total balance is insufficient for outcall affordability.
- Survival policy must use liquid balance.

## 2) Outcall Cycles Are Determined Upfront From Request Size + Max Response Bytes

Per IC docs, HTTPS outcall cycles are computed from:
- subnet size,
- request size,
- `max_response_bytes`.

Formula (as documented in gas-cost docs):
- `base_fee = (3_000_000 + 60_000 * n) * n`
- `size_fee = (400 * request_bytes + 800 * max_response_bytes) * n`
- `total_fee = base_fee + size_fee`

Key consequence:
- `max_response_bytes` dominates cost.
- If omitted, the default cap is 2,000,000 bytes (2 MB), which can be very expensive.

## 3) Current Outcall Wiring Is Mostly Correct, But Missing Runtime Affordability Controls

What is correct:
- Uses high-level `ic_cdk::management_canister::http_request`.
- That API computes required cycles via `cost_http_request` and attaches payment automatically.
- Uses non-replicated mode for inference (`is_replicated: Some(false)`).
- Sets explicit `max_response_bytes` in request args.

What is missing:
- No preflight affordability check against liquid cycles before attempting outcall.
- No survival-mode downgrade on cycle insufficiency.
- No cost telemetry to verify expected vs actual reserved cycles per call.

## 3b) Cost Surfaces Beyond HTTPS Outcalls

Survival logic must account for multiple cost models:

| Operation class | Typical API | Cost model shape | Key implication |
|---|---|---|---|
| HTTPS outcall | `management_canister::http_request` | Size/subnet dependent (`request_bytes`, `max_response_bytes`, subnet `n`) | `max_response_bytes` dominates, must stay low and explicit |
| Threshold signing | `management_canister::sign_with_ecdsa` / `sign_with_schnorr` | Management canister sign fee (`cost_sign_with_*`) | Expensive, should be admission-gated and rate-limited |
| Inter-canister EVM helpers | `Call::with_cycles` style calls | Depends on callee protocol and attached cycles budget | Need explicit per-call cycles envelope and retry policy |
| EVM tx lifecycle | compose: estimate/fetch + sign + broadcast + poll | Multi-step cumulative cost | Admission must be workflow-aware, not only per-step |

Operational implication:
- A scheduler that only protects inference can still burn out on signing/EVM workflows.
- Need global budget arbitration by operation class and task priority.

## 4) Why Failures Repeat Every Cadence

Because cycle insufficiency is treated like a generic turn failure:
- runtime transitions to `Faulted`,
- then next timer tick from `Faulted` goes back into `LoadingContext` and tries inference again,
- with no cooldown/backoff/survival gating tied to cycles.

## Cost Sensitivity Analysis for `max_response_bytes`

Illustrative costs using the documented formula and ~1.6 KB request payload:

| Subnet size (`n`) | `max_response_bytes` | Estimated outcall cycles |
|---|---:|---:|
| 13 | 2,000,000 | 20,857,460,000 |
| 13 | 65,536 | 739,034,400 |
| 13 | 16,384 | 227,853,600 |
| 13 | 8,192 | 142,656,800 |
| 34 | 2,000,000 | 54,593,120,000 |
| 34 | 65,536 | 1,975,699,200 |
| 34 | 16,384 | 638,764,800 |
| 34 | 8,192 | 415,942,400 |

Takeaway:
- Moving from 64 KB to 16 KB can reduce estimated outcall cycles by roughly 3x.
- Falling back to the 2 MB default is catastrophic for recurring inference cadence.

## Approaches To Survival Mode (With Tradeoffs)

## Approach A: Periodic-Only Cycle Check (No Per-Request Guard)

### Design
- `CheckCycles` task runs occasionally (e.g., every 5 minutes).
- It toggles scheduler low-cycles mode.
- Inference path itself does no affordability preflight.

### Pros
- Simpler implementation.
- Reduces continuous balance polling overhead.

### Cons
- Still allows expensive attempts between checks.
- Can produce repeated failures if balance drops quickly.
- Slower reaction to sudden affordability loss.

### Verdict
- Better than today, but insufficient for robust autonomy.

## Approach B: Per-Request Guard Only (No Periodic Check)

### Design
- Before each outcall, compute `estimated_cost = cost_http_request(&req)`.
- Compare against `canister_liquid_cycle_balance128`.
- Skip outcall when unaffordable.

### Pros
- Immediate protection at decision point.
- Prevents "run into wall every tick" behavior.

### Cons
- No broad scheduler-level policy (e.g., task degradation).
- No predictive runway/health posture.
- Can still spam skipped-attempt logs without cooldown policy.

### Verdict
- Necessary building block, but not sufficient alone.

## Approach C (Recommended): Hybrid Survival Controller

### Design
Combine periodic cycle controller plus per-request outcall affordability guard.

1. Periodic `CheckCycles` (occasional):
- Run every 5 minutes (not every heartbeat).
- Evaluate liquid cycles against tier thresholds.
- Set survival tier and scheduler gating policy.

2. Event-driven fast path:
- If any outcall fails with insufficient liquid cycles, immediately mark low-cycles tier and start cooldown.
- Do not wait for next periodic check.

3. Per-request preflight:
- Compute `estimated_op_cycles` per operation class:
  - HTTPS: `cost_http_request(&req)`
  - Threshold signing: `cost_sign_with_ecdsa(&args)` / `cost_sign_with_schnorr(&args)`
  - Other inter-canister steps: configured envelope + observed history
- Require `liquid >= estimated_op_cycles + safety_margin + reserve_floor`.
- If not affordable: skip/defer operation as a controlled degraded outcome (not hard fault).

4. Backoff:
- Exponential cooldown for repeated unaffordable inference attempts.
- Keep lightweight jobs alive (e.g., cycles checks, inbox staging if cheap).
- Apply backoff per operation class (`inference`, `evm_poll`, `evm_broadcast`, `threshold_sign`), not one shared bucket.

### Pros
- Fast reaction + stable long-term control.
- Stops repeated hard failures.
- Supports "survival mode" explicitly.
- Keeps canister operational and observable.

### Cons
- More implementation complexity.
- Requires careful threshold tuning.

### Verdict
- Best fit for autonomy and cost safety.

## Recommended Survival Policy

Introduce explicit runtime survival tiers:
- `Normal`
- `LowCycles`
- `CriticalCycles`
- `OutOfCycles` (optional terminal posture)

Suggested behavior:

### Normal
- Standard schedule.
- Inference enabled.

### LowCycles
- Disable expensive optional tasks.
- Allow inference only when preflight affordability passes.
- Increase inference backoff interval.

### CriticalCycles
- Disable all non-essential expensive operations (inference + signing + EVM outcalls).
- Keep only essential control-plane tasks:
  - `CheckCycles`
  - minimal observability and operator endpoints
- Avoid any recurring expensive outcall path.

### Recovery
- Exit low/critical tiers only after N consecutive healthy checks (hysteresis).
- Prevent mode flapping.

## "Only Check Balance Occasionally" Without Repeating Failures

Use this combined policy:
- Scheduled `CheckCycles` every 5 minutes (occasional).
- No frequent "global balance checks" in heartbeat path.
- But keep per-operation preflight affordability checks only when an expensive operation is actually attempted.

This satisfies both goals:
- no constant heartbeat-level balance polling,
- no repeated unaffordable expensive operations (inference, signing, EVM calls).

## HTTPS Outcalls: Correctness and Savings Investigation

## Are we doing HTTPS outcalls correctly?

Mostly yes:
- Correct API: `ic_cdk::management_canister::http_request`.
- Correct trust mode for inference: non-replicated (`is_replicated: Some(false)`).
- Explicit response cap present.

Improvements still needed:
- enforce affordability preflight before call,
- enforce lower `max_response_bytes` defaults for inference,
- add outcall cost telemetry.

## Ways to reduce outcall cycles materially

1. Lower `max_response_bytes` default for inference
- Candidate: from `64KB` to `16KB`.
- Add fallback escalation path:
  - If response limit exceeded/parsing fails due truncation, retry once with `32KB`.

2. Bound model output size explicitly
- Add provider params (e.g., `max_tokens`) so responses stay within low caps.
- This makes smaller `max_response_bytes` safe operationally.

3. Reduce request payload size
- Keep tool schema concise.
- Include only tools relevant for current turn when possible.
- Request bytes are cheaper than response bytes but still contribute.

4. Add runtime assertion/telemetry
- Log request size, `max_response_bytes`, computed `cost_http_request`, liquid cycles.
- Detect unexpected 2MB-default behavior immediately.

5. Keep replicated outcalls only for consensus-critical data
- Inference: non-replicated (already correct).
- Financial/oracle integrity paths: replicated + transform.

## Proposed Implementation Plan (High Level)

## Phase 1: Guardrails + Observability (low risk)
- Implement outcall affordability preflight.
- Add structured logs/metrics for cost inputs and liquid balance.
- Classify "insufficient liquid cycles" as controlled degraded status, not hard-fault loop.

## Phase 2: Survival Mode Controller
- Implement `CheckCycles` logic (currently no-op).
- Add survival tiers and scheduler gating.
- Add hysteresis and backoff.

## Phase 3: Multi-Operation Admission Controller
- Introduce operation classes and per-class admission checks:
  - `InferenceHttpOutcall`
  - `EvmRpcOutcall`
  - `ThresholdSign`
  - `EvmTxWorkflow`
- Add per-class cooldown/backoff and counters.
- Add task-level policy mapping (`TaskKind` -> allowed operation classes by survival tier).

## Phase 4: Outcall Cost Tuning
- Reduce default `max_response_bytes`.
- Add bounded response sizing controls in provider request.
- Add fallback retry with larger cap only when necessary.

## Tradeoff Summary

| Decision | Benefit | Cost/Risk |
|---|---|---|
| Hybrid survival controller | Stops repeated failures and preserves autonomy | More state/policy complexity |
| Global admission controller (all expensive ops) | Prevents cost-shift regressions from new features | Larger surface area and tuning complexity |
| Lower `max_response_bytes` | Large cycle savings | Risk of truncation unless outputs are bounded |
| Per-request affordability preflight | Prevents unaffordable calls | Requires threshold and margin tuning |
| 5-minute periodic cycle checks | Lower scheduler overhead/noise | Coarser visibility without event-triggered updates |
| Hysteresis on recovery | Prevents flapping | Slower return to full throughput |

## Recommended Defaults

- `CheckCycles` interval: `300s`.
- Inference default `max_response_bytes`: `16KB`.
- Inference affordability margin:
  - `required = cost_http_request(req) + safety_margin`.
  - `safety_margin` initial: `25%` of computed cost (tune via telemetry).
- Recovery hysteresis: 3 consecutive healthy checks.
- Critical mode inference cooldown: at least 10 minutes between affordability probes.

## Open Questions Before Implementation

1. In low-cycles mode, should `AgentTurn` continue local-only work (no inference) or be skipped entirely?
2. Should `PollInbox` remain active in critical mode (queue growth tradeoff)?
3. Should top-up automation via CMC be in this phase or deferred?
4. What SLO for recovery time is acceptable after top-up?
5. How should limited liquid cycles be allocated between `ThresholdSign` and `EvmRpcOutcall` when both are pending?
6. Which operations are strictly essential vs deferrable under `CriticalCycles`?

## References

- IC gas-cost formula for HTTPS outcalls:  
  https://internetcomputer.org/docs/references/cycles-cost-formulas/
- IC HTTPS outcalls cycles-cost guidance:  
  https://internetcomputer.org/docs/current/developer-docs/gas-cost#https-outcalls
- IC interface spec (`http_request`, `max_response_bytes`, `is_replicated`):  
  https://internetcomputer.org/docs/references/ic-interface-spec#ic-http_request
- IC resource reservation and liquid cycles concepts:  
  https://internetcomputer.org/docs/building-apps/canister-management/resource-limits
- `ic-cdk` management canister API docs (`http_request`, `cost_http_request`):  
  https://docs.rs/ic-cdk/latest/ic_cdk/management_canister/fn.http_request.html  
  https://docs.rs/ic-cdk/latest/ic_cdk/management_canister/fn.cost_http_request.html
- `ic-cdk` management canister API docs (`sign_with_ecdsa`, `cost_sign_with_ecdsa`):  
  https://docs.rs/ic-cdk/latest/ic_cdk/management_canister/fn.sign_with_ecdsa.html  
  https://docs.rs/ic-cdk/latest/ic_cdk/management_canister/fn.cost_sign_with_ecdsa.html
- `ic-cdk` canister balance APIs (`canister_balance128`, `canister_liquid_cycle_balance128`):  
  https://docs.rs/ic-cdk/latest/ic_cdk/api/fn.canister_balance128.html  
  https://docs.rs/ic-cdk/latest/ic_cdk/api/fn.canister_liquid_cycle_balance128.html
- Threshold signature fee formulas:  
  https://internetcomputer.org/docs/references/cycles-cost-formulas/#threshold-signature-fees
