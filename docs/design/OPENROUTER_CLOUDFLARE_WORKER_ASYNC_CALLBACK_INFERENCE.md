# Design Doc: Third Inference Method via Cloudflare Worker Async Callback

**Status:** Proposed  
**Date:** 2026-02-24  
**Author:** Codex

---

## 1. Goal

Add a third inference method that avoids ICP HTTPS outcall timeout limits for long-running model calls by introducing an async proxy layer:

1. Canister sends a short request to a Cloudflare Worker.
2. Worker calls OpenRouter and waits for completion off-chain.
3. Worker calls back into the canister using `ic-agent`.
4. Initial outcall response stays very small to reduce cycle cost.

This must preserve core project priorities:
- canister survival first,
- autonomous self-healing,
- no manual resets for transient failures.

---

## 2. Problem Statement

Current OpenRouter inference runs inside a single ICP HTTPS outcall. This is bounded by replica-side timeout behavior and can fail for longer completions.

When inference duration exceeds that bound, turns are deferred/retried and can degrade autonomy quality.

We need an asynchronous transport where the IC outcall only submits work and returns quickly, while completion is delivered later through a callback.

---

## 3. Scope

### In scope

- New inference provider path: `OpenRouterProxyWorker` (third method).
- Cloudflare Worker proxy API for job submission and callback.
- Callback update method on canister, invoked via `ic-agent`.
- Multi-automata support in the same worker deployment.
- Tight response-size controls on the initial HTTPS outcall.
- Durable, idempotent, retry-safe job/result handling.

### Out of scope

- Replacing existing `IcLlm` or direct `OpenRouter` providers.
- Streaming token delivery into canister.
- Building a full operator dashboard for worker tenancy.

---

## 4. Design Summary

### 4.1 High-level flow

1. `AgentTurn` reaches inference step with provider `OpenRouterProxyWorker`.
2. Canister POSTs to worker `/v1/inference/jobs` with request payload and auth metadata.
3. Worker responds `202 Accepted` with tiny body (`job_id`, `accepted_at`, maybe `eta_hint`).
4. Canister persists `PendingInferenceJob` and marks turn as deferred (not faulted).
5. Worker executes long OpenRouter call.
6. Worker calls canister update `submit_inference_result(...)` using `ic-agent`.
7. Canister validates/authenticates callback, stores result idempotently, enqueues resume job.
8. Scheduler resumes deferred turn and continues tool execution/persistence.

### 4.2 Why this solves timeout + cycles

- Long latency is moved off ICP outcall path.
- The only HTTPS outcall response is a compact acceptance envelope.
- `max_response_bytes` for submission outcall can be aggressively small (default target: `512`).

---

## 5. Multi-Automata Worker Model

A single worker serves multiple automata (tenants), keyed by canister principal text.

### 5.1 Tenant record

Worker-side tenant config should include:

- `canister_id`
- `ic_network_url` (`https://icp-api.io` or env-specific)
- `callback_method` (default `submit_inference_result`)
- `callback_identity` reference (worker key material)
- OpenRouter credentials/model policy for that automaton

### 5.2 Isolation requirements

- Per-tenant principal allowlist and rate limits.
- Per-tenant queue partitioning (or durable-object key partitioning).
- No cross-tenant read/write path for jobs or results.

---

## 6. Canister-Side Architecture Changes

### 6.1 Types

Add provider and proxy config/state:

- `InferenceProvider::OpenRouterProxyWorker`
- `InferenceProxyConfig`
  - `enabled: bool`
  - `worker_base_url: String`
  - `worker_api_key: Option<String>`
  - `submit_max_response_bytes: u64` (default `512`)
  - `submit_timeout_secs: u64`
  - `max_pending_jobs: u32`
  - `pending_job_ttl_secs: u64`
- `PendingInferenceJob`
  - `job_id`
  - `turn_id`
  - `requested_at_ns`
  - `status` (`Submitted|Completed|Failed|Expired`)
- `CompletedInferenceResult`
  - normalized `InferenceOutput` payload
  - metadata (`provider_latency_ms`, token usage if available)

### 6.2 New update methods

- `submit_inference_result(args)`
  - called by worker via `ic-agent`
  - validates auth, idempotency, schema, and size bounds
  - persists result and triggers resume scheduling

Optional admin/runtime methods:

- `set_inference_proxy_config(...)`
- `get_inference_proxy_status()` (safe view only; no secrets)

### 6.3 Scheduler behavior

- New task kind: `ResumeDeferredInference`.
- Submission path defers turn intentionally instead of faulting.
- Timeout sweeper marks stale pending jobs and applies survival backoff.

### 6.4 Autonomy and self-healing

- Duplicate callbacks are safe (idempotent by `job_id`).
- Missing callback triggers retry policy and eventual expiration handling.
- Expired jobs do not wedge scheduler; turn is marked deferred-failed and loop continues.

---

## 7. Worker-Side Architecture

### 7.1 API surface

- `POST /v1/inference/jobs`
  - validates tenant identity (`canister_id`) and optional service token
  - stores job and schedules async execution
  - returns compact ack payload only

### 7.2 Execution pipeline

1. Deserialize request and resolve tenant policy.
2. Call OpenRouter with long timeout profile.
3. Normalize response to canister callback schema.
4. Call canister update using `ic-agent`.
5. Retry callback on transient network/replica failures.
6. Dead-letter after max retries for operator visibility.

### 7.3 Callback using `ic-agent`

Use Rust worker implementation (workers-rs) so callback client uses:
- `ic-agent` crate: https://docs.rs/ic-agent/latest/ic_agent/

Required callback call properties:
- bounded ingress expiry,
- nonce/replay resistance,
- explicit wait/poll until update finalization,
- structured error classification for retries.

---

## 8. Security Model

### 8.1 Submit authentication (canister -> worker)

- `canister_id` is mandatory in every submit request and must match a configured tenant.
- Optional global service token (`Authorization: Bearer ...`) via `worker_api_key`.
- Worker enforces strict request size/rate limits per tenant to prevent abuse.

### 8.2 Callback authentication (worker -> canister)

- Principal-only trust policy: caller principal must be allowlisted for the target automaton.
- Idempotency key: `job_id`.

### 8.3 Validation constraints

- Max callback payload size bound.
- Strict JSON schema for tool calls and arguments.
- Reject mismatched `turn_id`, unknown `job_id`, or expired job.

---

## 9. Cost and Performance Controls

### 9.1 IC outcall cost controls

- Submission outcall response is intentionally tiny.
- Set `submit_max_response_bytes` low (target `512`, upper bound configurable).
- Ack schema should stay under ~200 bytes in normal path.

### 9.2 Prompt and payload controls

- Keep submit request body compact (same existing prompt budget controls apply).
- Strip non-essential fields from worker ack.
- Return full inference only via callback update, not outcall response.

---

## 10. Failure Policy

1. Worker submit outcall transient failure:
- classify as deferred inference failure,
- apply inference survival backoff,
- retry next turn opportunity.

2. OpenRouter transient failure inside worker:
- worker retries with exponential backoff,
- callback only when terminal status known.

3. Callback transient failure:
- worker retries callback idempotently.

4. Callback permanent rejection (auth/schema):
- mark job failed,
- canlog error with redacted metadata,
- avoid infinite retry loops.

5. Pending job timeout:
- canister marks job expired,
- unblocks turn lifecycle and schedules fresh inference when policy allows.

---

## 11. Observability

Add structured canlog events:

- `inference_proxy_submit_dispatched`
- `inference_proxy_submit_accepted`
- `inference_proxy_callback_accepted`
- `inference_proxy_callback_duplicate`
- `inference_proxy_job_expired`
- `inference_proxy_resume_scheduled`

Expose safe telemetry:

- pending job count,
- age of oldest pending job,
- callback success/failure counts,
- median end-to-end proxy latency.

---

## 12. Proposed Implementation Touchpoints

- `src/domain/types.rs`
  - provider enum + proxy config/state structs
- `src/features/inference.rs`
  - third provider adapter and submit path
- `src/storage/stable.rs`
  - pending/completed proxy job persistence + idempotency index
- `src/scheduler.rs`
  - resume/timeout tasks and job orchestration
- `src/lib.rs`
  - callback update method + config entrypoints
- `src/http.rs`
  - safe config/status exposure
- `tests/`
  - unit + PocketIC coverage for defer/resume/idempotency/failure recovery

---

## 13. Testing Strategy

### Unit

- provider selection routes to proxy adapter.
- submit ack parser enforces compact schema.
- callback auth/idempotency/size validation.
- timeout expiry and resume orchestration.

### Integration (PocketIC)

- deferred turn resumes after callback and completes tool phase.
- duplicate callback does not double-apply.
- missing callback expires safely and loop remains healthy.
- low-cycles mode still gates expensive submission attempts.

---

## 14. Decisions and Follow-up

### 14.1 Locked decisions

1. Worker runtime: Rust workers-rs + `ic-agent`.
2. Callback trust policy: principal-only (allowlisted caller principal).
3. Tenant secret storage: no per-tenant callback secrets required under principal-only callback trust.

### 14.2 Follow-up

1. Deferred-turn retention policy:
- finalize maximum pending lifetime before forced abandon/recompute.

---

## 15. References

- `ic-agent` crate docs: https://docs.rs/ic-agent/latest/ic_agent/
- Existing provider abstraction: `src/features/inference.rs`
- Existing runtime snapshot/config model: `src/domain/types.rs`
- Existing scheduler/job orchestration: `src/scheduler.rs`
