# Design Doc: Autonomous OpenRouter Inference Payments via Base USDC

**Status:** Proposed  
**Date:** 2026-02-23  
**Author:** Codex

---

## 1. Goal

Enable the canister to autonomously keep OpenRouter credits funded by paying from its Base wallet in USDC, without human intervention, while preserving the project's survival priorities:

1. Protect canister cycles first.
2. Keep inference operational when credits run low.
3. Self-heal from transient API, RPC, and settlement failures.

---

## 2. Verified External Facts (as of 2026-02-23)

1. OpenRouter supports Coinbase charge creation at `POST /api/v1/credits/coinbase`.
   - Request fields include `amount` (double), optional `sender`, optional `chain_id`.
   - Supported chain IDs include `1`, `137`, and `8453` (Base).
   - Source: https://openrouter.ai/docs/api/api-reference/credits/create-coinbase-charge

2. Charge response includes EVM payment data:
   - `web3_data.transfer_intent.metadata` includes `contract_address`, `chain_id`, `sender`, `recipient`, `expires_at`.
   - `web3_data.call_data` includes fields needed for onchain execution (`transfer_amount`, `recipient_amount`, `fee_amount`, `signature`, `prefix`, `suffix`, `id`, `operator`, etc).
   - Source: https://openrouter.ai/docs/api/api-reference/credits/create-coinbase-charge

3. OpenRouter's crypto guide explicitly supports Base and provides ABI snippets for payment-intent execution, including `transferTokenPreApproved(...)` for token payments.
   - Source: https://openrouter.ai/docs/guides/guides/crypto-api

4. OpenRouter provides two useful credit-observation surfaces:
   - `GET /api/v1/credits` returns account `total_credits` and `total_usage` (docs say management key required).
   - `GET /api/v1/key` returns key-level usage/limits (`usage`, `limit`, `limit_remaining`, etc).
   - Sources:
     - https://openrouter.ai/docs/api/api-reference/credits/get-credits
     - https://openrouter.ai/docs/api-reference/limits

5. OpenRouter signals insufficient credits with HTTP `402`.
   - Source: https://openrouter.ai/docs/api-reference/limits

Inference from docs: there is no clearly documented "charge status by id" endpoint in OpenRouter API reference today; verification should therefore use credit deltas plus transaction confirmation.

---

## 3. Current Codebase Baseline

The repository already has most primitives needed:

1. OpenRouter inference adapter with non-replicated HTTPS outcalls and survival-aware cycle checks.
   - `src/features/inference.rs`

2. Runtime-managed Base wallet telemetry (ETH + USDC) with freshness and bootstrap gating.
   - `src/scheduler.rs` (`maybe_sync_wallet_balances`)
   - `src/storage/stable.rs`
   - `src/domain/types.rs`

3. Robust autonomous multi-step top-up pattern with persisted stage machine + scheduler dedupe/recovery.
   - `src/features/cycle_topup/mod.rs`
   - `src/features/cycle_topup_host.rs`
   - `src/scheduler.rs`

4. Reusable Base EIP-1559 signing/broadcast flow for contract calls.
   - `src/features/evm.rs` (`send_eth_tool`)
   - `src/features/cycle_topup/mod.rs` (`evm_send_transaction`)

Conclusion: this should be implemented as a sibling state machine to cycle top-up, not a one-shot tool call.

---

## 4. Design Summary

Implement a new autonomous subsystem: `inference_payment_topup`.

1. Observe credits from OpenRouter (`/api/v1/key` by default; `/credits` optionally when management key exists).
2. Trigger top-up when credits fall below threshold.
3. Create Coinbase charge on Base (`chain_id=8453`, sender=automaton EVM address).
4. Execute payment-intent transaction from automaton wallet in USDC (approve if needed, then `transferTokenPreApproved`).
5. Verify success via Base tx confirmation plus OpenRouter credit delta.
6. Recover automatically on transient failures with backoff and dedupe singleton jobs.

This keeps inference funded without manual actions and follows the same autonomy pattern already used for cycles.

---

## 5. Proposed Architecture

### 5.1 New Module

Add `src/features/inference_payment_topup/` with a portable state machine shape similar to `cycle_topup`:

- `OpenRouterPort` trait:
  - `create_coinbase_charge(...)`
  - `get_key_limits(...)`
  - `get_account_credits(...)` (optional path)
- `EvmPort` trait:
  - query nonce/gas/allowance
  - sign + broadcast contract tx
- `StoragePort` trait:
  - load/save/clear payment stage

### 5.2 Scheduler Integration

Add new task kind:

- `TaskKind::TopUpInferenceCredits` (essential, default disabled, singleton dedupe key).

Triggering model:

1. `run_check_cycles` (or a narrow helper called from it) evaluates whether credits are low.
2. If low and no active flow, start top-up stage and enqueue one `TopUpInferenceCredits` job.
3. `TopUpInferenceCredits` advances state every scheduler opportunity until terminal state.

### 5.3 Reactive Fallback in Inference Path

When OpenRouter chat completion returns HTTP `402`:

1. Treat as "inference deferred due to provider credits", not a hard-faulting deterministic error.
2. Mark credit snapshot low/depleted.
3. Enqueue singleton `TopUpInferenceCredits` job.

This prevents repeated fault loops when credits are exhausted.

---

## 6. State Machine

`InferencePaymentStage` (persisted):

1. `Preflight`
2. `CreatingCharge { requested_usdc_raw }`
3. `ApprovingSpender { charge_id, contract, amount_raw }`
4. `PayingCharge { charge_id, tx_hash }`
5. `WaitingPaymentConfirmation { charge_id, tx_hash, confirmations }`
6. `VerifyingCredits { charge_id, expected_min_delta_usd_micros, polls }`
7. `Completed { charge_id, tx_hash, funded_usdc_raw, completed_at_ns }`
8. `Failed { stage, error, failed_at_ns, attempts }`

Stage rules:

1. Never submit payment if charge is near expiration.
2. Never spend below cycle-topup reserve budget.
3. Never run when survival tier is `Critical` or `OutOfCycles`.
4. Auto-recover failed stages after cooldown (same posture as cycle top-up recovery).

---

## 7. Runtime Data Model

Add to `RuntimeSnapshot`:

1. `inference_payment: InferencePaymentConfig`
2. `openrouter_credit_snapshot: OpenRouterCreditSnapshot`
3. `openrouter_billing_api_key: Option<String>` (optional separate secret; fallback to inference key if absent)

Suggested config fields:

- `enabled: bool` (default `true`)
- `chain_id: u64` (default `8453`)
- `low_credit_threshold_usd_micros: u64` (default `2_000_000`)
- `target_credit_balance_usd_micros: u64` (default `10_000_000`)
- `min_topup_usd_micros: u64` (default `1_000_000`)
- `max_topup_usdc_raw: u64` (default `25_000_000`)
- `min_eth_gas_reserve_wei: u128`
- `credit_check_interval_secs: u64`
- `credit_verify_max_polls: u8`
- `failure_backoff_secs: u64`
- `use_management_credits_endpoint: bool` (default `false`)

Credit snapshot:

- `last_checked_at_ns`
- `source` (`KeyLimits` or `AccountCredits`)
- `estimated_available_usd_micros`
- `last_error`
- `stale`

All secret fields must remain excluded from query and HTTP safe views.

---

## 8. Payment Execution Details (USDC on Base)

### 8.1 Charge Creation

Call OpenRouter:

- `POST /api/v1/credits/coinbase`
- Body:
  - `amount`: requested USD amount
  - `sender`: automaton EVM address
  - `chain_id`: `8453`

### 8.2 Intent Validation Before Spending

Validate all critical fields from response:

1. `metadata.chain_id == 8453`
2. `metadata.sender` equals automaton EVM address
3. `metadata.expires_at` sufficiently in future
4. `metadata.contract_address` is valid address
5. `call_data.transfer_amount` does not exceed configured caps/budget

Reject otherwise.

### 8.3 USDC Approval + Settlement

1. Read USDC allowance `allowance(owner, contract_address)`.
2. If allowance < `transfer_amount`, send `approve(contract_address, transfer_amount)` tx.
3. Send payment tx to `metadata.contract_address` calling `transferTokenPreApproved(...)` with OpenRouter-provided `call_data`.
4. Wait for receipt confirmations.

Use existing internal EIP-1559 + threshold signing pattern (same as cycle top-up/send_eth flow).

### 8.4 Success Verification

After tx confirmation, poll credit source:

1. `/api/v1/key` (limit_remaining delta), or
2. `/api/v1/credits` (`total_credits - total_usage` delta),

until credited or timeout. If timeout, fail with backoff (no manual reset required).

---

## 9. Treasury and Priority Policy

USDC spending order must preserve canister survival:

1. Reserve budget for cycles top-up first (`cycle_topup.min_usdc_reserve` and policy floor).
2. Inference credit top-up can only spend surplus above that reserve.
3. If both top-up flows are eligible, prioritize cycles top-up.

This matches project goals: agent existence first, inference continuity second.

---

## 10. Failure Handling and Self-Healing

Failure policy:

1. OpenRouter 5xx/timeout/transport: retry with exponential backoff.
2. OpenRouter 401/403: deterministic config fault (disable feature until config fixed).
3. OpenRouter 402 in inference path: defer inference + enqueue funding flow.
4. EVM revert due allowance: run approve stage then retry payment.
5. Charge expiration: recreate charge.
6. Credit verify timeout after confirmed tx: retry verification; avoid duplicate spending until charge state resolved/expired.

Operational guardrails:

1. Singleton dedupe key for funding job.
2. Persist charge ID + tx hash to avoid duplicate payment attempts.
3. Structured canlog events at each transition with redacted secrets.

---

## 11. Security Considerations

1. Key separation:
   - Keep inference key and billing key distinct where possible.
   - Never expose keys in query/http/logs.

2. Domain pinning:
   - Billing outcalls should pin to OpenRouter base URL/domain policy.

3. Intent authenticity:
   - Execute only the returned payment-intent contract address and validated chain/sender fields.

4. Amount safety:
   - Hard cap per top-up and per-day budget (optional second-phase guard).

5. Time safety:
   - Reject intents close to deadline to reduce stuck funds/expiry races.

---

## 12. Implementation Plan (Repo-Concrete)

### 12.1 Files to Add

1. `src/features/inference_payment_topup/mod.rs`
2. `src/features/inference_payment_topup_host.rs`

### 12.2 Files to Modify

1. `src/domain/types.rs`
   - new config/state structs
   - `TaskKind::TopUpInferenceCredits`
2. `src/storage/stable.rs`
   - persistence + validation + safe view helpers
3. `src/scheduler.rs`
   - trigger logic + dispatch + failed-state recovery
4. `src/features/inference.rs`
   - map HTTP 402 to deferred outcome and enqueue funding job
5. `src/lib.rs`
   - update/query methods for non-secret config and status
6. `src/http.rs`
   - optional safe HTTP views for funding telemetry/config

---

## 13. Testing Strategy

Unit tests:

1. Charge response parsing and strict validation.
2. Allowance/approve/payment stage transitions.
3. 402 classification and deferred inference behavior.
4. Recovery/backoff and singleton dedupe behavior.

Integration (PocketIC + mocked outcall surfaces):

1. Low-credit signal triggers autonomous funding flow.
2. Confirmed Base payment leads to recovered credits snapshot.
3. Transient OpenRouter/API/EVM failures self-heal without manual reset.
4. Cycles top-up reserve is respected when inference funding is requested.

Regression:

1. Existing cycle top-up and wallet-balance sync tests remain green.
2. Existing OpenRouter inference tests remain green with new 402 behavior.

---

## 14. Rollout Plan

Phase 1 (low risk):

1. Credit telemetry + 402 reactive defer/enqueue semantics.
2. No autonomous payment yet (observe only).

Phase 2 (autonomous funding):

1. Enable charge creation + USDC settlement state machine.
2. Enable singleton scheduler task in staging/local first.

Phase 3 (hardening):

1. Daily spend caps.
2. Optional contract allowlist controls.
3. Richer observability and alert counters.

---

## 15. Open Questions

1. Which key type should be mandated for production funding (`/key` only vs management-key `/credits` support)?
2. Do we require strict allowlisting of payment-intent contract addresses, or trust dynamic `metadata.contract_address` with signature validation only?
3. Should inference be fully paused while top-up is in progress when credits are below hard minimum, or continue until 402?

