# Spec: Autonomous Wallet Balance Awareness (Cycles + ETH + USDC) with Cost-Bounded Freshness

**Status:** LOCKED
**Date:** 2026-02-21
**Author:** Codex (spec-writer) | Mode: interactive
**Complexity:** complex
**Authority:** approval
**Tier:** 3

---

## Problem
The agent currently knows cycles directly but only knows ETH balance when it happens to call `evm_read` itself, and it has no first-class USDC balance snapshot path. This makes solvency awareness incomplete and tool-call dependent.

That violates the autonomy goal: the runtime should proactively maintain balance awareness (cycles, ETH, USDC) and provide freshness metadata without requiring the model to spend tool calls for basic state introspection.

There is also a startup gap: after `init`/`post_upgrade`, the first inference can run before ETH/USDC balances are fetched, so the first economic decisions may start from unknown external-wallet state.

## Goal
Implement runtime-managed balance telemetry so the agent always receives:
1. Current cycles telemetry (already present),
2. Cached ETH + USDC balances for its configured EVM wallet,
3. Explicit freshness metadata (last sync time, age, stale/fresh status, last sync error),
4. Cost-aware sync cadence that adapts to survival tier.

Measurable success:
1. Layer-10 dynamic context includes cycles + ETH + USDC + freshness on every turn.
2. ETH/USDC balance sync occurs automatically on a configured schedule, without model tool calls.
3. Sync frequency is bounded and survival-aware, with no repeated hard-failure loops on RPC issues.
4. After `init`/`post_upgrade`, first inference does not run until at least one successful ETH+USDC snapshot has been persisted.

## Non-Goals
- Multi-chain balance support.
- Portfolio valuation/pricing conversion (USD mark-to-market).
- Replacing the existing `evm_read` tool (it remains for ad hoc reads).
- Introducing the EVM RPC canister or consensus-read architecture in this slice.

---

## Autonomous Decisions
- Reuse existing scheduler lanes and `PollInbox` execution path for balance sync gating rather than adding a new scheduler lane.
- Add typed runtime balance snapshot state instead of relying only on `MemoryFact` keys.
- Keep USDC token address resolution hybrid: explicit config override + optional one-time discovery from `Inbox.usdc()`.
- Add an explicit bootstrap barrier so inference is blocked until initial wallet snapshot is successful.
- Default to conservative sync cadence: 5 minutes in `Normal`, 15 minutes in `LowCycles`, disabled in `Critical`/`OutOfCycles`.

---

## Alternatives Considered

### Alternative A: LLM-driven on-demand tool reads only (status quo)
- Description: Agent calls `evm_read` (`eth_getBalance`/`eth_call`) when it decides to.
- Pros:
  - No new runtime machinery.
  - Zero background cost.
- Cons:
  - Balance awareness is missing/stale unless model remembers to ask.
  - Freshness is not guaranteed before economic decisions.
  - Consumes tool budget and inference tokens for baseline telemetry.
- Verdict: Reject.

### Alternative B: Force refresh every `AgentTurn`
- Description: Always refresh ETH+USDC immediately before inference.
- Pros:
  - Best freshness (<= one turn).
  - Simple mental model.
- Cons:
  - High recurring cycle cost at 30s cadence.
  - Increased turn latency and larger failure surface in the hottest path.
- Cost profile (approx, non-replicated size assumptions):
  - One ETH + one USDC call snapshot ~= 106M cycles.
  - At 30s cadence: ~316.8B cycles/day.
- Verdict: Reject as default policy (too expensive for survival posture).

### Alternative C: Dedicated new `TaskKind::SyncBalances`
- Description: Add a new scheduled task solely for wallet balance sync.
- Pros:
  - Clean isolation of concerns and tunable interval.
  - Easy observability for sync-specific runtime.
- Cons:
  - Adds scheduler/task-kind complexity and extra persistent runtime state.
  - More moving parts for lease/backoff behavior.
- Verdict: Viable, but unnecessary complexity for current architecture.

### Alternative D (Recommended): Cost-bounded sync integrated into `PollInbox` with independent due-window
- Description: Keep existing scheduler shape; inside `run_poll_inbox_job`, run `maybe_sync_wallet_balances` when due.
- Pros:
  - Reuses existing survival operation gating and backoff discipline.
  - No new task kind; minimal architecture expansion.
  - Decouples sync interval from turn frequency.
- Cons:
  - `PollInbox` job handles one more concern (must keep function boundaries clean).
- Verdict: Recommended.

---

## Recommended Design

### 1) Introduce first-class wallet balance snapshot state
Add typed runtime telemetry for wallet balances:
- `eth_balance_wei_hex: Option<String>`
- `usdc_balance_raw_hex: Option<String>`
- `usdc_decimals: u8` (default `6`)
- `usdc_contract_address: Option<String>`
- `last_synced_at_ns: Option<u64>`
- `last_synced_block: Option<u64>`
- `last_error: Option<String>`

Derived freshness fields for context/view:
- `age_secs`
- `freshness_window_secs`
- `is_stale`
- `status` (`Unknown | Fresh | Stale | Error`)

### 2) Add runtime sync policy config
Add `WalletBalanceSyncConfig` to runtime:
- `enabled: bool` (default `true`)
- `normal_interval_secs: u64` (default `300`)
- `low_cycles_interval_secs: u64` (default `900`)
- `freshness_window_secs: u64` (default `600`)
- `max_response_bytes: u64` (default `256`, bounded)
- `discover_usdc_via_inbox: bool` (default `true`)

Policy by survival tier:
- `Normal`: use `normal_interval_secs`.
- `LowCycles`: use `low_cycles_interval_secs`.
- `Critical` / `OutOfCycles`: skip sync.

### 3) Bootstrap gate before first inference
Add bootstrap runtime flag:
- `wallet_balance_bootstrap_pending: bool` (set `true` on `init` and `post_upgrade`).
- Set to `false` only after one successful ETH+USDC sync.

Enforcement:
- `run_scheduled_turn_job` must skip inference when `wallet_balance_bootstrap_pending == true`.
- `PollInbox` keeps attempting balance sync while bootstrap is pending (ignore normal due-window until first success, but still respect survival operation gating/backoff).
- External inbox messages may stage during bootstrap, but no inference/action execution starts until bootstrap is cleared.

### 4) Internal (non-tool) balance sync flow
Inside `run_poll_inbox_job(now_ns)`:
1. Perform existing inbox poll path.
2. Call `maybe_sync_wallet_balances(now_ns, &snapshot)`:
   - Return early if disabled/missing wallet address.
   - Enforce due-window only after bootstrap has completed.
   - Resolve USDC contract:
     - use configured `usdc_contract_address` if set,
     - else if enabled and `inbox_contract_address` exists, call `Inbox.usdc()` once and cache.
   - Fetch ETH via `eth_getBalance(wallet, latest)`.
   - Fetch USDC via `eth_call(balanceOf(wallet))`.
   - Update snapshot and freshness timestamps.
   - If bootstrap was pending and sync succeeds, clear bootstrap flag.
   - On sync failure: keep prior balances, set `last_error`, do not fail `PollInbox` job.

### 5) Agent prompt context wiring
Replace current ETH-only memory-fact dependency with snapshot-backed fields:
- `eth_balance`, `usdc_balance`, `wallet_balance_last_synced_at_ns`,
- `wallet_balance_age_secs`, `wallet_balance_freshness_window_secs`,
- `wallet_balance_is_stale`, `wallet_balance_status`, `wallet_balance_last_error`.

Cycles fields remain as-is from existing telemetry.

### 6) Cost/freshness guidance
Approximate per-snapshot cost (ETH + USDC, capped small responses): ~106M cycles.

Estimated daily cost:
- every 30s: ~316.8B cycles/day,
- every 60s: ~158.4B cycles/day,
- every 300s (recommended normal): ~31.68B cycles/day,
- every 900s (recommended low-cycles): ~10.56B cycles/day.

Recommended baseline:
- 5-minute sync in `Normal` gives acceptable freshness for treasury awareness.
- 15-minute sync in `LowCycles` preserves runway while maintaining situational awareness.

---

## Requirements

### Must Have
- [ ] Add typed wallet balance telemetry structs to domain model and stable snapshot persistence.
- [ ] Add wallet balance sync config with strict validation bounds and sane defaults.
- [ ] Implement internal ETH/USDC sync function that does not use model tool calls.
- [ ] Integrate sync into scheduler runtime path with tier-aware due gating.
- [ ] Enforce bootstrap gate: no inference before first successful ETH+USDC sync after `init`/`post_upgrade`.
- [ ] Include freshness metadata and last sync error in dynamic context for every turn.
- [ ] Keep sync failures non-fatal for `PollInbox` and `AgentTurn` continuity.
- [ ] Add unit tests for due gating, freshness derivation, and error degradation behavior.
- [ ] Add PocketIC integration coverage showing regular refresh + stale transition behavior.

### Should Have
- [ ] Add query/API view for wallet-balance telemetry and sync config (safe, non-secret fields only).
- [ ] Add canlog entries for sync outcomes (`fresh`, `stale`, `error`, `skipped_due_not_reached`).
- [ ] Add optional admin setter for explicit `usdc_contract_address` override.

### Could Have
- [ ] Add dirty-flag triggered fast refresh after successful `send_eth` or ingested payment events.
- [ ] Add per-balance source block tracking in UI snapshot rendering.

---

## Constraints
- Keep KISS: no scheduler lane redesign and no unnecessary new task kinds.
- No secret leakage through logs, query methods, or HTTP endpoints.
- Maintain autonomy guarantees: transient sync failures must not require manual reset.
- Bootstrap gating must not deadlock control-plane operation: retries continue automatically until success.
- Respect host-safe time guidance in tests/helpers.
- Preserve Candid generation workflow from Rust export; do not hand-edit `ic-automaton.did`.

---

## Success Criteria
- Agent dynamic context consistently includes cycles + ETH + USDC balances with freshness metadata.
- ETH/USDC telemetry is refreshed by runtime scheduling even when the model makes zero `evm_read` tool calls.
- First inference after `init`/`post_upgrade` occurs only after initial balance snapshot succeeds.
- Low-cycle tiers reduce sync frequency and critical tiers disable sync without fault loops.
- Validation suite and targeted PocketIC tests pass with no stale-Wasm false failures.

---

## Implementation Plan

- [x] **Task 1: Build wallet telemetry foundation (types + storage + EVM sync helpers)**
      - Files: `src/domain/types.rs`, `src/storage/stable.rs`, `src/features/evm.rs`
      - Validation: `cargo test --lib domain::types::tests:: storage::stable::tests:: features::evm::tests::`
      - Notes: add defaults/serde migration behavior, including bootstrap-pending flag; implement ETH fetch, USDC `balanceOf` read, and optional `Inbox.usdc()` discovery.

- [ ] **Task 2: Wire runtime orchestration and agent context**
      - Files: `src/scheduler.rs`, `src/storage/stable.rs`, `src/agent.rs`
      - Validation: `cargo test --lib scheduler::tests:: agent::tests::`
      - Notes: run sync opportunistically in `run_poll_inbox_job` with tier-aware due windows; enforce no-inference bootstrap gate until first sync success; update Layer-10 context to consume typed telemetry/freshness.

- [ ] **Task 3: Expose safe interfaces and add integration coverage**
      - Files: `src/lib.rs`, `src/http.rs`, `src/domain/types.rs`, `tests/pocketic_scheduler_queue.rs`, `tests/pocketic_ui_observability.rs` (or new `tests/pocketic_wallet_balance_sync.rs`)
      - Validation: `cargo test --lib http::tests:: && icp build && cargo test --features pocketic_tests --test pocketic_scheduler_queue -- --nocapture`
      - Notes: expose only non-secret telemetry/config fields and verify bootstrap gating (first inference blocked until sync), periodic refresh, stale transition, and non-fatal degradation behavior.

- [ ] **Task 4: Full validation**
      - Files: `src/agent.rs`, `src/scheduler.rs`, `src/features/evm.rs`, `src/storage/stable.rs`, `src/domain/types.rs`, `src/http.rs`, `src/lib.rs`
      - Validation: `cargo fmt --all -- --check && cargo clippy --all-targets --all-features && cargo test && icp build`
      - Dependencies: Task 1-3

---

## Context Files

- `AGENTS.md`
- `src/agent.rs`
- `src/scheduler.rs`
- `src/features/evm.rs`
- `src/domain/types.rs`
- `src/storage/stable.rs`
- `src/http.rs`
- `src/lib.rs`
- `docs/design/CYCLES_SURVIVAL_MODE_AND_HTTPS_OUTCALL_COST_CONTROL.md`
- `docs/design/HIGH_LEVERAGE_TOOLS.md`

---

## Codebase Snapshot

Snapshot date: 2026-02-21

- `src/agent.rs` currently surfaces ETH balance in dynamic context only via `MemoryFact` keys populated from successful `evm_read` tool calls.
- `src/agent.rs` has no first-class USDC balance telemetry path in dynamic context.
- `src/scheduler.rs` already has survival-tier-aware task execution and `PollInbox` EVM outcall flow with backoff.
- `src/domain/types.rs` and `src/storage/stable.rs` already persist runtime and observability telemetry, but not typed wallet balance snapshots.
- `src/features/evm.rs` already provides internal RPC calls (`eth_getBalance`, `eth_call`) suitable for reuse in runtime-managed sync.
- Current runtime has no bootstrap barrier that guarantees first inference sees fetched ETH/USDC balances.

---

## Autonomy Scope

### Decide yourself:
- Exact bounds for sync config (`min/max interval`, `max_response_bytes` cap).
- Final naming of wallet telemetry structs and status enum.
- Whether to place telemetry in `RuntimeSnapshot` directly or in a dedicated stable key with view projection.

### Escalate (log blocker, skip, continue):
- Any requirement to support multi-chain or multi-token beyond ETH + USDC.
- Any requirement to guarantee externally consistent token metadata beyond configured/known contracts.
- Any request to enforce token valuation or trading behavior in this slice.

---

## Verification

### Smoke Tests
- `cargo fmt --all -- --check` -- formatting and generated edits are clean.
- `cargo clippy --all-targets --all-features` -- lint/correctness checks pass.
- `cargo test --lib agent::tests::` -- dynamic context and freshness logic are covered.
- `cargo test --lib scheduler::tests::` -- due-window, tier gating, and bootstrap no-inference guard behavior are covered.
- `cargo test --lib features::evm::tests::` -- ETH/USDC read helpers and degradation behavior are covered.
- `icp build` -- Wasm/canister build path is healthy.

### Expected State
- `rg -n "WalletBalance|wallet_balance|usdc_balance|last_synced_at_ns" src/domain/types.rs src/storage/stable.rs src/agent.rs` returns typed balance telemetry definitions/usages.
- `rg -n "maybe_sync_wallet_balances|sync_wallet_balances" src/scheduler.rs src/features/evm.rs` returns runtime sync integration points.
- `rg -n "bootstrap_pending|wallet_balance_bootstrap" src/domain/types.rs src/storage/stable.rs src/scheduler.rs src/agent.rs` returns first-inference bootstrap gating points.
- `rg -n "wallet_balance_is_stale|wallet_balance_age_secs" src/agent.rs` returns freshness context fields.
- `rg -n "usdc_contract_address" src/domain/types.rs src/storage/stable.rs src/lib.rs src/http.rs` returns config and API wiring.

### Regression
- `bash .githooks/pre-commit` passes.

### Integration Test
- `icp build && cargo test --features pocketic_tests --test pocketic_scheduler_queue -- --nocapture` validates bootstrap gating and scheduler-driven sync behavior.
- `icp build && cargo test --features pocketic_tests --test pocketic_ui_observability -- --nocapture` validates telemetry exposure and freshness transitions in a canister-like runtime.

---

## Progress

### Completed
- Spec locked.

### Blockers
- None.

### Learnings
- Existing architecture already has the key primitives (survival tiers, EVM RPC client, dynamic context assembly); the gap is telemetry ownership and scheduler-driven freshness policy, not missing low-level EVM access.

---

## Ship Checklist (non-negotiable final step)

- [ ] Run smoke, regression, and integration verification commands.
- [ ] Confirm first inference is blocked until initial ETH/USDC sync succeeds after init/upgrade.
- [ ] Confirm runtime keeps operating when ETH/USDC sync fails transiently.
- [ ] Confirm dynamic context shows freshness and staleness explicitly.
- [ ] Confirm no secrets are exposed by new telemetry/config endpoints.
- [ ] Confirm `ic-automaton.did` remains generated from Rust exports only.
