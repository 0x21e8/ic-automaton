# Cycle Top-Up Runtime: Triggering and Scheduling (Current Implementation)

## Scope
This document explains how the current USDC -> cycles top-up mechanism works in this repository today, with emphasis on:

- how top-up is triggered
- how top-up is scheduled/executed
- how the state machine progresses
- what is persisted and what operational behaviors to expect

It describes implemented behavior, not planned behavior.

## Implementation map
Top-up behavior is split across these files:

- `src/features/cycle_topup/mod.rs`
  - core state machine and transition logic
  - EVM transaction creation/sign/broadcast helpers
  - Onesec/Kong/ledger/CMC inter-canister call wrappers
- `src/features/cycle_topup_host.rs`
  - host wiring from runtime snapshot to `TopUpConfig`
  - adapters: `AutomatonEvmPort`, `AutomatonStoragePort`
  - enqueue helpers and tool helpers
- `src/scheduler.rs`
  - auto-trigger logic in `run_check_cycles`
  - `TaskKind::TopUpCycles` dispatch path
  - periodic job scheduling (`refresh_due_jobs`)
- `src/storage/stable.rs`
  - top-up state persistence (`TOPUP_STATE_KEY`, memory id 24)
  - scheduler queue, dedupe, task configs/runtime
- `src/domain/types.rs`
  - `CycleTopUpConfig` runtime config schema/defaults
  - `TaskKind::TopUpCycles` scheduler metadata
- `src/tools.rs` and `src/features/inference.rs`
  - `top_up_status` and `trigger_top_up` tool exposure

## Configuration and persisted state

### Runtime config (`RuntimeSnapshot.cycle_topup`)
`CycleTopUpConfig` is stored inside `RuntimeSnapshot` and defaults to:

- `enabled = true`
- `auto_topup_cycle_threshold = 200_000_000_000`
- `usdc_contract_address = None`
- `onesec_locker_address = 0xae2351b15cff68b5863c6690dca58dce383bf45a`
- `onesec_canister_id = 5okwm-giaaa-aaaar-qbn6a-cai`
- `bridged_usdc_ledger_id = 53nhb-haaaa-aaaar-qbn5q-cai`
- `kong_backend_id = 2ipq2-uqaaa-aaaar-qailq-cai`
- `icp_ledger_id = ryjl3-tyaaa-aaaaa-aaaba-cai`
- `cmc_id = rkp4c-7iaaa-aaaaa-aaaca-cai`
- `target_canister_id = None` (falls back to current canister id)
- `min_usdc_reserve = 2_000_000` (2 USDC raw units)
- `max_usdc_per_topup = 50_000_000` (50 USDC raw units)
- `max_slippage_pct = 5.0`
- `max_bridge_polls = 60`
- `lock_confirmations = 12`

### Init args currently supported
Only two top-up fields can be overridden via canister init args:

- `cycle_topup_enabled`
- `auto_topup_cycle_threshold`

All other top-up config fields use runtime defaults unless changed through other internal state updates.

### Persisted top-up state
Top-up stage is persisted under storage key:

- key: `cycle_topup.state`
- map: `TOPUP_STATE_MAP`
- memory id: `MemoryId::new(24)`

This is what survives between scheduler ticks/upgrades and drives resume behavior.

## How `TopUpConfig` is built at runtime
`build_cycle_topup(snapshot)` in `cycle_topup_host` resolves effective config:

- `evm_address` is required from snapshot, else build fails.
- `usdc_contract_address` resolution order:
  1. `snapshot.cycle_topup.usdc_contract_address`
  2. `snapshot.wallet_balance.usdc_contract_address`
  3. `TopUpConfig::default().usdc_contract_address` (Base USDC contract)
- principal ids are parsed from the string ids in `cycle_topup`.
- EVM address/contract addresses are normalized/validated as lowercase `0x` 20-byte hex.

If config cannot be built, trigger/dispatch paths fail early.

## Trigger paths

### 1. Automatic trigger in `CheckCycles`
`run_check_cycles()` is invoked by scheduler when `TaskKind::CheckCycles` runs (default interval: 60s).

Auto-start conditions (`should_trigger_cycle_topup`) are all required:

- `snapshot.cycle_topup.enabled == true`
- `total_cycles > 60_000_000_000`
- `total_cycles < auto_topup_cycle_threshold`
- top-up state is `None` or `Completed` only
- cached USDC balance (from `snapshot.wallet_balance.usdc_balance_raw_hex`) is strictly greater than:
  - `min_usdc_reserve + 5_000_000`

If true:

1. scheduler builds `CycleTopUp`
2. calls `topup.start()` (moves state to `Preflight`)
3. enqueues one `TopUpCycles` job via `enqueue_topup_cycles_job("auto", now_ns)`

### 2. Manual trigger via agent tool
The `trigger_top_up` tool path:

- reads runtime snapshot
- requires `cycle_topup.enabled == true`
- builds `CycleTopUp` from snapshot
- calls `start()` (same start rules as auto path)
- enqueues one `TopUpCycles` job via `enqueue_topup_cycles_job("tool", now_ns)`

Tool policy:

- `trigger_top_up` allowed in `AgentState::ExecutingActions`
- `top_up_status` allowed in `ExecutingActions` and `Inferring`

### 3. Periodic `TopUpCycles` schedule (disabled by default)
`TaskKind::TopUpCycles` exists in task configs with:

- default interval: 30s
- default priority: 3
- `essential = true`
- `enabled = false` by default

So periodic enqueue for `TopUpCycles` does not happen unless explicitly enabled via:

- `set_task_enabled(TopUpCycles, true)`

When enabled, `refresh_due_jobs` can enqueue periodic `TopUpCycles` jobs like any other task kind.

## Scheduling and dedupe details

### Scheduler tick loop
Global scheduler runs every 30 seconds (`set_timer_interval_serial`).
Per tick:

1. `refresh_due_jobs(now_ns)` enqueues due periodic tasks (if enabled)
2. scheduler executes up to 4 mutating jobs
3. each job runs under a mutating lease

### Dedupe keys used for top-up jobs
All enqueue paths now use one shared dedupe key namespace for top-up:

- key: `TopUpCycles:singleton`
- used by:
  - explicit top-up enqueue helper (`auto` and `tool` trigger sources)
  - periodic scheduler enqueue for `TaskKind::TopUpCycles`

Deduplication blocks creating a new top-up job when a non-terminal job already exists for this singleton key.

### Q&A: Can `CheckCycles` and tool trigger enqueue at the same time?
Short answer:

- two `TopUpCycles` jobs do **not** run concurrently in this canister
- with singleton dedupe, only one non-terminal top-up job can be queued across all trigger sources

Details:

- `CheckCycles` auto-trigger requires top-up state to be `None` or `Completed`.
- `trigger_top_up` calls `start()`, and `start()` rejects if top-up is already in progress.
- Because canister execution is serialized per message, there is no race where both successfully `start()` the same flow concurrently.
- Scheduler execution of mutating jobs is serialized behind one mutating lease, so two top-up jobs do not execute at the same time.

## `TopUpCycles` job execution path
When a `TopUpCycles` job is dequeued:

1. scheduler loads runtime snapshot
2. builds `CycleTopUp`
3. calls `topup.advance().await`

`advance()` behavior:

- if no saved top-up state: returns `Ok(true)` (idle)
- otherwise loops transitions until:
  - terminal stage (`Completed` or `Failed`) -> `Ok(true)`
  - waiting stage -> `Ok(false)`
  - transition error -> writes `Failed{...}` and `Ok(true)`

Scheduler currently treats any `Ok(_)` as successful job completion.

## State machine stages and transitions
Current `TopUpStage` states:

1. `Preflight`
2. `ApprovingLocker { usdc_amount }`
3. `WaitingApprovalConfirmation { usdc_amount, tx_hash }`
4. `LockingUSDC { usdc_amount }`
5. `WaitingLockConfirmation { usdc_amount, tx_hash, confirmations }`
6. `ValidatingOnOnesec { usdc_amount, tx_hash }`
7. `WaitingForBridgedUSDC { usdc_amount, transfer_id, polls }`
8. `ApprovingKongSwap { bridged_usdc_amount }`
9. `SwappingToICP { bridged_usdc_amount }`
10. `TransferringToCMC { icp_amount }`
11. `MintingCycles { block_index }`
12. `Completed { cycles_minted, usdc_spent, completed_at_ns }`
13. `Failed { stage, error, failed_at_ns, attempts }`

### Transition summary
- `Preflight`
  - checks canister has at least 60B cycles (`canister_balance128`)
  - reads EVM USDC balance via `eth_call(balanceOf)`
  - computes `available = balance - min_usdc_reserve`
  - requires `available >= 5_000_000`
  - caps amount by `max_usdc_per_topup`
  - calls Onesec `get_transfer_fees` and validates amount in [min, max]
  - next: `ApprovingLocker`

- `ApprovingLocker`
  - sends ERC20 `approve(locker, amount)` tx
  - next: `WaitingApprovalConfirmation`

- `WaitingApprovalConfirmation`
  - polls `eth_getTransactionReceipt`
  - if receipt missing: remains in waiting stage
  - if receipt status is revert: error -> `Failed`
  - next after 1 confirmation: `LockingUSDC`

- `LockingUSDC`
  - sends locker `lock1(amount, data1)` tx where `data1` encodes principal
  - next: `WaitingLockConfirmation`

- `WaitingLockConfirmation`
  - polls tx receipt and block confirmations
  - if insufficient confirmations: remains in waiting stage with updated `confirmations`
  - next on enough confirmations: `ValidatingOnOnesec`

- `ValidatingOnOnesec`
  - calls Onesec `transfer_evm_to_icp` with token USDC, chain Base
  - `Accepted(id)` -> `WaitingForBridgedUSDC`
  - `Fetching` -> remain same state
  - `Failed` -> error

- `WaitingForBridgedUSDC`
  - polls Onesec `get_transfer(transfer_id)`
  - `Pending`/`Fetching` -> increment `polls`
  - `Succeeded(amount)` -> `ApprovingKongSwap`
  - `Failed(error)` -> error
  - hard error when `polls >= max_bridge_polls`

- `ApprovingKongSwap`
  - calls bridged USDC ledger `icrc2_approve` for Kong backend
  - next: `SwappingToICP`

- `SwappingToICP`
  - calls Kong `swap` from bridged USDC to ICP
  - requires status `"success"` (case-insensitive)
  - next: `TransferringToCMC`

- `TransferringToCMC`
  - calls ICP ledger `icrc1_transfer` to CMC subaccount for target canister
  - next: `MintingCycles`

- `MintingCycles`
  - calls CMC `notify_top_up`
  - next: `Completed`

### EVM transaction construction details
For EVM sends (`approve`, `lock1`), runtime builds an EIP-1559 tx:

- nonce: `eth_getTransactionCount(..., "pending")`
- base gas price: `eth_gasPrice`
- priority fee: fixed 1 gwei
- max fee: base + priority
- gas limit: `eth_estimateGas` or fallback `250_000`
- signs tx hash via threshold signer (`sign_message`)
- recovers `y_parity` from signature (wasm path)
- broadcasts with `eth_sendRawTransaction`

## Failure and reset behavior
- Any transition error is persisted as `TopUpStage::Failed`.
- `start()` rejects when current state is `Failed` (`reset() first`).
- `reset()` exists in core state machine and clears failed state to idle.
- In current host wiring, there is no dedicated public update/query endpoint for direct manual `reset()`.
- Self-heal path: `CheckCycles` now attempts automatic failed-state recovery:
  - if top-up is `Failed` and backoff elapsed (currently 120 seconds), scheduler calls `reset()`, then `start()`, then enqueues `TopUpCycles` (`auto-recover` trigger source).
  - if backoff has not elapsed, recovery is skipped for that tick.

## Current scheduling implications (important)
Because of current wiring:

- `TopUpCycles` periodic schedule is disabled by default.
- `dispatch_job` runs `advance()` once per enqueued `TopUpCycles` job.
- if `advance()` stops at a waiting stage and returns `Ok(false)`, scheduler marks the current job as succeeded and automatically enqueues a continuation `TopUpCycles` job (scheduled for the next interval window).

Practical consequence:

- After entering a waiting stage, further progress requires another enqueue source:
  - continuation is automatic via scheduler re-enqueue while in waiting stages
  - automatic failed-state recovery from `CheckCycles` (only when state is `Failed` and backoff elapsed)
  - optional manual `trigger_top_up` (if idle/completed)
  - optional periodic `TopUpCycles` scheduling

## Observability surfaces
- Scheduler logs include check-cycles and auto-trigger attempts (`topup_triggered` flag).
- `top_up_status` tool returns the current mapped `TopUpStatus` as debug text.
- `list_task_schedules` and recent job listing show whether `TopUpCycles` is enabled, pending, running, or completed.

## End-to-end trigger/scheduling example
Typical current auto path:

1. `CheckCycles` runs and detects cycles below threshold but above operational floor.
2. Cached USDC is sufficient and top-up state is idle/completed.
3. State set to `Preflight`; one `TopUpCycles` job enqueued (`trigger=auto`).
4. Scheduler executes `TopUpCycles` and advances through as many non-waiting stages as possible.
5. If a waiting stage is reached, execution pauses at that state.
6. A later enqueue event is needed to continue from persisted state.
