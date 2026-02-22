# Design Doc: Bridge USDC from Base to ICP Cycles

**Status:** Draft
**Date:** 2026-02-22
**Author:** IC-Automaton Team

---

## 1. Goal

Enable the IC-Automaton canister to **autonomously top itself up with cycles** by converting USDC held on Base L2 into ICP cycles. The mechanism runs as an autonomous scheduler job — a heartbeat process that triggers when cycles run low, not an LLM-driven tool.

---

## 2. Background

### Current State

The IC-Automaton canister is a self-sovereign AI agent on ICP that:
- Controls an EVM wallet on Base via threshold ECDSA
- Receives ETH and USDC via an `Inbox.sol` contract on Base
- Has cycle survival tiers (Normal >200B, LowCycles 50-200B, Critical 10-50B, OutOfCycles <10B)
- Can read EVM state, sign transactions, and broadcast them to Base
- **Cannot** currently convert its Base USDC balance into ICP cycles

When cycles deplete, the canister freezes. Today the only top-up path is manual intervention — a fundamental gap for a self-sovereign agent.

### Why USDC on Base?

USDC on Base is the canister's primary revenue source (received via `Inbox.sol` from users paying for agent interactions). Base has low gas fees (~$0.01) making frequent small transactions practical.

### Why Not a Tool?

The USDC→cycles conversion is a **mechanical multi-step process**, not an LLM reasoning task:

1. **Doesn't fit in a single turn.** The agent turn has a 90-second max duration, 3 inference rounds, and 12 tool calls. The full flow requires 2 ECDSA signings, 12+ Base block confirmations (~23s), bridge polling, DEX swap, and CMC minting — exceeding the turn budget.

2. **No LLM judgment needed.** Every step is deterministic: check balance → approve → lock → wait → swap → mint. There are no decisions for the LLM to make.

3. **The canister has no inter-canister call infrastructure yet.** All current tools use HTTPS outcalls. The ICP-side steps (Onesec validation, KongSwap swap, ICRC-2 approve, CMC notify) require `ic_cdk::call`, which is a new capability regardless of whether it's a tool or job.

4. **The scheduler already handles this pattern.** `CheckCycles` monitors cycle balance on a 60-second interval. A new `TopUpCycles` job type naturally extends this with state-machine persistence, retry logic, and lease-based execution — all built into the scheduler.

5. **Lightweight tools for visibility.** The agent can still observe and interact with the process via two simple read-only tools: `top_up_status` (check progress) and `trigger_top_up` (manually initiate).

---

## 3. Bridge Path: Onesec (Base → ICP)

### Options Considered

| Option | Path | Latency | Gas Cost | Verdict |
|--------|------|---------|----------|---------|
| **A: Onesec** | Base USDC → Locker → Bridged USDC → KongSwap → ICP → CMC | ~1 min | ~$0.01 | **Selected** |
| B: ckUSDC | Base → Ethereum L1 → ckERC20 Minter → ckUSDC → DEX → CMC | 7 days or 20+ min | $5-20 | Rejected (slow, expensive) |
| C: Base DEX | Swap USDC→ICP on Base, bridge ICP | N/A | N/A | Rejected (no ICP liquidity) |
| D: Off-chain | External service monitors + tops up | N/A | N/A | Rejected (defeats sovereignty) |

### Selected Path

```
Base USDC → Onesec Locker → Bridged USDC on ICP → KongSwap → ICP → CMC → Cycles
```

**Sub-option: Direct Lock (A1) vs Forwarding Address (A2)**

| | Direct Lock (A1) | Forwarding Address (A2) |
|---|---|---|
| EVM transactions | 2 (approve + lock1) | 1 (transfer) |
| ECDSA signings | 2 × ~26B cycles | 1 × ~26B cycles |
| ICP-side calls | transfer_evm_to_icp + poll | forward_evm_to_icp + poll status + transfer_evm_to_icp |
| Control | Explicit amount, immediate validation | Implicit detection, extra polling step |

**Start with A1 (Direct Lock)** for explicit control. A2 saves ~26B cycles per operation and can be adopted later as an optimization.

---

## 4. Contract Addresses & Canister IDs

**Base L2 (Chain ID 8453):**

| Contract | Address | Purpose |
|----------|---------|---------|
| USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | ERC-20 token (6 decimals) |
| Onesec Locker | `0xAe2351B15cFf68b5863c6690dCA58Dce383bf45A` | Locks USDC for bridging |

**ICP Canisters:**

| Canister | ID | Purpose |
|----------|----|---------|
| Onesec Bridge | `5okwm-giaaa-aaaar-qbn6a-cai` | Bridge coordinator |
| Bridged USDC Ledger | `53nhb-haaaa-aaaar-qbn5q-cai` | ICRC-1/2 token on ICP (confirmed ICRC-2 support) |
| KongSwap Backend | `2ipq2-uqaaa-aaaar-qailq-cai` | DEX swap engine (bridged USDC listed as token_id 465) |
| ICP Ledger | `ryjl3-tyaaa-aaaaa-aaaba-cai` | ICP token |
| CMC | `rkp4c-7iaaa-aaaaa-aaaca-cai` | Cycles minting |

**EVM Function Selectors (verified via `cast sig`):**

| Function | Selector | Usage |
|----------|----------|-------|
| `approve(address,uint256)` | `0x095ea7b3` | USDC approval for Locker |
| `lock1(uint256,bytes32)` | `0x3455fccc` | Lock without subaccount |
| `lock2(uint256,bytes32,bytes32)` | `0x00e76bdc` | Lock with subaccount |
| `balanceOf(address)` | `0x70a08231` | Check USDC balance |

---

## 5. Architecture: Scheduler Job with State Machine

### 5.1 Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         IC-Automaton Canister                            │
│                                                                         │
│  Scheduler                                                              │
│  ┌──────────────┐     ┌──────────────────────────────────────────────┐ │
│  │ CheckCycles  │────→│ TopUpCycles (new TaskKind)                   │ │
│  │ (every 60s)  │     │                                              │ │
│  │              │     │  State machine in stable memory:             │ │
│  │ if cycles <  │     │  ┌─────┐ ┌──────┐ ┌────┐ ┌─────┐ ┌──────┐ │ │
│  │ threshold && │     │  │Check│→│Bridge│→│Swap│→│ CMC │→│Done! │ │ │
│  │ usdc > min   │     │  │Bal. │ │ EVM  │ │DEX │ │TopUp│ │      │ │ │
│  │              │     │  └─────┘ └──────┘ └────┘ └─────┘ └──────┘ │ │
│  └──────────────┘     └──────────────────────────────────────────────┘ │
│                                                                         │
│  Agent (optional visibility)                                            │
│  ┌───────────────────┐  ┌──────────────────┐                           │
│  │ top_up_status tool │  │ trigger_top_up   │                           │
│  │ (read-only query)  │  │ tool (manual)    │                           │
│  └───────────────────┘  └──────────────────┘                           │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 New TaskKind: TopUpCycles

Added to the existing scheduler alongside `AgentTurn`, `PollInbox`, `CheckCycles`, and `Reconcile`:

```rust
pub enum TaskKind {
    AgentTurn,
    PollInbox,
    CheckCycles,
    Reconcile,
    TopUpCycles,  // NEW
}
```

**Scheduling:** Not periodic. Enqueued on-demand by `CheckCycles` when:
1. Cycle balance < `auto_topup_cycle_threshold` (default: 200B)
2. Cycle balance > 60B (enough to pay for the operation itself)
3. No `TopUpCycles` job is already pending or running
4. USDC balance on Base > `min_usdc_reserve` + `topup_usdc_amount`

**Lease TTL:** 300 seconds (5 minutes) — long enough for the full flow including block confirmations and polling.

### 5.3 State Machine

The top-up process is a linear state machine persisted in stable memory. Each scheduler tick advances the machine by one or more steps (as many as fit within the lease).

```rust
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum TopUpStage {
    /// Initial: fetch USDC balance and Onesec fees, validate preconditions
    Preflight,

    /// EVM tx: USDC.approve(Onesec Locker, amount)
    ApprovingLocker {
        usdc_amount: u64,  // raw units (6 decimals)
    },

    /// Waiting for approve tx to be mined
    WaitingApprovalConfirmation {
        usdc_amount: u64,
        approve_tx_hash: String,
    },

    /// EVM tx: Locker.lock1(amount, encoded_principal)
    LockingUSDC {
        usdc_amount: u64,
    },

    /// Waiting for lock tx to reach 12 confirmations on Base
    WaitingLockConfirmation {
        usdc_amount: u64,
        lock_tx_hash: String,
        confirmations_seen: u8,
    },

    /// Inter-canister call: Onesec.transfer_evm_to_icp(...)
    ValidatingOnOnesec {
        usdc_amount: u64,
        lock_tx_hash: String,
    },

    /// Polling Onesec.get_transfer(...) until Succeeded
    WaitingForBridgedUSDC {
        usdc_amount: u64,
        transfer_id: u128,
        polls: u8,
    },

    /// Inter-canister call: bridged_usdc.icrc2_approve(KongSwap, amount)
    ApprovingKongSwap {
        bridged_usdc_amount: u64,  // amount after bridge fees
    },

    /// Inter-canister call: KongSwap.swap(bridged_usdc → ICP)
    SwappingToICP {
        bridged_usdc_amount: u64,
    },

    /// Inter-canister call: icp_ledger.icrc1_transfer(→ CMC subaccount)
    TransferringToCMC {
        icp_amount: u64,  // e8s
    },

    /// Inter-canister call: CMC.notify_top_up(block_index, canister_id)
    MintingCycles {
        block_index: u64,
    },

    /// Terminal: success
    Completed {
        cycles_minted: u128,
        usdc_spent: u64,
        icp_intermediate: u64,
        completed_at_ns: u64,
    },

    /// Terminal: failure
    Failed {
        stage_name: String,
        error: String,
        failed_at_ns: u64,
        attempts: u32,
    },
}
```

**Stable memory key:** `top_up_state` — a single `TopUpStage` value. Only one top-up can be in progress at a time.

### 5.4 Execution: One Tick, One (or More) Steps

Each time the scheduler dispatches `TopUpCycles`, it calls `advance_top_up()`:

```rust
/// Advance the top-up state machine as far as possible within this tick.
/// Returns Ok(true) if the machine reached a terminal state, Ok(false) if
/// it needs more ticks, or Err if an unrecoverable error occurred.
pub async fn advance_top_up(config: &TopUpConfig) -> Result<bool, String> {
    let mut state = load_top_up_state();  // from stable memory

    loop {
        let next = match &state {
            TopUpStage::Preflight => preflight(config).await?,
            TopUpStage::ApprovingLocker { .. } => approve_locker(&state, config).await?,
            TopUpStage::WaitingApprovalConfirmation { .. } => poll_approval(&state).await?,
            TopUpStage::LockingUSDC { .. } => lock_usdc(&state, config).await?,
            TopUpStage::WaitingLockConfirmation { .. } => poll_lock(&state).await?,
            TopUpStage::ValidatingOnOnesec { .. } => validate_on_onesec(&state, config).await?,
            TopUpStage::WaitingForBridgedUSDC { .. } => poll_bridge(&state, config).await?,
            TopUpStage::ApprovingKongSwap { .. } => approve_kongswap(&state, config).await?,
            TopUpStage::SwappingToICP { .. } => swap_to_icp(&state, config).await?,
            TopUpStage::TransferringToCMC { .. } => transfer_to_cmc(&state, config).await?,
            TopUpStage::MintingCycles { .. } => mint_cycles(&state, config).await?,
            TopUpStage::Completed { .. } | TopUpStage::Failed { .. } => return Ok(true),
        };

        save_top_up_state(&next);  // persist before continuing
        state = next;

        // If we hit a Waiting* state, yield — we'll continue on the next tick
        if matches!(state,
            TopUpStage::WaitingApprovalConfirmation { .. } |
            TopUpStage::WaitingLockConfirmation { .. } |
            TopUpStage::WaitingForBridgedUSDC { .. }
        ) {
            return Ok(false);
        }
    }
}
```

**Key property:** The state is persisted to stable memory after every transition. If the canister traps, upgrades, or runs out of cycles, the machine resumes from the last saved state.

### 5.5 Step Implementations

#### Preflight

```rust
async fn preflight(config: &TopUpConfig) -> Result<TopUpStage, String> {
    // 1. Check cycle balance
    let cycles = ic_cdk::api::canister_balance128();
    if cycles < 60_000_000_000 {
        return Err("Insufficient cycles to cover operation cost (~53B)".into());
    }

    // 2. Check USDC balance on Base (HTTPS outcall)
    let usdc_balance = evm_read_balance(
        &config.usdc_contract_address,
        &automaton_evm_address(),
    ).await?;

    let available = usdc_balance.saturating_sub(config.min_usdc_reserve);
    if available < 5_000_000 {  // minimum 5 USDC
        return Err(format!("USDC available ({}) below minimum 5 USDC", available));
    }

    let usdc_amount = available.min(config.max_usdc_per_topup);

    // 3. Check Onesec fees (inter-canister call)
    let fees = onesec::get_transfer_fees(&config.onesec_canister).await?;
    let usdc_fee = find_fee(&fees, Token::USDC, EvmChain::Base)?;

    if usdc_amount < usdc_fee.min_amount {
        return Err(format!("Amount {} below Onesec minimum {}", usdc_amount, usdc_fee.min_amount));
    }
    if usdc_amount > usdc_fee.max_amount {
        return Err(format!("Amount {} above Onesec maximum {}", usdc_amount, usdc_fee.max_amount));
    }

    Ok(TopUpStage::ApprovingLocker { usdc_amount })
}
```

#### ApprovingLocker (EVM: USDC.approve)

```rust
async fn approve_locker(state: &TopUpStage, config: &TopUpConfig) -> Result<TopUpStage, String> {
    let usdc_amount = match state {
        TopUpStage::ApprovingLocker { usdc_amount } => *usdc_amount,
        _ => unreachable!(),
    };

    // Construct approve(spender, amount) calldata
    // selector: 0x095ea7b3
    let calldata = encode_approve(
        &config.onesec_locker_address,  // spender
        usdc_amount,
    );

    // Sign + broadcast (reuses existing send_eth infrastructure)
    let tx_hash = sign_and_broadcast_evm_tx(
        &config.usdc_contract_address,  // to: USDC contract
        0,                               // value: 0 ETH
        &calldata,
    ).await?;

    Ok(TopUpStage::WaitingApprovalConfirmation {
        usdc_amount,
        approve_tx_hash: tx_hash,
    })
}
```

#### WaitingApprovalConfirmation / WaitingLockConfirmation

```rust
async fn poll_confirmation(tx_hash: &str, required: u8) -> Result<Option<u8>, String> {
    // HTTPS outcall: eth_getTransactionReceipt
    let receipt = evm_rpc::eth_get_transaction_receipt(tx_hash).await?;

    match receipt {
        None => Ok(Some(0)),  // not mined yet
        Some(r) if !r.status => Err("Transaction reverted".into()),
        Some(r) => {
            let current_block = evm_rpc::eth_block_number().await?;
            let confirmations = current_block.saturating_sub(r.block_number);
            if confirmations >= required as u64 {
                Ok(None)  // done — proceed to next stage
            } else {
                Ok(Some(confirmations as u8))
            }
        }
    }
}
```

For `approve`: requires 1 confirmation, then transitions to `LockingUSDC`.
For `lock1`: requires 12 confirmations, then transitions to `ValidatingOnOnesec`.

#### LockingUSDC (EVM: Locker.lock1)

```rust
async fn lock_usdc(state: &TopUpStage, config: &TopUpConfig) -> Result<TopUpStage, String> {
    let usdc_amount = match state {
        TopUpStage::LockingUSDC { usdc_amount } => *usdc_amount,
        _ => unreachable!(),
    };

    // Encode ICP principal as data1 (32 bytes)
    let data1 = encode_principal_for_onesec(&ic_cdk::id());

    // Construct lock1(uint256, bytes32) calldata
    // selector: 0x3455fccc
    let calldata = encode_lock1(usdc_amount, &data1);

    let tx_hash = sign_and_broadcast_evm_tx(
        &config.onesec_locker_address,
        0,
        &calldata,
    ).await?;

    Ok(TopUpStage::WaitingLockConfirmation {
        usdc_amount,
        lock_tx_hash: tx_hash,
        confirmations_seen: 0,
    })
}
```

#### ValidatingOnOnesec (inter-canister call)

```rust
async fn validate_on_onesec(state: &TopUpStage, config: &TopUpConfig) -> Result<TopUpStage, String> {
    let (usdc_amount, lock_tx_hash) = match state {
        TopUpStage::ValidatingOnOnesec { usdc_amount, lock_tx_hash } =>
            (*usdc_amount, lock_tx_hash.clone()),
        _ => unreachable!(),
    };

    let result: (TransferResponse,) = ic_cdk::call(
        config.onesec_canister,
        "transfer_evm_to_icp",
        (TransferEvmToIcpArg {
            token: Token::USDC,
            evm_chain: EvmChain::Base,
            evm_account: EvmAccount { address: automaton_evm_address() },
            evm_tx: EvmTx { hash: lock_tx_hash, log_index: None },
            icp_account: OnesecIcpAccount::ICRC {
                owner: ic_cdk::id(),
                subaccount: None,
            },
            evm_amount: usdc_amount as u128,
            icp_amount: None,
        },)
    ).await.map_err(|(code, msg)| format!("Onesec call failed: {:?} {}", code, msg))?;

    match result.0 {
        TransferResponse::Accepted(tid) => Ok(TopUpStage::WaitingForBridgedUSDC {
            usdc_amount,
            transfer_id: tid.id,
            polls: 0,
        }),
        TransferResponse::Fetching { .. } => {
            // Onesec hasn't synced yet — stay in this state, retry next tick
            Ok(state.clone())
        }
        TransferResponse::Failed { error } => {
            Err(format!("Onesec rejected transfer: {}", error))
        }
    }
}
```

#### WaitingForBridgedUSDC (poll Onesec transfer status)

```rust
async fn poll_bridge(state: &TopUpStage, config: &TopUpConfig) -> Result<TopUpStage, String> {
    let (usdc_amount, transfer_id, polls) = match state {
        TopUpStage::WaitingForBridgedUSDC { usdc_amount, transfer_id, polls } =>
            (*usdc_amount, *transfer_id, *polls),
        _ => unreachable!(),
    };

    if polls > 60 {  // ~5 minutes at 5s/poll
        return Err("Bridge transfer timed out after 60 polls".into());
    }

    let result: (Result<Transfer, String>,) = ic_cdk::call(
        config.onesec_canister,
        "get_transfer",
        (TransferId { id: transfer_id },),
    ).await.map_err(|(code, msg)| format!("get_transfer failed: {:?} {}", code, msg))?;

    let transfer = result.0.map_err(|e| format!("get_transfer error: {}", e))?;

    match transfer.status {
        TransferStatus::Succeeded => {
            // Query actual bridged USDC received (after Onesec fees)
            let balance: (Nat,) = ic_cdk::call(
                config.bridged_usdc_ledger,
                "icrc1_balance_of",
                (Account { owner: ic_cdk::id(), subaccount: None },),
            ).await.map_err(|(c, m)| format!("balance query failed: {:?} {}", c, m))?;

            let bridged_amount = nat_to_u64(&balance.0)?;
            Ok(TopUpStage::ApprovingKongSwap { bridged_usdc_amount: bridged_amount })
        }
        TransferStatus::Failed => Err("Onesec transfer failed".into()),
        _ => Ok(TopUpStage::WaitingForBridgedUSDC {
            usdc_amount,
            transfer_id,
            polls: polls + 1,
        }),
    }
}
```

#### ApprovingKongSwap (ICRC-2 approve)

```rust
async fn approve_kongswap(state: &TopUpStage, config: &TopUpConfig) -> Result<TopUpStage, String> {
    let bridged_usdc_amount = match state {
        TopUpStage::ApprovingKongSwap { bridged_usdc_amount } => *bridged_usdc_amount,
        _ => unreachable!(),
    };

    let result: (Result<Nat, ApproveError>,) = ic_cdk::call(
        config.bridged_usdc_ledger,
        "icrc2_approve",
        (ApproveArgs {
            from_subaccount: None,
            spender: Account { owner: config.kong_backend, subaccount: None },
            amount: Nat::from(bridged_usdc_amount) + Nat::from(10_000u64),  // + ledger fee
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },),
    ).await.map_err(|(c, m)| format!("icrc2_approve failed: {:?} {}", c, m))?;

    result.0.map_err(|e| format!("Approval rejected: {:?}", e))?;

    Ok(TopUpStage::SwappingToICP { bridged_usdc_amount })
}
```

#### SwappingToICP (KongSwap)

```rust
async fn swap_to_icp(state: &TopUpStage, config: &TopUpConfig) -> Result<TopUpStage, String> {
    let bridged_usdc_amount = match state {
        TopUpStage::SwappingToICP { bridged_usdc_amount } => *bridged_usdc_amount,
        _ => unreachable!(),
    };

    // Optional: query estimate first
    // let estimate = kong.swap_amounts("IC.53nhb...", amount, "ICP").await?;

    let result: (Result<SwapReply, String>,) = ic_cdk::call(
        config.kong_backend,
        "swap",
        (SwapArgs {
            pay_token: format!("IC.{}", config.bridged_usdc_ledger),
            pay_amount: Nat::from(bridged_usdc_amount),
            pay_tx_id: None,  // use icrc2_transfer_from
            receive_token: "ICP".to_string(),
            receive_amount: None,  // let KongSwap find best route
            receive_address: Some(ic_cdk::id().to_text()),
            max_slippage: Some(config.max_slippage_pct),
            referred_by: None,
        },),
    ).await.map_err(|(c, m)| format!("KongSwap call failed: {:?} {}", c, m))?;

    let reply = result.0.map_err(|e| format!("Swap failed: {}", e))?;

    if reply.status != "Success" {
        return Err(format!("Swap status: {}", reply.status));
    }

    let icp_amount = nat_to_u64(&reply.receive_amount)?;  // in e8s

    Ok(TopUpStage::TransferringToCMC { icp_amount })
}
```

#### TransferringToCMC (ICP Ledger → CMC subaccount)

```rust
async fn transfer_to_cmc(state: &TopUpStage, config: &TopUpConfig) -> Result<TopUpStage, String> {
    let icp_amount = match state {
        TopUpStage::TransferringToCMC { icp_amount } => *icp_amount,
        _ => unreachable!(),
    };

    // CMC subaccount = SHA-256("\x0Acanister-id" || canister_id_bytes)
    let subaccount = compute_cmc_subaccount(ic_cdk::id());

    let result: (Result<Nat, TransferError>,) = ic_cdk::call(
        config.icp_ledger,
        "icrc1_transfer",
        (TransferArg {
            from_subaccount: None,
            to: Account {
                owner: config.cmc,
                subaccount: Some(subaccount),
            },
            amount: Nat::from(icp_amount),
            fee: None,
            memo: None,
            created_at_time: None,
        },),
    ).await.map_err(|(c, m)| format!("ICP transfer failed: {:?} {}", c, m))?;

    let block_index = result.0.map_err(|e| format!("Transfer rejected: {:?}", e))?;

    Ok(TopUpStage::MintingCycles {
        block_index: nat_to_u64(&block_index)?,
    })
}
```

#### MintingCycles (CMC notify_top_up)

```rust
async fn mint_cycles(state: &TopUpStage, config: &TopUpConfig) -> Result<TopUpStage, String> {
    let block_index = match state {
        TopUpStage::MintingCycles { block_index } => *block_index,
        _ => unreachable!(),
    };

    let result: (Result<u128, NotifyError>,) = ic_cdk::call(
        config.cmc,
        "notify_top_up",
        (NotifyTopUpArg {
            block_index: Nat::from(block_index),
            canister_id: ic_cdk::id(),
        },),
    ).await.map_err(|(c, m)| format!("CMC call failed: {:?} {}", c, m))?;

    let cycles_minted = result.0.map_err(|e| format!("CMC rejected: {:?}", e))?;

    Ok(TopUpStage::Completed {
        cycles_minted,
        usdc_spent: 0,     // populated from earlier state
        icp_intermediate: 0,
        completed_at_ns: ic_cdk::api::time(),
    })
}
```

### 5.6 Integration with CheckCycles

The existing `CheckCycles` job gains a trigger condition:

```rust
// In scheduler.rs, within the CheckCycles dispatch:
async fn run_check_cycles() {
    let cycles = ic_cdk::api::canister_balance128();
    let tier = survival_tier(cycles);

    // ... existing tier logic ...

    // NEW: Auto-trigger top-up
    if cycles < config.auto_topup_cycle_threshold
        && cycles > 60_000_000_000  // enough for the operation
        && !is_top_up_in_progress()
    {
        // Check USDC balance (cached from last reconcile, or fresh query)
        if cached_usdc_balance() > config.min_usdc_reserve + 5_000_000 {
            enqueue_job(TaskKind::TopUpCycles);
            log::info!("Enqueued TopUpCycles: cycles={}, usdc={}", cycles, cached_usdc_balance());
        }
    }
}
```

### 5.7 Agent Tools (Lightweight, Read-Only)

Two optional tools give the LLM visibility into the process:

```rust
// Tool: top_up_status
// Returns current state of any in-progress or last-completed top-up
pub fn top_up_status() -> String {
    match load_top_up_state() {
        None => "No top-up in progress or history.".into(),
        Some(state) => format!("{:?}", state),
    }
}

// Tool: trigger_top_up
// Manually enqueue a top-up (e.g., if a user requests it)
pub fn trigger_top_up(usdc_amount: Option<u64>) -> String {
    if is_top_up_in_progress() {
        return "Top-up already in progress.".into();
    }
    enqueue_job(TaskKind::TopUpCycles);
    "Top-up job enqueued.".into()
}
```

These are registered in the tool manager with `Inferring` + `ExecutingActions` access (low cost, no signing).

---

## 6. Candid Types

### 6.1 Onesec Bridge

```rust
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum Token { ICP, USDC, USDT, ckBTC, cbBTC, BOB, GLDT }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum EvmChain { Base, Ethereum, Arbitrum }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmAccount { pub address: String }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmTx { pub hash: String, pub log_index: Option<u64> }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum OnesecIcpAccount {
    ICRC { owner: Principal, subaccount: Option<Vec<u8>> },
    AccountId(String),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TransferEvmToIcpArg {
    pub token: Token,
    pub evm_chain: EvmChain,
    pub evm_account: EvmAccount,
    pub evm_tx: EvmTx,
    pub icp_account: OnesecIcpAccount,
    pub evm_amount: u128,
    pub icp_amount: Option<u128>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TransferId { pub id: u128 }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum TransferResponse {
    Accepted(TransferId),
    Failed { error: String },
    Fetching { block_height: u128 },
}
```

### 6.2 KongSwap

```rust
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum TxId { BlockIndex(Nat), TransactionHash(String) }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SwapArgs {
    pub pay_token: String,
    pub pay_amount: Nat,
    pub pay_tx_id: Option<TxId>,
    pub receive_token: String,
    pub receive_amount: Option<Nat>,
    pub receive_address: Option<String>,
    pub max_slippage: Option<f64>,
    pub referred_by: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SwapReply {
    pub tx_id: u64,
    pub request_id: u64,
    pub status: String,
    pub pay_symbol: String,
    pub pay_amount: Nat,
    pub receive_symbol: String,
    pub receive_amount: Nat,
    pub mid_price: f64,
    pub price: f64,
    pub slippage: f64,
    pub claim_ids: Vec<u64>,
    pub ts: u64,
}
```

---

## 7. Configuration

```rust
pub struct TopUpConfig {
    /// Onesec Locker contract on Base
    pub onesec_locker_address: String,     // 0xAe2351B15cFf68b5863c6690dCA58Dce383bf45A
    /// USDC contract on Base
    pub usdc_contract_address: String,     // 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
    /// Onesec bridge canister on ICP
    pub onesec_canister: Principal,        // 5okwm-giaaa-aaaar-qbn6a-cai
    /// Bridged USDC ledger on ICP
    pub bridged_usdc_ledger: Principal,    // 53nhb-haaaa-aaaar-qbn5q-cai
    /// KongSwap backend canister
    pub kong_backend: Principal,           // 2ipq2-uqaaa-aaaar-qailq-cai
    /// ICP Ledger
    pub icp_ledger: Principal,             // ryjl3-tyaaa-aaaaa-aaaba-cai
    /// Cycles Minting Canister
    pub cmc: Principal,                    // rkp4c-7iaaa-aaaaa-aaaca-cai
    /// Minimum USDC to keep on Base (raw units, 6 decimals)
    pub min_usdc_reserve: u64,             // default: 2_000_000 (2 USDC)
    /// Default USDC per top-up (raw units)
    pub topup_usdc_amount: u64,            // default: 10_000_000 (10 USDC)
    /// Maximum USDC per top-up (raw units)
    pub max_usdc_per_topup: u64,           // default: 50_000_000 (50 USDC)
    /// Cycle threshold to trigger auto-top-up
    pub auto_topup_cycle_threshold: u128,  // default: 200_000_000_000 (200B)
    /// Max slippage for DEX swap (percentage)
    pub max_slippage_pct: f64,             // default: 5.0
}
```

---

## 8. Error Handling & Recovery

Every stage transition is persisted to stable memory. On failure:

| Failure Point | Funds Location | Recovery |
|---------------|---------------|----------|
| `Preflight` fails | Base wallet (unchanged) | Auto-retry on next `CheckCycles` trigger |
| `ApprovingLocker` tx reverts | Base wallet | Retry. No funds at risk (approval is free to retry). |
| `LockingUSDC` tx reverts | Base wallet | Retry. Approval may need refreshing. |
| `WaitingLockConfirmation` timeout | Onesec Locker holds USDC | Manual investigation. Store tx hash in `Failed` state. |
| `ValidatingOnOnesec` returns `Fetching` | Onesec Locker | Retry on next tick (Onesec still syncing). |
| `ValidatingOnOnesec` returns `Failed` | Onesec Locker | Log error. May need manual recovery via Onesec support. |
| `WaitingForBridgedUSDC` timeout (60 polls) | In transit | Store transfer_id in `Failed` state for manual investigation. |
| `ApprovingKongSwap` fails | Bridged USDC in canister's ICP account | Retry. Funds safe as ICRC-1 balance. |
| `SwappingToICP` fails (slippage) | Bridged USDC in canister's ICP account | Retry with wider slippage or wait for better price. |
| `SwappingToICP` returns `claim_ids` | Held by KongSwap | Call `claims()` to retrieve. |
| `TransferringToCMC` fails | ICP in canister's account | Retry immediately. |
| `MintingCycles` fails | ICP in CMC subaccount | Retry `notify_top_up` — idempotent. |
| Canister runs out of cycles mid-flow | Wherever the state machine stopped | On restart after external top-up, `advance_top_up()` resumes from persisted state. |

**Retry policy:** On transient failures (network errors, `Fetching` responses), the job stays in the current state and retries on the next scheduler tick. After `max_retries` (default: 5) consecutive failures at the same stage, transition to `Failed` state and log. The `CheckCycles` job will not enqueue a new `TopUpCycles` while a `Failed` state exists — requires manual clearing or operator intervention.

---

## 9. Cycle Cost of the Operation

| Operation | Estimated Cycles |
|-----------|-----------------|
| EVM read (balance check, receipt polls × ~15) | ~750M |
| EVM tx: approve (ECDSA signing + broadcast) | ~26B + ~100M |
| EVM tx: lock1 (ECDSA signing + broadcast) | ~26B + ~100M |
| Onesec canister calls (transfer_evm_to_icp, get_transfer × ~10) | ~50M |
| ICRC-1/2 calls (balance, approve, transfer) | ~5M |
| KongSwap calls (swap_amounts, swap) | ~20M |
| CMC call (notify_top_up) | ~10M |
| **Total** | **~53B cycles** |

ECDSA signing dominates (~52B of 53B total). The canister must have >60B cycles before starting.

---

## 10. Implementation Plan

### Phase 1: Inter-Canister Call Infrastructure
- [ ] Add `ic_cdk::call` wrapper utilities (typed call + error mapping)
- [ ] Add Candid type definitions for Onesec, KongSwap, ICRC-1/2, CMC
- [ ] Test basic inter-canister calls (e.g., `icrc1_balance_of` on bridged USDC ledger)

### Phase 2: CMC Top-Up (ICP → Cycles)
- [ ] Implement `compute_cmc_subaccount()`
- [ ] Implement ICP ledger transfer to CMC subaccount
- [ ] Implement `notify_top_up` call
- [ ] Test with manually transferred ICP (cheapest to test, most well-understood)

### Phase 3: KongSwap Swap (Bridged USDC → ICP)
- [ ] Implement `icrc2_approve` on bridged USDC ledger for KongSwap
- [ ] Implement KongSwap `swap()` call
- [ ] Test with manually bridged USDC (skip bridge, test swap + CMC only)

### Phase 4: Onesec Bridge (Base USDC → Bridged USDC)
- [ ] Implement `encode_principal_for_onesec()`
- [ ] Implement ERC-20 approve calldata encoding
- [ ] Implement `lock1()` calldata encoding
- [ ] Implement `transfer_evm_to_icp()` inter-canister call
- [ ] Implement `get_transfer()` polling
- [ ] Test full bridge flow with small amount (1 USDC) on mainnet

### Phase 5: Scheduler Integration
- [ ] Add `TopUpCycles` variant to `TaskKind`
- [ ] Implement `TopUpStage` state machine with stable memory persistence
- [ ] Implement `advance_top_up()` dispatch loop
- [ ] Wire `CheckCycles` trigger logic
- [ ] Add `top_up_status` and `trigger_top_up` agent tools
- [ ] Add `TopUpConfig` to canister init args

### Phase 6: Hardening
- [ ] Retry policy with max attempts per stage
- [ ] Concurrency guard (single top-up at a time)
- [ ] Cycle reserve check before starting
- [ ] Logging at every state transition
- [ ] End-to-end test: let `CheckCycles` trigger the full flow
- [ ] Mainnet dry run with 5 USDC

---

## 11. Resolved Questions

1. ~~**KongSwap bridged-USDC pool**~~: Listed as token_id 465, symbol "USDC", ~$8.8K market cap. Low liquidity but functional; multi-hop routing available.

2. ~~**Onesec lock function selectors**~~: `lock1(uint256,bytes32)` → `0x3455fccc`, `lock2(uint256,bytes32,bytes32)` → `0x00e76bdc`. Verified via `cast sig`.

3. ~~**Onesec fee levels**~~: Dynamic, fetched via `get_transfer_fees()`. Structure: `latestTransferFee + (amount × protocolFeeInPercent)`. Min/max amounts per token/chain pair.

4. ~~**Minimum viable top-up**~~: ~5 USDC minimum, ~10 USDC recommended. 10 USDC → ~7T cycles net. Operation cost (~53B) is negligible relative to yield.

5. ~~**ICRC-2 support for bridged USDC**~~: Fully supported. Standard DFINITY ICRC ledger with `icrc2` feature flag enabled.

---

## 12. Appendix: Alternative Forwarding Address Flow

If the direct lock flow proves problematic, the forwarding address alternative saves one ECDSA signing (~26B cycles):

```rust
// 1. Get forwarding address (one-time, can be cached)
let fwd_address: String = onesec.get_forwarding_address(
    OnesecIcpAccount::ICRC { owner: ic_cdk::id(), subaccount: None }
).await?;

// 2. Single EVM tx: USDC.transfer(fwd_address, amount)
//    selector: 0xa9059cbb

// 3. Notify: onesec.forward_evm_to_icp(...)
// 4. Poll: onesec.get_forwarding_status(...) until Forwarded
// 5. Validate: onesec.transfer_evm_to_icp(...) — same as direct flow
// 6. Continue: KongSwap → CMC (identical)
```

Trade-off: saves ~26B cycles per operation but adds an extra polling phase. Consider adopting once the direct lock flow is proven stable.
