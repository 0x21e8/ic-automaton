# Design Doc: Bridge USDC from Base to ICP Cycles

**Status:** Draft
**Date:** 2026-02-22
**Author:** IC-Automaton Team

---

## 1. Goal

Enable any ICP canister that controls an EVM wallet on Base to **autonomously top itself up with cycles** by converting USDC into ICP cycles. The core logic is a self-contained, portable Rust module (`cycle_topup`) that can be embedded in the IC-Automaton canister or deployed as a standalone canister.

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

### Why a Portable Module?

The USDC→cycles conversion is useful beyond IC-Automaton. Any canister that holds USDC on Base could benefit. Designing it as a module with clean trait boundaries means:

1. **Embed in IC-Automaton** — the scheduler calls `advance()`, traits are backed by the existing signer and RPC client.
2. **Deploy standalone** — a lightweight canister with its own timer, signer, and stable memory.
3. **Reuse in other projects** — any canister that implements two traits gets the full flow for free.

### Why Not a Tool?

The USDC→cycles conversion is a **mechanical multi-step process**, not an LLM reasoning task:

1. **Doesn't fit in a single turn.** The agent turn has a 90-second max duration. The full flow requires 2 ECDSA signings, 12+ Base block confirmations (~23s), bridge polling, DEX swap, and CMC minting.
2. **No LLM judgment needed.** Every step is deterministic.
3. **The scheduler already handles this pattern.** `CheckCycles` monitors cycle balance on a 60-second interval. A new `TopUpCycles` job type naturally extends this.

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

**Start with Direct Lock (A1)** for explicit control. Forwarding address mode (A2) saves ~26B cycles per operation and can be adopted later (see Appendix).

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
| Bridged USDC Ledger | `53nhb-haaaa-aaaar-qbn5q-cai` | ICRC-1/2 token (confirmed ICRC-2) |
| KongSwap Backend | `2ipq2-uqaaa-aaaar-qailq-cai` | DEX (bridged USDC = token_id 465) |
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

## 5. Module Architecture

### 5.1 Design Principle: Two Traits, One Entry Point

The `cycle_topup` module owns the state machine, Candid types, ABI encoding, and all inter-canister call logic. It depends on the host for exactly **two capabilities**:

```rust
/// Everything the module needs from the host canister for EVM interaction.
#[async_trait(?Send)]
pub trait EvmPort {
    /// Sign a raw message hash via threshold ECDSA.
    /// Input: 0x-prefixed hex hash (32 bytes). Output: 0x-prefixed hex signature.
    async fn sign_message(&self, message_hash: &str) -> Result<String, String>;

    /// Send a JSON-RPC request to the Base RPC endpoint.
    /// Input: method name + JSON params. Output: JSON result string.
    async fn evm_rpc_call(&self, method: &str, params: &str) -> Result<String, String>;
}

/// Everything the module needs for persisting its state machine across ticks.
pub trait StoragePort {
    /// Load the current top-up state (None = idle).
    fn load_state(&self) -> Option<TopUpStage>;

    /// Persist the top-up state.
    fn save_state(&self, state: &TopUpStage);

    /// Clear the state (after completion or manual reset).
    fn clear_state(&self);
}
```

The module's public API is minimal:

```rust
pub struct CycleTopUp<E: EvmPort, S: StoragePort> {
    config: TopUpConfig,
    evm: E,
    storage: S,
}

impl<E: EvmPort, S: StoragePort> CycleTopUp<E, S> {
    pub fn new(config: TopUpConfig, evm: E, storage: S) -> Self;

    /// Advance the state machine as far as possible in this tick.
    /// Returns Ok(true) if terminal state reached, Ok(false) if more ticks needed.
    pub async fn advance(&self) -> Result<bool, String>;

    /// Read current status (no side effects).
    pub fn status(&self) -> TopUpStatus;

    /// Start a new top-up from Preflight. Fails if one is already in progress.
    /// Allowed from Idle and Completed; Failed requires reset().
    pub fn start(&self) -> Result<(), String>;

    /// Clear a Failed state so a new top-up can be triggered.
    pub fn reset(&self) -> Result<(), String>;
}
```

### 5.2 What the Module Owns (No Host Dependency)

Everything below is internal to the module — the host never touches it:

- **State machine** (`TopUpStage` enum + transition logic)
- **ABI encoding** (`encode_approve`, `encode_lock1`, `encode_principal_for_onesec`)
- **EVM transaction construction** (EIP-1559 tx building, RLP encoding, gas estimation)
- **Inter-canister calls** to Onesec, KongSwap, ICRC-1/2 ledgers, CMC (via `ic_cdk::call`)
- **Candid types** for all external canisters
- **Fee validation** (query `get_transfer_fees`, check min/max/liquidity)
- **CMC subaccount computation** (`SHA-256("\x0Acanister-id" || canister_id_bytes)`)

### 5.3 What the Host Provides (Via Traits)

| Capability | Trait | IC-Automaton Implementation | Standalone Implementation |
|-----------|-------|----------------------------|--------------------------|
| ECDSA signing | `EvmPort::sign_message` | `ThresholdSignerAdapter` (existing) | Direct `sign_with_ecdsa` call |
| EVM JSON-RPC | `EvmPort::evm_rpc_call` | `HttpEvmRpcClient` (existing) | `management_canister::http_request` |
| State persistence | `StoragePort::load/save/clear` | Stable memory (`MemoryId::new(24)`) | Stable memory (own `MemoryId::new(0)`) |
| Periodic ticking | Calls `advance()` | Scheduler `TopUpCycles` job | `ic_cdk_timers::set_timer_interval` |
| Trigger decision | Calls `start()` | `CheckCycles` scheduler job | Timer callback or `#[update]` endpoint |

### 5.4 Overview Diagram

```
┌──────────────────────────────────────────────┐
│  cycle_topup module (portable)               │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │ TopUpStage state machine               │  │
│  │ Preflight → Bridge → Swap → CMC → Done │  │
│  └────────┬──────────────┬────────────────┘  │
│           │              │                    │
│     EvmPort trait   StoragePort trait         │
│     (host impl)    (host impl)               │
│           │              │                    │
│  ┌────────┴──────┐ ┌────┴────┐               │
│  │ sign_message  │ │ load    │               │
│  │ evm_rpc_call  │ │ save    │               │
│  └───────────────┘ │ clear   │               │
│                     └─────────┘               │
│                                              │
│  Module also makes direct ic_cdk::call to:   │
│  • Onesec (5okwm..)                          │
│  • Bridged USDC ledger (53nhb..)             │
│  • KongSwap (2ipq2..)                        │
│  • ICP Ledger (ryjl3..)                      │
│  • CMC (rkp4c..)                             │
└──────────────────────────────────────────────┘
           ▲                    ▲
           │                    │
    ┌──────┴──────┐     ┌──────┴──────────┐
    │ IC-Automaton │     │ Standalone       │
    │ (embedded)   │     │ Canister         │
    │              │     │                  │
    │ Scheduler    │     │ Timer callback   │
    │ calls        │     │ calls            │
    │ advance()    │     │ advance()        │
    │              │     │                  │
    │ CheckCycles  │     │ Timer checks     │
    │ calls        │     │ cycle balance,   │
    │ start()      │     │ calls start()    │
    └──────────────┘     └─────────────────┘
```

---

## 6. State Machine

### 6.1 Stages

```rust
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum TopUpStage {
    /// Fetch USDC balance and Onesec fees, validate preconditions
    Preflight,

    /// EVM tx: USDC.approve(Onesec Locker, amount)
    ApprovingLocker { usdc_amount: u64 },

    /// Waiting for approve tx to be mined (1 confirmation)
    WaitingApprovalConfirmation { usdc_amount: u64, tx_hash: String },

    /// EVM tx: Locker.lock1(amount, encoded_principal)
    LockingUSDC { usdc_amount: u64 },

    /// Waiting for lock tx (12 confirmations on Base)
    WaitingLockConfirmation { usdc_amount: u64, tx_hash: String, confirmations: u8 },

    /// Call Onesec.transfer_evm_to_icp(...)
    ValidatingOnOnesec { usdc_amount: u64, tx_hash: String },

    /// Poll Onesec.get_transfer(...) until Succeeded
    WaitingForBridgedUSDC { usdc_amount: u64, transfer_id: u128, polls: u8 },

    /// Call bridged_usdc.icrc2_approve(KongSwap, amount)
    ApprovingKongSwap { bridged_usdc_amount: u64 },

    /// Call KongSwap.swap(bridged_usdc → ICP)
    SwappingToICP { bridged_usdc_amount: u64 },

    /// Call icp_ledger.icrc1_transfer(→ CMC subaccount)
    TransferringToCMC { icp_amount: u64 },

    /// Call CMC.notify_top_up(block_index, canister_id)
    MintingCycles { block_index: u64 },

    /// Terminal: success
    Completed { cycles_minted: u128, usdc_spent: u64, completed_at_ns: u64 },

    /// Terminal: failure (requires manual reset via `reset()`)
    Failed { stage: String, error: String, failed_at_ns: u64, attempts: u32 },
}
```

### 6.2 Advance Loop

```rust
pub async fn advance(&self) -> Result<bool, String> {
    let Some(mut state) = self.storage.load_state() else {
        return Ok(true);  // idle, nothing to do
    };

    loop {
        let next = match &state {
            TopUpStage::Preflight                      => self.preflight().await,
            TopUpStage::ApprovingLocker { .. }          => self.approve_locker(&state).await,
            TopUpStage::WaitingApprovalConfirmation { .. } => self.poll_tx(&state, 1).await,
            TopUpStage::LockingUSDC { .. }              => self.lock_usdc(&state).await,
            TopUpStage::WaitingLockConfirmation { .. }  => self.poll_tx(&state, 12).await,
            TopUpStage::ValidatingOnOnesec { .. }       => self.validate_on_onesec(&state).await,
            TopUpStage::WaitingForBridgedUSDC { .. }    => self.poll_bridge(&state).await,
            TopUpStage::ApprovingKongSwap { .. }        => self.approve_kongswap(&state).await,
            TopUpStage::SwappingToICP { .. }            => self.swap_to_icp(&state).await,
            TopUpStage::TransferringToCMC { .. }        => self.transfer_to_cmc(&state).await,
            TopUpStage::MintingCycles { .. }            => self.mint_cycles(&state).await,
            TopUpStage::Completed { .. } | TopUpStage::Failed { .. } => return Ok(true),
        };

        match next {
            Ok(next_state) => {
                self.storage.save_state(&next_state);
                state = next_state;
            }
            Err(e) => {
                let failed = TopUpStage::Failed {
                    stage: format!("{:?}", std::mem::discriminant(&state)),
                    error: e,
                    failed_at_ns: ic_cdk::api::time(),
                    attempts: 0,
                };
                self.storage.save_state(&failed);
                return Ok(true);
            }
        }

        // Yield at waiting states — continue on next tick
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

### 6.3 Key Step: Preflight

```rust
async fn preflight(&self) -> Result<TopUpStage, String> {
    // 1. Check cycle balance (must afford the operation)
    let cycles = ic_cdk::api::canister_balance128();
    if cycles < 60_000_000_000 {
        return Err("Insufficient cycles for operation (~53B needed)".into());
    }

    // 2. Check USDC balance on Base (via EvmPort)
    let balance_hex = self.evm.evm_rpc_call("eth_call", &format!(
        r#"[{{"to":"{}","data":"0x70a08231{}"}}, "latest"]"#,
        self.config.usdc_contract_address,
        pad_address(&self.config.evm_address),
    )).await?;
    let usdc_balance = parse_hex_u64(&balance_hex)?;

    let available = usdc_balance.saturating_sub(self.config.min_usdc_reserve);
    if available < 5_000_000 {
        return Err(format!("USDC available ({}) below minimum 5 USDC", available));
    }
    let usdc_amount = available.min(self.config.max_usdc_per_topup);

    // 3. Check Onesec fees (inter-canister call)
    let fees: (Vec<TransferFee>,) = ic_cdk::call(
        self.config.onesec_canister, "get_transfer_fees", ()
    ).await.map_err(|(c, m)| format!("get_transfer_fees failed: {:?} {}", c, m))?;

    let fee = find_usdc_base_fee(&fees.0)?;
    if usdc_amount < fee.min_amount || usdc_amount > fee.max_amount {
        return Err(format!("Amount {} outside Onesec bounds [{}, {}]",
            usdc_amount, fee.min_amount, fee.max_amount));
    }

    Ok(TopUpStage::ApprovingLocker { usdc_amount })
}
```

### 6.4 Key Step: EVM Transactions (via EvmPort)

The module builds raw EVM transactions internally and uses `EvmPort` only for signing and RPC:

```rust
async fn approve_locker(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
    let usdc_amount = extract_usdc_amount(state);

    // Module builds calldata internally (no host involvement)
    let calldata = abi::encode_approve(&self.config.onesec_locker_address, usdc_amount);

    // Module builds unsigned EIP-1559 tx internally
    let nonce = self.evm_get_nonce().await?;
    let gas_price = self.evm_gas_price().await?;
    let unsigned_tx = eip1559_tx(
        &self.config.usdc_contract_address, 0, &calldata, nonce, gas_price,
    );

    // Only the hash + signature go through the trait boundary
    let msg_hash = unsigned_tx.signing_hash();
    let signature = self.evm.sign_message(&msg_hash).await?;

    let signed_tx = unsigned_tx.with_signature(&signature);
    let tx_hash = self.evm_send_raw_tx(&signed_tx).await?;

    Ok(TopUpStage::WaitingApprovalConfirmation {
        usdc_amount, tx_hash,
    })
}
```

### 6.5 Key Step: Inter-Canister Calls (Module-Owned)

All ICP canister calls are made directly by the module via `ic_cdk::call`. The host doesn't mediate:

```rust
async fn swap_to_icp(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
    let bridged_usdc_amount = extract_bridged_amount(state);

    let result: (Result<SwapReply, String>,) = ic_cdk::call(
        self.config.kong_backend,
        "swap",
        (SwapArgs {
            pay_token: format!("IC.{}", self.config.bridged_usdc_ledger),
            pay_amount: Nat::from(bridged_usdc_amount),
            pay_tx_id: None,
            receive_token: "ICP".to_string(),
            receive_amount: None,
            receive_address: Some(ic_cdk::id().to_text()),
            max_slippage: Some(self.config.max_slippage_pct),
            referred_by: None,
        },),
    ).await.map_err(|(c, m)| format!("KongSwap failed: {:?} {}", c, m))?;

    let reply = result.0.map_err(|e| format!("Swap failed: {}", e))?;
    if reply.status != "Success" {
        return Err(format!("Swap status: {}", reply.status));
    }

    Ok(TopUpStage::TransferringToCMC {
        icp_amount: nat_to_u64(&reply.receive_amount)?,
    })
}
```

### 6.6 Principal Encoding for Onesec

```rust
/// Encode an ICP principal into the 32-byte data1 field for Onesec's lock1().
pub fn encode_principal_for_onesec(principal: &Principal) -> [u8; 32] {
    let mut data1 = [0u8; 32];
    let bytes = principal.as_slice();
    data1[0] = 0x00;  // ICRC account tag
    data1[1] = bytes.len() as u8;
    data1[2..2 + bytes.len()].copy_from_slice(bytes);
    data1
}
```

---

## 7. Configuration

```rust
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TopUpConfig {
    // --- EVM addresses ---
    /// This canister's EVM address on Base (derived from threshold ECDSA key)
    pub evm_address: String,
    /// USDC contract on Base
    pub usdc_contract_address: String,     // 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
    /// Onesec Locker contract on Base
    pub onesec_locker_address: String,     // 0xAe2351B15cFf68b5863c6690dCA58Dce383bf45A
    /// EVM chain ID
    pub evm_chain_id: u64,                 // 8453 (Base)

    // --- ICP canister IDs ---
    /// Onesec bridge canister
    pub onesec_canister: Principal,        // 5okwm-giaaa-aaaar-qbn6a-cai
    /// Bridged USDC ledger
    pub bridged_usdc_ledger: Principal,    // 53nhb-haaaa-aaaar-qbn5q-cai
    /// KongSwap backend
    pub kong_backend: Principal,           // 2ipq2-uqaaa-aaaar-qailq-cai
    /// ICP Ledger
    pub icp_ledger: Principal,             // ryjl3-tyaaa-aaaaa-aaaba-cai
    /// Cycles Minting Canister
    pub cmc: Principal,                    // rkp4c-7iaaa-aaaaa-aaaca-cai
    /// Canister to top up (defaults to ic_cdk::id() if None)
    pub target_canister: Option<Principal>,

    // --- Tuning ---
    /// Minimum USDC to keep on Base (raw units, 6 decimals)
    pub min_usdc_reserve: u64,             // default: 2_000_000 (2 USDC)
    /// Maximum USDC per top-up (raw units)
    pub max_usdc_per_topup: u64,           // default: 50_000_000 (50 USDC)
    /// Max slippage for DEX swap (percentage)
    pub max_slippage_pct: f64,             // default: 5.0
    /// Max polls before timing out bridge transfer
    pub max_bridge_polls: u8,              // default: 60
    /// Base block confirmations required for lock tx
    pub lock_confirmations: u8,            // default: 12
}
```

Note: `target_canister` allows topping up a **different** canister. This is useful for a standalone "cycle funder" canister that tops up other canisters.

---

## 8. Host Integration

### 8.1 IC-Automaton (Embedded)

```rust
// --- In src/features/cycle_topup_host.rs (glue code) ---

/// Adapt IC-Automaton's existing signer + RPC to the module's traits.
struct AutomatonEvmPort {
    signer: ThresholdSignerAdapter,
    rpc: HttpEvmRpcClient,
}

#[async_trait(?Send)]
impl EvmPort for AutomatonEvmPort {
    async fn sign_message(&self, hash: &str) -> Result<String, String> {
        self.signer.sign_message(hash).await
    }
    async fn evm_rpc_call(&self, method: &str, params: &str) -> Result<String, String> {
        self.rpc.json_rpc_call(method, params).await
    }
}

/// Adapt IC-Automaton's stable memory (MemoryId 24).
struct AutomatonStoragePort;
impl StoragePort for AutomatonStoragePort {
    fn load_state(&self) -> Option<TopUpStage> {
        stable::read_topup_state()  // StableBTreeMap on MemoryId::new(24)
    }
    fn save_state(&self, state: &TopUpStage) {
        stable::write_topup_state(state);
    }
    fn clear_state(&self) {
        stable::clear_topup_state();
    }
}

// --- In src/scheduler.rs ---

// Add to TaskKind enum
pub enum TaskKind {
    AgentTurn,
    PollInbox,
    CheckCycles,
    Reconcile,
    TopUpCycles,  // NEW
}

// In dispatch_job():
TaskKind::TopUpCycles => {
    let snapshot = stable::runtime_snapshot();
    let topup = CycleTopUp::new(
        topup_config_from_snapshot(&snapshot),
        AutomatonEvmPort {
            signer: ThresholdSignerAdapter::new(snapshot.ecdsa_key_name.clone()),
            rpc: HttpEvmRpcClient::from_snapshot(&snapshot)?,
        },
        AutomatonStoragePort,
    );
    topup.advance().await?;
    Ok(())
}

// In run_check_cycles() — trigger logic:
if cycles < config.auto_topup_cycle_threshold
    && cycles > 60_000_000_000
    && !is_top_up_in_progress()
    && cached_usdc_balance() > config.min_usdc_reserve + 5_000_000
{
    enqueue_job(TaskKind::TopUpCycles);
}
```

### 8.2 Standalone Canister

```rust
// --- In a standalone canister's lib.rs ---

use cycle_topup::{CycleTopUp, EvmPort, StoragePort, TopUpConfig, TopUpStage};

struct StandaloneEvmPort { key_name: String, rpc_url: String }

#[async_trait(?Send)]
impl EvmPort for StandaloneEvmPort {
    async fn sign_message(&self, hash: &str) -> Result<String, String> {
        // Direct threshold ECDSA call
        let sig = sign_with_ecdsa(SignWithEcdsaArgument {
            message_hash: hex::decode(&hash[2..]).unwrap(),
            derivation_path: vec![b"evm".to_vec()],
            key_id: EcdsaKeyId { curve: Secp256k1, name: self.key_name.clone() },
        }).await?;
        Ok(format!("0x{}", hex::encode(&sig.signature)))
    }
    async fn evm_rpc_call(&self, method: &str, params: &str) -> Result<String, String> {
        // Direct HTTPS outcall to Base RPC
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{}}}"#, method, params);
        let response = http_request(&HttpRequestArgs {
            url: self.rpc_url.clone(),
            method: HttpMethod::POST,
            body: Some(body.into_bytes()),
            ..Default::default()
        }).await?;
        Ok(parse_json_rpc_result(&response.body)?)
    }
}

struct StandaloneStoragePort;  // Uses MemoryId::new(0), owns entire stable memory
impl StoragePort for StandaloneStoragePort { /* ... */ }

#[ic_cdk::init]
fn init(config: TopUpConfig) {
    // Store config in stable memory
    TOPUP_CONFIG.with(|c| c.replace(Some(config)));
    // Start periodic advance timer (every 10 seconds)
    ic_cdk_timers::set_timer_interval(Duration::from_secs(10), || {
        ic_cdk::spawn(async {
            let config = load_config();
            let topup = CycleTopUp::new(
                config.clone(),
                StandaloneEvmPort { key_name: config.ecdsa_key_name, rpc_url: config.rpc_url },
                StandaloneStoragePort,
            );
            let _ = topup.advance().await;
        });
    });
}

/// Manual trigger
#[ic_cdk::update]
async fn trigger_top_up() -> Result<String, String> {
    let topup = build_topup();
    topup.start()?;
    Ok("Top-up started".into())
}

/// Check status
#[ic_cdk::query]
fn top_up_status() -> String {
    let topup = build_topup();
    format!("{:?}", topup.status())
}
```

### 8.3 Agent Visibility (IC-Automaton Only)

Two lightweight tools for the LLM:

```rust
// Tool: top_up_status (read-only, available in Inferring + ExecutingActions)
pub fn top_up_status_tool() -> String {
    let topup = build_topup();
    format!("{:?}", topup.status())
}

// Tool: trigger_top_up (available in ExecutingActions)
pub fn trigger_top_up_tool() -> String {
    let topup = build_topup();
    match topup.start() {
        Ok(()) => {
            enqueue_job(TaskKind::TopUpCycles);
            "Top-up enqueued.".into()
        }
        Err(e) => format!("Cannot start: {}", e),
    }
}
```

---

## 9. Candid Types (Module-Owned)

### 9.1 Onesec Bridge

```rust
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
    pub token: Token, pub evm_chain: EvmChain, pub evm_account: EvmAccount,
    pub evm_tx: EvmTx, pub icp_account: OnesecIcpAccount,
    pub evm_amount: u128, pub icp_amount: Option<u128>,
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

### 9.2 KongSwap

```rust
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum TxId { BlockIndex(Nat), TransactionHash(String) }

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SwapArgs {
    pub pay_token: String, pub pay_amount: Nat, pub pay_tx_id: Option<TxId>,
    pub receive_token: String, pub receive_amount: Option<Nat>,
    pub receive_address: Option<String>, pub max_slippage: Option<f64>,
    pub referred_by: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SwapReply {
    pub tx_id: u64, pub request_id: u64, pub status: String,
    pub pay_symbol: String, pub pay_amount: Nat,
    pub receive_symbol: String, pub receive_amount: Nat,
    pub mid_price: f64, pub price: f64, pub slippage: f64,
    pub claim_ids: Vec<u64>, pub ts: u64,
}
```

---

## 10. Error Handling & Recovery

Every stage transition is persisted via `StoragePort`. On failure:

| Failure Point | Funds Location | Recovery |
|---------------|---------------|----------|
| `Preflight` | Base wallet (unchanged) | Auto-retry on next trigger |
| `ApprovingLocker` reverts | Base wallet | Retry (approval is idempotent) |
| `LockingUSDC` reverts | Base wallet | Retry |
| `WaitingLockConfirmation` timeout | Onesec Locker | Manual investigation (tx hash in `Failed` state) |
| `ValidatingOnOnesec` → `Fetching` | Onesec Locker | Auto-retry next tick |
| `WaitingForBridgedUSDC` timeout | In transit | Manual investigation (transfer_id in `Failed` state) |
| `ApprovingKongSwap` fails | Bridged USDC in canister | Retry (ICRC-1 balance safe) |
| `SwappingToICP` slippage | Bridged USDC in canister | Retry later |
| `SwappingToICP` → `claim_ids` | Held by KongSwap | Call `claims()` to retrieve |
| `TransferringToCMC` fails | ICP in canister | Retry |
| `MintingCycles` fails | ICP in CMC subaccount | Retry (`notify_top_up` is idempotent) |
| Out of cycles mid-flow | Last-reached account | Resume from persisted state after external top-up |

**Retry policy:** Transient failures stay in current state for next tick. After reaching `Failed`, the state sticks until `reset()` is called (manual or programmatic).

---

## 11. Cycle Cost

| Operation | Estimated Cycles |
|-----------|-----------------|
| EVM reads (balance, nonce, gas, receipt polls × ~15) | ~750M |
| EVM tx: approve (ECDSA + broadcast) | ~26.1B |
| EVM tx: lock1 (ECDSA + broadcast) | ~26.1B |
| Inter-canister calls (Onesec, KongSwap, ICRC, CMC) | ~100M |
| **Total** | **~53B cycles** |

Canister must have >60B cycles before starting.

---

## 12. Implementation Plan

### Phase 1: Module Skeleton
- [x] Create `src/features/cycle_topup/` module directory
- [x] Define `EvmPort` and `StoragePort` traits
- [x] Define `TopUpConfig`, `TopUpStage`, `CycleTopUp<E, S>` struct
- [x] Implement `advance()` dispatch loop (transitions return `Err("not implemented")` initially)
- [x] Implement `status()`, `start()`, `reset()`

### Phase 2: ICP-Side Steps (Bottom-Up)
- [ ] Implement `mint_cycles` step (CMC `notify_top_up`)
- [ ] Implement `transfer_to_cmc` step (ICP ledger transfer)
- [ ] Implement `swap_to_icp` step (KongSwap `swap`)
- [ ] Implement `approve_kongswap` step (ICRC-2 approve)
- [ ] Test Phase 2 with manually deposited bridged USDC and ICP

### Phase 3: Bridge Steps
- [ ] Implement `encode_principal_for_onesec()` and ABI encoding helpers
- [ ] Implement `approve_locker` step (EVM tx via `EvmPort`)
- [ ] Implement `lock_usdc` step (EVM tx via `EvmPort`)
- [ ] Implement `poll_tx` step (confirmation polling via `EvmPort`)
- [ ] Implement `validate_on_onesec` step (Onesec `transfer_evm_to_icp`)
- [ ] Implement `poll_bridge` step (Onesec `get_transfer`)
- [ ] Implement `preflight` step (balance + fee checks)

### Phase 4: Host Integration (IC-Automaton)
- [ ] Implement `AutomatonEvmPort` and `AutomatonStoragePort`
- [ ] Add `TopUpCycles` to `TaskKind` enum + scheduler dispatch
- [ ] Add trigger logic to `CheckCycles`
- [ ] Add `top_up_status` and `trigger_top_up` agent tools
- [ ] Add `TopUpConfig` fields to init args / `RuntimeSnapshot`
- [ ] Allocate `MemoryId::new(24)` for top-up state

### Phase 5: Testing & Hardening
- [ ] Unit tests for ABI encoding, principal encoding, CMC subaccount
- [ ] Integration test: mock `EvmPort` + mock `StoragePort`, drive full state machine
- [ ] End-to-end test on mainnet with 1 USDC
- [ ] Mainnet dry run with 5-10 USDC via `CheckCycles` trigger

---

## 13. Resolved Questions

1. ~~**KongSwap bridged-USDC pool**~~: Listed as token_id 465, symbol "USDC", ~$8.8K market cap. Multi-hop routing available.

2. ~~**Onesec lock function selectors**~~: `lock1(uint256,bytes32)` → `0x3455fccc`, `lock2(uint256,bytes32,bytes32)` → `0x00e76bdc`. Verified via `cast sig`.

3. ~~**Onesec fee levels**~~: Dynamic via `get_transfer_fees()`. Structure: `latestTransferFee + (amount × protocolFeeInPercent)`.

4. ~~**Minimum viable top-up**~~: ~5 USDC minimum, ~10 USDC recommended. 10 USDC → ~7T cycles net.

5. ~~**ICRC-2 support for bridged USDC**~~: Fully supported. Standard DFINITY ICRC ledger with `icrc2` feature flag.

---

## 14. Appendix: Alternative Forwarding Address Flow

Saves one ECDSA signing (~26B cycles) by using a single ERC-20 `transfer()` instead of `approve()` + `lock1()`:

```rust
// 1. Get forwarding address (cache after first call)
let fwd: String = onesec.get_forwarding_address(account).await?;

// 2. Single EVM tx: USDC.transfer(fwd, amount)  — selector: 0xa9059cbb

// 3. Notify: onesec.forward_evm_to_icp(...)
// 4. Poll: onesec.get_forwarding_status(...) until Forwarded
// 5. Validate: onesec.transfer_evm_to_icp(...) — same as direct flow
// 6. Continue: KongSwap → CMC (identical)
```

Trade-off: saves ~26B cycles but adds extra polling. Adopt once direct lock flow is proven stable.
