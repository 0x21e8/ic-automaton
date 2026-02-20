# High-Leverage Tools: Detailed Design

**Date:** 2026-02-20
**Status:** Draft
**Scope:** Detailed implementation design for the five highest-leverage tools that turn the agent from a demo loop into a functional on-chain actor.

## Table of Contents

1. [Tool 1: Threshold ECDSA Signing (`sign_with_ecdsa`)](#tool-1-threshold-ecdsa-signing)
2. [Tool 2: EVM Chain Read (`evm_read`)](#tool-2-evm-chain-read)
3. [Tool 3: EVM Transaction Broadcast (`broadcast_raw_tx`)](#tool-3-evm-transaction-broadcast)
4. [Tool 4: Agent Memory (`remember` / `recall`)](#tool-4-agent-memory)
5. [Tool 5: Bounded HTTP Fetch (`http_fetch`)](#tool-5-bounded-http-fetch)
6. [Cross-Cutting Concerns](#cross-cutting-concerns)
7. [Dependency Changes](#dependency-changes)
8. [Implementation Order](#implementation-order)

---

## Tool 1: Threshold ECDSA Signing

### Why First

Every on-chain action requires a signature. Without real threshold signing, the agent cannot construct transactions, prove identity, or interact with any contract. This tool unblocks tools 2–3.

### ICP Management Canister API

The canister calls two management canister methods:

- `ecdsa_public_key` — derive the canister's public key (called once at init, cached).
- `sign_with_ecdsa` — sign a 32-byte message hash (called per signing request).

### Key Decisions

- **Key name:** `"key_1"` on mainnet, `"dfx_test_key"` on local, `"test_key_1"` on testnet. Stored in `RuntimeSnapshot` as `ecdsa_key_name: String`.
- **Derivation path:** Single derivation path `vec![b"evm".to_vec()]` for all EVM operations. This produces one stable Ethereum address per canister.
- **Address caching:** The derived Ethereum address (`keccak256(uncompressed_pubkey[1..])[12..]`) is computed once at init/post_upgrade and cached in stable memory. No need to re-derive per turn.

### Cycle Cost

From the existing `cycle_admission.rs`:

```rust
// Already implemented:
#[cfg(target_arch = "wasm32")]
fn estimate_threshold_sign_cost(key_name: &str, ecdsa_curve: u32) -> Result<u128, String> {
    ic_cdk::api::cost_sign_with_ecdsa(key_name, ecdsa_curve)
        .map_err(|error| format!("..."))
}

// Host fallback (already implemented):
// ~26B cycles per signature on the fiduciary subnet
Ok(26_153_846_153)
```

Pre-flight affordability check pattern (same as OpenRouter adapter):

```rust
async fn sign_with_threshold_ecdsa(
    message_hash: &[u8; 32],
    key_name: &str,
    derivation_path: Vec<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let now_ns = current_time_ns();
    if !stable::can_run_survival_operation(&SurvivalOperationClass::ThresholdSign, now_ns) {
        return Err("signing blocked by survival policy".to_string());
    }

    // Pre-flight cycle check
    let operation = OperationClass::ThresholdSign {
        key_name: key_name.to_string(),
        ecdsa_curve: 0, // secp256k1
    };
    let estimated = estimate_operation_cost(&operation)?;
    let requirements = affordability_requirements(
        estimated,
        DEFAULT_SAFETY_MARGIN_BPS,
        DEFAULT_RESERVE_FLOOR_CYCLES,
    );

    let liquid = ic_cdk::api::canister_liquid_cycle_balance();
    if !can_afford(liquid, &requirements) {
        stable::record_survival_operation_failure(
            &SurvivalOperationClass::ThresholdSign,
            now_ns,
            stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_THRESHOLD_SIGN,
        );
        return Err(format!(
            "insufficient cycles for threshold sign: need {} liquid, have {}",
            requirements.required_cycles, liquid
        ));
    }

    // Actual management canister call
    let response = ic_cdk::management_canister::ecdsa::sign_with_ecdsa(
        &SignWithEcdsaArgs {
            message_hash: message_hash.to_vec(),
            derivation_path,
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name.to_string(),
            },
        },
    ).await.map_err(|e| format!("sign_with_ecdsa failed: {:?}", e))?;

    stable::record_survival_operation_success(&SurvivalOperationClass::ThresholdSign);
    Ok(response.signature)
}
```

### Public Key Derivation and Address Caching

Called once at `init` / `post_upgrade`:

```rust
async fn derive_and_cache_evm_address(key_name: &str) -> Result<String, String> {
    let response = ic_cdk::management_canister::ecdsa::ecdsa_public_key(
        &EcdsaPublicKeyArgs {
            canister_id: None, // self
            derivation_path: vec![b"evm".to_vec()],
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name.to_string(),
            },
        },
    ).await.map_err(|e| format!("ecdsa_public_key failed: {:?}", e))?;

    // SEC1 uncompressed public key is 65 bytes (0x04 || x || y)
    let pubkey_bytes = &response.public_key;
    if pubkey_bytes.len() != 65 || pubkey_bytes[0] != 0x04 {
        return Err("unexpected public key format".to_string());
    }

    // Ethereum address = last 20 bytes of keccak256(pubkey[1..65])
    // Use ic_crypto_sha3 or manual Keccak-256
    let hash = keccak256(&pubkey_bytes[1..]);
    let address_bytes = &hash[12..32];
    let address = format!("0x{}", hex::encode(address_bytes));

    stable::set_evm_address(&address);
    Ok(address)
}
```

### Tool Schema (Exposed to LLM)

```json
{
  "name": "sign_message",
  "description": "Sign a message hash with the canister's threshold ECDSA key. Returns the signature as a hex string.",
  "parameters": {
    "type": "object",
    "properties": {
      "message_hash": {
        "type": "string",
        "description": "The 32-byte hash to sign, as a 0x-prefixed hex string"
      }
    },
    "required": ["message_hash"]
  }
}
```

### Edge Cases

| Case | Handling |
|---|---|
| Key not yet derived (first install) | Queue signing requests; derive key in init via `spawn`. Reject sign calls until address is cached. |
| Signature response exceeds canister memory | Not possible — ECDSA signature is always 64 bytes. |
| Management canister temporarily unavailable | Return error, survival backoff kicks in (existing mechanism). |
| Concurrent sign requests in same turn | ToolManager already enforces `max_calls_per_turn: 3`. Each call is sequential within the turn. |
| Invalid hex in `message_hash` arg | Validate before calling management canister. Return tool error, don't waste cycles. |
| Key rotation / different derivation paths | Out of scope for v1. Single derivation path, single address. |

### Changes Required

- **New file:** `src/features/threshold_signer.rs` — real `SignerAdapter` implementation.
- **Modify:** `src/features/signer.rs` — add `ThresholdSignerAdapter` implementing existing `SignerPort` trait.
- **Modify:** `src/agent.rs` — replace `MockSignerAdapter::new()` with conditional real/mock based on config.
- **Modify:** `src/domain/types.rs` — add `ecdsa_key_name: String` and `evm_address: Option<String>` to `RuntimeSnapshot`.
- **Modify:** `src/storage/stable.rs` — add `set_evm_address` / `get_evm_address` helpers.
- **Note:** The `SignerPort` trait is currently synchronous (`fn sign_message(&self, message: &str) -> Result<String, String>`). The real implementation needs `async`. This requires making the trait async or wrapping the management canister call. Since `ToolManager::execute_actions` is synchronous today, **this is the key architectural change** — tool execution must become async. See [Cross-Cutting: Async Tool Execution](#async-tool-execution).

### Async Tool Execution

The current `ToolManager::execute_actions` is synchronous. Threshold signing requires an inter-canister call, which is async. Two options:

**Option A (Recommended): Make `execute_actions` async.**

```rust
#[async_trait(?Send)]
pub trait SignerPort {
    async fn sign_message(&self, message_hash: &str) -> Result<String, String>;
}

// ToolManager becomes:
pub async fn execute_actions(
    &mut self,
    state: &AgentState,
    calls: &[ToolCall],
    signer: &dyn SignerPort,
    turn_id: &str,
) -> Vec<ToolCallRecord> {
    let mut records = Vec::new();
    for call in calls {
        // ... policy checks (same as today) ...
        let result = match call.tool.as_str() {
            "sign_message" => {
                // ... survival check ...
                signer.sign_message(&call.args_json).await
            }
            // ...
        };
        records.push(/* ... */);
    }
    records
}
```

This is straightforward because `run_scheduled_turn_job` is already async. The mock adapter's `sign_message` becomes an async fn that returns immediately.

**Option B: Two-phase execution (plan sync, execute async).**

More complex. Not recommended for the current tool count. Revisit if tool count exceeds ~10 and some tools are pure-sync.

---

## Tool 2: EVM Chain Read

### Purpose

Replace `MockEvmPoller` with real EVM JSON-RPC calls to observe on-chain state. This is the agent's sensory input.

### RPC Strategy: Direct HTTPS Outcalls

After research, the approach is **direct HTTPS outcalls** to Base mainnet public RPC endpoints:

| Endpoint | Auth Required | Rate Limit | Notes |
|---|---|---|---|
| `https://mainnet.base.org` | No | Undisclosed, low | Official Coinbase/Base. Dev/testing only. |
| `https://base.publicnode.com` | No | Moderate | PublicNode free tier. |
| `https://base-rpc.publicnode.com` | No | Moderate | Alternative PublicNode. |
| `https://1rpc.io/base` | No | Moderate | 1RPC privacy-preserving. |

**Why not the EVM RPC canister:** The EVM RPC canister (`7hfb6-caaaa-aaaar-qadga-cai`) adds an inter-canister hop, which costs additional cycles and adds latency. For a single-chain read-only use case with no consensus requirement (the agent is non-replicated for reads anyway via `is_replicated: Some(false)`), direct HTTPS outcalls are simpler and cheaper. The EVM RPC canister becomes valuable when you need multi-provider consensus or multi-chain, which is out of scope for Base-only v1.

**Fallback strategy:** Configure a primary and secondary RPC URL in `RuntimeSnapshot`. If primary fails, try secondary. Both are configurable at runtime via update call.

### RPC Methods Needed

| Method | Purpose | Response Size | Frequency |
|---|---|---|---|
| `eth_getLogs` | Poll for contract events | Variable, can be large | Every agent turn (~30s) |
| `eth_blockNumber` | Get latest block for cursor | ~100 bytes | Every poll |
| `eth_getBalance` | Check agent's ETH balance | ~100 bytes | On demand (tool) |
| `eth_call` | Read contract state | Variable | On demand (tool) |

### Architecture

Two distinct capabilities built on the same HTTP adapter:

1. **Internal poller** (replaces `MockEvmPoller`) — runs every turn as part of the agent loop. Not a tool. Uses `eth_blockNumber` + `eth_getLogs`.
2. **`evm_read` tool** — model-invokable for on-demand queries (`eth_getBalance`, `eth_call`). Exposed to LLM.

### Internal Poller Implementation

```rust
pub struct HttpEvmPoller {
    rpc_url: String,
    fallback_rpc_url: Option<String>,
    max_response_bytes: u64,
    max_logs_per_poll: usize,
}

impl HttpEvmPoller {
    pub async fn poll(&self, cursor: &EvmPollCursor) -> Result<EvmPollResult, String> {
        let now_ns = current_time_ns();
        // Cycle affordability check
        let operation = OperationClass::HttpOutcall {
            request_size_bytes: 512, // eth_getLogs request is small
            max_response_bytes: self.max_response_bytes,
        };
        let estimated = estimate_operation_cost(&operation)?;
        let requirements = affordability_requirements(
            estimated,
            DEFAULT_SAFETY_MARGIN_BPS,
            DEFAULT_RESERVE_FLOOR_CYCLES,
        );
        let liquid = canister_liquid_cycle_balance();
        if !can_afford(liquid, &requirements) {
            return Err("insufficient cycles for EVM poll".to_string());
        }

        // Step 1: Get latest block number
        let latest_block = self.eth_block_number().await?;

        // Don't poll ahead of chain tip. Cap range to avoid huge responses.
        let from_block = cursor.next_block;
        let to_block = latest_block.min(from_block.saturating_add(1000));

        if from_block > to_block {
            return Ok(EvmPollResult {
                cursor: cursor.clone(),
                events: vec![],
            });
        }

        // Step 2: Get logs
        let logs = self.eth_get_logs(cursor.chain_id, from_block, to_block).await?;

        let events: Vec<EvmEvent> = logs.iter().enumerate().map(|(i, log)| {
            EvmEvent {
                chain_id: cursor.chain_id,
                block_number: log.block_number,
                log_index: log.log_index,
                source: format!("0x{}", hex::encode(&log.address)),
                payload: format!("0x{}", hex::encode(&log.data)),
            }
        }).collect();

        Ok(EvmPollResult {
            cursor: EvmPollCursor {
                chain_id: cursor.chain_id,
                next_block: to_block.saturating_add(1),
                next_log_index: 0,
            },
            events,
        })
    }

    async fn eth_block_number(&self) -> Result<u64, String> {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        })).map_err(|e| format!("json serialize failed: {e}"))?;

        let response = self.http_post(&body, 256).await?;
        // Parse hex block number from {"result": "0x..."}
        parse_hex_u64_result(&response)
    }

    async fn eth_get_logs(
        &self,
        chain_id: u64,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<RpcLog>, String> {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [{
                "fromBlock": format!("0x{:x}", from_block),
                "toBlock": format!("0x{:x}", to_block),
                // No address/topic filter initially — poll everything.
                // TODO: Add configurable address + topic filters.
            }],
            "id": 1
        })).map_err(|e| format!("json serialize failed: {e}"))?;

        let response = self.http_post(&body, self.max_response_bytes).await?;
        parse_logs_result(&response)
    }

    async fn http_post(
        &self,
        body: &[u8],
        max_response_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        let request = HttpRequestArgs {
            url: self.rpc_url.clone(),
            max_response_bytes: Some(max_response_bytes),
            method: HttpMethod::POST,
            headers: vec![HttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: Some(body.to_vec()),
            transform: None,
            is_replicated: Some(false),
        };

        let result = http_request(&request).await
            .map_err(|e| format!("EVM RPC outcall failed: {e}"))?;

        let status = nat_to_u16(&result.status)?;
        if !(200..300).contains(&status) {
            // Try fallback
            if let Some(fallback_url) = &self.fallback_rpc_url {
                let fallback_request = HttpRequestArgs {
                    url: fallback_url.clone(),
                    ..request
                };
                let fallback_result = http_request(&fallback_request).await
                    .map_err(|e| format!("EVM RPC fallback outcall failed: {e}"))?;
                return Ok(fallback_result.body);
            }
            return Err(format!("EVM RPC returned status {status}"));
        }
        Ok(result.body)
    }
}
```

### `evm_read` Tool (LLM-Invokable)

```json
{
  "name": "evm_read",
  "description": "Read on-chain state from Base. Supports eth_getBalance and eth_call.",
  "parameters": {
    "type": "object",
    "properties": {
      "method": {
        "type": "string",
        "enum": ["eth_getBalance", "eth_call"],
        "description": "The JSON-RPC method to call"
      },
      "address": {
        "type": "string",
        "description": "The 0x-prefixed address to query"
      },
      "calldata": {
        "type": "string",
        "description": "For eth_call only: the 0x-prefixed ABI-encoded call data"
      }
    },
    "required": ["method", "address"]
  }
}
```

### Cycle Costs for EVM Reads

Using the existing `estimate_http_outcall` formula:

```
Cost = (3_000_000 + 60_000 * N) * N + (400 * req_size + 800 * resp_size) * N
where N = subnet_size (13 for non-replicated)
```

| Operation | Request ~bytes | Max Response bytes | Estimated cycles |
|---|---|---|---|
| `eth_blockNumber` | 100 | 256 | ~60M cycles (~0.06B) |
| `eth_getLogs` (small) | 256 | 65,536 (64KB) | ~730M cycles (~0.73B) |
| `eth_getLogs` (large) | 256 | 2,097,152 (2MB) | ~22B cycles |
| `eth_getBalance` | 150 | 256 | ~60M cycles |
| `eth_call` | 512 | 4,096 | ~95M cycles |

**Key constraint:** `eth_getLogs` response size is unpredictable. Use conservative `max_response_bytes`:
- Default: 65,536 (64KB) — handles ~50 log entries.
- If response is truncated, narrow the block range and retry with smaller window.
- Hard cap: 2MB (matches ICP outcall response limit and existing `openrouter_max_response_bytes` pattern).

### Edge Cases

| Case | Handling |
|---|---|
| RPC returns empty logs for range | Normal — no events, cursor advances. |
| RPC returns error (rate limited) | Try fallback URL. If both fail, return error, survival backoff via `EvmPoll` class. |
| Response truncated (logs too large) | Detect via JSON parse failure or partial response. Halve block range and retry once. If still fails, return partial and advance cursor to avoid stuck polling. |
| Chain reorg (block reorganization) | For v1, ignore. Cursor always advances. Future: track finalized blocks only. |
| Poller falls far behind chain tip | Cap catch-up to 1000 blocks per poll. Will catch up over multiple turns. |
| No filter configured (all logs) | Very expensive on busy chains. For v1, require at least an address filter in config. Default to monitoring the agent's own EVM address. |
| `eth_call` with invalid calldata | Validate hex format before sending. Return tool error if malformed. |

### Changes Required

- **Modify:** `src/features/evm.rs` — add `HttpEvmPoller` implementing the existing `EvmPoller` trait. The trait must become async.
- **Modify:** `src/agent.rs` — replace `MockEvmPoller` with `HttpEvmPoller` when configured.
- **Modify:** `src/domain/types.rs` — add `evm_rpc_url`, `evm_rpc_fallback_url`, `evm_rpc_max_response_bytes` to `RuntimeSnapshot`.
- **New fields in stable memory:** RPC URLs, log filter addresses, max response bytes.

### Making EvmPoller Async

The current `EvmPoller` trait is synchronous:

```rust
pub trait EvmPoller {
    fn poll(&self, cursor: &EvmPollCursor) -> Result<EvmPollResult, String>;
}
```

Must become:

```rust
#[async_trait(?Send)]
pub trait EvmPoller {
    async fn poll(&self, cursor: &EvmPollCursor) -> Result<EvmPollResult, String>;
}
```

This propagates to `run_scheduled_turn_job`, which is already async — clean change.

---

## Tool 3: EVM Transaction Broadcast

### Purpose

Submit signed raw transactions to the Base network. This is the agent's primary mutating action on-chain.

### Dependencies

Requires Tool 1 (signing) to produce signatures, and `alloy-primitives` + `alloy-rlp` for transaction encoding.

### Transaction Construction Flow

```
1. Agent decides to send a transaction (via LLM tool call)
2. Build unsigned transaction: {to, value, data, nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas, chain_id}
3. RLP-encode the unsigned transaction (EIP-1559 type 2)
4. Hash the RLP-encoded transaction (keccak256)
5. Sign the hash with threshold ECDSA (Tool 1)
6. Reconstruct signed transaction: RLP-encode with v, r, s
7. Broadcast via eth_sendRawTransaction
```

### Why alloy-primitives + alloy-rlp

- `alloy-primitives` provides `Address`, `U256`, `Bytes`, `FixedBytes`, `keccak256` — all no_std compatible.
- `alloy-rlp` provides `Encodable`/`Decodable` traits for RLP serialization.
- Both are no_std / wasm32-compatible.
- Combined ~200KB Wasm size increase (acceptable — current canister is small).
- Avoids reimplementing RLP encoding, which is error-prone and security-critical.

### Tool Schema

The LLM should NOT construct raw transactions. Instead, expose a higher-level tool:

```json
{
  "name": "send_eth",
  "description": "Send ETH to an address on Base. The canister handles nonce, gas estimation, signing, and broadcast.",
  "parameters": {
    "type": "object",
    "properties": {
      "to": {
        "type": "string",
        "description": "Destination address (0x-prefixed, 20 bytes)"
      },
      "value_wei": {
        "type": "string",
        "description": "Amount to send in wei (decimal string)"
      },
      "data": {
        "type": "string",
        "description": "Optional calldata for contract interaction (0x-prefixed hex). Omit for plain ETH transfer."
      }
    },
    "required": ["to", "value_wei"]
  }
}
```

### Internal Implementation

```rust
pub async fn build_and_send_transaction(
    to: Address,
    value: U256,
    data: Bytes,
    rpc: &HttpEvmRpc,
    key_name: &str,
) -> Result<String, String> {
    // Step 1: Get nonce
    let nonce = rpc.eth_get_transaction_count(
        &stable::get_evm_address().ok_or("EVM address not derived yet")?,
    ).await?;

    // Step 2: Estimate gas (or use safe defaults)
    let gas_limit = if data.is_empty() { 21_000u64 } else {
        rpc.eth_estimate_gas(&to, &value, &data).await?
            .saturating_mul(120).checked_div(100) // 20% buffer
            .unwrap_or(21_000)
    };

    // Step 3: Get gas price
    let (max_fee, max_priority_fee) = rpc.fee_history_based_gas_price().await?;

    // Step 4: Build unsigned EIP-1559 transaction
    let tx = Eip1559Transaction {
        chain_id: 8453,
        nonce,
        max_priority_fee_per_gas: max_priority_fee,
        max_fee_per_gas: max_fee,
        gas_limit,
        to,
        value,
        data,
        access_list: vec![],
    };

    // Step 5: RLP-encode and hash
    let mut rlp_buf = Vec::new();
    rlp_buf.push(0x02); // EIP-1559 type prefix
    tx.rlp_encode(&mut rlp_buf);
    let tx_hash = keccak256(&rlp_buf);

    // Step 6: Sign
    let signature = sign_with_threshold_ecdsa(
        tx_hash.as_ref().try_into().map_err(|_| "hash length mismatch")?,
        key_name,
        vec![b"evm".to_vec()],
    ).await?;

    // Step 7: Recover v from signature + compute signed RLP
    let (r, s, v) = decode_ecdsa_signature(&signature, &tx_hash, &get_cached_pubkey()?)?;

    let mut signed_rlp = Vec::new();
    signed_rlp.push(0x02);
    tx.rlp_encode_signed(r, s, v, &mut signed_rlp);

    // Step 8: Broadcast
    let tx_hash = rpc.eth_send_raw_transaction(&signed_rlp).await?;
    Ok(tx_hash)
}
```

### Cycle Budget for a Complete Transaction

| Step | Estimated Cycles |
|---|---|
| `eth_getTransactionCount` (nonce) | ~60M |
| `eth_estimateGas` | ~60M |
| `eth_feeHistory` (gas price) | ~60M |
| `sign_with_ecdsa` | ~26B |
| `eth_sendRawTransaction` | ~60M |
| **Total** | **~26.3B cycles** |

Threshold signing dominates. A transaction costs ~26B cycles (~$0.035 USD at current ICP price). The pre-flight affordability check must account for the full workflow, not individual steps:

```rust
fn estimate_full_transaction_cost(key_name: &str) -> Result<u128, String> {
    let sign_cost = estimate_operation_cost(&OperationClass::ThresholdSign {
        key_name: key_name.to_string(),
        ecdsa_curve: 0,
    })?;
    // 4 HTTP outcalls at ~60M each
    let http_cost = 4 * estimate_operation_cost(&OperationClass::HttpOutcall {
        request_size_bytes: 512,
        max_response_bytes: 4096,
    })?;
    Ok(sign_cost.saturating_add(http_cost))
}
```

### Edge Cases

| Case | Handling |
|---|---|
| Nonce too low (tx already sent) | Retry with fresh nonce once. If still fails, return error. |
| Gas estimation fails | Fall back to `gas_limit = 100_000` for simple transfers, `300_000` for contract calls. |
| Insufficient ETH balance | Check balance before broadcasting. Return clear error to LLM. |
| Transaction reverts on-chain | Not detectable at broadcast time. `eth_sendRawTransaction` returns tx hash even for eventually-reverting txs. Inform LLM that broadcast succeeded but execution is not guaranteed. |
| Duplicate broadcast (idempotency) | Same signed tx broadcast twice → same tx hash, second is a no-op. Safe. |
| Recovery ID (v value) computation | Requires trying both v=0 and v=1 to find which recovers to our known public key. Use `ecrecover` locally or derive from signature format. |
| Signature malleability | ICP threshold signatures produce canonical low-s signatures. No additional normalization needed. |

### Changes Required

- **New file:** `src/features/evm_rpc.rs` — HTTP-based EVM JSON-RPC client.
- **New file:** `src/features/evm_tx.rs` — transaction construction and signing orchestration.
- **Modify:** `src/tools.rs` — add `send_eth` tool, make `execute_actions` async.
- **Modify:** `Cargo.toml` — add `alloy-primitives` and `alloy-rlp`.

---

## Tool 4: Agent Memory

### Purpose

Give the agent persistent memory across turns. Without this, every turn starts with zero context beyond the inbox/EVM events of that turn. The agent cannot track balances, remember strategies, or accumulate knowledge.

### Design: Key-Value Fact Store

Simple `StableBTreeMap<String, MemoryFact>` keyed by a human-readable fact key.

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MemoryFact {
    pub key: String,
    pub value: String,
    pub created_at_ns: u64,
    pub updated_at_ns: u64,
    pub source_turn_id: String,
}
```

**Stable memory:** New `StableBTreeMap` at `MemoryId::new(16)`.

### Tool Schemas

**`remember`** — Store or update a fact.

```json
{
  "name": "remember",
  "description": "Store a fact in persistent memory. If the key already exists, the value is overwritten.",
  "parameters": {
    "type": "object",
    "properties": {
      "key": {
        "type": "string",
        "description": "A short, descriptive key for the fact (e.g., 'my_eth_balance', 'target_price_ETH', 'strategy')"
      },
      "value": {
        "type": "string",
        "description": "The fact value to store"
      }
    },
    "required": ["key", "value"]
  }
}
```

**`recall`** — Retrieve facts by prefix or list all.

```json
{
  "name": "recall",
  "description": "Retrieve stored facts from persistent memory. Returns all facts matching the key prefix, or all facts if no prefix given.",
  "parameters": {
    "type": "object",
    "properties": {
      "prefix": {
        "type": "string",
        "description": "Optional key prefix to filter facts. Omit to return all stored facts."
      }
    },
    "required": []
  }
}
```

### Implementation

```rust
const MAX_FACTS: usize = 500;
const MAX_KEY_BYTES: usize = 128;
const MAX_VALUE_BYTES: usize = 4096;

pub fn remember_fact(key: &str, value: &str, turn_id: &str) -> Result<String, String> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(format!("key must be 1-{MAX_KEY_BYTES} bytes"));
    }
    if value.len() > MAX_VALUE_BYTES {
        return Err(format!("value must be at most {MAX_VALUE_BYTES} bytes"));
    }

    let now_ns = current_time_ns();
    let existing = stable::get_memory_fact(key);
    let fact = MemoryFact {
        key: key.to_string(),
        value: value.to_string(),
        created_at_ns: existing.map(|f| f.created_at_ns).unwrap_or(now_ns),
        updated_at_ns: now_ns,
        source_turn_id: turn_id.to_string(),
    };

    // Enforce max facts limit (only on insert, not update)
    if existing.is_none() && stable::memory_fact_count() >= MAX_FACTS {
        return Err(format!("memory full: max {MAX_FACTS} facts"));
    }

    stable::set_memory_fact(&fact);
    Ok(format!("stored: {key}"))
}

pub fn recall_facts(prefix: &str) -> Result<String, String> {
    let facts = if prefix.is_empty() {
        stable::list_all_memory_facts(50) // cap output
    } else {
        stable::list_memory_facts_by_prefix(prefix, 50)
    };

    if facts.is_empty() {
        return Ok("no facts found".to_string());
    }

    let formatted: Vec<String> = facts.iter().map(|f| {
        format!("{}={}", f.key, f.value)
    }).collect();

    Ok(formatted.join("\n"))
}
```

### Context Injection

On each turn, automatically inject a summary of stored facts into the inference context:

```rust
// In run_scheduled_turn_job, before inference:
let memory_facts = stable::list_all_memory_facts(20); // top 20 most recent
let memory_context = if memory_facts.is_empty() {
    String::new()
} else {
    let facts_str: Vec<String> = memory_facts.iter()
        .map(|f| format!("  {}={}", f.key, f.value))
        .collect();
    format!("\n[memory]\n{}", facts_str.join("\n"))
};

// Append to context_snippet
let context_summary = format!(
    "inbox_messages:{staged_message_count};evm_events:{evm_events}{memory_context};inbox_preview:{inbox_preview}"
);
```

### Edge Cases

| Case | Handling |
|---|---|
| Key collision between turns | Last writer wins. `updated_at_ns` tracks when. |
| Memory fills up (500 facts) | Return error on new inserts. Agent must `forget` old facts first. |
| Very long values | Hard cap at 4KB per value. Reject at tool level. |
| Recall returns too many facts | Cap at 50 facts per recall. Prefix filtering helps narrow. |
| Memory injection bloats inference context | Cap auto-injected facts to 20 most recent. Full recall available via tool. |
| Unicode / special characters in keys | Allow but normalize: trim whitespace, lowercase. Reject control characters. |

### Cycle Cost

Zero — this is a pure stable memory operation. No inter-canister calls, no HTTP outcalls. The only cost is Wasm execution cycles for StableBTreeMap operations (negligible, ~1M cycles per read/write).

### Changes Required

- **Modify:** `src/storage/stable.rs` — add `MEMORY_FACTS_MAP` at `MemoryId::new(16)`, with get/set/list/count helpers.
- **Modify:** `src/tools.rs` — add `remember` and `recall` tool handlers.
- **Modify:** `src/agent.rs` — inject memory context before inference.
- **Modify:** `src/features/inference.rs` — add `remember` and `recall` to tool schemas for both IcLlm and OpenRouter adapters.
- **Add `forget` tool** — optional, allows the agent to delete facts. Simple delete from StableBTreeMap.

---

## Tool 5: Bounded HTTP Fetch

### Purpose

Allow the agent to fetch external data (price feeds, API responses, web pages) beyond on-chain state. Tightly scoped with domain allowlists.

### Security Model

**Never expose a generic HTTP tool to the model.** Instead:

- Maintain a **domain allowlist** in stable memory.
- Only `GET` requests. No `POST`, no auth headers.
- Strict `max_response_bytes` cap.
- Model specifies URL; runtime validates domain against allowlist before fetching.

### Tool Schema

```json
{
  "name": "http_fetch",
  "description": "Fetch data from an allowed external URL via HTTPS GET. Only domains in the allowlist are permitted.",
  "parameters": {
    "type": "object",
    "properties": {
      "url": {
        "type": "string",
        "description": "The HTTPS URL to fetch. Must be on an allowed domain."
      }
    },
    "required": ["url"]
  }
}
```

### Domain Allowlist

```rust
// Default allowlist — configurable via update call
const DEFAULT_ALLOWED_DOMAINS: &[&str] = &[
    "api.coingecko.com",
    "api.coinbase.com",
    "min-api.cryptocompare.com",
    "base.blockscout.com",
    "basescan.org",
];

fn is_domain_allowed(url: &str) -> Result<bool, String> {
    let parsed = url.strip_prefix("https://")
        .ok_or("only HTTPS URLs are allowed")?;
    let host = parsed.split('/').next()
        .ok_or("could not parse host")?;
    let host = host.split(':').next().unwrap_or(host); // strip port

    let allowed = stable::list_allowed_http_domains();
    Ok(allowed.iter().any(|domain| {
        host == *domain || host.ends_with(&format!(".{domain}"))
    }))
}
```

### Implementation

```rust
pub async fn http_fetch_tool(url: &str) -> Result<String, String> {
    // Validate domain
    if !is_domain_allowed(url)? {
        return Err(format!("domain not in allowlist: {url}"));
    }

    let max_response_bytes: u64 = 65_536; // 64KB cap

    // Cycle affordability check
    let operation = OperationClass::HttpOutcall {
        request_size_bytes: url.len() as u64 + 128, // headers overhead
        max_response_bytes,
    };
    let estimated = estimate_operation_cost(&operation)?;
    let requirements = affordability_requirements(
        estimated,
        DEFAULT_SAFETY_MARGIN_BPS,
        DEFAULT_RESERVE_FLOOR_CYCLES,
    );
    let liquid = ic_cdk::api::canister_liquid_cycle_balance();
    if !can_afford(liquid, &requirements) {
        return Err("insufficient cycles for HTTP fetch".to_string());
    }

    let request = HttpRequestArgs {
        url: url.to_string(),
        max_response_bytes: Some(max_response_bytes),
        method: HttpMethod::GET,
        headers: vec![],
        body: None,
        transform: None,
        is_replicated: Some(false),
    };

    let response = http_request(&request).await
        .map_err(|e| format!("HTTP fetch failed: {e}"))?;

    let status = nat_to_u16(&response.status)?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status} from {url}"));
    }

    let body = String::from_utf8(response.body)
        .unwrap_or_else(|_| "binary response (not UTF-8)".to_string());

    // Truncate to avoid blowing up inference context
    let max_chars = 8_000;
    if body.len() > max_chars {
        Ok(format!("{}... [truncated, {} total bytes]", &body[..max_chars], body.len()))
    } else {
        Ok(body)
    }
}
```

### Edge Cases

| Case | Handling |
|---|---|
| URL not HTTPS | Reject — HTTPS only. |
| Domain not in allowlist | Reject with clear error listing the requested domain. |
| Response too large | `max_response_bytes` caps at 64KB. IC truncates at the outcall level. |
| Response not UTF-8 (binary) | Return a placeholder message. Don't try to interpret binary as text. |
| Redirect (301/302) | ICP HTTPS outcalls do not follow redirects. Return error with the redirect URL for the model to retry. |
| DNS failure / timeout | Return the IC error message. Survival backoff is NOT applied (this is a tool, not a core subsystem). |
| Model tries to exfiltrate data via URL parameters | Domain allowlist limits targets. URL path/query are not restricted (needed for API calls). This is an acceptable risk for v1 with a tight allowlist. |
| Empty allowlist | All `http_fetch` calls return "no domains allowed". Tool is effectively disabled. |

### Changes Required

- **Modify:** `src/storage/stable.rs` — add `HTTP_DOMAIN_ALLOWLIST_MAP` at `MemoryId::new(17)`, with list/add/remove helpers.
- **Modify:** `src/tools.rs` — add `http_fetch` tool handler (async).
- **New update method:** `set_http_allowed_domains(Vec<String>)` for controller to manage allowlist.
- **Modify:** `src/features/inference.rs` — add `http_fetch` to tool schemas.

---

## Cross-Cutting Concerns

### Async Tool Execution

**This is the single most impactful architectural change.** Today, `ToolManager::execute_actions` is synchronous. Tools 1, 2, 3, and 5 all require async (inter-canister calls or HTTPS outcalls).

**Migration plan:**

1. Make `SignerPort` trait async (`#[async_trait(?Send)]`).
2. Make `EvmBroadcastPort` trait async.
3. Make `ToolManager::execute_actions` async.
4. Update `MockSignerAdapter` and `MockEvmBroadcastAdapter` — trivial, just add `async` keyword.
5. All tests that call `execute_actions` need the async block_on wrapper (already exists in `agent.rs` tests).

This is a one-time breaking change that unblocks all future tools.

### Tool Execution Budget Per Turn

With 5+ tools, the total cycle budget per turn needs a cap:

```rust
const MAX_CYCLES_PER_TURN: u128 = 50_000_000_000; // 50B cycles

// Before each tool execution in ToolManager:
fn check_turn_budget(&self, tool: &str) -> Result<(), String> {
    let spent = self.cycles_spent_this_turn;
    if spent >= MAX_CYCLES_PER_TURN {
        return Err(format!(
            "turn cycle budget exhausted: spent {} of {} max",
            spent, MAX_CYCLES_PER_TURN
        ));
    }
    Ok(())
}
```

### Updated Tool Registry

After all five tools, the `ToolManager::new()` policies become:

| Tool | Max/Turn | Allowed States | Survival Class | Async |
|---|---|---|---|---|
| `sign_message` | 3 | ExecutingActions | ThresholdSign | Yes |
| `send_eth` | 1 | ExecutingActions | ThresholdSign + EvmBroadcast | Yes |
| `evm_read` | 3 | ExecutingActions, Inferring | EvmPoll | Yes |
| `record_signal` | 5 | ExecutingActions, Inferring | None | No |
| `remember` | 5 | ExecutingActions, Inferring | None | No |
| `recall` | 3 | ExecutingActions, Inferring | None | No |
| `http_fetch` | 2 | ExecutingActions | None (but cycle-gated) | Yes |

### Updated Inference Tool Schemas

Both IcLlm and OpenRouter adapters must advertise all tools. Extract tool schema generation into a shared function:

```rust
fn agent_tool_schemas() -> Vec<ToolSchema> {
    vec![
        sign_message_schema(),
        send_eth_schema(),
        evm_read_schema(),
        record_signal_schema(),
        remember_schema(),
        recall_schema(),
        http_fetch_schema(),
    ]
}
```

### Stable Memory Layout After Changes

| MemoryId | Purpose | Status |
|---|---|---|
| 0–15 | Existing maps | Unchanged |
| 16 | `MEMORY_FACTS_MAP` (agent memory) | New |
| 17 | `HTTP_DOMAIN_ALLOWLIST_MAP` | New |

### New `RuntimeSnapshot` Fields

```rust
pub struct RuntimeSnapshot {
    // ... existing fields ...

    // Tool 1: Signing
    pub ecdsa_key_name: String,         // "key_1", "dfx_test_key", etc.
    pub evm_address: Option<String>,    // Cached derived address

    // Tool 2: EVM Read
    pub evm_rpc_url: String,            // Primary RPC endpoint
    pub evm_rpc_fallback_url: Option<String>,
    pub evm_rpc_max_response_bytes: u64,

    // Tool 5: HTTP Fetch (allowlist is separate StableBTreeMap)
}
```

---

## Dependency Changes

Add to `Cargo.toml`:

```toml
[dependencies]
# ... existing ...
alloy-primitives = { version = "0.8", default-features = false, features = ["rlp"] }
alloy-rlp = { version = "0.3", default-features = false }
hex = { version = "0.4", default-features = false, features = ["alloc"] }
```

**Why `default-features = false`:** Minimizes Wasm size. `alloy-primitives` has optional `std`, `serde`, `arbitrary` features we don't need. The `rlp` feature gives us `Encodable`/`Decodable` for primitives.

**Wasm size impact estimate:** ~200KB increase (alloy-primitives is well-optimized for no_std/wasm targets).

**Note:** `keccak256` is included in `alloy-primitives`. No separate keccak crate needed.

---

## Implementation Order

[x] Phase 1: Async foundation + signing (unblocks everything)
- [x] 1a. Make `SignerPort`, `EvmBroadcastPort`, `EvmPoller` traits async
- [x] 1b. Make `ToolManager::execute_actions` async
- [x] 1c. Update all mocks and tests
- [x] 1d. Implement `ThresholdSignerAdapter` (`sign_with_ecdsa`)
- [x] 1e. Add `ecdsa_key_name` config + derive/cache EVM address during startup execution
- [x] 1f. Wire real signer into `agent.rs` (conditional on config)

[x] Phase 2: EVM reads (gives the agent eyes)
- [x] 2a. Add `alloy-primitives`, `alloy-rlp`, `hex` to `Cargo.toml`
- [x] 2b. Implement `HttpEvmPoller` (`eth_blockNumber` + `eth_getLogs`)
- [x] 2c. Add `evm_rpc_url` config fields to `RuntimeSnapshot`
- [x] 2d. Wire `HttpEvmPoller` into `agent.rs` (replacing `MockEvmPoller`)
- [x] 2e. Implement `evm_read` tool (`eth_getBalance`, `eth_call`)
- [x] 2f. Add `evm_read` to inference tool schemas

[x] Phase 3: Transaction broadcast (gives the agent hands)
- [x] 3a. Implement EIP-1559 transaction construction with alloy types
- [x] 3b. Implement `send_eth` tool (nonce, gas, sign, broadcast)
- [x] 3c. Add full-workflow cycle budget estimation
- [x] 3d. Add `send_eth` to inference tool schemas

[ ] Phase 4: Agent memory (gives the agent a brain)
- [ ] 4a. Add `MEMORY_FACTS_MAP` to stable storage (`MemoryId::new(16)`)
- [ ] 4b. Implement `remember` / `recall` / `forget` tools
- [ ] 4c. Add memory context injection in `agent.rs`
- [ ] 4d. Add memory tools to inference tool schemas

[ ] Phase 5: HTTP fetch (gives the agent broader awareness)
- [ ] 5a. Add `HTTP_DOMAIN_ALLOWLIST_MAP` to stable storage (`MemoryId::new(17)`)
- [ ] 5b. Implement `http_fetch` tool with domain validation
- [ ] 5c. Add `set_http_allowed_domains` update method
- [ ] 5d. Add `http_fetch` to inference tool schemas

Each phase is independently deployable. Phase 1 is the only one that requires a structural refactor (async traits). Phases 2–5 are additive.

---

## Research References

- [ICP threshold ECDSA signing](https://docs.internetcomputer.org/building-apps/chain-fusion/signatures/t-ecdsa/making-transactions)
- [ICP HTTPS outcalls](https://docs.internetcomputer.org/building-apps/interact-with-external-services/https-outcalls/overview)
- [ICP EVM RPC canister](https://docs.internetcomputer.org/building-apps/chain-fusion/ethereum/evm-rpc/overview)
- [Base mainnet public RPC](https://docs.base.org/base-chain/tools/node-providers)
- [alloy-primitives crate](https://docs.rs/alloy-primitives)
- [alloy-rlp crate](https://docs.rs/alloy-rlp)
- [EIP-1559 transaction format](https://eips.ethereum.org/EIPS/eip-1559)
- [ICP cycles cost formulas](https://docs.internetcomputer.org/docs/references/cycles-cost-formulas)
