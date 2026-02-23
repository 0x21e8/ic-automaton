# Inter-Canister Call Tool: Detailed Design

**Date:** 2026-02-22
**Status:** Draft
**Scope:** Design a generic inter-canister call tool with principal+method allowlists that enables the agent to interact with ICP ledgers, the management canister, DEX canisters, and other IC services.

## Table of Contents

1. [Motivation](#motivation)
2. [Architecture](#architecture)
3. [Tool Schema](#tool-schema)
4. [Allowlist Design](#allowlist-design)
5. [Candid Encoding Bridge](#candid-encoding-bridge)
6. [Use Case Analysis](#use-case-analysis)
7. [Gaps and Open Issues](#gaps-and-open-issues)
8. [Cycle Costs](#cycle-costs)
9. [Edge Cases](#edge-cases)
10. [Changes Required](#changes-required)
11. [Implementation Order](#implementation-order)

---

## Motivation

The agent currently has no way to call other ICP canisters beyond the LLM canister (hardcoded in `inference.rs`) and the management canister for threshold signing (hardcoded in `threshold_signer.rs`). To become a fully autonomous on-chain actor, the agent needs to:

- Transfer ICP and ICRC tokens (pay for services, manage treasury)
- Query canister status and cycle balances (monitor infrastructure)
- Interact with DEX canisters for token swaps (execute the USDC→cycles path)
- Read state from arbitrary canisters (discover services, verify contracts)

A generic tool with strict allowlists provides maximum flexibility while keeping the attack surface bounded by configuration rather than code changes.

---

## Architecture

### Why Generic Over Typed

The TOOL_CALL_ABSTRACTION_BOUNDARY design doc recommends against exposing `call_canister(method, args)` to the model. The rationale is sound for a fully autonomous production agent. However, the current development phase favors iteration speed:

1. **The allowlist is the safety boundary**, not the tool shape. A generic tool with `[(principal, method)]` allowlist entries is equivalent in security to N typed tools, each hardcoded to one `(principal, method)` pair — as long as argument validation is equivalent.
2. **Typed tools require code changes per new capability.** Every new canister interaction requires modifying `tools.rs`, adding a parser, updating inference schemas. With ~20 target methods across 4+ canisters, this is significant friction.
3. **The LLM already handles JSON argument construction** for `evm_read` and `send_eth`. Candid-over-JSON is the same pattern.

**Compromise:** One generic `canister_call` tool with strict allowlists, plus optional per-method argument schemas in the allowlist entries for validation. If a method has a schema, args are validated before dispatch. If not, the raw JSON is passed through the Candid bridge.

### Call Flow

```
LLM emits tool call: canister_call({canister_id, method, args, cycles?})
        │
        ▼
   ┌─────────────────────┐
   │  Policy Check        │  Tool enabled? State allowed? Survival policy?
   └─────────┬───────────┘
             │
             ▼
   ┌─────────────────────┐
   │  Allowlist Check     │  (canister_id, method) in allowed set?
   └─────────┬───────────┘
             │
             ▼
   ┌─────────────────────┐
   │  Schema Validation   │  If method has registered schema, validate args
   └─────────┬───────────┘
             │
             ▼
   ┌─────────────────────┐
   │  Candid Encoding     │  JSON args → Candid bytes via type hints
   └─────────┬───────────┘
             │
             ▼
   ┌─────────────────────┐
   │  Call Dispatch        │  ic_cdk::call with optional cycles attachment
   └─────────┬───────────┘
             │
             ▼
   ┌─────────────────────┐
   │  Response Decode     │  Candid bytes → JSON string for LLM
   └─────────┬───────────┘
             │
             ▼
   ┌─────────────────────┐
   │  Record & Return     │  Persist ToolCallRecord, return JSON to LLM
   └─────────────────────┘
```

---

## Tool Schema

```json
{
  "name": "canister_call",
  "description": "Call a method on an allowed ICP canister. Only (canister_id, method) pairs in the allowlist are permitted. Arguments are JSON objects that map to Candid types.",
  "parameters": {
    "type": "object",
    "properties": {
      "canister_id": {
        "type": "string",
        "description": "The target canister principal (e.g., 'ryjl3-tyaaa-aaaaa-aaaba-cai' for the ICP ledger)"
      },
      "method": {
        "type": "string",
        "description": "The canister method to call (e.g., 'icrc1_balance_of', 'icrc1_transfer')"
      },
      "args": {
        "type": "object",
        "description": "Method arguments as a JSON object. Structure depends on the target method's Candid interface."
      },
      "cycles": {
        "type": "string",
        "description": "Optional: cycles to attach to the call (decimal string). Required for CMC top-up and some management canister methods. Omit for most calls."
      }
    },
    "required": ["canister_id", "method", "args"]
  }
}
```

### Why `args` is a JSON object, not raw Candid hex

The LLM cannot produce valid Candid binary. JSON is the natural interface. The canister runtime handles the JSON→Candid conversion using type hints from the allowlist entry (see [Candid Encoding Bridge](#candid-encoding-bridge)).

---

## Allowlist Design

### Data Model

```rust
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct AllowedCanisterMethod {
    /// Target canister principal.
    pub canister_id: Principal,
    /// Exact method name (no wildcards).
    pub method: String,
    /// Whether this is a query (true) or update (false) call.
    pub query: bool,
    /// Side-effect classification.
    pub effect: MethodEffect,
    /// Optional: Candid type signature for args, used to guide JSON→Candid encoding.
    /// Format: IDL text type (e.g., "record { owner : principal; subaccount : opt blob }").
    /// If None, args are encoded as a generic Candid record from JSON.
    pub arg_type: Option<String>,
    /// Optional: Candid type signature for the return value, used for decoding.
    pub ret_type: Option<String>,
    /// Maximum cycles the agent may attach to this call (0 = no cycles allowed).
    pub max_cycles: u128,
    /// Human-readable description injected into inference context.
    pub description: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MethodEffect {
    /// Pure read, no state mutation on the target canister.
    ReadOnly,
    /// Mutates state on the target canister (transfers, approvals, swaps).
    Mutating,
}
```

### Storage

New `StableBTreeMap` at a free `MemoryId` (e.g., `MemoryId::new(20)`). Key: `"{canister_id}:{method}"` string. Value: serialized `AllowedCanisterMethod`.

### Default Allowlist

Populated at init with a conservative set. Controller can add/remove entries via an update method.

```rust
fn default_canister_call_allowlist() -> Vec<AllowedCanisterMethod> {
    vec![
        // --- ICP Ledger (ryjl3-tyaaa-aaaaa-aaaba-cai) ---
        AllowedCanisterMethod {
            canister_id: ICP_LEDGER,
            method: "icrc1_balance_of".into(),
            query: true,
            effect: MethodEffect::ReadOnly,
            arg_type: Some("record { owner : principal; subaccount : opt blob }".into()),
            ret_type: Some("nat".into()),
            max_cycles: 0,
            description: "Check ICP balance for an account".into(),
        },
        AllowedCanisterMethod {
            canister_id: ICP_LEDGER,
            method: "icrc1_transfer".into(),
            query: false,
            effect: MethodEffect::Mutating,
            arg_type: Some("record { to : record { owner : principal; subaccount : opt blob }; amount : nat; memo : opt blob; fee : opt nat; from_subaccount : opt blob; created_at_time : opt nat64 }".into()),
            ret_type: Some("variant { Ok : nat; Err : variant { BadFee : record { expected_fee : nat }; BadBurn : record { min_burn_amount : nat }; InsufficientFunds : record { balance : nat }; TooOld; CreatedInFuture : record { ledger_time : nat64 }; Duplicate : record { duplicate_of : nat }; TemporarilyUnavailable; GenericError : record { error_code : nat; message : text } } }".into()),
            max_cycles: 0,
            description: "Transfer ICP to another account".into(),
        },
        AllowedCanisterMethod {
            canister_id: ICP_LEDGER,
            method: "icrc2_approve".into(),
            query: false,
            effect: MethodEffect::Mutating,
            arg_type: Some("record { spender : record { owner : principal; subaccount : opt blob }; amount : nat; expected_allowance : opt nat; expires_at : opt nat64; fee : opt nat; memo : opt blob; from_subaccount : opt blob; created_at_time : opt nat64 }".into()),
            ret_type: Some("variant { Ok : nat; Err : variant { BadFee : record { expected_fee : nat }; InsufficientFunds : record { balance : nat }; AllowanceChanged : record { current_allowance : nat }; TooOld; CreatedInFuture : record { ledger_time : nat64 }; Duplicate : record { duplicate_of : nat }; Expired : record { ledger_time : nat64 }; TemporarilyUnavailable; GenericError : record { error_code : nat; message : text } } }".into()),
            max_cycles: 0,
            description: "Approve a spender for ICP (ICRC-2)".into(),
        },

        // --- Management Canister (aaaaa-aa) ---
        AllowedCanisterMethod {
            canister_id: MANAGEMENT_CANISTER,
            method: "canister_status".into(),
            query: false,  // canister_status is an update call
            effect: MethodEffect::ReadOnly,
            arg_type: Some("record { canister_id : principal }".into()),
            ret_type: None,  // Complex nested type, return raw JSON
            max_cycles: 0,
            description: "Query status and cycle balance of a canister".into(),
        },
        AllowedCanisterMethod {
            canister_id: MANAGEMENT_CANISTER,
            method: "deposit_cycles".into(),
            query: false,
            effect: MethodEffect::Mutating,
            arg_type: Some("record { canister_id : principal }".into()),
            ret_type: Some("null".into()),
            max_cycles: 10_000_000_000_000,  // 10T cycles max per deposit
            description: "Deposit cycles to a canister".into(),
        },

        // --- KongSwap (2ipq2-uqaaa-aaaar-qailq-cai) ---
        AllowedCanisterMethod {
            canister_id: KONG_BACKEND,
            method: "swap".into(),
            query: false,
            effect: MethodEffect::Mutating,
            arg_type: None,  // Complex, pass through
            ret_type: None,
            max_cycles: 0,
            description: "Execute a token swap on KongSwap".into(),
        },
        AllowedCanisterMethod {
            canister_id: KONG_BACKEND,
            method: "swap_amounts".into(),
            query: true,
            effect: MethodEffect::ReadOnly,
            arg_type: None,
            ret_type: None,
            max_cycles: 0,
            description: "Get swap quote from KongSwap".into(),
        },

        // --- CMC (rkp4c-7iaaa-aaaaa-aaaca-cai) ---
        AllowedCanisterMethod {
            canister_id: CMC,
            method: "notify_top_up".into(),
            query: false,
            effect: MethodEffect::Mutating,
            arg_type: Some("record { block_index : nat64; canister_id : principal }".into()),
            ret_type: Some("variant { Ok : nat; Err : variant { Refunded : record { block_index : opt nat64; reason : text }; InvalidTransaction : text; Other : record { error_code : nat64; error_message : text }; Processing; TransactionTooOld : nat64 } }".into()),
            max_cycles: 0,
            description: "Notify CMC to mint cycles from an ICP transfer".into(),
        },
    ]
}
```

### Allowlist Enforcement

```rust
fn check_allowlist(canister_id: &Principal, method: &str) -> Result<AllowedCanisterMethod, String> {
    let key = format!("{}:{}", canister_id, method);
    stable::get_canister_call_allowlist_entry(&key)
        .ok_or_else(|| format!(
            "canister_call blocked: ({}, {}) not in allowlist",
            canister_id, method
        ))
}
```

---

## Candid Encoding Bridge

This is the hardest part of the design. The LLM produces JSON; the IC expects Candid-encoded bytes. The bridge is split into two directions with different strategies.

### Response Decoding: Candid→JSON via `idl2json`

The [`idl2json`](https://crates.io/crates/idl2json) crate (v0.10.1, maintained by DFINITY) converts Candid values to clean JSON. It provides:

- `idl2json()` — converts `IDLValue` → `JsonValue` without type info
- `idl2json_with_weak_names()` — converts `IDLValue` → `JsonValue` using type info to produce proper field names instead of numeric hashes
- `idl_args2json()` / `idl_args2json_with_weak_names()` — same for `IDLArgs`

This is strictly better than hand-rolling Candid text format output. The `with_weak_names` variants produce LLM-friendly JSON when a `ret_type` is available:

```rust
use idl2json::{idl_args2json_with_weak_names, Idl2JsonOptions, BytesFormat};

fn candid_to_json(bytes: &[u8], ret_type: Option<&str>) -> Result<String, String> {
    let args = match ret_type {
        Some(type_str) => {
            let ty = parse_idl_type(type_str)?;
            IDLArgs::from_bytes_with_types(bytes, &[ty])
                .map_err(|e| format!("candid decode failed: {e}"))?
        }
        None => {
            IDLArgs::from_bytes(bytes)
                .map_err(|e| format!("candid decode failed: {e}"))?
        }
    };

    let options = Idl2JsonOptions {
        bytes_as: Some(BytesFormat::Hex),
        ..Default::default()
    };

    let json_value = idl_args2json_with_weak_names(&args, &options);
    serde_json::to_string(&json_value)
        .map_err(|e| format!("json serialize failed: {e}"))
}
```

**Advantages over hand-rolled approach:**
- Battle-tested by the dfx ecosystem
- Proper handling of variants, optional fields, and nested records
- `BytesFormat::Hex` produces consistent blob representation
- Field names derived from type info when available

### Request Encoding: JSON→Candid via `candid` crate

`idl2json` is **Candid→JSON only** — it has no reverse direction. For encoding LLM-produced JSON into Candid bytes, we use the `candid` crate's `IDLValue` API directly, guided by the `arg_type` string from the allowlist entry.

**Strategy:**
1. **If `arg_type` is set:** Parse the IDL type signature, then convert JSON values to `IDLValue` guided by the type. This handles `principal`, `nat`, `blob`, `opt`, `vec`, and `record` correctly.
2. **If `arg_type` is None:** Attempt best-effort JSON→Candid using heuristic type inference. Strings stay strings, numbers become `nat` or `int`, booleans become `bool`, objects become records, arrays become vectors.

### JSON→IDLValue Conversion Rules (Typed Path)

| Candid Type | JSON Representation | Example |
|---|---|---|
| `nat` | String or number | `"1000000"` or `1000000` |
| `nat64` | String or number | `"1677654321"` |
| `int` | String or number | `"-42"` |
| `text` | String | `"hello"` |
| `bool` | Boolean | `true` |
| `principal` | String (textual principal) | `"ryjl3-tyaaa-aaaaa-aaaba-cai"` |
| `blob` | String (hex-encoded, 0x-prefixed) | `"0xdeadbeef"` |
| `opt T` | Value or null | `null` for None, value for Some |
| `vec T` | Array | `[1, 2, 3]` |
| `record { ... }` | Object | `{"owner": "aaaa-aa", "amount": "100"}` |
| `variant { Ok : T; Err : U }` | Object with single key | `{"Ok": 42}` |
| `null` | null | `null` |

### Implementation Sketch (Request Encoding)

```rust
use candid::{IDLArgs, IDLValue};

fn json_to_candid(json: &serde_json::Value, type_hint: Option<&str>) -> Result<Vec<u8>, String> {
    match type_hint {
        Some(type_str) => {
            let ty = parse_idl_type(type_str)?;
            let idl_value = json_to_idl_value(json, &ty)?;
            let args = IDLArgs::new(&[idl_value]);
            args.to_bytes()
                .map_err(|e| format!("candid encode failed: {e}"))
        }
        None => {
            let idl_value = json_to_idl_value_untyped(json)?;
            let args = IDLArgs::new(&[idl_value]);
            args.to_bytes()
                .map_err(|e| format!("candid encode failed: {e}"))
        }
    }
}
```

### Limitations of the Candid Bridge

1. **Request encoding is custom code.** `idl2json` only covers response decoding. The JSON→Candid direction is our own implementation, guided by `arg_type` strings. This is the primary risk area.
2. **No .did file parsing at runtime.** We rely on inline type strings in the allowlist, not full service descriptions. The allowlist author must manually specify types. Future improvement: fetch `.did` files from canisters via `read_state_canister_metadata` and cache them.
3. **Complex nested types are verbose.** A KongSwap `swap` method has deeply nested arguments. Without a type hint, encoding may fail or produce incorrect types.
4. **`blob` encoding is ambiguous.** JSON has no native binary type. We use hex strings with `0x` prefix (matching `idl2json`'s `BytesFormat::Hex` output), but the LLM must know this convention.
5. **Large `nat` values.** Candid `nat` is arbitrary-precision. JSON numbers lose precision above 2^53. We accept string-encoded numbers for all numeric Candid types.

---

## Use Case Analysis

### Use Case 1: Check ICP Balance

**Scenario:** The agent wants to check its own ICP balance before deciding whether to swap USDC for cycles.

**Tool call:**
```json
{
  "canister_id": "ryjl3-tyaaa-aaaaa-aaaba-cai",
  "method": "icrc1_balance_of",
  "args": {
    "owner": "bkyz2-fmaaa-aaaaa-qaaaq-cai",
    "subaccount": null
  }
}
```

**Flow:**
1. Allowlist check passes — `(ICP_LEDGER, "icrc1_balance_of")` is registered.
2. `arg_type` is `"record { owner : principal; subaccount : opt blob }"`.
3. JSON→Candid: `owner` string → `Principal`, `subaccount` null → `opt blob = None`.
4. Query call to ledger (no cycles attached).
5. Response: Candid `nat` → JSON string `"1000000000"` (10 ICP in e8s).

**Verdict: Works well.** The type hint handles principal encoding correctly. Query call is cheap. No issues.

### Use Case 2: Transfer ICP to CMC for Cycle Minting

**Scenario:** The agent transfers ICP to the CMC minting account, then calls `notify_top_up` to mint cycles.

**Step 1 — Transfer ICP:**
```json
{
  "canister_id": "ryjl3-tyaaa-aaaaa-aaaba-cai",
  "method": "icrc1_transfer",
  "args": {
    "to": {
      "owner": "rkp4c-7iaaa-aaaaa-aaaca-cai",
      "subaccount": "0x<canister-id-as-32-bytes>"
    },
    "amount": "100000000",
    "memo": null,
    "fee": null,
    "from_subaccount": null,
    "created_at_time": null
  }
}
```

**Step 2 — Notify CMC (next turn):**
```json
{
  "canister_id": "rkp4c-7iaaa-aaaaa-aaaca-cai",
  "method": "notify_top_up",
  "args": {
    "block_index": "42",
    "canister_id": "bkyz2-fmaaa-aaaaa-qaaaq-cai"
  }
}
```

**Verdict: Works, but multi-turn coordination is fragile.** The agent must:
- Extract the `block_index` from the transfer result (returned as `variant { Ok : nat }`)
- Remember it across turns (use `remember` tool)
- Call `notify_top_up` in a subsequent turn with the correct `block_index`

**Gap:** If the agent crashes or restarts between step 1 and step 2, the ICP is transferred but cycles are never minted. The `remember` tool mitigates this (the block_index survives upgrades), but there's no built-in saga/retry mechanism. The cycle_topup module handles this better with its explicit state machine. For the generic tool, the agent's LLM reasoning must handle recovery — which is unreliable.

### Use Case 3: KongSwap Token Swap

**Scenario:** The agent swaps bridged USDC for ICP on KongSwap.

**Tool call:**
```json
{
  "canister_id": "2ipq2-uqaaa-aaaar-qailq-cai",
  "method": "swap",
  "args": {
    "pay_token": "USDC",
    "pay_amount": "10000000",
    "receive_token": "ICP",
    "max_slippage": 0.5,
    "receive_amount": null,
    "receive_address": null,
    "referred_by": null
  }
}
```

**Verdict: Partially works, significant gaps.**

1. **Candid encoding without type hints is risky.** KongSwap's `swap` method has a complex argument type. Without `arg_type` in the allowlist, the generic JSON→Candid bridge may produce incorrect types (e.g., encoding `"10000000"` as `text` instead of `nat`).
2. **Pre-approval required.** Before swapping, the agent must approve KongSwap to spend its USDC via `icrc2_approve` on the bridged USDC ledger. This is another multi-turn dependency.
3. **Slippage as float.** Candid doesn't have a native float type in all contexts. The DEX may expect a different representation (basis points as nat, for example).

**Gap:** The tool needs either (a) a type hint for every DEX method, or (b) a way for the LLM to specify Candid types inline. Option (a) is the safer path but requires the allowlist maintainer to reverse-engineer each DEX's Candid interface.

### Use Case 4: Query Canister Status (Monitoring)

**Scenario:** The agent checks cycle balance and status of a child canister or itself.

**Tool call:**
```json
{
  "canister_id": "aaaaa-aa",
  "method": "canister_status",
  "args": {
    "canister_id": "bkyz2-fmaaa-aaaaa-qaaaq-cai"
  }
}
```

**Verdict: Works well.**

1. Simple argument type (single principal in a record).
2. Response is complex (nested records with cycles, memory, module hash, controllers, etc.) but the Candid text-format representation is human-readable enough for the LLM.
3. Only the controller can call `canister_status`, so this only works for canisters the agent controls.

**No significant gaps.** This is a clean read-only use case.

### Use Case 5: Deposit Cycles to Another Canister

**Scenario:** The agent mints cycles and deposits them to a child canister it manages.

**Tool call:**
```json
{
  "canister_id": "aaaaa-aa",
  "method": "deposit_cycles",
  "args": {
    "canister_id": "child-canister-principal"
  },
  "cycles": "1000000000000"
}
```

**Verdict: Works, with caveats.**

1. The `cycles` field in the tool schema maps to `ic_cdk::call::Call::with_cycles()`. This is the correct way to attach cycles.
2. **Safety concern:** The LLM decides how many cycles to attach. The `max_cycles` field in the allowlist entry caps this, but the LLM could still drain cycles up to the cap in a single call.
3. **Pre-condition:** The agent must have sufficient cycles. The tool should check `canister_liquid_cycle_balance()` minus a reserve floor before attaching cycles.

**Gap:** The tool needs a pre-flight affordability check that accounts for both the inter-canister call cost AND the attached cycles. The existing `cycle_admission.rs` framework handles call cost but not attached cycles.

---

## Gaps and Open Issues

### Gap 1: Candid Type Bridge Complexity

**Problem:** The JSON→Candid conversion is the single highest-risk component. Getting it wrong means:
- Calls fail with decode errors on the target canister (recoverable but wasteful).
- Calls succeed with wrong argument values (dangerous for mutating calls like transfers).

**Mitigations:**
- Require `arg_type` for all `Mutating` effect entries. Only `ReadOnly` entries may omit type hints.
- Add integration tests that round-trip known ICRC-1/ICRC-2 calls through the bridge.
- Consider shipping a small set of "well-known methods" with hardcoded type mappings (ICRC-1 standard methods, CMC methods) that bypass the generic bridge entirely.

**Alternative considered:** Use Candid text format (`"(record { owner = principal \"...\"; subaccount = null })"`) instead of JSON. This avoids the bridge entirely but is extremely hostile to LLM generation — Candid text format has precise syntax that LLMs frequently get wrong (missing semicolons, wrong quoting).

### Gap 2: Multi-Step Workflow Reliability

**Problem:** Use cases 2 and 3 require chaining multiple `canister_call` invocations across turns. The agent's reasoning loop must:
- Extract results from step N
- Store intermediate state (via `remember`)
- Execute step N+1 in a later turn
- Handle failures and retries

This is exactly the problem the `cycle_topup` module solves with an explicit state machine. The generic tool offloads orchestration to the LLM, which is less reliable.

**Mitigations:**
- For critical multi-step flows (cycle top-up), keep the dedicated state machine (`cycle_topup` module). Don't rely on the generic tool.
- For ad-hoc multi-step flows (e.g., one-off treasury management), the generic tool + `remember` is acceptable.
- Add a `canister_call` result format that clearly surfaces the return value in a way the LLM can parse and `remember`.

### Gap 3: No Dry-Run / Simulation

**Problem:** Mutating inter-canister calls are irreversible. The LLM might construct incorrect arguments (wrong amount, wrong recipient) and there's no undo. Unlike EVM where `eth_call` simulates transactions, the IC has no native "simulate this update call" mechanism.

**Mitigations:**
- For token transfers: add a confirmation step. The tool could emit a "plan" (formatted description of what it's about to do) and require the LLM to confirm in a second tool call. This doubles the latency but catches argument errors.
- For reads: no risk, execute immediately.
- For cycle deposits: the `max_cycles` cap limits damage.
- Consider a `canister_call_preview` mode that validates arguments and allowlist without executing.

### Gap 4: Response Size and Parsing

**Problem:** Some canister responses are large (e.g., `canister_status` returns module hash, controllers list, memory stats). The Candid text representation could exceed the inference context budget.

**Mitigations:**
- Truncate response to a configurable max (e.g., 4KB text).
- For known return types, extract and format only the most useful fields.
- Add a `max_response_display_bytes` field to `AllowedCanisterMethod`.

### Gap 5: Query vs Update Semantics

**Problem:** The IC distinguishes query calls (fast, non-replicated, non-certified) from update calls (consensus-required, state-mutating). Some methods that appear read-only are actually update calls (e.g., `canister_status`). The tool must dispatch correctly.

**Mitigations:**
- The `query: bool` field in `AllowedCanisterMethod` explicitly marks the call type.
- Query calls use `ic_cdk::call::Call::new()` without state commitment.
- Update calls use the standard `ic_cdk::call::Call::unbounded_wait()` pattern (same as the existing LLM adapter).

**Note:** On the IC, a canister cannot make query calls to other canisters from within an update call context. All inter-canister calls from update methods are update calls regardless of the `query` flag. True query calls are only possible from query endpoints. Since the agent loop runs as an update call (timer-triggered), all `canister_call` invocations will be update calls in practice. The `query` flag serves as documentation and cost estimation guidance only.

### Gap 6: Cycle Attachment Safety

**Problem:** The `cycles` parameter lets the LLM attach cycles to calls. A malicious or confused LLM could drain the canister's cycle balance in a single call.

**Mitigations:**
- `max_cycles` per allowlist entry caps individual calls.
- Pre-flight check: `requested_cycles + call_cost + reserve_floor < liquid_balance`.
- Global per-turn cycle budget (existing pattern from HIGH_LEVERAGE_TOOLS.md).
- Only `deposit_cycles` and CMC-related methods should have non-zero `max_cycles`.

### Gap 7: Reentrancy and Concurrent Calls

**Problem:** Inter-canister calls are async. Between the call and the response, the canister can receive other messages. If the agent loop runs concurrently (it shouldn't, due to lease-based exclusion), state could be corrupted.

**Mitigations:**
- The existing scheduler lease mechanism prevents concurrent agent turns. This is sufficient.
- The tool executes calls sequentially within a turn (same as all existing tools).
- No new reentrancy risk beyond what `send_eth` already introduces.

---

## Cycle Costs

### Per-Call Cost Estimate

Inter-canister calls cost cycles based on:
- **Base cost:** ~590K cycles per call + response
- **Argument size:** ~400 cycles per byte of request
- **Response size:** ~800 cycles per byte of response

For typical ICRC-1 calls:

| Operation | Request ~bytes | Response ~bytes | Estimated Cycles |
|---|---|---|---|
| `icrc1_balance_of` | 64 | 16 | ~650K |
| `icrc1_transfer` | 256 | 32 | ~730K |
| `icrc2_approve` | 256 | 32 | ~730K |
| `canister_status` | 32 | 512 | ~1.1M |
| `deposit_cycles` | 32 | 8 | ~620K |
| `swap` (KongSwap) | 512 | 256 | ~1.0M |

Inter-canister calls are **dramatically cheaper** than HTTPS outcalls (~60M+ cycles) or threshold signing (~26B cycles). This tool is the cheapest async operation in the agent's toolkit.

### Pre-Flight Check

```rust
fn estimate_canister_call_cost(request_bytes: usize, max_response_bytes: usize) -> u128 {
    let base = 590_000u128;
    let request_cost = 400u128 * request_bytes as u128;
    let response_cost = 800u128 * max_response_bytes as u128;
    base + request_cost + response_cost
}
```

---

## Edge Cases

| Case | Handling |
|---|---|
| Target canister is stopped or deleted | IC returns `CanisterError`. Return error to LLM. No retry. |
| Target canister traps (panics) | IC returns `CanisterError`. Return error to LLM. Cycles for the call are consumed. |
| Response exceeds expected size | Candid responses are bounded by the target canister's implementation. No `max_response_bytes` equivalent for inter-canister calls. Rely on response truncation at display time. |
| LLM provides invalid principal string | Validate with `Principal::from_text()` before dispatch. Return parse error. |
| LLM provides cycles for a method with `max_cycles: 0` | Reject: "cycles attachment not allowed for this method". |
| LLM requests cycles exceeding `max_cycles` | Reject: "requested N cycles exceeds max M for this method". |
| Allowlist is empty | All `canister_call` invocations fail with "not in allowlist". Tool is effectively disabled. |
| Method exists in allowlist but canister is on a different subnet | No issue — IC handles cross-subnet calls transparently. May add latency (~2s). |
| Candid encode fails due to type mismatch | Return error with details. LLM can retry with corrected args. |
| Candid decode fails on response | Return raw hex of response bytes as fallback. LLM gets partial information. |
| Agent calls itself (recursive call) | Allowed if `(self_canister_id, method)` is in the allowlist. Dangerous — could cause unbounded recursion. **Default: do not add self to the allowlist.** |
| Multiple canister_call invocations in one turn | Executed sequentially (same as all tools). Each has independent allowlist check and cycle budget. |

---

## Changes Required

### New Files

- **`src/features/canister_call.rs`** — Core module: allowlist check, JSON→Candid bridge, call dispatch, response decoding.

### Modified Files

- **`src/tools.rs`** — Add `canister_call` tool to `ToolManager::new()` policies and `execute_actions` match arm. New survival operation class `InterCanisterCall`.
- **`src/storage/stable.rs`** — Add `CANISTER_CALL_ALLOWLIST_MAP` at new `MemoryId`. CRUD helpers for allowlist entries.
- **`src/domain/types.rs`** — Add `SurvivalOperationClass::InterCanisterCall`. Add `AllowedCanisterMethod` and `MethodEffect` types.
- **`src/features/mod.rs`** — Add `pub mod canister_call;`.
- **`src/features/inference.rs`** — Add `canister_call` to tool schemas for both IcLlm and OpenRouter adapters. Include allowlist method descriptions in the tool description.
- **`src/lib.rs`** — Add controller update method `set_canister_call_allowlist(Vec<AllowedCanisterMethod>)`.

### New Dependencies

```toml
[dependencies]
# candid is already a dependency — used for JSON→Candid encoding (IDLValue, IDLArgs, type parsing).
# idl2json is new — used for Candid→JSON response decoding.
idl2json = { version = "0.10", default-features = false }
```

**Note:** Verify `idl2json` compiles under `wasm32-unknown-unknown`. The crate is used in the dfx ecosystem (native targets). If it pulls in std-only dependencies, we may need to vendor a subset or use it with `default-features = false`. The core conversion functions (`idl2json`, `idl_args2json_with_weak_names`) operate on in-memory `IDLValue`/`IDLArgs` and should not require I/O.

### Stable Memory Layout

| MemoryId | Purpose | Status |
|---|---|---|
| 0–19 | Existing maps | Unchanged |
| 20 | `CANISTER_CALL_ALLOWLIST_MAP` | New |

---

## Implementation Order

### Phase 1: Foundation (allowlist + dispatch, read-only calls only)

1. Add `AllowedCanisterMethod` type and `CANISTER_CALL_ALLOWLIST_MAP` to stable storage.
2. Implement allowlist CRUD (init defaults, controller update method).
3. Implement JSON→Candid bridge for typed path only (require `arg_type` for all entries).
4. Implement `canister_call` tool for query/read-only methods only (`MethodEffect::ReadOnly`).
5. Wire into `tools.rs` and inference schemas.
6. Test with `icrc1_balance_of` and `canister_status`.

### Phase 2: Mutating calls

1. Enable `MethodEffect::Mutating` dispatch.
2. Add cycle attachment support (parse `cycles` arg, enforce `max_cycles`).
3. Add pre-flight affordability check for attached cycles.
4. Test with `icrc1_transfer` and `deposit_cycles`.

### Phase 3: Untyped fallback + DEX integration

1. Implement untyped JSON→Candid path (best-effort encoding for entries without `arg_type`).
2. Add KongSwap `swap` and `swap_amounts` with allowlist entries.
3. Test full swap flow.

### Phase 4: Hardening

1. Add response truncation and formatting.
2. Add per-turn cycle budget enforcement for canister calls.
3. Add integration tests for the Candid bridge with all default allowlist entries.
4. Add deduplication for canister_call (reuse existing tool fingerprinting).

---

## Relationship to `cycle_topup` Module

The `cycle_topup` module (`src/features/cycle_topup/mod.rs`) implements a state machine for the full USDC→cycles conversion. This module makes many of the same inter-canister calls (ICRC transfers, approvals, KongSwap swaps, CMC notify).

**Should `cycle_topup` use `canister_call` under the hood?**

No. The `cycle_topup` module is a scheduler-driven state machine, not an LLM-driven tool. It:
- Runs without LLM involvement (deterministic steps).
- Has explicit retry/recovery for each stage.
- Manages its own state persistence (`TopUpStage`).

The `canister_call` tool serves a different purpose: ad-hoc, LLM-directed canister interactions that don't justify a dedicated state machine. The two systems are complementary:

- **`cycle_topup`**: Critical path, must succeed, state machine handles retries.
- **`canister_call`**: Exploratory/ad-hoc, LLM handles orchestration, acceptable to fail.

---

## Research References

- [ICP Rust inter-canister calls](https://internetcomputer.org/docs/building-apps/developer-tools/cdks/rust/intercanister)
- [ICP interface spec (management canister)](https://internetcomputer.org/docs/references/ic-interface-spec)
- [Candid specification](https://github.com/dfinity/candid/blob/master/spec/Candid.md)
- [ICRC-1 token standard](https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1)
- [ICRC-2 approval standard](https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2)
- [ICP cycles cost formulas](https://internetcomputer.org/docs/references/cycles-cost-formulas)
- [KongSwap documentation](https://docs.kongswap.io/)
- [CMC (Cycles Minting Canister)](https://internetcomputer.org/docs/developer-docs/defi/cycles/cycles-ledger)

### Codebase References

- `src/tools.rs` — existing tool dispatch
- `src/features/inference.rs:274-282` — existing inter-canister call pattern (IcLlm)
- `src/features/threshold_signer.rs` — existing management canister call pattern
- `src/features/cycle_topup/mod.rs` — multi-step inter-canister workflow
- `src/storage/stable.rs` — stable memory map patterns
- `docs/design/TOOL_CALL_ABSTRACTION_BOUNDARY_AND_RUNTIME_EXTENSION.md` — tool classification framework
- `docs/design/HIGH_LEVERAGE_TOOLS.md` — existing tool design patterns
