# Versioned Strategy Template Registry and Generic ABI Encoder/Validator (Base DeFi)

**Date:** 2026-02-22  
**Status:** Exploratory design  
**Scope:** Add a versioned strategy-template registry plus a generic ABI encoder/validator so the automaton can safely learn and execute DeFi opportunities on Base without hardcoded per-protocol transaction logic.

---

## Problem

Today the automaton can:

- read EVM state with `evm_read` (`eth_getBalance`, `eth_call`)
- execute EVM writes with `send_eth` (custom calldata)
- persist memory and run autonomous scheduler loops

But it does not have:

- a first-class registry of protocol strategies/templates
- a trusted ABI and address provenance pipeline
- deterministic calldata validation before execution
- a reusable postcondition validator per DeFi primitive

This creates a brittle gap: opportunity selection may improve, but execution reliability and safety remain heavily dependent on ad-hoc calldata construction.

---

## Goals

1. Create a **versioned strategy-template registry** in stable memory.
2. Create a **generic ABI encoder/validator** that deterministically compiles tx intents into calldata.
3. Support high-value Base primitives:
- swaps (DEX routers)
- lending supply/withdraw/borrow/repay
- yield-token primitives (PT/YT style)
4. Keep the execution path auditable, gated, and recoverable under existing survival policies.

## Non-Goals

- Universal support for every protocol function on day one.
- Fully autonomous onboarding of untrusted protocols without provenance checks.
- Replacing existing `send_eth` and `evm_read` tools; this design builds on top of them.

---

## Current Baseline in This Repo

- Tool surface: `evm_read`, `send_eth`, `http_fetch`, signing/broadcast wrappers (`src/features/inference.rs`, `src/tools.rs`).
- EVM execution path already handles nonce/gas/sign/broadcast in `send_eth` (`src/features/evm.rs`).
- Existing deterministic selector/encoding helpers for some flows (`src/features/evm.rs`, `src/features/cycle_topup/mod.rs`).
- Scheduler + backoff + survival-gate controls already exist (`src/scheduler.rs`, `src/storage/stable.rs`).

This design extends these capabilities instead of introducing a second execution stack.

---

## Design Overview

### New Logical Components

1. `StrategyTemplateRegistry`
- Versioned templates that define:
  - protocol + primitive
  - chain/network
  - contract roles
  - callable actions
  - validation rules
  - risk limits

2. `AbiArtifactRegistry`
- Canonical ABI fragments by contract role and version.
- Stores selector map and normalized arg types.

3. `IntentCompiler`
- Converts high-level action intent into deterministic calldata via ABI artifacts.
- Produces `ExecutionPlan` (one or more txs + preconditions + postconditions).

4. `ExecutionValidator`
- Validates addresses, selector existence, argument types, risk/budget constraints.
- Runs preflight simulation (`eth_call`, `eth_estimateGas`) when applicable.

5. `OutcomeLearner`
- Updates per-template confidence and per-action reliability using observed outcomes.
- Does not mutate ABI or addresses automatically; only confidence and parameter hints.

---

## Data Model

```rust
pub struct StrategyTemplateKey {
    pub protocol: String,       // "aave-v3", "uniswap-v3", "aerodrome-v1", ...
    pub primitive: String,      // "swap_exact_in", "lend_supply", "lend_borrow", ...
    pub chain_id: u64,          // 8453 for Base
    pub template_id: String,    // stable logical id
}

pub struct TemplateVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

pub enum TemplateStatus {
    Draft,
    Active,
    Deprecated,
    Revoked,
}

pub struct ContractRoleBinding {
    pub role: String,           // "router", "pool", "quoter", "comet", ...
    pub address: String,        // 0x...
    pub source_ref: String,     // url + commit/tag or docs snapshot id
    pub codehash: Option<String>,
}

pub struct AbiFunctionSpec {
    pub role: String,           // contract role to call
    pub name: String,           // function name
    pub selector_hex: String,   // 0x + 4 bytes
    pub inputs: Vec<AbiTypeSpec>,
    pub outputs: Vec<AbiTypeSpec>,
    pub state_mutability: String,
}

pub struct ActionSpec {
    pub action_id: String,      // "supply", "withdraw", "swap_exact_in"
    pub call_sequence: Vec<AbiFunctionSpec>,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub risk_checks: Vec<String>,
}

pub struct StrategyTemplate {
    pub key: StrategyTemplateKey,
    pub version: TemplateVersion,
    pub status: TemplateStatus,
    pub contract_roles: Vec<ContractRoleBinding>,
    pub actions: Vec<ActionSpec>,
    pub constraints_json: String,  // slippage limits, ttl, size caps
    pub created_at_ns: u64,
    pub updated_at_ns: u64,
}
```

### Versioning Rules

- `major`: breaking change (function signatures, role addresses, semantics).
- `minor`: backward-compatible additions (new optional args, new action variants).
- `patch`: metadata/risk tuning/documentation fixes.

Execution always pins to an explicit template version; no implicit floating latest.

---

## Generic ABI Encoder/Validator

### ABI Normalization

1. Parse ABI JSON into canonical internal schema.
2. Build deterministic signature strings (`name(type1,type2,...)`).
3. Recompute selector `keccak(signature)[0..4]`.
4. Reject artifact if declared selector does not match recomputed selector.

### Intent -> Calldata Compilation

Input:
- template version + action id
- typed runtime parameters

Process:
1. Resolve target contract role/address.
2. Validate parameter completeness and type match.
3. ABI-encode function selector + args.
4. Produce tx payload for `send_eth`:
- `to`: resolved contract address
- `value_wei`: usually `0` for ERC20/lending calls
- `data`: encoded calldata

### Validation Layers (Fail Closed)

1. `Schema validation`
- template/action/param presence, type shape, bounds.

2. `Address validation`
- chain id compatibility
- checksummed/normalized EVM address
- optional codehash match if provided.

3. `Policy validation`
- exposure caps
- slippage/max-loss constraints
- survival operation gate and cycle affordability.

4. `Preflight validation`
- read-only simulation via `eth_call` where possible
- gas sanity via `eth_estimateGas`
- revert string classification into deterministic/non-deterministic failure buckets.

5. `Postcondition validation`
- verify expected state deltas (balances, debt shares, LP/token receipts).

Any failed layer blocks execution and writes structured failure evidence.

---

## Strategy Template Lifecycle

1. `Ingest`
- Load candidate template from trusted source pack.

2. `Verify`
- ABI selector checks + role/address provenance + optional codehash checks.

3. `Activate`
- Mark `Active` only after preflight + canary success thresholds.

4. `Learn`
- Update confidence/risk metadata from outcomes.

5. `Rotate`
- Publish new version when addresses/ABIs change.
- Keep old versions available for replay/audit.

6. `Revoke`
- Hard-disable compromised/broken templates.

---

## Base Protocol/Primitive Coverage (Initial Set)

The set below is chosen by Base relevance and practical integrator value, using a TVL snapshot plus official deployment/address sources.

### Snapshot Method (2026-02-22)

Derived from `https://api.llama.fi/protocols`, filtered by `chainTvls["Base"]`, grouped by category.

Repro command:

```bash
curl -L -s https://api.llama.fi/protocols \
  | jq '[.[] | select(.chainTvls["Base"] != null) | {name, category, base_tvl: .chainTvls["Base"]}]'
```

Top Base lending cohort in snapshot:
- Morpho V1
- Aave V3
- Moonwell Lending
- Compound V3

Top Base DEX cohort in snapshot:
- Aerodrome (Slipstream + V1)
- Uniswap (V3/V2/V4)

This ranking is dynamic and must be treated as runtime data, not hardcoded truth.

### Primitive A: Spot Swap / Routing

Representative protocols on Base:
- Aerodrome
- Uniswap (V3/V4)

Template actions:
- `quote_exact_in` (read)
- `swap_exact_in` (write)
- optional `approve_if_needed` (write)

Required checks:
- max slippage bps
- pool liquidity floor
- quote freshness TTL
- positive net-edge after gas + fee

### Primitive B: Lending Supply/Withdraw/Borrow/Repay

Representative protocols on Base:
- Aave V3
- Morpho Blue ecosystem
- Compound V3
- Moonwell

Template actions:
- `supply`
- `withdraw`
- `borrow`
- `repay`

Required checks:
- health factor / LTV guardrails
- borrow cap and available liquidity
- oracle freshness and confidence
- liquidation-buffer constraints

### Primitive C: Yield Tokenization / Rate Positioning

Representative protocol on Base:
- Pendle

Template actions:
- `mint_or_buy_pt`
- `redeem_pt`
- optional `route_via_swap`

Required checks:
- maturity horizon fit
- implied APY vs benchmark spread
- liquidity depth and unwind path
- deterministic exit plan before entry

---

## Address and ABI Provenance

### Source Classes

1. Official docs deployment pages.
2. Official protocol address-book repositories.
3. Protocol-maintained deployment manifests.

### Examples Used in This Design

- Uniswap deployment docs (Base contract addresses).
- Aave Base address book (autogenerated onchain addresses).
- Aerodrome contracts repo deployment table.
- Compound Comet deployment manifests for Base.
- Moonwell Base chain manifest (includes Moonwell and Morpho-related addresses).
- Pendle contracts docs index.

Each template must retain `source_ref` metadata for every role binding.

---

## Learning Model (What Learns vs What Is Immutable)

### Learns Automatically

- confidence per template/action
- parameter priors (slippage defaults, gas buffers, size limits)
- strategy ranking weights by realized risk-adjusted outcomes

### Never Learns Autonomously (Requires New Signed Version)

- ABI function signatures
- contract role addresses
- selector maps
- critical safety invariants

This separation prevents model drift from mutating execution-critical artifacts.

---

## End-to-End Example (Lending Supply on Base)

1. Opportunity module identifies positive carry for USDC lending.
2. Select template:
- `protocol=aave-v3`
- `primitive=lend_supply`
- pinned version `v1.2.0`
3. Resolve role bindings:
- `pool` address from template source refs.
4. Compile intent:
- action `supply(asset=USDC, amount=..., on_behalf_of=self, referral=0)`.
5. Validate:
- address provenance
- ABI selector match
- health and exposure checks
- `eth_estimateGas` sanity
6. Execute:
- `send_eth` with encoded calldata.
7. Verify:
- aToken balance delta > 0
- no invariant breaches
8. Learn:
- update success metrics and confidence.

---

## Integration Plan in This Repo

### New Modules (proposed)

- `src/strategy/registry.rs`
- `src/strategy/abi.rs`
- `src/strategy/compiler.rs`
- `src/strategy/validator.rs`
- `src/strategy/learner.rs`

### Tool Surface

Add high-level control tools while keeping `send_eth` as executor:

- `list_strategy_templates`
- `simulate_strategy_action`
- `execute_strategy_action`
- `get_strategy_outcomes`

### Scheduler

Add/repurpose periodic jobs for:

- template freshness checks
- ABI provenance verification
- canary probes for active templates

---

## Security and Operational Controls

1. Fail closed on missing ABI/address provenance.
2. Per-template budget caps and max notional per action.
3. Mandatory canary for new template versions.
4. Runtime kill-switch by protocol/template id.
5. Structured audit log for every compile/validate/execute step.
6. Automatic deactivation on repeated deterministic failures.

---

## Rollout Phases

1. Phase 1: Registry + ABI normalization (read-only simulation).
2. Phase 2: Execute-only for one primitive per protocol family:
- swap exact-in
- lending supply
3. Phase 3: Borrow/repay and multi-call strategy actions.
4. Phase 4: Full outcome-weighted strategy allocation.

---

## References

- DeFiLlama API protocols dataset: `https://api.llama.fi/protocols`
- DeFiLlama Base chain page: `https://defillama.com/chain/Base`
- Uniswap docs (deployments / Base): `https://docs.uniswap.org/contracts/v4/deployments`
- Aave Base address book: `https://raw.githubusercontent.com/bgd-labs/aave-address-book/main/src/AaveV3Base.sol`
- Aerodrome contracts deployment table: `https://raw.githubusercontent.com/aerodrome-finance/contracts/main/README.md`
- Compound Comet Base deployment manifests:
  - `https://raw.githubusercontent.com/compound-finance/comet/main/deployments/base/usdc/configuration.json`
  - `https://raw.githubusercontent.com/compound-finance/comet/main/deployments/base/usdc/roots.json`
- Moonwell Base chain manifest: `https://raw.githubusercontent.com/moonwell-fi/moonwell-contracts-v2/main/chains/8453.json`
- Pendle contracts docs index: `https://docs.pendle.finance/pendle-v2/Developers/Contracts/Overview`

---

## Implementation Checklist (Repo-Scoped)

### Block 1) Registry and ABI Foundation

- [x] Add strategy and ABI types in `src/domain/types.rs`:
  `StrategyTemplateKey`, `TemplateVersion`, `TemplateStatus`, role/action specs, ABI artifacts, execution/validation/outcome structs.
- [x] Implement stable persistence and indexes in `src/storage/stable.rs` for versioned templates, ABI artifacts, activation state, revocation/kill-switch, and outcome stats.
- [x] Create strategy module tree:
  `src/strategy/mod.rs`, `src/strategy/registry.rs`, `src/strategy/abi.rs`, `src/strategy/compiler.rs`, `src/strategy/validator.rs`, `src/strategy/learner.rs`.
- [x] Implement ABI normalization and selector verification in `src/strategy/abi.rs` (canonical signatures + recomputed selectors), with mandatory `source_ref` provenance and optional `codehash`.

### Block 2) Compile, Validate, Execute Path

- [x] Implement intent compilation in `src/strategy/compiler.rs`:
  `(template_version, action_id, typed params) -> ExecutionPlan` with deterministic calldata.
- [x] Implement fail-closed validation in `src/strategy/validator.rs`:
  schema/type/bounds, chain/address checks, policy/risk checks, preflight (`eth_call`, `eth_estimateGas`), and postconditions.
- [x] Reuse existing EVM execution in `src/features/evm.rs` by compiling actions into `send_eth` payloads (`to`, `value_wei`, `data`), not a parallel execution stack.
- [x] Classify deterministic vs non-deterministic failures and persist structured failure evidence.

### Block 3) Tooling, API, Scheduler, and Learning

- [x] Extend `src/tools.rs` with:
  `list_strategy_templates`, `simulate_strategy_action`, `execute_strategy_action`, `get_strategy_outcomes`.
- [x] Add/extend canister methods in `src/lib.rs` for strategy queries/updates and admin lifecycle controls (ingest, activate, deprecate, revoke, kill-switch), with controller gating.
- [x] Add scheduler tasks in `src/scheduler.rs` for template freshness checks, ABI provenance re-verification, and canary probes before activation.
- [x] Implement `src/strategy/learner.rs` updates for confidence/priors/ranking only; never auto-mutate ABI signatures, selector maps, addresses, or critical invariants.

### Block 4) Security, Testing, and Delivery Workflow

- [x] Enforce operational controls: per-template budgets, max notional caps, runtime kill-switch, and auto-deactivation after repeated deterministic failures; log compile/validate/execute trail with `canlog`.
- [x] Follow TDD with unit tests (strategy modules), integration tests (`src/tools.rs`, `src/scheduler.rs`), and PocketIC end-to-end tests in `tests/`.
- [x] Run `icp build` after code changes and before `cargo test --features pocketic_tests` to avoid stale wasm artifacts.
- [x] Keep Candid generated from `ic_cdk::export_candid!()`; do not hand-edit `ic-automaton.did`.
- [x] Run strict validation before commit:
  `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and full test suites.
- [x] If init args change, update defaults in `icp.yaml`; use explicit Candid numeric types (example: `opt (31337 : nat64)`).

---

## Implementation Notes / Keep in Mind

- Execution must always pin an explicit template version; do not float to implicit latest.
- Provenance is mandatory for role bindings; missing provenance is a hard block.
- Validation is fail-closed; partial validation is equivalent to rejection.
- Reuse existing EVM primitives in `src/features/evm.rs` (`eth_call`, `eth_estimateGas`, `send_eth`) instead of introducing parallel transaction stacks.
- Respect scheduler survival tiers and cycle affordability gates before expensive outcalls/signing/broadcast.
- Keep host-safe time behavior for native tests; avoid direct `ic_cdk::api::time()` in testable host paths.
- Preserve immutable execution-critical artifacts (ABI/address/selector/safety invariants) across autonomous learning updates.
