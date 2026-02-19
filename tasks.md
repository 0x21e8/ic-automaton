# Survival Mode + Cycles Cost Control Task List

Status legend:
- `[ ]` pending
- `[-]` in progress
- `[x]` done and verified

Rule for every step:
1. Write/update tests first (TDD).
2. Implement minimal code to pass.
3. Run verification commands.
4. Commit only that verified step.

---

- [ ] **Step 1: Add cycle admission primitives (core)**
  - Scope:
    - Add operation-class cost estimator interface (HTTP outcall, threshold sign, workflow envelope).
    - Add liquid-balance affordability check utility and safety margin handling.
  - Tests first:
    - Unit tests for affordability decisions and margin math.
  - Verification:
    - `cargo test -q`
    - `cargo clippy --all-targets --all-features -- -D warnings`
  - Commit:
    - `TBD`

- [ ] **Step 2: Wire inference through admission checks**
  - Scope:
    - Preflight `cost_http_request` before OpenRouter call.
    - Convert insufficient-cycles from hard loop fault into controlled degraded outcome.
    - Emit structured canlog entries with estimated cost + liquid balance.
  - Tests first:
    - Unit tests for inference guard behavior.
    - Update integration tests for degraded-path expectations.
  - Verification:
    - `cargo test -q`
    - `cargo clippy --all-targets --all-features -- -D warnings`
  - Commit:
    - `TBD`

- [ ] **Step 3: Implement real `CheckCycles` scheduler task**
  - Scope:
    - Replace no-op `CheckCycles` with actual balance/liquid evaluation.
    - Introduce persisted survival tier state and hysteresis counters.
  - Tests first:
    - Scheduler/state tests for tier transitions and hysteresis.
  - Verification:
    - `cargo test -q`
    - `cargo clippy --all-targets --all-features -- -D warnings`
  - Commit:
    - `TBD`

- [ ] **Step 4: Scheduler gating + cooldown policy**
  - Scope:
    - Gate expensive operation classes by survival tier.
    - Add per-class cooldown/backoff (`inference`, `evm_poll`, `evm_broadcast`, `threshold_sign`).
  - Tests first:
    - Unit/integration tests for gating and backoff.
  - Verification:
    - `cargo test -q`
    - `cargo clippy --all-targets --all-features -- -D warnings`
  - Commit:
    - `TBD`

- [ ] **Step 5: Add hooks for future EVM + signing paths**
  - Scope:
    - Add shared admission API usage points for EVM RPC and threshold signing call sites.
    - No-op/placeholder adapters in current v1 code should still compile and be covered.
  - Tests first:
    - Unit tests for operation-class routing and policy decisions.
  - Verification:
    - `cargo test -q`
    - `cargo clippy --all-targets --all-features -- -D warnings`
  - Commit:
    - `TBD`

- [ ] **Step 6: HTTPS outcall cost optimization**
  - Scope:
    - Lower default inference `max_response_bytes` (target 16KB).
    - Add one-step bounded fallback retry (e.g. 32KB) for truncation/size failures only.
    - Add explicit output-bounding request fields where provider supports it.
  - Tests first:
    - Unit tests for request shaping and fallback trigger conditions.
  - Verification:
    - `cargo test -q`
    - `cargo clippy --all-targets --all-features -- -D warnings`
  - Commit:
    - `TBD`

- [ ] **Step 7: PocketIC regression/integration coverage**
  - Scope:
    - Add integration coverage for low/critical survival behavior and recovery.
    - Verify no repeated unaffordable expensive-op attempts at heartbeat cadence.
  - Tests first:
    - New PocketIC tests + fixture updates.
  - Verification:
    - `cargo test -q`
    - `cargo test -q --features pocketic_tests`
    - `cargo clippy --all-targets --all-features -- -D warnings`
  - Commit:
    - `TBD`

- [ ] **Step 8: Final validation + docs sync**
  - Scope:
    - Sync docs/spec references to implemented behavior and knobs.
    - Confirm no secret leakage in logs/responses.
  - Verification:
    - `cargo test -q`
    - `cargo clippy --all-targets --all-features -- -D warnings`
    - `cargo fmt --all -- --check`
  - Commit:
    - `TBD`
