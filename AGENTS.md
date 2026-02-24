# Agent Instructions

Follow the KISS principle. Clarify with the human if you need to introduce complexity.

## Goal of this project
- Autonomous agent (Automaton) implemented as a canister on ICP with wallet on EVM chain.
- Automaton needs to pay for cycles for its existence on ICP as well as USDC for inference.
- Automaton can think and do on its own without human involvement and needs to be creative to generate income for its survival.
- We always need to think about the requirements of the automaton first when designing or implementing features not about a human user/owner.

## Delivery workflow
- Use `icp-cli` as the default toolchain to set up and drive this project (network, build, deploy, and related lifecycle tasks).
- Follow TDD: write or update tests first, implement incrementally, and keep tests green throughout development.
- Do extensive tests. Try to identify edge cases and ICP specifics. Be aware of the ICP security best practices
- DO NOT edit tests to pass tests later on. If this is necessary communicate with the user.
- Maintain extensive automated test coverage with both unit tests and integration tests for each implemented feature.
- Use PocketIC for Internet Computer integration test execution.
- PocketIC integration tests install the prebuilt Wasm artifact from `target/wasm32-unknown-unknown/release/backend.wasm`; always run `icp build` after code changes and before `cargo test --features pocketic_tests` to avoid stale-artifact false failures.
- Candid is generated from Rust canister code via `ic_cdk::export_candid!()` and extracted from compiled Wasm using `./scripts/generate-candid.sh [output_did_path]`; do not hand-edit `ic-automaton.did`.
- Candid generation workflow: run `icp build` first, then run `./scripts/generate-candid.sh ic-automaton.did` (or omit the arg to use the default output path).
- We are still in the development phase without users, as such we don't care about backward compatbility and can reinstall the canister and wipe the stable memory.
- Use canlog rust crate for structured logging.
- Autonomy is mandatory: the canister runtime must self-heal and continue scheduled operation after transient failures, without requiring manual resets or operator intervention.

## Host-safe time guidance
- Do not call `ic_cdk::api::time()` directly in code that runs in native/unit tests.
- Use a small local helper, for example `current_time_ns()`, with `cfg` branches:
  - `wasm32`: use `ic_cdk::api::time()`
  - non-`wasm32`: use a host-safe fallback (system time or deterministic test value, depending on test needs)
- Keep time-source behavior explicit in tests that validate backoff/retry windows to avoid flaky or always-expired assertions.

## Documentation workflow
- Treat `docs/design/` and `docs/specs/` as a primary source of truth for requirements, architecture/design decisions, and user flows.

## Validation and commits
- After each feature is implemented, create a git commit.
- Before committing, run pre-commit hooks and ensure strict validation passes:
  - all tests pass
  - linter passes
  - clippy passes

## Init args
- If you add new canister init arguments. Make sure to add defaults to `icp.yml`.
- When passing numeric init args through `icp canister install --args` (especially `nat64` fields), always use explicit Candid typing, for example `opt (31337 : nat64)` instead of `opt 31337`. Untyped numerics may decode as `int` and silently fall back to defaults.
