# Agent Instructions

Follow the KISS principle. Clarify with the human if you need to introduce complexity.

## Delivery workflow
- Use `icp-cli` as the default toolchain to set up and drive this project (network, build, deploy, and related lifecycle tasks).
- Follow TDD: write or update tests first, implement incrementally, and keep tests green throughout development.
- Do extensive tests. Try to identify edge cases and ICP specifics. Be aware of the ICP security best practices
- DO NOT edit tests to pass tests later on. If this is necessary communicate with the user.
- Maintain extensive automated test coverage with both unit tests and integration tests for each implemented feature.
- Use PocketIC for Internet Computer integration test execution.
- PocketIC integration tests install the prebuilt Wasm artifact from `target/wasm32-unknown-unknown/release/backend.wasm`; always run `icp build` after code changes and before `cargo test --features pocketic_tests` to avoid stale-artifact false failures.
- Candid is generated from Rust canister code via `ic_cdk::export_candid!()` and extracted from the compiled Wasm using `./scripts/generate-candid.sh ic-automaton.did` (automatically run by `.githooks/pre-commit`); do not hand-edit `ic-automaton.did`.
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
- Treat `docs/design/` and `specs/` as a primary source of truth for requirements, architecture/design decisions, and user flows.
- For agent-based testing of flows check `docs/runbooks/`.

## Validation and commits
- After each feature is implemented, create a git commit.
- Before committing, run pre-commit hooks and ensure strict validation passes:
  - all tests pass
  - linter passes
  - clippy passes

## Init args
- If you add new canister init arguments. Make sure to add defaults to `icp.yml`.

## Skills
A skill is a set of local instructions to follow that is stored in a `SKILL.md` file.
Use the one relevant to your task.

### Available skills
- spec-writer: Spec writing workflow from idea to locked executable spec (file: `/Users/domwoe/.codex/skills/spec-writer/SKILL.md`)
