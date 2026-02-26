# Base Morpho USDC Carry (`base-usdc-carry-cbbtc-01`)

This folder turns a draft strategy into an executable strategy payload bundle.

## Files

- `strategy-template.json`
- `abi-artifact-morpho.json`
- `activate-template.json`
- `simulate-enter_supply.json`
- `simulate-exit_supply.json`
- `execute-enter_supply.json`
- `execute-exit_supply.json`

## End-to-End Sequence

1. Ingest template as draft:
- method: `ingest_strategy_template_admin`
- args: `strategy-template.json`

2. Ingest ABI artifact:
- method: `ingest_strategy_abi_artifact_admin`
- args: `abi-artifact-morpho.json`

3. Activate template (runs canary probe):
- method: `activate_strategy_template_admin`
- args: `key`, `version`, `reason` from `activate-template.json`

4. Validate before live txs:
- tool: `simulate_strategy_action`
- args: `simulate-enter_supply.json` and/or `simulate-exit_supply.json`
- expect: `validation.passed == true`

5. Execute when simulation passes:
- tool: `execute_strategy_action`
- args: `execute-enter_supply.json` or `execute-exit_supply.json`

6. Monitor outcomes:
- query: `get_strategy_outcome_stats`
- tool: `get_strategy_outcomes`

7. Emergency halt (if needed):
- method: `set_strategy_kill_switch_admin(key, true, reason)`

## Required Runtime Preconditions

- `evm_chain_id` is `8453`
- `evm_rpc_url` is configured and reachable
- automaton EVM address is derived (for execution)
- caller is a canister controller (for admin methods)

## Notes

- `required_postconditions` are template-wide. Keep them shared across actions.
- `typed_params.calls[*].args` for tuple ABI inputs must be JSON arrays in exact component order.
- Replace `0x1111...1111` placeholders in simulate/execute payloads with the automaton EVM address.
