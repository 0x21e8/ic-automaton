# Strategy Template Authoring Checklist

## Required Fields

- `key.protocol`
- `key.primitive`
- `key.chain_id`
- `key.template_id`
- `version.major`
- `version.minor`
- `version.patch`
- `status`
- `contract_roles[]` with `role`, `address`, `source_ref`
- `actions[]` with `action_id`, `call_sequence`, `preconditions`, `postconditions`, `risk_checks`
- `constraints_json`

## Defaults

- `chain_id`: `8453` (Base)
- `version`: `1.0.0`
- `status`: `Draft`

## `constraints_json` Keys

Use only:

- `max_calls`
- `max_total_value_wei`
- `max_notional_wei`
- `max_value_wei_per_call`
- `template_budget_wei`
- `required_postconditions`

Example:

```json
{
  "max_calls": 2,
  "max_total_value_wei": "0",
  "max_notional_wei": "0",
  "max_value_wei_per_call": "0",
  "template_budget_wei": "0",
  "required_postconditions": ["wallet_usdc_delta_positive_expected"]
}
```

## Minimal Action Shape

```json
{
  "action_id": "enter",
  "call_sequence": [
    {
      "role": "router",
      "name": "exactInputSingle",
      "selector_hex": "0x414bf389"
    }
  ],
  "preconditions": ["liquidity_ok"],
  "postconditions": ["wallet_usdc_delta_positive_expected"],
  "risk_checks": ["max_slippage_bps_obeyed"]
}
```

## Quality Gates Before Activation

- Every `contract_roles` address has a trusted `source_ref`.
- `call_sequence` function selectors match canonical signatures.
- `preconditions`/`postconditions` are concrete and testable.
- `required_postconditions` are present in plan postconditions.
- Template remains `Draft` until preflight simulation passes.
