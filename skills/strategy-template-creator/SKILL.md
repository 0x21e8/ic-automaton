---
name: strategy-template-creator
description: Create and refine `StrategyTemplate` artifacts for `ic-automaton` on Base (chain `8453`) using source-backed addresses, ABI selectors, risk checks, and validator-compatible `constraints_json`. Use when asked to design custom strategies, produce annotated example strategies, convert market research into template JSON, or harden existing strategy templates before activation.
---

# Strategy Template Creator

Use this skill to turn opportunity research into safe, ingestible strategy templates that prioritize automaton survival (income generation with controlled downside and preserved cycle/inference runway).

## Workflow

1. Define the strategy target.
- Choose one `primitive` and one profit engine (carry, liquidation, LP fees, PT roll-down, etc.).
- Default to `chain_id = 8453` unless the user explicitly changes chain.
- Ensure the strategy serves automaton needs first, not human convenience.

2. Gather fresh evidence from primary sources.
- Pull current TVL, liquidity, APY, and volume snapshots (include concrete date in output).
- Pull deployment addresses from protocol-owned docs/repos or canonical APIs.
- Treat all market stats as time-volatile; always refresh instead of relying on memory.

3. Draft `StrategyTemplate` fields.
- Fill `key`, `version`, `status`, `contract_roles`, `actions`, and `constraints_json`.
- Keep `status = Draft` until activation checks are complete.
- Add `source_ref` per contract role; avoid unreferenced addresses.

4. Encode action safety.
- Add non-empty `preconditions`, `postconditions`, and `risk_checks`.
- Define explicit entry and exit conditions.
- Include at least one postcondition that protects or improves survival runway.

5. Apply validator-compatible constraints.
- Only use supported `constraints_json` keys:
  - `max_calls`
  - `max_total_value_wei`
  - `max_notional_wei`
  - `max_value_wei_per_call`
  - `template_budget_wei`
  - `required_postconditions`
- Keep values as strings where wei-denominated values are expected.

6. Deliver in requested format.
- If user asks for examples: provide annotated templates with thesis, triggers, risks, and source links.
- If user asks for ingestible output: return raw JSON-shaped template objects ready for registry ingestion.
- If uncertainty remains on addresses or callable surfaces: keep template in Draft and call out missing evidence.

## Repo Contracts

- `StrategyTemplate` model: `src/domain/types.rs`.
- Validation behavior and allowed constraint keys: `src/strategy/validator.rs`.
- Registry lifecycle semantics: `src/strategy/registry.rs`.

Use [template-authoring-checklist.md](references/template-authoring-checklist.md) for a compact checklist and defaults.
