# SolidityScan Triage: `evm/src/Inbox.sol`

This document tracks remediation status for the reported findings against the current Inbox implementation.

## Fixed in code

- `#1 CONTROLLED LOW-LEVEL CALL` (critical)
  - Added contract-level reentrancy protection (`nonReentrant`) on both external queue functions.
  - Added regression test with malicious receiver reentry attempt.

- `#4 EVENT BASED REENTRANCY` (low)
  - Same mitigation as #1 (`nonReentrant`) plus CEI ordering remains enforced.

- `#5 USE OF FLOATING PRAGMA` (low)
  - Updated Solidity pragma from floating to exact: `pragma solidity 0.8.32;`.

- `#6 OUTDATED COMPILER VERSION` (low)
  - Upgraded project compiler pin to latest stable release in this project: `0.8.32`.

- `#8, #10, #12, #14, #16, #17` (informational NatSpec/documentation)
  - Added NatSpec coverage for contract, constructor, public state vars, interface methods, and external/public functions.

- `#11 NAME MAPPING PARAMETERS` (informational)
  - Switched to named mapping keys in `Inbox.sol`.

- `#20 STORING STORAGE VARIABLES IN MEMORY` (gas)
  - `minPricesFor` now uses a storage reference instead of copying struct to memory.

- Additional hardening
  - Constructor now rejects non-contract token addresses using `code.length` check.
  - Removed low-level token call helper; USDC transfers now use typed `IERC20.transferFrom`.

## Accepted-by-design / false positive

- `#2 INCORRECT ACCESS CONTROL` (critical)
  - `setMinPrices` is intentionally self-scoped (`msg.sender` only). There is no admin/global mutable state in this function.

- `#3 ACCOUNT EXISTENCE CHECK FOR LOW LEVEL CALLS` (medium)
  - ETH forwarding target (`automaton`) is intentionally allowed to be either EOA or contract.
  - A contract-code check would break EOA automaton addresses.

- `#7 MISSING EVENTS` (low)
  - Core user action is already captured by `MessageQueued`.
  - USDC transfers emit ERC-20 `Transfer` event in token contract.

- `#13 REVERT STATEMENTS MAY CAUSE DOS` (informational)
  - Reverts are explicit validation guards for underpayment/invalid inputs and expected behavior.

- `#9 @inheritdoc on override functions` (informational)
  - Report appears tool-noise in this contract (no override implementations present).

## Deferred / not adopted

- `#15 underscore naming`, `#21 constants visibility`, `#23/#26/#27 micro gas if-condition tweaks`, `#24 payable constructor`, `#25 struct assignment style`, `#28 inline single-use function`.
  - Deferred intentionally to preserve readability and avoid unnecessary semantic risk for negligible gas savings.
