//! Cycle budget estimation and affordability checks.
//!
//! This module answers the question "can this canister afford to run a given
//! operation right now?" by:
//!
//! 1. **Estimating** the cycle cost of an `OperationClass` (HTTP outcall,
//!    threshold sign, or a pre-computed envelope).
//! 2. **Computing** an `AffordabilityRequirements` struct that adds a safety
//!    margin and a reserve floor to the raw estimate.
//! 3. **Deciding** affordability by comparing the canister's current liquid
//!    balance against the requirements.
//!
//! # Key constants
//!
//! | Constant                      | Value                |
//! |-------------------------------|----------------------|
//! | `DEFAULT_SAFETY_MARGIN_BPS`   | 2 500 bps (25 %)     |
//! | `DEFAULT_RESERVE_FLOOR_CYCLES`| 200 000 000 000      |

// ── Operation classes ────────────────────────────────────────────────────────

/// The class of operation whose cycle cost is to be estimated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationClass {
    /// An HTTPS outcall; cost depends on request size and max response bytes.
    HttpOutcall {
        request_size_bytes: u64,
        max_response_bytes: u64,
    },
    /// A threshold-ECDSA signing call; cost is key-name and curve dependent.
    #[allow(dead_code)]
    ThresholdSign { key_name: String, ecdsa_curve: u32 },
    /// A caller-provided cycle envelope (e.g. for inter-canister calls).
    WorkflowEnvelope { envelope_cycles: u128 },
}

// ── Affordability types and constants ────────────────────────────────────────

/// Fully expanded affordability requirements for a single operation.
///
/// Created by `affordability_requirements`; consumed by `can_afford`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffordabilityRequirements {
    /// Raw estimated cycle cost of the operation.
    pub estimated_cycles: u128,
    /// Safety margin rate in basis points (clamped to 10 000).
    pub safety_margin_bps: u32,
    /// Absolute safety buffer added on top of the estimate.
    pub safety_margin: u128,
    /// Minimum cycle reserve that must remain untouched after the operation.
    pub reserve_floor_cycles: u128,
    /// Total cycles required: `estimated + safety_margin + reserve_floor`.
    pub required_cycles: u128,
}

/// Default safety margin applied when no override is provided (25 %).
pub const DEFAULT_SAFETY_MARGIN_BPS: u32 = 2_500;
/// Default reserve floor: cycles that must remain in the canister at all times.
pub const DEFAULT_RESERVE_FLOOR_CYCLES: u128 = 200_000_000_000;
/// Assumed subnet size for non-replicated (host/test) cost estimation.
#[cfg(not(target_arch = "wasm32"))]
const NON_REPLICATED_DEFAULT_SUBNET_SIZE: u128 = 13;

// ── Public API ───────────────────────────────────────────────────────────────

/// Estimate the cycle cost of `operation`.
///
/// On `wasm32` targets this delegates to the IC system API; on other targets
/// it uses a conservative host-side approximation suitable for unit tests.
pub fn estimate_operation_cost(operation: &OperationClass) -> Result<u128, String> {
    match operation {
        OperationClass::HttpOutcall {
            request_size_bytes,
            max_response_bytes,
        } => Ok(estimate_http_outcall(
            *request_size_bytes,
            *max_response_bytes,
        )),
        OperationClass::ThresholdSign {
            key_name,
            ecdsa_curve,
        } => estimate_threshold_sign_cost(key_name, *ecdsa_curve),
        OperationClass::WorkflowEnvelope { envelope_cycles } => Ok(*envelope_cycles),
    }
}

/// Compute affordability requirements from an estimate and policy parameters.
///
/// `safety_margin_bps` is clamped to 10 000 (100 %).  The resulting
/// `required_cycles` = `estimated + safety_margin + reserve_floor`.
pub fn affordability_requirements(
    estimated_cycles: u128,
    safety_margin_bps: u32,
    reserve_floor_cycles: u128,
) -> AffordabilityRequirements {
    let clamped_margin_bps = safety_margin_bps.min(10_000);
    let safety_margin = (estimated_cycles.saturating_mul(u128::from(clamped_margin_bps))) / 10_000;
    let required_cycles = estimated_cycles
        .saturating_add(safety_margin)
        .saturating_add(reserve_floor_cycles);

    AffordabilityRequirements {
        estimated_cycles,
        safety_margin_bps: clamped_margin_bps,
        safety_margin,
        reserve_floor_cycles,
        required_cycles,
    }
}

/// Return `true` when `liquid_cycles` meets or exceeds the pre-computed requirements.
pub fn can_afford(liquid_cycles: u128, requirements: &AffordabilityRequirements) -> bool {
    liquid_cycles >= requirements.required_cycles
}

/// One-shot affordability check: estimate cost, compute requirements, decide.
///
/// `liquid_cycles` is the canister balance already reduced by any reserve the
/// caller wants to protect; `reserve_floor_cycles` is added on top.
#[allow(dead_code)]
pub fn can_afford_operation(
    liquid_cycles: u128,
    operation: &OperationClass,
    safety_margin_bps: u32,
    reserve_floor_cycles: u128,
) -> Result<bool, String> {
    let estimated = estimate_operation_cost(operation)?;
    let requirements =
        affordability_requirements(estimated, safety_margin_bps, reserve_floor_cycles);
    Ok(can_afford(liquid_cycles, &requirements))
}

/// Reserve-aware affordability check: deducts `reserve_floor_cycles` from
/// `total_cycles` first, then checks whether the remainder can cover the operation.
pub fn can_afford_with_reserve(
    total_cycles: u128,
    operation: &OperationClass,
    safety_margin_bps: u32,
    reserve_floor_cycles: u128,
) -> Result<bool, String> {
    let liquid_cycles = total_cycles.saturating_sub(reserve_floor_cycles);
    let estimated = estimate_operation_cost(operation)?;
    let requirements = affordability_requirements(estimated, safety_margin_bps, 0);
    Ok(can_afford(liquid_cycles, &requirements))
}

// ── Private cost estimators ──────────────────────────────────────────────────

/// Host-side HTTP outcall cost approximation using the IC pricing formula.
///
/// Formula: `(3_000_000 + 60_000 × n) × n + (400 × req + 800 × resp) × n`
/// where `n = NON_REPLICATED_DEFAULT_SUBNET_SIZE`.
#[cfg(not(target_arch = "wasm32"))]
fn estimate_http_outcall(request_size_bytes: u64, max_response_bytes: u64) -> u128 {
    let request_fee = 400u128
        .saturating_mul(u128::from(request_size_bytes))
        .saturating_add(800u128.saturating_mul(u128::from(max_response_bytes)));
    let subnet_fee = (3_000_000u128
        + 60_000u128.saturating_mul(NON_REPLICATED_DEFAULT_SUBNET_SIZE))
    .saturating_mul(NON_REPLICATED_DEFAULT_SUBNET_SIZE);
    let size_fee = request_fee.saturating_mul(NON_REPLICATED_DEFAULT_SUBNET_SIZE);
    subnet_fee.saturating_add(size_fee)
}

/// On-chain HTTP outcall cost via the IC system API.
#[cfg(target_arch = "wasm32")]
fn estimate_http_outcall(request_size_bytes: u64, max_response_bytes: u64) -> u128 {
    ic_cdk::api::cost_http_request(request_size_bytes, max_response_bytes)
}

/// Host-side threshold sign cost: fixed conservative estimate (~26.15 B cycles).
#[cfg(not(target_arch = "wasm32"))]
fn estimate_threshold_sign_cost(key_name: &str, _ecdsa_curve: u32) -> Result<u128, String> {
    if key_name.trim().is_empty() {
        return Err("threshold sign key_name cannot be empty".to_string());
    }
    Ok(26_153_846_153)
}

/// On-chain threshold sign cost via the IC system API.
#[cfg(target_arch = "wasm32")]
fn estimate_threshold_sign_cost(key_name: &str, ecdsa_curve: u32) -> Result<u128, String> {
    ic_cdk::api::cost_sign_with_ecdsa(key_name, ecdsa_curve).map_err(|error| {
        format!("failed to estimate threshold sign cost with key_name={key_name}, ecdsa_curve={ecdsa_curve}: {error}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_affordability_adds_safety_margin_and_reserve_floor() {
        let requirements = affordability_requirements(100, 2_500, 10);
        assert_eq!(requirements.required_cycles, 100u128 + 25u128 + 10u128);
        assert!(can_afford(100 + 25 + 10, &requirements));
        assert!(!can_afford(100 + 25 + 10 - 1, &requirements));
    }

    #[test]
    fn test_affordability_with_zero_margin() {
        let requirements = affordability_requirements(200, 0, 50);
        assert_eq!(requirements.required_cycles, 250);
        assert!(can_afford(250, &requirements));
        assert!(!can_afford(249, &requirements));
    }

    #[test]
    fn test_affordability_clamps_margin_bps_over_10000() {
        let requirements = affordability_requirements(100, 12_000, 0);
        assert_eq!(requirements.safety_margin_bps, 10_000);
        assert_eq!(requirements.safety_margin, 100);
        assert_eq!(requirements.required_cycles, 200);
    }

    #[test]
    fn test_workflow_envelope_cost_is_exact() {
        let estimate = estimate_operation_cost(&OperationClass::WorkflowEnvelope {
            envelope_cycles: 42_000,
        })
        .expect("workflow envelope should estimate");
        assert_eq!(estimate, 42_000);
    }

    #[test]
    fn test_can_afford_operation_evaluates_workflow_envelope_with_margin() {
        let operation = OperationClass::WorkflowEnvelope { envelope_cycles: 5 };
        let affordable = can_afford_operation(20, &operation, 1_000, DEFAULT_RESERVE_FLOOR_CYCLES)
            .expect("affordability should evaluate");
        assert!(!affordable);
    }

    #[test]
    fn test_can_afford_with_reserve_cycles_subtracts_total_balance() {
        let operation = OperationClass::WorkflowEnvelope {
            envelope_cycles: 10,
        };
        let affordable = can_afford_with_reserve(55, &operation, 0, 50)
            .expect("reserve-aware affordability should evaluate");
        assert!(!affordable);

        let affordable = can_afford_with_reserve(60, &operation, 0, 50)
            .expect("reserve-aware affordability should evaluate");
        assert!(affordable);

        let affordable = can_afford_with_reserve(80, &operation, 0, 50)
            .expect("reserve-aware affordability should evaluate");
        assert!(affordable);
    }

    #[test]
    fn test_threshold_sign_estimation_requires_key_name_on_host() {
        let error = estimate_operation_cost(&OperationClass::ThresholdSign {
            key_name: "".to_string(),
            ecdsa_curve: 0,
        })
        .expect_err("empty key should be invalid");
        assert!(error.contains("key_name cannot be empty"));
    }

    #[test]
    fn test_http_outcall_estimator_matches_host_formula_on_non_wasm() {
        let estimate = estimate_operation_cost(&OperationClass::HttpOutcall {
            request_size_bytes: 2_048,
            max_response_bytes: 16_000,
        })
        .expect("host estimate should be computable");
        assert!(estimate > 0);

        let request_fee = 400u128
            .saturating_mul(2_048u128)
            .saturating_add(800u128.saturating_mul(16_000u128));
        let subnet_fee = (3_000_000u128
            + 60_000u128.saturating_mul(NON_REPLICATED_DEFAULT_SUBNET_SIZE))
        .saturating_mul(NON_REPLICATED_DEFAULT_SUBNET_SIZE);
        let expected = subnet_fee
            .saturating_add(request_fee.saturating_mul(NON_REPLICATED_DEFAULT_SUBNET_SIZE));
        assert_eq!(estimate, expected);
    }
}
