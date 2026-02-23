use crate::domain::types::{ExecutionPlan, ValidationFinding, ValidationLayer, ValidationReport};
use crate::features::evm::HttpEvmRpcClient;
use crate::storage::stable;
use crate::strategy::registry;
use alloy_primitives::U256;
use serde::Deserialize;
use std::future::Future;
use std::str::FromStr;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

#[derive(Clone, Debug, Deserialize, Default)]
struct ConstraintPolicy {
    #[serde(default)]
    max_calls: Option<usize>,
    #[serde(default)]
    max_total_value_wei: Option<String>,
    #[serde(default)]
    max_notional_wei: Option<String>,
    #[serde(default)]
    max_value_wei_per_call: Option<String>,
    #[serde(default)]
    template_budget_wei: Option<String>,
    #[serde(default)]
    required_postconditions: Vec<String>,
}

pub fn validate_execution_plan(plan: &ExecutionPlan) -> Result<ValidationReport, String> {
    let snapshot = stable::runtime_snapshot();
    let mut findings = Vec::new();

    validate_schema_layer(plan, &mut findings);
    let template = registry::get_template(&plan.key, &plan.version);
    validate_address_layer(plan, template.as_ref(), &snapshot, &mut findings);
    validate_policy_layer(plan, template.as_ref(), &mut findings);
    validate_preflight_layer(plan, &snapshot, &mut findings);
    validate_postcondition_layer(plan, template.as_ref(), &mut findings);

    Ok(ValidationReport {
        passed: findings.is_empty(),
        findings,
        checked_at_ns: current_time_ns(),
    })
}

pub fn classify_failure_determinism(error: &str) -> bool {
    let normalized = error.to_ascii_lowercase();
    let nondeterministic_markers = [
        "timeout",
        "temporarily unavailable",
        "connection reset",
        "connection refused",
        "network",
        "dns",
        "tls",
        "503",
        "502",
        "429",
        "gateway",
        "rate limit",
        "deadline exceeded",
    ];
    if nondeterministic_markers
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return false;
    }

    let deterministic_markers = [
        "invalid",
        "missing",
        "mismatch",
        "must be",
        "revert",
        "rejected",
        "unsupported",
        "overflow",
        "underflow",
        "insufficient balance",
        "insufficient allowance",
        "not configured",
        "kill switch",
        "revoked",
        "inactive",
        "decode",
    ];
    if deterministic_markers
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return true;
    }

    true
}

fn validate_schema_layer(plan: &ExecutionPlan, findings: &mut Vec<ValidationFinding>) {
    if plan.key.protocol.trim().is_empty() {
        findings.push(finding(
            ValidationLayer::Schema,
            "missing_protocol",
            "strategy protocol must be non-empty".to_string(),
            true,
        ));
    }
    if plan.key.primitive.trim().is_empty() {
        findings.push(finding(
            ValidationLayer::Schema,
            "missing_primitive",
            "strategy primitive must be non-empty".to_string(),
            true,
        ));
    }
    if plan.key.template_id.trim().is_empty() {
        findings.push(finding(
            ValidationLayer::Schema,
            "missing_template_id",
            "strategy template_id must be non-empty".to_string(),
            true,
        ));
    }
    if plan.key.chain_id == 0 {
        findings.push(finding(
            ValidationLayer::Schema,
            "invalid_chain_id",
            "strategy chain_id must be greater than zero".to_string(),
            true,
        ));
    }
    if plan.action_id.trim().is_empty() {
        findings.push(finding(
            ValidationLayer::Schema,
            "missing_action_id",
            "strategy action_id must be non-empty".to_string(),
            true,
        ));
    }
    if plan.calls.is_empty() {
        findings.push(finding(
            ValidationLayer::Schema,
            "missing_calls",
            "execution plan must include at least one call".to_string(),
            true,
        ));
    }

    for (index, call) in plan.calls.iter().enumerate() {
        if call.role.trim().is_empty() {
            findings.push(finding(
                ValidationLayer::Schema,
                "missing_call_role",
                format!("call[{index}] role must be non-empty"),
                true,
            ));
        }
        if parse_u256_decimal(&call.value_wei, "value_wei").is_err() {
            findings.push(finding(
                ValidationLayer::Schema,
                "invalid_value_wei",
                format!("call[{index}] value_wei must be a decimal string"),
                true,
            ));
        }
        if let Err(error) = normalize_hex_blob(&call.data, "data") {
            findings.push(finding(
                ValidationLayer::Schema,
                "invalid_calldata",
                format!("call[{index}] invalid calldata: {error}"),
                true,
            ));
        } else if call.data.trim().len() < 10 {
            findings.push(finding(
                ValidationLayer::Schema,
                "missing_selector",
                format!("call[{index}] calldata must include at least a 4-byte selector"),
                true,
            ));
        }
    }
}

fn validate_address_layer(
    plan: &ExecutionPlan,
    template: Option<&crate::domain::types::StrategyTemplate>,
    snapshot: &crate::domain::types::RuntimeSnapshot,
    findings: &mut Vec<ValidationFinding>,
) {
    if snapshot.evm_cursor.chain_id != plan.key.chain_id {
        findings.push(finding(
            ValidationLayer::Address,
            "chain_id_mismatch",
            format!(
                "runtime chain_id {} does not match plan chain_id {}",
                snapshot.evm_cursor.chain_id, plan.key.chain_id
            ),
            true,
        ));
    }

    for (index, call) in plan.calls.iter().enumerate() {
        if let Err(error) = normalize_address(&call.to) {
            findings.push(finding(
                ValidationLayer::Address,
                "invalid_to_address",
                format!("call[{index}] invalid to address: {error}"),
                true,
            ));
        }
    }

    let Some(template) = template else {
        findings.push(finding(
            ValidationLayer::Address,
            "template_not_found",
            "strategy template not found for execution plan key/version".to_string(),
            true,
        ));
        return;
    };

    for (index, call) in plan.calls.iter().enumerate() {
        let role = call.role.trim();
        let Some(binding) = template
            .contract_roles
            .iter()
            .find(|binding| binding.role == role)
        else {
            findings.push(finding(
                ValidationLayer::Address,
                "missing_role_binding",
                format!("call[{index}] missing role binding for role={role}"),
                true,
            ));
            continue;
        };
        if binding.source_ref.trim().is_empty() {
            findings.push(finding(
                ValidationLayer::Address,
                "missing_source_ref",
                format!("role binding {role} is missing source_ref"),
                true,
            ));
            continue;
        }
        let expected = normalize_address(&binding.address);
        let actual = normalize_address(&call.to);
        if let (Ok(expected), Ok(actual)) = (expected, actual) {
            if expected != actual {
                findings.push(finding(
                    ValidationLayer::Address,
                    "binding_address_mismatch",
                    format!("call[{index}] to address does not match role binding {role}"),
                    true,
                ));
            }
        }
    }
}

fn validate_policy_layer(
    plan: &ExecutionPlan,
    template: Option<&crate::domain::types::StrategyTemplate>,
    findings: &mut Vec<ValidationFinding>,
) {
    let Some(template) = template else {
        return;
    };

    if !matches!(
        template.status,
        crate::domain::types::TemplateStatus::Active
    ) {
        findings.push(finding(
            ValidationLayer::Policy,
            "template_not_active",
            "strategy template status is not Active".to_string(),
            true,
        ));
    }

    match registry::activation(&plan.key, &plan.version) {
        Some(state) if state.enabled => {}
        Some(_state) => findings.push(finding(
            ValidationLayer::Policy,
            "activation_disabled",
            "strategy template activation is disabled".to_string(),
            true,
        )),
        None => findings.push(finding(
            ValidationLayer::Policy,
            "activation_missing",
            "strategy template activation record is missing".to_string(),
            true,
        )),
    }

    if let Some(state) = registry::revocation(&plan.key, &plan.version) {
        if state.revoked {
            findings.push(finding(
                ValidationLayer::Policy,
                "template_revoked",
                "strategy template is revoked".to_string(),
                true,
            ));
        }
    }

    if let Some(state) = registry::kill_switch(&plan.key) {
        if state.enabled {
            findings.push(finding(
                ValidationLayer::Policy,
                "kill_switch_enabled",
                "strategy kill switch is enabled".to_string(),
                true,
            ));
        }
    }

    let constraints = parse_constraints_policy(&template.constraints_json, findings);
    if let Some(max_calls) = constraints.max_calls {
        if plan.calls.len() > max_calls {
            findings.push(finding(
                ValidationLayer::Policy,
                "max_calls_exceeded",
                format!(
                    "execution plan has {} calls but max_calls is {max_calls}",
                    plan.calls.len()
                ),
                true,
            ));
        }
    }

    let mut total_value = U256::ZERO;
    for (index, call) in plan.calls.iter().enumerate() {
        let Ok(value_wei) = parse_u256_decimal(&call.value_wei, "value_wei") else {
            continue;
        };
        total_value = total_value.saturating_add(value_wei);

        if let Some(raw_limit) = constraints.max_notional_wei.as_deref() {
            if let Ok(limit) = parse_u256_decimal(raw_limit, "max_notional_wei") {
                if value_wei > limit {
                    findings.push(finding(
                        ValidationLayer::Policy,
                        "max_notional_exceeded",
                        format!(
                            "call[{index}] value_wei={} exceeds max_notional_wei={}",
                            call.value_wei, raw_limit
                        ),
                        true,
                    ));
                }
            } else {
                findings.push(finding(
                    ValidationLayer::Policy,
                    "invalid_max_notional_wei",
                    format!("constraints max_notional_wei is invalid: {raw_limit}"),
                    true,
                ));
            }
        }

        if let Some(raw_limit) = constraints.max_value_wei_per_call.as_deref() {
            if let Ok(limit) = parse_u256_decimal(raw_limit, "max_value_wei_per_call") {
                if value_wei > limit {
                    findings.push(finding(
                        ValidationLayer::Policy,
                        "value_per_call_exceeded",
                        format!(
                            "call[{index}] value_wei={} exceeds max_value_wei_per_call={}",
                            call.value_wei, raw_limit
                        ),
                        true,
                    ));
                }
            }
        }
    }

    if let Some(raw_limit) = constraints.max_total_value_wei.as_deref() {
        if let Ok(limit) = parse_u256_decimal(raw_limit, "max_total_value_wei") {
            if total_value > limit {
                findings.push(finding(
                    ValidationLayer::Policy,
                    "max_total_value_exceeded",
                    format!(
                        "plan total value {} exceeds max_total_value_wei={raw_limit}",
                        total_value
                    ),
                    true,
                ));
            }
        } else {
            findings.push(finding(
                ValidationLayer::Policy,
                "invalid_max_total_value_wei",
                format!("constraints max_total_value_wei is invalid: {raw_limit}"),
                true,
            ));
        }
    }

    if let Some(raw_limit) = constraints.max_notional_wei.as_deref() {
        if let Ok(limit) = parse_u256_decimal(raw_limit, "max_notional_wei") {
            if total_value > limit {
                findings.push(finding(
                    ValidationLayer::Policy,
                    "total_notional_exceeded",
                    format!(
                        "plan total value {} exceeds max_notional_wei={raw_limit}",
                        total_value
                    ),
                    true,
                ));
            }
        }
    }

    if let Some(raw_limit) = constraints.template_budget_wei.as_deref() {
        if let Ok(limit) = parse_u256_decimal(raw_limit, "template_budget_wei") {
            let spent_raw = stable::strategy_template_budget_spent_wei(&plan.key, &plan.version)
                .unwrap_or_else(|| "0".to_string());
            if let Ok(spent) = parse_u256_decimal(&spent_raw, "strategy budget spent_wei") {
                let projected = spent.saturating_add(total_value);
                if projected > limit {
                    findings.push(finding(
                        ValidationLayer::Policy,
                        "template_budget_exceeded",
                        format!(
                            "projected template spend {} exceeds template_budget_wei={} (current_spent={})",
                            projected, raw_limit, spent_raw
                        ),
                        true,
                    ));
                }
            } else {
                findings.push(finding(
                    ValidationLayer::Policy,
                    "invalid_template_budget_state",
                    format!("stored template budget spent_wei is invalid: {spent_raw}"),
                    true,
                ));
            }
        } else {
            findings.push(finding(
                ValidationLayer::Policy,
                "invalid_template_budget_wei",
                format!("constraints template_budget_wei is invalid: {raw_limit}"),
                true,
            ));
        }
    }

    if !constraints.required_postconditions.is_empty() {
        for required in &constraints.required_postconditions {
            if !plan.postconditions.contains(required) {
                findings.push(finding(
                    ValidationLayer::Policy,
                    "required_postcondition_missing",
                    format!("missing required postcondition: {required}"),
                    true,
                ));
            }
        }
    }
}

fn validate_preflight_layer(
    plan: &ExecutionPlan,
    snapshot: &crate::domain::types::RuntimeSnapshot,
    findings: &mut Vec<ValidationFinding>,
) {
    if !findings.is_empty() {
        findings.push(finding(
            ValidationLayer::Preflight,
            "preflight_skipped_due_to_prior_failures",
            "preflight skipped because earlier validation layers failed".to_string(),
            true,
        ));
        return;
    }

    let from = match snapshot.evm_address.as_deref() {
        Some(address) => match normalize_address(address) {
            Ok(address) => address,
            Err(error) => {
                findings.push(finding(
                    ValidationLayer::Preflight,
                    "invalid_from_address",
                    format!("runtime evm address is invalid: {error}"),
                    true,
                ));
                return;
            }
        },
        None => {
            findings.push(finding(
                ValidationLayer::Preflight,
                "missing_from_address",
                "runtime evm address is not configured".to_string(),
                true,
            ));
            return;
        }
    };

    let rpc = match HttpEvmRpcClient::from_snapshot(snapshot) {
        Ok(rpc) => rpc,
        Err(error) => {
            findings.push(finding(
                ValidationLayer::Preflight,
                "preflight_unavailable",
                format!("failed to initialize rpc preflight client: {error}"),
                classify_failure_determinism(&error),
            ));
            return;
        }
    };

    for (index, call) in plan.calls.iter().enumerate() {
        let Ok(value_wei) = parse_u256_decimal(&call.value_wei, "value_wei") else {
            continue;
        };
        match block_on_with_spin(rpc.eth_estimate_gas(&from, &call.to, value_wei, &call.data)) {
            Ok(_estimate) => {}
            Err(error) => findings.push(finding(
                ValidationLayer::Preflight,
                "estimate_gas_failed",
                format!("call[{index}] eth_estimateGas failed: {error}"),
                classify_failure_determinism(&error),
            )),
        }

        match block_on_with_spin(rpc.eth_call(&call.to, &call.data)) {
            Ok(_result) => {}
            Err(error) => findings.push(finding(
                ValidationLayer::Preflight,
                "eth_call_failed",
                format!("call[{index}] eth_call failed: {error}"),
                classify_failure_determinism(&error),
            )),
        }
    }
}

fn validate_postcondition_layer(
    plan: &ExecutionPlan,
    _template: Option<&crate::domain::types::StrategyTemplate>,
    findings: &mut Vec<ValidationFinding>,
) {
    if plan.postconditions.is_empty() {
        findings.push(finding(
            ValidationLayer::Postcondition,
            "missing_postconditions",
            "execution plan must include postconditions".to_string(),
            true,
        ));
        return;
    }
    for (index, postcondition) in plan.postconditions.iter().enumerate() {
        if postcondition.trim().is_empty() {
            findings.push(finding(
                ValidationLayer::Postcondition,
                "empty_postcondition",
                format!("postconditions[{index}] must be non-empty"),
                true,
            ));
        }
    }
}

fn parse_constraints_policy(raw: &str, findings: &mut Vec<ValidationFinding>) -> ConstraintPolicy {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ConstraintPolicy::default();
    }
    match serde_json::from_str::<ConstraintPolicy>(trimmed) {
        Ok(policy) => policy,
        Err(error) => {
            findings.push(finding(
                ValidationLayer::Policy,
                "invalid_constraints_json",
                format!("template constraints_json is invalid: {error}"),
                true,
            ));
            ConstraintPolicy::default()
        }
    }
}

fn parse_u256_decimal(raw: &str, field: &str) -> Result<U256, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    if !trimmed.as_bytes().iter().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{field} must be a decimal string"));
    }
    U256::from_str(trimmed).map_err(|error| format!("failed to parse {field}: {error}"))
}

fn normalize_hex_blob(raw: &str, field: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .ok_or_else(|| format!("{field} must be 0x-prefixed hex"))?;
    if without_prefix.len() % 2 != 0 {
        return Err(format!("{field} hex length must be even"));
    }
    if !without_prefix
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("{field} must be valid hex"));
    }
    Ok(trimmed)
}

fn normalize_address(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let valid = trimmed.len() == 42
        && trimmed.starts_with("0x")
        && trimmed
            .as_bytes()
            .iter()
            .skip(2)
            .all(|byte| byte.is_ascii_hexdigit());
    if !valid {
        return Err("address must be a 0x-prefixed 20-byte hex string".to_string());
    }
    Ok(trimmed)
}

fn finding(
    layer: ValidationLayer,
    code: &str,
    message: String,
    deterministic: bool,
) -> ValidationFinding {
    ValidationFinding {
        layer,
        code: code.to_string(),
        message,
        deterministic,
    }
}

fn current_time_ns() -> u64 {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::time();

    #[cfg(not(target_arch = "wasm32"))]
    return 1;
}

fn block_on_with_spin<F: Future>(future: F) -> F::Output {
    unsafe fn clone(_ptr: *const ()) -> RawWaker {
        dummy_raw_waker()
    }
    unsafe fn wake(_ptr: *const ()) {}
    unsafe fn wake_by_ref(_ptr: *const ()) {}
    unsafe fn drop(_ptr: *const ()) {}

    fn dummy_raw_waker() -> RawWaker {
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        RawWaker::new(std::ptr::null(), &VTABLE)
    }

    let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);

    for _ in 0..10_000 {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::hint::spin_loop(),
        }
    }

    panic!("future did not complete in validator polling loop");
}

#[cfg(test)]
mod tests {
    use super::{classify_failure_determinism, validate_execution_plan};
    use crate::domain::types::{
        ActionSpec, ContractRoleBinding, ExecutionPlan, StrategyExecutionCall, StrategyTemplate,
        StrategyTemplateKey, TemplateActivationState, TemplateStatus, TemplateVersion,
    };
    use crate::storage::stable;
    use crate::strategy::registry;

    fn sample_key(template_id: &str) -> StrategyTemplateKey {
        StrategyTemplateKey {
            protocol: "erc20".to_string(),
            primitive: "transfer".to_string(),
            chain_id: 8453,
            template_id: template_id.to_string(),
        }
    }

    fn sample_version() -> TemplateVersion {
        TemplateVersion {
            major: 1,
            minor: 0,
            patch: 0,
        }
    }

    fn sample_plan(template_id: &str) -> ExecutionPlan {
        ExecutionPlan {
            key: sample_key(template_id),
            version: sample_version(),
            action_id: "transfer".to_string(),
            calls: vec![StrategyExecutionCall {
                role: "token".to_string(),
                to: "0x2222222222222222222222222222222222222222".to_string(),
                value_wei: "0".to_string(),
                data: "0xa9059cbb00000000000000000000000033333333333333333333333333333333333333330000000000000000000000000000000000000000000000000000000000000001".to_string(),
            }],
            preconditions: vec!["allowance_ok".to_string()],
            postconditions: vec!["balance_delta_gt_zero".to_string()],
        }
    }

    fn seed_template(template_id: &str) {
        let key = sample_key(template_id);
        let version = sample_version();
        registry::upsert_template(StrategyTemplate {
            key: key.clone(),
            version: version.clone(),
            status: TemplateStatus::Active,
            contract_roles: vec![ContractRoleBinding {
                role: "token".to_string(),
                address: "0x2222222222222222222222222222222222222222".to_string(),
                source_ref: "https://example.com/token".to_string(),
                codehash: None,
            }],
            actions: vec![ActionSpec {
                action_id: "transfer".to_string(),
                call_sequence: Vec::new(),
                preconditions: vec!["allowance_ok".to_string()],
                postconditions: vec!["balance_delta_gt_zero".to_string()],
                risk_checks: vec!["max_notional".to_string()],
            }],
            constraints_json: r#"{"max_calls":2,"max_total_value_wei":"1000"}"#.to_string(),
            created_at_ns: 1,
            updated_at_ns: 1,
        })
        .expect("template should persist");
        registry::set_activation(TemplateActivationState {
            key,
            version,
            enabled: true,
            updated_at_ns: 1,
            reason: None,
        })
        .expect("activation should persist");
    }

    #[test]
    fn validate_execution_plan_passes_for_valid_plan() {
        stable::init_storage();
        stable::set_evm_chain_id(8453).expect("chain id should persist");
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc should persist");
        stable::set_ecdsa_key_name("dfx_test_key".to_string()).expect("key should persist");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should persist");
        let template_id = "validator-pass";
        seed_template(template_id);

        let report = validate_execution_plan(&sample_plan(template_id))
            .expect("validator should return a report");
        assert!(
            report.passed,
            "report should pass, findings={:?}",
            report.findings
        );
        assert!(report.findings.is_empty());
    }

    #[test]
    fn validate_execution_plan_fails_closed_when_kill_switch_is_enabled() {
        stable::init_storage();
        stable::set_evm_chain_id(8453).expect("chain id should persist");
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc should persist");
        stable::set_ecdsa_key_name("dfx_test_key".to_string()).expect("key should persist");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should persist");
        let template_id = "validator-kill-switch";
        let key = sample_key(template_id);
        seed_template(template_id);
        registry::set_kill_switch(crate::domain::types::StrategyKillSwitchState {
            key,
            enabled: true,
            updated_at_ns: 1,
            reason: Some("manual override".to_string()),
        })
        .expect("kill switch should persist");

        let report = validate_execution_plan(&sample_plan(template_id))
            .expect("validator should return a report");
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|finding| { finding.code == "kill_switch_enabled" && finding.deterministic }));
    }

    #[test]
    fn classify_failure_determinism_distinguishes_revert_and_transport_errors() {
        assert!(classify_failure_determinism(
            "execution reverted: slippage exceeded"
        ));
        assert!(!classify_failure_determinism(
            "rpc timeout while talking to upstream"
        ));
    }

    #[test]
    fn validate_execution_plan_enforces_template_budget_cap() {
        stable::init_storage();
        stable::set_evm_chain_id(8453).expect("chain id should persist");
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc should persist");
        stable::set_ecdsa_key_name("dfx_test_key".to_string()).expect("key should persist");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should persist");
        let template_id = "validator-budget";
        seed_template(template_id);
        let key = sample_key(template_id);
        let version = sample_version();

        let mut template = registry::get_template(&key, &version).expect("template should exist");
        template.constraints_json =
            r#"{"template_budget_wei":"0","max_calls":2,"max_total_value_wei":"1000"}"#.to_string();
        registry::upsert_template(template).expect("template should update");
        stable::set_strategy_template_budget_spent_wei(&key, &version, "0".to_string())
            .expect("budget spent should persist");

        let mut plan = sample_plan(template_id);
        plan.calls[0].value_wei = "1".to_string();
        let report = validate_execution_plan(&plan).expect("validator should return report");
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "template_budget_exceeded"));
    }

    #[test]
    fn validate_execution_plan_enforces_max_notional_cap() {
        stable::init_storage();
        stable::set_evm_chain_id(8453).expect("chain id should persist");
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc should persist");
        stable::set_ecdsa_key_name("dfx_test_key".to_string()).expect("key should persist");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should persist");
        let template_id = "validator-notional";
        seed_template(template_id);
        let key = sample_key(template_id);
        let version = sample_version();

        let mut template = registry::get_template(&key, &version).expect("template should exist");
        template.constraints_json =
            r#"{"max_notional_wei":"0","max_calls":2,"max_total_value_wei":"1000"}"#.to_string();
        registry::upsert_template(template).expect("template should update");

        let mut plan = sample_plan(template_id);
        plan.calls[0].value_wei = "1".to_string();
        let report = validate_execution_plan(&plan).expect("validator should return report");
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "max_notional_exceeded"));
    }
}
