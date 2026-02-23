use crate::domain::types::{
    AbiArtifact, AbiArtifactKey, StrategyKillSwitchState, StrategyOutcomeStats, StrategyTemplate,
    StrategyTemplateKey, TemplateActivationState, TemplateRevocationState, TemplateStatus,
    TemplateVersion,
};
use crate::storage::stable;
use crate::strategy::abi;
use std::collections::BTreeMap;

pub fn upsert_template(template: StrategyTemplate) -> Result<StrategyTemplate, String> {
    stable::upsert_strategy_template(template)
}

pub fn get_template(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Option<StrategyTemplate> {
    stable::strategy_template(key, version)
}

pub fn list_template_versions(key: &StrategyTemplateKey) -> Vec<TemplateVersion> {
    stable::list_strategy_template_versions(key)
}

pub fn list_templates(key: &StrategyTemplateKey, limit: usize) -> Vec<StrategyTemplate> {
    stable::list_strategy_templates(key, limit)
}

pub fn list_all_templates(limit: usize) -> Vec<StrategyTemplate> {
    stable::list_all_strategy_templates(limit)
}

pub fn upsert_abi_artifact(artifact: AbiArtifact) -> Result<AbiArtifact, String> {
    stable::upsert_abi_artifact(artifact)
}

pub fn get_abi_artifact(key: &AbiArtifactKey) -> Option<AbiArtifact> {
    stable::abi_artifact(key)
}

pub fn list_abi_artifact_versions(
    protocol: &str,
    chain_id: u64,
    role: &str,
) -> Vec<TemplateVersion> {
    stable::list_abi_artifact_versions(protocol, chain_id, role)
}

pub fn set_activation(state: TemplateActivationState) -> Result<TemplateActivationState, String> {
    stable::set_strategy_template_activation(state)
}

pub fn activation(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Option<TemplateActivationState> {
    stable::strategy_template_activation(key, version)
}

pub fn set_revocation(state: TemplateRevocationState) -> Result<TemplateRevocationState, String> {
    stable::set_strategy_template_revocation(state)
}

pub fn revocation(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Option<TemplateRevocationState> {
    stable::strategy_template_revocation(key, version)
}

pub fn set_kill_switch(state: StrategyKillSwitchState) -> Result<StrategyKillSwitchState, String> {
    stable::set_strategy_kill_switch(state)
}

pub fn kill_switch(key: &StrategyTemplateKey) -> Option<StrategyKillSwitchState> {
    stable::strategy_kill_switch(key)
}

pub fn outcome_stats(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Option<StrategyOutcomeStats> {
    stable::strategy_outcome_stats(key, version)
}

pub fn canary_probe_template(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Result<(), String> {
    let template = get_template(key, version).ok_or_else(|| {
        format!(
            "strategy template not found for {}:{}:{}:{}@{}.{}.{}",
            key.protocol,
            key.primitive,
            key.chain_id,
            key.template_id,
            version.major,
            version.minor,
            version.patch
        )
    })?;
    if matches!(template.status, TemplateStatus::Revoked) {
        return Err("cannot canary probe a revoked template".to_string());
    }
    if template.actions.is_empty() {
        return Err("template has no actions".to_string());
    }

    let role_bindings = template
        .contract_roles
        .iter()
        .map(|binding| {
            if binding.role.trim().is_empty() {
                return Err("contract role must be non-empty".to_string());
            }
            if binding.source_ref.trim().is_empty() {
                return Err(format!(
                    "contract role {} is missing source_ref",
                    binding.role
                ));
            }
            Ok((binding.role.trim().to_string(), binding.clone()))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    if role_bindings.is_empty() {
        return Err("template has no contract role bindings".to_string());
    }

    for action in &template.actions {
        if action.action_id.trim().is_empty() {
            return Err("template action_id must be non-empty".to_string());
        }
        if action.call_sequence.is_empty() {
            return Err(format!(
                "template action {} has an empty call_sequence",
                action.action_id
            ));
        }
        if action.postconditions.is_empty() {
            return Err(format!(
                "template action {} has no postconditions",
                action.action_id
            ));
        }

        for function in &action.call_sequence {
            let signature = abi::verify_function_selector(function)?;
            let role = function.role.trim();
            if role.is_empty() {
                return Err(format!(
                    "template action {} contains an empty call role",
                    action.action_id
                ));
            }
            if !role_bindings.contains_key(role) {
                return Err(format!(
                    "template action {} references unknown role {}",
                    action.action_id, role
                ));
            }

            let artifact_key = AbiArtifactKey {
                protocol: template.key.protocol.clone(),
                chain_id: template.key.chain_id,
                role: role.to_string(),
                version: template.version.clone(),
            };
            let artifact = get_abi_artifact(&artifact_key).ok_or_else(|| {
                format!(
                    "abi artifact missing for protocol={} role={} chain_id={} version={}.{}.{}",
                    artifact_key.protocol,
                    artifact_key.role,
                    artifact_key.chain_id,
                    artifact_key.version.major,
                    artifact_key.version.minor,
                    artifact_key.version.patch
                )
            })?;
            if artifact.source_ref.trim().is_empty() {
                return Err(format!(
                    "abi artifact source_ref missing for role={}",
                    artifact_key.role
                ));
            }
            let contains_signature = artifact.functions.iter().any(|candidate| {
                abi::verify_function_selector(candidate)
                    .map(|candidate_sig| candidate_sig == signature)
                    .unwrap_or(false)
            });
            if !contains_signature {
                return Err(format!(
                    "abi artifact role={} missing signature {}",
                    artifact_key.role, signature
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{
        AbiFunctionSpec, AbiTypeSpec, ActionSpec, ContractRoleBinding, StrategyTemplate,
    };

    fn key(template_id: &str) -> StrategyTemplateKey {
        StrategyTemplateKey {
            protocol: "erc20".to_string(),
            primitive: "transfer".to_string(),
            chain_id: 8453,
            template_id: template_id.to_string(),
        }
    }

    fn version() -> TemplateVersion {
        TemplateVersion {
            major: 1,
            minor: 0,
            patch: 0,
        }
    }

    fn seed_template(template_id: &str, selector_hex: &str) {
        let key = key(template_id);
        let version = version();
        let function = AbiFunctionSpec {
            role: "token".to_string(),
            name: "transfer".to_string(),
            selector_hex: selector_hex.to_string(),
            inputs: vec![
                AbiTypeSpec {
                    kind: "address".to_string(),
                    components: Vec::new(),
                },
                AbiTypeSpec {
                    kind: "uint256".to_string(),
                    components: Vec::new(),
                },
            ],
            outputs: vec![AbiTypeSpec {
                kind: "bool".to_string(),
                components: Vec::new(),
            }],
            state_mutability: "nonpayable".to_string(),
        };
        upsert_template(StrategyTemplate {
            key: key.clone(),
            version: version.clone(),
            status: TemplateStatus::Active,
            contract_roles: vec![ContractRoleBinding {
                role: "token".to_string(),
                address: "0x2222222222222222222222222222222222222222".to_string(),
                source_ref: "https://example.com/token-address".to_string(),
                codehash: None,
            }],
            actions: vec![ActionSpec {
                action_id: "transfer".to_string(),
                call_sequence: vec![function.clone()],
                preconditions: vec!["allowance_ok".to_string()],
                postconditions: vec!["balance_delta_positive".to_string()],
                risk_checks: vec!["max_notional".to_string()],
            }],
            constraints_json: "{}".to_string(),
            created_at_ns: 1,
            updated_at_ns: 1,
        })
        .expect("template should persist");
        upsert_abi_artifact(AbiArtifact {
            key: AbiArtifactKey {
                protocol: key.protocol.clone(),
                chain_id: key.chain_id,
                role: "token".to_string(),
                version,
            },
            source_ref: "https://example.com/token-abi".to_string(),
            codehash: None,
            abi_json: "[]".to_string(),
            functions: vec![function],
            created_at_ns: 1,
            updated_at_ns: 1,
        })
        .expect("abi should persist");
    }

    #[test]
    fn canary_probe_template_passes_when_template_and_artifact_align() {
        crate::storage::stable::init_storage();
        seed_template("registry-canary-pass", "0xa9059cbb");

        let result = canary_probe_template(&key("registry-canary-pass"), &version());
        assert!(result.is_ok(), "probe should pass: {result:?}");
    }

    #[test]
    fn canary_probe_template_fails_on_selector_mismatch() {
        crate::storage::stable::init_storage();
        seed_template("registry-canary-fail", "0xdeadbeef");

        let result = canary_probe_template(&key("registry-canary-fail"), &version());
        assert!(result.is_err(), "probe should fail");
    }
}
