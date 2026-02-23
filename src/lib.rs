mod agent;
mod domain;
mod features;
mod http;
pub mod prompt;
mod scheduler;
mod storage;
#[allow(dead_code)]
mod strategy;
mod tools;

use crate::domain::types::{
    AbiArtifact, AbiArtifactKey, AbiSelectorAssertion, ConversationLog, ConversationSummary,
    EvmRouteStateView, InboxMessage, InboxStats, InferenceConfigView, InferenceProvider,
    MemoryRollup, ObservabilitySnapshot, OutboxMessage, OutboxStats, PromptLayer, PromptLayerView,
    RetentionConfig, RetentionMaintenanceRuntime, RuntimeView, ScheduledJob, SchedulerRuntime,
    SessionSummary, SkillRecord, StrategyKillSwitchState, StrategyOutcomeStats, StrategyTemplate,
    StrategyTemplateKey, TaskKind, TaskScheduleConfig, TaskScheduleRuntime,
    TemplateActivationState, TemplateRevocationState, TemplateStatus, TemplateVersion,
    ToolCallRecord, TurnWindowSummary, WalletBalanceSyncConfigView, WalletBalanceTelemetryView,
};
use crate::scheduler::scheduler_tick;
use crate::storage::stable;
use crate::tools::ToolManager;
use candid::{CandidType, Principal};
use ic_cdk_timers::set_timer_interval_serial;
use ic_http_certification::{HttpRequest, HttpResponse, HttpUpdateRequest, HttpUpdateResponse};
use serde::Deserialize;
use std::time::Duration;

const SCHEDULER_TICK_INTERVAL_SECS: u64 = 30;

#[derive(CandidType, Deserialize)]
struct InitArgs {
    ecdsa_key_name: String,
    #[serde(default)]
    inbox_contract_address: Option<String>,
    #[serde(default)]
    evm_chain_id: Option<u64>,
    #[serde(default)]
    evm_rpc_url: Option<String>,
    #[serde(default)]
    evm_confirmation_depth: Option<u64>,
    #[serde(default)]
    http_allowed_domains: Option<Vec<String>>,
    #[serde(default)]
    llm_canister_id: Option<Principal>,
    #[serde(default)]
    cycle_topup_enabled: Option<bool>,
    #[serde(default)]
    auto_topup_cycle_threshold: Option<u64>,
}

#[derive(CandidType, Deserialize)]
struct StrategyAbiIngestArgs {
    key: AbiArtifactKey,
    abi_json: String,
    source_ref: String,
    #[serde(default)]
    codehash: Option<String>,
    #[serde(default)]
    selector_assertions: Vec<AbiSelectorAssertion>,
}

fn current_time_ns() -> u64 {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::time();

    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_nanos().try_into().unwrap_or(u64::MAX))
            .unwrap_or_default()
    }
}

fn ensure_controller() -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let caller = ic_cdk::api::msg_caller();
        if !ic_cdk::api::is_controller(&caller) {
            return Err("caller is not a controller".to_string());
        }
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        Ok(())
    }
}

fn ensure_controller_or_trap() {
    if let Err(error) = ensure_controller() {
        ic_cdk::trap(&error);
    }
}

fn caller_for_audit() -> String {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::msg_caller().to_text();

    #[cfg(not(target_arch = "wasm32"))]
    return "native".to_string();
}

fn require_strategy_template(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Result<StrategyTemplate, String> {
    crate::strategy::registry::get_template(key, version).ok_or_else(|| {
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
    })
}

fn upsert_template_status(
    key: StrategyTemplateKey,
    version: TemplateVersion,
    status: TemplateStatus,
) -> Result<StrategyTemplate, String> {
    let mut template = require_strategy_template(&key, &version)?;
    template.status = status;
    template.updated_at_ns = current_time_ns();
    crate::strategy::registry::upsert_template(template)
}

#[ic_cdk::init]
fn init(args: InitArgs) {
    apply_init_args(args);
    crate::features::MockSkillLoader::install_defaults();
    crate::http::init_certification();
    arm_timer();
}

fn apply_init_args(args: InitArgs) {
    stable::init_storage();
    let _ = stable::set_ecdsa_key_name(args.ecdsa_key_name)
        .unwrap_or_else(|error| ic_cdk::trap(&error));
    if let Some(chain_id) = args.evm_chain_id {
        let _ = stable::set_evm_chain_id(chain_id).unwrap_or_else(|error| ic_cdk::trap(&error));
    }
    if let Some(rpc_url) = args.evm_rpc_url {
        let _ = stable::set_evm_rpc_url(rpc_url).unwrap_or_else(|error| ic_cdk::trap(&error));
    }
    if let Some(confirmation_depth) = args.evm_confirmation_depth {
        let _ = stable::set_evm_confirmation_depth(confirmation_depth)
            .unwrap_or_else(|error| ic_cdk::trap(&error));
    }
    let _ = stable::set_evm_address(None).unwrap_or_else(|error| ic_cdk::trap(&error));
    let _ = stable::set_inbox_contract_address(args.inbox_contract_address)
        .unwrap_or_else(|error| ic_cdk::trap(&error));
    if let Some(domains) = args.http_allowed_domains {
        let _ =
            stable::set_http_allowed_domains(domains).unwrap_or_else(|error| ic_cdk::trap(&error));
    }
    if let Some(llm_canister_id) = args.llm_canister_id {
        let _ = stable::set_llm_canister_id(llm_canister_id.to_text())
            .unwrap_or_else(|error| ic_cdk::trap(&error));
    }

    let mut snapshot = stable::runtime_snapshot();
    let mut changed = false;
    if let Some(enabled) = args.cycle_topup_enabled {
        snapshot.cycle_topup.enabled = enabled;
        changed = true;
    }
    if let Some(threshold) = args.auto_topup_cycle_threshold {
        snapshot.cycle_topup.auto_topup_cycle_threshold = u128::from(threshold);
        changed = true;
    }
    if changed {
        stable::save_runtime_snapshot(&snapshot);
    }
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    stable::init_storage();
    crate::http::init_certification();
    arm_timer();
}

#[ic_cdk::update]
fn set_loop_enabled(enabled: bool) -> String {
    ensure_controller_or_trap();
    stable::set_loop_enabled(enabled);
    format!("loop_enabled={enabled}")
}

#[ic_cdk::update]
fn set_inference_provider(provider: InferenceProvider) -> String {
    stable::set_inference_provider(provider.clone());
    format!("inference_provider={provider:?}")
}

#[ic_cdk::update]
fn set_inference_model(model: String) -> Result<String, String> {
    stable::set_inference_model(model)
}

#[ic_cdk::update]
fn set_openrouter_base_url(base_url: String) -> Result<String, String> {
    stable::set_openrouter_base_url(base_url)
}

#[ic_cdk::update]
fn set_openrouter_api_key(api_key: Option<String>) -> String {
    stable::set_openrouter_api_key(api_key);
    "openrouter_api_key_updated".to_string()
}

#[ic_cdk::update]
fn set_evm_rpc_url(url: String) -> Result<String, String> {
    ensure_controller()?;
    stable::set_evm_rpc_url(url)
}

#[ic_cdk::update]
fn set_evm_rpc_fallback_url(url: Option<String>) -> Result<Option<String>, String> {
    ensure_controller()?;
    stable::set_evm_rpc_fallback_url(url)
}

#[ic_cdk::update]
fn set_evm_rpc_max_response_bytes(max_response_bytes: u64) -> Result<u64, String> {
    ensure_controller()?;
    stable::set_evm_rpc_max_response_bytes(max_response_bytes)
}

#[ic_cdk::update]
fn set_inbox_contract_address_admin(address: Option<String>) -> Result<Option<String>, String> {
    ensure_controller()?;
    stable::set_inbox_contract_address(address)
}

#[ic_cdk::update]
fn set_evm_chain_id_admin(chain_id: u64) -> Result<u64, String> {
    ensure_controller()?;
    stable::set_evm_chain_id(chain_id)
}

#[ic_cdk::update]
fn set_evm_confirmation_depth_admin(confirmation_depth: u64) -> Result<u64, String> {
    ensure_controller()?;
    stable::set_evm_confirmation_depth(confirmation_depth)
}

#[ic_cdk::update]
fn set_http_allowed_domains(domains: Vec<String>) -> Result<Vec<String>, String> {
    ensure_controller()?;
    stable::set_http_allowed_domains(domains)
}

#[ic_cdk::query]
fn get_runtime_view() -> RuntimeView {
    stable::snapshot_to_view()
}

#[ic_cdk::query]
fn get_evm_route_state_view() -> EvmRouteStateView {
    stable::evm_route_state_view()
}

#[ic_cdk::query]
fn get_automaton_evm_address() -> Option<String> {
    stable::get_automaton_evm_address()
}

#[ic_cdk::update]
fn set_automaton_evm_address_admin(address: Option<String>) -> Result<Option<String>, String> {
    ensure_controller()?;
    stable::set_evm_address(address)
}

#[ic_cdk::query]
fn get_wallet_balance_telemetry() -> WalletBalanceTelemetryView {
    stable::wallet_balance_telemetry_view()
}

#[ic_cdk::query]
fn get_wallet_balance_sync_config() -> WalletBalanceSyncConfigView {
    stable::wallet_balance_sync_config_view()
}

#[ic_cdk::query]
fn get_scheduler_view() -> SchedulerRuntime {
    stable::scheduler_runtime_view()
}

#[ic_cdk::query]
fn get_retention_config() -> RetentionConfig {
    stable::retention_config()
}

#[ic_cdk::query]
fn get_retention_maintenance_runtime() -> RetentionMaintenanceRuntime {
    stable::retention_maintenance_runtime()
}

#[ic_cdk::query]
fn list_scheduler_jobs(limit: u32) -> Vec<ScheduledJob> {
    stable::list_recent_jobs(limit as usize)
}

#[ic_cdk::query]
fn list_task_schedules() -> Vec<(TaskScheduleConfig, TaskScheduleRuntime)> {
    stable::list_task_schedules()
}

#[ic_cdk::query]
fn get_observability_snapshot(limit: u32) -> ObservabilitySnapshot {
    stable::observability_snapshot(limit as usize)
}

#[ic_cdk::update]
fn post_inbox_message(message: String) -> Result<String, String> {
    stable::post_inbox_message(message, ic_cdk::api::msg_caller().to_text())
}

#[ic_cdk::query]
fn list_inbox_messages(limit: u32) -> Vec<InboxMessage> {
    stable::list_inbox_messages(limit as usize)
}

#[ic_cdk::query]
fn get_prompt_layers() -> Vec<PromptLayerView> {
    stable::list_prompt_layers()
}

#[ic_cdk::update]
fn update_prompt_layer_admin(layer_id: u8, content: String) -> Result<PromptLayer, String> {
    ensure_controller()?;
    crate::tools::update_prompt_layer_content(
        layer_id,
        content,
        &format!("admin:{}", caller_for_audit()),
    )
}

#[ic_cdk::query]
fn list_conversations() -> Vec<ConversationSummary> {
    stable::list_conversation_summaries()
}

#[ic_cdk::query]
fn list_session_summaries(limit: u32) -> Vec<SessionSummary> {
    stable::list_session_summaries(limit as usize)
}

#[ic_cdk::query]
fn list_turn_window_summaries(limit: u32) -> Vec<TurnWindowSummary> {
    stable::list_turn_window_summaries(limit as usize)
}

#[ic_cdk::query]
fn list_memory_rollups(limit: u32) -> Vec<MemoryRollup> {
    stable::list_memory_rollups(limit as usize)
}

#[ic_cdk::query]
fn get_conversation(sender: String) -> Option<ConversationLog> {
    stable::get_conversation_log(&sender)
}

#[ic_cdk::query]
fn get_inbox_stats() -> InboxStats {
    stable::inbox_stats()
}

#[ic_cdk::query]
fn list_outbox_messages(limit: u32) -> Vec<OutboxMessage> {
    stable::list_outbox_messages(limit as usize)
}

#[ic_cdk::query]
fn get_outbox_stats() -> OutboxStats {
    stable::outbox_stats()
}

#[ic_cdk::update]
fn set_scheduler_enabled(enabled: bool) -> String {
    ensure_controller_or_trap();
    stable::set_scheduler_enabled(enabled)
}

#[ic_cdk::update]
fn set_scheduler_low_cycles_mode(enabled: bool) -> String {
    ensure_controller_or_trap();
    stable::set_scheduler_low_cycles_mode(enabled)
}

#[ic_cdk::update]
fn set_task_interval_secs(kind: TaskKind, interval_secs: u64) -> Result<String, String> {
    ensure_controller()?;
    stable::set_task_interval_secs(&kind, interval_secs)?;
    Ok("task_interval_updated".to_string())
}

#[ic_cdk::update]
fn set_task_enabled(kind: TaskKind, enabled: bool) -> String {
    ensure_controller_or_trap();
    stable::set_task_enabled(&kind, enabled);
    "task_enabled_updated".to_string()
}

#[ic_cdk::update]
fn set_retention_config(config: RetentionConfig) -> Result<RetentionConfig, String> {
    ensure_controller()?;
    stable::set_retention_config(config)
}

#[ic_cdk::query]
fn get_inference_config() -> InferenceConfigView {
    stable::inference_config_view()
}

#[ic_cdk::query]
fn get_soul() -> String {
    stable::get_soul()
}

#[ic_cdk::update]
fn update_soul(new_soul: String) -> Result<String, String> {
    ensure_controller()?;
    if new_soul.trim().is_empty() {
        return Err("soul cannot be empty".to_string());
    }
    Ok(stable::set_soul(new_soul))
}

#[ic_cdk::query]
fn list_recent_events(limit: u32) -> Vec<String> {
    stable::list_recent_transitions(limit as usize)
        .into_iter()
        .map(|record| format!("{record:?}"))
        .collect()
}

#[ic_cdk::query]
fn list_turns(limit: u32) -> Vec<String> {
    stable::list_turns(limit as usize)
        .into_iter()
        .map(|turn| format!("{turn:?}"))
        .collect()
}

#[ic_cdk::query]
fn list_skills() -> Vec<SkillRecord> {
    stable::list_skills()
}

#[ic_cdk::query]
fn list_tool_policies() -> Vec<String> {
    let manager = ToolManager::new();
    manager
        .list_tools()
        .into_iter()
        .map(|(name, policy)| format!("{name}: {policy:?}"))
        .collect()
}

#[ic_cdk::query]
fn get_tool_calls_for_turn(turn_id: String) -> Vec<ToolCallRecord> {
    stable::get_tools_for_turn(&turn_id)
}

#[ic_cdk::query]
fn list_strategy_templates(key: Option<StrategyTemplateKey>, limit: u32) -> Vec<StrategyTemplate> {
    let bounded_limit = limit.max(1) as usize;
    match key {
        Some(key) => crate::strategy::registry::list_templates(&key, bounded_limit),
        None => crate::strategy::registry::list_all_templates(bounded_limit),
    }
}

#[ic_cdk::query]
fn get_strategy_template(
    key: StrategyTemplateKey,
    version: TemplateVersion,
) -> Option<StrategyTemplate> {
    crate::strategy::registry::get_template(&key, &version)
}

#[ic_cdk::query]
fn get_strategy_outcome_stats(
    key: StrategyTemplateKey,
    version: TemplateVersion,
) -> Option<StrategyOutcomeStats> {
    crate::strategy::learner::outcome_stats(&key, &version)
}

#[ic_cdk::update]
fn ingest_strategy_template_admin(template: StrategyTemplate) -> Result<StrategyTemplate, String> {
    ensure_controller()?;
    let mut template = template;
    let now_ns = current_time_ns();
    if template.created_at_ns == 0 {
        template.created_at_ns = now_ns;
    }
    template.updated_at_ns = now_ns;
    crate::strategy::registry::upsert_template(template)
}

#[ic_cdk::update]
fn ingest_strategy_abi_artifact_admin(args: StrategyAbiIngestArgs) -> Result<AbiArtifact, String> {
    ensure_controller()?;
    crate::strategy::abi::normalize_and_store_abi_artifact(
        args.key,
        &args.abi_json,
        &args.source_ref,
        args.codehash,
        &args.selector_assertions,
        current_time_ns(),
    )
}

#[ic_cdk::update]
fn activate_strategy_template_admin(
    key: StrategyTemplateKey,
    version: TemplateVersion,
    reason: Option<String>,
) -> Result<TemplateActivationState, String> {
    ensure_controller()?;
    let _template = upsert_template_status(key.clone(), version.clone(), TemplateStatus::Active)?;
    crate::strategy::registry::canary_probe_template(&key, &version)?;
    crate::strategy::registry::set_activation(TemplateActivationState {
        key,
        version,
        enabled: true,
        updated_at_ns: current_time_ns(),
        reason: reason.or_else(|| Some("controller activation after canary probe".to_string())),
    })
}

#[ic_cdk::update]
fn deprecate_strategy_template_admin(
    key: StrategyTemplateKey,
    version: TemplateVersion,
    reason: Option<String>,
) -> Result<StrategyTemplate, String> {
    ensure_controller()?;
    let template =
        upsert_template_status(key.clone(), version.clone(), TemplateStatus::Deprecated)?;
    let _ = crate::strategy::registry::set_activation(TemplateActivationState {
        key,
        version,
        enabled: false,
        updated_at_ns: current_time_ns(),
        reason,
    });
    Ok(template)
}

#[ic_cdk::update]
fn revoke_strategy_template_admin(
    key: StrategyTemplateKey,
    version: TemplateVersion,
    reason: Option<String>,
) -> Result<TemplateRevocationState, String> {
    ensure_controller()?;
    let _ = upsert_template_status(key.clone(), version.clone(), TemplateStatus::Revoked)?;
    let now_ns = current_time_ns();
    let revocation = crate::strategy::registry::set_revocation(TemplateRevocationState {
        key: key.clone(),
        version: version.clone(),
        revoked: true,
        updated_at_ns: now_ns,
        reason: reason.clone(),
    })?;
    let _ = crate::strategy::registry::set_activation(TemplateActivationState {
        key,
        version,
        enabled: false,
        updated_at_ns: now_ns,
        reason: reason.or_else(|| Some("revoked".to_string())),
    });
    Ok(revocation)
}

#[ic_cdk::update]
fn set_strategy_kill_switch_admin(
    key: StrategyTemplateKey,
    enabled: bool,
    reason: Option<String>,
) -> Result<StrategyKillSwitchState, String> {
    ensure_controller()?;
    crate::strategy::registry::set_kill_switch(StrategyKillSwitchState {
        key,
        enabled,
        updated_at_ns: current_time_ns(),
        reason,
    })
}

#[ic_cdk::query]
fn http_request(request: HttpRequest) -> HttpResponse {
    crate::http::handle_http_request(request)
}

#[ic_cdk::update]
fn http_request_update(request: HttpUpdateRequest) -> HttpUpdateResponse {
    crate::http::handle_http_request_update(request)
}

fn arm_timer() {
    set_timer_interval_serial(
        Duration::from_secs(SCHEDULER_TICK_INTERVAL_SECS),
        scheduler_tick,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{
        AbiFunctionSpec, AbiTypeSpec, ActionSpec, ContractRoleBinding, StrategyTemplate,
        StrategyTemplateKey, TemplateStatus, TemplateVersion,
    };

    #[test]
    fn get_automaton_evm_address_query_returns_stored_value() {
        stable::init_storage();
        let expected = "0x1111111111111111111111111111111111111111".to_string();
        stable::set_evm_address(Some(expected.clone())).expect("automaton address should store");

        assert_eq!(get_automaton_evm_address(), Some(expected));
    }

    #[test]
    fn apply_init_args_can_seed_http_allowlist() {
        apply_init_args(InitArgs {
            ecdsa_key_name: "dfx_test_key".to_string(),
            inbox_contract_address: None,
            evm_chain_id: None,
            evm_rpc_url: None,
            evm_confirmation_depth: None,
            http_allowed_domains: Some(vec!["api.coingecko.com".to_string()]),
            llm_canister_id: None,
            cycle_topup_enabled: None,
            auto_topup_cycle_threshold: None,
        });

        assert!(stable::is_http_allowlist_enforced());
        assert_eq!(
            stable::list_allowed_http_domains(),
            vec!["api.coingecko.com".to_string()]
        );
    }

    #[test]
    fn apply_init_args_can_set_llm_canister_id() {
        apply_init_args(InitArgs {
            ecdsa_key_name: "dfx_test_key".to_string(),
            inbox_contract_address: None,
            evm_chain_id: None,
            evm_rpc_url: None,
            evm_confirmation_depth: None,
            http_allowed_domains: None,
            llm_canister_id: Some(
                Principal::from_text("w36hm-eqaaa-aaaal-qr76a-cai")
                    .expect("test principal should parse"),
            ),
            cycle_topup_enabled: None,
            auto_topup_cycle_threshold: None,
        });

        assert_eq!(stable::get_llm_canister_id(), "w36hm-eqaaa-aaaal-qr76a-cai");
    }

    #[test]
    fn apply_init_args_can_override_cycle_topup_controls() {
        apply_init_args(InitArgs {
            ecdsa_key_name: "dfx_test_key".to_string(),
            inbox_contract_address: None,
            evm_chain_id: None,
            evm_rpc_url: None,
            evm_confirmation_depth: None,
            http_allowed_domains: None,
            llm_canister_id: None,
            cycle_topup_enabled: Some(false),
            auto_topup_cycle_threshold: Some(150_000_000_000),
        });

        let snapshot = stable::runtime_snapshot();
        assert!(!snapshot.cycle_topup.enabled);
        assert_eq!(
            snapshot.cycle_topup.auto_topup_cycle_threshold,
            150_000_000_000
        );
    }

    fn sample_strategy_key() -> StrategyTemplateKey {
        StrategyTemplateKey {
            protocol: "erc20".to_string(),
            primitive: "transfer".to_string(),
            chain_id: 8453,
            template_id: "lib-strategy".to_string(),
        }
    }

    fn sample_version() -> TemplateVersion {
        TemplateVersion {
            major: 1,
            minor: 0,
            patch: 0,
        }
    }

    fn sample_template(status: TemplateStatus) -> StrategyTemplate {
        StrategyTemplate {
            key: sample_strategy_key(),
            version: sample_version(),
            status,
            contract_roles: vec![ContractRoleBinding {
                role: "token".to_string(),
                address: "0x2222222222222222222222222222222222222222".to_string(),
                source_ref: "https://example.com/token-address".to_string(),
                codehash: None,
            }],
            actions: vec![ActionSpec {
                action_id: "transfer".to_string(),
                call_sequence: vec![AbiFunctionSpec {
                    role: "token".to_string(),
                    name: "transfer".to_string(),
                    selector_hex: "0xa9059cbb".to_string(),
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
                }],
                preconditions: vec!["allowance_ok".to_string()],
                postconditions: vec!["balance_delta_positive".to_string()],
                risk_checks: vec!["max_notional".to_string()],
            }],
            constraints_json:
                r#"{"max_calls":1,"max_total_value_wei":"0","required_postconditions":["balance_delta_positive"]}"#
                    .to_string(),
            created_at_ns: 0,
            updated_at_ns: 0,
        }
    }

    fn seed_template_and_artifact() {
        ingest_strategy_template_admin(sample_template(TemplateStatus::Draft))
            .expect("template should ingest");
        ingest_strategy_abi_artifact_admin(StrategyAbiIngestArgs {
            key: AbiArtifactKey {
                protocol: "erc20".to_string(),
                chain_id: 8453,
                role: "token".to_string(),
                version: sample_version(),
            },
            abi_json: r#"[{"type":"function","name":"transfer","stateMutability":"nonpayable","inputs":[{"type":"address"},{"type":"uint256"}],"outputs":[{"type":"bool"}]}]"#.to_string(),
            source_ref: "https://example.com/token-abi".to_string(),
            codehash: None,
            selector_assertions: vec![AbiSelectorAssertion {
                signature: "transfer(address,uint256)".to_string(),
                selector_hex: "0xa9059cbb".to_string(),
            }],
        })
        .expect("abi should ingest");
    }

    #[test]
    fn strategy_lifecycle_admin_methods_manage_status_activation_and_kill_switch() {
        stable::init_storage();
        seed_template_and_artifact();

        let activated = activate_strategy_template_admin(
            sample_strategy_key(),
            sample_version(),
            Some("manual activation".to_string()),
        )
        .expect("activation should succeed");
        assert!(activated.enabled);

        let deprecated = deprecate_strategy_template_admin(
            sample_strategy_key(),
            sample_version(),
            Some("rotating template".to_string()),
        )
        .expect("deprecation should succeed");
        assert!(matches!(deprecated.status, TemplateStatus::Deprecated));

        let revoked = revoke_strategy_template_admin(
            sample_strategy_key(),
            sample_version(),
            Some("safety incident".to_string()),
        )
        .expect("revocation should succeed");
        assert!(revoked.revoked);

        let kill_switch = set_strategy_kill_switch_admin(
            sample_strategy_key(),
            true,
            Some("protocol halt".to_string()),
        )
        .expect("kill switch should persist");
        assert!(kill_switch.enabled);
    }

    #[test]
    fn strategy_queries_return_ingested_templates() {
        stable::init_storage();
        seed_template_and_artifact();

        let listed = list_strategy_templates(Some(sample_strategy_key()), 10);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].version, sample_version());

        let fetched = get_strategy_template(sample_strategy_key(), sample_version())
            .expect("template exists");
        assert_eq!(fetched.actions[0].action_id, "transfer");
    }
}

ic_cdk::export_candid!();
