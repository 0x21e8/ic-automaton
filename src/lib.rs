mod agent;
mod domain;
mod features;
mod http;
pub mod prompt;
mod scheduler;
mod storage;
mod tools;

use crate::domain::types::{
    ConversationLog, ConversationSummary, EvmRouteStateView, InboxMessage, InboxStats,
    InferenceConfigView, InferenceProvider, MemoryRollup, ObservabilitySnapshot, OutboxMessage,
    OutboxStats, PromptLayer, PromptLayerView, RetentionConfig, RetentionMaintenanceRuntime,
    RuntimeView, ScheduledJob, SchedulerRuntime, SessionSummary, SkillRecord, TaskKind,
    TaskScheduleConfig, TaskScheduleRuntime, ToolCallRecord, TurnWindowSummary,
    WalletBalanceSyncConfigView, WalletBalanceTelemetryView,
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
}

ic_cdk::export_candid!();
