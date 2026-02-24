/// IC canister entry point for the automaton, exposing all candid methods.
///
/// This module wires together every subsystem — scheduler, agent, storage,
/// HTTP, strategy registry — and surfaces them as candid-typed `update` /
/// `query` calls.  Initialization (`init` / `post_upgrade`) arms the
/// recurring timer and bootstraps the HTTP certification tree.
///
/// # Candid surface
///
/// Methods are grouped below into five sections:
/// - **Initialization** – canister lifecycle hooks
/// - **Configuration** – runtime tunables (inference, EVM, scheduler, …)
/// - **Strategy management** – template CRUD and lifecycle transitions
/// - **Observability** – read-only snapshots, logs, turn/conversation history
/// - **HTTP interface** – certified query and upgrade-to-update handlers
mod agent;
mod domain;
mod features;
mod http;
pub mod prompt;
mod sanitize;
mod scheduler;
mod storage;
#[allow(dead_code)]
mod strategy;
mod timing;
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
use crate::timing::current_time_ns;
use crate::tools::ToolManager;
use candid::{CandidType, Principal};
use ic_cdk_timers::set_timer_interval_serial;
use ic_http_certification::{HttpRequest, HttpResponse, HttpUpdateRequest, HttpUpdateResponse};
use serde::Deserialize;
use std::time::Duration;

// ── Initialization ──────────────────────────────────────────────────────────

/// Arguments supplied once at canister creation via `dfx deploy --argument`.
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

/// Arguments for the `ingest_strategy_abi_artifact_admin` update call.
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

/// Returns `Err` when the caller is not a canister controller (wasm32 only;
/// always succeeds in native/test builds).
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

/// Traps the canister (unconditionally aborts the call) when the caller is
/// not a controller.  Use this variant for update methods that do not return
/// `Result`.
fn ensure_controller_or_trap() {
    if let Err(error) = ensure_controller() {
        ic_cdk::trap(&error);
    }
}

/// Returns a human-readable caller identity for audit log entries.
/// On wasm32 this is the principal text; in native builds it is `"native"`.
fn caller_for_audit() -> String {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::msg_caller().to_text();

    #[cfg(not(target_arch = "wasm32"))]
    return "native".to_string();
}

/// Looks up a strategy template by key and version, returning a descriptive
/// error when not found.
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

/// Atomically sets a template's `status` field and bumps `updated_at_ns`.
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

/// Called once when the canister is first installed.
/// Seeds stable storage, installs default skills, initialises the HTTP
/// certification tree, and arms the recurring scheduler timer.
#[ic_cdk::init]
fn init(args: InitArgs) {
    apply_init_args(args);
    crate::features::MockSkillLoader::install_defaults();
    crate::http::init_certification();
    arm_timer();
}

/// Applies all `InitArgs` fields to stable storage, trapping on the first
/// validation error.  Separated from `init` so tests can call it directly.
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

/// Called after every canister upgrade.
/// Re-initialises storage (migrating any new stable structures), rebuilds
/// the HTTP certification tree, and re-arms the timer.
#[ic_cdk::post_upgrade]
fn post_upgrade() {
    stable::init_storage();
    crate::http::init_certification();
    arm_timer();
}

// ── Configuration ────────────────────────────────────────────────────────────

/// Enables or disables the autonomous agent loop (controller only).
#[ic_cdk::update]
fn set_loop_enabled(enabled: bool) -> String {
    ensure_controller_or_trap();
    stable::set_loop_enabled(enabled);
    format!("loop_enabled={enabled}")
}

/// Sets the active inference backend (`IcLlm` or `OpenRouter`) (controller only).
#[ic_cdk::update]
fn set_inference_provider(provider: InferenceProvider) -> String {
    ensure_controller_or_trap();
    stable::set_inference_provider(provider.clone());
    format!("inference_provider={provider:?}")
}

/// Sets the inference model identifier (e.g. `"llama3.1:8b"` or `"openai/gpt-4o-mini"`)
/// (controller only).
#[ic_cdk::update]
fn set_inference_model(model: String) -> Result<String, String> {
    ensure_controller()?;
    stable::set_inference_model(model)
}

/// Stores (or clears) the OpenRouter API key in stable storage.
/// Pass `None` to remove the key (controller only).
#[ic_cdk::update]
fn set_openrouter_api_key(api_key: Option<String>) -> String {
    ensure_controller_or_trap();
    stable::set_openrouter_api_key(api_key);
    "openrouter_api_key_updated".to_string()
}

/// Updates the primary EVM JSON-RPC endpoint (controller only).
#[ic_cdk::update]
fn set_evm_rpc_url(url: String) -> Result<String, String> {
    ensure_controller()?;
    stable::set_evm_rpc_url(url)
}

/// Sets an optional fallback EVM RPC URL used when the primary is unavailable (controller only).
#[ic_cdk::update]
fn set_evm_rpc_fallback_url(url: Option<String>) -> Result<Option<String>, String> {
    ensure_controller()?;
    stable::set_evm_rpc_fallback_url(url)
}

/// Caps the maximum response size (bytes) returned by EVM RPC outbound calls (controller only).
#[ic_cdk::update]
fn set_evm_rpc_max_response_bytes(max_response_bytes: u64) -> Result<u64, String> {
    ensure_controller()?;
    stable::set_evm_rpc_max_response_bytes(max_response_bytes)
}

/// Overrides the EVM inbox contract address (controller only).
#[ic_cdk::update]
fn set_inbox_contract_address_admin(address: Option<String>) -> Result<Option<String>, String> {
    ensure_controller()?;
    stable::set_inbox_contract_address(address)
}

/// Updates the EVM chain ID used for all on-chain operations (controller only).
#[ic_cdk::update]
fn set_evm_chain_id_admin(chain_id: u64) -> Result<u64, String> {
    ensure_controller()?;
    stable::set_evm_chain_id(chain_id)
}

/// Sets how many block confirmations must pass before an EVM event is
/// considered finalised (controller only).
#[ic_cdk::update]
fn set_evm_confirmation_depth_admin(confirmation_depth: u64) -> Result<u64, String> {
    ensure_controller()?;
    stable::set_evm_confirmation_depth(confirmation_depth)
}

/// Replaces the HTTP outbound allowlist.  An empty slice disables the allowlist
/// and permits all domains (controller only).
#[ic_cdk::update]
fn set_http_allowed_domains(domains: Vec<String>) -> Result<Vec<String>, String> {
    ensure_controller()?;
    stable::set_http_allowed_domains(domains)
}

// ── Observability ────────────────────────────────────────────────────────────

/// Returns a combined runtime snapshot (cycles, scheduler state, inference
/// config, top-up config, …).
#[ic_cdk::query]
fn get_runtime_view() -> RuntimeView {
    stable::snapshot_to_view()
}

/// Returns the current EVM route state (chain ID, RPC URL, addresses, …).
#[ic_cdk::query]
fn get_evm_route_state_view() -> EvmRouteStateView {
    stable::evm_route_state_view()
}

/// Returns the automaton's derived EVM address, or `None` before first derivation.
#[ic_cdk::query]
fn get_automaton_evm_address() -> Option<String> {
    stable::get_automaton_evm_address()
}

/// Manually overrides the stored automaton EVM address (controller only).
#[ic_cdk::update]
fn set_automaton_evm_address_admin(address: Option<String>) -> Result<Option<String>, String> {
    ensure_controller()?;
    stable::set_evm_address(address)
}

/// Returns the latest synced wallet balance telemetry (ETH, USDC, sync status).
#[ic_cdk::query]
fn get_wallet_balance_telemetry() -> WalletBalanceTelemetryView {
    stable::wallet_balance_telemetry_view()
}

/// Returns the wallet balance sync configuration (intervals, freshness window, …).
#[ic_cdk::query]
fn get_wallet_balance_sync_config() -> WalletBalanceSyncConfigView {
    stable::wallet_balance_sync_config_view()
}

/// Returns the scheduler's current runtime state (enabled flag, last tick, …).
#[ic_cdk::query]
fn get_scheduler_view() -> SchedulerRuntime {
    stable::scheduler_runtime_view()
}

/// Returns the current conversation-retention configuration.
#[ic_cdk::query]
fn get_retention_config() -> RetentionConfig {
    stable::retention_config()
}

/// Returns runtime statistics from the last retention-maintenance pass.
#[ic_cdk::query]
fn get_retention_maintenance_runtime() -> RetentionMaintenanceRuntime {
    stable::retention_maintenance_runtime()
}

/// Returns up to `limit` most-recently enqueued scheduler job records.
#[ic_cdk::query]
fn list_scheduler_jobs(limit: u32) -> Vec<ScheduledJob> {
    stable::list_recent_jobs(limit as usize)
}

/// Returns the configured schedule and live runtime state for every task kind.
#[ic_cdk::query]
fn list_task_schedules() -> Vec<(TaskScheduleConfig, TaskScheduleRuntime)> {
    stable::list_task_schedules()
}

/// Returns an observability snapshot containing up to `limit` recent events,
/// combined with the current runtime and scheduler views.
#[ic_cdk::query]
fn get_observability_snapshot(limit: u32) -> ObservabilitySnapshot {
    stable::observability_snapshot(limit as usize)
}

/// Returns up to `limit` inbox messages ordered by arrival time (newest last).
#[ic_cdk::query]
fn list_inbox_messages(limit: u32) -> Vec<InboxMessage> {
    stable::list_inbox_messages(limit as usize)
}

/// Returns all prompt layers ordered by layer ID.
#[ic_cdk::query]
fn get_prompt_layers() -> Vec<PromptLayerView> {
    stable::list_prompt_layers()
}

/// Replaces the content of a prompt layer identified by `layer_id` (controller only).
#[ic_cdk::update]
fn update_prompt_layer_admin(layer_id: u8, content: String) -> Result<PromptLayer, String> {
    ensure_controller()?;
    crate::tools::update_prompt_layer_content(
        layer_id,
        content,
        &format!("admin:{}", caller_for_audit()),
    )
}

/// Returns summary records for all active conversations (one per sender).
#[ic_cdk::query]
fn list_conversations() -> Vec<ConversationSummary> {
    stable::list_conversation_summaries()
}

/// Returns up to `limit` most-recent session summaries.
#[ic_cdk::query]
fn list_session_summaries(limit: u32) -> Vec<SessionSummary> {
    stable::list_session_summaries(limit as usize)
}

/// Returns up to `limit` most-recent turn-window summaries used for context compression.
#[ic_cdk::query]
fn list_turn_window_summaries(limit: u32) -> Vec<TurnWindowSummary> {
    stable::list_turn_window_summaries(limit as usize)
}

/// Returns up to `limit` most-recent memory rollups (compressed long-term context).
#[ic_cdk::query]
fn list_memory_rollups(limit: u32) -> Vec<MemoryRollup> {
    stable::list_memory_rollups(limit as usize)
}

/// Returns the full conversation log for the given sender address, or `None`
/// if no conversation exists.
#[ic_cdk::query]
fn get_conversation(sender: String) -> Option<ConversationLog> {
    stable::get_conversation_log(&sender)
}

/// Returns aggregate inbox statistics (total messages, pending count, …).
#[ic_cdk::query]
fn get_inbox_stats() -> InboxStats {
    stable::inbox_stats()
}

/// Returns up to `limit` most-recent outbox messages (agent replies queued for delivery).
#[ic_cdk::query]
fn list_outbox_messages(limit: u32) -> Vec<OutboxMessage> {
    stable::list_outbox_messages(limit as usize)
}

/// Returns aggregate outbox statistics (total messages, delivered count, …).
#[ic_cdk::query]
fn get_outbox_stats() -> OutboxStats {
    stable::outbox_stats()
}

/// Enables or disables the scheduler (controller only).
/// Disabling prevents new jobs from being dispatched without stopping the timer.
#[ic_cdk::update]
fn set_scheduler_enabled(enabled: bool) -> String {
    ensure_controller_or_trap();
    stable::set_scheduler_enabled(enabled)
}

/// Activates low-cycles mode, which throttles task dispatch to conserve cycles
/// (controller only).
#[ic_cdk::update]
fn set_scheduler_low_cycles_mode(enabled: bool) -> String {
    ensure_controller_or_trap();
    stable::set_scheduler_low_cycles_mode(enabled)
}

/// Overrides the recurrence interval (seconds) for the given task kind
/// (controller only).
#[ic_cdk::update]
fn set_task_interval_secs(kind: TaskKind, interval_secs: u64) -> Result<String, String> {
    ensure_controller()?;
    stable::set_task_interval_secs(&kind, interval_secs)?;
    Ok("task_interval_updated".to_string())
}

/// Enables or disables a specific task kind without affecting the scheduler
/// globally (controller only).
#[ic_cdk::update]
fn set_task_enabled(kind: TaskKind, enabled: bool) -> String {
    ensure_controller_or_trap();
    stable::set_task_enabled(&kind, enabled);
    "task_enabled_updated".to_string()
}

/// Replaces the conversation-retention policy (controller only).
#[ic_cdk::update]
fn set_retention_config(config: RetentionConfig) -> Result<RetentionConfig, String> {
    ensure_controller()?;
    stable::set_retention_config(config)
}

/// Returns the current inference configuration (provider, model, key presence flag).
#[ic_cdk::query]
fn get_inference_config() -> InferenceConfigView {
    stable::inference_config_view()
}

/// Returns the agent's "soul" — the core identity/persona prompt layer.
#[ic_cdk::query]
fn get_soul() -> String {
    stable::get_soul()
}

/// Replaces the agent's soul prompt.  Rejects empty strings (controller only).
#[ic_cdk::update]
fn update_soul(new_soul: String) -> Result<String, String> {
    ensure_controller()?;
    if new_soul.trim().is_empty() {
        return Err("soul cannot be empty".to_string());
    }
    Ok(stable::set_soul(new_soul))
}

/// Returns up to `limit` recent state-transition event records as debug strings.
#[ic_cdk::query]
fn list_recent_events(limit: u32) -> Vec<String> {
    stable::list_recent_transitions(limit as usize)
        .into_iter()
        .map(|record| format!("{record:?}"))
        .collect()
}

/// Returns up to `limit` recent agent turn records as debug strings.
#[ic_cdk::query]
fn list_turns(limit: u32) -> Vec<String> {
    stable::list_turns(limit as usize)
        .into_iter()
        .map(|turn| format!("{turn:?}"))
        .collect()
}

/// Returns all registered skill records.
#[ic_cdk::query]
fn list_skills() -> Vec<SkillRecord> {
    stable::list_skills()
}

/// Returns the policy (autonomy mode, allowed callers, …) for every registered
/// tool as human-readable strings.
#[ic_cdk::query]
fn list_tool_policies() -> Vec<String> {
    let manager = ToolManager::new();
    manager
        .list_tools()
        .into_iter()
        .map(|(name, policy)| format!("{name}: {policy:?}"))
        .collect()
}

/// Returns all tool call records associated with the given turn ID.
#[ic_cdk::query]
fn get_tool_calls_for_turn(turn_id: String) -> Vec<ToolCallRecord> {
    stable::get_tools_for_turn(&turn_id)
}

// ── Strategy management ──────────────────────────────────────────────────────

/// Lists strategy templates.  When `key` is supplied only templates matching
/// that key are returned; otherwise all templates are returned (up to `limit`).
#[ic_cdk::query]
fn list_strategy_templates(key: Option<StrategyTemplateKey>, limit: u32) -> Vec<StrategyTemplate> {
    let bounded_limit = limit.max(1) as usize;
    match key {
        Some(key) => crate::strategy::registry::list_templates(&key, bounded_limit),
        None => crate::strategy::registry::list_all_templates(bounded_limit),
    }
}

/// Returns a single strategy template by key and version, or `None` if absent.
#[ic_cdk::query]
fn get_strategy_template(
    key: StrategyTemplateKey,
    version: TemplateVersion,
) -> Option<StrategyTemplate> {
    crate::strategy::registry::get_template(&key, &version)
}

/// Returns accumulated outcome statistics (success/failure counts, last outcome)
/// for the given template, or `None` if no executions have been recorded yet.
#[ic_cdk::query]
fn get_strategy_outcome_stats(
    key: StrategyTemplateKey,
    version: TemplateVersion,
) -> Option<StrategyOutcomeStats> {
    crate::strategy::learner::outcome_stats(&key, &version)
}

/// Inserts or updates a strategy template (controller only).
/// Stamps `created_at_ns` on first insert and always updates `updated_at_ns`.
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

/// Normalises and stores an ABI artifact, optionally verifying selector hashes
/// (controller only).
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

/// Transitions a template to `Active`, runs a canary probe to validate it,
/// and records an activation state entry (controller only).
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

/// Marks a template as `Deprecated` and deactivates it.  Use this for orderly
/// rotation; the template remains readable (controller only).
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

/// Hard-revokes a template: sets status to `Revoked`, deactivates it, and
/// records an immutable revocation entry.  Use for security incidents
/// (controller only).
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

/// Arms or disarms the kill switch for all versions of a strategy template.
/// When `enabled` is `true` the agent will refuse to execute any action for
/// that template (controller only).
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

// ── HTTP interface ───────────────────────────────────────────────────────────

/// Certified HTTP query handler.  Serves static UI assets and read-only API
/// routes from the pre-built certification tree.  Mutable routes return an
/// upgrade signal to be retried via `http_request_update`.
#[ic_cdk::query]
fn http_request(request: HttpRequest) -> HttpResponse {
    crate::http::handle_http_request(request)
}

/// Mutable HTTP update handler for write routes (`POST /api/conversation`, …).
/// Called automatically by the IC boundary nodes when `http_request` signals
/// an upgrade.
#[ic_cdk::update]
fn http_request_update(request: HttpUpdateRequest) -> HttpUpdateResponse {
    crate::http::handle_http_request_update(request)
}

/// Registers the recurring scheduler timer.  Called from both `init` and
/// `post_upgrade` so the timer is never left unarmed after an upgrade.
fn arm_timer() {
    set_timer_interval_serial(
        Duration::from_secs(timing::SCHEDULER_TICK_INTERVAL_SECS),
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
