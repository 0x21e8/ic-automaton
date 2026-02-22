use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum AgentState {
    Bootstrapping,
    Idle,
    LoadingContext,
    Inferring,
    ExecutingActions,
    Persisting,
    Sleeping,
    Faulted,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum AgentEvent {
    TimerTick,
    EvmPollCompleted { new_events: u32, has_input: bool },
    ContextLoaded,
    InferenceCompleted,
    ActionsCompleted,
    PersistCompleted,
    SleepRequested,
    TurnFailed { reason: String },
    ResetFault,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TransitionError {
    pub from: AgentState,
    pub event: String,
    pub reason: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ToolCall {
    #[serde(default)]
    pub tool_call_id: Option<String>,
    pub tool: String,
    pub args_json: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ToolCallRecord {
    pub turn_id: String,
    pub tool: String,
    pub args_json: String,
    pub output: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct MemoryFact {
    pub key: String,
    pub value: String,
    pub created_at_ns: u64,
    pub updated_at_ns: u64,
    pub source_turn_id: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmPollCursor {
    pub chain_id: u64,
    #[serde(default)]
    pub contract_address: Option<String>,
    #[serde(default)]
    pub automaton_address_topic: Option<String>,
    pub next_block: u64,
    pub next_log_index: u64,
    #[serde(default = "default_evm_confirmation_depth")]
    pub confirmation_depth: u64,
    #[serde(default)]
    pub last_poll_at_ns: u64,
    #[serde(default)]
    pub consecutive_empty_polls: u32,
}

impl Default for EvmPollCursor {
    fn default() -> Self {
        Self {
            chain_id: 8453,
            contract_address: None,
            automaton_address_topic: None,
            next_block: 0,
            next_log_index: 0,
            confirmation_depth: default_evm_confirmation_depth(),
            last_poll_at_ns: 0,
            consecutive_empty_polls: 0,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmEvent {
    pub tx_hash: String,
    pub chain_id: u64,
    pub block_number: u64,
    pub log_index: u64,
    pub source: String,
    pub payload: String,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum WalletBalanceStatus {
    #[default]
    Unknown,
    Fresh,
    Stale,
    Error,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WalletBalanceFreshness {
    pub age_secs: Option<u64>,
    pub freshness_window_secs: u64,
    pub is_stale: bool,
    pub status: WalletBalanceStatus,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WalletBalanceSnapshot {
    #[serde(default)]
    pub eth_balance_wei_hex: Option<String>,
    #[serde(default)]
    pub usdc_balance_raw_hex: Option<String>,
    #[serde(default = "default_usdc_decimals")]
    pub usdc_decimals: u8,
    #[serde(default)]
    pub usdc_contract_address: Option<String>,
    #[serde(default)]
    pub last_synced_at_ns: Option<u64>,
    #[serde(default)]
    pub last_synced_block: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[allow(dead_code)]
impl WalletBalanceSnapshot {
    pub fn derive_freshness(
        &self,
        now_ns: u64,
        freshness_window_secs: u64,
    ) -> WalletBalanceFreshness {
        let age_secs = self
            .last_synced_at_ns
            .map(|synced_at| now_ns.saturating_sub(synced_at) / 1_000_000_000);
        let is_stale = age_secs
            .map(|age| age > freshness_window_secs)
            .unwrap_or(true);
        let status = if self.last_error.is_some() {
            WalletBalanceStatus::Error
        } else if self.last_synced_at_ns.is_none() {
            WalletBalanceStatus::Unknown
        } else if is_stale {
            WalletBalanceStatus::Stale
        } else {
            WalletBalanceStatus::Fresh
        };

        WalletBalanceFreshness {
            age_secs,
            freshness_window_secs,
            is_stale,
            status,
        }
    }
}

impl Default for WalletBalanceSnapshot {
    fn default() -> Self {
        Self {
            eth_balance_wei_hex: None,
            usdc_balance_raw_hex: None,
            usdc_decimals: default_usdc_decimals(),
            usdc_contract_address: None,
            last_synced_at_ns: None,
            last_synced_block: None,
            last_error: None,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WalletBalanceSyncConfig {
    #[serde(default = "default_wallet_balance_sync_enabled")]
    pub enabled: bool,
    #[serde(default = "default_wallet_balance_sync_normal_interval_secs")]
    pub normal_interval_secs: u64,
    #[serde(default = "default_wallet_balance_sync_low_cycles_interval_secs")]
    pub low_cycles_interval_secs: u64,
    #[serde(default = "default_wallet_balance_sync_freshness_window_secs")]
    pub freshness_window_secs: u64,
    #[serde(default = "default_wallet_balance_sync_max_response_bytes")]
    pub max_response_bytes: u64,
    #[serde(default = "default_wallet_balance_sync_discover_usdc_via_inbox")]
    pub discover_usdc_via_inbox: bool,
}

impl Default for WalletBalanceSyncConfig {
    fn default() -> Self {
        Self {
            enabled: default_wallet_balance_sync_enabled(),
            normal_interval_secs: default_wallet_balance_sync_normal_interval_secs(),
            low_cycles_interval_secs: default_wallet_balance_sync_low_cycles_interval_secs(),
            freshness_window_secs: default_wallet_balance_sync_freshness_window_secs(),
            max_response_bytes: default_wallet_balance_sync_max_response_bytes(),
            discover_usdc_via_inbox: default_wallet_balance_sync_discover_usdc_via_inbox(),
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WalletBalanceTelemetryView {
    pub eth_balance_wei_hex: Option<String>,
    pub usdc_balance_raw_hex: Option<String>,
    pub usdc_decimals: u8,
    pub usdc_contract_address: Option<String>,
    pub last_synced_at_ns: Option<u64>,
    pub last_synced_block: Option<u64>,
    pub last_error: Option<String>,
    pub age_secs: Option<u64>,
    pub freshness_window_secs: u64,
    pub is_stale: bool,
    pub status: WalletBalanceStatus,
    pub bootstrap_pending: bool,
}

impl WalletBalanceTelemetryView {
    pub fn from_snapshot(snapshot: &RuntimeSnapshot, now_ns: u64) -> Self {
        let freshness = snapshot
            .wallet_balance
            .derive_freshness(now_ns, snapshot.wallet_balance_sync.freshness_window_secs);
        Self {
            eth_balance_wei_hex: snapshot.wallet_balance.eth_balance_wei_hex.clone(),
            usdc_balance_raw_hex: snapshot.wallet_balance.usdc_balance_raw_hex.clone(),
            usdc_decimals: snapshot.wallet_balance.usdc_decimals,
            usdc_contract_address: snapshot.wallet_balance.usdc_contract_address.clone(),
            last_synced_at_ns: snapshot.wallet_balance.last_synced_at_ns,
            last_synced_block: snapshot.wallet_balance.last_synced_block,
            last_error: snapshot.wallet_balance.last_error.clone(),
            age_secs: freshness.age_secs,
            freshness_window_secs: freshness.freshness_window_secs,
            is_stale: freshness.is_stale,
            status: freshness.status,
            bootstrap_pending: snapshot.wallet_balance_bootstrap_pending,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WalletBalanceSyncConfigView {
    pub enabled: bool,
    pub normal_interval_secs: u64,
    pub low_cycles_interval_secs: u64,
    pub freshness_window_secs: u64,
    pub max_response_bytes: u64,
    pub discover_usdc_via_inbox: bool,
}

impl From<&WalletBalanceSyncConfig> for WalletBalanceSyncConfigView {
    fn from(config: &WalletBalanceSyncConfig) -> Self {
        Self {
            enabled: config.enabled,
            normal_interval_secs: config.normal_interval_secs,
            low_cycles_interval_secs: config.low_cycles_interval_secs,
            freshness_window_secs: config.freshness_window_secs,
            max_response_bytes: config.max_response_bytes,
            discover_usdc_via_inbox: config.discover_usdc_via_inbox,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct RuntimeSnapshot {
    pub state: AgentState,
    pub turn_in_flight: bool,
    pub loop_enabled: bool,
    pub turn_counter: u64,
    pub last_turn_id: Option<String>,
    pub last_error: Option<String>,
    pub soul: String,
    pub evm_cursor: EvmPollCursor,
    pub event_seq: u64,
    pub transition_seq: u64,
    pub last_transition_at_ns: u64,
    #[serde(default)]
    pub inference_provider: InferenceProvider,
    #[serde(default = "default_inference_model")]
    pub inference_model: String,
    #[serde(default = "default_llm_canister_id")]
    pub llm_canister_id: String,
    #[serde(default)]
    pub openrouter_api_key: Option<String>,
    #[serde(default = "default_openrouter_base_url")]
    pub openrouter_base_url: String,
    #[serde(default = "default_openrouter_max_response_bytes")]
    pub openrouter_max_response_bytes: u64,
    #[serde(default)]
    pub ecdsa_key_name: String,
    #[serde(default)]
    pub evm_address: Option<String>,
    #[serde(default)]
    pub inbox_contract_address: Option<String>,
    #[serde(default = "default_evm_rpc_url")]
    pub evm_rpc_url: String,
    #[serde(default)]
    pub evm_rpc_fallback_url: Option<String>,
    #[serde(default = "default_evm_rpc_max_response_bytes")]
    pub evm_rpc_max_response_bytes: u64,
    #[serde(default)]
    pub wallet_balance: WalletBalanceSnapshot,
    #[serde(default)]
    pub wallet_balance_sync: WalletBalanceSyncConfig,
    #[serde(default = "default_wallet_balance_bootstrap_pending")]
    pub wallet_balance_bootstrap_pending: bool,
}

impl Default for RuntimeSnapshot {
    fn default() -> Self {
        Self {
            state: AgentState::Bootstrapping,
            turn_in_flight: false,
            loop_enabled: true,
            turn_counter: 0,
            last_turn_id: None,
            last_error: None,
            soul: "ic-automaton-v1".to_string(),
            evm_cursor: EvmPollCursor::default(),
            event_seq: 0,
            transition_seq: 0,
            last_transition_at_ns: 0,
            inference_provider: InferenceProvider::default(),
            inference_model: default_inference_model(),
            llm_canister_id: default_llm_canister_id(),
            openrouter_api_key: None,
            openrouter_base_url: default_openrouter_base_url(),
            openrouter_max_response_bytes: default_openrouter_max_response_bytes(),
            ecdsa_key_name: String::new(),
            evm_address: None,
            inbox_contract_address: None,
            evm_rpc_url: default_evm_rpc_url(),
            evm_rpc_fallback_url: None,
            evm_rpc_max_response_bytes: default_evm_rpc_max_response_bytes(),
            wallet_balance: WalletBalanceSnapshot::default(),
            wallet_balance_sync: WalletBalanceSyncConfig::default(),
            wallet_balance_bootstrap_pending: default_wallet_balance_bootstrap_pending(),
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TransitionLogRecord {
    pub id: String,
    pub turn_id: String,
    pub from_state: AgentState,
    pub to_state: AgentState,
    pub event: String,
    pub error: Option<String>,
    pub occurred_at_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum ContinuationStopReason {
    #[default]
    None,
    MaxRounds,
    MaxDuration,
    InferenceError,
    MaxToolCalls,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TurnRecord {
    pub id: String,
    pub created_at_ns: u64,
    pub state_from: AgentState,
    pub state_to: AgentState,
    pub source_events: u32,
    pub tool_call_count: u32,
    pub input_summary: String,
    #[serde(default)]
    pub inner_dialogue: Option<String>,
    #[serde(default)]
    pub inference_round_count: u32,
    #[serde(default)]
    pub continuation_stop_reason: ContinuationStopReason,
    pub error: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SkillRecord {
    pub name: String,
    pub description: String,
    pub instructions: String,
    pub enabled: bool,
    pub mutable: bool,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PromptLayer {
    pub layer_id: u8,
    pub content: String,
    pub updated_at_ns: u64,
    pub updated_by_turn: String,
    pub version: u32,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PromptLayerView {
    pub layer_id: u8,
    pub is_mutable: bool,
    pub content: String,
    pub updated_at_ns: Option<u64>,
    pub updated_by_turn: Option<String>,
    pub version: Option<u32>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConversationEntry {
    pub inbox_message_id: String,
    pub sender_body: String,
    pub agent_reply: String,
    pub turn_id: String,
    pub timestamp_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConversationLog {
    pub sender: String,
    pub entries: Vec<ConversationEntry>,
    pub last_activity_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConversationSummary {
    pub sender: String,
    pub last_activity_ns: u64,
    pub entry_count: u32,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    pub sender: String,
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub source_count: u32,
    pub inbox_message_count: u32,
    pub outbox_message_count: u32,
    pub inbox_preview: String,
    pub outbox_preview: String,
    pub generated_at_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TurnWindowSummary {
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub source_count: u32,
    pub turn_count: u32,
    pub transition_count: u32,
    pub tool_call_count: u32,
    pub succeeded_turn_count: u32,
    pub failed_turn_count: u32,
    pub tool_success_count: u32,
    pub tool_failure_count: u32,
    pub top_errors: Vec<String>,
    pub generated_at_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MemoryRollup {
    pub namespace: String,
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub source_count: u32,
    pub source_keys: Vec<String>,
    pub canonical_value: String,
    pub generated_at_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct RuntimeView {
    pub state: AgentState,
    pub turn_in_flight: bool,
    pub loop_enabled: bool,
    pub turn_counter: u64,
    pub last_turn_id: Option<String>,
    pub last_error: Option<String>,
    pub soul: String,
    pub evm_chain_id: u64,
    pub evm_next_block: u64,
    pub evm_next_log_index: u64,
    pub last_transition_at_ns: u64,
    pub inference_provider: InferenceProvider,
    pub inference_model: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmRouteStateView {
    pub chain_id: u64,
    pub automaton_evm_address: Option<String>,
    pub inbox_contract_address: Option<String>,
    pub automaton_address_topic: Option<String>,
    pub next_block: u64,
    pub next_log_index: u64,
    pub confirmation_depth: u64,
    pub last_poll_at_ns: u64,
    pub consecutive_empty_polls: u32,
}

impl From<&RuntimeSnapshot> for RuntimeView {
    fn from(snapshot: &RuntimeSnapshot) -> Self {
        Self {
            state: snapshot.state.clone(),
            turn_in_flight: snapshot.turn_in_flight,
            loop_enabled: snapshot.loop_enabled,
            turn_counter: snapshot.turn_counter,
            last_turn_id: snapshot.last_turn_id.clone(),
            last_error: snapshot.last_error.clone(),
            soul: snapshot.soul.clone(),
            evm_chain_id: snapshot.evm_cursor.chain_id,
            evm_next_block: snapshot.evm_cursor.next_block,
            evm_next_log_index: snapshot.evm_cursor.next_log_index,
            last_transition_at_ns: snapshot.last_transition_at_ns,
            inference_provider: snapshot.inference_provider.clone(),
            inference_model: snapshot.inference_model.clone(),
        }
    }
}

impl From<&RuntimeSnapshot> for EvmRouteStateView {
    fn from(snapshot: &RuntimeSnapshot) -> Self {
        Self {
            chain_id: snapshot.evm_cursor.chain_id,
            automaton_evm_address: snapshot.evm_address.clone(),
            inbox_contract_address: snapshot.inbox_contract_address.clone(),
            automaton_address_topic: snapshot.evm_cursor.automaton_address_topic.clone(),
            next_block: snapshot.evm_cursor.next_block,
            next_log_index: snapshot.evm_cursor.next_log_index,
            confirmation_depth: snapshot.evm_cursor.confirmation_depth,
            last_poll_at_ns: snapshot.evm_cursor.last_poll_at_ns,
            consecutive_empty_polls: snapshot.evm_cursor.consecutive_empty_polls,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ObservabilitySnapshot {
    pub captured_at_ns: u64,
    pub runtime: RuntimeView,
    pub scheduler: SchedulerRuntime,
    #[serde(default)]
    pub storage_growth: StorageGrowthMetrics,
    pub inbox_stats: InboxStats,
    pub inbox_messages: Vec<InboxMessage>,
    pub outbox_stats: OutboxStats,
    pub outbox_messages: Vec<OutboxMessage>,
    pub prompt_layers: Vec<PromptLayerView>,
    pub conversation_summaries: Vec<ConversationSummary>,
    #[serde(default)]
    pub session_summaries: Vec<SessionSummary>,
    #[serde(default)]
    pub turn_window_summaries: Vec<TurnWindowSummary>,
    #[serde(default)]
    pub memory_rollups: Vec<MemoryRollup>,
    #[serde(default)]
    pub cycles: CycleTelemetry,
    pub recent_turns: Vec<TurnRecord>,
    pub recent_transitions: Vec<TransitionLogRecord>,
    pub recent_jobs: Vec<ScheduledJob>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default)]
pub enum StoragePressureLevel {
    #[default]
    Normal,
    Elevated,
    High,
    Critical,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default)]
pub struct StorageGrowthMetrics {
    pub runtime_map_entries: u64,
    pub transition_map_entries: u64,
    pub turn_map_entries: u64,
    pub tool_map_entries: u64,
    pub job_map_entries: u64,
    pub job_queue_map_entries: u64,
    pub dedupe_map_entries: u64,
    pub inbox_map_entries: u64,
    pub inbox_pending_queue_entries: u64,
    pub inbox_staged_queue_entries: u64,
    pub outbox_map_entries: u64,
    #[serde(default)]
    pub session_summary_entries: u64,
    #[serde(default)]
    pub session_summary_limit: u64,
    #[serde(default)]
    pub turn_window_summary_entries: u64,
    #[serde(default)]
    pub turn_window_summary_limit: u64,
    #[serde(default)]
    pub memory_rollup_entries: u64,
    #[serde(default)]
    pub memory_rollup_limit: u64,
    pub memory_fact_entries: u64,
    pub memory_fact_limit: u64,
    #[serde(default)]
    pub session_summary_utilization_percent: u8,
    #[serde(default)]
    pub turn_window_summary_utilization_percent: u8,
    #[serde(default)]
    pub memory_rollup_utilization_percent: u8,
    #[serde(default)]
    pub memory_fact_utilization_percent: u8,
    #[serde(default)]
    pub near_limit: bool,
    #[serde(default)]
    pub pressure_level: StoragePressureLevel,
    #[serde(default)]
    pub pressure_warnings: Vec<String>,
    #[serde(default)]
    pub tracked_entry_count: u64,
    #[serde(default)]
    pub tracked_entries_delta_per_hour: Option<i64>,
    #[serde(default)]
    pub trend_window_seconds: u64,
    #[serde(default)]
    pub trend_sample_count: u32,
    pub retention_progress_percent: u8,
    pub summarization_progress_percent: u8,
    #[serde(default)]
    pub heap_memory_mb: f64,
    #[serde(default)]
    pub stable_memory_mb: f64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RetentionConfig {
    #[serde(default = "default_jobs_max_age_secs")]
    pub jobs_max_age_secs: u64,
    #[serde(default = "default_jobs_max_records")]
    pub jobs_max_records: u64,
    #[serde(default = "default_dedupe_max_age_secs")]
    pub dedupe_max_age_secs: u64,
    #[serde(default = "default_turns_max_age_secs")]
    pub turns_max_age_secs: u64,
    #[serde(default = "default_transitions_max_age_secs")]
    pub transitions_max_age_secs: u64,
    #[serde(default = "default_tools_max_age_secs")]
    pub tools_max_age_secs: u64,
    #[serde(default = "default_inbox_max_age_secs")]
    pub inbox_max_age_secs: u64,
    #[serde(default = "default_outbox_max_age_secs")]
    pub outbox_max_age_secs: u64,
    #[serde(default = "default_maintenance_batch_size")]
    pub maintenance_batch_size: u32,
    #[serde(default = "default_maintenance_interval_secs")]
    pub maintenance_interval_secs: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            jobs_max_age_secs: default_jobs_max_age_secs(),
            jobs_max_records: default_jobs_max_records(),
            dedupe_max_age_secs: default_dedupe_max_age_secs(),
            turns_max_age_secs: default_turns_max_age_secs(),
            transitions_max_age_secs: default_transitions_max_age_secs(),
            tools_max_age_secs: default_tools_max_age_secs(),
            inbox_max_age_secs: default_inbox_max_age_secs(),
            outbox_max_age_secs: default_outbox_max_age_secs(),
            maintenance_batch_size: default_maintenance_batch_size(),
            maintenance_interval_secs: default_maintenance_interval_secs(),
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionMaintenanceRuntime {
    #[serde(default)]
    pub next_run_after_ns: u64,
    #[serde(default)]
    pub job_scan_cursor: Option<String>,
    #[serde(default)]
    pub dedupe_scan_cursor: Option<String>,
    #[serde(default)]
    pub inbox_scan_cursor: Option<String>,
    #[serde(default)]
    pub outbox_scan_cursor: Option<String>,
    #[serde(default)]
    pub turn_scan_cursor: Option<String>,
    #[serde(default)]
    pub transition_scan_cursor: Option<String>,
    #[serde(default)]
    pub last_started_ns: Option<u64>,
    #[serde(default)]
    pub last_finished_ns: Option<u64>,
    #[serde(default)]
    pub last_deleted_jobs: u32,
    #[serde(default)]
    pub last_deleted_dedupe: u32,
    #[serde(default)]
    pub last_deleted_inbox: u32,
    #[serde(default)]
    pub last_deleted_outbox: u32,
    #[serde(default)]
    pub last_deleted_turns: u32,
    #[serde(default)]
    pub last_deleted_transitions: u32,
    #[serde(default)]
    pub last_deleted_tools: u32,
    #[serde(default)]
    pub last_generated_session_summaries: u32,
    #[serde(default)]
    pub last_generated_turn_window_summaries: u32,
    #[serde(default)]
    pub last_generated_memory_rollups: u32,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub retention_progress_percent: u8,
    #[serde(default)]
    pub summarization_progress_percent: u8,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default)]
pub struct CycleTelemetry {
    pub total_cycles: u128,
    pub liquid_cycles: u128,
    pub freezing_threshold_cycles: u128,
    pub moving_window_seconds: u64,
    pub window_duration_seconds: u64,
    pub window_sample_count: u32,
    pub burn_rate_cycles_per_hour: Option<u128>,
    pub burn_rate_cycles_per_day: Option<u128>,
    pub burn_rate_usd_per_hour: Option<f64>,
    pub burn_rate_usd_per_day: Option<f64>,
    pub estimated_seconds_until_freezing_threshold: Option<u64>,
    pub estimated_freeze_time_ns: Option<u64>,
    pub usd_per_trillion_cycles: f64,
}

#[derive(
    CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default,
)]
pub enum InferenceProvider {
    #[default]
    IcLlm,
    OpenRouter,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct InferenceConfigView {
    pub provider: InferenceProvider,
    pub model: String,
    pub openrouter_base_url: String,
    pub openrouter_has_api_key: bool,
    pub openrouter_max_response_bytes: u64,
}

impl From<&RuntimeSnapshot> for InferenceConfigView {
    fn from(snapshot: &RuntimeSnapshot) -> Self {
        Self {
            provider: snapshot.inference_provider.clone(),
            model: snapshot.inference_model.clone(),
            openrouter_base_url: snapshot.openrouter_base_url.clone(),
            openrouter_has_api_key: snapshot
                .openrouter_api_key
                .as_ref()
                .map(|key| !key.trim().is_empty())
                .unwrap_or(false),
            openrouter_max_response_bytes: snapshot.openrouter_max_response_bytes,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct InferenceInput {
    pub input: String,
    pub context_snippet: String,
    pub turn_id: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum InboxMessageStatus {
    Pending,
    Staged,
    Consumed,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct InboxMessage {
    pub id: String,
    pub seq: u64,
    pub body: String,
    pub posted_at_ns: u64,
    pub posted_by: String,
    pub status: InboxMessageStatus,
    pub staged_at_ns: Option<u64>,
    pub consumed_at_ns: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default)]
pub struct InboxStats {
    pub total_messages: u64,
    pub pending_count: u64,
    pub staged_count: u64,
    pub consumed_count: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct OutboxMessage {
    pub id: String,
    pub seq: u64,
    pub turn_id: String,
    pub body: String,
    pub created_at_ns: u64,
    pub source_inbox_ids: Vec<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default)]
pub struct OutboxStats {
    pub total_messages: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TaskKind {
    AgentTurn,
    PollInbox,
    CheckCycles,
    Reconcile,
}

impl TaskKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AgentTurn => "AgentTurn",
            Self::PollInbox => "PollInbox",
            Self::CheckCycles => "CheckCycles",
            Self::Reconcile => "Reconcile",
        }
    }

    pub const fn default_priority(&self) -> u8 {
        match self {
            Self::AgentTurn => 0,
            Self::PollInbox => 1,
            Self::CheckCycles => 2,
            Self::Reconcile => 3,
        }
    }

    pub const fn essential(&self) -> bool {
        match self {
            Self::AgentTurn => true,
            Self::PollInbox => true,
            Self::CheckCycles => true,
            Self::Reconcile => false,
        }
    }

    pub const fn default_interval_secs(&self) -> u64 {
        match self {
            Self::AgentTurn => 30,
            Self::PollInbox => 30,
            Self::CheckCycles => 60,
            Self::Reconcile => 300,
        }
    }

    pub const fn all() -> &'static [Self] {
        static TASK_KINDS: [TaskKind; 4] = [
            TaskKind::AgentTurn,
            TaskKind::PollInbox,
            TaskKind::CheckCycles,
            TaskKind::Reconcile,
        ];
        &TASK_KINDS
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum SurvivalTier {
    #[default]
    Normal,
    LowCycles,
    Critical,
    OutOfCycles,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TaskLane {
    Mutating,
    ReadOnly,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SurvivalOperationClass {
    Inference,
    EvmPoll,
    EvmBroadcast,
    ThresholdSign,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum RecoveryOperation {
    WalletBalanceSync,
    EvmPoll,
    Inference,
    ToolExecution,
    #[default]
    Unknown,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum OutcallFailureKind {
    ResponseTooLarge,
    Timeout,
    Transport,
    RateLimited,
    UpstreamUnavailable,
    InvalidRequest,
    InvalidResponse,
    RejectedByPolicy,
    Unknown,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OutcallFailure {
    pub kind: OutcallFailureKind,
    #[serde(default)]
    pub retry_after_secs: Option<u64>,
    #[serde(default)]
    pub observed_response_bytes: Option<u64>,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum OperationFailureKind {
    BlockedBySurvivalPolicy,
    MissingConfiguration,
    InvalidConfiguration,
    InsufficientCycles,
    Unauthorized,
    Deterministic,
    Unknown,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OperationFailure {
    pub kind: OperationFailureKind,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum RecoveryFailure {
    Outcall(OutcallFailure),
    Operation(OperationFailure),
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum RecoveryPolicyAction {
    Skip,
    RetryImmediate,
    Backoff,
    TuneResponseLimit,
    #[default]
    EscalateFault,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum RecoveryDecisionReason {
    ResponseTooLarge,
    ResponseLimitAlreadyMaxed,
    TransientOutcallFailure,
    OutcallRateLimited,
    NonRetriableOutcallFailure,
    SurvivalPolicyBlocked,
    InsufficientCycles,
    NonRetriableOperationFailure,
    UnknownFailure,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ResponseLimitAdjustment {
    pub from_bytes: u64,
    pub to_bytes: u64,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RecoveryDecision {
    pub action: RecoveryPolicyAction,
    pub reason: RecoveryDecisionReason,
    #[serde(default)]
    pub backoff_secs: Option<u64>,
    #[serde(default)]
    pub response_limit_adjustment: Option<ResponseLimitAdjustment>,
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ResponseLimitPolicy {
    pub current_bytes: u64,
    pub min_bytes: u64,
    pub max_bytes: u64,
    #[serde(default = "default_response_limit_tune_multiplier")]
    pub tune_multiplier: u64,
}

impl Default for ResponseLimitPolicy {
    fn default() -> Self {
        Self {
            current_bytes: 256,
            min_bytes: 256,
            max_bytes: 4 * 1024,
            tune_multiplier: default_response_limit_tune_multiplier(),
        }
    }
}

#[allow(dead_code)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RecoveryContext {
    #[serde(default)]
    pub operation: RecoveryOperation,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default = "default_recovery_backoff_base_secs")]
    pub backoff_base_secs: u64,
    #[serde(default = "default_recovery_backoff_max_secs")]
    pub backoff_max_secs: u64,
    #[serde(default)]
    pub response_limit: Option<ResponseLimitPolicy>,
}

impl Default for RecoveryContext {
    fn default() -> Self {
        Self {
            operation: RecoveryOperation::Unknown,
            consecutive_failures: 0,
            backoff_base_secs: default_recovery_backoff_base_secs(),
            backoff_max_secs: default_recovery_backoff_max_secs(),
            response_limit: None,
        }
    }
}

impl TaskLane {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Mutating => "mutating",
            Self::ReadOnly => "read_only",
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TaskScheduleConfig {
    pub kind: TaskKind,
    pub enabled: bool,
    pub essential: bool,
    pub interval_secs: u64,
    pub priority: u8,
    pub max_backoff_secs: u64,
}

impl TaskScheduleConfig {
    pub fn default_for(kind: &TaskKind) -> Self {
        Self {
            kind: kind.clone(),
            enabled: true,
            essential: kind.essential(),
            interval_secs: kind.default_interval_secs(),
            priority: kind.default_priority(),
            max_backoff_secs: 120,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TaskScheduleRuntime {
    pub kind: TaskKind,
    pub next_due_ns: u64,
    pub backoff_until_ns: Option<u64>,
    pub consecutive_failures: u32,
    pub pending_job_id: Option<String>,
    pub last_started_ns: Option<u64>,
    pub last_finished_ns: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    InFlight,
    Succeeded,
    Failed,
    TimedOut,
    Skipped,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ScheduledJob {
    pub id: String,
    pub kind: TaskKind,
    pub lane: TaskLane,
    pub dedupe_key: String,
    pub priority: u8,
    pub created_at_ns: u64,
    pub scheduled_for_ns: u64,
    pub started_at_ns: Option<u64>,
    pub finished_at_ns: Option<u64>,
    pub status: JobStatus,
    pub attempts: u32,
    pub max_attempts: u32,
    pub last_error: Option<String>,
}

impl ScheduledJob {
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            JobStatus::Succeeded | JobStatus::Failed | JobStatus::TimedOut | JobStatus::Skipped
        )
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SchedulerLease {
    pub lane: TaskLane,
    pub job_id: String,
    pub acquired_at_ns: u64,
    pub expires_at_ns: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SchedulerRuntime {
    pub enabled: bool,
    pub paused_reason: Option<String>,
    pub low_cycles_mode: bool,
    #[serde(default)]
    pub survival_tier: SurvivalTier,
    #[serde(default)]
    pub survival_tier_recovery_checks: u32,
    pub next_job_seq: u64,
    pub active_mutating_lease: Option<SchedulerLease>,
    pub last_tick_started_ns: u64,
    pub last_tick_finished_ns: u64,
    pub last_tick_error: Option<String>,
}

impl Default for SchedulerRuntime {
    fn default() -> Self {
        Self {
            enabled: true,
            paused_reason: None,
            low_cycles_mode: false,
            survival_tier: SurvivalTier::Normal,
            survival_tier_recovery_checks: 0,
            next_job_seq: 0,
            active_mutating_lease: None,
            last_tick_started_ns: 0,
            last_tick_finished_ns: 0,
            last_tick_error: None,
        }
    }
}

fn default_inference_model() -> String {
    "llama3.1:8b".to_string()
}

fn default_llm_canister_id() -> String {
    "w36hm-eqaaa-aaaal-qr76a-cai".to_string()
}

fn default_openrouter_base_url() -> String {
    "https://openrouter.ai/api/v1".to_string()
}

fn default_openrouter_max_response_bytes() -> u64 {
    64 * 1024
}

fn default_evm_rpc_url() -> String {
    "https://mainnet.base.org".to_string()
}

fn default_evm_rpc_max_response_bytes() -> u64 {
    64 * 1024
}

fn default_evm_confirmation_depth() -> u64 {
    6
}

fn default_usdc_decimals() -> u8 {
    6
}

fn default_wallet_balance_sync_enabled() -> bool {
    true
}

fn default_wallet_balance_sync_normal_interval_secs() -> u64 {
    300
}

fn default_wallet_balance_sync_low_cycles_interval_secs() -> u64 {
    900
}

fn default_wallet_balance_sync_freshness_window_secs() -> u64 {
    600
}

fn default_wallet_balance_sync_max_response_bytes() -> u64 {
    256
}

fn default_wallet_balance_sync_discover_usdc_via_inbox() -> bool {
    true
}

fn default_wallet_balance_bootstrap_pending() -> bool {
    true
}

#[allow(dead_code)]
fn default_recovery_backoff_base_secs() -> u64 {
    5
}

#[allow(dead_code)]
fn default_recovery_backoff_max_secs() -> u64 {
    300
}

#[allow(dead_code)]
fn default_response_limit_tune_multiplier() -> u64 {
    2
}

fn default_jobs_max_age_secs() -> u64 {
    14 * 24 * 60 * 60
}

fn default_jobs_max_records() -> u64 {
    60_000
}

fn default_dedupe_max_age_secs() -> u64 {
    3 * 24 * 60 * 60
}

fn default_turns_max_age_secs() -> u64 {
    7 * 24 * 60 * 60
}

fn default_transitions_max_age_secs() -> u64 {
    7 * 24 * 60 * 60
}

fn default_tools_max_age_secs() -> u64 {
    7 * 24 * 60 * 60
}

fn default_inbox_max_age_secs() -> u64 {
    14 * 24 * 60 * 60
}

fn default_outbox_max_age_secs() -> u64 {
    14 * 24 * 60 * 60
}

fn default_maintenance_batch_size() -> u32 {
    120
}

fn default_maintenance_interval_secs() -> u64 {
    10 * 60
}

#[cfg(test)]
mod tests {
    use super::{
        MemoryRollup, RecoveryContext, ResponseLimitPolicy, RetentionConfig,
        RetentionMaintenanceRuntime, RuntimeSnapshot, SessionSummary, TurnWindowSummary,
        WalletBalanceSnapshot, WalletBalanceStatus, WalletBalanceSyncConfig,
        WalletBalanceSyncConfigView, WalletBalanceTelemetryView,
    };

    #[test]
    fn wallet_balance_defaults_match_locked_spec() {
        let config = WalletBalanceSyncConfig::default();
        assert!(config.enabled);
        assert_eq!(config.normal_interval_secs, 300);
        assert_eq!(config.low_cycles_interval_secs, 900);
        assert_eq!(config.freshness_window_secs, 600);
        assert_eq!(config.max_response_bytes, 256);
        assert!(config.discover_usdc_via_inbox);

        let snapshot = WalletBalanceSnapshot::default();
        assert_eq!(snapshot.usdc_decimals, 6);
        assert!(snapshot.eth_balance_wei_hex.is_none());
        assert!(snapshot.usdc_balance_raw_hex.is_none());
        assert!(snapshot.last_synced_at_ns.is_none());
        assert!(snapshot.last_error.is_none());
    }

    #[test]
    fn wallet_balance_freshness_derives_status_with_error_precedence() {
        let now_ns = 1_000_000_000_000;
        let freshness_window_secs = 600;

        let unknown =
            WalletBalanceSnapshot::default().derive_freshness(now_ns, freshness_window_secs);
        assert_eq!(unknown.status, WalletBalanceStatus::Unknown);
        assert!(unknown.is_stale);
        assert_eq!(unknown.age_secs, None);

        let fresh = WalletBalanceSnapshot {
            last_synced_at_ns: Some(now_ns.saturating_sub(120 * 1_000_000_000)),
            ..WalletBalanceSnapshot::default()
        }
        .derive_freshness(now_ns, freshness_window_secs);
        assert_eq!(fresh.status, WalletBalanceStatus::Fresh);
        assert!(!fresh.is_stale);
        assert_eq!(fresh.age_secs, Some(120));

        let stale = WalletBalanceSnapshot {
            last_synced_at_ns: Some(now_ns.saturating_sub(601 * 1_000_000_000)),
            ..WalletBalanceSnapshot::default()
        }
        .derive_freshness(now_ns, freshness_window_secs);
        assert_eq!(stale.status, WalletBalanceStatus::Stale);
        assert!(stale.is_stale);
        assert_eq!(stale.age_secs, Some(601));

        let errored = WalletBalanceSnapshot {
            last_synced_at_ns: Some(now_ns.saturating_sub(10 * 1_000_000_000)),
            last_error: Some("rpc unavailable".to_string()),
            ..WalletBalanceSnapshot::default()
        }
        .derive_freshness(now_ns, freshness_window_secs);
        assert_eq!(errored.status, WalletBalanceStatus::Error);
    }

    #[test]
    fn runtime_snapshot_defaults_bootstrap_pending_for_wallet_sync() {
        let snapshot = RuntimeSnapshot::default();
        assert!(snapshot.wallet_balance_bootstrap_pending);
    }

    #[test]
    fn wallet_balance_telemetry_view_derives_freshness_from_snapshot() {
        let now_ns: u64 = 2_000_000_000_000;
        let snapshot = RuntimeSnapshot {
            wallet_balance: WalletBalanceSnapshot {
                eth_balance_wei_hex: Some("0x1".to_string()),
                usdc_balance_raw_hex: Some("0x2a".to_string()),
                usdc_decimals: 6,
                usdc_contract_address: Some(
                    "0x3333333333333333333333333333333333333333".to_string(),
                ),
                last_synced_at_ns: Some(now_ns.saturating_sub(601 * 1_000_000_000)),
                last_synced_block: Some(123),
                last_error: None,
            },
            wallet_balance_sync: WalletBalanceSyncConfig {
                freshness_window_secs: 600,
                ..WalletBalanceSyncConfig::default()
            },
            wallet_balance_bootstrap_pending: true,
            ..RuntimeSnapshot::default()
        };

        let view = WalletBalanceTelemetryView::from_snapshot(&snapshot, now_ns);
        assert_eq!(view.eth_balance_wei_hex.as_deref(), Some("0x1"));
        assert_eq!(view.usdc_balance_raw_hex.as_deref(), Some("0x2a"));
        assert_eq!(
            view.usdc_contract_address.as_deref(),
            Some("0x3333333333333333333333333333333333333333")
        );
        assert_eq!(view.last_synced_block, Some(123));
        assert_eq!(view.age_secs, Some(601));
        assert_eq!(view.freshness_window_secs, 600);
        assert!(view.is_stale);
        assert_eq!(view.status, WalletBalanceStatus::Stale);
        assert!(view.bootstrap_pending);
    }

    #[test]
    fn wallet_balance_sync_config_view_matches_runtime_config() {
        let snapshot = RuntimeSnapshot {
            wallet_balance_sync: WalletBalanceSyncConfig {
                enabled: true,
                normal_interval_secs: 300,
                low_cycles_interval_secs: 900,
                freshness_window_secs: 777,
                max_response_bytes: 512,
                discover_usdc_via_inbox: false,
            },
            ..RuntimeSnapshot::default()
        };

        let view = WalletBalanceSyncConfigView::from(&snapshot.wallet_balance_sync);
        assert_eq!(view.normal_interval_secs, 300);
        assert_eq!(view.low_cycles_interval_secs, 900);
        assert_eq!(view.freshness_window_secs, 777);
        assert_eq!(view.max_response_bytes, 512);
        assert!(!view.discover_usdc_via_inbox);
    }

    #[test]
    fn recovery_context_defaults_are_bounded_and_safe() {
        let context = RecoveryContext::default();
        assert_eq!(context.backoff_base_secs, 5);
        assert_eq!(context.backoff_max_secs, 300);
        assert!(context.response_limit.is_none());
    }

    #[test]
    fn response_limit_policy_defaults_match_wallet_sync_bounds() {
        let policy = ResponseLimitPolicy::default();
        assert_eq!(policy.current_bytes, 256);
        assert_eq!(policy.min_bytes, 256);
        assert_eq!(policy.max_bytes, 4 * 1024);
        assert_eq!(policy.tune_multiplier, 2);
    }

    #[test]
    fn retention_defaults_match_phase_one_policy() {
        let retention = RetentionConfig::default();
        assert_eq!(retention.jobs_max_age_secs, 14 * 24 * 60 * 60);
        assert_eq!(retention.dedupe_max_age_secs, 3 * 24 * 60 * 60);
        assert_eq!(retention.jobs_max_records, 60_000);
        assert_eq!(retention.maintenance_batch_size, 120);
        assert_eq!(retention.maintenance_interval_secs, 10 * 60);

        let runtime = RetentionMaintenanceRuntime::default();
        assert_eq!(runtime.next_run_after_ns, 0);
        assert_eq!(runtime.retention_progress_percent, 0);
        assert_eq!(runtime.summarization_progress_percent, 0);
    }

    #[test]
    fn summary_schemas_round_trip_json_with_provenance_fields() {
        let session = SessionSummary {
            sender: "0xabc".to_string(),
            window_start_ns: 10,
            window_end_ns: 20,
            source_count: 3,
            inbox_message_count: 2,
            outbox_message_count: 1,
            inbox_preview: "inbox".to_string(),
            outbox_preview: "outbox".to_string(),
            generated_at_ns: 30,
        };
        let encoded_session = serde_json::to_vec(&session).expect("session summary should encode");
        let decoded_session: SessionSummary =
            serde_json::from_slice(&encoded_session).expect("session summary should decode");
        assert_eq!(decoded_session, session);

        let turn = TurnWindowSummary {
            window_start_ns: 100,
            window_end_ns: 200,
            source_count: 4,
            turn_count: 2,
            transition_count: 2,
            tool_call_count: 3,
            succeeded_turn_count: 1,
            failed_turn_count: 1,
            tool_success_count: 2,
            tool_failure_count: 1,
            top_errors: vec!["timeout".to_string()],
            generated_at_ns: 300,
        };
        let encoded_turn = serde_json::to_vec(&turn).expect("turn window summary should encode");
        let decoded_turn: TurnWindowSummary =
            serde_json::from_slice(&encoded_turn).expect("turn window summary should decode");
        assert_eq!(decoded_turn, turn);

        let rollup = MemoryRollup {
            namespace: "strategy".to_string(),
            window_start_ns: 400,
            window_end_ns: 500,
            source_count: 2,
            source_keys: vec!["strategy.alpha".to_string(), "strategy.beta".to_string()],
            canonical_value: "alpha=buy; beta=sell".to_string(),
            generated_at_ns: 600,
        };
        let encoded_rollup = serde_json::to_vec(&rollup).expect("memory rollup should encode");
        let decoded_rollup: MemoryRollup =
            serde_json::from_slice(&encoded_rollup).expect("memory rollup should decode");
        assert_eq!(decoded_rollup, rollup);
    }
}
