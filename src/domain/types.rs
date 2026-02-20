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
    pub next_block: u64,
    pub next_log_index: u64,
}

impl Default for EvmPollCursor {
    fn default() -> Self {
        Self {
            chain_id: 8453,
            next_block: 0,
            next_log_index: 0,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmEvent {
    pub chain_id: u64,
    pub block_number: u64,
    pub log_index: u64,
    pub source: String,
    pub payload: String,
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
    #[serde(default = "default_evm_rpc_url")]
    pub evm_rpc_url: String,
    #[serde(default)]
    pub evm_rpc_fallback_url: Option<String>,
    #[serde(default = "default_evm_rpc_max_response_bytes")]
    pub evm_rpc_max_response_bytes: u64,
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
            openrouter_api_key: None,
            openrouter_base_url: default_openrouter_base_url(),
            openrouter_max_response_bytes: default_openrouter_max_response_bytes(),
            ecdsa_key_name: String::new(),
            evm_address: None,
            evm_rpc_url: default_evm_rpc_url(),
            evm_rpc_fallback_url: None,
            evm_rpc_max_response_bytes: default_evm_rpc_max_response_bytes(),
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct ObservabilitySnapshot {
    pub captured_at_ns: u64,
    pub runtime: RuntimeView,
    pub scheduler: SchedulerRuntime,
    pub inbox_stats: InboxStats,
    pub inbox_messages: Vec<InboxMessage>,
    pub outbox_stats: OutboxStats,
    pub outbox_messages: Vec<OutboxMessage>,
    pub prompt_layers: Vec<PromptLayerView>,
    pub conversation_summaries: Vec<ConversationSummary>,
    #[serde(default)]
    pub cycles: CycleTelemetry,
    pub recent_turns: Vec<TurnRecord>,
    pub recent_transitions: Vec<TransitionLogRecord>,
    pub recent_jobs: Vec<ScheduledJob>,
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
    Mock,
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

fn default_openrouter_base_url() -> String {
    "https://openrouter.ai/api/v1".to_string()
}

fn default_openrouter_max_response_bytes() -> u64 {
    64 * 1024
}

fn default_evm_rpc_url() -> String {
    String::new()
}

fn default_evm_rpc_max_response_bytes() -> u64 {
    64 * 1024
}
