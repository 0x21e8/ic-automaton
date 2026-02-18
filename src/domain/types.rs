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
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct InferenceInput {
    pub input: String,
    pub context_snippet: String,
    pub turn_id: String,
}
