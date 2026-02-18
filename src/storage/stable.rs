use crate::domain::types::{AgentEvent, AgentState};
use crate::domain::types::{
    EvmPollCursor, InferenceConfigView, InferenceProvider, RuntimeSnapshot, RuntimeView,
    SkillRecord, ToolCallRecord, TransitionLogRecord, TurnRecord,
};
use ic_cdk::api::time;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use serde::{de::DeserializeOwned, Serialize};
use std::cell::RefCell;

const RUNTIME_KEY: &str = "runtime.snapshot";

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static RUNTIME_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
        ));
    static TRANSITION_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
        ));
    static TURN_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
        ));
    static TOOL_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
        ));
    static SKILL_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))
        ));
}

pub fn init_storage() {
    let _ = runtime_snapshot();
}

pub fn runtime_snapshot() -> RuntimeSnapshot {
    let payload = RUNTIME_MAP.with(|map| map.borrow().get(&RUNTIME_KEY.to_string()));
    read_json(payload.as_deref()).unwrap_or_default()
}

pub fn save_runtime_snapshot(snapshot: &RuntimeSnapshot) {
    RUNTIME_MAP.with(|map| {
        map.borrow_mut()
            .insert(RUNTIME_KEY.to_string(), encode_json(snapshot));
    });
}

pub fn set_loop_enabled(enabled: bool) {
    let mut snapshot = runtime_snapshot();
    snapshot.loop_enabled = enabled;
    save_runtime_snapshot(&snapshot);
}

#[allow(dead_code)]
pub fn set_turn_lock(in_flight: bool) {
    let mut snapshot = runtime_snapshot();
    snapshot.turn_in_flight = in_flight;
    save_runtime_snapshot(&snapshot);
}

#[allow(dead_code)]
pub fn update_state(state: AgentState) {
    let mut snapshot = runtime_snapshot();
    snapshot.state = state;
    snapshot.last_transition_at_ns = time();
    save_runtime_snapshot(&snapshot);
}

pub fn set_soul(soul: String) -> String {
    let mut snapshot = runtime_snapshot();
    snapshot.soul = soul;
    snapshot.last_transition_at_ns = time();
    let out = snapshot.soul.clone();
    save_runtime_snapshot(&snapshot);
    out
}

pub fn get_soul() -> String {
    runtime_snapshot().soul
}

pub fn set_last_error(error: Option<String>) {
    let mut snapshot = runtime_snapshot();
    snapshot.last_error = error;
    save_runtime_snapshot(&snapshot);
}

pub fn increment_turn_counter() -> RuntimeSnapshot {
    let mut snapshot = runtime_snapshot();
    snapshot.turn_counter = snapshot.turn_counter.saturating_add(1);
    snapshot.turn_in_flight = true;
    snapshot.last_turn_id = Some(format!("turn-{}", snapshot.turn_counter));
    snapshot.last_error = None;
    snapshot.last_transition_at_ns = time();
    save_runtime_snapshot(&snapshot);
    snapshot
}

pub fn snapshot_to_view() -> RuntimeView {
    RuntimeView::from(&runtime_snapshot())
}

pub fn inference_config_view() -> InferenceConfigView {
    InferenceConfigView::from(&runtime_snapshot())
}

pub fn set_inference_provider(provider: InferenceProvider) {
    let mut snapshot = runtime_snapshot();
    snapshot.inference_provider = provider;
    snapshot.last_transition_at_ns = time();
    save_runtime_snapshot(&snapshot);
}

pub fn set_inference_model(model: String) -> Result<String, String> {
    if model.trim().is_empty() {
        return Err("inference model cannot be empty".to_string());
    }
    let mut snapshot = runtime_snapshot();
    snapshot.inference_model = model.trim().to_string();
    snapshot.last_transition_at_ns = time();
    let out = snapshot.inference_model.clone();
    save_runtime_snapshot(&snapshot);
    Ok(out)
}

pub fn set_openrouter_base_url(base_url: String) -> Result<String, String> {
    if base_url.trim().is_empty() {
        return Err("openrouter base url cannot be empty".to_string());
    }
    let mut snapshot = runtime_snapshot();
    snapshot.openrouter_base_url = base_url.trim().trim_end_matches('/').to_string();
    snapshot.last_transition_at_ns = time();
    let out = snapshot.openrouter_base_url.clone();
    save_runtime_snapshot(&snapshot);
    Ok(out)
}

pub fn set_openrouter_api_key(api_key: Option<String>) {
    let mut snapshot = runtime_snapshot();
    snapshot.openrouter_api_key = api_key.and_then(|key| {
        let trimmed = key.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    snapshot.last_transition_at_ns = time();
    save_runtime_snapshot(&snapshot);
}

pub fn record_transition(
    turn_id: &str,
    from: &AgentState,
    to: &AgentState,
    event: &AgentEvent,
    error: Option<String>,
) {
    let mut snapshot = runtime_snapshot();
    snapshot.transition_seq = snapshot.transition_seq.saturating_add(1);
    snapshot.event_seq = snapshot.event_seq.saturating_add(1);
    snapshot.last_transition_at_ns = time();

    let record = TransitionLogRecord {
        id: format!("{:020}-{:020}", snapshot.transition_seq, snapshot.event_seq),
        turn_id: turn_id.to_string(),
        from_state: from.clone(),
        to_state: to.clone(),
        event: format!("{event:?}"),
        error,
        occurred_at_ns: snapshot.last_transition_at_ns,
    };

    TRANSITION_MAP.with(|map| {
        map.borrow_mut()
            .insert(record.id.clone(), encode_json(&record));
    });

    save_runtime_snapshot(&snapshot);
}

pub fn append_turn_record(record: &TurnRecord, tool_calls: &[ToolCallRecord]) {
    let turn_key = format!("{:020}-{}", record.created_at_ns, record.id);
    TURN_MAP.with(|map| {
        map.borrow_mut().insert(turn_key, encode_json(record));
    });

    set_tool_records(&record.id, tool_calls);
}

pub fn list_recent_transitions(limit: usize) -> Vec<TransitionLogRecord> {
    if limit == 0 {
        return Vec::new();
    }
    TRANSITION_MAP.with(|map| {
        map.borrow()
            .iter()
            .rev()
            .take(limit)
            .filter_map(|entry| read_json(Some(entry.value().as_slice())))
            .collect()
    })
}

pub fn list_turns(limit: usize) -> Vec<TurnRecord> {
    if limit == 0 {
        return Vec::new();
    }
    TURN_MAP.with(|map| {
        map.borrow()
            .iter()
            .rev()
            .take(limit)
            .filter_map(|entry| read_json(Some(entry.value().as_slice())))
            .collect()
    })
}

pub fn set_tool_records(turn_id: &str, tool_calls: &[ToolCallRecord]) {
    let tool_key = format!("tools:{turn_id}");
    TOOL_MAP.with(|map| {
        map.borrow_mut().insert(tool_key, encode_json(tool_calls));
    });
}

pub fn complete_turn(state: AgentState, error: Option<String>) {
    let mut snapshot = runtime_snapshot();
    snapshot.turn_in_flight = false;
    snapshot.state = state;
    snapshot.last_error = error;
    snapshot.last_transition_at_ns = time();
    save_runtime_snapshot(&snapshot);
}

pub fn get_tools_for_turn(turn_id: &str) -> Vec<ToolCallRecord> {
    let key = format!("tools:{turn_id}");
    TOOL_MAP.with(|map| read_json(map.borrow().get(&key).as_deref()).unwrap_or_default())
}

pub fn set_evm_cursor(cursor: &EvmPollCursor) {
    let mut snapshot = runtime_snapshot();
    snapshot.evm_cursor = cursor.clone();
    snapshot.last_transition_at_ns = time();
    save_runtime_snapshot(&snapshot);
}

pub fn upsert_skill(skill: &SkillRecord) {
    SKILL_MAP.with(|map| {
        map.borrow_mut()
            .insert(skill.name.clone(), encode_json(skill));
    });
}

pub fn list_skills() -> Vec<SkillRecord> {
    SKILL_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| read_json::<SkillRecord>(Some(entry.value().as_slice())))
            .collect()
    })
}

fn encode_json<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

fn read_json<T: DeserializeOwned>(value: Option<&[u8]>) -> Option<T> {
    value.and_then(|raw| serde_json::from_slice(raw).ok())
}
