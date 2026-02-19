use crate::domain::types::{
    AgentEvent, AgentState, EvmPollCursor, InboxMessage, InboxMessageStatus, InboxStats,
    InferenceConfigView, InferenceProvider, JobStatus, ObservabilitySnapshot, OutboxMessage,
    OutboxStats, RuntimeSnapshot, RuntimeView, ScheduledJob, SchedulerLease, SchedulerRuntime,
    SkillRecord, SurvivalOperationClass, SurvivalTier, TaskKind, TaskLane, TaskScheduleConfig,
    TaskScheduleRuntime, ToolCallRecord, TransitionLogRecord, TurnRecord,
};
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::cell::RefCell;

fn now_ns() -> u64 {
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

const RUNTIME_KEY: &str = "runtime.snapshot";
const SCHEDULER_RUNTIME_KEY: &str = "scheduler.runtime";
const INBOX_SEQ_KEY: &str = "inbox.seq";
const OUTBOX_SEQ_KEY: &str = "outbox.seq";
const MAX_RECENT_JOBS: usize = 200;
const DEFAULT_OBSERVABILITY_LIMIT: usize = 25;
const MAX_OBSERVABILITY_LIMIT: usize = 100;
pub const SURVIVAL_TIER_RECOVERY_CHECKS_REQUIRED: u32 = 3;
pub const SURVIVAL_OPERATION_MAX_BACKOFF_SECS_INFERENCE: u64 = 120;
pub const SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_POLL: u64 = 120;
pub const SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_BROADCAST: u64 = 300;
pub const SURVIVAL_OPERATION_MAX_BACKOFF_SECS_THRESHOLD_SIGN: u64 = 120;

#[derive(Clone, Copy, Debug, LogPriorityLevels)]
enum SchedulerStorageLogPriority {
    #[log_level(capacity = 2000, name = "SCHED_STORAGE_INFO")]
    Info,
    #[log_level(capacity = 500, name = "SCHED_STORAGE_WARN")]
    Warn,
    #[log_level(capacity = 100, name = "SCHED_STORAGE_ERROR")]
    Error,
}

impl GetLogFilter for SchedulerStorageLogPriority {
    fn get_log_filter() -> LogFilter {
        LogFilter::ShowAll
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SurvivalOperationRuntime {
    pub consecutive_failures: u32,
    pub backoff_until_ns: Option<u64>,
}

fn survival_operation_runtime_key(operation: &SurvivalOperationClass) -> String {
    match operation {
        SurvivalOperationClass::Inference => "survival.operation:inference".to_string(),
        SurvivalOperationClass::EvmPoll => "survival.operation:evm_poll".to_string(),
        SurvivalOperationClass::EvmBroadcast => "survival.operation:evm_broadcast".to_string(),
        SurvivalOperationClass::ThresholdSign => "survival.operation:threshold_sign".to_string(),
    }
}

fn get_survival_operation_runtime(operation: &SurvivalOperationClass) -> SurvivalOperationRuntime {
    SURVIVAL_OPERATION_RUNTIME_MAP
        .with(|map| map.borrow().get(&survival_operation_runtime_key(operation)))
        .and_then(|payload| read_json(Some(payload.as_slice())))
        .unwrap_or_default()
}

fn set_survival_operation_runtime(
    operation: &SurvivalOperationClass,
    runtime: &SurvivalOperationRuntime,
) {
    SURVIVAL_OPERATION_RUNTIME_MAP.with(|map| {
        map.borrow_mut().insert(
            survival_operation_runtime_key(operation),
            encode_json(runtime),
        );
    });
}

fn survival_operation_backoff_secs(failures: u32, max_backoff_secs: u64) -> u64 {
    let capped = max_backoff_secs.max(1);
    let exponent = failures.min(20);
    let delay = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
    delay.min(capped)
}

fn survival_operation_allows_in_tier(
    tier: &SurvivalTier,
    operation: &SurvivalOperationClass,
) -> bool {
    !matches!(
        (tier, operation),
        (SurvivalTier::Critical, _)
            | (SurvivalTier::OutOfCycles, _)
            | (
                SurvivalTier::LowCycles,
                SurvivalOperationClass::ThresholdSign
            )
            | (
                SurvivalTier::LowCycles,
                SurvivalOperationClass::EvmBroadcast
            )
    )
}

pub fn can_run_survival_operation(operation: &SurvivalOperationClass, now_ns: u64) -> bool {
    if !survival_operation_allows_in_tier(&scheduler_survival_tier(), operation) {
        return false;
    }
    get_survival_operation_runtime(operation)
        .backoff_until_ns
        .is_none_or(|until| until <= now_ns)
}

pub fn record_survival_operation_failure(
    operation: &SurvivalOperationClass,
    now_ns: u64,
    max_backoff_secs: u64,
) {
    let mut runtime = get_survival_operation_runtime(operation);
    runtime.consecutive_failures = runtime.consecutive_failures.saturating_add(1);
    let backoff_ns =
        survival_operation_backoff_secs(runtime.consecutive_failures, max_backoff_secs)
            .saturating_mul(1_000_000_000);
    runtime.backoff_until_ns = now_ns.checked_add(backoff_ns);
    if runtime.backoff_until_ns.is_none() {
        runtime.backoff_until_ns = Some(u64::MAX);
    }
    set_survival_operation_runtime(operation, &runtime);
    log!(
        SchedulerStorageLogPriority::Warn,
        "survival_operation_failure operation={:?} consecutive_failures={} backoff_until_ns={}",
        operation,
        runtime.consecutive_failures,
        runtime.backoff_until_ns.unwrap_or_default()
    );
}

pub fn record_survival_operation_success(operation: &SurvivalOperationClass) {
    let runtime = get_survival_operation_runtime(operation);
    if runtime.consecutive_failures == 0 && runtime.backoff_until_ns.is_none() {
        return;
    }
    log!(
        SchedulerStorageLogPriority::Info,
        "survival_operation_success operation={:?}",
        operation
    );
    set_survival_operation_runtime(operation, &SurvivalOperationRuntime::default());
}

#[allow(dead_code)]
pub fn survival_operation_backoff_until(operation: &SurvivalOperationClass) -> Option<u64> {
    get_survival_operation_runtime(operation).backoff_until_ns
}

#[allow(dead_code)]
pub fn survival_operation_consecutive_failures(operation: &SurvivalOperationClass) -> u32 {
    get_survival_operation_runtime(operation).consecutive_failures
}

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
    static TASK_CONFIG_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(6)))
        ));
    static TASK_RUNTIME_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(7)))
    ));
    static JOB_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(8)))
        ));
    static JOB_QUEUE_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(9)))
        ));
    static DEDUPE_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(10)))
        ));
    static SCHEDULER_RUNTIME_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5)))
    ));
    static INBOX_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(11)))
        ));
    static INBOX_PENDING_QUEUE_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(12)))
        ));
    static INBOX_STAGED_QUEUE_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(13)))
        ));
    static OUTBOX_MAP: RefCell<StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(14)))
        ));
    static SURVIVAL_OPERATION_RUNTIME_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(15)))
    ));
}

pub fn init_storage() {
    let _ = runtime_snapshot();
    if runtime_u64(INBOX_SEQ_KEY).is_none() {
        save_runtime_u64(INBOX_SEQ_KEY, 0);
    }
    if runtime_u64(OUTBOX_SEQ_KEY).is_none() {
        save_runtime_u64(OUTBOX_SEQ_KEY, 0);
    }
    init_scheduler_defaults(now_ns());
}

pub fn init_scheduler_defaults(now_ns: u64) {
    if SCHEDULER_RUNTIME_MAP
        .with(|map| map.borrow().get(&SCHEDULER_RUNTIME_KEY.to_string()))
        .is_none()
    {
        save_scheduler_runtime(&SchedulerRuntime::default());
    }
    for kind in TaskKind::all() {
        let key = task_kind_key(kind);
        if TASK_CONFIG_MAP.with(|map| map.borrow().get(&key)).is_none() {
            upsert_task_config(TaskScheduleConfig::default_for(kind));
        }
        if TASK_RUNTIME_MAP
            .with(|map| map.borrow().get(&key))
            .is_none()
        {
            save_task_runtime(
                kind,
                &TaskScheduleRuntime {
                    kind: kind.clone(),
                    next_due_ns: now_ns
                        .saturating_add(kind.default_interval_secs().saturating_mul(1_000_000_000)),
                    backoff_until_ns: None,
                    consecutive_failures: 0,
                    pending_job_id: None,
                    last_started_ns: None,
                    last_finished_ns: None,
                    last_error: None,
                },
            );
        }
    }
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

pub fn list_task_configs() -> Vec<(TaskKind, TaskScheduleConfig)> {
    let mut entries = TASK_CONFIG_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| {
                parse_task_kind(entry.key()).map(|kind| (kind, entry.value().as_slice().to_vec()))
            })
            .filter_map(|(kind, payload)| {
                read_json::<TaskScheduleConfig>(Some(&payload)).map(|cfg| (kind, cfg))
            })
            .collect::<Vec<_>>()
    });
    entries.sort_by_key(|(kind, cfg)| (cfg.priority, kind.as_str().to_string()));
    entries
}

pub fn list_task_schedules() -> Vec<(TaskScheduleConfig, TaskScheduleRuntime)> {
    let mut schedules = list_task_configs()
        .into_iter()
        .map(|(kind, config)| (config, get_task_runtime(&kind)))
        .collect::<Vec<_>>();
    schedules.sort_by_key(|(config, _)| config.priority);
    schedules
}

pub fn upsert_task_config(config: TaskScheduleConfig) {
    TASK_CONFIG_MAP.with(|map| {
        map.borrow_mut()
            .insert(task_kind_key(&config.kind), encode_json(&config));
    });
}

pub fn get_task_config(kind: &TaskKind) -> Option<TaskScheduleConfig> {
    TASK_CONFIG_MAP
        .with(|map| map.borrow().get(&task_kind_key(kind)))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn set_task_interval_secs(kind: &TaskKind, interval_secs: u64) -> Result<(), String> {
    if interval_secs == 0 {
        return Err("interval_secs must be greater than 0".to_string());
    }
    let mut config = get_task_config(kind).unwrap_or_else(|| TaskScheduleConfig::default_for(kind));
    config.interval_secs = interval_secs;
    upsert_task_config(config);
    let mut runtime = get_task_runtime(kind);
    runtime.next_due_ns = now_ns().saturating_add(interval_secs.saturating_mul(1_000_000_000));
    save_task_runtime(kind, &runtime);
    Ok(())
}

pub fn set_task_enabled(kind: &TaskKind, enabled: bool) {
    let mut config = get_task_config(kind).unwrap_or_else(|| TaskScheduleConfig::default_for(kind));
    config.enabled = enabled;
    upsert_task_config(config);
}

pub fn get_task_runtime(kind: &TaskKind) -> TaskScheduleRuntime {
    TASK_RUNTIME_MAP
        .with(|map| map.borrow().get(&task_kind_key(kind)))
        .and_then(|payload| read_json(Some(payload.as_slice())))
        .unwrap_or_else(|| TaskScheduleRuntime {
            kind: kind.clone(),
            next_due_ns: now_ns()
                .saturating_add(kind.default_interval_secs().saturating_mul(1_000_000_000)),
            backoff_until_ns: None,
            consecutive_failures: 0,
            pending_job_id: None,
            last_started_ns: None,
            last_finished_ns: None,
            last_error: None,
        })
}

pub fn save_task_runtime(kind: &TaskKind, runtime: &TaskScheduleRuntime) {
    TASK_RUNTIME_MAP.with(|map| {
        map.borrow_mut()
            .insert(task_kind_key(kind), encode_json(runtime));
    });
}

pub fn scheduler_runtime_view() -> SchedulerRuntime {
    scheduler_runtime()
}

pub fn set_scheduler_enabled(enabled: bool) -> String {
    let mut runtime = scheduler_runtime();
    runtime.enabled = enabled;
    runtime.paused_reason = if enabled {
        None
    } else {
        Some("disabled".to_string())
    };
    save_scheduler_runtime(&runtime);
    format!("scheduler_enabled={enabled}")
}

pub fn set_scheduler_low_cycles_mode(enabled: bool) -> String {
    let previous = scheduler_low_cycles_mode();
    let mut runtime = scheduler_runtime();
    runtime.low_cycles_mode = enabled;
    runtime.survival_tier = if enabled {
        SurvivalTier::LowCycles
    } else {
        SurvivalTier::Normal
    };
    runtime.survival_tier_recovery_checks = 0;
    runtime.paused_reason = if enabled {
        Some("low_cycles".to_string())
    } else {
        None
    };
    if previous != enabled {
        log!(
            SchedulerStorageLogPriority::Info,
            "scheduler_low_cycles_mode transition new={enabled}"
        );
    }
    save_scheduler_runtime(&runtime);
    if enabled {
        "low_cycles_mode=on".to_string()
    } else {
        "low_cycles_mode=off".to_string()
    }
}

pub fn set_scheduler_survival_tier(observed_tier: SurvivalTier) {
    let mut runtime = scheduler_runtime();
    let previous_tier = runtime.survival_tier.clone();
    let previous_checks = runtime.survival_tier_recovery_checks;

    let (resolved_tier, resolved_checks) =
        next_survival_tier_with_recovery(previous_tier.clone(), previous_checks, observed_tier);
    let resolved_low_cycles = resolved_tier != SurvivalTier::Normal;
    let resolved_paused_reason = if resolved_low_cycles {
        Some("low_cycles".to_string())
    } else {
        None
    };
    if resolved_tier == previous_tier
        && resolved_checks == previous_checks
        && runtime.low_cycles_mode == resolved_low_cycles
        && runtime.paused_reason == resolved_paused_reason
    {
        return;
    }

    runtime.survival_tier = resolved_tier.clone();
    runtime.survival_tier_recovery_checks = resolved_checks;
    runtime.low_cycles_mode = resolved_low_cycles;
    runtime.paused_reason = resolved_paused_reason;

    log!(
        SchedulerStorageLogPriority::Info,
        "scheduler_survival_tier transition previous_tier={:?} next_tier={:?} recovery_checks={}",
        previous_tier,
        resolved_tier,
        resolved_checks
    );
    save_scheduler_runtime(&runtime);
}

pub fn scheduler_low_cycles_mode() -> bool {
    scheduler_runtime().low_cycles_mode
}

pub fn scheduler_survival_tier() -> SurvivalTier {
    scheduler_runtime().survival_tier
}

pub fn scheduler_survival_tier_recovery_checks() -> u32 {
    scheduler_runtime().survival_tier_recovery_checks
}

pub fn scheduler_enabled() -> bool {
    scheduler_runtime().enabled
}

pub fn mutating_lease_active(now_ns: u64) -> bool {
    scheduler_runtime()
        .active_mutating_lease
        .is_some_and(|lease| lease.expires_at_ns > now_ns)
}

fn next_survival_tier_with_recovery(
    current: SurvivalTier,
    current_checks: u32,
    observed: SurvivalTier,
) -> (SurvivalTier, u32) {
    match observed {
        SurvivalTier::Normal => {
            if current == SurvivalTier::Normal
                || current_checks.saturating_add(1) >= SURVIVAL_TIER_RECOVERY_CHECKS_REQUIRED
            {
                (SurvivalTier::Normal, 0)
            } else {
                (current, current_checks.saturating_add(1))
            }
        }
        _ => (observed, 0),
    }
}

pub fn record_scheduler_tick_start(now_ns: u64) {
    let mut runtime = scheduler_runtime();
    runtime.last_tick_started_ns = now_ns;
    runtime.last_tick_error = None;
    save_scheduler_runtime(&runtime);
}

pub fn record_scheduler_tick_end(now_ns: u64, error: Option<String>) {
    let mut runtime = scheduler_runtime();
    runtime.last_tick_finished_ns = now_ns;
    runtime.last_tick_error = error;
    save_scheduler_runtime(&runtime);
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
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
}

pub fn set_soul(soul: String) -> String {
    let mut snapshot = runtime_snapshot();
    snapshot.soul = soul;
    snapshot.last_transition_at_ns = now_ns();
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
    snapshot.last_transition_at_ns = now_ns();
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
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
}

pub fn set_inference_model(model: String) -> Result<String, String> {
    if model.trim().is_empty() {
        return Err("inference model cannot be empty".to_string());
    }
    let mut snapshot = runtime_snapshot();
    snapshot.inference_model = model.trim().to_string();
    snapshot.last_transition_at_ns = now_ns();
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
    snapshot.last_transition_at_ns = now_ns();
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
    snapshot.last_transition_at_ns = now_ns();
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
    snapshot.last_transition_at_ns = now_ns();

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
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
}

pub fn get_tools_for_turn(turn_id: &str) -> Vec<ToolCallRecord> {
    let key = format!("tools:{turn_id}");
    TOOL_MAP.with(|map| read_json(map.borrow().get(&key).as_deref()).unwrap_or_default())
}

pub fn set_evm_cursor(cursor: &EvmPollCursor) {
    let mut snapshot = runtime_snapshot();
    snapshot.evm_cursor = cursor.clone();
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
}

pub fn post_inbox_message(body: String, caller: String) -> Result<String, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("message cannot be empty".to_string());
    }

    let seq = next_inbox_seq();
    let id = format!("inbox:{seq:020}");
    let message = InboxMessage {
        id: id.clone(),
        seq,
        body: trimmed.to_string(),
        posted_at_ns: now_ns(),
        posted_by: caller,
        status: InboxMessageStatus::Pending,
        staged_at_ns: None,
        consumed_at_ns: None,
    };
    INBOX_MAP.with(|map| {
        map.borrow_mut().insert(id.clone(), encode_json(&message));
    });
    INBOX_PENDING_QUEUE_MAP.with(|map| {
        map.borrow_mut()
            .insert(inbox_pending_key(seq), id.clone().into_bytes());
    });
    log!(
        SchedulerStorageLogPriority::Info,
        "inbox_posted id={} seq={}",
        id,
        seq
    );
    Ok(id)
}

pub fn list_inbox_messages(limit: usize) -> Vec<InboxMessage> {
    if limit == 0 {
        return Vec::new();
    }
    let mut messages = INBOX_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| read_json::<InboxMessage>(Some(entry.value().as_slice())))
            .collect::<Vec<_>>()
    });
    messages.sort_by_key(|message| std::cmp::Reverse(message.seq));
    messages.truncate(limit);
    messages
}

pub fn inbox_stats() -> InboxStats {
    let mut stats = InboxStats::default();
    INBOX_MAP.with(|map| {
        for entry in map.borrow().iter() {
            if let Some(message) = read_json::<InboxMessage>(Some(entry.value().as_slice())) {
                stats.total_messages = stats.total_messages.saturating_add(1);
                match message.status {
                    InboxMessageStatus::Pending => {
                        stats.pending_count = stats.pending_count.saturating_add(1)
                    }
                    InboxMessageStatus::Staged => {
                        stats.staged_count = stats.staged_count.saturating_add(1)
                    }
                    InboxMessageStatus::Consumed => {
                        stats.consumed_count = stats.consumed_count.saturating_add(1)
                    }
                }
            }
        }
    });
    stats
}

pub fn observability_snapshot(limit: usize) -> ObservabilitySnapshot {
    let bounded_limit = if limit == 0 {
        DEFAULT_OBSERVABILITY_LIMIT
    } else {
        limit.min(MAX_OBSERVABILITY_LIMIT)
    };

    ObservabilitySnapshot {
        captured_at_ns: now_ns(),
        runtime: snapshot_to_view(),
        scheduler: scheduler_runtime_view(),
        inbox_stats: inbox_stats(),
        inbox_messages: list_inbox_messages(bounded_limit),
        outbox_stats: outbox_stats(),
        outbox_messages: list_outbox_messages(bounded_limit),
        recent_turns: list_turns(bounded_limit),
        recent_transitions: list_recent_transitions(bounded_limit),
        recent_jobs: list_recent_jobs(bounded_limit),
    }
}

pub fn post_outbox_message(
    turn_id: String,
    body: String,
    source_inbox_ids: Vec<String>,
) -> Result<String, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("outbox message cannot be empty".to_string());
    }

    let seq = next_outbox_seq();
    let id = format!("outbox:{seq:020}");
    let message = OutboxMessage {
        id: id.clone(),
        seq,
        turn_id,
        body: trimmed.to_string(),
        created_at_ns: now_ns(),
        source_inbox_ids,
    };
    OUTBOX_MAP.with(|map| {
        map.borrow_mut().insert(id.clone(), encode_json(&message));
    });
    Ok(id)
}

pub fn list_outbox_messages(limit: usize) -> Vec<OutboxMessage> {
    if limit == 0 {
        return Vec::new();
    }
    let mut messages = OUTBOX_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| read_json::<OutboxMessage>(Some(entry.value().as_slice())))
            .collect::<Vec<_>>()
    });
    messages.sort_by_key(|message| std::cmp::Reverse(message.seq));
    messages.truncate(limit);
    messages
}

pub fn outbox_stats() -> OutboxStats {
    let total_messages = OUTBOX_MAP.with(|map| map.borrow().len());
    OutboxStats { total_messages }
}

pub fn stage_pending_inbox_messages(batch_size: usize, now_ns: u64) -> usize {
    if batch_size == 0 {
        return 0;
    }
    let mut staged_count = 0usize;
    let mut to_remove = Vec::new();

    INBOX_PENDING_QUEUE_MAP.with(|pending_map| {
        let pending = pending_map.borrow();
        for entry in pending.iter().take(batch_size) {
            to_remove.push((entry.key().clone(), entry.value().clone()));
        }
    });

    for (pending_key, raw_id) in &to_remove {
        let Ok(message_id) = String::from_utf8(raw_id.clone()) else {
            continue;
        };
        if let Some(mut message) = get_inbox_message_by_id(&message_id) {
            if matches!(message.status, InboxMessageStatus::Pending) {
                message.status = InboxMessageStatus::Staged;
                message.staged_at_ns = Some(now_ns);
                save_inbox_message(&message);
                INBOX_STAGED_QUEUE_MAP.with(|staged_map| {
                    staged_map
                        .borrow_mut()
                        .insert(inbox_staged_key(message.seq), message_id.into_bytes());
                });
                staged_count = staged_count.saturating_add(1);
            }
        }
        INBOX_PENDING_QUEUE_MAP.with(|pending_map| {
            pending_map.borrow_mut().remove(pending_key);
        });
    }

    if staged_count > 0 {
        log!(
            SchedulerStorageLogPriority::Info,
            "inbox_staged count={} now_ns={}",
            staged_count,
            now_ns
        );
    }
    staged_count
}

pub fn list_staged_inbox_messages(batch_size: usize) -> Vec<InboxMessage> {
    if batch_size == 0 {
        return Vec::new();
    }

    INBOX_STAGED_QUEUE_MAP.with(|staged_map| {
        staged_map
            .borrow()
            .iter()
            .take(batch_size)
            .filter_map(|entry| String::from_utf8(entry.value().clone()).ok())
            .filter_map(|id| get_inbox_message_by_id(&id))
            .filter(|message| matches!(message.status, InboxMessageStatus::Staged))
            .collect::<Vec<_>>()
    })
}

pub fn consume_staged_inbox_messages(ids: &[String], now_ns: u64) -> usize {
    if ids.is_empty() {
        return 0;
    }
    let mut consumed = 0usize;
    for id in ids {
        let Some(mut message) = get_inbox_message_by_id(id) else {
            continue;
        };
        if !matches!(message.status, InboxMessageStatus::Staged) {
            continue;
        }
        message.status = InboxMessageStatus::Consumed;
        message.consumed_at_ns = Some(now_ns);
        save_inbox_message(&message);
        INBOX_STAGED_QUEUE_MAP.with(|staged_map| {
            staged_map
                .borrow_mut()
                .remove(&inbox_staged_key(message.seq));
        });
        consumed = consumed.saturating_add(1);
    }
    if consumed > 0 {
        log!(
            SchedulerStorageLogPriority::Info,
            "inbox_consumed count={} now_ns={}",
            consumed,
            now_ns
        );
    }
    consumed
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

pub fn enqueue_job_if_absent(
    kind: TaskKind,
    lane: TaskLane,
    dedupe_key: String,
    scheduled_for_ns: u64,
    priority: u8,
) -> Option<String> {
    if let Some(existing_job_id) = DEDUPE_MAP
        .with(|map| map.borrow().get(&dedupe_index_key(&dedupe_key)))
        .and_then(|payload| String::from_utf8(payload).ok())
    {
        if let Some(existing) = get_job_by_id(&existing_job_id) {
            if !existing.is_terminal() {
                log!(
                    SchedulerStorageLogPriority::Warn,
                    "scheduler_dedupe_hit kind={:?} dedupe_key={} existing_job_id={} status={:?}",
                    kind,
                    dedupe_key,
                    existing_job_id,
                    existing.status
                );
                return None;
            }
        }
    }

    let mut runtime = scheduler_runtime();
    let job_seq = runtime.next_job_seq.saturating_add(1);
    runtime.next_job_seq = job_seq;
    save_scheduler_runtime(&runtime);

    let now_ns = now_ns();
    let job_id = format!("job:{:020}:{:020}", job_seq, scheduled_for_ns);
    let job = ScheduledJob {
        id: job_id.clone(),
        kind: kind.clone(),
        lane: lane.clone(),
        dedupe_key: dedupe_key.clone(),
        priority,
        created_at_ns: now_ns,
        scheduled_for_ns,
        started_at_ns: None,
        finished_at_ns: None,
        status: JobStatus::Pending,
        attempts: 0,
        max_attempts: 3,
        last_error: None,
    };

    JOB_MAP.with(|map| {
        map.borrow_mut().insert(job_id.clone(), encode_json(&job));
    });
    JOB_QUEUE_MAP.with(|map| {
        map.borrow_mut().insert(
            queue_index_key(&lane, scheduled_for_ns, priority, job_seq),
            job_id.clone().into_bytes(),
        );
    });
    DEDUPE_MAP.with(|map| {
        map.borrow_mut()
            .insert(dedupe_index_key(&dedupe_key), job_id.clone().into_bytes());
    });

    if let Some(mut task_runtime) = TASK_RUNTIME_MAP
        .with(|map| map.borrow().get(&task_kind_key(&kind)))
        .and_then(|payload| read_json::<TaskScheduleRuntime>(Some(payload.as_slice())))
    {
        task_runtime.pending_job_id = Some(job_id.clone());
        save_task_runtime(&kind, &task_runtime);
    }
    log!(
        SchedulerStorageLogPriority::Info,
        "scheduler_enqueue_job kind={:?} lane={:?} job_id={} dedupe_key={} scheduled_for={}",
        kind,
        lane,
        job_id,
        dedupe_key,
        scheduled_for_ns
    );

    Some(job_id)
}

pub fn pop_next_pending_job(lane: TaskLane, now_ns: u64) -> Option<ScheduledJob> {
    let lane_prefix = format!("queue:{}", lane.as_str());
    let mut selected_queue_key: Option<String> = None;
    let mut selected_job_id: Option<String> = None;

    JOB_QUEUE_MAP.with(|map| {
        for entry in map.borrow().iter() {
            let queue_key = entry.key();
            if !queue_key.starts_with(&lane_prefix) {
                continue;
            }
            let scheduled_for_ns = match parse_queue_index_key(queue_key) {
                Some(value) => value,
                None => {
                    selected_queue_key = Some(queue_key.clone());
                    break;
                }
            };
            if scheduled_for_ns > now_ns {
                continue;
            }

            let job_id = String::from_utf8(entry.value().clone()).unwrap_or_default();
            if let Some(mut job) = get_job_by_id(&job_id) {
                if matches!(job.status, JobStatus::Pending) {
                    job.started_at_ns = Some(now_ns);
                    job.status = JobStatus::InFlight;
                    save_job(&job);
                    selected_job_id = Some(job_id);
                    selected_queue_key = Some(queue_key.clone());
                    log!(
                        SchedulerStorageLogPriority::Info,
                        "scheduler_pop_pending job_id={} lane={:?} scheduled_for_ns={}",
                        queue_key,
                        lane,
                        scheduled_for_ns
                    );
                    break;
                }
                if job.is_terminal() {
                    log!(
                        SchedulerStorageLogPriority::Info,
                        "scheduler_pop_discard_terminal job_id={} status={:?} lane={:?}",
                        job_id,
                        job.status,
                        lane
                    );
                    selected_queue_key = Some(queue_key.clone());
                }
            } else {
                log!(
                    SchedulerStorageLogPriority::Warn,
                    "scheduler_pop_missing_job queue_key={}",
                    queue_key
                );
                selected_queue_key = Some(queue_key.clone());
            }
        }
    });

    let queue_key = selected_queue_key?;
    JOB_QUEUE_MAP.with(|map| {
        map.borrow_mut().remove(&queue_key);
    });
    let job_id = selected_job_id?;
    get_job_by_id(&job_id)
}

pub fn acquire_mutating_lease(job_id: &str, now_ns: u64, ttl_ns: u64) -> Result<(), String> {
    let mut runtime = scheduler_runtime();
    if runtime
        .active_mutating_lease
        .as_ref()
        .is_some_and(|lease| lease.expires_at_ns > now_ns)
    {
        log!(
            SchedulerStorageLogPriority::Warn,
            "scheduler_lease_active_reject job_id={}",
            job_id
        );
        return Err("mutating lease already active".to_string());
    }
    if get_job_by_id(job_id).is_none() {
        log!(
            SchedulerStorageLogPriority::Warn,
            "scheduler_lease_acquire_missing_job job_id={}",
            job_id
        );
        return Err("job not found".to_string());
    }
    runtime.active_mutating_lease = Some(SchedulerLease {
        lane: TaskLane::Mutating,
        job_id: job_id.to_string(),
        acquired_at_ns: now_ns,
        expires_at_ns: now_ns.saturating_add(ttl_ns),
    });
    log!(
        SchedulerStorageLogPriority::Info,
        "scheduler_lease_acquired job_id={} ttl_ns={}",
        job_id,
        ttl_ns
    );
    save_scheduler_runtime(&runtime);
    Ok(())
}

pub fn complete_job(job_id: &str, status: JobStatus, error: Option<String>, now_ns: u64) {
    let mut job = match get_job_by_id(job_id) {
        Some(job) => job,
        None => return,
    };
    let old_status = job.status.clone();
    job.status = status.clone();
    job.finished_at_ns = Some(now_ns);
    job.last_error = error.clone();
    job.attempts = job.attempts.saturating_add(1);
    save_job(&job);

    let cfg =
        get_task_config(&job.kind).unwrap_or_else(|| TaskScheduleConfig::default_for(&job.kind));
    let mut task_runtime = get_task_runtime(&job.kind);
    task_runtime.last_started_ns = job.started_at_ns;
    task_runtime.last_finished_ns = Some(now_ns);
    task_runtime.last_error = error.clone();

    match status {
        JobStatus::Succeeded => {
            task_runtime.consecutive_failures = 0;
            task_runtime.backoff_until_ns = None;
        }
        JobStatus::Failed | JobStatus::TimedOut => {
            task_runtime.consecutive_failures = task_runtime.consecutive_failures.saturating_add(1);
            let exponent = task_runtime.consecutive_failures.min(20) as u32;
            let base_delay = 1u64 << exponent;
            let capped = base_delay.min(cfg.max_backoff_secs.max(1));
            task_runtime.backoff_until_ns =
                now_ns.checked_add(capped.saturating_mul(1_000_000_000));
        }
        _ => {}
    }

    if task_runtime
        .pending_job_id
        .as_ref()
        .is_some_and(|id| id == job_id)
    {
        task_runtime.pending_job_id = None;
    }
    save_task_runtime(&job.kind, &task_runtime);

    let mut runtime = scheduler_runtime();
    if runtime
        .active_mutating_lease
        .as_ref()
        .is_some_and(|lease| lease.job_id == job_id)
    {
        runtime.active_mutating_lease = None;
        log!(
            SchedulerStorageLogPriority::Info,
            "scheduler_lease_released job_id={}",
            job_id
        );
        save_scheduler_runtime(&runtime);
    }

    log!(
        SchedulerStorageLogPriority::Info,
        "scheduler_job_complete job_id={} from={:?} to={:?} attempts={} error={:?}",
        job_id,
        old_status,
        status,
        job.attempts,
        error
    );
}

pub fn recover_stale_lease(now_ns: u64) {
    let expired_job_id = scheduler_runtime()
        .active_mutating_lease
        .filter(|lease| lease.expires_at_ns <= now_ns)
        .map(|lease| lease.job_id);
    if let Some(job_id) = expired_job_id {
        log!(
            SchedulerStorageLogPriority::Warn,
            "scheduler_recover_stale_lease job_id={}",
            job_id
        );
        complete_job(
            &job_id,
            JobStatus::TimedOut,
            Some("mutating lease expired".to_string()),
            now_ns,
        );
    }
}

pub fn list_recent_jobs(limit: usize) -> Vec<ScheduledJob> {
    if limit == 0 {
        return Vec::new();
    }
    let mut jobs = JOB_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| read_json::<ScheduledJob>(Some(entry.value().as_slice())))
            .collect::<Vec<_>>()
    });
    jobs.sort_by_key(|job| std::cmp::Reverse(job.created_at_ns));
    let keep = limit.min(MAX_RECENT_JOBS);
    if jobs.len() > keep {
        jobs.truncate(keep);
    }
    jobs
}

fn scheduler_runtime() -> SchedulerRuntime {
    SCHEDULER_RUNTIME_MAP
        .with(|map| map.borrow().get(&SCHEDULER_RUNTIME_KEY.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
        .unwrap_or_default()
}

fn save_scheduler_runtime(runtime: &SchedulerRuntime) {
    SCHEDULER_RUNTIME_MAP.with(|map| {
        map.borrow_mut()
            .insert(SCHEDULER_RUNTIME_KEY.to_string(), encode_json(runtime));
    });
}

fn task_kind_key(kind: &TaskKind) -> String {
    format!("task:{kind:?}")
}

fn parse_task_kind(raw_key: &str) -> Option<TaskKind> {
    if !raw_key.starts_with("task:") {
        return None;
    }
    match &raw_key[5..] {
        "AgentTurn" => Some(TaskKind::AgentTurn),
        "PollInbox" => Some(TaskKind::PollInbox),
        "CheckCycles" => Some(TaskKind::CheckCycles),
        "Reconcile" => Some(TaskKind::Reconcile),
        _ => None,
    }
}

fn dedupe_index_key(dedupe_key: &str) -> String {
    format!("dedupe:{dedupe_key}")
}

fn inbox_pending_key(seq: u64) -> String {
    format!("inbox:pending:{seq:020}")
}

fn inbox_staged_key(seq: u64) -> String {
    format!("inbox:staged:{seq:020}")
}

fn next_outbox_seq() -> u64 {
    let next = runtime_u64(OUTBOX_SEQ_KEY).unwrap_or(0).saturating_add(1);
    save_runtime_u64(OUTBOX_SEQ_KEY, next);
    next
}

fn queue_index_key(lane: &TaskLane, scheduled_for_ns: u64, priority: u8, seq: u64) -> String {
    format!(
        "queue:{}:{:020}:{:03}:{:020}",
        lane.as_str(),
        scheduled_for_ns,
        priority,
        seq
    )
}

fn parse_queue_index_key(raw_key: &str) -> Option<u64> {
    let parts = raw_key.split(':').collect::<Vec<_>>();
    if parts.len() != 5 {
        return None;
    }
    parts[2].parse::<u64>().ok()
}

fn get_job_by_id(job_id: &str) -> Option<ScheduledJob> {
    JOB_MAP
        .with(|map| map.borrow().get(&job_id.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

fn save_job(job: &ScheduledJob) {
    JOB_MAP.with(|map| {
        map.borrow_mut().insert(job.id.clone(), encode_json(job));
    });
}

fn get_inbox_message_by_id(id: &str) -> Option<InboxMessage> {
    INBOX_MAP
        .with(|map| map.borrow().get(&id.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

fn save_inbox_message(message: &InboxMessage) {
    INBOX_MAP.with(|map| {
        map.borrow_mut()
            .insert(message.id.clone(), encode_json(message));
    });
}

fn next_inbox_seq() -> u64 {
    let next = runtime_u64(INBOX_SEQ_KEY).unwrap_or(0).saturating_add(1);
    save_runtime_u64(INBOX_SEQ_KEY, next);
    next
}

fn runtime_u64(key: &str) -> Option<u64> {
    RUNTIME_MAP
        .with(|map| map.borrow().get(&key.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

fn save_runtime_u64(key: &str, value: u64) {
    RUNTIME_MAP.with(|map| {
        map.borrow_mut()
            .insert(key.to_string(), encode_json(&value));
    });
}

fn encode_json<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

fn read_json<T: DeserializeOwned>(value: Option<&[u8]>) -> Option<T> {
    value.and_then(|raw| serde_json::from_slice(raw).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{InboxMessageStatus, TaskKind, TaskLane};

    fn sample_job(id: &str, kind: TaskKind, when: u64, priority: u8) -> ScheduledJob {
        ScheduledJob {
            id: id.to_string(),
            kind,
            lane: TaskLane::Mutating,
            dedupe_key: format!("dedupe:{id}"),
            priority,
            created_at_ns: when,
            scheduled_for_ns: when,
            started_at_ns: None,
            finished_at_ns: None,
            status: JobStatus::Pending,
            attempts: 0,
            max_attempts: 3,
            last_error: None,
        }
    }

    fn seed_task_runtime(kind: TaskKind, next_due_ns: u64) {
        let kind_for_runtime = kind.clone();
        save_task_runtime(
            &kind,
            &TaskScheduleRuntime {
                kind: kind_for_runtime,
                next_due_ns,
                backoff_until_ns: None,
                consecutive_failures: 0,
                pending_job_id: None,
                last_started_ns: None,
                last_finished_ns: None,
                last_error: None,
            },
        );
    }

    #[test]
    fn pop_next_pending_job_obeys_queue_order() {
        let lane = TaskLane::Mutating;

        save_job(&sample_job("job:b", TaskKind::PollInbox, 20, 1));
        save_job(&sample_job("job:a", TaskKind::AgentTurn, 10, 0));

        JOB_QUEUE_MAP.with(|map| {
            let mut queue = map.borrow_mut();
            queue.insert(queue_index_key(&lane, 20, 1, 2), b"job:b".to_vec());
            queue.insert(queue_index_key(&lane, 10, 0, 1), b"job:a".to_vec());
        });

        let job = pop_next_pending_job(lane.clone(), 20).expect("a pending job should be returned");
        assert_eq!(job.id, "job:a");
    }

    #[test]
    fn mutating_lease_blocks_second_acquisition() {
        let lane = TaskLane::Mutating;
        seed_task_runtime(TaskKind::AgentTurn, 1);
        save_job(&sample_job("lease:first", TaskKind::AgentTurn, 1, 0));
        save_job(&sample_job("lease:second", TaskKind::AgentTurn, 2, 0));
        JOB_QUEUE_MAP.with(|map| {
            let mut queue = map.borrow_mut();
            queue.insert(queue_index_key(&lane, 1, 0, 1), b"lease:first".to_vec());
            queue.insert(queue_index_key(&lane, 2, 0, 2), b"lease:second".to_vec());
        });

        let ttl = 120;
        acquire_mutating_lease("lease:first", 1, ttl).expect("first lease acquired");
        assert!(acquire_mutating_lease("lease:second", 2, ttl).is_err());

        complete_job("lease:first", JobStatus::Succeeded, None, 3);
        assert!(acquire_mutating_lease("lease:second", 3, ttl).is_ok());
    }

    #[test]
    fn stale_lease_recovers_as_timed_out() {
        seed_task_runtime(TaskKind::PollInbox, 4);
        save_job(&sample_job("lease:stale", TaskKind::PollInbox, 4, 1));
        acquire_mutating_lease("lease:stale", 4, 1).expect("lease acquired");

        recover_stale_lease(10);

        let runtime = scheduler_runtime();
        assert!(runtime.active_mutating_lease.is_none());

        let reloaded = get_job_by_id("lease:stale").expect("job still exists");
        assert!(matches!(reloaded.status, JobStatus::TimedOut));
    }

    #[test]
    fn inbox_post_stage_consume_is_ordered_and_idempotent() {
        init_storage();

        let first_id =
            post_inbox_message("first message".to_string(), "2vxsx-fae".to_string()).unwrap();
        let second_id =
            post_inbox_message("second message".to_string(), "2vxsx-fae".to_string()).unwrap();
        let third_id =
            post_inbox_message("third message".to_string(), "2vxsx-fae".to_string()).unwrap();

        let staged_first = stage_pending_inbox_messages(2, 100);
        assert_eq!(
            staged_first, 2,
            "first poll should stage first two messages"
        );

        let staged_second = stage_pending_inbox_messages(10, 101);
        assert_eq!(
            staged_second, 1,
            "second poll should only stage the remaining pending message"
        );

        let staged_third = stage_pending_inbox_messages(10, 102);
        assert_eq!(staged_third, 0, "no pending messages should remain");

        let consumed = list_staged_inbox_messages(10);
        let consumed_ids = consumed
            .iter()
            .map(|message| message.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(consume_staged_inbox_messages(&consumed_ids, 200), 3);
        assert_eq!(consumed.len(), 3);
        assert_eq!(consumed[0].id, first_id);
        assert_eq!(consumed[1].id, second_id);
        assert_eq!(consumed[2].id, third_id);

        let consumed_again = list_staged_inbox_messages(10);
        let consumed_again_ids = consumed_again
            .iter()
            .map(|message| message.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(consume_staged_inbox_messages(&consumed_again_ids, 201), 0);
        assert!(
            consumed_again.is_empty(),
            "consuming staged queue twice must be idempotent"
        );

        let messages = list_inbox_messages(10);
        let status_by_id = messages
            .into_iter()
            .map(|message| (message.id, message.status))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            status_by_id.get(&first_id),
            Some(&InboxMessageStatus::Consumed)
        );
        assert_eq!(
            status_by_id.get(&second_id),
            Some(&InboxMessageStatus::Consumed)
        );
        assert_eq!(
            status_by_id.get(&third_id),
            Some(&InboxMessageStatus::Consumed)
        );
    }

    #[test]
    fn observability_snapshot_applies_limits_and_includes_runtime() {
        init_storage();
        post_inbox_message("snapshot message one".to_string(), "2vxsx-fae".to_string()).unwrap();
        post_inbox_message("snapshot message two".to_string(), "2vxsx-fae".to_string()).unwrap();

        let bounded = observability_snapshot(1);
        assert_eq!(bounded.inbox_messages.len(), 1);
        assert_eq!(bounded.recent_jobs.len(), 0);
        assert!(
            bounded.captured_at_ns > 0,
            "captured timestamp should be populated"
        );

        let defaulted = observability_snapshot(0);
        assert!(
            defaulted.inbox_messages.len() <= DEFAULT_OBSERVABILITY_LIMIT,
            "default limit should bound inbox messages"
        );
    }

    #[test]
    fn outbox_post_and_snapshot_are_ordered() {
        init_storage();
        let first_id = post_outbox_message(
            "turn-1".to_string(),
            "first assistant reply".to_string(),
            vec!["inbox:00000000000000000001".to_string()],
        )
        .expect("first outbox message should be accepted");
        let second_id = post_outbox_message(
            "turn-2".to_string(),
            "second assistant reply".to_string(),
            vec!["inbox:00000000000000000002".to_string()],
        )
        .expect("second outbox message should be accepted");

        let outbox = list_outbox_messages(10);
        assert_eq!(outbox.len(), 2);
        assert_eq!(outbox[0].id, second_id);
        assert_eq!(outbox[1].id, first_id);

        let snapshot = observability_snapshot(10);
        assert_eq!(snapshot.outbox_stats.total_messages, 2);
        assert_eq!(snapshot.outbox_messages.len(), 2);
    }
}
