use crate::domain::types::{
    AgentEvent, AgentState, ConversationEntry, ConversationLog, ConversationSummary,
    CycleTelemetry, EvmPollCursor, EvmRouteStateView, InboxMessage, InboxMessageStatus, InboxStats,
    InferenceConfigView, InferenceProvider, JobStatus, MemoryFact, ObservabilitySnapshot,
    OutboxMessage, OutboxStats, PromptLayer, PromptLayerView, RuntimeSnapshot, RuntimeView,
    ScheduledJob, SchedulerLease, SchedulerRuntime, SkillRecord, SurvivalOperationClass,
    SurvivalTier, TaskKind, TaskLane, TaskScheduleConfig, TaskScheduleRuntime, ToolCallRecord,
    TransitionLogRecord, TurnRecord, WalletBalanceSnapshot, WalletBalanceSyncConfig,
};
use crate::prompt;
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
const HTTP_ALLOWLIST_INITIALIZED_KEY: &str = "http.allowlist.initialized";
const CYCLE_BALANCE_SAMPLES_KEY: &str = "cycles.balance.samples";
const MAX_RECENT_JOBS: usize = 200;
const DEFAULT_OBSERVABILITY_LIMIT: usize = 25;
const MAX_OBSERVABILITY_LIMIT: usize = 100;
const CYCLES_BURN_MOVING_WINDOW_SECONDS: u64 = 15 * 60;
const CYCLES_BURN_MOVING_WINDOW_NS: u64 = CYCLES_BURN_MOVING_WINDOW_SECONDS * 1_000_000_000;
const CYCLES_BURN_MAX_SAMPLES: usize = 450;
const CYCLES_USD_PER_TRILLION_ESTIMATE: f64 = 1.35;
const MAX_CONVERSATION_ENTRIES_PER_SENDER: usize = 20;
const MAX_CONVERSATION_SENDERS: usize = 200;
const MAX_CONVERSATION_BODY_CHARS: usize = 500;
const MAX_CONVERSATION_REPLY_CHARS: usize = 500;
const MAX_EVM_CONFIRMATION_DEPTH: u64 = 100;
const AUTONOMY_TOOL_SUCCESS_KEY_PREFIX: &str = "autonomy.tool_success.";
const EVM_INGEST_DEDUPE_KEY_PREFIX: &str = "evm.ingest";
#[cfg(not(target_arch = "wasm32"))]
const HOST_TOTAL_CYCLES_OVERRIDE_KEY: &str = "host.total_cycles";
#[cfg(not(target_arch = "wasm32"))]
const HOST_LIQUID_CYCLES_OVERRIDE_KEY: &str = "host.liquid_cycles";
pub const SURVIVAL_TIER_RECOVERY_CHECKS_REQUIRED: u32 = 3;
pub const SURVIVAL_OPERATION_MAX_BACKOFF_SECS_INFERENCE: u64 = 120;
pub const SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_POLL: u64 = 120;
pub const SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_BROADCAST: u64 = 300;
pub const SURVIVAL_OPERATION_MAX_BACKOFF_SECS_THRESHOLD_SIGN: u64 = 120;
const MAX_EVM_RPC_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
#[allow(dead_code)]
const MIN_WALLET_BALANCE_SYNC_INTERVAL_SECS: u64 = 30;
#[allow(dead_code)]
const MAX_WALLET_BALANCE_SYNC_INTERVAL_SECS: u64 = 24 * 60 * 60;
#[allow(dead_code)]
const MIN_WALLET_BALANCE_FRESHNESS_WINDOW_SECS: u64 = 60;
#[allow(dead_code)]
const MAX_WALLET_BALANCE_FRESHNESS_WINDOW_SECS: u64 = 24 * 60 * 60;
#[allow(dead_code)]
const MIN_WALLET_BALANCE_SYNC_RESPONSE_BYTES: u64 = 256;
#[allow(dead_code)]
const MAX_WALLET_BALANCE_SYNC_RESPONSE_BYTES: u64 = 4 * 1024;
const DEFAULT_HTTP_ALLOWED_DOMAINS: &[&str] = &[
    "api.coingecko.com",
    "api.coinbase.com",
    "min-api.cryptocompare.com",
    "base.blockscout.com",
    "basescan.org",
];

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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CycleBalanceSample {
    captured_at_ns: u64,
    total_cycles: u128,
    liquid_cycles: u128,
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
    static MEMORY_FACTS_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(16)))
    ));
    static HTTP_DOMAIN_ALLOWLIST_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(17)))
    ));
    static PROMPT_LAYER_MAP: RefCell<
        StableBTreeMap<u8, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(18)))
    ));
    static CONVERSATION_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(19)))
    ));
}

pub fn init_storage() {
    let mut snapshot = runtime_snapshot();
    let mut snapshot_changed = false;
    if snapshot.evm_cursor.contract_address.is_none() {
        if let Some(contract_address) = snapshot.inbox_contract_address.clone() {
            snapshot.evm_cursor.contract_address = Some(contract_address);
            snapshot_changed = true;
        }
    }
    if snapshot.evm_cursor.automaton_address_topic.is_none() {
        if let Some(address) = snapshot.evm_address.as_deref() {
            snapshot.evm_cursor.automaton_address_topic = Some(evm_address_to_topic(address));
            snapshot_changed = true;
        }
    }
    if !snapshot.wallet_balance_bootstrap_pending {
        snapshot.wallet_balance_bootstrap_pending = true;
        snapshot_changed = true;
    }
    if snapshot_changed {
        save_runtime_snapshot(&snapshot);
    }
    seed_default_prompt_layers();
    if runtime_u64(INBOX_SEQ_KEY).is_none() {
        save_runtime_u64(INBOX_SEQ_KEY, 0);
    }
    if runtime_u64(OUTBOX_SEQ_KEY).is_none() {
        save_runtime_u64(OUTBOX_SEQ_KEY, 0);
    }
    if !runtime_bool(HTTP_ALLOWLIST_INITIALIZED_KEY).unwrap_or(false) {
        seed_default_http_allowed_domains();
        save_runtime_bool(HTTP_ALLOWLIST_INITIALIZED_KEY, true);
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

fn seed_default_prompt_layers() {
    for layer_id in prompt::MUTABLE_LAYER_MIN_ID..=prompt::MUTABLE_LAYER_MAX_ID {
        if get_prompt_layer(layer_id).is_some() {
            continue;
        }
        if let Some(content) = prompt::default_layer_content(layer_id) {
            let _ = save_prompt_layer(&PromptLayer {
                layer_id,
                content: content.to_string(),
                updated_at_ns: now_ns(),
                updated_by_turn: "init".to_string(),
                version: 1,
            });
        }
    }
}

pub fn get_prompt_layer(layer_id: u8) -> Option<PromptLayer> {
    PROMPT_LAYER_MAP
        .with(|map| map.borrow().get(&layer_id))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn save_prompt_layer(layer: &PromptLayer) -> Result<(), String> {
    if !(prompt::MUTABLE_LAYER_MIN_ID..=prompt::MUTABLE_LAYER_MAX_ID).contains(&layer.layer_id) {
        return Err(format!(
            "mutable prompt layer id must be in range {}..={}",
            prompt::MUTABLE_LAYER_MIN_ID,
            prompt::MUTABLE_LAYER_MAX_ID
        ));
    }

    PROMPT_LAYER_MAP.with(|map| {
        map.borrow_mut().insert(layer.layer_id, encode_json(layer));
    });
    Ok(())
}

pub fn list_prompt_layers() -> Vec<PromptLayerView> {
    let mut layers = Vec::with_capacity(
        usize::from(prompt::IMMUTABLE_LAYER_MAX_ID - prompt::IMMUTABLE_LAYER_MIN_ID + 1)
            + usize::from(prompt::MUTABLE_LAYER_MAX_ID - prompt::MUTABLE_LAYER_MIN_ID + 1),
    );

    for layer_id in prompt::IMMUTABLE_LAYER_MIN_ID..=prompt::IMMUTABLE_LAYER_MAX_ID {
        if let Some(content) = prompt::immutable_layer_content(layer_id) {
            layers.push(PromptLayerView {
                layer_id,
                is_mutable: false,
                content: content.to_string(),
                updated_at_ns: None,
                updated_by_turn: None,
                version: None,
            });
        }
    }

    for layer_id in prompt::MUTABLE_LAYER_MIN_ID..=prompt::MUTABLE_LAYER_MAX_ID {
        if let Some(layer) = get_prompt_layer(layer_id) {
            layers.push(PromptLayerView {
                layer_id,
                is_mutable: true,
                content: layer.content,
                updated_at_ns: Some(layer.updated_at_ns),
                updated_by_turn: Some(layer.updated_by_turn),
                version: Some(layer.version),
            });
            continue;
        }

        layers.push(PromptLayerView {
            layer_id,
            is_mutable: true,
            content: prompt::default_layer_content(layer_id)
                .unwrap_or_default()
                .to_string(),
            updated_at_ns: None,
            updated_by_turn: None,
            version: None,
        });
    }

    layers
}

pub fn append_conversation_entry(sender: &str, mut entry: ConversationEntry) {
    let sender_key = normalize_conversation_sender(sender);
    if sender_key.is_empty() {
        return;
    }

    entry.sender_body = truncate_to_chars(&entry.sender_body, MAX_CONVERSATION_BODY_CHARS);
    entry.agent_reply = truncate_to_chars(&entry.agent_reply, MAX_CONVERSATION_REPLY_CHARS);

    let mut log = get_conversation_log(&sender_key).unwrap_or_else(|| ConversationLog {
        sender: sender_key.clone(),
        entries: Vec::new(),
        last_activity_ns: 0,
    });
    log.sender = sender_key.clone();
    log.last_activity_ns = entry.timestamp_ns;
    log.entries.push(entry);
    if log.entries.len() > MAX_CONVERSATION_ENTRIES_PER_SENDER {
        let drop_count = log
            .entries
            .len()
            .saturating_sub(MAX_CONVERSATION_ENTRIES_PER_SENDER);
        log.entries.drain(0..drop_count);
    }

    CONVERSATION_MAP.with(|map| {
        map.borrow_mut().insert(sender_key, encode_json(&log));
    });
    evict_oldest_conversation_sender_if_needed();
}

pub fn get_conversation_log(sender: &str) -> Option<ConversationLog> {
    let sender_key = normalize_conversation_sender(sender);
    if sender_key.is_empty() {
        return None;
    }
    CONVERSATION_MAP
        .with(|map| map.borrow().get(&sender_key))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn list_conversation_summaries() -> Vec<ConversationSummary> {
    let mut summaries = CONVERSATION_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| read_json::<ConversationLog>(Some(entry.value().as_slice())))
            .map(|log| ConversationSummary {
                sender: log.sender,
                last_activity_ns: log.last_activity_ns,
                entry_count: u32::try_from(log.entries.len()).unwrap_or(u32::MAX),
            })
            .collect::<Vec<_>>()
    });

    summaries.sort_by(|left, right| {
        right
            .last_activity_ns
            .cmp(&left.last_activity_ns)
            .then_with(|| left.sender.cmp(&right.sender))
    });
    summaries
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

fn normalize_https_url(raw: &str, field: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    if !trimmed.starts_with("https://") {
        return Err(format!("{field} must be an https:// URL"));
    }
    Ok(trimmed.to_string())
}

fn normalize_evm_hex_address(raw: &str, field: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let valid_len = trimmed.len() == 42;
    let valid_prefix = trimmed.starts_with("0x");
    let valid_hex = trimmed
        .as_bytes()
        .iter()
        .skip(2)
        .all(|byte| byte.is_ascii_hexdigit());
    if !(valid_len && valid_prefix && valid_hex) {
        return Err(format!("{field} must be a 0x-prefixed 20-byte hex string"));
    }
    Ok(trimmed)
}

fn evm_address_to_topic(address: &str) -> String {
    let suffix = address.strip_prefix("0x").unwrap_or(address);
    format!("0x{:0>64}", suffix)
}

pub fn set_ecdsa_key_name(key_name: String) -> Result<String, String> {
    let trimmed = key_name.trim();
    if trimmed.is_empty() {
        return Err("ecdsa key name cannot be empty".to_string());
    }

    let mut snapshot = runtime_snapshot();
    snapshot.ecdsa_key_name = trimmed.to_string();
    snapshot.last_transition_at_ns = now_ns();
    let out = snapshot.ecdsa_key_name.clone();
    save_runtime_snapshot(&snapshot);
    Ok(out)
}

#[allow(dead_code)]
pub fn get_ecdsa_key_name() -> String {
    runtime_snapshot().ecdsa_key_name
}

pub fn set_evm_address(address: Option<String>) -> Result<Option<String>, String> {
    let normalized = match address {
        Some(raw) => Some(normalize_evm_hex_address(&raw, "evm address")?),
        None => None,
    };

    let mut snapshot = runtime_snapshot();
    snapshot.evm_address = normalized.clone();
    snapshot.evm_cursor.automaton_address_topic = normalized.as_deref().map(evm_address_to_topic);
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
    Ok(normalized)
}

pub fn get_evm_address() -> Option<String> {
    runtime_snapshot().evm_address
}

pub fn set_automaton_evm_address(address: Option<String>) -> Result<Option<String>, String> {
    set_evm_address(address)
}

#[allow(dead_code)]
pub fn get_automaton_evm_address() -> Option<String> {
    get_evm_address()
}

pub fn set_inbox_contract_address(address: Option<String>) -> Result<Option<String>, String> {
    let normalized = match address {
        Some(raw) => Some(normalize_evm_hex_address(&raw, "inbox contract address")?),
        None => None,
    };

    let mut snapshot = runtime_snapshot();
    snapshot.inbox_contract_address = normalized.clone();
    snapshot.evm_cursor.contract_address = normalized.clone();
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
    Ok(normalized)
}

pub fn set_evm_chain_id(chain_id: u64) -> Result<u64, String> {
    if chain_id == 0 {
        return Err("evm chain id must be greater than 0".to_string());
    }

    let mut snapshot = runtime_snapshot();
    snapshot.evm_cursor.chain_id = chain_id;
    snapshot.evm_cursor.next_block = 0;
    snapshot.evm_cursor.next_log_index = 0;
    snapshot.evm_cursor.last_poll_at_ns = 0;
    snapshot.evm_cursor.consecutive_empty_polls = 0;
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
    Ok(chain_id)
}

pub fn set_evm_confirmation_depth(confirmation_depth: u64) -> Result<u64, String> {
    if confirmation_depth > MAX_EVM_CONFIRMATION_DEPTH {
        return Err(format!(
            "evm confirmation depth must be <= {MAX_EVM_CONFIRMATION_DEPTH}"
        ));
    }
    let mut snapshot = runtime_snapshot();
    snapshot.evm_cursor.confirmation_depth = confirmation_depth;
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
    Ok(confirmation_depth)
}

pub fn set_memory_fact(fact: &MemoryFact) {
    MEMORY_FACTS_MAP.with(|map| {
        map.borrow_mut().insert(fact.key.clone(), encode_json(fact));
    });
}

pub fn get_memory_fact(key: &str) -> Option<MemoryFact> {
    MEMORY_FACTS_MAP
        .with(|map| map.borrow().get(&key.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn remove_memory_fact(key: &str) -> bool {
    MEMORY_FACTS_MAP
        .with(|map| map.borrow_mut().remove(&key.to_string()))
        .is_some()
}

pub fn memory_fact_count() -> usize {
    MEMORY_FACTS_MAP.with(|map| map.borrow().len() as usize)
}

pub fn list_all_memory_facts(limit: usize) -> Vec<MemoryFact> {
    if limit == 0 {
        return Vec::new();
    }

    let facts = MEMORY_FACTS_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| read_json::<MemoryFact>(Some(entry.value().as_slice())))
            .collect::<Vec<_>>()
    });
    sort_memory_facts_desc_by_updated(facts, limit)
}

pub fn list_memory_facts_by_prefix(prefix: &str, limit: usize) -> Vec<MemoryFact> {
    if limit == 0 {
        return Vec::new();
    }

    let normalized_prefix = prefix.trim().to_ascii_lowercase();
    let facts = MEMORY_FACTS_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter(|entry| entry.key().starts_with(&normalized_prefix))
            .filter_map(|entry| read_json::<MemoryFact>(Some(entry.value().as_slice())))
            .collect::<Vec<_>>()
    });
    sort_memory_facts_desc_by_updated(facts, limit)
}

pub fn autonomy_tool_last_success_ns(fingerprint: &str) -> Option<u64> {
    runtime_u64(&autonomy_tool_success_key(fingerprint))
}

pub fn record_autonomy_tool_success(fingerprint: &str, succeeded_at_ns: u64) {
    save_runtime_u64(&autonomy_tool_success_key(fingerprint), succeeded_at_ns);
}

fn autonomy_tool_success_key(fingerprint: &str) -> String {
    format!("{AUTONOMY_TOOL_SUCCESS_KEY_PREFIX}{fingerprint}")
}

fn sort_memory_facts_desc_by_updated(mut facts: Vec<MemoryFact>, limit: usize) -> Vec<MemoryFact> {
    facts.sort_by(|left, right| {
        right
            .updated_at_ns
            .cmp(&left.updated_at_ns)
            .then_with(|| left.key.cmp(&right.key))
    });
    if facts.len() > limit {
        facts.truncate(limit);
    }
    facts
}

pub fn list_allowed_http_domains() -> Vec<String> {
    HTTP_DOMAIN_ALLOWLIST_MAP.with(|map| {
        map.borrow()
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>()
    })
}

pub fn set_http_allowed_domains(domains: Vec<String>) -> Result<Vec<String>, String> {
    let mut normalized = domains
        .into_iter()
        .map(|domain| normalize_http_allowed_domain(&domain))
        .collect::<Result<Vec<_>, _>>()?;
    normalized.sort();
    normalized.dedup();

    HTTP_DOMAIN_ALLOWLIST_MAP.with(|map| {
        let keys = map
            .borrow()
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        let mut map_ref = map.borrow_mut();
        for key in keys {
            map_ref.remove(&key);
        }
        for domain in normalized {
            map_ref.insert(domain, vec![1]);
        }
    });

    let mut snapshot = runtime_snapshot();
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
    save_runtime_bool(HTTP_ALLOWLIST_INITIALIZED_KEY, true);
    Ok(list_allowed_http_domains())
}

#[allow(dead_code)]
pub fn add_http_allowed_domain(domain: String) -> Result<String, String> {
    let normalized = normalize_http_allowed_domain(&domain)?;
    HTTP_DOMAIN_ALLOWLIST_MAP.with(|map| {
        map.borrow_mut().insert(normalized.clone(), vec![1]);
    });
    save_runtime_bool(HTTP_ALLOWLIST_INITIALIZED_KEY, true);
    Ok(normalized)
}

#[allow(dead_code)]
pub fn remove_http_allowed_domain(domain: String) -> Result<bool, String> {
    let normalized = normalize_http_allowed_domain(&domain)?;
    let removed = HTTP_DOMAIN_ALLOWLIST_MAP
        .with(|map| map.borrow_mut().remove(&normalized))
        .is_some();
    save_runtime_bool(HTTP_ALLOWLIST_INITIALIZED_KEY, true);
    Ok(removed)
}

fn normalize_http_allowed_domain(raw: &str) -> Result<String, String> {
    let domain = raw.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return Err("http allowed domain cannot be empty".to_string());
    }
    if domain.contains("://")
        || domain.contains('/')
        || domain.contains('?')
        || domain.contains('#')
        || domain.contains('@')
        || domain.contains(':')
    {
        return Err("http allowed domain must be a bare host without scheme/path/port".to_string());
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err("http allowed domain must not start or end with '.'".to_string());
    }

    for label in domain.split('.') {
        if label.is_empty() {
            return Err("http allowed domain labels must not be empty".to_string());
        }
        let bytes = label.as_bytes();
        let starts_ok = bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
        let ends_ok = bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
        if !starts_ok || !ends_ok {
            return Err(
                "http allowed domain labels must start and end with alphanumeric characters"
                    .to_string(),
            );
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err("http allowed domain labels may only contain [a-z0-9-]".to_string());
        }
    }

    Ok(domain)
}

fn seed_default_http_allowed_domains() {
    let defaults = DEFAULT_HTTP_ALLOWED_DOMAINS
        .iter()
        .map(|domain| normalize_http_allowed_domain(domain))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();
    HTTP_DOMAIN_ALLOWLIST_MAP.with(|map| {
        let mut map_ref = map.borrow_mut();
        for domain in defaults {
            map_ref.insert(domain, vec![1]);
        }
    });
}

pub fn set_evm_rpc_url(url: String) -> Result<String, String> {
    let normalized = normalize_https_url(&url, "evm rpc url")?;
    let mut snapshot = runtime_snapshot();
    snapshot.evm_rpc_url = normalized.clone();
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
    Ok(normalized)
}

pub fn set_evm_rpc_fallback_url(url: Option<String>) -> Result<Option<String>, String> {
    let normalized = match url {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(normalize_https_url(trimmed, "evm rpc fallback url")?)
            }
        }
        None => None,
    };

    let mut snapshot = runtime_snapshot();
    snapshot.evm_rpc_fallback_url = normalized.clone();
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
    Ok(normalized)
}

pub fn set_evm_rpc_max_response_bytes(max_response_bytes: u64) -> Result<u64, String> {
    if max_response_bytes == 0 {
        return Err("evm rpc max_response_bytes must be greater than 0".to_string());
    }
    if max_response_bytes > MAX_EVM_RPC_RESPONSE_BYTES {
        return Err(format!(
            "evm rpc max_response_bytes must be <= {MAX_EVM_RPC_RESPONSE_BYTES}"
        ));
    }
    let mut snapshot = runtime_snapshot();
    snapshot.evm_rpc_max_response_bytes = max_response_bytes;
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
    Ok(max_response_bytes)
}

#[allow(dead_code)]
fn validate_wallet_balance_sync_config(config: &WalletBalanceSyncConfig) -> Result<(), String> {
    if config.normal_interval_secs < MIN_WALLET_BALANCE_SYNC_INTERVAL_SECS
        || config.normal_interval_secs > MAX_WALLET_BALANCE_SYNC_INTERVAL_SECS
    {
        return Err(format!(
            "wallet balance sync normal_interval_secs must be in {MIN_WALLET_BALANCE_SYNC_INTERVAL_SECS}..={MAX_WALLET_BALANCE_SYNC_INTERVAL_SECS}"
        ));
    }
    if config.low_cycles_interval_secs < MIN_WALLET_BALANCE_SYNC_INTERVAL_SECS
        || config.low_cycles_interval_secs > MAX_WALLET_BALANCE_SYNC_INTERVAL_SECS
    {
        return Err(format!(
            "wallet balance sync low_cycles_interval_secs must be in {MIN_WALLET_BALANCE_SYNC_INTERVAL_SECS}..={MAX_WALLET_BALANCE_SYNC_INTERVAL_SECS}"
        ));
    }
    if config.low_cycles_interval_secs < config.normal_interval_secs {
        return Err(
            "wallet balance sync low_cycles_interval_secs must be >= normal_interval_secs"
                .to_string(),
        );
    }
    if config.freshness_window_secs < MIN_WALLET_BALANCE_FRESHNESS_WINDOW_SECS
        || config.freshness_window_secs > MAX_WALLET_BALANCE_FRESHNESS_WINDOW_SECS
    {
        return Err(format!(
            "wallet balance sync freshness_window_secs must be in {MIN_WALLET_BALANCE_FRESHNESS_WINDOW_SECS}..={MAX_WALLET_BALANCE_FRESHNESS_WINDOW_SECS}"
        ));
    }
    if config.max_response_bytes < MIN_WALLET_BALANCE_SYNC_RESPONSE_BYTES
        || config.max_response_bytes > MAX_WALLET_BALANCE_SYNC_RESPONSE_BYTES
    {
        return Err(format!(
            "wallet balance sync max_response_bytes must be in {MIN_WALLET_BALANCE_SYNC_RESPONSE_BYTES}..={MAX_WALLET_BALANCE_SYNC_RESPONSE_BYTES}"
        ));
    }

    Ok(())
}

#[allow(dead_code)]
pub fn wallet_balance_snapshot() -> WalletBalanceSnapshot {
    runtime_snapshot().wallet_balance
}

#[allow(dead_code)]
pub fn set_wallet_balance_snapshot(balance: WalletBalanceSnapshot) {
    let mut snapshot = runtime_snapshot();
    snapshot.wallet_balance = balance;
    save_runtime_snapshot(&snapshot);
}

#[allow(dead_code)]
pub fn wallet_balance_sync_config() -> WalletBalanceSyncConfig {
    runtime_snapshot().wallet_balance_sync
}

#[allow(dead_code)]
pub fn set_wallet_balance_sync_config(
    config: WalletBalanceSyncConfig,
) -> Result<WalletBalanceSyncConfig, String> {
    validate_wallet_balance_sync_config(&config)?;

    let mut snapshot = runtime_snapshot();
    snapshot.wallet_balance_sync = config.clone();
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);

    Ok(config)
}

#[allow(dead_code)]
pub fn wallet_balance_bootstrap_pending() -> bool {
    runtime_snapshot().wallet_balance_bootstrap_pending
}

#[allow(dead_code)]
pub fn set_wallet_balance_bootstrap_pending(pending: bool) {
    let mut snapshot = runtime_snapshot();
    snapshot.wallet_balance_bootstrap_pending = pending;
    save_runtime_snapshot(&snapshot);
}

pub fn record_wallet_balance_sync_success(
    now_ns: u64,
    eth_balance_wei_hex: String,
    usdc_balance_raw_hex: String,
    usdc_contract_address: String,
) -> WalletBalanceSnapshot {
    let mut snapshot = runtime_snapshot();
    snapshot.wallet_balance.eth_balance_wei_hex = Some(eth_balance_wei_hex);
    snapshot.wallet_balance.usdc_balance_raw_hex = Some(usdc_balance_raw_hex);
    snapshot.wallet_balance.usdc_contract_address = Some(usdc_contract_address);
    snapshot.wallet_balance.last_synced_at_ns = Some(now_ns);
    snapshot.wallet_balance.last_synced_block = None;
    snapshot.wallet_balance.last_error = None;
    snapshot.wallet_balance_bootstrap_pending = false;
    let updated = snapshot.wallet_balance.clone();
    save_runtime_snapshot(&snapshot);
    updated
}

pub fn record_wallet_balance_sync_error(error: String) -> WalletBalanceSnapshot {
    let mut snapshot = runtime_snapshot();
    snapshot.wallet_balance.last_error = Some(error);
    let updated = snapshot.wallet_balance.clone();
    save_runtime_snapshot(&snapshot);
    updated
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

pub fn evm_route_state_view() -> EvmRouteStateView {
    EvmRouteStateView::from(&runtime_snapshot())
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
    let mut next_cursor = cursor.clone();
    if next_cursor.contract_address.is_none() {
        next_cursor.contract_address = snapshot.inbox_contract_address.clone();
    }
    if next_cursor.automaton_address_topic.is_none() {
        next_cursor.automaton_address_topic =
            snapshot.evm_address.as_deref().map(evm_address_to_topic);
    }
    snapshot.evm_cursor = next_cursor;
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
}

pub fn try_mark_evm_event_ingested(tx_hash: &str, log_index: u64) -> bool {
    let key = evm_ingest_dedupe_key(tx_hash, log_index);
    let already_seen = RUNTIME_MAP.with(|map| map.borrow().get(&key).is_some());
    if already_seen {
        return false;
    }
    save_runtime_bool(&key, true);
    true
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

fn current_total_cycle_balance() -> u128 {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::canister_cycle_balance();

    #[cfg(not(target_arch = "wasm32"))]
    {
        runtime_u128(HOST_TOTAL_CYCLES_OVERRIDE_KEY).unwrap_or_default()
    }
}

fn current_liquid_cycle_balance(total_cycles: u128) -> u128 {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::canister_liquid_cycle_balance().min(total_cycles);

    #[cfg(not(target_arch = "wasm32"))]
    {
        runtime_u128(HOST_LIQUID_CYCLES_OVERRIDE_KEY)
            .unwrap_or(total_cycles)
            .min(total_cycles)
    }
}

fn load_cycle_balance_samples() -> Vec<CycleBalanceSample> {
    RUNTIME_MAP
        .with(|map| map.borrow().get(&CYCLE_BALANCE_SAMPLES_KEY.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
        .unwrap_or_default()
}

fn save_cycle_balance_samples(samples: &[CycleBalanceSample]) {
    RUNTIME_MAP.with(|map| {
        map.borrow_mut()
            .insert(CYCLE_BALANCE_SAMPLES_KEY.to_string(), encode_json(samples));
    });
}

fn push_cycle_balance_sample(
    now_ns: u64,
    total_cycles: u128,
    liquid_cycles: u128,
) -> Vec<CycleBalanceSample> {
    let mut samples = load_cycle_balance_samples();
    let sample = CycleBalanceSample {
        captured_at_ns: now_ns,
        total_cycles,
        liquid_cycles,
    };

    if let Some(last) = samples.last_mut() {
        if last.captured_at_ns == now_ns {
            *last = sample;
        } else {
            samples.push(sample);
        }
    } else {
        samples.push(sample);
    }

    let cutoff_ns = now_ns.saturating_sub(CYCLES_BURN_MOVING_WINDOW_NS);
    samples.retain(|entry| entry.captured_at_ns >= cutoff_ns);
    if samples.len() > CYCLES_BURN_MAX_SAMPLES {
        let drop_count = samples.len() - CYCLES_BURN_MAX_SAMPLES;
        samples.drain(0..drop_count);
    }
    save_cycle_balance_samples(&samples);
    samples
}

fn round_f64_to_u128(value: f64) -> Option<u128> {
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    if value >= u128::MAX as f64 {
        return Some(u128::MAX);
    }
    Some(value.round() as u128)
}

fn cycles_to_usd_estimate(cycles: u128) -> f64 {
    (cycles as f64 / 1_000_000_000_000f64) * CYCLES_USD_PER_TRILLION_ESTIMATE
}

fn calculate_liquid_burn_cycles_per_sec(samples: &[CycleBalanceSample]) -> Option<f64> {
    let first = samples.first()?;
    let last = samples.last()?;
    if last.captured_at_ns <= first.captured_at_ns {
        return None;
    }

    let burned_cycles = samples.windows(2).fold(0u128, |acc, pair| {
        let prev = &pair[0];
        let next = &pair[1];
        if next.captured_at_ns <= prev.captured_at_ns {
            return acc;
        }
        acc.saturating_add(prev.liquid_cycles.saturating_sub(next.liquid_cycles))
    });

    if burned_cycles == 0 {
        return None;
    }

    let elapsed_secs = (last.captured_at_ns.saturating_sub(first.captured_at_ns)) as f64 / 1e9f64;
    if elapsed_secs <= 0.0 {
        return None;
    }
    Some(burned_cycles as f64 / elapsed_secs)
}

fn derive_cycle_telemetry(
    now_ns: u64,
    total_cycles: u128,
    liquid_cycles: u128,
    samples: &[CycleBalanceSample],
) -> CycleTelemetry {
    let freezing_threshold_cycles = total_cycles.saturating_sub(liquid_cycles);
    let window_duration_seconds = samples
        .first()
        .zip(samples.last())
        .map(|(first, last)| {
            last.captured_at_ns
                .saturating_sub(first.captured_at_ns)
                .saturating_div(1_000_000_000)
        })
        .unwrap_or_default();

    let burn_per_sec = calculate_liquid_burn_cycles_per_sec(samples);
    let burn_per_hour = burn_per_sec.and_then(|rate| round_f64_to_u128(rate * 3_600f64));
    let burn_per_day = burn_per_sec.and_then(|rate| round_f64_to_u128(rate * 86_400f64));

    let estimated_seconds_until_freezing_threshold = burn_per_sec.and_then(|rate| {
        if rate <= 0.0 {
            return None;
        }
        let estimate = (liquid_cycles as f64 / rate).floor();
        if !estimate.is_finite() || estimate < 0.0 || estimate > u64::MAX as f64 {
            return None;
        }
        Some(estimate as u64)
    });
    let estimated_freeze_time_ns = estimated_seconds_until_freezing_threshold.and_then(|seconds| {
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|delta_ns| now_ns.checked_add(delta_ns))
    });

    CycleTelemetry {
        total_cycles,
        liquid_cycles,
        freezing_threshold_cycles,
        moving_window_seconds: CYCLES_BURN_MOVING_WINDOW_SECONDS,
        window_duration_seconds,
        window_sample_count: u32::try_from(samples.len()).unwrap_or(u32::MAX),
        burn_rate_cycles_per_hour: burn_per_hour,
        burn_rate_cycles_per_day: burn_per_day,
        burn_rate_usd_per_hour: burn_per_hour.map(cycles_to_usd_estimate),
        burn_rate_usd_per_day: burn_per_day.map(cycles_to_usd_estimate),
        estimated_seconds_until_freezing_threshold,
        estimated_freeze_time_ns,
        usd_per_trillion_cycles: CYCLES_USD_PER_TRILLION_ESTIMATE,
    }
}

pub fn observability_snapshot(limit: usize) -> ObservabilitySnapshot {
    let bounded_limit = if limit == 0 {
        DEFAULT_OBSERVABILITY_LIMIT
    } else {
        limit.min(MAX_OBSERVABILITY_LIMIT)
    };
    let captured_at_ns = now_ns();
    let total_cycles = current_total_cycle_balance();
    let liquid_cycles = current_liquid_cycle_balance(total_cycles);
    let cycle_samples = push_cycle_balance_sample(captured_at_ns, total_cycles, liquid_cycles);
    let cycles =
        derive_cycle_telemetry(captured_at_ns, total_cycles, liquid_cycles, &cycle_samples);
    let mut conversation_summaries = list_conversation_summaries();
    conversation_summaries.truncate(bounded_limit);

    ObservabilitySnapshot {
        captured_at_ns,
        runtime: snapshot_to_view(),
        scheduler: scheduler_runtime_view(),
        inbox_stats: inbox_stats(),
        inbox_messages: list_inbox_messages(bounded_limit),
        outbox_stats: outbox_stats(),
        outbox_messages: list_outbox_messages(bounded_limit),
        prompt_layers: list_prompt_layers(),
        conversation_summaries,
        cycles,
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

fn evm_ingest_dedupe_key(tx_hash: &str, log_index: u64) -> String {
    format!("{EVM_INGEST_DEDUPE_KEY_PREFIX}:{tx_hash}:{log_index}")
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

fn normalize_conversation_sender(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn truncate_to_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
}

fn evict_oldest_conversation_sender_if_needed() {
    loop {
        let len = CONVERSATION_MAP.with(|map| map.borrow().len() as usize);
        if len <= MAX_CONVERSATION_SENDERS {
            return;
        }

        let candidate = CONVERSATION_MAP.with(|map| {
            map.borrow()
                .iter()
                .filter_map(|entry| {
                    read_json::<ConversationLog>(Some(entry.value().as_slice()))
                        .map(|log| (entry.key().clone(), log.last_activity_ns))
                })
                .min_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)))
        });
        let Some((sender, _)) = candidate else {
            return;
        };
        CONVERSATION_MAP.with(|map| {
            map.borrow_mut().remove(&sender);
        });
    }
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

fn runtime_u128(key: &str) -> Option<u128> {
    RUNTIME_MAP
        .with(|map| map.borrow().get(&key.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

#[cfg(test)]
fn save_runtime_u128(key: &str, value: u128) {
    RUNTIME_MAP.with(|map| {
        map.borrow_mut()
            .insert(key.to_string(), encode_json(&value));
    });
}

fn runtime_bool(key: &str) -> Option<bool> {
    RUNTIME_MAP
        .with(|map| map.borrow().get(&key.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

fn save_runtime_bool(key: &str, value: bool) {
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
    use crate::domain::types::{
        ConversationEntry, InboxMessageStatus, MemoryFact, PromptLayer, RuntimeSnapshot, TaskKind,
        TaskLane, WalletBalanceSnapshot, WalletBalanceSyncConfig,
    };

    fn clear_conversation_map() {
        let keys = CONVERSATION_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        CONVERSATION_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in keys {
                map_ref.remove(&key);
            }
        });
    }

    fn sender_for(seed: usize) -> String {
        format!("0x{seed:040x}")
    }

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
    fn init_storage_seeds_default_prompt_layers() {
        for layer_id in prompt::MUTABLE_LAYER_MIN_ID..=prompt::MUTABLE_LAYER_MAX_ID {
            PROMPT_LAYER_MAP.with(|map| {
                map.borrow_mut().remove(&layer_id);
            });
        }

        init_storage();

        for layer_id in prompt::MUTABLE_LAYER_MIN_ID..=prompt::MUTABLE_LAYER_MAX_ID {
            let layer = get_prompt_layer(layer_id).expect("default prompt layer should be seeded");
            assert_eq!(layer.layer_id, layer_id);
            assert_eq!(
                layer.content,
                prompt::default_layer_content(layer_id)
                    .expect("default content should be available")
                    .to_string()
            );
            assert_eq!(layer.updated_by_turn, "init");
            assert_eq!(layer.version, 1);
        }
    }

    #[test]
    fn save_prompt_layer_validates_mutable_range() {
        let result = save_prompt_layer(&PromptLayer {
            layer_id: 5,
            content: "invalid".to_string(),
            updated_at_ns: 1,
            updated_by_turn: "turn-1".to_string(),
            version: 1,
        });

        assert!(result.is_err());
    }

    #[test]
    fn save_prompt_layer_persists_content() {
        let layer = PromptLayer {
            layer_id: 8,
            content: "## Layer 8: Custom".to_string(),
            updated_at_ns: 77,
            updated_by_turn: "turn-77".to_string(),
            version: 3,
        };

        save_prompt_layer(&layer).expect("save should succeed");
        let stored = get_prompt_layer(8).expect("layer must be persisted");
        assert_eq!(stored, layer);
    }

    #[test]
    fn list_prompt_layers_includes_immutable_and_mutable_layers() {
        init_storage();
        let layers = list_prompt_layers();
        assert_eq!(layers.len(), 10);
        assert_eq!(layers[0].layer_id, 0);
        assert!(!layers[0].is_mutable);
        assert!(layers[0].content.contains("Layer 0"));

        let layer_6 = layers
            .iter()
            .find(|layer| layer.layer_id == 6)
            .expect("layer 6 must exist");
        assert!(layer_6.is_mutable);
        assert!(layer_6.updated_by_turn.is_some());
        assert!(layer_6.version.is_some());
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
    fn inbox_messages_stay_pending_until_explicit_stage_call() {
        init_storage();
        post_inbox_message(
            "do not auto-stage".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )
        .expect("inbox message should post");

        let stats = inbox_stats();
        assert_eq!(stats.pending_count, 1);
        assert_eq!(stats.staged_count, 0);
        assert_eq!(stats.consumed_count, 0);
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
        append_conversation_entry(
            "0xAbCd00000000000000000000000000000000Ef12",
            ConversationEntry {
                inbox_message_id: "inbox:1".to_string(),
                sender_body: "hello".to_string(),
                agent_reply: "hi".to_string(),
                turn_id: "turn-1".to_string(),
                timestamp_ns: 1,
            },
        );

        let bounded = observability_snapshot(1);
        assert_eq!(bounded.inbox_messages.len(), 1);
        assert_eq!(bounded.recent_jobs.len(), 0);
        assert_eq!(bounded.prompt_layers.len(), 10);
        assert_eq!(bounded.conversation_summaries.len(), 1);
        assert!(
            bounded.cycles.total_cycles >= bounded.cycles.liquid_cycles,
            "total cycle balance should be at least liquid balance"
        );
        assert_eq!(
            bounded.cycles.freezing_threshold_cycles,
            bounded
                .cycles
                .total_cycles
                .saturating_sub(bounded.cycles.liquid_cycles)
        );
        assert_eq!(
            bounded.conversation_summaries[0].sender,
            "0xabcd00000000000000000000000000000000ef12"
        );
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
    fn derive_cycle_telemetry_uses_moving_window_and_ignores_topups() {
        let samples = vec![
            CycleBalanceSample {
                captured_at_ns: 0,
                total_cycles: 2_000,
                liquid_cycles: 1_000,
            },
            CycleBalanceSample {
                captured_at_ns: 10_000_000_000,
                total_cycles: 1_980,
                liquid_cycles: 980,
            },
            CycleBalanceSample {
                captured_at_ns: 20_000_000_000,
                total_cycles: 2_020,
                liquid_cycles: 1_020,
            },
            CycleBalanceSample {
                captured_at_ns: 30_000_000_000,
                total_cycles: 1_980,
                liquid_cycles: 980,
            },
        ];

        let telemetry = derive_cycle_telemetry(30_000_000_000, 1_980, 980, &samples);
        assert_eq!(telemetry.window_sample_count, 4);
        assert_eq!(telemetry.window_duration_seconds, 30);
        assert_eq!(telemetry.burn_rate_cycles_per_hour, Some(7_200));
        assert_eq!(telemetry.burn_rate_cycles_per_day, Some(172_800));
        assert_eq!(
            telemetry.estimated_seconds_until_freezing_threshold,
            Some(490)
        );
    }

    #[test]
    fn derive_cycle_telemetry_estimates_lifetime_to_freezing_threshold() {
        let samples = vec![
            CycleBalanceSample {
                captured_at_ns: 0,
                total_cycles: 3_000,
                liquid_cycles: 2_000,
            },
            CycleBalanceSample {
                captured_at_ns: 10_000_000_000,
                total_cycles: 2_900,
                liquid_cycles: 1_900,
            },
        ];

        let telemetry = derive_cycle_telemetry(20_000_000_000, 2_500, 1_800, &samples);
        assert_eq!(telemetry.freezing_threshold_cycles, 700);
        assert_eq!(
            telemetry.estimated_seconds_until_freezing_threshold,
            Some(180)
        );
        assert_eq!(telemetry.estimated_freeze_time_ns, Some(200_000_000_000));
    }

    #[test]
    fn observability_snapshot_uses_host_cycle_overrides() {
        init_storage();
        save_runtime_u128(HOST_TOTAL_CYCLES_OVERRIDE_KEY, 2_000_000_000_000);
        save_runtime_u128(HOST_LIQUID_CYCLES_OVERRIDE_KEY, 1_500_000_000_000);

        let snapshot = observability_snapshot(10);
        assert_eq!(snapshot.cycles.total_cycles, 2_000_000_000_000);
        assert_eq!(snapshot.cycles.liquid_cycles, 1_500_000_000_000);
        assert_eq!(snapshot.cycles.freezing_threshold_cycles, 500_000_000_000);
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

    #[test]
    fn conversation_append_and_get_normalizes_sender() {
        init_storage();
        clear_conversation_map();
        let mixed_case = "0xAbCd00000000000000000000000000000000Ef12";
        let expected_sender = mixed_case.to_ascii_lowercase();
        append_conversation_entry(
            mixed_case,
            ConversationEntry {
                inbox_message_id: "inbox:1".to_string(),
                sender_body: "hello".to_string(),
                agent_reply: "hi".to_string(),
                turn_id: "turn-1".to_string(),
                timestamp_ns: 1,
            },
        );

        let stored = get_conversation_log(&expected_sender)
            .expect("conversation log should be retrievable with normalized sender");
        assert_eq!(stored.sender, expected_sender);
        assert_eq!(stored.entries.len(), 1);
        assert_eq!(stored.entries[0].inbox_message_id, "inbox:1");
    }

    #[test]
    fn conversation_append_truncates_long_fields() {
        init_storage();
        clear_conversation_map();
        let sender = sender_for(1);
        append_conversation_entry(
            &sender,
            ConversationEntry {
                inbox_message_id: "inbox:trunc".to_string(),
                sender_body: "s".repeat(700),
                agent_reply: "r".repeat(900),
                turn_id: "turn-trunc".to_string(),
                timestamp_ns: 10,
            },
        );

        let stored = get_conversation_log(&sender).expect("conversation log should exist");
        assert_eq!(stored.entries.len(), 1);
        assert_eq!(stored.entries[0].sender_body.len(), 500);
        assert_eq!(stored.entries[0].agent_reply.len(), 500);
    }

    #[test]
    fn conversation_append_applies_fifo_eviction_per_sender() {
        init_storage();
        clear_conversation_map();
        let sender = sender_for(2);
        for idx in 0..25u64 {
            append_conversation_entry(
                &sender,
                ConversationEntry {
                    inbox_message_id: format!("inbox:{idx}"),
                    sender_body: format!("msg-{idx}"),
                    agent_reply: "reply".to_string(),
                    turn_id: format!("turn-{idx}"),
                    timestamp_ns: idx,
                },
            );
        }

        let stored = get_conversation_log(&sender).expect("conversation log should exist");
        assert_eq!(stored.entries.len(), 20);
        assert_eq!(stored.entries[0].inbox_message_id, "inbox:5");
        assert_eq!(stored.entries[19].inbox_message_id, "inbox:24");
        assert_eq!(stored.last_activity_ns, 24);
    }

    #[test]
    fn conversation_append_evicts_oldest_sender_when_capacity_exceeded() {
        init_storage();
        clear_conversation_map();

        for idx in 0..200u64 {
            let sender = sender_for(idx as usize);
            append_conversation_entry(
                &sender,
                ConversationEntry {
                    inbox_message_id: format!("inbox:{idx}"),
                    sender_body: "hello".to_string(),
                    agent_reply: "reply".to_string(),
                    turn_id: format!("turn-{idx}"),
                    timestamp_ns: idx,
                },
            );
        }

        let oldest_sender = sender_for(0);
        assert!(
            get_conversation_log(&oldest_sender).is_some(),
            "oldest sender should still exist at exact capacity"
        );

        let newest_sender = sender_for(200);
        append_conversation_entry(
            &newest_sender,
            ConversationEntry {
                inbox_message_id: "inbox:200".to_string(),
                sender_body: "hello".to_string(),
                agent_reply: "reply".to_string(),
                turn_id: "turn-200".to_string(),
                timestamp_ns: 200,
            },
        );

        assert!(
            get_conversation_log(&oldest_sender).is_none(),
            "least recently active sender should be evicted"
        );
        assert!(
            get_conversation_log(&newest_sender).is_some(),
            "newest sender should be retained"
        );
    }

    #[test]
    fn list_conversation_summaries_orders_by_last_activity_desc() {
        init_storage();
        clear_conversation_map();
        let sender_a = sender_for(10);
        let sender_b = sender_for(11);

        append_conversation_entry(
            &sender_a,
            ConversationEntry {
                inbox_message_id: "inbox:a".to_string(),
                sender_body: "hello".to_string(),
                agent_reply: "reply".to_string(),
                turn_id: "turn-a".to_string(),
                timestamp_ns: 10,
            },
        );
        append_conversation_entry(
            &sender_b,
            ConversationEntry {
                inbox_message_id: "inbox:b".to_string(),
                sender_body: "hello".to_string(),
                agent_reply: "reply".to_string(),
                turn_id: "turn-b".to_string(),
                timestamp_ns: 20,
            },
        );

        let summaries = list_conversation_summaries();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].sender, sender_b);
        assert_eq!(summaries[0].last_activity_ns, 20);
        assert_eq!(summaries[0].entry_count, 1);
        assert_eq!(summaries[1].sender, sender_a);
    }

    #[test]
    fn ecdsa_key_name_requires_non_empty_value() {
        init_storage();
        assert!(set_ecdsa_key_name("".to_string()).is_err());
        let stored = set_ecdsa_key_name("dfx_test_key".to_string())
            .expect("valid key name should be stored");
        assert_eq!(stored, "dfx_test_key");
        assert_eq!(get_ecdsa_key_name(), "dfx_test_key");
    }

    #[test]
    fn evm_address_validation_enforces_hex_format() {
        init_storage();
        assert!(set_evm_address(Some("bad".to_string())).is_err());

        let stored = set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("valid address should store");
        assert_eq!(
            stored.as_deref().unwrap_or_default(),
            "0x1111111111111111111111111111111111111111"
        );
        assert_eq!(
            get_evm_address().as_deref().unwrap_or_default(),
            "0x1111111111111111111111111111111111111111"
        );

        let route = evm_route_state_view();
        assert_eq!(
            route.automaton_address_topic.as_deref().unwrap_or_default(),
            "0x0000000000000000000000001111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn inbox_contract_address_validation_enforces_hex_format() {
        init_storage();
        assert!(set_inbox_contract_address(Some("bad".to_string())).is_err());

        let stored = set_inbox_contract_address(Some(
            "0x2222222222222222222222222222222222222222".to_string(),
        ))
        .expect("valid inbox contract address should store");
        assert_eq!(
            stored.as_deref().unwrap_or_default(),
            "0x2222222222222222222222222222222222222222"
        );

        let snapshot = runtime_snapshot();
        assert_eq!(
            snapshot
                .inbox_contract_address
                .as_deref()
                .unwrap_or_default(),
            "0x2222222222222222222222222222222222222222"
        );
        assert_eq!(
            snapshot
                .evm_cursor
                .contract_address
                .as_deref()
                .unwrap_or_default(),
            "0x2222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn evm_chain_id_validation_and_cursor_reset() {
        init_storage();
        assert!(set_evm_chain_id(0).is_err());

        set_evm_cursor(&EvmPollCursor {
            chain_id: 8453,
            next_block: 123,
            next_log_index: 7,
            last_poll_at_ns: 55,
            consecutive_empty_polls: 4,
            ..EvmPollCursor::default()
        });
        let stored = set_evm_chain_id(84532).expect("valid chain id should store");
        assert_eq!(stored, 84532);

        let snapshot = runtime_snapshot();
        assert_eq!(snapshot.evm_cursor.chain_id, 84532);
        assert_eq!(snapshot.evm_cursor.next_block, 0);
        assert_eq!(snapshot.evm_cursor.next_log_index, 0);
        assert_eq!(snapshot.evm_cursor.last_poll_at_ns, 0);
        assert_eq!(snapshot.evm_cursor.consecutive_empty_polls, 0);
    }

    #[test]
    fn evm_route_state_view_reports_binding_and_cursor() {
        init_storage();
        set_automaton_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("automaton address should store");
        set_inbox_contract_address(Some(
            "0x2222222222222222222222222222222222222222".to_string(),
        ))
        .expect("inbox contract should store");
        set_evm_chain_id(84532).expect("chain id should store");
        set_evm_confirmation_depth(12).expect("confirmation depth should store");
        set_evm_cursor(&EvmPollCursor {
            chain_id: 84532,
            next_block: 123,
            next_log_index: 7,
            confirmation_depth: 12,
            last_poll_at_ns: 9,
            consecutive_empty_polls: 2,
            ..EvmPollCursor::default()
        });

        let route = evm_route_state_view();
        assert_eq!(route.chain_id, 84532);
        assert_eq!(
            route.automaton_evm_address.as_deref().unwrap_or_default(),
            "0x1111111111111111111111111111111111111111"
        );
        assert_eq!(
            route.inbox_contract_address.as_deref().unwrap_or_default(),
            "0x2222222222222222222222222222222222222222"
        );
        assert_eq!(
            route.automaton_address_topic.as_deref().unwrap_or_default(),
            "0x0000000000000000000000001111111111111111111111111111111111111111"
        );
        assert_eq!(route.next_block, 123);
        assert_eq!(route.next_log_index, 7);
        assert_eq!(route.confirmation_depth, 12);
        assert_eq!(route.last_poll_at_ns, 9);
        assert_eq!(route.consecutive_empty_polls, 2);
    }

    #[test]
    fn evm_confirmation_depth_validation_enforces_upper_bound() {
        init_storage();
        assert!(set_evm_confirmation_depth(MAX_EVM_CONFIRMATION_DEPTH + 1).is_err());
        let stored =
            set_evm_confirmation_depth(MAX_EVM_CONFIRMATION_DEPTH).expect("depth should store");
        assert_eq!(stored, MAX_EVM_CONFIRMATION_DEPTH);
    }

    #[test]
    fn evm_ingest_idempotency_key_dedupes_tx_hash_and_log_index() {
        init_storage();
        let tx_hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(try_mark_evm_event_ingested(tx_hash, 7));
        assert!(
            !try_mark_evm_event_ingested(tx_hash, 7),
            "same (tx_hash, log_index) must dedupe"
        );
        assert!(
            try_mark_evm_event_ingested(tx_hash, 8),
            "different log_index must be independent"
        );
    }

    #[test]
    fn evm_rpc_config_validates_and_persists() {
        init_storage();

        assert!(set_evm_rpc_url("".to_string()).is_err());
        assert!(set_evm_rpc_url("http://example.com".to_string()).is_err());
        assert!(set_evm_rpc_max_response_bytes(0).is_err());

        let primary = set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("primary rpc should accept https");
        let fallback = set_evm_rpc_fallback_url(Some("https://base.publicnode.com".to_string()))
            .expect("fallback should accept https");
        let max_response =
            set_evm_rpc_max_response_bytes(65_536).expect("max response bytes should persist");

        assert_eq!(primary, "https://mainnet.base.org");
        assert_eq!(
            fallback.as_deref().unwrap_or_default(),
            "https://base.publicnode.com"
        );
        assert_eq!(max_response, 65_536);

        let snapshot = runtime_snapshot();
        assert_eq!(snapshot.evm_rpc_url, "https://mainnet.base.org");
        assert_eq!(
            snapshot.evm_rpc_fallback_url.as_deref().unwrap_or_default(),
            "https://base.publicnode.com"
        );
        assert_eq!(snapshot.evm_rpc_max_response_bytes, 65_536);
    }

    #[test]
    fn runtime_snapshot_uses_mainnet_base_as_default_evm_rpc_url() {
        init_storage();
        let snapshot = runtime_snapshot();
        assert_eq!(snapshot.evm_rpc_url, "https://mainnet.base.org");
    }

    #[test]
    fn runtime_snapshot_migration_defaults_wallet_balance_fields() {
        init_storage();
        let mut legacy = serde_json::to_value(RuntimeSnapshot::default())
            .expect("runtime snapshot should serialize");
        let legacy_obj = legacy
            .as_object_mut()
            .expect("runtime snapshot json should be an object");
        legacy_obj.remove("wallet_balance");
        legacy_obj.remove("wallet_balance_sync");
        legacy_obj.remove("wallet_balance_bootstrap_pending");
        let payload = serde_json::to_vec(&legacy).expect("legacy json should serialize");

        RUNTIME_MAP.with(|map| {
            map.borrow_mut().insert(RUNTIME_KEY.to_string(), payload);
        });

        let loaded = runtime_snapshot();
        assert_eq!(loaded.wallet_balance.usdc_decimals, 6);
        assert_eq!(loaded.wallet_balance_sync.normal_interval_secs, 300);
        assert_eq!(loaded.wallet_balance_sync.low_cycles_interval_secs, 900);
        assert_eq!(loaded.wallet_balance_sync.freshness_window_secs, 600);
        assert_eq!(loaded.wallet_balance_sync.max_response_bytes, 256);
        assert!(loaded.wallet_balance_bootstrap_pending);
    }

    #[test]
    fn wallet_balance_sync_config_validates_and_persists() {
        init_storage();
        assert!(set_wallet_balance_sync_config(WalletBalanceSyncConfig {
            normal_interval_secs: 29,
            ..WalletBalanceSyncConfig::default()
        })
        .is_err());
        assert!(set_wallet_balance_sync_config(WalletBalanceSyncConfig {
            low_cycles_interval_secs: 299,
            normal_interval_secs: 300,
            ..WalletBalanceSyncConfig::default()
        })
        .is_err());
        assert!(set_wallet_balance_sync_config(WalletBalanceSyncConfig {
            max_response_bytes: 128,
            ..WalletBalanceSyncConfig::default()
        })
        .is_err());
        assert!(set_wallet_balance_sync_config(WalletBalanceSyncConfig {
            freshness_window_secs: 10,
            ..WalletBalanceSyncConfig::default()
        })
        .is_err());

        let expected = WalletBalanceSyncConfig {
            enabled: false,
            normal_interval_secs: 600,
            low_cycles_interval_secs: 1200,
            freshness_window_secs: 1800,
            max_response_bytes: 512,
            discover_usdc_via_inbox: false,
        };
        let stored = set_wallet_balance_sync_config(expected.clone())
            .expect("wallet balance sync config should persist");
        assert_eq!(stored, expected);
        assert_eq!(wallet_balance_sync_config(), expected);
    }

    #[test]
    fn wallet_balance_snapshot_and_bootstrap_flag_persist() {
        init_storage();
        let expected = WalletBalanceSnapshot {
            eth_balance_wei_hex: Some("0x123".to_string()),
            usdc_balance_raw_hex: Some("0x456".to_string()),
            usdc_decimals: 6,
            usdc_contract_address: Some("0x3333333333333333333333333333333333333333".to_string()),
            last_synced_at_ns: Some(42),
            last_synced_block: Some(7),
            last_error: Some("rpc timeout".to_string()),
        };
        set_wallet_balance_snapshot(expected.clone());
        assert_eq!(wallet_balance_snapshot(), expected);

        set_wallet_balance_bootstrap_pending(false);
        assert!(!wallet_balance_bootstrap_pending());
    }

    #[test]
    fn init_storage_rearms_wallet_balance_bootstrap_pending() {
        init_storage();
        set_wallet_balance_bootstrap_pending(false);
        assert!(!wallet_balance_bootstrap_pending());

        init_storage();
        assert!(wallet_balance_bootstrap_pending());
    }

    #[test]
    fn wallet_balance_sync_record_helpers_preserve_existing_fields() {
        init_storage();
        set_wallet_balance_snapshot(WalletBalanceSnapshot {
            eth_balance_wei_hex: Some("0xaaaa".to_string()),
            usdc_balance_raw_hex: Some("0xbbbb".to_string()),
            usdc_decimals: 6,
            usdc_contract_address: Some("0x1111111111111111111111111111111111111111".to_string()),
            last_synced_at_ns: Some(100),
            last_synced_block: Some(10),
            last_error: None,
        });

        let failed = record_wallet_balance_sync_error("rpc timeout".to_string());
        assert_eq!(failed.eth_balance_wei_hex.as_deref(), Some("0xaaaa"));
        assert_eq!(failed.usdc_balance_raw_hex.as_deref(), Some("0xbbbb"));
        assert_eq!(failed.last_synced_at_ns, Some(100));
        assert_eq!(failed.last_synced_block, Some(10));
        assert_eq!(failed.last_error.as_deref(), Some("rpc timeout"));
        assert!(wallet_balance_bootstrap_pending());

        let succeeded = record_wallet_balance_sync_success(
            500,
            "0x1".to_string(),
            "0x2a".to_string(),
            "0x3333333333333333333333333333333333333333".to_string(),
        );
        assert_eq!(succeeded.eth_balance_wei_hex.as_deref(), Some("0x1"));
        assert_eq!(succeeded.usdc_balance_raw_hex.as_deref(), Some("0x2a"));
        assert_eq!(
            succeeded.usdc_contract_address.as_deref(),
            Some("0x3333333333333333333333333333333333333333")
        );
        assert_eq!(succeeded.last_synced_at_ns, Some(500));
        assert_eq!(succeeded.last_synced_block, None);
        assert_eq!(succeeded.last_error, None);
        assert!(!wallet_balance_bootstrap_pending());
    }

    #[test]
    fn memory_fact_store_list_prefix_and_delete() {
        init_storage();
        let first = MemoryFact {
            key: "strategy.primary".to_string(),
            value: "hold".to_string(),
            created_at_ns: 10,
            updated_at_ns: 10,
            source_turn_id: "turn-1".to_string(),
        };
        let second = MemoryFact {
            key: "balance.eth".to_string(),
            value: "42".to_string(),
            created_at_ns: 20,
            updated_at_ns: 20,
            source_turn_id: "turn-2".to_string(),
        };

        set_memory_fact(&first);
        set_memory_fact(&second);

        assert_eq!(memory_fact_count(), 2);
        assert_eq!(
            get_memory_fact("strategy.primary")
                .as_ref()
                .map(|fact| fact.value.as_str())
                .unwrap_or_default(),
            "hold"
        );

        let prefix = list_memory_facts_by_prefix("balance.", 10);
        assert_eq!(prefix.len(), 1);
        assert_eq!(prefix[0].key, "balance.eth");

        let all = list_all_memory_facts(10);
        assert_eq!(all.len(), 2);
        assert_eq!(
            all[0].key, "balance.eth",
            "facts should be returned in descending updated_at order"
        );

        assert!(remove_memory_fact("strategy.primary"));
        assert!(!remove_memory_fact("strategy.primary"));
        assert_eq!(memory_fact_count(), 1);
    }

    #[test]
    fn http_domain_allowlist_set_add_remove_and_list() {
        init_storage();

        let stored = set_http_allowed_domains(vec![
            "api.coingecko.com".to_string(),
            " API.COINBASE.COM ".to_string(),
        ])
        .expect("allowlist should be configurable");
        assert_eq!(stored, vec!["api.coinbase.com", "api.coingecko.com"]);

        let added =
            add_http_allowed_domain("basescan.org".to_string()).expect("single add should succeed");
        assert_eq!(added, "basescan.org");
        assert!(list_allowed_http_domains().contains(&"basescan.org".to_string()));

        let removed = remove_http_allowed_domain("basescan.org".to_string())
            .expect("single remove should succeed");
        assert!(removed);

        assert!(set_http_allowed_domains(vec!["https://example.com".to_string()]).is_err());
    }
}
