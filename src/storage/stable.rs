use crate::domain::types::{
    AbiArtifact, AbiArtifactKey, AgentEvent, AgentState, ConversationEntry, ConversationLog,
    ConversationSummary, CycleTelemetry, EvmPollCursor, EvmRouteStateView, InboxMessage,
    InboxMessageStatus, InboxStats, InferenceConfigView, InferenceProvider, JobStatus, MemoryFact,
    MemoryRollup, ObservabilitySnapshot, OutboxMessage, OutboxStats, PromptLayer, PromptLayerView,
    RetentionConfig, RetentionMaintenanceRuntime, RuntimeSnapshot, RuntimeView, ScheduledJob,
    SchedulerLease, SchedulerRuntime, SessionSummary, SkillRecord, StorageGrowthMetrics,
    StoragePressureLevel, StrategyKillSwitchState, StrategyOutcomeEvent, StrategyOutcomeKind,
    StrategyOutcomeStats, StrategyTemplate, StrategyTemplateKey, SurvivalOperationClass,
    SurvivalTier, TaskKind, TaskLane, TaskScheduleConfig, TaskScheduleRuntime,
    TemplateActivationState, TemplateRevocationState, TemplateVersion, ToolCallRecord,
    TransitionLogRecord, TurnRecord, TurnWindowSummary, WalletBalanceSnapshot,
    WalletBalanceSyncConfig, WalletBalanceSyncConfigView, WalletBalanceTelemetryView,
};
use crate::features::cycle_topup::TopUpStage;
use crate::prompt;
use candid::Principal;
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{Digest, Keccak256};
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
const STORAGE_GROWTH_SAMPLES_KEY: &str = "storage.growth.samples";
const RETENTION_CONFIG_KEY: &str = "retention.config";
const RETENTION_RUNTIME_KEY: &str = "retention.runtime";
const TOPUP_STATE_KEY: &str = "cycle_topup.state";
const MAX_RECENT_JOBS: usize = 200;
const DEFAULT_OBSERVABILITY_LIMIT: usize = 25;
const MAX_OBSERVABILITY_LIMIT: usize = 100;
const CYCLES_BURN_MOVING_WINDOW_SECONDS: u64 = 15 * 60;
const CYCLES_BURN_MOVING_WINDOW_NS: u64 = CYCLES_BURN_MOVING_WINDOW_SECONDS * 1_000_000_000;
const CYCLES_BURN_MAX_SAMPLES: usize = 450;
const STORAGE_GROWTH_TREND_WINDOW_SECONDS: u64 = 6 * 60 * 60;
const STORAGE_GROWTH_TREND_WINDOW_NS: u64 = STORAGE_GROWTH_TREND_WINDOW_SECONDS * 1_000_000_000;
const STORAGE_GROWTH_MAX_SAMPLES: usize = 360;
const STORAGE_PRESSURE_ELEVATED_PERCENT: u8 = 70;
const STORAGE_PRESSURE_HIGH_PERCENT: u8 = 85;
const STORAGE_PRESSURE_CRITICAL_PERCENT: u8 = 95;
const STORAGE_GROWTH_WARNING_ENTRIES_PER_HOUR: i64 = 5_000;
const CYCLES_USD_PER_TRILLION_ESTIMATE: f64 = 1.35;
const MAX_CONVERSATION_ENTRIES_PER_SENDER: usize = 20;
const MAX_CONVERSATION_SENDERS: usize = 200;
const MAX_CONVERSATION_BODY_CHARS: usize = 500;
const MAX_CONVERSATION_REPLY_CHARS: usize = 500;
const MAX_EVM_CONFIRMATION_DEPTH: u64 = 100;
pub const MAX_MEMORY_FACTS: usize = 500;
pub const MAX_INBOX_BODY_CHARS: usize = 4_096;
const MAX_TURN_INNER_DIALOGUE_CHARS: usize = 12_000;
const MAX_TOOL_ARGS_JSON_CHARS: usize = 4_000;
const MAX_TOOL_OUTPUT_CHARS: usize = 8_000;
const MIN_RETENTION_BATCH_SIZE: u32 = 1;
const MAX_RETENTION_BATCH_SIZE: u32 = 1_000;
const MIN_RETENTION_INTERVAL_SECS: u64 = 1;
const SUMMARY_WINDOW_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const MEMORY_ROLLUP_STALE_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const MAX_SESSION_SUMMARIES: usize = 2_000;
const MAX_TURN_WINDOW_SUMMARIES: usize = 1_000;
const MAX_MEMORY_ROLLUPS: usize = 128;
const MAX_TURN_SUMMARY_ERRORS: usize = 5;
const MAX_MEMORY_ROLLUP_SOURCE_KEYS: usize = 10;
const MAX_MEMORY_ROLLUP_FACTS_PER_NAMESPACE: usize = 5;
#[cfg(test)]
const MAX_FIELD_TRUNCATION_MARKER_RESERVE_CHARS: usize = 120;
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
const MIN_WALLET_BALANCE_SYNC_INTERVAL_SECS: u64 = 60;
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StorageGrowthSample {
    captured_at_ns: u64,
    tracked_entries: u64,
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
    static RETENTION_RUNTIME_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(20)))
    ));
    static SESSION_SUMMARY_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(21)))
    ));
    static TURN_WINDOW_SUMMARY_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(22)))
    ));
    static MEMORY_ROLLUP_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(23)))
    ));
    static TOPUP_STATE_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(24)))
    ));
    static STRATEGY_TEMPLATE_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(25)))
    ));
    static STRATEGY_TEMPLATE_INDEX_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(26)))
    ));
    static ABI_ARTIFACT_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(27)))
    ));
    static ABI_ARTIFACT_INDEX_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(28)))
    ));
    static STRATEGY_ACTIVATION_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(29)))
    ));
    static STRATEGY_REVOCATION_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(30)))
    ));
    static STRATEGY_KILL_SWITCH_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(31)))
    ));
    static STRATEGY_OUTCOME_STATS_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(32)))
    ));
    static STRATEGY_BUDGET_MAP: RefCell<
        StableBTreeMap<String, Vec<u8>, VirtualMemory<DefaultMemoryImpl>>,
    > = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(33)))
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
    if runtime_bool(HTTP_ALLOWLIST_INITIALIZED_KEY).is_none() {
        save_runtime_bool(HTTP_ALLOWLIST_INITIALIZED_KEY, false);
    }
    init_scheduler_defaults(now_ns());
    init_retention_defaults(now_ns());
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

fn init_retention_defaults(now_ns: u64) {
    if RETENTION_RUNTIME_MAP
        .with(|map| map.borrow().get(&RETENTION_CONFIG_KEY.to_string()))
        .is_none()
    {
        RETENTION_RUNTIME_MAP.with(|map| {
            map.borrow_mut().insert(
                RETENTION_CONFIG_KEY.to_string(),
                encode_json(&RetentionConfig::default()),
            );
        });
    }

    if RETENTION_RUNTIME_MAP
        .with(|map| map.borrow().get(&RETENTION_RUNTIME_KEY.to_string()))
        .is_none()
    {
        RETENTION_RUNTIME_MAP.with(|map| {
            map.borrow_mut().insert(
                RETENTION_RUNTIME_KEY.to_string(),
                encode_json(&RetentionMaintenanceRuntime {
                    next_run_after_ns: now_ns,
                    ..RetentionMaintenanceRuntime::default()
                }),
            );
        });
    }
}

pub fn retention_config() -> RetentionConfig {
    RETENTION_RUNTIME_MAP
        .with(|map| map.borrow().get(&RETENTION_CONFIG_KEY.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
        .unwrap_or_default()
}

pub fn set_retention_config(config: RetentionConfig) -> Result<RetentionConfig, String> {
    if !(MIN_RETENTION_BATCH_SIZE..=MAX_RETENTION_BATCH_SIZE)
        .contains(&config.maintenance_batch_size)
    {
        return Err(format!(
            "maintenance_batch_size must be in range {}..={}",
            MIN_RETENTION_BATCH_SIZE, MAX_RETENTION_BATCH_SIZE
        ));
    }
    if config.maintenance_interval_secs < MIN_RETENTION_INTERVAL_SECS {
        return Err(format!(
            "maintenance_interval_secs must be at least {}",
            MIN_RETENTION_INTERVAL_SECS
        ));
    }

    RETENTION_RUNTIME_MAP.with(|map| {
        map.borrow_mut()
            .insert(RETENTION_CONFIG_KEY.to_string(), encode_json(&config));
    });
    Ok(config)
}

pub fn retention_maintenance_runtime() -> RetentionMaintenanceRuntime {
    RETENTION_RUNTIME_MAP
        .with(|map| map.borrow().get(&RETENTION_RUNTIME_KEY.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
        .unwrap_or_default()
}

fn save_retention_maintenance_runtime(runtime: &RetentionMaintenanceRuntime) {
    RETENTION_RUNTIME_MAP.with(|map| {
        map.borrow_mut()
            .insert(RETENTION_RUNTIME_KEY.to_string(), encode_json(runtime));
    });
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionPruneStats {
    pub deleted_jobs: u32,
    pub deleted_dedupe: u32,
    pub deleted_inbox: u32,
    pub deleted_outbox: u32,
    pub deleted_turns: u32,
    pub deleted_transitions: u32,
    pub deleted_tools: u32,
    pub generated_session_summaries: u32,
    pub generated_turn_window_summaries: u32,
    pub generated_memory_rollups: u32,
}

#[derive(Clone, Debug)]
struct SessionSummaryAccumulator {
    sender: String,
    window_start_ns: u64,
    window_end_ns: u64,
    source_count: u32,
    inbox_message_count: u32,
    outbox_message_count: u32,
    inbox_preview: String,
    outbox_preview: String,
}

#[derive(Clone, Debug)]
struct TurnSummaryAccumulator {
    window_start_ns: u64,
    window_end_ns: u64,
    source_count: u32,
    turn_count: u32,
    transition_count: u32,
    tool_call_count: u32,
    succeeded_turn_count: u32,
    failed_turn_count: u32,
    tool_success_count: u32,
    tool_failure_count: u32,
    top_errors: Vec<String>,
}

#[derive(Clone, Debug)]
struct InboxCandidate {
    key: String,
    message: InboxMessage,
}

#[derive(Clone, Debug)]
struct OutboxCandidate {
    key: String,
    message: OutboxMessage,
}

#[derive(Clone, Debug)]
struct TurnCandidate {
    key: String,
    turn: TurnRecord,
}

#[derive(Clone, Debug)]
struct TransitionCandidate {
    key: String,
    transition: TransitionLogRecord,
}

pub fn run_retention_maintenance_if_due(now_ns: u64) -> Option<RetentionPruneStats> {
    let runtime = retention_maintenance_runtime();
    if runtime.next_run_after_ns > now_ns {
        return None;
    }
    Some(run_retention_maintenance_once(now_ns))
}

pub fn run_retention_maintenance_once(now_ns: u64) -> RetentionPruneStats {
    let config = retention_config();
    let mut runtime = retention_maintenance_runtime();
    runtime.last_started_ns = Some(now_ns);
    runtime.last_finished_ns = None;
    runtime.last_error = None;
    save_retention_maintenance_runtime(&runtime);

    let keep_from_seq = oldest_job_seq_to_keep(config.jobs_max_records);
    let jobs_budget = usize::try_from(config.maintenance_batch_size).unwrap_or(usize::MAX);
    let jobs_cutoff_ns =
        now_ns.saturating_sub(config.jobs_max_age_secs.saturating_mul(1_000_000_000));
    let dedupe_cutoff_ns =
        now_ns.saturating_sub(config.dedupe_max_age_secs.saturating_mul(1_000_000_000));
    let inbox_cutoff_ns =
        now_ns.saturating_sub(config.inbox_max_age_secs.saturating_mul(1_000_000_000));
    let outbox_cutoff_ns =
        now_ns.saturating_sub(config.outbox_max_age_secs.saturating_mul(1_000_000_000));
    let turns_cutoff_ns =
        now_ns.saturating_sub(config.turns_max_age_secs.saturating_mul(1_000_000_000));
    let transitions_cutoff_ns = now_ns.saturating_sub(
        config
            .transitions_max_age_secs
            .saturating_mul(1_000_000_000),
    );
    let tools_cutoff_ns =
        now_ns.saturating_sub(config.tools_max_age_secs.saturating_mul(1_000_000_000));
    let protected_inbox_ids = protected_conversation_inbox_ids();

    let (job_candidates, next_job_cursor, jobs_reached_end) = collect_prunable_jobs(
        runtime.job_scan_cursor.as_deref(),
        jobs_budget,
        jobs_cutoff_ns,
        keep_from_seq,
        config.jobs_max_records,
    );
    let deleted_jobs = delete_job_candidates(&job_candidates);

    let (dedupe_candidates, next_dedupe_cursor, dedupe_reached_end) = collect_prunable_dedupe(
        runtime.dedupe_scan_cursor.as_deref(),
        jobs_budget,
        dedupe_cutoff_ns,
    );
    let deleted_dedupe = delete_dedupe_candidates(&dedupe_candidates);

    let (inbox_candidates, next_inbox_cursor, inbox_reached_end) = collect_prunable_inbox(
        runtime.inbox_scan_cursor.as_deref(),
        jobs_budget,
        inbox_cutoff_ns,
        &protected_inbox_ids,
    );
    let (outbox_candidates, next_outbox_cursor, outbox_reached_end) = collect_prunable_outbox(
        runtime.outbox_scan_cursor.as_deref(),
        jobs_budget,
        outbox_cutoff_ns,
        &protected_inbox_ids,
    );

    let generated_session_summaries =
        summarize_inbox_outbox_candidates(&inbox_candidates, &outbox_candidates, now_ns);
    let deleted_inbox = delete_inbox_candidates(&inbox_candidates);
    let deleted_outbox = delete_outbox_candidates(&outbox_candidates);

    let (turn_candidates, next_turn_cursor, turn_reached_end) = collect_prunable_turns(
        runtime.turn_scan_cursor.as_deref(),
        jobs_budget,
        turns_cutoff_ns,
    );
    let (transition_candidates, next_transition_cursor, transition_reached_end) =
        collect_prunable_transitions(
            runtime.transition_scan_cursor.as_deref(),
            jobs_budget,
            transitions_cutoff_ns,
        );

    let (generated_turn_window_summaries, generated_tools_to_delete) =
        summarize_turn_and_transition_candidates(
            &turn_candidates,
            &transition_candidates,
            tools_cutoff_ns,
            now_ns,
        );
    let deleted_turns = delete_turn_candidates(&turn_candidates);
    let deleted_transitions = delete_transition_candidates(&transition_candidates);
    let deleted_tools = delete_tool_candidates(&generated_tools_to_delete);

    let generated_memory_rollups = update_memory_rollups(now_ns);

    runtime.job_scan_cursor = if jobs_reached_end {
        None
    } else {
        next_job_cursor
    };
    runtime.dedupe_scan_cursor = if dedupe_reached_end {
        None
    } else {
        next_dedupe_cursor
    };
    runtime.inbox_scan_cursor = if inbox_reached_end {
        None
    } else {
        next_inbox_cursor
    };
    runtime.outbox_scan_cursor = if outbox_reached_end {
        None
    } else {
        next_outbox_cursor
    };
    runtime.turn_scan_cursor = if turn_reached_end {
        None
    } else {
        next_turn_cursor
    };
    runtime.transition_scan_cursor = if transition_reached_end {
        None
    } else {
        next_transition_cursor
    };
    runtime.last_deleted_jobs = deleted_jobs;
    runtime.last_deleted_dedupe = deleted_dedupe;
    runtime.last_deleted_inbox = deleted_inbox;
    runtime.last_deleted_outbox = deleted_outbox;
    runtime.last_deleted_turns = deleted_turns;
    runtime.last_deleted_transitions = deleted_transitions;
    runtime.last_deleted_tools = deleted_tools;
    runtime.last_generated_session_summaries = generated_session_summaries;
    runtime.last_generated_turn_window_summaries = generated_turn_window_summaries;
    runtime.last_generated_memory_rollups = generated_memory_rollups;
    runtime.last_finished_ns = Some(now_ns);
    runtime.next_run_after_ns = now_ns.saturating_add(
        config
            .maintenance_interval_secs
            .saturating_mul(1_000_000_000),
    );
    runtime.retention_progress_percent = retention_progress_percent(&runtime);
    runtime.summarization_progress_percent = summarization_progress_percent(&runtime);
    save_retention_maintenance_runtime(&runtime);

    RetentionPruneStats {
        deleted_jobs,
        deleted_dedupe,
        deleted_inbox,
        deleted_outbox,
        deleted_turns,
        deleted_transitions,
        deleted_tools,
        generated_session_summaries,
        generated_turn_window_summaries,
        generated_memory_rollups,
    }
}

fn retention_progress_percent(runtime: &RetentionMaintenanceRuntime) -> u8 {
    if runtime.job_scan_cursor.is_none() && runtime.dedupe_scan_cursor.is_none() {
        return 100;
    }
    if runtime.last_deleted_jobs > 0 || runtime.last_deleted_dedupe > 0 {
        return 50;
    }
    0
}

fn summarization_progress_percent(runtime: &RetentionMaintenanceRuntime) -> u8 {
    if runtime.inbox_scan_cursor.is_none()
        && runtime.outbox_scan_cursor.is_none()
        && runtime.turn_scan_cursor.is_none()
        && runtime.transition_scan_cursor.is_none()
    {
        return 100;
    }
    if runtime.last_deleted_inbox > 0
        || runtime.last_deleted_outbox > 0
        || runtime.last_deleted_turns > 0
        || runtime.last_deleted_transitions > 0
        || runtime.last_deleted_tools > 0
        || runtime.last_generated_session_summaries > 0
        || runtime.last_generated_turn_window_summaries > 0
        || runtime.last_generated_memory_rollups > 0
    {
        return 50;
    }
    0
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

fn summary_window_start_ns(timestamp_ns: u64) -> u64 {
    timestamp_ns.saturating_sub(timestamp_ns % SUMMARY_WINDOW_NS)
}

fn session_summary_key(sender: &str, window_start_ns: u64) -> String {
    format!(
        "session:{window_start_ns:020}:{}",
        normalize_conversation_sender(sender)
    )
}

fn turn_window_summary_key(window_start_ns: u64) -> String {
    format!("turn-window:{window_start_ns:020}")
}

fn accumulate_error(errors: &mut Vec<String>, error: Option<&str>) {
    let Some(error) = error else {
        return;
    };
    let normalized = error.trim();
    if normalized.is_empty() {
        return;
    }
    if errors.iter().any(|existing| existing == normalized) {
        return;
    }
    if errors.len() >= MAX_TURN_SUMMARY_ERRORS {
        return;
    }
    errors.push(normalized.to_string());
}

fn merge_top_errors(left: &mut Vec<String>, right: &[String]) {
    for error in right {
        accumulate_error(left, Some(error.as_str()));
        if left.len() >= MAX_TURN_SUMMARY_ERRORS {
            break;
        }
    }
}

fn upsert_session_summary(acc: SessionSummaryAccumulator, now_ns: u64) {
    let key = session_summary_key(&acc.sender, acc.window_start_ns);
    let mut merged = SESSION_SUMMARY_MAP
        .with(|map| map.borrow().get(&key))
        .and_then(|payload| read_json::<SessionSummary>(Some(payload.as_slice())))
        .unwrap_or(SessionSummary {
            sender: acc.sender.clone(),
            window_start_ns: acc.window_start_ns,
            window_end_ns: acc.window_end_ns,
            source_count: 0,
            inbox_message_count: 0,
            outbox_message_count: 0,
            inbox_preview: String::new(),
            outbox_preview: String::new(),
            generated_at_ns: now_ns,
        });

    merged.window_end_ns = merged.window_end_ns.max(acc.window_end_ns);
    merged.source_count = merged.source_count.saturating_add(acc.source_count);
    merged.inbox_message_count = merged
        .inbox_message_count
        .saturating_add(acc.inbox_message_count);
    merged.outbox_message_count = merged
        .outbox_message_count
        .saturating_add(acc.outbox_message_count);
    if !acc.inbox_preview.is_empty() {
        merged.inbox_preview = acc.inbox_preview;
    }
    if !acc.outbox_preview.is_empty() {
        merged.outbox_preview = acc.outbox_preview;
    }
    merged.generated_at_ns = now_ns;

    SESSION_SUMMARY_MAP.with(|map| {
        map.borrow_mut().insert(key, encode_json(&merged));
    });
    enforce_session_summary_cap();
}

fn upsert_turn_window_summary(acc: TurnSummaryAccumulator, now_ns: u64) {
    let key = turn_window_summary_key(acc.window_start_ns);
    let mut merged = TURN_WINDOW_SUMMARY_MAP
        .with(|map| map.borrow().get(&key))
        .and_then(|payload| read_json::<TurnWindowSummary>(Some(payload.as_slice())))
        .unwrap_or(TurnWindowSummary {
            window_start_ns: acc.window_start_ns,
            window_end_ns: acc.window_end_ns,
            source_count: 0,
            turn_count: 0,
            transition_count: 0,
            tool_call_count: 0,
            succeeded_turn_count: 0,
            failed_turn_count: 0,
            tool_success_count: 0,
            tool_failure_count: 0,
            top_errors: Vec::new(),
            generated_at_ns: now_ns,
        });

    merged.window_end_ns = merged.window_end_ns.max(acc.window_end_ns);
    merged.source_count = merged.source_count.saturating_add(acc.source_count);
    merged.turn_count = merged.turn_count.saturating_add(acc.turn_count);
    merged.transition_count = merged.transition_count.saturating_add(acc.transition_count);
    merged.tool_call_count = merged.tool_call_count.saturating_add(acc.tool_call_count);
    merged.succeeded_turn_count = merged
        .succeeded_turn_count
        .saturating_add(acc.succeeded_turn_count);
    merged.failed_turn_count = merged
        .failed_turn_count
        .saturating_add(acc.failed_turn_count);
    merged.tool_success_count = merged
        .tool_success_count
        .saturating_add(acc.tool_success_count);
    merged.tool_failure_count = merged
        .tool_failure_count
        .saturating_add(acc.tool_failure_count);
    merge_top_errors(&mut merged.top_errors, &acc.top_errors);
    merged.generated_at_ns = now_ns;

    TURN_WINDOW_SUMMARY_MAP.with(|map| {
        map.borrow_mut().insert(key, encode_json(&merged));
    });
    enforce_turn_window_summary_cap();
}

fn enforce_session_summary_cap() {
    let current_len = SESSION_SUMMARY_MAP.with(|map| map.borrow().len() as usize);
    if current_len <= MAX_SESSION_SUMMARIES {
        return;
    }
    let remove_count = current_len.saturating_sub(MAX_SESSION_SUMMARIES);
    let keys = SESSION_SUMMARY_MAP.with(|map| {
        map.borrow()
            .iter()
            .take(remove_count)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>()
    });
    SESSION_SUMMARY_MAP.with(|map| {
        let mut summaries = map.borrow_mut();
        for key in keys {
            summaries.remove(&key);
        }
    });
}

fn enforce_turn_window_summary_cap() {
    let current_len = TURN_WINDOW_SUMMARY_MAP.with(|map| map.borrow().len() as usize);
    if current_len <= MAX_TURN_WINDOW_SUMMARIES {
        return;
    }
    let remove_count = current_len.saturating_sub(MAX_TURN_WINDOW_SUMMARIES);
    let keys = TURN_WINDOW_SUMMARY_MAP.with(|map| {
        map.borrow()
            .iter()
            .take(remove_count)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>()
    });
    TURN_WINDOW_SUMMARY_MAP.with(|map| {
        let mut summaries = map.borrow_mut();
        for key in keys {
            summaries.remove(&key);
        }
    });
}

fn enforce_memory_rollup_cap() {
    let len = MEMORY_ROLLUP_MAP.with(|map| map.borrow().len() as usize);
    if len <= MAX_MEMORY_ROLLUPS {
        return;
    }

    let mut rollups = MEMORY_ROLLUP_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| {
                read_json::<MemoryRollup>(Some(entry.value().as_slice()))
                    .map(|rollup| (entry.key().clone(), rollup.generated_at_ns))
            })
            .collect::<Vec<_>>()
    });
    rollups.sort_by_key(|(_key, generated_at_ns)| *generated_at_ns);
    let remove_count = len.saturating_sub(MAX_MEMORY_ROLLUPS);
    let keys = rollups
        .into_iter()
        .take(remove_count)
        .map(|(key, _)| key)
        .collect::<Vec<_>>();

    MEMORY_ROLLUP_MAP.with(|map| {
        let mut rollup_map = map.borrow_mut();
        for key in keys {
            rollup_map.remove(&key);
        }
    });
}

pub fn list_session_summaries(limit: usize) -> Vec<SessionSummary> {
    if limit == 0 {
        return Vec::new();
    }
    let keep = limit.min(MAX_OBSERVABILITY_LIMIT);
    SESSION_SUMMARY_MAP.with(|map| {
        map.borrow()
            .iter()
            .rev()
            .take(keep)
            .filter_map(|entry| read_json::<SessionSummary>(Some(entry.value().as_slice())))
            .collect()
    })
}

pub fn list_turn_window_summaries(limit: usize) -> Vec<TurnWindowSummary> {
    if limit == 0 {
        return Vec::new();
    }
    let keep = limit.min(MAX_OBSERVABILITY_LIMIT);
    TURN_WINDOW_SUMMARY_MAP.with(|map| {
        map.borrow()
            .iter()
            .rev()
            .take(keep)
            .filter_map(|entry| read_json::<TurnWindowSummary>(Some(entry.value().as_slice())))
            .collect()
    })
}

pub fn list_memory_rollups(limit: usize) -> Vec<MemoryRollup> {
    if limit == 0 {
        return Vec::new();
    }
    let keep = limit.min(MAX_MEMORY_ROLLUPS);
    let mut rollups: Vec<MemoryRollup> = MEMORY_ROLLUP_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| read_json::<MemoryRollup>(Some(entry.value().as_slice())))
            .collect()
    });
    rollups.sort_by(|left, right| {
        right
            .generated_at_ns
            .cmp(&left.generated_at_ns)
            .then_with(|| left.namespace.cmp(&right.namespace))
    });
    rollups.truncate(keep);
    rollups
}

fn is_critical_exact_memory_key(key: &str) -> bool {
    key == "balance.eth"
        || key == "balance.eth.last_checked_ns"
        || key.starts_with("balance.eth.")
        || key.starts_with("wallet.")
        || key.starts_with("config.")
}

pub fn list_memory_for_context(
    raw_limit: usize,
    rollup_limit: usize,
) -> (Vec<MemoryFact>, Vec<MemoryRollup>) {
    let all = list_all_memory_facts(MAX_MEMORY_FACTS);
    let mut critical = Vec::new();
    let mut non_critical = Vec::new();
    for fact in all {
        if is_critical_exact_memory_key(&fact.key) {
            critical.push(fact);
        } else {
            non_critical.push(fact);
        }
    }

    let mut selected_raw = critical;
    if selected_raw.len() < raw_limit {
        let remaining = raw_limit.saturating_sub(selected_raw.len());
        selected_raw.extend(non_critical.into_iter().take(remaining));
    }
    selected_raw.truncate(raw_limit);

    let include_rollups = selected_raw.len() >= raw_limit;
    let rollups = if include_rollups {
        list_memory_rollups(rollup_limit)
    } else {
        Vec::new()
    };

    (selected_raw, rollups)
}

pub fn runtime_snapshot() -> RuntimeSnapshot {
    let payload = RUNTIME_MAP.with(|map| map.borrow().get(&RUNTIME_KEY.to_string()));
    read_json(payload.as_deref()).unwrap_or_default()
}

pub fn read_topup_state() -> Option<TopUpStage> {
    TOPUP_STATE_MAP
        .with(|map| map.borrow().get(&TOPUP_STATE_KEY.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn write_topup_state(state: &TopUpStage) {
    TOPUP_STATE_MAP.with(|map| {
        map.borrow_mut()
            .insert(TOPUP_STATE_KEY.to_string(), encode_json(state));
    });
}

pub fn clear_topup_state() {
    TOPUP_STATE_MAP.with(|map| {
        map.borrow_mut().remove(&TOPUP_STATE_KEY.to_string());
    });
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
    let lowered = trimmed.to_ascii_lowercase();
    if lowered.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    if lowered.starts_with("http://") && is_local_http_url(&lowered) {
        return Ok(trimmed.to_string());
    }
    Err(format!(
        "{field} must be an https:// URL or localhost http:// URL"
    ))
}

fn is_local_http_url(url: &str) -> bool {
    let without_scheme = match url.strip_prefix("http://") {
        Some(value) => value,
        None => return false,
    };
    let authority = without_scheme.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return false;
    }

    let host = if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .unwrap_or_default()
            .trim_start_matches('[')
    } else {
        authority.split(':').next().unwrap_or_default()
    };

    matches!(host, "localhost" | "127.0.0.1" | "0.0.0.0" | "::1")
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

#[allow(dead_code)]
pub fn get_automaton_evm_address() -> Option<String> {
    get_evm_address()
}

pub fn get_evm_rpc_url() -> String {
    runtime_snapshot().evm_rpc_url
}

pub fn get_discovered_usdc_address() -> Option<String> {
    runtime_snapshot().wallet_balance.usdc_contract_address
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

pub fn set_memory_fact(fact: &MemoryFact) -> Result<(), String> {
    MEMORY_FACTS_MAP.with(|map| {
        let mut map_ref = map.borrow_mut();
        let exists = map_ref.get(&fact.key).is_some();
        if !exists && map_ref.len() as usize >= MAX_MEMORY_FACTS {
            return Err(format!("memory full: max {MAX_MEMORY_FACTS} facts"));
        }
        map_ref.insert(fact.key.clone(), encode_json(fact));
        Ok(())
    })
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

#[allow(dead_code)]
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

pub fn upsert_strategy_template(template: StrategyTemplate) -> Result<StrategyTemplate, String> {
    validate_strategy_template(&template)?;
    let lookup_key = strategy_template_lookup_key(&template.key);
    let record_key = strategy_template_record_key(&lookup_key, &template.version);
    let index_key = strategy_template_index_key(&lookup_key, &template.version);

    STRATEGY_TEMPLATE_MAP.with(|map| {
        map.borrow_mut()
            .insert(record_key.clone(), encode_json(&template));
    });
    STRATEGY_TEMPLATE_INDEX_MAP.with(|map| {
        map.borrow_mut().insert(index_key, record_key.into_bytes());
    });
    Ok(template)
}

pub fn strategy_template(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Option<StrategyTemplate> {
    let record_key = strategy_template_record_key(&strategy_template_lookup_key(key), version);
    STRATEGY_TEMPLATE_MAP
        .with(|map| map.borrow().get(&record_key))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn list_strategy_template_versions(key: &StrategyTemplateKey) -> Vec<TemplateVersion> {
    let prefix = strategy_template_index_prefix(&strategy_template_lookup_key(key));
    let mut versions = STRATEGY_TEMPLATE_INDEX_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| {
                let raw_key = entry.key();
                if !raw_key.starts_with(&prefix) {
                    return None;
                }
                parse_version_sort_key(raw_key.rsplit(':').next().unwrap_or_default())
            })
            .collect::<Vec<_>>()
    });
    versions.sort();
    versions.reverse();
    versions
}

pub fn list_strategy_templates(key: &StrategyTemplateKey, limit: usize) -> Vec<StrategyTemplate> {
    if limit == 0 {
        return Vec::new();
    }
    list_strategy_template_versions(key)
        .into_iter()
        .take(limit)
        .filter_map(|version| strategy_template(key, &version))
        .collect()
}

pub fn list_all_strategy_templates(limit: usize) -> Vec<StrategyTemplate> {
    if limit == 0 {
        return Vec::new();
    }

    let mut templates = STRATEGY_TEMPLATE_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| read_json::<StrategyTemplate>(Some(entry.value().as_slice())))
            .collect::<Vec<_>>()
    });

    templates.sort_by(|left, right| {
        right
            .updated_at_ns
            .cmp(&left.updated_at_ns)
            .then_with(|| left.key.protocol.cmp(&right.key.protocol))
            .then_with(|| left.key.primitive.cmp(&right.key.primitive))
            .then_with(|| left.key.template_id.cmp(&right.key.template_id))
            .then_with(|| right.version.cmp(&left.version))
    });
    if templates.len() > limit {
        templates.truncate(limit);
    }
    templates
}

pub fn upsert_abi_artifact(artifact: AbiArtifact) -> Result<AbiArtifact, String> {
    validate_abi_artifact(&artifact)?;
    let lookup_key = abi_artifact_lookup_key(&artifact.key);
    let record_key = abi_artifact_record_key(&lookup_key, &artifact.key.version);
    let index_key = abi_artifact_index_key(&lookup_key, &artifact.key.version);

    ABI_ARTIFACT_MAP.with(|map| {
        map.borrow_mut()
            .insert(record_key.clone(), encode_json(&artifact));
    });
    ABI_ARTIFACT_INDEX_MAP.with(|map| {
        map.borrow_mut().insert(index_key, record_key.into_bytes());
    });
    Ok(artifact)
}

pub fn abi_artifact(key: &AbiArtifactKey) -> Option<AbiArtifact> {
    let record_key = abi_artifact_record_key(&abi_artifact_lookup_key(key), &key.version);
    ABI_ARTIFACT_MAP
        .with(|map| map.borrow().get(&record_key))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn list_abi_artifact_versions(
    protocol: &str,
    chain_id: u64,
    role: &str,
) -> Vec<TemplateVersion> {
    let lookup_key = abi_artifact_lookup_key(&AbiArtifactKey {
        protocol: protocol.to_string(),
        chain_id,
        role: role.to_string(),
        version: TemplateVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
    });
    let prefix = abi_artifact_index_prefix(&lookup_key);
    let mut versions = ABI_ARTIFACT_INDEX_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| {
                let raw_key = entry.key();
                if !raw_key.starts_with(&prefix) {
                    return None;
                }
                parse_version_sort_key(raw_key.rsplit(':').next().unwrap_or_default())
            })
            .collect::<Vec<_>>()
    });
    versions.sort();
    versions.reverse();
    versions
}

pub fn set_strategy_template_activation(
    state: TemplateActivationState,
) -> Result<TemplateActivationState, String> {
    validate_strategy_template_key(&state.key)?;
    validate_template_version(&state.version)?;
    let record_key = template_state_record_key("activation", &state.key, &state.version);
    STRATEGY_ACTIVATION_MAP.with(|map| {
        map.borrow_mut().insert(record_key, encode_json(&state));
    });
    Ok(state)
}

pub fn strategy_template_activation(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Option<TemplateActivationState> {
    let record_key = template_state_record_key("activation", key, version);
    STRATEGY_ACTIVATION_MAP
        .with(|map| map.borrow().get(&record_key))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn set_strategy_template_revocation(
    state: TemplateRevocationState,
) -> Result<TemplateRevocationState, String> {
    validate_strategy_template_key(&state.key)?;
    validate_template_version(&state.version)?;
    let record_key = template_state_record_key("revocation", &state.key, &state.version);
    STRATEGY_REVOCATION_MAP.with(|map| {
        map.borrow_mut().insert(record_key, encode_json(&state));
    });
    Ok(state)
}

#[allow(dead_code)]
pub fn strategy_template_revocation(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Option<TemplateRevocationState> {
    let record_key = template_state_record_key("revocation", key, version);
    STRATEGY_REVOCATION_MAP
        .with(|map| map.borrow().get(&record_key))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn set_strategy_kill_switch(
    state: StrategyKillSwitchState,
) -> Result<StrategyKillSwitchState, String> {
    validate_strategy_template_key(&state.key)?;
    let record_key = strategy_kill_switch_record_key(&state.key);
    STRATEGY_KILL_SWITCH_MAP.with(|map| {
        map.borrow_mut().insert(record_key, encode_json(&state));
    });
    Ok(state)
}

pub fn strategy_kill_switch(key: &StrategyTemplateKey) -> Option<StrategyKillSwitchState> {
    let record_key = strategy_kill_switch_record_key(key);
    STRATEGY_KILL_SWITCH_MAP
        .with(|map| map.borrow().get(&record_key))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn strategy_outcome_stats(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Option<StrategyOutcomeStats> {
    let record_key = strategy_outcome_stats_record_key(key, version);
    STRATEGY_OUTCOME_STATS_MAP
        .with(|map| map.borrow().get(&record_key))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn upsert_strategy_outcome_stats(
    stats: StrategyOutcomeStats,
) -> Result<StrategyOutcomeStats, String> {
    validate_strategy_template_key(&stats.key)?;
    validate_template_version(&stats.version)?;
    let record_key = strategy_outcome_stats_record_key(&stats.key, &stats.version);
    STRATEGY_OUTCOME_STATS_MAP.with(|map| {
        map.borrow_mut().insert(record_key, encode_json(&stats));
    });
    Ok(stats)
}

pub fn strategy_template_budget_spent_wei(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Option<String> {
    let record_key = strategy_budget_record_key(key, version);
    STRATEGY_BUDGET_MAP
        .with(|map| map.borrow().get(&record_key))
        .and_then(|payload| read_json(Some(payload.as_slice())))
}

pub fn set_strategy_template_budget_spent_wei(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
    spent_wei: String,
) -> Result<String, String> {
    validate_strategy_template_key(key)?;
    validate_template_version(version)?;
    let normalized = normalize_decimal_string(&spent_wei, "strategy budget spent_wei")?;
    let record_key = strategy_budget_record_key(key, version);
    STRATEGY_BUDGET_MAP.with(|map| {
        map.borrow_mut()
            .insert(record_key, encode_json(&normalized));
    });
    Ok(normalized)
}

pub fn record_strategy_outcome(
    outcome: StrategyOutcomeEvent,
) -> Result<StrategyOutcomeStats, String> {
    validate_strategy_template_key(&outcome.key)?;
    validate_template_version(&outcome.version)?;
    if outcome.action_id.trim().is_empty() {
        return Err("outcome action_id must be non-empty".to_string());
    }

    let mut stats = strategy_outcome_stats(&outcome.key, &outcome.version).unwrap_or_else(|| {
        StrategyOutcomeStats {
            key: outcome.key.clone(),
            version: outcome.version.clone(),
            total_runs: 0,
            success_runs: 0,
            deterministic_failures: 0,
            nondeterministic_failures: 0,
            deterministic_failure_streak: 0,
            confidence_bps: 0,
            ranking_score_bps: 0,
            parameter_priors: crate::domain::types::StrategyParameterPriors::default(),
            last_error: None,
            last_tx_hash: None,
            last_observed_at_ns: None,
        }
    });

    stats.total_runs = stats.total_runs.saturating_add(1);
    match outcome.outcome {
        StrategyOutcomeKind::Success => {
            stats.success_runs = stats.success_runs.saturating_add(1);
            stats.deterministic_failure_streak = 0;
            stats.last_error = None;
        }
        StrategyOutcomeKind::DeterministicFailure => {
            stats.deterministic_failures = stats.deterministic_failures.saturating_add(1);
            stats.deterministic_failure_streak =
                stats.deterministic_failure_streak.saturating_add(1);
            stats.last_error = outcome.error.clone();
        }
        StrategyOutcomeKind::NondeterministicFailure => {
            stats.nondeterministic_failures = stats.nondeterministic_failures.saturating_add(1);
            stats.deterministic_failure_streak = 0;
            stats.last_error = outcome.error.clone();
        }
    }
    stats.last_tx_hash = outcome.tx_hash.clone();
    stats.last_observed_at_ns = Some(outcome.observed_at_ns);
    upsert_strategy_outcome_stats(stats)
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

pub fn is_http_allowlist_enforced() -> bool {
    runtime_bool(HTTP_ALLOWLIST_INITIALIZED_KEY).unwrap_or(false)
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

pub fn wallet_balance_telemetry_view() -> WalletBalanceTelemetryView {
    WalletBalanceTelemetryView::from_snapshot(&runtime_snapshot(), now_ns())
}

pub fn wallet_balance_sync_config_view() -> WalletBalanceSyncConfigView {
    WalletBalanceSyncConfigView::from(&runtime_snapshot().wallet_balance_sync)
}

fn inbox_usdc_discovery_blocked(snapshot: &RuntimeSnapshot) -> bool {
    snapshot
        .wallet_balance
        .last_error
        .as_deref()
        .map(|error| {
            error
                .to_ascii_lowercase()
                .contains("inbox.usdc returned zero address")
        })
        .unwrap_or(false)
}

fn wallet_balance_sync_has_discoverable_usdc_source(snapshot: &RuntimeSnapshot) -> bool {
    snapshot.wallet_balance_sync.discover_usdc_via_inbox
        && snapshot.inbox_contract_address.is_some()
        && !inbox_usdc_discovery_blocked(snapshot)
}

fn wallet_balance_sync_has_usdc_source(snapshot: &RuntimeSnapshot) -> bool {
    snapshot.wallet_balance.usdc_contract_address.is_some()
        || wallet_balance_sync_has_discoverable_usdc_source(snapshot)
}

pub fn wallet_balance_sync_capable(snapshot: &RuntimeSnapshot) -> bool {
    if !snapshot.wallet_balance_sync.enabled {
        return false;
    }
    if snapshot.evm_rpc_url.trim().is_empty() {
        return false;
    }
    if snapshot.evm_address.is_some() {
        if snapshot.wallet_balance.usdc_contract_address.is_some() {
            return true;
        }
        if !snapshot.wallet_balance_sync.discover_usdc_via_inbox {
            // Let the sync path emit a deterministic missing-config error.
            return true;
        }
        return wallet_balance_sync_has_discoverable_usdc_source(snapshot);
    }
    if snapshot.ecdsa_key_name.trim().is_empty() {
        return false;
    }
    wallet_balance_sync_has_usdc_source(snapshot)
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

pub fn set_llm_canister_id(canister_id: String) -> Result<String, String> {
    let trimmed = canister_id.trim();
    if trimmed.is_empty() {
        return Err("llm canister id cannot be empty".to_string());
    }
    let normalized = Principal::from_text(trimmed)
        .map_err(|error| format!("invalid llm canister id: {error}"))?
        .to_text();

    let mut snapshot = runtime_snapshot();
    snapshot.llm_canister_id = normalized.clone();
    snapshot.last_transition_at_ns = now_ns();
    save_runtime_snapshot(&snapshot);
    Ok(normalized)
}

#[allow(dead_code)]
pub fn get_llm_canister_id() -> String {
    runtime_snapshot().llm_canister_id
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
    let mut bounded_record = record.clone();
    bounded_record.inner_dialogue = bounded_record
        .inner_dialogue
        .as_ref()
        .map(|dialogue| truncate_text_field(dialogue, MAX_TURN_INNER_DIALOGUE_CHARS));
    let turn_key = format!("{:020}-{}", bounded_record.created_at_ns, bounded_record.id);
    TURN_MAP.with(|map| {
        map.borrow_mut()
            .insert(turn_key, encode_json(&bounded_record));
    });

    set_tool_records(&bounded_record.id, tool_calls);
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
    let bounded_tool_calls = tool_calls
        .iter()
        .map(|record| {
            let mut bounded = record.clone();
            bounded.args_json = truncate_text_field(&bounded.args_json, MAX_TOOL_ARGS_JSON_CHARS);
            bounded.output = truncate_text_field(&bounded.output, MAX_TOOL_OUTPUT_CHARS);
            bounded
        })
        .collect::<Vec<_>>();
    let tool_key = format!("tools:{turn_id}");
    TOOL_MAP.with(|map| {
        map.borrow_mut()
            .insert(tool_key, encode_json(&bounded_tool_calls));
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

pub fn normalize_inbox_body(raw_body: &str) -> Result<String, String> {
    let trimmed = raw_body.trim();
    if trimmed.is_empty() {
        return Err("message cannot be empty".to_string());
    }
    Ok(truncate_text_field(trimmed, MAX_INBOX_BODY_CHARS))
}

pub fn post_inbox_message(body: String, caller: String) -> Result<String, String> {
    let bounded_body = normalize_inbox_body(&body)?;

    let seq = next_inbox_seq();
    let id = format!("inbox:{seq:020}");
    let message = InboxMessage {
        id: id.clone(),
        seq,
        body: bounded_body,
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
    INBOX_MAP.with(|map| {
        map.borrow()
            .iter()
            .rev()
            .take(limit)
            .filter_map(|entry| read_json::<InboxMessage>(Some(entry.value().as_slice())))
            .collect()
    })
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

fn load_storage_growth_samples() -> Vec<StorageGrowthSample> {
    RUNTIME_MAP
        .with(|map| map.borrow().get(&STORAGE_GROWTH_SAMPLES_KEY.to_string()))
        .and_then(|payload| read_json(Some(payload.as_slice())))
        .unwrap_or_default()
}

fn save_storage_growth_samples(samples: &[StorageGrowthSample]) {
    RUNTIME_MAP.with(|map| {
        map.borrow_mut()
            .insert(STORAGE_GROWTH_SAMPLES_KEY.to_string(), encode_json(samples));
    });
}

fn push_storage_growth_sample(now_ns: u64, tracked_entries: u64) -> Vec<StorageGrowthSample> {
    let mut samples = load_storage_growth_samples();
    let sample = StorageGrowthSample {
        captured_at_ns: now_ns,
        tracked_entries,
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

    let cutoff_ns = now_ns.saturating_sub(STORAGE_GROWTH_TREND_WINDOW_NS);
    samples.retain(|entry| entry.captured_at_ns >= cutoff_ns);
    if samples.len() > STORAGE_GROWTH_MAX_SAMPLES {
        let drop_count = samples.len() - STORAGE_GROWTH_MAX_SAMPLES;
        samples.drain(0..drop_count);
    }
    save_storage_growth_samples(&samples);
    samples
}

fn calculate_tracked_entries_delta_per_hour(samples: &[StorageGrowthSample]) -> Option<i64> {
    let first = samples.first()?;
    let last = samples.last()?;
    if last.captured_at_ns <= first.captured_at_ns {
        return None;
    }

    let delta = last.tracked_entries as f64 - first.tracked_entries as f64;
    let elapsed_secs = (last.captured_at_ns.saturating_sub(first.captured_at_ns)) as f64 / 1e9f64;
    if elapsed_secs <= 0.0 {
        return None;
    }

    let per_hour = (delta / elapsed_secs) * 3_600f64;
    if !per_hour.is_finite() {
        return None;
    }

    if per_hour >= i64::MAX as f64 {
        return Some(i64::MAX);
    }
    if per_hour <= i64::MIN as f64 {
        return Some(i64::MIN);
    }
    Some(per_hour.round() as i64)
}

fn utilization_percent(entries: u64, limit: u64) -> u8 {
    if limit == 0 {
        return 0;
    }
    let numerator = entries.saturating_mul(100);
    let rounded = numerator
        .saturating_add(limit.saturating_sub(1))
        .saturating_div(limit)
        .min(100);
    u8::try_from(rounded).unwrap_or(100)
}

fn pressure_level_for_percent(max_utilization_percent: u8) -> StoragePressureLevel {
    if max_utilization_percent >= STORAGE_PRESSURE_CRITICAL_PERCENT {
        StoragePressureLevel::Critical
    } else if max_utilization_percent >= STORAGE_PRESSURE_HIGH_PERCENT {
        StoragePressureLevel::High
    } else if max_utilization_percent >= STORAGE_PRESSURE_ELEVATED_PERCENT {
        StoragePressureLevel::Elevated
    } else {
        StoragePressureLevel::Normal
    }
}

fn storage_growth_metrics(captured_at_ns: u64) -> StorageGrowthMetrics {
    #[cfg(target_arch = "wasm32")]
    let heap_memory_mb = {
        let pages = core::arch::wasm32::memory_size(0) as u64;
        pages as f64 * 65536.0 / 1_048_576.0
    };
    #[cfg(not(target_arch = "wasm32"))]
    let heap_memory_mb = 0.0_f64;

    #[cfg(target_arch = "wasm32")]
    let stable_memory_mb = {
        let pages = ic_cdk::api::stable_size();
        pages as f64 * 65536.0 / 1_048_576.0
    };
    #[cfg(not(target_arch = "wasm32"))]
    let stable_memory_mb = 0.0_f64;

    let runtime_map_entries = RUNTIME_MAP.with(|map| map.borrow().len());
    let transition_map_entries = TRANSITION_MAP.with(|map| map.borrow().len());
    let turn_map_entries = TURN_MAP.with(|map| map.borrow().len());
    let tool_map_entries = TOOL_MAP.with(|map| map.borrow().len());
    let job_map_entries = JOB_MAP.with(|map| map.borrow().len());
    let job_queue_map_entries = JOB_QUEUE_MAP.with(|map| map.borrow().len());
    let dedupe_map_entries = DEDUPE_MAP.with(|map| map.borrow().len());
    let inbox_map_entries = INBOX_MAP.with(|map| map.borrow().len());
    let inbox_pending_queue_entries = INBOX_PENDING_QUEUE_MAP.with(|map| map.borrow().len());
    let inbox_staged_queue_entries = INBOX_STAGED_QUEUE_MAP.with(|map| map.borrow().len());
    let outbox_map_entries = OUTBOX_MAP.with(|map| map.borrow().len());
    let session_summary_entries = SESSION_SUMMARY_MAP.with(|map| map.borrow().len());
    let turn_window_summary_entries = TURN_WINDOW_SUMMARY_MAP.with(|map| map.borrow().len());
    let memory_rollup_entries = MEMORY_ROLLUP_MAP.with(|map| map.borrow().len());
    let memory_fact_entries = MEMORY_FACTS_MAP.with(|map| map.borrow().len());

    let session_summary_limit = u64::try_from(MAX_SESSION_SUMMARIES).unwrap_or(u64::MAX);
    let turn_window_summary_limit = u64::try_from(MAX_TURN_WINDOW_SUMMARIES).unwrap_or(u64::MAX);
    let memory_rollup_limit = u64::try_from(MAX_MEMORY_ROLLUPS).unwrap_or(u64::MAX);
    let memory_fact_limit = u64::try_from(MAX_MEMORY_FACTS).unwrap_or(u64::MAX);

    let tracked_entry_count = runtime_map_entries
        .saturating_add(transition_map_entries)
        .saturating_add(turn_map_entries)
        .saturating_add(tool_map_entries)
        .saturating_add(job_map_entries)
        .saturating_add(job_queue_map_entries)
        .saturating_add(dedupe_map_entries)
        .saturating_add(inbox_map_entries)
        .saturating_add(inbox_pending_queue_entries)
        .saturating_add(inbox_staged_queue_entries)
        .saturating_add(outbox_map_entries)
        .saturating_add(session_summary_entries)
        .saturating_add(turn_window_summary_entries)
        .saturating_add(memory_rollup_entries)
        .saturating_add(memory_fact_entries);
    let growth_samples = push_storage_growth_sample(captured_at_ns, tracked_entry_count);
    let tracked_entries_delta_per_hour = calculate_tracked_entries_delta_per_hour(&growth_samples);
    let trend_window_seconds = growth_samples
        .first()
        .zip(growth_samples.last())
        .map(|(first, last)| {
            last.captured_at_ns
                .saturating_sub(first.captured_at_ns)
                .saturating_div(1_000_000_000)
        })
        .unwrap_or_default();
    let trend_sample_count = u32::try_from(growth_samples.len()).unwrap_or(u32::MAX);

    let session_summary_utilization_percent =
        utilization_percent(session_summary_entries, session_summary_limit);
    let turn_window_summary_utilization_percent =
        utilization_percent(turn_window_summary_entries, turn_window_summary_limit);
    let memory_rollup_utilization_percent =
        utilization_percent(memory_rollup_entries, memory_rollup_limit);
    let memory_fact_utilization_percent =
        utilization_percent(memory_fact_entries, memory_fact_limit);

    let max_utilization_percent = [
        session_summary_utilization_percent,
        turn_window_summary_utilization_percent,
        memory_rollup_utilization_percent,
        memory_fact_utilization_percent,
    ]
    .into_iter()
    .max()
    .unwrap_or_default();
    let pressure_level = pressure_level_for_percent(max_utilization_percent);

    let mut pressure_warnings = Vec::new();
    if session_summary_utilization_percent >= STORAGE_PRESSURE_HIGH_PERCENT {
        pressure_warnings.push(format!(
            "session summaries at {}% capacity ({}/{})",
            session_summary_utilization_percent, session_summary_entries, session_summary_limit
        ));
    }
    if turn_window_summary_utilization_percent >= STORAGE_PRESSURE_HIGH_PERCENT {
        pressure_warnings.push(format!(
            "turn window summaries at {}% capacity ({}/{})",
            turn_window_summary_utilization_percent,
            turn_window_summary_entries,
            turn_window_summary_limit
        ));
    }
    if memory_rollup_utilization_percent >= STORAGE_PRESSURE_HIGH_PERCENT {
        pressure_warnings.push(format!(
            "memory rollups at {}% capacity ({}/{})",
            memory_rollup_utilization_percent, memory_rollup_entries, memory_rollup_limit
        ));
    }
    if memory_fact_utilization_percent >= STORAGE_PRESSURE_HIGH_PERCENT {
        pressure_warnings.push(format!(
            "memory facts at {}% capacity ({}/{})",
            memory_fact_utilization_percent, memory_fact_entries, memory_fact_limit
        ));
    }
    if tracked_entries_delta_per_hour
        .map(|delta| delta >= STORAGE_GROWTH_WARNING_ENTRIES_PER_HOUR)
        .unwrap_or(false)
    {
        pressure_warnings.push(format!(
            "tracked entries growing quickly ({} entries/hour)",
            tracked_entries_delta_per_hour.unwrap_or_default()
        ));
    }
    let near_limit = max_utilization_percent >= STORAGE_PRESSURE_HIGH_PERCENT;

    let retention_runtime = retention_maintenance_runtime();

    StorageGrowthMetrics {
        runtime_map_entries,
        transition_map_entries,
        turn_map_entries,
        tool_map_entries,
        job_map_entries,
        job_queue_map_entries,
        dedupe_map_entries,
        inbox_map_entries,
        inbox_pending_queue_entries,
        inbox_staged_queue_entries,
        outbox_map_entries,
        session_summary_entries,
        session_summary_limit,
        turn_window_summary_entries,
        turn_window_summary_limit,
        memory_rollup_entries,
        memory_rollup_limit,
        memory_fact_entries,
        memory_fact_limit,
        session_summary_utilization_percent,
        turn_window_summary_utilization_percent,
        memory_rollup_utilization_percent,
        memory_fact_utilization_percent,
        near_limit,
        pressure_level,
        pressure_warnings,
        tracked_entry_count,
        tracked_entries_delta_per_hour,
        trend_window_seconds,
        trend_sample_count,
        retention_progress_percent: retention_runtime.retention_progress_percent,
        summarization_progress_percent: retention_runtime.summarization_progress_percent,
        heap_memory_mb,
        stable_memory_mb,
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
    let session_summaries = list_session_summaries(bounded_limit);
    let turn_window_summaries = list_turn_window_summaries(bounded_limit);
    let memory_rollups = list_memory_rollups(bounded_limit);

    ObservabilitySnapshot {
        captured_at_ns,
        runtime: snapshot_to_view(),
        scheduler: scheduler_runtime_view(),
        storage_growth: storage_growth_metrics(captured_at_ns),
        inbox_stats: inbox_stats(),
        inbox_messages: list_inbox_messages(bounded_limit),
        outbox_stats: outbox_stats(),
        outbox_messages: list_outbox_messages(bounded_limit),
        prompt_layers: list_prompt_layers(),
        conversation_summaries,
        session_summaries,
        turn_window_summaries,
        memory_rollups,
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
    OUTBOX_MAP.with(|map| {
        map.borrow()
            .iter()
            .rev()
            .take(limit)
            .filter_map(|entry| read_json::<OutboxMessage>(Some(entry.value().as_slice())))
            .collect()
    })
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

pub fn complete_job(
    job_id: &str,
    status: JobStatus,
    error: Option<String>,
    now_ns: u64,
    retry_after_secs: Option<u64>,
) {
    let mut job = match get_job_by_id(job_id) {
        Some(job) => job,
        None => return,
    };
    let old_status = job.status.clone();
    let started_at_ns = job.started_at_ns;
    job.last_error = error.clone();
    job.attempts = job.attempts.saturating_add(1);
    let should_retry = matches!(status, JobStatus::Failed | JobStatus::TimedOut)
        && retry_after_secs.is_some()
        && job.attempts < job.max_attempts;
    let mut retry_at_ns = None;
    let mut retried = false;

    if should_retry {
        let retry_delay_secs = retry_after_secs.unwrap_or_default();
        let scheduled_for_ns =
            now_ns.saturating_add(retry_delay_secs.saturating_mul(1_000_000_000));
        let queue_seq = parse_job_seq(&job.id).unwrap_or_default();
        job.status = JobStatus::Pending;
        job.scheduled_for_ns = scheduled_for_ns;
        job.started_at_ns = None;
        job.finished_at_ns = None;
        save_job(&job);
        JOB_QUEUE_MAP.with(|map| {
            map.borrow_mut().insert(
                queue_index_key(&job.lane, scheduled_for_ns, job.priority, queue_seq),
                job.id.clone().into_bytes(),
            );
        });
        retry_at_ns = Some(scheduled_for_ns);
        retried = true;
    } else {
        job.status = status.clone();
        job.finished_at_ns = Some(now_ns);
        save_job(&job);
    }

    let cfg =
        get_task_config(&job.kind).unwrap_or_else(|| TaskScheduleConfig::default_for(&job.kind));
    let mut task_runtime = get_task_runtime(&job.kind);
    task_runtime.last_started_ns = started_at_ns;
    task_runtime.last_finished_ns = Some(now_ns);
    task_runtime.last_error = error.clone();

    if status == JobStatus::Succeeded {
        task_runtime.consecutive_failures = 0;
        task_runtime.backoff_until_ns = None;
    } else if retried {
        task_runtime.consecutive_failures = task_runtime.consecutive_failures.saturating_add(1);
        task_runtime.backoff_until_ns = retry_at_ns;
        task_runtime.pending_job_id = Some(job.id.clone());
    } else if matches!(status, JobStatus::Failed | JobStatus::TimedOut) {
        task_runtime.consecutive_failures = task_runtime.consecutive_failures.saturating_add(1);
        let capped = retry_after_secs.unwrap_or_else(|| {
            let exponent = task_runtime.consecutive_failures.min(20) as u32;
            let base_delay = 1u64 << exponent;
            base_delay.min(cfg.max_backoff_secs.max(1))
        });
        task_runtime.backoff_until_ns = now_ns.checked_add(capped.saturating_mul(1_000_000_000));
    }

    if !retried
        && task_runtime
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
        "scheduler_job_complete job_id={} from={:?} to={:?} attempts={} max_attempts={} retried={} retry_at_ns={:?} error={:?}",
        job_id,
        old_status,
        job.status,
        job.attempts,
        job.max_attempts,
        retried,
        retry_at_ns,
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
            None,
        );
    }
}

pub fn list_recent_jobs(limit: usize) -> Vec<ScheduledJob> {
    if limit == 0 {
        return Vec::new();
    }
    let keep = limit.min(MAX_RECENT_JOBS);
    JOB_MAP.with(|map| {
        map.borrow()
            .iter()
            .rev()
            .take(keep)
            .filter_map(|entry| read_json::<ScheduledJob>(Some(entry.value().as_slice())))
            .collect()
    })
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

fn validate_strategy_template(template: &StrategyTemplate) -> Result<(), String> {
    validate_strategy_template_key(&template.key)?;
    validate_template_version(&template.version)?;
    for role in &template.contract_roles {
        if role.role.trim().is_empty() {
            return Err("contract role binding role must be non-empty".to_string());
        }
        if role.address.trim().is_empty() {
            return Err("contract role binding address must be non-empty".to_string());
        }
        if role.source_ref.trim().is_empty() {
            return Err("contract role binding source_ref must be non-empty".to_string());
        }
    }
    for action in &template.actions {
        if action.action_id.trim().is_empty() {
            return Err("strategy action_id must be non-empty".to_string());
        }
    }
    Ok(())
}

fn validate_abi_artifact(artifact: &AbiArtifact) -> Result<(), String> {
    validate_abi_artifact_key(&artifact.key)?;
    if artifact.source_ref.trim().is_empty() {
        return Err("abi artifact source_ref must be non-empty".to_string());
    }
    if artifact.functions.is_empty() {
        return Err("abi artifact must include at least one function".to_string());
    }
    Ok(())
}

fn validate_abi_artifact_key(key: &AbiArtifactKey) -> Result<(), String> {
    if key.protocol.trim().is_empty() {
        return Err("abi artifact protocol must be non-empty".to_string());
    }
    if key.chain_id == 0 {
        return Err("abi artifact chain_id must be greater than zero".to_string());
    }
    if key.role.trim().is_empty() {
        return Err("abi artifact role must be non-empty".to_string());
    }
    validate_template_version(&key.version)
}

fn validate_strategy_template_key(key: &StrategyTemplateKey) -> Result<(), String> {
    if key.protocol.trim().is_empty() {
        return Err("strategy protocol must be non-empty".to_string());
    }
    if key.primitive.trim().is_empty() {
        return Err("strategy primitive must be non-empty".to_string());
    }
    if key.chain_id == 0 {
        return Err("strategy chain_id must be greater than zero".to_string());
    }
    if key.template_id.trim().is_empty() {
        return Err("strategy template_id must be non-empty".to_string());
    }
    Ok(())
}

fn validate_template_version(version: &TemplateVersion) -> Result<(), String> {
    if version.major == 0 && version.minor == 0 && version.patch == 0 {
        return Err("template version must not be 0.0.0".to_string());
    }
    Ok(())
}

fn strategy_template_lookup_key(key: &StrategyTemplateKey) -> String {
    let normalized = format!(
        "{}|{}|{}|{}",
        key.protocol.trim().to_ascii_lowercase(),
        key.primitive.trim().to_ascii_lowercase(),
        key.chain_id,
        key.template_id.trim().to_ascii_lowercase()
    );
    lookup_digest("strategy:template", &normalized)
}

fn abi_artifact_lookup_key(key: &AbiArtifactKey) -> String {
    let normalized = format!(
        "{}|{}|{}",
        key.protocol.trim().to_ascii_lowercase(),
        key.chain_id,
        key.role.trim().to_ascii_lowercase()
    );
    lookup_digest("strategy:abi", &normalized)
}

fn lookup_digest(prefix: &str, payload: &str) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(payload.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("{prefix}:{digest}")
}

fn template_version_sort_key(version: &TemplateVersion) -> String {
    format!(
        "{:05}.{:05}.{:05}",
        version.major, version.minor, version.patch
    )
}

fn parse_version_sort_key(raw: &str) -> Option<TemplateVersion> {
    let mut parts = raw.split('.');
    let major = parts.next()?.parse::<u16>().ok()?;
    let minor = parts.next()?.parse::<u16>().ok()?;
    let patch = parts.next()?.parse::<u16>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(TemplateVersion {
        major,
        minor,
        patch,
    })
}

fn strategy_template_record_key(lookup_key: &str, version: &TemplateVersion) -> String {
    format!(
        "strategy:template:record:{lookup_key}:{}",
        template_version_sort_key(version)
    )
}

fn strategy_template_index_prefix(lookup_key: &str) -> String {
    format!("strategy:template:index:{lookup_key}:")
}

fn strategy_template_index_key(lookup_key: &str, version: &TemplateVersion) -> String {
    format!(
        "{}{}",
        strategy_template_index_prefix(lookup_key),
        template_version_sort_key(version)
    )
}

fn abi_artifact_record_key(lookup_key: &str, version: &TemplateVersion) -> String {
    format!(
        "strategy:abi:record:{lookup_key}:{}",
        template_version_sort_key(version)
    )
}

fn abi_artifact_index_prefix(lookup_key: &str) -> String {
    format!("strategy:abi:index:{lookup_key}:")
}

fn abi_artifact_index_key(lookup_key: &str, version: &TemplateVersion) -> String {
    format!(
        "{}{}",
        abi_artifact_index_prefix(lookup_key),
        template_version_sort_key(version)
    )
}

fn template_state_record_key(
    kind: &str,
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> String {
    format!(
        "strategy:{kind}:{}:{}",
        strategy_template_lookup_key(key),
        template_version_sort_key(version)
    )
}

fn strategy_kill_switch_record_key(key: &StrategyTemplateKey) -> String {
    format!("strategy:kill_switch:{}", strategy_template_lookup_key(key))
}

fn strategy_outcome_stats_record_key(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> String {
    format!(
        "strategy:outcome:{}:{}",
        strategy_template_lookup_key(key),
        template_version_sort_key(version)
    )
}

fn strategy_budget_record_key(key: &StrategyTemplateKey, version: &TemplateVersion) -> String {
    format!(
        "strategy:budget:{}:{}",
        strategy_template_lookup_key(key),
        template_version_sort_key(version)
    )
}

fn normalize_decimal_string(raw: &str, field: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} must be non-empty"));
    }
    if !trimmed.as_bytes().iter().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{field} must be a decimal string"));
    }
    Ok(trimmed.to_string())
}

fn parse_task_kind(raw_key: &str) -> Option<TaskKind> {
    if !raw_key.starts_with("task:") {
        return None;
    }
    match &raw_key[5..] {
        "AgentTurn" => Some(TaskKind::AgentTurn),
        "PollInbox" => Some(TaskKind::PollInbox),
        "CheckCycles" => Some(TaskKind::CheckCycles),
        "TopUpCycles" => Some(TaskKind::TopUpCycles),
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

fn parse_job_seq(job_id: &str) -> Option<u64> {
    let mut parts = job_id.split(':');
    if parts.next() != Some("job") {
        return None;
    }
    parts.next()?.parse::<u64>().ok()
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

#[cfg(test)]
pub fn save_job_for_tests(job: ScheduledJob) {
    save_job(&job);
}

#[cfg(test)]
pub fn insert_dedupe_for_tests(dedupe_key: String, job_id: String) {
    DEDUPE_MAP.with(|map| {
        map.borrow_mut()
            .insert(dedupe_index_key(&dedupe_key), job_id.into_bytes());
    });
}

fn oldest_job_seq_to_keep(max_records: u64) -> Option<u64> {
    if max_records == 0 {
        return None;
    }
    let keep = usize::try_from(max_records).unwrap_or(usize::MAX);
    JOB_MAP.with(|map| {
        map.borrow()
            .iter()
            .rev()
            .take(keep)
            .filter_map(|entry| parse_job_seq(entry.key()))
            .last()
    })
}

fn should_prune_job(
    job: &ScheduledJob,
    jobs_cutoff_ns: u64,
    keep_from_seq: Option<u64>,
    jobs_max_records: u64,
) -> bool {
    if !job.is_terminal() {
        return false;
    }
    let finished_at_ns = job.finished_at_ns.unwrap_or(job.scheduled_for_ns);
    if finished_at_ns > jobs_cutoff_ns {
        return false;
    }

    if jobs_max_records == 0 {
        return true;
    }

    let Some(keep_seq) = keep_from_seq else {
        return false;
    };
    parse_job_seq(&job.id).is_some_and(|seq| seq < keep_seq)
}

fn collect_prunable_jobs(
    start_after: Option<&str>,
    budget: usize,
    jobs_cutoff_ns: u64,
    keep_from_seq: Option<u64>,
    jobs_max_records: u64,
) -> (Vec<String>, Option<String>, bool) {
    if budget == 0 {
        return (Vec::new(), start_after.map(ToString::to_string), false);
    }

    let mut candidates: Vec<String> = Vec::new();
    let mut last_scanned: Option<String> = None;
    let mut reached_end = true;
    let mut passed_start = start_after.is_none();

    JOB_MAP.with(|map| {
        for entry in map.borrow().iter() {
            if !passed_start {
                if start_after.is_some_and(|cursor| entry.key().as_str() <= cursor) {
                    continue;
                }
                passed_start = true;
            }

            let key = entry.key().clone();
            last_scanned = Some(key.clone());
            let should_prune = read_json::<ScheduledJob>(Some(entry.value().as_slice()))
                .is_some_and(|job| {
                    should_prune_job(&job, jobs_cutoff_ns, keep_from_seq, jobs_max_records)
                });
            if should_prune {
                candidates.push(key);
                if candidates.len() >= budget {
                    reached_end = false;
                    break;
                }
            }
        }
    });

    let next_cursor = if reached_end { None } else { last_scanned };
    (candidates, next_cursor, reached_end)
}

fn dedupe_key_slot_ns(dedupe_index: &str) -> Option<u64> {
    let dedupe_key = dedupe_index.strip_prefix("dedupe:")?;
    dedupe_key.rsplit(':').next()?.parse::<u64>().ok()
}

fn should_prune_dedupe_entry(
    index_key: &str,
    job: Option<&ScheduledJob>,
    dedupe_cutoff_ns: u64,
) -> bool {
    if let Some(job) = job {
        if !job.is_terminal() {
            return false;
        }
    }

    if dedupe_key_slot_ns(index_key).is_some_and(|slot| slot <= dedupe_cutoff_ns) {
        return true;
    }

    match job {
        None => true,
        Some(job) => {
            let finished_at_ns = job.finished_at_ns.unwrap_or(job.scheduled_for_ns);
            finished_at_ns <= dedupe_cutoff_ns
        }
    }
}

fn collect_prunable_dedupe(
    start_after: Option<&str>,
    budget: usize,
    dedupe_cutoff_ns: u64,
) -> (Vec<String>, Option<String>, bool) {
    if budget == 0 {
        return (Vec::new(), start_after.map(ToString::to_string), false);
    }

    let mut candidates: Vec<String> = Vec::new();
    let mut last_scanned: Option<String> = None;
    let mut reached_end = true;
    let mut passed_start = start_after.is_none();

    DEDUPE_MAP.with(|map| {
        for entry in map.borrow().iter() {
            if !passed_start {
                if start_after.is_some_and(|cursor| entry.key().as_str() <= cursor) {
                    continue;
                }
                passed_start = true;
            }

            let key = entry.key().clone();
            let job_id = String::from_utf8(entry.value().clone()).unwrap_or_default();
            last_scanned = Some(key.clone());
            let job = get_job_by_id(&job_id);
            if should_prune_dedupe_entry(&key, job.as_ref(), dedupe_cutoff_ns) {
                candidates.push(key);
                if candidates.len() >= budget {
                    reached_end = false;
                    break;
                }
            }
        }
    });

    let next_cursor = if reached_end { None } else { last_scanned };
    (candidates, next_cursor, reached_end)
}

fn remove_queue_entries_for_job(job_id: &str) {
    let queue_keys = JOB_QUEUE_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| {
                String::from_utf8(entry.value().clone())
                    .ok()
                    .filter(|queued| queued == job_id)
                    .map(|_| entry.key().clone())
            })
            .collect::<Vec<_>>()
    });
    if queue_keys.is_empty() {
        return;
    }
    JOB_QUEUE_MAP.with(|map| {
        let mut queue = map.borrow_mut();
        for key in queue_keys {
            queue.remove(&key);
        }
    });
}

fn clear_pending_job_runtime_refs(job_id: &str) {
    for kind in TaskKind::all() {
        let mut runtime = get_task_runtime(kind);
        if runtime
            .pending_job_id
            .as_ref()
            .is_some_and(|pending| pending == job_id)
        {
            runtime.pending_job_id = None;
            save_task_runtime(kind, &runtime);
        }
    }
}

fn delete_job_candidates(job_keys: &[String]) -> u32 {
    let mut deleted = 0u32;
    for key in job_keys {
        let Some(job) = get_job_by_id(key) else {
            continue;
        };
        if !job.is_terminal() {
            continue;
        }
        JOB_MAP.with(|map| {
            map.borrow_mut().remove(key);
        });
        remove_queue_entries_for_job(&job.id);
        clear_pending_job_runtime_refs(&job.id);
        let dedupe_index = dedupe_index_key(&job.dedupe_key);
        DEDUPE_MAP.with(|map| {
            let mut dedupe = map.borrow_mut();
            let should_remove = dedupe
                .get(&dedupe_index)
                .and_then(|raw| String::from_utf8(raw).ok())
                .is_some_and(|mapped_job_id| mapped_job_id == job.id);
            if should_remove {
                dedupe.remove(&dedupe_index);
            }
        });
        deleted = deleted.saturating_add(1);
    }
    deleted
}

fn delete_dedupe_candidates(dedupe_keys: &[String]) -> u32 {
    let mut deleted = 0u32;
    DEDUPE_MAP.with(|map| {
        let mut dedupe = map.borrow_mut();
        for key in dedupe_keys {
            if dedupe.remove(key).is_some() {
                deleted = deleted.saturating_add(1);
            }
        }
    });
    deleted
}

fn protected_conversation_inbox_ids() -> std::collections::BTreeSet<String> {
    CONVERSATION_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|entry| read_json::<ConversationLog>(Some(entry.value().as_slice())))
            .flat_map(|log| {
                log.entries
                    .into_iter()
                    .map(|entry| entry.inbox_message_id)
                    .collect::<Vec<_>>()
            })
            .collect()
    })
}

fn collect_prunable_inbox(
    start_after: Option<&str>,
    budget: usize,
    inbox_cutoff_ns: u64,
    protected_inbox_ids: &std::collections::BTreeSet<String>,
) -> (Vec<InboxCandidate>, Option<String>, bool) {
    if budget == 0 {
        return (Vec::new(), start_after.map(ToString::to_string), false);
    }

    let mut candidates = Vec::<InboxCandidate>::new();
    let mut last_scanned: Option<String> = None;
    let mut reached_end = true;
    let mut passed_start = start_after.is_none();

    INBOX_MAP.with(|map| {
        for entry in map.borrow().iter() {
            if !passed_start {
                if start_after.is_some_and(|cursor| entry.key().as_str() <= cursor) {
                    continue;
                }
                passed_start = true;
            }

            let key = entry.key().clone();
            last_scanned = Some(key.clone());
            let Some(message) = read_json::<InboxMessage>(Some(entry.value().as_slice())) else {
                continue;
            };
            if !matches!(message.status, InboxMessageStatus::Consumed) {
                continue;
            }
            if protected_inbox_ids.contains(&message.id) {
                continue;
            }
            let cutoff_field = message.consumed_at_ns.unwrap_or(message.posted_at_ns);
            if cutoff_field > inbox_cutoff_ns {
                continue;
            }
            candidates.push(InboxCandidate { key, message });
            if candidates.len() >= budget {
                reached_end = false;
                break;
            }
        }
    });

    let next_cursor = if reached_end { None } else { last_scanned };
    (candidates, next_cursor, reached_end)
}

fn collect_prunable_outbox(
    start_after: Option<&str>,
    budget: usize,
    outbox_cutoff_ns: u64,
    protected_inbox_ids: &std::collections::BTreeSet<String>,
) -> (Vec<OutboxCandidate>, Option<String>, bool) {
    if budget == 0 {
        return (Vec::new(), start_after.map(ToString::to_string), false);
    }

    let mut candidates = Vec::<OutboxCandidate>::new();
    let mut last_scanned: Option<String> = None;
    let mut reached_end = true;
    let mut passed_start = start_after.is_none();

    OUTBOX_MAP.with(|map| {
        for entry in map.borrow().iter() {
            if !passed_start {
                if start_after.is_some_and(|cursor| entry.key().as_str() <= cursor) {
                    continue;
                }
                passed_start = true;
            }

            let key = entry.key().clone();
            last_scanned = Some(key.clone());
            let Some(message) = read_json::<OutboxMessage>(Some(entry.value().as_slice())) else {
                continue;
            };
            if message.created_at_ns > outbox_cutoff_ns {
                continue;
            }
            if message
                .source_inbox_ids
                .iter()
                .any(|id| protected_inbox_ids.contains(id))
            {
                continue;
            }
            candidates.push(OutboxCandidate { key, message });
            if candidates.len() >= budget {
                reached_end = false;
                break;
            }
        }
    });

    let next_cursor = if reached_end { None } else { last_scanned };
    (candidates, next_cursor, reached_end)
}

fn session_summary_accumulator(
    sender: &str,
    window_start_ns: u64,
    window_end_ns: u64,
) -> SessionSummaryAccumulator {
    SessionSummaryAccumulator {
        sender: sender.to_string(),
        window_start_ns,
        window_end_ns,
        source_count: 0,
        inbox_message_count: 0,
        outbox_message_count: 0,
        inbox_preview: String::new(),
        outbox_preview: String::new(),
    }
}

fn resolve_outbox_sender(
    message: &OutboxMessage,
    cached_inbox_senders: &std::collections::BTreeMap<String, String>,
) -> String {
    for inbox_id in &message.source_inbox_ids {
        if let Some(sender) = cached_inbox_senders.get(inbox_id) {
            return sender.clone();
        }
        if let Some(inbox) = get_inbox_message_by_id(inbox_id) {
            return normalize_conversation_sender(&inbox.posted_by);
        }
    }
    "unknown".to_string()
}

fn summarize_inbox_outbox_candidates(
    inbox_candidates: &[InboxCandidate],
    outbox_candidates: &[OutboxCandidate],
    now_ns: u64,
) -> u32 {
    if inbox_candidates.is_empty() && outbox_candidates.is_empty() {
        return 0;
    }

    let mut grouped = std::collections::BTreeMap::<(String, u64), SessionSummaryAccumulator>::new();
    let mut cached_inbox_senders = std::collections::BTreeMap::<String, String>::new();

    for candidate in inbox_candidates {
        let sender = normalize_conversation_sender(&candidate.message.posted_by);
        cached_inbox_senders.insert(candidate.message.id.clone(), sender.clone());
        let cutoff_field = candidate
            .message
            .consumed_at_ns
            .unwrap_or(candidate.message.posted_at_ns);
        let window_start_ns = summary_window_start_ns(cutoff_field);
        let key = (sender.clone(), window_start_ns);
        let accumulator = grouped.entry(key).or_insert_with(|| {
            session_summary_accumulator(
                &sender,
                window_start_ns,
                window_start_ns.saturating_add(SUMMARY_WINDOW_NS),
            )
        });
        accumulator.window_end_ns = accumulator.window_end_ns.max(cutoff_field);
        accumulator.source_count = accumulator.source_count.saturating_add(1);
        accumulator.inbox_message_count = accumulator.inbox_message_count.saturating_add(1);
        if accumulator.inbox_preview.is_empty() {
            accumulator.inbox_preview = truncate_to_chars(&candidate.message.body, 220);
        }
    }

    for candidate in outbox_candidates {
        let sender = resolve_outbox_sender(&candidate.message, &cached_inbox_senders);
        let window_start_ns = summary_window_start_ns(candidate.message.created_at_ns);
        let key = (sender.clone(), window_start_ns);
        let accumulator = grouped.entry(key).or_insert_with(|| {
            session_summary_accumulator(
                &sender,
                window_start_ns,
                window_start_ns.saturating_add(SUMMARY_WINDOW_NS),
            )
        });
        accumulator.window_end_ns = accumulator
            .window_end_ns
            .max(candidate.message.created_at_ns);
        accumulator.source_count = accumulator.source_count.saturating_add(1);
        accumulator.outbox_message_count = accumulator.outbox_message_count.saturating_add(1);
        if accumulator.outbox_preview.is_empty() {
            accumulator.outbox_preview = truncate_to_chars(&candidate.message.body, 220);
        }
    }

    let generated = u32::try_from(grouped.len()).unwrap_or(u32::MAX);
    for (_key, accumulator) in grouped {
        upsert_session_summary(accumulator, now_ns);
    }
    generated
}

fn delete_inbox_candidates(candidates: &[InboxCandidate]) -> u32 {
    let mut deleted = 0u32;
    for candidate in candidates {
        if !matches!(candidate.message.status, InboxMessageStatus::Consumed) {
            continue;
        }
        INBOX_MAP.with(|map| {
            map.borrow_mut().remove(&candidate.key);
        });
        INBOX_PENDING_QUEUE_MAP.with(|map| {
            map.borrow_mut()
                .remove(&inbox_pending_key(candidate.message.seq));
        });
        INBOX_STAGED_QUEUE_MAP.with(|map| {
            map.borrow_mut()
                .remove(&inbox_staged_key(candidate.message.seq));
        });
        deleted = deleted.saturating_add(1);
    }
    deleted
}

fn delete_outbox_candidates(candidates: &[OutboxCandidate]) -> u32 {
    let mut deleted = 0u32;
    OUTBOX_MAP.with(|map| {
        let mut outbox = map.borrow_mut();
        for candidate in candidates {
            if outbox.remove(&candidate.key).is_some() {
                deleted = deleted.saturating_add(1);
            }
        }
    });
    deleted
}

fn collect_prunable_turns(
    start_after: Option<&str>,
    budget: usize,
    turns_cutoff_ns: u64,
) -> (Vec<TurnCandidate>, Option<String>, bool) {
    if budget == 0 {
        return (Vec::new(), start_after.map(ToString::to_string), false);
    }

    let mut candidates = Vec::<TurnCandidate>::new();
    let mut last_scanned: Option<String> = None;
    let mut reached_end = true;
    let mut passed_start = start_after.is_none();

    TURN_MAP.with(|map| {
        for entry in map.borrow().iter() {
            if !passed_start {
                if start_after.is_some_and(|cursor| entry.key().as_str() <= cursor) {
                    continue;
                }
                passed_start = true;
            }

            let key = entry.key().clone();
            last_scanned = Some(key.clone());
            let Some(turn) = read_json::<TurnRecord>(Some(entry.value().as_slice())) else {
                continue;
            };
            if turn.created_at_ns > turns_cutoff_ns {
                continue;
            }
            candidates.push(TurnCandidate { key, turn });
            if candidates.len() >= budget {
                reached_end = false;
                break;
            }
        }
    });

    let next_cursor = if reached_end { None } else { last_scanned };
    (candidates, next_cursor, reached_end)
}

fn collect_prunable_transitions(
    start_after: Option<&str>,
    budget: usize,
    transitions_cutoff_ns: u64,
) -> (Vec<TransitionCandidate>, Option<String>, bool) {
    if budget == 0 {
        return (Vec::new(), start_after.map(ToString::to_string), false);
    }

    let mut candidates = Vec::<TransitionCandidate>::new();
    let mut last_scanned: Option<String> = None;
    let mut reached_end = true;
    let mut passed_start = start_after.is_none();

    TRANSITION_MAP.with(|map| {
        for entry in map.borrow().iter() {
            if !passed_start {
                if start_after.is_some_and(|cursor| entry.key().as_str() <= cursor) {
                    continue;
                }
                passed_start = true;
            }

            let key = entry.key().clone();
            last_scanned = Some(key.clone());
            let Some(transition) = read_json::<TransitionLogRecord>(Some(entry.value().as_slice()))
            else {
                continue;
            };
            if transition.occurred_at_ns > transitions_cutoff_ns {
                continue;
            }
            candidates.push(TransitionCandidate { key, transition });
            if candidates.len() >= budget {
                reached_end = false;
                break;
            }
        }
    });

    let next_cursor = if reached_end { None } else { last_scanned };
    (candidates, next_cursor, reached_end)
}

fn turn_summary_accumulator(window_start_ns: u64) -> TurnSummaryAccumulator {
    TurnSummaryAccumulator {
        window_start_ns,
        window_end_ns: window_start_ns.saturating_add(SUMMARY_WINDOW_NS),
        source_count: 0,
        turn_count: 0,
        transition_count: 0,
        tool_call_count: 0,
        succeeded_turn_count: 0,
        failed_turn_count: 0,
        tool_success_count: 0,
        tool_failure_count: 0,
        top_errors: Vec::new(),
    }
}

fn summarize_turn_and_transition_candidates(
    turn_candidates: &[TurnCandidate],
    transition_candidates: &[TransitionCandidate],
    tools_cutoff_ns: u64,
    now_ns: u64,
) -> (u32, Vec<String>) {
    if turn_candidates.is_empty() && transition_candidates.is_empty() {
        return (0, Vec::new());
    }

    let mut grouped = std::collections::BTreeMap::<u64, TurnSummaryAccumulator>::new();
    let mut tool_keys_to_delete = std::collections::BTreeSet::<String>::new();

    for candidate in turn_candidates {
        let window_start = summary_window_start_ns(candidate.turn.created_at_ns);
        let accumulator = grouped
            .entry(window_start)
            .or_insert_with(|| turn_summary_accumulator(window_start));
        accumulator.window_end_ns = accumulator.window_end_ns.max(candidate.turn.created_at_ns);
        accumulator.source_count = accumulator.source_count.saturating_add(1);
        accumulator.turn_count = accumulator.turn_count.saturating_add(1);
        if candidate.turn.error.is_some() {
            accumulator.failed_turn_count = accumulator.failed_turn_count.saturating_add(1);
        } else {
            accumulator.succeeded_turn_count = accumulator.succeeded_turn_count.saturating_add(1);
        }
        accumulate_error(&mut accumulator.top_errors, candidate.turn.error.as_deref());

        let tool_records = get_tools_for_turn(&candidate.turn.id);
        accumulator.tool_call_count = accumulator
            .tool_call_count
            .saturating_add(u32::try_from(tool_records.len()).unwrap_or(u32::MAX));
        for tool in &tool_records {
            if tool.success {
                accumulator.tool_success_count = accumulator.tool_success_count.saturating_add(1);
            } else {
                accumulator.tool_failure_count = accumulator.tool_failure_count.saturating_add(1);
            }
            accumulate_error(&mut accumulator.top_errors, tool.error.as_deref());
        }

        if candidate.turn.created_at_ns <= tools_cutoff_ns {
            tool_keys_to_delete.insert(format!("tools:{}", candidate.turn.id));
        }
    }

    for candidate in transition_candidates {
        let window_start = summary_window_start_ns(candidate.transition.occurred_at_ns);
        let accumulator = grouped
            .entry(window_start)
            .or_insert_with(|| turn_summary_accumulator(window_start));
        accumulator.window_end_ns = accumulator
            .window_end_ns
            .max(candidate.transition.occurred_at_ns);
        accumulator.source_count = accumulator.source_count.saturating_add(1);
        accumulator.transition_count = accumulator.transition_count.saturating_add(1);
        accumulate_error(
            &mut accumulator.top_errors,
            candidate.transition.error.as_deref(),
        );
    }

    let generated = u32::try_from(grouped.len()).unwrap_or(u32::MAX);
    for (_window_start, accumulator) in grouped {
        upsert_turn_window_summary(accumulator, now_ns);
    }

    (generated, tool_keys_to_delete.into_iter().collect())
}

fn delete_turn_candidates(candidates: &[TurnCandidate]) -> u32 {
    let mut deleted = 0u32;
    TURN_MAP.with(|map| {
        let mut turns = map.borrow_mut();
        for candidate in candidates {
            if turns.remove(&candidate.key).is_some() {
                deleted = deleted.saturating_add(1);
            }
        }
    });
    deleted
}

fn delete_transition_candidates(candidates: &[TransitionCandidate]) -> u32 {
    let mut deleted = 0u32;
    TRANSITION_MAP.with(|map| {
        let mut transitions = map.borrow_mut();
        for candidate in candidates {
            if transitions.remove(&candidate.key).is_some() {
                deleted = deleted.saturating_add(1);
            }
        }
    });
    deleted
}

fn delete_tool_candidates(keys: &[String]) -> u32 {
    let mut deleted = 0u32;
    TOOL_MAP.with(|map| {
        let mut tools = map.borrow_mut();
        for key in keys {
            if tools.remove(key).is_some() {
                deleted = deleted.saturating_add(1);
            }
        }
    });
    deleted
}

fn memory_namespace(key: &str) -> String {
    key.split('.').next().unwrap_or(key).trim().to_string()
}

fn update_memory_rollups(now_ns: u64) -> u32 {
    let cutoff_ns = now_ns.saturating_sub(MEMORY_ROLLUP_STALE_NS);
    let mut grouped = std::collections::BTreeMap::<String, Vec<MemoryFact>>::new();
    for fact in list_all_memory_facts(MAX_MEMORY_FACTS) {
        if fact.updated_at_ns > cutoff_ns {
            continue;
        }
        if is_critical_exact_memory_key(&fact.key) {
            continue;
        }
        let namespace = memory_namespace(&fact.key);
        if namespace.is_empty() {
            continue;
        }
        grouped.entry(namespace).or_default().push(fact);
    }

    if grouped.is_empty() {
        return 0;
    }

    let mut generated = 0u32;
    for (namespace, mut facts) in grouped {
        facts.sort_by(|left, right| {
            right
                .updated_at_ns
                .cmp(&left.updated_at_ns)
                .then_with(|| left.key.cmp(&right.key))
        });
        let source_count = u32::try_from(facts.len()).unwrap_or(u32::MAX);
        let selected = facts
            .iter()
            .take(MAX_MEMORY_ROLLUP_FACTS_PER_NAMESPACE)
            .collect::<Vec<_>>();
        if selected.is_empty() {
            continue;
        }
        let window_start_ns = selected
            .iter()
            .map(|fact| fact.updated_at_ns)
            .min()
            .unwrap_or(now_ns);
        let window_end_ns = selected
            .iter()
            .map(|fact| fact.updated_at_ns)
            .max()
            .unwrap_or(now_ns);
        let source_keys = selected
            .iter()
            .take(MAX_MEMORY_ROLLUP_SOURCE_KEYS)
            .map(|fact| fact.key.clone())
            .collect::<Vec<_>>();
        let canonical_value = selected
            .iter()
            .map(|fact| format!("{}={}", fact.key, truncate_to_chars(&fact.value, 80)))
            .collect::<Vec<_>>()
            .join("; ");

        let rollup = MemoryRollup {
            namespace: namespace.clone(),
            window_start_ns,
            window_end_ns,
            source_count,
            source_keys,
            canonical_value,
            generated_at_ns: now_ns,
        };
        MEMORY_ROLLUP_MAP.with(|map| {
            map.borrow_mut().insert(namespace, encode_json(&rollup));
        });
        generated = generated.saturating_add(1);
    }
    enforce_memory_rollup_cap();
    generated
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

fn truncate_text_field(value: &str, max_chars: usize) -> String {
    let total_chars = value.chars().count();
    if total_chars <= max_chars {
        return value.to_string();
    }
    if max_chars == 0 {
        return String::new();
    }

    let truncated = total_chars.saturating_sub(max_chars);
    let digest = Keccak256::digest(value.as_bytes());
    let digest_hex = hex::encode(digest);
    let marker = format!(
        "...[truncated {truncated} chars keccak:{}]",
        &digest_hex[..16]
    );
    let marker_len = marker.chars().count();
    if marker_len >= max_chars {
        return marker.chars().take(max_chars).collect();
    }

    let keep_chars = max_chars.saturating_sub(marker_len);
    let prefix_chars = keep_chars / 2;
    let suffix_chars = keep_chars.saturating_sub(prefix_chars);
    let prefix = value.chars().take(prefix_chars).collect::<String>();
    let suffix = value
        .chars()
        .rev()
        .take(suffix_chars)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{prefix}{marker}{suffix}")
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

#[cfg(feature = "canbench-rs")]
mod canbench_pilots {
    use super::*;
    use canbench_rs::bench;

    const BENCH_DATASET_SIZE: u64 = 2_000;
    const BENCH_LIST_LIMIT: usize = 50;
    const BENCH_PRUNE_NOW_NS: u64 = 90_000_000_000;

    fn clear_inbox_maps() {
        let inbox_keys = INBOX_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        INBOX_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in inbox_keys {
                map_ref.remove(&key);
            }
        });

        let pending_keys = INBOX_PENDING_QUEUE_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        INBOX_PENDING_QUEUE_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in pending_keys {
                map_ref.remove(&key);
            }
        });

        let staged_keys = INBOX_STAGED_QUEUE_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        INBOX_STAGED_QUEUE_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in staged_keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_outbox_map() {
        let keys = OUTBOX_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        OUTBOX_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_job_map() {
        let keys = JOB_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        JOB_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_dedupe_map() {
        let keys = DEDUPE_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        DEDUPE_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_summary_maps() {
        let session_keys = SESSION_SUMMARY_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        SESSION_SUMMARY_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in session_keys {
                map_ref.remove(&key);
            }
        });

        let turn_keys = TURN_WINDOW_SUMMARY_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        TURN_WINDOW_SUMMARY_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in turn_keys {
                map_ref.remove(&key);
            }
        });

        let rollup_keys = MEMORY_ROLLUP_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        MEMORY_ROLLUP_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in rollup_keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_turn_transition_tool_maps() {
        let turn_keys = TURN_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        TURN_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in turn_keys {
                map_ref.remove(&key);
            }
        });

        let transition_keys = TRANSITION_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        TRANSITION_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in transition_keys {
                map_ref.remove(&key);
            }
        });

        let tool_keys = TOOL_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        TOOL_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in tool_keys {
                map_ref.remove(&key);
            }
        });
    }

    fn seed_inbox_messages(count: u64) {
        init_storage();
        clear_inbox_maps();
        for seq in 1..=count {
            let id = format!("inbox:{seq:020}");
            let message = InboxMessage {
                id: id.clone(),
                seq,
                body: format!("seed inbox message {seq}"),
                posted_at_ns: seq,
                posted_by: "bench".to_string(),
                status: InboxMessageStatus::Pending,
                staged_at_ns: None,
                consumed_at_ns: None,
            };
            INBOX_MAP.with(|map| {
                map.borrow_mut().insert(id, encode_json(&message));
            });
        }
        save_runtime_u64(INBOX_SEQ_KEY, count);
    }

    fn seed_outbox_messages(count: u64) {
        init_storage();
        clear_outbox_map();
        for seq in 1..=count {
            let id = format!("outbox:{seq:020}");
            let message = OutboxMessage {
                id: id.clone(),
                seq,
                turn_id: format!("turn-{seq}"),
                body: format!("seed outbox message {seq}"),
                created_at_ns: seq,
                source_inbox_ids: Vec::new(),
            };
            OUTBOX_MAP.with(|map| {
                map.borrow_mut().insert(id, encode_json(&message));
            });
        }
        save_runtime_u64(OUTBOX_SEQ_KEY, count);
    }

    fn seed_jobs(count: u64) {
        init_storage();
        clear_job_map();
        for seq in 1..=count {
            let job = ScheduledJob {
                id: format!("job:{seq:020}:{seq:020}"),
                kind: TaskKind::PollInbox,
                lane: TaskLane::Mutating,
                dedupe_key: format!("PollInbox:{seq}"),
                priority: 1,
                created_at_ns: seq,
                scheduled_for_ns: seq,
                started_at_ns: None,
                finished_at_ns: None,
                status: JobStatus::Pending,
                attempts: 0,
                max_attempts: 3,
                last_error: None,
            };
            JOB_MAP.with(|map| {
                map.borrow_mut().insert(job.id.clone(), encode_json(&job));
            });
        }
    }

    fn seed_terminal_jobs_for_prune(count: u64, now_ns: u64) {
        init_storage();
        clear_job_map();
        clear_dedupe_map();
        save_retention_maintenance_runtime(&RetentionMaintenanceRuntime {
            next_run_after_ns: now_ns,
            ..RetentionMaintenanceRuntime::default()
        });
        for seq in 1..=count {
            let scheduled_for_ns = now_ns.saturating_sub(30_000_000_000).saturating_sub(seq);
            let dedupe_key = format!("PollInbox:{scheduled_for_ns}");
            let job = ScheduledJob {
                id: format!("job:{seq:020}:{scheduled_for_ns:020}"),
                kind: TaskKind::PollInbox,
                lane: TaskLane::Mutating,
                dedupe_key: dedupe_key.clone(),
                priority: 1,
                created_at_ns: scheduled_for_ns,
                scheduled_for_ns,
                started_at_ns: Some(scheduled_for_ns.saturating_add(1)),
                finished_at_ns: Some(scheduled_for_ns.saturating_add(2)),
                status: JobStatus::Succeeded,
                attempts: 1,
                max_attempts: 3,
                last_error: None,
            };
            JOB_MAP.with(|map| {
                map.borrow_mut().insert(job.id.clone(), encode_json(&job));
            });
            DEDUPE_MAP.with(|map| {
                map.borrow_mut()
                    .insert(dedupe_index_key(&dedupe_key), job.id.clone().into_bytes());
            });
        }
    }

    fn seed_consumed_inbox_outbox_for_summary(count: u64, now_ns: u64) {
        init_storage();
        clear_inbox_maps();
        clear_outbox_map();
        clear_summary_maps();
        for seq in 1..=count {
            let inbox_id = format!("inbox:{seq:020}");
            INBOX_MAP.with(|map| {
                map.borrow_mut().insert(
                    inbox_id.clone(),
                    encode_json(&InboxMessage {
                        id: inbox_id.clone(),
                        seq,
                        body: format!("bench consumed inbox {seq}"),
                        posted_at_ns: now_ns.saturating_sub(20_000_000_000),
                        posted_by: format!("0x{seq:040x}"),
                        status: InboxMessageStatus::Consumed,
                        staged_at_ns: Some(now_ns.saturating_sub(19_000_000_000)),
                        consumed_at_ns: Some(now_ns.saturating_sub(18_000_000_000)),
                    }),
                );
            });

            let outbox_id = format!("outbox:{seq:020}");
            OUTBOX_MAP.with(|map| {
                map.borrow_mut().insert(
                    outbox_id.clone(),
                    encode_json(&OutboxMessage {
                        id: outbox_id,
                        seq,
                        turn_id: format!("turn-{seq}"),
                        body: format!("bench outbox {seq}"),
                        created_at_ns: now_ns.saturating_sub(17_000_000_000),
                        source_inbox_ids: vec![inbox_id],
                    }),
                );
            });
        }
    }

    fn seed_turn_transition_tool_for_summary(count: u64, now_ns: u64) {
        init_storage();
        clear_turn_transition_tool_maps();
        clear_summary_maps();
        for seq in 1..=count {
            let created_at_ns = now_ns.saturating_sub(20_000_000_000).saturating_sub(seq);
            let turn = TurnRecord {
                id: format!("turn-{seq}"),
                created_at_ns,
                state_from: AgentState::Sleeping,
                state_to: AgentState::Sleeping,
                source_events: 0,
                tool_call_count: 1,
                input_summary: "bench".to_string(),
                inner_dialogue: Some("bench".to_string()),
                inference_round_count: 1,
                continuation_stop_reason: crate::domain::types::ContinuationStopReason::None,
                error: if seq.is_multiple_of(10) {
                    Some("bench error".to_string())
                } else {
                    None
                },
            };
            TURN_MAP.with(|map| {
                map.borrow_mut().insert(
                    format!("{created_at_ns:020}-{}", turn.id),
                    encode_json(&turn),
                );
            });
            TRANSITION_MAP.with(|map| {
                map.borrow_mut().insert(
                    format!("{seq:020}-{seq:020}"),
                    encode_json(&TransitionLogRecord {
                        id: format!("{seq:020}-{seq:020}"),
                        turn_id: turn.id.clone(),
                        from_state: AgentState::Sleeping,
                        to_state: AgentState::Inferring,
                        event: "TimerTick".to_string(),
                        error: None,
                        occurred_at_ns: created_at_ns,
                    }),
                );
            });
            TOOL_MAP.with(|map| {
                map.borrow_mut().insert(
                    format!("tools:{}", turn.id),
                    encode_json(&vec![ToolCallRecord {
                        turn_id: turn.id.clone(),
                        tool: "evm_read".to_string(),
                        args_json: "{}".to_string(),
                        output: "ok".to_string(),
                        success: true,
                        error: None,
                    }]),
                );
            });
        }
    }

    #[bench(raw)]
    fn bench_list_inbox_messages_recent() -> canbench_rs::BenchResult {
        seed_inbox_messages(BENCH_DATASET_SIZE);
        canbench_rs::bench_fn(|| {
            std::hint::black_box(list_inbox_messages(BENCH_LIST_LIMIT));
        })
    }

    #[bench(raw)]
    fn bench_list_outbox_messages_recent() -> canbench_rs::BenchResult {
        seed_outbox_messages(BENCH_DATASET_SIZE);
        canbench_rs::bench_fn(|| {
            std::hint::black_box(list_outbox_messages(BENCH_LIST_LIMIT));
        })
    }

    #[bench(raw)]
    fn bench_list_recent_jobs() -> canbench_rs::BenchResult {
        seed_jobs(BENCH_DATASET_SIZE);
        canbench_rs::bench_fn(|| {
            std::hint::black_box(list_recent_jobs(BENCH_LIST_LIMIT));
        })
    }

    #[bench(raw)]
    fn bench_prune_jobs_and_dedupe_batch_25() -> canbench_rs::BenchResult {
        seed_terminal_jobs_for_prune(BENCH_DATASET_SIZE, BENCH_PRUNE_NOW_NS);
        let _ = set_retention_config(RetentionConfig {
            jobs_max_age_secs: 1,
            jobs_max_records: 0,
            dedupe_max_age_secs: 1,
            turns_max_age_secs: 7 * 24 * 60 * 60,
            transitions_max_age_secs: 7 * 24 * 60 * 60,
            tools_max_age_secs: 7 * 24 * 60 * 60,
            inbox_max_age_secs: 14 * 24 * 60 * 60,
            outbox_max_age_secs: 14 * 24 * 60 * 60,
            maintenance_batch_size: 25,
            maintenance_interval_secs: 60,
        });
        canbench_rs::bench_fn(|| {
            std::hint::black_box(run_retention_maintenance_once(BENCH_PRUNE_NOW_NS));
        })
    }

    #[bench(raw)]
    fn bench_prune_jobs_and_dedupe_batch_100() -> canbench_rs::BenchResult {
        seed_terminal_jobs_for_prune(BENCH_DATASET_SIZE, BENCH_PRUNE_NOW_NS);
        let _ = set_retention_config(RetentionConfig {
            jobs_max_age_secs: 1,
            jobs_max_records: 0,
            dedupe_max_age_secs: 1,
            turns_max_age_secs: 7 * 24 * 60 * 60,
            transitions_max_age_secs: 7 * 24 * 60 * 60,
            tools_max_age_secs: 7 * 24 * 60 * 60,
            inbox_max_age_secs: 14 * 24 * 60 * 60,
            outbox_max_age_secs: 14 * 24 * 60 * 60,
            maintenance_batch_size: 100,
            maintenance_interval_secs: 60,
        });
        canbench_rs::bench_fn(|| {
            std::hint::black_box(run_retention_maintenance_once(BENCH_PRUNE_NOW_NS));
        })
    }

    #[bench(raw)]
    fn bench_summarize_inbox_outbox_batch_50() -> canbench_rs::BenchResult {
        seed_consumed_inbox_outbox_for_summary(BENCH_DATASET_SIZE, BENCH_PRUNE_NOW_NS);
        canbench_rs::bench_fn(|| {
            let protected = std::collections::BTreeSet::new();
            let (inbox, _, _) = collect_prunable_inbox(None, 50, BENCH_PRUNE_NOW_NS, &protected);
            let (outbox, _, _) = collect_prunable_outbox(None, 50, BENCH_PRUNE_NOW_NS, &protected);
            std::hint::black_box(summarize_inbox_outbox_candidates(
                &inbox,
                &outbox,
                BENCH_PRUNE_NOW_NS,
            ));
        })
    }

    #[bench(raw)]
    fn bench_prune_inbox_outbox_batch_50() -> canbench_rs::BenchResult {
        seed_consumed_inbox_outbox_for_summary(BENCH_DATASET_SIZE, BENCH_PRUNE_NOW_NS);
        canbench_rs::bench_fn(|| {
            let protected = std::collections::BTreeSet::new();
            let (inbox, _, _) = collect_prunable_inbox(None, 50, BENCH_PRUNE_NOW_NS, &protected);
            let (outbox, _, _) = collect_prunable_outbox(None, 50, BENCH_PRUNE_NOW_NS, &protected);
            std::hint::black_box(delete_inbox_candidates(&inbox));
            std::hint::black_box(delete_outbox_candidates(&outbox));
        })
    }

    #[bench(raw)]
    fn bench_summarize_turn_transition_batch_50() -> canbench_rs::BenchResult {
        seed_turn_transition_tool_for_summary(BENCH_DATASET_SIZE, BENCH_PRUNE_NOW_NS);
        canbench_rs::bench_fn(|| {
            let (turns, _, _) = collect_prunable_turns(None, 50, BENCH_PRUNE_NOW_NS);
            let (transitions, _, _) = collect_prunable_transitions(None, 50, BENCH_PRUNE_NOW_NS);
            std::hint::black_box(summarize_turn_and_transition_candidates(
                &turns,
                &transitions,
                BENCH_PRUNE_NOW_NS,
                BENCH_PRUNE_NOW_NS,
            ));
        })
    }

    #[bench(raw)]
    fn bench_prune_turn_transition_batch_50() -> canbench_rs::BenchResult {
        seed_turn_transition_tool_for_summary(BENCH_DATASET_SIZE, BENCH_PRUNE_NOW_NS);
        canbench_rs::bench_fn(|| {
            let (turns, _, _) = collect_prunable_turns(None, 50, BENCH_PRUNE_NOW_NS);
            let (transitions, _, _) = collect_prunable_transitions(None, 50, BENCH_PRUNE_NOW_NS);
            let (_, tool_keys) = summarize_turn_and_transition_candidates(
                &turns,
                &transitions,
                BENCH_PRUNE_NOW_NS,
                BENCH_PRUNE_NOW_NS,
            );
            std::hint::black_box(delete_turn_candidates(&turns));
            std::hint::black_box(delete_transition_candidates(&transitions));
            std::hint::black_box(delete_tool_candidates(&tool_keys));
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{
        AbiArtifact, AbiArtifactKey, AbiFunctionSpec, AbiTypeSpec, ConversationEntry,
        InboxMessageStatus, MemoryFact, PromptLayer, RetentionConfig, RuntimeSnapshot,
        StoragePressureLevel, StrategyKillSwitchState, StrategyOutcomeEvent, StrategyOutcomeKind,
        StrategyTemplate, StrategyTemplateKey, TaskKind, TaskLane, TemplateActivationState,
        TemplateRevocationState, TemplateStatus, TemplateVersion, WalletBalanceSnapshot,
        WalletBalanceSyncConfig,
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

    fn clear_session_summary_map() {
        let keys = SESSION_SUMMARY_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        SESSION_SUMMARY_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_turn_window_summary_map() {
        let keys = TURN_WINDOW_SUMMARY_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        TURN_WINDOW_SUMMARY_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_memory_rollup_map() {
        let keys = MEMORY_ROLLUP_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        MEMORY_ROLLUP_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_strategy_maps_for_tests() {
        let template_keys = STRATEGY_TEMPLATE_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        STRATEGY_TEMPLATE_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in template_keys {
                map_ref.remove(&key);
            }
        });

        let template_index_keys = STRATEGY_TEMPLATE_INDEX_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        STRATEGY_TEMPLATE_INDEX_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in template_index_keys {
                map_ref.remove(&key);
            }
        });

        let abi_keys = ABI_ARTIFACT_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        ABI_ARTIFACT_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in abi_keys {
                map_ref.remove(&key);
            }
        });

        let abi_index_keys = ABI_ARTIFACT_INDEX_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        ABI_ARTIFACT_INDEX_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in abi_index_keys {
                map_ref.remove(&key);
            }
        });

        let activation_keys = STRATEGY_ACTIVATION_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        STRATEGY_ACTIVATION_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in activation_keys {
                map_ref.remove(&key);
            }
        });

        let revocation_keys = STRATEGY_REVOCATION_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        STRATEGY_REVOCATION_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in revocation_keys {
                map_ref.remove(&key);
            }
        });

        let kill_switch_keys = STRATEGY_KILL_SWITCH_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        STRATEGY_KILL_SWITCH_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in kill_switch_keys {
                map_ref.remove(&key);
            }
        });

        let outcome_keys = STRATEGY_OUTCOME_STATS_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        STRATEGY_OUTCOME_STATS_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in outcome_keys {
                map_ref.remove(&key);
            }
        });

        let budget_keys = STRATEGY_BUDGET_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        STRATEGY_BUDGET_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in budget_keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_inbox_maps_for_tests() {
        let inbox_keys = INBOX_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        INBOX_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in inbox_keys {
                map_ref.remove(&key);
            }
        });

        let pending_keys = INBOX_PENDING_QUEUE_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        INBOX_PENDING_QUEUE_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in pending_keys {
                map_ref.remove(&key);
            }
        });

        let staged_keys = INBOX_STAGED_QUEUE_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        INBOX_STAGED_QUEUE_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in staged_keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_outbox_map_for_tests() {
        let keys = OUTBOX_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        OUTBOX_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in keys {
                map_ref.remove(&key);
            }
        });
    }

    fn clear_turn_transition_tool_maps_for_tests() {
        let turn_keys = TURN_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        TURN_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in turn_keys {
                map_ref.remove(&key);
            }
        });

        let transition_keys = TRANSITION_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        TRANSITION_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in transition_keys {
                map_ref.remove(&key);
            }
        });

        let tool_keys = TOOL_MAP.with(|map| {
            map.borrow()
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>()
        });
        TOOL_MAP.with(|map| {
            let mut map_ref = map.borrow_mut();
            for key in tool_keys {
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

        complete_job("lease:first", JobStatus::Succeeded, None, 3, None);
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
    fn complete_job_retries_until_max_attempts_then_terminal_failure() {
        init_storage();
        seed_task_runtime(TaskKind::PollInbox, 0);

        let job_id = enqueue_job_if_absent(
            TaskKind::PollInbox,
            TaskLane::Mutating,
            "PollInbox:retry-policy".to_string(),
            0,
            0,
        )
        .expect("job should enqueue");
        let _ = pop_next_pending_job(TaskLane::Mutating, 0).expect("job should dequeue");

        complete_job(
            &job_id,
            JobStatus::Failed,
            Some("rpc timeout".to_string()),
            10,
            Some(2),
        );
        let after_first = get_job_by_id(&job_id).expect("job should persist");
        assert_eq!(after_first.status, JobStatus::Pending);
        assert_eq!(after_first.attempts, 1);
        assert_eq!(after_first.scheduled_for_ns, 2_000_000_010);
        assert!(
            pop_next_pending_job(TaskLane::Mutating, 2_000_000_009).is_none(),
            "retry should respect backoff delay"
        );
        let _ = pop_next_pending_job(TaskLane::Mutating, 2_000_000_010)
            .expect("retry should become due");

        complete_job(
            &job_id,
            JobStatus::Failed,
            Some("rpc timeout".to_string()),
            20,
            Some(0),
        );
        let after_second = get_job_by_id(&job_id).expect("job should persist");
        assert_eq!(after_second.status, JobStatus::Pending);
        assert_eq!(after_second.attempts, 2);
        let _ =
            pop_next_pending_job(TaskLane::Mutating, 20).expect("immediate retry should enqueue");

        complete_job(
            &job_id,
            JobStatus::Failed,
            Some("rpc timeout".to_string()),
            30,
            Some(0),
        );
        let final_job = get_job_by_id(&job_id).expect("job should persist");
        assert_eq!(final_job.status, JobStatus::Failed);
        assert_eq!(final_job.attempts, 3);
        assert!(
            pop_next_pending_job(TaskLane::Mutating, 30).is_none(),
            "retry queue must be empty once max attempts are exhausted"
        );
        let runtime = get_task_runtime(&TaskKind::PollInbox);
        assert!(runtime.pending_job_id.is_none());
    }

    #[test]
    fn list_recent_jobs_prefers_key_recency_over_created_at_field() {
        init_storage();
        save_job(&ScheduledJob {
            id: "job:00000000000000000001:00000000000000000001".to_string(),
            kind: TaskKind::PollInbox,
            lane: TaskLane::Mutating,
            dedupe_key: "PollInbox:1".to_string(),
            priority: 1,
            created_at_ns: 999,
            scheduled_for_ns: 1,
            started_at_ns: None,
            finished_at_ns: None,
            status: JobStatus::Pending,
            attempts: 0,
            max_attempts: 3,
            last_error: None,
        });
        save_job(&ScheduledJob {
            id: "job:00000000000000000002:00000000000000000002".to_string(),
            kind: TaskKind::PollInbox,
            lane: TaskLane::Mutating,
            dedupe_key: "PollInbox:2".to_string(),
            priority: 1,
            created_at_ns: 100,
            scheduled_for_ns: 2,
            started_at_ns: None,
            finished_at_ns: None,
            status: JobStatus::Pending,
            attempts: 0,
            max_attempts: 3,
            last_error: None,
        });

        let listed = list_recent_jobs(2);
        assert_eq!(listed.len(), 2);
        assert_eq!(
            listed[0].id,
            "job:00000000000000000002:00000000000000000002"
        );
        assert_eq!(
            listed[1].id,
            "job:00000000000000000001:00000000000000000001"
        );
    }

    #[test]
    fn retention_config_persists_and_validates() {
        init_storage();

        let defaults = retention_config();
        assert!(defaults.jobs_max_age_secs > 0);
        assert!(defaults.jobs_max_records > 0);
        assert!(defaults.dedupe_max_age_secs > 0);
        assert!(defaults.maintenance_batch_size > 0);
        assert!(defaults.maintenance_interval_secs > 0);

        let updated = RetentionConfig {
            jobs_max_age_secs: 30,
            jobs_max_records: 12,
            dedupe_max_age_secs: 60,
            turns_max_age_secs: 90,
            transitions_max_age_secs: 91,
            tools_max_age_secs: 92,
            inbox_max_age_secs: 120,
            outbox_max_age_secs: 121,
            maintenance_batch_size: 3,
            maintenance_interval_secs: 45,
        };
        let stored = set_retention_config(updated.clone()).expect("retention config should store");
        assert_eq!(stored, updated);
        assert_eq!(retention_config(), updated);

        let invalid = set_retention_config(RetentionConfig {
            maintenance_batch_size: 0,
            ..RetentionConfig::default()
        });
        assert!(invalid.is_err(), "batch size zero must be rejected");
    }

    #[test]
    fn retention_prune_is_checkpointed_idempotent_and_queue_safe() {
        init_storage();
        let now_ns = 100_000_000_000u64;
        set_retention_config(RetentionConfig {
            jobs_max_age_secs: 1,
            jobs_max_records: 0,
            dedupe_max_age_secs: 1,
            maintenance_batch_size: 1,
            maintenance_interval_secs: 1,
            ..RetentionConfig::default()
        })
        .expect("retention config should store");

        post_inbox_message(
            "queued-one".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )
        .expect("first inbox post should succeed");
        post_inbox_message(
            "queued-two".to_string(),
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        )
        .expect("second inbox post should succeed");
        assert_eq!(
            stage_pending_inbox_messages(1, now_ns.saturating_sub(10)),
            1,
            "one inbox item should be staged for queue safety assertions"
        );
        let inbox_before = inbox_stats();

        for seq in 1..=3u64 {
            let job_id = format!(
                "job:{seq:020}:{:020}",
                now_ns.saturating_sub(20_000_000_000)
            );
            save_job(&ScheduledJob {
                id: job_id.clone(),
                kind: TaskKind::PollInbox,
                lane: TaskLane::Mutating,
                dedupe_key: format!("PollInbox:{}", now_ns.saturating_sub(20_000_000_000 + seq)),
                priority: 1,
                created_at_ns: now_ns.saturating_sub(20_000_000_000),
                scheduled_for_ns: now_ns.saturating_sub(20_000_000_000),
                started_at_ns: Some(now_ns.saturating_sub(19_000_000_000)),
                finished_at_ns: Some(now_ns.saturating_sub(18_000_000_000)),
                status: JobStatus::Succeeded,
                attempts: 1,
                max_attempts: 3,
                last_error: None,
            });
            DEDUPE_MAP.with(|map| {
                map.borrow_mut().insert(
                    dedupe_index_key(&format!(
                        "PollInbox:{}",
                        now_ns.saturating_sub(20_000_000_000 + seq)
                    )),
                    job_id.into_bytes(),
                );
            });
        }

        save_job(&ScheduledJob {
            id: "job:00000000000000000099:00000000000000000099".to_string(),
            kind: TaskKind::PollInbox,
            lane: TaskLane::Mutating,
            dedupe_key: "PollInbox:999".to_string(),
            priority: 0,
            created_at_ns: now_ns,
            scheduled_for_ns: now_ns,
            started_at_ns: None,
            finished_at_ns: None,
            status: JobStatus::Pending,
            attempts: 0,
            max_attempts: 3,
            last_error: None,
        });
        DEDUPE_MAP.with(|map| {
            map.borrow_mut().insert(
                dedupe_index_key("PollInbox:999"),
                b"job:00000000000000000099:00000000000000000099".to_vec(),
            );
            map.borrow_mut().insert(
                dedupe_index_key(&format!(
                    "PollInbox:{}",
                    now_ns.saturating_sub(30_000_000_000)
                )),
                b"job:missing".to_vec(),
            );
        });

        let first = run_retention_maintenance_once(now_ns);
        assert_eq!(first.deleted_jobs, 1, "batch budget should cap first run");
        let runtime_after_first = retention_maintenance_runtime();
        assert!(
            runtime_after_first.job_scan_cursor.is_some()
                || runtime_after_first.dedupe_scan_cursor.is_some(),
            "first bounded run should persist a checkpoint cursor"
        );

        let second = run_retention_maintenance_once(now_ns);
        assert!(
            second.deleted_jobs <= 1,
            "second run must continue respecting the same delete budget"
        );
        let third = run_retention_maintenance_once(now_ns);
        assert!(
            third.deleted_jobs <= 1,
            "third run must continue respecting the same delete budget"
        );

        let fourth = run_retention_maintenance_once(now_ns);
        assert_eq!(
            fourth.deleted_jobs, 0,
            "re-running maintenance after convergence should be idempotent"
        );

        let remaining_jobs = list_recent_jobs(200);
        assert!(
            remaining_jobs.iter().all(|job| !job.is_terminal()
                || job.scheduled_for_ns >= now_ns.saturating_sub(1_000_000_000)),
            "old terminal jobs should be pruned while non-terminal/fresh jobs remain"
        );
        assert!(
            remaining_jobs
                .iter()
                .any(|job| job.id == "job:00000000000000000099:00000000000000000099"),
            "pending jobs must never be pruned by retention"
        );

        let inbox_after = inbox_stats();
        assert_eq!(inbox_before.pending_count, inbox_after.pending_count);
        assert_eq!(inbox_before.staged_count, inbox_after.staged_count);
        assert_eq!(inbox_before.consumed_count, inbox_after.consumed_count);
    }

    #[test]
    fn retention_summarizes_then_prunes_inbox_and_outbox_with_conversation_guardrail() {
        init_storage();
        clear_inbox_maps_for_tests();
        clear_outbox_map_for_tests();
        clear_conversation_map();
        clear_session_summary_map();

        let now_ns = 200_000_000_000u64;
        let old_ns = now_ns.saturating_sub(20_000_000_000);
        set_retention_config(RetentionConfig {
            inbox_max_age_secs: 1,
            outbox_max_age_secs: 1,
            maintenance_batch_size: 50,
            maintenance_interval_secs: 1,
            ..RetentionConfig::default()
        })
        .expect("retention config should store");

        let protected_id = "inbox:00000000000000000001".to_string();
        let prune_id = "inbox:00000000000000000002".to_string();
        let protected_sender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let prune_sender = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();

        INBOX_MAP.with(|map| {
            map.borrow_mut().insert(
                protected_id.clone(),
                encode_json(&InboxMessage {
                    id: protected_id.clone(),
                    seq: 1,
                    body: "protected consumed".to_string(),
                    posted_at_ns: old_ns,
                    posted_by: protected_sender.clone(),
                    status: InboxMessageStatus::Consumed,
                    staged_at_ns: Some(old_ns),
                    consumed_at_ns: Some(old_ns),
                }),
            );
            map.borrow_mut().insert(
                prune_id.clone(),
                encode_json(&InboxMessage {
                    id: prune_id.clone(),
                    seq: 2,
                    body: "prune consumed".to_string(),
                    posted_at_ns: old_ns,
                    posted_by: prune_sender.clone(),
                    status: InboxMessageStatus::Consumed,
                    staged_at_ns: Some(old_ns),
                    consumed_at_ns: Some(old_ns),
                }),
            );
        });

        append_conversation_entry(
            &protected_sender,
            ConversationEntry {
                inbox_message_id: protected_id.clone(),
                sender_body: "protected consumed".to_string(),
                agent_reply: "ack".to_string(),
                turn_id: "turn-protected".to_string(),
                timestamp_ns: old_ns,
            },
        );

        OUTBOX_MAP.with(|map| {
            map.borrow_mut().insert(
                "outbox:00000000000000000001".to_string(),
                encode_json(&OutboxMessage {
                    id: "outbox:00000000000000000001".to_string(),
                    seq: 1,
                    turn_id: "turn-protected".to_string(),
                    body: "protected outbox".to_string(),
                    created_at_ns: old_ns,
                    source_inbox_ids: vec![protected_id.clone()],
                }),
            );
            map.borrow_mut().insert(
                "outbox:00000000000000000002".to_string(),
                encode_json(&OutboxMessage {
                    id: "outbox:00000000000000000002".to_string(),
                    seq: 2,
                    turn_id: "turn-pruned".to_string(),
                    body: "pruned outbox".to_string(),
                    created_at_ns: old_ns,
                    source_inbox_ids: vec![prune_id.clone()],
                }),
            );
        });

        let stats = run_retention_maintenance_once(now_ns);
        assert_eq!(
            stats.deleted_inbox, 1,
            "only unprotected consumed inbox should prune"
        );
        assert_eq!(
            stats.deleted_outbox, 1,
            "only unprotected outbox should prune"
        );
        assert!(
            stats.generated_session_summaries >= 1,
            "summary should be persisted before deletion"
        );
        assert!(
            get_inbox_message_by_id(&protected_id).is_some(),
            "conversation-protected inbox message must remain"
        );
        assert!(
            get_inbox_message_by_id(&prune_id).is_none(),
            "unprotected consumed inbox message should be pruned"
        );
        let summaries = list_session_summaries(10);
        assert!(
            summaries
                .iter()
                .any(|summary| summary.sender == prune_sender),
            "summary store should retain provenance for pruned sender history"
        );
    }

    #[test]
    fn retention_summarizes_then_prunes_turn_transition_and_tools() {
        init_storage();
        clear_turn_transition_tool_maps_for_tests();
        clear_turn_window_summary_map();

        let now_ns = 300_000_000_000u64;
        let old_ns = now_ns.saturating_sub(20_000_000_000);
        set_retention_config(RetentionConfig {
            turns_max_age_secs: 1,
            transitions_max_age_secs: 1,
            tools_max_age_secs: 1,
            maintenance_batch_size: 50,
            maintenance_interval_secs: 1,
            ..RetentionConfig::default()
        })
        .expect("retention config should store");

        let turn = TurnRecord {
            id: "turn-old".to_string(),
            created_at_ns: old_ns,
            state_from: AgentState::Sleeping,
            state_to: AgentState::Sleeping,
            source_events: 0,
            tool_call_count: 1,
            input_summary: "old turn".to_string(),
            inner_dialogue: Some("dialogue".to_string()),
            inference_round_count: 1,
            continuation_stop_reason: crate::domain::types::ContinuationStopReason::None,
            error: Some("tool execution reported failures".to_string()),
        };
        TURN_MAP.with(|map| {
            map.borrow_mut()
                .insert(format!("{:020}-{}", old_ns, turn.id), encode_json(&turn));
        });

        TRANSITION_MAP.with(|map| {
            map.borrow_mut().insert(
                "00000000000000000001-00000000000000000001".to_string(),
                encode_json(&TransitionLogRecord {
                    id: "00000000000000000001-00000000000000000001".to_string(),
                    turn_id: turn.id.clone(),
                    from_state: AgentState::Sleeping,
                    to_state: AgentState::Inferring,
                    event: "TimerTick".to_string(),
                    error: Some("transition error".to_string()),
                    occurred_at_ns: old_ns,
                }),
            );
        });

        TOOL_MAP.with(|map| {
            map.borrow_mut().insert(
                format!("tools:{}", turn.id),
                encode_json(&vec![ToolCallRecord {
                    turn_id: turn.id.clone(),
                    tool: "evm_read".to_string(),
                    args_json: "{}".to_string(),
                    output: "rpc timeout".to_string(),
                    success: false,
                    error: Some("rpc timeout".to_string()),
                }]),
            );
        });

        let stats = run_retention_maintenance_once(now_ns);
        assert_eq!(
            stats.deleted_turns, 1,
            "old turn should prune after summary"
        );
        assert_eq!(
            stats.deleted_transitions, 1,
            "old transition should prune after summary"
        );
        assert_eq!(
            stats.deleted_tools, 1,
            "tool records should prune only with summarized/pruned turns"
        );
        assert!(
            stats.generated_turn_window_summaries >= 1,
            "turn-window summaries should be generated before deletion"
        );
        assert!(
            list_turn_window_summaries(10)
                .iter()
                .any(|summary| summary.turn_count >= 1 && summary.tool_call_count >= 1),
            "turn summary should retain aggregate tool provenance"
        );
    }

    #[test]
    fn context_memory_prefers_critical_raw_and_uses_rollups_when_raw_budget_is_full() {
        init_storage();
        clear_memory_rollup_map();

        let now_ns = 200_000_000_000_000u64;
        for idx in 0..16u64 {
            set_memory_fact(&MemoryFact {
                key: format!("strategy.{idx}"),
                value: format!("value-{idx}"),
                created_at_ns: now_ns.saturating_sub(MEMORY_ROLLUP_STALE_NS + 5_000_000_000),
                updated_at_ns: now_ns.saturating_sub(MEMORY_ROLLUP_STALE_NS + 5_000_000_000),
                source_turn_id: "turn-rollup".to_string(),
            })
            .expect("strategy fact should persist");
        }
        set_memory_fact(&MemoryFact {
            key: "balance.eth".to_string(),
            value: "0x1".to_string(),
            created_at_ns: now_ns,
            updated_at_ns: now_ns,
            source_turn_id: "turn-critical".to_string(),
        })
        .expect("critical fact should persist");
        let generated = update_memory_rollups(now_ns);
        assert!(
            generated >= 1,
            "rollups should be generated from stale non-critical facts"
        );

        let (raw, rollups) = list_memory_for_context(1, 5);
        assert_eq!(raw.len(), 1, "raw context should respect configured limit");
        assert_eq!(raw[0].key, "balance.eth");
        assert!(
            !rollups.is_empty(),
            "rollups should be included when raw context is saturated"
        );
    }

    #[test]
    fn summary_stores_enforce_independent_caps() {
        init_storage();
        clear_session_summary_map();
        clear_turn_window_summary_map();
        clear_memory_rollup_map();

        for idx in 0..(MAX_SESSION_SUMMARIES + 25) {
            upsert_session_summary(
                SessionSummaryAccumulator {
                    sender: format!("0x{idx:040x}"),
                    window_start_ns: idx as u64,
                    window_end_ns: idx as u64,
                    source_count: 1,
                    inbox_message_count: 1,
                    outbox_message_count: 0,
                    inbox_preview: "inbox".to_string(),
                    outbox_preview: String::new(),
                },
                idx as u64,
            );
        }
        assert!(
            SESSION_SUMMARY_MAP.with(|map| map.borrow().len() as usize) <= MAX_SESSION_SUMMARIES
        );

        for idx in 0..(MAX_TURN_WINDOW_SUMMARIES + 10) {
            upsert_turn_window_summary(
                TurnSummaryAccumulator {
                    window_start_ns: idx as u64,
                    window_end_ns: idx as u64,
                    source_count: 1,
                    turn_count: 1,
                    transition_count: 0,
                    tool_call_count: 0,
                    succeeded_turn_count: 1,
                    failed_turn_count: 0,
                    tool_success_count: 0,
                    tool_failure_count: 0,
                    top_errors: Vec::new(),
                },
                idx as u64,
            );
        }
        assert!(
            TURN_WINDOW_SUMMARY_MAP.with(|map| map.borrow().len() as usize)
                <= MAX_TURN_WINDOW_SUMMARIES
        );

        for idx in 0..(MAX_MEMORY_ROLLUPS + 10) {
            MEMORY_ROLLUP_MAP.with(|map| {
                map.borrow_mut().insert(
                    format!("namespace-{idx}"),
                    encode_json(&MemoryRollup {
                        namespace: format!("namespace-{idx}"),
                        window_start_ns: 0,
                        window_end_ns: idx as u64,
                        source_count: 1,
                        source_keys: vec![format!("k{idx}")],
                        canonical_value: "v".to_string(),
                        generated_at_ns: idx as u64,
                    }),
                );
            });
        }
        enforce_memory_rollup_cap();
        assert!(MEMORY_ROLLUP_MAP.with(|map| map.borrow().len() as usize) <= MAX_MEMORY_ROLLUPS);
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
    fn inbox_post_truncates_oversized_payloads() {
        init_storage();
        let oversized = "x".repeat(MAX_INBOX_BODY_CHARS.saturating_add(128));
        let posted_id = post_inbox_message(oversized, "2vxsx-fae".to_string())
            .expect("oversized inbox payload should be accepted with truncation");

        let messages = list_inbox_messages(10);
        let stored = messages
            .iter()
            .find(|message| message.id == posted_id)
            .expect("posted message must be persisted");
        assert!(
            stored.body.chars().count() <= MAX_INBOX_BODY_CHARS,
            "stored inbox payload must be bounded"
        );
        assert!(
            stored.body.contains("[truncated"),
            "stored inbox payload should retain truncation marker for debugging"
        );
    }

    #[test]
    fn inbox_post_handles_oversized_burst_with_bounded_persisted_payloads() {
        init_storage();
        let burst_size = 180usize;
        let oversized_body = "y".repeat(
            MAX_INBOX_BODY_CHARS.saturating_add(MAX_FIELD_TRUNCATION_MARKER_RESERVE_CHARS + 512),
        );

        for idx in 0..burst_size {
            let message_id = post_inbox_message(oversized_body.clone(), format!("sender-{idx}"))
                .expect("oversized burst payload should persist after truncation");
            assert!(
                message_id.starts_with("inbox:"),
                "burst insert should return stable inbox ids"
            );
        }

        let stats = inbox_stats();
        assert_eq!(stats.total_messages, burst_size as u64);
        assert_eq!(stats.pending_count, burst_size as u64);
        assert_eq!(stats.staged_count, 0);
        assert_eq!(stats.consumed_count, 0);

        let stored = list_inbox_messages(burst_size);
        assert_eq!(stored.len(), burst_size);
        assert!(stored
            .iter()
            .all(|message| message.body.chars().count() <= MAX_INBOX_BODY_CHARS));
        assert!(
            stored
                .iter()
                .all(|message| message.body.contains("[truncated")),
            "all oversized burst payloads should keep truncation markers for debugging"
        );
    }

    #[test]
    fn append_turn_record_truncates_inner_dialogue_and_tool_text_fields() {
        init_storage();
        let turn_id = "turn-large";
        let turn = TurnRecord {
            id: turn_id.to_string(),
            created_at_ns: 42,
            state_from: AgentState::Inferring,
            state_to: AgentState::Persisting,
            source_events: 1,
            tool_call_count: 1,
            input_summary: "oversized fields".to_string(),
            inner_dialogue: Some(
                "d".repeat(
                    MAX_TURN_INNER_DIALOGUE_CHARS
                        .saturating_add(MAX_FIELD_TRUNCATION_MARKER_RESERVE_CHARS)
                        .saturating_add(200),
                ),
            ),
            inference_round_count: 1,
            continuation_stop_reason: crate::domain::types::ContinuationStopReason::None,
            error: None,
        };
        let tool_records = vec![ToolCallRecord {
            turn_id: turn_id.to_string(),
            tool: "remember".to_string(),
            args_json: "a".repeat(
                MAX_TOOL_ARGS_JSON_CHARS
                    .saturating_add(MAX_FIELD_TRUNCATION_MARKER_RESERVE_CHARS)
                    .saturating_add(120),
            ),
            output: "o".repeat(
                MAX_TOOL_OUTPUT_CHARS
                    .saturating_add(MAX_FIELD_TRUNCATION_MARKER_RESERVE_CHARS)
                    .saturating_add(120),
            ),
            success: true,
            error: None,
        }];

        append_turn_record(&turn, &tool_records);

        let stored_turn = list_turns(1)
            .into_iter()
            .find(|record| record.id == turn_id)
            .expect("stored turn should be listed");
        assert!(
            stored_turn
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .chars()
                .count()
                <= MAX_TURN_INNER_DIALOGUE_CHARS
        );
        assert!(
            stored_turn
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("[truncated"),
            "turn inner dialogue should preserve truncation marker"
        );

        let stored_tools = get_tools_for_turn(turn_id);
        assert_eq!(stored_tools.len(), 1);
        assert!(stored_tools[0].args_json.chars().count() <= MAX_TOOL_ARGS_JSON_CHARS);
        assert!(stored_tools[0].output.chars().count() <= MAX_TOOL_OUTPUT_CHARS);
        assert!(
            stored_tools[0].output.contains("[truncated"),
            "tool output should preserve truncation marker"
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
        assert_eq!(
            bounded.storage_growth.inbox_map_entries, 2,
            "storage growth metrics should report inbox cardinality"
        );
        assert_eq!(
            bounded.storage_growth.memory_fact_limit, MAX_MEMORY_FACTS as u64,
            "storage growth metrics should expose memory fact cap"
        );
        assert!(
            bounded.storage_growth.tracked_entry_count >= 2,
            "storage growth metrics should expose tracked entry count"
        );
        assert!(
            bounded.storage_growth.trend_sample_count >= 1,
            "storage growth metrics should expose trend sample count"
        );
    }

    #[test]
    fn observability_storage_growth_exposes_pressure_and_trend_signals() {
        init_storage();
        for idx in 0..(MAX_MEMORY_FACTS * 9 / 10) {
            set_memory_fact(&MemoryFact {
                key: format!("phase3.fact.{idx:03}"),
                value: "x".to_string(),
                created_at_ns: idx as u64,
                updated_at_ns: idx as u64,
                source_turn_id: "phase3-storage-pressure-test".to_string(),
            })
            .expect("memory fact setup should remain within configured cap");
        }

        let baseline = observability_snapshot(1);
        post_inbox_message("phase3 trend probe".to_string(), "2vxsx-fae".to_string())
            .expect("inbox message should persist");
        let after_growth = observability_snapshot(1);

        assert!(
            after_growth.storage_growth.memory_fact_utilization_percent >= 90,
            "memory fact utilization signal should reflect high occupancy"
        );
        assert!(after_growth.storage_growth.near_limit);
        assert!(matches!(
            after_growth.storage_growth.pressure_level,
            StoragePressureLevel::High | StoragePressureLevel::Critical
        ));
        assert!(
            after_growth
                .storage_growth
                .pressure_warnings
                .iter()
                .any(|warning| warning.contains("memory facts")),
            "pressure warnings should include near-limit map diagnostics"
        );
        assert!(
            after_growth.storage_growth.trend_sample_count >= 2,
            "trend samples should accumulate across snapshots"
        );
        assert!(
            after_growth
                .storage_growth
                .tracked_entries_delta_per_hour
                .is_some(),
            "storage growth trend should expose a per-hour delta once multiple samples exist"
        );
        assert!(
            after_growth.storage_growth.tracked_entry_count
                >= baseline.storage_growth.tracked_entry_count,
            "tracked entry count should not regress after adding a new inbox message"
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

    fn sample_strategy_key() -> StrategyTemplateKey {
        StrategyTemplateKey {
            protocol: "aave-v3".to_string(),
            primitive: "lend_supply".to_string(),
            chain_id: 8453,
            template_id: "supply-usdc".to_string(),
        }
    }

    fn sample_strategy_template(
        version: TemplateVersion,
        status: TemplateStatus,
    ) -> StrategyTemplate {
        StrategyTemplate {
            key: sample_strategy_key(),
            version,
            status,
            contract_roles: vec![crate::domain::types::ContractRoleBinding {
                role: "pool".to_string(),
                address: "0x1111111111111111111111111111111111111111".to_string(),
                source_ref: "https://example.com/aave/base".to_string(),
                codehash: None,
            }],
            actions: vec![crate::domain::types::ActionSpec {
                action_id: "supply".to_string(),
                call_sequence: vec![AbiFunctionSpec {
                    role: "pool".to_string(),
                    name: "supply".to_string(),
                    selector_hex: "0x617ba037".to_string(),
                    inputs: vec![
                        AbiTypeSpec {
                            kind: "address".to_string(),
                            components: Vec::new(),
                        },
                        AbiTypeSpec {
                            kind: "uint256".to_string(),
                            components: Vec::new(),
                        },
                        AbiTypeSpec {
                            kind: "address".to_string(),
                            components: Vec::new(),
                        },
                        AbiTypeSpec {
                            kind: "uint16".to_string(),
                            components: Vec::new(),
                        },
                    ],
                    outputs: Vec::new(),
                    state_mutability: "nonpayable".to_string(),
                }],
                preconditions: vec!["balance_usdc_gte_amount".to_string()],
                postconditions: vec!["a_token_balance_delta_positive".to_string()],
                risk_checks: vec!["max_notional_cap".to_string()],
            }],
            constraints_json: "{\"max_notional\":\"100000000\"}".to_string(),
            created_at_ns: 10,
            updated_at_ns: 10,
        }
    }

    #[test]
    fn strategy_template_storage_persists_versioned_records_and_index() {
        init_storage();
        clear_strategy_maps_for_tests();

        let v1 = TemplateVersion {
            major: 1,
            minor: 0,
            patch: 0,
        };
        let v2 = TemplateVersion {
            major: 1,
            minor: 1,
            patch: 0,
        };

        upsert_strategy_template(sample_strategy_template(v1.clone(), TemplateStatus::Draft))
            .expect("template v1 should persist");
        upsert_strategy_template(sample_strategy_template(v2.clone(), TemplateStatus::Active))
            .expect("template v2 should persist");

        let key = sample_strategy_key();
        let versions = list_strategy_template_versions(&key);
        assert_eq!(versions, vec![v2.clone(), v1.clone()]);

        let listed = list_strategy_templates(&key, 10);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].version, v2);
        assert_eq!(listed[1].version, v1);

        let listed_all = list_all_strategy_templates(10);
        assert!(
            listed_all
                .iter()
                .any(|template| template.key.template_id == key.template_id),
            "global list should include seeded key"
        );

        let fetched = strategy_template(
            &key,
            &TemplateVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
        )
        .expect("template v1 should be retrievable");
        assert_eq!(fetched.actions[0].action_id, "supply");
    }

    #[test]
    fn abi_artifact_storage_persists_versioned_records_and_index() {
        init_storage();
        clear_strategy_maps_for_tests();

        let base_key = AbiArtifactKey {
            protocol: "uniswap-v3".to_string(),
            chain_id: 8453,
            role: "router".to_string(),
            version: TemplateVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
        };
        let v2_key = AbiArtifactKey {
            version: TemplateVersion {
                major: 1,
                minor: 2,
                patch: 0,
            },
            ..base_key.clone()
        };

        let artifact_v1 = AbiArtifact {
            key: base_key.clone(),
            source_ref: "https://example.com/uniswap/deployments".to_string(),
            codehash: None,
            abi_json: "[]".to_string(),
            functions: vec![AbiFunctionSpec {
                role: "router".to_string(),
                name: "exactInputSingle".to_string(),
                selector_hex: "0x414bf389".to_string(),
                inputs: vec![AbiTypeSpec {
                    kind: "bytes".to_string(),
                    components: Vec::new(),
                }],
                outputs: vec![AbiTypeSpec {
                    kind: "uint256".to_string(),
                    components: Vec::new(),
                }],
                state_mutability: "payable".to_string(),
            }],
            created_at_ns: 100,
            updated_at_ns: 100,
        };
        let mut artifact_v2 = artifact_v1.clone();
        artifact_v2.key = v2_key.clone();
        artifact_v2.updated_at_ns = 200;

        upsert_abi_artifact(artifact_v1).expect("abi artifact v1 should persist");
        upsert_abi_artifact(artifact_v2).expect("abi artifact v2 should persist");

        let versions = list_abi_artifact_versions("uniswap-v3", 8453, "router");
        assert_eq!(
            versions,
            vec![
                TemplateVersion {
                    major: 1,
                    minor: 2,
                    patch: 0
                },
                TemplateVersion {
                    major: 1,
                    minor: 0,
                    patch: 0
                }
            ]
        );

        let loaded = abi_artifact(&v2_key).expect("abi artifact v2 should be retrievable");
        assert_eq!(loaded.key.version.minor, 2);
        assert_eq!(loaded.functions[0].name, "exactInputSingle");
    }

    #[test]
    fn strategy_runtime_control_and_outcome_stats_persist() {
        init_storage();
        clear_strategy_maps_for_tests();

        let key = sample_strategy_key();
        let version = TemplateVersion {
            major: 1,
            minor: 0,
            patch: 0,
        };

        let activation = set_strategy_template_activation(TemplateActivationState {
            key: key.clone(),
            version: version.clone(),
            enabled: true,
            updated_at_ns: 10,
            reason: Some("canary passed".to_string()),
        })
        .expect("activation should persist");
        assert!(activation.enabled);
        assert_eq!(
            strategy_template_activation(&key, &version)
                .as_ref()
                .and_then(|value| value.reason.as_deref()),
            Some("canary passed")
        );

        let revocation = set_strategy_template_revocation(TemplateRevocationState {
            key: key.clone(),
            version: version.clone(),
            revoked: true,
            updated_at_ns: 20,
            reason: Some("deterministic failure threshold".to_string()),
        })
        .expect("revocation should persist");
        assert!(revocation.revoked);

        let kill_switch = set_strategy_kill_switch(StrategyKillSwitchState {
            key: key.clone(),
            enabled: true,
            updated_at_ns: 30,
            reason: Some("global protocol halt".to_string()),
        })
        .expect("kill switch should persist");
        assert!(kill_switch.enabled);
        assert!(strategy_kill_switch(&key)
            .as_ref()
            .map(|state| state.enabled)
            .unwrap_or(false));

        record_strategy_outcome(StrategyOutcomeEvent {
            key: key.clone(),
            version: version.clone(),
            action_id: "supply".to_string(),
            outcome: StrategyOutcomeKind::Success,
            tx_hash: Some("0xaaa".to_string()),
            error: None,
            observed_at_ns: 40,
        })
        .expect("successful outcome should record");
        record_strategy_outcome(StrategyOutcomeEvent {
            key: key.clone(),
            version: version.clone(),
            action_id: "supply".to_string(),
            outcome: StrategyOutcomeKind::DeterministicFailure,
            tx_hash: Some("0xbbb".to_string()),
            error: Some("slippage breach".to_string()),
            observed_at_ns: 50,
        })
        .expect("failure outcome should record");

        let stats = strategy_outcome_stats(&key, &version).expect("stats should exist");
        assert_eq!(stats.total_runs, 2);
        assert_eq!(stats.success_runs, 1);
        assert_eq!(stats.deterministic_failures, 1);
        assert_eq!(stats.nondeterministic_failures, 0);
        assert_eq!(stats.deterministic_failure_streak, 1);
        assert_eq!(stats.last_error.as_deref(), Some("slippage breach"));
        assert_eq!(stats.last_tx_hash.as_deref(), Some("0xbbb"));
        assert_eq!(stats.last_observed_at_ns, Some(50));

        let spent = set_strategy_template_budget_spent_wei(&key, &version, "42".to_string())
            .expect("budget spent should persist");
        assert_eq!(spent, "42");
        assert_eq!(
            strategy_template_budget_spent_wei(&key, &version).as_deref(),
            Some("42")
        );
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
    fn llm_canister_id_requires_valid_principal() {
        init_storage();
        assert!(set_llm_canister_id("".to_string()).is_err());
        assert!(set_llm_canister_id("not-a-principal".to_string()).is_err());
        let stored = set_llm_canister_id("w36hm-eqaaa-aaaal-qr76a-cai".to_string())
            .expect("valid canister id should be stored");
        assert_eq!(stored, "w36hm-eqaaa-aaaal-qr76a-cai");
        assert_eq!(get_llm_canister_id(), "w36hm-eqaaa-aaaal-qr76a-cai");
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
        set_evm_address(Some(
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

        let local_http = set_evm_rpc_url("http://127.0.0.1:18545".to_string())
            .expect("localhost http rpc should be accepted for local development");
        assert_eq!(local_http, "http://127.0.0.1:18545");

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
    fn wallet_balance_sync_capability_blocks_zero_address_discovery_until_override() {
        init_storage();
        set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should be configurable");
        set_inbox_contract_address(Some(
            "0x2222222222222222222222222222222222222222".to_string(),
        ))
        .expect("inbox contract should be configurable");

        assert!(wallet_balance_sync_capable(&runtime_snapshot()));

        record_wallet_balance_sync_error("Inbox.usdc returned zero address".to_string());
        assert!(
            !wallet_balance_sync_capable(&runtime_snapshot()),
            "discovery should be treated as incapable after zero-address resolution"
        );

        set_wallet_balance_snapshot(WalletBalanceSnapshot {
            eth_balance_wei_hex: None,
            usdc_balance_raw_hex: None,
            usdc_decimals: 6,
            usdc_contract_address: Some("0x3333333333333333333333333333333333333333".to_string()),
            last_synced_at_ns: None,
            last_synced_block: None,
            last_error: Some("Inbox.usdc returned zero address".to_string()),
        });
        assert!(
            wallet_balance_sync_capable(&runtime_snapshot()),
            "explicit usdc contract should restore capability"
        );
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

        set_memory_fact(&first).expect("first memory fact should store");
        set_memory_fact(&second).expect("second memory fact should store");

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
    fn memory_fact_store_enforces_max_cardinality_for_new_keys() {
        init_storage();
        let now_ns = 77u64;
        for idx in 0..MAX_MEMORY_FACTS {
            set_memory_fact(&MemoryFact {
                key: format!("fact.{idx}"),
                value: format!("value-{idx}"),
                created_at_ns: now_ns,
                updated_at_ns: now_ns,
                source_turn_id: "turn-fill".to_string(),
            })
            .expect("fact within cap should store");
        }
        assert_eq!(memory_fact_count(), MAX_MEMORY_FACTS);

        let overflow = set_memory_fact(&MemoryFact {
            key: "fact.overflow".to_string(),
            value: "overflow".to_string(),
            created_at_ns: now_ns,
            updated_at_ns: now_ns,
            source_turn_id: "turn-overflow".to_string(),
        });
        assert!(overflow.is_err(), "new key beyond cap must be rejected");
        assert_eq!(memory_fact_count(), MAX_MEMORY_FACTS);

        let update_existing = set_memory_fact(&MemoryFact {
            key: "fact.0".to_string(),
            value: "updated".to_string(),
            created_at_ns: now_ns,
            updated_at_ns: now_ns.saturating_add(1),
            source_turn_id: "turn-update".to_string(),
        });
        assert!(
            update_existing.is_ok(),
            "existing fact updates should still succeed at capacity"
        );
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

    #[test]
    fn http_domain_allowlist_is_unenforced_by_default() {
        init_storage();
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
        });
        save_runtime_bool(HTTP_ALLOWLIST_INITIALIZED_KEY, false);

        assert!(!is_http_allowlist_enforced());
        assert!(list_allowed_http_domains().is_empty());
    }
}
