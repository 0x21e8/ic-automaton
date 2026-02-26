/// Scheduler tick — the heartbeat of the IC-Automaton canister.
///
/// `scheduler_tick` is called by the IC timer every `BASE_TICK_SECS` seconds.
/// Each tick performs three main duties:
///
/// 1. **Lease recovery** — stale mutating leases (jobs that crashed without
///    releasing their lock) are reclaimed so the queue can continue.
/// 2. **Job materialisation** (`refresh_due_jobs`) — for every enabled
///    `TaskKind`, a pending job is enqueued into the mutating lane when the
///    task's `next_due_ns` is in the past.
/// 3. **Job dispatch** — up to `MAX_MUTATING_JOBS_PER_TICK` pending jobs are
///    popped, individually lease-gated, survival-policy checked, dispatched,
///    and their outcomes persisted before the next job is attempted.
///
/// # Task kinds
///
/// | Kind            | Survival gate | Lease TTL             |
/// |-----------------|---------------|-----------------------|
/// | `AgentTurn`     | Inference     | `AGENT_TURN_LEASE_TTL_NS` |
/// | `PollInbox`     | EvmPoll       | `LIGHTWEIGHT_LEASE_TTL_NS` |
/// | `CheckCycles`   | —             | `LIGHTWEIGHT_LEASE_TTL_NS` |
/// | `TopUpCycles`   | —             | `LIGHTWEIGHT_LEASE_TTL_NS` |
/// | `Reconcile`     | —             | `LIGHTWEIGHT_LEASE_TTL_NS` |
///
/// Failed jobs are passed through the recovery policy, which may retry
/// immediately, apply exponential backoff, tune response-byte limits, or
/// escalate to a fault.
use crate::agent::run_scheduled_turn_job;
use crate::domain::cycle_admission::{
    affordability_requirements, can_afford_with_reserve, estimate_operation_cost,
    AffordabilityRequirements, OperationClass, DEFAULT_RESERVE_FLOOR_CYCLES,
    DEFAULT_SAFETY_MARGIN_BPS,
};
use crate::domain::recovery_policy::decide_recovery_action;
use crate::domain::types::{
    EvmEvent, JobStatus, OperationFailure, OperationFailureKind, RecoveryContext, RecoveryFailure,
    RecoveryOperation, RecoveryPolicyAction, ResponseLimitAdjustment, ResponseLimitPolicy,
    RuntimeSnapshot, ScheduledJob, SurvivalOperationClass, SurvivalTier, TaskKind, TaskLane,
    TemplateActivationState, TemplateStatus,
};
use crate::features::cycle_topup::{
    TopUpStage, TOPUP_MIN_OPERATIONAL_CYCLES, TOPUP_MIN_USDC_AVAILABLE_RAW,
};
use crate::features::cycle_topup_host::{
    build_cycle_topup, enqueue_topup_cycles_job, topup_cycles_dedupe_key,
};
use crate::features::evm::{
    classify_evm_failure, decode_message_queued_payload, fetch_wallet_balance_sync_read,
};
use crate::features::inference::classify_inference_failure;
use crate::features::{EvmPoller, HttpEvmPoller};
use crate::storage::stable;
use crate::timing::{self, current_time_ns};
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};
use serde_json::json;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum inbox messages promoted from pending → staged in one `PollInbox` job.
const POLL_INBOX_STAGE_BATCH_SIZE: usize = 50;

/// Reference workflow-envelope cost (cycles) used by `CheckCycles` to
/// estimate the minimum operational floor.
const CHECKCYCLES_REFERENCE_ENVELOPE_CYCLES: u128 = 5_000_000_000;

/// Liquid-cycles multiple of the critical floor that triggers `LowCycles` tier.
/// A canister with fewer than `required × 15` liquid cycles is classified low.
const CHECKCYCLES_LOW_TIER_MULTIPLIER: u128 = 15;

/// Maximum number of mutating jobs dispatched per scheduler tick.
/// Prevents a single tick from dominating the IC message queue.
const MAX_MUTATING_JOBS_PER_TICK: u8 = 4;

/// Upper bound for the EVM RPC `max_response_bytes` tuning policy.
const EVM_RPC_MAX_RESPONSE_BYTES_POLICY_MAX: u64 = 2 * 1024 * 1024;

/// Lower bound for any response-bytes tuning policy (both EVM and wallet sync).
const RESPONSE_BYTES_POLICY_MIN: u64 = 256;

/// Base interval (seconds) for exponential backoff on job failures.
const RECOVERY_BACKOFF_BASE_SECS: u64 = 1;

/// Upper bound for the wallet-balance sync `max_response_bytes` tuning policy.
const WALLET_SYNC_MAX_RESPONSE_BYTES_RECOVERY_MAX: u64 = 4 * 1024;

/// Minimum wait (seconds) before a failed top-up is automatically retried.
const TOPUP_FAILED_RECOVERY_BACKOFF_SECS: u64 = 120;

/// Maximum number of strategy templates iterated per `Reconcile` job.
const STRATEGY_RECONCILE_MAX_TEMPLATES: usize = 200;

/// Templates older than this window (14 days) are disabled by the reconciler.
const STRATEGY_TEMPLATE_FRESHNESS_WINDOW_SECS: u64 = 14 * 24 * 60 * 60;

// ── Log types ────────────────────────────────────────────────────────────────

/// Outcome returned by `dispatch_job` to indicate whether a `TopUpCycles` job
/// needs a follow-up continuation (multi-stage top-up still in progress).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JobDispatchOutcome {
    Completed,
    TopUpWaiting,
}

#[derive(Clone, Copy, Debug, LogPriorityLevels)]
enum SchedulerLogPriority {
    #[log_level(capacity = 2000, name = "SCHEDULER_INFO")]
    Info,
    #[log_level(capacity = 500, name = "SCHEDULER_ERROR")]
    Error,
}

impl GetLogFilter for SchedulerLogPriority {
    fn get_log_filter() -> LogFilter {
        LogFilter::ShowAll
    }
}

// ── Tick entry point ─────────────────────────────────────────────────────────

/// Main scheduler heartbeat, invoked by the IC timer every `BASE_TICK_SECS`.
///
/// Sequence:
/// 1. Record tick start timestamp.
/// 2. Recover any stale mutating leases.
/// 3. Return early (no-op) if the scheduler is disabled.
/// 4. Materialise due jobs via `refresh_due_jobs`.
/// 5. Dispatch up to `MAX_MUTATING_JOBS_PER_TICK` pending jobs.
/// 6. Run retention maintenance if its interval has elapsed.
/// 7. Refresh HTTP certification state.
pub async fn scheduler_tick() {
    let now_ns = current_time_ns();
    stable::record_scheduler_tick_start(now_ns);

    log!(
        SchedulerLogPriority::Info,
        "scheduler_tick_start now={now_ns}"
    );

    stable::recover_stale_lease(now_ns);

    if !stable::scheduler_enabled() {
        log!(
            SchedulerLogPriority::Info,
            "scheduler_tick_end disabled now={now_ns}"
        );
        stable::record_scheduler_tick_end(now_ns, None);
        crate::http::init_certification();
        return;
    }

    refresh_due_jobs(now_ns);

    let mut processed_jobs = 0u8;
    let mut terminal_error: Option<String> = None;
    while processed_jobs < MAX_MUTATING_JOBS_PER_TICK {
        match run_one_pending_mutating_job(current_time_ns()).await {
            Ok(true) => processed_jobs = processed_jobs.saturating_add(1),
            Ok(false) => break,
            Err(error) => {
                terminal_error = Some(error);
                break;
            }
        }
    }

    if let Some(pruned) = stable::run_retention_maintenance_if_due(current_time_ns()) {
        log!(
            SchedulerLogPriority::Info,
            "scheduler_retention_maintenance deleted_jobs={} deleted_dedupe={} deleted_inbox={} deleted_outbox={} deleted_turns={} deleted_transitions={} deleted_tools={} generated_session_summaries={} generated_turn_window_summaries={} generated_memory_rollups={}",
            pruned.deleted_jobs,
            pruned.deleted_dedupe,
            pruned.deleted_inbox,
            pruned.deleted_outbox,
            pruned.deleted_turns,
            pruned.deleted_transitions,
            pruned.deleted_tools,
            pruned.generated_session_summaries,
            pruned.generated_turn_window_summaries,
            pruned.generated_memory_rollups
        );
    }

    log!(
        SchedulerLogPriority::Info,
        "scheduler_tick_end processed_jobs={} now={}",
        processed_jobs,
        current_time_ns()
    );
    stable::record_scheduler_tick_end(current_time_ns(), terminal_error);
    crate::http::init_certification();
}

// ── Job dispatch ─────────────────────────────────────────────────────────────

/// Pops the next pending mutating job, acquires its lease, checks the survival
/// policy, dispatches it, and applies the recovery policy on failure.
///
/// Returns `Ok(true)` if a job was processed, `Ok(false)` if the queue is empty
/// or a mutating lease is already active, and `Err` on a terminal lease error.
async fn run_one_pending_mutating_job(now_ns: u64) -> Result<bool, String> {
    if stable::mutating_lease_active(now_ns) {
        log!(
            SchedulerLogPriority::Info,
            "scheduler_tick mutating lease active now={now_ns}",
        );
        return Ok(false);
    }

    let job = match stable::pop_next_pending_job(TaskLane::Mutating, now_ns) {
        Some(job) => {
            log!(
                SchedulerLogPriority::Info,
                "scheduler_tick_dequeue job_id={} kind={:?} lane={:?}",
                job.id,
                job.kind,
                job.lane,
            );
            job
        }
        None => return Ok(false),
    };

    if let Err(error) = stable::acquire_mutating_lease(&job.id, now_ns, lease_ttl_ns(&job.kind)) {
        log!(
            SchedulerLogPriority::Error,
            "scheduler_tick_lease_error job_id={} err={}",
            job.id,
            error
        );
        stable::complete_job(
            &job.id,
            JobStatus::Failed,
            Some(format!("lease acquire failed: {error}")),
            current_time_ns(),
            None,
        );
        return Err(error);
    }

    if let Some(operation_class) = operation_class_for_task(&job.kind) {
        if !stable::can_run_survival_operation(&operation_class, now_ns) {
            let reason = format!(
                "operation blocked by survival policy (operation={:?})",
                operation_class
            );
            stable::complete_job(
                &job.id,
                JobStatus::Skipped,
                Some(reason.clone()),
                current_time_ns(),
                None,
            );
            log!(
                SchedulerLogPriority::Info,
                "scheduler_job_skipped job_id={} kind={:?} operation={:?} reason={reason}",
                job.id,
                job.kind,
                operation_class
            );
            return Ok(true);
        }
    }

    let result = dispatch_job(&job).await;
    match result {
        Ok(outcome) => {
            stable::complete_job(&job.id, JobStatus::Succeeded, None, current_time_ns(), None);
            maybe_enqueue_topup_waiting_continuation(outcome, current_time_ns());
        }
        Err(error) => apply_recovery_policy_for_failed_job(&job, error, current_time_ns()),
    }

    Ok(true)
}

/// Routes a job to the appropriate handler based on its `TaskKind`.
async fn dispatch_job(job: &ScheduledJob) -> Result<JobDispatchOutcome, String> {
    match job.kind {
        TaskKind::AgentTurn => {
            run_scheduled_turn_job().await?;
            Ok(JobDispatchOutcome::Completed)
        }
        TaskKind::PollInbox => {
            run_poll_inbox_job(current_time_ns()).await?;
            Ok(JobDispatchOutcome::Completed)
        }
        TaskKind::CheckCycles => {
            run_check_cycles().await?;
            Ok(JobDispatchOutcome::Completed)
        }
        TaskKind::TopUpCycles => {
            let snapshot = stable::runtime_snapshot();
            let topup = build_cycle_topup(&snapshot)?;
            let done = topup.advance().await?;
            if done {
                Ok(JobDispatchOutcome::Completed)
            } else {
                Ok(JobDispatchOutcome::TopUpWaiting)
            }
        }
        TaskKind::Reconcile => {
            run_reconcile_job(current_time_ns())?;
            Ok(JobDispatchOutcome::Completed)
        }
    }
}

/// Runs the strategy reconciliation job: iterates registered templates, disabling
/// stale or provenance-failed entries and activating those that pass the canary probe.
fn run_reconcile_job(now_ns: u64) -> Result<(), String> {
    let templates = crate::strategy::registry::list_all_templates(STRATEGY_RECONCILE_MAX_TEMPLATES);
    if templates.is_empty() {
        log!(
            SchedulerLogPriority::Info,
            "scheduler_reconcile_strategy empty=true"
        );
        return Ok(());
    }

    let mut stale_disabled = 0u32;
    let mut provenance_disabled = 0u32;
    let mut canary_activated = 0u32;

    for template in templates {
        let key = template.key.clone();
        let version = template.version.clone();

        let age_secs = if now_ns >= template.updated_at_ns {
            now_ns
                .saturating_sub(template.updated_at_ns)
                .checked_div(1_000_000_000)
                .unwrap_or(u64::MAX)
        } else {
            0
        };
        if age_secs > STRATEGY_TEMPLATE_FRESHNESS_WINDOW_SECS {
            let _ = stable::set_strategy_template_activation(TemplateActivationState {
                key: key.clone(),
                version: version.clone(),
                enabled: false,
                updated_at_ns: now_ns,
                reason: Some(format!(
                    "stale_template age_secs={age_secs} freshness_window_secs={STRATEGY_TEMPLATE_FRESHNESS_WINDOW_SECS}"
                )),
            });
            stale_disabled = stale_disabled.saturating_add(1);
            continue;
        }

        if let Err(error) = crate::strategy::registry::canary_probe_template(&key, &version) {
            let _ = stable::set_strategy_template_activation(TemplateActivationState {
                key: key.clone(),
                version: version.clone(),
                enabled: false,
                updated_at_ns: now_ns,
                reason: Some(format!("provenance_or_canary_failed: {error}")),
            });
            provenance_disabled = provenance_disabled.saturating_add(1);
            continue;
        }

        if !matches!(template.status, TemplateStatus::Active) {
            continue;
        }
        let currently_enabled = stable::strategy_template_activation(&key, &version)
            .map(|state| state.enabled)
            .unwrap_or(false);
        if currently_enabled {
            continue;
        }

        stable::set_strategy_template_activation(TemplateActivationState {
            key,
            version,
            enabled: true,
            updated_at_ns: now_ns,
            reason: Some("scheduler canary probe passed".to_string()),
        })?;
        canary_activated = canary_activated.saturating_add(1);
    }

    log!(
        SchedulerLogPriority::Info,
        "scheduler_reconcile_strategy stale_disabled={} provenance_disabled={} canary_activated={}",
        stale_disabled,
        provenance_disabled,
        canary_activated
    );

    Ok(())
}

/// If `outcome` is `TopUpWaiting`, enqueues a continuation `TopUpCycles` job
/// scheduled one task-interval into the future so the multi-stage top-up
/// resumes on the next eligible tick.
fn maybe_enqueue_topup_waiting_continuation(outcome: JobDispatchOutcome, now_ns: u64) {
    if !matches!(outcome, JobDispatchOutcome::TopUpWaiting) {
        return;
    }

    let interval_secs = stable::get_task_config(&TaskKind::TopUpCycles)
        .map(|config| config.interval_secs.max(1))
        .unwrap_or(TaskKind::TopUpCycles.default_interval_secs().max(1));
    let continuation_hint_ns = now_ns.saturating_add(interval_secs.saturating_mul(1_000_000_000));
    let enqueued = enqueue_topup_cycles_job("wait", continuation_hint_ns).is_some();
    log!(
        SchedulerLogPriority::Info,
        "scheduler_topup_waiting_continuation enqueued={} continuation_hint_ns={}",
        enqueued,
        continuation_hint_ns
    );
}

// ── Survival policy helpers ───────────────────────────────────────────────────

/// Maps a task kind + error string to a `RecoveryFailure` classification used
/// by the recovery policy to decide the appropriate action.
fn classify_failure_for_task(kind: &TaskKind, error: &str) -> RecoveryFailure {
    match kind {
        TaskKind::AgentTurn => classify_inference_failure(error),
        TaskKind::PollInbox => classify_evm_failure(error),
        TaskKind::CheckCycles | TaskKind::TopUpCycles | TaskKind::Reconcile => {
            RecoveryFailure::Operation(OperationFailure {
                kind: OperationFailureKind::Unknown,
            })
        }
    }
}

/// Returns `true` when `error` originated from an `eth_getLogs` poll call.
fn is_eth_get_logs_failure(error: &str) -> bool {
    error.to_ascii_lowercase().contains("eth_getlogs")
}

/// Maps a task kind to the `RecoveryOperation` tag used in recovery contexts.
fn recovery_operation_for_task(kind: &TaskKind) -> RecoveryOperation {
    match kind {
        TaskKind::AgentTurn => RecoveryOperation::Inference,
        TaskKind::PollInbox => RecoveryOperation::EvmPoll,
        TaskKind::CheckCycles | TaskKind::TopUpCycles | TaskKind::Reconcile => {
            RecoveryOperation::Unknown
        }
    }
}

/// Builds a `RecoveryContext` for `job`, pulling consecutive-failure counters,
/// backoff caps, and response-limit policies from stable storage.
fn recovery_context_for_task_job(job: &ScheduledJob) -> RecoveryContext {
    let task_runtime = stable::get_task_runtime(&job.kind);
    let task_config = stable::get_task_config(&job.kind)
        .unwrap_or_else(|| crate::domain::types::TaskScheduleConfig::default_for(&job.kind));
    let snapshot = stable::runtime_snapshot();

    let response_limit = if job.kind == TaskKind::PollInbox {
        Some(ResponseLimitPolicy {
            current_bytes: snapshot.evm_rpc_max_response_bytes,
            min_bytes: RESPONSE_BYTES_POLICY_MIN,
            max_bytes: EVM_RPC_MAX_RESPONSE_BYTES_POLICY_MAX,
            tune_multiplier: 2,
        })
    } else {
        None
    };

    RecoveryContext {
        operation: recovery_operation_for_task(&job.kind),
        consecutive_failures: task_runtime.consecutive_failures,
        backoff_base_secs: RECOVERY_BACKOFF_BASE_SECS,
        backoff_max_secs: task_config.max_backoff_secs,
        response_limit,
    }
}

/// Applies a `ResponseLimitAdjustment` for `operation` by persisting the new
/// `max_response_bytes` to stable storage.
fn apply_response_limit_tuning(
    operation: &RecoveryOperation,
    adjustment: &ResponseLimitAdjustment,
) -> Result<(), String> {
    match operation {
        RecoveryOperation::EvmPoll => {
            stable::set_evm_rpc_max_response_bytes(adjustment.to_bytes).map(|_| ())
        }
        RecoveryOperation::WalletBalanceSync => {
            let mut config = stable::wallet_balance_sync_config();
            config.max_response_bytes = adjustment.to_bytes;
            stable::set_wallet_balance_sync_config(config).map(|_| ())
        }
        _ => Err("response limit tuning is not supported for this operation".to_string()),
    }
}

/// Runs the full recovery policy pipeline for a failed job: classifies the
/// failure, decides the action (skip / retry-immediate / backoff / tune
/// response-limit / escalate), and completes the job record accordingly.
fn apply_recovery_policy_for_failed_job(job: &ScheduledJob, error: String, now_ns: u64) {
    let defer_poll_inbox_retry_to_next_slot =
        job.kind == TaskKind::PollInbox && is_eth_get_logs_failure(&error);
    let failure = classify_failure_for_task(&job.kind, &error);
    let context = recovery_context_for_task_job(job);
    let decision = decide_recovery_action(&failure, &context);

    let mut status = JobStatus::Failed;
    let mut retry_after_secs = None;
    let mut final_error = error;

    match decision.action {
        RecoveryPolicyAction::Skip => {
            status = JobStatus::Skipped;
        }
        RecoveryPolicyAction::RetryImmediate => {
            retry_after_secs = Some(0);
        }
        RecoveryPolicyAction::Backoff => {
            retry_after_secs = decision.backoff_secs.or(Some(1));
        }
        RecoveryPolicyAction::TuneResponseLimit => {
            if let Some(adjustment) = decision.response_limit_adjustment.as_ref() {
                if let Err(tune_error) = apply_response_limit_tuning(&context.operation, adjustment)
                {
                    final_error = format!(
                        "{final_error}; response_limit_tune_failed {}->{}: {tune_error}",
                        adjustment.from_bytes, adjustment.to_bytes
                    );
                } else {
                    retry_after_secs = Some(0);
                }
            } else {
                final_error = format!("{final_error}; response limit adjustment missing");
            }
        }
        RecoveryPolicyAction::EscalateFault => {}
    }

    if defer_poll_inbox_retry_to_next_slot {
        status = JobStatus::Skipped;
        retry_after_secs = None;
    }

    log!(
        SchedulerLogPriority::Info,
        "scheduler_job_recovery_decision job_id={} kind={:?} action={:?} reason={:?} retry_after_secs={:?} backoff_secs={:?}",
        job.id,
        job.kind,
        decision.action,
        decision.reason,
        retry_after_secs,
        decision.backoff_secs
    );

    stable::complete_job(&job.id, status, Some(final_error), now_ns, retry_after_secs);
}

// ── Recovery ─────────────────────────────────────────────────────────────────

/// Serialises an `EvmEvent` as a JSON fallback body when ABI decoding fails.
fn evm_event_to_inbox_body(event: &EvmEvent) -> String {
    json!({
        "source": "evm_log",
        "tx_hash": event.tx_hash,
        "chain_id": event.chain_id,
        "block_number": event.block_number,
        "log_index": event.log_index,
        "address": event.source,
        "data": event.payload,
    })
    .to_string()
}

/// Decodes an `EvmEvent` into an `(inbox_body, sender)` pair.
/// Falls back to the raw JSON envelope when ABI decoding fails.
fn evm_event_to_inbox_message(event: &EvmEvent) -> (String, String) {
    match decode_message_queued_payload(&event.payload) {
        Ok(decoded) => {
            let bounded = stable::normalize_inbox_body(&decoded.message)
                .unwrap_or_else(|_| "[invalid decoded message]".to_string());
            (bounded, decoded.sender)
        }
        Err(error) => {
            log!(
                SchedulerLogPriority::Error,
                "scheduler_poll_inbox_decode_failed tx_hash={} log_index={} error={}",
                event.tx_hash,
                event.log_index,
                error
            );
            let fallback = stable::normalize_inbox_body(&evm_event_to_inbox_body(event))
                .unwrap_or_else(|_| "[evm log decode failed]".to_string());
            (fallback, event.source.clone())
        }
    }
}

/// Returns the minimum delay in nanoseconds before the next EVM poll, based on
/// the number of consecutive empty polls and the `EMPTY_POLL_BACKOFF_SCHEDULE_SECS`.
fn empty_poll_backoff_delay_ns(consecutive_empty_polls: u32) -> u64 {
    // Use the first backoff slot for both "no empties yet" and "first empty poll observed".
    // This keeps the first empty-poll retry window at 60s instead of jumping to 120s.
    let schedule_idx = consecutive_empty_polls.saturating_sub(1);
    let idx = usize::try_from(schedule_idx).unwrap_or(usize::MAX);
    let secs = timing::EMPTY_POLL_BACKOFF_SCHEDULE_SECS
        .get(idx)
        .copied()
        .unwrap_or(
            *timing::EMPTY_POLL_BACKOFF_SCHEDULE_SECS
                .last()
                .unwrap_or(&300),
        );
    secs.saturating_mul(1_000_000_000)
}

/// Returns `true` when enough time has elapsed since `last_poll_at_ns` given
/// the current empty-poll backoff level.
fn poll_inbox_rpc_due(now_ns: u64, last_poll_at_ns: u64, consecutive_empty_polls: u32) -> bool {
    if last_poll_at_ns == 0 {
        return true;
    }
    let min_delay_ns = empty_poll_backoff_delay_ns(consecutive_empty_polls);
    now_ns >= last_poll_at_ns.saturating_add(min_delay_ns)
}

/// Returns the wallet-balance sync interval for the current survival tier,
/// or `None` if syncing is disabled or the tier prohibits it (Critical / OutOfCycles).
fn wallet_balance_sync_interval_secs(
    snapshot: &RuntimeSnapshot,
    tier: &SurvivalTier,
) -> Option<u64> {
    if !snapshot.wallet_balance_sync.enabled {
        return None;
    }

    match tier {
        SurvivalTier::Normal => Some(snapshot.wallet_balance_sync.normal_interval_secs),
        SurvivalTier::LowCycles => Some(snapshot.wallet_balance_sync.low_cycles_interval_secs),
        SurvivalTier::Critical | SurvivalTier::OutOfCycles => None,
    }
}

/// Returns `true` when a wallet balance sync should be attempted now —
/// either because the bootstrap gate is pending or because the freshness
/// interval has elapsed since the last successful sync.
fn wallet_balance_sync_due(snapshot: &RuntimeSnapshot, now_ns: u64, interval_secs: u64) -> bool {
    if snapshot.wallet_balance_bootstrap_pending {
        return true;
    }

    let Some(last_synced_at_ns) = snapshot.wallet_balance.last_synced_at_ns else {
        return true;
    };
    let due_ns = interval_secs.saturating_mul(1_000_000_000);
    now_ns >= last_synced_at_ns.saturating_add(due_ns)
}

/// Builds a `RecoveryContext` for wallet-balance sync failures, wiring in
/// the current `max_response_bytes` and the sync-specific backoff cap.
fn wallet_sync_recovery_context(snapshot: &RuntimeSnapshot) -> RecoveryContext {
    let consecutive_failures = u32::from(snapshot.wallet_balance.last_error.is_some());
    RecoveryContext {
        operation: RecoveryOperation::WalletBalanceSync,
        consecutive_failures,
        backoff_base_secs: RECOVERY_BACKOFF_BASE_SECS,
        backoff_max_secs: stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_POLL,
        response_limit: Some(ResponseLimitPolicy {
            current_bytes: snapshot.wallet_balance_sync.max_response_bytes,
            min_bytes: RESPONSE_BYTES_POLICY_MIN,
            max_bytes: WALLET_SYNC_MAX_RESPONSE_BYTES_RECOVERY_MAX,
            tune_multiplier: 2,
        }),
    }
}

/// Conditionally fetches and persists the latest wallet balances.
///
/// Skips when syncing is disabled, the canister is on a Critical/OutOfCycles
/// tier, the required address routes are not yet configured, or the freshness
/// interval has not elapsed.  On failure, applies the sync recovery policy
/// (response-limit tuning / immediate retry) before persisting the error.
async fn maybe_sync_wallet_balances(now_ns: u64, snapshot: &RuntimeSnapshot) {
    let tier = stable::scheduler_survival_tier();
    let Some(interval_secs) = wallet_balance_sync_interval_secs(snapshot, &tier) else {
        log!(
            SchedulerLogPriority::Info,
            "scheduler_wallet_balance_sync_skipped reason=disabled_or_tier tier={:?}",
            tier
        );
        return;
    };
    if !stable::wallet_balance_sync_capable(snapshot) {
        if snapshot.wallet_balance_bootstrap_pending {
            stable::set_wallet_balance_bootstrap_pending(false);
        }
        log!(
            SchedulerLogPriority::Info,
            "scheduler_wallet_balance_sync_skipped reason=not_configured_or_incomplete_route tier={:?}",
            tier
        );
        return;
    }
    if !wallet_balance_sync_due(snapshot, now_ns, interval_secs) {
        let next_due_ns = snapshot
            .wallet_balance
            .last_synced_at_ns
            .unwrap_or(0)
            .saturating_add(interval_secs.saturating_mul(1_000_000_000));
        log!(
            SchedulerLogPriority::Info,
            "scheduler_wallet_balance_sync_skipped reason=due_not_reached now_ns={} next_due_ns={} tier={:?}",
            now_ns,
            next_due_ns,
            tier
        );
        return;
    }

    let mut sync_snapshot = snapshot.clone();
    if sync_snapshot.evm_address.is_none() && !sync_snapshot.ecdsa_key_name.trim().is_empty() {
        match crate::features::threshold_signer::derive_and_cache_evm_address(
            &sync_snapshot.ecdsa_key_name,
        )
        .await
        {
            Ok(derived_address) => {
                sync_snapshot.evm_address = Some(derived_address);
            }
            Err(error) => {
                stable::record_wallet_balance_sync_error(format!(
                    "wallet address derivation failed: {error}"
                ));
                log!(
                    SchedulerLogPriority::Error,
                    "scheduler_wallet_balance_sync_error stage=derive_wallet_address error={}",
                    error
                );
                return;
            }
        }
    }

    match fetch_wallet_balance_sync_read(&sync_snapshot).await {
        Ok(read) => {
            stable::record_wallet_balance_sync_success(
                now_ns,
                read.eth_balance_wei_hex,
                read.usdc_balance_raw_hex,
                read.usdc_contract_address,
            );
            log!(
                SchedulerLogPriority::Info,
                "scheduler_wallet_balance_sync_success now_ns={} bootstrap_pending_cleared={}",
                now_ns,
                snapshot.wallet_balance_bootstrap_pending
            );
        }
        Err(error) => {
            let failure = classify_evm_failure(&error);
            let decision =
                decide_recovery_action(&failure, &wallet_sync_recovery_context(&sync_snapshot));
            let mut retry_snapshot: Option<RuntimeSnapshot> = None;
            let mut retry_reason = "none";
            let mut final_error = error;

            match decision.action {
                RecoveryPolicyAction::TuneResponseLimit => {
                    if let Some(adjustment) = decision.response_limit_adjustment.as_ref() {
                        if let Err(tune_error) = apply_response_limit_tuning(
                            &RecoveryOperation::WalletBalanceSync,
                            adjustment,
                        ) {
                            final_error = format!(
                                "{final_error}; wallet_sync_response_limit_tune_failed {}->{}: {tune_error}",
                                adjustment.from_bytes, adjustment.to_bytes
                            );
                        } else {
                            let mut updated = sync_snapshot.clone();
                            updated.wallet_balance_sync.max_response_bytes = adjustment.to_bytes;
                            retry_snapshot = Some(updated);
                            retry_reason = "tune_response_limit";
                        }
                    } else {
                        final_error =
                            format!("{final_error}; wallet sync tune action missing adjustment");
                    }
                }
                RecoveryPolicyAction::RetryImmediate => {
                    retry_snapshot = Some(sync_snapshot.clone());
                    retry_reason = "retry_immediate";
                }
                RecoveryPolicyAction::Backoff
                | RecoveryPolicyAction::EscalateFault
                | RecoveryPolicyAction::Skip => {}
            }

            log!(
                SchedulerLogPriority::Info,
                "scheduler_wallet_balance_sync_recovery_decision action={:?} reason={:?} retry_reason={} backoff_secs={:?}",
                decision.action,
                decision.reason,
                retry_reason,
                decision.backoff_secs
            );

            if let Some(retry_snapshot) = retry_snapshot {
                match fetch_wallet_balance_sync_read(&retry_snapshot).await {
                    Ok(read) => {
                        stable::record_wallet_balance_sync_success(
                            now_ns,
                            read.eth_balance_wei_hex,
                            read.usdc_balance_raw_hex,
                            read.usdc_contract_address,
                        );
                        log!(
                            SchedulerLogPriority::Info,
                            "scheduler_wallet_balance_sync_recovered now_ns={} retry_reason={} bootstrap_pending_cleared={}",
                            now_ns,
                            retry_reason,
                            snapshot.wallet_balance_bootstrap_pending
                        );
                        return;
                    }
                    Err(retry_error) => {
                        final_error =
                            format!("{final_error}; retry({retry_reason}) failed: {retry_error}");
                    }
                }
            }

            stable::record_wallet_balance_sync_error(final_error.clone());
            log!(
                SchedulerLogPriority::Error,
                "scheduler_wallet_balance_sync_error stage=fetch_balances error={}",
                final_error
            );
        }
    }
}

/// Executes the `PollInbox` job: polls the EVM inbox contract for new
/// `MessageQueued` events, ingests them as inbox messages, advances the cursor,
/// then calls `maybe_sync_wallet_balances` and stages any pending messages.
async fn run_poll_inbox_job(now_ns: u64) -> Result<(), String> {
    let snapshot = stable::runtime_snapshot();
    let mut fetched_events = 0usize;
    let mut ingested_events = 0usize;
    let mut skipped_duplicate_events = 0usize;

    if snapshot.evm_rpc_url.trim().is_empty() {
        log!(
            SchedulerLogPriority::Info,
            "scheduler_poll_inbox_rpc_unconfigured skipping_evm_rpc=true"
        );
    } else if snapshot.inbox_contract_address.is_none() {
        log!(
            SchedulerLogPriority::Info,
            "scheduler_poll_inbox_contract_unconfigured skipping_evm_rpc=true"
        );
    } else if snapshot.evm_address.is_none() {
        log!(
            SchedulerLogPriority::Info,
            "scheduler_poll_inbox_agent_address_unavailable skipping_evm_rpc=true"
        );
    } else if !poll_inbox_rpc_due(
        now_ns,
        snapshot.evm_cursor.last_poll_at_ns,
        snapshot.evm_cursor.consecutive_empty_polls,
    ) {
        let next_due_ns =
            snapshot
                .evm_cursor
                .last_poll_at_ns
                .saturating_add(empty_poll_backoff_delay_ns(
                    snapshot.evm_cursor.consecutive_empty_polls,
                ));
        log!(
            SchedulerLogPriority::Info,
            "scheduler_poll_inbox_backoff_skip now_ns={} last_poll_at_ns={} empty_polls={} next_due_ns={}",
            now_ns,
            snapshot.evm_cursor.last_poll_at_ns,
            snapshot.evm_cursor.consecutive_empty_polls,
            next_due_ns
        );
    } else {
        let poller = HttpEvmPoller::from_snapshot(&snapshot)?;
        let poll = poller
            .poll(&snapshot.evm_cursor)
            .await
            .inspect_err(|error| {
                if is_eth_get_logs_failure(error) {
                    log!(
                        SchedulerLogPriority::Info,
                        "scheduler_poll_inbox_retry_deferred reason=eth_getLogs_failure"
                    );
                } else {
                    stable::record_survival_operation_failure(
                        &SurvivalOperationClass::EvmPoll,
                        now_ns,
                        stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_POLL,
                    );
                }
            })?;

        fetched_events = poll.events.len();
        for event in &poll.events {
            if !stable::try_mark_evm_event_ingested(&event.tx_hash, event.log_index) {
                skipped_duplicate_events = skipped_duplicate_events.saturating_add(1);
                continue;
            }
            let (body, sender) = evm_event_to_inbox_message(event);
            stable::post_inbox_message(body, sender)?;
            ingested_events = ingested_events.saturating_add(1);
        }

        let mut next_cursor = poll.cursor.clone();
        next_cursor.last_poll_at_ns = now_ns;
        if ingested_events > 0 {
            next_cursor.consecutive_empty_polls = 0;
        } else {
            next_cursor.consecutive_empty_polls = snapshot
                .evm_cursor
                .consecutive_empty_polls
                .saturating_add(1);
        }
        stable::set_evm_cursor(&next_cursor);
        stable::record_survival_operation_success(&SurvivalOperationClass::EvmPoll);
    }

    maybe_sync_wallet_balances(now_ns, &snapshot).await;

    let staged =
        stable::stage_pending_inbox_messages(POLL_INBOX_STAGE_BATCH_SIZE, current_time_ns());
    log!(
        SchedulerLogPriority::Info,
        "scheduler_poll_inbox_staged count={} evm_events_fetched={} evm_events_ingested={} evm_events_duplicate_skipped={}",
        staged,
        fetched_events,
        ingested_events,
        skipped_duplicate_events
    );
    Ok(())
}

/// Executes the `CheckCycles` job: reads the canister cycle balances, classifies
/// the survival tier, persists it, and — when conditions are met — triggers or
/// recovers an automated cycle top-up.
async fn run_check_cycles() -> Result<(), String> {
    let now_ns = current_time_ns();
    let total_cycles = ic_cdk::api::canister_cycle_balance();
    let liquid_cycles = ic_cdk::api::canister_liquid_cycle_balance();
    let expected = classify_survival_tier(total_cycles, liquid_cycles)?;
    let requirements = check_cycles_requirements()?;
    let snapshot = stable::runtime_snapshot();
    let cached_usdc_balance_raw =
        parse_hex_quantity_u64(snapshot.wallet_balance.usdc_balance_raw_hex.as_deref());
    let mut topup_state = stable::read_topup_state();
    let mut topup_triggered = false;

    stable::set_scheduler_survival_tier(expected.clone());
    let runtime_tier = stable::scheduler_survival_tier();
    let recovery_checks = stable::scheduler_survival_tier_recovery_checks();

    if snapshot.cycle_topup.enabled
        && maybe_recover_failed_topup(&snapshot, topup_state.as_ref(), now_ns)
    {
        topup_triggered = true;
        topup_state = stable::read_topup_state();
    }

    if !topup_triggered
        && should_trigger_cycle_topup(
            total_cycles,
            &snapshot,
            topup_state.as_ref(),
            cached_usdc_balance_raw,
        )
    {
        match build_cycle_topup(&snapshot) {
            Ok(topup) => match topup.start() {
                Ok(()) => {
                    let _ = enqueue_topup_cycles_job("auto", now_ns);
                    topup_triggered = true;
                }
                Err(error) => {
                    log!(
                        SchedulerLogPriority::Error,
                        "scheduler_checkcycles_topup_start_rejected error={error}",
                    );
                }
            },
            Err(error) => {
                log!(
                    SchedulerLogPriority::Error,
                    "scheduler_checkcycles_topup_config_error error={error}",
                );
            }
        }
    }

    log!(
        SchedulerLogPriority::Info,
    "scheduler_checkcycles total_cycles={} liquid_cycles={} reserve_floor_cycles={} required_cycles={} low_tier_limit={} observed_tier={:?} runtime_tier={:?} recovery_checks={} cached_usdc_balance_raw={:?} topup_triggered={} topup_state={:?}",
        total_cycles,
        liquid_cycles,
        DEFAULT_RESERVE_FLOOR_CYCLES,
        requirements.required_cycles,
        requirements.required_cycles.saturating_mul(CHECKCYCLES_LOW_TIER_MULTIPLIER),
        expected,
        runtime_tier,
        recovery_checks,
        cached_usdc_balance_raw,
        topup_triggered,
        topup_state
    );
    Ok(())
}

/// Parses an optional hex string (with or without `0x` prefix) into a `u64`.
/// Returns `None` when the input is absent or unparseable.
fn parse_hex_quantity_u64(raw: Option<&str>) -> Option<u64> {
    let raw = raw?;
    let normalized = raw.trim();
    let without_prefix = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
        .unwrap_or(normalized);
    if without_prefix.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(without_prefix, 16).ok()
}

/// Returns `true` when the top-up state machine is idle (no stage in progress),
/// allowing a new automated top-up to be started.
fn topup_state_allows_auto_start(state: Option<&TopUpStage>) -> bool {
    matches!(state, None | Some(TopUpStage::Completed { .. }))
}

/// Returns `true` when the top-up is in a `Failed` state and the
/// `TOPUP_FAILED_RECOVERY_BACKOFF_SECS` window has elapsed since failure.
fn topup_failed_recovery_due(state: Option<&TopUpStage>, now_ns: u64) -> bool {
    let Some(TopUpStage::Failed { failed_at_ns, .. }) = state else {
        return false;
    };
    let backoff_ns = TOPUP_FAILED_RECOVERY_BACKOFF_SECS.saturating_mul(1_000_000_000);
    now_ns >= failed_at_ns.saturating_add(backoff_ns)
}

/// Attempts to recover a failed top-up if the backoff window has passed.
/// Resets the state machine, re-starts the top-up, and enqueues a
/// continuation job.  Returns `true` on a successful recovery start.
fn maybe_recover_failed_topup(
    snapshot: &RuntimeSnapshot,
    topup_state: Option<&TopUpStage>,
    now_ns: u64,
) -> bool {
    let Some(TopUpStage::Failed {
        stage,
        error,
        failed_at_ns,
        attempts,
    }) = topup_state
    else {
        return false;
    };

    let retry_at_ns = failed_at_ns
        .saturating_add(TOPUP_FAILED_RECOVERY_BACKOFF_SECS.saturating_mul(1_000_000_000));
    if !topup_failed_recovery_due(topup_state, now_ns) {
        log!(
            SchedulerLogPriority::Info,
            "scheduler_checkcycles_topup_recovery_backoff active=true retry_at_ns={} failed_stage={} attempts={}",
            retry_at_ns,
            stage,
            attempts
        );
        return false;
    }

    let topup = match build_cycle_topup(snapshot) {
        Ok(topup) => topup,
        Err(recover_error) => {
            log!(
                SchedulerLogPriority::Error,
                "scheduler_checkcycles_topup_recovery_config_error error={recover_error}",
            );
            return false;
        }
    };

    if let Err(recover_error) = topup.reset() {
        log!(
            SchedulerLogPriority::Error,
            "scheduler_checkcycles_topup_recovery_reset_error error={recover_error}",
        );
        return false;
    }
    if let Err(recover_error) = topup.start() {
        log!(
            SchedulerLogPriority::Error,
            "scheduler_checkcycles_topup_recovery_start_error error={recover_error}",
        );
        return false;
    }

    let enqueued = enqueue_topup_cycles_job("auto-recover", now_ns).is_some();
    log!(
        SchedulerLogPriority::Info,
        "scheduler_checkcycles_topup_recovery_started enqueued={} failed_stage={} failed_error={} previous_attempts={}",
        enqueued,
        stage,
        error,
        attempts
    );
    true
}

/// Returns `true` when all conditions for an automated cycle top-up are met:
/// top-up is enabled, cycles are below the threshold but above the operational
/// floor, no top-up is already in progress, and the USDC balance is sufficient.
fn should_trigger_cycle_topup(
    total_cycles: u128,
    snapshot: &RuntimeSnapshot,
    topup_state: Option<&TopUpStage>,
    cached_usdc_balance_raw: Option<u64>,
) -> bool {
    if !snapshot.cycle_topup.enabled {
        return false;
    }
    if total_cycles <= TOPUP_MIN_OPERATIONAL_CYCLES {
        return false;
    }
    if total_cycles >= snapshot.cycle_topup.auto_topup_cycle_threshold {
        return false;
    }
    if !topup_state_allows_auto_start(topup_state) {
        return false;
    }

    let min_required = snapshot
        .cycle_topup
        .min_usdc_reserve
        .saturating_add(TOPUP_MIN_USDC_AVAILABLE_RAW);
    cached_usdc_balance_raw.unwrap_or_default() >= min_required
}

/// Computes the minimum cycles required to sustain one workflow envelope,
/// used as the affordability baseline by `classify_survival_tier`.
fn check_cycles_requirements() -> Result<AffordabilityRequirements, String> {
    let operation_cost = estimate_operation_cost(&OperationClass::WorkflowEnvelope {
        envelope_cycles: CHECKCYCLES_REFERENCE_ENVELOPE_CYCLES,
    })?;
    Ok(affordability_requirements(
        operation_cost,
        DEFAULT_SAFETY_MARGIN_BPS,
        0,
    ))
}

/// Classifies the current canister into `Critical`, `LowCycles`, or `Normal`
/// based on whether liquid cycles satisfy the reserve floor and the low-tier
/// multiplier threshold.
fn classify_survival_tier(total_cycles: u128, liquid_cycles: u128) -> Result<SurvivalTier, String> {
    let can_cover_critical_floor = can_afford_with_reserve(
        total_cycles,
        &OperationClass::WorkflowEnvelope {
            envelope_cycles: CHECKCYCLES_REFERENCE_ENVELOPE_CYCLES,
        },
        DEFAULT_SAFETY_MARGIN_BPS,
        DEFAULT_RESERVE_FLOOR_CYCLES,
    )?;
    if !can_cover_critical_floor {
        return Ok(SurvivalTier::Critical);
    }

    let requirements = check_cycles_requirements()?;
    if liquid_cycles < requirements.required_cycles {
        return Ok(SurvivalTier::Critical);
    }

    let low_threshold = requirements
        .required_cycles
        .saturating_mul(CHECKCYCLES_LOW_TIER_MULTIPLIER);
    if liquid_cycles < low_threshold {
        return Ok(SurvivalTier::LowCycles);
    }

    Ok(SurvivalTier::Normal)
}

// ── Lease helpers ────────────────────────────────────────────────────────────

/// Materialises pending jobs for every enabled task whose `next_due_ns` has
/// elapsed, using slot-aligned dedupe keys to prevent duplicate enqueuing.
///
/// After enqueuing, `next_due_ns` is advanced by one interval — but never
/// placed before the current slot start — to avoid bursty catch-up when the
/// canister is behind wall-clock time.
pub fn refresh_due_jobs(now_ns: u64) {
    let mut schedules = stable::list_task_configs();
    schedules.sort_by_key(|(_kind, config)| (config.priority, config.kind.as_str().to_string()));
    let low_cycles = stable::scheduler_low_cycles_mode();

    for (kind, config) in schedules {
        if !config.enabled {
            continue;
        }
        if low_cycles && !config.essential {
            continue;
        }
        let interval_ns = config.interval_secs.saturating_mul(1_000_000_000);
        if interval_ns == 0 {
            continue;
        }

        let mut runtime = stable::get_task_runtime(&kind);
        if runtime.pending_job_id.is_some() {
            continue;
        }
        if runtime.backoff_until_ns.is_some_and(|until| until > now_ns) {
            continue;
        }
        if runtime.next_due_ns > now_ns {
            continue;
        }

        let slot_start_ns = now_ns - (now_ns % interval_ns);
        let dedupe_key = if kind == TaskKind::TopUpCycles {
            topup_cycles_dedupe_key()
        } else {
            format!("{}:{}", kind.as_str(), slot_start_ns)
        };
        if let Some(job_id) = stable::enqueue_job_if_absent(
            kind.clone(),
            TaskLane::Mutating,
            dedupe_key,
            slot_start_ns,
            config.priority,
        ) {
            log!(
                SchedulerLogPriority::Info,
                "scheduler_job_enqueued kind={:?} job_id={} scheduled_for={} priority={}",
                kind,
                job_id,
                slot_start_ns,
                config.priority,
            );
        }

        // Prevent bursty "catch-up" scheduling when runtime is far behind wall-clock.
        // We advance by one interval, but never leave next_due_ns behind the current slot.
        let advanced_due_ns = runtime.next_due_ns.saturating_add(interval_ns);
        let aligned_due_ns = slot_start_ns.saturating_add(interval_ns);
        runtime.next_due_ns = advanced_due_ns.max(aligned_due_ns);
        stable::save_task_runtime(&kind, &runtime);
    }
}

/// Returns the `SurvivalOperationClass` that gates execution of `kind`, or
/// `None` for tasks that are not gated by the survival policy.
fn operation_class_for_task(kind: &TaskKind) -> Option<SurvivalOperationClass> {
    match kind {
        TaskKind::AgentTurn => Some(SurvivalOperationClass::Inference),
        TaskKind::PollInbox => Some(SurvivalOperationClass::EvmPoll),
        _ => None,
    }
}

/// Returns the lease TTL in nanoseconds for `kind`.
/// Agent turns use the extended TTL to accommodate multi-round inference;
/// all other tasks use the lightweight TTL.
fn lease_ttl_ns(kind: &TaskKind) -> u64 {
    match kind {
        TaskKind::AgentTurn => timing::AGENT_TURN_LEASE_TTL_NS,
        _ => timing::LIGHTWEIGHT_LEASE_TTL_NS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{
        AbiArtifact, AbiArtifactKey, AbiFunctionSpec, AbiTypeSpec, ActionSpec, ContractRoleBinding,
        EvmEvent, RecoveryOperation, RecoveryPolicyAction, ResponseLimitAdjustment,
        RetentionConfig, StrategyTemplate, StrategyTemplateKey, SurvivalOperationClass,
        TaskScheduleConfig, TaskScheduleRuntime, TemplateActivationState, TemplateStatus,
        TemplateVersion, WalletBalanceSnapshot, WalletBalanceSyncConfig,
    };
    use crate::storage::stable;
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn settle_pending_topup_jobs(now_ns: u64) {
        for job in stable::list_recent_jobs(500)
            .into_iter()
            .filter(|job| job.kind == TaskKind::TopUpCycles && !job.is_terminal())
        {
            stable::complete_job(&job.id, JobStatus::Succeeded, None, now_ns, None);
        }
    }

    fn topup_job_count() -> usize {
        stable::list_recent_jobs(500)
            .into_iter()
            .filter(|job| job.kind == TaskKind::TopUpCycles)
            .count()
    }

    fn block_on_with_spin<F: Future>(future: F) -> F::Output {
        unsafe fn clone(_ptr: *const ()) -> RawWaker {
            dummy_raw_waker()
        }
        unsafe fn wake(_ptr: *const ()) {}
        unsafe fn wake_by_ref(_ptr: *const ()) {}
        unsafe fn drop(_ptr: *const ()) {}

        fn dummy_raw_waker() -> RawWaker {
            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
            RawWaker::new(std::ptr::null(), &VTABLE)
        }

        let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);

        for _ in 0..10_000 {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::hint::spin_loop(),
            }
        }

        panic!("future did not complete in test polling loop");
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn with_host_stub_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        crate::test_support::with_locked_host_env(vars, f);
    }

    fn init_scheduler_scope() {
        stable::init_scheduler_defaults(0);
        let target_kind = TaskKind::PollInbox;
        for kind in TaskKind::all() {
            stable::set_task_enabled(kind, kind == &target_kind);
        }

        let mut config =
            stable::get_task_config(&target_kind).unwrap_or_else(|| TaskScheduleConfig {
                kind: target_kind.clone(),
                enabled: true,
                essential: true,
                interval_secs: 10,
                priority: 0,
                max_backoff_secs: 120,
            });
        config.enabled = true;
        config.interval_secs = 10;
        config.essential = true;
        config.priority = 0;
        stable::upsert_task_config(config);
    }

    fn strategy_key(template_id: &str) -> StrategyTemplateKey {
        StrategyTemplateKey {
            protocol: "erc20".to_string(),
            primitive: "transfer".to_string(),
            chain_id: 8453,
            template_id: template_id.to_string(),
        }
    }

    fn strategy_version() -> TemplateVersion {
        TemplateVersion {
            major: 1,
            minor: 0,
            patch: 0,
        }
    }

    fn seed_strategy_for_reconcile(
        template_id: &str,
        updated_at_ns: u64,
        call_selector_hex: &str,
        status: TemplateStatus,
        activation_enabled: bool,
    ) {
        let key = strategy_key(template_id);
        let version = strategy_version();
        let function = AbiFunctionSpec {
            role: "token".to_string(),
            name: "transfer".to_string(),
            selector_hex: call_selector_hex.to_string(),
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
        };
        crate::strategy::registry::upsert_template(StrategyTemplate {
            key: key.clone(),
            version: version.clone(),
            status,
            contract_roles: vec![ContractRoleBinding {
                role: "token".to_string(),
                address: "0x2222222222222222222222222222222222222222".to_string(),
                source_ref: "https://example.com/token-address".to_string(),
                codehash: None,
            }],
            actions: vec![ActionSpec {
                action_id: "transfer".to_string(),
                call_sequence: vec![function.clone()],
                preconditions: vec!["allowance_ok".to_string()],
                postconditions: vec!["balance_delta_positive".to_string()],
                risk_checks: vec!["max_notional".to_string()],
            }],
            constraints_json: "{}".to_string(),
            created_at_ns: updated_at_ns,
            updated_at_ns,
        })
        .expect("template should persist");
        crate::strategy::registry::upsert_abi_artifact(AbiArtifact {
            key: AbiArtifactKey {
                protocol: key.protocol.clone(),
                chain_id: key.chain_id,
                role: "token".to_string(),
                version: version.clone(),
            },
            source_ref: "https://example.com/token-abi".to_string(),
            codehash: None,
            abi_json: "[]".to_string(),
            functions: vec![function],
            created_at_ns: updated_at_ns,
            updated_at_ns,
        })
        .expect("abi should persist");
        crate::strategy::registry::set_activation(TemplateActivationState {
            key,
            version,
            enabled: activation_enabled,
            updated_at_ns,
            reason: Some("seed".to_string()),
        })
        .expect("activation should persist");
    }

    fn encode_message_queued_payload_for_test(
        sender: &str,
        message: &str,
        usdc_amount: u128,
        eth_amount: u128,
    ) -> String {
        let sender_hex = sender.trim().to_ascii_lowercase();
        let sender_hex = sender_hex.trim_start_matches("0x");
        let message_hex = hex::encode(message.as_bytes());
        let padded_message = if message_hex.len().is_multiple_of(64) {
            message_hex.clone()
        } else {
            format!(
                "{}{}",
                message_hex,
                "0".repeat(64 - (message_hex.len() % 64))
            )
        };

        format!(
            "0x{:0>64}{:064x}{:064x}{:064x}{:064x}{}",
            sender_hex,
            128u128,
            usdc_amount,
            eth_amount,
            message.len(),
            padded_message
        )
    }

    #[test]
    fn evm_event_to_inbox_message_decodes_sender_and_message_payload() {
        let event = EvmEvent {
            tx_hash: "0xfab6ba6ed49ad8b578b64692b324c5935d3216185eddc30411a0f29ba9485c6f"
                .to_string(),
            chain_id: 31_337,
            block_number: 9,
            log_index: 0,
            source: "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707".to_string(),
            payload: encode_message_queued_payload_for_test(
                "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                "message=who are you?",
                0,
                500_000_000_000_000,
            ),
        };

        let (body, sender) = evm_event_to_inbox_message(&event);
        assert_eq!(body, "message=who are you?");
        assert_eq!(sender, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    }

    #[test]
    fn evm_event_to_inbox_message_falls_back_to_raw_event_body_on_decode_error() {
        let event = EvmEvent {
            tx_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            chain_id: 31_337,
            block_number: 7,
            log_index: 1,
            source: "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707".to_string(),
            payload: "0x1234".to_string(),
        };

        let (body, sender) = evm_event_to_inbox_message(&event);
        assert_eq!(sender, event.source);
        assert!(
            body.contains("\"source\":\"evm_log\""),
            "fallback body should preserve raw evm event envelope"
        );
        assert!(
            body.contains(&event.tx_hash),
            "fallback body should preserve transaction hash for debugging"
        );
    }

    #[test]
    fn evm_event_fallback_payload_is_truncated_under_oversized_burst_inputs() {
        let oversized_payload = format!("0x{}", "ab".repeat(16_000));
        let event = EvmEvent {
            tx_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            chain_id: 31_337,
            block_number: 88,
            log_index: 4,
            source: "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707".to_string(),
            payload: oversized_payload,
        };

        let (body, sender) = evm_event_to_inbox_message(&event);
        assert_eq!(sender, event.source);
        assert!(
            body.chars().count() <= crate::storage::stable::MAX_INBOX_BODY_CHARS,
            "scheduler fallback body must remain capped for oversized decode failures"
        );
        assert!(
            body.contains("[truncated"),
            "scheduler fallback body should include truncation marker for diagnostics"
        );
        assert!(
            body.contains(&event.tx_hash),
            "scheduler fallback body should still include tx hash metadata"
        );
    }

    #[test]
    fn refresh_due_jobs_advances_single_interval_once() {
        init_scheduler_scope();
        let now_ns = 2_500u64;
        let interval_secs = 3u64;
        let interval_ns = interval_secs.saturating_mul(1_000_000_000);

        let mut config =
            stable::get_task_config(&TaskKind::PollInbox).expect("poll inbox config should exist");
        config.interval_secs = interval_secs;
        stable::upsert_task_config(config);

        stable::save_task_runtime(
            &TaskKind::PollInbox,
            &TaskScheduleRuntime {
                kind: TaskKind::PollInbox,
                next_due_ns: now_ns,
                backoff_until_ns: None,
                consecutive_failures: 0,
                pending_job_id: None,
                last_started_ns: None,
                last_finished_ns: None,
                last_error: None,
            },
        );

        let slot_start_ns = now_ns - (now_ns % interval_ns);
        let dedupe_key = format!("PollInbox:{slot_start_ns}");

        refresh_due_jobs(now_ns);
        let first = stable::list_recent_jobs(200)
            .into_iter()
            .find(|job| job.dedupe_key == dedupe_key)
            .expect("initial slot should be materialized");
        assert_eq!(first.status, JobStatus::Pending);

        let runtime_after_first = stable::get_task_runtime(&TaskKind::PollInbox);
        assert_eq!(
            runtime_after_first.next_due_ns,
            now_ns.saturating_add(interval_ns)
        );

        stable::complete_job(
            &first.id,
            JobStatus::Succeeded,
            None,
            now_ns.saturating_add(1),
            None,
        );

        let burst_check_now_ns = now_ns.saturating_add(3 * interval_ns);
        refresh_due_jobs(burst_check_now_ns);
        let second_slot_start_ns = burst_check_now_ns - (burst_check_now_ns % interval_ns);
        let second_dedupe_key = format!("PollInbox:{second_slot_start_ns}");
        let second = stable::list_recent_jobs(200)
            .into_iter()
            .find(|job| job.dedupe_key == second_dedupe_key)
            .expect("next slot should be materialized once");
        assert_eq!(second.status, JobStatus::Pending);

        let runtime_after_second = stable::get_task_runtime(&TaskKind::PollInbox);
        assert_eq!(
            runtime_after_second.next_due_ns,
            second_slot_start_ns.saturating_add(interval_ns)
        );
    }

    #[test]
    fn refresh_due_jobs_does_not_duplicate_slot_jobs() {
        init_scheduler_scope();
        let now_ns = 0u64;
        stable::save_task_runtime(
            &TaskKind::PollInbox,
            &TaskScheduleRuntime {
                kind: TaskKind::PollInbox,
                next_due_ns: now_ns,
                backoff_until_ns: None,
                consecutive_failures: 0,
                pending_job_id: None,
                last_started_ns: None,
                last_finished_ns: None,
                last_error: None,
            },
        );

        let interval_ns = 1_000_000_000u64; // 1 second
        let mut config =
            stable::get_task_config(&TaskKind::PollInbox).expect("poll inbox config should exist");
        config.interval_secs = 1;
        stable::upsert_task_config(config);
        let slot_start_ns = now_ns - (now_ns % interval_ns);
        let dedupe_key = format!("PollInbox:{slot_start_ns}");

        refresh_due_jobs(now_ns);
        let first_slot_count = stable::list_recent_jobs(200)
            .into_iter()
            .filter(|job| job.dedupe_key == dedupe_key)
            .count();
        assert_eq!(first_slot_count, 1);

        refresh_due_jobs(now_ns);
        let second_slot_count = stable::list_recent_jobs(200)
            .into_iter()
            .filter(|job| job.dedupe_key == dedupe_key)
            .count();
        assert_eq!(second_slot_count, 1);
    }

    #[test]
    fn topup_jobs_use_singleton_dedupe_across_periodic_and_explicit_triggers() {
        init_scheduler_scope();
        let now_ns = 30_000_000_000u64;

        let mut topup_config =
            stable::get_task_config(&TaskKind::TopUpCycles).expect("top-up config should exist");
        topup_config.enabled = true;
        topup_config.interval_secs = 30;
        stable::upsert_task_config(topup_config);

        let mut topup_runtime = stable::get_task_runtime(&TaskKind::TopUpCycles);
        topup_runtime.next_due_ns = now_ns;
        topup_runtime.pending_job_id = None;
        topup_runtime.backoff_until_ns = None;
        stable::save_task_runtime(&TaskKind::TopUpCycles, &topup_runtime);

        refresh_due_jobs(now_ns);
        let dedupe_key = topup_cycles_dedupe_key();
        let singleton_jobs: Vec<_> = stable::list_recent_jobs(200)
            .into_iter()
            .filter(|job| job.kind == TaskKind::TopUpCycles && job.dedupe_key == dedupe_key)
            .collect();
        assert_eq!(singleton_jobs.len(), 1, "periodic path should enqueue once");

        assert!(
            enqueue_topup_cycles_job("auto", now_ns).is_none(),
            "auto trigger should dedupe against pending singleton job"
        );
        assert!(
            enqueue_topup_cycles_job("tool", now_ns.saturating_add(1)).is_none(),
            "tool trigger should dedupe against pending singleton job"
        );

        let all_topup_jobs = stable::list_recent_jobs(200)
            .into_iter()
            .filter(|job| job.kind == TaskKind::TopUpCycles)
            .count();
        assert_eq!(
            all_topup_jobs, 1,
            "only one top-up job should remain queued"
        );
    }

    #[test]
    fn topup_waiting_outcome_enqueues_continuation_job() {
        stable::init_storage();
        settle_pending_topup_jobs(100);
        let before = topup_job_count();
        maybe_enqueue_topup_waiting_continuation(JobDispatchOutcome::TopUpWaiting, 100);
        let after = topup_job_count();
        assert_eq!(after, before.saturating_add(1));
        let continuation = stable::list_recent_jobs(500)
            .into_iter()
            .find(|job| job.kind == TaskKind::TopUpCycles && !job.is_terminal())
            .expect("continuation topup job should be pending");
        assert_eq!(continuation.dedupe_key, topup_cycles_dedupe_key());
        assert!(
            continuation.scheduled_for_ns > 100,
            "continuation should be scheduled in the future"
        );
    }

    #[test]
    fn topup_completed_outcome_does_not_enqueue_continuation_job() {
        stable::init_storage();
        settle_pending_topup_jobs(100);
        let before = topup_job_count();
        maybe_enqueue_topup_waiting_continuation(JobDispatchOutcome::Completed, 100);
        let after = topup_job_count();
        assert_eq!(after, before);
    }

    #[test]
    fn checkcycles_classifies_survival_tier_by_liquid_cycles() {
        let requirements = check_cycles_requirements().expect("requirements should compute");
        let low_threshold = requirements
            .required_cycles
            .saturating_mul(CHECKCYCLES_LOW_TIER_MULTIPLIER);

        let below_critical = requirements.required_cycles.saturating_sub(1);
        assert_eq!(
            classify_survival_tier(
                below_critical.saturating_add(DEFAULT_RESERVE_FLOOR_CYCLES),
                below_critical,
            )
            .expect("tier should classify"),
            SurvivalTier::Critical
        );

        let low_tier = requirements
            .required_cycles
            .saturating_add((low_threshold.saturating_sub(requirements.required_cycles)) / 2);
        assert_eq!(
            classify_survival_tier(
                low_tier.saturating_add(DEFAULT_RESERVE_FLOOR_CYCLES),
                low_tier
            )
            .expect("tier should classify"),
            SurvivalTier::LowCycles
        );

        assert_eq!(
            classify_survival_tier(
                low_threshold.saturating_add(DEFAULT_RESERVE_FLOOR_CYCLES),
                low_threshold,
            )
            .expect("tier should classify"),
            SurvivalTier::Normal
        );
    }

    #[test]
    fn checkcycles_survival_tier_recovery_hysteresis() {
        init_scheduler_scope();
        stable::set_scheduler_survival_tier(SurvivalTier::Critical);
        let mut runtime = stable::scheduler_runtime_view();
        assert_eq!(runtime.survival_tier, SurvivalTier::Critical);
        assert_eq!(runtime.survival_tier_recovery_checks, 0);

        stable::set_scheduler_survival_tier(SurvivalTier::Normal);
        runtime = stable::scheduler_runtime_view();
        assert_eq!(runtime.survival_tier, SurvivalTier::Critical);
        assert_eq!(runtime.survival_tier_recovery_checks, 1);

        stable::set_scheduler_survival_tier(SurvivalTier::Normal);
        runtime = stable::scheduler_runtime_view();
        assert_eq!(runtime.survival_tier, SurvivalTier::Critical);
        assert_eq!(runtime.survival_tier_recovery_checks, 2);

        stable::set_scheduler_survival_tier(SurvivalTier::Normal);
        runtime = stable::scheduler_runtime_view();
        assert_eq!(runtime.survival_tier, SurvivalTier::Normal);
        assert_eq!(runtime.survival_tier_recovery_checks, 0);
    }

    #[test]
    fn checkcycles_topup_trigger_requires_threshold_usdc_and_idle_state() {
        let mut snapshot = RuntimeSnapshot::default();
        snapshot.cycle_topup.enabled = true;
        snapshot.cycle_topup.auto_topup_cycle_threshold = 2_000_000_000_000;
        snapshot.cycle_topup.min_usdc_reserve = 10_000_000;

        assert!(should_trigger_cycle_topup(
            1_900_000_000_000,
            &snapshot,
            None,
            Some(20_000_001)
        ));
        assert!(!should_trigger_cycle_topup(
            2_100_000_000_000,
            &snapshot,
            None,
            Some(20_000_001)
        ));
        assert!(!should_trigger_cycle_topup(
            249_000_000_000,
            &snapshot,
            None,
            Some(20_000_001)
        ));
        assert!(!should_trigger_cycle_topup(
            1_900_000_000_000,
            &snapshot,
            Some(&TopUpStage::Preflight),
            Some(20_000_001)
        ));
        assert!(!should_trigger_cycle_topup(
            1_900_000_000_000,
            &snapshot,
            Some(&TopUpStage::Failed {
                stage: "Preflight".to_string(),
                error: "boom".to_string(),
                failed_at_ns: 1,
                attempts: 1,
            }),
            Some(20_000_001)
        ));
        assert!(should_trigger_cycle_topup(
            1_900_000_000_000,
            &snapshot,
            Some(&TopUpStage::Completed {
                cycles_minted: 1,
                usdc_spent: 1,
                completed_at_ns: 1,
            }),
            Some(20_000_000)
        ));
    }

    #[test]
    fn topup_failed_recovery_due_only_after_backoff_window() {
        let failed_at_ns = 1_000_000_000_u64;
        let failed_state = TopUpStage::Failed {
            stage: "Preflight".to_string(),
            error: "boom".to_string(),
            failed_at_ns,
            attempts: 1,
        };
        let backoff_ns = TOPUP_FAILED_RECOVERY_BACKOFF_SECS.saturating_mul(1_000_000_000);

        assert!(!topup_failed_recovery_due(None, failed_at_ns));
        assert!(!topup_failed_recovery_due(
            Some(&failed_state),
            failed_at_ns.saturating_add(backoff_ns).saturating_sub(1),
        ));
        assert!(topup_failed_recovery_due(
            Some(&failed_state),
            failed_at_ns.saturating_add(backoff_ns),
        ));
    }

    #[test]
    fn maybe_recover_failed_topup_resets_and_restarts_when_backoff_elapsed() {
        stable::init_storage();
        stable::clear_topup_state();

        let now_ns = TOPUP_FAILED_RECOVERY_BACKOFF_SECS
            .saturating_mul(1_000_000_000)
            .saturating_add(100);
        let failed_state = TopUpStage::Failed {
            stage: "Preflight".to_string(),
            error: "boom".to_string(),
            failed_at_ns: 0,
            attempts: 1,
        };
        stable::write_topup_state(&failed_state);

        let snapshot = RuntimeSnapshot {
            evm_address: Some("0x1111111111111111111111111111111111111111".to_string()),
            cycle_topup: crate::domain::types::CycleTopUpConfig {
                enabled: true,
                ..crate::domain::types::CycleTopUpConfig::default()
            },
            ..RuntimeSnapshot::default()
        };

        assert!(maybe_recover_failed_topup(
            &snapshot,
            Some(&failed_state),
            now_ns
        ));
        assert!(matches!(
            stable::read_topup_state(),
            Some(TopUpStage::Preflight)
        ));
    }

    #[test]
    fn maybe_recover_failed_topup_respects_backoff_window() {
        stable::init_storage();
        stable::clear_topup_state();

        let failed_at_ns = 10_000u64;
        let failed_state = TopUpStage::Failed {
            stage: "Preflight".to_string(),
            error: "boom".to_string(),
            failed_at_ns,
            attempts: 1,
        };
        stable::write_topup_state(&failed_state);

        let snapshot = RuntimeSnapshot {
            evm_address: Some("0x1111111111111111111111111111111111111111".to_string()),
            cycle_topup: crate::domain::types::CycleTopUpConfig {
                enabled: true,
                ..crate::domain::types::CycleTopUpConfig::default()
            },
            ..RuntimeSnapshot::default()
        };

        let now_ns = failed_at_ns.saturating_add(1);
        assert!(!maybe_recover_failed_topup(
            &snapshot,
            Some(&failed_state),
            now_ns,
        ));
        assert!(matches!(
            stable::read_topup_state(),
            Some(TopUpStage::Failed { .. })
        ));
    }

    #[test]
    fn operation_class_mapping_for_scheduler_tasks_is_stable() {
        assert_eq!(
            operation_class_for_task(&TaskKind::AgentTurn),
            Some(SurvivalOperationClass::Inference)
        );
        assert_eq!(
            operation_class_for_task(&TaskKind::PollInbox),
            Some(SurvivalOperationClass::EvmPoll)
        );
        assert_eq!(operation_class_for_task(&TaskKind::CheckCycles), None);
        assert_eq!(operation_class_for_task(&TaskKind::TopUpCycles), None);
        assert_eq!(operation_class_for_task(&TaskKind::Reconcile), None);
    }

    #[test]
    fn lease_ttl_for_agent_turn_is_extended_for_continuation_rounds() {
        assert_eq!(
            lease_ttl_ns(&TaskKind::AgentTurn),
            timing::AGENT_TURN_LEASE_TTL_NS
        );
        assert_eq!(
            lease_ttl_ns(&TaskKind::PollInbox),
            timing::LIGHTWEIGHT_LEASE_TTL_NS
        );
        assert_eq!(
            lease_ttl_ns(&TaskKind::CheckCycles),
            timing::LIGHTWEIGHT_LEASE_TTL_NS
        );
        assert_eq!(
            lease_ttl_ns(&TaskKind::TopUpCycles),
            timing::LIGHTWEIGHT_LEASE_TTL_NS
        );
        assert_eq!(
            lease_ttl_ns(&TaskKind::Reconcile),
            timing::LIGHTWEIGHT_LEASE_TTL_NS
        );
    }

    #[test]
    fn low_tier_policy_allows_only_inference_and_evm_poll_operations() {
        init_scheduler_scope();
        stable::set_scheduler_survival_tier(SurvivalTier::LowCycles);

        assert!(stable::can_run_survival_operation(
            &SurvivalOperationClass::Inference,
            10
        ));
        assert!(stable::can_run_survival_operation(
            &SurvivalOperationClass::EvmPoll,
            10
        ));
        assert!(!stable::can_run_survival_operation(
            &SurvivalOperationClass::EvmBroadcast,
            10
        ));
        assert!(!stable::can_run_survival_operation(
            &SurvivalOperationClass::ThresholdSign,
            10
        ));
    }

    #[test]
    fn scheduler_blocks_inference_job_when_survival_operation_backoff_active() {
        init_scheduler_scope();
        let now_ns = 10u64;
        stable::set_scheduler_survival_tier(SurvivalTier::Normal);
        stable::record_survival_operation_failure(&SurvivalOperationClass::Inference, now_ns, 1);

        assert!(!stable::can_run_survival_operation(
            &SurvivalOperationClass::Inference,
            now_ns.saturating_add(500),
        ));
        assert_eq!(
            stable::survival_operation_consecutive_failures(&SurvivalOperationClass::Inference),
            1
        );
    }

    #[test]
    fn scheduler_blocks_operation_class_on_critical_tier() {
        init_scheduler_scope();
        stable::set_scheduler_survival_tier(SurvivalTier::Critical);

        assert!(!stable::can_run_survival_operation(
            &SurvivalOperationClass::Inference,
            10
        ));
        assert!(!stable::can_run_survival_operation(
            &SurvivalOperationClass::EvmPoll,
            10
        ));
    }

    #[test]
    fn scheduler_allows_operations_after_low_tier_backoff_cooldown() {
        init_scheduler_scope();
        stable::set_scheduler_survival_tier(SurvivalTier::Normal);
        let now_ns = 10u64;
        stable::record_survival_operation_failure(&SurvivalOperationClass::Inference, now_ns, 1);

        assert!(!stable::can_run_survival_operation(
            &SurvivalOperationClass::Inference,
            now_ns.saturating_add(500),
        ));

        let cooldown = stable::survival_operation_backoff_until(&SurvivalOperationClass::Inference)
            .expect("backoff should be active");
        assert!(
            !stable::can_run_survival_operation(
                &SurvivalOperationClass::Inference,
                cooldown.saturating_sub(1)
            ),
            "operation should remain blocked at backoff boundary"
        );
        let after_backoff = cooldown.saturating_add(1);
        assert!(
            stable::can_run_survival_operation(&SurvivalOperationClass::Inference, after_backoff),
            "operation should be runnable after backoff window"
        );
    }

    #[test]
    fn scheduler_tick_drains_multiple_pending_jobs_in_one_tick() {
        stable::init_storage();
        stable::init_scheduler_defaults(0);
        for kind in TaskKind::all() {
            stable::set_task_enabled(kind, false);
        }

        let poll_job = stable::enqueue_job_if_absent(
            TaskKind::PollInbox,
            TaskLane::Mutating,
            "PollInbox:manual-1".to_string(),
            0,
            0,
        );
        let reconcile_job = stable::enqueue_job_if_absent(
            TaskKind::Reconcile,
            TaskLane::Mutating,
            "Reconcile:manual-1".to_string(),
            0,
            1,
        );
        assert!(poll_job.is_some(), "poll job should enqueue");
        assert!(reconcile_job.is_some(), "reconcile job should enqueue");

        block_on_with_spin(scheduler_tick());

        let jobs = stable::list_recent_jobs(10);
        let poll = jobs
            .iter()
            .find(|job| job.dedupe_key == "PollInbox:manual-1")
            .expect("poll job should be present");
        let reconcile = jobs
            .iter()
            .find(|job| job.dedupe_key == "Reconcile:manual-1")
            .expect("reconcile job should be present");
        assert_eq!(poll.status, JobStatus::Succeeded);
        assert_eq!(reconcile.status, JobStatus::Succeeded);
    }

    #[test]
    fn reconcile_job_activates_template_when_canary_passes() {
        stable::init_storage();
        stable::init_scheduler_defaults(0);
        for kind in TaskKind::all() {
            stable::set_task_enabled(kind, false);
        }

        seed_strategy_for_reconcile(
            "reconcile-activate",
            current_time_ns(),
            "0xa9059cbb",
            TemplateStatus::Active,
            false,
        );

        let reconcile_job = stable::enqueue_job_if_absent(
            TaskKind::Reconcile,
            TaskLane::Mutating,
            "Reconcile:strategy-activate".to_string(),
            0,
            0,
        );
        assert!(reconcile_job.is_some(), "reconcile job should enqueue");
        block_on_with_spin(scheduler_tick());

        let activation = crate::strategy::registry::activation(
            &strategy_key("reconcile-activate"),
            &strategy_version(),
        )
        .expect("activation should exist");
        assert!(activation.enabled);
        assert!(activation
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("canary"));
    }

    #[test]
    fn reconcile_job_disables_stale_template_activation() {
        stable::init_storage();
        stable::init_scheduler_defaults(0);
        for kind in TaskKind::all() {
            stable::set_task_enabled(kind, false);
        }

        let stale_updated_at_ns = current_time_ns().saturating_sub(
            STRATEGY_TEMPLATE_FRESHNESS_WINDOW_SECS
                .saturating_add(1)
                .saturating_mul(1_000_000_000),
        );
        seed_strategy_for_reconcile(
            "reconcile-stale",
            stale_updated_at_ns,
            "0xa9059cbb",
            TemplateStatus::Active,
            true,
        );

        let reconcile_job = stable::enqueue_job_if_absent(
            TaskKind::Reconcile,
            TaskLane::Mutating,
            "Reconcile:strategy-stale".to_string(),
            0,
            0,
        );
        assert!(reconcile_job.is_some(), "reconcile job should enqueue");
        block_on_with_spin(scheduler_tick());

        let activation = crate::strategy::registry::activation(
            &strategy_key("reconcile-stale"),
            &strategy_version(),
        )
        .expect("activation should exist");
        assert!(!activation.enabled);
        assert!(activation
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("stale_template"));
    }

    #[test]
    fn reconcile_job_disables_activation_when_provenance_fails() {
        stable::init_storage();
        stable::init_scheduler_defaults(0);
        for kind in TaskKind::all() {
            stable::set_task_enabled(kind, false);
        }

        seed_strategy_for_reconcile(
            "reconcile-provenance",
            current_time_ns(),
            "0xdeadbeef",
            TemplateStatus::Active,
            true,
        );

        let reconcile_job = stable::enqueue_job_if_absent(
            TaskKind::Reconcile,
            TaskLane::Mutating,
            "Reconcile:strategy-provenance".to_string(),
            0,
            0,
        );
        assert!(reconcile_job.is_some(), "reconcile job should enqueue");
        block_on_with_spin(scheduler_tick());

        let activation = crate::strategy::registry::activation(
            &strategy_key("reconcile-provenance"),
            &strategy_version(),
        )
        .expect("activation should exist");
        assert!(!activation.enabled);
        assert!(activation
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("provenance_or_canary_failed"));
    }

    #[test]
    fn scheduler_tick_runs_retention_maintenance_in_low_priority_lane() {
        stable::init_storage();
        stable::init_scheduler_defaults(0);
        for kind in TaskKind::all() {
            stable::set_task_enabled(kind, false);
        }
        stable::set_retention_config(RetentionConfig {
            jobs_max_age_secs: 1,
            jobs_max_records: 0,
            dedupe_max_age_secs: 1,
            turns_max_age_secs: 7 * 24 * 60 * 60,
            transitions_max_age_secs: 7 * 24 * 60 * 60,
            tools_max_age_secs: 7 * 24 * 60 * 60,
            inbox_max_age_secs: 14 * 24 * 60 * 60,
            outbox_max_age_secs: 14 * 24 * 60 * 60,
            maintenance_batch_size: 50,
            maintenance_interval_secs: 30,
        })
        .expect("retention config should persist");
        let now_ns = current_time_ns();
        let old_scheduled_for_ns = now_ns.saturating_sub(5_000_000_000);
        let old_job_id = "job:00000000000000000001:00000000000000000001".to_string();
        stable::save_job_for_tests(ScheduledJob {
            id: old_job_id.clone(),
            kind: TaskKind::PollInbox,
            lane: TaskLane::Mutating,
            dedupe_key: format!("PollInbox:{}", old_scheduled_for_ns),
            priority: 1,
            created_at_ns: old_scheduled_for_ns,
            scheduled_for_ns: old_scheduled_for_ns,
            started_at_ns: Some(old_scheduled_for_ns),
            finished_at_ns: Some(old_scheduled_for_ns.saturating_add(1)),
            status: JobStatus::Succeeded,
            attempts: 1,
            max_attempts: 3,
            last_error: None,
        });
        stable::insert_dedupe_for_tests(
            format!("PollInbox:{}", old_scheduled_for_ns),
            old_job_id.clone(),
        );

        let poll_job = stable::enqueue_job_if_absent(
            TaskKind::PollInbox,
            TaskLane::Mutating,
            "PollInbox:maintenance-order".to_string(),
            now_ns,
            0,
        );
        assert!(poll_job.is_some(), "poll job should enqueue");

        block_on_with_spin(scheduler_tick());

        let recent = stable::list_recent_jobs(200);
        let manual = recent
            .iter()
            .find(|job| job.dedupe_key == "PollInbox:maintenance-order")
            .expect("manual poll job should still run before maintenance");
        assert_eq!(manual.status, JobStatus::Succeeded);
        assert!(
            recent.iter().all(|job| job.id != old_job_id),
            "retention maintenance should prune old terminal jobs"
        );
    }

    #[test]
    fn poll_inbox_job_skips_evm_poll_when_inbox_contract_is_unset() {
        stable::init_storage();
        stable::init_scheduler_defaults(0);
        for kind in TaskKind::all() {
            stable::set_task_enabled(kind, false);
        }

        stable::set_evm_cursor(&crate::domain::types::EvmPollCursor {
            chain_id: 8453,
            next_block: 0,
            next_log_index: 0,
            ..crate::domain::types::EvmPollCursor::default()
        });

        let poll_job = stable::enqueue_job_if_absent(
            TaskKind::PollInbox,
            TaskLane::Mutating,
            "PollInbox:evm-cursor".to_string(),
            0,
            0,
        );
        assert!(poll_job.is_some(), "poll job should enqueue");

        block_on_with_spin(scheduler_tick());

        let cursor = stable::runtime_snapshot().evm_cursor;
        assert_eq!(cursor.next_block, 0);
        assert_eq!(
            stable::survival_operation_consecutive_failures(&SurvivalOperationClass::EvmPoll),
            0
        );

        let jobs = stable::list_recent_jobs(10);
        let poll = jobs
            .iter()
            .find(|job| job.dedupe_key == "PollInbox:evm-cursor")
            .expect("poll job should be present");
        assert_eq!(poll.status, JobStatus::Succeeded);
    }

    #[test]
    fn poll_inbox_job_stages_pending_messages_without_running_agent_turn() {
        stable::init_storage();
        stable::init_scheduler_defaults(0);
        for kind in TaskKind::all() {
            stable::set_task_enabled(kind, false);
        }

        stable::post_inbox_message(
            "first staged by poll".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )
        .expect("first inbox message should be accepted");
        stable::post_inbox_message(
            "second staged by poll".to_string(),
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        )
        .expect("second inbox message should be accepted");

        let turn_counter_before = stable::runtime_snapshot().turn_counter;
        let poll_job = stable::enqueue_job_if_absent(
            TaskKind::PollInbox,
            TaskLane::Mutating,
            "PollInbox:stage-only".to_string(),
            0,
            0,
        );
        assert!(poll_job.is_some(), "poll job should enqueue");

        block_on_with_spin(scheduler_tick());

        let stats = stable::inbox_stats();
        assert_eq!(stats.pending_count, 0);
        assert_eq!(stats.staged_count, 2);
        assert_eq!(stats.consumed_count, 0);
        assert_eq!(stable::runtime_snapshot().turn_counter, turn_counter_before);
        assert!(
            stable::list_outbox_messages(10).is_empty(),
            "poll job must not emit an outbox reply"
        );
    }

    #[test]
    fn poll_inbox_job_advances_evm_cursor_when_filters_are_configured() {
        with_host_stub_env(
            &[("IC_AUTOMATON_EVM_RPC_STUB_MAX_LOG_BLOCK_SPAN", Some("10"))],
            || {
                stable::init_storage();
                stable::init_scheduler_defaults(0);
                for kind in TaskKind::all() {
                    stable::set_task_enabled(kind, false);
                }

                stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
                    .expect("rpc url should be configurable");
                stable::set_evm_address(Some(
                    "0x1111111111111111111111111111111111111111".to_string(),
                ))
                .expect("evm address should be configurable");
                stable::set_inbox_contract_address(Some(
                    "0x2222222222222222222222222222222222222222".to_string(),
                ))
                .expect("inbox contract should be configurable");
                stable::set_evm_cursor(&crate::domain::types::EvmPollCursor {
                    chain_id: 8453,
                    next_block: 0,
                    next_log_index: 0,
                    ..crate::domain::types::EvmPollCursor::default()
                });

                let poll_job = stable::enqueue_job_if_absent(
                    TaskKind::PollInbox,
                    TaskLane::Mutating,
                    "PollInbox:evm-cursor".to_string(),
                    0,
                    0,
                );
                assert!(poll_job.is_some(), "poll job should enqueue");

                block_on_with_spin(scheduler_tick());

                let cursor = stable::runtime_snapshot().evm_cursor;
                assert_eq!(cursor.next_block, 1);
                assert_eq!(cursor.consecutive_empty_polls, 1);
                assert!(cursor.last_poll_at_ns > 0);

                let jobs = stable::list_recent_jobs(10);
                let poll = jobs
                    .iter()
                    .find(|job| job.dedupe_key == "PollInbox:evm-cursor")
                    .expect("poll job should be present");
                assert_eq!(poll.status, JobStatus::Succeeded);
            },
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn poll_inbox_eth_get_logs_failures_wait_for_next_scheduling_slot() {
        stable::init_storage();
        init_scheduler_scope();
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should be configurable");
        stable::set_inbox_contract_address(Some(
            "0x2222222222222222222222222222222222222222".to_string(),
        ))
        .expect("inbox contract should be configurable");

        let dedupe_key = "PollInbox:no-retry-eth-getlogs".to_string();
        with_host_stub_env(
            &[("IC_AUTOMATON_EVM_RPC_STUB_MAX_LOG_BLOCK_SPAN", Some("0"))],
            || {
                let poll_job = stable::enqueue_job_if_absent(
                    TaskKind::PollInbox,
                    TaskLane::Mutating,
                    dedupe_key.clone(),
                    0,
                    0,
                );
                assert!(poll_job.is_some(), "poll job should enqueue");

                let processed = block_on_with_spin(run_one_pending_mutating_job(0))
                    .expect("poll job should be processed");
                assert!(processed, "one job should be processed");
            },
        );

        let jobs = stable::list_recent_jobs(20);
        let poll = jobs
            .iter()
            .find(|job| job.dedupe_key == dedupe_key)
            .expect("poll job should be present");
        assert_eq!(poll.status, JobStatus::Skipped);
        assert!(
            poll.last_error
                .as_deref()
                .unwrap_or_default()
                .contains("eth_getLogs failed"),
            "failed eth_getLogs error should be preserved for diagnostics"
        );
        assert_eq!(
            stable::survival_operation_consecutive_failures(&SurvivalOperationClass::EvmPoll),
            0
        );

        let runtime = stable::get_task_runtime(&TaskKind::PollInbox);
        assert!(runtime.pending_job_id.is_none());
        assert!(runtime.backoff_until_ns.is_none());
        assert_eq!(runtime.consecutive_failures, 0);
        assert!(
            !jobs.iter().any(|job| {
                job.kind == TaskKind::PollInbox && matches!(job.status, JobStatus::Pending)
            }),
            "poll inbox failure should not enqueue immediate/backoff retries"
        );
    }

    #[test]
    fn poll_inbox_job_skips_rpc_outcall_until_empty_poll_backoff_expires() {
        stable::init_storage();
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should be configurable");
        stable::set_inbox_contract_address(Some(
            "0x2222222222222222222222222222222222222222".to_string(),
        ))
        .expect("inbox contract should be configurable");

        let now_ns = 500_000_000_000u64;
        // Gap must be shorter than the backoff for consecutive_empty_polls=2.
        // Backoff index 1 = BASE_TICK_SECS * 4 seconds.
        let gap_ns = 1_000_000_000u64; // 1 second — well within any backoff window
        stable::set_evm_cursor(&crate::domain::types::EvmPollCursor {
            chain_id: 8453,
            next_block: 10,
            next_log_index: 0,
            last_poll_at_ns: now_ns.saturating_sub(gap_ns),
            consecutive_empty_polls: 2,
            ..crate::domain::types::EvmPollCursor::default()
        });

        block_on_with_spin(run_poll_inbox_job(now_ns)).expect("poll job should not fail");
        let after = stable::runtime_snapshot().evm_cursor;
        assert_eq!(
            after.next_block, 10,
            "cursor must not advance when backoff window is active"
        );
        assert_eq!(
            after.last_poll_at_ns,
            now_ns.saturating_sub(gap_ns),
            "last poll timestamp must stay unchanged when skipping rpc outcall"
        );
    }

    #[test]
    fn poll_inbox_job_syncs_wallet_balances_and_clears_bootstrap_pending() {
        stable::init_storage();
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should be configurable");
        stable::set_inbox_contract_address(Some(
            "0x2222222222222222222222222222222222222222".to_string(),
        ))
        .expect("inbox contract should be configurable");
        stable::set_wallet_balance_bootstrap_pending(true);

        let now_ns = 123_000_000_000u64;
        block_on_with_spin(run_poll_inbox_job(now_ns)).expect("poll job should not fail");

        let balance = stable::wallet_balance_snapshot();
        assert_eq!(balance.eth_balance_wei_hex.as_deref(), Some("0x1"));
        assert_eq!(balance.usdc_balance_raw_hex.as_deref(), Some("0x2a"));
        assert_eq!(
            balance.usdc_contract_address.as_deref(),
            Some("0x3333333333333333333333333333333333333333")
        );
        assert_eq!(balance.last_synced_at_ns, Some(now_ns));
        assert!(balance.last_error.is_none());
        assert!(
            !stable::wallet_balance_bootstrap_pending(),
            "successful first sync should clear bootstrap gate"
        );
    }

    #[test]
    fn wallet_sync_recovery_policy_tunes_response_limit_for_oversized_errors() {
        let snapshot = RuntimeSnapshot {
            wallet_balance_sync: WalletBalanceSyncConfig {
                max_response_bytes: 256,
                ..WalletBalanceSyncConfig::default()
            },
            ..RuntimeSnapshot::default()
        };
        let failure = classify_evm_failure(
            "eth_call failed: evm rpc outcall failed: call rejected: 1 - Http body exceeds size limit of 256 bytes.",
        );
        let decision = decide_recovery_action(&failure, &wallet_sync_recovery_context(&snapshot));

        assert_eq!(decision.action, RecoveryPolicyAction::TuneResponseLimit);
        assert_eq!(
            decision
                .response_limit_adjustment
                .as_ref()
                .map(|adjustment| (adjustment.from_bytes, adjustment.to_bytes)),
            Some((256, 512))
        );
    }

    #[test]
    fn wallet_sync_response_limit_recovery_persists_in_runtime_config() {
        stable::init_storage();
        let config = WalletBalanceSyncConfig {
            max_response_bytes: 256,
            ..WalletBalanceSyncConfig::default()
        };
        stable::set_wallet_balance_sync_config(config).expect("wallet sync config should persist");

        apply_response_limit_tuning(
            &RecoveryOperation::WalletBalanceSync,
            &ResponseLimitAdjustment {
                from_bytes: 256,
                to_bytes: 512,
            },
        )
        .expect("wallet sync max response bytes should tune");

        assert_eq!(stable::wallet_balance_sync_config().max_response_bytes, 512);
    }

    #[test]
    fn poll_inbox_job_wallet_sync_uses_tier_aware_due_windows_after_bootstrap() {
        stable::init_storage();
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should be configurable");
        stable::set_inbox_contract_address(Some(
            "0x2222222222222222222222222222222222222222".to_string(),
        ))
        .expect("inbox contract should be configurable");
        stable::set_wallet_balance_sync_config(WalletBalanceSyncConfig {
            normal_interval_secs: 300,
            low_cycles_interval_secs: 900,
            ..WalletBalanceSyncConfig::default()
        })
        .expect("wallet sync config should persist");
        stable::set_wallet_balance_snapshot(WalletBalanceSnapshot {
            eth_balance_wei_hex: Some("0xaaaa".to_string()),
            usdc_balance_raw_hex: Some("0xbbbb".to_string()),
            usdc_decimals: 6,
            usdc_contract_address: Some("0x3333333333333333333333333333333333333333".to_string()),
            last_synced_at_ns: Some(1_000_000_000_000),
            last_synced_block: None,
            last_error: None,
        });
        stable::set_wallet_balance_bootstrap_pending(false);

        stable::set_scheduler_survival_tier(SurvivalTier::Normal);
        block_on_with_spin(run_poll_inbox_job(1_250_000_000_000))
            .expect("normal-tier pre-due poll should succeed");
        let after_normal_skip = stable::wallet_balance_snapshot();
        assert_eq!(
            after_normal_skip.eth_balance_wei_hex.as_deref(),
            Some("0xaaaa")
        );
        assert_eq!(after_normal_skip.last_synced_at_ns, Some(1_000_000_000_000));

        stable::set_scheduler_survival_tier(SurvivalTier::LowCycles);
        block_on_with_spin(run_poll_inbox_job(1_600_000_000_000))
            .expect("low-tier pre-due poll should succeed");
        let after_low_skip = stable::wallet_balance_snapshot();
        assert_eq!(
            after_low_skip.eth_balance_wei_hex.as_deref(),
            Some("0xaaaa")
        );
        assert_eq!(after_low_skip.last_synced_at_ns, Some(1_000_000_000_000));

        block_on_with_spin(run_poll_inbox_job(1_901_000_000_000))
            .expect("low-tier due poll should succeed");
        let after_due = stable::wallet_balance_snapshot();
        assert_eq!(after_due.eth_balance_wei_hex.as_deref(), Some("0x1"));
        assert_eq!(after_due.usdc_balance_raw_hex.as_deref(), Some("0x2a"));
        assert_eq!(after_due.last_synced_at_ns, Some(1_901_000_000_000));
    }

    #[test]
    fn poll_inbox_job_wallet_sync_failure_is_non_fatal_and_preserves_last_good_snapshot() {
        stable::init_storage();
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should be configurable");
        stable::set_wallet_balance_sync_config(WalletBalanceSyncConfig {
            discover_usdc_via_inbox: false,
            ..WalletBalanceSyncConfig::default()
        })
        .expect("wallet sync config should persist");
        stable::set_wallet_balance_snapshot(WalletBalanceSnapshot {
            eth_balance_wei_hex: Some("0x9999".to_string()),
            usdc_balance_raw_hex: Some("0x8888".to_string()),
            usdc_decimals: 6,
            usdc_contract_address: None,
            last_synced_at_ns: Some(55),
            last_synced_block: Some(7),
            last_error: None,
        });
        stable::set_wallet_balance_bootstrap_pending(true);

        block_on_with_spin(run_poll_inbox_job(777)).expect("poll job should not fail");

        let balance = stable::wallet_balance_snapshot();
        assert_eq!(balance.eth_balance_wei_hex.as_deref(), Some("0x9999"));
        assert_eq!(balance.usdc_balance_raw_hex.as_deref(), Some("0x8888"));
        assert_eq!(balance.last_synced_at_ns, Some(55));
        assert_eq!(balance.last_synced_block, Some(7));
        assert_eq!(
            balance.last_error.as_deref(),
            Some("usdc contract address is not configured")
        );
        assert!(
            stable::wallet_balance_bootstrap_pending(),
            "bootstrap gate must remain set until a successful sync occurs"
        );
    }
}
