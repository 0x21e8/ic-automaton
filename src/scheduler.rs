use crate::agent::run_scheduled_turn_job;
use crate::domain::cycle_admission::{
    affordability_requirements, can_afford_with_reserve, estimate_operation_cost,
    AffordabilityRequirements, OperationClass, DEFAULT_RESERVE_FLOOR_CYCLES,
    DEFAULT_SAFETY_MARGIN_BPS,
};
use crate::domain::types::{
    EvmEvent, JobStatus, RuntimeSnapshot, ScheduledJob, SurvivalOperationClass, SurvivalTier,
    TaskKind, TaskLane,
};
use crate::features::evm::fetch_wallet_balance_sync_read;
use crate::features::{EvmPoller, HttpEvmPoller};
use crate::storage::stable;
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};
use serde_json::json;

const POLL_INBOX_STAGE_BATCH_SIZE: usize = 50;
const CHECKCYCLES_REFERENCE_ENVELOPE_CYCLES: u128 = 5_000_000_000;
const CHECKCYCLES_LOW_TIER_MULTIPLIER: u128 = 4;
const MAX_MUTATING_JOBS_PER_TICK: u8 = 4;
const EMPTY_POLL_BACKOFF_SCHEDULE_SECS: &[u64] = &[30, 60, 120, 300];

fn current_time_ns() -> u64 {
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

    log!(
        SchedulerLogPriority::Info,
        "scheduler_tick_end processed_jobs={} now={}",
        processed_jobs,
        current_time_ns()
    );
    stable::record_scheduler_tick_end(current_time_ns(), terminal_error);
}

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
        );
        return Err(error);
    }

    if let Some(operation_class) = operation_class_for_task(&job.kind) {
        if !stable::can_run_survival_operation(&operation_class, now_ns) {
            let reason = "operation blocked by survival policy";
            stable::complete_job(
                &job.id,
                JobStatus::Skipped,
                Some(reason.to_string()),
                current_time_ns(),
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
        Ok(()) => stable::complete_job(&job.id, JobStatus::Succeeded, None, current_time_ns()),
        Err(error) => stable::complete_job(
            &job.id,
            JobStatus::Failed,
            Some(error.clone()),
            current_time_ns(),
        ),
    }

    Ok(true)
}

async fn dispatch_job(job: &ScheduledJob) -> Result<(), String> {
    match job.kind {
        TaskKind::AgentTurn => run_scheduled_turn_job().await,
        TaskKind::PollInbox => run_poll_inbox_job(current_time_ns()).await,
        TaskKind::CheckCycles => run_check_cycles().await,
        TaskKind::Reconcile => Ok(()),
    }
}

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

fn empty_poll_backoff_delay_ns(consecutive_empty_polls: u32) -> u64 {
    let idx = usize::try_from(consecutive_empty_polls).unwrap_or(usize::MAX);
    let secs = EMPTY_POLL_BACKOFF_SCHEDULE_SECS
        .get(idx)
        .copied()
        .unwrap_or(*EMPTY_POLL_BACKOFF_SCHEDULE_SECS.last().unwrap_or(&300));
    secs.saturating_mul(1_000_000_000)
}

fn poll_inbox_rpc_due(now_ns: u64, last_poll_at_ns: u64, consecutive_empty_polls: u32) -> bool {
    if last_poll_at_ns == 0 {
        return true;
    }
    let min_delay_ns = empty_poll_backoff_delay_ns(consecutive_empty_polls);
    now_ns >= last_poll_at_ns.saturating_add(min_delay_ns)
}

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
            stable::record_wallet_balance_sync_error(error.clone());
            log!(
                SchedulerLogPriority::Error,
                "scheduler_wallet_balance_sync_error stage=fetch_balances error={}",
                error
            );
        }
    }
}

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
        let poll = poller.poll(&snapshot.evm_cursor).await.inspect_err(|_| {
            stable::record_survival_operation_failure(
                &SurvivalOperationClass::EvmPoll,
                now_ns,
                stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_POLL,
            );
        })?;

        fetched_events = poll.events.len();
        for event in &poll.events {
            if !stable::try_mark_evm_event_ingested(&event.tx_hash, event.log_index) {
                skipped_duplicate_events = skipped_duplicate_events.saturating_add(1);
                continue;
            }
            stable::post_inbox_message(evm_event_to_inbox_body(event), event.source.clone())?;
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

async fn run_check_cycles() -> Result<(), String> {
    let total_cycles = ic_cdk::api::canister_cycle_balance();
    let liquid_cycles = ic_cdk::api::canister_liquid_cycle_balance();
    let expected = classify_survival_tier(total_cycles, liquid_cycles)?;
    let requirements = check_cycles_requirements()?;

    stable::set_scheduler_survival_tier(expected.clone());
    let runtime_tier = stable::scheduler_survival_tier();
    let recovery_checks = stable::scheduler_survival_tier_recovery_checks();

    log!(
        SchedulerLogPriority::Info,
    "scheduler_checkcycles total_cycles={} liquid_cycles={} reserve_floor_cycles={} required_cycles={} low_tier_limit={} observed_tier={:?} runtime_tier={:?} recovery_checks={}",
        total_cycles,
        liquid_cycles,
        DEFAULT_RESERVE_FLOOR_CYCLES,
        requirements.required_cycles,
        requirements.required_cycles.saturating_mul(CHECKCYCLES_LOW_TIER_MULTIPLIER),
        expected,
        runtime_tier,
        recovery_checks
    );
    Ok(())
}

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
        let dedupe_key = format!("{}:{}", kind.as_str(), slot_start_ns);
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

fn operation_class_for_task(kind: &TaskKind) -> Option<SurvivalOperationClass> {
    match kind {
        TaskKind::AgentTurn => Some(SurvivalOperationClass::Inference),
        TaskKind::PollInbox => Some(SurvivalOperationClass::EvmPoll),
        _ => None,
    }
}

fn lease_ttl_ns(kind: &TaskKind) -> u64 {
    match kind {
        TaskKind::AgentTurn => 240_000_000_000,
        TaskKind::PollInbox => 60_000_000_000,
        TaskKind::CheckCycles => 60_000_000_000,
        TaskKind::Reconcile => 60_000_000_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{
        SurvivalOperationClass, TaskScheduleConfig, TaskScheduleRuntime, WalletBalanceSnapshot,
        WalletBalanceSyncConfig,
    };
    use crate::storage::stable;
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

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
        assert_eq!(operation_class_for_task(&TaskKind::Reconcile), None);
    }

    #[test]
    fn lease_ttl_for_agent_turn_is_extended_for_continuation_rounds() {
        assert_eq!(lease_ttl_ns(&TaskKind::AgentTurn), 240_000_000_000);
        assert_eq!(lease_ttl_ns(&TaskKind::PollInbox), 60_000_000_000);
        assert_eq!(lease_ttl_ns(&TaskKind::CheckCycles), 60_000_000_000);
        assert_eq!(lease_ttl_ns(&TaskKind::Reconcile), 60_000_000_000);
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
        stable::set_evm_cursor(&crate::domain::types::EvmPollCursor {
            chain_id: 8453,
            next_block: 10,
            next_log_index: 0,
            last_poll_at_ns: now_ns.saturating_sub(30_000_000_000),
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
            now_ns.saturating_sub(30_000_000_000),
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
