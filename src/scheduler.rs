use crate::agent::run_scheduled_turn_job;
use crate::domain::cycle_admission::{
    affordability_requirements, can_afford_with_reserve, estimate_operation_cost,
    AffordabilityRequirements, OperationClass, DEFAULT_RESERVE_FLOOR_CYCLES,
    DEFAULT_SAFETY_MARGIN_BPS,
};
use crate::domain::types::{
    JobStatus, ScheduledJob, SurvivalOperationClass, SurvivalTier, TaskKind, TaskLane,
};
use crate::storage::stable;
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};

const POLL_INBOX_STAGE_BATCH_SIZE: usize = 50;
const CHECKCYCLES_REFERENCE_ENVELOPE_CYCLES: u128 = 5_000_000_000;
const CHECKCYCLES_LOW_TIER_MULTIPLIER: u128 = 4;
const MAX_MUTATING_JOBS_PER_TICK: u8 = 4;

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
        TaskKind::PollInbox => {
            let staged = stable::stage_pending_inbox_messages(
                POLL_INBOX_STAGE_BATCH_SIZE,
                current_time_ns(),
            );
            log!(
                SchedulerLogPriority::Info,
                "scheduler_poll_inbox_staged count={}",
                staged
            );
            Ok(())
        }
        TaskKind::CheckCycles => run_check_cycles().await,
        TaskKind::Reconcile => Ok(()),
    }
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
        TaskKind::AgentTurn => 120_000_000_000,
        TaskKind::PollInbox => 60_000_000_000,
        TaskKind::CheckCycles => 60_000_000_000,
        TaskKind::Reconcile => 60_000_000_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{SurvivalOperationClass, TaskScheduleConfig, TaskScheduleRuntime};
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
}
