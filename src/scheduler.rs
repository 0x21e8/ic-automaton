use crate::agent::run_scheduled_turn_job;
use crate::domain::types::{JobStatus, ScheduledJob, TaskKind, TaskLane};
use crate::storage::stable;
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};

const POLL_INBOX_STAGE_BATCH_SIZE: usize = 50;

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
    let now_ns = ic_cdk::api::time();
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

    if stable::mutating_lease_active(now_ns) {
        log!(
            SchedulerLogPriority::Info,
            "scheduler_tick_end mutating lease active now={now_ns}",
        );
        stable::record_scheduler_tick_end(now_ns, None);
        return;
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
        None => {
            log!(
                SchedulerLogPriority::Info,
                "scheduler_tick_end no_job now={now_ns}"
            );
            stable::record_scheduler_tick_end(now_ns, None);
            return;
        }
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
            ic_cdk::api::time(),
        );
        stable::record_scheduler_tick_end(ic_cdk::api::time(), Some(error));
        return;
    }

    let result = dispatch_job(&job).await;
    match result {
        Ok(()) => stable::complete_job(&job.id, JobStatus::Succeeded, None, ic_cdk::api::time()),
        Err(error) => stable::complete_job(
            &job.id,
            JobStatus::Failed,
            Some(error.clone()),
            ic_cdk::api::time(),
        ),
    }

    log!(
        SchedulerLogPriority::Info,
        "scheduler_tick_end result job_id={} kind={:?}",
        job.id,
        job.kind
    );
    stable::record_scheduler_tick_end(ic_cdk::api::time(), None);
}

async fn dispatch_job(job: &ScheduledJob) -> Result<(), String> {
    match job.kind {
        TaskKind::AgentTurn => run_scheduled_turn_job().await,
        TaskKind::PollInbox => {
            let staged = stable::stage_pending_inbox_messages(
                POLL_INBOX_STAGE_BATCH_SIZE,
                ic_cdk::api::time(),
            );
            log!(
                SchedulerLogPriority::Info,
                "scheduler_poll_inbox_staged count={}",
                staged
            );
            Ok(())
        }
        TaskKind::CheckCycles | TaskKind::Reconcile => Ok(()),
    }
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

        runtime.next_due_ns = runtime.next_due_ns.saturating_add(interval_ns);
        stable::save_task_runtime(&kind, &runtime);
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
    use crate::domain::types::{TaskScheduleConfig, TaskScheduleRuntime};

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
            now_ns.saturating_add(2 * interval_ns)
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
}
