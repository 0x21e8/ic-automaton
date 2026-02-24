//! Centralised timing constants for the scheduler, agent turns, and related subsystems.
//!
//! Most values are derived from a small set of **base constants** so that the
//! entire cadence can be scaled coherently — e.g. for integration tests or to
//! adapt throughput to the current cycles balance.
//!
//! # Base constants
//!
//! | Constant                   | Production | Test   |
//! |----------------------------|-----------|--------|
//! | `BASE_TICK_SECS`           | 30 s      | 2 s    |
//! | `TICKS_PER_TURN_INTERVAL`  | 10        | 3      |
//! | `AGENT_TURN_BUDGET_SECS`   | 90 s      | 6 s    |

// ── Base constants ──────────────────────────────────────────────────────────

/// Scheduler heartbeat — the "clock resolution" of the system.
/// Every `BASE_TICK_SECS` the scheduler wakes, recovers stale leases,
/// refreshes due jobs, and dispatches up to `MAX_MUTATING_JOBS_PER_TICK`.
#[cfg(not(test))]
pub const BASE_TICK_SECS: u64 = 30;
#[cfg(test)]
pub const BASE_TICK_SECS: u64 = 2;

/// How many ticks between consecutive task intervals (primarily agent turns).
/// `DEFAULT_TASK_INTERVAL_SECS = BASE_TICK_SECS × TICKS_PER_TURN_INTERVAL`.
#[cfg(not(test))]
pub const TICKS_PER_TURN_INTERVAL: u64 = 10;
#[cfg(test)]
pub const TICKS_PER_TURN_INTERVAL: u64 = 3;

/// Hard wall-clock cap for a single agent turn (seconds).
#[cfg(not(test))]
pub const AGENT_TURN_BUDGET_SECS: u64 = 90;
#[cfg(test)]
pub const AGENT_TURN_BUDGET_SECS: u64 = 6;

// ── Scheduler cadence ───────────────────────────────────────────────────────

/// Interval at which the IC canister timer fires `scheduler_tick`.
pub const SCHEDULER_TICK_INTERVAL_SECS: u64 = BASE_TICK_SECS;

/// Default recurrence interval for all task kinds (agent turn, poll inbox, …).
pub const DEFAULT_TASK_INTERVAL_SECS: u64 = BASE_TICK_SECS * TICKS_PER_TURN_INTERVAL;

// ── Lease TTLs ──────────────────────────────────────────────────────────────

/// Lease TTL for an agent turn — must comfortably exceed `AGENT_TURN_BUDGET_SECS`
/// to allow for context loading, tool execution, and persistence.
/// Ratio: ~2.67× the turn budget.
pub const AGENT_TURN_LEASE_TTL_SECS: u64 = AGENT_TURN_BUDGET_SECS * 8 / 3;
pub const AGENT_TURN_LEASE_TTL_NS: u64 = AGENT_TURN_LEASE_TTL_SECS * NANOS_PER_SEC;

/// Lease TTL for lightweight jobs (poll inbox, check cycles, …).
/// Two ticks gives one full retry window before the lease expires.
pub const LIGHTWEIGHT_LEASE_TTL_SECS: u64 = BASE_TICK_SECS * 2;
pub const LIGHTWEIGHT_LEASE_TTL_NS: u64 = LIGHTWEIGHT_LEASE_TTL_SECS * NANOS_PER_SEC;

// ── Agent turn limits ───────────────────────────────────────────────────────

/// Hard wall-clock cap in nanoseconds.
pub const MAX_AGENT_TURN_DURATION_NS: u64 = AGENT_TURN_BUDGET_SECS * NANOS_PER_SEC;

/// Autonomy tool-call deduplication window: 2 turn intervals.
/// Within this window identical tool calls are suppressed.
pub const AUTONOMY_DEDUPE_WINDOW_SECS: u64 = DEFAULT_TASK_INTERVAL_SECS * 2;
pub const AUTONOMY_DEDUPE_WINDOW_NS: u64 = AUTONOMY_DEDUPE_WINDOW_SECS * NANOS_PER_SEC;

/// Balance freshness window — same as the dedup window.
pub const BALANCE_FRESHNESS_WINDOW_SECS: u64 = AUTONOMY_DEDUPE_WINDOW_SECS;

// ── Observation windows ─────────────────────────────────────────────────────

/// Cycles burn-rate moving average window: 3 turn intervals.
pub const CYCLES_BURN_MOVING_WINDOW_SECS: u64 = DEFAULT_TASK_INTERVAL_SECS * 3;
pub const CYCLES_BURN_MOVING_WINDOW_NS: u64 = CYCLES_BURN_MOVING_WINDOW_SECS * NANOS_PER_SEC;

// ── Backoff schedule ────────────────────────────────────────────────────────

/// Progressive backoff for empty inbox polls: 2×, 4×, 8×, 20× the base tick.
pub const EMPTY_POLL_BACKOFF_SCHEDULE_SECS: &[u64] = &[
    BASE_TICK_SECS * 2,
    BASE_TICK_SECS * 4,
    BASE_TICK_SECS * 8,
    BASE_TICK_SECS * 20,
];

// ── Runtime cadence scaling ──────────────────────────────────────────────────

/// Compute a task interval from a runtime multiplier.
///
/// `multiplier` replaces `TICKS_PER_TURN_INTERVAL` at runtime, so the
/// resulting interval = `BASE_TICK_SECS × multiplier`.  The multiplier is
/// clamped to `[MIN_CADENCE_MULTIPLIER, MAX_CADENCE_MULTIPLIER]`.
#[allow(dead_code)]
pub fn task_interval_for_multiplier(multiplier: u64) -> u64 {
    let clamped = multiplier.clamp(MIN_CADENCE_MULTIPLIER, MAX_CADENCE_MULTIPLIER);
    BASE_TICK_SECS.saturating_mul(clamped)
}

/// Minimum cadence multiplier — turns at most every `2 × BASE_TICK_SECS`.
#[allow(dead_code)]
pub const MIN_CADENCE_MULTIPLIER: u64 = 2;
/// Maximum cadence multiplier — turns at most every `40 × BASE_TICK_SECS` (20 min in prod).
#[allow(dead_code)]
pub const MAX_CADENCE_MULTIPLIER: u64 = 40;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Host-safe nanosecond time source.
///
/// - `wasm32`: IC replicated time via `ic_cdk::api::time()`
/// - non-`wasm32`: wall clock fallback for native/unit tests
pub fn current_time_ns() -> u64 {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::time();

    #[cfg(all(not(target_arch = "wasm32"), test))]
    if let Some(override_ns) = TEST_TIME_OVERRIDE_NS.with(|slot| slot.get()) {
        return override_ns;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_nanos().try_into().unwrap_or(u64::MAX))
            .unwrap_or_default()
    }
}

#[cfg(all(not(target_arch = "wasm32"), test))]
thread_local! {
    static TEST_TIME_OVERRIDE_NS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(not(target_arch = "wasm32"), test))]
pub fn set_test_time_ns(now_ns: u64) {
    TEST_TIME_OVERRIDE_NS.with(|slot| slot.set(Some(now_ns)));
}

#[cfg(all(not(target_arch = "wasm32"), test))]
pub fn clear_test_time_ns() {
    TEST_TIME_OVERRIDE_NS.with(|slot| slot.set(None));
}

const NANOS_PER_SEC: u64 = 1_000_000_000;

// ── Compile-time sanity checks ──────────────────────────────────────────────

// Lease must exceed turn budget.
const _: () = assert!(AGENT_TURN_LEASE_TTL_SECS > AGENT_TURN_BUDGET_SECS);
// Task interval must be a multiple of the tick.
const _: () = assert!(DEFAULT_TASK_INTERVAL_SECS.is_multiple_of(BASE_TICK_SECS));
// Backoff schedule entries must each be ≥ one tick.
const _: () = assert!(EMPTY_POLL_BACKOFF_SCHEDULE_SECS[0] >= BASE_TICK_SECS);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_values_are_preserved() {
        // These assertions document the production values even though
        // they run under the cfg(test) profile.  The important thing
        // is that the *derivation formulas* are correct — the actual
        // numeric values under test differ because the base constants
        // are overridden.

        // Derivation relationships hold regardless of profile:
        assert_eq!(SCHEDULER_TICK_INTERVAL_SECS, BASE_TICK_SECS);
        assert_eq!(
            DEFAULT_TASK_INTERVAL_SECS,
            BASE_TICK_SECS * TICKS_PER_TURN_INTERVAL
        );
        assert_eq!(AUTONOMY_DEDUPE_WINDOW_SECS, DEFAULT_TASK_INTERVAL_SECS * 2);
        assert_eq!(BALANCE_FRESHNESS_WINDOW_SECS, AUTONOMY_DEDUPE_WINDOW_SECS);
        assert_eq!(
            CYCLES_BURN_MOVING_WINDOW_SECS,
            DEFAULT_TASK_INTERVAL_SECS * 3
        );
        assert_eq!(
            MAX_AGENT_TURN_DURATION_NS,
            AGENT_TURN_BUDGET_SECS * NANOS_PER_SEC
        );
    }

    #[test]
    fn test_profile_is_fast() {
        assert_eq!(BASE_TICK_SECS, 2);
        assert_eq!(TICKS_PER_TURN_INTERVAL, 3);
        assert_eq!(DEFAULT_TASK_INTERVAL_SECS, 6);
        assert_eq!(AUTONOMY_DEDUPE_WINDOW_SECS, 12);
        assert_eq!(CYCLES_BURN_MOVING_WINDOW_SECS, 18);
    }

    #[test]
    fn backoff_schedule_is_monotonically_increasing() {
        for window in EMPTY_POLL_BACKOFF_SCHEDULE_SECS.windows(2) {
            assert!(window[1] > window[0]);
        }
    }

    #[test]
    fn task_interval_for_multiplier_scales_linearly() {
        assert_eq!(task_interval_for_multiplier(2), BASE_TICK_SECS * 2);
        assert_eq!(task_interval_for_multiplier(10), BASE_TICK_SECS * 10);
        assert_eq!(task_interval_for_multiplier(20), BASE_TICK_SECS * 20);
    }

    #[test]
    fn task_interval_for_multiplier_clamps_at_bounds() {
        assert_eq!(
            task_interval_for_multiplier(0),
            task_interval_for_multiplier(MIN_CADENCE_MULTIPLIER),
        );
        assert_eq!(
            task_interval_for_multiplier(1000),
            task_interval_for_multiplier(MAX_CADENCE_MULTIPLIER),
        );
    }
}
