/// Agent lifecycle state machine.
///
/// A pure function (`transition`) maps `(current_state, event)` pairs to the
/// next `AgentState`.  All valid transitions are listed explicitly; any pair
/// not covered returns a `TransitionError`, making illegal state transitions
/// compile-time visible through exhaustive match analysis.
///
/// # State diagram (happy path)
///
/// ```text
/// Bootstrapping / Idle / Sleeping / Faulted
///         │  TimerTick
///         ▼
///   LoadingContext
///         │  ContextLoaded  ──────────────────────────────────┐
///         │  EvmPollCompleted { has_input: true }             │
///         ▼                                                    ▼
///      Inferring  ── InferenceCompleted ──► ExecutingActions
///                                                 │ ActionsCompleted
///                                                 ▼
///                                           Persisting
///                                                 │ PersistCompleted
///                                                 ▼
///                                            Sleeping
/// ```
///
/// Any state transitions to `Faulted` on `TurnFailed`; `Faulted` recovers
/// to `Bootstrapping` on `ResetFault` or to `LoadingContext` on `TimerTick`.
use crate::domain::types::{AgentEvent, AgentState, TransitionError};

/// Attempt the state transition `(current, event) → next`.
///
/// Returns the new `AgentState` on success, or a `TransitionError` describing
/// the invalid `(from, event)` pair.
pub fn transition(current: &AgentState, event: &AgentEvent) -> Result<AgentState, TransitionError> {
    match (current, event) {
        (AgentState::Bootstrapping, AgentEvent::TimerTick) => Ok(AgentState::LoadingContext),
        (AgentState::Idle, AgentEvent::TimerTick) => Ok(AgentState::LoadingContext),
        (AgentState::Sleeping, AgentEvent::TimerTick) => Ok(AgentState::LoadingContext),
        (AgentState::Faulted, AgentEvent::TimerTick) => Ok(AgentState::LoadingContext),
        (
            AgentState::LoadingContext,
            AgentEvent::EvmPollCompleted {
                has_input: true, ..
            },
        ) => Ok(AgentState::Inferring),
        (
            AgentState::LoadingContext,
            AgentEvent::EvmPollCompleted {
                has_input: false, ..
            },
        ) => Ok(AgentState::Sleeping),
        (AgentState::LoadingContext, AgentEvent::ContextLoaded) => Ok(AgentState::Inferring),
        (AgentState::Inferring, AgentEvent::InferenceCompleted) => Ok(AgentState::ExecutingActions),
        (AgentState::ExecutingActions, AgentEvent::ActionsCompleted) => Ok(AgentState::Persisting),
        (AgentState::Persisting, AgentEvent::PersistCompleted) => Ok(AgentState::Sleeping),
        (AgentState::Sleeping, AgentEvent::SleepRequested) => Ok(AgentState::Sleeping),
        (AgentState::Faulted, AgentEvent::ResetFault) => Ok(AgentState::Bootstrapping),
        (AgentState::Bootstrapping, AgentEvent::TurnFailed { .. }) => Ok(AgentState::Faulted),
        (AgentState::Idle, AgentEvent::TurnFailed { .. }) => Ok(AgentState::Faulted),
        (AgentState::LoadingContext, AgentEvent::TurnFailed { .. }) => Ok(AgentState::Faulted),
        (AgentState::Inferring, AgentEvent::TurnFailed { .. }) => Ok(AgentState::Faulted),
        (AgentState::ExecutingActions, AgentEvent::TurnFailed { .. }) => Ok(AgentState::Faulted),
        (AgentState::Persisting, AgentEvent::TurnFailed { .. }) => Ok(AgentState::Faulted),
        (AgentState::Sleeping, AgentEvent::TurnFailed { .. }) => Ok(AgentState::Faulted),
        (_, AgentEvent::TurnFailed { .. }) if matches!(current, AgentState::Faulted) => {
            Ok(AgentState::Faulted)
        }
        _ => Err(TransitionError {
            from: current.clone(),
            event: format!("{event:?}"),
            reason: "invalid transition".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faulted_state_recovers_on_timer_tick() {
        let next = transition(&AgentState::Faulted, &AgentEvent::TimerTick)
            .expect("faulted state should recover on timer tick");
        assert_eq!(next, AgentState::LoadingContext);
    }

    #[test]
    fn reset_fault_path_still_supported() {
        let next = transition(&AgentState::Faulted, &AgentEvent::ResetFault)
            .expect("explicit reset should remain valid");
        assert_eq!(next, AgentState::Bootstrapping);
    }

    #[test]
    fn faulted_state_preserves_fault_signal() {
        let next = transition(
            &AgentState::Faulted,
            &AgentEvent::TurnFailed {
                reason: "repeat".to_string(),
            },
        )
        .expect("faulted state should remain faulted on repeated failure");
        assert_eq!(next, AgentState::Faulted);
    }

    #[test]
    fn inferring_does_not_accept_timer_tick_directly() {
        let transition_result = transition(&AgentState::Inferring, &AgentEvent::TimerTick);
        assert!(
            transition_result.is_err(),
            "timer tick must not re-enter mid-turn execution state"
        );
    }
}
