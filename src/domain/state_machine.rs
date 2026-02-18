use crate::domain::types::{AgentEvent, AgentState, TransitionError};

pub fn transition(current: &AgentState, event: &AgentEvent) -> Result<AgentState, TransitionError> {
    match (current, event) {
        (AgentState::Bootstrapping, AgentEvent::TimerTick) => Ok(AgentState::LoadingContext),
        (AgentState::Idle, AgentEvent::TimerTick) => Ok(AgentState::LoadingContext),
        (AgentState::Sleeping, AgentEvent::TimerTick) => Ok(AgentState::LoadingContext),
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
