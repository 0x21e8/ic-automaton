use crate::domain::state_machine;
use crate::domain::types::{AgentEvent, AgentState, InferenceInput, TurnRecord};
use crate::features::{
    EvmPoller, InferenceAdapter, MockEvmPoller, MockInferenceAdapter, MockSignerAdapter,
};
use crate::storage::stable;
use crate::tools::ToolManager;

pub const TURN_TIMER_SECONDS: u64 = 30;

pub async fn run_scheduled_turn() {
    let snapshot = stable::runtime_snapshot();
    if !snapshot.loop_enabled || snapshot.turn_in_flight {
        return;
    }

    let mut snapshot = stable::increment_turn_counter();
    let turn_id = snapshot
        .last_turn_id
        .clone()
        .unwrap_or_else(|| "turn-0".to_string());
    let started_at_ns = ic_cdk::api::time();
    let initial_state = snapshot.state.clone();
    let mut state = snapshot.state.clone();
    let mut last_error: Option<String> = None;
    let mut tool_calls = Vec::new();

    if let Err(error) = advance_state(&mut state, &AgentEvent::TimerTick, &turn_id) {
        let _ = advance_state(
            &mut state,
            &AgentEvent::TurnFailed {
                reason: error.clone(),
            },
            &turn_id,
        );
        stable::complete_turn(AgentState::Faulted, Some(error));
        return;
    }

    let poll = MockEvmPoller::poll(&MockEvmPoller, &snapshot.evm_cursor);
    let (next_cursor, evm_events) = match poll {
        Ok(poll) => (poll.cursor, poll.events.len()),
        Err(reason) => {
            let _ = advance_state(
                &mut state,
                &AgentEvent::TurnFailed {
                    reason: reason.clone(),
                },
                &turn_id,
            );
            stable::complete_turn(AgentState::Faulted, Some(reason));
            return;
        }
    };
    let has_input = evm_events > 0;

    if let Err(reason) = advance_state(
        &mut state,
        &AgentEvent::EvmPollCompleted {
            new_events: evm_events as u32,
            has_input,
        },
        &turn_id,
    ) {
        snapshot.last_error = Some(reason.clone());
        stable::set_last_error(Some(reason.clone()));
        stable::complete_turn(AgentState::Faulted, Some(reason));
        return;
    }

    if has_input {
        let context_summary = format!("evm_events:{evm_events}");
        let input = InferenceInput {
            input: "poll:".to_string(),
            context_snippet: context_summary,
            turn_id: turn_id.clone(),
        };

        match MockInferenceAdapter::infer(&MockInferenceAdapter, &input) {
            Ok(inference) => {
                if let Err(error) =
                    advance_state(&mut state, &AgentEvent::InferenceCompleted, &turn_id)
                {
                    last_error = Some(error);
                } else {
                    let signer = MockSignerAdapter::new();
                    let mut manager = ToolManager::new();
                    tool_calls =
                        manager.execute_actions(&state, &inference.tool_calls, &signer, &turn_id);

                    if tool_calls.iter().any(|record| !record.success) {
                        last_error = Some("tool execution reported failures".to_string());
                    }

                    if let Err(error) =
                        advance_state(&mut state, &AgentEvent::ActionsCompleted, &turn_id)
                    {
                        last_error = Some(error);
                    }
                }
            }
            Err(reason) => {
                let _ = advance_state(
                    &mut state,
                    &AgentEvent::TurnFailed {
                        reason: reason.clone(),
                    },
                    &turn_id,
                );
                last_error = Some(reason);
            }
        }

        if last_error.is_none() {
            if let Err(reason) = advance_state(&mut state, &AgentEvent::PersistCompleted, &turn_id)
            {
                last_error = Some(reason);
            } else {
                let _ = advance_state(&mut state, &AgentEvent::SleepRequested, &turn_id);
            }
        }
    }

    if let Some(reason) = last_error.clone() {
        let _ = advance_state(&mut state, &AgentEvent::TurnFailed { reason }, &turn_id);
    }

    let turn_record = TurnRecord {
        id: turn_id.clone(),
        created_at_ns: started_at_ns,
        state_from: initial_state,
        state_to: state.clone(),
        source_events: evm_events as u32,
        tool_call_count: u32::try_from(tool_calls.len()).unwrap_or(0),
        input_summary: if has_input {
            format!("evm:{}:{}", next_cursor.chain_id, evm_events)
        } else {
            "no-input".to_string()
        },
        error: last_error.clone(),
    };

    stable::append_turn_record(&turn_record, &tool_calls);
    if last_error.is_none() {
        stable::set_evm_cursor(&next_cursor);
    }

    stable::complete_turn(state, last_error);
}

fn advance_state(state: &mut AgentState, event: &AgentEvent, turn_id: &str) -> Result<(), String> {
    let next = state_machine::transition(state, event).map_err(|error| {
        format!(
            "invalid transition from {:?} on {:?}: {}",
            error.from, event, error.reason
        )
    })?;
    stable::record_transition(turn_id, state, &next, event, None);
    *state = next;
    Ok(())
}
