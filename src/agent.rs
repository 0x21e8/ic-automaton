use crate::domain::state_machine;
use crate::domain::types::{AgentEvent, AgentState, InferenceInput, TurnRecord};
use crate::features::{infer_with_provider, EvmPoller, MockEvmPoller, MockSignerAdapter};
use crate::storage::stable;
use crate::tools::ToolManager;

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

pub async fn run_scheduled_turn_job() -> Result<(), String> {
    let snapshot = stable::runtime_snapshot();
    if !snapshot.loop_enabled || snapshot.turn_in_flight {
        return Ok(());
    }

    let snapshot = stable::increment_turn_counter();
    let turn_id = snapshot
        .last_turn_id
        .clone()
        .unwrap_or_else(|| "turn-0".to_string());
    let started_at_ns = current_time_ns();
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
        stable::complete_turn(AgentState::Faulted, Some(error.clone()));
        return Err(error);
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
            stable::complete_turn(AgentState::Faulted, Some(reason.clone()));
            return Err(reason);
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
        stable::set_last_error(Some(reason.clone()));
        stable::complete_turn(AgentState::Faulted, Some(reason.clone()));
        return Err(reason);
    }

    if has_input {
        let context_summary = format!("evm_events:{evm_events}");
        let input = InferenceInput {
            input: "poll:".to_string(),
            context_snippet: context_summary,
            turn_id: turn_id.clone(),
        };

        match infer_with_provider(&snapshot, &input).await {
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

    stable::complete_turn(state, last_error.clone());
    if let Some(reason) = last_error {
        return Err(reason);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::RuntimeSnapshot;
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn reset_runtime(
        state: AgentState,
        loop_enabled: bool,
        turn_in_flight: bool,
        turn_counter: u64,
    ) {
        stable::init_storage();
        let snapshot = RuntimeSnapshot {
            state,
            loop_enabled,
            turn_in_flight,
            turn_counter,
            last_turn_id: Some(format!("turn-{turn_counter}")),
            ..RuntimeSnapshot::default()
        };
        stable::save_runtime_snapshot(&snapshot);
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

    #[test]
    fn skipped_when_loop_disabled_is_successful_and_non_mutating() {
        reset_runtime(AgentState::Sleeping, false, false, 41);

        let result = block_on_with_spin(run_scheduled_turn_job());
        assert!(
            result.is_ok(),
            "disabled loop should be treated as non-failure"
        );

        let snapshot = stable::runtime_snapshot();
        assert_eq!(snapshot.turn_counter, 41);
        assert_eq!(snapshot.state, AgentState::Sleeping);
        assert!(!snapshot.turn_in_flight);
    }

    #[test]
    fn skipped_when_turn_already_in_flight_is_successful_and_non_mutating() {
        reset_runtime(AgentState::Sleeping, true, true, 7);

        let result = block_on_with_spin(run_scheduled_turn_job());
        assert!(
            result.is_ok(),
            "in-flight guard should skip without reporting a failure"
        );

        let snapshot = stable::runtime_snapshot();
        assert_eq!(snapshot.turn_counter, 7);
        assert_eq!(snapshot.state, AgentState::Sleeping);
        assert!(snapshot.turn_in_flight);
    }

    #[test]
    fn invalid_start_state_faults_turn_and_releases_lock() {
        reset_runtime(AgentState::Inferring, true, false, 0);

        let result = block_on_with_spin(run_scheduled_turn_job());
        assert!(result.is_err(), "invalid transition should fail the turn");

        let snapshot = stable::runtime_snapshot();
        assert_eq!(snapshot.state, AgentState::Faulted);
        assert_eq!(snapshot.turn_counter, 1);
        assert!(!snapshot.turn_in_flight);
        assert!(
            snapshot.last_error.is_some(),
            "failure reason should be persisted for observability"
        );
    }

    #[test]
    fn faulted_state_recovers_autonomously_on_next_tick() {
        reset_runtime(AgentState::Faulted, true, false, 0);

        let result = block_on_with_spin(run_scheduled_turn_job());
        assert!(
            result.is_ok(),
            "faulted runtime should self-heal without manual reset"
        );

        let snapshot = stable::runtime_snapshot();
        assert_eq!(snapshot.state, AgentState::Sleeping);
        assert_eq!(snapshot.turn_counter, 1);
        assert!(!snapshot.turn_in_flight);
        assert!(
            snapshot.last_error.is_none(),
            "successful recovery turn should clear persisted error"
        );
    }
}
