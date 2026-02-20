use crate::domain::state_machine;
use crate::domain::types::SurvivalOperationClass;
use crate::domain::types::{
    AgentEvent, AgentState, ConversationEntry, InboxMessage, InferenceInput, MemoryFact, TurnRecord,
};
#[cfg(target_arch = "wasm32")]
use crate::features::ThresholdSignerAdapter;
use crate::features::{
    infer_with_provider, EvmPoller, HttpEvmPoller, MockEvmPoller, MockSignerAdapter,
};
use crate::storage::stable;
use crate::tools::{SignerPort, ToolManager};
use std::collections::BTreeSet;

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

fn build_inference_context_summary(
    staged_message_count: usize,
    evm_events: usize,
    inbox_preview: &str,
    memory_facts: &[MemoryFact],
) -> String {
    let mut parts = vec![
        format!("inbox_messages:{staged_message_count}"),
        format!("evm_events:{evm_events}"),
    ];
    if !memory_facts.is_empty() {
        let memory_lines = memory_facts
            .iter()
            .map(|fact| format!("{}={}", fact.key, fact.value))
            .collect::<Vec<_>>()
            .join("\n");
        parts.push(format!("[memory]\n{memory_lines}"));
    }
    parts.push(format!("inbox_preview:{inbox_preview}"));
    parts.join(";")
}

fn record_conversation_entries(
    turn_id: &str,
    staged_messages: &[InboxMessage],
    consumed_message_ids: &[String],
    agent_reply: &str,
    timestamp_ns: u64,
) {
    if consumed_message_ids.is_empty() || agent_reply.trim().is_empty() {
        return;
    }

    let consumed_ids = consumed_message_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for message in staged_messages {
        if !consumed_ids.contains(message.id.as_str()) {
            continue;
        }
        stable::append_conversation_entry(
            &message.posted_by,
            ConversationEntry {
                inbox_message_id: message.id.clone(),
                sender_body: message.body.clone(),
                agent_reply: agent_reply.to_string(),
                turn_id: turn_id.to_string(),
                timestamp_ns,
            },
        );
    }
}

pub async fn run_scheduled_turn_job() -> Result<(), String> {
    let snapshot = stable::runtime_snapshot();
    if !snapshot.loop_enabled || snapshot.turn_in_flight {
        return Ok(());
    }

    let snapshot = stable::increment_turn_counter();
    #[cfg(target_arch = "wasm32")]
    if snapshot.evm_address.is_none() && !snapshot.ecdsa_key_name.trim().is_empty() {
        let _ = crate::features::threshold_signer::derive_and_cache_evm_address(
            &snapshot.ecdsa_key_name,
        )
        .await;
    }

    let turn_id = snapshot
        .last_turn_id
        .clone()
        .unwrap_or_else(|| "turn-0".to_string());
    let started_at_ns = current_time_ns();
    let initial_state = snapshot.state.clone();
    let mut state = snapshot.state.clone();
    let mut last_error: Option<String> = None;
    let mut tool_calls = Vec::new();
    let mut assistant_reply: Option<String> = None;

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

    let staged_messages = stable::list_staged_inbox_messages(50);
    let staged_message_ids = staged_messages
        .iter()
        .map(|message| message.id.clone())
        .collect::<Vec<_>>();
    let staged_message_count = staged_messages.len();

    let can_poll =
        stable::can_run_survival_operation(&SurvivalOperationClass::EvmPoll, started_at_ns);
    let poll = if can_poll {
        if snapshot.evm_rpc_url.trim().is_empty() {
            Some(MockEvmPoller::poll(&MockEvmPoller, &snapshot.evm_cursor).await)
        } else {
            Some(match HttpEvmPoller::from_snapshot(&snapshot) {
                Ok(poller) => poller.poll(&snapshot.evm_cursor).await,
                Err(error) => Err(error),
            })
        }
    } else {
        None
    };
    let (next_cursor, evm_events) = match poll {
        Some(Ok(poll)) => {
            stable::record_survival_operation_success(&SurvivalOperationClass::EvmPoll);
            (poll.cursor, poll.events.len())
        }
        Some(Err(reason)) => {
            stable::record_survival_operation_failure(
                &SurvivalOperationClass::EvmPoll,
                started_at_ns,
                stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_POLL,
            );
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
        None => (snapshot.evm_cursor.clone(), 0),
    };
    let has_input = evm_events > 0 || staged_message_count > 0;

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
        let inbox_preview = staged_messages
            .iter()
            .map(|message| message.body.as_str())
            .collect::<Vec<_>>()
            .join(" | ");
        let memory_facts = stable::list_all_memory_facts(20);
        let context_summary = build_inference_context_summary(
            staged_message_count,
            evm_events,
            &inbox_preview,
            &memory_facts,
        );
        let input = InferenceInput {
            input: if staged_message_count > 0 {
                format!("inbox:{inbox_preview}")
            } else {
                "poll:".to_string()
            },
            context_snippet: context_summary,
            turn_id: turn_id.clone(),
        };

        match infer_with_provider(&snapshot, &input).await {
            Ok(inference) => {
                let trimmed_reply = inference.explanation.trim().to_string();
                if !trimmed_reply.is_empty() {
                    assistant_reply = Some(trimmed_reply);
                }
                if let Err(error) =
                    advance_state(&mut state, &AgentEvent::InferenceCompleted, &turn_id)
                {
                    last_error = Some(error);
                } else {
                    #[cfg(target_arch = "wasm32")]
                    let signer: Box<dyn SignerPort> = if snapshot.ecdsa_key_name.trim().is_empty() {
                        Box::new(MockSignerAdapter::new())
                    } else {
                        Box::new(ThresholdSignerAdapter::new(snapshot.ecdsa_key_name.clone()))
                    };

                    #[cfg(not(target_arch = "wasm32"))]
                    let signer: Box<dyn SignerPort> = Box::new(MockSignerAdapter::new());

                    let mut manager = ToolManager::new();
                    tool_calls = manager
                        .execute_actions(&state, &inference.tool_calls, signer.as_ref(), &turn_id)
                        .await;

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
                if staged_message_count > 0 {
                    if let Some(reply) = assistant_reply.clone() {
                        match stable::post_outbox_message(
                            turn_id.clone(),
                            reply.clone(),
                            staged_message_ids.clone(),
                        ) {
                            Ok(_) => {
                                record_conversation_entries(
                                    &turn_id,
                                    &staged_messages,
                                    &staged_message_ids,
                                    &reply,
                                    current_time_ns(),
                                );
                            }
                            Err(error) => {
                                last_error = Some(error);
                            }
                        }
                    }
                }
                if last_error.is_none() {
                    if !staged_message_ids.is_empty() {
                        let _ = stable::consume_staged_inbox_messages(
                            &staged_message_ids,
                            current_time_ns(),
                        );
                    }
                    let _ = advance_state(&mut state, &AgentEvent::SleepRequested, &turn_id);
                }
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
        source_events: (evm_events as u32)
            .saturating_add(u32::try_from(staged_message_count).unwrap_or(u32::MAX)),
        tool_call_count: u32::try_from(tool_calls.len()).unwrap_or(0),
        input_summary: if has_input {
            format!(
                "inbox:{}:evm:{}:{}",
                staged_message_count, next_cursor.chain_id, evm_events
            )
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
    use crate::domain::types::{MemoryFact, RuntimeSnapshot};
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

    #[test]
    fn inference_context_summary_includes_memory_lines() {
        let memory = vec![MemoryFact {
            key: "strategy".to_string(),
            value: "buy dips".to_string(),
            created_at_ns: 1,
            updated_at_ns: 2,
            source_turn_id: "turn-1".to_string(),
        }];
        let summary = build_inference_context_summary(2, 3, "hello | world", &memory);
        assert!(summary.contains("inbox_messages:2"));
        assert!(summary.contains("evm_events:3"));
        assert!(summary.contains("[memory]"));
        assert!(summary.contains("strategy=buy dips"));
    }

    #[test]
    fn scheduled_turn_records_conversation_entries_for_consumed_inbox_messages() {
        reset_runtime(AgentState::Sleeping, true, false, 0);
        let sender_a = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let sender_b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();

        stable::post_inbox_message("hello sender a".to_string(), sender_a.clone())
            .expect("first inbox message should be accepted");
        stable::post_inbox_message("hello sender b".to_string(), sender_b.clone())
            .expect("second inbox message should be accepted");
        assert_eq!(
            stable::stage_pending_inbox_messages(10, 100),
            2,
            "both pending messages should be staged before turn execution"
        );

        let result = block_on_with_spin(run_scheduled_turn_job());
        assert!(result.is_ok(), "turn should complete successfully");

        let outbox = stable::list_outbox_messages(10);
        assert_eq!(outbox.len(), 1, "one assistant reply should be recorded");
        let expected_reply = outbox[0].body.clone();

        let sender_a_log = stable::get_conversation_log(&sender_a)
            .expect("sender A conversation should be recorded");
        assert_eq!(sender_a_log.entries.len(), 1);
        assert_eq!(sender_a_log.entries[0].sender_body, "hello sender a");
        assert_eq!(sender_a_log.entries[0].agent_reply, expected_reply);

        let sender_b_log = stable::get_conversation_log(&sender_b)
            .expect("sender B conversation should be recorded");
        assert_eq!(sender_b_log.entries.len(), 1);
        assert_eq!(sender_b_log.entries[0].sender_body, "hello sender b");
        assert_eq!(sender_b_log.entries[0].agent_reply, expected_reply);
    }
}
