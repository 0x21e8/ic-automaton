use crate::domain::state_machine;
use crate::domain::types::SurvivalOperationClass;
use crate::domain::types::{
    AgentEvent, AgentState, ConversationEntry, InboxMessage, InferenceInput, InferenceProvider,
    MemoryFact, ToolCallRecord, TurnRecord,
};
#[cfg(target_arch = "wasm32")]
use crate::features::ThresholdSignerAdapter;
use crate::features::{
    infer_with_provider, EvmPoller, HttpEvmPoller, MockEvmPoller, MockSignerAdapter,
};
use crate::storage::stable;
use crate::tools::{SignerPort, ToolManager};
use alloy_primitives::U256;
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

fn current_cycle_balance() -> Option<u128> {
    #[cfg(target_arch = "wasm32")]
    return Some(ic_cdk::api::canister_cycle_balance());

    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

fn current_liquid_cycle_balance() -> Option<u128> {
    #[cfg(target_arch = "wasm32")]
    return Some(ic_cdk::api::canister_liquid_cycle_balance());

    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

fn sanitize_preview(text: &str, max_chars: usize) -> String {
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        return compact;
    }
    let mut out = compact.chars().take(max_chars).collect::<String>();
    out.push_str("...");
    out
}

fn parse_hex_quantity_u256(raw: &str) -> Option<U256> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("0x") {
        return None;
    }
    let digits = trimmed.trim_start_matches("0x");
    if digits.is_empty() {
        return Some(U256::ZERO);
    }
    U256::from_str_radix(digits, 16).ok()
}

fn format_wei_as_eth(wei: U256) -> String {
    let one_eth = U256::from(1_000_000_000_000_000_000u128);
    let whole = wei / one_eth;
    let remainder = wei % one_eth;
    if remainder.is_zero() {
        return whole.to_string();
    }

    let mut frac = format!("{:018}", remainder);
    while frac.ends_with('0') {
        frac.pop();
    }
    format!("{whole}.{frac}")
}

fn summarize_eth_balance_call(call: &ToolCallRecord) -> Option<String> {
    if !call.success || call.tool != "evm_read" {
        return None;
    }
    let args = serde_json::from_str::<serde_json::Value>(&call.args_json).ok()?;
    let method = args.get("method")?.as_str()?;
    if method != "eth_getBalance" {
        return None;
    }

    let address = args
        .get("address")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let balance_hex = call.output.trim();
    let balance_wei = parse_hex_quantity_u256(balance_hex)?;
    let balance_eth = format_wei_as_eth(balance_wei);
    Some(format!(
        "balance `{address}` = `{balance_hex}` wei ({balance_eth} ETH)"
    ))
}

fn summarize_tool_call(call: &ToolCallRecord) -> String {
    if call.success {
        if let Some(balance_summary) = summarize_eth_balance_call(call) {
            return balance_summary;
        }
        let output = sanitize_preview(call.output.trim(), 220);
        if output.is_empty() {
            return format!("`{}`: ok", call.tool);
        }
        return format!("`{}`: {}", call.tool, output);
    }

    let reason = call
        .error
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(call.output.as_str());
    format!("`{}` failed: {}", call.tool, sanitize_preview(reason, 220))
}

fn render_tool_results_reply(tool_calls: &[ToolCallRecord]) -> Option<String> {
    if tool_calls.is_empty() {
        return None;
    }

    let succeeded = tool_calls.iter().filter(|call| call.success).count();
    let failed = tool_calls.len().saturating_sub(succeeded);
    let mut lines = vec![format!(
        "Tool results: {succeeded} succeeded, {failed} failed."
    )];
    for call in tool_calls {
        lines.push(format!("- {}", summarize_tool_call(call)));
    }
    Some(lines.join("\n"))
}

fn build_pending_obligations_section(staged_messages: &[InboxMessage]) -> String {
    let unique_senders = staged_messages
        .iter()
        .map(|message| message.posted_by.as_str())
        .collect::<BTreeSet<_>>();
    let mut lines = vec![
        "### Pending Obligations".to_string(),
        format!("- staged_count: {}", staged_messages.len()),
        format!("- active_senders: {}", unique_senders.len()),
    ];

    if staged_messages.is_empty() {
        lines.push("- none".to_string());
    } else {
        for message in staged_messages {
            lines.push(format!(
                "- id={} sender={} body_preview={}",
                message.id,
                message.posted_by,
                sanitize_preview(&message.body, 140)
            ));
        }
    }

    lines.join("\n")
}

fn build_conversation_context(staged_messages: &[InboxMessage], per_sender_limit: usize) -> String {
    let senders = staged_messages
        .iter()
        .map(|message| message.posted_by.as_str())
        .collect::<BTreeSet<_>>();

    if senders.is_empty() {
        return "### Conversation History\n- none".to_string();
    }

    let mut lines = vec!["### Conversation History".to_string()];
    let mut any_entries = false;
    for sender in senders {
        let Some(log) = stable::get_conversation_log(sender) else {
            continue;
        };
        let recent = log
            .entries
            .iter()
            .rev()
            .take(per_sender_limit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>();
        if recent.is_empty() {
            continue;
        }
        any_entries = true;
        lines.push(format!("### Conversation with {sender}"));
        for entry in recent {
            lines.push(format!(
                "  [{}]: {}",
                sender,
                sanitize_preview(&entry.sender_body, 220)
            ));
            lines.push(format!(
                "  [you]: {}",
                sanitize_preview(&entry.agent_reply, 220)
            ));
        }
    }

    if !any_entries {
        lines.push("- none".to_string());
    }

    lines.join("\n")
}

fn build_available_tools_section(turn_id: &str) -> String {
    let manager = ToolManager::new();
    let usage = stable::get_tools_for_turn(turn_id).into_iter().fold(
        std::collections::BTreeMap::new(),
        |mut acc, call| {
            let entry = acc.entry(call.tool).or_insert(0usize);
            *entry = entry.saturating_add(1);
            acc
        },
    );

    let mut lines = vec!["### Available Tools".to_string()];
    for (name, policy) in manager.list_tools() {
        if !policy.enabled {
            continue;
        }
        let used = usage.get(&name).copied().unwrap_or_default();
        let max = usize::from(policy.max_calls_per_turn);
        let remaining = max.saturating_sub(used);
        lines.push(format!("- {name}: remaining={remaining}/{max}"));
    }
    if lines.len() == 1 {
        lines.push("- none".to_string());
    }
    lines.join("\n")
}

fn conversation_history_limit_for_provider(provider: &InferenceProvider) -> usize {
    match provider {
        InferenceProvider::IcLlm => 2,
        _ => 5,
    }
}

fn build_dynamic_context(
    snapshot: &crate::domain::types::RuntimeSnapshot,
    staged_messages: &[InboxMessage],
    evm_events: usize,
    memory_facts: &[MemoryFact],
    turn_id: &str,
    conversation_history_limit: usize,
) -> String {
    let cycles_balance = current_cycle_balance()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let liquid_cycles_balance = current_liquid_cycle_balance()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let survival_tier = format!("{:?}", stable::scheduler_survival_tier());
    let recovery_checks = stable::scheduler_survival_tier_recovery_checks();
    let eth_balance = stable::list_memory_facts_by_prefix("balance.eth", 1)
        .first()
        .map(|fact| fact.value.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let memory_section = if memory_facts.is_empty() {
        "### Recent Memory\n- none".to_string()
    } else {
        let mut lines = vec!["### Recent Memory".to_string()];
        for fact in memory_facts {
            lines.push(format!(
                "- {}={}",
                fact.key,
                sanitize_preview(&fact.value, 220)
            ));
        }
        lines.join("\n")
    };

    [
        "## Layer 10: Dynamic Context".to_string(),
        "### Current State".to_string(),
        format!("- cycles_balance: {cycles_balance}"),
        format!("- liquid_cycles_balance: {liquid_cycles_balance}"),
        "- cycles_runway_hours: unknown".to_string(),
        format!("- survival_tier: {survival_tier}"),
        format!("- survival_tier_recovery_checks: {recovery_checks}"),
        format!(
            "- base_wallet: {}",
            snapshot.evm_address.as_deref().unwrap_or("unconfigured")
        ),
        format!("- eth_balance: {eth_balance}"),
        format!("- turn_number: {}", snapshot.turn_counter),
        format!("- turn_id: {turn_id}"),
        format!("- timestamp_ns: {}", current_time_ns()),
        format!("- state: {:?}", snapshot.state),
        format!("- evm_events: {evm_events}"),
        build_pending_obligations_section(staged_messages),
        build_conversation_context(staged_messages, conversation_history_limit),
        memory_section,
        build_available_tools_section(turn_id),
    ]
    .join("\n\n")
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
        let conversation_history_limit =
            conversation_history_limit_for_provider(&snapshot.inference_provider);
        let context_summary = build_dynamic_context(
            &snapshot,
            &staged_messages,
            evm_events,
            &memory_facts,
            &turn_id,
            conversation_history_limit,
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
                    if let Some(tool_results_reply) = render_tool_results_reply(&tool_calls) {
                        assistant_reply = Some(tool_results_reply);
                    }

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
    use crate::domain::types::{
        InboxMessageStatus, MemoryFact, RuntimeSnapshot, SurvivalTier, ToolCallRecord,
    };
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

    fn staged_message(id: &str, seq: u64, sender: &str, body: &str) -> InboxMessage {
        InboxMessage {
            id: id.to_string(),
            seq,
            body: body.to_string(),
            posted_at_ns: 1,
            posted_by: sender.to_string(),
            status: InboxMessageStatus::Staged,
            staged_at_ns: Some(1),
            consumed_at_ns: None,
        }
    }

    #[test]
    fn render_tool_results_reply_formats_eth_get_balance_result() {
        let calls = vec![ToolCallRecord {
            turn_id: "turn-1".to_string(),
            tool: "evm_read".to_string(),
            args_json:
                r#"{"method":"eth_getBalance","address":"0x1111111111111111111111111111111111111111"}"#
                    .to_string(),
            output: "0xde0b6b3a7640000".to_string(),
            success: true,
            error: None,
        }];

        let reply = render_tool_results_reply(&calls).expect("reply should be rendered");
        assert!(reply.contains("Tool results: 1 succeeded, 0 failed."));
        assert!(reply.contains("balance `0x1111111111111111111111111111111111111111`"));
        assert!(reply.contains("0xde0b6b3a7640000"));
        assert!(reply.contains("1 ETH"));
    }

    #[test]
    fn render_tool_results_reply_summarizes_generic_success_and_failures() {
        let calls = vec![
            ToolCallRecord {
                turn_id: "turn-1".to_string(),
                tool: "remember".to_string(),
                args_json: r#"{"key":"k","value":"v"}"#.to_string(),
                output: "stored".to_string(),
                success: true,
                error: None,
            },
            ToolCallRecord {
                turn_id: "turn-1".to_string(),
                tool: "evm_read".to_string(),
                args_json: r#"{"method":"eth_call","address":"0x1111111111111111111111111111111111111111","calldata":"0x1234"}"#.to_string(),
                output: "tool execution failed".to_string(),
                success: false,
                error: Some("rpc timeout".to_string()),
            },
        ];

        let reply = render_tool_results_reply(&calls).expect("reply should be rendered");
        assert!(reply.contains("Tool results: 1 succeeded, 1 failed."));
        assert!(reply.contains("`remember`: stored"));
        assert!(reply.contains("`evm_read` failed: rpc timeout"));
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
    fn dynamic_context_uses_structured_markdown_and_state_sections() {
        reset_runtime(AgentState::Sleeping, true, false, 12);
        stable::set_scheduler_survival_tier(SurvivalTier::LowCycles);
        stable::set_evm_address(Some(
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        ))
        .expect("evm address should be accepted");
        stable::set_memory_fact(&MemoryFact {
            key: "balance.eth".to_string(),
            value: "0.42".to_string(),
            created_at_ns: 1,
            updated_at_ns: 10,
            source_turn_id: "turn-10".to_string(),
        });

        let memory = vec![MemoryFact {
            key: "strategy".to_string(),
            value: "buy dips".to_string(),
            created_at_ns: 1,
            updated_at_ns: 2,
            source_turn_id: "turn-1".to_string(),
        }];
        let staged = vec![
            staged_message(
                "inbox-1",
                1,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "hello from sender a",
            ),
            staged_message(
                "inbox-2",
                2,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "hello from sender b",
            ),
        ];
        let snapshot = stable::runtime_snapshot();

        let context = build_dynamic_context(&snapshot, &staged, 3, &memory, "turn-12", 5);
        assert!(context.contains("## Layer 10: Dynamic Context"));
        assert!(context.contains("### Current State"));
        assert!(context.contains("- survival_tier: LowCycles"));
        assert!(context.contains("- base_wallet: 0x1234567890abcdef1234567890abcdef12345678"));
        assert!(context.contains("- eth_balance: 0.42"));
        assert!(context.contains("### Pending Obligations"));
        assert!(context.contains("- staged_count: 2"));
        assert!(context.contains("### Recent Memory"));
        assert!(context.contains("- strategy=buy dips"));
        assert!(context.contains("### Available Tools"));
    }

    #[test]
    fn dynamic_context_scopes_conversation_to_active_senders_and_last_five_entries() {
        reset_runtime(AgentState::Sleeping, true, false, 2);
        let sender_a = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let sender_b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let sender_c = "0xcccccccccccccccccccccccccccccccccccccccc";

        for idx in 0..6 {
            stable::append_conversation_entry(
                sender_a,
                ConversationEntry {
                    inbox_message_id: format!("a-{idx}"),
                    sender_body: format!("a-msg-{idx}"),
                    agent_reply: format!("a-reply-{idx}"),
                    turn_id: "turn-history".to_string(),
                    timestamp_ns: u64::try_from(idx).unwrap_or_default(),
                },
            );
        }
        stable::append_conversation_entry(
            sender_c,
            ConversationEntry {
                inbox_message_id: "c-0".to_string(),
                sender_body: "c-msg-0".to_string(),
                agent_reply: "c-reply-0".to_string(),
                turn_id: "turn-history".to_string(),
                timestamp_ns: 999,
            },
        );

        let staged = vec![
            staged_message("inbox-a", 1, sender_a, "new msg from a"),
            staged_message("inbox-b", 2, sender_b, "new msg from b"),
        ];
        let snapshot = stable::runtime_snapshot();
        let context = build_dynamic_context(&snapshot, &staged, 0, &[], "turn-2", 5);

        assert!(context.contains(&format!("### Conversation with {sender_a}")));
        assert!(context.contains("a-msg-1"));
        assert!(context.contains("a-reply-5"));
        assert!(!context.contains("a-msg-0"));
        assert!(!context.contains(sender_c));
    }

    #[test]
    fn dynamic_context_reports_remaining_tool_budget_for_turn() {
        reset_runtime(AgentState::Sleeping, true, false, 3);
        let turn_id = "turn-3";
        stable::set_tool_records(
            turn_id,
            &[
                ToolCallRecord {
                    turn_id: turn_id.to_string(),
                    tool: "record_signal".to_string(),
                    args_json: "{}".to_string(),
                    output: "ok".to_string(),
                    success: true,
                    error: None,
                },
                ToolCallRecord {
                    turn_id: turn_id.to_string(),
                    tool: "record_signal".to_string(),
                    args_json: "{}".to_string(),
                    output: "ok".to_string(),
                    success: true,
                    error: None,
                },
                ToolCallRecord {
                    turn_id: turn_id.to_string(),
                    tool: "evm_read".to_string(),
                    args_json: "{}".to_string(),
                    output: "ok".to_string(),
                    success: true,
                    error: None,
                },
            ],
        );

        let snapshot = stable::runtime_snapshot();
        let context = build_dynamic_context(&snapshot, &[], 0, &[], turn_id, 5);
        assert!(context.contains("- record_signal: remaining=3/5"));
        assert!(context.contains("- evm_read: remaining=2/3"));
    }

    #[test]
    fn dynamic_context_compact_mode_limits_conversation_to_last_two_entries() {
        reset_runtime(AgentState::Sleeping, true, false, 4);
        let sender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        for idx in 0..4 {
            stable::append_conversation_entry(
                sender,
                ConversationEntry {
                    inbox_message_id: format!("msg-{idx}"),
                    sender_body: format!("sender-{idx}"),
                    agent_reply: format!("reply-{idx}"),
                    turn_id: "turn-history".to_string(),
                    timestamp_ns: u64::try_from(idx).unwrap_or_default(),
                },
            );
        }

        let staged = vec![staged_message("inbox-1", 1, sender, "newest incoming")];
        let snapshot = stable::runtime_snapshot();
        let context = build_dynamic_context(&snapshot, &staged, 0, &[], "turn-4", 2);
        assert!(context.contains("sender-2"));
        assert!(context.contains("sender-3"));
        assert!(!context.contains("sender-1"));
        assert!(!context.contains("sender-0"));
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
