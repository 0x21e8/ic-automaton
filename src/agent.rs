use crate::domain::state_machine;
use crate::domain::types::{
    AgentEvent, AgentState, ContinuationStopReason, ConversationEntry, InboxMessage,
    InferenceInput, InferenceProvider, MemoryFact, ToolCall, ToolCallRecord, TurnRecord,
};
#[cfg(target_arch = "wasm32")]
use crate::features::ThresholdSignerAdapter;
use crate::features::{
    infer_with_provider, infer_with_provider_transcript, InferenceTranscriptMessage,
    MockSignerAdapter,
};
use crate::storage::stable;
use crate::tools::{SignerPort, ToolManager};
use alloy_primitives::U256;
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::BTreeSet;

const BALANCE_FRESHNESS_WINDOW_SECS: u64 = 60 * 60;
const AUTONOMY_DUPLICATE_SUCCESS_WINDOW_NS: u64 = BALANCE_FRESHNESS_WINDOW_SECS * 1_000_000_000;
const MAX_INFERENCE_ROUNDS_PER_TURN: usize = 3;
const MAX_AGENT_TURN_DURATION_NS: u64 = 90 * 1_000_000_000;
const MAX_TOOL_CALLS_PER_TURN: usize = 12;
const AUTONOMY_DEDUPE_SKIP_REASON: &str = "skipped due to freshness dedupe";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, LogPriorityLevels)]
enum AgentLogPriority {
    #[log_level(capacity = 2000, name = "AGENT_INFO")]
    Info,
    #[log_level(capacity = 500, name = "AGENT_ERROR")]
    Error,
}

impl GetLogFilter for AgentLogPriority {
    fn get_log_filter() -> LogFilter {
        LogFilter::ShowAll
    }
}

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

fn canonical_tool_args_json(args_json: &str) -> String {
    let trimmed = args_json.trim();
    if trimmed.is_empty() {
        return "{}".to_string();
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Ok(serialized) = serde_json::to_string(&value) {
            return serialized;
        }
    }
    trimmed.to_string()
}

fn tool_call_fingerprint(tool: &str, args_json: &str) -> String {
    let canonical_args = canonical_tool_args_json(args_json);
    let mut hasher = Keccak256::new();
    hasher.update(tool.trim().as_bytes());
    hasher.update(b":");
    hasher.update(canonical_args.as_bytes());
    hex::encode(hasher.finalize())
}

fn suppress_duplicate_autonomy_tool_calls(
    calls: &[ToolCall],
    now_ns: u64,
) -> (Vec<ToolCall>, Vec<SuppressedAutonomyToolCall>) {
    let mut allowed = Vec::with_capacity(calls.len());
    let mut suppressed = Vec::new();

    for (index, call) in calls.iter().enumerate() {
        let fingerprint = tool_call_fingerprint(&call.tool, &call.args_json);
        let Some(last_success_ns) = stable::autonomy_tool_last_success_ns(&fingerprint) else {
            allowed.push(call.clone());
            continue;
        };

        let elapsed_ns = now_ns.saturating_sub(last_success_ns);
        if elapsed_ns < AUTONOMY_DUPLICATE_SUCCESS_WINDOW_NS {
            suppressed.push(SuppressedAutonomyToolCall {
                index,
                call: call.clone(),
                age_secs: elapsed_ns / 1_000_000_000,
            });
            continue;
        }

        allowed.push(call.clone());
    }

    (allowed, suppressed)
}

#[derive(Clone, Debug)]
struct SuppressedAutonomyToolCall {
    index: usize,
    call: ToolCall,
    age_secs: u64,
}

fn synthetic_suppressed_autonomy_tool_record(
    turn_id: &str,
    call: &ToolCall,
    age_secs: u64,
) -> ToolCallRecord {
    ToolCallRecord {
        turn_id: turn_id.to_string(),
        tool: call.tool.clone(),
        args_json: call.args_json.clone(),
        output: format!(
            "{AUTONOMY_DEDUPE_SKIP_REASON}: last success {} seconds ago within {} second window",
            age_secs, BALANCE_FRESHNESS_WINDOW_SECS
        ),
        success: true,
        error: None,
    }
}

fn record_successful_autonomy_tool_calls(tool_calls: &[ToolCallRecord], succeeded_at_ns: u64) {
    for call in tool_calls.iter().filter(|call| call.success) {
        let fingerprint = tool_call_fingerprint(&call.tool, &call.args_json);
        stable::record_autonomy_tool_success(&fingerprint, succeeded_at_ns);
    }
}

fn normalize_tool_call_ids(calls: Vec<ToolCall>, round_index: usize) -> Vec<ToolCall> {
    calls
        .into_iter()
        .enumerate()
        .map(|(tool_index, mut call)| {
            let normalized_id = call
                .tool_call_id
                .as_deref()
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("round-{round_index}-tool-{tool_index}"));
            call.tool_call_id = Some(normalized_id);
            call
        })
        .collect()
}

fn continuation_tool_content(record: &ToolCallRecord) -> String {
    serde_json::json!({
        "success": record.success,
        "output": record.output,
        "error": record.error,
    })
    .to_string()
}

fn upsert_memory_fact(key: &str, value: String, turn_id: &str, now_ns: u64) {
    let existing = stable::get_memory_fact(key);
    stable::set_memory_fact(&MemoryFact {
        key: key.to_string(),
        value,
        created_at_ns: existing
            .as_ref()
            .map(|fact| fact.created_at_ns)
            .unwrap_or(now_ns),
        updated_at_ns: now_ns,
        source_turn_id: turn_id.to_string(),
    });
}

fn successful_eth_balance_read(call: &ToolCallRecord) -> Option<(String, String)> {
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
        .map(|value| value.trim().to_ascii_lowercase())?;
    let balance_hex = call.output.trim().to_ascii_lowercase();
    let _ = parse_hex_quantity_u256(&balance_hex)?;
    Some((address, balance_hex))
}

fn persist_eth_balance_from_tool_calls(tool_calls: &[ToolCallRecord], turn_id: &str, now_ns: u64) {
    for call in tool_calls {
        let Some((address, balance_hex)) = successful_eth_balance_read(call) else {
            continue;
        };
        upsert_memory_fact("balance.eth", balance_hex.clone(), turn_id, now_ns);
        upsert_memory_fact(
            &format!("balance.eth.{address}"),
            balance_hex,
            turn_id,
            now_ns,
        );
        upsert_memory_fact(
            "balance.eth.last_checked_ns",
            now_ns.to_string(),
            turn_id,
            now_ns,
        );
    }
}

fn append_inner_dialogue(inner_dialogue: &mut Option<String>, segment: &str) {
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        return;
    }
    match inner_dialogue {
        Some(current) => {
            current.push_str("\n\n");
            current.push_str(trimmed);
        }
        None => *inner_dialogue = Some(trimmed.to_string()),
    }
}

fn current_turn_goal_and_why(staged_message_count: usize, evm_events: usize) -> (String, String) {
    if staged_message_count > 0 {
        return (
            format!("respond to {staged_message_count} staged inbox message(s)"),
            "new external inbox input is waiting and requires a response".to_string(),
        );
    }

    if evm_events > 0 {
        return (
            format!("process {evm_events} newly observed EVM event(s)"),
            "new chain activity was detected during the latest poll".to_string(),
        );
    }

    (
        "run an autonomy tick and execute useful low-risk maintenance work".to_string(),
        "the scheduler fired with no external input, so proactive autonomous work is allowed"
            .to_string(),
    )
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
        lines.push(format!("- {name}: calls_this_turn={used}"));
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
    let now_ns = current_time_ns();
    let cycles_balance = current_cycle_balance()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let liquid_cycles_balance = current_liquid_cycle_balance()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let survival_tier = format!("{:?}", stable::scheduler_survival_tier());
    let recovery_checks = stable::scheduler_survival_tier_recovery_checks();
    let eth_balance_fact = stable::get_memory_fact("balance.eth");
    let eth_balance = eth_balance_fact
        .as_ref()
        .map(|fact| fact.value.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let eth_balance_last_checked_ns = stable::get_memory_fact("balance.eth.last_checked_ns")
        .and_then(|fact| fact.value.parse::<u64>().ok())
        .or_else(|| eth_balance_fact.as_ref().map(|fact| fact.updated_at_ns));
    let eth_balance_last_checked_age_secs = eth_balance_last_checked_ns
        .map(|last_checked_ns| now_ns.saturating_sub(last_checked_ns) / 1_000_000_000);
    let eth_balance_is_stale = eth_balance_last_checked_age_secs
        .map(|age_secs| age_secs > BALANCE_FRESHNESS_WINDOW_SECS)
        .unwrap_or(true);

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
        format!(
            "- eth_balance_last_checked_ns: {}",
            eth_balance_last_checked_ns
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        format!(
            "- eth_balance_last_checked_age_secs: {}",
            eth_balance_last_checked_age_secs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        format!("- eth_balance_freshness_window_secs: {BALANCE_FRESHNESS_WINDOW_SECS}"),
        format!("- eth_balance_is_stale: {eth_balance_is_stale}"),
        format!("- turn_number: {}", snapshot.turn_counter),
        format!("- turn_id: {turn_id}"),
        format!("- timestamp_ns: {now_ns}"),
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
    run_scheduled_turn_job_with_limits_and_tool_cap(
        MAX_INFERENCE_ROUNDS_PER_TURN,
        MAX_AGENT_TURN_DURATION_NS,
        MAX_TOOL_CALLS_PER_TURN,
    )
    .await
}

#[cfg(test)]
async fn run_scheduled_turn_job_with_limits(
    max_inference_rounds: usize,
    max_turn_duration_ns: u64,
) -> Result<(), String> {
    run_scheduled_turn_job_with_limits_and_tool_cap(
        max_inference_rounds,
        max_turn_duration_ns,
        MAX_TOOL_CALLS_PER_TURN,
    )
    .await
}

async fn run_scheduled_turn_job_with_limits_and_tool_cap(
    max_inference_rounds: usize,
    max_turn_duration_ns: u64,
    max_tool_calls_per_turn: usize,
) -> Result<(), String> {
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
    let mut all_tool_calls = Vec::new();
    let mut assistant_reply: Option<String> = None;
    let mut inner_dialogue: Option<String> = None;
    let mut inference_round_count = 0usize;
    let mut continuation_stop_reason = ContinuationStopReason::None;

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

    let next_cursor = snapshot.evm_cursor.clone();
    let evm_events = 0usize;
    let has_external_input = staged_message_count > 0;
    let should_infer = true;

    if let Err(reason) = advance_state(
        &mut state,
        &AgentEvent::EvmPollCompleted {
            new_events: evm_events as u32,
            has_input: should_infer,
        },
        &turn_id,
    ) {
        stable::set_last_error(Some(reason.clone()));
        stable::complete_turn(AgentState::Faulted, Some(reason.clone()));
        return Err(reason);
    }

    if should_infer {
        let (goal, why) = current_turn_goal_and_why(staged_message_count, evm_events);
        append_inner_dialogue(&mut inner_dialogue, &format!("goal: {goal}\nwhy: {why}"));

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
            } else if evm_events > 0 {
                format!("poll:new_events={evm_events}")
            } else {
                "autonomy_tick".to_string()
            },
            context_snippet: context_summary,
            turn_id: turn_id.clone(),
        };

        #[cfg(target_arch = "wasm32")]
        let signer: Box<dyn SignerPort> = if snapshot.ecdsa_key_name.trim().is_empty() {
            Box::new(MockSignerAdapter::new())
        } else {
            Box::new(ThresholdSignerAdapter::new(snapshot.ecdsa_key_name.clone()))
        };

        #[cfg(not(target_arch = "wasm32"))]
        let signer: Box<dyn SignerPort> = Box::new(MockSignerAdapter::new());

        let mut manager = ToolManager::new();
        let mut transcript = Vec::<InferenceTranscriptMessage>::new();
        let mut inference_completed = false;
        let mut executed_any_tool = false;

        loop {
            if inference_round_count >= max_inference_rounds {
                append_inner_dialogue(
                    &mut inner_dialogue,
                    &format!(
                        "continuation stopped: max inference rounds reached ({max_inference_rounds})"
                    ),
                );
                continuation_stop_reason = ContinuationStopReason::MaxRounds;
                log!(
                    AgentLogPriority::Info,
                    "turn={} continuation_stop reason=max_rounds rounds={} max_rounds={} max_duration_ms={} tool_calls_so_far={}",
                    turn_id,
                    inference_round_count,
                    max_inference_rounds,
                    max_turn_duration_ns / 1_000_000,
                    all_tool_calls.len(),
                );
                break;
            }

            let elapsed_ns = current_time_ns().saturating_sub(started_at_ns);
            if elapsed_ns >= max_turn_duration_ns {
                append_inner_dialogue(
                    &mut inner_dialogue,
                    &format!(
                        "continuation stopped: max turn duration reached ({} ms)",
                        max_turn_duration_ns / 1_000_000
                    ),
                );
                continuation_stop_reason = ContinuationStopReason::MaxDuration;
                log!(
                    AgentLogPriority::Info,
                    "turn={} continuation_stop reason=max_duration rounds={} elapsed_ms={} max_duration_ms={} tool_calls_so_far={}",
                    turn_id,
                    inference_round_count,
                    elapsed_ns / 1_000_000,
                    max_turn_duration_ns / 1_000_000,
                    all_tool_calls.len(),
                );
                break;
            }

            inference_round_count = inference_round_count.saturating_add(1);
            let inference_result = if transcript.is_empty() {
                infer_with_provider(&snapshot, &input).await
            } else {
                infer_with_provider_transcript(&snapshot, &input, &transcript).await
            };
            let inference = match inference_result {
                Ok(inference) => inference,
                Err(reason) => {
                    if inference_round_count == 1 {
                        if has_external_input {
                            last_error = Some(reason);
                        } else {
                            append_inner_dialogue(
                                &mut inner_dialogue,
                                &format!("autonomy inference error: {reason}"),
                            );
                            if !inference_completed {
                                if let Err(error) = advance_state(
                                    &mut state,
                                    &AgentEvent::InferenceCompleted,
                                    &turn_id,
                                ) {
                                    last_error = Some(error);
                                } else {
                                    inference_completed = true;
                                }
                            }
                        }
                    } else if executed_any_tool {
                        append_inner_dialogue(
                            &mut inner_dialogue,
                            &format!(
                                "continuation inference degraded after tool execution: {reason}"
                            ),
                        );
                        continuation_stop_reason = ContinuationStopReason::InferenceError;
                        log!(
                            AgentLogPriority::Error,
                            "turn={} continuation_stop reason=inference_error rounds={} tool_calls_so_far={} error={}",
                            turn_id,
                            inference_round_count,
                            all_tool_calls.len(),
                            reason,
                        );
                    } else {
                        last_error = Some(reason);
                    }
                    break;
                }
            };

            let trimmed_reply = inference.explanation.trim().to_string();
            if !trimmed_reply.is_empty() {
                append_inner_dialogue(&mut inner_dialogue, &format!("inference: {trimmed_reply}"));
                assistant_reply = Some(trimmed_reply.clone());
            }

            if !inference_completed {
                if let Err(error) =
                    advance_state(&mut state, &AgentEvent::InferenceCompleted, &turn_id)
                {
                    last_error = Some(error);
                    break;
                }
                inference_completed = true;
            }

            let mut planned_tool_calls =
                normalize_tool_call_ids(inference.tool_calls, inference_round_count - 1);
            if !planned_tool_calls.is_empty() {
                let remaining_tool_budget =
                    max_tool_calls_per_turn.saturating_sub(all_tool_calls.len());
                if remaining_tool_budget == 0 {
                    append_inner_dialogue(
                        &mut inner_dialogue,
                        &format!(
                            "continuation stopped: max tool calls reached ({max_tool_calls_per_turn})"
                        ),
                    );
                    continuation_stop_reason = ContinuationStopReason::MaxToolCalls;
                    log!(
                        AgentLogPriority::Info,
                        "turn={} continuation_stop reason=max_tool_calls rounds={} max_tool_calls={} elapsed_ms={}",
                        turn_id,
                        inference_round_count,
                        max_tool_calls_per_turn,
                        elapsed_ns / 1_000_000,
                    );
                    break;
                }
                if planned_tool_calls.len() > remaining_tool_budget {
                    planned_tool_calls.truncate(remaining_tool_budget);
                    append_inner_dialogue(
                        &mut inner_dialogue,
                        &format!(
                            "continuation limited: truncated tool calls to remaining cap {} of {}",
                            remaining_tool_budget, max_tool_calls_per_turn
                        ),
                    );
                }
            }
            let mut executable_tool_calls = planned_tool_calls.clone();
            let mut suppressed_autonomy_calls = Vec::new();
            if inference_round_count == 1 && !has_external_input {
                let (filtered_calls, suppressed_calls) =
                    suppress_duplicate_autonomy_tool_calls(&planned_tool_calls, started_at_ns);
                executable_tool_calls = filtered_calls;
                if !suppressed_calls.is_empty() {
                    let details = suppressed_calls
                        .iter()
                        .map(|entry| {
                            format!(
                                "{} args={} age_secs={}",
                                entry.call.tool,
                                sanitize_preview(&entry.call.args_json, 100),
                                entry.age_secs
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n- ");
                    append_inner_dialogue(
                        &mut inner_dialogue,
                        &format!(
                            "autonomy dedupe suppressed {} repeated successful tool call(s) within {} seconds:\n- {}",
                            suppressed_calls.len(),
                            BALANCE_FRESHNESS_WINDOW_SECS,
                            details,
                        ),
                    );
                }
                suppressed_autonomy_calls = suppressed_calls;
            }

            if planned_tool_calls.is_empty() {
                break;
            }

            transcript.push(InferenceTranscriptMessage::Assistant {
                content: if trimmed_reply.is_empty() {
                    None
                } else {
                    Some(trimmed_reply)
                },
                tool_calls: planned_tool_calls.clone(),
            });

            let executed = manager
                .execute_actions(&state, &executable_tool_calls, signer.as_ref(), &turn_id)
                .await;
            executed_any_tool = executed_any_tool || !executed.is_empty();

            let execution_completed_ns = current_time_ns();
            if !has_external_input {
                record_successful_autonomy_tool_calls(&executed, execution_completed_ns);
            }
            let mut executed_iter = executed.into_iter();
            let mut suppressed_iter = suppressed_autonomy_calls.into_iter().peekable();
            let mut round_tool_records = Vec::with_capacity(planned_tool_calls.len());
            for (index, call) in planned_tool_calls.iter().enumerate() {
                let is_suppressed = suppressed_iter
                    .peek()
                    .map(|entry| entry.index == index)
                    .unwrap_or(false);
                if is_suppressed {
                    let suppressed = suppressed_iter
                        .next()
                        .expect("suppressed iterator must provide matching index");
                    round_tool_records.push(synthetic_suppressed_autonomy_tool_record(
                        &turn_id,
                        call,
                        suppressed.age_secs,
                    ));
                    continue;
                }

                let Some(record) = executed_iter.next() else {
                    last_error =
                        Some("tool execution record mismatch: missing executed record".to_string());
                    break;
                };
                round_tool_records.push(record);
            }
            if last_error.is_none()
                && (executed_iter.next().is_some() || suppressed_iter.next().is_some())
            {
                last_error = Some(
                    "tool execution record mismatch: unexpected extra tool record".to_string(),
                );
            }
            if last_error.is_some() {
                break;
            }

            persist_eth_balance_from_tool_calls(
                &round_tool_records,
                &turn_id,
                execution_completed_ns,
            );
            if let Some(tool_results_reply) = render_tool_results_reply(&round_tool_records) {
                append_inner_dialogue(&mut inner_dialogue, &tool_results_reply);
                assistant_reply = Some(tool_results_reply);
            }

            if round_tool_records.iter().any(|record| !record.success) {
                last_error = Some("tool execution reported failures".to_string());
            }

            for (call, record) in planned_tool_calls.iter().zip(round_tool_records.iter()) {
                if let Some(tool_call_id) = call.tool_call_id.clone() {
                    transcript.push(InferenceTranscriptMessage::Tool {
                        tool_call_id,
                        content: continuation_tool_content(record),
                    });
                }
            }

            all_tool_calls.extend(round_tool_records);

            if last_error.is_some() {
                break;
            }
        }

        if last_error.is_none() && !inference_completed {
            if let Err(error) = advance_state(&mut state, &AgentEvent::InferenceCompleted, &turn_id)
            {
                last_error = Some(error);
            } else {
                inference_completed = true;
            }
        }

        if last_error.is_none() && inference_completed {
            if let Err(error) = advance_state(&mut state, &AgentEvent::ActionsCompleted, &turn_id) {
                last_error = Some(error);
            }
        }

        if last_error.is_none() {
            if let Err(reason) = advance_state(&mut state, &AgentEvent::PersistCompleted, &turn_id)
            {
                last_error = Some(reason);
            } else {
                if staged_message_count > 0 {
                    if let Some(reply) = assistant_reply.clone().or_else(|| inner_dialogue.clone())
                    {
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
    if inner_dialogue.is_none() && !has_external_input && last_error.is_none() {
        inner_dialogue = Some("autonomy tick complete: no action".to_string());
    }

    let turn_record = TurnRecord {
        id: turn_id.clone(),
        created_at_ns: started_at_ns,
        state_from: initial_state,
        state_to: state.clone(),
        source_events: (evm_events as u32)
            .saturating_add(u32::try_from(staged_message_count).unwrap_or(u32::MAX)),
        tool_call_count: u32::try_from(all_tool_calls.len()).unwrap_or(0),
        input_summary: if has_external_input {
            format!(
                "inbox:{}:evm:{}:{}",
                staged_message_count, next_cursor.chain_id, evm_events
            )
        } else {
            "autonomy:no-input".to_string()
        },
        inner_dialogue,
        inference_round_count: u32::try_from(inference_round_count).unwrap_or(u32::MAX),
        continuation_stop_reason,
        error: last_error.clone(),
    };

    stable::append_turn_record(&turn_record, &all_tool_calls);
    if last_error.is_none() {
        stable::set_evm_cursor(&next_cursor);
    }

    stable::complete_turn(state, last_error.clone());
    log!(
        AgentLogPriority::Info,
        "turn={} completed state={:?} error_present={} inference_round_count={} continuation_stop_reason={:?} tool_calls={} duration_ms={}",
        turn_id,
        turn_record.state_to,
        turn_record.error.is_some(),
        turn_record.inference_round_count,
        turn_record.continuation_stop_reason,
        all_tool_calls.len(),
        current_time_ns().saturating_sub(started_at_ns) / 1_000_000,
    );
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
        ContinuationStopReason, InboxMessageStatus, MemoryFact, RuntimeSnapshot, SurvivalTier,
        ToolCall, ToolCallRecord,
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
    fn persist_eth_balance_from_tool_calls_stores_balance_and_last_checked() {
        reset_runtime(AgentState::Sleeping, true, false, 8);
        let calls = vec![ToolCallRecord {
            turn_id: "turn-9".to_string(),
            tool: "evm_read".to_string(),
            args_json:
                r#"{"method":"eth_getBalance","address":"0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD"}"#
                    .to_string(),
            output: "0x1".to_string(),
            success: true,
            error: None,
        }];

        persist_eth_balance_from_tool_calls(&calls, "turn-9", 100);

        let global = stable::get_memory_fact("balance.eth").expect("global balance should exist");
        assert_eq!(global.value, "0x1");
        assert_eq!(global.created_at_ns, 100);
        assert_eq!(global.updated_at_ns, 100);

        let by_address =
            stable::get_memory_fact("balance.eth.0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
                .expect("address balance should exist");
        assert_eq!(by_address.value, "0x1");

        let checked = stable::get_memory_fact("balance.eth.last_checked_ns")
            .expect("last checked fact should exist");
        assert_eq!(checked.value, "100");

        let second_calls = vec![ToolCallRecord {
            output: "0x2".to_string(),
            ..calls[0].clone()
        }];
        persist_eth_balance_from_tool_calls(&second_calls, "turn-10", 200);
        let updated_global = stable::get_memory_fact("balance.eth").expect("updated balance");
        assert_eq!(updated_global.value, "0x2");
        assert_eq!(updated_global.created_at_ns, 100);
        assert_eq!(updated_global.updated_at_ns, 200);
    }

    #[test]
    fn suppress_duplicate_autonomy_tool_calls_respects_60m_window() {
        reset_runtime(AgentState::Sleeping, true, false, 0);
        let call = ToolCall {
            tool_call_id: None,
            tool: "evm_read".to_string(),
            args_json:
                r#"{"method":"eth_getBalance","address":"0x1111111111111111111111111111111111111111"}"#
                    .to_string(),
        };
        let fingerprint = tool_call_fingerprint(&call.tool, &call.args_json);
        stable::record_autonomy_tool_success(&fingerprint, 1_000);

        let (allowed_early, suppressed_early) = suppress_duplicate_autonomy_tool_calls(
            std::slice::from_ref(&call),
            1_000 + AUTONOMY_DUPLICATE_SUCCESS_WINDOW_NS - 1,
        );
        assert!(allowed_early.is_empty());
        assert_eq!(suppressed_early.len(), 1);

        let (allowed_late, suppressed_late) = suppress_duplicate_autonomy_tool_calls(
            &[call],
            1_000 + AUTONOMY_DUPLICATE_SUCCESS_WINDOW_NS,
        );
        assert_eq!(allowed_late.len(), 1);
        assert!(suppressed_late.is_empty());
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
        assert!(context.contains("- eth_balance_last_checked_ns: 10"));
        assert!(context.contains("- eth_balance_freshness_window_secs: 3600"));
        assert!(context.contains("- eth_balance_is_stale: true"));
        assert!(context.contains("### Pending Obligations"));
        assert!(context.contains("- staged_count: 2"));
        assert!(context.contains("### Recent Memory"));
        assert!(context.contains("- strategy=buy dips"));
        assert!(context.contains("### Available Tools"));
    }

    #[test]
    fn dynamic_context_marks_eth_balance_fresh_with_recent_check() {
        reset_runtime(AgentState::Sleeping, true, false, 12);
        let now_ns = current_time_ns();
        stable::set_memory_fact(&MemoryFact {
            key: "balance.eth".to_string(),
            value: "0x10".to_string(),
            created_at_ns: now_ns,
            updated_at_ns: now_ns,
            source_turn_id: "turn-11".to_string(),
        });
        stable::set_memory_fact(&MemoryFact {
            key: "balance.eth.last_checked_ns".to_string(),
            value: now_ns.to_string(),
            created_at_ns: now_ns,
            updated_at_ns: now_ns,
            source_turn_id: "turn-11".to_string(),
        });

        let snapshot = stable::runtime_snapshot();
        let context = build_dynamic_context(&snapshot, &[], 0, &[], "turn-12", 5);
        assert!(context.contains("- eth_balance_is_stale: false"));
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
    fn dynamic_context_reports_tool_usage_for_turn() {
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
        assert!(context.contains("- record_signal: calls_this_turn=2"));
        assert!(context.contains("- evm_read: calls_this_turn=1"));
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
    fn no_input_turn_runs_autonomous_inference_and_records_inner_dialogue() {
        reset_runtime(AgentState::Sleeping, true, false, 0);
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be set");

        let result = block_on_with_spin(run_scheduled_turn_job());
        assert!(result.is_ok(), "autonomous no-input turn should complete");

        let turns = stable::list_turns(1);
        assert_eq!(turns.len(), 1);
        let turn = &turns[0];
        assert_eq!(turn.input_summary, "autonomy:no-input");
        assert!(
            turn.tool_call_count >= 1,
            "mock autonomous turn should execute at least one tool"
        );
        assert!(
            turn.inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("goal: run an autonomy tick"),
            "inner dialogue should include autonomous turn goal"
        );
        assert!(
            turn.inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("why: the scheduler fired with no external input"),
            "inner dialogue should include autonomous turn rationale"
        );
        assert!(
            turn.inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("Tool results"),
            "inner dialogue should include tool execution summary"
        );
    }

    #[test]
    fn no_input_turn_suppresses_repeated_successful_autonomy_calls_within_window() {
        reset_runtime(AgentState::Sleeping, true, false, 0);
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be set");

        let first = block_on_with_spin(run_scheduled_turn_job());
        assert!(first.is_ok(), "first no-input turn should succeed");
        let second = block_on_with_spin(run_scheduled_turn_job());
        assert!(second.is_ok(), "second no-input turn should succeed");

        let turns = stable::list_turns(2);
        assert_eq!(turns.len(), 2);
        assert!(
            turns[1].tool_call_count >= 1,
            "first turn should execute at least one autonomous tool"
        );
        assert_eq!(
            turns[0].tool_call_count, 1,
            "second turn should keep one synthetic skipped tool result for continuation completeness"
        );
        assert!(
            turns[0]
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("autonomy dedupe suppressed"),
            "inner dialogue should explain autonomous dedupe suppression"
        );
        assert!(
            turns[0]
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("mocked continuation"),
            "suppressed calls should still feed continuation inference"
        );
    }

    #[test]
    fn autonomy_dedupe_suppressed_calls_emit_synthetic_tool_records_for_continuation() {
        reset_runtime(AgentState::Sleeping, true, false, 0);
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be set");

        let first = block_on_with_spin(run_scheduled_turn_job());
        assert!(first.is_ok(), "first no-input turn should succeed");
        let second = block_on_with_spin(run_scheduled_turn_job());
        assert!(second.is_ok(), "second no-input turn should succeed");

        let turns = stable::list_turns(1);
        assert_eq!(turns.len(), 1);
        let latest_turn = &turns[0];
        let tool_records = stable::get_tools_for_turn(&latest_turn.id);
        assert_eq!(
            tool_records.len(),
            usize::try_from(latest_turn.tool_call_count).expect("count conversion should succeed"),
            "turn tool count should match persisted records"
        );
        assert!(
            tool_records
                .iter()
                .all(|record| record.output.contains("skipped due to freshness dedupe")),
            "suppressed autonomous calls should be persisted as synthetic skipped tool outputs"
        );
        assert!(
            latest_turn
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("mocked continuation"),
            "synthetic tool outputs must allow continuation inference to complete"
        );
    }

    #[test]
    fn scheduled_turn_performs_continuation_inference_after_tool_execution() {
        reset_runtime(AgentState::Sleeping, true, false, 0);
        stable::post_inbox_message(
            "please continue after tool call".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )
        .expect("inbox message should be accepted");
        assert_eq!(stable::stage_pending_inbox_messages(10, 100), 1);

        let result = block_on_with_spin(run_scheduled_turn_job());
        assert!(result.is_ok(), "continuation turn should succeed");

        let outbox = stable::list_outbox_messages(10);
        assert_eq!(outbox.len(), 1, "reply should be posted for staged input");
        assert!(
            outbox[0].body.contains("mocked continuation"),
            "outbox should prefer continuation model text"
        );

        let turns = stable::list_turns(1);
        assert_eq!(turns.len(), 1);
        assert!(
            turns[0].tool_call_count >= 1,
            "initial round should execute at least one tool"
        );
        assert!(
            turns[0]
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("goal: respond to 1 staged inbox message(s)"),
            "inner dialogue should include inbox-driven turn goal"
        );
        assert!(
            turns[0]
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("why: new external inbox input is waiting"),
            "inner dialogue should include inbox-driven rationale"
        );
    }

    #[test]
    fn scheduled_turn_stops_continuation_when_max_rounds_reached() {
        reset_runtime(AgentState::Sleeping, true, false, 0);
        stable::post_inbox_message(
            "request_continuation_loop:true".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )
        .expect("inbox message should be accepted");
        assert_eq!(stable::stage_pending_inbox_messages(10, 100), 1);

        let result = block_on_with_spin(run_scheduled_turn_job_with_limits(2, u64::MAX));
        assert!(
            result.is_ok(),
            "turn should stop at round cap without failing"
        );

        let turns = stable::list_turns(1);
        assert_eq!(turns.len(), 1);
        assert_eq!(
            turns[0].tool_call_count, 2,
            "two rounds should produce two executed tool calls"
        );
        assert!(
            turns[0]
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("max inference rounds reached (2)"),
            "inner dialogue should explain round-cap stop reason"
        );
        assert_eq!(turns[0].inference_round_count, 2);
        assert_eq!(
            turns[0].continuation_stop_reason,
            ContinuationStopReason::MaxRounds
        );
    }

    #[test]
    fn scheduled_turn_stops_continuation_when_max_duration_reached() {
        reset_runtime(AgentState::Sleeping, true, false, 0);
        stable::post_inbox_message(
            "request_continuation_loop:true".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )
        .expect("inbox message should be accepted");
        assert_eq!(stable::stage_pending_inbox_messages(10, 100), 1);

        let result = block_on_with_spin(run_scheduled_turn_job_with_limits(5, 0));
        assert!(
            result.is_ok(),
            "turn should stop at duration cap without failing"
        );

        let turns = stable::list_turns(1);
        assert_eq!(turns.len(), 1);
        assert_eq!(
            turns[0].tool_call_count, 0,
            "duration cap hit before first inference should avoid executing tools"
        );
        assert_eq!(turns[0].inference_round_count, 0);
        assert_eq!(
            turns[0].continuation_stop_reason,
            ContinuationStopReason::MaxDuration
        );
        assert!(
            turns[0]
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("max turn duration reached (0 ms)"),
            "inner dialogue should explain duration-cap stop reason"
        );
    }

    #[test]
    fn scheduled_turn_stops_continuation_when_max_tool_calls_reached() {
        reset_runtime(AgentState::Sleeping, true, false, 0);
        stable::post_inbox_message(
            "request_continuation_loop:true".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )
        .expect("inbox message should be accepted");
        assert_eq!(stable::stage_pending_inbox_messages(10, 100), 1);

        let result = block_on_with_spin(run_scheduled_turn_job_with_limits_and_tool_cap(
            10,
            u64::MAX,
            1,
        ));
        assert!(
            result.is_ok(),
            "turn should stop at per-turn tool call cap without failing"
        );

        let turns = stable::list_turns(1);
        assert_eq!(turns.len(), 1);
        assert_eq!(
            turns[0].tool_call_count, 1,
            "tool call cap should prevent additional round executions"
        );
        assert_eq!(
            turns[0].continuation_stop_reason,
            ContinuationStopReason::MaxToolCalls
        );
        assert!(
            turns[0]
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("max tool calls reached (1)"),
            "inner dialogue should explain tool-call cap stop reason"
        );
    }

    #[test]
    fn continuation_inference_error_after_tools_is_degraded_success() {
        reset_runtime(AgentState::Sleeping, true, false, 0);
        stable::post_inbox_message(
            "request_continuation_error:true".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )
        .expect("inbox message should be accepted");
        assert_eq!(stable::stage_pending_inbox_messages(10, 100), 1);

        let result = block_on_with_spin(run_scheduled_turn_job());
        assert!(
            result.is_ok(),
            "continuation-stage inference errors after tool execution must degrade, not fail"
        );

        let turns = stable::list_turns(1);
        assert_eq!(turns.len(), 1);
        assert!(
            turns[0].error.is_none(),
            "degraded continuation should not mark turn as failed"
        );
        assert!(
            turns[0]
                .inner_dialogue
                .as_deref()
                .unwrap_or_default()
                .contains("continuation inference degraded after tool execution"),
            "inner dialogue should capture degraded continuation reason"
        );
        assert_eq!(turns[0].inference_round_count, 2);
        assert_eq!(
            turns[0].continuation_stop_reason,
            ContinuationStopReason::InferenceError
        );

        let outbox = stable::list_outbox_messages(10);
        assert_eq!(outbox.len(), 1, "reply should still be posted");
        assert!(
            outbox[0].body.contains("Tool results:"),
            "fallback response should use deterministic tool summary"
        );
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
