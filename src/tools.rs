/// Tool registry and policy enforcement for the agent's action surface.
///
/// This module owns three concerns:
///
/// 1. **Port traits** — `SignerPort` and `EvmBroadcastPort` abstract over IC threshold
///    cryptography and EVM broadcast so they can be swapped for test doubles.
/// 2. **Policy layer** — `ToolPolicy` gates each named tool on an `enabled` flag and a
///    whitelist of `AgentState` values.  `ToolManager` holds the per-tool registry and
///    enforces those gates before dispatching.
/// 3. **Tool implementations** — each named tool is a small, focused function.  Tools that
///    touch external services (signing, EVM, HTTP) also consult the survival-operation
///    backoff tracker in `storage::stable` before executing.
///
/// # Content limits
///
/// | Constant                        | Value  |
/// |---------------------------------|--------|
/// | `MAX_PROMPT_LAYER_CONTENT_CHARS`| 4 000  |
/// | `MAX_MEMORY_KEY_BYTES`          | 128    |
/// | `MAX_MEMORY_VALUE_BYTES`        | 4 096  |
/// | `MAX_MEMORY_RECALL_RESULTS`     | 50     |
/// | `MAX_STRATEGY_TEMPLATE_RESULTS` | 50     |
use crate::domain::types::{
    AgentState, MemoryFact, PromptLayer, StrategyExecutionIntent, StrategyTemplateKey,
    SurvivalOperationClass, TemplateVersion, ToolCall, ToolCallRecord,
};
use crate::features::cycle_topup_host::{top_up_status_tool, trigger_top_up_tool};
use crate::features::evm::{evm_read_tool, send_eth_tool};
use crate::features::http_fetch::http_fetch_tool;
use crate::prompt;
use crate::storage::stable;
use crate::strategy::{compiler, learner, registry, validator};
use crate::timing::current_time_ns;
use alloy_primitives::U256;
use async_trait::async_trait;
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};
use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum byte length of a memory key (after trimming and lowercasing).
const MAX_MEMORY_KEY_BYTES: usize = 128;
/// Maximum byte length of a memory value stored by the `remember` tool.
const MAX_MEMORY_VALUE_BYTES: usize = 4096;
/// Maximum number of memory facts returned by a single `recall` call.
const MAX_MEMORY_RECALL_RESULTS: usize = 50;
/// Maximum number of strategy templates returned by `list_strategy_templates`.
const MAX_STRATEGY_TEMPLATE_RESULTS: usize = 50;
/// Maximum character count for content written via `update_prompt_layer`.
pub const MAX_PROMPT_LAYER_CONTENT_CHARS: usize = 4_000;
/// Phrases that are never allowed in mutable prompt-layer content — prevents
/// an agent turn from injecting policy-override instructions into the prompt.
const FORBIDDEN_PROMPT_LAYER_PHRASES: &[&str] = &[
    "ignore layer 0",
    "ignore layer 1",
    "ignore layer 2",
    "ignore previous instructions",
    "override constitution",
    "disable safety",
    "bypass safety",
    "weaken safety",
];

#[derive(Clone, Copy, Debug, LogPriorityLevels)]
enum StrategyToolLogPriority {
    #[log_level(capacity = 2_000, name = "STRATEGY_TOOL_INFO")]
    Info,
    #[log_level(capacity = 500, name = "STRATEGY_TOOL_ERROR")]
    Error,
}

impl GetLogFilter for StrategyToolLogPriority {
    fn get_log_filter() -> LogFilter {
        LogFilter::ShowAll
    }
}

// ── Ports (external-service abstractions) ────────────────────────────────────

/// Abstraction over IC threshold-ECDSA signing.
///
/// In production this calls `ic_cdk::api::management_canister::ecdsa::sign_with_ecdsa`.
/// In tests a `CountingSigner` or `HexSigner` stub is injected instead.
#[async_trait(?Send)]
pub trait SignerPort {
    async fn sign_message(&self, message_hash: &str) -> Result<String, String>;
}

/// Abstraction over EVM transaction broadcast.
///
/// Decouples the tool dispatch loop from the concrete HTTP-outcall broadcast path,
/// enabling unit tests to verify call counts without performing real broadcasts.
#[async_trait(?Send)]
pub trait EvmBroadcastPort {
    async fn broadcast_transaction(&self, signed_transaction: &str) -> Result<String, String>;
}

// ── Policies ─────────────────────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct MockEvmBroadcastAdapter;

#[async_trait(?Send)]
impl EvmBroadcastPort for MockEvmBroadcastAdapter {
    async fn broadcast_transaction(&self, signed_transaction: &str) -> Result<String, String> {
        Ok(format!("0x{signed_transaction}-mock-hash"))
    }
}

/// Per-tool access policy.
///
/// A tool is permitted only when `enabled` is `true` **and** the current
/// `AgentState` is present in `allowed_states`.  Both conditions must hold;
/// failing either returns a "tool blocked by policy" error record.
#[derive(Clone, Debug)]
pub struct ToolPolicy {
    /// When `false` the tool is unconditionally blocked regardless of state.
    pub enabled: bool,
    /// Agent states from which this tool may be called.
    pub allowed_states: Vec<AgentState>,
}

impl Default for ToolPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_states: vec![
                AgentState::ExecutingActions,
                AgentState::Inferring,
                AgentState::Persisting,
            ],
        }
    }
}

// ── Tool manager ─────────────────────────────────────────────────────────────

/// Central dispatcher for all agent tool calls.
///
/// `ToolManager` holds the per-tool `ToolPolicy` registry and enforces it on
/// every call via `execute_actions` / `execute_actions_with_broadcaster`.
/// Tool implementations are matched by name inside `execute_actions_with_broadcaster`.
pub struct ToolManager {
    policies: HashMap<String, ToolPolicy>,
}

impl ToolManager {
    /// Construct a `ToolManager` pre-populated with the canonical tool policies.
    ///
    /// Dangerous tools (`sign_message`, `broadcast_transaction`, `send_eth`, …)
    /// are restricted to `ExecutingActions`; read-only tools also allow `Inferring`.
    pub fn new() -> Self {
        let mut policies = HashMap::new();
        policies.insert(
            "sign_message".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions],
            },
        );
        policies.insert(
            "broadcast_transaction".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions],
            },
        );
        policies.insert(
            "record_signal".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
            },
        );
        policies.insert(
            "evm_read".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
            },
        );
        policies.insert(
            "send_eth".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions],
            },
        );
        policies.insert(
            "remember".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
            },
        );
        policies.insert(
            "recall".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
            },
        );
        policies.insert(
            "forget".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
            },
        );
        policies.insert(
            "http_fetch".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions],
            },
        );
        policies.insert(
            "update_prompt_layer".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions],
            },
        );
        policies.insert(
            "top_up_status".to_string(),
            ToolPolicy {
                enabled: false,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
            },
        );
        policies.insert(
            "trigger_top_up".to_string(),
            ToolPolicy {
                enabled: false,
                allowed_states: vec![AgentState::ExecutingActions],
            },
        );
        policies.insert(
            "list_strategy_templates".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
            },
        );
        policies.insert(
            "simulate_strategy_action".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
            },
        );
        policies.insert(
            "execute_strategy_action".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions],
            },
        );
        policies.insert(
            "get_strategy_outcomes".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
            },
        );

        Self { policies }
    }

    /// Register or overwrite a tool policy at runtime.
    #[allow(dead_code)]
    pub fn register_tool(&mut self, name: String, policy: ToolPolicy) {
        self.policies.insert(name, policy);
    }

    /// Return all registered tools sorted alphabetically by name.
    pub fn list_tools(&self) -> Vec<(String, ToolPolicy)> {
        let mut rows: Vec<_> = self
            .policies
            .iter()
            .map(|(name, policy)| (name.clone(), policy.clone()))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    /// Look up the policy for a named tool, returning `None` if unregistered.
    #[allow(dead_code)]
    pub fn policy_for(&self, tool: &str) -> Option<&ToolPolicy> {
        self.policies.get(tool)
    }

    /// Execute tool calls without an EVM broadcaster.
    ///
    /// Convenience wrapper around `execute_actions_with_broadcaster` for callers
    /// that do not need raw transaction broadcast (e.g. signing-only flows).
    pub async fn execute_actions(
        &mut self,
        state: &AgentState,
        calls: &[ToolCall],
        signer: &dyn SignerPort,
        turn_id: &str,
    ) -> Vec<ToolCallRecord> {
        self.execute_actions_with_broadcaster(state, calls, signer, None, turn_id)
            .await
    }

    /// Execute a batch of tool calls, enforcing policies and survival-operation gates.
    ///
    /// Each call is checked against its `ToolPolicy` first.  Calls that pass are
    /// dispatched to the matching tool implementation.  The returned `Vec` preserves
    /// call order and always has the same length as `calls`.
    pub async fn execute_actions_with_broadcaster(
        &mut self,
        state: &AgentState,
        calls: &[ToolCall],
        signer: &dyn SignerPort,
        broadcaster: Option<&dyn EvmBroadcastPort>,
        turn_id: &str,
    ) -> Vec<ToolCallRecord> {
        let mut records = Vec::with_capacity(calls.len());
        for call in calls {
            let policy = match self.policies.get(&call.tool) {
                Some(policy) => policy,
                None => {
                    records.push(ToolCallRecord {
                        turn_id: turn_id.to_string(),
                        tool: call.tool.clone(),
                        args_json: call.args_json.clone(),
                        output: "unknown tool".to_string(),
                        success: false,
                        error: Some("unknown tool".to_string()),
                    });
                    continue;
                }
            };

            if !policy.enabled || !policy.allowed_states.contains(state) {
                records.push(ToolCallRecord {
                    turn_id: turn_id.to_string(),
                    tool: call.tool.clone(),
                    args_json: call.args_json.clone(),
                    output: "tool blocked by policy".to_string(),
                    success: false,
                    error: Some("tool blocked".to_string()),
                });
                continue;
            }

            let result = match call.tool.as_str() {
                "sign_message" => {
                    let now_ns = current_time_ns();
                    if !stable::can_run_survival_operation(
                        &SurvivalOperationClass::ThresholdSign,
                        now_ns,
                    ) {
                        Err("signing skipped due to survival policy".to_string())
                    } else {
                        let message_hash = match parse_sign_message_args(&call.args_json) {
                            Ok(message_hash) => message_hash,
                            Err(error) => {
                                records.push(ToolCallRecord {
                                    turn_id: turn_id.to_string(),
                                    tool: call.tool.clone(),
                                    args_json: call.args_json.clone(),
                                    output: "tool execution failed".to_string(),
                                    success: false,
                                    error: Some(error),
                                });
                                continue;
                            }
                        };

                        let result = signer.sign_message(&message_hash).await;
                        if result.is_ok() {
                            stable::record_survival_operation_success(
                                &SurvivalOperationClass::ThresholdSign,
                            );
                        } else {
                            stable::record_survival_operation_failure(
                                &SurvivalOperationClass::ThresholdSign,
                                now_ns,
                                stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_THRESHOLD_SIGN,
                            );
                        }
                        result
                    }
                }
                "broadcast_transaction" => {
                    let now_ns = current_time_ns();
                    if !stable::can_run_survival_operation(
                        &SurvivalOperationClass::EvmBroadcast,
                        now_ns,
                    ) {
                        Err("broadcast skipped due to survival policy".to_string())
                    } else if let Some(adapter) = broadcaster {
                        let result = adapter.broadcast_transaction(&call.args_json).await;
                        if result.is_ok() {
                            stable::record_survival_operation_success(
                                &SurvivalOperationClass::EvmBroadcast,
                            );
                        } else {
                            stable::record_survival_operation_failure(
                                &SurvivalOperationClass::EvmBroadcast,
                                now_ns,
                                stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_BROADCAST,
                            );
                        }
                        result
                    } else {
                        Err("broadcast adapter unavailable".to_string())
                    }
                }
                "record_signal" => Ok("recorded".to_string()),
                "remember" => remember_fact_tool(&call.args_json, turn_id),
                "recall" => recall_facts_tool(&call.args_json),
                "forget" => forget_fact_tool(&call.args_json),
                "http_fetch" => http_fetch_tool(&call.args_json).await,
                "top_up_status" => Ok(top_up_status_tool()),
                "trigger_top_up" => trigger_top_up_tool(),
                "list_strategy_templates" => list_strategy_templates_tool(&call.args_json),
                "simulate_strategy_action" => {
                    let now_ns = current_time_ns();
                    if !stable::can_run_survival_operation(&SurvivalOperationClass::EvmPoll, now_ns)
                    {
                        Err("simulate_strategy_action skipped due to survival policy".to_string())
                    } else {
                        let result = simulate_strategy_action_tool(&call.args_json);
                        if result.is_ok() {
                            stable::record_survival_operation_success(
                                &SurvivalOperationClass::EvmPoll,
                            );
                        } else {
                            stable::record_survival_operation_failure(
                                &SurvivalOperationClass::EvmPoll,
                                now_ns,
                                stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_POLL,
                            );
                        }
                        result
                    }
                }
                "execute_strategy_action" => {
                    let now_ns = current_time_ns();
                    if !stable::can_run_survival_operation(
                        &SurvivalOperationClass::ThresholdSign,
                        now_ns,
                    ) {
                        Err(
                            "execute_strategy_action skipped due to threshold sign survival policy"
                                .to_string(),
                        )
                    } else if !stable::can_run_survival_operation(
                        &SurvivalOperationClass::EvmBroadcast,
                        now_ns,
                    ) {
                        Err(
                            "execute_strategy_action skipped due to evm broadcast survival policy"
                                .to_string(),
                        )
                    } else if !stable::can_run_survival_operation(
                        &SurvivalOperationClass::EvmPoll,
                        now_ns,
                    ) {
                        Err(
                            "execute_strategy_action skipped due to preflight survival policy"
                                .to_string(),
                        )
                    } else {
                        let result = execute_strategy_action_tool(&call.args_json, signer).await;
                        if result.is_ok() {
                            stable::record_survival_operation_success(
                                &SurvivalOperationClass::EvmPoll,
                            );
                        } else {
                            stable::record_survival_operation_failure(
                                &SurvivalOperationClass::EvmPoll,
                                now_ns,
                                stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_POLL,
                            );
                        }
                        result
                    }
                }
                "get_strategy_outcomes" => get_strategy_outcomes_tool(&call.args_json),
                "update_prompt_layer" => parse_update_prompt_layer_args(&call.args_json).and_then(
                    |(layer_id, content)| {
                        update_prompt_layer_content(layer_id, content, turn_id).map(|layer| {
                            format!(
                                "updated prompt layer {} to version {}",
                                layer.layer_id, layer.version
                            )
                        })
                    },
                ),
                "evm_read" => {
                    let now_ns = current_time_ns();
                    if !stable::can_run_survival_operation(&SurvivalOperationClass::EvmPoll, now_ns)
                    {
                        Err("evm_read skipped due to survival policy".to_string())
                    } else {
                        let result = evm_read_tool(&call.args_json).await;
                        if result.is_ok() {
                            stable::record_survival_operation_success(
                                &SurvivalOperationClass::EvmPoll,
                            );
                        } else {
                            stable::record_survival_operation_failure(
                                &SurvivalOperationClass::EvmPoll,
                                now_ns,
                                stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_POLL,
                            );
                        }
                        result
                    }
                }
                "send_eth" => {
                    let now_ns = current_time_ns();
                    if !stable::can_run_survival_operation(
                        &SurvivalOperationClass::ThresholdSign,
                        now_ns,
                    ) {
                        Err("send_eth skipped due to threshold sign survival policy".to_string())
                    } else if !stable::can_run_survival_operation(
                        &SurvivalOperationClass::EvmBroadcast,
                        now_ns,
                    ) {
                        Err("send_eth skipped due to evm broadcast survival policy".to_string())
                    } else {
                        let result = send_eth_tool(&call.args_json, signer).await;
                        if result.is_ok() {
                            stable::record_survival_operation_success(
                                &SurvivalOperationClass::ThresholdSign,
                            );
                            stable::record_survival_operation_success(
                                &SurvivalOperationClass::EvmBroadcast,
                            );
                        } else {
                            stable::record_survival_operation_failure(
                                &SurvivalOperationClass::ThresholdSign,
                                now_ns,
                                stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_THRESHOLD_SIGN,
                            );
                            stable::record_survival_operation_failure(
                                &SurvivalOperationClass::EvmBroadcast,
                                now_ns,
                                stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_EVM_BROADCAST,
                            );
                        }
                        result
                    }
                }
                _ => Err("unknown tool".to_string()),
            };

            records.push(match result {
                Ok(output) => ToolCallRecord {
                    turn_id: turn_id.to_string(),
                    tool: call.tool.clone(),
                    args_json: call.args_json.clone(),
                    output,
                    success: true,
                    error: None,
                },
                Err(error) => ToolCallRecord {
                    turn_id: turn_id.to_string(),
                    tool: call.tool.clone(),
                    args_json: call.args_json.clone(),
                    output: "tool execution failed".to_string(),
                    success: false,
                    error: Some(error),
                },
            });
        }
        records
    }
}

// ── Tool implementations ──────────────────────────────────────────────────────

/// Validate content intended for a mutable prompt layer.
///
/// Returns the trimmed content on success, or an error if the content is empty,
/// exceeds `MAX_PROMPT_LAYER_CONTENT_CHARS`, or contains a forbidden phrase.
fn validate_prompt_layer_content(content: &str) -> Result<String, String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err("content cannot be empty".to_string());
    }
    if trimmed.chars().count() > MAX_PROMPT_LAYER_CONTENT_CHARS {
        return Err(format!(
            "content must be at most {MAX_PROMPT_LAYER_CONTENT_CHARS} chars"
        ));
    }
    let normalized = trimmed.to_ascii_lowercase();
    if FORBIDDEN_PROMPT_LAYER_PHRASES
        .iter()
        .any(|phrase| normalized.contains(phrase))
    {
        return Err("content contains forbidden policy-override phrase".to_string());
    }
    Ok(trimmed.to_string())
}

/// Write new content to a mutable prompt layer and persist it to stable storage.
///
/// Only layers in the range `[MUTABLE_LAYER_MIN_ID, MUTABLE_LAYER_MAX_ID]` are
/// writable.  The version counter is bumped monotonically on each successful write.
pub fn update_prompt_layer_content(
    layer_id: u8,
    content: String,
    updated_by_turn: &str,
) -> Result<PromptLayer, String> {
    if !(prompt::MUTABLE_LAYER_MIN_ID..=prompt::MUTABLE_LAYER_MAX_ID).contains(&layer_id) {
        return Err(format!(
            "layer_id must be in range {}..={}",
            prompt::MUTABLE_LAYER_MIN_ID,
            prompt::MUTABLE_LAYER_MAX_ID
        ));
    }
    let normalized_content = validate_prompt_layer_content(&content)?;
    let previous = stable::get_prompt_layer(layer_id);
    let layer = PromptLayer {
        layer_id,
        content: normalized_content,
        updated_at_ns: current_time_ns(),
        updated_by_turn: updated_by_turn.trim().to_string(),
        version: previous
            .map(|layer| layer.version.saturating_add(1))
            .unwrap_or(1),
    };
    stable::save_prompt_layer(&layer)?;
    Ok(layer)
}

// ── Argument parsers ──────────────────────────────────────────────────────────

/// Extract `message_hash` from the JSON args of a `sign_message` call.
fn parse_sign_message_args(args_json: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid sign_message args json: {error}"))?;
    value
        .get("message_hash")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| "missing required field: message_hash".to_string())
}

/// Trim, lowercase, and validate a memory key.
fn normalize_memory_key(raw: &str) -> Result<String, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > MAX_MEMORY_KEY_BYTES {
        return Err(format!("key must be 1-{MAX_MEMORY_KEY_BYTES} bytes"));
    }
    if normalized.chars().any(|char| char.is_control()) {
        return Err("key must not contain control characters".to_string());
    }
    Ok(normalized)
}

/// Trim, lowercase, and validate a memory prefix (may be empty for "list all").
fn normalize_memory_prefix(raw: &str) -> Result<String, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.len() > MAX_MEMORY_KEY_BYTES {
        return Err(format!(
            "prefix must be at most {MAX_MEMORY_KEY_BYTES} bytes"
        ));
    }
    if normalized.chars().any(|char| char.is_control()) {
        return Err("prefix must not contain control characters".to_string());
    }
    Ok(normalized)
}

/// Parse and validate the `key` and `value` fields for the `remember` tool.
fn parse_remember_args(args_json: &str) -> Result<(String, String), String> {
    let value: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid remember args json: {error}"))?;
    let key_raw = value
        .get("key")
        .and_then(|entry| entry.as_str())
        .ok_or_else(|| "missing required field: key".to_string())?;
    let value_raw = value
        .get("value")
        .and_then(|entry| entry.as_str())
        .ok_or_else(|| "missing required field: value".to_string())?;
    if value_raw.len() > MAX_MEMORY_VALUE_BYTES {
        return Err(format!(
            "value must be at most {MAX_MEMORY_VALUE_BYTES} bytes"
        ));
    }
    Ok((normalize_memory_key(key_raw)?, value_raw.to_string()))
}

/// Parse the optional `prefix` field for the `recall` tool.
/// Returns an empty string when no prefix is provided (match all facts).
fn parse_recall_args(args_json: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid recall args json: {error}"))?;
    match value.get("prefix") {
        Some(prefix) => {
            let prefix = prefix
                .as_str()
                .ok_or_else(|| "prefix must be a string".to_string())?;
            normalize_memory_prefix(prefix)
        }
        None => Ok(String::new()),
    }
}

/// Extract and validate the `key` field for the `forget` tool.
fn parse_forget_args(args_json: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid forget args json: {error}"))?;
    let key_raw = value
        .get("key")
        .and_then(|entry| entry.as_str())
        .ok_or_else(|| "missing required field: key".to_string())?;
    normalize_memory_key(key_raw)
}

/// Extract `layer_id` (u8) and `content` from `update_prompt_layer` args.
fn parse_update_prompt_layer_args(args_json: &str) -> Result<(u8, String), String> {
    let value: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid update_prompt_layer args json: {error}"))?;
    let layer_id = value
        .get("layer_id")
        .and_then(|entry| entry.as_u64())
        .ok_or_else(|| "missing required field: layer_id".to_string())?;
    let content = value
        .get("content")
        .and_then(|entry| entry.as_str())
        .ok_or_else(|| "missing required field: content".to_string())?;
    let layer_id = u8::try_from(layer_id)
        .map_err(|_| "layer_id must be an integer in the u8 range".to_string())?;
    Ok((layer_id, content.to_string()))
}

#[derive(Debug, Deserialize, Default)]
struct ListStrategyTemplatesArgs {
    #[serde(default)]
    key: Option<StrategyTemplateKey>,
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct StrategyOutcomesArgs {
    key: StrategyTemplateKey,
    version: TemplateVersion,
}

#[derive(Debug, Deserialize)]
struct StrategyIntentArgs {
    key: StrategyTemplateKey,
    version: TemplateVersion,
    action_id: String,
    #[serde(default)]
    typed_params_json: Option<String>,
    #[serde(default)]
    typed_params: Option<serde_json::Value>,
}

/// Parse args for `list_strategy_templates`; all fields are optional.
fn parse_list_strategy_templates_args(
    args_json: &str,
) -> Result<ListStrategyTemplatesArgs, String> {
    serde_json::from_str(args_json)
        .map_err(|error| format!("invalid list_strategy_templates args json: {error}"))
}

/// Parse `key` and `version` for the `get_strategy_outcomes` tool.
fn parse_strategy_outcomes_args(args_json: &str) -> Result<StrategyOutcomesArgs, String> {
    serde_json::from_str(args_json)
        .map_err(|error| format!("invalid get_strategy_outcomes args json: {error}"))
}

/// Parse strategy action intent args, normalising `typed_params` vs `typed_params_json`.
///
/// Accepts either a pre-serialised JSON string (`typed_params_json`) or an
/// inline JSON object (`typed_params`); if both are present the string form wins.
fn parse_strategy_intent_args(args_json: &str) -> Result<StrategyExecutionIntent, String> {
    let args: StrategyIntentArgs = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid strategy action args json: {error}"))?;
    let typed_params_json = match (args.typed_params_json, args.typed_params) {
        (Some(json), None) => json,
        (None, Some(value)) => value.to_string(),
        (Some(json), Some(_value)) => json,
        (None, None) => {
            return Err("missing required field: typed_params or typed_params_json".to_string())
        }
    };
    Ok(StrategyExecutionIntent {
        key: args.key,
        version: args.version,
        action_id: args.action_id,
        typed_params_json,
    })
}

fn list_strategy_templates_tool(args_json: &str) -> Result<String, String> {
    let args = parse_list_strategy_templates_args(args_json)?;
    let limit = args
        .limit
        .map(|value| value.max(1) as usize)
        .unwrap_or(20)
        .min(MAX_STRATEGY_TEMPLATE_RESULTS);
    let templates = match args.key {
        Some(key) => registry::list_templates(&key, limit),
        None => registry::list_all_templates(limit),
    };
    serde_json::to_string(&templates)
        .map_err(|error| format!("failed to serialize templates: {error}"))
}

/// Compile and validate a strategy intent without submitting any transactions.
/// Returns the compiled plan and validation findings as JSON.
fn simulate_strategy_action_tool(args_json: &str) -> Result<String, String> {
    let intent = parse_strategy_intent_args(args_json)?;
    log!(
        StrategyToolLogPriority::Info,
        "strategy_compile_start mode=simulate protocol={} primitive={} template_id={} version={}.{}.{} action_id={}",
        intent.key.protocol,
        intent.key.primitive,
        intent.key.template_id,
        intent.version.major,
        intent.version.minor,
        intent.version.patch,
        intent.action_id
    );
    let plan = compiler::compile_intent(&intent)?;
    log!(
        StrategyToolLogPriority::Info,
        "strategy_compile_ok mode=simulate protocol={} template_id={} action_id={} call_count={}",
        plan.key.protocol,
        plan.key.template_id,
        plan.action_id,
        plan.calls.len()
    );
    let validation = validator::validate_execution_plan(&plan)?;
    log!(
        StrategyToolLogPriority::Info,
        "strategy_validate_complete mode=simulate protocol={} template_id={} action_id={} passed={} findings={}",
        plan.key.protocol,
        plan.key.template_id,
        plan.action_id,
        validation.passed,
        validation.findings.len()
    );
    serde_json::to_string(&serde_json::json!({
        "plan": plan,
        "validation": validation,
    }))
    .map_err(|error| format!("failed to serialize simulation result: {error}"))
}

/// Compile, validate, and execute a strategy intent — sends real transactions.
///
/// Aborts before broadcast if validation does not pass.  On success the
/// template's budget-spend counter is updated in stable storage.
async fn execute_strategy_action_tool(
    args_json: &str,
    signer: &dyn SignerPort,
) -> Result<String, String> {
    let intent = parse_strategy_intent_args(args_json)?;
    log!(
        StrategyToolLogPriority::Info,
        "strategy_compile_start mode=execute protocol={} primitive={} template_id={} version={}.{}.{} action_id={}",
        intent.key.protocol,
        intent.key.primitive,
        intent.key.template_id,
        intent.version.major,
        intent.version.minor,
        intent.version.patch,
        intent.action_id
    );
    let plan = compiler::compile_intent(&intent)?;
    log!(
        StrategyToolLogPriority::Info,
        "strategy_compile_ok mode=execute protocol={} template_id={} action_id={} call_count={}",
        plan.key.protocol,
        plan.key.template_id,
        plan.action_id,
        plan.calls.len()
    );
    let validation = validator::validate_execution_plan(&plan)?;
    log!(
        StrategyToolLogPriority::Info,
        "strategy_validate_complete mode=execute protocol={} template_id={} action_id={} passed={} findings={}",
        plan.key.protocol,
        plan.key.template_id,
        plan.action_id,
        validation.passed,
        validation.findings.len()
    );
    if !validation.passed {
        let error = validation
            .findings
            .iter()
            .map(|finding| format!("{}:{}", finding.code, finding.message))
            .collect::<Vec<_>>()
            .join("; ");
        log!(
            StrategyToolLogPriority::Error,
            "strategy_validate_failed protocol={} template_id={} action_id={} error={}",
            plan.key.protocol,
            plan.key.template_id,
            plan.action_id,
            error
        );
        return Err(format!("strategy validation failed: {error}"));
    }

    log!(
        StrategyToolLogPriority::Info,
        "strategy_execute_start protocol={} template_id={} action_id={} call_count={}",
        plan.key.protocol,
        plan.key.template_id,
        plan.action_id,
        plan.calls.len()
    );
    let tx_hashes = crate::features::evm::execute_strategy_plan(&plan, signer).await?;
    if let Err(error) = record_strategy_budget_spend(&plan) {
        log!(
            StrategyToolLogPriority::Error,
            "strategy_budget_update_failed protocol={} template_id={} action_id={} error={}",
            plan.key.protocol,
            plan.key.template_id,
            plan.action_id,
            error
        );
        return Err(format!(
            "strategy execution budget bookkeeping failed: {error}"
        ));
    }
    log!(
        StrategyToolLogPriority::Info,
        "strategy_execute_ok protocol={} template_id={} action_id={} tx_hash_count={}",
        plan.key.protocol,
        plan.key.template_id,
        plan.action_id,
        tx_hashes.len()
    );
    serde_json::to_string(&serde_json::json!({
        "key": plan.key,
        "version": plan.version,
        "action_id": plan.action_id,
        "tx_hashes": tx_hashes
    }))
    .map_err(|error| format!("failed to serialize execution result: {error}"))
}

/// Query the learner's outcome statistics for a specific template version.
fn get_strategy_outcomes_tool(args_json: &str) -> Result<String, String> {
    let args = parse_strategy_outcomes_args(args_json)?;
    let stats = learner::outcome_stats(&args.key, &args.version);
    serde_json::to_string(&serde_json::json!({
        "key": args.key,
        "version": args.version,
        "stats": stats,
    }))
    .map_err(|error| format!("failed to serialize strategy outcomes: {error}"))
}

/// Accumulate the Wei value of all calls in `plan` against the template's budget counter.
/// No-ops when the total spend for this execution is zero.
fn record_strategy_budget_spend(plan: &crate::domain::types::ExecutionPlan) -> Result<(), String> {
    let spent_total = plan.calls.iter().try_fold(U256::ZERO, |acc, call| {
        parse_u256_decimal(&call.value_wei)
            .map(|value| acc.saturating_add(value))
            .map_err(|error| format!("invalid plan value_wei for budget update: {error}"))
    })?;
    if spent_total == U256::ZERO {
        return Ok(());
    }

    let current_spent_raw = stable::strategy_template_budget_spent_wei(&plan.key, &plan.version)
        .unwrap_or_else(|| "0".to_string());
    let current_spent = parse_u256_decimal(&current_spent_raw)
        .map_err(|error| format!("invalid stored template budget: {error}"))?;
    let updated = current_spent.saturating_add(spent_total);
    stable::set_strategy_template_budget_spent_wei(&plan.key, &plan.version, updated.to_string())
        .map(|_| ())
}

/// Parse a decimal (non-hex) string into a `U256`.  Rejects empty input and hex strings.
fn parse_u256_decimal(raw: &str) -> Result<U256, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("value cannot be empty".to_string());
    }
    if !trimmed.as_bytes().iter().all(|byte| byte.is_ascii_digit()) {
        return Err("value must be a decimal string".to_string());
    }
    U256::from_str(trimmed).map_err(|error| format!("failed to parse decimal quantity: {error}"))
}

/// Store a key/value fact in stable memory, preserving the original `created_at_ns`
/// timestamp on updates so the fact's age remains accurate.
fn remember_fact_tool(args_json: &str, turn_id: &str) -> Result<String, String> {
    let (key, value) = parse_remember_args(args_json)?;
    let now_ns = current_time_ns();
    let existing = stable::get_memory_fact(&key);
    stable::set_memory_fact(&MemoryFact {
        key: key.clone(),
        value,
        created_at_ns: existing
            .as_ref()
            .map(|fact| fact.created_at_ns)
            .unwrap_or(now_ns),
        updated_at_ns: now_ns,
        source_turn_id: turn_id.to_string(),
    })?;
    Ok(format!("stored: {key}"))
}

/// Return up to `MAX_MEMORY_RECALL_RESULTS` facts matching the given prefix,
/// formatted as `key=value` lines.
fn recall_facts_tool(args_json: &str) -> Result<String, String> {
    let prefix = parse_recall_args(args_json)?;
    let facts = if prefix.is_empty() {
        stable::list_all_memory_facts(MAX_MEMORY_RECALL_RESULTS)
    } else {
        stable::list_memory_facts_by_prefix(&prefix, MAX_MEMORY_RECALL_RESULTS)
    };

    if facts.is_empty() {
        return Ok("no facts found".to_string());
    }

    Ok(facts
        .into_iter()
        .map(|fact| format!("{}={}", fact.key, fact.value))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Remove a named fact from stable memory; succeeds even if the key is absent.
fn forget_fact_tool(args_json: &str) -> Result<String, String> {
    let key = parse_forget_args(args_json)?;
    if stable::remove_memory_fact(&key) {
        Ok(format!("forgot: {key}"))
    } else {
        Ok(format!("no fact for key: {key}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{
        AbiArtifact, AbiArtifactKey, AbiFunctionSpec, AbiTypeSpec, ActionSpec, AgentState,
        ContractRoleBinding, StrategyTemplate, StrategyTemplateKey, SurvivalOperationClass,
        SurvivalTier, TemplateActivationState, TemplateStatus, TemplateVersion,
    };
    use crate::features::cycle_topup::TopUpStage;
    use crate::storage::stable;
    use crate::timing;
    use async_trait::async_trait;
    use std::cell::Cell;
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    struct CountingSigner {
        calls: Cell<u32>,
    }

    impl CountingSigner {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
            }
        }
    }

    #[async_trait(?Send)]
    impl SignerPort for CountingSigner {
        async fn sign_message(&self, message: &str) -> Result<String, String> {
            self.calls.set(self.calls.get().saturating_add(1));
            Ok(format!("mock-signature-{message}"))
        }
    }

    struct CountingBroadcaster {
        calls: Cell<u32>,
    }

    impl CountingBroadcaster {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
            }
        }
    }

    #[async_trait(?Send)]
    impl EvmBroadcastPort for CountingBroadcaster {
        async fn broadcast_transaction(&self, signed_transaction: &str) -> Result<String, String> {
            self.calls.set(self.calls.get().saturating_add(1));
            Ok(format!("mock-broadcast-{signed_transaction}"))
        }
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

    struct TimeOverrideGuard;

    impl Drop for TimeOverrideGuard {
        fn drop(&mut self) {
            timing::clear_test_time_ns();
        }
    }

    fn with_fixed_time_ns(now_ns: u64) -> TimeOverrideGuard {
        timing::set_test_time_ns(now_ns);
        TimeOverrideGuard
    }

    fn sample_strategy_key() -> StrategyTemplateKey {
        StrategyTemplateKey {
            protocol: "erc20".to_string(),
            primitive: "transfer".to_string(),
            chain_id: 8453,
            template_id: "tool-transfer".to_string(),
        }
    }

    fn sample_version() -> TemplateVersion {
        TemplateVersion {
            major: 1,
            minor: 0,
            patch: 0,
        }
    }

    fn seed_strategy_template_and_artifact() {
        let key = sample_strategy_key();
        let version = sample_version();
        let function = AbiFunctionSpec {
            role: "token".to_string(),
            name: "transfer".to_string(),
            selector_hex: "0xa9059cbb".to_string(),
            inputs: vec![
                AbiTypeSpec {
                    kind: "address".to_string(),
                    components: Vec::new(),
                },
                AbiTypeSpec {
                    kind: "uint256".to_string(),
                    components: Vec::new(),
                },
            ],
            outputs: vec![AbiTypeSpec {
                kind: "bool".to_string(),
                components: Vec::new(),
            }],
            state_mutability: "nonpayable".to_string(),
        };
        crate::strategy::registry::upsert_template(StrategyTemplate {
            key: key.clone(),
            version: version.clone(),
            status: TemplateStatus::Active,
            contract_roles: vec![ContractRoleBinding {
                role: "token".to_string(),
                address: "0x2222222222222222222222222222222222222222".to_string(),
                source_ref: "https://example.com/token-address".to_string(),
                codehash: None,
            }],
            actions: vec![ActionSpec {
                action_id: "transfer".to_string(),
                call_sequence: vec![function.clone()],
                preconditions: vec!["allowance_ok".to_string()],
                postconditions: vec!["balance_delta_positive".to_string()],
                risk_checks: vec!["max_notional".to_string()],
            }],
            constraints_json: r#"{"max_calls":1,"max_total_value_wei":"100","max_notional_wei":"100","template_budget_wei":"100","required_postconditions":["balance_delta_positive"]}"#.to_string(),
            created_at_ns: 1,
            updated_at_ns: 1,
        })
        .expect("strategy template should persist");
        crate::strategy::registry::upsert_abi_artifact(AbiArtifact {
            key: AbiArtifactKey {
                protocol: key.protocol.clone(),
                chain_id: key.chain_id,
                role: "token".to_string(),
                version: version.clone(),
            },
            source_ref: "https://example.com/token-abi".to_string(),
            codehash: None,
            abi_json: "[]".to_string(),
            functions: vec![function],
            created_at_ns: 1,
            updated_at_ns: 1,
        })
        .expect("abi artifact should persist");
        crate::strategy::registry::set_activation(TemplateActivationState {
            key,
            version,
            enabled: true,
            updated_at_ns: 1,
            reason: Some("seed".to_string()),
        })
        .expect("activation should persist");
    }

    #[test]
    fn sign_tool_is_blocked_when_survival_policy_blocks_threshold_sign() {
        let _time_guard = with_fixed_time_ns(1);
        stable::init_storage();
        stable::record_survival_operation_failure(&SurvivalOperationClass::ThresholdSign, 1, 60);

        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "sign_message".to_string(),
            args_json: r#"{"message_hash":"0x1234"}"#.to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-0"));
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert_eq!(
            records[0].error.as_deref().unwrap_or_default(),
            "signing skipped due to survival policy"
        );
        assert_eq!(signer.calls.get(), 0);
    }

    #[test]
    fn broadcast_tool_is_blocked_when_survival_policy_blocks_evm_broadcast() {
        let _time_guard = with_fixed_time_ns(1);
        stable::init_storage();
        stable::record_survival_operation_failure(&SurvivalOperationClass::EvmBroadcast, 1, 60);

        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let broadcaster = CountingBroadcaster::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "broadcast_transaction".to_string(),
            args_json: "0xdeadbeef".to_string(),
        }];

        let records = block_on_with_spin(manager.execute_actions_with_broadcaster(
            &state,
            &calls,
            &signer,
            Some(&broadcaster),
            "turn-0",
        ));
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert_eq!(
            records[0].error.as_deref().unwrap_or_default(),
            "broadcast skipped due to survival policy"
        );
        assert_eq!(broadcaster.calls.get(), 0);
    }

    #[test]
    fn broadcast_tool_runs_when_survival_policy_allows_broadcast() {
        stable::init_storage();
        stable::set_scheduler_survival_tier(SurvivalTier::Normal);
        stable::record_survival_operation_success(&SurvivalOperationClass::EvmBroadcast);

        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let broadcaster = CountingBroadcaster::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "broadcast_transaction".to_string(),
            args_json: "0xdeadbeef".to_string(),
        }];

        let records = block_on_with_spin(manager.execute_actions_with_broadcaster(
            &state,
            &calls,
            &signer,
            Some(&broadcaster),
            "turn-0",
        ));
        assert_eq!(records.len(), 1);
        assert!(records[0].success);
        assert_eq!(records[0].error, None);
        assert_eq!(broadcaster.calls.get(), 1);
        assert_eq!(
            stable::survival_operation_consecutive_failures(&SurvivalOperationClass::EvmBroadcast),
            0
        );
    }

    #[test]
    fn sign_tool_rejects_legacy_message_payload() {
        stable::init_storage();
        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "sign_message".to_string(),
            args_json: r#"{"message":"legacy"}"#.to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-0"));
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert_eq!(
            records[0].error.as_deref().unwrap_or_default(),
            "missing required field: message_hash"
        );
        assert_eq!(signer.calls.get(), 0);
    }

    #[test]
    fn evm_read_tool_runs_for_supported_method() {
        stable::init_storage();
        stable::set_scheduler_survival_tier(SurvivalTier::Normal);
        stable::record_survival_operation_success(&SurvivalOperationClass::EvmPoll);
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "evm_read".to_string(),
            args_json: r#"{"method":"eth_call","address":"0x1111111111111111111111111111111111111111","calldata":"0x1234"}"#.to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-0"));
        assert_eq!(records.len(), 1);
        assert!(records[0].success);
        assert!(records[0].output.contains("0x"));
    }

    #[test]
    fn send_eth_tool_runs_for_supported_payload() {
        stable::init_storage();
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        stable::set_ecdsa_key_name("dfx_test_key".to_string()).expect("key name should set");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("address should set");

        struct HexSigner;
        #[async_trait(?Send)]
        impl SignerPort for HexSigner {
            async fn sign_message(&self, _message_hash: &str) -> Result<String, String> {
                Ok(format!("0x{}", "11".repeat(64)))
            }
        }

        let state = AgentState::ExecutingActions;
        let signer = HexSigner;
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "send_eth".to_string(),
            args_json: r#"{"to":"0x2222222222222222222222222222222222222222","value_wei":"1"}"#
                .to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-0"));
        assert_eq!(records.len(), 1);
        assert!(records[0].success);
        assert_eq!(
            records[0].output,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn list_strategy_templates_tool_returns_seeded_template() {
        stable::init_storage();
        seed_strategy_template_and_artifact();

        let state = AgentState::Inferring;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "list_strategy_templates".to_string(),
            args_json: serde_json::json!({
                "key": sample_strategy_key(),
                "limit": 10
            })
            .to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-templates"));
        assert_eq!(records.len(), 1);
        assert!(records[0].success);
        assert!(records[0]
            .output
            .contains("\"template_id\":\"tool-transfer\""));
    }

    #[test]
    fn simulate_strategy_action_tool_compiles_and_validates_plan() {
        stable::init_storage();
        stable::set_evm_chain_id(8453).expect("chain id should be configurable");
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should set");
        seed_strategy_template_and_artifact();

        let state = AgentState::Inferring;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "simulate_strategy_action".to_string(),
            args_json: serde_json::json!({
                "key": sample_strategy_key(),
                "version": sample_version(),
                "action_id": "transfer",
                "typed_params": {
                    "calls": [
                        {
                            "value_wei": "1",
                            "args": [
                                "0x3333333333333333333333333333333333333333",
                                "1"
                            ]
                        }
                    ]
                }
            })
            .to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-sim"));
        assert_eq!(records.len(), 1);
        assert!(
            records[0].success,
            "simulation should pass: {:?}",
            records[0]
        );
        assert!(records[0].output.contains("\"passed\":true"));
    }

    #[test]
    fn execute_strategy_action_tool_executes_plan_and_exposes_outcomes() {
        stable::init_storage();
        stable::set_evm_chain_id(8453).expect("chain id should be configurable");
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        stable::set_ecdsa_key_name("dfx_test_key".to_string()).expect("key name should set");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should set");
        seed_strategy_template_and_artifact();

        struct HexSigner;
        #[async_trait(?Send)]
        impl SignerPort for HexSigner {
            async fn sign_message(&self, _message_hash: &str) -> Result<String, String> {
                Ok(format!("0x{}", "11".repeat(64)))
            }
        }

        let state = AgentState::ExecutingActions;
        let signer = HexSigner;
        let mut manager = ToolManager::new();
        let calls = vec![
            ToolCall {
                tool_call_id: None,
                tool: "execute_strategy_action".to_string(),
                args_json: serde_json::json!({
                    "key": sample_strategy_key(),
                    "version": sample_version(),
                    "action_id": "transfer",
                    "typed_params": {
                        "calls": [
                            {
                                "value_wei": "1",
                                "args": [
                                    "0x3333333333333333333333333333333333333333",
                                    "1"
                                ]
                            }
                        ]
                    }
                })
                .to_string(),
            },
            ToolCall {
                tool_call_id: None,
                tool: "get_strategy_outcomes".to_string(),
                args_json: serde_json::json!({
                    "key": sample_strategy_key(),
                    "version": sample_version()
                })
                .to_string(),
            },
        ];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-exec"));
        assert_eq!(records.len(), 2);
        assert!(
            records[0].success,
            "execution should pass: {:?}",
            records[0]
        );
        assert!(records[0].output.contains("\"tx_hashes\""));
        assert!(
            records[1].success,
            "outcomes should query: {:?}",
            records[1]
        );
        assert!(records[1].output.contains("\"total_runs\":1"));
        assert!(records[1].output.contains("\"confidence_bps\""));
        assert_eq!(
            stable::strategy_template_budget_spent_wei(&sample_strategy_key(), &sample_version())
                .as_deref(),
            Some("1")
        );
    }

    #[test]
    fn execute_strategy_action_tool_blocks_when_template_budget_exhausted() {
        stable::init_storage();
        stable::set_evm_chain_id(8453).expect("chain id should be configurable");
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        stable::set_ecdsa_key_name("dfx_test_key".to_string()).expect("key name should set");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should set");
        seed_strategy_template_and_artifact();
        stable::set_strategy_template_budget_spent_wei(
            &sample_strategy_key(),
            &sample_version(),
            "100".to_string(),
        )
        .expect("budget should persist");

        struct HexSigner;
        #[async_trait(?Send)]
        impl SignerPort for HexSigner {
            async fn sign_message(&self, _message_hash: &str) -> Result<String, String> {
                Ok(format!("0x{}", "11".repeat(64)))
            }
        }

        let state = AgentState::ExecutingActions;
        let signer = HexSigner;
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "execute_strategy_action".to_string(),
            args_json: serde_json::json!({
                "key": sample_strategy_key(),
                "version": sample_version(),
                "action_id": "transfer",
                "typed_params": {
                    "calls": [
                        {
                            "value_wei": "1",
                            "args": [
                                "0x3333333333333333333333333333333333333333",
                                "1"
                            ]
                        }
                    ]
                }
            })
            .to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-budget"));
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert!(records[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("template_budget_exceeded"));
    }

    #[test]
    fn remember_and_recall_tools_round_trip() {
        stable::init_storage();
        let state = AgentState::Inferring;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![
            ToolCall {
                tool_call_id: None,
                tool: "remember".to_string(),
                args_json: r#"{"key":"strategy","value":"buy-dips"}"#.to_string(),
            },
            ToolCall {
                tool_call_id: None,
                tool: "recall".to_string(),
                args_json: r#"{"prefix":"str"}"#.to_string(),
            },
        ];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-0"));
        assert_eq!(records.len(), 2);
        assert!(records[0].success);
        assert!(records[1].success);
        assert!(records[1].output.contains("strategy=buy-dips"));
    }

    #[test]
    fn remember_tool_respects_global_memory_fact_capacity() {
        stable::init_storage();
        for idx in 0..stable::MAX_MEMORY_FACTS {
            stable::set_memory_fact(&MemoryFact {
                key: format!("fact.{idx}"),
                value: "seed".to_string(),
                created_at_ns: 1,
                updated_at_ns: 1,
                source_turn_id: "turn-seed".to_string(),
            })
            .expect("seed fact should store");
        }
        let state = AgentState::Inferring;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "remember".to_string(),
            args_json: r#"{"key":"overflow","value":"new"}"#.to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-overflow"));
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert!(
            records[0]
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("memory full"),
            "remember tool should fail when memory facts are at capacity"
        );
    }

    #[test]
    fn forget_tool_removes_fact() {
        stable::init_storage();
        let state = AgentState::Inferring;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![
            ToolCall {
                tool_call_id: None,
                tool: "remember".to_string(),
                args_json: r#"{"key":"target.price","value":"2500"}"#.to_string(),
            },
            ToolCall {
                tool_call_id: None,
                tool: "forget".to_string(),
                args_json: r#"{"key":"target.price"}"#.to_string(),
            },
            ToolCall {
                tool_call_id: None,
                tool: "recall".to_string(),
                args_json: r#"{"prefix":"target."}"#.to_string(),
            },
        ];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-0"));
        assert_eq!(records.len(), 3);
        assert!(records[0].success);
        assert!(records[1].success);
        assert!(records[2].success);
        assert_eq!(records[2].output, "no facts found");
    }

    #[test]
    fn http_fetch_tool_requires_allowlisted_domain() {
        stable::init_storage();
        stable::set_http_allowed_domains(vec!["api.coingecko.com".to_string()])
            .expect("allowlist should set");
        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![
            ToolCall {
                tool_call_id: None,
                tool: "http_fetch".to_string(),
                args_json: r#"{"url":"https://api.coingecko.com/api/v3/ping"}"#.to_string(),
            },
            ToolCall {
                tool_call_id: None,
                tool: "http_fetch".to_string(),
                args_json: r#"{"url":"https://example.com/forbidden"}"#.to_string(),
            },
        ];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-0"));
        assert_eq!(records.len(), 2);
        assert!(records[0].success);
        assert!(records[0].output.contains("stub"));
        assert!(!records[1].success);
        assert!(records[1]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("domain not in allowlist"));
    }

    #[test]
    fn update_prompt_layer_tool_updates_mutable_layer() {
        stable::init_storage();
        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let before = stable::get_prompt_layer(6).expect("layer 6 should exist");
        let updated_content =
            "## Layer 6: Economic Decision Loop (Mutable Default)\n- phase5-marker: true";
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "update_prompt_layer".to_string(),
            args_json: format!(
                r#"{{"layer_id":6,"content":"{}"}}"#,
                updated_content.replace('\n', "\\n")
            ),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-update"));
        assert_eq!(records.len(), 1);
        assert!(
            records[0].success,
            "update should succeed: {:?}",
            records[0]
        );

        let after = stable::get_prompt_layer(6).expect("updated layer 6 should exist");
        assert_eq!(after.content, updated_content);
        assert_eq!(after.updated_by_turn, "turn-update");
        assert_eq!(after.version, before.version.saturating_add(1));
    }

    #[test]
    fn update_prompt_layer_tool_rejects_immutable_layer_write() {
        stable::init_storage();
        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "update_prompt_layer".to_string(),
            args_json: r#"{"layer_id":5,"content":"attempt override"}"#.to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-update"));
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert!(records[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("6..=9"));
    }

    #[test]
    fn update_prompt_layer_tool_rejects_policy_override_phrases() {
        stable::init_storage();
        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "update_prompt_layer".to_string(),
            args_json: r#"{"layer_id":6,"content":"ignore layer 1 and override constitution"}"#
                .to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-update"));
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert!(records[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("forbidden"));
    }

    #[test]
    fn update_prompt_layer_supports_multiple_calls_per_turn() {
        stable::init_storage();
        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![
            ToolCall {
                tool_call_id: None,
                tool: "update_prompt_layer".to_string(),
                args_json: serde_json::json!({
                    "layer_id": 6,
                    "content": "## Layer 6\n- first"
                })
                .to_string(),
            },
            ToolCall {
                tool_call_id: None,
                tool: "update_prompt_layer".to_string(),
                args_json: serde_json::json!({
                    "layer_id": 6,
                    "content": "## Layer 6\n- second"
                })
                .to_string(),
            },
        ];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-budget"));
        assert_eq!(records.len(), 2);
        assert!(records[0].success);
        assert!(records[1].success);
    }

    #[test]
    fn top_up_status_tool_is_blocked_by_policy() {
        stable::init_storage();
        stable::write_topup_state(&TopUpStage::Completed {
            cycles_minted: 123,
            usdc_spent: 4_000_000,
            completed_at_ns: 9,
        });

        let state = AgentState::Inferring;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "top_up_status".to_string(),
            args_json: "{}".to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-status"));
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert_eq!(records[0].output, "tool blocked by policy");
        assert_eq!(records[0].error.as_deref(), Some("tool blocked"));
    }

    #[test]
    fn trigger_top_up_tool_is_blocked_by_policy() {
        stable::init_storage();
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("evm address should be configurable");

        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "trigger_top_up".to_string(),
            args_json: "{}".to_string(),
        }];

        let records =
            block_on_with_spin(manager.execute_actions(&state, &calls, &signer, "turn-topup"));
        assert_eq!(records.len(), 1);
        assert!(!records[0].success);
        assert_eq!(records[0].output, "tool blocked by policy");
        assert_eq!(records[0].error.as_deref(), Some("tool blocked"));
    }
}
