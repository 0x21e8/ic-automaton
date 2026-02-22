use crate::domain::types::{
    AgentState, MemoryFact, PromptLayer, SurvivalOperationClass, ToolCall, ToolCallRecord,
};
use crate::features::cycle_topup_host::{top_up_status_tool, trigger_top_up_tool};
use crate::features::evm::{evm_read_tool, send_eth_tool};
use crate::features::http_fetch::http_fetch_tool;
use crate::prompt;
use crate::storage::stable;
use async_trait::async_trait;
use std::collections::HashMap;

fn current_time_ns() -> u64 {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::time();

    #[cfg(not(target_arch = "wasm32"))]
    return 1;
}

const MAX_MEMORY_KEY_BYTES: usize = 128;
const MAX_MEMORY_VALUE_BYTES: usize = 4096;
const MAX_MEMORY_RECALL_RESULTS: usize = 50;
pub const MAX_PROMPT_LAYER_CONTENT_CHARS: usize = 4_000;
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

#[async_trait(?Send)]
pub trait SignerPort {
    async fn sign_message(&self, message_hash: &str) -> Result<String, String>;
}

#[async_trait(?Send)]
pub trait EvmBroadcastPort {
    async fn broadcast_transaction(&self, signed_transaction: &str) -> Result<String, String>;
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct MockEvmBroadcastAdapter;

#[async_trait(?Send)]
impl EvmBroadcastPort for MockEvmBroadcastAdapter {
    async fn broadcast_transaction(&self, signed_transaction: &str) -> Result<String, String> {
        Ok(format!("0x{signed_transaction}-mock-hash"))
    }
}

#[derive(Clone, Debug)]
pub struct ToolPolicy {
    pub enabled: bool,
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

pub struct ToolManager {
    policies: HashMap<String, ToolPolicy>,
}

impl ToolManager {
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
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
            },
        );
        policies.insert(
            "trigger_top_up".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions],
            },
        );

        Self { policies }
    }

    #[allow(dead_code)]
    pub fn register_tool(&mut self, name: String, policy: ToolPolicy) {
        self.policies.insert(name, policy);
    }

    pub fn list_tools(&self) -> Vec<(String, ToolPolicy)> {
        let mut rows: Vec<_> = self
            .policies
            .iter()
            .map(|(name, policy)| (name.clone(), policy.clone()))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    #[allow(dead_code)]
    pub fn policy_for(&self, tool: &str) -> Option<&ToolPolicy> {
        self.policies.get(tool)
    }

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

fn parse_sign_message_args(args_json: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid sign_message args json: {error}"))?;
    value
        .get("message_hash")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| "missing required field: message_hash".to_string())
}

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

fn parse_forget_args(args_json: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid forget args json: {error}"))?;
    let key_raw = value
        .get("key")
        .and_then(|entry| entry.as_str())
        .ok_or_else(|| "missing required field: key".to_string())?;
    normalize_memory_key(key_raw)
}

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
    use crate::domain::types::{AgentState, SurvivalOperationClass, SurvivalTier};
    use crate::features::cycle_topup::TopUpStage;
    use crate::storage::stable;
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

    #[test]
    fn sign_tool_is_blocked_when_survival_policy_blocks_threshold_sign() {
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
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be configurable");
        let state = AgentState::ExecutingActions;
        let signer = CountingSigner::new();
        let mut manager = ToolManager::new();
        let calls = vec![ToolCall {
            tool_call_id: None,
            tool: "evm_read".to_string(),
            args_json: r#"{"method":"eth_getBalance","address":"0x1111111111111111111111111111111111111111"}"#.to_string(),
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
    fn top_up_status_tool_reports_state_in_inferring() {
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
        assert!(records[0].success);
        assert!(records[0].output.contains("Completed"));
    }

    #[test]
    fn trigger_top_up_tool_starts_preflight_and_enqueues_job() {
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
        assert!(records[0].success, "{:?}", records[0]);
        assert_eq!(records[0].output, "Top-up enqueued.");
        assert!(matches!(
            stable::read_topup_state(),
            Some(TopUpStage::Preflight)
        ));
        assert!(
            stable::list_recent_jobs(10)
                .into_iter()
                .any(|job| job.kind == crate::domain::types::TaskKind::TopUpCycles),
            "trigger should enqueue a TopUpCycles job"
        );
    }
}
