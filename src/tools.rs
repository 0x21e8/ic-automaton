use crate::domain::types::{AgentState, SurvivalOperationClass, ToolCall, ToolCallRecord};
use crate::storage::stable;
use async_trait::async_trait;
use std::collections::HashMap;

fn current_time_ns() -> u64 {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::time();

    #[cfg(not(target_arch = "wasm32"))]
    return 1;
}

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
    pub max_calls_per_turn: u8,
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
            max_calls_per_turn: 10,
        }
    }
}

pub struct ToolManager {
    policies: HashMap<String, ToolPolicy>,
    executed_per_tool: HashMap<String, u8>,
}

impl ToolManager {
    pub fn new() -> Self {
        let mut policies = HashMap::new();
        policies.insert(
            "sign_message".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions],
                max_calls_per_turn: 3,
            },
        );
        policies.insert(
            "broadcast_transaction".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions],
                max_calls_per_turn: 1,
            },
        );
        policies.insert(
            "record_signal".to_string(),
            ToolPolicy {
                enabled: true,
                allowed_states: vec![AgentState::ExecutingActions, AgentState::Inferring],
                max_calls_per_turn: 5,
            },
        );

        Self {
            policies,
            executed_per_tool: HashMap::new(),
        }
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

            let used = self.executed_per_tool.get(&call.tool).copied().unwrap_or(0);
            if used >= policy.max_calls_per_turn {
                records.push(ToolCallRecord {
                    turn_id: turn_id.to_string(),
                    tool: call.tool.clone(),
                    args_json: call.args_json.clone(),
                    output: "tool budget exceeded".to_string(),
                    success: false,
                    error: Some("tool budget exceeded".to_string()),
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
                                self.executed_per_tool
                                    .insert(call.tool.clone(), used.saturating_add(1));
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
                _ => Err("unknown tool".to_string()),
            };

            self.executed_per_tool
                .insert(call.tool.clone(), used.saturating_add(1));

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

fn parse_sign_message_args(args_json: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid sign_message args json: {error}"))?;
    value
        .get("message_hash")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| "missing required field: message_hash".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{AgentState, SurvivalOperationClass, SurvivalTier};
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
}
