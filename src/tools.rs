use crate::domain::types::{AgentState, ToolCall, ToolCallRecord};
use crate::features::SignerAdapter;
use std::collections::HashMap;

pub trait SignerPort {
    fn sign_message(&self, message: &str) -> Result<String, String>;
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

    pub fn execute_actions(
        &mut self,
        state: &AgentState,
        calls: &[ToolCall],
        signer: &dyn SignerAdapter,
        turn_id: &str,
    ) -> Vec<ToolCallRecord> {
        calls
            .iter()
            .map(|call| {
                let policy = match self.policies.get(&call.tool) {
                    Some(policy) => policy,
                    None => {
                        return ToolCallRecord {
                            turn_id: turn_id.to_string(),
                            tool: call.tool.clone(),
                            args_json: call.args_json.clone(),
                            output: "unknown tool".to_string(),
                            success: false,
                            error: Some("unknown tool".to_string()),
                        };
                    }
                };

                if !policy.enabled || !policy.allowed_states.contains(state) {
                    return ToolCallRecord {
                        turn_id: turn_id.to_string(),
                        tool: call.tool.clone(),
                        args_json: call.args_json.clone(),
                        output: "tool blocked by policy".to_string(),
                        success: false,
                        error: Some("tool blocked".to_string()),
                    };
                }

                let used = self.executed_per_tool.get(&call.tool).copied().unwrap_or(0);
                if used >= policy.max_calls_per_turn {
                    return ToolCallRecord {
                        turn_id: turn_id.to_string(),
                        tool: call.tool.clone(),
                        args_json: call.args_json.clone(),
                        output: "tool budget exceeded".to_string(),
                        success: false,
                        error: Some("tool budget exceeded".to_string()),
                    };
                }

                let result = match call.tool.as_str() {
                    "sign_message" => signer.sign_message(&call.args_json),
                    "record_signal" => Ok("recorded".to_string()),
                    _ => Err("unknown tool".to_string()),
                };

                self.executed_per_tool
                    .insert(call.tool.clone(), used.saturating_add(1));

                match result {
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
                }
            })
            .collect()
    }
}
