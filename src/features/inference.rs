use crate::domain::types::{InferenceInput, ToolCall};

pub struct InferenceOutput {
    pub tool_calls: Vec<ToolCall>,
    #[allow(dead_code)]
    pub explanation: String,
}

pub trait InferenceAdapter {
    fn infer(&self, input: &InferenceInput) -> Result<InferenceOutput, String>;
}

pub struct MockInferenceAdapter;

impl InferenceAdapter for MockInferenceAdapter {
    fn infer(&self, input: &InferenceInput) -> Result<InferenceOutput, String> {
        let tool_calls = if input.context_snippet.contains("sign") {
            vec![ToolCall {
                tool: "sign_message".to_string(),
                args_json: r#"{"message":"heartbeat"}"#.to_string(),
            }]
        } else {
            vec![ToolCall {
                tool: "record_signal".to_string(),
                args_json: r#"{"signal":"tick"}"#.to_string(),
            }]
        };

        Ok(InferenceOutput {
            tool_calls,
            explanation: format!("mocked inference for {}", input.turn_id),
        })
    }
}

#[allow(dead_code)]
pub struct StubInferenceAdapter;

impl InferenceAdapter for StubInferenceAdapter {
    fn infer(&self, _input: &InferenceInput) -> Result<InferenceOutput, String> {
        Err("stub inference adapter disabled in v1".to_string())
    }
}
