use crate::domain::cycle_admission::{
    affordability_requirements, can_afford, estimate_operation_cost, AffordabilityRequirements,
    OperationClass, DEFAULT_RESERVE_FLOOR_CYCLES, DEFAULT_SAFETY_MARGIN_BPS,
};
use crate::domain::types::{
    InferenceInput, InferenceProvider, RuntimeSnapshot, SurvivalOperationClass, ToolCall,
};
use crate::storage::stable;
use async_trait::async_trait;
use candid::{CandidType, Nat, Principal};
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};
use ic_cdk::management_canister::{
    http_request, HttpHeader, HttpMethod, HttpRequestArgs, HttpRequestResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

const IC_LLM_CANISTER_ID: &str = "w36hm-eqaaa-aaaal-qr76a-cai";

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

#[derive(Clone, Copy, Serialize, Deserialize, LogPriorityLevels)]
enum InferenceLogPriority {
    #[log_level(capacity = 2000, name = "INFERENCE_INFO")]
    Info,
    #[log_level(capacity = 2000, name = "INFERENCE_ERROR")]
    Error,
}

impl GetLogFilter for InferenceLogPriority {
    fn get_log_filter() -> LogFilter {
        LogFilter::ShowAll
    }
}

#[derive(Debug)]
pub struct InferenceOutput {
    pub tool_calls: Vec<ToolCall>,
    #[allow(dead_code)]
    pub explanation: String,
}

#[async_trait(?Send)]
pub trait InferenceAdapter {
    async fn infer(&self, input: &InferenceInput) -> Result<InferenceOutput, String>;
}

pub async fn infer_with_provider(
    snapshot: &RuntimeSnapshot,
    input: &InferenceInput,
) -> Result<InferenceOutput, String> {
    let now_ns = current_time_ns();
    if !stable::can_run_survival_operation(&SurvivalOperationClass::Inference, now_ns) {
        return Ok(InferenceOutput {
            tool_calls: Vec::new(),
            explanation: "inference skipped due to survival policy".to_string(),
        });
    }

    let output = match snapshot.inference_provider {
        InferenceProvider::Mock => MockInferenceAdapter.infer(input).await,
        InferenceProvider::IcLlm => {
            IcLlmInferenceAdapter::from_snapshot(snapshot)
                .infer(input)
                .await
        }
        InferenceProvider::OpenRouter => {
            OpenRouterInferenceAdapter::from_snapshot(snapshot)
                .infer(input)
                .await
        }
    };

    if output.is_ok() {
        stable::record_survival_operation_success(&SurvivalOperationClass::Inference);
    }
    output
}

pub struct MockInferenceAdapter;

#[async_trait(?Send)]
impl InferenceAdapter for MockInferenceAdapter {
    async fn infer(&self, input: &InferenceInput) -> Result<InferenceOutput, String> {
        let tool_calls = if input.context_snippet.contains("sign") {
            vec![ToolCall {
                tool: "sign_message".to_string(),
                args_json: r#"{"message_hash":"0x1111111111111111111111111111111111111111111111111111111111111111"}"#.to_string(),
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

#[async_trait(?Send)]
impl InferenceAdapter for StubInferenceAdapter {
    async fn infer(&self, _input: &InferenceInput) -> Result<InferenceOutput, String> {
        Err("stub inference adapter disabled in v1".to_string())
    }
}

pub struct IcLlmInferenceAdapter {
    model: String,
}

impl IcLlmInferenceAdapter {
    pub fn from_snapshot(snapshot: &RuntimeSnapshot) -> Self {
        Self {
            model: snapshot.inference_model.clone(),
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
struct IcLlmRequest {
    model: String,
    messages: Vec<IcLlmChatMessage>,
    tools: Option<Vec<IcLlmTool>>,
}

#[async_trait(?Send)]
impl InferenceAdapter for IcLlmInferenceAdapter {
    async fn infer(&self, input: &InferenceInput) -> Result<InferenceOutput, String> {
        let model = parse_ic_llm_model(&self.model)?;
        let request = IcLlmRequest {
            model: model.to_string(),
            messages: vec![
                IcLlmChatMessage::System {
                    content: "You are an automaton that can only invoke known tools.".to_string(),
                },
                IcLlmChatMessage::User {
                    content: format!("{}\n{}", input.input, input.context_snippet),
                },
            ],
            tools: Some(ic_llm_tools()),
        };

        log!(
            InferenceLogPriority::Info,
            "turn={} provider=ic_llm model={} dispatching",
            input.turn_id,
            model
        );

        let llm_canister = Principal::from_text(IC_LLM_CANISTER_ID)
            .map_err(|error| format!("invalid ic_llm canister principal: {error}"))?;
        let call_result = ic_cdk::call::Call::unbounded_wait(llm_canister, "v1_chat")
            .with_arg(&request)
            .await
            .map_err(|error| format!("ic_llm call failed: {error}"))?;
        let (response,): (IcLlmResponse,) = call_result
            .candid()
            .map_err(|error| format!("ic_llm response decode failed: {error}"))?;

        parse_ic_llm_response(response).map_err(|error| {
            log!(
                InferenceLogPriority::Error,
                "turn={} provider=ic_llm parse_failed={}",
                input.turn_id,
                error
            );
            error
        })
    }
}

fn ic_llm_tools() -> Vec<IcLlmTool> {
    vec![
        IcLlmTool::Function(IcLlmFunction {
            name: "sign_message".to_string(),
            description: Some(
                "Sign a 32-byte message hash with the configured signer.".to_string(),
            ),
            parameters: Some(IcLlmParameters {
                type_: "object".to_string(),
                properties: Some(vec![IcLlmProperty {
                    type_: "string".to_string(),
                    name: "message_hash".to_string(),
                    description: Some("0x-prefixed 32-byte hash to sign".to_string()),
                }]),
                required: Some(vec!["message_hash".to_string()]),
            }),
        }),
        IcLlmTool::Function(IcLlmFunction {
            name: "record_signal".to_string(),
            description: Some("Record a signal in the automaton log.".to_string()),
            parameters: Some(IcLlmParameters {
                type_: "object".to_string(),
                properties: Some(vec![IcLlmProperty {
                    type_: "string".to_string(),
                    name: "signal".to_string(),
                    description: Some("Signal value to record".to_string()),
                }]),
                required: Some(vec!["signal".to_string()]),
            }),
        }),
        IcLlmTool::Function(IcLlmFunction {
            name: "evm_read".to_string(),
            description: Some(
                "Read on-chain state on EVM. Supported methods: eth_getBalance and eth_call."
                    .to_string(),
            ),
            parameters: Some(IcLlmParameters {
                type_: "object".to_string(),
                properties: Some(vec![
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "method".to_string(),
                        description: Some("Either eth_getBalance or eth_call.".to_string()),
                    },
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "address".to_string(),
                        description: Some("0x-prefixed 20-byte address target.".to_string()),
                    },
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "calldata".to_string(),
                        description: Some(
                            "For eth_call only: 0x-prefixed ABI-encoded calldata.".to_string(),
                        ),
                    },
                ]),
                required: Some(vec!["method".to_string(), "address".to_string()]),
            }),
        }),
    ]
}

fn parse_ic_llm_response(response: IcLlmResponse) -> Result<InferenceOutput, String> {
    let mut tool_calls = Vec::new();
    for tool_call in response.message.tool_calls {
        let mut args = Map::new();
        for argument in tool_call.function.arguments {
            args.insert(argument.name, Value::String(argument.value));
        }
        let args_json = serde_json::to_string(&args)
            .map_err(|error| format!("failed to serialize ic_llm tool args: {error}"))?;
        tool_calls.push(ToolCall {
            tool: tool_call.function.name,
            args_json,
        });
    }

    Ok(InferenceOutput {
        tool_calls,
        explanation: response.message.content.unwrap_or_default(),
    })
}

fn parse_ic_llm_model(model: &str) -> Result<IcLlmModel, String> {
    match model.trim().to_lowercase().as_str() {
        "llama3.1:8b" | "llama3_1_8b" => Ok(IcLlmModel::Llama3_1_8B),
        "qwen3:32b" | "qwen3_32b" => Ok(IcLlmModel::Qwen3_32B),
        "llama4-scout" | "llama4scout" => Ok(IcLlmModel::Llama4Scout),
        unsupported => Err(format!("unsupported ic_llm model: {unsupported}")),
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
enum IcLlmChatMessage {
    #[serde(rename = "user")]
    User { content: String },
    #[serde(rename = "system")]
    System { content: String },
    #[serde(rename = "assistant")]
    Assistant(IcLlmAssistantMessage),
    #[serde(rename = "tool")]
    Tool {
        content: String,
        tool_call_id: String,
    },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct IcLlmAssistantMessage {
    content: Option<String>,
    tool_calls: Vec<IcLlmToolCall>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct IcLlmResponse {
    message: IcLlmAssistantMessage,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct IcLlmToolCall {
    id: String,
    function: IcLlmFunctionCall,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct IcLlmFunctionCall {
    name: String,
    arguments: Vec<IcLlmToolCallArgument>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct IcLlmToolCallArgument {
    name: String,
    value: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum IcLlmTool {
    #[serde(rename = "function")]
    Function(IcLlmFunction),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct IcLlmFunction {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<IcLlmParameters>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct IcLlmParameters {
    #[serde(rename = "type")]
    type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Vec<IcLlmProperty>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required: Option<Vec<String>>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct IcLlmProperty {
    #[serde(rename = "type")]
    type_: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum IcLlmModel {
    Llama3_1_8B,
    Qwen3_32B,
    Llama4Scout,
}

impl std::fmt::Display for IcLlmModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            IcLlmModel::Llama3_1_8B => "llama3.1:8b",
            IcLlmModel::Qwen3_32B => "qwen3:32b",
            IcLlmModel::Llama4Scout => "llama4-scout",
        };
        write!(f, "{value}")
    }
}

pub struct OpenRouterInferenceAdapter {
    model: String,
    base_url: String,
    api_key: Option<String>,
    max_response_bytes: u64,
}

impl OpenRouterInferenceAdapter {
    fn affordability_requirements(
        request_size_bytes: u64,
        max_response_bytes: u64,
    ) -> Result<AffordabilityRequirements, String> {
        let operation = OperationClass::HttpOutcall {
            request_size_bytes,
            max_response_bytes,
        };
        let estimated = estimate_operation_cost(&operation)?;
        Ok(affordability_requirements(
            estimated,
            DEFAULT_SAFETY_MARGIN_BPS,
            0,
        ))
    }

    fn estimate_request_size_bytes(payload: &[u8]) -> u64 {
        u64::try_from(payload.len()).unwrap_or(u64::MAX)
    }

    pub fn from_snapshot(snapshot: &RuntimeSnapshot) -> Self {
        Self {
            model: snapshot.inference_model.clone(),
            base_url: snapshot.openrouter_base_url.clone(),
            api_key: snapshot.openrouter_api_key.clone(),
            max_response_bytes: snapshot.openrouter_max_response_bytes,
        }
    }

    fn validate_config(&self) -> Result<(), String> {
        if self.model.trim().is_empty() {
            return Err("openrouter model cannot be empty".to_string());
        }
        if self.base_url.trim().is_empty() {
            return Err("openrouter base url cannot be empty".to_string());
        }
        if self.max_response_bytes == 0 {
            return Err("openrouter max_response_bytes must be > 0".to_string());
        }
        let api_key = self
            .api_key
            .as_deref()
            .ok_or_else(|| "openrouter api key is not configured".to_string())?;
        if api_key.trim().is_empty() {
            return Err("openrouter api key is empty".to_string());
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl InferenceAdapter for OpenRouterInferenceAdapter {
    async fn infer(&self, input: &InferenceInput) -> Result<InferenceOutput, String> {
        let now_ns = current_time_ns();
        if !stable::can_run_survival_operation(&SurvivalOperationClass::Inference, now_ns) {
            return Ok(InferenceOutput {
                tool_calls: Vec::new(),
                explanation: "inference skipped due to survival policy".to_string(),
            });
        }

        self.validate_config()?;

        let api_key = self.api_key.clone().unwrap_or_default();
        let payload = serde_json::to_vec(&build_openrouter_request_body(input, &self.model))
            .map_err(|error| format!("failed to build openrouter request payload: {error}"))?;
        let request_size_bytes = Self::estimate_request_size_bytes(&payload);
        let requirements =
            Self::affordability_requirements(request_size_bytes, self.max_response_bytes)?;
        let total_cycles = ic_cdk::api::canister_cycle_balance();
        let liquid_cycles = ic_cdk::api::canister_liquid_cycle_balance();

        log!(
            InferenceLogPriority::Info,
            "turn={} provider=openrouter request_affordability_check estimated_cost={} safety_margin_bps={} safety_margin={} required_cycles={} liquid_cycles={} total_cycles={} reserve_floor_cycles={}",
            input.turn_id,
            requirements.estimated_cycles,
            requirements.safety_margin_bps,
            requirements.safety_margin,
            requirements.required_cycles,
            liquid_cycles,
            total_cycles,
            DEFAULT_RESERVE_FLOOR_CYCLES,
        );

        if !can_afford(liquid_cycles, &requirements) {
            stable::record_survival_operation_failure(
                &SurvivalOperationClass::Inference,
                now_ns,
                stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_INFERENCE,
            );
            log!(
                InferenceLogPriority::Error,
                "turn={} provider=openrouter inference_deferred insufficient_liquid_cycles estimated_cost={} liquid_cycles={} total_cycles={} reserve_floor_cycles={} required_cycles={}",
                input.turn_id,
                requirements.estimated_cycles,
                liquid_cycles,
                total_cycles,
                DEFAULT_RESERVE_FLOOR_CYCLES,
                requirements.required_cycles
            );
            return Ok(InferenceOutput {
                tool_calls: Vec::new(),
                explanation: "inference skipped due to low cycles".to_string(),
            });
        }

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let request = HttpRequestArgs {
            url,
            max_response_bytes: Some(self.max_response_bytes),
            method: HttpMethod::POST,
            headers: vec![
                HttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                HttpHeader {
                    name: "authorization".to_string(),
                    value: format!("Bearer {api_key}"),
                },
            ],
            body: Some(payload),
            transform: None,
            is_replicated: Some(false),
        };

        log!(
            InferenceLogPriority::Info,
            "turn={} provider=openrouter model={} outcall_non_replicated=true",
            input.turn_id,
            self.model
        );

        let response = match http_request(&request).await {
            Ok(response) => response,
            Err(error) => {
                let message = format!("openrouter http outcall failed: {error}");
                if is_insufficient_cycles_error(&message) {
                    stable::record_survival_operation_failure(
                        &SurvivalOperationClass::Inference,
                        now_ns,
                        stable::SURVIVAL_OPERATION_MAX_BACKOFF_SECS_INFERENCE,
                    );
                    log!(
                        InferenceLogPriority::Error,
                        "turn={} provider=openrouter inference_deferred insufficient_cycles_error_after_preflight message={} estimated_cost={} liquid_cycles={} total_cycles={}",
                        input.turn_id,
                        message,
                        requirements.estimated_cycles,
                        liquid_cycles,
                        total_cycles
                    );
                    return Ok(InferenceOutput {
                        tool_calls: Vec::new(),
                        explanation: "inference skipped due to low cycles".to_string(),
                    });
                }
                return Err(message);
            }
        };
        parse_openrouter_http_response(response)
    }
}

fn is_insufficient_cycles_error(error: &str) -> bool {
    let normalized = error.to_lowercase();
    let indicates_insufficient_cycles =
        normalized.contains("insufficient cycles") || normalized.contains("not enough cycles");
    let indicates_depleted =
        normalized.contains("out of cycles") || normalized.contains("cycles depleted");
    indicates_insufficient_cycles || indicates_depleted
}

fn parse_openrouter_http_response(response: HttpRequestResult) -> Result<InferenceOutput, String> {
    let status = nat_to_status_code(&response.status)?;
    let body = String::from_utf8(response.body)
        .map_err(|error| format!("openrouter response was not valid utf-8: {error}"))?;

    if !(200..300).contains(&status) {
        return Err(format!("openrouter returned status {status}: {body}"));
    }

    parse_openrouter_completion(&body)
}

fn build_openrouter_request_body(input: &InferenceInput, model: &str) -> Value {
    json!({
        "model": model,
        "messages": [
            { "role": "system", "content": "You are an automaton that can only invoke known tools." },
            { "role": "user", "content": format!("{}\n{}", input.input, input.context_snippet) }
        ],
        "tool_choice": "auto",
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "sign_message",
                    "description": "Sign a 32-byte message hash with the configured signer.",
                    "parameters": {
                        "type": "object",
                        "properties": { "message_hash": { "type": "string" } },
                        "required": ["message_hash"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "record_signal",
                    "description": "Record a signal in the automaton log.",
                    "parameters": {
                        "type": "object",
                        "properties": { "signal": { "type": "string" } },
                        "required": ["signal"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "evm_read",
                    "description": "Read on-chain state on EVM. Supports eth_getBalance and eth_call.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "method": { "type": "string", "enum": ["eth_getBalance", "eth_call"] },
                            "address": { "type": "string" },
                            "calldata": { "type": "string" }
                        },
                        "required": ["method", "address"]
                    }
                }
            }
        ]
    })
}

#[derive(Deserialize)]
struct OpenRouterResponse {
    choices: Vec<OpenRouterChoice>,
}

#[derive(Deserialize)]
struct OpenRouterChoice {
    message: OpenRouterMessage,
}

#[derive(Deserialize)]
struct OpenRouterMessage {
    #[allow(dead_code)]
    role: Option<String>,
    content: Option<String>,
    tool_calls: Option<Vec<OpenRouterToolCall>>,
}

#[derive(Deserialize)]
struct OpenRouterToolCall {
    #[allow(dead_code)]
    id: Option<String>,
    #[allow(dead_code)]
    r#type: Option<String>,
    function: OpenRouterFunction,
}

#[derive(Deserialize)]
struct OpenRouterFunction {
    name: String,
    arguments: String,
}

fn parse_openrouter_completion(raw: &str) -> Result<InferenceOutput, String> {
    let response: OpenRouterResponse = serde_json::from_str(raw)
        .map_err(|error| format!("failed to parse openrouter response json: {error}"))?;

    let first_choice = response
        .choices
        .first()
        .ok_or_else(|| "openrouter response contained no choices".to_string())?;

    let mut tool_calls = Vec::new();
    if let Some(calls) = first_choice.message.tool_calls.as_ref() {
        for tool_call in calls {
            let parsed_arguments: Value = serde_json::from_str(&tool_call.function.arguments)
                .map_err(|error| format!("openrouter tool arguments were invalid json: {error}"))?;
            if !parsed_arguments.is_object() {
                return Err("openrouter tool arguments must be a JSON object".to_string());
            }

            tool_calls.push(ToolCall {
                tool: tool_call.function.name.clone(),
                args_json: parsed_arguments.to_string(),
            });
        }
    }

    Ok(InferenceOutput {
        tool_calls,
        explanation: first_choice.message.content.clone().unwrap_or_default(),
    })
}

fn nat_to_status_code(status: &Nat) -> Result<u16, String> {
    status
        .to_string()
        .parse::<u16>()
        .map_err(|error| format!("invalid http status value {status}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ic_llm_models() {
        assert!(matches!(
            parse_ic_llm_model("llama3.1:8b"),
            Ok(IcLlmModel::Llama3_1_8B)
        ));
        assert!(matches!(
            parse_ic_llm_model("qwen3:32b"),
            Ok(IcLlmModel::Qwen3_32B)
        ));
        assert!(matches!(
            parse_ic_llm_model("llama4-scout"),
            Ok(IcLlmModel::Llama4Scout)
        ));
        assert!(parse_ic_llm_model("gpt-4.1").is_err());
    }

    #[test]
    fn parse_ic_llm_response_maps_tool_calls() {
        let response: IcLlmResponse = serde_json::from_value(json!({
            "message": {
                "content": "ok",
                "tool_calls": [
                    {
                        "id": "call-1",
                        "function": {
                            "name": "record_signal",
                            "arguments": [
                                { "name": "signal", "value": "tick" }
                            ]
                        }
                    }
                ]
            }
        }))
        .expect("response fixture should deserialize");

        let out = parse_ic_llm_response(response).expect("response should parse");
        assert_eq!(out.tool_calls.len(), 1);
        assert_eq!(out.tool_calls[0].tool, "record_signal");
        assert_eq!(out.tool_calls[0].args_json, r#"{"signal":"tick"}"#);
    }

    #[test]
    fn parse_openrouter_completion_maps_tool_calls() {
        let payload = r#"{
            "choices": [
                {
                    "message": {
                        "content": "calling tool",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "sign_message",
                                    "arguments": "{\"message_hash\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}"
                                }
                            }
                        ]
                    }
                }
            ]
        }"#;

        let out = parse_openrouter_completion(payload).expect("response should parse");
        assert_eq!(out.tool_calls.len(), 1);
        assert_eq!(out.tool_calls[0].tool, "sign_message");
        assert_eq!(
            out.tool_calls[0].args_json,
            r#"{"message_hash":"0x1111111111111111111111111111111111111111111111111111111111111111"}"#
        );
    }

    #[test]
    fn parse_openrouter_completion_rejects_non_object_arguments() {
        let payload = r#"{
            "choices": [
                {
                    "message": {
                        "content": null,
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "sign_message",
                                    "arguments": "\"just-string\""
                                }
                            }
                        ]
                    }
                }
            ]
        }"#;

        let error = parse_openrouter_completion(payload).expect_err("must reject invalid args");
        assert!(error.contains("must be a JSON object"));
    }

    #[test]
    fn openrouter_config_validation_rejects_missing_api_key() {
        let adapter = OpenRouterInferenceAdapter {
            model: "openai/gpt-4o-mini".to_string(),
            base_url: "https://openrouter.ai/api/v1".to_string(),
            api_key: None,
            max_response_bytes: 1_024,
        };

        let error = adapter
            .validate_config()
            .expect_err("should fail without key");
        assert!(error.contains("api key"));
    }

    #[test]
    fn openrouter_affordability_blocks_low_liquid_cycles() {
        let requirements = OpenRouterInferenceAdapter::affordability_requirements(1_024, 16_000)
            .expect("affordability estimate should compute");
        let total_cycles = 5 + requirements.required_cycles;
        let liquid_cycles = total_cycles.saturating_sub(DEFAULT_RESERVE_FLOOR_CYCLES);
        assert!(
            liquid_cycles < requirements.required_cycles,
            "fixture should exercise insufficient condition"
        );
    }

    #[test]
    fn openrouter_affordability_allows_high_liquid_cycles() {
        let requirements = OpenRouterInferenceAdapter::affordability_requirements(1_024, 16_000)
            .expect("affordability estimate should compute");
        let total_cycles = requirements.required_cycles + DEFAULT_RESERVE_FLOOR_CYCLES + 1_000;
        let liquid_cycles = total_cycles.saturating_sub(DEFAULT_RESERVE_FLOOR_CYCLES);
        assert!(liquid_cycles >= requirements.required_cycles);
    }

    #[test]
    fn insufficient_cycles_error_is_classified() {
        assert!(is_insufficient_cycles_error(
            "openrouter failed: insufficient cycles for this request"
        ));
        assert!(is_insufficient_cycles_error(
            "canister reported cycles depleted while sending outbound HTTP request"
        ));
        assert!(!is_insufficient_cycles_error(
            "openrouter returned status 500"
        ));
    }

    #[test]
    fn request_size_is_truncated_to_u64() {
        let size = OpenRouterInferenceAdapter::estimate_request_size_bytes(&[]);
        assert_eq!(size, 0);
    }

    #[test]
    fn ic_llm_tools_include_evm_read() {
        let names = ic_llm_tools()
            .into_iter()
            .map(|tool| match tool {
                IcLlmTool::Function(function) => function.name,
            })
            .collect::<Vec<_>>();
        assert!(names.contains(&"evm_read".to_string()));
    }

    #[test]
    fn openrouter_request_body_includes_evm_read_tool() {
        let body = build_openrouter_request_body(
            &InferenceInput {
                input: "hello".to_string(),
                context_snippet: "ctx".to_string(),
                turn_id: "turn-1".to_string(),
            },
            "openai/gpt-4o-mini",
        );

        let tools = body
            .get("tools")
            .and_then(|value| value.as_array())
            .expect("tools array must exist");
        let names = tools
            .iter()
            .filter_map(|entry| entry.get("function"))
            .filter_map(|function| function.get("name"))
            .filter_map(|name| name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"evm_read"));
    }
}
