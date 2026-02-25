/// LLM inference abstraction supporting IC LLM and OpenRouter backends.
///
/// Provides a unified `InferenceAdapter` trait with two concrete implementations:
/// - `IcLlmInferenceAdapter` — calls the on-chain IC LLM canister via Candid inter-canister call.
/// - `OpenRouterInferenceAdapter` — calls the OpenRouter REST API via an IC HTTPS outcall.
///
/// Both adapters support multi-round continuation via `infer_with_transcript`, which appends
/// prior assistant/tool messages before sending the next inference request.
///
/// # Survival policy
///
/// `infer_with_provider` and `infer_with_provider_transcript` check the survival policy before
/// dispatching.  On low-cycles conditions the call returns an empty `InferenceOutput` rather
/// than an error, allowing the agent turn to degrade gracefully.
// ── Imports ──────────────────────────────────────────────────────────────────
use crate::domain::cycle_admission::{
    affordability_requirements, can_afford, estimate_operation_cost, AffordabilityRequirements,
    OperationClass, DEFAULT_RESERVE_FLOOR_CYCLES, DEFAULT_SAFETY_MARGIN_BPS,
};
use crate::domain::types::{
    InferenceInput, InferenceProvider, OperationFailure, OperationFailureKind, OutcallFailure,
    OutcallFailureKind, RecoveryFailure, RuntimeSnapshot, SurvivalOperationClass, ToolCall,
};
use crate::prompt;
use crate::storage::stable;
use crate::timing::current_time_ns;
use async_trait::async_trait;
use candid::{CandidType, Nat, Principal};
use canlog::{log, GetLogFilter, LogFilter, LogPriorityLevels};
use ic_cdk::management_canister::{
    http_request, HttpHeader, HttpMethod, HttpRequestArgs, HttpRequestResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

// ── Internal constants ───────────────────────────────────────────────────────

// Sentinel model name that bypasses the real LLM canister and runs
// deterministic rule-based inference.  Only permitted when the ECDSA key
// name is "dfx_test_key" (local dfx network) or in cfg(test) builds.
const DETERMINISTIC_IC_LLM_MODEL: &str = "deterministic-local";
const DETERMINISTIC_LAYER_6_MARKER: &str = "phase5-layer6-marker";
const DETERMINISTIC_LAYER_6_UPDATE_CONTENT: &str =
    "## Layer 6: Economic Decision Loop (Mutable Default)\n- phase5-layer6-marker";
const INFERENCE_OUTCALL_TIMEOUT_MS: u64 = 45_000;
const INFERENCE_OUTCALL_TIMEOUT_NS: u64 = INFERENCE_OUTCALL_TIMEOUT_MS * 1_000_000;

fn outcall_elapsed_ms(started_at_ns: u64, finished_at_ns: u64) -> u64 {
    finished_at_ns.saturating_sub(started_at_ns) / 1_000_000
}

fn outcall_timeout_message(service: &str, timeout_ms: u64, elapsed_ms: u64) -> String {
    format!(
        "{service} outcall timeout envelope exceeded: elapsed={} ms timeout={} ms",
        elapsed_ms, timeout_ms
    )
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

// ── Public types ─────────────────────────────────────────────────────────────

/// The result of a single LLM inference call.
///
/// `tool_calls` contains zero or more structured tool invocations parsed from
/// the model response.  `explanation` holds the model's free-text content
/// (may be empty when only tool calls are returned).
#[derive(Debug)]
pub struct InferenceOutput {
    pub tool_calls: Vec<ToolCall>,
    #[allow(dead_code)]
    pub explanation: String,
}

/// A single entry in the multi-round conversation transcript.
///
/// Transcripts are built incrementally during a turn: each time the model
/// returns tool calls they are appended as `Assistant`, the tool results are
/// appended as `Tool`, and the whole slice is passed back on the next
/// `infer_with_transcript` call.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum InferenceTranscriptMessage {
    /// Model response — may carry text content and/or tool call requests.
    Assistant {
        content: Option<String>,
        tool_calls: Vec<ToolCall>,
    },
    /// Tool execution result matched to a prior assistant tool call by ID.
    Tool {
        tool_call_id: String,
        content: String,
    },
}

// ── Adapter trait ────────────────────────────────────────────────────────────

/// Abstraction over an LLM backend.
///
/// Implement this trait to add a new inference provider.  The default
/// `infer_with_transcript` implementation discards the transcript and
/// delegates to `infer`; concrete adapters override it to forward the
/// full conversation history.
#[async_trait(?Send)]
pub trait InferenceAdapter {
    /// Single-shot inference — no prior conversation context.
    async fn infer(&self, input: &InferenceInput) -> Result<InferenceOutput, String>;

    /// Continuation inference — appends `transcript` after the user message
    /// so the model sees prior tool calls and their results.
    async fn infer_with_transcript(
        &self,
        input: &InferenceInput,
        transcript: &[InferenceTranscriptMessage],
    ) -> Result<InferenceOutput, String> {
        let _ = transcript;
        self.infer(input).await
    }
}

// ── Public entry points ──────────────────────────────────────────────────────

/// Single-shot inference using the provider configured in `snapshot`.
///
/// Convenience wrapper around `infer_with_provider_transcript` with an empty
/// transcript.  Returns an empty `InferenceOutput` (no tool calls) when the
/// survival policy blocks inference rather than propagating an error.
pub async fn infer_with_provider(
    snapshot: &RuntimeSnapshot,
    input: &InferenceInput,
) -> Result<InferenceOutput, String> {
    infer_with_provider_transcript(snapshot, input, &[]).await
}

/// Continuation inference — forwards `transcript` to the configured provider.
///
/// Checks the survival policy first; defers (returns empty output) when the
/// canister has insufficient liquid cycles.  On success, records a survival
/// operation success so backoff is reset.
pub async fn infer_with_provider_transcript(
    snapshot: &RuntimeSnapshot,
    input: &InferenceInput,
    transcript: &[InferenceTranscriptMessage],
) -> Result<InferenceOutput, String> {
    let now_ns = current_time_ns();
    if !stable::can_run_survival_operation(&SurvivalOperationClass::Inference, now_ns) {
        return Ok(InferenceOutput {
            tool_calls: Vec::new(),
            explanation: "inference skipped due to survival policy".to_string(),
        });
    }

    let output = match snapshot.inference_provider {
        InferenceProvider::IcLlm => {
            IcLlmInferenceAdapter::from_snapshot(snapshot)
                .infer_with_transcript(input, transcript)
                .await
        }
        InferenceProvider::OpenRouter => {
            OpenRouterInferenceAdapter::from_snapshot(snapshot)
                .infer_with_transcript(input, transcript)
                .await
        }
    };

    if output.is_ok() {
        stable::record_survival_operation_success(&SurvivalOperationClass::Inference);
    }
    output
}

fn run_deterministic_inference(
    input: &InferenceInput,
    transcript: &[InferenceTranscriptMessage],
) -> Result<InferenceOutput, String> {
    let explicit_sign_request = input.input.contains("request_sign_message:true")
        || input.context_snippet.contains("request_sign_message:true");
    let update_prompt_layer_request = input.input.contains("request_update_prompt_layer:true");
    let layer_6_probe_request = input.input.contains("request_layer_6_probe:true");
    let continuation_loop_request = input.input.contains("request_continuation_loop:true")
        || input
            .context_snippet
            .contains("request_continuation_loop:true");
    let continuation_error_request = input.input.contains("request_continuation_error:true")
        || input
            .context_snippet
            .contains("request_continuation_error:true");

    let has_tool_transcript = transcript
        .iter()
        .any(|entry| matches!(entry, InferenceTranscriptMessage::Tool { .. }));

    if continuation_error_request && has_tool_transcript {
        return Err("deterministic continuation inference failed after tool execution".to_string());
    }

    if has_tool_transcript && !continuation_loop_request {
        return Ok(InferenceOutput {
            tool_calls: Vec::new(),
            explanation: format!("deterministic continuation for {}", input.turn_id),
        });
    }

    let tool_calls = if explicit_sign_request {
        vec![ToolCall {
            tool_call_id: None,
            tool: "sign_message".to_string(),
            args_json: r#"{"message_hash":"0x1111111111111111111111111111111111111111111111111111111111111111"}"#.to_string(),
        }]
    } else if update_prompt_layer_request {
        vec![ToolCall {
            tool_call_id: None,
            tool: "update_prompt_layer".to_string(),
            args_json: json!({
                "layer_id": 6,
                "content": DETERMINISTIC_LAYER_6_UPDATE_CONTENT
            })
            .to_string(),
        }]
    } else {
        vec![ToolCall {
            tool_call_id: None,
            tool: "record_signal".to_string(),
            args_json: r#"{"signal":"tick"}"#.to_string(),
        }]
    };

    let explanation = if layer_6_probe_request {
        let assembled = prompt::assemble_system_prompt(&input.context_snippet);
        if assembled.contains(DETERMINISTIC_LAYER_6_MARKER) {
            "layer6_probe:present".to_string()
        } else {
            "layer6_probe:missing".to_string()
        }
    } else {
        format!("deterministic inference for {}", input.turn_id)
    };

    Ok(InferenceOutput {
        tool_calls,
        explanation,
    })
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
    llm_canister_id: String,
    evm_tools_enabled: bool,
    allow_deterministic_model: bool,
}

impl IcLlmInferenceAdapter {
    pub fn from_snapshot(snapshot: &RuntimeSnapshot) -> Self {
        let allow_deterministic_model = {
            #[cfg(test)]
            {
                true
            }
            #[cfg(not(test))]
            {
                snapshot.ecdsa_key_name.trim() == "dfx_test_key"
            }
        };
        Self {
            model: snapshot.inference_model.clone(),
            llm_canister_id: snapshot.llm_canister_id.clone(),
            evm_tools_enabled: !snapshot.evm_rpc_url.trim().is_empty(),
            allow_deterministic_model,
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
        self.infer_with_transcript(input, &[]).await
    }

    async fn infer_with_transcript(
        &self,
        input: &InferenceInput,
        transcript: &[InferenceTranscriptMessage],
    ) -> Result<InferenceOutput, String> {
        if self.allow_deterministic_model
            && self
                .model
                .trim()
                .eq_ignore_ascii_case(DETERMINISTIC_IC_LLM_MODEL)
        {
            return run_deterministic_inference(input, transcript);
        }

        let model = parse_ic_llm_model(&self.model)?;
        let request =
            build_ic_llm_request_with_transcript(input, model, transcript, self.evm_tools_enabled);

        log!(
            InferenceLogPriority::Info,
            "turn={} provider=ic_llm model={} dispatching",
            input.turn_id,
            model
        );

        let llm_canister = Principal::from_text(self.llm_canister_id.trim())
            .map_err(|error| format!("invalid ic_llm canister principal: {error}"))?;
        let outcall_started_at_ns = current_time_ns();
        let call_result = match ic_cdk::call::Call::unbounded_wait(llm_canister, "v1_chat")
            .with_arg(&request)
            .await
        {
            Ok(call_result) => call_result,
            Err(error) => {
                let outcall_finished_at_ns = current_time_ns();
                let elapsed_ms = outcall_elapsed_ms(outcall_started_at_ns, outcall_finished_at_ns);
                let timed_out = outcall_finished_at_ns.saturating_sub(outcall_started_at_ns)
                    > INFERENCE_OUTCALL_TIMEOUT_NS;
                let message = if timed_out {
                    outcall_timeout_message("ic_llm call", INFERENCE_OUTCALL_TIMEOUT_MS, elapsed_ms)
                } else {
                    format!("ic_llm call failed: {error}")
                };
                stable::record_outcall_timing(
                    stable::RuntimeOutcallKind::Inference,
                    outcall_started_at_ns,
                    outcall_finished_at_ns,
                    Some(message.as_str()),
                    timed_out,
                );
                return Err(message);
            }
        };

        let outcall_finished_at_ns = current_time_ns();
        let elapsed_ms = outcall_elapsed_ms(outcall_started_at_ns, outcall_finished_at_ns);
        if outcall_finished_at_ns.saturating_sub(outcall_started_at_ns)
            > INFERENCE_OUTCALL_TIMEOUT_NS
        {
            let message =
                outcall_timeout_message("ic_llm call", INFERENCE_OUTCALL_TIMEOUT_MS, elapsed_ms);
            stable::record_outcall_timing(
                stable::RuntimeOutcallKind::Inference,
                outcall_started_at_ns,
                outcall_finished_at_ns,
                Some(message.as_str()),
                true,
            );
            return Err(message);
        }

        let (response,): (IcLlmResponse,) = match call_result.candid() {
            Ok(decoded) => decoded,
            Err(error) => {
                let message = format!("ic_llm response decode failed: {error}");
                stable::record_outcall_timing(
                    stable::RuntimeOutcallKind::Inference,
                    outcall_started_at_ns,
                    outcall_finished_at_ns,
                    Some(message.as_str()),
                    false,
                );
                return Err(message);
            }
        };

        let parsed = parse_ic_llm_response(response).map_err(|error| {
            log!(
                InferenceLogPriority::Error,
                "turn={} provider=ic_llm parse_failed={}",
                input.turn_id,
                error
            );
            error
        });
        match parsed {
            Ok(output) => {
                stable::record_outcall_timing(
                    stable::RuntimeOutcallKind::Inference,
                    outcall_started_at_ns,
                    outcall_finished_at_ns,
                    None,
                    false,
                );
                Ok(output)
            }
            Err(error) => {
                stable::record_outcall_timing(
                    stable::RuntimeOutcallKind::Inference,
                    outcall_started_at_ns,
                    outcall_finished_at_ns,
                    Some(error.as_str()),
                    false,
                );
                Err(error)
            }
        }
    }
}

#[allow(dead_code)]
fn build_ic_llm_request(input: &InferenceInput, model: IcLlmModel) -> IcLlmRequest {
    build_ic_llm_request_with_transcript(input, model, &[], true)
}

fn build_ic_llm_request_with_transcript(
    input: &InferenceInput,
    model: IcLlmModel,
    transcript: &[InferenceTranscriptMessage],
    evm_tools_enabled: bool,
) -> IcLlmRequest {
    let mut messages = vec![
        IcLlmChatMessage::System {
            content: prompt::assemble_system_prompt_compact(&input.context_snippet),
        },
        IcLlmChatMessage::User {
            content: input.input.clone(),
        },
    ];
    messages.extend(build_ic_llm_transcript_messages(transcript));

    IcLlmRequest {
        model: model.to_string(),
        messages,
        tools: Some(ic_llm_tools_with_capabilities(evm_tools_enabled)),
    }
}

fn build_ic_llm_transcript_messages(
    transcript: &[InferenceTranscriptMessage],
) -> Vec<IcLlmChatMessage> {
    let mut messages = Vec::new();
    for (transcript_index, entry) in transcript.iter().enumerate() {
        match entry {
            InferenceTranscriptMessage::Assistant {
                content,
                tool_calls,
            } => {
                let mapped_tool_calls = tool_calls
                    .iter()
                    .enumerate()
                    .map(|(tool_index, call)| IcLlmToolCall {
                        id: inferred_tool_call_id(call, transcript_index, tool_index),
                        function: IcLlmFunctionCall {
                            name: call.tool.clone(),
                            arguments: parse_ic_llm_tool_call_arguments(&call.args_json),
                        },
                    })
                    .collect::<Vec<_>>();
                messages.push(IcLlmChatMessage::Assistant(IcLlmAssistantMessage {
                    content: content.clone(),
                    tool_calls: mapped_tool_calls,
                }));
            }
            InferenceTranscriptMessage::Tool {
                tool_call_id,
                content,
            } => messages.push(IcLlmChatMessage::Tool {
                content: content.clone(),
                tool_call_id: tool_call_id.clone(),
            }),
        }
    }
    messages
}

fn parse_ic_llm_tool_call_arguments(args_json: &str) -> Vec<IcLlmToolCallArgument> {
    let value = match serde_json::from_str::<Value>(args_json) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let Value::Object(args) = value else {
        return Vec::new();
    };

    args.into_iter()
        .map(|(name, value)| IcLlmToolCallArgument {
            name,
            value: match value {
                Value::String(raw) => raw,
                other => other.to_string(),
            },
        })
        .collect()
}

fn inferred_tool_call_id(call: &ToolCall, transcript_index: usize, tool_index: usize) -> String {
    call.tool_call_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("generated-call-{transcript_index}-{tool_index}"))
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
                "Read EVM contract state via eth_call. Use Layer-10 wallet telemetry for ETH/USDC balances."
                    .to_string(),
            ),
            parameters: Some(IcLlmParameters {
                type_: "object".to_string(),
                properties: Some(vec![
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "method".to_string(),
                        description: Some("Must be eth_call.".to_string()),
                    },
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "address".to_string(),
                        description: Some("0x-prefixed 20-byte contract address target.".to_string()),
                    },
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "calldata".to_string(),
                        description: Some("0x-prefixed ABI-encoded calldata.".to_string()),
                    },
                ]),
                required: Some(vec![
                    "method".to_string(),
                    "address".to_string(),
                    "calldata".to_string(),
                ]),
            }),
        }),
        IcLlmTool::Function(IcLlmFunction {
            name: "send_eth".to_string(),
            description: Some(
                "Send ETH on Base. The runtime handles nonce, gas, signing, and broadcast."
                    .to_string(),
            ),
            parameters: Some(IcLlmParameters {
                type_: "object".to_string(),
                properties: Some(vec![
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "to".to_string(),
                        description: Some("0x-prefixed destination address.".to_string()),
                    },
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "value_wei".to_string(),
                        description: Some("Amount in wei as decimal string.".to_string()),
                    },
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "data".to_string(),
                        description: Some(
                            "Optional calldata for contract interaction.".to_string(),
                        ),
                    },
                ]),
                required: Some(vec!["to".to_string(), "value_wei".to_string()]),
            }),
        }),
        IcLlmTool::Function(IcLlmFunction {
            name: "remember".to_string(),
            description: Some(
                "Store a persistent memory fact by key; overwrites existing value for that key."
                    .to_string(),
            ),
            parameters: Some(IcLlmParameters {
                type_: "object".to_string(),
                properties: Some(vec![
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "key".to_string(),
                        description: Some("Memory key identifier.".to_string()),
                    },
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "value".to_string(),
                        description: Some("Memory value payload.".to_string()),
                    },
                ]),
                required: Some(vec!["key".to_string(), "value".to_string()]),
            }),
        }),
        IcLlmTool::Function(IcLlmFunction {
            name: "recall".to_string(),
            description: Some(
                "Retrieve memory facts. Optionally filter by key prefix.".to_string(),
            ),
            parameters: Some(IcLlmParameters {
                type_: "object".to_string(),
                properties: Some(vec![IcLlmProperty {
                    type_: "string".to_string(),
                    name: "prefix".to_string(),
                    description: Some("Optional key prefix filter.".to_string()),
                }]),
                required: None,
            }),
        }),
        IcLlmTool::Function(IcLlmFunction {
            name: "forget".to_string(),
            description: Some("Delete a memory fact by key.".to_string()),
            parameters: Some(IcLlmParameters {
                type_: "object".to_string(),
                properties: Some(vec![IcLlmProperty {
                    type_: "string".to_string(),
                    name: "key".to_string(),
                    description: Some("Memory key identifier.".to_string()),
                }]),
                required: Some(vec!["key".to_string()]),
            }),
        }),
        IcLlmTool::Function(IcLlmFunction {
            name: "http_fetch".to_string(),
            description: Some(
                "Fetch text from an allowlisted HTTPS URL via GET. Use optional `extract` to return only structured fields or regex-matching lines."
                    .to_string(),
            ),
            parameters: Some(IcLlmParameters {
                type_: "object".to_string(),
                properties: Some(vec![
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "url".to_string(),
                        description: Some("HTTPS URL on an allowed domain.".to_string()),
                    },
                    IcLlmProperty {
                        type_: "object".to_string(),
                        name: "extract".to_string(),
                        description: Some(
                            "Optional extraction config. JSON mode: {\"mode\":\"json_path\",\"path\":\"data.price\"}. Regex mode: {\"mode\":\"regex\",\"pattern\":\"^price:\\\\d+$\"}. Prefer extraction to minimize untrusted content."
                                .to_string(),
                        ),
                    },
                ]),
                required: Some(vec!["url".to_string()]),
            }),
        }),
        IcLlmTool::Function(IcLlmFunction {
            name: "update_prompt_layer".to_string(),
            description: Some(
                "Update a mutable prompt layer (6-9). Immutable layers cannot be modified."
                    .to_string(),
            ),
            parameters: Some(IcLlmParameters {
                type_: "object".to_string(),
                properties: Some(vec![
                    IcLlmProperty {
                        type_: "integer".to_string(),
                        name: "layer_id".to_string(),
                        description: Some("Mutable layer id, must be between 6 and 9.".to_string()),
                    },
                    IcLlmProperty {
                        type_: "string".to_string(),
                        name: "content".to_string(),
                        description: Some("Replacement markdown content.".to_string()),
                    },
                ]),
                required: Some(vec!["layer_id".to_string(), "content".to_string()]),
            }),
        }),
    ]
}

fn ic_llm_tool_name(tool: &IcLlmTool) -> &str {
    match tool {
        IcLlmTool::Function(function) => function.name.as_str(),
    }
}

fn ic_llm_tools_with_capabilities(evm_tools_enabled: bool) -> Vec<IcLlmTool> {
    let mut tools = ic_llm_tools();
    if !evm_tools_enabled {
        tools.retain(|tool| !matches!(ic_llm_tool_name(tool), "evm_read" | "send_eth"));
    }
    tools
}

fn openrouter_tools() -> Vec<Value> {
    ic_llm_tools()
        .into_iter()
        .map(ic_llm_tool_to_openrouter)
        .collect()
}

fn ic_llm_tool_to_openrouter(tool: IcLlmTool) -> Value {
    let IcLlmTool::Function(function) = tool;

    let mut function_json = Map::new();
    function_json.insert("name".to_string(), Value::String(function.name));
    if let Some(description) = function.description {
        function_json.insert("description".to_string(), Value::String(description));
    }
    if let Some(parameters) = function.parameters {
        function_json.insert(
            "parameters".to_string(),
            ic_llm_parameters_to_openrouter(parameters),
        );
    }

    let mut tool_json = Map::new();
    tool_json.insert("type".to_string(), Value::String("function".to_string()));
    tool_json.insert("function".to_string(), Value::Object(function_json));
    Value::Object(tool_json)
}

fn ic_llm_parameters_to_openrouter(parameters: IcLlmParameters) -> Value {
    let mut openrouter_parameters = Map::new();
    openrouter_parameters.insert("type".to_string(), Value::String(parameters.type_));

    let mut openrouter_properties = Map::new();
    for property in parameters.properties.unwrap_or_default() {
        let mut openrouter_property = Map::new();
        openrouter_property.insert("type".to_string(), Value::String(property.type_));
        if let Some(description) = property.description {
            openrouter_property.insert("description".to_string(), Value::String(description));
        }
        openrouter_properties.insert(property.name, Value::Object(openrouter_property));
    }
    openrouter_parameters.insert(
        "properties".to_string(),
        Value::Object(openrouter_properties),
    );

    if let Some(required) = parameters.required {
        openrouter_parameters.insert(
            "required".to_string(),
            Value::Array(required.into_iter().map(Value::String).collect()),
        );
    }

    Value::Object(openrouter_parameters)
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
            tool_call_id: Some(tool_call.id).filter(|id| !id.trim().is_empty()),
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
    evm_tools_enabled: bool,
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
            evm_tools_enabled: !snapshot.evm_rpc_url.trim().is_empty(),
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
        self.infer_with_transcript(input, &[]).await
    }

    async fn infer_with_transcript(
        &self,
        input: &InferenceInput,
        transcript: &[InferenceTranscriptMessage],
    ) -> Result<InferenceOutput, String> {
        self.validate_config()?;

        let now_ns = current_time_ns();
        let api_key = self.api_key.clone().unwrap_or_default();
        let payload =
            serde_json::to_vec(&build_openrouter_request_body_with_transcript_capabilities(
                input,
                &self.model,
                transcript,
                self.evm_tools_enabled,
            ))
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

        let outcall_started_at_ns = current_time_ns();
        let response = match http_request(&request).await {
            Ok(response) => response,
            Err(error) => {
                let outcall_finished_at_ns = current_time_ns();
                let elapsed_ms = outcall_elapsed_ms(outcall_started_at_ns, outcall_finished_at_ns);
                let timed_out = outcall_finished_at_ns.saturating_sub(outcall_started_at_ns)
                    > INFERENCE_OUTCALL_TIMEOUT_NS;
                let message = if timed_out {
                    outcall_timeout_message(
                        "openrouter http",
                        INFERENCE_OUTCALL_TIMEOUT_MS,
                        elapsed_ms,
                    )
                } else {
                    format!("openrouter http outcall failed: {error}")
                };
                stable::record_outcall_timing(
                    stable::RuntimeOutcallKind::Inference,
                    outcall_started_at_ns,
                    outcall_finished_at_ns,
                    Some(message.as_str()),
                    timed_out,
                );
                if timed_out {
                    log!(
                        InferenceLogPriority::Error,
                        "turn={} provider=openrouter outcall_timeout elapsed_ms={} timeout_ms={}",
                        input.turn_id,
                        elapsed_ms,
                        INFERENCE_OUTCALL_TIMEOUT_MS
                    );
                    return Err(message);
                }
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

        let outcall_finished_at_ns = current_time_ns();
        let elapsed_ms = outcall_elapsed_ms(outcall_started_at_ns, outcall_finished_at_ns);
        if outcall_finished_at_ns.saturating_sub(outcall_started_at_ns)
            > INFERENCE_OUTCALL_TIMEOUT_NS
        {
            let message = outcall_timeout_message(
                "openrouter http",
                INFERENCE_OUTCALL_TIMEOUT_MS,
                elapsed_ms,
            );
            stable::record_outcall_timing(
                stable::RuntimeOutcallKind::Inference,
                outcall_started_at_ns,
                outcall_finished_at_ns,
                Some(message.as_str()),
                true,
            );
            log!(
                InferenceLogPriority::Error,
                "turn={} provider=openrouter outcall_timeout elapsed_ms={} timeout_ms={}",
                input.turn_id,
                elapsed_ms,
                INFERENCE_OUTCALL_TIMEOUT_MS
            );
            return Err(message);
        }

        let parsed = parse_openrouter_http_response(response);
        match parsed {
            Ok(output) => {
                stable::record_outcall_timing(
                    stable::RuntimeOutcallKind::Inference,
                    outcall_started_at_ns,
                    outcall_finished_at_ns,
                    None,
                    false,
                );
                Ok(output)
            }
            Err(error) => {
                stable::record_outcall_timing(
                    stable::RuntimeOutcallKind::Inference,
                    outcall_started_at_ns,
                    outcall_finished_at_ns,
                    Some(error.as_str()),
                    false,
                );
                Err(error)
            }
        }
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

// ── Failure classification ───────────────────────────────────────────────────

/// Map a raw inference error string to a structured `RecoveryFailure`.
///
/// Used by the agent's error-handling path to decide whether to retry,
/// back off, or surface a permanent configuration error.
#[allow(dead_code)]
pub fn classify_inference_failure(error: &str) -> RecoveryFailure {
    let normalized = error.to_ascii_lowercase();
    if is_insufficient_cycles_error(&normalized) {
        return RecoveryFailure::Operation(OperationFailure {
            kind: OperationFailureKind::InsufficientCycles,
        });
    }
    if normalized.contains("is not configured") {
        return RecoveryFailure::Operation(OperationFailure {
            kind: OperationFailureKind::MissingConfiguration,
        });
    }
    if normalized.contains("cannot be empty")
        || normalized.contains("must be > 0")
        || normalized.contains("unsupported ic_llm model")
        || normalized.contains("invalid ic_llm canister principal")
    {
        return RecoveryFailure::Operation(OperationFailure {
            kind: OperationFailureKind::InvalidConfiguration,
        });
    }
    if normalized.contains("unauthorized") || normalized.contains("forbidden") {
        return RecoveryFailure::Operation(OperationFailure {
            kind: OperationFailureKind::Unauthorized,
        });
    }
    RecoveryFailure::Outcall(OutcallFailure {
        kind: classify_inference_outcall_failure_kind(&normalized),
        retry_after_secs: None,
        observed_response_bytes: None,
    })
}

#[allow(dead_code)]
fn classify_inference_outcall_failure_kind(normalized_error: &str) -> OutcallFailureKind {
    if normalized_error.contains("http body exceeds size limit")
        || normalized_error.contains("response exceeded max_response_bytes")
        || (normalized_error.contains("max_response_bytes") && normalized_error.contains("exceed"))
    {
        return OutcallFailureKind::ResponseTooLarge;
    }
    if normalized_error.contains("status 429")
        || normalized_error.contains("http 429")
        || normalized_error.contains("rate limit")
        || normalized_error.contains("too many requests")
    {
        return OutcallFailureKind::RateLimited;
    }
    if normalized_error.contains("timeout")
        || normalized_error.contains("timed out")
        || normalized_error.contains("deadline exceeded")
    {
        return OutcallFailureKind::Timeout;
    }
    if normalized_error.contains("status 503")
        || normalized_error.contains("status 502")
        || normalized_error.contains("status 504")
        || normalized_error.contains("http 503")
        || normalized_error.contains("http 502")
        || normalized_error.contains("http 504")
        || normalized_error.contains("service unavailable")
    {
        return OutcallFailureKind::UpstreamUnavailable;
    }
    if normalized_error.contains("status 401")
        || normalized_error.contains("status 403")
        || normalized_error.contains("http 401")
        || normalized_error.contains("http 403")
        || normalized_error.contains("rejected by policy")
    {
        return OutcallFailureKind::RejectedByPolicy;
    }
    if normalized_error.contains("status 400")
        || normalized_error.contains("status 404")
        || normalized_error.contains("status 422")
        || normalized_error.contains("http 400")
        || normalized_error.contains("http 404")
        || normalized_error.contains("http 422")
    {
        return OutcallFailureKind::InvalidRequest;
    }
    if normalized_error.contains("failed to parse")
        || normalized_error.contains("response decode failed")
        || normalized_error.contains("response was not valid utf-8")
        || normalized_error.contains("contained no choices")
        || normalized_error.contains("must be a json object")
    {
        return OutcallFailureKind::InvalidResponse;
    }
    if normalized_error.contains("outcall failed")
        || normalized_error.contains("transport")
        || normalized_error.contains("connection refused")
        || normalized_error.contains("connection reset")
        || normalized_error.contains("network is unreachable")
    {
        return OutcallFailureKind::Transport;
    }
    OutcallFailureKind::Unknown
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

#[allow(dead_code)]
fn build_openrouter_request_body(input: &InferenceInput, model: &str) -> Value {
    build_openrouter_request_body_with_transcript(input, model, &[])
}

fn build_openrouter_request_body_with_transcript_capabilities(
    input: &InferenceInput,
    model: &str,
    transcript: &[InferenceTranscriptMessage],
    evm_tools_enabled: bool,
) -> Value {
    let mut body = build_openrouter_request_body_with_transcript(input, model, transcript);
    if evm_tools_enabled {
        return body;
    }

    if let Some(tools) = body.get_mut("tools").and_then(Value::as_array_mut) {
        tools.retain(|tool| {
            let function_name = tool
                .get("function")
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str);
            !matches!(function_name, Some("evm_read" | "send_eth"))
        });
    }

    body
}

fn build_openrouter_request_body_with_transcript(
    input: &InferenceInput,
    model: &str,
    transcript: &[InferenceTranscriptMessage],
) -> Value {
    let system_prompt = prompt::assemble_system_prompt(&input.context_snippet);
    let mut messages = vec![
        json!({ "role": "system", "content": system_prompt }),
        json!({ "role": "user", "content": input.input }),
    ];
    messages.extend(build_openrouter_transcript_messages(transcript));

    json!({
        "model": model,
        "messages": messages,
        "tool_choice": "auto",
        "tools": openrouter_tools()
    })
}

fn build_openrouter_transcript_messages(transcript: &[InferenceTranscriptMessage]) -> Vec<Value> {
    let mut messages = Vec::new();
    for (transcript_index, entry) in transcript.iter().enumerate() {
        match entry {
            InferenceTranscriptMessage::Assistant {
                content,
                tool_calls,
            } => {
                let openrouter_tool_calls = tool_calls
                    .iter()
                    .enumerate()
                    .map(|(tool_index, call)| {
                        json!({
                            "id": inferred_tool_call_id(call, transcript_index, tool_index),
                            "type": "function",
                            "function": {
                                "name": call.tool,
                                "arguments": call.args_json,
                            }
                        })
                    })
                    .collect::<Vec<_>>();

                messages.push(json!({
                    "role": "assistant",
                    "content": content,
                    "tool_calls": openrouter_tool_calls,
                }));
            }
            InferenceTranscriptMessage::Tool {
                tool_call_id,
                content,
            } => messages.push(json!({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": content,
            })),
        }
    }
    messages
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

enum OpenRouterToolArgsError {
    JsonParse(String),
    NotObject,
}

fn parse_relaxed_json_value(raw: &str) -> Result<Value, String> {
    match serde_json::from_str::<Value>(raw) {
        Ok(value) => Ok(value),
        Err(primary_error) => match json5::from_str::<Value>(raw) {
            Ok(value) => Ok(value),
            Err(_) => Err(primary_error.to_string()),
        },
    }
}

fn parse_openrouter_tool_args_candidate(raw: &str) -> Result<Value, OpenRouterToolArgsError> {
    let parsed = parse_relaxed_json_value(raw).map_err(OpenRouterToolArgsError::JsonParse)?;
    match parsed {
        Value::Object(_) => Ok(parsed),
        Value::String(nested) => {
            let nested_trimmed = nested.trim();
            match parse_relaxed_json_value(nested_trimmed) {
                Ok(nested_parsed) if matches!(nested_parsed, Value::Object(_)) => Ok(nested_parsed),
                Ok(_) => Err(OpenRouterToolArgsError::NotObject),
                Err(_) => Err(OpenRouterToolArgsError::NotObject),
            }
        }
        _ => Err(OpenRouterToolArgsError::NotObject),
    }
}

fn strip_markdown_code_fence(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("```") {
        return None;
    }

    let mut lines = trimmed.lines();
    let opening = lines.next()?;
    if !opening.trim_start().starts_with("```") {
        return None;
    }

    let mut body = lines.collect::<Vec<_>>();
    if body.last().map(|line| line.trim()) != Some("```") {
        return None;
    }
    body.pop();
    Some(body.join("\n"))
}

fn parse_openrouter_tool_arguments(arguments: &str) -> Result<Value, String> {
    let mut candidates = vec![arguments.trim().to_string()];
    if let Some(stripped) = strip_markdown_code_fence(arguments) {
        let stripped_trimmed = stripped.trim().to_string();
        if !stripped_trimmed.is_empty() && stripped_trimmed != candidates[0] {
            candidates.push(stripped_trimmed);
        }
    }

    let mut last_json_error: Option<String> = None;
    let mut saw_non_object = false;
    for candidate in candidates {
        match parse_openrouter_tool_args_candidate(&candidate) {
            Ok(parsed) => return Ok(parsed),
            Err(OpenRouterToolArgsError::JsonParse(error)) => last_json_error = Some(error),
            Err(OpenRouterToolArgsError::NotObject) => saw_non_object = true,
        }
    }

    if saw_non_object {
        return Err("openrouter tool arguments must be a JSON object".to_string());
    }

    Err(format!(
        "openrouter tool arguments were invalid json: {}",
        last_json_error.unwrap_or_else(|| "unknown parse error".to_string())
    ))
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
            let parsed_arguments = parse_openrouter_tool_arguments(&tool_call.function.arguments)?;

            tool_calls.push(ToolCall {
                tool_call_id: tool_call.id.clone().filter(|id| !id.trim().is_empty()),
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
    use crate::domain::types::SkillRecord;
    use crate::storage::stable;
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

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
        assert_eq!(out.tool_calls[0].tool_call_id.as_deref(), Some("call-1"));
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
        assert_eq!(out.tool_calls[0].tool_call_id.as_deref(), Some("call_1"));
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
    fn parse_openrouter_completion_accepts_json5_style_arguments() {
        let payload = r#"{
            "choices": [
                {
                    "message": {
                        "content": "calling tool",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "record_signal",
                                    "arguments": "{signal: 'tick',}"
                                }
                            }
                        ]
                    }
                }
            ]
        }"#;

        let out = parse_openrouter_completion(payload).expect("json5 args should parse");
        assert_eq!(out.tool_calls.len(), 1);
        assert_eq!(out.tool_calls[0].tool, "record_signal");
        assert_eq!(out.tool_calls[0].args_json, r#"{"signal":"tick"}"#);
    }

    #[test]
    fn parse_openrouter_completion_accepts_nested_json_string_arguments() {
        let payload = r#"{
            "choices": [
                {
                    "message": {
                        "content": "calling tool",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "record_signal",
                                    "arguments": "\"{\\\"signal\\\":\\\"tick\\\"}\""
                                }
                            }
                        ]
                    }
                }
            ]
        }"#;

        let out = parse_openrouter_completion(payload).expect("nested json string should parse");
        assert_eq!(out.tool_calls.len(), 1);
        assert_eq!(out.tool_calls[0].tool, "record_signal");
        assert_eq!(out.tool_calls[0].args_json, r#"{"signal":"tick"}"#);
    }

    #[test]
    fn openrouter_config_validation_rejects_missing_api_key() {
        let adapter = OpenRouterInferenceAdapter {
            model: "openai/gpt-4o-mini".to_string(),
            base_url: "https://openrouter.ai/api/v1".to_string(),
            api_key: None,
            max_response_bytes: 1_024,
            evm_tools_enabled: true,
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
    fn classify_inference_failure_maps_missing_configuration_errors() {
        let failure = classify_inference_failure("openrouter api key is not configured");
        assert_eq!(
            failure,
            crate::domain::types::RecoveryFailure::Operation(
                crate::domain::types::OperationFailure {
                    kind: crate::domain::types::OperationFailureKind::MissingConfiguration,
                }
            )
        );
    }

    #[test]
    fn classify_inference_failure_maps_insufficient_cycles_errors() {
        let failure =
            classify_inference_failure("openrouter http outcall failed: insufficient cycles");
        assert_eq!(
            failure,
            crate::domain::types::RecoveryFailure::Operation(
                crate::domain::types::OperationFailure {
                    kind: crate::domain::types::OperationFailureKind::InsufficientCycles,
                }
            )
        );
    }

    #[test]
    fn classify_inference_failure_maps_rate_limit_errors() {
        let failure = classify_inference_failure("openrouter returned status 429: slow down");
        assert_eq!(
            failure,
            crate::domain::types::RecoveryFailure::Outcall(crate::domain::types::OutcallFailure {
                kind: crate::domain::types::OutcallFailureKind::RateLimited,
                retry_after_secs: None,
                observed_response_bytes: None,
            })
        );
    }

    #[test]
    fn classify_inference_failure_maps_timeout_envelope_errors() {
        let failure = classify_inference_failure(
            "openrouter http outcall timeout envelope exceeded: elapsed=47000 ms timeout=45000 ms",
        );
        assert_eq!(
            failure,
            crate::domain::types::RecoveryFailure::Outcall(crate::domain::types::OutcallFailure {
                kind: crate::domain::types::OutcallFailureKind::Timeout,
                retry_after_secs: None,
                observed_response_bytes: None,
            })
        );
    }

    #[test]
    fn classify_inference_failure_maps_invalid_response_errors() {
        let failure = classify_inference_failure(
            "failed to parse openrouter response json: expected value at line 1 column 1",
        );
        assert_eq!(
            failure,
            crate::domain::types::RecoveryFailure::Outcall(crate::domain::types::OutcallFailure {
                kind: crate::domain::types::OutcallFailureKind::InvalidResponse,
                retry_after_secs: None,
                observed_response_bytes: None,
            })
        );
    }

    #[test]
    fn request_size_is_truncated_to_u64() {
        let size = OpenRouterInferenceAdapter::estimate_request_size_bytes(&[]);
        assert_eq!(size, 0);
    }

    #[test]
    fn ic_llm_request_uses_compact_assembled_prompt_with_conversation_context() {
        stable::init_storage();
        stable::set_soul("compact-soul".to_string());
        stable::upsert_skill(&SkillRecord {
            name: "compact-skill".to_string(),
            description: "compact".to_string(),
            instructions: "Keep it short.".to_string(),
            enabled: true,
            mutable: true,
        });
        let input = InferenceInput {
            input: "hello".to_string(),
            context_snippet: "## Layer 10: Dynamic Context\n### Conversation with 0xabc\n  [0xabc]: hi\n  [you]: hello".to_string(),
            turn_id: "turn-compact".to_string(),
        };

        let request = build_ic_llm_request(&input, IcLlmModel::Llama3_1_8B);
        assert_eq!(request.messages.len(), 2);
        let IcLlmChatMessage::System { content } = &request.messages[0] else {
            panic!("first message must be system");
        };

        assert!(content.contains("## Layer 0: Interpretation & Precedence"));
        assert!(content.contains("## Layer 1: Constitution - Safety & Non-Harm"));
        assert!(content.contains("## Layer 5: Operational Reality"));
        assert!(content.contains("## Layer 10: Dynamic Context"));
        assert!(content.contains("### Conversation with 0xabc"));
        assert!(content.contains("compact-skill"));
        assert!(!content.contains("## Layer 2: Survival Economics"));
        assert!(!content.contains("## Layer 3: Identity & On-Chain Personhood"));
        assert!(!content.contains("## Layer 6: Economic Decision Loop"));
    }

    #[test]
    fn openrouter_request_body_uses_full_assembled_prompt_with_conversation_context() {
        stable::init_storage();
        stable::set_soul("full-soul".to_string());
        let input = InferenceInput {
            input: "hello".to_string(),
            context_snippet: "## Layer 10: Dynamic Context\n### Conversation with 0xdef\n  [0xdef]: ping\n  [you]: pong".to_string(),
            turn_id: "turn-openrouter".to_string(),
        };
        let body = build_openrouter_request_body(&input, "openai/gpt-4o-mini");

        let messages = body
            .get("messages")
            .and_then(|value| value.as_array())
            .expect("messages array must exist");
        let system_prompt = messages
            .first()
            .and_then(|value| value.get("content"))
            .and_then(|value| value.as_str())
            .expect("first message content must exist");

        assert!(system_prompt.contains("## Layer 0: Interpretation & Precedence"));
        assert!(system_prompt.contains("## Layer 1: Constitution - Safety & Non-Harm"));
        assert!(system_prompt.contains("## Layer 2: Survival Economics"));
        assert!(system_prompt.contains("## Layer 3: Identity & On-Chain Personhood"));
        assert!(system_prompt.contains("full-soul"));
        assert!(system_prompt.contains("## Layer 10: Dynamic Context"));
        assert!(system_prompt.contains("### Conversation with 0xdef"));
        assert!(system_prompt.contains("## Layer 6: Economic Decision Loop"));
    }

    #[test]
    fn ic_llm_request_appends_continuation_transcript_messages() {
        let input = InferenceInput {
            input: "inbox:ping".to_string(),
            context_snippet: "ctx".to_string(),
            turn_id: "turn-continue-ic-llm".to_string(),
        };
        let transcript = vec![
            InferenceTranscriptMessage::Assistant {
                content: Some("calling tool".to_string()),
                tool_calls: vec![ToolCall {
                    tool_call_id: Some("call-1".to_string()),
                    tool: "record_signal".to_string(),
                    args_json: r#"{"signal":"tick"}"#.to_string(),
                }],
            },
            InferenceTranscriptMessage::Tool {
                tool_call_id: "call-1".to_string(),
                content: r#"{"ok":true}"#.to_string(),
            },
        ];

        let request = build_ic_llm_request_with_transcript(
            &input,
            IcLlmModel::Llama3_1_8B,
            &transcript,
            true,
        );
        assert_eq!(request.messages.len(), 4);
        assert!(matches!(
            request.messages[0],
            IcLlmChatMessage::System { .. }
        ));
        assert!(matches!(request.messages[1], IcLlmChatMessage::User { .. }));

        let IcLlmChatMessage::Assistant(message) = &request.messages[2] else {
            panic!("third message must be assistant continuation");
        };
        assert_eq!(message.content.as_deref(), Some("calling tool"));
        assert_eq!(message.tool_calls.len(), 1);
        assert_eq!(message.tool_calls[0].id, "call-1");
        assert_eq!(message.tool_calls[0].function.name, "record_signal");
        assert_eq!(
            message.tool_calls[0].function.arguments,
            vec![IcLlmToolCallArgument {
                name: "signal".to_string(),
                value: "tick".to_string(),
            }]
        );

        let IcLlmChatMessage::Tool {
            content,
            tool_call_id,
        } = &request.messages[3]
        else {
            panic!("fourth message must be tool continuation");
        };
        assert_eq!(tool_call_id, "call-1");
        assert_eq!(content, r#"{"ok":true}"#);
    }

    #[test]
    fn openrouter_request_body_appends_continuation_transcript_messages() {
        let input = InferenceInput {
            input: "inbox:ping".to_string(),
            context_snippet: "ctx".to_string(),
            turn_id: "turn-continue-openrouter".to_string(),
        };
        let transcript = vec![
            InferenceTranscriptMessage::Assistant {
                content: Some("calling tool".to_string()),
                tool_calls: vec![ToolCall {
                    tool_call_id: Some("call-1".to_string()),
                    tool: "record_signal".to_string(),
                    args_json: r#"{"signal":"tick"}"#.to_string(),
                }],
            },
            InferenceTranscriptMessage::Tool {
                tool_call_id: "call-1".to_string(),
                content: r#"{"ok":true}"#.to_string(),
            },
        ];

        let body = build_openrouter_request_body_with_transcript(
            &input,
            "openai/gpt-4o-mini",
            &transcript,
        );
        let messages = body
            .get("messages")
            .and_then(|value| value.as_array())
            .expect("messages array must exist");
        assert_eq!(messages.len(), 4);
        assert_eq!(
            messages[2]
                .get("role")
                .and_then(|value| value.as_str())
                .expect("assistant role must exist"),
            "assistant"
        );
        assert_eq!(
            messages[2]
                .get("content")
                .and_then(|value| value.as_str())
                .expect("assistant content must exist"),
            "calling tool"
        );
        let tool_calls = messages[2]
            .get("tool_calls")
            .and_then(|value| value.as_array())
            .expect("assistant tool_calls must exist");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(
            tool_calls[0]
                .get("id")
                .and_then(|value| value.as_str())
                .expect("tool call id must exist"),
            "call-1"
        );
        assert_eq!(
            tool_calls[0]
                .get("function")
                .and_then(|value| value.get("name"))
                .and_then(|value| value.as_str())
                .expect("tool call name must exist"),
            "record_signal"
        );
        assert_eq!(
            tool_calls[0]
                .get("function")
                .and_then(|value| value.get("arguments"))
                .and_then(|value| value.as_str())
                .expect("tool call arguments must exist"),
            r#"{"signal":"tick"}"#
        );
        assert_eq!(
            messages[3]
                .get("role")
                .and_then(|value| value.as_str())
                .expect("tool role must exist"),
            "tool"
        );
        assert_eq!(
            messages[3]
                .get("tool_call_id")
                .and_then(|value| value.as_str())
                .expect("tool message tool_call_id must exist"),
            "call-1"
        );
        assert_eq!(
            messages[3]
                .get("content")
                .and_then(|value| value.as_str())
                .expect("tool message content must exist"),
            r#"{"ok":true}"#
        );
    }

    #[test]
    fn ic_llm_tools_include_agent_runtime_tools() {
        let names = ic_llm_tools()
            .into_iter()
            .map(|tool| match tool {
                IcLlmTool::Function(function) => function.name,
            })
            .collect::<Vec<_>>();
        assert!(names.contains(&"evm_read".to_string()));
        assert!(names.contains(&"send_eth".to_string()));
        assert!(names.contains(&"remember".to_string()));
        assert!(names.contains(&"recall".to_string()));
        assert!(names.contains(&"forget".to_string()));
        assert!(names.contains(&"http_fetch".to_string()));
        assert!(names.contains(&"update_prompt_layer".to_string()));
    }

    #[test]
    fn openrouter_request_body_includes_agent_runtime_tools() {
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
        assert!(names.contains(&"send_eth"));
        assert!(names.contains(&"remember"));
        assert!(names.contains(&"recall"));
        assert!(names.contains(&"forget"));
        assert!(names.contains(&"http_fetch"));
        assert!(names.contains(&"update_prompt_layer"));
    }

    #[test]
    fn openrouter_tools_stay_in_sync_with_ic_llm_tool_catalog() {
        let mut ic_names = ic_llm_tools()
            .into_iter()
            .map(|tool| match tool {
                IcLlmTool::Function(function) => function.name,
            })
            .collect::<Vec<_>>();
        ic_names.sort();

        let mut openrouter_names = openrouter_tools()
            .into_iter()
            .filter_map(|entry| entry.get("function").cloned())
            .filter_map(|function| function.get("name").cloned())
            .filter_map(|name| name.as_str().map(|value| value.to_string()))
            .collect::<Vec<_>>();
        openrouter_names.sort();

        assert_eq!(openrouter_names, ic_names);
    }

    #[test]
    fn ic_llm_http_fetch_schema_includes_extract_modes() {
        let http_fetch_tool = ic_llm_tools()
            .into_iter()
            .find(|tool| matches!(tool, IcLlmTool::Function(function) if function.name == "http_fetch"))
            .expect("http_fetch tool should exist");

        let IcLlmTool::Function(function) = http_fetch_tool;
        let params = function
            .parameters
            .expect("http_fetch tool should define parameters");
        let properties = params
            .properties
            .expect("http_fetch tool should define properties");
        let extract_property = properties
            .iter()
            .find(|property| property.name == "extract")
            .expect("http_fetch tool should include extract property");
        assert_eq!(extract_property.type_, "object");
        let description = extract_property.description.as_deref().unwrap_or_default();
        assert!(description.contains("json_path"));
        assert!(description.contains("regex"));
    }

    #[test]
    fn openrouter_http_fetch_schema_includes_extract_modes() {
        let http_fetch_tool = openrouter_tools()
            .into_iter()
            .find(|entry| {
                entry
                    .get("function")
                    .and_then(|function| function.get("name"))
                    .and_then(|name| name.as_str())
                    .is_some_and(|name| name == "http_fetch")
            })
            .expect("openrouter http_fetch tool should exist");

        let extract_property = http_fetch_tool
            .get("function")
            .and_then(|function| function.get("parameters"))
            .and_then(|parameters| parameters.get("properties"))
            .and_then(|properties| properties.get("extract"))
            .expect("openrouter http_fetch schema should include extract property");
        assert_eq!(
            extract_property
                .get("type")
                .and_then(|value| value.as_str())
                .unwrap_or_default(),
            "object"
        );
        let description = extract_property
            .get("description")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        assert!(description.contains("json_path"));
        assert!(description.contains("regex"));
    }

    #[test]
    fn ic_llm_tool_caps_exclude_evm_tools_when_rpc_is_unconfigured() {
        let names = ic_llm_tools_with_capabilities(false)
            .into_iter()
            .map(|tool| match tool {
                IcLlmTool::Function(function) => function.name,
            })
            .collect::<Vec<_>>();
        assert!(!names.contains(&"evm_read".to_string()));
        assert!(!names.contains(&"send_eth".to_string()));
        assert!(names.contains(&"remember".to_string()));
        assert!(!names.contains(&"top_up_status".to_string()));
        assert!(!names.contains(&"trigger_top_up".to_string()));
    }

    #[test]
    fn openrouter_request_body_caps_exclude_evm_tools_when_rpc_is_unconfigured() {
        let body = build_openrouter_request_body_with_transcript_capabilities(
            &InferenceInput {
                input: "hello".to_string(),
                context_snippet: "ctx".to_string(),
                turn_id: "turn-1".to_string(),
            },
            "openai/gpt-4o-mini",
            &[],
            false,
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
        assert!(!names.contains(&"evm_read"));
        assert!(!names.contains(&"send_eth"));
        assert!(names.contains(&"remember"));
        assert!(!names.contains(&"top_up_status"));
        assert!(!names.contains(&"trigger_top_up"));
    }

    #[test]
    fn deterministic_ic_llm_model_layer_6_probe_reflects_prompt_layer_updates() {
        stable::init_storage();
        let adapter = IcLlmInferenceAdapter {
            model: DETERMINISTIC_IC_LLM_MODEL.to_string(),
            llm_canister_id: "w36hm-eqaaa-aaaal-qr76a-cai".to_string(),
            evm_tools_enabled: true,
            allow_deterministic_model: true,
        };
        let no_marker = InferenceInput {
            input: "request_layer_6_probe:true".to_string(),
            context_snippet: "ctx".to_string(),
            turn_id: "turn-probe-1".to_string(),
        };

        let first = block_on_with_spin(adapter.infer(&no_marker))
            .expect("deterministic inference should succeed");
        assert_eq!(first.explanation, "layer6_probe:missing");

        stable::save_prompt_layer(&crate::domain::types::PromptLayer {
            layer_id: 6,
            content: DETERMINISTIC_LAYER_6_UPDATE_CONTENT.to_string(),
            updated_at_ns: 1,
            updated_by_turn: "test".to_string(),
            version: 99,
        })
        .expect("layer save should succeed");

        let with_marker = InferenceInput {
            input: "request_layer_6_probe:true".to_string(),
            context_snippet: "ctx".to_string(),
            turn_id: "turn-probe-2".to_string(),
        };
        let second = block_on_with_spin(adapter.infer(&with_marker))
            .expect("deterministic inference should succeed");
        assert_eq!(second.explanation, "layer6_probe:present");
    }

    #[test]
    fn ic_llm_adapter_rejects_invalid_llm_canister_id() {
        let adapter = IcLlmInferenceAdapter {
            model: "llama3.1:8b".to_string(),
            llm_canister_id: "not-a-principal".to_string(),
            evm_tools_enabled: true,
            allow_deterministic_model: false,
        };
        let input = InferenceInput {
            input: "hello".to_string(),
            context_snippet: "ctx".to_string(),
            turn_id: "turn-invalid-llm-id".to_string(),
        };

        let error = block_on_with_spin(adapter.infer(&input))
            .expect_err("invalid llm canister id should be rejected");
        assert!(error.contains("invalid ic_llm canister principal"));
    }
}
