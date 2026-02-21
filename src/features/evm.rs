use crate::domain::cycle_admission::{
    affordability_requirements, can_afford, estimate_operation_cost, OperationClass,
    DEFAULT_RESERVE_FLOOR_CYCLES, DEFAULT_SAFETY_MARGIN_BPS,
};
use crate::domain::types::{
    EvmEvent, EvmPollCursor, OperationFailure, OperationFailureKind, OutcallFailure,
    OutcallFailureKind, RecoveryFailure, RuntimeSnapshot,
};
use crate::storage::stable;
use crate::tools::SignerPort;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::{length_of_length, BufMut, Encodable, Header};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};
#[cfg(not(target_arch = "wasm32"))]
use std::io::Read;
use std::str::FromStr;

#[cfg(target_arch = "wasm32")]
use candid::Nat;
#[cfg(target_arch = "wasm32")]
use ic_cdk::management_canister::{http_request, HttpHeader, HttpMethod, HttpRequestArgs};
#[cfg(target_arch = "wasm32")]
use sha3::{Digest, Keccak256};

const MAX_EVM_RPC_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BLOCK_RANGE_PER_POLL: u64 = 1_000;
const DEFAULT_MAX_LOGS_PER_POLL: usize = 200;
const EMPTY_ACCESS_LIST_RLP_LEN: usize = 1;
const CONTROL_PLANE_MAX_RESPONSE_BYTES: u64 = 4 * 1024;
const INBOX_MESSAGE_QUEUED_EVENT_SIGNATURE: &str =
    "MessageQueued(address,uint64,address,string,uint256,uint256)";
const INBOX_USDC_FUNCTION_SIGNATURE: &str = "usdc()";
const ERC20_BALANCE_OF_FUNCTION_SIGNATURE: &str = "balanceOf(address)";
#[cfg(not(target_arch = "wasm32"))]
const HOST_EVM_RPC_MODE_ENV: &str = "IC_AUTOMATON_EVM_RPC_HOST_MODE";

pub struct EvmPollResult {
    pub cursor: EvmPollCursor,
    pub events: Vec<EvmEvent>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct EvmBroadcastResult {
    pub tx_hash: String,
}

#[allow(dead_code)]
pub trait EvmBroadcaster {
    fn broadcast(&self, signed_transaction: &str) -> Result<EvmBroadcastResult, String>;
}

#[async_trait(?Send)]
pub trait EvmPoller {
    async fn poll(&self, cursor: &EvmPollCursor) -> Result<EvmPollResult, String>;
}

#[derive(Clone, Debug)]
pub struct HttpEvmPoller {
    rpc: HttpEvmRpcClient,
    max_logs_per_poll: usize,
    log_filter_address: String,
    log_filter_topics: Vec<String>,
}

impl HttpEvmPoller {
    pub fn from_snapshot(snapshot: &RuntimeSnapshot) -> Result<Self, String> {
        let rpc = HttpEvmRpcClient::from_snapshot(snapshot)?;
        let log_filter_address = snapshot
            .evm_cursor
            .contract_address
            .as_deref()
            .or(snapshot.inbox_contract_address.as_deref())
            .ok_or_else(|| "inbox contract address is not configured".to_string())
            .and_then(normalize_address)?;
        let log_filter_topic1 = match snapshot.evm_cursor.automaton_address_topic.as_deref() {
            Some(topic) => normalize_topic(topic, "automaton address topic")?,
            None => {
                let agent_evm_address = snapshot
                    .evm_address
                    .as_deref()
                    .ok_or_else(|| "evm address is not configured".to_string())?;
                address_to_topic(agent_evm_address)?
            }
        };
        Ok(Self {
            rpc,
            max_logs_per_poll: DEFAULT_MAX_LOGS_PER_POLL,
            log_filter_address,
            log_filter_topics: vec![inbox_message_queued_topic0(), log_filter_topic1],
        })
    }
}

#[async_trait(?Send)]
impl EvmPoller for HttpEvmPoller {
    async fn poll(&self, cursor: &EvmPollCursor) -> Result<EvmPollResult, String> {
        let latest_block = self.rpc.eth_block_number().await?;
        let confirmed_head = latest_block.saturating_sub(cursor.confirmation_depth);
        let from_block = cursor.next_block;
        let to_block = confirmed_head.min(from_block.saturating_add(MAX_BLOCK_RANGE_PER_POLL));

        if from_block > to_block {
            return Ok(EvmPollResult {
                cursor: cursor.clone(),
                events: Vec::new(),
            });
        }

        let logs = self
            .rpc
            .eth_get_logs(
                from_block,
                to_block,
                Some(self.log_filter_address.as_str()),
                Some(self.log_filter_topics.as_slice()),
                self.rpc.max_response_bytes,
            )
            .await?;

        let events = filter_route_matched_logs(
            logs,
            cursor,
            self.log_filter_address.as_str(),
            self.log_filter_topics
                .get(1)
                .map(String::as_str)
                .ok_or_else(|| "log filter topic1 is missing".to_string())?,
            self.max_logs_per_poll,
        )?;

        let (next_block, next_log_index) = if let Some(last) = events.last() {
            if events.len() == self.max_logs_per_poll {
                (last.block_number, last.log_index.saturating_add(1))
            } else {
                (to_block.saturating_add(1), 0)
            }
        } else {
            (to_block.saturating_add(1), 0)
        };

        Ok(EvmPollResult {
            cursor: EvmPollCursor {
                chain_id: cursor.chain_id,
                contract_address: cursor.contract_address.clone(),
                automaton_address_topic: cursor.automaton_address_topic.clone(),
                next_block,
                next_log_index,
                confirmation_depth: cursor.confirmation_depth,
                last_poll_at_ns: cursor.last_poll_at_ns,
                consecutive_empty_polls: cursor.consecutive_empty_polls,
            },
            events,
        })
    }
}

#[allow(dead_code)]
pub struct MockEvmPoller;

#[async_trait(?Send)]
impl EvmPoller for MockEvmPoller {
    async fn poll(&self, cursor: &EvmPollCursor) -> Result<EvmPollResult, String> {
        let next_block = cursor.next_block.saturating_add(1);
        let next_log_index = cursor.next_log_index.saturating_add(1);

        let events = vec![EvmEvent {
            tx_hash: format!("0x{:0>64}", next_log_index),
            chain_id: cursor.chain_id,
            block_number: next_block,
            log_index: next_log_index,
            source: "mock_chain".to_string(),
            payload: "agent.heartbeat".to_string(),
        }];

        Ok(EvmPollResult {
            cursor: EvmPollCursor {
                chain_id: cursor.chain_id,
                contract_address: cursor.contract_address.clone(),
                automaton_address_topic: cursor.automaton_address_topic.clone(),
                next_block,
                next_log_index,
                confirmation_depth: cursor.confirmation_depth,
                last_poll_at_ns: cursor.last_poll_at_ns,
                consecutive_empty_polls: cursor.consecutive_empty_polls,
            },
            events,
        })
    }
}

#[allow(dead_code)]
pub struct MockEvmBroadcaster;

impl EvmBroadcaster for MockEvmBroadcaster {
    fn broadcast(&self, signed_transaction: &str) -> Result<EvmBroadcastResult, String> {
        Ok(EvmBroadcastResult {
            tx_hash: format!("0x{signed_transaction}-mock"),
        })
    }
}

#[derive(Clone, Debug)]
pub struct HttpEvmRpcClient {
    rpc_url: String,
    fallback_rpc_url: Option<String>,
    max_response_bytes: u64,
}

impl HttpEvmRpcClient {
    pub fn from_snapshot(snapshot: &RuntimeSnapshot) -> Result<Self, String> {
        let rpc_url = snapshot.evm_rpc_url.trim();
        if rpc_url.is_empty() {
            return Err("evm rpc url is not configured".to_string());
        }
        Ok(Self {
            rpc_url: rpc_url.to_string(),
            fallback_rpc_url: snapshot.evm_rpc_fallback_url.clone(),
            max_response_bytes: clamp_response_bytes(snapshot.evm_rpc_max_response_bytes),
        })
    }

    fn control_plane_max_response_bytes(&self) -> u64 {
        CONTROL_PLANE_MAX_RESPONSE_BYTES
    }

    async fn eth_block_number(&self) -> Result<u64, String> {
        let response = self
            .rpc_call(
                "eth_blockNumber",
                json!([]),
                self.control_plane_max_response_bytes(),
            )
            .await
            .map_err(|error| format!("eth_blockNumber failed: {error}"))?;
        let raw = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| "eth_blockNumber result was missing".to_string())?;
        parse_hex_u64(raw, "eth_blockNumber")
    }

    async fn eth_get_logs(
        &self,
        from_block: u64,
        to_block: u64,
        address_filter: Option<&str>,
        topics_filter: Option<&[String]>,
        max_response_bytes: u64,
    ) -> Result<Vec<RpcLog>, String> {
        let mut filter = serde_json::Map::new();
        filter.insert(
            "fromBlock".to_string(),
            Value::String(format!("0x{from_block:x}")),
        );
        filter.insert(
            "toBlock".to_string(),
            Value::String(format!("0x{to_block:x}")),
        );
        if let Some(address) = address_filter {
            filter.insert("address".to_string(), Value::String(address.to_string()));
        }
        if let Some(topics) = topics_filter {
            filter.insert(
                "topics".to_string(),
                Value::Array(
                    topics
                        .iter()
                        .map(|topic| Value::String(topic.clone()))
                        .collect(),
                ),
            );
        }

        let response = self
            .rpc_call(
                "eth_getLogs",
                Value::Array(vec![Value::Object(filter)]),
                max_response_bytes,
            )
            .await
            .map_err(|error| format!("eth_getLogs failed: {error}"))?;

        let raw_logs = response
            .get("result")
            .cloned()
            .ok_or_else(|| "eth_getLogs result was missing".to_string())?;
        serde_json::from_value::<Vec<RpcLog>>(raw_logs)
            .map_err(|error| format!("failed to decode eth_getLogs result: {error}"))
    }

    pub async fn eth_get_balance(&self, address: &str) -> Result<String, String> {
        self.eth_get_balance_with_limit(address, self.control_plane_max_response_bytes())
            .await
    }

    pub async fn eth_get_balance_with_limit(
        &self,
        address: &str,
        max_response_bytes: u64,
    ) -> Result<String, String> {
        let response = self
            .rpc_call(
                "eth_getBalance",
                json!([address, "latest"]),
                max_response_bytes,
            )
            .await
            .map_err(|error| format!("eth_getBalance failed: {error}"))?;
        let raw = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| "eth_getBalance result was missing".to_string())?;
        normalize_hex_quantity(raw, "eth_getBalance result")
    }

    pub async fn eth_call(&self, address: &str, calldata: &str) -> Result<String, String> {
        self.eth_call_with_limit(address, calldata, self.control_plane_max_response_bytes())
            .await
    }

    pub async fn eth_call_with_limit(
        &self,
        address: &str,
        calldata: &str,
        max_response_bytes: u64,
    ) -> Result<String, String> {
        let response = self
            .rpc_call(
                "eth_call",
                json!([{"to": address, "data": calldata}, "latest"]),
                max_response_bytes,
            )
            .await
            .map_err(|error| format!("eth_call failed: {error}"))?;
        let raw = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| "eth_call result was missing".to_string())?;
        normalize_hex_blob(raw, "eth_call result")
    }

    pub async fn eth_get_transaction_count(&self, address: &str) -> Result<u64, String> {
        let response = self
            .rpc_call(
                "eth_getTransactionCount",
                json!([address, "pending"]),
                self.control_plane_max_response_bytes(),
            )
            .await
            .map_err(|error| format!("eth_getTransactionCount failed: {error}"))?;
        let raw = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| "eth_getTransactionCount result was missing".to_string())?;
        parse_hex_u64(raw, "eth_getTransactionCount")
    }

    pub async fn eth_gas_price(&self) -> Result<U256, String> {
        let response = self
            .rpc_call(
                "eth_gasPrice",
                json!([]),
                self.control_plane_max_response_bytes(),
            )
            .await
            .map_err(|error| format!("eth_gasPrice failed: {error}"))?;
        let raw = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| "eth_gasPrice result was missing".to_string())?;
        parse_hex_u256(raw, "eth_gasPrice")
    }

    pub async fn eth_estimate_gas(
        &self,
        from: &str,
        to: &str,
        value_wei: U256,
        data_hex: &str,
    ) -> Result<u64, String> {
        let value_hex = format!("0x{:x}", value_wei);
        let response = self
            .rpc_call(
                "eth_estimateGas",
                json!([{
                    "from": from,
                    "to": to,
                    "value": value_hex,
                    "data": data_hex
                }]),
                self.control_plane_max_response_bytes(),
            )
            .await
            .map_err(|error| format!("eth_estimateGas failed: {error}"))?;
        let raw = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| "eth_estimateGas result was missing".to_string())?;
        parse_hex_u64(raw, "eth_estimateGas")
    }

    pub async fn eth_send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String, String> {
        let payload = format!("0x{}", hex::encode(raw_tx));
        let response = self
            .rpc_call(
                "eth_sendRawTransaction",
                json!([payload]),
                self.control_plane_max_response_bytes(),
            )
            .await
            .map_err(|error| format!("eth_sendRawTransaction failed: {error}"))?;
        let raw = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| "eth_sendRawTransaction result was missing".to_string())?;
        normalize_hex_blob(raw, "eth_sendRawTransaction result")
    }

    async fn rpc_call(
        &self,
        method: &str,
        params: Value,
        max_response_bytes: u64,
    ) -> Result<Value, String> {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }))
        .map_err(|error| format!("failed to serialize {method} request: {error}"))?;

        let request_size_bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
        ensure_http_affordable(request_size_bytes, max_response_bytes)?;

        let raw = self.http_post(&body, max_response_bytes).await?;
        let value: Value = serde_json::from_slice(&raw)
            .map_err(|error| format!("failed to parse {method} response JSON: {error}"))?;
        if let Some(error) = value.get("error") {
            return Err(format!("rpc returned error for {method}: {error}"));
        }
        Ok(value)
    }

    async fn http_post(&self, body: &[u8], max_response_bytes: u64) -> Result<Vec<u8>, String> {
        let normalized_max = clamp_response_bytes(max_response_bytes);
        match self
            .try_http_post(&self.rpc_url, body, normalized_max)
            .await
        {
            Ok(body) => Ok(body),
            Err(primary_error) => {
                if let Some(fallback_url) = self.fallback_rpc_url.as_deref() {
                    self.try_http_post(fallback_url, body, normalized_max)
                        .await
                        .map_err(|fallback_error| {
                            format!(
                                "primary rpc failed: {primary_error}; fallback rpc failed: {fallback_error}"
                            )
                        })
                } else {
                    Err(primary_error)
                }
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn try_http_post(
        &self,
        url: &str,
        body: &[u8],
        max_response_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        let request = HttpRequestArgs {
            url: url.to_string(),
            max_response_bytes: Some(max_response_bytes),
            method: HttpMethod::POST,
            headers: vec![HttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: Some(body.to_vec()),
            transform: None,
            is_replicated: Some(false),
        };

        let response = http_request(&request)
            .await
            .map_err(|error| format!("evm rpc outcall failed: {error}"))?;
        let status = nat_to_u16(&response.status)?;
        if !(200..300).contains(&status) {
            return Err(format!("evm rpc returned status {status}"));
        }
        Ok(response.body)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn try_http_post(
        &self,
        url: &str,
        body: &[u8],
        max_response_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        if !host_rpc_real_mode_enabled() {
            return host_rpc_stub_response(body);
        }

        let normalized_max = clamp_response_bytes(max_response_bytes);
        let response = ureq::post(url)
            .set("content-type", "application/json")
            .send_bytes(body)
            .map_err(|error| match error {
                ureq::Error::Status(status, _) => {
                    format!("evm rpc returned status {status}")
                }
                ureq::Error::Transport(transport) => {
                    format!("evm rpc host transport failed: {transport}")
                }
            })?;

        let mut raw = Vec::new();
        response
            .into_reader()
            .take(normalized_max.saturating_add(1))
            .read_to_end(&mut raw)
            .map_err(|error| format!("failed to read host rpc response body: {error}"))?;
        if u64::try_from(raw.len()).unwrap_or(u64::MAX) > normalized_max {
            return Err(format!(
                "host rpc response exceeded max_response_bytes={normalized_max}"
            ));
        }
        Ok(raw)
    }
}

#[cfg(target_arch = "wasm32")]
fn nat_to_u16(status: &Nat) -> Result<u16, String> {
    status
        .to_string()
        .parse::<u16>()
        .map_err(|error| format!("invalid HTTP status {status}: {error}"))
}

fn clamp_response_bytes(max_response_bytes: u64) -> u64 {
    max_response_bytes.clamp(256, MAX_EVM_RPC_RESPONSE_BYTES)
}

fn ensure_http_affordable(request_size_bytes: u64, max_response_bytes: u64) -> Result<(), String> {
    let operation = OperationClass::HttpOutcall {
        request_size_bytes,
        max_response_bytes: clamp_response_bytes(max_response_bytes),
    };
    let estimated = estimate_operation_cost(&operation)?;
    let requirements = affordability_requirements(
        estimated,
        DEFAULT_SAFETY_MARGIN_BPS,
        DEFAULT_RESERVE_FLOOR_CYCLES,
    );
    let liquid = liquid_cycle_balance();
    if !can_afford(liquid, &requirements) {
        return Err(format!(
            "insufficient cycles for evm rpc outcall: need {} liquid, have {}",
            requirements.required_cycles, liquid
        ));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn classify_evm_failure(error: &str) -> RecoveryFailure {
    let normalized = error.to_ascii_lowercase();
    if indicates_insufficient_cycles_error(&normalized) {
        return RecoveryFailure::Operation(OperationFailure {
            kind: OperationFailureKind::InsufficientCycles,
        });
    }
    if normalized.contains("is not configured") {
        return RecoveryFailure::Operation(OperationFailure {
            kind: OperationFailureKind::MissingConfiguration,
        });
    }
    if normalized.contains("must be 0x-prefixed")
        || normalized.contains("must be valid hex")
        || normalized.contains("must be a 32-byte topic")
        || normalized.contains("must be one of")
    {
        return RecoveryFailure::Operation(OperationFailure {
            kind: OperationFailureKind::InvalidConfiguration,
        });
    }
    RecoveryFailure::Outcall(OutcallFailure {
        kind: classify_evm_outcall_failure_kind(&normalized),
        retry_after_secs: None,
        observed_response_bytes: None,
    })
}

#[allow(dead_code)]
fn classify_evm_outcall_failure_kind(normalized_error: &str) -> OutcallFailureKind {
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
        || normalized_error.contains("forbidden")
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
        || normalized_error.contains("rpc returned error")
    {
        return OutcallFailureKind::InvalidRequest;
    }
    if normalized_error.contains("failed to parse")
        || normalized_error.contains("result was missing")
        || normalized_error.contains("response decode failed")
        || normalized_error.contains("response was not valid utf-8")
    {
        return OutcallFailureKind::InvalidResponse;
    }
    if normalized_error.contains("transport failed")
        || normalized_error.contains("connection reset")
        || normalized_error.contains("connection refused")
        || normalized_error.contains("network is unreachable")
        || normalized_error.contains("dns")
        || normalized_error.contains("outcall failed")
    {
        return OutcallFailureKind::Transport;
    }
    OutcallFailureKind::Unknown
}

#[allow(dead_code)]
fn indicates_insufficient_cycles_error(normalized_error: &str) -> bool {
    normalized_error.contains("insufficient cycles")
        || normalized_error.contains("not enough cycles")
        || normalized_error.contains("out of cycles")
        || normalized_error.contains("cycles depleted")
}

#[cfg(target_arch = "wasm32")]
fn liquid_cycle_balance() -> u128 {
    ic_cdk::api::canister_liquid_cycle_balance()
}

#[cfg(not(target_arch = "wasm32"))]
fn liquid_cycle_balance() -> u128 {
    u128::MAX
}

#[cfg(not(target_arch = "wasm32"))]
fn host_rpc_real_mode_enabled() -> bool {
    std::env::var(HOST_EVM_RPC_MODE_ENV)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "real" | "1" | "true" | "yes")
        })
        .unwrap_or(false)
}

#[cfg(not(target_arch = "wasm32"))]
fn host_rpc_stub_response(body: &[u8]) -> Result<Vec<u8>, String> {
    let request: Value = serde_json::from_slice(body)
        .map_err(|error| format!("host rpc stub could not parse request JSON: {error}"))?;
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "host rpc stub request is missing method".to_string())?;

    let response = match method {
        "eth_blockNumber" => json!({"jsonrpc":"2.0","id":1,"result":"0x0"}),
        "eth_getLogs" => json!({"jsonrpc":"2.0","id":1,"result":[]}),
        "eth_getBalance" => json!({"jsonrpc":"2.0","id":1,"result":"0x1"}),
        "eth_call" => host_rpc_stub_eth_call_result(&request),
        "eth_getTransactionCount" => json!({"jsonrpc":"2.0","id":1,"result":"0x0"}),
        "eth_gasPrice" => json!({"jsonrpc":"2.0","id":1,"result":"0x3b9aca00"}),
        "eth_estimateGas" => json!({"jsonrpc":"2.0","id":1,"result":"0x5208"}),
        "eth_sendRawTransaction" => json!({
            "jsonrpc":"2.0",
            "id":1,
            "result":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }),
        unsupported => {
            return Err(format!(
                "host rpc stub does not support method {unsupported}"
            ));
        }
    };

    serde_json::to_vec(&response)
        .map_err(|error| format!("host rpc stub failed to serialize response: {error}"))
}

#[cfg(not(target_arch = "wasm32"))]
fn host_rpc_stub_eth_call_result(request: &Value) -> Value {
    let data = request
        .pointer("/params/0/data")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let usdc_selector = encode_call_no_args(INBOX_USDC_FUNCTION_SIGNATURE);
    let balance_selector = format!(
        "0x{}",
        function_selector_hex(ERC20_BALANCE_OF_FUNCTION_SIGNATURE)
    );

    if data == usdc_selector {
        return json!({
            "jsonrpc":"2.0",
            "id":1,
            "result":"0x0000000000000000000000003333333333333333333333333333333333333333"
        });
    }
    if data.starts_with(&balance_selector) {
        return json!({
            "jsonrpc":"2.0",
            "id":1,
            "result":"0x000000000000000000000000000000000000000000000000000000000000002a"
        });
    }

    json!({"jsonrpc":"2.0","id":1,"result":"0x"})
}

fn parse_hex_u64(raw: &str, field: &str) -> Result<u64, String> {
    let value = raw.trim();
    let without_prefix = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| format!("{field} must be 0x-prefixed hex"))?;
    u64::from_str_radix(without_prefix, 16)
        .map_err(|error| format!("failed to parse {field} as hex u64: {error}"))
}

fn normalize_address(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let valid = trimmed.len() == 42
        && trimmed.starts_with("0x")
        && trimmed
            .as_bytes()
            .iter()
            .skip(2)
            .all(|byte| byte.is_ascii_hexdigit());
    if !valid {
        return Err("address must be a 0x-prefixed 20-byte hex string".to_string());
    }
    Ok(trimmed)
}

fn inbox_message_queued_topic0() -> String {
    let hash = keccak256(INBOX_MESSAGE_QUEUED_EVENT_SIGNATURE.as_bytes());
    format!("0x{}", hex::encode(hash.as_slice()))
}

fn address_to_topic(raw: &str) -> Result<String, String> {
    let normalized = normalize_address(raw)?;
    let bytes = normalized.trim_start_matches("0x");
    Ok(format!("0x{:0>64}", bytes))
}

fn function_selector_hex(signature: &str) -> String {
    let hash = keccak256(signature.as_bytes());
    hex::encode(&hash.as_slice()[..4])
}

fn encode_call_no_args(signature: &str) -> String {
    format!("0x{}", function_selector_hex(signature))
}

#[allow(dead_code)]
fn encode_call_single_address_arg(signature: &str, address: &str) -> Result<String, String> {
    let normalized = normalize_address(address)?;
    Ok(format!(
        "0x{}{:0>64}",
        function_selector_hex(signature),
        normalized.trim_start_matches("0x")
    ))
}

#[allow(dead_code)]
fn decode_u256_word_hex_as_quantity(raw: &str, field: &str) -> Result<String, String> {
    let normalized = normalize_hex_blob(raw, field)?;
    let payload = normalized.trim_start_matches("0x");
    if payload.is_empty() {
        return Ok("0x0".to_string());
    }
    let value_hex = if payload.len() >= 64 {
        &payload[..64]
    } else {
        payload
    };
    let value = parse_hex_u256(&format!("0x{value_hex}"), field)?;
    Ok(format!("0x{value:x}"))
}

#[allow(dead_code)]
fn decode_address_word_from_eth_call(raw: &str, field: &str) -> Result<String, String> {
    let normalized = normalize_hex_blob(raw, field)?;
    let payload = normalized.trim_start_matches("0x");
    if payload.len() < 64 {
        return Err(format!("{field} must be at least 32 bytes"));
    }
    let word = &payload[..64];
    let decoded = hex::decode(word)
        .map_err(|error| format!("failed to decode {field} return data: {error}"))?;
    let address = format!("0x{}", hex::encode(&decoded[12..32]));
    normalize_address(&address)
}

fn normalize_topic(raw: &str, field: &str) -> Result<String, String> {
    let normalized = normalize_hex_blob(raw, field)?;
    if normalized.len() != 66 {
        return Err(format!("{field} must be a 32-byte topic"));
    }
    Ok(normalized)
}

fn normalize_hex_blob(raw: &str, field: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .ok_or_else(|| format!("{field} must be 0x-prefixed hex"))?;
    if without_prefix.len() % 2 != 0 {
        return Err(format!("{field} hex length must be even"));
    }
    if !without_prefix
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("{field} must be valid hex"));
    }
    Ok(trimmed)
}

fn normalize_hex_quantity(raw: &str, field: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .ok_or_else(|| format!("{field} must be 0x-prefixed hex"))?;
    if !without_prefix
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("{field} must be valid hex"));
    }
    Ok(trimmed)
}

#[derive(Deserialize)]
struct RpcLog {
    #[serde(rename = "blockNumber")]
    block_number: Option<String>,
    #[serde(rename = "logIndex")]
    log_index: Option<String>,
    #[serde(rename = "transactionHash")]
    tx_hash: Option<String>,
    #[serde(default)]
    topics: Vec<String>,
    address: String,
    data: String,
}

fn filter_route_matched_logs(
    logs: Vec<RpcLog>,
    cursor: &EvmPollCursor,
    expected_contract: &str,
    expected_topic1: &str,
    max_logs_per_poll: usize,
) -> Result<Vec<EvmEvent>, String> {
    let expected_contract = normalize_address(expected_contract)?;
    let expected_topic0 = inbox_message_queued_topic0();
    let expected_topic1 = normalize_topic(expected_topic1, "topic1")?;

    let mut events = Vec::new();
    for log in logs {
        let block_number = match log
            .block_number
            .as_deref()
            .map(|value| parse_hex_u64(value, "blockNumber"))
        {
            Some(Ok(value)) => value,
            _ => continue,
        };
        let log_index = match log
            .log_index
            .as_deref()
            .map(|value| parse_hex_u64(value, "logIndex"))
        {
            Some(Ok(value)) => value,
            _ => continue,
        };
        if block_number < cursor.next_block {
            continue;
        }
        if block_number == cursor.next_block && log_index < cursor.next_log_index {
            continue;
        }

        let source = match normalize_address(&log.address) {
            Ok(value) if value == expected_contract => value,
            _ => continue,
        };
        if !matches!(
            log.topics
                .first()
                .map(|value| normalize_topic(value, "topic0")),
            Some(Ok(topic)) if topic == expected_topic0
        ) {
            continue;
        }
        if !matches!(
            log.topics
                .get(1)
                .map(|value| normalize_topic(value, "topic1")),
            Some(Ok(topic)) if topic == expected_topic1
        ) {
            continue;
        }

        let tx_hash = match log
            .tx_hash
            .as_deref()
            .map(|value| normalize_hex_blob(value, "transactionHash"))
        {
            Some(Ok(value)) if value.len() == 66 => value,
            _ => continue,
        };
        let payload = match normalize_hex_blob(&log.data, "data") {
            Ok(value) => value,
            Err(_) => continue,
        };

        events.push(EvmEvent {
            tx_hash,
            chain_id: cursor.chain_id,
            block_number,
            log_index,
            source,
            payload,
        });
    }

    events.sort_by_key(|event| (event.block_number, event.log_index));
    if events.len() > max_logs_per_poll {
        events.truncate(max_logs_per_poll);
    }
    Ok(events)
}

#[derive(Deserialize)]
struct EvmReadArgs {
    method: String,
    address: String,
    #[serde(default)]
    calldata: Option<String>,
}

enum EvmReadMethod {
    GetBalance,
    Call,
}

struct ParsedEvmReadArgs {
    method: EvmReadMethod,
    address: String,
    calldata: Option<String>,
}

fn parse_evm_read_args(args_json: &str) -> Result<ParsedEvmReadArgs, String> {
    let args: EvmReadArgs = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid evm_read args json: {error}"))?;

    let address = normalize_address(&args.address)?;
    let method = match args.method.trim() {
        "eth_getBalance" => EvmReadMethod::GetBalance,
        "eth_call" => EvmReadMethod::Call,
        unsupported => {
            return Err(format!(
                "evm_read method must be one of eth_getBalance or eth_call, got {unsupported}"
            ));
        }
    };

    let calldata = match method {
        EvmReadMethod::GetBalance => None,
        EvmReadMethod::Call => {
            let value = args
                .calldata
                .ok_or_else(|| "calldata is required for eth_call".to_string())?;
            Some(normalize_hex_blob(&value, "calldata")?)
        }
    };

    Ok(ParsedEvmReadArgs {
        method,
        address,
        calldata,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct WalletBalanceSyncRead {
    pub eth_balance_wei_hex: String,
    pub usdc_balance_raw_hex: String,
    pub usdc_contract_address: String,
}

#[allow(dead_code)]
pub async fn fetch_wallet_balance_sync_read(
    snapshot: &RuntimeSnapshot,
) -> Result<WalletBalanceSyncRead, String> {
    let wallet_address = snapshot
        .evm_address
        .as_deref()
        .ok_or_else(|| "evm address is not configured".to_string())
        .and_then(normalize_address)?;
    let rpc = HttpEvmRpcClient::from_snapshot(snapshot)?;
    let max_response_bytes = clamp_response_bytes(snapshot.wallet_balance_sync.max_response_bytes);
    let usdc_contract_address =
        resolve_usdc_contract_address(snapshot, &rpc, max_response_bytes).await?;
    let eth_balance_wei_hex =
        fetch_eth_balance_wei_hex(&rpc, &wallet_address, max_response_bytes).await?;
    let usdc_balance_raw_hex = fetch_usdc_balance_raw_hex(
        &rpc,
        &usdc_contract_address,
        &wallet_address,
        max_response_bytes,
    )
    .await?;

    Ok(WalletBalanceSyncRead {
        eth_balance_wei_hex,
        usdc_balance_raw_hex,
        usdc_contract_address,
    })
}

#[allow(dead_code)]
async fn resolve_usdc_contract_address(
    snapshot: &RuntimeSnapshot,
    rpc: &HttpEvmRpcClient,
    max_response_bytes: u64,
) -> Result<String, String> {
    if let Some(explicit) = snapshot.wallet_balance.usdc_contract_address.as_deref() {
        return normalize_address(explicit);
    }
    if !snapshot.wallet_balance_sync.discover_usdc_via_inbox {
        return Err("usdc contract address is not configured".to_string());
    }
    let inbox_contract_address = snapshot
        .inbox_contract_address
        .as_deref()
        .ok_or_else(|| "inbox contract address is not configured".to_string())?;
    discover_usdc_contract_address_via_inbox(rpc, inbox_contract_address, max_response_bytes).await
}

#[allow(dead_code)]
pub async fn fetch_eth_balance_wei_hex(
    rpc: &HttpEvmRpcClient,
    wallet_address: &str,
    max_response_bytes: u64,
) -> Result<String, String> {
    let wallet = normalize_address(wallet_address)?;
    rpc.eth_get_balance_with_limit(&wallet, max_response_bytes)
        .await
}

#[allow(dead_code)]
pub async fn fetch_usdc_balance_raw_hex(
    rpc: &HttpEvmRpcClient,
    usdc_contract_address: &str,
    wallet_address: &str,
    max_response_bytes: u64,
) -> Result<String, String> {
    let usdc_contract = normalize_address(usdc_contract_address)?;
    let wallet = normalize_address(wallet_address)?;
    let calldata = encode_call_single_address_arg(ERC20_BALANCE_OF_FUNCTION_SIGNATURE, &wallet)?;
    let raw = rpc
        .eth_call_with_limit(&usdc_contract, &calldata, max_response_bytes)
        .await?;
    decode_u256_word_hex_as_quantity(&raw, "usdc balanceOf result")
}

#[allow(dead_code)]
pub async fn discover_usdc_contract_address_via_inbox(
    rpc: &HttpEvmRpcClient,
    inbox_contract_address: &str,
    max_response_bytes: u64,
) -> Result<String, String> {
    let inbox_contract = normalize_address(inbox_contract_address)?;
    let calldata = encode_call_no_args(INBOX_USDC_FUNCTION_SIGNATURE);
    let raw = rpc
        .eth_call_with_limit(&inbox_contract, &calldata, max_response_bytes)
        .await?;
    let usdc_address = decode_address_word_from_eth_call(&raw, "Inbox.usdc result")?;
    if usdc_address == "0x0000000000000000000000000000000000000000" {
        return Err("Inbox.usdc returned zero address".to_string());
    }
    Ok(usdc_address)
}

pub async fn evm_read_tool(args_json: &str) -> Result<String, String> {
    let args = parse_evm_read_args(args_json)?;
    let snapshot = stable::runtime_snapshot();
    let rpc = HttpEvmRpcClient::from_snapshot(&snapshot)?;

    match args.method {
        EvmReadMethod::GetBalance => rpc.eth_get_balance(&args.address).await,
        EvmReadMethod::Call => {
            let calldata = args
                .calldata
                .as_deref()
                .ok_or_else(|| "calldata is required for eth_call".to_string())?;
            rpc.eth_call(&args.address, calldata).await
        }
    }
}

#[derive(Deserialize)]
struct SendEthArgs {
    to: String,
    value_wei: String,
    #[serde(default)]
    data: Option<String>,
}

struct ParsedSendEthArgs {
    to: Address,
    to_hex: String,
    value_wei: U256,
    data: Bytes,
    data_hex: String,
}

#[derive(Clone, Debug)]
struct Eip1559UnsignedTx {
    chain_id: U256,
    nonce: U256,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: U256,
    to: Address,
    value: U256,
    data: Bytes,
}

impl Eip1559UnsignedTx {
    fn payload_length(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.data.length()
            + EMPTY_ACCESS_LIST_RLP_LEN
    }
}

impl Encodable for Eip1559UnsignedTx {
    fn encode(&self, out: &mut dyn BufMut) {
        Header {
            list: true,
            payload_length: self.payload_length(),
        }
        .encode(out);
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.data.encode(out);
        Header {
            list: true,
            payload_length: 0,
        }
        .encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.payload_length();
        payload_length + length_of_length(payload_length)
    }
}

struct Eip1559SignedTx<'a> {
    tx: &'a Eip1559UnsignedTx,
    y_parity: u8,
    r: U256,
    s: U256,
}

impl Eip1559SignedTx<'_> {
    fn payload_length(&self) -> usize {
        self.tx.chain_id.length()
            + self.tx.nonce.length()
            + self.tx.max_priority_fee_per_gas.length()
            + self.tx.max_fee_per_gas.length()
            + self.tx.gas_limit.length()
            + self.tx.to.length()
            + self.tx.value.length()
            + self.tx.data.length()
            + EMPTY_ACCESS_LIST_RLP_LEN
            + self.y_parity.length()
            + self.r.length()
            + self.s.length()
    }
}

impl Encodable for Eip1559SignedTx<'_> {
    fn encode(&self, out: &mut dyn BufMut) {
        Header {
            list: true,
            payload_length: self.payload_length(),
        }
        .encode(out);
        self.tx.chain_id.encode(out);
        self.tx.nonce.encode(out);
        self.tx.max_priority_fee_per_gas.encode(out);
        self.tx.max_fee_per_gas.encode(out);
        self.tx.gas_limit.encode(out);
        self.tx.to.encode(out);
        self.tx.value.encode(out);
        self.tx.data.encode(out);
        Header {
            list: true,
            payload_length: 0,
        }
        .encode(out);
        self.y_parity.encode(out);
        self.r.encode(out);
        self.s.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.payload_length();
        payload_length + length_of_length(payload_length)
    }
}

fn parse_send_eth_args(args_json: &str) -> Result<ParsedSendEthArgs, String> {
    let args: SendEthArgs = serde_json::from_str(args_json)
        .map_err(|error| format!("invalid send_eth args json: {error}"))?;

    let to_hex = normalize_address(&args.to)?;
    let to = Address::from_str(&to_hex)
        .map_err(|error| format!("invalid destination address for send_eth: {error}"))?;
    let value_wei = parse_decimal_u256(&args.value_wei, "value_wei")?;
    let data_hex = match args.data {
        Some(data) => normalize_hex_blob(&data, "data")?,
        None => "0x".to_string(),
    };
    let data = Bytes::from(
        hex::decode(data_hex.trim_start_matches("0x"))
            .map_err(|error| format!("data must be valid hex: {error}"))?,
    );

    Ok(ParsedSendEthArgs {
        to,
        to_hex,
        value_wei,
        data,
        data_hex,
    })
}

fn parse_decimal_u256(raw: &str, field: &str) -> Result<U256, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    if !trimmed.as_bytes().iter().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{field} must be a decimal string"));
    }
    U256::from_str(trimmed).map_err(|error| format!("failed to parse {field} as decimal: {error}"))
}

fn parse_hex_u256(raw: &str, field: &str) -> Result<U256, String> {
    let normalized = normalize_hex_quantity(raw, field)?;
    let without_prefix = normalized.trim_start_matches("0x");
    if without_prefix.is_empty() {
        return Ok(U256::ZERO);
    }
    if without_prefix.len() > 64 {
        return Err(format!("{field} exceeds 32 bytes"));
    }
    let padded = if without_prefix.len() % 2 == 0 {
        without_prefix.to_string()
    } else {
        format!("0{without_prefix}")
    };
    let bytes = hex::decode(&padded)
        .map_err(|error| format!("failed to decode {field} as hex: {error}"))?;
    Ok(U256::from_be_slice(&bytes))
}

fn parse_compact_signature(raw: &str) -> Result<[u8; 64], String> {
    let normalized = normalize_hex_blob(raw, "signature")?;
    let without_prefix = normalized.trim_start_matches("0x");
    if without_prefix.len() != 128 {
        return Err("signature must be 64 bytes (r||s)".to_string());
    }
    let mut out = [0u8; 64];
    hex::decode_to_slice(without_prefix, &mut out)
        .map_err(|error| format!("failed to decode signature: {error}"))?;
    Ok(out)
}

fn encode_eip1559_unsigned_payload(tx: &Eip1559UnsignedTx) -> Vec<u8> {
    alloy_rlp::encode(tx)
}

fn encode_eip1559_unsigned(tx: &Eip1559UnsignedTx) -> Vec<u8> {
    let payload = encode_eip1559_unsigned_payload(tx);
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(0x02);
    out.extend_from_slice(&payload);
    out
}

fn encode_eip1559_signed(tx: &Eip1559UnsignedTx, y_parity: u8, r: U256, s: U256) -> Vec<u8> {
    let payload = alloy_rlp::encode(Eip1559SignedTx { tx, y_parity, r, s });
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(0x02);
    out.extend_from_slice(&payload);
    out
}

#[cfg(not(target_arch = "wasm32"))]
fn recover_y_parity(
    _tx_hash: &B256,
    _signature_compact: &[u8; 64],
    _expected_address: &str,
) -> Result<u8, String> {
    Ok(0)
}

#[cfg(target_arch = "wasm32")]
fn recover_y_parity(
    tx_hash: &B256,
    signature_compact: &[u8; 64],
    expected_address: &str,
) -> Result<u8, String> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let signature = Signature::from_slice(signature_compact)
        .map_err(|error| format!("invalid compact signature bytes: {error}"))?;
    let expected = expected_address.trim().to_ascii_lowercase();

    for candidate in [0u8, 1u8] {
        let Some(recovery_id) = RecoveryId::from_byte(candidate) else {
            continue;
        };
        let recovered =
            match VerifyingKey::recover_from_prehash(tx_hash.as_slice(), &signature, recovery_id) {
                Ok(key) => key,
                Err(_) => continue,
            };
        let uncompressed = recovered.to_encoded_point(false);
        let bytes = uncompressed.as_bytes();
        if bytes.len() != 65 || bytes.first().copied() != Some(0x04) {
            continue;
        }
        let digest = Keccak256::digest(&bytes[1..]);
        let address = format!("0x{}", hex::encode(&digest[12..32]));
        if address == expected {
            return Ok(candidate);
        }
    }

    Err("failed to recover EIP-1559 y_parity for send_eth signature".to_string())
}

fn estimate_send_eth_workflow_cost(key_name: &str) -> Result<u128, String> {
    let sign_cost = estimate_operation_cost(&OperationClass::ThresholdSign {
        key_name: key_name.to_string(),
        ecdsa_curve: 0,
    })?;
    let http_cost = estimate_operation_cost(&OperationClass::HttpOutcall {
        request_size_bytes: 512,
        max_response_bytes: 4_096,
    })?
    .saturating_mul(4);
    Ok(sign_cost.saturating_add(http_cost))
}

fn ensure_send_eth_affordable(key_name: &str) -> Result<(), String> {
    let estimated = estimate_send_eth_workflow_cost(key_name)?;
    let requirements = affordability_requirements(
        estimated,
        DEFAULT_SAFETY_MARGIN_BPS,
        DEFAULT_RESERVE_FLOOR_CYCLES,
    );
    let liquid = liquid_cycle_balance();
    if !can_afford(liquid, &requirements) {
        return Err(format!(
            "insufficient cycles for send_eth workflow: need {} liquid, have {}",
            requirements.required_cycles, liquid
        ));
    }
    Ok(())
}

pub async fn send_eth_tool(args_json: &str, signer: &dyn SignerPort) -> Result<String, String> {
    let args = parse_send_eth_args(args_json)?;
    let snapshot = stable::runtime_snapshot();
    let from_address = snapshot
        .evm_address
        .clone()
        .ok_or_else(|| "evm address not derived yet".to_string())?;
    ensure_send_eth_affordable(&snapshot.ecdsa_key_name)?;

    let rpc = HttpEvmRpcClient::from_snapshot(&snapshot)?;
    let balance = parse_hex_u256(
        &rpc.eth_get_balance(&from_address).await?,
        "eth_getBalance result",
    )?;
    if balance < args.value_wei {
        return Err(format!(
            "insufficient balance for send_eth: balance={} value={}",
            balance, args.value_wei
        ));
    }

    let nonce = rpc.eth_get_transaction_count(&from_address).await?;
    let gas_limit = if args.data.is_empty() {
        21_000u64
    } else {
        rpc.eth_estimate_gas(&from_address, &args.to_hex, args.value_wei, &args.data_hex)
            .await
            .unwrap_or(300_000)
    };

    let base_fee = rpc
        .eth_gas_price()
        .await
        .unwrap_or_else(|_| U256::from(1_000_000_000u64));
    let max_priority_fee_per_gas = U256::from(1_000_000_000u64);
    let max_fee_per_gas = base_fee + max_priority_fee_per_gas;

    let tx = Eip1559UnsignedTx {
        chain_id: U256::from(snapshot.evm_cursor.chain_id),
        nonce: U256::from(nonce),
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit: U256::from(gas_limit),
        to: args.to,
        value: args.value_wei,
        data: args.data,
    };

    let unsigned = encode_eip1559_unsigned(&tx);
    let tx_hash = keccak256(&unsigned);
    let message_hash = format!("0x{}", hex::encode(tx_hash.as_slice()));
    let signature = parse_compact_signature(&signer.sign_message(&message_hash).await?)?;
    let y_parity = recover_y_parity(&tx_hash, &signature, &from_address)?;
    let r = U256::from_be_slice(&signature[..32]);
    let s = U256::from_be_slice(&signature[32..]);
    let signed = encode_eip1559_signed(&tx, y_parity, r, s);

    rpc.eth_send_raw_transaction(&signed).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::SignerPort;
    use async_trait::async_trait;
    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    use serde_json::Map;
    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    use std::fs;
    use std::future::Future;
    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    use std::net::TcpListener;
    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    use std::path::PathBuf;
    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    use std::process::{Child, Command, Stdio};
    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    use std::sync::{Mutex, OnceLock};
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    use std::thread;
    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    use std::time::Duration;

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
    fn mock_evm_broadcaster_returns_mock_tx_hash() {
        let broadcaster = MockEvmBroadcaster;
        let result = broadcaster
            .broadcast("0xdeadbeef")
            .expect("mock broadcaster should succeed");
        assert_eq!(result.tx_hash, "0x0xdeadbeef-mock");
    }

    #[test]
    fn parse_evm_read_args_enforces_method_and_address() {
        assert!(parse_evm_read_args("{}").is_err());
        assert!(
            parse_evm_read_args(r#"{"method":"eth_getBalance","address":"not-an-address"}"#)
                .is_err()
        );
        assert!(parse_evm_read_args(
            r#"{"method":"eth_call","address":"0x1111111111111111111111111111111111111111"}"#
        )
        .is_err());
    }

    #[test]
    fn poll_filter_topic_is_derived_from_agent_evm_address() {
        let topic = address_to_topic("0x1111111111111111111111111111111111111111")
            .expect("topic derivation should succeed");
        assert_eq!(
            topic,
            "0x0000000000000000000000001111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn message_queued_topic_signature_matches_finalized_inbox_abi() {
        assert_eq!(
            INBOX_MESSAGE_QUEUED_EVENT_SIGNATURE,
            "MessageQueued(address,uint64,address,string,uint256,uint256)"
        );
    }

    #[test]
    fn filter_route_matched_logs_requires_address_topic_and_tx_hash() {
        let cursor = EvmPollCursor {
            chain_id: 8453,
            next_block: 100,
            next_log_index: 2,
            ..EvmPollCursor::default()
        };
        let contract = "0x2222222222222222222222222222222222222222";
        let topic0 = inbox_message_queued_topic0();
        let topic1 = address_to_topic("0x1111111111111111111111111111111111111111")
            .expect("topic derivation should succeed");

        let logs = vec![
            RpcLog {
                block_number: Some("0x64".to_string()),
                log_index: Some("0x1".to_string()),
                address: contract.to_string(),
                topics: vec![topic0.clone(), topic1.clone()],
                data: "0x1234".to_string(),
                tx_hash: Some(
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ),
            },
            RpcLog {
                block_number: Some("0x64".to_string()),
                log_index: Some("0x2".to_string()),
                address: "0x3333333333333333333333333333333333333333".to_string(),
                topics: vec![topic0.clone(), topic1.clone()],
                data: "0x1234".to_string(),
                tx_hash: Some(
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                ),
            },
            RpcLog {
                block_number: Some("0x64".to_string()),
                log_index: Some("0x3".to_string()),
                address: contract.to_string(),
                topics: vec![topic0.clone(), topic1],
                data: "0x1234".to_string(),
                tx_hash: None,
            },
            RpcLog {
                block_number: Some("0x64".to_string()),
                log_index: Some("0x4".to_string()),
                address: contract.to_string(),
                topics: vec![
                    topic0,
                    "0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff"
                        .to_string(),
                ],
                data: "0x1234".to_string(),
                tx_hash: Some(
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                ),
            },
        ];

        let filtered = filter_route_matched_logs(
            logs,
            &cursor,
            contract,
            &address_to_topic("0x1111111111111111111111111111111111111111")
                .expect("topic derivation should succeed"),
            DEFAULT_MAX_LOGS_PER_POLL,
        )
        .expect("filtering should succeed");

        assert_eq!(
            filtered.len(),
            0,
            "all logs should be dropped in this fixture"
        );
    }

    #[test]
    fn filter_route_matched_logs_orders_by_block_and_log_index() {
        let cursor = EvmPollCursor {
            chain_id: 8453,
            next_block: 100,
            next_log_index: 0,
            ..EvmPollCursor::default()
        };
        let contract = "0x2222222222222222222222222222222222222222";
        let topic0 = inbox_message_queued_topic0();
        let topic1 = address_to_topic("0x1111111111111111111111111111111111111111")
            .expect("topic derivation should succeed");

        let logs = vec![
            RpcLog {
                block_number: Some("0x65".to_string()),
                log_index: Some("0x2".to_string()),
                address: contract.to_string(),
                topics: vec![topic0.clone(), topic1.clone()],
                data: "0x1234".to_string(),
                tx_hash: Some(
                    "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                ),
            },
            RpcLog {
                block_number: Some("0x65".to_string()),
                log_index: Some("0x1".to_string()),
                address: contract.to_string(),
                topics: vec![topic0, topic1],
                data: "0x5678".to_string(),
                tx_hash: Some(
                    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                        .to_string(),
                ),
            },
        ];

        let filtered = filter_route_matched_logs(
            logs,
            &cursor,
            contract,
            &address_to_topic("0x1111111111111111111111111111111111111111")
                .expect("topic derivation should succeed"),
            DEFAULT_MAX_LOGS_PER_POLL,
        )
        .expect("filtering should succeed");

        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].block_number, 101);
        assert_eq!(filtered[0].log_index, 1);
        assert_eq!(filtered[1].log_index, 2);
    }

    #[test]
    fn http_evm_poller_requires_inbox_contract_and_agent_address() {
        let missing_contract = RuntimeSnapshot {
            evm_rpc_url: "https://mainnet.base.org".to_string(),
            evm_address: Some("0x1111111111111111111111111111111111111111".to_string()),
            ..RuntimeSnapshot::default()
        };
        assert!(HttpEvmPoller::from_snapshot(&missing_contract).is_err());

        let missing_agent = RuntimeSnapshot {
            evm_rpc_url: "https://mainnet.base.org".to_string(),
            inbox_contract_address: Some("0x2222222222222222222222222222222222222222".to_string()),
            ..RuntimeSnapshot::default()
        };
        assert!(HttpEvmPoller::from_snapshot(&missing_agent).is_err());
    }

    #[test]
    fn evm_read_tool_returns_hex_balance_in_host_mode() {
        stable::init_storage();
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be set");

        let out = block_on_with_spin(evm_read_tool(
            r#"{"method":"eth_getBalance","address":"0x1111111111111111111111111111111111111111"}"#,
        ))
        .expect("evm_read should succeed in host-mode stub");

        assert_eq!(out, "0x1");
    }

    #[test]
    fn fetch_wallet_balance_sync_read_discovers_usdc_and_reads_balances() {
        let snapshot = RuntimeSnapshot {
            evm_rpc_url: "https://mainnet.base.org".to_string(),
            evm_address: Some("0x1111111111111111111111111111111111111111".to_string()),
            inbox_contract_address: Some("0x2222222222222222222222222222222222222222".to_string()),
            wallet_balance_sync: crate::domain::types::WalletBalanceSyncConfig {
                max_response_bytes: 256,
                discover_usdc_via_inbox: true,
                ..crate::domain::types::WalletBalanceSyncConfig::default()
            },
            ..RuntimeSnapshot::default()
        };

        let read = block_on_with_spin(fetch_wallet_balance_sync_read(&snapshot))
            .expect("wallet balance sync read should succeed");
        assert_eq!(read.eth_balance_wei_hex, "0x1");
        assert_eq!(read.usdc_balance_raw_hex, "0x2a");
        assert_eq!(
            read.usdc_contract_address,
            "0x3333333333333333333333333333333333333333"
        );
    }

    #[test]
    fn fetch_wallet_balance_sync_read_prefers_explicit_usdc_contract_override() {
        let snapshot = RuntimeSnapshot {
            evm_rpc_url: "https://mainnet.base.org".to_string(),
            evm_address: Some("0x1111111111111111111111111111111111111111".to_string()),
            wallet_balance: crate::domain::types::WalletBalanceSnapshot {
                usdc_contract_address: Some(
                    "0x4444444444444444444444444444444444444444".to_string(),
                ),
                ..crate::domain::types::WalletBalanceSnapshot::default()
            },
            wallet_balance_sync: crate::domain::types::WalletBalanceSyncConfig {
                max_response_bytes: 256,
                discover_usdc_via_inbox: false,
                ..crate::domain::types::WalletBalanceSyncConfig::default()
            },
            ..RuntimeSnapshot::default()
        };

        let read = block_on_with_spin(fetch_wallet_balance_sync_read(&snapshot))
            .expect("wallet balance sync read should succeed with explicit usdc contract");
        assert_eq!(
            read.usdc_contract_address,
            "0x4444444444444444444444444444444444444444"
        );
        assert_eq!(read.usdc_balance_raw_hex, "0x2a");
    }

    #[test]
    fn fetch_wallet_balance_sync_read_requires_usdc_source() {
        let snapshot = RuntimeSnapshot {
            evm_rpc_url: "https://mainnet.base.org".to_string(),
            evm_address: Some("0x1111111111111111111111111111111111111111".to_string()),
            wallet_balance_sync: crate::domain::types::WalletBalanceSyncConfig {
                max_response_bytes: 256,
                discover_usdc_via_inbox: false,
                ..crate::domain::types::WalletBalanceSyncConfig::default()
            },
            ..RuntimeSnapshot::default()
        };

        let err = block_on_with_spin(fetch_wallet_balance_sync_read(&snapshot))
            .expect_err("missing usdc source should fail");
        assert!(err.contains("usdc contract address is not configured"));
    }

    #[test]
    fn control_plane_outcalls_use_safe_response_cap() {
        let snapshot = RuntimeSnapshot {
            evm_rpc_url: "https://mainnet.base.org".to_string(),
            evm_rpc_max_response_bytes: 256,
            ..RuntimeSnapshot::default()
        };
        let rpc = HttpEvmRpcClient::from_snapshot(&snapshot).expect("rpc client should build");
        assert_eq!(rpc.control_plane_max_response_bytes(), 4_096);
    }

    #[test]
    fn classify_evm_failure_maps_response_too_large_errors() {
        let failure = classify_evm_failure("HTTP body exceeds size limit");
        assert_eq!(
            failure,
            crate::domain::types::RecoveryFailure::Outcall(crate::domain::types::OutcallFailure {
                kind: crate::domain::types::OutcallFailureKind::ResponseTooLarge,
                retry_after_secs: None,
                observed_response_bytes: None,
            })
        );
    }

    #[test]
    fn classify_evm_failure_maps_rate_limit_status_errors() {
        let failure = classify_evm_failure("evm rpc returned status 429");
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
    fn classify_evm_failure_maps_missing_configuration_errors() {
        let failure = classify_evm_failure("evm rpc url is not configured");
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
    fn classify_evm_failure_maps_decode_errors_to_invalid_response() {
        let failure = classify_evm_failure("failed to parse eth_getLogs response JSON: bad json");
        assert_eq!(
            failure,
            crate::domain::types::RecoveryFailure::Outcall(crate::domain::types::OutcallFailure {
                kind: crate::domain::types::OutcallFailureKind::InvalidResponse,
                retry_after_secs: None,
                observed_response_bytes: None,
            })
        );
    }

    struct FixedSignatureSigner;

    #[async_trait(?Send)]
    impl SignerPort for FixedSignatureSigner {
        async fn sign_message(&self, _message_hash: &str) -> Result<String, String> {
            Ok(format!("0x{}", "11".repeat(64)))
        }
    }

    #[test]
    fn send_eth_tool_returns_tx_hash_in_host_mode() {
        stable::init_storage();
        stable::set_evm_rpc_url("https://mainnet.base.org".to_string())
            .expect("rpc url should be set");
        stable::set_ecdsa_key_name("dfx_test_key".to_string()).expect("key should be set");
        stable::set_evm_address(Some(
            "0x1111111111111111111111111111111111111111".to_string(),
        ))
        .expect("address should be set");

        let signer = FixedSignatureSigner;
        let tx_hash = block_on_with_spin(send_eth_tool(
            r#"{"to":"0x2222222222222222222222222222222222222222","value_wei":"1"}"#,
            &signer,
        ))
        .expect("send_eth should succeed");

        assert_eq!(
            tx_hash,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[cfg(all(not(feature = "anvil_e2e"), not(target_arch = "wasm32")))]
    #[test]
    #[ignore = "Enable feature `anvil_e2e` and ensure `anvil` is installed to run this E2E test"]
    fn placeholder_http_evm_poller_e2e_against_anvil() {}

    #[cfg(all(feature = "anvil_e2e", not(target_arch = "wasm32")))]
    #[test]
    fn http_evm_poller_e2e_against_anvil() {
        let port = find_free_local_port();
        let _anvil = start_anvil(port).expect("anvil must start for E2E test");

        with_host_rpc_mode_real(|| {
            let rpc_url = format!("http://127.0.0.1:{port}");
            let rpc_snapshot = RuntimeSnapshot {
                evm_rpc_url: rpc_url,
                evm_rpc_max_response_bytes: 65_536,
                evm_cursor: EvmPollCursor {
                    chain_id: 31_337,
                    ..EvmPollCursor::default()
                },
                ..RuntimeSnapshot::default()
            };
            let rpc = HttpEvmRpcClient::from_snapshot(&rpc_snapshot)
                .expect("rpc client should initialize");
            let chain_id = block_on_with_spin(rpc.rpc_call(
                "eth_chainId",
                json!([]),
                rpc.control_plane_max_response_bytes(),
            ))
            .expect("host rpc call should reach anvil");
            assert_eq!(
                chain_id
                    .get("result")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                "0x7a69"
            );

            let accounts = anvil_accounts(&rpc).expect("anvil accounts should be available");
            let deployer = accounts[0].clone();
            let payer = accounts[1].clone();
            let automaton = "0x1111111111111111111111111111111111111111".to_string();
            let message = "survival ping";
            let usdc_amount = U256::from(1_500_000u64);
            let eth_amount = U256::from(1_000_000_000_000_000u64);

            let mock_usdc_bytecode =
                load_contract_creation_bytecode("evm/out/MockUSDC.sol/MockUSDC.json")
                    .expect("mock usdc artifact should load");
            let mock_usdc = deploy_contract(&rpc, &deployer, &mock_usdc_bytecode)
                .expect("mock usdc should deploy");

            let inbox_base_bytecode =
                load_contract_creation_bytecode("evm/out/Inbox.sol/Inbox.json")
                    .expect("inbox artifact should load");
            let inbox_constructor_data = encode_constructor_single_address(&mock_usdc)
                .expect("inbox constructor args should encode");
            let inbox_bytecode =
                append_constructor_args(&inbox_base_bytecode, &inbox_constructor_data);
            let inbox =
                deploy_contract(&rpc, &deployer, &inbox_bytecode).expect("inbox should deploy");

            let mint_data = encode_call_address_u256("mint(address,uint256)", &payer, usdc_amount)
                .expect("mint calldata should encode");
            send_transaction(
                &rpc,
                &deployer,
                Some(mock_usdc.as_str()),
                mint_data.as_str(),
                None,
            )
            .expect("mint should succeed");

            let approve_data =
                encode_call_address_u256("approve(address,uint256)", &inbox, usdc_amount)
                    .expect("approve calldata should encode");
            send_transaction(
                &rpc,
                &payer,
                Some(mock_usdc.as_str()),
                approve_data.as_str(),
                None,
            )
            .expect("approve should succeed");

            let queue_message_data =
                encode_queue_message_calldata(&automaton, message, usdc_amount)
                    .expect("queueMessage calldata should encode");
            send_transaction(
                &rpc,
                &payer,
                Some(inbox.as_str()),
                queue_message_data.as_str(),
                Some(eth_amount),
            )
            .expect("queueMessage should succeed");

            let snapshot = RuntimeSnapshot {
                evm_rpc_url: rpc_snapshot.evm_rpc_url.clone(),
                evm_rpc_max_response_bytes: rpc_snapshot.evm_rpc_max_response_bytes,
                evm_address: Some(automaton.clone()),
                inbox_contract_address: Some(inbox.clone()),
                evm_cursor: EvmPollCursor {
                    chain_id: 31_337,
                    next_block: 0,
                    next_log_index: 0,
                    confirmation_depth: 0,
                    ..EvmPollCursor::default()
                },
                ..RuntimeSnapshot::default()
            };
            let poller = HttpEvmPoller::from_snapshot(&snapshot).expect("poller should initialize");
            let result = block_on_with_spin(poller.poll(&snapshot.evm_cursor))
                .expect("poll should succeed against anvil");
            assert!(
                result.cursor.next_block >= 1,
                "cursor should advance after polling anvil head"
            );
            assert_eq!(
                result.events.len(),
                1,
                "exactly one route-matching MessageQueued event is expected"
            );

            let event = &result.events[0];
            let decoded =
                decode_message_queued_payload(&event.payload).expect("event payload should decode");
            assert_eq!(
                decoded.sender,
                normalize_address(&payer).unwrap_or_default()
            );
            assert_eq!(decoded.message, message);
            assert_eq!(decoded.usdc_amount, usdc_amount);
            assert_eq!(decoded.eth_amount, eth_amount);

            let automaton_eth_balance = parse_hex_u256(
                &block_on_with_spin(rpc.eth_get_balance(&automaton))
                    .expect("eth balance should be readable"),
                "automaton eth balance",
            )
            .expect("automaton eth balance should parse");
            assert_eq!(
                automaton_eth_balance, eth_amount,
                "automaton should receive forwarded ETH payment"
            );

            let usdc_balance_call = encode_call_address("balanceOf(address)", &automaton)
                .expect("balanceOf calldata should encode");
            let automaton_usdc_balance = parse_hex_u256(
                &block_on_with_spin(rpc.eth_call(&mock_usdc, &usdc_balance_call))
                    .expect("usdc balance call should succeed"),
                "automaton usdc balance",
            )
            .expect("automaton usdc balance should parse");
            assert_eq!(
                automaton_usdc_balance, usdc_amount,
                "automaton should receive forwarded USDC payment"
            );
        });
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    #[derive(Debug, PartialEq, Eq)]
    struct DecodedMessageQueuedPayload {
        sender: String,
        message: String,
        usdc_amount: U256,
        eth_amount: U256,
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn anvil_accounts(rpc: &HttpEvmRpcClient) -> Result<Vec<String>, String> {
        let response = block_on_with_spin(rpc.rpc_call(
            "eth_accounts",
            json!([]),
            rpc.control_plane_max_response_bytes(),
        ))?;
        let result = response
            .get("result")
            .and_then(Value::as_array)
            .ok_or_else(|| "eth_accounts result was missing".to_string())?;
        let mut accounts = Vec::with_capacity(result.len());
        for value in result {
            let account = value
                .as_str()
                .ok_or_else(|| "eth_accounts result must contain strings".to_string())?;
            accounts.push(normalize_address(account)?);
        }
        if accounts.len() < 2 {
            return Err("anvil did not return enough unlocked accounts".to_string());
        }
        Ok(accounts)
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn load_contract_creation_bytecode(artifact_path: &str) -> Result<String, String> {
        let artifact_abs_path = project_root().join(artifact_path);
        let artifact_content = fs::read_to_string(&artifact_abs_path).map_err(|error| {
            format!(
                "failed to read contract artifact {}: {error}",
                artifact_abs_path.display()
            )
        })?;
        let json: Value = serde_json::from_str(&artifact_content).map_err(|error| {
            format!(
                "failed to parse contract artifact {} as JSON: {error}",
                artifact_abs_path.display()
            )
        })?;
        let bytecode = json
            .pointer("/bytecode/object")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "contract artifact {} is missing bytecode.object",
                    artifact_abs_path.display()
                )
            })?;
        normalize_hex_blob(bytecode, "artifact bytecode")
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn deploy_contract(
        rpc: &HttpEvmRpcClient,
        from: &str,
        creation_bytecode: &str,
    ) -> Result<String, String> {
        let receipt = send_transaction(rpc, from, None, creation_bytecode, None)?;
        let contract_address = receipt
            .get("contractAddress")
            .and_then(Value::as_str)
            .ok_or_else(|| "transaction receipt missing contractAddress".to_string())?;
        normalize_address(contract_address)
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn send_transaction(
        rpc: &HttpEvmRpcClient,
        from: &str,
        to: Option<&str>,
        data: &str,
        value_wei: Option<U256>,
    ) -> Result<Value, String> {
        let mut tx = Map::new();
        tx.insert("from".to_string(), Value::String(normalize_address(from)?));
        if let Some(to) = to {
            tx.insert("to".to_string(), Value::String(normalize_address(to)?));
        }
        tx.insert(
            "data".to_string(),
            Value::String(normalize_hex_blob(data, "transaction data")?),
        );
        if let Some(value) = value_wei {
            tx.insert("value".to_string(), Value::String(format!("0x{value:x}")));
        }

        let response = block_on_with_spin(rpc.rpc_call(
            "eth_sendTransaction",
            Value::Array(vec![Value::Object(tx)]),
            rpc.control_plane_max_response_bytes(),
        ))?;
        let tx_hash = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| "eth_sendTransaction result was missing".to_string())
            .and_then(|value| normalize_hex_blob(value, "transaction hash"))?;

        wait_for_receipt(rpc, &tx_hash)
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn wait_for_receipt(rpc: &HttpEvmRpcClient, tx_hash: &str) -> Result<Value, String> {
        for _ in 0..50 {
            let response = block_on_with_spin(rpc.rpc_call(
                "eth_getTransactionReceipt",
                json!([tx_hash]),
                rpc.control_plane_max_response_bytes(),
            ))?;
            if let Some(receipt) = response.get("result") {
                if !receipt.is_null() {
                    return Ok(receipt.clone());
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(format!(
            "transaction receipt was not mined in time for {tx_hash}"
        ))
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn encode_constructor_single_address(address: &str) -> Result<String, String> {
        Ok(format!("0x{}", encode_address_word_hex(address)?))
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn append_constructor_args(bytecode: &str, encoded_args: &str) -> String {
        format!(
            "0x{}{}",
            bytecode.trim_start_matches("0x"),
            encoded_args.trim_start_matches("0x")
        )
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn encode_call_address_u256(
        signature: &str,
        address: &str,
        amount: U256,
    ) -> Result<String, String> {
        Ok(format!(
            "0x{}{}{}",
            function_selector_hex(signature),
            encode_address_word_hex(address)?,
            encode_u256_word_hex(amount)
        ))
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn encode_call_address(signature: &str, address: &str) -> Result<String, String> {
        Ok(format!(
            "0x{}{}",
            function_selector_hex(signature),
            encode_address_word_hex(address)?
        ))
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn encode_queue_message_calldata(
        automaton: &str,
        message: &str,
        usdc_amount: U256,
    ) -> Result<String, String> {
        let message_hex = hex::encode(message.as_bytes());
        let message_padding = "0".repeat((64 - (message_hex.len() % 64)) % 64);
        Ok(format!(
            "0x{}{}{}{}{}{}",
            function_selector_hex("queueMessage(address,string,uint256)"),
            encode_address_word_hex(automaton)?,
            encode_u256_word_hex(U256::from(96u64)),
            encode_u256_word_hex(usdc_amount),
            encode_u256_word_hex(U256::from(message.len())),
            message_hex + &message_padding
        ))
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn function_selector_hex(signature: &str) -> String {
        let hash = keccak256(signature.as_bytes());
        hex::encode(&hash.as_slice()[..4])
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn encode_address_word_hex(address: &str) -> Result<String, String> {
        let normalized = normalize_address(address)?;
        Ok(format!("{:0>64}", normalized.trim_start_matches("0x")))
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn encode_u256_word_hex(value: U256) -> String {
        format!("{value:064x}")
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn decode_message_queued_payload(
        payload_hex: &str,
    ) -> Result<DecodedMessageQueuedPayload, String> {
        let payload = normalize_hex_blob(payload_hex, "message queued payload")?;
        let bytes = hex::decode(payload.trim_start_matches("0x"))
            .map_err(|error| format!("failed to decode message queued payload: {error}"))?;
        if bytes.len() < 128 {
            return Err("message queued payload must be at least 128 bytes".to_string());
        }

        let sender = format!("0x{}", hex::encode(&bytes[12..32]));
        let sender = normalize_address(&sender)?;
        let message_offset = read_usize_word(&bytes[32..64], "message offset")?;
        let usdc_amount = U256::from_be_slice(&bytes[64..96]);
        let eth_amount = U256::from_be_slice(&bytes[96..128]);
        if message_offset.saturating_add(32) > bytes.len() {
            return Err("message offset points outside payload".to_string());
        }
        let message_len = read_usize_word(
            &bytes[message_offset..message_offset + 32],
            "message length",
        )?;
        let message_start = message_offset + 32;
        let message_end = message_start.saturating_add(message_len);
        if message_end > bytes.len() {
            return Err("message bytes exceed payload length".to_string());
        }

        let message = std::str::from_utf8(&bytes[message_start..message_end])
            .map_err(|error| format!("message payload is not utf-8: {error}"))?
            .to_string();

        Ok(DecodedMessageQueuedPayload {
            sender,
            message,
            usdc_amount,
            eth_amount,
        })
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn read_usize_word(word: &[u8], field: &str) -> Result<usize, String> {
        if word.len() != 32 {
            return Err(format!("{field} word must be 32 bytes"));
        }
        let size = std::mem::size_of::<usize>();
        if word[..(32 - size)].iter().any(|byte| *byte != 0) {
            return Err(format!("{field} overflowed usize"));
        }
        let mut value = 0usize;
        for byte in &word[(32 - size)..] {
            value = (value << 8) | usize::from(*byte);
        }
        Ok(value)
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn find_free_local_port() -> u16 {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("ephemeral port binding should work");
        listener
            .local_addr()
            .expect("listener local addr should be available")
            .port()
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn start_anvil(port: u16) -> Result<ChildProcessGuard, String> {
        let child = Command::new("anvil")
            .args([
                "--chain-id",
                "31337",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--silent",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("failed to start anvil process: {error}"))?;
        let mut guard = ChildProcessGuard { child };
        wait_for_anvil_rpc(port).inspect_err(|_error| {
            let _ = guard.child.kill();
        })?;
        Ok(guard)
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn wait_for_anvil_rpc(port: u16) -> Result<(), String> {
        let url = format!("http://127.0.0.1:{port}");
        let request_body = json!({
            "jsonrpc": "2.0",
            "method": "eth_chainId",
            "params": [],
            "id": 1
        })
        .to_string();

        for _ in 0..50 {
            let response = ureq::post(&url)
                .set("content-type", "application/json")
                .send_string(&request_body);
            if let Ok(response) = response {
                if response.status() == 200 {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_millis(100));
        }

        Err("anvil rpc did not become ready in time".to_string())
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    struct ChildProcessGuard {
        child: Child,
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    impl Drop for ChildProcessGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "anvil_e2e"))]
    fn with_host_rpc_mode_real<T>(f: impl FnOnce() -> T) -> T {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("host rpc mode lock should not be poisoned");

        let previous = std::env::var_os(HOST_EVM_RPC_MODE_ENV);
        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var(HOST_EVM_RPC_MODE_ENV, "real");
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        match previous {
            Some(value) => {
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::set_var(HOST_EVM_RPC_MODE_ENV, value);
                }
            }
            None => {
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::remove_var(HOST_EVM_RPC_MODE_ENV);
                }
            }
        }

        match result {
            Ok(output) => output,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}
