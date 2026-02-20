use crate::domain::cycle_admission::{
    affordability_requirements, can_afford, estimate_operation_cost, OperationClass,
    DEFAULT_RESERVE_FLOOR_CYCLES, DEFAULT_SAFETY_MARGIN_BPS,
};
use crate::domain::types::{EvmEvent, EvmPollCursor, RuntimeSnapshot};
use crate::storage::stable;
use crate::tools::SignerPort;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::{length_of_length, BufMut, Encodable, Header};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};
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
    log_filter_address: Option<String>,
}

impl HttpEvmPoller {
    pub fn from_snapshot(snapshot: &RuntimeSnapshot) -> Result<Self, String> {
        let rpc = HttpEvmRpcClient::from_snapshot(snapshot)?;
        Ok(Self {
            rpc,
            max_logs_per_poll: DEFAULT_MAX_LOGS_PER_POLL,
            log_filter_address: snapshot.evm_address.clone(),
        })
    }
}

#[async_trait(?Send)]
impl EvmPoller for HttpEvmPoller {
    async fn poll(&self, cursor: &EvmPollCursor) -> Result<EvmPollResult, String> {
        let latest_block = self.rpc.eth_block_number().await?;
        let from_block = cursor.next_block;
        let to_block = latest_block.min(from_block.saturating_add(MAX_BLOCK_RANGE_PER_POLL));

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
                self.log_filter_address.as_deref(),
                self.rpc.max_response_bytes,
            )
            .await?;

        let mut events = Vec::new();
        for log in logs.into_iter().take(self.max_logs_per_poll) {
            events.push(EvmEvent {
                chain_id: cursor.chain_id,
                block_number: parse_hex_u64(
                    log.block_number
                        .as_deref()
                        .ok_or_else(|| "rpc log missing blockNumber".to_string())?,
                    "blockNumber",
                )?,
                log_index: parse_hex_u64(
                    log.log_index
                        .as_deref()
                        .ok_or_else(|| "rpc log missing logIndex".to_string())?,
                    "logIndex",
                )?,
                source: normalize_address(&log.address)?,
                payload: normalize_hex_blob(&log.data, "data")?,
            });
        }

        Ok(EvmPollResult {
            cursor: EvmPollCursor {
                chain_id: cursor.chain_id,
                next_block: to_block.saturating_add(1),
                next_log_index: 0,
            },
            events,
        })
    }
}

pub struct MockEvmPoller;

#[async_trait(?Send)]
impl EvmPoller for MockEvmPoller {
    async fn poll(&self, cursor: &EvmPollCursor) -> Result<EvmPollResult, String> {
        let next_block = cursor.next_block.saturating_add(1);
        let next_log_index = cursor.next_log_index.saturating_add(1);

        let events = vec![EvmEvent {
            chain_id: cursor.chain_id,
            block_number: next_block,
            log_index: next_log_index,
            source: "mock_chain".to_string(),
            payload: "agent.heartbeat".to_string(),
        }];

        Ok(EvmPollResult {
            cursor: EvmPollCursor {
                chain_id: cursor.chain_id,
                next_block,
                next_log_index,
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
        let response = self
            .rpc_call(
                "eth_getBalance",
                json!([address, "latest"]),
                self.control_plane_max_response_bytes(),
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
        let response = self
            .rpc_call(
                "eth_call",
                json!([{"to": address, "data": calldata}, "latest"]),
                self.control_plane_max_response_bytes(),
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
        _url: &str,
        body: &[u8],
        _max_response_bytes: u64,
    ) -> Result<Vec<u8>, String> {
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
            "eth_call" => json!({"jsonrpc":"2.0","id":1,"result":"0x"}),
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

#[cfg(target_arch = "wasm32")]
fn liquid_cycle_balance() -> u128 {
    ic_cdk::api::canister_liquid_cycle_balance()
}

#[cfg(not(target_arch = "wasm32"))]
fn liquid_cycle_balance() -> u128 {
    u128::MAX
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
    address: String,
    data: String,
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
    fn control_plane_outcalls_use_safe_response_cap() {
        let snapshot = RuntimeSnapshot {
            evm_rpc_url: "https://mainnet.base.org".to_string(),
            evm_rpc_max_response_bytes: 256,
            ..RuntimeSnapshot::default()
        };
        let rpc = HttpEvmRpcClient::from_snapshot(&snapshot).expect("rpc client should build");
        assert_eq!(rpc.control_plane_max_response_bytes(), 4_096);
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
}
