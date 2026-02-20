use crate::domain::cycle_admission::{
    affordability_requirements, can_afford, estimate_operation_cost, OperationClass,
    DEFAULT_RESERVE_FLOOR_CYCLES, DEFAULT_SAFETY_MARGIN_BPS,
};
use crate::domain::types::{EvmEvent, EvmPollCursor, RuntimeSnapshot};
use crate::storage::stable;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

#[cfg(target_arch = "wasm32")]
use candid::Nat;
#[cfg(target_arch = "wasm32")]
use ic_cdk::management_canister::{http_request, HttpHeader, HttpMethod, HttpRequestArgs};

const MAX_EVM_RPC_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BLOCK_RANGE_PER_POLL: u64 = 1_000;
const DEFAULT_MAX_LOGS_PER_POLL: usize = 200;

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
struct HttpEvmRpcClient {
    rpc_url: String,
    fallback_rpc_url: Option<String>,
    max_response_bytes: u64,
}

impl HttpEvmRpcClient {
    fn from_snapshot(snapshot: &RuntimeSnapshot) -> Result<Self, String> {
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

    async fn eth_block_number(&self) -> Result<u64, String> {
        let response = self
            .rpc_call("eth_blockNumber", json!([]), 256)
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

    async fn eth_get_balance(&self, address: &str) -> Result<String, String> {
        let response = self
            .rpc_call("eth_getBalance", json!([address, "latest"]), 256)
            .await
            .map_err(|error| format!("eth_getBalance failed: {error}"))?;
        let raw = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| "eth_getBalance result was missing".to_string())?;
        normalize_hex_quantity(raw, "eth_getBalance result")
    }

    async fn eth_call(&self, address: &str, calldata: &str) -> Result<String, String> {
        let response = self
            .rpc_call(
                "eth_call",
                json!([{"to": address, "data": calldata}, "latest"]),
                4096,
            )
            .await
            .map_err(|error| format!("eth_call failed: {error}"))?;
        let raw = response
            .get("result")
            .and_then(Value::as_str)
            .ok_or_else(|| "eth_call result was missing".to_string())?;
        normalize_hex_blob(raw, "eth_call result")
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
