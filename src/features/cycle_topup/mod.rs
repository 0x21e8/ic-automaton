use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::{length_of_length, BufMut, Encodable, Header};
use async_trait::async_trait;
use candid::{CandidType, Nat, Principal};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::str::FromStr;

pub(crate) const TOPUP_MIN_OPERATIONAL_CYCLES: u128 = 250_000_000_000;
pub(crate) const TOPUP_MIN_USDC_AVAILABLE_RAW: u64 = 10_000_000;
const DEFAULT_EVM_GAS_LIMIT: u64 = 250_000;
const DEFAULT_PRIORITY_FEE_PER_GAS_WEI: u64 = 1_000_000_000;
const EMPTY_ACCESS_LIST_RLP_LEN: usize = 1;

const SELECTOR_ERC20_BALANCE_OF: &str = "70a08231";
const SELECTOR_ERC20_APPROVE: &str = "095ea7b3";
const SELECTOR_LOCK1: &str = "3455fccc";

fn current_time_ns() -> u64 {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::time();

    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos().try_into().unwrap_or(u64::MAX))
            .unwrap_or_default()
    }
}

fn current_canister_id() -> Principal {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::id();

    #[cfg(not(target_arch = "wasm32"))]
    return Principal::anonymous();
}

fn current_cycle_balance128() -> u128 {
    #[cfg(target_arch = "wasm32")]
    return ic_cdk::api::canister_balance128();

    #[cfg(not(target_arch = "wasm32"))]
    return u128::MAX;
}

#[allow(dead_code)]
#[async_trait(?Send)]
pub trait EvmPort {
    async fn sign_message(&self, message_hash: &str) -> Result<String, String>;
    async fn evm_rpc_call(&self, method: &str, params: &str) -> Result<String, String>;
}

pub trait StoragePort {
    fn load_state(&self) -> Option<TopUpStage>;
    fn save_state(&self, state: &TopUpStage);
    fn clear_state(&self);
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TopUpConfig {
    pub evm_address: String,
    pub usdc_contract_address: String,
    pub onesec_locker_address: String,
    pub evm_chain_id: u64,
    pub onesec_canister: Principal,
    pub bridged_usdc_ledger: Principal,
    pub kong_backend: Principal,
    pub icp_ledger: Principal,
    pub cmc: Principal,
    pub target_canister: Option<Principal>,
    pub min_usdc_reserve: u64,
    pub max_usdc_per_topup: u64,
    pub max_slippage_pct: f64,
    pub max_bridge_polls: u8,
    pub lock_confirmations: u8,
}

impl Default for TopUpConfig {
    fn default() -> Self {
        Self {
            evm_address: String::new(),
            usdc_contract_address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_string(),
            onesec_locker_address: "0xAe2351B15cFf68b5863c6690dCA58Dce383bf45A".to_string(),
            evm_chain_id: 8453,
            onesec_canister: Principal::anonymous(),
            bridged_usdc_ledger: Principal::anonymous(),
            kong_backend: Principal::anonymous(),
            icp_ledger: Principal::anonymous(),
            cmc: Principal::anonymous(),
            target_canister: None,
            min_usdc_reserve: 10_000_000,
            max_usdc_per_topup: 50_000_000,
            max_slippage_pct: 5.0,
            max_bridge_polls: 60,
            lock_confirmations: 12,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TopUpStage {
    Preflight,
    ApprovingLocker {
        usdc_amount: u64,
    },
    WaitingApprovalConfirmation {
        usdc_amount: u64,
        tx_hash: String,
    },
    LockingUSDC {
        usdc_amount: u64,
    },
    WaitingLockConfirmation {
        usdc_amount: u64,
        tx_hash: String,
        confirmations: u8,
    },
    ValidatingOnOnesec {
        usdc_amount: u64,
        tx_hash: String,
    },
    WaitingForBridgedUSDC {
        usdc_amount: u64,
        transfer_id: u128,
        polls: u8,
    },
    ApprovingKongSwap {
        bridged_usdc_amount: u64,
        usdc_spent: u64,
    },
    SwappingToICP {
        bridged_usdc_amount: u64,
        usdc_spent: u64,
    },
    TransferringToCMC {
        icp_amount: u64,
        usdc_spent: u64,
    },
    MintingCycles {
        block_index: u64,
        usdc_spent: u64,
    },
    Completed {
        cycles_minted: u128,
        usdc_spent: u64,
        completed_at_ns: u64,
    },
    Failed {
        stage: String,
        error: String,
        failed_at_ns: u64,
        attempts: u32,
    },
}

impl TopUpStage {
    fn stage_name(&self) -> &'static str {
        match self {
            Self::Preflight => "Preflight",
            Self::ApprovingLocker { .. } => "ApprovingLocker",
            Self::WaitingApprovalConfirmation { .. } => "WaitingApprovalConfirmation",
            Self::LockingUSDC { .. } => "LockingUSDC",
            Self::WaitingLockConfirmation { .. } => "WaitingLockConfirmation",
            Self::ValidatingOnOnesec { .. } => "ValidatingOnOnesec",
            Self::WaitingForBridgedUSDC { .. } => "WaitingForBridgedUSDC",
            Self::ApprovingKongSwap { .. } => "ApprovingKongSwap",
            Self::SwappingToICP { .. } => "SwappingToICP",
            Self::TransferringToCMC { .. } => "TransferringToCMC",
            Self::MintingCycles { .. } => "MintingCycles",
            Self::Completed { .. } => "Completed",
            Self::Failed { .. } => "Failed",
        }
    }

    fn is_waiting(&self) -> bool {
        matches!(
            self,
            Self::WaitingApprovalConfirmation { .. }
                | Self::WaitingLockConfirmation { .. }
                | Self::WaitingForBridgedUSDC { .. }
        )
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed { .. } | Self::Failed { .. })
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TopUpStatus {
    Idle,
    InProgress {
        stage: TopUpStage,
    },
    Completed {
        cycles_minted: u128,
        usdc_spent: u64,
        completed_at_ns: u64,
    },
    Failed {
        stage: String,
        error: String,
        failed_at_ns: u64,
        attempts: u32,
    },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Account {
    owner: Principal,
    subaccount: Option<Vec<u8>>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Icrc2ApproveArg {
    spender: Account,
    amount: Nat,
    expected_allowance: Option<Nat>,
    expires_at: Option<u64>,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    from_subaccount: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum ApproveError {
    BadFee { expected_fee: Nat },
    InsufficientFunds { balance: Nat },
    AllowanceChanged { current_allowance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    Expired { ledger_time: u64 },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

type Icrc2ApproveResult = Result<Nat, ApproveError>;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Icrc1TransferArg {
    to: Account,
    amount: Nat,
    memo: Option<Vec<u8>>,
    fee: Option<Nat>,
    from_subaccount: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum TransferError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

type Icrc1TransferResult = Result<Nat, TransferError>;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum TxId {
    BlockIndex(Nat),
    TransactionHash(String),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct SwapArgs {
    pay_token: String,
    pay_amount: Nat,
    pay_tx_id: Option<TxId>,
    receive_token: String,
    receive_amount: Option<Nat>,
    receive_address: Option<String>,
    max_slippage: Option<f64>,
    referred_by: Option<String>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
struct SwapReply {
    tx_id: u64,
    request_id: u64,
    status: String,
    pay_symbol: String,
    pay_amount: Nat,
    receive_symbol: String,
    receive_amount: Nat,
    mid_price: f64,
    price: f64,
    slippage: f64,
    claim_ids: Vec<u64>,
    ts: u64,
}

type KongSwapResult = Result<SwapReply, String>;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct NotifyTopUpArg {
    block_index: u64,
    canister_id: Principal,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum NotifyError {
    Refunded {
        block_index: Option<u64>,
        reason: String,
    },
    InvalidTransaction(String),
    Other {
        error_code: u64,
        error_message: String,
    },
    Processing,
    TransactionTooOld(u64),
}

type NotifyTopUpResult = Result<Nat, NotifyError>;

#[allow(clippy::upper_case_acronyms)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum Token {
    ICP,
    USDC,
    USDT,
    #[serde(rename = "ckBTC")]
    CkBtc,
    #[serde(rename = "cbBTC")]
    CbBtc,
    BOB,
    GLDT,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum EvmChain {
    Base,
    Ethereum,
    Arbitrum,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct TransferFee {
    token: Token,
    evm_chain: EvmChain,
    min_amount: Nat,
    max_amount: Nat,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct EvmAccount {
    address: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct EvmTx {
    hash: String,
    log_index: Option<u64>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum OnesecIcpAccount {
    ICRC {
        owner: Principal,
        subaccount: Option<Vec<u8>>,
    },
    AccountId(String),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct TransferEvmToIcpArg {
    token: Token,
    evm_chain: EvmChain,
    evm_account: EvmAccount,
    evm_tx: EvmTx,
    icp_account: OnesecIcpAccount,
    evm_amount: u128,
    icp_amount: Option<u128>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct TransferId {
    id: u128,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum TransferResponse {
    Accepted(TransferId),
    Failed { error: String },
    Fetching { block_height: u128 },
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum BridgeTransferStatus {
    Pending,
    Fetching,
    Succeeded { amount: Nat },
    Failed { error: String },
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

#[cfg(all(test, not(target_arch = "wasm32")))]
#[derive(Default, Clone, Debug)]
struct NativeCallMocks {
    get_transfer_fees_results: Vec<Result<Vec<TransferFee>, String>>,
    transfer_evm_to_icp_results: Vec<Result<TransferResponse, String>>,
    get_transfer_results: Vec<Result<BridgeTransferStatus, String>>,
    icrc2_approve_results: Vec<Result<Icrc2ApproveResult, String>>,
    kongswap_results: Vec<Result<KongSwapResult, String>>,
    icrc1_transfer_results: Vec<Result<Icrc1TransferResult, String>>,
    notify_top_up_results: Vec<Result<NotifyTopUpResult, String>>,
    seen_transfer_evm_to_icp_args: Vec<TransferEvmToIcpArg>,
    seen_get_transfer_ids: Vec<u128>,
    seen_icrc2_approve_args: Vec<Icrc2ApproveArg>,
    seen_swap_args: Vec<SwapArgs>,
    seen_transfer_args: Vec<Icrc1TransferArg>,
    seen_notify_args: Vec<NotifyTopUpArg>,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
std::thread_local! {
    static NATIVE_CALL_MOCKS: std::cell::RefCell<NativeCallMocks> =
        std::cell::RefCell::new(NativeCallMocks::default());
}

fn nat_to_u64(value: &Nat, field: &str) -> Result<u64, String> {
    u64::try_from(&value.0).map_err(|_| format!("{field} exceeds u64"))
}

fn nat_to_u128(value: &Nat, field: &str) -> Result<u128, String> {
    u128::try_from(&value.0).map_err(|_| format!("{field} exceeds u128"))
}

fn parse_hex_u64(raw: &str, field: &str) -> Result<u64, String> {
    let normalized = normalize_hex_quantity(raw, field)?;
    let without_prefix = normalized.trim_start_matches("0x");
    if without_prefix.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(without_prefix, 16)
        .map_err(|error| format!("failed to parse {field} as hex u64: {error}"))
}

fn parse_hex_u128(raw: &str, field: &str) -> Result<u128, String> {
    let normalized = normalize_hex_quantity(raw, field)?;
    let without_prefix = normalized.trim_start_matches("0x");
    if without_prefix.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(without_prefix, 16)
        .map_err(|error| format!("failed to parse {field} as hex u128: {error}"))
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

pub(crate) fn normalize_evm_hex_address(raw: &str, field: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let valid = trimmed.len() == 42
        && trimmed.starts_with("0x")
        && trimmed
            .as_bytes()
            .iter()
            .skip(2)
            .all(|byte| byte.is_ascii_hexdigit());
    if !valid {
        return Err(format!("{field} must be a 0x-prefixed 20-byte hex string"));
    }
    Ok(trimmed)
}

fn normalize_address(raw: &str) -> Result<String, String> {
    normalize_evm_hex_address(raw, "address")
}

fn encode_u256_word(value: U256) -> String {
    format!("{value:064x}")
}

fn encode_address_word(address: &str) -> Result<String, String> {
    let normalized = normalize_address(address)?;
    Ok(format!("{:0>64}", normalized.trim_start_matches("0x")))
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

fn encode_eip1559_unsigned(tx: &Eip1559UnsignedTx) -> Vec<u8> {
    let payload = alloy_rlp::encode(tx);
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
    use sha3::{Digest, Keccak256};

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

    Err("failed to recover EIP-1559 y_parity".to_string())
}

fn parse_evm_rpc_payload(raw: &str) -> Result<Value, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("evm rpc response was empty".to_string());
    }
    serde_json::from_str::<Value>(trimmed).map_err(|error| format!("invalid evm rpc json: {error}"))
}

fn extract_evm_result_string(raw: &str, field: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"') {
        let value = parse_evm_rpc_payload(trimmed)?;
        if let Some(result) = value.get("result") {
            if result.is_null() {
                return Err(format!("{field} result was null"));
            }
            if let Some(as_str) = result.as_str() {
                return Ok(as_str.to_string());
            }
            return Ok(result.to_string());
        }
        if let Some(as_str) = value.as_str() {
            return Ok(as_str.to_string());
        }
        return Ok(value.to_string());
    }
    Ok(trimmed.to_string())
}

fn extract_evm_result_value(raw: &str) -> Result<Value, String> {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("null") {
        return Ok(Value::Null);
    }
    let value = parse_evm_rpc_payload(trimmed)?;
    Ok(value.get("result").cloned().unwrap_or(value))
}

fn find_usdc_base_fee(fees: &[TransferFee]) -> Result<&TransferFee, String> {
    fees.iter()
        .find(|fee| fee.token == Token::USDC && fee.evm_chain == EvmChain::Base)
        .ok_or_else(|| "missing Onesec USDC/Base fee".to_string())
}

fn encode_principal_for_onesec(principal: &Principal) -> [u8; 32] {
    let mut data1 = [0u8; 32];
    let bytes = principal.as_slice();
    let copy_len = bytes.len().min(30);
    data1[0] = 0x00;
    data1[1] = copy_len as u8;
    data1[2..2 + copy_len].copy_from_slice(&bytes[..copy_len]);
    data1
}

fn encode_erc20_balance_of(address: &str) -> Result<String, String> {
    Ok(format!(
        "0x{}{}",
        SELECTOR_ERC20_BALANCE_OF,
        encode_address_word(address)?
    ))
}

fn encode_approve(spender: &str, amount: u64) -> Result<String, String> {
    Ok(format!(
        "0x{}{}{}",
        SELECTOR_ERC20_APPROVE,
        encode_address_word(spender)?,
        encode_u256_word(U256::from(amount))
    ))
}

fn encode_lock1(amount: u64, data1: &[u8; 32]) -> String {
    format!(
        "0x{}{}{}",
        SELECTOR_LOCK1,
        encode_u256_word(U256::from(amount)),
        hex::encode(data1)
    )
}

fn cmc_subaccount_for_canister(canister_id: &Principal) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x0A]);
    hasher.update(b"canister-id");
    hasher.update(canister_id.as_slice());
    let digest = hasher.finalize();
    let mut subaccount = [0u8; 32];
    subaccount.copy_from_slice(&digest[..32]);
    subaccount
}

pub struct CycleTopUp<E: EvmPort, S: StoragePort> {
    config: TopUpConfig,
    evm: E,
    storage: S,
}

impl<E: EvmPort, S: StoragePort> CycleTopUp<E, S> {
    pub fn new(config: TopUpConfig, evm: E, storage: S) -> Self {
        Self {
            config,
            evm,
            storage,
        }
    }

    pub async fn advance(&self) -> Result<bool, String> {
        let Some(mut state) = self.storage.load_state() else {
            return Ok(true);
        };

        loop {
            let next = match &state {
                TopUpStage::Preflight => self.preflight().await,
                TopUpStage::ApprovingLocker { .. } => self.approve_locker(&state).await,
                TopUpStage::WaitingApprovalConfirmation { .. } => self.poll_tx(&state, 1).await,
                TopUpStage::LockingUSDC { .. } => self.lock_usdc(&state).await,
                TopUpStage::WaitingLockConfirmation { .. } => {
                    self.poll_tx(&state, self.config.lock_confirmations).await
                }
                TopUpStage::ValidatingOnOnesec { .. } => self.validate_on_onesec(&state).await,
                TopUpStage::WaitingForBridgedUSDC { .. } => self.poll_bridge(&state).await,
                TopUpStage::ApprovingKongSwap { .. } => self.approve_kongswap(&state).await,
                TopUpStage::SwappingToICP { .. } => self.swap_to_icp(&state).await,
                TopUpStage::TransferringToCMC { .. } => self.transfer_to_cmc(&state).await,
                TopUpStage::MintingCycles { .. } => self.mint_cycles(&state).await,
                TopUpStage::Completed { .. } | TopUpStage::Failed { .. } => return Ok(true),
            };

            match next {
                Ok(next_state) => {
                    self.storage.save_state(&next_state);
                    state = next_state;
                }
                Err(error) => {
                    let failed = TopUpStage::Failed {
                        stage: state.stage_name().to_string(),
                        error,
                        failed_at_ns: current_time_ns(),
                        attempts: 0,
                    };
                    self.storage.save_state(&failed);
                    return Ok(true);
                }
            }

            if state.is_terminal() {
                return Ok(true);
            }
            if state.is_waiting() {
                return Ok(false);
            }
        }
    }

    pub fn status(&self) -> TopUpStatus {
        topup_status_from_stage(self.storage.load_state())
    }

    pub fn start(&self) -> Result<(), String> {
        match self.storage.load_state() {
            None | Some(TopUpStage::Completed { .. }) => {
                self.storage.save_state(&TopUpStage::Preflight);
                Ok(())
            }
            Some(TopUpStage::Failed { .. }) => {
                Err("top-up is in failed state; call reset() first".to_string())
            }
            Some(_) => Err("top-up already in progress".to_string()),
        }
    }

    pub fn reset(&self) -> Result<(), String> {
        match self.storage.load_state() {
            Some(TopUpStage::Failed { .. }) => {
                self.storage.clear_state();
                Ok(())
            }
            Some(_) => Err("top-up is not in failed state".to_string()),
            None => Err("top-up is idle".to_string()),
        }
    }

    fn target_canister(&self) -> Principal {
        self.config
            .target_canister
            .unwrap_or_else(current_canister_id)
    }

    async fn preflight(&self) -> Result<TopUpStage, String> {
        if current_cycle_balance128() < TOPUP_MIN_OPERATIONAL_CYCLES {
            return Err(format!(
                "insufficient cycles for top-up operation: need at least {TOPUP_MIN_OPERATIONAL_CYCLES}"
            ));
        }

        let balance_calldata = encode_erc20_balance_of(&self.config.evm_address)?;
        let usdc_balance_raw = self
            .evm
            .evm_rpc_call(
                "eth_call",
                &format!(
                    r#"[{{"to":"{}","data":"{}"}}, "latest"]"#,
                    normalize_address(&self.config.usdc_contract_address)?,
                    balance_calldata
                ),
            )
            .await?;
        let usdc_balance = parse_hex_u128(
            &extract_evm_result_string(&usdc_balance_raw, "eth_call")?,
            "USDC balance",
        )?;
        let usdc_balance = u64::try_from(usdc_balance).map_err(|_| "USDC balance exceeds u64")?;

        let available = usdc_balance.saturating_sub(self.config.min_usdc_reserve);
        if available < TOPUP_MIN_USDC_AVAILABLE_RAW {
            return Err(format!(
                "USDC available ({available}) below minimum {}",
                TOPUP_MIN_USDC_AVAILABLE_RAW
            ));
        }
        let usdc_amount = available.min(self.config.max_usdc_per_topup);

        let fees = self.call_get_transfer_fees().await?;
        let fee = find_usdc_base_fee(&fees)?;
        let min_amount = nat_to_u64(&fee.min_amount, "Onesec fee min_amount")?;
        let max_amount = nat_to_u64(&fee.max_amount, "Onesec fee max_amount")?;
        if usdc_amount < min_amount || usdc_amount > max_amount {
            return Err(format!(
                "amount {usdc_amount} outside Onesec bounds [{min_amount}, {max_amount}]"
            ));
        }

        Ok(TopUpStage::ApprovingLocker { usdc_amount })
    }

    async fn approve_locker(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::ApprovingLocker { usdc_amount } = state else {
            return Err("invalid state for ApprovingLocker transition".to_string());
        };

        let calldata = encode_approve(&self.config.onesec_locker_address, *usdc_amount)?;
        let tx_hash = self
            .evm_send_transaction(&self.config.usdc_contract_address, &calldata)
            .await?;
        Ok(TopUpStage::WaitingApprovalConfirmation {
            usdc_amount: *usdc_amount,
            tx_hash,
        })
    }

    async fn poll_tx(
        &self,
        state: &TopUpStage,
        required_confirmations: u8,
    ) -> Result<TopUpStage, String> {
        let (usdc_amount, tx_hash, is_lock_wait) = match state {
            TopUpStage::WaitingApprovalConfirmation {
                usdc_amount,
                tx_hash,
            } => (*usdc_amount, tx_hash.clone(), false),
            TopUpStage::WaitingLockConfirmation {
                usdc_amount,
                tx_hash,
                ..
            } => (*usdc_amount, tx_hash.clone(), true),
            _ => return Err("invalid state for transaction polling".to_string()),
        };

        let receipt_raw = self
            .evm
            .evm_rpc_call(
                "eth_getTransactionReceipt",
                &format!(r#"["{}"]"#, normalize_hex_blob(&tx_hash, "tx hash")?),
            )
            .await?;
        let receipt = extract_evm_result_value(&receipt_raw)?;
        if receipt.is_null() {
            return Ok(state.clone());
        }
        let receipt_object = receipt
            .as_object()
            .ok_or_else(|| "eth_getTransactionReceipt result must be object or null".to_string())?;

        if let Some(status) = receipt_object.get("status").and_then(Value::as_str) {
            let status = parse_hex_u64(status, "receipt status")?;
            if status == 0 {
                return Err(format!("transaction reverted: {tx_hash}"));
            }
        }

        let mut confirmations = 1u64;
        if required_confirmations > 1 {
            let receipt_block = receipt_object
                .get("blockNumber")
                .and_then(Value::as_str)
                .ok_or_else(|| "receipt missing blockNumber".to_string())
                .and_then(|raw| parse_hex_u64(raw, "receipt blockNumber"))?;
            let latest_block_raw = self.evm.evm_rpc_call("eth_blockNumber", "[]").await?;
            let latest_block = parse_hex_u64(
                &extract_evm_result_string(&latest_block_raw, "eth_blockNumber")?,
                "eth_blockNumber",
            )?;
            if latest_block < receipt_block {
                return Err("latest block is behind receipt block".to_string());
            }
            confirmations = latest_block.saturating_sub(receipt_block).saturating_add(1);
        }

        if confirmations < u64::from(required_confirmations) {
            if is_lock_wait {
                return Ok(TopUpStage::WaitingLockConfirmation {
                    usdc_amount,
                    tx_hash,
                    confirmations: confirmations.min(u64::from(u8::MAX)) as u8,
                });
            }
            return Ok(state.clone());
        }

        if is_lock_wait {
            return Ok(TopUpStage::ValidatingOnOnesec {
                usdc_amount,
                tx_hash,
            });
        }
        Ok(TopUpStage::LockingUSDC { usdc_amount })
    }

    async fn lock_usdc(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::LockingUSDC { usdc_amount } = state else {
            return Err("invalid state for LockingUSDC transition".to_string());
        };

        let principal_data = encode_principal_for_onesec(&current_canister_id());
        let calldata = encode_lock1(*usdc_amount, &principal_data);
        let tx_hash = self
            .evm_send_transaction(&self.config.onesec_locker_address, &calldata)
            .await?;
        Ok(TopUpStage::WaitingLockConfirmation {
            usdc_amount: *usdc_amount,
            tx_hash,
            confirmations: 0,
        })
    }

    async fn validate_on_onesec(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::ValidatingOnOnesec {
            usdc_amount,
            tx_hash,
        } = state
        else {
            return Err("invalid state for ValidatingOnOnesec transition".to_string());
        };

        let response = self
            .call_transfer_evm_to_icp(TransferEvmToIcpArg {
                token: Token::USDC,
                evm_chain: EvmChain::Base,
                evm_account: EvmAccount {
                    address: normalize_address(&self.config.evm_address)?,
                },
                evm_tx: EvmTx {
                    hash: normalize_hex_blob(tx_hash, "lock tx hash")?,
                    log_index: None,
                },
                icp_account: OnesecIcpAccount::ICRC {
                    owner: current_canister_id(),
                    subaccount: None,
                },
                evm_amount: u128::from(*usdc_amount),
                icp_amount: None,
            })
            .await?;

        match response {
            TransferResponse::Accepted(transfer_id) => Ok(TopUpStage::WaitingForBridgedUSDC {
                usdc_amount: *usdc_amount,
                transfer_id: transfer_id.id,
                polls: 0,
            }),
            TransferResponse::Fetching { .. } => Ok(state.clone()),
            TransferResponse::Failed { error } => {
                Err(format!("transfer_evm_to_icp failed: {error}"))
            }
        }
    }

    async fn poll_bridge(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::WaitingForBridgedUSDC {
            usdc_amount,
            transfer_id,
            polls,
        } = state
        else {
            return Err("invalid state for WaitingForBridgedUSDC transition".to_string());
        };

        if *polls >= self.config.max_bridge_polls {
            return Err(format!(
                "bridge polling exceeded max attempts for transfer {transfer_id}"
            ));
        }

        match self.call_get_transfer(*transfer_id).await? {
            BridgeTransferStatus::Pending | BridgeTransferStatus::Fetching => {
                Ok(TopUpStage::WaitingForBridgedUSDC {
                    usdc_amount: *usdc_amount,
                    transfer_id: *transfer_id,
                    polls: polls.saturating_add(1),
                })
            }
            BridgeTransferStatus::Failed { error } => {
                Err(format!("bridge transfer failed: {error}"))
            }
            BridgeTransferStatus::Succeeded { amount } => Ok(TopUpStage::ApprovingKongSwap {
                bridged_usdc_amount: nat_to_u64(&amount, "bridged USDC amount")?,
                usdc_spent: *usdc_amount,
            }),
        }
    }

    async fn approve_kongswap(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::ApprovingKongSwap {
            bridged_usdc_amount,
            usdc_spent,
        } = state
        else {
            return Err("invalid state for ApprovingKongSwap transition".to_string());
        };

        let approve_result = self
            .call_icrc2_approve(Icrc2ApproveArg {
                spender: Account {
                    owner: self.config.kong_backend,
                    subaccount: None,
                },
                amount: Nat::from(*bridged_usdc_amount),
                expected_allowance: None,
                expires_at: None,
                fee: None,
                memo: None,
                from_subaccount: None,
                created_at_time: None,
            })
            .await?;

        match approve_result {
            Ok(_) => Ok(TopUpStage::SwappingToICP {
                bridged_usdc_amount: *bridged_usdc_amount,
                usdc_spent: *usdc_spent,
            }),
            Err(error) => Err(format!("icrc2_approve failed: {error:?}")),
        }
    }

    async fn swap_to_icp(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::SwappingToICP {
            bridged_usdc_amount,
            usdc_spent,
        } = state
        else {
            return Err("invalid state for SwappingToICP transition".to_string());
        };

        let swap_result = self
            .call_kongswap_swap(SwapArgs {
                pay_token: format!("IC.{}", self.config.bridged_usdc_ledger),
                pay_amount: Nat::from(*bridged_usdc_amount),
                pay_tx_id: None,
                receive_token: "ICP".to_string(),
                receive_amount: None,
                receive_address: Some(current_canister_id().to_text()),
                max_slippage: Some(self.config.max_slippage_pct),
                referred_by: None,
            })
            .await?;

        let reply = swap_result.map_err(|error| format!("swap failed: {error}"))?;
        if !reply.status.eq_ignore_ascii_case("success") {
            return Err(format!("swap status was {}", reply.status));
        }

        let icp_amount = nat_to_u64(&reply.receive_amount, "swap receive_amount")?;
        Ok(TopUpStage::TransferringToCMC {
            icp_amount,
            usdc_spent: *usdc_spent,
        })
    }

    async fn transfer_to_cmc(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::TransferringToCMC {
            icp_amount,
            usdc_spent,
        } = state
        else {
            return Err("invalid state for TransferringToCMC transition".to_string());
        };

        let target_canister = self.target_canister();
        let cmc_subaccount = cmc_subaccount_for_canister(&target_canister);
        let transfer_result = self
            .call_icrc1_transfer(Icrc1TransferArg {
                to: Account {
                    owner: self.config.cmc,
                    subaccount: Some(cmc_subaccount.to_vec()),
                },
                amount: Nat::from(*icp_amount),
                memo: None,
                fee: None,
                from_subaccount: None,
                created_at_time: None,
            })
            .await?;

        match transfer_result {
            Ok(block_index) => Ok(TopUpStage::MintingCycles {
                block_index: nat_to_u64(&block_index, "icrc1_transfer block index")?,
                usdc_spent: *usdc_spent,
            }),
            Err(error) => Err(format!("icrc1_transfer failed: {error:?}")),
        }
    }

    async fn mint_cycles(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::MintingCycles {
            block_index,
            usdc_spent,
        } = state
        else {
            return Err("invalid state for MintingCycles transition".to_string());
        };

        let notify_result = self
            .call_notify_top_up(NotifyTopUpArg {
                block_index: *block_index,
                canister_id: self.target_canister(),
            })
            .await?;

        match notify_result {
            Ok(cycles_minted) => Ok(TopUpStage::Completed {
                cycles_minted: nat_to_u128(&cycles_minted, "notify_top_up cycles minted")?,
                usdc_spent: *usdc_spent,
                completed_at_ns: current_time_ns(),
            }),
            Err(error) => Err(format!("notify_top_up failed: {error:?}")),
        }
    }

    async fn evm_nonce(&self) -> Result<U256, String> {
        let evm_address = normalize_address(&self.config.evm_address)?;
        let raw = self
            .evm
            .evm_rpc_call(
                "eth_getTransactionCount",
                &format!(r#"["{}", "pending"]"#, evm_address),
            )
            .await?;
        parse_hex_u256(
            &extract_evm_result_string(&raw, "eth_getTransactionCount")?,
            "eth_getTransactionCount",
        )
    }

    async fn evm_gas_price(&self) -> Result<U256, String> {
        let raw = self.evm.evm_rpc_call("eth_gasPrice", "[]").await?;
        parse_hex_u256(
            &extract_evm_result_string(&raw, "eth_gasPrice")?,
            "eth_gasPrice",
        )
    }

    async fn evm_estimate_gas(&self, to: &str, data: &str) -> Result<U256, String> {
        let from = normalize_address(&self.config.evm_address)?;
        let to = normalize_address(to)?;
        let data = normalize_hex_blob(data, "transaction calldata")?;
        let raw = self
            .evm
            .evm_rpc_call(
                "eth_estimateGas",
                &format!(
                    r#"[{{"from":"{}","to":"{}","value":"0x0","data":"{}"}}]"#,
                    from, to, data
                ),
            )
            .await?;
        parse_hex_u256(
            &extract_evm_result_string(&raw, "eth_estimateGas")?,
            "eth_estimateGas",
        )
    }

    async fn evm_send_raw_transaction(&self, tx: &[u8]) -> Result<String, String> {
        let payload = format!("0x{}", hex::encode(tx));
        let raw = self
            .evm
            .evm_rpc_call("eth_sendRawTransaction", &format!(r#"["{}"]"#, payload))
            .await?;
        normalize_hex_blob(
            &extract_evm_result_string(&raw, "eth_sendRawTransaction")?,
            "eth_sendRawTransaction result",
        )
    }

    async fn evm_send_transaction(&self, to: &str, calldata: &str) -> Result<String, String> {
        let to_hex = normalize_address(to)?;
        let to = Address::from_str(&to_hex)
            .map_err(|error| format!("failed to parse destination address: {error}"))?;
        let data_hex = normalize_hex_blob(calldata, "transaction calldata")?;
        let data = Bytes::from(
            hex::decode(data_hex.trim_start_matches("0x"))
                .map_err(|error| format!("calldata must be valid hex: {error}"))?,
        );

        let nonce = self.evm_nonce().await?;
        let base_fee = self.evm_gas_price().await?;
        let max_priority_fee_per_gas = U256::from(DEFAULT_PRIORITY_FEE_PER_GAS_WEI);
        let max_fee_per_gas = base_fee.saturating_add(max_priority_fee_per_gas);
        let gas_limit = self
            .evm_estimate_gas(&to_hex, &data_hex)
            .await
            .unwrap_or_else(|_| U256::from(DEFAULT_EVM_GAS_LIMIT));

        let tx = Eip1559UnsignedTx {
            chain_id: U256::from(self.config.evm_chain_id),
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value: U256::ZERO,
            data,
        };

        let unsigned = encode_eip1559_unsigned(&tx);
        let tx_hash = keccak256(&unsigned);
        let message_hash = format!("0x{}", hex::encode(tx_hash.as_slice()));
        let signature = parse_compact_signature(&self.evm.sign_message(&message_hash).await?)?;
        let y_parity = recover_y_parity(
            &tx_hash,
            &signature,
            &normalize_address(&self.config.evm_address)?,
        )?;
        let r = U256::from_be_slice(&signature[..32]);
        let s = U256::from_be_slice(&signature[32..]);
        let signed = encode_eip1559_signed(&tx, y_parity, r, s);
        self.evm_send_raw_transaction(&signed).await
    }

    #[cfg(target_arch = "wasm32")]
    async fn call_get_transfer_fees(&self) -> Result<Vec<TransferFee>, String> {
        let (fees,): (Vec<TransferFee>,) =
            ic_cdk::call(self.config.onesec_canister, "get_transfer_fees", ())
                .await
                .map_err(|(code, msg)| {
                    format!("onesec.get_transfer_fees failed: {code:?} {msg}")
                })?;
        Ok(fees)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn call_get_transfer_fees(&self) -> Result<Vec<TransferFee>, String> {
        #[cfg(test)]
        {
            NATIVE_CALL_MOCKS.with(|mocks| {
                let mut mocks = mocks.borrow_mut();
                if mocks.get_transfer_fees_results.is_empty() {
                    return Err("missing test mock for get_transfer_fees".to_string());
                }
                mocks.get_transfer_fees_results.remove(0)
            })
        }
        #[cfg(not(test))]
        {
            Err("onesec.get_transfer_fees is unavailable on non-wasm32 targets".to_string())
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn call_transfer_evm_to_icp(
        &self,
        args: TransferEvmToIcpArg,
    ) -> Result<TransferResponse, String> {
        let (result,): (TransferResponse,) =
            ic_cdk::call(self.config.onesec_canister, "transfer_evm_to_icp", (args,))
                .await
                .map_err(|(code, msg)| {
                    format!("onesec.transfer_evm_to_icp failed: {code:?} {msg}")
                })?;
        Ok(result)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn call_transfer_evm_to_icp(
        &self,
        args: TransferEvmToIcpArg,
    ) -> Result<TransferResponse, String> {
        #[cfg(test)]
        {
            NATIVE_CALL_MOCKS.with(|mocks| {
                let mut mocks = mocks.borrow_mut();
                mocks.seen_transfer_evm_to_icp_args.push(args);
                if mocks.transfer_evm_to_icp_results.is_empty() {
                    return Err("missing test mock for transfer_evm_to_icp".to_string());
                }
                mocks.transfer_evm_to_icp_results.remove(0)
            })
        }
        #[cfg(not(test))]
        {
            let _ = args;
            Err("onesec.transfer_evm_to_icp is unavailable on non-wasm32 targets".to_string())
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn call_get_transfer(&self, transfer_id: u128) -> Result<BridgeTransferStatus, String> {
        let (result,): (BridgeTransferStatus,) = ic_cdk::call(
            self.config.onesec_canister,
            "get_transfer",
            (TransferId { id: transfer_id },),
        )
        .await
        .map_err(|(code, msg)| format!("onesec.get_transfer failed: {code:?} {msg}"))?;
        Ok(result)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn call_get_transfer(&self, transfer_id: u128) -> Result<BridgeTransferStatus, String> {
        #[cfg(test)]
        {
            NATIVE_CALL_MOCKS.with(|mocks| {
                let mut mocks = mocks.borrow_mut();
                mocks.seen_get_transfer_ids.push(transfer_id);
                if mocks.get_transfer_results.is_empty() {
                    return Err("missing test mock for get_transfer".to_string());
                }
                mocks.get_transfer_results.remove(0)
            })
        }
        #[cfg(not(test))]
        {
            let _ = transfer_id;
            Err("onesec.get_transfer is unavailable on non-wasm32 targets".to_string())
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn call_icrc2_approve(
        &self,
        args: Icrc2ApproveArg,
    ) -> Result<Icrc2ApproveResult, String> {
        let (result,): (Icrc2ApproveResult,) =
            ic_cdk::call(self.config.bridged_usdc_ledger, "icrc2_approve", (args,))
                .await
                .map_err(|(code, msg)| {
                    format!("bridged_usdc.icrc2_approve call failed: {code:?} {msg}")
                })?;
        Ok(result)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn call_icrc2_approve(
        &self,
        args: Icrc2ApproveArg,
    ) -> Result<Icrc2ApproveResult, String> {
        #[cfg(test)]
        {
            NATIVE_CALL_MOCKS.with(|mocks| {
                let mut mocks = mocks.borrow_mut();
                mocks.seen_icrc2_approve_args.push(args);
                if mocks.icrc2_approve_results.is_empty() {
                    return Err("missing test mock for icrc2_approve".to_string());
                }
                mocks.icrc2_approve_results.remove(0)
            })
        }
        #[cfg(not(test))]
        {
            let _ = args;
            Err("icrc2_approve is unavailable on non-wasm32 targets".to_string())
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn call_kongswap_swap(&self, args: SwapArgs) -> Result<KongSwapResult, String> {
        let (result,): (KongSwapResult,) = ic_cdk::call(self.config.kong_backend, "swap", (args,))
            .await
            .map_err(|(code, msg)| format!("kong.swap call failed: {code:?} {msg}"))?;
        Ok(result)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn call_kongswap_swap(&self, args: SwapArgs) -> Result<KongSwapResult, String> {
        #[cfg(test)]
        {
            NATIVE_CALL_MOCKS.with(|mocks| {
                let mut mocks = mocks.borrow_mut();
                mocks.seen_swap_args.push(args);
                if mocks.kongswap_results.is_empty() {
                    return Err("missing test mock for kongswap.swap".to_string());
                }
                mocks.kongswap_results.remove(0)
            })
        }
        #[cfg(not(test))]
        {
            let _ = args;
            Err("kongswap.swap is unavailable on non-wasm32 targets".to_string())
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn call_icrc1_transfer(
        &self,
        args: Icrc1TransferArg,
    ) -> Result<Icrc1TransferResult, String> {
        let (result,): (Icrc1TransferResult,) =
            ic_cdk::call(self.config.icp_ledger, "icrc1_transfer", (args,))
                .await
                .map_err(|(code, msg)| {
                    format!("icp_ledger.icrc1_transfer failed: {code:?} {msg}")
                })?;
        Ok(result)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn call_icrc1_transfer(
        &self,
        args: Icrc1TransferArg,
    ) -> Result<Icrc1TransferResult, String> {
        #[cfg(test)]
        {
            NATIVE_CALL_MOCKS.with(|mocks| {
                let mut mocks = mocks.borrow_mut();
                mocks.seen_transfer_args.push(args);
                if mocks.icrc1_transfer_results.is_empty() {
                    return Err("missing test mock for icrc1_transfer".to_string());
                }
                mocks.icrc1_transfer_results.remove(0)
            })
        }
        #[cfg(not(test))]
        {
            let _ = args;
            Err("icrc1_transfer is unavailable on non-wasm32 targets".to_string())
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn call_notify_top_up(&self, args: NotifyTopUpArg) -> Result<NotifyTopUpResult, String> {
        let (result,): (NotifyTopUpResult,) =
            ic_cdk::call(self.config.cmc, "notify_top_up", (args,))
                .await
                .map_err(|(code, msg)| format!("cmc.notify_top_up failed: {code:?} {msg}"))?;
        Ok(result)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn call_notify_top_up(&self, args: NotifyTopUpArg) -> Result<NotifyTopUpResult, String> {
        #[cfg(test)]
        {
            NATIVE_CALL_MOCKS.with(|mocks| {
                let mut mocks = mocks.borrow_mut();
                mocks.seen_notify_args.push(args);
                if mocks.notify_top_up_results.is_empty() {
                    return Err("missing test mock for notify_top_up".to_string());
                }
                mocks.notify_top_up_results.remove(0)
            })
        }
        #[cfg(not(test))]
        {
            let _ = args;
            Err("notify_top_up is unavailable on non-wasm32 targets".to_string())
        }
    }
}

pub(crate) fn topup_status_from_stage(state: Option<TopUpStage>) -> TopUpStatus {
    match state {
        None => TopUpStatus::Idle,
        Some(TopUpStage::Completed {
            cycles_minted,
            usdc_spent,
            completed_at_ns,
        }) => TopUpStatus::Completed {
            cycles_minted,
            usdc_spent,
            completed_at_ns,
        },
        Some(TopUpStage::Failed {
            stage,
            error,
            failed_at_ns,
            attempts,
        }) => TopUpStatus::Failed {
            stage,
            error,
            failed_at_ns,
            attempts,
        },
        Some(stage) => TopUpStatus::InProgress { stage },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
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

    #[derive(Debug, Clone, Default)]
    struct TestEvmPort {
        rpc_responses: std::rc::Rc<RefCell<Vec<Result<String, String>>>>,
        rpc_calls: std::rc::Rc<RefCell<Vec<(String, String)>>>,
        sign_responses: std::rc::Rc<RefCell<Vec<Result<String, String>>>>,
        sign_requests: std::rc::Rc<RefCell<Vec<String>>>,
    }

    impl TestEvmPort {
        fn with_rpc_responses(responses: Vec<&str>) -> Self {
            Self {
                rpc_responses: std::rc::Rc::new(RefCell::new(
                    responses
                        .into_iter()
                        .map(|response| Ok(response.to_string()))
                        .collect(),
                )),
                ..Self::default()
            }
        }

        fn with_sign_response(signature: &str) -> Self {
            Self {
                sign_responses: std::rc::Rc::new(RefCell::new(vec![Ok(signature.to_string())])),
                ..Self::default()
            }
        }

        fn with_rpc_and_signature(responses: Vec<&str>, signature: &str) -> Self {
            Self {
                rpc_responses: std::rc::Rc::new(RefCell::new(
                    responses
                        .into_iter()
                        .map(|response| Ok(response.to_string()))
                        .collect(),
                )),
                sign_responses: std::rc::Rc::new(RefCell::new(vec![Ok(signature.to_string())])),
                ..Self::default()
            }
        }
    }

    #[async_trait(?Send)]
    impl EvmPort for TestEvmPort {
        async fn sign_message(&self, message_hash: &str) -> Result<String, String> {
            self.sign_requests
                .borrow_mut()
                .push(message_hash.to_string());
            let mut responses = self.sign_responses.borrow_mut();
            if responses.is_empty() {
                return Err("missing test mock for sign_message".to_string());
            }
            responses.remove(0)
        }

        async fn evm_rpc_call(&self, method: &str, params: &str) -> Result<String, String> {
            self.rpc_calls
                .borrow_mut()
                .push((method.to_string(), params.to_string()));
            let mut responses = self.rpc_responses.borrow_mut();
            if responses.is_empty() {
                return Err(format!("missing test mock for evm_rpc_call({method})"));
            }
            responses.remove(0)
        }
    }

    #[derive(Debug, Default)]
    struct TestStoragePort {
        state: RefCell<Option<TopUpStage>>,
    }

    impl TestStoragePort {
        fn with_state(state: TopUpStage) -> Self {
            let storage = Self::default();
            storage.save_state(&state);
            storage
        }
    }

    impl StoragePort for TestStoragePort {
        fn load_state(&self) -> Option<TopUpStage> {
            self.state.borrow().clone()
        }

        fn save_state(&self, state: &TopUpStage) {
            self.state.replace(Some(state.clone()));
        }

        fn clear_state(&self) {
            self.state.take();
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn reset_native_call_mocks() {
        NATIVE_CALL_MOCKS.with(|mocks| {
            *mocks.borrow_mut() = NativeCallMocks::default();
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn with_native_call_mocks<R>(f: impl FnOnce(&mut NativeCallMocks) -> R) -> R {
        NATIVE_CALL_MOCKS.with(|mocks| f(&mut mocks.borrow_mut()))
    }

    fn phase2_test_config() -> TopUpConfig {
        TopUpConfig {
            bridged_usdc_ledger: Principal::from_text("53nhb-haaaa-aaaar-qbn5q-cai")
                .expect("bridged usdc ledger principal must parse"),
            kong_backend: Principal::from_text("2ipq2-uqaaa-aaaar-qailq-cai")
                .expect("kong backend principal must parse"),
            icp_ledger: Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai")
                .expect("icp ledger principal must parse"),
            cmc: Principal::from_text("rkp4c-7iaaa-aaaaa-aaaca-cai")
                .expect("cmc principal must parse"),
            target_canister: Some(
                Principal::from_text("bkyz2-fmaaa-aaaaa-qaaaq-cai")
                    .expect("target canister principal must parse"),
            ),
            ..TopUpConfig::default()
        }
    }

    fn phase3_test_config() -> TopUpConfig {
        TopUpConfig {
            evm_address: "0x1111111111111111111111111111111111111111".to_string(),
            onesec_canister: Principal::from_text("5okwm-giaaa-aaaar-qbn6a-cai")
                .expect("onesec principal must parse"),
            ..phase2_test_config()
        }
    }

    fn full_word_hex_u64(value: u64) -> String {
        format!("0x{:064x}", value)
    }

    fn compact_signature_hex() -> &'static str {
        "0x11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222"
    }

    #[test]
    fn start_sets_preflight_when_idle() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort::default(),
            TestStoragePort::default(),
        );
        topup.start().expect("idle top-up should start");
        assert_eq!(
            topup.status(),
            TopUpStatus::InProgress {
                stage: TopUpStage::Preflight
            }
        );
    }

    #[test]
    fn start_rejects_in_progress_state() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort::default(),
            TestStoragePort::with_state(TopUpStage::ApprovingLocker { usdc_amount: 42 }),
        );
        let error = topup
            .start()
            .expect_err("active top-up should reject new start");
        assert!(error.contains("already in progress"));
    }

    #[test]
    fn start_rejects_failed_until_reset() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort::default(),
            TestStoragePort::with_state(TopUpStage::Failed {
                stage: "Preflight".to_string(),
                error: "boom".to_string(),
                failed_at_ns: 7,
                attempts: 1,
            }),
        );
        let error = topup
            .start()
            .expect_err("failed top-up should reject start");
        assert!(error.contains("reset"));
    }

    #[test]
    fn reset_clears_failed_state() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort::default(),
            TestStoragePort::with_state(TopUpStage::Failed {
                stage: "Preflight".to_string(),
                error: "boom".to_string(),
                failed_at_ns: 7,
                attempts: 1,
            }),
        );
        topup.reset().expect("reset should clear failed state");
        assert_eq!(topup.status(), TopUpStatus::Idle);
    }

    #[test]
    fn reset_rejects_when_not_failed() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort::default(),
            TestStoragePort::with_state(TopUpStage::Preflight),
        );
        let error = topup.reset().expect_err("reset requires failed state");
        assert!(error.contains("not in failed"));
    }

    #[test]
    fn status_maps_completed_state() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort::default(),
            TestStoragePort::with_state(TopUpStage::Completed {
                cycles_minted: 123,
                usdc_spent: 8_000_000,
                completed_at_ns: 99,
            }),
        );

        assert_eq!(
            topup.status(),
            TopUpStatus::Completed {
                cycles_minted: 123,
                usdc_spent: 8_000_000,
                completed_at_ns: 99
            }
        );
    }

    #[test]
    fn start_allows_restart_after_completed() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort::default(),
            TestStoragePort::with_state(TopUpStage::Completed {
                cycles_minted: 123,
                usdc_spent: 8_000_000,
                completed_at_ns: 99,
            }),
        );

        topup
            .start()
            .expect("completed top-up should allow restart without reset");
        assert_eq!(
            topup.status(),
            TopUpStatus::InProgress {
                stage: TopUpStage::Preflight
            }
        );
    }

    #[test]
    fn advance_returns_true_when_idle() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort::default(),
            TestStoragePort::default(),
        );
        let done = block_on_with_spin(topup.advance()).expect("idle advance should succeed");
        assert!(done);
    }

    #[test]
    fn advance_marks_failed_when_preflight_has_no_mocks() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort::default(),
            TestStoragePort::with_state(TopUpStage::Preflight),
        );

        let done = block_on_with_spin(topup.advance()).expect("advance should not throw");
        assert!(done);

        let status = topup.status();
        let TopUpStatus::Failed { stage, error, .. } = status else {
            panic!("expected failed status after preflight error");
        };
        assert_eq!(stage, "Preflight");
        assert!(!error.is_empty());
    }

    #[test]
    fn phase3_encode_principal_for_onesec_sets_tag_and_length() {
        let principal =
            Principal::from_text("bkyz2-fmaaa-aaaaa-qaaaq-cai").expect("principal must parse");
        let encoded = encode_principal_for_onesec(&principal);
        assert_eq!(encoded[0], 0);
        assert_eq!(usize::from(encoded[1]), principal.as_slice().len());
        assert_eq!(
            &encoded[2..2 + principal.as_slice().len()],
            principal.as_slice()
        );
    }

    #[test]
    fn phase3_preflight_advances_to_approve_locker() {
        #[cfg(not(target_arch = "wasm32"))]
        reset_native_call_mocks();
        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            mocks.get_transfer_fees_results.push(Ok(vec![TransferFee {
                token: Token::USDC,
                evm_chain: EvmChain::Base,
                min_amount: Nat::from(5_000_000_u64),
                max_amount: Nat::from(100_000_000_u64),
            }]));
        });

        let mut config = phase3_test_config();
        config.max_usdc_per_topup = 15_000_000;

        let evm = TestEvmPort::with_rpc_responses(vec![&full_word_hex_u64(30_000_000)]);
        let evm_spy = evm.clone();
        let topup = CycleTopUp::new(config, evm, TestStoragePort::default());
        let next = block_on_with_spin(topup.preflight()).expect("preflight should succeed");
        assert_eq!(
            next,
            TopUpStage::ApprovingLocker {
                usdc_amount: 15_000_000
            }
        );

        let calls = evm_spy.rpc_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "eth_call");
        assert!(calls[0].1.contains(SELECTOR_ERC20_BALANCE_OF));
    }

    #[test]
    fn phase3_preflight_rejects_when_amount_outside_fee_bounds() {
        #[cfg(not(target_arch = "wasm32"))]
        reset_native_call_mocks();
        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            mocks.get_transfer_fees_results.push(Ok(vec![TransferFee {
                token: Token::USDC,
                evm_chain: EvmChain::Base,
                min_amount: Nat::from(16_000_000_u64),
                max_amount: Nat::from(100_000_000_u64),
            }]));
        });

        let config = phase3_test_config();
        let evm = TestEvmPort::with_rpc_responses(vec![&full_word_hex_u64(25_000_000)]);
        let topup = CycleTopUp::new(config, evm, TestStoragePort::default());
        let error = block_on_with_spin(topup.preflight()).expect_err("preflight should fail");
        assert!(error.contains("outside Onesec bounds"));
    }

    #[test]
    fn phase3_approve_locker_sends_evm_tx_and_waits_for_confirmation() {
        let evm = TestEvmPort::with_rpc_and_signature(
            vec![
                "0x1",
                "0x3b9aca00",
                "0x5208",
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
            compact_signature_hex(),
        );
        let evm_spy = evm.clone();
        let topup = CycleTopUp::new(phase3_test_config(), evm, TestStoragePort::default());

        let next = block_on_with_spin(topup.approve_locker(&TopUpStage::ApprovingLocker {
            usdc_amount: 8_000_000,
        }))
        .expect("approve_locker should succeed");

        assert_eq!(
            next,
            TopUpStage::WaitingApprovalConfirmation {
                usdc_amount: 8_000_000,
                tx_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            }
        );
        let methods: Vec<String> = evm_spy
            .rpc_calls
            .borrow()
            .iter()
            .map(|(method, _)| method.clone())
            .collect();
        assert_eq!(
            methods,
            vec![
                "eth_getTransactionCount",
                "eth_gasPrice",
                "eth_estimateGas",
                "eth_sendRawTransaction",
            ]
        );
        assert_eq!(evm_spy.sign_requests.borrow().len(), 1);
    }

    #[test]
    fn phase3_lock_usdc_sends_lock_tx_and_waits_with_zero_confirmations() {
        let evm = TestEvmPort::with_rpc_and_signature(
            vec![
                "0x2",
                "0x3b9aca00",
                "0x100000",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
            compact_signature_hex(),
        );
        let topup = CycleTopUp::new(phase3_test_config(), evm, TestStoragePort::default());

        let next = block_on_with_spin(topup.lock_usdc(&TopUpStage::LockingUSDC {
            usdc_amount: 8_000_000,
        }))
        .expect("lock_usdc should succeed");

        assert_eq!(
            next,
            TopUpStage::WaitingLockConfirmation {
                usdc_amount: 8_000_000,
                tx_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
                confirmations: 0,
            }
        );
    }

    #[test]
    fn phase3_poll_tx_advances_approval_when_receipt_available() {
        let receipt = r#"{"status":"0x1","blockNumber":"0x10"}"#;
        let evm = TestEvmPort::with_rpc_responses(vec![receipt]);
        let topup = CycleTopUp::new(phase3_test_config(), evm, TestStoragePort::default());

        let next = block_on_with_spin(
            topup.poll_tx(
                &TopUpStage::WaitingApprovalConfirmation {
                    usdc_amount: 8_000_000,
                    tx_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                },
                1,
            ),
        )
        .expect("poll_tx should advance");

        assert_eq!(
            next,
            TopUpStage::LockingUSDC {
                usdc_amount: 8_000_000
            }
        );
    }

    #[test]
    fn phase3_poll_tx_keeps_waiting_lock_when_confirmations_insufficient() {
        let receipt = r#"{"status":"0x1","blockNumber":"0x10"}"#;
        let evm = TestEvmPort::with_rpc_responses(vec![receipt, "0x14"]);
        let topup = CycleTopUp::new(phase3_test_config(), evm, TestStoragePort::default());

        let next = block_on_with_spin(
            topup.poll_tx(
                &TopUpStage::WaitingLockConfirmation {
                    usdc_amount: 8_000_000,
                    tx_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                    confirmations: 0,
                },
                12,
            ),
        )
        .expect("poll_tx should remain waiting");

        assert_eq!(
            next,
            TopUpStage::WaitingLockConfirmation {
                usdc_amount: 8_000_000,
                tx_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
                confirmations: 5,
            }
        );
    }

    #[test]
    fn phase3_poll_tx_advances_lock_when_confirmed() {
        let receipt = r#"{"status":"0x1","blockNumber":"0x10"}"#;
        let evm = TestEvmPort::with_rpc_responses(vec![receipt, "0x1b"]);
        let topup = CycleTopUp::new(phase3_test_config(), evm, TestStoragePort::default());

        let next = block_on_with_spin(
            topup.poll_tx(
                &TopUpStage::WaitingLockConfirmation {
                    usdc_amount: 8_000_000,
                    tx_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                    confirmations: 0,
                },
                12,
            ),
        )
        .expect("poll_tx should advance");

        assert_eq!(
            next,
            TopUpStage::ValidatingOnOnesec {
                usdc_amount: 8_000_000,
                tx_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            }
        );
    }

    #[test]
    fn phase3_validate_on_onesec_moves_to_bridge_polling_on_accepted() {
        #[cfg(not(target_arch = "wasm32"))]
        reset_native_call_mocks();
        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            mocks
                .transfer_evm_to_icp_results
                .push(Ok(TransferResponse::Accepted(TransferId { id: 55 })));
        });

        let topup = CycleTopUp::new(
            phase3_test_config(),
            TestEvmPort::with_sign_response(compact_signature_hex()),
            TestStoragePort::default(),
        );
        let next =
            block_on_with_spin(
                topup.validate_on_onesec(&TopUpStage::ValidatingOnOnesec {
                    usdc_amount: 8_000_000,
                    tx_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                }),
            )
            .expect("validate_on_onesec should succeed");

        assert_eq!(
            next,
            TopUpStage::WaitingForBridgedUSDC {
                usdc_amount: 8_000_000,
                transfer_id: 55,
                polls: 0,
            }
        );
    }

    #[test]
    fn phase3_poll_bridge_increments_poll_counter_when_pending() {
        #[cfg(not(target_arch = "wasm32"))]
        reset_native_call_mocks();
        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            mocks
                .get_transfer_results
                .push(Ok(BridgeTransferStatus::Pending));
        });
        let topup = CycleTopUp::new(
            phase3_test_config(),
            TestEvmPort::default(),
            TestStoragePort::default(),
        );
        let next = block_on_with_spin(topup.poll_bridge(&TopUpStage::WaitingForBridgedUSDC {
            usdc_amount: 8_000_000,
            transfer_id: 66,
            polls: 2,
        }))
        .expect("poll_bridge should keep waiting");
        assert_eq!(
            next,
            TopUpStage::WaitingForBridgedUSDC {
                usdc_amount: 8_000_000,
                transfer_id: 66,
                polls: 3,
            }
        );
    }

    #[test]
    fn phase3_poll_bridge_advances_to_kongswap_approval_when_succeeded() {
        #[cfg(not(target_arch = "wasm32"))]
        reset_native_call_mocks();
        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            mocks
                .get_transfer_results
                .push(Ok(BridgeTransferStatus::Succeeded {
                    amount: Nat::from(7_500_000_u64),
                }));
        });
        let topup = CycleTopUp::new(
            phase3_test_config(),
            TestEvmPort::default(),
            TestStoragePort::default(),
        );
        let next = block_on_with_spin(topup.poll_bridge(&TopUpStage::WaitingForBridgedUSDC {
            usdc_amount: 8_000_000,
            transfer_id: 66,
            polls: 1,
        }))
        .expect("poll_bridge should advance");
        assert_eq!(
            next,
            TopUpStage::ApprovingKongSwap {
                bridged_usdc_amount: 7_500_000,
                usdc_spent: 8_000_000,
            }
        );
    }

    #[test]
    fn phase3_poll_bridge_fails_after_max_polls() {
        let mut config = phase3_test_config();
        config.max_bridge_polls = 3;
        let topup = CycleTopUp::new(config, TestEvmPort::default(), TestStoragePort::default());
        let error = block_on_with_spin(topup.poll_bridge(&TopUpStage::WaitingForBridgedUSDC {
            usdc_amount: 8_000_000,
            transfer_id: 66,
            polls: 3,
        }))
        .expect_err("poll_bridge should fail on timeout");
        assert!(error.contains("exceeded max attempts"));
    }

    #[test]
    fn phase2_approve_kongswap_advances_to_swap_stage() {
        #[cfg(not(target_arch = "wasm32"))]
        reset_native_call_mocks();

        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            mocks.icrc2_approve_results.push(Ok(Ok(Nat::from(1_u64))));
        });

        let topup = CycleTopUp::new(
            phase2_test_config(),
            TestEvmPort::default(),
            TestStoragePort::default(),
        );

        let next = block_on_with_spin(topup.approve_kongswap(&TopUpStage::ApprovingKongSwap {
            bridged_usdc_amount: 9_000_000,
            usdc_spent: 9_000_000,
        }))
        .expect("approve_kongswap should succeed");

        assert_eq!(
            next,
            TopUpStage::SwappingToICP {
                bridged_usdc_amount: 9_000_000,
                usdc_spent: 9_000_000
            }
        );

        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            let seen = mocks
                .seen_icrc2_approve_args
                .first()
                .expect("approve args should be recorded");
            assert_eq!(seen.spender.owner, phase2_test_config().kong_backend);
            assert_eq!(seen.amount, Nat::from(9_000_000_u64));
        });
    }

    #[test]
    fn phase2_swap_to_icp_advances_to_transfer_stage() {
        #[cfg(not(target_arch = "wasm32"))]
        reset_native_call_mocks();

        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            mocks.kongswap_results.push(Ok(Ok(SwapReply {
                tx_id: 1,
                request_id: 2,
                status: "Success".to_string(),
                pay_symbol: "USDC".to_string(),
                pay_amount: Nat::from(9_000_000_u64),
                receive_symbol: "ICP".to_string(),
                receive_amount: Nat::from(123_456_789_u64),
                mid_price: 0.0,
                price: 0.0,
                slippage: 0.0,
                claim_ids: vec![],
                ts: 0,
            })));
        });

        let topup = CycleTopUp::new(
            phase2_test_config(),
            TestEvmPort::default(),
            TestStoragePort::default(),
        );

        let next = block_on_with_spin(topup.swap_to_icp(&TopUpStage::SwappingToICP {
            bridged_usdc_amount: 9_000_000,
            usdc_spent: 9_000_000,
        }))
        .expect("swap_to_icp should succeed");

        assert_eq!(
            next,
            TopUpStage::TransferringToCMC {
                icp_amount: 123_456_789,
                usdc_spent: 9_000_000
            }
        );

        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            let seen = mocks
                .seen_swap_args
                .first()
                .expect("swap args should be recorded");
            assert_eq!(seen.pay_token, "IC.53nhb-haaaa-aaaar-qbn5q-cai");
            assert_eq!(seen.pay_amount, Nat::from(9_000_000_u64));
            assert_eq!(seen.receive_token, "ICP");
        });
    }

    #[test]
    fn phase2_transfer_to_cmc_advances_to_mint_stage() {
        #[cfg(not(target_arch = "wasm32"))]
        reset_native_call_mocks();

        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            mocks.icrc1_transfer_results.push(Ok(Ok(Nat::from(42_u64))));
        });

        let topup = CycleTopUp::new(
            phase2_test_config(),
            TestEvmPort::default(),
            TestStoragePort::default(),
        );

        let next = block_on_with_spin(topup.transfer_to_cmc(&TopUpStage::TransferringToCMC {
            icp_amount: 123_456_789,
            usdc_spent: 9_000_000,
        }))
        .expect("transfer_to_cmc should succeed");

        assert_eq!(
            next,
            TopUpStage::MintingCycles {
                block_index: 42,
                usdc_spent: 9_000_000
            }
        );

        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            let seen = mocks
                .seen_transfer_args
                .first()
                .expect("transfer args should be recorded");
            assert_eq!(seen.to.owner, phase2_test_config().cmc);
            assert_eq!(seen.amount, Nat::from(123_456_789_u64));
            let expected_subaccount = cmc_subaccount_for_canister(
                &phase2_test_config()
                    .target_canister
                    .expect("target canister should be configured"),
            );
            assert_eq!(
                seen.to.subaccount.clone().expect("subaccount must be set"),
                expected_subaccount.to_vec()
            );
        });
    }

    #[test]
    fn phase2_mint_cycles_advances_to_completed() {
        #[cfg(not(target_arch = "wasm32"))]
        reset_native_call_mocks();

        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            mocks
                .notify_top_up_results
                .push(Ok(Ok(Nat::from(987_654_321_000_u64))));
        });

        let topup = CycleTopUp::new(
            phase2_test_config(),
            TestEvmPort::default(),
            TestStoragePort::default(),
        );

        let next = block_on_with_spin(topup.mint_cycles(&TopUpStage::MintingCycles {
            block_index: 42,
            usdc_spent: 9_000_000,
        }))
        .expect("mint_cycles should succeed");
        let TopUpStage::Completed {
            cycles_minted,
            usdc_spent,
            ..
        } = next
        else {
            panic!("expected completed status");
        };
        assert_eq!(cycles_minted, 987_654_321_000);
        assert_eq!(usdc_spent, 9_000_000);

        #[cfg(not(target_arch = "wasm32"))]
        with_native_call_mocks(|mocks| {
            let seen = mocks
                .seen_notify_args
                .first()
                .expect("notify args should be recorded");
            assert_eq!(seen.block_index, 42);
            assert_eq!(
                seen.canister_id,
                phase2_test_config()
                    .target_canister
                    .expect("target canister should be configured")
            );
        });
    }
}
