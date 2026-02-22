use async_trait::async_trait;
use candid::{CandidType, Nat, Principal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
            min_usdc_reserve: 2_000_000,
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
    },
    SwappingToICP {
        bridged_usdc_amount: u64,
    },
    TransferringToCMC {
        icp_amount: u64,
    },
    MintingCycles {
        block_index: u64,
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

#[cfg(all(test, not(target_arch = "wasm32")))]
#[derive(Default, Clone, Debug)]
struct NativeCallMocks {
    icrc2_approve_results: Vec<Result<Icrc2ApproveResult, String>>,
    kongswap_results: Vec<Result<KongSwapResult, String>>,
    icrc1_transfer_results: Vec<Result<Icrc1TransferResult, String>>,
    notify_top_up_results: Vec<Result<NotifyTopUpResult, String>>,
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
        match self.storage.load_state() {
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

    fn transition_not_implemented(&self, stage: &str) -> Result<TopUpStage, String> {
        let _ = (&self.config, &self.evm);
        Err(format!("{stage} transition not implemented"))
    }

    fn target_canister(&self) -> Principal {
        self.config
            .target_canister
            .unwrap_or_else(current_canister_id)
    }

    async fn preflight(&self) -> Result<TopUpStage, String> {
        self.transition_not_implemented("Preflight")
    }

    async fn approve_locker(&self, _state: &TopUpStage) -> Result<TopUpStage, String> {
        self.transition_not_implemented("ApprovingLocker")
    }

    async fn poll_tx(
        &self,
        _state: &TopUpStage,
        _required_confirmations: u8,
    ) -> Result<TopUpStage, String> {
        self.transition_not_implemented("PollingTransaction")
    }

    async fn lock_usdc(&self, _state: &TopUpStage) -> Result<TopUpStage, String> {
        self.transition_not_implemented("LockingUSDC")
    }

    async fn validate_on_onesec(&self, _state: &TopUpStage) -> Result<TopUpStage, String> {
        self.transition_not_implemented("ValidatingOnOnesec")
    }

    async fn poll_bridge(&self, _state: &TopUpStage) -> Result<TopUpStage, String> {
        self.transition_not_implemented("WaitingForBridgedUSDC")
    }

    async fn approve_kongswap(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::ApprovingKongSwap {
            bridged_usdc_amount,
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
            }),
            Err(error) => Err(format!("icrc2_approve failed: {error:?}")),
        }
    }

    async fn swap_to_icp(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::SwappingToICP {
            bridged_usdc_amount,
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
        Ok(TopUpStage::TransferringToCMC { icp_amount })
    }

    async fn transfer_to_cmc(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::TransferringToCMC { icp_amount } = state else {
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
            }),
            Err(error) => Err(format!("icrc1_transfer failed: {error:?}")),
        }
    }

    async fn mint_cycles(&self, state: &TopUpStage) -> Result<TopUpStage, String> {
        let TopUpStage::MintingCycles { block_index } = state else {
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
                usdc_spent: 0,
                completed_at_ns: current_time_ns(),
            }),
            Err(error) => Err(format!("notify_top_up failed: {error:?}")),
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

    #[derive(Clone, Debug)]
    struct TestEvmPort;

    #[async_trait(?Send)]
    impl EvmPort for TestEvmPort {
        async fn sign_message(&self, _message_hash: &str) -> Result<String, String> {
            Ok("0xdeadbeef".to_string())
        }

        async fn evm_rpc_call(&self, _method: &str, _params: &str) -> Result<String, String> {
            Ok("0x1".to_string())
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

    #[test]
    fn start_sets_preflight_when_idle() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort,
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
            TestEvmPort,
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
            TestEvmPort,
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
            TestEvmPort,
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
            TestEvmPort,
            TestStoragePort::with_state(TopUpStage::Preflight),
        );
        let error = topup.reset().expect_err("reset requires failed state");
        assert!(error.contains("not in failed"));
    }

    #[test]
    fn status_maps_completed_state() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort,
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
            TestEvmPort,
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
            TestEvmPort,
            TestStoragePort::default(),
        );
        let done = block_on_with_spin(topup.advance()).expect("idle advance should succeed");
        assert!(done);
    }

    #[test]
    fn advance_marks_failed_when_transition_unimplemented() {
        let topup = CycleTopUp::new(
            TopUpConfig::default(),
            TestEvmPort,
            TestStoragePort::with_state(TopUpStage::Preflight),
        );

        let done = block_on_with_spin(topup.advance()).expect("advance should not throw");
        assert!(done);

        let status = topup.status();
        let TopUpStatus::Failed { stage, error, .. } = status else {
            panic!("expected failed status after unimplemented transition");
        };
        assert_eq!(stage, "Preflight");
        assert!(error.contains("not implemented"));
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
            TestEvmPort,
            TestStoragePort::default(),
        );

        let next = block_on_with_spin(topup.approve_kongswap(&TopUpStage::ApprovingKongSwap {
            bridged_usdc_amount: 9_000_000,
        }))
        .expect("approve_kongswap should succeed");

        assert_eq!(
            next,
            TopUpStage::SwappingToICP {
                bridged_usdc_amount: 9_000_000
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
            TestEvmPort,
            TestStoragePort::default(),
        );

        let next = block_on_with_spin(topup.swap_to_icp(&TopUpStage::SwappingToICP {
            bridged_usdc_amount: 9_000_000,
        }))
        .expect("swap_to_icp should succeed");

        assert_eq!(
            next,
            TopUpStage::TransferringToCMC {
                icp_amount: 123_456_789
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
            TestEvmPort,
            TestStoragePort::default(),
        );

        let next = block_on_with_spin(topup.transfer_to_cmc(&TopUpStage::TransferringToCMC {
            icp_amount: 123_456_789,
        }))
        .expect("transfer_to_cmc should succeed");

        assert_eq!(next, TopUpStage::MintingCycles { block_index: 42 });

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
            TestEvmPort,
            TestStoragePort::default(),
        );

        let next =
            block_on_with_spin(topup.mint_cycles(&TopUpStage::MintingCycles { block_index: 42 }))
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
        assert_eq!(usdc_spent, 0);

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
