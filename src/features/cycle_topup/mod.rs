use async_trait::async_trait;
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

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

    async fn approve_kongswap(&self, _state: &TopUpStage) -> Result<TopUpStage, String> {
        self.transition_not_implemented("ApprovingKongSwap")
    }

    async fn swap_to_icp(&self, _state: &TopUpStage) -> Result<TopUpStage, String> {
        self.transition_not_implemented("SwappingToICP")
    }

    async fn transfer_to_cmc(&self, _state: &TopUpStage) -> Result<TopUpStage, String> {
        self.transition_not_implemented("TransferringToCMC")
    }

    async fn mint_cycles(&self, _state: &TopUpStage) -> Result<TopUpStage, String> {
        self.transition_not_implemented("MintingCycles")
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
}
