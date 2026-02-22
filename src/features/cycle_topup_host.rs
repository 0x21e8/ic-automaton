use crate::domain::types::{RuntimeSnapshot, TaskKind, TaskLane};
use crate::features::cycle_topup::{
    normalize_evm_hex_address, topup_status_from_stage, CycleTopUp, EvmPort, StoragePort,
    TopUpConfig, TopUpStage, TopUpStatus,
};
use crate::features::evm::HttpEvmRpcClient;
use crate::features::threshold_signer::ThresholdSignerAdapter;
use crate::storage::stable;
use crate::tools::SignerPort;
use async_trait::async_trait;
use candid::Principal;

const BASE_EVM_CHAIN_ID: u64 = 8453;

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

fn parse_principal(raw: &str, field: &str) -> Result<Principal, String> {
    Principal::from_text(raw.trim())
        .map_err(|error| format!("{field} must be a valid principal: {error}"))
}

#[derive(Clone, Debug)]
pub struct AutomatonEvmPort {
    signer: ThresholdSignerAdapter,
    rpc: HttpEvmRpcClient,
}

impl AutomatonEvmPort {
    pub fn from_snapshot(snapshot: &RuntimeSnapshot) -> Result<Self, String> {
        Ok(Self {
            signer: ThresholdSignerAdapter::new(snapshot.ecdsa_key_name.clone()),
            rpc: HttpEvmRpcClient::from_snapshot(snapshot)?,
        })
    }
}

#[async_trait(?Send)]
impl EvmPort for AutomatonEvmPort {
    async fn sign_message(&self, message_hash: &str) -> Result<String, String> {
        self.signer.sign_message(message_hash).await
    }

    async fn evm_rpc_call(&self, method: &str, params: &str) -> Result<String, String> {
        self.rpc.json_rpc_call(method, params).await
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AutomatonStoragePort;

impl StoragePort for AutomatonStoragePort {
    fn load_state(&self) -> Option<TopUpStage> {
        stable::read_topup_state()
    }

    fn save_state(&self, state: &TopUpStage) {
        stable::write_topup_state(state);
    }

    fn clear_state(&self) {
        stable::clear_topup_state();
    }
}

pub fn topup_config_from_snapshot(snapshot: &RuntimeSnapshot) -> Result<TopUpConfig, String> {
    let cycle_topup = &snapshot.cycle_topup;
    let evm_chain_id = snapshot.evm_cursor.chain_id;
    if evm_chain_id != BASE_EVM_CHAIN_ID {
        return Err(format!(
            "cycle top-up only supports Base chain id {} (configured {})",
            BASE_EVM_CHAIN_ID, evm_chain_id
        ));
    }

    let evm_address = snapshot
        .evm_address
        .as_deref()
        .ok_or_else(|| "evm address is not configured".to_string())
        .and_then(|raw| normalize_evm_hex_address(raw, "evm address"))?;
    let usdc_contract_address = cycle_topup
        .usdc_contract_address
        .as_deref()
        .or(snapshot.wallet_balance.usdc_contract_address.as_deref())
        .map(|raw| normalize_evm_hex_address(raw, "usdc contract address"))
        .transpose()?
        .unwrap_or_else(|| TopUpConfig::default().usdc_contract_address);
    let onesec_locker_address =
        normalize_evm_hex_address(&cycle_topup.onesec_locker_address, "onesec locker address")?;

    let target_canister = cycle_topup
        .target_canister_id
        .as_deref()
        .map(|raw| parse_principal(raw, "target canister id"))
        .transpose()?;

    Ok(TopUpConfig {
        evm_address,
        usdc_contract_address,
        onesec_locker_address,
        evm_chain_id,
        onesec_canister: parse_principal(&cycle_topup.onesec_canister_id, "onesec canister id")?,
        bridged_usdc_ledger: parse_principal(
            &cycle_topup.bridged_usdc_ledger_id,
            "bridged usdc ledger id",
        )?,
        kong_backend: parse_principal(&cycle_topup.kong_backend_id, "kong backend id")?,
        icp_ledger: parse_principal(&cycle_topup.icp_ledger_id, "icp ledger id")?,
        cmc: parse_principal(&cycle_topup.cmc_id, "cmc id")?,
        target_canister,
        min_usdc_reserve: cycle_topup.min_usdc_reserve,
        max_usdc_per_topup: cycle_topup.max_usdc_per_topup,
        max_slippage_pct: cycle_topup.max_slippage_pct,
        max_bridge_polls: cycle_topup.max_bridge_polls,
        lock_confirmations: cycle_topup.lock_confirmations,
    })
}

pub fn build_cycle_topup(
    snapshot: &RuntimeSnapshot,
) -> Result<CycleTopUp<AutomatonEvmPort, AutomatonStoragePort>, String> {
    Ok(CycleTopUp::new(
        topup_config_from_snapshot(snapshot)?,
        AutomatonEvmPort::from_snapshot(snapshot)?,
        AutomatonStoragePort,
    ))
}

pub fn topup_status_from_storage() -> TopUpStatus {
    topup_status_from_stage(stable::read_topup_state())
}

pub fn topup_cycles_dedupe_key() -> String {
    format!("{}:singleton", TaskKind::TopUpCycles.as_str())
}

pub fn enqueue_topup_cycles_job(_trigger: &str, now_ns: u64) -> Option<String> {
    let slot_ns = now_ns - (now_ns % 30_000_000_000);
    stable::enqueue_job_if_absent(
        TaskKind::TopUpCycles,
        TaskLane::Mutating,
        topup_cycles_dedupe_key(),
        slot_ns,
        TaskKind::TopUpCycles.default_priority(),
    )
}

pub fn top_up_status_tool() -> String {
    format!("{:?}", topup_status_from_storage())
}

pub fn trigger_top_up_tool() -> Result<String, String> {
    let snapshot = stable::runtime_snapshot();
    if !snapshot.cycle_topup.enabled {
        return Err("cycle top-up is disabled".to_string());
    }
    let topup = build_cycle_topup(&snapshot)?;
    topup.start()?;
    let _ = enqueue_topup_cycles_job("tool", current_time_ns());
    Ok("Top-up enqueued.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topup_config_from_snapshot_rejects_non_base_chain_id() {
        let mut snapshot = RuntimeSnapshot::default();
        snapshot.evm_cursor.chain_id = 31_337;
        snapshot.evm_address = Some("0x1111111111111111111111111111111111111111".to_string());

        let error = topup_config_from_snapshot(&snapshot)
            .expect_err("top-up config must reject non-Base chain ids");
        assert!(error.contains("only supports Base chain id 8453"));
        assert!(error.contains("31337"));
    }

    #[test]
    fn topup_config_from_snapshot_accepts_base_chain_id() {
        let mut snapshot = RuntimeSnapshot::default();
        snapshot.evm_cursor.chain_id = BASE_EVM_CHAIN_ID;
        snapshot.evm_address = Some("0x1111111111111111111111111111111111111111".to_string());

        let config =
            topup_config_from_snapshot(&snapshot).expect("top-up config should build for Base");
        assert_eq!(config.evm_chain_id, BASE_EVM_CHAIN_ID);
        assert_eq!(
            config.evm_address,
            "0x1111111111111111111111111111111111111111"
        );
    }
}
