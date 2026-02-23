#![cfg(feature = "pocketic_tests")]

use std::path::Path;

use candid::{decode_one, encode_args, CandidType, Principal};
use pocket_ic::PocketIc;
use serde::{Deserialize, Serialize};

const WASM_PATHS: &[&str] = &[
    "target/wasm32-unknown-unknown/release/backend.wasm",
    "target/wasm32-unknown-unknown/release/deps/backend.wasm",
];

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct InitArgs {
    ecdsa_key_name: String,
    inbox_contract_address: Option<String>,
    evm_chain_id: Option<u64>,
    evm_rpc_url: Option<String>,
    evm_confirmation_depth: Option<u64>,
    http_allowed_domains: Option<Vec<String>>,
    llm_canister_id: Option<Principal>,
    cycle_topup_enabled: Option<bool>,
    auto_topup_cycle_threshold: Option<u64>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct StrategyTemplateKey {
    protocol: String,
    primitive: String,
    chain_id: u64,
    template_id: String,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct TemplateVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum TemplateStatus {
    Draft,
    Active,
    Deprecated,
    Revoked,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct ContractRoleBinding {
    role: String,
    address: String,
    source_ref: String,
    codehash: Option<String>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct AbiTypeSpec {
    kind: String,
    components: Vec<AbiTypeSpec>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct AbiFunctionSpec {
    role: String,
    name: String,
    selector_hex: String,
    inputs: Vec<AbiTypeSpec>,
    outputs: Vec<AbiTypeSpec>,
    state_mutability: String,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct ActionSpec {
    action_id: String,
    call_sequence: Vec<AbiFunctionSpec>,
    preconditions: Vec<String>,
    postconditions: Vec<String>,
    risk_checks: Vec<String>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct StrategyTemplate {
    key: StrategyTemplateKey,
    version: TemplateVersion,
    status: TemplateStatus,
    contract_roles: Vec<ContractRoleBinding>,
    actions: Vec<ActionSpec>,
    constraints_json: String,
    created_at_ns: u64,
    updated_at_ns: u64,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct AbiArtifactKey {
    protocol: String,
    chain_id: u64,
    role: String,
    version: TemplateVersion,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct AbiSelectorAssertion {
    signature: String,
    selector_hex: String,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct StrategyAbiIngestArgs {
    key: AbiArtifactKey,
    abi_json: String,
    source_ref: String,
    codehash: Option<String>,
    selector_assertions: Vec<AbiSelectorAssertion>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct AbiArtifact {
    key: AbiArtifactKey,
    source_ref: String,
    codehash: Option<String>,
    abi_json: String,
    functions: Vec<AbiFunctionSpec>,
    created_at_ns: u64,
    updated_at_ns: u64,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct TemplateActivationState {
    key: StrategyTemplateKey,
    version: TemplateVersion,
    enabled: bool,
    updated_at_ns: u64,
    reason: Option<String>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct StrategyKillSwitchState {
    key: StrategyTemplateKey,
    enabled: bool,
    updated_at_ns: u64,
    reason: Option<String>,
}

fn assert_wasm_artifact_present() -> Vec<u8> {
    for path in WASM_PATHS {
        if Path::new(path).exists() {
            return std::fs::read(path).unwrap_or_else(|error| {
                panic!("cannot read PocketIC test artifact {path}: {error}");
            });
        }
    }
    panic!(
        "build artifact not found at any expected path ({:?}); run `icp build` before PocketIC tests",
        WASM_PATHS
    );
}

fn with_backend_canister() -> (PocketIc, Principal) {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    let wasm = assert_wasm_artifact_present();
    let init_args = encode_args((InitArgs {
        ecdsa_key_name: "dfx_test_key".to_string(),
        inbox_contract_address: None,
        evm_chain_id: Some(8453),
        evm_rpc_url: Some("https://mainnet.base.org".to_string()),
        evm_confirmation_depth: None,
        http_allowed_domains: None,
        llm_canister_id: None,
        cycle_topup_enabled: None,
        auto_topup_cycle_threshold: None,
    },))
    .expect("failed to encode init args");

    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, init_args, None);

    (pic, canister_id)
}

fn call_update<T>(pic: &PocketIc, canister_id: Principal, method: &str, payload: Vec<u8>) -> T
where
    T: for<'de> Deserialize<'de> + CandidType,
{
    let response = pic
        .update_call(canister_id, Principal::anonymous(), method, payload)
        .unwrap_or_else(|error| panic!("update call {method} failed: {error:?}"));
    decode_one(&response)
        .unwrap_or_else(|error| panic!("failed decoding {method} response: {error:?}"))
}

fn call_update_as<T>(
    pic: &PocketIc,
    canister_id: Principal,
    caller: Principal,
    method: &str,
    payload: Vec<u8>,
) -> T
where
    T: for<'de> Deserialize<'de> + CandidType,
{
    let response = pic
        .update_call(canister_id, caller, method, payload)
        .unwrap_or_else(|error| panic!("update call {method} failed: {error:?}"));
    decode_one(&response)
        .unwrap_or_else(|error| panic!("failed decoding {method} response: {error:?}"))
}

fn call_query<T>(pic: &PocketIc, canister_id: Principal, method: &str, payload: Vec<u8>) -> T
where
    T: for<'de> Deserialize<'de> + CandidType,
{
    let response = pic
        .query_call(canister_id, Principal::anonymous(), method, payload)
        .unwrap_or_else(|error| panic!("query call {method} failed: {error:?}"));
    decode_one(&response)
        .unwrap_or_else(|error| panic!("failed decoding {method} response: {error:?}"))
}

fn sample_key() -> StrategyTemplateKey {
    StrategyTemplateKey {
        protocol: "erc20".to_string(),
        primitive: "transfer".to_string(),
        chain_id: 8453,
        template_id: "pocketic-strategy".to_string(),
    }
}

fn sample_version() -> TemplateVersion {
    TemplateVersion {
        major: 1,
        minor: 0,
        patch: 0,
    }
}

fn sample_template() -> StrategyTemplate {
    StrategyTemplate {
        key: sample_key(),
        version: sample_version(),
        status: TemplateStatus::Draft,
        contract_roles: vec![ContractRoleBinding {
            role: "token".to_string(),
            address: "0x2222222222222222222222222222222222222222".to_string(),
            source_ref: "https://example.com/token-address".to_string(),
            codehash: None,
        }],
        actions: vec![ActionSpec {
            action_id: "transfer".to_string(),
            call_sequence: vec![AbiFunctionSpec {
                role: "token".to_string(),
                name: "transfer".to_string(),
                selector_hex: "0xa9059cbb".to_string(),
                inputs: vec![
                    AbiTypeSpec {
                        kind: "address".to_string(),
                        components: Vec::new(),
                    },
                    AbiTypeSpec {
                        kind: "uint256".to_string(),
                        components: Vec::new(),
                    },
                ],
                outputs: vec![AbiTypeSpec {
                    kind: "bool".to_string(),
                    components: Vec::new(),
                }],
                state_mutability: "nonpayable".to_string(),
            }],
            preconditions: vec!["allowance_ok".to_string()],
            postconditions: vec!["balance_delta_positive".to_string()],
            risk_checks: vec!["max_notional".to_string()],
        }],
        constraints_json:
            r#"{"max_calls":1,"max_total_value_wei":"100","template_budget_wei":"100"}"#.to_string(),
        created_at_ns: 0,
        updated_at_ns: 0,
    }
}

#[test]
fn strategy_control_plane_lifecycle_and_controller_gating_work_in_pocketic() {
    let (pic, canister_id) = with_backend_canister();
    let template = sample_template();
    let payload = encode_args((template,)).unwrap_or_else(|error| {
        panic!("failed to encode ingest_strategy_template_admin args: {error}")
    });
    let ingested: Result<StrategyTemplate, String> =
        call_update(&pic, canister_id, "ingest_strategy_template_admin", payload);
    assert!(ingested.is_ok(), "template ingest failed: {ingested:?}");

    let abi_payload = encode_args((StrategyAbiIngestArgs {
        key: AbiArtifactKey {
            protocol: sample_key().protocol.clone(),
            chain_id: sample_key().chain_id,
            role: "token".to_string(),
            version: sample_version(),
        },
        abi_json: r#"[{"type":"function","name":"transfer","stateMutability":"nonpayable","inputs":[{"type":"address"},{"type":"uint256"}],"outputs":[{"type":"bool"}]}]"#.to_string(),
        source_ref: "https://example.com/token-abi".to_string(),
        codehash: None,
        selector_assertions: vec![AbiSelectorAssertion {
            signature: "transfer(address,uint256)".to_string(),
            selector_hex: "0xa9059cbb".to_string(),
        }],
    },))
    .unwrap_or_else(|error| panic!("failed to encode ingest_strategy_abi_artifact_admin args: {error}"));
    let abi_ingested: Result<AbiArtifact, String> = call_update(
        &pic,
        canister_id,
        "ingest_strategy_abi_artifact_admin",
        abi_payload,
    );
    assert!(abi_ingested.is_ok(), "abi ingest failed: {abi_ingested:?}");

    let activate_payload =
        encode_args((sample_key(), sample_version(), Some("activate".to_string()))).unwrap_or_else(
            |error| panic!("failed to encode activate_strategy_template_admin args: {error}"),
        );
    let activation: Result<TemplateActivationState, String> = call_update(
        &pic,
        canister_id,
        "activate_strategy_template_admin",
        activate_payload,
    );
    let activation = activation.unwrap_or_else(|error| panic!("activation failed: {error}"));
    assert!(activation.enabled, "activation should be enabled");

    let listed: Vec<StrategyTemplate> = call_query(
        &pic,
        canister_id,
        "list_strategy_templates",
        encode_args((Some(sample_key()), 10u32))
            .expect("failed to encode list_strategy_templates args"),
    );
    assert_eq!(listed.len(), 1, "strategy template should be listable");
    assert!(
        matches!(listed[0].status, TemplateStatus::Active),
        "activate endpoint should promote status to Active"
    );

    let fetched: Option<StrategyTemplate> = call_query(
        &pic,
        canister_id,
        "get_strategy_template",
        encode_args((sample_key(), sample_version()))
            .expect("failed to encode get_strategy_template args"),
    );
    let fetched = fetched.expect("strategy template should be fetchable");
    assert!(matches!(fetched.status, TemplateStatus::Active));

    let kill_payload =
        encode_args((sample_key(), true, Some("halt".to_string()))).unwrap_or_else(|error| {
            panic!("failed to encode set_strategy_kill_switch_admin args: {error}")
        });
    let kill_state: Result<StrategyKillSwitchState, String> = call_update(
        &pic,
        canister_id,
        "set_strategy_kill_switch_admin",
        kill_payload,
    );
    let kill_state = kill_state.unwrap_or_else(|error| panic!("kill switch failed: {error}"));
    assert!(kill_state.enabled);

    let outsider = Principal::self_authenticating(b"outsider-pocketic-strategy-controls");
    let outsider_payload = encode_args((sample_key(), false, Some("outsider".to_string())))
        .expect("failed to encode outsider kill-switch args");
    let outsider_result: Result<StrategyKillSwitchState, String> = call_update_as(
        &pic,
        canister_id,
        outsider,
        "set_strategy_kill_switch_admin",
        outsider_payload,
    );
    assert_eq!(
        outsider_result,
        Err("caller is not a controller".to_string()),
        "non-controller should be rejected"
    );
}
