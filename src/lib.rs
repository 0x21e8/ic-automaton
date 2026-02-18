mod agent;
mod domain;
mod features;
mod storage;
mod tools;

use crate::agent::{run_scheduled_turn, TURN_TIMER_SECONDS};
use crate::domain::types::{
    InferenceConfigView, InferenceProvider, RuntimeView, SkillRecord, ToolCallRecord,
};
use crate::storage::stable;
use crate::tools::ToolManager;
use ic_cdk_timers::set_timer_interval;
use std::time::Duration;

#[ic_cdk::init]
fn init() {
    stable::init_storage();
    crate::features::MockSkillLoader::install_defaults();
    arm_timer();
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    stable::init_storage();
    arm_timer();
}

#[ic_cdk::update]
fn set_loop_enabled(enabled: bool) -> String {
    stable::set_loop_enabled(enabled);
    format!("loop_enabled={enabled}")
}

#[ic_cdk::update]
fn set_inference_provider(provider: InferenceProvider) -> String {
    stable::set_inference_provider(provider.clone());
    format!("inference_provider={provider:?}")
}

#[ic_cdk::update]
fn set_inference_model(model: String) -> Result<String, String> {
    stable::set_inference_model(model)
}

#[ic_cdk::update]
fn set_openrouter_base_url(base_url: String) -> Result<String, String> {
    stable::set_openrouter_base_url(base_url)
}

#[ic_cdk::update]
fn set_openrouter_api_key(api_key: Option<String>) -> String {
    stable::set_openrouter_api_key(api_key);
    "openrouter_api_key_updated".to_string()
}

#[ic_cdk::query]
fn get_runtime_view() -> RuntimeView {
    stable::snapshot_to_view()
}

#[ic_cdk::query]
fn get_inference_config() -> InferenceConfigView {
    stable::inference_config_view()
}

#[ic_cdk::query]
fn get_soul() -> String {
    stable::get_soul()
}

#[ic_cdk::update]
fn update_soul(new_soul: String) -> Result<String, String> {
    if new_soul.trim().is_empty() {
        return Err("soul cannot be empty".to_string());
    }
    Ok(stable::set_soul(new_soul))
}

#[ic_cdk::query]
fn list_recent_events(limit: u32) -> Vec<String> {
    stable::list_recent_transitions(limit as usize)
        .into_iter()
        .map(|record| format!("{record:?}"))
        .collect()
}

#[ic_cdk::query]
fn list_turns(limit: u32) -> Vec<String> {
    stable::list_turns(limit as usize)
        .into_iter()
        .map(|turn| format!("{turn:?}"))
        .collect()
}

#[ic_cdk::query]
fn list_skills() -> Vec<SkillRecord> {
    stable::list_skills()
}

#[ic_cdk::query]
fn list_tool_policies() -> Vec<String> {
    let manager = ToolManager::new();
    manager
        .list_tools()
        .into_iter()
        .map(|(name, policy)| format!("{name}: {policy:?}"))
        .collect()
}

#[ic_cdk::query]
fn get_tool_calls_for_turn(turn_id: String) -> Vec<ToolCallRecord> {
    stable::get_tools_for_turn(&turn_id)
}

fn arm_timer() {
    set_timer_interval(Duration::from_secs(TURN_TIMER_SECONDS), || {
        run_scheduled_turn()
    });
}

ic_cdk::export_candid!();
