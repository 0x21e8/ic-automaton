use crate::domain::types::{CanisterCallPermission, CanisterCallType, SkillRecord};
use crate::storage::stable;

/// Well-known canister ID of the ICP cycles ledger (ICRC-1 token representing cycles).
const CYCLES_LEDGER_CANISTER_ID: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";

#[allow(dead_code)]
pub trait SkillsStore {
    fn list(&self) -> Vec<SkillRecord>;
}

#[allow(dead_code)]
pub struct StableSkillStore;

impl SkillsStore for StableSkillStore {
    fn list(&self) -> Vec<SkillRecord> {
        stable::list_skills()
    }
}

pub struct DefaultSkillLoader;

impl DefaultSkillLoader {
    pub fn load_defaults() -> Vec<SkillRecord> {
        vec![
            SkillRecord {
                name: "agent-loop".to_string(),
                description: "Default loop safety profile".to_string(),
                instructions: "Stay in FSM order and prefer deterministic behavior.".to_string(),
                enabled: true,
                mutable: true,
                allowed_canister_calls: vec![],
            },
            Self::cycles_management_skill(),
        ]
    }

    pub fn install_defaults() {
        for skill in Self::load_defaults() {
            stable::upsert_skill(&skill);
        }
    }

    /// Seed any default skills that are not yet present in stable storage.
    ///
    /// Unlike `install_defaults`, this does not overwrite existing skills —
    /// skills that have already been stored (possibly customised by a controller)
    /// are left untouched.  Safe to call from `post_upgrade`.
    pub fn seed_missing_defaults() {
        let existing: std::collections::HashSet<String> = stable::list_skills()
            .into_iter()
            .map(|s| s.name)
            .collect();
        for skill in Self::load_defaults() {
            if !existing.contains(&skill.name) {
                stable::upsert_skill(&skill);
            }
        }
    }

    /// Default skill that grants the agent permission to check its cycles ledger
    /// balance and withdraw cycles to top itself up.
    ///
    /// The `canister_call` tool will only allow calls to the cycles ledger when
    /// this skill (or another skill with the same permissions) is enabled.
    pub fn cycles_management_skill() -> SkillRecord {
        SkillRecord {
            name: "cycles-management".to_string(),
            description: "Cycles ledger balance monitoring and self-top-up via canister_call"
                .to_string(),
            instructions: format!(
                r#"To check cycles ledger balance, use canister_call:
- canister_id: "{CYCLES_LEDGER_CANISTER_ID}"
- method: "icrc1_balance_of"
- args_candid: "(record {{ owner = principal \"<self-canister-id>\"; subaccount = null }})"

The response is a nat (number of cycles, 1 T-cycle = 1_000_000_000_000).

To withdraw cycles from the ledger and deposit them into this canister, use:
- canister_id: "{CYCLES_LEDGER_CANISTER_ID}"
- method: "withdraw"
- args_candid: "(record {{ amount = <amount> : nat; from_subaccount = null; to = principal \"<self-canister-id>\"; created_at_time = null }})"

Always check balance before withdrawing. Prefer conservative top-up amounts.
Replace <self-canister-id> with this canister's own principal from context."#
            ),
            enabled: true,
            mutable: true,
            allowed_canister_calls: vec![
                CanisterCallPermission {
                    canister_id: CYCLES_LEDGER_CANISTER_ID.to_string(),
                    method: "icrc1_balance_of".to_string(),
                    call_type: CanisterCallType::Query,
                },
                CanisterCallPermission {
                    canister_id: CYCLES_LEDGER_CANISTER_ID.to_string(),
                    method: "withdraw".to_string(),
                    call_type: CanisterCallType::Update,
                },
            ],
        }
    }
}
