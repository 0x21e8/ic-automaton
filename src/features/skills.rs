use crate::domain::types::SkillRecord;
use crate::storage::stable;

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

pub struct MockSkillLoader;

impl MockSkillLoader {
    pub fn load_defaults() -> Vec<SkillRecord> {
        vec![SkillRecord {
            name: "agent-loop".to_string(),
            description: "Default loop safety profile".to_string(),
            instructions: "Stay in FSM order and prefer deterministic behavior.".to_string(),
            enabled: true,
            mutable: true,
        }]
    }

    pub fn install_defaults() {
        for skill in Self::load_defaults() {
            stable::upsert_skill(&skill);
        }
    }
}
