use crate::domain::types::TurnRecord;
use std::collections::HashMap;

#[derive(Default)]
#[allow(dead_code)]
pub struct SqlProjection {
    // Phase-1 placeholder rows used as a deterministic in-memory replay target.
    // This keeps the same API shape as a future ic-rusqlite-backed implementation.
    pub rows: Vec<TurnRecord>,
}

#[allow(dead_code)]
impl SqlProjection {
    pub fn upsert_turn_record(&mut self, turn: TurnRecord) {
        self.rows.push(turn);
    }

    pub fn upsert_turn(&mut self, turn: TurnRecord) {
        self.rows.push(turn);
    }

    pub fn clear(&mut self) {
        self.rows.clear();
    }

    pub fn list_turns(&self, limit: usize) -> Vec<TurnRecord> {
        let mut rows = self.rows.clone();
        rows.sort_by_key(|r| r.created_at_ns);
        rows.reverse();
        rows.into_iter().take(limit).collect()
    }

    pub fn query_tools_used(&self, tool: &str) -> Vec<String> {
        let mut rows = Vec::new();
        for turn in &self.rows {
            if turn.input_summary.contains(tool) {
                rows.push(format!("{}:{}", turn.id, tool));
            }
        }
        rows
    }

    pub fn query_state_histogram(&self) -> Vec<(String, usize)> {
        let mut seen: HashMap<String, usize> = HashMap::new();
        for turn in &self.rows {
            *seen.entry(format!("{:?}", turn.state_to)).or_insert(0) += 1usize;
        }
        let mut list: Vec<(String, usize)> = seen.into_iter().collect();
        list.sort_by_key(|row| row.0.clone());
        list
    }
}

#[allow(dead_code)]
// Placeholder for ic-rusqlite-backed implementation in the next iteration.
// This struct keeps the same method shape as the planned projection layer.
pub trait ProjectionStore {
    fn clear(&mut self);
    fn upsert_turn(&mut self, turn: TurnRecord);
    fn list_turns(&self, limit: usize) -> Vec<TurnRecord>;
}

impl ProjectionStore for SqlProjection {
    fn upsert_turn(&mut self, turn: TurnRecord) {
        self.upsert_turn(turn);
    }

    fn clear(&mut self) {
        Self::clear(self);
    }

    fn list_turns(&self, limit: usize) -> Vec<TurnRecord> {
        self.list_turns(limit)
    }
}
