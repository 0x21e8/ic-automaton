use crate::storage::{projection::SqlProjection, stable};

pub fn rebuild_projection(projection: &mut SqlProjection) {
    projection.clear();
    for turn in stable::list_turns(usize::MAX) {
        projection.upsert_turn(turn);
    }
}
