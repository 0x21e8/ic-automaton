use crate::domain::types::{EvmEvent, EvmPollCursor};
use async_trait::async_trait;

pub struct EvmPollResult {
    pub cursor: EvmPollCursor,
    pub events: Vec<EvmEvent>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct EvmBroadcastResult {
    pub tx_hash: String,
}

#[allow(dead_code)]
pub trait EvmBroadcaster {
    fn broadcast(&self, signed_transaction: &str) -> Result<EvmBroadcastResult, String>;
}

#[async_trait(?Send)]
pub trait EvmPoller {
    async fn poll(&self, cursor: &EvmPollCursor) -> Result<EvmPollResult, String>;
}

pub struct MockEvmPoller;

#[async_trait(?Send)]
impl EvmPoller for MockEvmPoller {
    async fn poll(&self, cursor: &EvmPollCursor) -> Result<EvmPollResult, String> {
        let next_block = cursor.next_block.saturating_add(1);
        let next_log_index = cursor.next_log_index.saturating_add(1);

        let events = vec![EvmEvent {
            chain_id: cursor.chain_id,
            block_number: next_block,
            log_index: next_log_index,
            source: "mock_chain".to_string(),
            payload: "agent.heartbeat".to_string(),
        }];

        Ok(EvmPollResult {
            cursor: EvmPollCursor {
                chain_id: cursor.chain_id,
                next_block,
                next_log_index,
            },
            events,
        })
    }
}

#[allow(dead_code)]
pub struct MockEvmBroadcaster;

impl EvmBroadcaster for MockEvmBroadcaster {
    fn broadcast(&self, signed_transaction: &str) -> Result<EvmBroadcastResult, String> {
        Ok(EvmBroadcastResult {
            tx_hash: format!("0x{signed_transaction}-mock"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_evm_broadcaster_returns_mock_tx_hash() {
        let broadcaster = MockEvmBroadcaster;
        let result = broadcaster
            .broadcast("0xdeadbeef")
            .expect("mock broadcaster should succeed");
        assert_eq!(result.tx_hash, "0x0xdeadbeef-mock");
    }
}
