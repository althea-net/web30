//! This module contains functions for managing Ethereum events
use crate::{client::Web3, types::NewFilter};
use crate::{jsonrpc::error::Web3Error, types::Log};
use clarity::{abi::derive_signature, utils::bytes_to_hex_str};
use clarity::{Address, Uint256};
use std::time::Duration;
use tokio::time::delay_for;

fn bytes_to_data(s: &[u8]) -> String {
    let mut val = "0x".to_string();
    val.push_str(&bytes_to_hex_str(&s));
    val
}

impl Web3 {
    /// Same as wait_for_event, but doesn't use eth_newFilter
    pub async fn wait_for_event_alt<F: Fn(Log) -> bool + 'static>(
        &self,
        contract_address: Address,
        event: &str,
        topic1: Option<Vec<[u8; 32]>>,
        topic2: Option<Vec<[u8; 32]>>,
        topic3: Option<Vec<[u8; 32]>>,
        local_filter: F,
    ) -> Result<Log, Web3Error> {
        let new_filter = NewFilter {
            address: vec![contract_address],
            from_block: None,
            to_block: None,
            topics: Some(vec![
                Some(vec![Some(bytes_to_data(&derive_signature(event)))]),
                topic1.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
                topic2.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
                topic3.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
            ]),
        };

        delay_for(Duration::from_secs(10)).await;
        let logs = match self.eth_get_logs(new_filter.clone()).await {
            Ok(logs) => logs,
            Err(e) => return Err(e),
        };

        for log in logs {
            if local_filter(log.clone()) {
                return Ok(log);
            }
        }
        Err(Web3Error::EventNotFound(event.to_string()))
    }

    /// Sets up an event filter, waits for the event to happen, then removes the filter. Includes a
    /// local filter. If a captured event does not pass this filter, it is ignored.
    pub async fn wait_for_event<F: Fn(Log) -> bool + 'static>(
        &self,
        contract_address: Address,
        event: &str,
        topic1: Option<Vec<[u8; 32]>>,
        topic2: Option<Vec<[u8; 32]>>,
        topic3: Option<Vec<[u8; 32]>>,
        local_filter: F,
    ) -> Result<Log, Web3Error> {
        let mut new_filter = NewFilter::default();
        new_filter.address = vec![contract_address];
        new_filter.from_block = None;
        new_filter.to_block = None;
        new_filter.topics = Some(vec![
            Some(vec![Some(bytes_to_data(&derive_signature(event)))]),
            topic1.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
            topic2.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
            topic3.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
        ]);

        let filter_id = match self.eth_new_filter(new_filter).await {
            Ok(f) => f,
            Err(e) => return Err(e),
        };

        delay_for(Duration::from_secs(10)).await;
        let logs = match self.eth_get_filter_changes(filter_id.clone()).await {
            Ok(changes) => changes,
            Err(e) => return Err(e),
        };
        let mut found_log = None;
        for log in logs {
            if local_filter(log.clone()) {
                found_log = Some(log);
            }
        }

        if let Err(e) = self.eth_uninstall_filter(filter_id).await {
            return Err(Web3Error::CouldNotRemoveFilter(format!("{}", e)));
        }

        match found_log {
            Some(log) => Ok(log),
            None => Err(Web3Error::EventNotFound(event.to_string())),
        }
    }

    /// Checks if a singular event has already happened. If multiple events match
    /// the description only the first match is provided.
    pub async fn check_for_event(
        &self,
        contract_address: Address,
        event: &str,
        topic1: Option<Vec<[u8; 32]>>,
        topic2: Option<Vec<[u8; 32]>>,
    ) -> Result<Option<Log>, Web3Error> {
        // Build a filter with specified topics
        let mut new_filter = NewFilter::default();
        new_filter.address = vec![contract_address];
        new_filter.topics = Some(vec![
            Some(vec![Some(bytes_to_data(&derive_signature(event)))]),
            topic1.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
            topic2.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
        ]);

        match self.eth_get_logs(new_filter).await {
            // Assuming the latest log is at the head of the vec
            Ok(log) => Ok(log.first().cloned()),
            Err(e) => Err(e),
        }
    }

    /// Checks for multiple events over a block range. If no ending block is provided
    /// the latest will be used.
    pub async fn check_for_events(
        &self,
        start_block: Uint256,
        end_block: Option<Uint256>,
        contract_address: Address,
        event: &str,
        topic1: Option<Vec<[u8; 32]>>,
        topic2: Option<Vec<[u8; 32]>>,
    ) -> Result<Vec<Log>, Web3Error> {
        // Build a filter with specified topics
        let mut new_filter = NewFilter::default();
        new_filter.from_block = Some(format!("{:#x}", start_block));
        if let Some(end_block) = end_block {
            new_filter.to_block = Some(format!("{:#x}", end_block));
        } else {
            let latest_block = self.eth_block_number().await?;
            new_filter.to_block = Some(format!("{:#x}", latest_block));
        }

        new_filter.address = vec![contract_address];
        new_filter.topics = Some(vec![
            Some(vec![Some(bytes_to_data(&derive_signature(event)))]),
            topic1.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
            topic2.map(|v| v.into_iter().map(|val| Some(bytes_to_data(&val))).collect()),
        ]);

        Ok(self.eth_get_logs(new_filter).await?)
    }
}
