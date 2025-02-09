use std::time::Duration;

use alloy_primitives::B256;
use futures::future::join_all;
use mordor::{SlotSynchronizer, SLOTS_PER_PERIOD};
use parser::{
    beacon::{
        light_client_bootstrap::LightClientBootstrap,
        light_client_update::Updates,
        light_finality_update::{self, FinalityUpdate},
        light_optimistic_update::LightOptimisticUpdate,
    },
    types::{Beacon, LightClientOptimisticUpdate, LightClientUpdate, SyncCommittee},
};
use reqwest::Client;
use thiserror::Error;
use tokio::task;

use crate::concensus::ConsensusError;

/// Stores the current state of a light client, including finalized and optimistic headers,
/// and sync committee information
pub struct LightClientStore {
    pub finalized_header: Beacon,
    pub optimistic_header: Beacon,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
}

/// Manages the synchronization process for a light client by coordinating updates
/// and maintaining the client state
pub struct LightClientSyncer {
    pub client: LightClient,
    pub slot_sync: SlotSynchronizer,
    pub store: Option<LightClientStore>,
}

/// A light client implementation for interacting with Ethereum beacon chain endpoints.
/// This client supports concurrent querying of multiple endpoints for redundancy and
/// consensus verification.
pub struct LightClient {
    pub endpoints: Vec<String>,
    pub client: Client,
}

impl LightClient {
    pub fn new(endpoints: Vec<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        Self { endpoints, client }
    }

    /// Retrieves the latest finality update from the beacon chain.
    ///
    /// Queries all configured endpoints concurrently and selects the popular response
    ///
    /// # Returns
    /// - `Result<FinalityUpdate, ConsensusError>`: The latest finality update or error
    pub async fn get_latest_finality_update(&self) -> Result<FinalityUpdate, ConsensusError> {
        let mut responses = Vec::new();

        // Query all endpoints concurrently
        let results = futures::future::join_all(self.endpoints.iter().map(|endpoint| {
            self.client
                .get(format!(
                    "{}/eth/v1/beacon/light_client/finality_update",
                    endpoint
                ))
                .send()
        }))
        .await;

        // Collect responses with signatures
        for response in results {
            if let Ok(resp) = response {
                let input = resp
                    .bytes()
                    .await
                    .map(|b| b.to_vec())
                    .map_err(|_| ConsensusError::Parse)?;

                let update = FinalityUpdate::parse(&input).ok_or(ConsensusError::Parse)?;

                responses.push((update.sync_aggregate.sync_committee_signature, update));
            }
        }

        responses.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(responses[0].1.clone())
    }

    /// Retrieves light client updates for a specific period.
    ///
    /// # Arguments
    /// * `period` - The sync committee period to query
    /// * `count` - Number of updates to retrieve
    ///
    /// # Returns
    /// - `Result<Updates, ConsensusError>`: The requested updates or error
    pub async fn get_latest_update(
        &self,
        period: u64,
        count: u64,
    ) -> Result<Updates, ConsensusError> {
        let mut responses = Vec::new();

        // Query all endpoints concurrently
        let results = futures::future::join_all(self.endpoints.iter().map(|endpoint| {
            self.client
                .get(format!(
                    "{}/eth/v1/beacon/light_client/updates?period={}&count={}",
                    endpoint, period, count
                ))
                .send()
        }))
        .await;

        // Collect responses with signatures
        for response in results {
            if let Ok(resp) = response {
                let input = resp
                    .bytes()
                    .await
                    .map(|b| b.to_vec())
                    .map_err(|_| ConsensusError::Parse)?;

                let update = Updates::parse(&input).ok_or(ConsensusError::Parse)?;

                responses.push((update.sync_aggregate.sync_committee_signature, update));
            }
        }

        responses.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(responses[0].1.clone())
    }

    /// Retrieves the light client bootstrap data for a specific block.
    ///
    /// # Arguments
    /// * `block_root` - The root hash of the block to bootstrap from
    ///
    /// # Returns
    /// - `Result<LightClientBootstrap, ConsensusError>`: Bootstrap data or error
    pub async fn get_bootstrap(
        &self,
        block_root: B256,
    ) -> Result<LightClientBootstrap, ConsensusError> {
        let mut responses = Vec::new();

        // Query all endpoints concurrently
        let results = futures::future::join_all(self.endpoints.iter().map(|endpoint| {
            self.client
                .get(format!(
                    "{}/eth/v1/beacon/light_client/bootstrap/{}",
                    endpoint, block_root,
                ))
                .send()
        }))
        .await;

        // Collect responses with signatures
        for response in results {
            if let Ok(resp) = response {
                let input = resp
                    .bytes()
                    .await
                    .map(|b| b.to_vec())
                    .map_err(|_| ConsensusError::Parse)?;

                let update = LightClientBootstrap::parse(&input).ok_or(ConsensusError::Parse)?;

                responses.push((update.current_sync_committee.aggregate_pubkey, update));
            }
        }

        responses.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(responses[0].1.clone())
    }

    /// Retrieves the latest optimistic update from the beacon chain.
    ///
    /// Similar to finality update but for optimistic sync data.
    ///
    /// # Returns
    /// - `Result<LightOptimisticUpdate, ConsensusError>`: Latest optimistic update or error
    pub async fn get_optimistic_update(&self) -> Result<LightOptimisticUpdate, ConsensusError> {
        let mut responses = Vec::new();

        // Query all endpoints concurrently
        let results = futures::future::join_all(self.endpoints.iter().map(|endpoint| {
            self.client
                .get(format!(
                    "{}/eth/v1/beacon/light_client/optimistic_update",
                    endpoint,
                ))
                .send()
        }))
        .await;

        // Collect responses with signatures
        for response in results {
            if let Ok(resp) = response {
                let input = resp
                    .bytes()
                    .await
                    .map(|b| b.to_vec())
                    .map_err(|_| ConsensusError::Parse)?;

                let update = LightOptimisticUpdate::parse(&input).ok_or(ConsensusError::Parse)?;

                responses.push((update.sync_aggregate.sync_committee_signature, update));
            }
        }

        responses.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(responses[0].1.clone())
    }

    pub fn get_sync_committee_period(&self, slot: u64) -> u64 {
        slot / SLOTS_PER_PERIOD
    }
}
