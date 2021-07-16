// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

pub mod rocks;
pub mod mock;

mod sorted_intersect;

use std::{error::Error, path::Path};
use serde::Deserialize;
use super::{tables::*, common};

pub trait Database {
    fn store_connection(&self, item: connection::Item);
    fn update_connection(&self, item: connection::Item);
    fn store_chunk(&self, item: chunk::Item);
    fn store_message(&self, item: message::Item);
    fn store_log(&self, item: node_log::Item);
}

#[derive(Deserialize)]
pub struct ConnectionsFilter {
    pub limit: Option<u64>,
}

#[derive(Deserialize)]
pub struct ChunksFilter {
    pub limit: Option<u64>,
    pub cn: Option<String>,
}

#[derive(Deserialize)]
pub struct MessagesFilter {
    pub limit: Option<u64>,
    pub cursor: Option<u64>,
    pub remote_addr: Option<String>,
    pub source_type: Option<common::Initiator>,
    pub incoming: Option<bool>,
    pub types: Option<String>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    // compatibility
    pub node_name: Option<String>,
}

#[derive(Deserialize)]
pub struct LogsFilter {
    pub direction: Option<String>,
    pub limit: Option<u64>,
    pub cursor: Option<u64>,
    pub log_level: Option<String>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub timestamp: Option<u64>,
    // compatibility
    pub node_name: Option<String>,
}

pub trait DatabaseFetch
where
    Self: DatabaseNew,
{
    fn fetch_connections(
        &self,
        filter: &ConnectionsFilter,
    ) -> Result<Vec<(connection::Key, connection::Value)>, Self::Error>;

    fn fetch_chunks_truncated(
        &self,
        filter: &ChunksFilter,
    ) -> Result<Vec<(chunk::Key, chunk::ValueTruncated)>, Self::Error>;

    fn fetch_chunk(&self, key: &chunk::Key) -> Result<Option<chunk::Value>, Self::Error>;

    fn fetch_messages(
        &self,
        filter: &MessagesFilter,
    ) -> Result<Vec<message::MessageFrontend>, Self::Error>;

    fn fetch_message(&self, id: u64) -> Result<Option<message::MessageDetails>, Self::Error>;

    fn fetch_log(&self, filter: &LogsFilter) -> Result<Vec<node_log::ItemWithId>, Self::Error>;
}

pub trait DatabaseNew
where
    Self: Sized,
{
    type Error: 'static + Send + Sync + Error;

    fn open<P>(path: P) -> Result<Self, Self::Error>
    where
        P: AsRef<Path>;
}
