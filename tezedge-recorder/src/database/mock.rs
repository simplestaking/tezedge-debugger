// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{
    path::Path,
    sync::Mutex,
    fs::File,
    io::{self, Write},
};
use anyhow::Result;
#[rustfmt::skip]
use super::{
    // core traits
    Database, DatabaseNew, DatabaseFetch,
    // filters
    ConnectionsFilter, ChunksFilter, MessagesFilter, LogsFilter,
    // tables
    connection, chunk, message, node_log,
};

pub struct Db {
    file: Mutex<File>,
}

impl DatabaseNew for Db {
    type Error = io::Error;

    fn open<P>(path: P) -> Result<Self, Self::Error>
    where
        P: AsRef<Path>,
    {
        Ok(Db {
            file: Mutex::new(File::create(path)?),
        })
    }
}

impl Database for Db {
    fn store_connection(&self, item: connection::Item) {
        self.file.lock().unwrap()
            .write_fmt(format_args!("cn: {:?}", item))
            .unwrap();
    }

    fn update_connection(&self, item: connection::Item) {
        self.file.lock().unwrap()
            .write_fmt(format_args!("cn_: {:?}", item))
            .unwrap();
    }

    fn store_chunk(&self, item: chunk::Item) {
        let (key, value) = item.split();
        self.file.lock().unwrap()
            .write_fmt(format_args!("chunk: {}, length: {}", key, value.plain.len()))
            .unwrap();
    }

    fn store_message(&self, item: message::Item) {
        self.file.lock().unwrap()
            .write_fmt(format_args!("message: {:?}", item.ty))
            .unwrap();
    }

    fn store_log(&self, item: node_log::Item) {
        self.file.lock().unwrap()
            .write_fmt(format_args!("log: {:?}", item.level))
            .unwrap();

    }
}

impl DatabaseFetch for Db {
    fn fetch_connections(
        &self,
        filter: &ConnectionsFilter,
    ) -> Result<Vec<(connection::Key, connection::Value)>, Self::Error> {
        let _ = filter;
        Ok(vec![])
    }

    fn fetch_chunks_truncated(
        &self,
        filter: &ChunksFilter,
    ) -> Result<Vec<(chunk::Key, chunk::ValueTruncated)>, Self::Error> {
        let _ = filter;
        Ok(vec![])
    }

    fn fetch_chunk(&self, key: &chunk::Key) -> Result<Option<chunk::Value>, Self::Error> {
        let _ = key;
        Ok(None)
    }

    fn fetch_messages(
        &self,
        filter: &MessagesFilter,
    ) -> Result<Vec<message::MessageFrontend>, Self::Error> {
        let _ = filter;
        Ok(vec![])
    }

    fn fetch_message(&self, id: u64) -> Result<Option<message::MessageDetails>, Self::Error> {
        let _ = id;
        Ok(None)
    }

    fn fetch_log(&self, filter: &LogsFilter) -> Result<Vec<node_log::ItemWithId>, Self::Error> {
        let _ = filter;
        Ok(vec![])
    }
}
