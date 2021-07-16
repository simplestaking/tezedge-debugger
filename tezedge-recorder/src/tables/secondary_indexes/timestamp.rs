// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::convert::TryFrom;
use storage::persistent::{KeyValueSchema, Encoder, Decoder, SchemaError, database::RocksDbKeyValueSchema};

/// * bytes layout: `[timestamp(8)][index(8)]`
pub struct Item {
    pub timestamp: u64,
    pub index: u64,
}

impl Encoder for Item {
    fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        let mut v = Vec::with_capacity(16);

        v.extend_from_slice(&self.timestamp.to_be_bytes());
        v.extend_from_slice(&self.index.to_be_bytes());

        Ok(v)
    }
}

impl Decoder for Item {
    fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
        if bytes.len() != 16 {
            return Err(SchemaError::DecodeError);
        }

        Ok(Item {
            timestamp: u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[..8]).unwrap()),
            index: u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..]).unwrap()),
        })
    }
}

pub struct MessageSchema;

impl KeyValueSchema for MessageSchema {
    type Key = Item;
    type Value = ();
}

impl RocksDbKeyValueSchema for MessageSchema {
    fn name() -> &'static str {
        "message_timestamp_secondary_index"
    }
}

pub struct LogSchema;

impl KeyValueSchema for LogSchema {
    type Key = Item;
    type Value = ();
}

impl RocksDbKeyValueSchema for LogSchema {
    fn name() -> &'static str {
        "log_timestamp_secondary_index"
    }
}
