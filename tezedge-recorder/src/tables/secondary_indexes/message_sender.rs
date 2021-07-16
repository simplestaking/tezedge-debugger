// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::convert::TryFrom;
use storage::persistent::{KeyValueSchema, Encoder, Decoder, SchemaError, database::RocksDbKeyValueSchema};
use rocksdb::{ColumnFamilyDescriptor, Cache};
use super::*;

/// WARNING: this index work only with 56 bit index, should be enough
/// * bytes layout: `[sender(1)][index(7)]`
pub struct Item {
    pub sender: Sender,
    pub index: u64,
}

impl Encoder for Item {
    fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        let mut v = self.index.to_be_bytes();
        v[0] = if self.sender.incoming() { 0xff } else { 0x00 };
        Ok(v.into())
    }
}

impl Decoder for Item {
    fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
        let mut bytes = <[u8; 8]>::try_from(bytes).map_err(|_| SchemaError::DecodeError)?;
        let sender = Sender::new(bytes[0] != 0);
        bytes[0] = 0;
        Ok(Item {
            sender,
            index: u64::from_be_bytes(bytes),
        })
    }
}

pub struct Schema;

impl KeyValueSchema for Schema {
    type Key = Item;
    type Value = ();
}

impl RocksDbKeyValueSchema for Schema {
    fn descriptor(_cache: &Cache) -> ColumnFamilyDescriptor {
        use rocksdb::{Options, SliceTransform};

        let mut cf_opts = Options::default();
        cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(1));
        cf_opts.set_memtable_prefix_bloom_ratio(0.2);
        ColumnFamilyDescriptor::new(Self::name(), cf_opts)
    }

    fn name() -> &'static str {
        "message_sender_secondary_index"
    }
}
