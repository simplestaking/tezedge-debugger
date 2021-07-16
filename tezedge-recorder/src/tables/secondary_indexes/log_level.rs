// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::convert::TryFrom;
use storage::persistent::{KeyValueSchema, Encoder, Decoder, SchemaError, database::RocksDbKeyValueSchema};
use rocksdb::{ColumnFamilyDescriptor, Cache};
use super::*;

/// WARNING: this index work only with 56 bit index, should be enough
/// * bytes layout: `[level(1)][index(7)]`
pub struct Item {
    pub lv: LogLevel,
    pub index: u64,
}

impl Encoder for Item {
    fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        let mut v = self.index.to_be_bytes();
        v[0] = self.lv.clone() as u8;
        Ok(v.into())
    }
}

impl Decoder for Item {
    fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
        let mut bytes = <[u8; 8]>::try_from(bytes).map_err(|_| SchemaError::DecodeError)?;
        let lv = LogLevel::try_from(bytes[0])
            .map_err(|e| SchemaError::DecodeValidationError(e.to_string()))?;
        bytes[0] = 0;
        Ok(Item {
            lv,
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
        "log_level_secondary_index"
    }
}
