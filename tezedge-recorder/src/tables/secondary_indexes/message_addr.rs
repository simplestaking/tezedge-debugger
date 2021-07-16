// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{
    convert::TryFrom,
    net::{SocketAddr, IpAddr},
};
use storage::persistent::{KeyValueSchema, Encoder, Decoder, SchemaError, database::RocksDbKeyValueSchema};
use rocksdb::{ColumnFamilyDescriptor, Cache};

/// WARNING: this index work only with 48 bit index, should be enough
/// * bytes layout: `[addr(16)][port(2)][index(6)]`
pub struct Item {
    pub addr: SocketAddr,
    pub index: u64,
}

impl Encoder for Item {
    fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        let mut v = Vec::with_capacity(24);

        let ip = match self.addr.ip() {
            IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
            IpAddr::V6(ip) => ip.octets(),
        };
        v.extend_from_slice(&ip);
        v.extend_from_slice(&self.addr.port().to_le_bytes());
        v.extend_from_slice(&self.index.to_be_bytes()[2..]);

        Ok(v)
    }
}

impl Decoder for Item {
    fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
        if bytes.len() != 24 {
            return Err(SchemaError::DecodeError);
        }

        Ok(Item {
            addr: {
                let ip = <[u8; 16]>::try_from(&bytes[..16]).unwrap();
                let port = u16::from_le_bytes(TryFrom::try_from(&bytes[16..18]).unwrap());
                (ip, port).into()
            },
            index: {
                let mut bytes = <[u8; 8]>::try_from(&bytes[16..]).unwrap();
                bytes[0] = 0;
                bytes[1] = 0;
                u64::from_be_bytes(bytes)
            },
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
        cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(18));
        cf_opts.set_memtable_prefix_bloom_ratio(0.2);
        ColumnFamilyDescriptor::new(Self::name(), cf_opts)
    }

    fn name() -> &'static str {
        "message_address_secondary_index"
    }
}
