// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{convert::TryFrom, fmt, str::FromStr, num::ParseIntError};
use thiserror::Error;
use serde::{
    Serialize,
    ser::{self, SerializeStruct},
};
use rocksdb::{Cache, ColumnFamilyDescriptor};
use storage::persistent::{KeyValueSchema, Encoder, Decoder, SchemaError, database::RocksDbKeyValueSchema};
use super::{common::Sender, connection};

#[derive(Clone)]
pub struct Item {
    cn_id: connection::Key,
    pub sender: Sender,
    pub counter: u64,
    timestamp: u64,
    net: bool,
    pub bytes: Vec<u8>,
    pub plain: Vec<u8>,
}

impl Item {
    pub fn new(
        cn_id: connection::Key,
        sender: Sender,
        counter: u64,
        bytes: Vec<u8>,
        plain: Vec<u8>,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Item {
            cn_id,
            sender,
            counter,
            net: true,
            timestamp,
            bytes,
            plain,
        }
    }

    pub fn net(&mut self, net: bool) {
        self.net = net;
    }

    #[rustfmt::skip]
    pub fn split(self) -> (Key, Value) {
        let Item { cn_id, counter, sender, net, timestamp, bytes, plain } = self;
        (Key { cn_id, counter, sender }, Value { net, timestamp, bytes, plain })
    }
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("connection_id", &self.cn_id)
            .field("sender", &self.sender)
            .field("counter", &self.counter)
            .field("timestamp", &self.timestamp)
            .field("bytes", &hex::encode(&self.bytes))
            .field("plain", &hex::encode(&self.plain))
            .finish()
    }
}

#[derive(Debug, Default, Clone)]
pub struct Key {
    pub cn_id: connection::Key,
    pub counter: u64,
    pub sender: Sender,
}

impl Key {
    pub fn begin(cn_id: connection::Key) -> Key {
        Key {
            cn_id,
            counter: 0,
            sender: Sender::Local,
        }
    }

    pub fn end(cn_id: connection::Key) -> Key {
        Key {
            cn_id,
            counter: u64::MAX / 2,
            sender: Sender::Remote,
        }
    }
}

#[derive(Error, Debug)]
pub enum KeyFromStrError {
    #[error("wrong formatted chunk key")]
    ChunkKey,
    #[error("wrong formatted connection key {}", _0)]
    ConnectionKey(connection::KeyFromStrError),
    #[error("cannot parse decimal: {}", _0)]
    DecimalParse(ParseIntError),
}

impl FromStr for Key {
    type Err = KeyFromStrError;

    // format: [connection-key]-[sender]-[counter]
    // example: 1617005682.953928051-remote-15
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('-');
        let cn_id = parts
            .next()
            .ok_or(KeyFromStrError::ChunkKey)?
            .parse()
            .map_err(KeyFromStrError::ConnectionKey)?;
        let sender = parts.next().ok_or(KeyFromStrError::ChunkKey)?;
        let counter = parts
            .next()
            .ok_or(KeyFromStrError::ChunkKey)?
            .parse()
            .map_err(KeyFromStrError::DecimalParse)?;
        Ok(Key {
            cn_id,
            counter,
            sender: Sender::new(sender == "remote"),
        })
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}-{}",
            self.cn_id,
            self.sender.to_string(),
            self.counter
        )
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl Encoder for Key {
    fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        let mut v = Vec::with_capacity(20);
        v.extend_from_slice(&self.cn_id.encode()?);
        let c = if self.sender.incoming() {
            self.counter * 2 + 1
        } else {
            self.counter * 2
        };
        v.extend_from_slice(&c.to_be_bytes());
        Ok(v)
    }
}

impl Decoder for Key {
    fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
        if bytes.len() != 20 {
            return Err(SchemaError::DecodeError);
        }

        let c = u64::from_be_bytes(TryFrom::try_from(&bytes[12..]).unwrap());
        Ok(Key {
            cn_id: connection::Key::decode(&bytes[..12])?,
            counter: c / 2,
            sender: Sender::new(c & 1 != 0),
        })
    }
}

pub struct Value {
    net: bool,
    timestamp: u64,
    pub bytes: Vec<u8>,
    pub plain: Vec<u8>,
}

pub struct ValueTruncated(pub Value);

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut s = serializer.serialize_struct("Chunk", 4)?;
        s.serialize_field("net", &self.net)?;
        s.serialize_field("timestamp", &self.timestamp)?;
        s.serialize_field("bytes", &hex::encode(&self.bytes))?;
        s.serialize_field("plain", &hex::encode(&self.plain))?;
        s.end()
    }
}

impl Serialize for ValueTruncated {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let truncated_hex = |d: &[u8]| -> String {
            if d.len() > 0x10000 {
                format!(
                    "{}...truncated {} bytes",
                    hex::encode(&d[..0x10000]),
                    d.len() - 0x10000,
                )
            } else {
                hex::encode(d)
            }
        };

        let mut s = serializer.serialize_struct("Chunk", 3)?;
        s.serialize_field("net", &self.0.net)?;
        s.serialize_field("timestamp", &self.0.timestamp)?;
        s.serialize_field("bytes", &truncated_hex(&self.0.bytes))?;
        s.serialize_field("plain", &truncated_hex(&self.0.plain))?;
        s.end()
    }
}

impl Encoder for Value {
    fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        let mut v = Vec::with_capacity(self.bytes.len() + self.plain.len() + 17);
        v.extend_from_slice(&self.timestamp.to_le_bytes());
        v.extend_from_slice(&(self.bytes.len() as u64).to_le_bytes());
        v.push(if self.net { 1 } else { 0 });
        v.extend_from_slice(&self.bytes);
        v.extend_from_slice(&self.plain);
        Ok(v)
    }
}

impl Decoder for Value {
    fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
        if bytes.len() < 17 {
            return Err(SchemaError::DecodeError);
        }

        let len = u64::from_le_bytes(TryFrom::try_from(&bytes[8..16]).unwrap()) as usize;
        Ok(Value {
            net: bytes[16] != 0,
            timestamp: u64::from_le_bytes(TryFrom::try_from(&bytes[..8]).unwrap()),
            bytes: {
                if bytes.len() < 16 + len {
                    return Err(SchemaError::DecodeError);
                }
                bytes[17..(17 + len)].to_vec()
            },
            plain: bytes[(17 + len)..].to_vec(),
        })
    }
}

pub struct Schema;

impl KeyValueSchema for Schema {
    type Key = Key;
    type Value = Value;
}

impl RocksDbKeyValueSchema for Schema {
    fn descriptor(_cache: &Cache) -> ColumnFamilyDescriptor {
        use rocksdb::{Options, SliceTransform};

        let mut cf_opts = Options::default();
        cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(12));
        cf_opts.set_memtable_prefix_bloom_ratio(0.2);
        ColumnFamilyDescriptor::new(Self::name(), cf_opts)
    }

    fn name() -> &'static str {
        "chunk_storage"
    }
}
