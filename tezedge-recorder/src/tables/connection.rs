// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{convert::TryFrom, net::SocketAddr, num::ParseIntError, str::FromStr, fmt};
use thiserror::Error;
use serde::{
    Serialize,
    ser::{self, SerializeSeq, SerializeStruct},
};
use typenum::Bit;
use storage::persistent::{KeyValueSchema, Encoder, Decoder, SchemaError, database::RocksDbKeyValueSchema};
use super::common::{Initiator, Sender};

#[derive(Debug, Clone, Default)]
pub struct Comments {
    pub incoming_wrong_pow: Option<f64>,
    pub incoming_too_short: Option<usize>,
    pub incoming_uncertain: bool,
    pub incoming_cannot_decrypt: Option<u64>,
    pub incoming_suspicious: Option<u64>,
    pub outgoing_wrong_pow: Option<f64>,
    pub outgoing_too_short: Option<usize>,
    pub outgoing_uncertain: bool,
    pub outgoing_wrong_pk: bool,
    pub outgoing_cannot_decrypt: Option<u64>,
}

impl Comments {
    fn ser(&self) -> ([u8; 18], [u8; 18]) {
        let mut i = [0; 18];
        i[0] = self.incoming_wrong_pow.as_ref().cloned().unwrap_or(0.0) as u8;
        i[1] = self
            .incoming_too_short
            .as_ref()
            .cloned()
            .unwrap_or(u8::MAX as _) as u8;
        i[2] = if self.incoming_uncertain { 1 } else { 0 };
        let c = self
            .incoming_cannot_decrypt
            .as_ref()
            .cloned()
            .unwrap_or(u64::MAX);
        i[4..12].clone_from_slice(&c.to_le_bytes());
        i[12..16].clone_from_slice(&(self.incoming_suspicious.unwrap_or(0) as u32).to_le_bytes());
        let mut o = [0; 18];
        o[0] = self.outgoing_wrong_pow.as_ref().cloned().unwrap_or(0.0) as u8;
        o[1] = self
            .outgoing_too_short
            .as_ref()
            .cloned()
            .unwrap_or(u8::MAX as _) as u8;
        o[2] = if self.outgoing_uncertain { 1 } else { 0 };
        o[3] = if self.outgoing_wrong_pk { 1 } else { 0 };
        let c = self
            .outgoing_cannot_decrypt
            .as_ref()
            .cloned()
            .unwrap_or(u64::MAX);
        o[4..12].clone_from_slice(&c.to_le_bytes());

        (i, o)
    }

    fn de((i, o): ([u8; 18], [u8; 18])) -> Self {
        let i_c = u64::from_le_bytes(TryFrom::try_from(&i[4..12]).unwrap());
        let i_s = u32::from_le_bytes(TryFrom::try_from(&i[12..16]).unwrap()) as u64;
        let o_c = u64::from_le_bytes(TryFrom::try_from(&o[4..12]).unwrap());
        Comments {
            incoming_wrong_pow: if i[0] == 0 { None } else { Some(i[0] as f64) },
            incoming_too_short: if i[1] == u8::MAX {
                None
            } else {
                Some(i[1] as usize)
            },
            incoming_uncertain: i[2] != 0,
            incoming_suspicious: if i_s == 0 { None } else { Some(i_c) }, 
            incoming_cannot_decrypt: if i_c == u64::MAX { None } else { Some(i_c) },
            outgoing_wrong_pow: if o[0] == 0 { None } else { Some(o[0] as f64) },
            outgoing_too_short: if o[1] == u8::MAX {
                None
            } else {
                Some(o[1] as usize)
            },
            outgoing_uncertain: o[2] != 0,
            outgoing_wrong_pk: o[3] != 0,
            outgoing_cannot_decrypt: if o_c == u64::MAX { None } else { Some(o_c) },
        }
    }
}

impl Serialize for Comments {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut s = serializer.serialize_seq(None)?;
        if let Some(target) = self.incoming_wrong_pow {
            let msg = format!(
                "incoming connection message bad proof-of-work, target: {}",
                target
            );
            s.serialize_element(&msg)?;
        }
        if let Some(size) = self.incoming_too_short {
            let msg = format!("incoming connection message is too short: {} bytes", size);
            s.serialize_element(&msg)?;
        }
        if self.incoming_uncertain {
            let msg = "incoming data does not look like a connection message";
            s.serialize_element(&msg)?;
        }
        if let Some(n) = self.incoming_suspicious {
            let msg = format!("incoming message lack chunks, at: {}", n);
            s.serialize_element(&msg)?;
        }
        if let Some(position) = self.incoming_cannot_decrypt {
            let msg = format!("incoming chunk cannot decrypt, position: {}", position);
            s.serialize_element(&msg)?;
        }
        if let Some(target) = self.outgoing_wrong_pow {
            let msg = format!(
                "outgoing connection message bad proof-of-work, target: {}",
                target
            );
            s.serialize_element(&msg)?;
        }
        if let Some(size) = self.outgoing_too_short {
            let msg = format!("outgoing connection message is too short: {} bytes", size);
            s.serialize_element(&msg)?;
        }
        if self.outgoing_uncertain {
            let msg = "outgoing data does not look like a connection message";
            s.serialize_element(&msg)?;
        }
        if self.outgoing_wrong_pk {
            let msg = "outgoing connection message public key does not match with identity";
            s.serialize_element(&msg)?;
        }
        if let Some(position) = self.outgoing_cannot_decrypt {
            let msg = format!("outgoing chunk cannot decrypt, position: {}", position);
            s.serialize_element(&msg)?;
        }

        s.end()
    }
}

#[derive(Debug, Clone)]
pub struct Item {
    pub ts: u64,
    pub ts_nanos: u32,
    pub initiator: Initiator,
    pub remote_addr: SocketAddr,
    peer_pk: [u8; 32],
    comments: Comments,
}

impl Item {
    pub fn new(initiator: Initiator, remote_addr: SocketAddr) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let ts = (timestamp / 1_000_000_000) as u64;
        let ts_nanos = (timestamp % 1_000_000_000) as u32;

        Item {
            ts,
            ts_nanos,
            initiator,
            remote_addr,
            peer_pk: [0; 32],
            comments: Comments::default(),
        }
    }

    pub fn set_peer_pk(&mut self, peer_pk: [u8; 32]) {
        self.peer_pk = peer_pk;
    }

    pub fn add_comment(&mut self) -> &mut Comments {
        &mut self.comments
    }

    pub fn mark_uncertain(&mut self) {
        let cn_value = match serde_json::to_string(&self.value()) {
            Ok(s) => s,
            Err(s) => format!("{:?}", s),
        };
        log::warn!("uncertain connection: {}, {}", cn_value, self.key(),);
        self.add_comment().incoming_uncertain = true;
        self.add_comment().outgoing_uncertain = true;
    }

    pub fn mark_cannot_decrypt<S>(&mut self, position: u64)
    where
        S: Bit,
    {
        let cn_value = match serde_json::to_string(&self.value()) {
            Ok(s) => s,
            Err(s) => format!("{:?}", s),
        };
        log::warn!(
            "cannot decrypt: {}-{}-{}, connection: {}",
            self.key(),
            Sender::new(S::BOOL),
            position,
            cn_value,
        );
        if S::BOOL {
            self.add_comment().incoming_cannot_decrypt = Some(position);
        } else {
            self.add_comment().outgoing_cannot_decrypt = Some(position);
        }
    }

    #[rustfmt::skip]
    pub fn split(self) -> (Key, Value) {
        let Item { ts, ts_nanos, initiator, remote_addr, peer_pk, comments } = self;
        (Key { ts, ts_nanos }, Value { initiator, remote_addr, peer_pk, comments })
    }

    #[rustfmt::skip]
    pub fn unite(key: Key, value: Value) -> Self {
        let (Key { ts, ts_nanos }, Value { initiator, remote_addr, peer_pk, comments }) = (key, value);
        Item { ts, ts_nanos, initiator, remote_addr, peer_pk, comments }
    }

    pub fn key(&self) -> Key {
        Key {
            ts: self.ts,
            ts_nanos: self.ts_nanos,
        }
    }

    pub fn value(&self) -> Value {
        Value {
            initiator: self.initiator.clone(),
            remote_addr: self.remote_addr,
            peer_pk: self.peer_pk,
            comments: self.comments.clone(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Key {
    pub ts: u64,
    pub ts_nanos: u32,
}

#[derive(Error, Debug)]
pub enum KeyFromStrError {
    #[error("wrong formatted connection key")]
    ConnectionKey,
    #[error("cannot parse decimal: {}", _0)]
    DecimalParse(ParseIntError),
}

impl FromStr for Key {
    type Err = KeyFromStrError;

    // format: [seconds].[nanos]
    // example: 1617005682.953928051
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('.');
        let ts = parts
            .next()
            .ok_or(KeyFromStrError::ConnectionKey)?
            .parse()
            .map_err(KeyFromStrError::DecimalParse)?;
        let ts_nanos = parts
            .next()
            .ok_or(KeyFromStrError::ConnectionKey)?
            .parse()
            .map_err(KeyFromStrError::DecimalParse)?;
        Ok(Key { ts, ts_nanos })
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.ts, self.ts_nanos)
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
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(&self.ts.to_be_bytes());
        v.extend_from_slice(&self.ts_nanos.to_be_bytes());
        Ok(v)
    }
}

impl Decoder for Key {
    fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
        if bytes.len() != 12 {
            return Err(SchemaError::DecodeError);
        }

        Ok(Key {
            ts: u64::from_be_bytes(TryFrom::try_from(&bytes[..8]).unwrap()),
            ts_nanos: u32::from_be_bytes(TryFrom::try_from(&bytes[8..]).unwrap()),
        })
    }
}

// ip 16 bytes, port 2 bytes, initiator 1 byte, padding 1 byte, comments 36 bytes, peer_pk 32 bytes
pub struct Value {
    initiator: Initiator,
    remote_addr: SocketAddr,
    peer_pk: [u8; 32],
    comments: Comments,
}

impl Encoder for Value {
    fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        use std::net::IpAddr;

        let mut v = Vec::with_capacity(88);

        let ip = match self.remote_addr.ip() {
            IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
            IpAddr::V6(ip) => ip.octets(),
        };
        v.extend_from_slice(&ip);
        v.extend_from_slice(&self.remote_addr.port().to_le_bytes());

        v.push(if self.initiator.incoming() { 1 } else { 0 });
        v.push(0);

        let (i, o) = self.comments.ser();
        v.extend_from_slice(&i);
        v.extend_from_slice(&o);

        v.extend_from_slice(&self.peer_pk);

        Ok(v)
    }
}

impl Decoder for Value {
    fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
        if bytes.len() != 88 {
            return Err(SchemaError::DecodeError);
        }

        Ok(Value {
            initiator: Initiator::new(bytes[18] != 0),
            remote_addr: {
                let ip = <[u8; 16]>::try_from(&bytes[0..16]).unwrap();
                let port = u16::from_le_bytes(TryFrom::try_from(&bytes[16..18]).unwrap());
                (ip, port).into()
            },
            peer_pk: TryFrom::try_from(&bytes[56..88]).unwrap(),
            comments: {
                let i = TryFrom::try_from(&bytes[20..38]).unwrap();
                let o = TryFrom::try_from(&bytes[38..56]).unwrap();
                Comments::de((i, o))
            },
        })
    }
}

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use crypto::{blake2b, hash::HashType};

        let calc_peer_id = || -> Result<String, String> {
            if self.peer_pk == [0; 32] {
                return Err("unknown".to_string());
            }
            let hash = blake2b::digest_128(&self.peer_pk).map_err(|e| e.to_string())?;
            HashType::CryptoboxPublicKeyHash
                .hash_to_b58check(&hash)
                .map_err(|e| e.to_string())
        };
        let peer_id = match calc_peer_id() {
            Ok(s) => s,
            Err(s) => s,
        };

        let mut s = serializer.serialize_struct("Connection", 4)?;
        s.serialize_field("initiator", &self.initiator)?;
        s.serialize_field("remote_addr", &self.remote_addr)?;
        s.serialize_field("peer_id", &peer_id)?;
        s.serialize_field("comments", &self.comments)?;
        s.end()
    }
}

pub struct Schema;

impl KeyValueSchema for Schema {
    type Key = Key;
    type Value = Value;
}

impl RocksDbKeyValueSchema for Schema {
    fn name() -> &'static str {
        "connection_storage"
    }
}
