// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{net::SocketAddr, ops::Range, convert::TryFrom};
use serde::{Deserialize, Serialize, ser};
use storage::persistent::{KeyValueSchema, BincodeEncoded, database::RocksDbKeyValueSchema};
use tezos_messages::p2p::{
    encoding::{
        connection::ConnectionMessage,
        metadata::MetadataMessage,
        ack::AckMessage,
        peer::{PeerMessage, PeerMessageResponse},
    },
    binary_message::BinaryRead,
};
use super::{
    common::{Initiator, Sender, MessageCategory, MessageKind, MessageType},
    connection, chunk,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    cn_ts: u64,
    cn_ts_nanos: u32,
    pub timestamp: u64,
    pub remote_addr: SocketAddr,
    pub initiator: Initiator,
    pub sender: Sender,
    pub ty: MessageType,
    chunks: Range<u64>,
}

impl Item {
    pub fn chunks(&self) -> impl Iterator<Item = chunk::Key> + '_ {
        let cn_id = connection::Key {
            ts: self.cn_ts,
            ts_nanos: self.cn_ts_nanos,
        };
        let sender = self.sender.clone();
        self.chunks.clone().map(move |counter| chunk::Key {
            cn_id: cn_id.clone(),
            counter,
            sender: sender.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageFrontend {
    id: u64,
    timestamp: u128,
    remote_addr: SocketAddr,
    source_type: Initiator,
    incoming: bool,
    category: MessageCategory,
    kind: Option<MessageKind>,
    message_preview: Option<String>,
}

impl MessageFrontend {
    pub fn new(item: Item, id: u64, message_preview: Option<String>) -> Self {
        let (category, kind) = item.ty.split();
        MessageFrontend {
            id,
            timestamp: (item.timestamp as u128) * 1_000_000,
            remote_addr: item.remote_addr,
            source_type: item.initiator,
            incoming: item.sender.incoming(),
            category,
            kind,
            message_preview,
        }
    }
}

#[derive(Debug)]
pub enum TezosMessage {
    ConnectionMessage(ConnectionMessage),
    MetadataMessage(MetadataMessage),
    AckMessage(AckMessage),
    PeerMessage(PeerMessage),
}

impl TezosMessage {
    pub fn json_string(&self) -> Result<String, serde_json::Error> {
        match self {
            TezosMessage::ConnectionMessage(m) => serde_json::to_string(m),
            TezosMessage::MetadataMessage(m) => serde_json::to_string(m),
            TezosMessage::AckMessage(m) => serde_json::to_string(m),
            TezosMessage::PeerMessage(m) => serde_json::to_string(m),
        }
    }
}

#[derive(Debug)]
pub struct MessageDetails {
    id: u64,
    message: Option<TezosMessage>,
    original_bytes: Vec<Vec<u8>>,
    decrypted_bytes: Vec<Vec<u8>>,
    error: Option<String>,
}

impl Serialize for MessageDetails {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use self::ser::SerializeStruct;

        struct HexString<'a>(&'a [Vec<u8>]);

        impl<'a> Serialize for HexString<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ser::Serializer,
            {
                use self::ser::SerializeSeq;

                let len = self.0.iter().map(|v| v.len()).sum();
                let mut s = serializer.serialize_seq(Some(len))?;
                for v in self.0 {
                    let hex = hex::encode(v);
                    for i in 0..v.len() {
                        s.serialize_element(&hex[(2 * i)..(2 * (i + 1))])?;
                    }
                }
                s.end()
            }
        }

        let mut s = serializer.serialize_struct("MessageDetails", 5)?;
        s.serialize_field("id", &self.id)?;
        match &self.message {
            Some(TezosMessage::ConnectionMessage(m)) => s.serialize_field("message", m)?,
            Some(TezosMessage::MetadataMessage(m)) => s.serialize_field("message", m)?,
            Some(TezosMessage::AckMessage(m)) => s.serialize_field("message", m)?,
            Some(TezosMessage::PeerMessage(m)) => s.serialize_field("message", m)?,
            None => s.serialize_field("message", &None::<()>)?,
        }
        s.serialize_field("original_bytes", &HexString(&self.original_bytes))?;
        s.serialize_field("decrypted_bytes", &HexString(&self.decrypted_bytes))?;
        s.serialize_field("error", &self.error)?;
        s.end()
    }
}

impl MessageDetails {
    pub fn new(id: u64, ty: &MessageType, chunks: &[chunk::Value]) -> Self {
        let mut bytes = Vec::with_capacity(chunks.iter().map(|c| c.plain.len()).sum());
        for c in chunks {
            bytes.extend_from_slice(&c.plain);
        }
        let message = match ty {
            MessageType::Connection => ConnectionMessage::from_bytes(&bytes)
                .map_err(|e| e.to_string())
                .map(TezosMessage::ConnectionMessage),
            MessageType::Meta => MetadataMessage::from_bytes(&bytes)
                .map_err(|e| e.to_string())
                .map(TezosMessage::MetadataMessage),
            MessageType::Ack => AckMessage::from_bytes(&bytes)
                .map_err(|e| e.to_string())
                .map(TezosMessage::AckMessage),
            MessageType::P2p(_) => PeerMessageResponse::from_bytes(&bytes)
                .map_err(|e| e.to_string())
                .map(|n| TezosMessage::PeerMessage(n.message().clone())),
        };
        let (message, error) = match message {
            Ok(m) => (Some(m), None),
            Err(e) => (None, Some(e)),
        };
        MessageDetails {
            id,
            message,
            original_bytes: chunks.iter().map(|c| c.bytes.clone()).collect(),
            decrypted_bytes: chunks.iter().map(|c| c.plain.clone()).collect(),
            error,
        }
    }

    pub fn json_string(&self) -> Result<Option<String>, serde_json::Error> {
        self.message.as_ref().map(|m| m.json_string()).transpose()
    }
}

pub struct MessageBuilder {
    ty: MessageType,
    length: u32,
    chunks: Range<u64>,
}

pub struct MessageBuilderFull(MessageBuilder);

impl MessageBuilder {
    pub fn connection_message() -> MessageBuilderFull {
        MessageBuilderFull(MessageBuilder {
            ty: MessageType::Connection,
            length: 0,
            chunks: 0..1,
        })
    }

    pub fn metadata_message() -> MessageBuilderFull {
        MessageBuilderFull(MessageBuilder {
            ty: MessageType::Meta,
            length: 0,
            chunks: 1..2,
        })
    }

    pub fn acknowledge_message() -> MessageBuilderFull {
        MessageBuilderFull(MessageBuilder {
            ty: MessageType::Ack,
            length: 0,
            chunks: 2..3,
        })
    }

    // chunk_number >= 3
    pub fn peer_message(bytes: [u8; 6], chunk_number: u64) -> Self {
        MessageBuilder {
            ty: MessageType::P2p({
                let tag = u16::from_be_bytes(<[u8; 2]>::try_from(&bytes[4..]).unwrap());
                MessageKind::from_tag(tag)
            }),
            length: u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[..4]).unwrap()) + 4,
            chunks: chunk_number..chunk_number,
        }
    }

    pub fn link_chunk(mut self, length: usize) -> Result<MessageBuilderFull, Option<Self>> {
        let length = length as u32;
        if self.length < length {
            Err(None)
        } else {
            self.length -= length;
            self.chunks.end += 1;
            if self.length == 0 {
                Ok(MessageBuilderFull(self))
            } else {
                Err(Some(self))
            }
        }
    }

    pub fn remaining(&self) -> usize {
        self.length as usize
    }
}

impl MessageBuilderFull {
    pub fn build(self, sender: &Sender, connection: &connection::Item) -> Item {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Item {
            cn_ts: connection.ts,
            cn_ts_nanos: connection.ts_nanos,
            timestamp,
            remote_addr: connection.remote_addr,
            initiator: connection.initiator.clone(),
            sender: sender.clone(),
            ty: self.0.ty,
            chunks: self.0.chunks,
        }
    }
}

impl BincodeEncoded for Item {}

pub struct Schema;

impl KeyValueSchema for Schema {
    type Key = u64;
    type Value = Item;
}

impl RocksDbKeyValueSchema for Schema {
    fn name() -> &'static str {
        "message_storage"
    }
}
