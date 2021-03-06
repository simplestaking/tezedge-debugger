// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use super::{
    chunk_parser::ChunkHandler,
    Database,
    tables::{connection, chunk, message},
};

pub struct MessageParser<Db> {
    builder: Option<message::MessageBuilder>,
    error: bool,
    db: Arc<Db>,
}

impl<Db> MessageParser<Db>
where
    Db: Database,
{
    pub fn new(db: Arc<Db>) -> Self {
        MessageParser {
            builder: None,
            error: false,
            db,
        }
    }
}

impl<Db> ChunkHandler for MessageParser<Db>
where
    Db: Database,
{
    fn handle_chunk(&mut self, chunk: chunk::Item, cn: &mut connection::Item) {
        use std::convert::TryFrom;
        use self::message::MessageBuilder;
        use super::common::MessageKind;

        let too_small = match chunk.counter {
            0 => chunk.plain.len() < 82,
            1 => chunk.plain.len() < 2,
            2 => chunk.plain.is_empty(),
            _ => {
                if self.builder.is_some() {
                    chunk.plain.is_empty()
                } else {
                    chunk.plain.len() < 6
                }
            },
        };

        if self.error || too_small {
            self.error = true;
            if !chunk.bytes.is_empty() {
                self.db.store_chunk(chunk);
            }
            return;
        }

        let sender = &chunk.sender;

        let message = match chunk.counter {
            0 => Some(MessageBuilder::connection_message().build(&sender, &cn)),
            1 => Some(MessageBuilder::metadata_message().build(&sender, &cn)),
            2 => Some(MessageBuilder::acknowledge_message().build(&sender, &cn)),
            c => {
                let building_result = self
                    .builder
                    .take()
                    .and_then(|builder| {
                        // we already have some builder
                        if chunk.bytes.len() < 6 {
                            return Some(builder);
                        }
                        let bytes = &chunk.bytes[..6];
                        let len = u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[..4]).unwrap());
                        let tag = u16::from_be_bytes(<[u8; 2]>::try_from(&bytes[4..]).unwrap());
                        // but first 6 bytes seems it is a new message
                        // the probability that arbitrary 6 bytes pass such check is:
                        // `(20 / 2 ^ 16) * (1 << 24) / (1 << 32)`, fairly small
                        if MessageKind::from_tag(tag).valid_tag() && len < 1 << 24 {
                            cn.add_comment().incoming_suspicious = Some(c);
                            // return here `None` to reset the builder
                            Some(builder)
                        } else {
                            Some(builder)
                        }
                    })
                    .unwrap_or_else(|| {
                        let six_bytes = <[u8; 6]>::try_from(&chunk.plain[0..6]).unwrap();
                        MessageBuilder::peer_message(six_bytes, chunk.counter)
                    })
                    .link_chunk(chunk.plain.len());
                match building_result {
                    Ok(builder_full) => Some(builder_full.build(&sender, &cn)),
                    Err(builder) => {
                        self.builder = builder;
                        None
                    },
                }
            },
        };

        self.db.store_chunk(chunk);
        if let Some(message) = message {
            self.db.store_message(message);
        }
    }

    fn update_cn(&mut self, cn: &connection::Item) {
        self.db.update_connection(cn.clone());
    }
}
