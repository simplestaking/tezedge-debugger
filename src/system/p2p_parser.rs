// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{net::IpAddr, string::ToString};
use tokio::sync::mpsc;
use tracing::{trace, error, warn};
use tezos_messages::p2p::{
    encoding::{
        connection::ConnectionMessage,
        metadata::MetadataMessage,
        ack::AckMessage,
        peer::PeerMessageResponse,
    },
    binary_message::BinaryMessage,
};
use tezos_encoding::binary_reader::BinaryReaderError;
use tezos_conversation::{Conversation, Packet, ConsumeResult, Identity, ChunkInfoPair, ChunkMetadata, Sender};
use crate::{
    system::{SystemSettings, raw_socket_producer::P2pPacket},
    messages::{p2p_message::{P2pMessage, SourceType, TezosPeerMessage, PartialPeerMessage, HandshakeMessage}},
};

/// Spawn new p2p parser, returning channel to send packets for processing
pub fn spawn_p2p_parser(
    processor_sender: mpsc::UnboundedSender<P2pMessage>,
    settings: SystemSettings,
) -> mpsc::UnboundedSender<P2pPacket> {
    let (sender, receiver) = mpsc::unbounded_channel::<P2pPacket>();
    tokio::spawn(async move {
        let identity_json = serde_json::to_string(&settings.identity).unwrap();
        let identity = Identity::from_json(&identity_json).unwrap();
        let mut parser = Parser::new(settings.local_address.clone(), receiver, processor_sender, identity);
        while parser.parse_next().await {
            trace!("parsed new message");
        }
    });
    sender
}

/// TezosPacket -> P2pMessage
struct Parser {
    local_ip: IpAddr,
    receiver: mpsc::UnboundedReceiver<P2pPacket>,
    sender: mpsc::UnboundedSender<P2pMessage>,
    identity: Identity,
    conversation: Conversation,
    chunk_incoming_counter: usize,
    chunk_outgoing_counter: usize,
    buffer: Vec<u8>,
}

impl Parser {
    pub const DEFAULT_POW_TARGET: f64 = 26.0;

    pub fn new(
        local_ip: IpAddr,
        receiver: mpsc::UnboundedReceiver<P2pPacket>,
        sender: mpsc::UnboundedSender<P2pMessage>,
        identity: Identity,
    ) -> Self {
        Parser {
            local_ip,
            receiver,
            sender,
            identity,
            conversation: Conversation::new(Self::DEFAULT_POW_TARGET),
            chunk_incoming_counter: 0,
            chunk_outgoing_counter: 0,
            buffer: Vec::new(),
        }
    }

    pub fn inc(&mut self, incoming: bool) {
        if incoming {
            self.chunk_incoming_counter += 1;
        } else {
            self.chunk_outgoing_counter += 1;
        }
    }

    pub fn chunk(&self, incoming: bool) -> usize {
        if incoming {
            self.chunk_incoming_counter
        } else {
            self.chunk_outgoing_counter
        }
    }

    pub async fn parse_next(&mut self) -> bool {
        match self.receiver.recv().await {
            Some(packet) => {
                if packet.payload.is_empty() {
                    return true;
                }
                let packet = Packet {
                    source: packet.source_address,
                    destination: packet.destination_address,
                    number: packet.counter,
                    payload: packet.payload.to_vec(),
                };
                let (result, sender, _) = self.conversation.add(Some(&self.identity), &packet);
                let incoming = packet.source.ip() != self.local_ip;
                let remote_addr = if incoming {
                    assert_eq!(packet.destination.ip(), self.local_ip);
                    packet.source.clone()
                } else {
                    assert_eq!(packet.source.ip(), self.local_ip);
                    packet.destination.clone()
                };
                tracing::trace!(
                    number = packet.number,
                    sender = tracing::field::display(format!("{:?}", sender)),
                    chunk = self.chunk(incoming),
                    address = tracing::field::display(&remote_addr),
                    process_length = packet.payload.len(),
                    "processing packet",
                );
                let source_type = match sender {
                    Sender::Initiator => if incoming { SourceType::Remote } else { SourceType::Local },
                    Sender::Responder => if incoming { SourceType::Local } else { SourceType::Remote },
                };
                match result {
                    ConsumeResult::Pending => true,
                    ConsumeResult::ConnectionMessage(chunk_info) => {
                        let message = ConnectionMessage::from_bytes(&chunk_info.data()[2..])
                            .map(HandshakeMessage::ConnectionMessage)
                            .map(TezosPeerMessage::HandshakeMessage)
                            .map_err(|error| error.to_string());
                        let p2p_msg = P2pMessage::new(
                            remote_addr,
                            incoming,
                            source_type,
                            chunk_info.data().to_vec(),
                            chunk_info.data().to_vec(),
                            message,
                        );
                        if let Err(err) = self.sender.send(p2p_msg) {
                            error!(error = tracing::field::display(&err), "processor channel closed abruptly");
                            return false;
                        }
                        self.inc(incoming);
                        tracing::info!("connection message {}", remote_addr);
                        true
                    },
                    ConsumeResult::Chunks { regular, failed_to_decrypt } => {
                        for ChunkInfoPair { encrypted, decrypted } in regular {
                            let length = decrypted.data().len();
                            if length < 18 {
                                error!("the chunk is too small");
                                return true;
                            }
                            let content = &decrypted.data()[2..(length - 16)];
                            let message = match self.chunk(incoming) {
                                0 => {
                                    warn!("Connection message should not come here");
                                    ConnectionMessage::from_bytes(&decrypted.data()[2..])
                                        .map(HandshakeMessage::ConnectionMessage)
                                        .map(TezosPeerMessage::HandshakeMessage)
                                        .map_err(|error| error.to_string())
                                },
                                1 => MetadataMessage::from_bytes(content)
                                        .map(HandshakeMessage::MetadataMessage)
                                        .map(TezosPeerMessage::HandshakeMessage)
                                        .map_err(|error| error.to_string()),
                                2 => AckMessage::from_bytes(content)
                                        .map(HandshakeMessage::AckMessage)
                                        .map(TezosPeerMessage::HandshakeMessage)
                                        .map_err(|error| error.to_string()),
                                _ => {
                                    self.buffer.extend_from_slice(content);
                                    match PeerMessageResponse::from_bytes(self.buffer.as_slice()) {
                                        Err(e) => match &e {
                                            &BinaryReaderError::Underflow { .. } => {
                                                match PartialPeerMessage::from_bytes(self.buffer.as_slice()) {
                                                    Some(p) => Ok(TezosPeerMessage::PartialPeerMessage(p)),
                                                    None => Err(e.to_string()),
                                                }
                                            },
                                            _ => Err(e.to_string()),
                                        },
                                        Ok(r) => {
                                            self.buffer.clear();
                                            r.messages()
                                                .first()
                                                .ok_or("empty".to_string())
                                                .map(|m| TezosPeerMessage::PeerMessage(m.clone().into()))
                                        },
                                    }
                                },
                            };
                            let p2p_msg = P2pMessage::new(
                                remote_addr,
                                incoming,
                                source_type,
                                encrypted.data().to_vec(),
                                decrypted.data().to_vec(),
                                message,
                            );
                            if let Err(err) = self.sender.send(p2p_msg) {
                                error!(error = tracing::field::display(&err), "processor channel closed abruptly");
                                return false;
                            }
                            self.inc(incoming);
                        }
                        for chunk in &failed_to_decrypt {
                            let p2p_msg = P2pMessage::new(
                                remote_addr,
                                incoming,
                                source_type,
                                chunk.data().to_vec(),
                                Vec::new(),
                                Err("cannot decrypt".to_string()),
                            );
                            if let Err(err) = self.sender.send(p2p_msg) {
                                error!(error = tracing::field::display(&err), "processor channel closed abruptly");
                                return false;
                            }
                            self.inc(incoming);
                        }
                        failed_to_decrypt.is_empty()
                    },
                    ConsumeResult::NoDecipher(_) => {
                        warn!("identity wrong");
                        false
                    },
                    ConsumeResult::PowInvalid => {
                        warn!("received connection message with wrong pow, maybe foreign packet");
                        false
                    },
                    ConsumeResult::UnexpectedChunks | ConsumeResult::InvalidConversation => {
                        warn!("probably foreign packet");
                        false
                    },
                }
            }
            None => {
                error!("p2p parser channel closed abruptly");
                false
            }
        }
    }
}
