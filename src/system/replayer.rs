use std::{net::{SocketAddr, IpAddr}, iter::ExactSizeIterator, convert::TryFrom, io};
use tezos_messages::p2p::{
    binary_message::{BinaryMessage, BinaryChunk},
    encoding::{
        metadata::MetadataMessage,
        ack::AckMessage,
        advertise::AdvertiseMessage,
        peer::{PeerMessageResponse, PeerMessage},
    }
};
use tezos_conversation::{Decipher, Identity, NonceAddition};
use tokio::{net::{TcpStream, TcpListener}, io::{AsyncReadExt, AsyncWriteExt}};
use bytes::Buf;
use crate::messages::p2p_message::{P2pMessage, TezosPeerMessage, HandshakeMessage, FullPeerMessage};
use crate::storage::P2pMessageType;

/// Create an replay of given message onto the given address
pub async fn replay<I>(node_address: SocketAddr, messages: I) -> Result<(), failure::Error>
where
    I: Iterator<Item = P2pMessage> + ExactSizeIterator + Send + 'static,
{
    let mut messages = messages;

    // constant identity
    let identity = Identity::from_json("\
        {\
            \"peer_id\":\"idtJunqYgD1M6r6o2qvGpiD5xKZWRu\",\
            \"public_key\":\"7e8108e598b056b52cb430ee0e5e7ffd080b1b6bd9c9ad17dd9c44e2ced7fd75\",\
            \"secret_key\":\"a9f36be41dd4cfec7ec1e4a134d660254006e0ce16ae272f10dbc19a3097adcf\",\
            \"proof_of_work_stamp\":\"79eb7e72262e067a7e4e65fedacef484be52a35de686d1c8\"\
        }\
    ").unwrap();

    // identity to advertise
    let identity_advertiser = Identity::from_json("\
        {\
            \"peer_id\":\"idssJHDL1z8fkryZaYVF9fQRMktoWg\",\
            \"public_key\":\"d8246d13d0270cbfff4046b6d94b05ab19920bc5ad9fb77f3e945c40b340e874\",\
            \"secret_key\":\"8b4622bc512c8621a35fa19ff252129b208c8cdffb57e2d29c7974df718c7ff2\",\
            \"proof_of_work_stamp\":\"d1d0ebd55784bc92852d913dbf0fb5152d505b567d930fb2\"\
        }\
    ").unwrap();

    // TODO: error handling
    let init_connection_message = messages.next().unwrap();
    let resp_connection_message = messages.next().unwrap();

    let prepare_connection_message = |original: P2pMessage, identity: &Identity| -> Result<BinaryChunk, failure::Error> {
        let mut cm = original;
        let cm = cm.message.first_mut().unwrap().as_mut_cm().unwrap();
        cm.port = 0; // TODO: ?
        cm.public_key = identity.public_key();
        cm.proof_of_work_stamp = identity.proof_of_work();
        BinaryChunk::from_content(&cm.as_bytes()?)
            .map_err(Into::into)
    };

    let incoming = init_connection_message.incoming;
    tracing::info!(message_count = messages.len(), incoming, "starting replay of messages");
    if incoming {
        let cm_chunk = prepare_connection_message(init_connection_message, &identity)?;
        let mut stream = TcpStream::connect(node_address).await?;
        stream.write_all(cm_chunk.raw()).await?;
        let respond_cm_chunk = read_chunk_data(&mut stream).await?;
        let decipher = identity.decipher(cm_chunk.raw(), respond_cm_chunk.as_ref()).ok().unwrap();
        tracing::info!("handshake done");
        replay_messages(stream, messages, decipher, true).await
    } else {
        // Prepare Tcp Listener for incoming connection
        let mut listener = TcpListener::bind("0.0.0.0:0").await?;
        // Extract assigned port of the newly established listening port
        let listening_port = listener.local_addr()?.port();

        let cm_chunk = prepare_connection_message(resp_connection_message, &identity_advertiser)?;
        let mut stream = TcpStream::connect(node_address).await?;
        stream.write_all(cm_chunk.raw()).await?;
        let respond_cm_chunk = read_chunk_data(&mut stream).await?;
        let decipher = identity_advertiser.decipher(cm_chunk.raw(), respond_cm_chunk.as_ref()).ok().unwrap();

        let metadata = MetadataMessage::new(true, true);
        write_small_message(&mut stream, NonceAddition::Initiator(0), &decipher, metadata).await?;
        let _metadata = read_small_message::<_, MetadataMessage>(&mut stream, NonceAddition::Responder(0), &decipher).await?;

        let ack = AckMessage::Ack;
        write_small_message(&mut stream, NonceAddition::Initiator(1), &decipher, ack).await?;
        let ack = read_small_message::<_, AckMessage>(&mut stream, NonceAddition::Responder(1), &decipher).await?;
        tracing::info!("ack received {:#?}", ack);

        let advertise = PeerMessage::Advertise(AdvertiseMessage::new(&[
            SocketAddr::new(IpAddr::from([0, 0, 0, 0]), listening_port),
        ]));
        let message = PeerMessageResponse::from(advertise);
        write_small_message(&mut stream, NonceAddition::Initiator(2), &decipher, message).await?;
        tracing::info!("advertise sent");

        let (mut stream, _peer_addr) = listener.accept().await?;
        let cm_chunk = read_chunk_data(&mut stream).await?;
        let respond_cm_chunk = prepare_connection_message(init_connection_message, &identity)?;
        stream.write_all(respond_cm_chunk.raw()).await?;
        let decipher = identity.decipher(cm_chunk.as_ref(), respond_cm_chunk.raw()).ok().unwrap();
        tracing::info!("second handshake done");
        replay_messages(stream, messages, decipher, false).await
    }
}

async fn read_small_message<R, M>(
    stream: &mut R,
    adder: NonceAddition,
    decipher: &Decipher,
) -> Result<M, failure::Error>
where
    R: Unpin + AsyncReadExt,
    M: BinaryMessage,
{
    let data = read_chunk_data(stream).await?;
    let decrypted = decipher.decrypt(&data[2..], adder)?;
    M::from_bytes(decrypted).map_err(Into::into)
}

async fn write_small_message<W, M>(
    stream: &mut W,
    adder: NonceAddition,
    decipher: &Decipher,
    message: M,
) -> Result<(), failure::Error>
where
    W: Unpin + AsyncWriteExt,
    M: BinaryMessage,
{
    let mut bytes = message.as_bytes()?;
    let encrypted = decipher.encrypt(bytes.as_mut(), adder).unwrap();
    let chunk = BinaryChunk::from_content(encrypted.as_ref())?;
    stream.write_all(chunk.raw()).await.map_err(Into::into)
}

async fn read_chunk_data<R>(stream: &mut R) -> Result<Vec<u8>, io::Error>
where
    R: Unpin + AsyncReadExt,
{
    let mut chunk_buffer = vec![0; 0x10000];
    stream.read_exact(&mut chunk_buffer[0..2]).await?;
    let size = (&chunk_buffer[0..2]).get_u16() as usize;
    stream.read_exact(&mut chunk_buffer[2..(2 + size)]).await?;
    chunk_buffer.drain((size + 2)..);

    Ok(chunk_buffer)
}

async fn replay_messages<I>(
    stream: TcpStream,
    messages: I,
    decipher: Decipher,
    incoming: bool,
) -> Result<(), failure::Error>
where
    I: Iterator<Item = P2pMessage> + Send + 'static,
{
    tokio::time::delay_for(std::time::Duration::from_secs(1)).await;
    let mut initiators = 0;
    let mut responders = 0;
    let mut stream = stream;
    let mut reply = Vec::with_capacity(0x10000);
    for message in messages {
        // if this message is incoming and first message is also incoming
        // or this message is outgoing and first message is also outgoing
        // then the message goes from initiator
        let (chunk_number, counter) = if message.incoming == incoming {
            (NonceAddition::Initiator(initiators), &mut initiators)
        } else {
            (NonceAddition::Responder(responders), &mut responders)
        };
        if message.incoming {
            let mut bytes = message.decrypted_bytes;
            let l = bytes.len();
            let will_send_message = deserialize(*counter, &bytes[2..(l - 16)]);
            tracing::info!("replay chunk\nSENT: {:x?}", will_send_message);
            let encrypted = decipher.encrypt(&mut bytes[2..(l - 16)], chunk_number.clone()).unwrap();
            bytes[2..l].clone_from_slice(encrypted.as_ref());
            let chunk = BinaryChunk::try_from(bytes).unwrap();
            reply.extend_from_slice(chunk.raw());
        } else {
            if !reply.is_empty() {
                stream.write_all(reply.as_ref()).await?;
                reply.clear();
            }
            let mut chunk = read_chunk_data(&mut stream).await?;
            let l = chunk.len();
            let decrypted = decipher.decrypt(&chunk[2..], chunk_number).unwrap();
            let received_message = deserialize(*counter, decrypted.as_slice());
            chunk[2..(l - 16)].clone_from_slice(decrypted.as_ref());
            let expected = &message.decrypted_bytes[2..(message.decrypted_bytes.len() - 16)];
            if decrypted != expected {
                let expected_message = deserialize(*counter, expected);
                tracing::warn!("unexpected chunk\nRECEIVED: {:x?}\nEXPECTED: {:x?}", received_message, expected_message);
            } else {
                tracing::info!("expected chunk\nRECEIVED: {:x?}", received_message);
            }
        }
        *counter += 1;
    }
    Ok(())
}

fn deserialize(counter: u64, data: &[u8]) -> Result<(P2pMessageType, String), failure::Error> {
    match counter {
        0 => {
            let m = MetadataMessage::from_bytes(data)?;
            let s = format!("{:x?}", m);
            let ty = P2pMessageType::extract_from_tezos_peer_message(&TezosPeerMessage::HandshakeMessage(HandshakeMessage::MetadataMessage(m)));
            Ok((ty, s))
        },
        1 => {
            let m = AckMessage::from_bytes(data)?;
            let s = format!("{:x?}", m);
            let ty = P2pMessageType::extract_from_tezos_peer_message(&TezosPeerMessage::HandshakeMessage(HandshakeMessage::AckMessage(m)));
            Ok((ty, s))
        },
        _ => {
            let m: PeerMessageResponse = PeerMessageResponse::from_bytes(data)?;
            let m = m.messages().first()
                .ok_or(failure::Error::from(io::Error::new(io::ErrorKind::NotFound, "empty")))?;
            let s = format!("{:x?}", m);
            let ty = P2pMessageType::extract_from_tezos_peer_message(&TezosPeerMessage::PeerMessage(FullPeerMessage::from(m.clone())));
            Ok((ty, s))
        }
    }
}
