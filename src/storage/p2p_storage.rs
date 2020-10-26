// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use storage::{StorageError, persistent::{KeyValueSchema, KeyValueStoreWithSchema}, IteratorMode, Direction};
use tracing::{info, warn};
use rocksdb::DB;
use std::{
    sync::{
        atomic::{Ordering, AtomicU64}, Arc,
    }, net::SocketAddr,
};
use crate::storage::{secondary_index::SecondaryIndex, dissect};
use crate::storage::sorted_intersect::sorted_intersect;
use secondary_indexes::*;
use itertools::Itertools;
use crate::messages::p2p_message::P2pMessage;

/// Defined Key Value store for Log storage
pub type P2pMessageStorageKV = dyn KeyValueStoreWithSchema<P2pStore> + Sync + Send;

#[derive(Debug, Default, Clone)]
/// Allowed filters for p2p message store
pub struct P2pFilters {
    pub remote_addr: Option<SocketAddr>,
    pub types: Option<u32>,
    pub request_id: Option<u64>,
    pub incoming: Option<bool>,
    pub source_type: Option<bool>,
}

impl P2pFilters {
    /// Check, if there are no set filters
    pub fn empty(&self) -> bool {
        self.remote_addr.is_none() && self.types.is_none()
            && self.request_id.is_none() && self.incoming.is_none()
            && self.source_type.is_none()
    }
}

#[derive(Clone)]
/// P2P message store
pub struct P2pStore {
    kv: Arc<P2pMessageStorageKV>,
    remote_addr_index: RemoteAddrIndex,
    type_index: TypeIndex,
    incoming_index: IncomingIndex,
    source_type_index: SourceTypeIndex,
    count: Arc<AtomicU64>,
    seq: Arc<AtomicU64>,
}

#[allow(dead_code)]
impl P2pStore {
    /// Create new store on top of the RocksDB
    pub fn new(kv: Arc<DB>) -> Self {
        Self {
            kv: kv.clone(),
            remote_addr_index: RemoteAddrIndex::new(kv.clone()),
            type_index: TypeIndex::new(kv.clone()),
            incoming_index: IncomingIndex::new(kv.clone()),
            source_type_index: SourceTypeIndex::new(kv.clone()),
            count: Arc::new(AtomicU64::new(0)),
            seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get current index
    fn index(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }

    /// Increment count of messages in the store
    fn inc_count(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }

    /// Reserve new index for later use. The index must be manually inserted
    /// with [LogStore::put_message]
    pub fn reserve_index(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Create all indexes for given value
    pub fn make_indexes(&self, primary_index: u64, value: &P2pMessage) -> Result<(), StorageError> {
        self.remote_addr_index.store_index(&primary_index, value)?;
        self.type_index.store_index(&primary_index, value)?;
        self.incoming_index.store_index(&primary_index, value)?;
        self.source_type_index.store_index(&primary_index, value)
    }

    /// Put messages onto specific index
    pub fn delete_indexes(&self, primary_index: u64, value: &P2pMessage) -> Result<(), StorageError> {
        self.remote_addr_index.delete_index(&primary_index, value)?;
        self.type_index.delete_index(&primary_index, value)?;
        self.incoming_index.delete_index(&primary_index, value)?;
        self.source_type_index.delete_index(&primary_index, value)
    }

    /// Store message at the end of the store. Return ID of newly inserted value
    pub fn put_message(&self, index: u64, msg: &P2pMessage) -> Result<(), StorageError> {
        if self.kv.contains(&index)? {
            self.kv.merge(&index, &msg)?;
        } else {
            self.kv.put(&index, &msg)?;
            self.inc_count();
        }
        self.make_indexes(index, msg)?;
        Ok(())
    }

    /// Create cursor into the database, allowing iteration over values matching given filters.
    /// Values are sorted by the index in descending order.
    /// * Arguments:
    /// - cursor_index: Index of start of the sequence (if no value provided, start at the end)
    /// - limit: Limit result to maximum of specified value
    /// - filters: Specified filters for values
    pub fn store_message(&self, msg: &mut P2pMessage) -> Result<u64, StorageError> {
        let index = self.reserve_index();
        msg.id = Some(index);
        self.kv.put(&index, &msg)?;
        self.make_indexes(index, &msg)?;
        self.inc_count();
        Ok(index)
    }

    /// Create iterator ending on given index. If no value is provided
    /// start at the end
    pub fn get_cursor(&self, cursor_index: Option<u64>, limit: usize, filters: P2pFilters) -> Result<Vec<P2pMessage>, StorageError> {
        let mut ret = Vec::with_capacity(limit);
        if filters.empty() {
            ret.extend(self.cursor_iterator(cursor_index)?.take(limit).map(|(_, value)| value));
        } else {
            let mut iters: Vec<Box<dyn Iterator<Item=u64>>> = Default::default();
            if let Some(remote_addr) = filters.remote_addr {
                iters.push(self.remote_addr_iterator(cursor_index, remote_addr)?);
            }
            if let Some(types) = filters.types {
                if types != 0 {
                    iters.push(self.type_iterator(cursor_index, types)?);
                }
            }
            if let Some(incoming) = filters.incoming {
                iters.push(self.incoming_iterator(cursor_index, incoming)?);
            }
            if let Some(source_type) = filters.source_type {
                iters.push(self.source_type_iterator(cursor_index, source_type)?);
            }
            ret.extend(self.load_indexes(sorted_intersect(iters, limit).into_iter()));
        }
        Ok(ret)
    }

    /// Create iterator with at maximum given index, having specified log level
    fn cursor_iterator<'a>(&'a self, cursor_index: Option<u64>) -> Result<Box<dyn 'a + Iterator<Item=(u64, P2pMessage)>>, StorageError> {
        Ok(Box::new(self.kv.iterator(IteratorMode::From(&cursor_index.unwrap_or(std::u64::MAX), Direction::Reverse))?
            .filter_map(|(k, v)| {
                k.ok().and_then(|key| Some((key, v.ok()?)))
            })))
    }

    /// Create iterator with at maximum given index, having specified remote address
    fn remote_addr_iterator<'a>(&'a self, cursor_index: Option<u64>, remote_addr: SocketAddr) -> Result<Box<dyn 'a + Iterator<Item=u64>>, StorageError> {
        Ok(Box::new(self.remote_addr_index.get_concrete_prefix_iterator(&cursor_index.unwrap_or(std::u64::MAX), remote_addr)?
            .filter_map(|(_, value)| {
                value.ok()
            })))
    }

    /// Create iterator with at maximum given index, having specified type of message
    pub fn type_iterator<'a>(&'a self, cursor_index: Option<u64>, types: u32) -> Result<Box<dyn 'a + Iterator<Item=u64>>, StorageError> {
        let types = dissect(types);
        let mut iterators = Vec::with_capacity(types.len());
        for r#type in types {
            iterators.push(self.type_index.get_concrete_prefix_iterator(&cursor_index.unwrap_or(std::u64::MAX), r#type)?
                .filter_map(|(_, value)| {
                    value.ok()
                }));
        }
        Ok(Box::new(iterators.into_iter().kmerge_by(|x, y| x > y)))
    }

    /// Create iterator with at maximum given index, having incoming flag set to specific value
    pub fn incoming_iterator<'a>(&'a self, cursor_index: Option<u64>, is_incoming: bool) -> Result<Box<dyn 'a + Iterator<Item=u64>>, StorageError> {
        Ok(Box::new(self.incoming_index.get_concrete_prefix_iterator(&cursor_index.unwrap_or(std::u64::MAX), is_incoming)?
            .filter_map(|(_, value)| {
                value.ok()
            })))
    }

    pub fn source_type_iterator<'a>(&'a self, cursor_index: Option<u64>, source_type: bool) -> Result<Box<dyn 'a + Iterator<Item=u64>>, StorageError> {
        Ok(Box::new(self.source_type_index.get_concrete_prefix_iterator(&cursor_index.unwrap_or(std::u64::MAX), source_type)?
            .filter_map(|(_, value)| {
                value.ok()
            })))
    }

    /// Load all values for indexes given.
    pub fn load_indexes<Iter: 'static + Iterator<Item=u64>>(&self, indexes: Iter) -> impl Iterator<Item=P2pMessage> + 'static {
        let kv = self.kv.clone();
        indexes.filter_map(move |index| {
            match kv.get(&index) {
                Ok(Some(value)) => {
                    Some(value)
                }
                Ok(None) => {
                    info!("No value at index: {}", index);
                    None
                }
                Err(err) => {
                    warn!("Failed to load value at index {}: {}", index, err);
                    None
                }
            }
        })
    }
}

impl KeyValueSchema for P2pStore {
    type Key = u64;
    type Value = P2pMessage;

    fn name() -> &'static str { "p2p_message_storage" }
}

pub(crate) mod secondary_indexes {
    use storage::persistent::{KeyValueStoreWithSchema, KeyValueSchema, Decoder, SchemaError, Encoder};
    use std::sync::Arc;
    use rocksdb::{DB, ColumnFamilyDescriptor, Options, SliceTransform};
    use std::net::SocketAddr;
    use crate::storage::{encode_address, P2pStore};
    use crate::storage::secondary_index::SecondaryIndex;
    use serde::{Serialize, Deserialize};
    use std::str::FromStr;
    use failure::Fail;
    use crate::messages::p2p_message::{P2pMessage, TezosPeerMessage, SourceType, FullPeerMessage, PartialPeerMessage, HandshakeMessage};

    pub type RemoteAddressIndexKV = dyn KeyValueStoreWithSchema<RemoteAddrIndex> + Sync + Send;

    // 1. Remote Reverse index for getting latest messages from specific host

    #[derive(Clone)]
    pub struct RemoteAddrIndex {
        kv: Arc<RemoteAddressIndexKV>,
    }

    impl RemoteAddrIndex {
        pub fn new(kv: Arc<DB>) -> Self {
            Self { kv }
        }
    }

    impl AsRef<(dyn KeyValueStoreWithSchema<RemoteAddrIndex> + 'static)> for RemoteAddrIndex {
        fn as_ref(&self) -> &(dyn KeyValueStoreWithSchema<RemoteAddrIndex> + 'static) {
            self.kv.as_ref()
        }
    }

    impl KeyValueSchema for RemoteAddrIndex {
        type Key = RemoteKey;
        type Value = <P2pStore as KeyValueSchema>::Key;

        fn descriptor() -> ColumnFamilyDescriptor {
            let mut cf_opts = Options::default();
            cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(16 + 2));
            cf_opts.set_memtable_prefix_bloom_ratio(0.2);
            ColumnFamilyDescriptor::new(Self::name(), cf_opts)
        }

        fn name() -> &'static str {
            "p2p_reverse_remote_index"
        }
    }

    impl SecondaryIndex<P2pStore> for RemoteAddrIndex {
        type FieldType = SocketAddr;

        fn accessor(value: &<P2pStore as KeyValueSchema>::Value) -> Option<Self::FieldType> {
            Some(value.remote_addr())
        }

        fn make_index(key: &<P2pStore as KeyValueSchema>::Key, value: Self::FieldType) -> <Self as KeyValueSchema>::Key {
            RemoteKey::new(value, key.clone())
        }

        fn make_prefix_index(value: Self::FieldType) -> <Self as KeyValueSchema>::Key {
            RemoteKey::prefix(value)
        }
    }

    #[derive(Debug, Clone)]
    pub struct RemoteKey {
        pub addr: u128,
        pub port: u16,
        pub index: u64,
    }

    impl RemoteKey {
        pub fn new(sock_addr: SocketAddr, index: u64) -> Self {
            let addr = sock_addr.ip();
            let port = sock_addr.port();
            Self {
                addr: encode_address(&addr),
                port,
                index: std::u64::MAX.saturating_sub(index),
            }
        }

        pub fn prefix(sock_addr: SocketAddr) -> Self {
            let addr = sock_addr.ip();
            let port = sock_addr.port();
            Self {
                addr: encode_address(&addr),
                port,
                index: 0,
            }
        }
    }

    /// * bytes layout: `[address(16)][port(2)][index(8)]`
    impl Decoder for RemoteKey {
        #[inline]
        fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
            if bytes.len() != 26 {
                return Err(SchemaError::DecodeError);
            }
            let addr_value = &bytes[0..16];
            let port_value = &bytes[16..16 + 2];
            let index_value = &bytes[16 + 2..];
            // index
            let mut index = [0u8; 8];
            for (x, y) in index.iter_mut().zip(index_value) {
                *x = *y;
            }
            let index = u64::from_be_bytes(index);
            // port
            let mut port = [0u8; 2];
            for (x, y) in port.iter_mut().zip(port_value) {
                *x = *y;
            }
            let port = u16::from_be_bytes(port);
            // addr
            let mut addr = [0u8; 16];
            for (x, y) in addr.iter_mut().zip(addr_value) {
                *x = *y;
            }
            let addr = u128::from_be_bytes(addr);

            Ok(Self {
                addr,
                port,
                index,
            })
        }
    }

    /// * bytes layout: `[address(16)][port(2)][index(8)]`
    impl Encoder for RemoteKey {
        #[inline]
        fn encode(&self) -> Result<Vec<u8>, SchemaError> {
            let mut buf = Vec::with_capacity(26);
            buf.extend_from_slice(&self.addr.to_be_bytes());
            buf.extend_from_slice(&self.port.to_be_bytes());
            buf.extend_from_slice(&self.index.to_be_bytes());

            if buf.len() != 26 {
                println!("{:?} - {:?}", self, buf);
                Err(SchemaError::EncodeError)
            } else {
                Ok(buf)
            }
        }
    }

    // 2. Type index

    pub type TypeIndexKV = dyn KeyValueStoreWithSchema<TypeIndex> + Sync + Send;

    #[derive(Clone)]
    pub struct TypeIndex {
        kv: Arc<TypeIndexKV>,
    }

    impl TypeIndex {
        pub fn new(kv: Arc<DB>) -> Self {
            Self { kv }
        }
    }

    impl AsRef<(dyn KeyValueStoreWithSchema<TypeIndex> + 'static)> for TypeIndex {
        fn as_ref(&self) -> &(dyn KeyValueStoreWithSchema<TypeIndex> + 'static) {
            self.kv.as_ref()
        }
    }

    impl KeyValueSchema for TypeIndex {
        type Key = TypeKey;
        type Value = <P2pStore as KeyValueSchema>::Key;

        fn descriptor() -> ColumnFamilyDescriptor {
            let mut cf_opts = Options::default();
            cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(std::mem::size_of::<u32>()));
            cf_opts.set_memtable_prefix_bloom_ratio(0.2);
            ColumnFamilyDescriptor::new(Self::name(), cf_opts)
        }

        fn name() -> &'static str {
            "p2p_type_index"
        }
    }

    impl SecondaryIndex<P2pStore> for TypeIndex {
        type FieldType = u32;

        fn accessor(value: &<P2pStore as KeyValueSchema>::Value) -> Option<Self::FieldType> {
            Some(Type::extract(value) as u32)
        }

        fn make_index(key: &<P2pStore as KeyValueSchema>::Key, value: Self::FieldType) -> <Self as KeyValueSchema>::Key {
            let type_key = TypeKey::new(value, key.clone());
            type_key
        }

        fn make_prefix_index(value: Self::FieldType) -> <Self as KeyValueSchema>::Key {
            TypeKey::prefix(value)
        }
    }

    #[derive(Debug, Copy, Clone, Serialize, Deserialize)]
    pub struct TypeKey {
        pub r#type: u32,
        pub index: u64,
    }

    impl TypeKey {
        pub fn new(r#type: u32, index: u64) -> Self {
            Self {
                r#type,
                index: std::u64::MAX.saturating_sub(index),
            }
        }

        pub fn prefix(r#type: u32) -> Self {
            Self {
                r#type,
                index: 0,
            }
        }
    }


    /// * bytes layout: `[type(4)][padding(4)][index(8)]`
    impl Decoder for TypeKey {
        fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
            if bytes.len() != 16 {
                return Err(SchemaError::DecodeError);
            }
            let type_value = &bytes[0..4];
            let _padding = &bytes[4..4 + 4];
            let index_value = &bytes[4 + 4..];
            // Type
            let mut r#type = [0u8; 4];
            for (x, y) in r#type.iter_mut().zip(type_value) {
                *x = *y;
            }
            let r#type = u32::from_be_bytes(r#type);
            // Index
            let mut index = [0u8; 8];
            for (x, y) in index.iter_mut().zip(index_value) {
                *x = *y;
            }
            let index = u64::from_be_bytes(index);

            Ok(Self {
                r#type,
                index,
            })
        }
    }

    /// * bytes layout: `[type(4)][padding(4)][index(8)]`
    impl Encoder for TypeKey {
        fn encode(&self) -> Result<Vec<u8>, SchemaError> {
            let mut buf: Vec<u8> = Vec::with_capacity(16);
            buf.extend_from_slice(&self.r#type.to_be_bytes());
            buf.extend_from_slice(&[0, 0, 0, 0]);
            buf.extend_from_slice(&self.index.to_be_bytes());

            if buf.len() != 16 {
                println!("{:?} - {:?}", self, buf);
                Err(SchemaError::EncodeError)
            } else {
                Ok(buf)
            }
        }
    }

    #[repr(u32)]
    #[derive(Debug)]
    pub enum Type {
        // Base Types
        Tcp = 0x1 << 0,
        Metadata = 0x1 << 1,
        ConnectionMessage = 0x1 << 2,
        RestMessage = 0x1 << 3,
        // P2P messages
        P2PMessage = 0x1 << 4,
        Disconnect = 0x1 << 5,
        Advertise = 0x1 << 6,
        SwapRequest = 0x1 << 7,
        SwapAck = 0x1 << 8,
        Bootstrap = 0x1 << 9,
        GetCurrentBranch = 0x1 << 10,
        CurrentBranch = 0x1 << 11,
        Deactivate = 0x1 << 12,
        GetCurrentHead = 0x1 << 13,
        CurrentHead = 0x1 << 14,
        GetBlockHeaders = 0x1 << 15,
        BlockHeader = 0x1 << 16,
        GetOperations = 0x1 << 17,
        Operation = 0x1 << 18,
        GetProtocols = 0x1 << 19,
        Protocol = 0x1 << 20,
        GetOperationHashesForBlocks = 0x1 << 21,
        OperationHashesForBlock = 0x1 << 22,
        GetOperationsForBlocks = 0x1 << 23,
        OperationsForBlocks = 0x1 << 24,
        AckMessage = 0x1 << 25,
    }

    impl Type {
        pub fn extract_from_tezos_peer_message(msg: &TezosPeerMessage) -> Self {
            match msg {
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::Disconnect) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::Disconnect) => Self::Disconnect,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::Bootstrap) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::Bootstrap) => Self::Bootstrap,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::Advertise) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::Advertise(_)) => Self::Advertise,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::SwapRequest) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::SwapRequest(_)) => Self::SwapRequest,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::SwapAck) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::SwapAck(_)) => Self::SwapAck,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::GetCurrentBranch) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::GetCurrentBranch(_)) => Self::GetCurrentBranch,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::CurrentBranch) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::CurrentBranch(_)) => Self::CurrentBranch,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::Deactivate) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::Deactivate(_)) => Self::Deactivate,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::GetCurrentHead) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::GetCurrentHead(_)) => Self::GetCurrentHead,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::CurrentHead) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::CurrentHead(_)) => Self::CurrentHead,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::GetBlockHeaders) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::GetBlockHeaders(_)) => Self::GetBlockHeaders,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::BlockHeader) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::BlockHeader(_)) => Self::BlockHeader,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::GetOperations) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::GetOperations(_)) => Self::GetOperations,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::Operation) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::Operation(_)) => Self::Operation,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::GetProtocols) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::GetProtocols(_)) => Self::GetProtocols,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::Protocol) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::Protocol(_)) => Self::Protocol,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::GetOperationHashesForBlocks) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::GetOperationHashesForBlocks(_)) => Self::GetOperationHashesForBlocks,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::OperationHashesForBlock) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::OperationHashesForBlock(_)) => Self::OperationHashesForBlock,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::GetOperationsForBlocks) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::GetOperationsForBlocks(_)) => Self::GetOperationsForBlocks,
                TezosPeerMessage::PartialPeerMessage(PartialPeerMessage::OperationsForBlocks) |
                TezosPeerMessage::PeerMessage(FullPeerMessage::OperationsForBlocks(_)) => Self::OperationsForBlocks,
                TezosPeerMessage::HandshakeMessage(HandshakeMessage::ConnectionMessage(_)) => Self::ConnectionMessage,
                TezosPeerMessage::HandshakeMessage(HandshakeMessage::MetadataMessage(_)) => Self::Metadata,
                TezosPeerMessage::HandshakeMessage(HandshakeMessage::AckMessage(_)) => Self::AckMessage,
            }
        }

        pub fn extract(value: &P2pMessage) -> Self {
            if let Some(msg) = value.message.first() {
                Self::extract_from_tezos_peer_message(msg)
            } else {
                Self::P2PMessage
            }
        }
    }


    #[derive(Debug, Fail)]
    #[fail(display = "Invalid message type {}", _0)]
    pub struct ParseTypeError(String);

    impl<T: AsRef<str>> From<T> for ParseTypeError {
        fn from(value: T) -> Self {
            Self(value.as_ref().to_string())
        }
    }

    impl FromStr for Type {
        type Err = ParseTypeError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "tcp" => Ok(Self::Tcp),
                "metadata" => Ok(Self::Metadata),
                "connection_message" => Ok(Self::ConnectionMessage),
                "rest_message" => Ok(Self::RestMessage),
                "p2p_message" => Ok(Self::P2PMessage),
                "disconnect" => Ok(Self::Disconnect),
                "advertise" => Ok(Self::Advertise),
                "swap_request" => Ok(Self::SwapRequest),
                "swap_ack" => Ok(Self::SwapAck),
                "bootstrap" => Ok(Self::Bootstrap),
                "get_current_branch" => Ok(Self::GetCurrentBranch),
                "current_branch" => Ok(Self::CurrentBranch),
                "deactivate" => Ok(Self::Deactivate),
                "get_current_head" => Ok(Self::GetCurrentHead),
                "current_head" => Ok(Self::CurrentHead),
                "get_block_headers" => Ok(Self::GetBlockHeaders),
                "block_header" => Ok(Self::BlockHeader),
                "get_operations" => Ok(Self::GetOperations),
                "operation" => Ok(Self::Operation),
                "get_protocols" => Ok(Self::GetProtocols),
                "protocol" => Ok(Self::Protocol),
                "get_operation_hashes_for_blocks" => Ok(Self::GetOperationHashesForBlocks),
                "operation_hashes_for_block" => Ok(Self::OperationHashesForBlock),
                "get_operations_for_blocks" => Ok(Self::GetOperationsForBlocks),
                "operations_for_blocks" => Ok(Self::OperationsForBlocks),
                "ack_message" => Ok(Self::AckMessage),
                s => Err(s.into())
            }
        }
    }

    // 4. Incoming Index
    pub type IncomingIndexKV = dyn KeyValueStoreWithSchema<IncomingIndex> + Sync + Send;

    #[derive(Clone)]
    pub struct IncomingIndex {
        kv: Arc<IncomingIndexKV>,
    }

    impl IncomingIndex {
        pub fn new(kv: Arc<DB>) -> Self {
            Self { kv }
        }
    }

    impl AsRef<(dyn KeyValueStoreWithSchema<IncomingIndex> + 'static)> for IncomingIndex {
        fn as_ref(&self) -> &(dyn KeyValueStoreWithSchema<IncomingIndex> + 'static) {
            self.kv.as_ref()
        }
    }

    impl KeyValueSchema for IncomingIndex {
        type Key = IncomingKey;
        type Value = <P2pStore as KeyValueSchema>::Key;

        fn descriptor() -> ColumnFamilyDescriptor {
            let mut cf_opts = Options::default();
            cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(std::mem::size_of::<bool>()));
            cf_opts.set_memtable_prefix_bloom_ratio(0.2);
            ColumnFamilyDescriptor::new(Self::name(), cf_opts)
        }

        fn name() -> &'static str {
            "p2p_incoming_index"
        }
    }

    impl SecondaryIndex<P2pStore> for IncomingIndex {
        type FieldType = bool;

        fn accessor(value: &<P2pStore as KeyValueSchema>::Value) -> Option<Self::FieldType> {
            Some(value.is_incoming())
        }

        fn make_index(key: &<P2pStore as KeyValueSchema>::Key, value: Self::FieldType) -> IncomingKey {
            IncomingKey::new(value, key.clone())
        }

        fn make_prefix_index(value: Self::FieldType) -> IncomingKey {
            IncomingKey::prefix(value)
        }
    }

    #[derive(Debug, Copy, Clone, Serialize, Deserialize)]
    pub struct IncomingKey {
        pub is_incoming: bool,
        pub index: u64,
    }

    impl IncomingKey {
        pub fn new(is_incoming: bool, index: u64) -> Self {
            Self { is_incoming, index: std::u64::MAX.saturating_sub(index) }
        }

        pub fn prefix(is_incoming: bool) -> Self {
            Self { is_incoming, index: 0 }
        }
    }

    /// * bytes layout: `[is_incoming(1)][padding(7)][index(8)]`
    impl Decoder for IncomingKey {
        #[inline]
        fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
            if bytes.len() != 16 {
                return Err(SchemaError::DecodeError);
            }
            let is_incoming_value = &bytes[0..1];
            let _padding_value = &bytes[1..1 + 7];
            let index_value = &bytes[1 + 7..];
            // is_incoming
            let is_incoming = if is_incoming_value == &[true as u8] {
                true
            } else if is_incoming_value == &[false as u8] {
                true
            } else {
                return Err(SchemaError::DecodeError);
            };
            // index
            let mut index = [0u8; 8];
            for (x, y) in index.iter_mut().zip(index_value) {
                *x = *y;
            }
            let index = u64::from_be_bytes(index);
            Ok(Self {
                is_incoming,
                index,
            })
        }
    }

    /// * bytes layout: `[is_incoming(1)][padding(7)][index(8)]`
    impl Encoder for IncomingKey {
        #[inline]
        fn encode(&self) -> Result<Vec<u8>, SchemaError> {
            let mut buf = Vec::with_capacity(16);
            buf.extend_from_slice(&[self.is_incoming as u8]); // is_incoming
            buf.extend_from_slice(&[0u8; 7]); // padding
            buf.extend_from_slice(&self.index.to_be_bytes()); // index

            if buf.len() != 16 {
                println!("{:?} - {:?}", self, buf);
                Err(SchemaError::EncodeError)
            } else {
                Ok(buf)
            }
        }
    }

    // 5. SourceType Index
    pub type SourceTypeIndexKV = dyn KeyValueStoreWithSchema<SourceTypeIndex> + Sync + Send;

    #[derive(Clone)]
    pub struct SourceTypeIndex {
        kv: Arc<SourceTypeIndexKV>,
    }

    impl SourceTypeIndex {
        pub fn new(kv: Arc<DB>) -> Self {
            Self { kv }
        }
    }

    impl AsRef<(dyn KeyValueStoreWithSchema<SourceTypeIndex> + 'static)> for SourceTypeIndex {
        fn as_ref(&self) -> &(dyn KeyValueStoreWithSchema<SourceTypeIndex> + 'static) {
            self.kv.as_ref()
        }
    }

    impl KeyValueSchema for SourceTypeIndex {
        type Key = SourceTypeKey;
        type Value = <P2pStore as KeyValueSchema>::Key;

        fn descriptor() -> ColumnFamilyDescriptor {
            let mut cf_opts = Options::default();
            cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(std::mem::size_of::<bool>()));
            cf_opts.set_memtable_prefix_bloom_ratio(0.2);
            ColumnFamilyDescriptor::new(Self::name(), cf_opts)
        }

        fn name() -> &'static str {
            "p2p_source_type_index"
        }
    }

    impl SecondaryIndex<P2pStore> for SourceTypeIndex {
        type FieldType = bool;

        fn accessor(value: &<P2pStore as KeyValueSchema>::Value) -> Option<Self::FieldType> {
            Some(value.source_type() == SourceType::Remote)
        }

        fn make_index(key: &<P2pStore as KeyValueSchema>::Key, value: Self::FieldType) -> SourceTypeKey {
            SourceTypeKey::new(value, key.clone())
        }

        fn make_prefix_index(value: Self::FieldType) -> SourceTypeKey {
            SourceTypeKey::prefix(value)
        }
    }

    #[derive(Debug, Copy, Clone, Serialize, Deserialize)]
    pub struct SourceTypeKey {
        pub source_type: bool,
        pub index: u64,
    }

    impl SourceTypeKey {
        pub fn new(source_type: bool, index: u64) -> Self {
            Self { source_type, index: std::u64::MAX.saturating_sub(index) }
        }

        pub fn prefix(source_type: bool) -> Self {
            Self { source_type, index: 0 }
        }
    }

    /// * bytes layout: `[is_remote_requested(1)][padding(7)][index(8)]`
    impl Decoder for SourceTypeKey {
        #[inline]
        fn decode(bytes: &[u8]) -> Result<Self, SchemaError> {
            if bytes.len() != 16 {
                return Err(SchemaError::DecodeError);
            }
            let source_type_value = &bytes[0..1];
            let _padding_value = &bytes[1..1 + 7];
            let index_value = &bytes[1 + 7..];
            // source_type
            let source_type = if source_type_value == &[true as u8] {
                true
            } else if source_type_value == &[false as u8] {
                true
            } else {
                return Err(SchemaError::DecodeError);
            };
            // index
            let mut index = [0u8; 8];
            for (x, y) in index.iter_mut().zip(index_value) {
                *x = *y;
            }
            let index = u64::from_be_bytes(index);
            Ok(Self {
                source_type,
                index,
            })
        }
    }

    /// * bytes layout: `[is_remote_requested(1)][padding(7)][index(8)]`
    impl Encoder for SourceTypeKey {
        #[inline]
        fn encode(&self) -> Result<Vec<u8>, SchemaError> {
            let mut buf = Vec::with_capacity(16);
            buf.extend_from_slice(&[self.source_type as u8]); // is_remote_requested
            buf.extend_from_slice(&[0u8; 7]); // padding
            buf.extend_from_slice(&self.index.to_be_bytes()); // index

            if buf.len() != 16 {
                println!("{:?} - {:?}", self, buf);
                Err(SchemaError::EncodeError)
            } else {
                Ok(buf)
            }
        }
    }
}