// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tracing::{Level};
//use tezedge_debugger::system::replayer::replay;
use tezedge_debugger::{
    storage::{MessageStore, cfs, P2pFilters},
    system::replayer::replay,
};
use structopt::StructOpt;
use std::path::Path;
use std::sync::Arc;
use storage::persistent::{open_kv, DbConfiguration};
use std::net::SocketAddr;

#[derive(StructOpt, Debug)]
#[structopt(name = "tezos message replayer")]
/// Commandline arguments
struct Opt {
    #[structopt(long, default_value = "tests/rust-node-record")]
    /// Path to the snapshot, to be replayed
    pub path: String,
    #[structopt(short, long, default_value = "127.0.0.1:9732")]
    /// Address of the node to replay messages
    pub node_ip: SocketAddr,
    #[structopt(short, long, default_value = "51.15.220.7:9732")]
    /// Address of the peer which conversation to be replayed
    pub peer_ip: SocketAddr,
    #[structopt(short, long, default_value = "65536")]
    /// Number of chunks, to be replayed
    pub limit: usize,
}

fn open_snapshot<P: AsRef<Path>>(path: P) -> Result<MessageStore, failure::Error> {
    let schemas = cfs();
    let db = Arc::new(open_kv(path, schemas, &DbConfiguration::default())?);
    Ok(MessageStore::new(db))
}

#[tokio::main]
async fn main() -> Result<(), failure::Error> {
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .init();
    let opts: Opt = Opt::from_args();
    let path = &opts.path;
    let addr = opts.node_ip;
    let storage = open_snapshot(path)?;
    let filter = P2pFilters {
        remote_addr: Some(opts.peer_ip),
        types: None,
        request_id: None,
        incoming: None,
        source_type: None,
    };
    let msgs = storage.p2p().get_cursor(None, 0x10000, filter)?;
    replay(addr, msgs.into_iter().rev().take(opts.limit)).await
}
