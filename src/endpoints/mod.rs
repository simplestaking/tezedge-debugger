// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

mod p2p;
mod log;
#[allow(dead_code)]
mod rpc;
#[allow(dead_code)]
mod stat;
mod version;
#[cfg(target_os = "linux")]
mod report;

#[cfg(target_os = "linux")]
use {
    std::sync::{Arc, Mutex},
    super::system::Reporter,
};

use warp::{Filter, Reply, reject::Rejection, reply::with::header};
use super::storage_::{P2pStore, LogStore};

/// Create router for consisting of all endpoint
#[cfg(target_os = "linux")]
pub fn routes(p2p_db: P2pStore, log_db: LogStore, reporter: Arc<Mutex<Reporter>>) -> impl Filter<Extract=impl Reply, Error=Rejection> + Clone + Sync + Send + 'static {
    warp::get().and(
        self::p2p::p2p(p2p_db.clone())
            .or(self::report::p2p_report(reporter))
            .or(self::log::log(log_db.clone()))
            .or(self::version::api_call())
    )
        .with(header("Content-Type", "application/json"))
        .with(header("Access-Control-Allow-Origin", "*"))
}

#[cfg(not(target_os = "linux"))]
pub fn routes(p2p_db: P2pStore, log_db: LogStore) -> impl Filter<Extract=impl Reply, Error=Rejection> + Clone + Sync + Send + 'static {
    warp::get().and(
        self::p2p::p2p(p2p_db.clone())
            .or(self::log::log(log_db.clone()))
            .or(self::version::api_call())
    )
        .with(header("Content-Type", "application/json"))
        .with(header("Access-Control-Allow-Origin", "*"))
}
