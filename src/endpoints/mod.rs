// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

mod p2p;
mod log;
mod version;
mod report;

use std::sync::{Arc, Mutex};
use warp::{Filter, Reply, reject::Rejection, reply::with::header};
use super::{storage_::{P2pStore, LogStore, PerfStore}, system::Reporter};

/// Create router for consisting of all endpoint
pub fn routes(p2p_db: P2pStore, log_db: LogStore, perf_db: PerfStore, reporter: Arc<Mutex<Reporter>>) -> impl Filter<Extract=impl Reply, Error=Rejection> + Clone + Sync + Send + 'static {
    warp::get().and(
        self::p2p::p2p(p2p_db.clone())
            .or(self::p2p::p2p_message(p2p_db.clone()))
            .or(self::report::p2p_report(reporter.clone()))
            .or(self::report::rb_report(reporter.clone()))
            .or(self::report::perf_report(perf_db.clone()))
            .or(self::log::log(log_db.clone()))
            .or(self::version::api_call())
    )
        .with(header("Content-Type", "application/json"))
        .with(header("Access-Control-Allow-Origin", "*"))
}
