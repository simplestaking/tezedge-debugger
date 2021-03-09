// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

mod utils;

pub mod syslog_producer;
//pub mod rpc_parser;
//pub mod replayer;

// new socket capturing system
mod parser;
mod reporter;
mod p2p;

pub use self::{
    parser::Parser,
    reporter::Reporter,
    p2p::Report as P2pReport,
};

mod processor;

mod settings {
    use serde::Deserialize;

    #[derive(Clone, Deserialize)]
    pub struct NodeConfig {
        pub name: String,
        pub identity_path: String,
        pub syslog_port: u16,
        pub p2p_port: u16,
    }

    #[derive(Clone, Deserialize)]
    pub struct DebuggerConfig {
        pub db_path: String,
        pub rpc_port: u16,
        pub p2p_message_limit: u64,
        pub log_message_limit: u64,
        pub run_bpf: bool,
        pub keep_db: bool,
        pub nodes: Vec<NodeConfig>,
    }
}
pub use self::settings::{NodeConfig, DebuggerConfig};
