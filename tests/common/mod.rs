// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::env;

use warp::hyper::Client;
use bytes::buf::BufExt;

pub const DEFAULT_LIMIT: usize = 100;

pub async fn get_rpc_as_json(url: &str) -> Result<serde_json::value::Value, serde_json::error::Error> {
    let client = Client::new();
    let uri = url.parse().expect("Invalid URL");

    let body = match client.get(uri).await {
        Ok(res) => warp::hyper::body::aggregate(res.into_body()).await.expect("Failed to read response body"),
        Err(e) => panic!("RPC call failed with: {}", e)
    };

    serde_json::from_reader(&mut body.reader())
}

/// Make x number of rpc calls to the node
pub async fn make_rpc_calls(x: i32) {
    let node_url = node_url();
    for _ in 0..x {
        let _ = get_rpc_as_json(&format!("{}/{}", node_url, "chains/main/blocks/head")).await.unwrap();
    }
}

pub fn debugger_url() -> String {
    env::var("DEBUGGER_URL")
        //.unwrap_or("http://116.202.128.230:17732".to_string())
        .unwrap()
}

pub fn node_url() -> String {
    env::var("NODE_URL")
        //.unwrap_or("http://116.202.128.230:48732".to_string())
        .unwrap()
}

pub fn node_type() -> String {
    env::var("NODE_TYPE")
        .unwrap()
}