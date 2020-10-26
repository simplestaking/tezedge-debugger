// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tracing::{info, error, Level};
use tezedge_debugger::{
    system::build_raw_socket_system,
    utility::{
        identity::Identity,
        ip_settings::get_local_ip,
    },
};
use std::process::exit;
use tezedge_debugger::system::SystemSettings;
use std::time::Instant;
use tezedge_debugger::storage::{MessageStore, get_ts, cfs};
use std::path::Path;
use std::sync::Arc;
use storage::persistent::{open_kv, DbConfiguration};
use tezedge_debugger::system::syslog_producer::syslog_producer;

/// Create new message store, from well defined path
fn open_database() -> Result<MessageStore, failure::Error> {
    let storage_path = format!("/tmp/volume/{}", get_ts());
    let path = Path::new(&storage_path);
    let schemas = cfs();
    let rocksdb = Arc::new(open_kv(path, schemas, &DbConfiguration::default())?);
    Ok(MessageStore::new(rocksdb))
}

/// Try to load identity from one of the well defined paths
/// This method will block until, some identity is found
async fn load_identity() -> Identity {
    // Wait until identity appears
    let mut last_try = Instant::now();

    let identity_paths = [
        "/tmp/volume/identity.json".to_string(),
        "/tmp/volume/data/identity.json".to_string(),
        "/home/vladislav/disk/simplestaking.com/tezedge/light_node/etc/tezedge/identity.json".to_string(),
    ];

    loop {
        for (path, file) in identity_paths
            .iter().map(|path| (path, tokio::fs::read_to_string(path)))
        {
            match file.await {
                Ok(content) => {
                    match serde_json::from_str::<Identity>(&content) {
                        Ok(identity) => {
                            info!(file_path = tracing::field::display(&path), "loaded identity");
                            return identity;
                        }
                        Err(err) => {
                            error!(error = tracing::field::display(&err), "identity file does not contains valid identity");
                            exit(1);
                        }
                    }
                }
                Err(err) => {
                    if last_try.elapsed().as_secs() >= 5 {
                        last_try = Instant::now();
                        info!(error = tracing::field::display(&err), "waiting for identity");
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), failure::Error> {
    // Initialize tracing default tracing console subscriber
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    // Identify the local address
    let local_address = if let Some(ip_addr) = get_local_ip() {
        ip_addr
    } else {
        error!("failed to detect local ip address");
        exit(1);
    };

    info!(ip_address = tracing::field::display(&local_address), "detected local IP address");

    // Load identity
    let identity = load_identity().await;

    info!(peer_id = tracing::field::display(&identity.peer_id), "loaded identity");

    // Initialize storage for messages
    let storage = match open_database() {
        Ok(storage) => storage,
        Err(err) => {
            error!(error = tracing::field::display(&err), "failed to open database");
            exit(1);
        }
    };

    // Create system setting to drive the rest of the system
    let settings = SystemSettings {
        identity,
        local_address,
        storage: storage.clone(),
        syslog_port: 13131,
        rpc_port: 17732,
        node_rpc_port: 18732,
    };

    // Create syslog server to capture logs from docker / syslogs
    if let Err(err) = syslog_producer(settings.clone()).await {
        error!(error = tracing::field::display(&err), "failed to build syslog server");
        exit(1);
    }

    // Create actual system
    match build_raw_socket_system(settings.clone()) {
        Ok(_) => {
            info!("system built");
        }
        Err(err) => {
            error!(error = tracing::field::display(&err), "failed to build system");
            exit(1);
        }
    }

    // Spawn warp RPC server
    tokio::spawn(async move {
        use tezedge_debugger::endpoints::routes;
        warp::serve(routes(storage))
            .run(([0, 0, 0, 0], settings.rpc_port))
            .await;
    });

    // Wait for SIGTERM signal
    if let Err(err) = tokio::signal::ctrl_c().await {
        error!(error = tracing::field::display(&err), "failed while listening for signal");
        exit(1)
    }

    info!("ctrl-c received");

    Ok(())
}