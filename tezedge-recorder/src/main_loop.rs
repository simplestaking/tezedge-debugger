// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{Ordering, AtomicBool},
    },
};
use anyhow::Result;
use bpf_sniffer_common::{BpfModuleClient, SnifferEvent, Command, EventId, SocketId};

use super::{
    processor::Connection,
    database::{Database, DatabaseNew, DatabaseFetch},
    system::System,
};

pub fn run<Db>(system: System<Db>, running: Arc<AtomicBool>) -> Result<()>
where
    Db: Database + DatabaseNew + DatabaseFetch + Sync + Send + 'static,
{
    let (client, mut rb) = BpfModuleClient::new_sync(system.sniffer_path())?;
    let mut list = ConnectionList::new(client, system);
    list.watching()?;

    while running.load(Ordering::Relaxed) {
        let events = rb.read_blocking::<SnifferEvent>(&running)?;
        for event in events {
            match event {
                SnifferEvent::Bind { id, address } => {
                    // TODO: remove old connections on this port
                    if let Err(error) = list.system.handle_bind(id.socket_id.pid, address.port()) {
                        log::error!("failed to handle bind syscall: {}", error);
                    }
                },
                SnifferEvent::Listen { id } => {
                    let _ = id;
                },
                SnifferEvent::Connect { id, address } => {
                    list.handle_connection(id, address, false);
                },
                SnifferEvent::Accept {
                    id,
                    address,
                    listen_on_fd,
                } => {
                    let _ = listen_on_fd;
                    list.handle_connection(id, address, true);
                },
                SnifferEvent::Data {
                    id,
                    data,
                    net,
                    incoming,
                } => {
                    list.handle_data(id, data, net, incoming);
                },
                SnifferEvent::Close { id } => {
                    list.handle_close(id);
                },
                SnifferEvent::GetFd { id } => {
                    list.handle_get_fd(id);
                },
                SnifferEvent::Debug { id, msg } => {
                    log::warn!("{} {}", id, msg);
                },
            }
        }
    }

    Ok(())
}

struct ConnectionList<Db> {
    client: BpfModuleClient,
    system: System<Db>,
    connections: HashMap<SocketId, Connection<Db>>,
}

impl<Db> ConnectionList<Db>
where
    Db: Database + DatabaseNew + DatabaseFetch + Sync + Send + 'static,
{
    fn new(client: BpfModuleClient, system: System<Db>) -> Self {
        ConnectionList {
            client,
            system,
            connections: HashMap::new(),
        }
    }

    fn watching(&mut self) -> Result<()> {
        for node_config in self.system.node_configs() {
            self.client.send_command(Command::WatchPort {
                port: node_config.p2p_port,
            })?;
        }

        Ok(())
    }

    fn handle_connection(&mut self, event_id: EventId, address: SocketAddr, incoming: bool) {
        let socket_id = event_id.socket_id;
        let pid = socket_id.pid;
        let fd = socket_id.fd;
        if !self.system.should_ignore(&address) {
            if let Some((info, db)) = self.system.get_mut(pid) {
                let connection = Connection::new(address, incoming, info.identity(), db);
                if let Some(old) = self.connections.insert(socket_id, connection) {
                    old.join();
                }
                return;
            }
        }
        match self
            .client
            .send_command(Command::IgnoreConnection { pid, fd })
        {
            Ok(()) => (),
            Err(error) => {
                log::error!(
                    "cannot ignore connection id: {}, error: {}",
                    socket_id,
                    error
                )
            },
        }
    }

    fn handle_data(&mut self, id: EventId, payload: Vec<u8>, net: bool, incoming: bool) {
        if payload.len() > 0x1000000 {
            log::warn!("received from ring buffer big payload {}", payload.len());
        }
        if let Some(connection) = self.connections.get_mut(&id.socket_id) {
            connection.handle_data(&payload, net, incoming);
        } else {
            log::debug!("failed to handle data, connection does not exist: {}", id);
        }
    }

    fn handle_get_fd(&mut self, id: EventId) {
        let socket_id = id.socket_id;
        if let Some(c) = self.connections.remove(&socket_id) {
            c.warn_fd_changed();
            c.join();
        }
    }

    fn handle_close(&mut self, id: EventId) {
        let socket_id = id.socket_id;
        if let Some(old) = self.connections.remove(&socket_id) {
            old.join();
        }
    }
}
