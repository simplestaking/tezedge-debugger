// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread, io,
    net::UdpSocket,
    time::Duration,
};
use super::{database::Database, tables::node_log};

pub fn spawn<Db>(
    port: u16,
    db: Arc<Db>,
    running: Arc<AtomicBool>,
) -> io::Result<thread::JoinHandle<()>>
where
    Db: Database + Sync + Send + 'static,
{
    let socket = UdpSocket::bind(("0.0.0.0", port))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    Ok(thread::spawn(move || {
        let mut buffer = [0u8; 0x10000];
        while running.load(Ordering::Relaxed) {
            match socket.recv(&mut buffer) {
                Ok(read) => {
                    if let Ok(log) = std::str::from_utf8(&buffer[..read]) {
                        let msg = syslog_loose::parse_message(log);
                        let item = node_log::Item::from(msg);
                        db.store_log(item);
                    }
                },
                Err(error) => {
                    if error.kind() == io::ErrorKind::WouldBlock {
                        log::trace!("receiving log timeout");
                    } else {
                        log::error!("receiving log error: {}", error)
                    }
                },
            }
        }
    }))
}
