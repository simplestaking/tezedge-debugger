// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{ops::Range, net::UdpSocket, env};

const START_TIME: i64 = 1626264000;

fn main() {
    let socket = UdpSocket::bind("127.0.0.1:54254").unwrap();

    if let Some(a) = env::args().nth(1) {
        match a.as_str() {
            "first" => prepare_db_range(0..5_000, &socket),
            "second" => prepare_db_range(5_000..10_000, &socket),
            _ => (),
        }
    }
}

fn prepare_db_range(range: Range<i64>, socket: &UdpSocket) {
    use std::{time::Duration, thread};
    use chrono::prelude::*;

    for i in range {
        let timestamp = START_TIME + i;

        let level = match timestamp % 19 {
            1 | 4 | 5 | 8 => "WARN",
            7 | 10 => "ERROR",
            _ => "INFO",
        };

        let local = Local.timestamp(timestamp, 0).to_rfc3339();
        let fake = "Jul 14 12:00:00.000";
        let msg = format!(
            "<27>1 {} wsvl eb3fdbc716e5 665 eb3fdbc716e5 - {} {} some message",
            local,
            fake,
            level,
        );

        let _ = socket.send_to(msg.as_bytes(), "127.0.0.1:10000").unwrap();
        thread::sleep(Duration::from_micros(400));
    }
}
