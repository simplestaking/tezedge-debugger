use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use storage::persistent::{KeyValueSchema, BincodeEncoded};
use super::{Access, indices::NodeName};

/// Received logs saved in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub node_name: u16,
    pub level: String,
    #[serde(alias = "timestamp", alias = "time", rename(serialize = "timestamp"))]
    pub date: u128,
    #[serde(alias = "module")]
    pub section: String,
    #[serde(alias = "msg", rename(serialize = "message"))]
    pub message: String,
}

fn get_ts() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

impl Message {
    /// Create new log from undefined raw string
    pub fn raw(line: String, node_name: u16) -> Self {
        Message {
            node_name,
            level: "fatal".to_string(),
            date: get_ts(),
            section: "".to_string(),
            message: line,
        }
    }

    /// Parse rust formatted log
    fn rust_log_line(line: &str) -> Option<(&str, &str)> {
        let (_, level_msg) = line.split_at(20);
        let level = level_msg.split_whitespace().next()?;
        let msg = &level_msg[level.len() + 1..];
        Some((level, msg))
    }

    /// Parse ocaml formatted log
    fn ocaml_log_line(line: &str) -> Option<(&str, &str)> {
        let mut parts = line.split("-");
        let _ = parts.next();
        let msg = parts.next();
        if let Some(value) = msg {
            let mut parts = value.split(":");
            let _ = parts.next();
            let msg = parts.next();
            if let Some(msg) = msg {
                Some(("info", msg.trim()))
            } else {
                Some(("info", value.trim()))
            }
        } else {
            Some(("info", line.trim()))
        }
    }
}

impl<S: AsRef<str> + Ord + PartialEq + Clone> From<syslog_loose::Message<S>> for Message {
    /// Create LogMessage from received syslog message
    /// Syslog messages are of format:
    /// <27>1 2020-06-24T10:32:37.026683+02:00 Ubuntu-1910-eoan-64-minimal 451e91e7df18 1482 451e91e7df18 - Jun 24 08:32:37.026 INFO Blacklisting IP because peer failed at bootstrap process, ip: 104.248.136.94
    fn from(msg: syslog_loose::Message<S>) -> Self {
        let date = msg.timestamp
            .map(|dt| dt.timestamp_nanos() as u128)
            .unwrap_or_else(get_ts);
        let line = msg.msg.as_ref();

        let pos = line.find('.').unwrap_or_default();
        if pos == 15 {
            if let Some((level, message)) = Self::rust_log_line(line) {
                Message {
                    node_name: 0,
                    date,
                    level: level.to_string(),
                    message: message.to_string(),
                    section: "".to_string(),
                }
            } else {
                Message {
                    node_name: 0,
                    date,
                    level: "fatal".to_string(),
                    section: "".to_string(),
                    message: line.to_string(),
                }
            }
        } else {
            if let Some((level, message)) = Self::ocaml_log_line(line) {
                Message {
                    node_name: 0,
                    date,
                    level: level.to_string(),
                    message: message.to_string(),
                    section: "".to_string(),
                }
            } else {
                Message {
                    node_name: 0,
                    date,
                    level: "fatal".to_string(),
                    section: "".to_string(),
                    message: line.to_string(),
                }
            }
        }
    }
}

impl Access<NodeName> for Message {
    fn accessor(&self) -> NodeName {
        NodeName(self.node_name)
    }
}

impl BincodeEncoded for Message {}

pub struct Schema;

impl KeyValueSchema for Schema {
    type Key = u64;
    type Value = Message;

    fn name() -> &'static str { "log_message_storage" }
}