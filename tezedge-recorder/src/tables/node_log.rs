// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{str::FromStr, convert::TryFrom};
use thiserror::Error;
use serde::{Serialize, Deserialize};
use storage::persistent::{BincodeEncoded, KeyValueSchema, database::RocksDbKeyValueSchema};

#[derive(Serialize, Deserialize)]
pub struct ItemWithId {
    pub id: u64,
    pub level: LogLevel,
    #[serde(alias = "time")]
    pub timestamp: u128,
    #[serde(alias = "module")]
    pub section: String,
    #[serde(alias = "msg")]
    pub message: String,
}

/// Received logs saved in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub level: LogLevel,
    pub timestamp: u128,
    pub section: String,
    pub message: String,
}

#[repr(u8)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Trace = 0x1 << 0,
    Debug = 0x1 << 1,
    Info = 0x1 << 2,
    Notice = 0x1 << 3,
    Warning = 0x1 << 4,
    Error = 0x1 << 5,
    Fatal = 0x1 << 6,
}

#[derive(Error, Debug)]
pub enum ParseLogLevelError {
    #[error("Invalid log level name {}", _0)]
    InvalidName(String),
    #[error("Invalid log level value {}", _0)]
    InvalidValue(u8),
}

impl FromStr for LogLevel {
    type Err = ParseLogLevelError;

    fn from_str(level: &str) -> Result<Self, Self::Err> {
        let level = level.to_lowercase();
        Ok(match level.as_ref() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "notice" => LogLevel::Notice,
            "warn" | "warning" => LogLevel::Warning,
            "error" => LogLevel::Error,
            "fatal" => LogLevel::Fatal,
            _ => return Err(ParseLogLevelError::InvalidName(level)),
        })
    }
}

impl TryFrom<u8> for LogLevel {
    type Error = ParseLogLevelError;

    fn try_from(value: u8) -> Result<Self, ParseLogLevelError> {
        match value {
            x if x == Self::Trace as u8 => Ok(Self::Trace),
            x if x == Self::Debug as u8 => Ok(Self::Debug),
            x if x == Self::Info as u8 => Ok(Self::Info),
            x if x == Self::Notice as u8 => Ok(Self::Notice),
            x if x == Self::Warning as u8 => Ok(Self::Warning),
            x if x == Self::Error as u8 => Ok(Self::Error),
            x if x == Self::Fatal as u8 => Ok(Self::Fatal),
            x => Err(ParseLogLevelError::InvalidValue(x)),
        }
    }
}

impl<S> From<syslog_loose::Message<S>> for Item
where
    S: AsRef<str> + Ord + PartialEq + Clone,
{
    /// Create LogMessage from received syslog message
    /// Syslog messages are of format:
    /// <27>1 2020-06-24T10:32:37.026683+02:00 Ubuntu-1910-eoan-64-minimal 451e91e7df18 1482 451e91e7df18 - Jun 24 08:32:37.026 INFO Blacklisting IP because peer failed at bootstrap process, ip: 104.248.136.94
    // TODO: handle error
    fn from(msg: syslog_loose::Message<S>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        /// Parse rust formatted log
        fn rust_log_line(line: &str) -> Option<(&str, &str)> {
            let (_, level_msg) = line.split_at(20);
            let level = level_msg.split_whitespace().next()?;
            let msg = &level_msg[(level.len() + 1)..];
            Some((level, msg))
        }

        /// Parse ocaml formatted log
        fn ocaml_log_line(line: &str) -> Option<(&str, &str)> {
            let mut parts = line.split('-');
            let _ = parts.next();
            let msg = parts.next();
            if let Some(value) = msg {
                let mut parts = value.split(':');
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

        let timestamp = msg
            .timestamp
            .map(|dt| dt.timestamp_nanos() as u128)
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            });
        let line = msg.msg.as_ref();

        let pos = line.find('.').unwrap_or_default();
        #[allow(clippy::collapsible_else_if)]
        if pos == 15 {
            if let Some((level, message)) = rust_log_line(line) {
                Item {
                    timestamp,
                    level: LogLevel::from_str(level).unwrap_or(LogLevel::Fatal),
                    message: message.to_string(),
                    section: "".to_string(),
                }
            } else {
                Item {
                    timestamp,
                    level: LogLevel::Fatal,
                    section: "".to_string(),
                    message: line.to_string(),
                }
            }
        } else {
            if let Some((level, message)) = ocaml_log_line(line) {
                Item {
                    timestamp,
                    level: LogLevel::from_str(level).unwrap_or(LogLevel::Fatal),
                    message: message.to_string(),
                    section: "".to_string(),
                }
            } else {
                Item {
                    timestamp,
                    level: LogLevel::Fatal,
                    section: "".to_string(),
                    message: line.to_string(),
                }
            }
        }
    }
}

impl BincodeEncoded for Item {}

pub struct Schema;

impl KeyValueSchema for Schema {
    type Key = u64;
    type Value = Item;
}

impl RocksDbKeyValueSchema for Schema {
    fn name() -> &'static str {
        "log_storage"
    }
}
