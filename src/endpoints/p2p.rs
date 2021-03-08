// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{net::SocketAddr, convert::TryInto, sync::{Arc, Mutex}};
use warp::{Filter, Rejection, reply::{with_status, json, WithStatus, Json}, http::StatusCode};
use serde::{Serialize, Deserialize};
use crate::{
    storage_::{P2pStore, p2p::Filters, indices::{P2pType, ParseTypeError, Initiator, Sender, NodeName}},
    system::Reporter,
};

/// Cursor structure mapped from the endpoint URI
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct P2pCursor {
    cursor_id: Option<u64>,
    limit: Option<usize>,
    remote_addr: Option<SocketAddr>,
    types: Option<String>,
    request_id: Option<u64>,
    incoming: Option<bool>,
    source_type: Option<Initiator>,
    node_name: Option<u16>,
}

impl P2pCursor {
    fn get_types(&self) -> Result<Vec<P2pType>, ParseTypeError> {
        let mut types = vec![];
        if let Some(ref values) = self.types {
            for ty in values.split(',') {
                types.push(ty.parse()?);
            }
        }
        Ok(types)
    }
}

impl TryInto<Filters> for P2pCursor {
    type Error = ParseTypeError;

    fn try_into(self) -> Result<Filters, Self::Error> {
        Ok(Filters {
            initiator: self.source_type,
            remote_addr: self.remote_addr,
            types: self.get_types()?,
            sender: self.incoming.map(|incoming| Sender::new(incoming)),
            node_name: self.node_name.map(NodeName),
        })
    }
}

/// Basic handler for p2p message endpoint with cursor
pub fn p2p(storage: P2pStore) -> impl Filter<Extract=(WithStatus<Json>, ), Error=Rejection> + Clone + Sync + Send + 'static {
    warp::path!("v2" / "p2p")
        .and(warp::query::query())
        .map(move |cursor: P2pCursor| -> WithStatus<Json> {
            let limit = cursor.limit.unwrap_or(100);
            let cursor_id = cursor.cursor_id.clone();
            match cursor.try_into() {
                Ok(filters) => match storage.get_cursor(cursor_id, limit, &filters) {
                    Ok(msgs) => with_status(json(&msgs), StatusCode::OK),
                    Err(err) => with_status(json(&format!("database error: {}", err)), StatusCode::INTERNAL_SERVER_ERROR),
                },
                Err(type_err) => with_status(json(&format!("invalid type-name: {}", type_err)), StatusCode::BAD_REQUEST),
            }
        })
}

/// Basic handler for p2p message endpoint with cursor
pub fn p2p_report(reporter: Arc<Mutex<Reporter>>) -> impl Filter<Extract=(WithStatus<Json>, ), Error=Rejection> + Clone + Sync + Send + 'static {
    warp::path!("v2" / "p2p_summary")
        .and(warp::query::query())
        .map(move |()| -> WithStatus<Json> {
            let report = tokio::task::block_in_place(|| futures::executor::block_on(reporter.lock().unwrap().get_p2p_report()));

            with_status(json(&report), StatusCode::OK)
        })
}

#[allow(dead_code)]
pub fn types(_storage: P2pStore) -> impl Filter<Extract=(WithStatus<Json>, ), Error=Rejection> + Clone + Sync + Send + 'static {
    warp::path!("types"/ u64 / u32)
        .map(move |_index: u64, _types: u32| -> WithStatus<Json> {
            /*match storage.type_iterator(Some(index), types) {
                Ok(values) => {
                    with_status(json(&values.collect_vec()), StatusCode::OK)
                }
                Err(err) => with_status(json(&format!("database error: {}", err)), StatusCode::INTERNAL_SERVER_ERROR),
            }*/ unimplemented!()
        })
}
