// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{sync::Arc, collections::HashMap};
use anyhow::Result;
use warp::{
    Filter, Rejection, Reply,
    reply::{WithStatus, Json, self},
    http::StatusCode,
};
use super::{
    database::{DatabaseFetch, ConnectionsFilter, ChunksFilter, MessagesFilter, LogsFilter},
    tables::chunk,
};

fn connections<Db>(
    db: Arc<Db>,
) -> impl Filter<Extract = (WithStatus<Json>,), Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    warp::path!("v3" / "connections")
        .and(warp::query::query())
        .map(move |filter: ConnectionsFilter| -> WithStatus<Json> {
            match db.fetch_connections(&filter) {
                Ok(connections) => reply::with_status(reply::json(&connections), StatusCode::OK),
                Err(err) => {
                    let r = &format!("database error: {}", err);
                    reply::with_status(reply::json(&r), StatusCode::INTERNAL_SERVER_ERROR)
                },
            }
        })
}

fn chunks<Db>(
    db: Arc<Db>,
) -> impl Filter<Extract = (WithStatus<Json>,), Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    warp::path!("v3" / "chunks").and(warp::query::query()).map(
        move |filter: ChunksFilter| -> WithStatus<Json> {
            match db.fetch_chunks_truncated(&filter) {
                Ok(chunks) => reply::with_status(reply::json(&chunks), StatusCode::OK),
                Err(err) => {
                    let r = &format!("database error: {}", err);
                    reply::with_status(reply::json(&r), StatusCode::INTERNAL_SERVER_ERROR)
                },
            }
        },
    )
}

fn chunk<Db>(
    db: Arc<Db>,
) -> impl Filter<Extract = (WithStatus<Json>,), Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    fn inner<Db>(db: &Arc<Db>, chunk_id: String) -> Result<Option<chunk::Value>>
    where
        Db: DatabaseFetch + Sync + Send + 'static,
    {
        let key = chunk_id.parse()?;
        db.fetch_chunk(&key).map_err(Into::into)
    }

    warp::path!("v3" / "chunk" / String).map(move |chunk_id: String| -> WithStatus<Json> {
        match inner(&db, chunk_id) {
            Ok(v) => reply::with_status(reply::json(&v), StatusCode::OK),
            Err(err) => {
                let r = format!("database error: {}", err);
                reply::with_status(reply::json(&r), StatusCode::INTERNAL_SERVER_ERROR)
            },
        }
    })
}

fn messages<Db>(
    db: Arc<Db>,
) -> impl Filter<Extract = (WithStatus<Json>,), Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    warp::path!("v3" / "messages")
        .and(warp::query::query())
        .map(move |filter: MessagesFilter| -> reply::WithStatus<Json> {
            match db.fetch_messages(&filter) {
                Ok(messages) => reply::with_status(reply::json(&messages), StatusCode::OK),
                Err(err) => {
                    let r = &format!("database error: {}", err);
                    reply::with_status(reply::json(&r), StatusCode::INTERNAL_SERVER_ERROR)
                },
            }
        })
}

fn message<Db>(
    db: Arc<Db>,
) -> impl Filter<Extract = (WithStatus<Json>,), Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    warp::path!("v3" / "message" / u64).map(move |id: u64| -> reply::WithStatus<Json> {
        match db.fetch_message(id) {
            Ok(message) => reply::with_status(reply::json(&message), StatusCode::OK),
            Err(err) => {
                let r = &format!("database error: {}", err);
                reply::with_status(reply::json(&r), StatusCode::INTERNAL_SERVER_ERROR)
            },
        }
    })
}

fn logs<Db>(
    db: Arc<Db>,
) -> impl Filter<Extract = (WithStatus<Json>,), Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    warp::path!("v3" / "logs").and(warp::query::query()).map(
        move |filter: LogsFilter| -> reply::WithStatus<Json> {
            match db.fetch_log(&filter) {
                Ok(v) => reply::with_status(reply::json(&v), StatusCode::OK),
                Err(err) => {
                    let r = &format!("database error: {}", err);
                    reply::with_status(reply::json(&r), StatusCode::INTERNAL_SERVER_ERROR)
                },
            }
        },
    )
}

pub fn version() -> impl Filter<Extract=(WithStatus<Json>, ), Error=Rejection> + Clone + Sync + Send + 'static {
    warp::path!("v2" / "version")
        .and(warp::query::query())
        .map(move |()| -> reply::WithStatus<Json> {
            reply::with_status(reply::json(&env!("GIT_HASH")), StatusCode::OK)
        })
}

pub fn routes<Db>(
    db: Arc<Db>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    use warp::reply::with;

    warp::get()
        .and(
            connections(db.clone())
                .or(chunks(db.clone()))
                .or(chunk(db.clone()))
                .or(messages(db.clone()))
                .or(message(db.clone()))
                .or(logs(db))
                .or(version()),
        )
        .with(with::header("Content-Type", "application/json"))
        .with(with::header("Access-Control-Allow-Origin", "*"))
}

fn p2p<Db>(
    dbs: HashMap<String, Arc<Db>>,
) -> impl Filter<Extract = (WithStatus<Json>,), Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    warp::path!("v2" / "p2p").and(warp::query::query()).map(
        move |filter: MessagesFilter| -> reply::WithStatus<Json> {
            let node_name = filter.node_name.clone().unwrap_or("tezedge".to_string());
            match dbs.get(&node_name) {
                Some(db) => match db.fetch_messages(&filter) {
                    Ok(messages) => reply::with_status(reply::json(&messages), StatusCode::OK),
                    Err(err) => {
                        let r = &format!("database error: {}", err);
                        reply::with_status(reply::json(&r), StatusCode::INTERNAL_SERVER_ERROR)
                    },
                },
                None => {
                    let r = &format!("no such node: {:?}", node_name);
                    reply::with_status(reply::json(&r), StatusCode::NOT_FOUND)
                },
            }
        },
    )
}

fn p2p_details<Db>(
    dbs: HashMap<String, Arc<Db>>,
) -> impl Filter<Extract = (WithStatus<Json>,), Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    warp::path!("v2" / "p2p" / u64)
        .and(warp::query::query())
        .map(move |id: u64, filter: MessagesFilter| -> reply::WithStatus<Json> {
            let node_name = filter.node_name.clone().unwrap_or("tezedge".to_string());
            match dbs.get(&node_name) {
                Some(db) => match db.fetch_message(id) {
                    Ok(message) => reply::with_status(reply::json(&message), StatusCode::OK),
                    Err(err) => {
                        let r = &format!("database error: {}", err);
                        reply::with_status(reply::json(&r), StatusCode::INTERNAL_SERVER_ERROR)
                    },
                },
                None => {
                    let r = &format!("no such node: {:?}", node_name);
                    reply::with_status(reply::json(&r), StatusCode::NOT_FOUND)
                },
            }
        })
}

fn log_old<Db>(
    dbs: HashMap<String, Arc<Db>>,
) -> impl Filter<Extract = (WithStatus<Json>,), Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    warp::path!("v2" / "log").and(warp::query::query()).map(
        move |filter: LogsFilter| -> reply::WithStatus<Json> {
            let node_name = filter.node_name.clone().unwrap_or("tezedge".to_string());
            match dbs.get(&node_name) {
                Some(db) => match db.fetch_log(&filter) {
                    Ok(v) => reply::with_status(reply::json(&v), StatusCode::OK),
                    Err(err) => {
                        let r = &format!("database error: {}", err);
                        reply::with_status(reply::json(&r), StatusCode::INTERNAL_SERVER_ERROR)
                    },
                },
                None => {
                    let r = &format!("no such node: {:?}", node_name);
                    reply::with_status(reply::json(&r), StatusCode::NOT_FOUND)
                },
            }
        },
    )
}

pub fn routes_old<Db>(
    dbs: HashMap<String, Arc<Db>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone + Sync + Send + 'static
where
    Db: DatabaseFetch + Sync + Send + 'static,
{
    use warp::reply::with;

    warp::get()
        .and(
            p2p(dbs.clone())
                .or(p2p_details(dbs.clone()))
                .or(log_old(dbs))
                .or(version()),
        )
        .with(with::header("Content-Type", "application/json"))
        .with(with::header("Access-Control-Allow-Origin", "*"))
}
