use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
    routing::get,
};
use serde_json::json;
use tracing::{debug, warn};

use crate::app::api::{
    AppState,
    handlers::{
        connection::GetConnectionsQuery,
        flows::ws_handle as flows_ws_handle,
        memory::{GetMemoryQuery, GetMemoryResponse},
    },
};

pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/events", get(events))
        .route("/connections", get(connections))
        .route("/traffic", get(traffic))
        .route("/memory", get(memory))
        .route("/logs", get(log))
        .route("/flows", get(flows_ws_handle))
        .with_state(state)
}

async fn events(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_failed_upgrade(|e| {
        warn!("runtime event websocket upgrade failed: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        let mut receiver = crate::app::events::subscribe();
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if let Err(error) =
                        socket.send(Message::Text(event.into())).await
                    {
                        debug!("runtime event websocket closed: {}", error);
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!("runtime event websocket lagged by {} messages", skipped);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

pub async fn connections(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    query: Query<GetConnectionsQuery>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let interval = query.interval.unwrap_or(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval));

        loop {
            interval.tick().await;
            let snapshot = state.statistics_manager.snapshot(false).await;

            let body = match serde_json::to_string(&snapshot) {
                Ok(body) => body,
                Err(e) => {
                    debug!("failed to serialize snapshot for ws connection: {}", e);
                    break;
                }
            };

            if let Err(e) = socket.send(Message::Text(body.into())).await {
                debug!("ws connection closed with error: {}", e);
                break;
            }
        }
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await;
    })
}

pub async fn traffic(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            interval.tick().await;
            let (up, down) = state.statistics_manager.now(false);
            let response = json!({
                "up": up,
                "down": down,
            })
            .to_string();

            if let Err(e) = socket.send(Message::Text(response.into())).await {
                debug!("ws connection closed with error: {}", e);
                break;
            }
        }
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await;
    })
}

pub async fn memory(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    query: Query<GetMemoryQuery>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let interval = query.interval.unwrap_or(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval));

        loop {
            interval.tick().await;
            let snapshot = GetMemoryResponse {
                inuse: state.statistics_manager.memory_usage(),
                oslimit: 0,
            };

            let body = match serde_json::to_string(&snapshot) {
                Ok(body) => body,
                Err(e) => {
                    debug!("failed to serialize memory snapshot: {}", e);
                    break;
                }
            };

            if let Err(e) = socket.send(Message::Text(body.into())).await {
                debug!("ws connection closed with error: {}", e);
                break;
            }
        }
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await;
    })
}

pub async fn log(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        let mut rx = state.log_source_tx.subscribe();
        while let Ok(evt) = rx.recv().await {
            let res = match serde_json::to_string(&evt) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to serialize log event: {}", e);
                    continue;
                }
            };

            if let Err(e) = socket.send(Message::Text(res.into())).await {
                warn!("ws send error: {}", e);
                break;
            }
        }
    })
}
