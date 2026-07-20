use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{FromRequest, Query, Request, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::app::api::{AppState, handlers::utils::is_request_websocket};

#[derive(Deserialize)]
pub struct TrafficQuery {
    #[serde(rename = "only-proxy", default)]
    only_proxy: bool,
}

#[derive(Serialize)]
struct TrafficResponse {
    up: u64,
    down: u64,
}

pub async fn handle(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Query(query): Query<TrafficQuery>,
    req: Request<Body>,
) -> impl IntoResponse {
    if !is_request_websocket(&headers) {
        let (up, down) = state.statistics_manager.now(query.only_proxy);
        return Json(TrafficResponse { up, down }).into_response();
    }

    let ws = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(ws) => ws,
        Err(error) => return error.into_response(),
    };
    ws.on_failed_upgrade(|error| warn!("ws upgrade error: {error}"))
        .on_upgrade(move |mut socket| async move {
            loop {
                let (up, down) = state.statistics_manager.now(query.only_proxy);
                let response = TrafficResponse { up, down };
                let body = match serde_json::to_string(&response) {
                    Ok(body) => body,
                    Err(error) => {
                        warn!("failed to serialize traffic stats: {error}");
                        continue;
                    }
                };

                if let Err(error) = socket.send(Message::Text(body.into())).await {
                    warn!("ws send error: {error}");
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        })
        .into_response()
}
