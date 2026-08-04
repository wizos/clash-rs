use std::sync::LazyLock;

use serde::Serialize;
use tokio::sync::broadcast;

static RUNTIME_EVENTS: LazyLock<broadcast::Sender<String>> =
    LazyLock::new(|| broadcast::channel(512).0);
static APP_EVENTS: LazyLock<broadcast::Sender<String>> =
    LazyLock::new(|| broadcast::channel(512).0);

fn message(event_type: &str, data: impl Serialize) -> Option<String> {
    serde_json::to_string(&serde_json::json!({
        "type": event_type,
        "data": data,
    }))
    .ok()
}

/// Emit a FlClash-compatible runtime event. Keeping the wire shape here makes
/// connection, provider and delay producers share one ordered event stream.
pub fn emit(event_type: &str, data: impl Serialize) {
    if let Some(message) = message(event_type, data) {
        let _ = RUNTIME_EVENTS.send(message.clone());
        let _ = APP_EVENTS.send(message);
    }
}

pub fn emit_app(event_type: &str, data: impl Serialize) {
    if let Some(message) = message(event_type, data) {
        let _ = APP_EVENTS.send(message);
    }
}

pub fn subscribe() -> broadcast::Receiver<String> {
    RUNTIME_EVENTS.subscribe()
}

pub fn subscribe_app() -> broadcast::Receiver<String> {
    APP_EVENTS.subscribe()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn emits_the_flclash_message_shape() {
        let mut receiver = subscribe();
        let mut app_receiver = subscribe_app();
        emit("loaded", "provider-a");

        let value: serde_json::Value =
            serde_json::from_str(&receiver.recv().await.unwrap()).unwrap();
        assert_eq!(value["type"], "loaded");
        assert_eq!(value["data"], "provider-a");
        assert_eq!(app_receiver.recv().await.unwrap(), value.to_string());
    }
}
