use std::sync::LazyLock;

use serde::Serialize;
use tokio::sync::broadcast;

static RUNTIME_EVENTS: LazyLock<broadcast::Sender<String>> =
    LazyLock::new(|| broadcast::channel(512).0);

/// Emit a FlClash-compatible runtime event. Keeping the wire shape here makes
/// connection, provider and delay producers share one ordered event stream.
pub fn emit(event_type: &str, data: impl Serialize) {
    if let Ok(message) = serde_json::to_string(&serde_json::json!({
        "type": event_type,
        "data": data,
    })) {
        let _ = RUNTIME_EVENTS.send(message);
    }
}

pub fn subscribe() -> broadcast::Receiver<String> {
    RUNTIME_EVENTS.subscribe()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn emits_the_flclash_message_shape() {
        let mut receiver = subscribe();
        emit("loaded", "provider-a");

        let value: serde_json::Value =
            serde_json::from_str(&receiver.recv().await.unwrap()).unwrap();
        assert_eq!(value["type"], "loaded");
        assert_eq!(value["data"], "provider-a");
    }
}
