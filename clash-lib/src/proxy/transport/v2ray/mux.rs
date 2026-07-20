use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::proxy::AnyStream;

const SESSION_NEW: u8 = 0x01;
const SESSION_KEEP: u8 = 0x02;
const SESSION_END: u8 = 0x03;
const SESSION_KEEP_ALIVE: u8 = 0x04;
const OPTION_NONE: u8 = 0x00;
const OPTION_DATA: u8 = 0x01;
const MAX_METADATA_LENGTH: usize = 512;
const STREAM_ID: [u8; 2] = [0, 0];

/// Wraps a WebSocket with the compact mux stream used specifically by
/// v2ray-plugin. This is not sing-mux/SMUX: Mihomo uses the framing implemented
/// in `transport/v2ray-plugin/mux.go` with a single fixed sub-connection.
pub(super) fn wrap(stream: AnyStream) -> AnyStream {
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);
    let (app, relay) = tokio::io::duplex(64 * 1024);
    let (mut relay_read, mut relay_write) = tokio::io::split(relay);
    let cancellation = CancellationToken::new();
    let write_cancellation = cancellation.clone();
    let read_cancellation = cancellation;

    tokio::spawn(async move {
        let result = async {
            remote_write.write_all(&new_session_frame()).await?;
            remote_write.flush().await?;

            let mut payload = vec![0u8; u16::MAX as usize];
            loop {
                let read = relay_read.read(&mut payload).await?;
                if read == 0 {
                    remote_write.write_all(&end_session_frame()).await?;
                    remote_write.flush().await?;
                    return Ok::<_, io::Error>(());
                }
                write_data_frame(&mut remote_write, &payload[..read]).await?;
            }
        }
        .await;
        if let Err(error) = result {
            debug!("v2ray-plugin mux writer stopped: {error}");
        }
        write_cancellation.cancel();
    });

    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = read_cancellation.cancelled() => break,
                result = read_data_frame(&mut remote_read) => {
                    match result {
                        Ok(Some(data)) => {
                            if let Err(error) = relay_write.write_all(&data).await {
                                debug!("v2ray-plugin mux relay stopped: {error}");
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            debug!("v2ray-plugin mux reader stopped: {error}");
                            break;
                        }
                    }
                }
            }
        }
        let _ = relay_write.shutdown().await;
        read_cancellation.cancel();
    });

    Box::new(app)
}

fn new_session_frame() -> Vec<u8> {
    // Fixed target used by Mihomo/v2ray-plugin: TCP 127.0.0.1:0. The actual
    // destination remains inside the Shadowsocks stream.
    vec![
        0x00,
        0x0c,
        STREAM_ID[0],
        STREAM_ID[1],
        SESSION_NEW,
        OPTION_NONE,
        0x01, // TCP
        0x00,
        0x00, // port 0
        0x01, // IPv4
        127,
        0,
        0,
        1,
    ]
}

fn end_session_frame() -> [u8; 6] {
    [0, 4, STREAM_ID[0], STREAM_ID[1], SESSION_END, OPTION_NONE]
}

async fn write_data_frame(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    payload: &[u8],
) -> io::Result<()> {
    debug_assert!(payload.len() <= u16::MAX as usize);
    writer.write_u16(4).await?;
    writer.write_all(&STREAM_ID).await?;
    writer.write_u8(SESSION_KEEP).await?;
    writer.write_u8(OPTION_DATA).await?;
    writer.write_u16(payload.len() as u16).await?;
    writer.write_all(payload).await
}

async fn read_data_frame(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
) -> io::Result<Option<Vec<u8>>> {
    let metadata_length = reader.read_u16().await? as usize;
    if !(4..=MAX_METADATA_LENGTH).contains(&metadata_length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid v2ray-plugin mux metadata length: {metadata_length}"),
        ));
    }
    let mut metadata = vec![0u8; metadata_length];
    reader.read_exact(&mut metadata).await?;
    let status = metadata[2];
    let option = metadata[3];
    if status == SESSION_KEEP_ALIVE || option != OPTION_DATA {
        return Ok(None);
    }
    let length = reader.read_u16().await? as usize;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[test]
    fn initial_and_end_frames_match_mihomo() {
        assert_eq!(
            new_session_frame(),
            [0, 12, 0, 0, 1, 0, 1, 0, 0, 1, 127, 0, 0, 1]
        );
        assert_eq!(end_session_frame(), [0, 4, 0, 0, 3, 0]);
    }

    #[tokio::test]
    async fn mux_round_trip_uses_v2ray_plugin_frames() {
        let (client, mut server) = duplex(4096);
        let mut app = wrap(Box::new(client));

        app.write_all(b"hello").await.unwrap();
        let mut initial = [0u8; 14];
        server.read_exact(&mut initial).await.unwrap();
        assert_eq!(initial.as_slice(), new_session_frame());
        assert_eq!(server.read_u16().await.unwrap(), 4);
        let mut metadata = [0u8; 4];
        server.read_exact(&mut metadata).await.unwrap();
        assert_eq!(metadata, [0, 0, SESSION_KEEP, OPTION_DATA]);
        assert_eq!(server.read_u16().await.unwrap(), 5);
        let mut payload = [0u8; 5];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");

        server.write_u16(4).await.unwrap();
        server
            .write_all(&[0, 0, SESSION_KEEP, OPTION_DATA])
            .await
            .unwrap();
        server.write_u16(5).await.unwrap();
        server.write_all(b"world").await.unwrap();
        let mut reply = [0u8; 5];
        app.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"world");
    }
}
