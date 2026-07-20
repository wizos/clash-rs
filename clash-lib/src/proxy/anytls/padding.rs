use std::{collections::HashMap, io, sync::Arc};

use bytes::{BufMut, BytesMut};
use md5::Digest;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::RwLock,
};

use super::CMD_WASTE;

const FRAME_HEADER_SIZE: usize = 7;

pub(super) const DEFAULT_PADDING_SCHEME: &str =
    "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,\
     500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

pub(super) type SharedPadding = Arc<RwLock<Arc<PaddingFactory>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PaddingItem {
    Size(usize),
    CheckMark,
}

#[derive(Clone, Debug)]
pub(super) struct PaddingFactory {
    #[cfg(test)]
    raw_scheme: Vec<u8>,
    stop: u32,
    md5: String,
    scheme: HashMap<u32, Vec<PaddingItem>>,
}

impl PaddingFactory {
    pub(super) fn default_factory() -> Arc<Self> {
        Arc::new(
            Self::new(DEFAULT_PADDING_SCHEME.as_bytes())
                .expect("the built-in AnyTLS padding scheme must be valid"),
        )
    }

    pub(super) fn new(raw_scheme: &[u8]) -> io::Result<Self> {
        let text = std::str::from_utf8(raw_scheme).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("AnyTLS padding scheme is not UTF-8: {error}"),
            )
        })?;
        let mut values = HashMap::new();
        for line in text.split('\n') {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            values.insert(key, value);
        }
        if values.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "AnyTLS padding scheme is empty",
            ));
        }
        let stop = values
            .get("stop")
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AnyTLS padding scheme has no stop value",
                )
            })?
            .parse::<u32>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid AnyTLS padding stop value: {error}"),
                )
            })?;

        let mut scheme = HashMap::new();
        for (key, value) in values {
            let Ok(packet) = key.parse::<u32>() else {
                continue;
            };
            let mut items = Vec::new();
            for item in value.split(',') {
                if item == "c" {
                    items.push(PaddingItem::CheckMark);
                    continue;
                }
                let Some((minimum, maximum)) = item.split_once('-') else {
                    continue;
                };
                let (Ok(minimum), Ok(maximum)) =
                    (minimum.parse::<usize>(), maximum.parse::<usize>())
                else {
                    continue;
                };
                let (minimum, maximum) = if minimum <= maximum {
                    (minimum, maximum)
                } else {
                    (maximum, minimum)
                };
                if minimum == 0 || maximum > u16::MAX as usize {
                    continue;
                }
                let size = if minimum == maximum {
                    minimum
                } else {
                    // Mihomo deliberately treats the upper endpoint as
                    // exclusive (`rand.Int(max-min) + min`).
                    rand::random_range(minimum..maximum)
                };
                items.push(PaddingItem::Size(size));
            }
            scheme.insert(packet, items);
        }

        let mut hasher = md5::Md5::new();
        hasher.update(raw_scheme);
        let md5 = hex::encode(hasher.finalize());
        Ok(Self {
            #[cfg(test)]
            raw_scheme: raw_scheme.to_vec(),
            stop,
            md5,
            scheme,
        })
    }

    pub(super) fn md5(&self) -> &str {
        &self.md5
    }

    #[cfg(test)]
    #[cfg(test)]
    pub(super) fn raw_scheme(&self) -> &[u8] {
        &self.raw_scheme
    }

    fn generate_record_payload_sizes(&self, packet: u32) -> Vec<PaddingItem> {
        self.scheme.get(&packet).cloned().unwrap_or_default()
    }

    pub(super) fn authentication_padding_size(&self) -> usize {
        self.generate_record_payload_sizes(0)
            .into_iter()
            .find_map(|item| match item {
                PaddingItem::Size(size) => Some(size),
                PaddingItem::CheckMark => None,
            })
            .unwrap_or_default()
    }
}

pub(super) fn new_shared_padding() -> SharedPadding {
    Arc::new(RwLock::new(PaddingFactory::default_factory()))
}

pub(super) async fn write_padded(
    writer: &mut (impl AsyncWrite + Unpin),
    mut payload: BytesMut,
    padding: &SharedPadding,
    packet_counter: &std::sync::atomic::AtomicU32,
) -> io::Result<()> {
    // Mihomo's atomic Add returns the incremented value, so packet 0 is
    // reserved for authentication and framed traffic starts at packet 1.
    let packet = packet_counter
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
        .wrapping_add(1);
    let factory = padding.read().await.clone();
    if packet >= factory.stop {
        return writer.write_all(&payload).await;
    }

    for item in factory.generate_record_payload_sizes(packet) {
        let remaining = payload.len();
        let PaddingItem::Size(target_size) = item else {
            if remaining == 0 {
                break;
            }
            continue;
        };

        if remaining > target_size {
            let record = payload.split_to(target_size);
            writer.write_all(&record).await?;
        } else if remaining > 0 {
            let padding_len = target_size
                .checked_sub(remaining + FRAME_HEADER_SIZE)
                .unwrap_or_default();
            if padding_len > 0 {
                append_waste_frame(&mut payload, padding_len);
            }
            writer.write_all(&payload).await?;
            payload.clear();
        } else {
            let mut waste = BytesMut::with_capacity(FRAME_HEADER_SIZE + target_size);
            append_waste_frame(&mut waste, target_size);
            writer.write_all(&waste).await?;
        }
    }

    if !payload.is_empty() {
        writer.write_all(&payload).await?;
    }
    Ok(())
}

fn append_waste_frame(buffer: &mut BytesMut, padding_len: usize) {
    debug_assert!(padding_len <= u16::MAX as usize);
    buffer.reserve(FRAME_HEADER_SIZE + padding_len);
    buffer.put_u8(CMD_WASTE);
    buffer.put_u32(0);
    buffer.put_u16(padding_len as u16);
    buffer.resize(buffer.len() + padding_len, 0);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;

    use tokio::io::AsyncReadExt;

    use super::*;

    #[test]
    fn parses_mihomo_default_scheme() {
        let factory = PaddingFactory::default_factory();
        assert_eq!(factory.stop, 8);
        assert_eq!(factory.authentication_padding_size(), 30);
        assert_eq!(factory.raw_scheme(), DEFAULT_PADDING_SCHEME.as_bytes());
        assert_eq!(factory.md5(), "75cff2ad89aadf5e257059ee571ebe11");
    }

    #[tokio::test]
    async fn pads_first_framed_packet_to_requested_record_size() {
        let factory = Arc::new(PaddingFactory::new(b"stop=2\n1=100-100").unwrap());
        let padding = Arc::new(RwLock::new(factory));
        let counter = AtomicU32::new(0);
        let (mut client, mut server) = tokio::io::duplex(256);

        let task = tokio::spawn(async move {
            write_padded(
                &mut client,
                BytesMut::from(&b"payload"[..]),
                &padding,
                &counter,
            )
            .await
            .unwrap();
        });
        let mut wire = vec![0u8; 100];
        server.read_exact(&mut wire).await.unwrap();
        task.await.unwrap();

        assert_eq!(&wire[..7], b"payload");
        assert_eq!(wire[7], CMD_WASTE);
        assert_eq!(u16::from_be_bytes([wire[12], wire[13]]), 86);
        assert!(wire[14..].iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn check_mark_stops_after_payload_is_consumed() {
        let factory = Arc::new(PaddingFactory::new(b"stop=2\n1=4-4,c,8-8").unwrap());
        let padding = Arc::new(RwLock::new(factory));
        let counter = AtomicU32::new(0);
        let (mut client, mut server) = tokio::io::duplex(64);

        write_padded(
            &mut client,
            BytesMut::from(&b"data"[..]),
            &padding,
            &counter,
        )
        .await
        .unwrap();
        let mut wire = [0u8; 4];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire, b"data");
    }
}
