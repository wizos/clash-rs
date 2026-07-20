use std::{
    io::IoSliceMut,
    ops::DerefMut,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::ready;
use quinn::{
    AsyncUdpSocket, TokioRuntime,
    udp::{RecvMeta, Transmit},
};
use sha2::{Digest, Sha256};

const SALT_LEN: usize = 16;

struct XPlusObfs {
    key: Vec<u8>,
}

impl XPlusObfs {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Obfuscate: prepend a random salt, then XOR the payload with
    /// SHA-256(key || salt)
    fn encrypt(&self, data: &mut [u8]) -> Bytes {
        let salt: [u8; SALT_LEN] = rand::random::<[u8; SALT_LEN]>();

        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(&salt);
        let key_hash: [u8; 32] = hasher.finalize().into();

        // XOR the payload with the key hash (repeating as needed)
        data.iter_mut().enumerate().for_each(|(i, v)| {
            *v ^= key_hash[i % 32];
        });

        let mut res = BytesMut::with_capacity(SALT_LEN + data.len());
        res.put_slice(&salt);
        res.put_slice(data);

        res.freeze()
    }

    /// Deobfuscate: extract the salt, then XOR the payload with
    /// SHA-256(key || salt)
    fn decrypt(&self, data: &mut [u8]) {
        assert!(data.len() > SALT_LEN, "data len must > salt_len");

        let (salt, payload) = data.split_at_mut(SALT_LEN);

        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(salt);
        let key_hash: [u8; 32] = hasher.finalize().into();

        payload.iter_mut().enumerate().for_each(|(i, v)| {
            *v ^= key_hash[i % 32];
        });
    }
}

pub struct XPlus {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: XPlusObfs,
}

impl XPlus {
    pub fn new(socket: std::net::UdpSocket, key: Vec<u8>) -> std::io::Result<Self> {
        use quinn::Runtime;
        let inner = TokioRuntime.wrap_udp_socket(socket)?;

        std::io::Result::Ok(Self {
            inner,
            obfs: XPlusObfs::new(key),
        })
    }
}

impl std::fmt::Debug for XPlus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl AsyncUdpSocket for XPlus {
    fn create_io_poller(
        self: std::sync::Arc<Self>,
    ) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let mut v = transmit.to_owned();
        // Encrypt the contents
        let x = self.obfs.encrypt(&mut v.contents.to_vec());
        v.contents = &x;
        self.inner.try_send(&v)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let packet_nums = ready!(self.inner.poll_recv(cx, bufs, meta))?;

        let mut valid_count = 0;

        for i in 0..packet_nums {
            tracing::trace!(
                "meta addr {:?}, dst_ip: {:?}, len: {}, stride: {}",
                meta[i].addr,
                meta[i].dst_ip,
                meta[i].len,
                meta[i].stride,
            );

            let total_len = meta[i].len;
            let stride = meta[i].stride;
            let buf = bufs[i].deref_mut();
            let buf_len = buf.len();

            // Validate buffer bounds
            if total_len > buf_len {
                tracing::error!(
                    "invalid buffer: total_len={} > buf_len={}, addr={:?}",
                    total_len,
                    buf_len,
                    meta[i].addr
                );
                continue;
            }

            // XPlus packets must have at least SALT_LEN bytes (salt) + 1 byte
            // (data)
            if total_len <= SALT_LEN || stride <= SALT_LEN {
                tracing::debug!(
                    "invalid xplus packet: len={}, stride={}, addr={:?}",
                    total_len,
                    stride,
                    meta[i].addr
                );
                continue;
            }

            // Fast path: single packet (no GRO, typical on Windows/Mac)
            if total_len == stride {
                // Decrypt and strip the SALT_LEN-byte salt prefix
                self.obfs.decrypt(&mut buf[..total_len]);
                buf.copy_within(SALT_LEN..total_len, 0);

                // Compact valid packets to the front
                if i != valid_count {
                    meta[valid_count] = meta[i];
                    bufs.swap(i, valid_count);
                }
                meta[valid_count].len = total_len - SALT_LEN;
                meta[valid_count].stride = stride - SALT_LEN;
                valid_count += 1;
                continue;
            }

            // Slow path: GRO-merged packets (Linux with GRO enabled)
            let mut read_offset = 0;
            let mut write_offset = 0;
            while read_offset < total_len {
                let seg_len = stride.min(total_len - read_offset);
                if seg_len <= SALT_LEN {
                    break;
                }

                if read_offset + seg_len > buf_len {
                    tracing::error!(
                        "GRO segment out of bounds: read_offset={}, seg_len={}, \
                         buf_len={}",
                        read_offset,
                        seg_len,
                        buf_len
                    );
                    break;
                }

                // Decrypt this segment in place
                self.obfs
                    .decrypt(&mut buf[read_offset..read_offset + seg_len]);

                let payload_len = seg_len - SALT_LEN;
                if write_offset + payload_len > buf_len {
                    tracing::error!(
                        "GRO write out of bounds: write_offset={}, payload_len={}, \
                         buf_len={}",
                        write_offset,
                        payload_len,
                        buf_len
                    );
                    break;
                }

                // Copy decrypted payload (skip SALT_LEN-byte salt) to compacted
                // position
                buf.copy_within(
                    read_offset + SALT_LEN..read_offset + seg_len,
                    write_offset,
                );

                read_offset += seg_len;
                write_offset += payload_len;
            }

            if write_offset > 0 {
                if i != valid_count {
                    meta[valid_count] = meta[i];
                    bufs.swap(i, valid_count);
                }
                meta[valid_count].len = write_offset;
                meta[valid_count].stride = stride - SALT_LEN;
                valid_count += 1;
            }
        }

        Poll::Ready(Ok(valid_count))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[test]
fn test_xplus_obfs_roundtrip() {
    let obfs = XPlusObfs::new(b"test_key".to_vec());
    let mut data = b"hello world".to_vec();
    let encrypted = obfs.encrypt(&mut data);

    // Verify encrypted data has salt prefix
    assert!(encrypted.len() == SALT_LEN + 11);

    // Decrypt
    let mut encrypted_mut = encrypted.to_vec();
    obfs.decrypt(&mut encrypted_mut);

    // After decrypt, the payload (after salt) should match original
    assert_eq!(&encrypted_mut[SALT_LEN..], b"hello world");
}
