use std::{
    collections::BTreeMap,
    io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{Mutex, mpsc},
};

use super::{
    packet::{ControlPacket, Opcode, SessionId, parse_opcode},
    tls_crypt::TlsCrypt,
};

#[async_trait]
pub(super) trait PacketIo: Send + Sync + 'static {
    async fn read_packet(&self) -> io::Result<Vec<u8>>;
    async fn write_packet(&self, packet: &[u8]) -> io::Result<()>;
    async fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct PacketMux {
    io: Arc<dyn PacketIo>,
    control: Mutex<mpsc::Receiver<Vec<u8>>>,
    data: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl PacketMux {
    pub(super) fn new(io: Arc<dyn PacketIo>) -> Arc<Self> {
        let (control_tx, control) = mpsc::channel(64);
        let (data_tx, data) = mpsc::channel(256);
        let mux = Arc::new(Self {
            io: io.clone(),
            control: Mutex::new(control),
            data: Mutex::new(data),
        });
        tokio::spawn(async move {
            while let Ok(packet) = io.read_packet().await {
                if packet.is_empty() {
                    continue;
                }
                let sender = match parse_opcode(&packet) {
                    Ok(opcode) if opcode.is_control() => &control_tx,
                    Ok(_) => &data_tx,
                    Err(_) => continue,
                };
                if sender.send(packet).await.is_err() {
                    break;
                }
            }
        });
        mux
    }

    async fn read_control(&self) -> io::Result<Vec<u8>> {
        self.control.lock().await.recv().await.ok_or_else(closed)
    }

    pub(super) async fn read_data(&self) -> io::Result<Vec<u8>> {
        self.data.lock().await.recv().await.ok_or_else(closed)
    }

    pub(super) async fn write(&self, packet: &[u8]) -> io::Result<()> {
        self.io.write_packet(packet).await
    }

    pub(super) async fn close(&self) -> io::Result<()> {
        self.io.close().await
    }
}

struct State {
    remote: SessionId,
    send_packet_id: u32,
    send_message: u32,
    recv_message: u32,
    ack_pending: Vec<u32>,
    pending: BTreeMap<u32, ControlPacket>,
    recv_pending: BTreeMap<u32, ControlPacket>,
}

pub(super) struct ControlChannel {
    mux: Arc<PacketMux>,
    crypt: Option<TlsCrypt>,
    local: SessionId,
    state: Mutex<State>,
}

impl ControlChannel {
    pub(super) fn new(
        mux: Arc<PacketMux>,
        crypt: Option<TlsCrypt>,
        local: SessionId,
    ) -> Arc<Self> {
        Arc::new(Self {
            mux,
            crypt,
            local,
            state: Mutex::new(State {
                remote: SessionId::default(),
                send_packet_id: 0,
                send_message: 0,
                recv_message: 0,
                ack_pending: Vec::new(),
                pending: BTreeMap::new(),
                recv_pending: BTreeMap::new(),
            }),
        })
    }

    pub(super) fn local_session(&self) -> SessionId {
        self.local
    }

    pub(super) async fn remote_session(&self) -> SessionId {
        self.state.lock().await.remote
    }

    pub(super) async fn send_reset(&self) -> io::Result<()> {
        self.send(Opcode::ControlHardResetClientV2, &[]).await?;
        Ok(())
    }

    pub(super) async fn send(
        &self,
        opcode: Opcode,
        payload: &[u8],
    ) -> io::Result<u32> {
        if !opcode.is_control() || opcode == Opcode::AckV1 {
            return Err(invalid("opcode cannot carry an openvpn reliable message"));
        }
        let (message_id, packet) = {
            let mut state = self.state.lock().await;
            let message_id = state.send_message;
            state.send_message = state
                .send_message
                .checked_add(1)
                .ok_or_else(|| invalid("openvpn control message id exhausted"))?;
            let packet = ControlPacket {
                opcode,
                key_id: 0,
                local_session: self.local,
                ack_ids: std::mem::take(&mut state.ack_pending),
                ack_remote_session: state.remote,
                message_id,
                payload: payload.to_vec(),
            };
            state.pending.insert(message_id, packet.clone());
            (message_id, packet)
        };
        self.write_packet(&packet).await?;
        Ok(message_id)
    }

    pub(super) async fn send_ack(&self) -> io::Result<()> {
        let packet = {
            let mut state = self.state.lock().await;
            if state.ack_pending.is_empty() {
                return Ok(());
            }
            ControlPacket {
                opcode: Opcode::AckV1,
                key_id: 0,
                local_session: self.local,
                ack_ids: std::mem::take(&mut state.ack_pending),
                ack_remote_session: state.remote,
                message_id: 0,
                payload: Vec::new(),
            }
        };
        self.write_packet(&packet).await
    }

    pub(super) async fn read(&self) -> io::Result<ControlPacket> {
        loop {
            if let Some(packet) = {
                let mut state = self.state.lock().await;
                let expected = state.recv_message;
                state.recv_pending.remove(&expected).inspect(|_| {
                    state.recv_message += 1;
                })
            } {
                return Ok(packet);
            }

            let raw = self.mux.read_control().await?;
            let (packet, ..) = ControlPacket::decode(self.crypt.as_ref(), &raw)?;
            let mut deliver = None;
            let mut send_ack = false;
            {
                let mut state = self.state.lock().await;
                if state.remote == SessionId::default()
                    && packet.local_session != self.local
                {
                    state.remote = packet.local_session;
                }
                for ack_id in &packet.ack_ids {
                    state.pending.remove(ack_id);
                }
                if packet.opcode.has_message_id()
                    && !state.ack_pending.contains(&packet.message_id)
                {
                    state.ack_pending.push(packet.message_id);
                }
                match packet.opcode {
                    Opcode::AckV1 => {}
                    _ if packet.message_id < state.recv_message => send_ack = true,
                    _ if packet.message_id == state.recv_message => {
                        state.recv_message += 1;
                        deliver = Some(packet);
                    }
                    _ => {
                        state
                            .recv_pending
                            .entry(packet.message_id)
                            .or_insert(packet);
                        send_ack = true;
                    }
                }
            }
            if send_ack {
                self.send_ack().await?;
            }
            if let Some(packet) = deliver {
                return Ok(packet);
            }
        }
    }

    pub(super) async fn retransmit_pending(&self) -> io::Result<()> {
        let packets = {
            let mut state = self.state.lock().await;
            let ack_ids = std::mem::take(&mut state.ack_pending);
            let remote = state.remote;
            state
                .pending
                .values()
                .cloned()
                .map(|mut packet| {
                    packet.ack_ids = ack_ids.clone();
                    packet.ack_remote_session = remote;
                    packet
                })
                .collect::<Vec<_>>()
        };
        for packet in packets {
            self.write_packet(&packet).await?;
        }
        Ok(())
    }

    pub(super) fn open_tls_transport(
        self: &Arc<Self>,
        retransmit: bool,
    ) -> DuplexStream {
        let (tls, bridge) = tokio::io::duplex(256 * 1024);
        let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge);
        let reader = self.clone();
        tokio::spawn(async move {
            loop {
                let read = if retransmit {
                    match tokio::time::timeout(Duration::from_secs(1), reader.read())
                        .await
                    {
                        Ok(result) => result,
                        Err(_) => {
                            if reader.retransmit_pending().await.is_err() {
                                break;
                            }
                            continue;
                        }
                    }
                } else {
                    reader.read().await
                };
                let Ok(packet) = read else { break };
                if reader.send_ack().await.is_err() {
                    break;
                }
                if packet.opcode == Opcode::ControlV1
                    && !packet.payload.is_empty()
                    && bridge_write.write_all(&packet.payload).await.is_err()
                {
                    break;
                }
            }
        });
        let writer = self.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 16 * 1024];
            loop {
                let Ok(length) = bridge_read.read(&mut buffer).await else {
                    break;
                };
                if length == 0
                    || writer
                        .send(Opcode::ControlV1, &buffer[..length])
                        .await
                        .is_err()
                {
                    break;
                }
            }
        });
        tls
    }

    async fn write_packet(&self, packet: &ControlPacket) -> io::Result<()> {
        let packet = {
            let mut state = self.state.lock().await;
            state.send_packet_id = state
                .send_packet_id
                .checked_add(1)
                .ok_or_else(|| invalid("openvpn control packet id exhausted"))?;
            packet.encode(
                self.crypt.as_ref(),
                state.send_packet_id,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32,
            )?
        };
        self.mux.write(&packet).await
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "openvpn packet transport closed")
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::{ControlChannel, PacketIo, PacketMux};
    use crate::proxy::openvpn::{packet::Opcode, tls_crypt::TlsCrypt};
    use async_trait::async_trait;
    use std::{io, sync::Arc};
    use tokio::sync::{Mutex, mpsc};

    struct MemoryIo {
        receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
        sender: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait]
    impl PacketIo for MemoryIo {
        async fn read_packet(&self) -> io::Result<Vec<u8>> {
            self.receiver
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
        }

        async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
            self.sender
                .send(packet.to_vec())
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    fn pair() -> (Arc<MemoryIo>, Arc<MemoryIo>) {
        let (client_tx, server_rx) = mpsc::channel(64);
        let (server_tx, client_rx) = mpsc::channel(64);
        (
            Arc::new(MemoryIo {
                receiver: Mutex::new(client_rx),
                sender: client_tx,
            }),
            Arc::new(MemoryIo {
                receiver: Mutex::new(server_rx),
                sender: server_tx,
            }),
        )
    }

    #[tokio::test]
    async fn reliable_tls_crypt_channel_delivers_and_acks() {
        let (client_io, server_io) = pair();
        let key: Vec<u8> = (0..=255).collect();
        let client = ControlChannel::new(
            PacketMux::new(client_io),
            Some(TlsCrypt::new(&key, true).unwrap()),
            super::SessionId(*b"client01"),
        );
        let server = ControlChannel::new(
            PacketMux::new(server_io),
            Some(TlsCrypt::new(&key, false).unwrap()),
            super::SessionId(*b"server01"),
        );
        client.send_reset().await.unwrap();
        let reset = server.read().await.unwrap();
        assert_eq!(reset.opcode, Opcode::ControlHardResetClientV2);
        server.send_ack().await.unwrap();
        client.send(Opcode::ControlV1, b"TLS record").await.unwrap();
        let record = server.read().await.unwrap();
        assert_eq!(record.payload, b"TLS record");
        assert_eq!(server.remote_session().await.0, *b"client01");
    }
}
