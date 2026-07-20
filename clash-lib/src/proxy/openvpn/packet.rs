use std::{fmt, io};

use rand::RngExt;

use super::tls_crypt::{HEADER_SIZE, TlsCrypt};

const KEY_ID_MASK: u8 = 0x07;
const OPCODE_SHIFT: u8 = 3;
pub(super) const PEER_ID_UNSET: u32 = 0x00ff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum Opcode {
    ControlHardResetClientV1 = 1,
    ControlHardResetServerV1 = 2,
    ControlSoftResetV1 = 3,
    ControlV1          = 4,
    AckV1              = 5,
    DataV1             = 6,
    ControlHardResetClientV2 = 7,
    ControlHardResetServerV2 = 8,
    DataV2             = 9,
    ControlHardResetClientV3 = 10,
    ControlWkcV1       = 11,
}

impl Opcode {
    fn parse(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::ControlHardResetClientV1),
            2 => Ok(Self::ControlHardResetServerV1),
            3 => Ok(Self::ControlSoftResetV1),
            4 => Ok(Self::ControlV1),
            5 => Ok(Self::AckV1),
            6 => Ok(Self::DataV1),
            7 => Ok(Self::ControlHardResetClientV2),
            8 => Ok(Self::ControlHardResetServerV2),
            9 => Ok(Self::DataV2),
            10 => Ok(Self::ControlHardResetClientV3),
            11 => Ok(Self::ControlWkcV1),
            _ => Err(invalid(format!("unknown openvpn opcode {value}"))),
        }
    }

    pub(super) fn is_control(self) -> bool {
        !matches!(self, Self::DataV1 | Self::DataV2)
    }

    pub(super) fn has_message_id(self) -> bool {
        self.is_control() && self != Self::AckV1
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct SessionId(pub [u8; 8]);

impl SessionId {
    pub(super) fn random() -> Self {
        let mut id = [0u8; 8];
        rand::rng().fill(&mut id);
        Self(id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ControlPacket {
    pub opcode: Opcode,
    pub key_id: u8,
    pub local_session: SessionId,
    pub ack_ids: Vec<u32>,
    pub ack_remote_session: SessionId,
    pub message_id: u32,
    pub payload: Vec<u8>,
}

impl ControlPacket {
    fn encode_plain(&self) -> io::Result<Vec<u8>> {
        if !self.opcode.is_control() || self.ack_ids.len() > u8::MAX as usize {
            return Err(invalid("invalid openvpn control packet"));
        }
        let mut output = Vec::new();
        output.push(self.ack_ids.len() as u8);
        for id in &self.ack_ids {
            output.extend_from_slice(&id.to_be_bytes());
        }
        if !self.ack_ids.is_empty() {
            output.extend_from_slice(&self.ack_remote_session.0);
        }
        if self.opcode.has_message_id() {
            output.extend_from_slice(&self.message_id.to_be_bytes());
            output.extend_from_slice(&self.payload);
        }
        Ok(output)
    }

    pub(super) fn encode(
        &self,
        crypt: Option<&TlsCrypt>,
        packet_id: u32,
        unix_time: u32,
    ) -> io::Result<Vec<u8>> {
        let mut header = [0u8; HEADER_SIZE];
        header[0] = (self.opcode as u8) << OPCODE_SHIFT | self.key_id & KEY_ID_MASK;
        header[1..].copy_from_slice(&self.local_session.0);
        let plain = self.encode_plain()?;
        match crypt {
            Some(crypt) => crypt.wrap(&header, packet_id, unix_time, &plain),
            None => Ok([header.as_slice(), plain.as_slice()].concat()),
        }
    }

    pub(super) fn decode(
        crypt: Option<&TlsCrypt>,
        packet: &[u8],
    ) -> io::Result<(Self, u32, u32)> {
        let (header, packet_id, unix_time, plain) = match crypt {
            Some(crypt) => crypt.unwrap(packet)?,
            None if packet.len() >= HEADER_SIZE + 1 => (
                packet[..HEADER_SIZE].to_vec(),
                0,
                0,
                packet[HEADER_SIZE..].to_vec(),
            ),
            None => return Err(invalid("openvpn control packet too short")),
        };
        let opcode = Opcode::parse(header[0] >> OPCODE_SHIFT)?;
        if !opcode.is_control() {
            return Err(invalid("not an openvpn control packet"));
        }
        let key_id = header[0] & KEY_ID_MASK;
        let local_session = SessionId(header[1..].try_into().unwrap());
        if plain.is_empty() {
            return Err(invalid("openvpn control payload too short"));
        }
        let ack_len = plain[0] as usize;
        let mut offset = 1;
        if plain.len() < offset + ack_len * 4 {
            return Err(invalid("openvpn ack array truncated"));
        }
        let mut ack_ids = Vec::with_capacity(ack_len);
        for _ in 0..ack_len {
            ack_ids.push(u32::from_be_bytes(
                plain[offset..offset + 4].try_into().unwrap(),
            ));
            offset += 4;
        }
        let ack_remote_session = if ack_len > 0 {
            if plain.len() < offset + 8 {
                return Err(invalid("openvpn ack session truncated"));
            }
            let session = SessionId(plain[offset..offset + 8].try_into().unwrap());
            offset += 8;
            session
        } else {
            SessionId::default()
        };
        let (message_id, payload) = if opcode.has_message_id() {
            if plain.len() < offset + 4 {
                return Err(invalid("openvpn message id truncated"));
            }
            let message_id =
                u32::from_be_bytes(plain[offset..offset + 4].try_into().unwrap());
            (message_id, plain[offset + 4..].to_vec())
        } else {
            if plain.len() != offset {
                return Err(invalid("openvpn ack packet has trailing payload"));
            }
            (0, Vec::new())
        };
        Ok((
            Self {
                opcode,
                key_id,
                local_session,
                ack_ids,
                ack_remote_session,
                message_id,
                payload,
            },
            packet_id,
            unix_time,
        ))
    }
}

pub(super) fn parse_opcode(packet: &[u8]) -> io::Result<Opcode> {
    packet
        .first()
        .ok_or_else(|| invalid("empty openvpn packet"))
        .and_then(|value| Opcode::parse(value >> OPCODE_SHIFT))
}

pub(super) fn data_header(peer_id: u32, key_id: u8) -> Vec<u8> {
    if peer_id == PEER_ID_UNSET {
        vec![(Opcode::DataV1 as u8) << OPCODE_SHIFT | key_id & KEY_ID_MASK]
    } else {
        vec![
            (Opcode::DataV2 as u8) << OPCODE_SHIFT | key_id & KEY_ID_MASK,
            (peer_id >> 16) as u8,
            (peer_id >> 8) as u8,
            peer_id as u8,
        ]
    }
}

pub(super) fn data_header_size(packet: &[u8]) -> io::Result<usize> {
    match parse_opcode(packet)? {
        Opcode::DataV1 => Ok(1),
        Opcode::DataV2 if packet.len() >= 4 => Ok(4),
        Opcode::DataV2 => Err(invalid("openvpn P_DATA_V2 missing peer id")),
        opcode => Err(invalid(format!("not an openvpn data packet: {opcode}"))),
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::{ControlPacket, Opcode, SessionId};
    use crate::proxy::openvpn::tls_crypt::TlsCrypt;

    fn packet() -> ControlPacket {
        ControlPacket {
            opcode: Opcode::ControlV1,
            key_id: 1,
            local_session: SessionId(*b"client01"),
            ack_ids: vec![3, 4],
            ack_remote_session: SessionId(*b"server01"),
            message_id: 9,
            payload: b"TLS ciphertext".to_vec(),
        }
    }

    #[test]
    fn plain_and_tls_crypt_control_packets_round_trip() {
        let original = packet();
        let plain = original.encode(None, 0, 0).unwrap();
        assert_eq!(ControlPacket::decode(None, &plain).unwrap().0, original);

        let key: Vec<u8> = (0..=255).collect();
        let client = TlsCrypt::new(&key, true).unwrap();
        let server = TlsCrypt::new(&key, false).unwrap();
        let encrypted = original.encode(Some(&client), 77, 1_714_567_890).unwrap();
        let (decoded, packet_id, unix_time) =
            ControlPacket::decode(Some(&server), &encrypted).unwrap();
        assert_eq!(decoded, original);
        assert_eq!((packet_id, unix_time), (77, 1_714_567_890));
    }
}
