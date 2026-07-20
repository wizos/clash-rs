use std::io;

use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use rand::RngExt;
use sha1::Sha1;

use super::{
    config::{Auth, Cipher, Proto},
    packet::SessionId,
};

const PRE_MASTER_SIZE: usize = 48;
const RANDOM_SIZE: usize = 32;
const MAX_CIPHER_KEY_LENGTH: usize = 64;
const MAX_HMAC_KEY_LENGTH: usize = 64;
const KEY_BLOCK_SIZE: usize = 2 * (MAX_CIPHER_KEY_LENGTH + MAX_HMAC_KEY_LENGTH);

#[derive(Clone)]
pub(super) struct KeySource {
    pub pre_master: [u8; PRE_MASTER_SIZE],
    pub random1: [u8; RANDOM_SIZE],
    pub random2: [u8; RANDOM_SIZE],
}

impl Default for KeySource {
    fn default() -> Self {
        Self {
            pre_master: [0; PRE_MASTER_SIZE],
            random1: [0; RANDOM_SIZE],
            random2: [0; RANDOM_SIZE],
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct KeySources {
    pub client: KeySource,
    pub server: KeySource,
}

pub(super) struct KeyMaterial {
    pub send_cipher_key: Vec<u8>,
    pub send_hmac_key: Vec<u8>,
    pub recv_cipher_key: Vec<u8>,
    pub recv_hmac_key: Vec<u8>,
}

pub(super) struct KeyMethod2Record {
    pub sources: KeySources,
    pub options: String,
    pub username: String,
    pub password: String,
    pub peer_info: String,
}

impl KeyMethod2Record {
    pub(super) fn new_client(
        proto: Proto,
        cipher: Cipher,
        auth: Auth,
        comp_lzo: bool,
        username: &str,
        password: &str,
    ) -> Self {
        let mut client = KeySource::default();
        let mut rng = rand::rng();
        rng.fill(&mut client.pre_master);
        rng.fill(&mut client.random1);
        rng.fill(&mut client.random2);
        Self {
            sources: KeySources {
                client,
                ..Default::default()
            },
            options: options_string(proto, cipher, auth, comp_lzo),
            username: username.to_owned(),
            password: password.to_owned(),
            peer_info: peer_info(cipher, comp_lzo),
        }
    }

    pub(super) fn marshal_client(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&0u32.to_be_bytes());
        output.push(2);
        output.extend_from_slice(&self.sources.client.pre_master);
        output.extend_from_slice(&self.sources.client.random1);
        output.extend_from_slice(&self.sources.client.random2);
        append_string(&mut output, &self.options);
        append_string(&mut output, &self.username);
        append_string(&mut output, &self.password);
        append_string(&mut output, &self.peer_info);
        output
    }

    pub(super) fn parse_server(packet: &[u8]) -> io::Result<Self> {
        if packet.len() < 5 + 2 * RANDOM_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "openvpn key method 2 packet too short",
            ));
        }
        if packet[..4] != [0; 4] || packet[4] & 0x0f != 2 {
            return Err(invalid("invalid openvpn key method 2 header"));
        }
        let mut offset = 5;
        let mut server = KeySource::default();
        server
            .random1
            .copy_from_slice(&packet[offset..offset + RANDOM_SIZE]);
        offset += RANDOM_SIZE;
        server
            .random2
            .copy_from_slice(&packet[offset..offset + RANDOM_SIZE]);
        offset += RANDOM_SIZE;
        let options = read_string(packet, &mut offset)?;
        let username = read_optional_string(packet, &mut offset);
        let password = read_optional_string(packet, &mut offset);
        let peer_info = read_optional_string(packet, &mut offset);
        Ok(Self {
            sources: KeySources {
                server,
                ..Default::default()
            },
            options,
            username,
            password,
            peer_info,
        })
    }

    #[cfg(test)]
    pub(super) fn new_server(options: &str) -> Self {
        let mut server = KeySource::default();
        let mut rng = rand::rng();
        rng.fill(&mut server.random1);
        rng.fill(&mut server.random2);
        Self {
            sources: KeySources {
                server,
                ..Default::default()
            },
            options: options.to_owned(),
            username: String::new(),
            password: String::new(),
            peer_info: "IV_VER=test-openvpn-server\n".to_owned(),
        }
    }

    #[cfg(test)]
    pub(super) fn marshal_server(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&0u32.to_be_bytes());
        output.push(2);
        output.extend_from_slice(&self.sources.server.random1);
        output.extend_from_slice(&self.sources.server.random2);
        append_string(&mut output, &self.options);
        append_string(&mut output, &self.username);
        append_string(&mut output, &self.password);
        append_string(&mut output, &self.peer_info);
        output
    }

    #[cfg(test)]
    pub(super) fn parse_client(packet: &[u8]) -> io::Result<Self> {
        if packet.len() < 5 + PRE_MASTER_SIZE + 2 * RANDOM_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "openvpn client key method 2 packet too short",
            ));
        }
        if packet[..4] != [0; 4] || packet[4] & 0x0f != 2 {
            return Err(invalid("invalid openvpn client key method 2 header"));
        }
        let mut offset = 5;
        let mut client = KeySource::default();
        client
            .pre_master
            .copy_from_slice(&packet[offset..offset + PRE_MASTER_SIZE]);
        offset += PRE_MASTER_SIZE;
        client
            .random1
            .copy_from_slice(&packet[offset..offset + RANDOM_SIZE]);
        offset += RANDOM_SIZE;
        client
            .random2
            .copy_from_slice(&packet[offset..offset + RANDOM_SIZE]);
        offset += RANDOM_SIZE;
        Ok(Self {
            sources: KeySources {
                client,
                ..Default::default()
            },
            options: read_string(packet, &mut offset)?,
            username: read_string(packet, &mut offset)?,
            password: read_string(packet, &mut offset)?,
            peer_info: read_string(packet, &mut offset)?,
        })
    }
}

pub(super) fn derive_client_key_material(
    sources: &KeySources,
    client_session: SessionId,
    server_session: SessionId,
    cipher_key_len: usize,
) -> io::Result<KeyMaterial> {
    if !matches!(cipher_key_len, 16 | 24 | 32) {
        return Err(invalid("unsupported openvpn data cipher key length"));
    }
    let master = prf(
        &sources.client.pre_master,
        b"OpenVPN master secret",
        &[&sources.client.random1, &sources.server.random1],
        48,
    );
    let key_block = prf(
        &master,
        b"OpenVPN key expansion",
        &[
            &sources.client.random2,
            &sources.server.random2,
            &client_session.0,
            &server_session.0,
        ],
        KEY_BLOCK_SIZE,
    );
    let split = MAX_CIPHER_KEY_LENGTH + MAX_HMAC_KEY_LENGTH;
    let (send, recv) = key_block.split_at(split);
    Ok(KeyMaterial {
        send_cipher_key: send[..cipher_key_len].to_vec(),
        send_hmac_key: send[MAX_CIPHER_KEY_LENGTH..split].to_vec(),
        recv_cipher_key: recv[..cipher_key_len].to_vec(),
        recv_hmac_key: recv[MAX_CIPHER_KEY_LENGTH..split].to_vec(),
    })
}

fn prf(secret: &[u8], label: &[u8], seeds: &[&[u8]], size: usize) -> Vec<u8> {
    let mut seed = Vec::new();
    seed.extend_from_slice(label);
    for part in seeds {
        seed.extend_from_slice(part);
    }
    let split = secret.len().div_ceil(2);
    let md5_output = p_hash(&secret[..split], &seed, size, hmac_md5);
    let sha1_output =
        p_hash(&secret[secret.len() - split..], &seed, size, hmac_sha1);
    md5_output
        .into_iter()
        .zip(sha1_output)
        .map(|(left, right)| left ^ right)
        .collect()
}

fn p_hash(
    secret: &[u8],
    seed: &[u8],
    size: usize,
    hmac: fn(&[u8], &[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(size);
    let mut a = hmac(secret, seed);
    while output.len() < size {
        let mut input = a.clone();
        input.extend_from_slice(seed);
        output.extend_from_slice(&hmac(secret, &input));
        a = hmac(secret, &a);
    }
    output.truncate(size);
    output
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        Hmac::<Md5>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn options_string(
    proto: Proto,
    cipher: Cipher,
    auth: Auth,
    comp_lzo: bool,
) -> String {
    let proto = if proto == Proto::Tcp {
        "TCPv4_CLIENT"
    } else {
        "UDPv4"
    };
    let key_size = cipher.key_len() * 8;
    let (link_mtu, comp) = if comp_lzo {
        (1544, "comp-lzo,")
    } else {
        (1550, "")
    };
    format!(
        "V4,dev-type tun,link-mtu {link_mtu},tun-mtu 1500,proto \
         {proto},{comp}cipher {},auth {},keysize {key_size},key-method 2,tls-client",
        cipher.name(),
        auth.name(),
    )
}

fn peer_info(cipher: Cipher, comp_lzo: bool) -> String {
    format!(
        "IV_VER=mihomo-openvpn\nIV_PROTO=6\n{}IV_CIPHERS={}\n",
        if comp_lzo { "IV_LZO=1\n" } else { "" },
        cipher.name(),
    )
}

fn append_string(output: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        output.extend_from_slice(&0u16.to_be_bytes());
        return;
    }
    let length = bytes.len().min(u16::MAX as usize - 1);
    output.extend_from_slice(&((length + 1) as u16).to_be_bytes());
    output.extend_from_slice(&bytes[..length]);
    output.push(0);
}

fn read_string(packet: &[u8], offset: &mut usize) -> io::Result<String> {
    if packet.len() < *offset + 2 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "openvpn string truncated",
        ));
    }
    let length = u16::from_be_bytes(packet[*offset..*offset + 2].try_into().unwrap())
        as usize;
    *offset += 2;
    if packet.len() < *offset + length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "openvpn string truncated",
        ));
    }
    let mut bytes = &packet[*offset..*offset + length];
    *offset += length;
    if bytes.last() == Some(&0) {
        bytes = &bytes[..bytes.len() - 1];
    }
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn read_optional_string(packet: &[u8], offset: &mut usize) -> String {
    read_string(packet, offset).unwrap_or_default()
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::{KeyMethod2Record, derive_client_key_material};
    use crate::proxy::openvpn::{
        config::{Auth, Cipher, Proto},
        packet::SessionId,
    };

    #[test]
    fn client_record_and_key_material_are_well_formed() {
        let record = KeyMethod2Record::new_client(
            Proto::Udp,
            Cipher::Aes256Gcm,
            Auth::Sha256,
            false,
            "user",
            "password",
        );
        let encoded = record.marshal_client();
        assert_eq!(&encoded[..5], &[0, 0, 0, 0, 2]);
        let material = derive_client_key_material(
            &record.sources,
            SessionId(*b"client01"),
            SessionId(*b"server01"),
            32,
        )
        .unwrap();
        assert_eq!(material.send_cipher_key.len(), 32);
        assert_eq!(material.send_hmac_key.len(), 64);
        assert_eq!(material.recv_cipher_key.len(), 32);
        assert_eq!(material.recv_hmac_key.len(), 64);
    }
}
