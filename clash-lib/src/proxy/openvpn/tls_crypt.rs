use std::io;

use aes_vless::Aes256;
use ctr_vless::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type Aes256Ctr = ctr_vless::Ctr128BE<Aes256>;

pub(super) const HEADER_SIZE: usize = 9;
const PACKET_ID_SIZE: usize = 8;
const TAG_SIZE: usize = 32;

#[derive(Clone)]
pub(super) struct TlsCrypt {
    encrypt_cipher_key: [u8; 32],
    encrypt_hmac_key: [u8; 32],
    decrypt_cipher_key: [u8; 32],
    decrypt_hmac_key: [u8; 32],
}

impl TlsCrypt {
    pub(super) fn new(static_key: &[u8], client: bool) -> io::Result<Self> {
        if static_key.len() != 256 {
            return Err(invalid(format!(
                "invalid tls-crypt static key length {}, expected 256",
                static_key.len()
            )));
        }
        let (mut encrypt, mut decrypt) = static_key.split_at(128);
        if client {
            std::mem::swap(&mut encrypt, &mut decrypt);
        }
        Ok(Self {
            encrypt_cipher_key: encrypt[..32].try_into().expect("checked key slot"),
            encrypt_hmac_key: encrypt[64..96].try_into().expect("checked key slot"),
            decrypt_cipher_key: decrypt[..32].try_into().expect("checked key slot"),
            decrypt_hmac_key: decrypt[64..96].try_into().expect("checked key slot"),
        })
    }

    pub(super) fn wrap(
        &self,
        header: &[u8],
        packet_id: u32,
        unix_time: u32,
        plaintext: &[u8],
    ) -> io::Result<Vec<u8>> {
        if header.len() != HEADER_SIZE {
            return Err(invalid("invalid tls-crypt header length"));
        }
        let mut associated = Vec::with_capacity(HEADER_SIZE + PACKET_ID_SIZE);
        associated.extend_from_slice(header);
        associated.extend_from_slice(&packet_id.to_be_bytes());
        associated.extend_from_slice(&unix_time.to_be_bytes());
        let tag = hmac_sha256(&self.encrypt_hmac_key, &[&associated, plaintext]);
        let mut ciphertext = plaintext.to_vec();
        Aes256Ctr::new((&self.encrypt_cipher_key).into(), (&tag[..16]).into())
            .apply_keystream(&mut ciphertext);
        associated.extend_from_slice(&tag);
        associated.extend_from_slice(&ciphertext);
        Ok(associated)
    }

    pub(super) fn unwrap(
        &self,
        packet: &[u8],
    ) -> io::Result<(Vec<u8>, u32, u32, Vec<u8>)> {
        let associated_end = HEADER_SIZE + PACKET_ID_SIZE;
        let tag_end = associated_end + TAG_SIZE;
        if packet.len() < tag_end {
            return Err(invalid("tls-crypt packet too short"));
        }
        let tag = &packet[associated_end..tag_end];
        let mut plaintext = packet[tag_end..].to_vec();
        Aes256Ctr::new((&self.decrypt_cipher_key).into(), tag[..16].into())
            .apply_keystream(&mut plaintext);
        let expected = hmac_sha256(
            &self.decrypt_hmac_key,
            &[&packet[..associated_end], &plaintext],
        );
        if !constant_time_eq(tag, &expected) {
            return Err(invalid("tls-crypt authentication failed"));
        }
        Ok((
            packet[..HEADER_SIZE].to_vec(),
            u32::from_be_bytes(
                packet[HEADER_SIZE..HEADER_SIZE + 4].try_into().unwrap(),
            ),
            u32::from_be_bytes(
                packet[HEADER_SIZE + 4..associated_end].try_into().unwrap(),
            ),
            plaintext,
        ))
    }
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |diff, (left, right)| diff | (left ^ right))
            == 0
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::TlsCrypt;

    #[test]
    fn client_server_round_trip_and_tamper_rejection() {
        let key: Vec<u8> = (0..=255).collect();
        let client = TlsCrypt::new(&key, true).unwrap();
        let server = TlsCrypt::new(&key, false).unwrap();
        let header = [0x38, 1, 2, 3, 4, 5, 6, 7, 8];
        let packet = client
            .wrap(&header, 7, 1_714_567_890, b"openvpn control")
            .unwrap();
        let (decoded_header, packet_id, time, plaintext) =
            server.unwrap(&packet).unwrap();
        assert_eq!(decoded_header, header);
        assert_eq!(packet_id, 7);
        assert_eq!(time, 1_714_567_890);
        assert_eq!(plaintext, b"openvpn control");

        let mut tampered = packet;
        *tampered.last_mut().unwrap() ^= 0xff;
        assert!(server.unwrap(&tampered).is_err());
    }
}
