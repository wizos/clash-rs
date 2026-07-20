use std::io;

use aes::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7,
};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, AesGcm, KeyInit,
    aead::{Aead, Payload, consts::U12},
};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::RngExt;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use super::{
    config::{Auth, Cipher},
    key_method::KeyMaterial,
    packet::{data_header, data_header_size},
};

type Aes192Gcm = AesGcm<aes::Aes192, U12>;

const TAG_SIZE: usize = 16;
const IV_SIZE: usize = 12;
const CBC_IV_SIZE: usize = 16;
const REPLAY_WINDOW: u32 = 64;

enum AeadCipher {
    Aes128(Aes128Gcm),
    Aes192(Aes192Gcm),
    Aes256(Aes256Gcm),
    Chacha(ChaCha20Poly1305),
}

impl AeadCipher {
    fn new(cipher: Cipher, key: &[u8]) -> io::Result<Self> {
        match cipher {
            Cipher::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map(Self::Aes128)
                .map_err(|_| invalid("invalid AES-128-GCM key")),
            Cipher::Aes192Gcm => Aes192Gcm::new_from_slice(key)
                .map(Self::Aes192)
                .map_err(|_| invalid("invalid AES-192-GCM key")),
            Cipher::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map(Self::Aes256)
                .map_err(|_| invalid("invalid AES-256-GCM key")),
            Cipher::Chacha20Poly1305 => {
                <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new_from_slice(key)
                    .map(Self::Chacha)
                    .map_err(|_| invalid("invalid ChaCha20-Poly1305 key"))
            }
            _ => Err(invalid("openvpn CBC cipher used as AEAD")),
        }
    }

    fn encrypt(
        &self,
        nonce: &[u8; IV_SIZE],
        plain: &[u8],
        ad: &[u8],
    ) -> io::Result<Vec<u8>> {
        let payload = Payload {
            msg: plain,
            aad: ad,
        };
        match self {
            Self::Aes128(cipher) => cipher.encrypt(nonce.into(), payload),
            Self::Aes192(cipher) => cipher.encrypt(nonce.into(), payload),
            Self::Aes256(cipher) => cipher.encrypt(nonce.into(), payload),
            Self::Chacha(cipher) => {
                return chacha20poly1305::aead::Aead::encrypt(
                    cipher,
                    nonce.into(),
                    chacha20poly1305::aead::Payload {
                        msg: plain,
                        aad: ad,
                    },
                )
                .map_err(|_| invalid("openvpn AEAD encryption failed"));
            }
        }
        .map_err(|_| invalid("openvpn AEAD encryption failed"))
    }

    fn decrypt(
        &self,
        nonce: &[u8; IV_SIZE],
        sealed: &[u8],
        ad: &[u8],
    ) -> io::Result<Vec<u8>> {
        let payload = Payload {
            msg: sealed,
            aad: ad,
        };
        match self {
            Self::Aes128(cipher) => cipher.decrypt(nonce.into(), payload),
            Self::Aes192(cipher) => cipher.decrypt(nonce.into(), payload),
            Self::Aes256(cipher) => cipher.decrypt(nonce.into(), payload),
            Self::Chacha(cipher) => {
                return chacha20poly1305::aead::Aead::decrypt(
                    cipher,
                    nonce.into(),
                    chacha20poly1305::aead::Payload {
                        msg: sealed,
                        aad: ad,
                    },
                )
                .map_err(|_| invalid("openvpn AEAD authentication failed"));
            }
        }
        .map_err(|_| invalid("openvpn AEAD authentication failed"))
    }
}

pub(super) struct DataChannel {
    cipher: Cipher,
    auth: Auth,
    send_aead: Option<AeadCipher>,
    recv_aead: Option<AeadCipher>,
    send_cipher_key: Vec<u8>,
    recv_cipher_key: Vec<u8>,
    send_hmac_key: Vec<u8>,
    recv_hmac_key: Vec<u8>,
    send_implicit_iv: [u8; IV_SIZE],
    recv_implicit_iv: [u8; IV_SIZE],
    header: Vec<u8>,
    send_packet_id: u32,
    recv_highest: u32,
    recv_window: u64,
    recv_seen: bool,
}

impl DataChannel {
    pub(super) fn new(
        keys: KeyMaterial,
        cipher: Cipher,
        auth: Auth,
        peer_id: u32,
    ) -> io::Result<Self> {
        let (send_aead, recv_aead) = if cipher.is_aead() {
            (
                Some(AeadCipher::new(cipher, &keys.send_cipher_key)?),
                Some(AeadCipher::new(cipher, &keys.recv_cipher_key)?),
            )
        } else {
            (None, None)
        };
        if !cipher.is_aead()
            && (keys.send_hmac_key.len() < auth.tag_len()
                || keys.recv_hmac_key.len() < auth.tag_len())
        {
            return Err(invalid("openvpn HMAC key is too short"));
        }
        if cipher.is_aead()
            && (keys.send_hmac_key.len() < IV_SIZE - 4
                || keys.recv_hmac_key.len() < IV_SIZE - 4)
        {
            return Err(invalid("openvpn implicit IV key is too short"));
        }
        let mut send_implicit_iv = [0u8; IV_SIZE];
        let mut recv_implicit_iv = [0u8; IV_SIZE];
        send_implicit_iv[4..].copy_from_slice(&keys.send_hmac_key[..IV_SIZE - 4]);
        recv_implicit_iv[4..].copy_from_slice(&keys.recv_hmac_key[..IV_SIZE - 4]);
        Ok(Self {
            cipher,
            auth,
            send_aead,
            recv_aead,
            send_cipher_key: keys.send_cipher_key,
            recv_cipher_key: keys.recv_cipher_key,
            send_hmac_key: keys.send_hmac_key,
            recv_hmac_key: keys.recv_hmac_key,
            send_implicit_iv,
            recv_implicit_iv,
            header: data_header(peer_id, 0),
            send_packet_id: 0,
            recv_highest: 0,
            recv_window: 0,
            recv_seen: false,
        })
    }

    pub(super) fn encrypt(&mut self, packet: &[u8]) -> io::Result<Vec<u8>> {
        self.send_packet_id = self
            .send_packet_id
            .checked_add(1)
            .ok_or_else(|| invalid("openvpn data packet id exhausted"))?;
        if let Some(aead) = &self.send_aead {
            self.encrypt_aead(aead, packet)
        } else {
            self.encrypt_cbc(packet)
        }
    }

    pub(super) fn decrypt(&mut self, packet: &[u8]) -> io::Result<Vec<u8>> {
        let header_size = data_header_size(packet)?;
        if self.recv_aead.is_some() {
            self.decrypt_aead(packet, header_size)
        } else {
            self.decrypt_cbc(packet, header_size)
        }
    }

    fn encrypt_aead(&self, aead: &AeadCipher, packet: &[u8]) -> io::Result<Vec<u8>> {
        let packet_id = self.send_packet_id.to_be_bytes();
        let mut ad = self.header.clone();
        ad.extend_from_slice(&packet_id);
        let sealed = aead.encrypt(
            &nonce(self.send_packet_id, self.send_implicit_iv),
            packet,
            &ad,
        )?;
        let split = sealed.len() - TAG_SIZE;
        let mut output = ad;
        output.extend_from_slice(&sealed[split..]);
        output.extend_from_slice(&sealed[..split]);
        Ok(output)
    }

    fn decrypt_aead(
        &mut self,
        packet: &[u8],
        header_size: usize,
    ) -> io::Result<Vec<u8>> {
        if packet.len() < header_size + 4 + TAG_SIZE + 1 {
            return Err(invalid("openvpn AEAD data packet too short"));
        }
        let packet_id = u32::from_be_bytes(
            packet[header_size..header_size + 4].try_into().unwrap(),
        );
        let tag = &packet[header_size + 4..header_size + 4 + TAG_SIZE];
        let ciphertext = &packet[header_size + 4 + TAG_SIZE..];
        let mut sealed = Vec::with_capacity(ciphertext.len() + TAG_SIZE);
        sealed.extend_from_slice(ciphertext);
        sealed.extend_from_slice(tag);
        let plain = self
            .recv_aead
            .as_ref()
            .expect("selected AEAD mode")
            .decrypt(
                &nonce(packet_id, self.recv_implicit_iv),
                &sealed,
                &packet[..header_size + 4],
            )?;
        self.accept_packet_id(packet_id)?;
        Ok(plain)
    }

    fn encrypt_cbc(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        let mut plain = Vec::with_capacity(4 + packet.len());
        plain.extend_from_slice(&self.send_packet_id.to_be_bytes());
        plain.extend_from_slice(packet);
        let mut iv = [0u8; CBC_IV_SIZE];
        rand::rng().fill(&mut iv);
        let ciphertext =
            cbc_encrypt(self.cipher, &self.send_cipher_key, &iv, &plain)?;
        let mut authenticated = iv.to_vec();
        authenticated.extend_from_slice(&ciphertext);
        let tag = calculate_hmac(self.auth, &self.send_hmac_key, &authenticated);
        let mut output = self.header.clone();
        output.extend_from_slice(&tag);
        output.extend_from_slice(&authenticated);
        Ok(output)
    }

    fn decrypt_cbc(
        &mut self,
        packet: &[u8],
        header_size: usize,
    ) -> io::Result<Vec<u8>> {
        let tag_size = self.auth.tag_len();
        if packet.len() < header_size + tag_size + 2 * CBC_IV_SIZE {
            return Err(invalid("openvpn CBC data packet too short"));
        }
        let tag = &packet[header_size..header_size + tag_size];
        let authenticated = &packet[header_size + tag_size..];
        let expected = calculate_hmac(self.auth, &self.recv_hmac_key, authenticated);
        if !constant_time_eq(tag, &expected) {
            return Err(invalid("openvpn CBC HMAC authentication failed"));
        }
        let (iv, ciphertext) = authenticated.split_at(CBC_IV_SIZE);
        let plain = cbc_decrypt(self.cipher, &self.recv_cipher_key, iv, ciphertext)?;
        if plain.len() < 4 {
            return Err(invalid("openvpn CBC plaintext missing packet id"));
        }
        let packet_id = u32::from_be_bytes(plain[..4].try_into().unwrap());
        self.accept_packet_id(packet_id)?;
        Ok(plain[4..].to_vec())
    }

    fn accept_packet_id(&mut self, packet_id: u32) -> io::Result<()> {
        if !self.recv_seen {
            self.recv_highest = packet_id;
            self.recv_window = 1;
            self.recv_seen = true;
            return Ok(());
        }
        if packet_id > self.recv_highest {
            let shift = packet_id - self.recv_highest;
            self.recv_window = if shift >= REPLAY_WINDOW {
                1
            } else {
                self.recv_window << shift | 1
            };
            self.recv_highest = packet_id;
            return Ok(());
        }
        let difference = self.recv_highest - packet_id;
        if difference >= REPLAY_WINDOW
            || self.recv_window & (1u64 << difference) != 0
        {
            return Err(invalid(format!(
                "replayed openvpn data packet id {packet_id}"
            )));
        }
        self.recv_window |= 1u64 << difference;
        Ok(())
    }
}

fn nonce(packet_id: u32, mut implicit: [u8; IV_SIZE]) -> [u8; IV_SIZE] {
    let value = u32::from_be_bytes(implicit[..4].try_into().unwrap()) ^ packet_id;
    implicit[..4].copy_from_slice(&value.to_be_bytes());
    implicit
}

fn cbc_encrypt(
    cipher: Cipher,
    key: &[u8],
    iv: &[u8],
    plain: &[u8],
) -> io::Result<Vec<u8>> {
    macro_rules! encrypt {
        ($aes:ty, $message:literal) => {{
            let cipher = cbc::Encryptor::<$aes>::new_from_slices(key, iv)
                .map_err(|_| invalid($message))?;
            let mut output = vec![0u8; plain.len() + CBC_IV_SIZE];
            output[..plain.len()].copy_from_slice(plain);
            let length = cipher
                .encrypt_padded::<Pkcs7>(&mut output, plain.len())
                .map_err(|_| invalid("openvpn CBC padding failed"))?
                .len();
            output.truncate(length);
            Ok(output)
        }};
    }
    match cipher {
        Cipher::Aes128Cbc => encrypt!(aes::Aes128, "invalid AES-128-CBC key/iv"),
        Cipher::Aes192Cbc => encrypt!(aes::Aes192, "invalid AES-192-CBC key/iv"),
        Cipher::Aes256Cbc => encrypt!(aes::Aes256, "invalid AES-256-CBC key/iv"),
        _ => Err(invalid("openvpn AEAD cipher used as CBC")),
    }
}

fn cbc_decrypt(
    cipher: Cipher,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> io::Result<Vec<u8>> {
    macro_rules! decrypt {
        ($aes:ty, $message:literal) => {{
            let cipher = cbc::Decryptor::<$aes>::new_from_slices(key, iv)
                .map_err(|_| invalid($message))?;
            let mut output = ciphertext.to_vec();
            let length = cipher
                .decrypt_padded::<Pkcs7>(&mut output)
                .map_err(|_| invalid("invalid openvpn CBC padding"))?
                .len();
            output.truncate(length);
            Ok(output)
        }};
    }
    match cipher {
        Cipher::Aes128Cbc => decrypt!(aes::Aes128, "invalid AES-128-CBC key/iv"),
        Cipher::Aes192Cbc => decrypt!(aes::Aes192, "invalid AES-192-CBC key/iv"),
        Cipher::Aes256Cbc => decrypt!(aes::Aes256, "invalid AES-256-CBC key/iv"),
        _ => Err(invalid("openvpn AEAD cipher used as CBC")),
    }
}

fn calculate_hmac(auth: Auth, key: &[u8], data: &[u8]) -> Vec<u8> {
    macro_rules! calculate {
        ($digest:ty) => {{
            let mut mac = Hmac::<$digest>::new_from_slice(key)
                .expect("HMAC accepts any key size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match auth {
        Auth::Md5 => calculate!(Md5),
        Auth::Sha1 => calculate!(Sha1),
        Auth::Sha256 => calculate!(Sha256),
        Auth::Sha384 => calculate!(Sha384),
        Auth::Sha512 => calculate!(Sha512),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::DataChannel;
    use crate::proxy::openvpn::{
        config::{Auth, Cipher},
        key_method::KeyMaterial,
        packet::PEER_ID_UNSET,
    };

    fn channels(cipher: Cipher, auth: Auth) -> (DataChannel, DataChannel) {
        let key_len = cipher.key_len();
        let client_send = vec![0x11; key_len];
        let server_send = vec![0x22; key_len];
        let client_hmac = vec![0x33; 64];
        let server_hmac = vec![0x44; 64];
        let client = DataChannel::new(
            KeyMaterial {
                send_cipher_key: client_send.clone(),
                send_hmac_key: client_hmac.clone(),
                recv_cipher_key: server_send.clone(),
                recv_hmac_key: server_hmac.clone(),
            },
            cipher,
            auth,
            PEER_ID_UNSET,
        )
        .unwrap();
        let server = DataChannel::new(
            KeyMaterial {
                send_cipher_key: server_send,
                send_hmac_key: server_hmac,
                recv_cipher_key: client_send,
                recv_hmac_key: client_hmac,
            },
            cipher,
            auth,
            PEER_ID_UNSET,
        )
        .unwrap();
        (client, server)
    }

    #[test]
    fn all_mihomo_data_ciphers_round_trip_and_reject_replay() {
        for cipher in [
            Cipher::Aes128Gcm,
            Cipher::Aes192Gcm,
            Cipher::Aes256Gcm,
            Cipher::Chacha20Poly1305,
            Cipher::Aes128Cbc,
            Cipher::Aes192Cbc,
            Cipher::Aes256Cbc,
        ] {
            let (mut client, mut server) = channels(cipher, Auth::Sha256);
            let packet = client.encrypt(b"openvpn IP packet").unwrap();
            assert_eq!(server.decrypt(&packet).unwrap(), b"openvpn IP packet");
            assert!(
                server.decrypt(&packet).is_err(),
                "replay accepted for {cipher:?}"
            );
        }
    }

    #[test]
    fn all_mihomo_cbc_auth_hashes_round_trip() {
        for auth in [
            Auth::Md5,
            Auth::Sha1,
            Auth::Sha256,
            Auth::Sha384,
            Auth::Sha512,
        ] {
            let (mut client, mut server) = channels(Cipher::Aes128Cbc, auth);
            let packet = client.encrypt(b"authenticated packet").unwrap();
            assert_eq!(server.decrypt(&packet).unwrap(), b"authenticated packet");
        }
    }
}
