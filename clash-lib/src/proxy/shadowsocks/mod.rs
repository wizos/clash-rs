use shadowsocks::crypto::CipherKind;
use std::io;

pub mod inbound;
pub mod outbound;
pub(crate) mod ssr_obfs;
pub(crate) mod ssr_protocol;

pub(crate) fn map_cipher(cipher: &str) -> std::io::Result<CipherKind> {
    match cipher {
        "2022-blake3-chacha20-ietf-poly1305" => {
            Ok(CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305)
        }
        _ => cipher.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported cipher `{cipher}`"),
            )
        }),
    }
}
