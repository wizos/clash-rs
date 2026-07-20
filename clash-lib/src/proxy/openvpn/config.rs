use std::{io, str::FromStr, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Proto {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cipher {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    Chacha20Poly1305,
}

impl Cipher {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Cbc => 16,
            Self::Aes192Gcm | Self::Aes192Cbc => 24,
            Self::Aes256Gcm | Self::Aes256Cbc | Self::Chacha20Poly1305 => 32,
        }
    }

    pub fn is_aead(self) -> bool {
        matches!(
            self,
            Self::Aes128Gcm
                | Self::Aes192Gcm
                | Self::Aes256Gcm
                | Self::Chacha20Poly1305
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes192Gcm => "AES-192-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Aes128Cbc => "AES-128-CBC",
            Self::Aes192Cbc => "AES-192-CBC",
            Self::Aes256Cbc => "AES-256-CBC",
            Self::Chacha20Poly1305 => "CHACHA20-POLY1305",
        }
    }
}

impl FromStr for Cipher {
    type Err = io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_uppercase().as_str() {
            "" | "AES-128-GCM" => Ok(Self::Aes128Gcm),
            "AES-192-GCM" => Ok(Self::Aes192Gcm),
            "AES-256-GCM" => Ok(Self::Aes256Gcm),
            "AES-CBC" | "AES-128-CBC" => Ok(Self::Aes128Cbc),
            "AES-192-CBC" => Ok(Self::Aes192Cbc),
            "AES-256-CBC" => Ok(Self::Aes256Cbc),
            "CHACHA20-POLY1305" => Ok(Self::Chacha20Poly1305),
            value => Err(invalid(format!("unsupported openvpn cipher `{value}`"))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Auth {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Auth {
    pub fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
        }
    }

    pub fn tag_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

impl FromStr for Auth {
    type Err = io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_uppercase().as_str() {
            "MD5" => Ok(Self::Md5),
            "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "" | "SHA256" => Ok(Self::Sha256),
            "SHA384" => Ok(Self::Sha384),
            "SHA512" => Ok(Self::Sha512),
            value => Err(invalid(format!("unsupported openvpn auth `{value}`"))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub remote_host: String,
    pub remote_port: u16,
    pub proto: Proto,
    pub cipher: Cipher,
    pub auth: Auth,
    pub comp_lzo: bool,
    pub ca: String,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub tls_crypt_key: Option<Vec<u8>>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ping_interval: Duration,
    pub ping_restart: Duration,
}

impl ClientConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        remote_host: String,
        remote_port: u16,
        proto: Option<&str>,
        dev: Option<&str>,
        cipher: Option<&str>,
        auth: Option<&str>,
        comp_lzo: Option<&str>,
        ca: String,
        cert: Option<String>,
        key: Option<String>,
        tls_crypt: Option<&str>,
        username: Option<String>,
        password: Option<String>,
        ping_interval: Duration,
        ping_restart: Duration,
    ) -> io::Result<Self> {
        if remote_host.trim().is_empty() || remote_port == 0 {
            return Err(invalid("openvpn config requires remote host and port"));
        }
        if !dev.unwrap_or("tun").trim().eq_ignore_ascii_case("tun") {
            return Err(invalid("openvpn only supports `dev: tun`"));
        }
        let proto = match proto.unwrap_or("udp").trim().to_ascii_lowercase().as_str()
        {
            "udp" | "udp4" => Proto::Udp,
            "tcp" | "tcp-client" | "tcp4" | "tcp4-client" => Proto::Tcp,
            value => {
                return Err(invalid(format!("unsupported openvpn proto `{value}`")));
            }
        };
        let cipher = cipher.unwrap_or_default().parse()?;
        let auth = auth.unwrap_or_default().parse()?;
        validate_certificate(&ca, "CA")?;
        let cert = cert.filter(|value| !value.trim().is_empty());
        let key = key.filter(|value| !value.trim().is_empty());
        match (&cert, &key) {
            (Some(cert), Some(key)) => {
                validate_certificate(cert, "client certificate")?;
                validate_private_key(key)?;
            }
            (None, None)
                if username.as_deref().unwrap_or_default().trim().is_empty() =>
            {
                return Err(invalid(
                    "openvpn requires either cert+key or username (auth-user-pass)",
                ));
            }
            (None, None) => {}
            _ => return Err(invalid("openvpn cert and key must both be set")),
        }
        let tls_crypt_key = tls_crypt
            .filter(|value| !value.trim().is_empty())
            .map(decode_static_key)
            .transpose()?;
        Ok(Self {
            remote_host: remote_host.trim().to_owned(),
            remote_port,
            proto,
            cipher,
            auth,
            comp_lzo: matches!(
                comp_lzo
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "yes" | "adaptive"
            ),
            ca,
            cert,
            key,
            tls_crypt_key,
            username,
            password,
            ping_interval,
            ping_restart,
        })
    }
}

fn validate_certificate(value: &str, name: &str) -> io::Result<()> {
    match rustls_pemfile::certs(&mut value.as_bytes()).next() {
        Some(Ok(_)) => Ok(()),
        Some(Err(error)) => {
            Err(invalid(format!("invalid openvpn {name} PEM: {error}")))
        }
        None => Err(invalid(format!("inline openvpn `{name}` is not PEM"))),
    }
}

fn validate_private_key(value: &str) -> io::Result<()> {
    match rustls_pemfile::private_key(&mut value.as_bytes()) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(invalid("inline openvpn client key is not PEM")),
        Err(error) => {
            Err(invalid(format!("invalid openvpn client key PEM: {error}")))
        }
    }
}

fn decode_static_key(value: &str) -> io::Result<Vec<u8>> {
    let encoded: String = value
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with('#') && !line.starts_with("-----")
        })
        .collect();
    let key = hex::decode(encoded)
        .map_err(|error| invalid(format!("parse tls-crypt key: {error}")))?;
    if key.len() != 256 {
        return Err(invalid(format!(
            "invalid tls-crypt key length {}, expected 256 bytes",
            key.len()
        )));
    }
    Ok(key)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::{Auth, Cipher, Proto};

    #[test]
    fn normalizes_mihomo_crypto_and_transport_aliases() {
        assert_eq!("".parse::<Cipher>().unwrap(), Cipher::Aes128Gcm);
        assert_eq!("AES-CBC".parse::<Cipher>().unwrap(), Cipher::Aes128Cbc);
        assert_eq!("sha-1".parse::<Auth>().unwrap(), Auth::Sha1);
        assert_eq!(Proto::Udp, Proto::Udp);
    }
}
