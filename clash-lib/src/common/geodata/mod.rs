use super::{cidr_trie::CidrTrie, http::HttpClient};
use crate::{Error, common::utils::download};
use prost::Message;
use std::{
    collections::HashMap,
    io::{ErrorKind, Read, Seek, SeekFrom},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tracing::{debug, info, warn};

pub static DEFAULT_GEOIP_DOWNLOAD_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat";
pub static DEFAULT_GEOSITE_DOWNLOAD_URL: &str = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202406182210/geosite.dat";

#[allow(dead_code)]
pub(crate) mod geodata_proto {
    include!(concat!(env!("OUT_DIR"), "/geodata.rs"));
}

pub struct GeoData {
    geosite_path: Option<PathBuf>,
    geoip_path: Option<PathBuf>,
    ip_cache: Mutex<HashMap<String, Arc<CidrTrie>>>,
}

pub type GeoDataLookup = std::sync::Arc<dyn GeoDataLookupTrait + Send + Sync>;

#[cfg_attr(test, mockall::automock)]
pub trait GeoDataLookupTrait {
    fn get(&self, list: &str) -> Option<geodata_proto::GeoSite>;

    fn has_geoip(&self) -> bool {
        false
    }

    fn get_ip(&self, _country: &str) -> Option<Arc<CidrTrie>> {
        None
    }
}

impl GeoDataLookupTrait for GeoData {
    fn get(&self, list: &str) -> Option<geodata_proto::GeoSite> {
        let path = self.geosite_path.as_ref()?;
        match load_site(path, list) {
            Ok(Some(site)) => Some(site),
            Ok(None) => None,
            Err(error) => {
                warn!("failed to load geosite list {list}: {error}");
                None
            }
        }
    }

    fn has_geoip(&self) -> bool {
        self.geoip_path.is_some()
    }

    fn get_ip(&self, country: &str) -> Option<Arc<CidrTrie>> {
        let path = self.geoip_path.as_ref()?;
        let key = country.to_ascii_lowercase();
        let mut cache = self
            .ip_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(matcher) = cache.get(&key) {
            return Some(matcher.clone());
        }

        match load_ip(path, country) {
            Ok(Some(matcher)) => {
                let matcher = Arc::new(matcher);
                cache.insert(key, matcher.clone());
                Some(matcher)
            }
            Ok(None) => None,
            Err(error) => {
                warn!("failed to load geoip country {country}: {error}");
                None
            }
        }
    }
}

impl GeoData {
    pub async fn new(
        geosite: Option<(PathBuf, String)>,
        geoip: Option<(PathBuf, String)>,
        http_client: HttpClient,
    ) -> Result<Self, Error> {
        let geosite_path =
            prepare_resource("geosite", geosite, &http_client).await?;
        let geoip_path = prepare_resource("geoip", geoip, &http_client).await?;
        Ok(Self {
            geosite_path,
            geoip_path,
            ip_cache: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    pub async fn from_files(
        geosite_path: Option<PathBuf>,
        geoip_path: Option<PathBuf>,
    ) -> Result<Self, Error> {
        for path in [&geosite_path, &geoip_path].into_iter().flatten() {
            std::fs::File::open(path)?;
        }
        Ok(Self {
            geosite_path,
            geoip_path,
            ip_cache: Mutex::new(HashMap::new()),
        })
    }
}

async fn prepare_resource(
    kind: &str,
    resource: Option<(PathBuf, String)>,
    http_client: &HttpClient,
) -> Result<Option<PathBuf>, Error> {
    let Some((path, download_url)) = resource else {
        return Ok(None);
    };
    debug!("{kind} path: {}", path.to_string_lossy());
    if !path.exists() || download_url.contains("force=true") {
        info!("downloading {kind} from {download_url}");
        download(&download_url, &path, http_client)
            .await
            .map_err(|error| {
                Error::InvalidConfig(format!("{kind} download failed: {error}"))
            })?;
    }
    std::fs::File::open(&path)?;
    Ok(Some(path))
}

fn load_site(
    path: &Path,
    list: &str,
) -> Result<Option<geodata_proto::GeoSite>, Error> {
    let Some(bytes) = load_entry(path, list, "geosite")? else {
        return Ok(None);
    };
    geodata_proto::GeoSite::decode(bytes.as_slice())
        .map(Some)
        .map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to decode geosite list {list}: {error}"
            ))
        })
}

fn load_ip(path: &Path, country: &str) -> Result<Option<CidrTrie>, Error> {
    let Some(bytes) = load_entry(path, country, "geoip")? else {
        return Ok(None);
    };
    let entry = geodata_proto::GeoIp::decode(bytes.as_slice()).map_err(|error| {
        Error::InvalidConfig(format!(
            "failed to decode geoip country {country}: {error}"
        ))
    })?;
    let mut matcher = CidrTrie::new();
    for cidr in entry.cidr {
        let ip = match cidr.ip.as_slice() {
            [a, b, c, d] => IpAddr::from([*a, *b, *c, *d]),
            bytes if bytes.len() == 16 => {
                IpAddr::from(<[u8; 16]>::try_from(bytes).expect("length checked"))
            }
            _ => {
                return Err(Error::InvalidConfig(format!(
                    "invalid geoip address length for {country}"
                )));
            }
        };
        let prefix = u8::try_from(cidr.prefix).map_err(|_| {
            Error::InvalidConfig(format!(
                "invalid geoip prefix {} for {country}",
                cidr.prefix
            ))
        })?;
        if !matcher.insert_ip(ip, prefix) {
            return Err(Error::InvalidConfig(format!(
                "invalid geoip prefix {prefix} for {country}"
            )));
        }
    }
    Ok(Some(matcher))
}

fn load_entry(
    path: &Path,
    list: &str,
    kind: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let mut file = std::fs::File::open(path)?;
    let file_length = file.metadata()?.len();
    // ponytail: uncached lists scan the file once; add an offset index only if
    // startup profiling shows the cached O(n) lookup is material.
    while let Some(key) = read_varint(&mut file)? {
        if key != 0x0a {
            return Err(Error::InvalidConfig(format!(
                "invalid {kind} entry key: {key}"
            )));
        }

        let length = read_varint(&mut file)?.ok_or_else(|| {
            Error::InvalidConfig(format!("missing {kind} entry length"))
        })?;
        let entry_start = file.stream_position()?;
        let entry_end = entry_start.checked_add(length).ok_or_else(|| {
            Error::InvalidConfig(format!("{kind} entry length overflow"))
        })?;
        if entry_end > file_length {
            return Err(Error::InvalidConfig(format!(
                "{kind} entry exceeds file length"
            )));
        }

        // Mihomo's memconservative loader likewise relies on country_code being
        // the first field emitted for each GeoIP or GeoSite message.
        let country_key = read_varint(&mut file)?.ok_or_else(|| {
            Error::InvalidConfig(format!("missing {kind} country code"))
        })?;
        if country_key != 0x0a {
            return Err(Error::InvalidConfig(format!(
                "invalid {kind} country key: {country_key}"
            )));
        }
        let country_length = read_varint(&mut file)?.ok_or_else(|| {
            Error::InvalidConfig(format!("missing {kind} country length"))
        })?;
        let country_start = file.stream_position()?;
        if country_length > entry_end.saturating_sub(country_start) {
            return Err(Error::InvalidConfig(format!(
                "{kind} country code exceeds entry length"
            )));
        }
        let country_length = usize::try_from(country_length).map_err(|_| {
            Error::InvalidConfig(format!("{kind} country length overflow"))
        })?;
        let mut country = vec![0; country_length];
        file.read_exact(&mut country)?;

        if country.eq_ignore_ascii_case(list.as_bytes()) {
            file.seek(SeekFrom::Start(entry_start))?;
            let length = usize::try_from(length).map_err(|_| {
                Error::InvalidConfig(format!("{kind} entry is too large"))
            })?;
            let mut bytes = vec![0; length];
            file.read_exact(&mut bytes)?;
            return Ok(Some(bytes));
        }

        file.seek(SeekFrom::Start(entry_end))?;
    }

    Ok(None)
}

fn read_varint(reader: &mut impl Read) -> std::io::Result<Option<u64>> {
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let mut byte = [0u8; 1];
        if let Err(error) = reader.read_exact(&mut byte) {
            if error.kind() == ErrorKind::UnexpectedEof && shift == 0 {
                return Ok(None);
            }
            return Err(error);
        }
        if shift == 63 && byte[0] > 1 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "protobuf varint overflow",
            ));
        }
        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(Some(value));
        }
    }

    Err(std::io::Error::new(
        ErrorKind::InvalidData,
        "unterminated protobuf varint",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loads_only_requested_site_without_retaining_raw_protobuf() {
        let site = geodata_proto::GeoSite {
            country_code: "CN".to_owned(),
            domain: vec![geodata_proto::Domain {
                r#type: geodata_proto::domain::Type::Full.into(),
                value: "example.cn".to_owned(),
                attribute: vec![],
            }],
        };
        let mut bytes = geodata_proto::GeoSiteList {
            entry: vec![site.clone()],
        }
        .encode_to_vec();
        bytes.extend_from_slice(&[0x0a, 0x02, 0xff, 0xff]);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("geosite.dat");
        std::fs::write(&path, bytes).unwrap();
        let loader = GeoData::from_files(Some(path.clone()), None).await.unwrap();

        assert_eq!(loader.get("cn"), Some(site.clone()));
        std::fs::remove_file(path).unwrap();
        assert_eq!(loader.get("CN"), None);
    }

    #[tokio::test]
    async fn loads_only_requested_geoip_country_and_caches_it() {
        let country = geodata_proto::GeoIp {
            country_code: "CN".to_owned(),
            cidr: vec![
                geodata_proto::Cidr {
                    ip: vec![1, 2, 3, 0],
                    prefix: 24,
                },
                geodata_proto::Cidr {
                    ip: "2001:db8::"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                    prefix: 32,
                },
            ],
            reverse_match: false,
        };
        let mut bytes = geodata_proto::GeoIpList {
            entry: vec![country],
        }
        .encode_to_vec();
        bytes.extend_from_slice(&[0x0a, 0x02, 0xff, 0xff]);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("geoip.dat");
        std::fs::write(&path, bytes).unwrap();
        let loader = GeoData::from_files(None, Some(path.clone())).await.unwrap();

        let matcher = loader.get_ip("cn").unwrap();
        assert!(matcher.contains("1.2.3.4".parse().unwrap()));
        assert!(matcher.contains("2001:db8::1".parse().unwrap()));
        assert!(!matcher.contains("8.8.8.8".parse().unwrap()));
        std::fs::remove_file(path).unwrap();
        assert!(
            loader
                .get_ip("CN")
                .unwrap()
                .contains("1.2.3.4".parse().unwrap())
        );
    }
}
