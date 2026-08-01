use super::http::HttpClient;
use crate::{Error, common::utils::download};
use prost::Message;
use std::{
    collections::HashMap,
    io::{ErrorKind, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Mutex,
};
use tracing::{debug, info, warn};

pub static DEFAULT_GEOSITE_DOWNLOAD_URL: &str = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202406182210/geosite.dat";

#[allow(dead_code)]
pub(crate) mod geodata_proto {
    include!(concat!(env!("OUT_DIR"), "/geodata.rs"));
}

pub struct GeoData {
    path: PathBuf,
    cache: Mutex<HashMap<String, geodata_proto::GeoSite>>,
}

pub type GeoDataLookup = std::sync::Arc<dyn GeoDataLookupTrait + Send + Sync>;

#[cfg_attr(test, mockall::automock)]
pub trait GeoDataLookupTrait {
    fn get(&self, list: &str) -> Option<geodata_proto::GeoSite>;
}

impl GeoDataLookupTrait for GeoData {
    fn get(&self, list: &str) -> Option<geodata_proto::GeoSite> {
        let key = list.to_ascii_lowercase();
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(site) = cache.get(&key) {
            return Some(site.clone());
        }

        match load_site(&self.path, list) {
            Ok(Some(site)) => {
                cache.insert(key, site.clone());
                Some(site)
            }
            Ok(None) => None,
            Err(error) => {
                warn!("failed to load geosite list {list}: {error}");
                None
            }
        }
    }
}

impl GeoData {
    pub async fn new<P: AsRef<Path>>(
        path: P,
        download_url: String,
        http_client: HttpClient,
    ) -> Result<Self, Error> {
        debug!("geosite path: {}", path.as_ref().to_string_lossy());

        let geosite_file = path.as_ref().to_path_buf();

        if !geosite_file.exists() || download_url.contains("force=true") {
            info!("downloading geodata from {}", download_url);
            download(&download_url, &geosite_file, &http_client)
                .await
                .map_err(|x| {
                    Error::InvalidConfig(format!("geosite download failed: {x}"))
                })?;
        }
        std::fs::File::open(&geosite_file)?;
        Ok(Self {
            path: geosite_file,
            cache: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        std::fs::File::open(&path)?;
        Ok(Self {
            path,
            cache: Mutex::new(HashMap::new()),
        })
    }
}

fn load_site(
    path: &Path,
    list: &str,
) -> Result<Option<geodata_proto::GeoSite>, Error> {
    let mut file = std::fs::File::open(path)?;
    let file_length = file.metadata()?.len();
    // ponytail: uncached lists scan the file once; add an offset index only if
    // startup profiling shows the cached O(n) lookup is material.
    while let Some(key) = read_varint(&mut file)? {
        if key != 0x0a {
            return Err(Error::InvalidConfig(format!(
                "invalid geosite entry key: {key}"
            )));
        }

        let length = read_varint(&mut file)?.ok_or_else(|| {
            Error::InvalidConfig("missing geosite entry length".to_owned())
        })?;
        let entry_start = file.stream_position()?;
        let entry_end = entry_start.checked_add(length).ok_or_else(|| {
            Error::InvalidConfig("geosite entry length overflow".to_owned())
        })?;
        if entry_end > file_length {
            return Err(Error::InvalidConfig(
                "geosite entry exceeds file length".to_owned(),
            ));
        }

        // Mihomo's memconservative loader likewise relies on country_code being
        // the first field emitted for each GeoSite message.
        let country_key = read_varint(&mut file)?.ok_or_else(|| {
            Error::InvalidConfig("missing geosite country code".to_owned())
        })?;
        if country_key != 0x0a {
            return Err(Error::InvalidConfig(format!(
                "invalid geosite country key: {country_key}"
            )));
        }
        let country_length = read_varint(&mut file)?.ok_or_else(|| {
            Error::InvalidConfig("missing geosite country length".to_owned())
        })?;
        let country_start = file.stream_position()?;
        if country_length > entry_end.saturating_sub(country_start) {
            return Err(Error::InvalidConfig(
                "geosite country code exceeds entry length".to_owned(),
            ));
        }
        let country_length = usize::try_from(country_length).map_err(|_| {
            Error::InvalidConfig("geosite country length overflow".to_owned())
        })?;
        let mut country = vec![0; country_length];
        file.read_exact(&mut country)?;

        if country.eq_ignore_ascii_case(list.as_bytes()) {
            file.seek(SeekFrom::Start(entry_start))?;
            let length = usize::try_from(length).map_err(|_| {
                Error::InvalidConfig("geosite entry is too large".to_owned())
            })?;
            let mut bytes = vec![0; length];
            file.read_exact(&mut bytes)?;
            return geodata_proto::GeoSite::decode(bytes.as_slice())
                .map(Some)
                .map_err(|error| {
                    Error::InvalidConfig(format!(
                        "failed to decode geosite list {list}: {error}"
                    ))
                });
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
    async fn loads_only_requested_site_and_caches_it() {
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
        let loader = GeoData::from_file(&path).await.unwrap();

        assert_eq!(loader.get("cn"), Some(site.clone()));
        std::fs::remove_file(path).unwrap();
        assert_eq!(loader.get("CN"), Some(site));
    }
}
