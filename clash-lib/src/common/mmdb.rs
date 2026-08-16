use super::http::HttpClient;
use crate::{
    Error,
    common::{
        errors::{map_io_error, new_io_error},
        utils::download,
    },
};
use maxminddb::geoip2;
use serde::Deserialize;
use std::{
    fs,
    net::IpAddr,
    path::Path,
    sync::{Arc, LazyLock, OnceLock, RwLock},
};
use tracing::{debug, info, warn};

pub static DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL: &str =
    "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb";
pub static DEFAULT_ASN_MMDB_DOWNLOAD_URL: &str = "https://git.io/GeoLite2-ASN.mmdb";

pub struct Mmdb {
    path: std::path::PathBuf,
    reader: OnceLock<MmdbReader>,
}

#[cfg(not(target_os = "windows"))]
type MmdbReader = maxminddb::Reader<maxminddb::Mmap>;
#[cfg(target_os = "windows")]
type MmdbReader = maxminddb::Reader<Vec<u8>>;

pub type MmdbLookup = Arc<dyn MmdbLookupTrait + Send + Sync>;

// ponytail: one active runtime per process; move ownership into a runtime
// controller if concurrent runtimes become supported.
static ACTIVE_COUNTRY_MMDB: LazyLock<RwLock<Option<MmdbLookup>>> =
    LazyLock::new(|| RwLock::new(None));

pub(crate) fn set_active_country_mmdb(mmdb: Option<MmdbLookup>) {
    *ACTIVE_COUNTRY_MMDB
        .write()
        .expect("active country MMDB lock poisoned") = mmdb;
}

pub(crate) fn active_country_code(ip: IpAddr) -> Option<String> {
    let mmdb = ACTIVE_COUNTRY_MMDB
        .read()
        .expect("active country MMDB lock poisoned")
        .clone()?;
    mmdb.lookup_country(ip)
        .ok()
        .map(|country| country.country_code)
}

// mockall can't seem to mock the return value mmdb::Country<'a> with lifetime
// issue
#[derive(Debug)]
pub struct MmdbLookupCountry {
    pub country_code: String,
}

#[derive(Debug)]
pub struct MmdbLookupAsn {
    pub asn_number: u32,
    pub asn_name: String,
}

#[cfg_attr(test, mockall::automock)]
pub trait MmdbLookupTrait {
    fn lookup_country(&self, ip: IpAddr) -> std::io::Result<MmdbLookupCountry>;
    fn matches_geoip(&self, ip: IpAddr, code: &str) -> std::io::Result<bool> {
        self.lookup_country(ip)
            .map(|country| country.country_code.eq_ignore_ascii_case(code))
    }
    fn lookup_asn(&self, ip: IpAddr) -> std::io::Result<MmdbLookupAsn>;
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MetaGeoIpRecord {
    Code(String),
    Codes(Vec<String>),
}

impl MetaGeoIpRecord {
    fn into_codes(self) -> Vec<String> {
        match self {
            Self::Code(code) => vec![code],
            Self::Codes(codes) => codes,
        }
    }
}

impl MmdbLookupTrait for Mmdb {
    fn lookup_country(&self, ip: IpAddr) -> std::io::Result<MmdbLookupCountry> {
        let country_code = self
            .lookup_geoip_codes(ip)?
            .into_iter()
            .rev()
            .find(|code| {
                code.len() == 2
                    && code.bytes().all(|byte| byte.is_ascii_alphabetic())
            })
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "country not found",
                )
            })?;
        Ok(MmdbLookupCountry {
            country_code: country_code.to_ascii_uppercase(),
        })
    }

    fn matches_geoip(&self, ip: IpAddr, code: &str) -> std::io::Result<bool> {
        self.lookup_geoip_codes(ip).map(|codes| {
            codes
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(code))
        })
    }

    fn lookup_asn(&self, ip: IpAddr) -> std::io::Result<MmdbLookupAsn> {
        match self
            .reader()?
            .lookup(ip)
            .map_err(map_io_error)?
            .decode::<geoip2::Asn>()
        {
            Err(err) => Err(new_io_error(err)),
            Ok(Some(asn)) => Ok(MmdbLookupAsn {
                asn_number: asn.autonomous_system_number.unwrap_or(0),
                asn_name: asn
                    .autonomous_system_organization
                    .unwrap_or_default()
                    .to_string(),
            }),
            Ok(None) => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "asn not found",
            )),
        }
    }
}

impl Mmdb {
    pub async fn new<P: AsRef<Path>>(
        path: P,
        download_url: String,
        http_client: HttpClient,
    ) -> Result<Mmdb, Error> {
        debug!("mmdb path: {}", path.as_ref().to_string_lossy());
        let path = Self::prepare_mmdb(path, download_url, &http_client).await?;
        Ok(Self {
            path,
            reader: OnceLock::new(),
        })
    }

    async fn prepare_mmdb<P: AsRef<Path>>(
        path: P,
        download_url: String,
        http_client: &HttpClient,
    ) -> Result<std::path::PathBuf, Error> {
        let mmdb_file = path.as_ref().to_path_buf();

        if !mmdb_file.exists() || download_url.contains("force=true") {
            info!("downloading mmdb from {}", download_url);
            download(&download_url, &mmdb_file, http_client)
                .await
                .map_err(|x| {
                    Error::InvalidConfig(format!("mmdb download failed: {x}"))
                })?;
        }

        match open_mmap(&path) {
            Ok(_) => Ok(mmdb_file),
            Err(e) => {
                warn!(
                    "invalid mmdb `{}`: {}, trying to download again",
                    path.as_ref().to_string_lossy(),
                    e.to_string()
                );

                // try to download again; ignore ENOENT — another concurrent
                // caller may have already removed the file
                let _ = fs::remove_file(&mmdb_file);

                info!(
                    "mmdb {:?} corrupt, re-downloading mmdb from {download_url}",
                    mmdb_file.file_name()
                );
                download(&download_url, &mmdb_file, http_client)
                    .await
                    .map_err(|x| {
                        Error::InvalidConfig(format!("mmdb download failed: {x}"))
                    })?;
                open_mmap(&path).map_err(|x| {
                    Error::InvalidConfig(format!(
                        "cant open mmdb `{}`: {}",
                        path.as_ref().to_string_lossy(),
                        x
                    ))
                })?;
                Ok(mmdb_file)
            }
        }
    }

    fn reader(&self) -> std::io::Result<&MmdbReader> {
        if let Some(reader) = self.reader.get() {
            return Ok(reader);
        }
        let reader = open_mmap(&self.path).map_err(new_io_error)?;
        let _ = self.reader.set(reader);
        Ok(self
            .reader
            .get()
            .expect("MMDB reader was initialized by this call or a concurrent call"))
    }

    fn lookup_geoip_codes(&self, ip: IpAddr) -> std::io::Result<Vec<String>> {
        let reader = self.reader()?;
        let lookup = reader.lookup(ip).map_err(map_io_error)?;
        let codes = match reader.metadata().database_type.as_str() {
            "sing-geoip" => lookup
                .decode::<String>()
                .map_err(new_io_error)?
                .into_iter()
                .collect(),
            "Meta-geoip0" => lookup
                .decode::<MetaGeoIpRecord>()
                .map_err(new_io_error)?
                .map(MetaGeoIpRecord::into_codes)
                .unwrap_or_default(),
            _ => lookup
                .decode::<geoip2::Country>()
                .map_err(new_io_error)?
                .and_then(|country| country.country.iso_code.map(str::to_owned))
                .into_iter()
                .collect(),
        };
        if codes.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "geoip code not found",
            ))
        } else {
            Ok(codes)
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn open_mmap<P: AsRef<Path>>(
    path: P,
) -> Result<MmdbReader, maxminddb::MaxMindDbError> {
    // SAFETY: the runtime update path publishes MMDB files by replacement and
    // keeps the mapped generation immutable for the lifetime of this reader.
    unsafe { maxminddb::Reader::open_mmap(path) }
}

#[cfg(target_os = "windows")]
fn open_mmap<P: AsRef<Path>>(
    path: P,
) -> Result<MmdbReader, maxminddb::MaxMindDbError> {
    // The shared downloader may replace an existing file by copying on
    // Windows. Keep a private heap reader there until immutable generation
    // files are available; mapping a file that can be modified is unsound.
    maxminddb::Reader::open_readfile(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_fixture(path: impl AsRef<Path>) -> Mmdb {
        Mmdb {
            path: path.as_ref().to_path_buf(),
            reader: OnceLock::new(),
        }
    }

    #[test]
    fn meta_geoip_matches_country_and_category_codes() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../assets/data/GEOIP.metadb");
        assert!(path.exists(), "missing project GEOIP.metadb fixture");
        let mmdb = open_fixture(path);

        let github = "185.199.110.153".parse().unwrap();
        assert!(mmdb.matches_geoip(github, "US").unwrap());
        assert!(mmdb.matches_geoip(github, "FASTLY").unwrap());
        assert_eq!(mmdb.lookup_country(github).unwrap().country_code, "US");

        let scalar = "179.255.100.72".parse().unwrap();
        assert!(mmdb.matches_geoip(scalar, "BR").unwrap());
        assert_eq!(mmdb.lookup_country(scalar).unwrap().country_code, "BR");
    }

    #[test]
    fn standard_country_mmdb_still_matches_iso_code() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/Country.mmdb");
        let mmdb = open_fixture(path);
        let ip = "89.160.20.112".parse().unwrap();
        let country = mmdb.lookup_country(ip).unwrap();

        assert_eq!(country.country_code, "SE");
        assert!(mmdb.matches_geoip(ip, &country.country_code).unwrap());
    }
}
