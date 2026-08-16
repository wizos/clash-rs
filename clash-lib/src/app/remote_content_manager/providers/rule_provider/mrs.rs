use anyhow::{Context, Result, bail};
use byteorder::{BigEndian, ReadBytesExt};
use std::{
    io::{BufReader, Cursor, Read},
    net::IpAddr,
};
use tracing::debug;

use crate::{
    app::remote_content_manager::providers::rule_provider::{
        RuleSetBehavior,
        provider::{IpCidrContent, RuleContent},
    },
    common::{ip_range_set::IpRangeSet, succinct_set::DomainSet},
};

// MRS Magic bytes for version 1
const MRS_MAGIC_BYTES: [u8; 4] = [b'M', b'R', b'S', 1]; // MRSv1

// MRS Payload Versions
const DOMAIN_SET_VERSION: u8 = 0x01;
const IP_CIDR_SET_VERSION: u8 = 0x01;

// Behavior byte values from spec
const BEHAVIOR_DOMAIN: u8 = 0x00;
const BEHAVIOR_IPCIDR: u8 = 0x01;

impl RuleSetBehavior {
    /// Convert behavior to byte representation used in MRS format
    pub fn to_mrs_byte(self) -> Option<u8> {
        match self {
            RuleSetBehavior::Domain => Some(BEHAVIOR_DOMAIN),
            RuleSetBehavior::Ipcidr => Some(BEHAVIOR_IPCIDR),
            RuleSetBehavior::Classical => None, // Classical is not supported by MRS
        }
    }

    /// Create behavior from MRS byte representation
    pub fn from_mrs_byte(b: u8) -> Result<Self> {
        match b {
            BEHAVIOR_DOMAIN => Ok(RuleSetBehavior::Domain),
            BEHAVIOR_IPCIDR => Ok(RuleSetBehavior::Ipcidr),
            _ => bail!("Invalid MRS behavior byte: {}", b),
        }
    }
}

/// Parses MRS format rule set according to the v1 specification.
pub fn rules_mrs_parse(
    buf: &[u8],
    expected_behavior: RuleSetBehavior,
) -> Result<RuleContent> {
    // 1. Decompress using Zstandard
    let cursor = Cursor::new(buf);
    let mut reader = BufReader::new(
        zstd::Decoder::new(cursor).context("Failed to create zstd decoder")?,
    );

    // --- Header Parsing ---
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .context("Failed to read MRS magic bytes")?;
    if magic != MRS_MAGIC_BYTES {
        bail!(
            "Invalid MRS magic bytes. Expected {:?} but got {:?}",
            MRS_MAGIC_BYTES,
            magic
        );
    }

    let behavior_byte = reader
        .read_u8()
        .context("Failed to read MRS behavior byte")?;
    let actual_behavior = RuleSetBehavior::from_mrs_byte(behavior_byte)?;

    if actual_behavior != expected_behavior {
        bail!(
            "MRS behavior mismatch: file contains {:?} but expected {:?}",
            actual_behavior,
            expected_behavior
        );
    }

    let count = reader
        .read_i64::<BigEndian>()
        .context("Failed to read MRS rule count")?;
    if count < 0 {
        bail!("Invalid MRS rule count: {}", count);
    }
    debug!("MRS rule count: {}", count);

    let extra_length = reader
        .read_i64::<BigEndian>()
        .context("Failed to read MRS extra length")?;
    if extra_length != 0 {
        bail!(
            "Invalid MRS extra length for v1: expected 0, got {}",
            extra_length
        );
    }

    // --- Payload Parsing ---
    match actual_behavior {
        RuleSetBehavior::Domain => parse_domain_payload(&mut reader),
        RuleSetBehavior::Ipcidr => parse_ipcidr_payload(&mut reader),
        RuleSetBehavior::Classical => {
            bail!("Classical behavior is not supported by MRS format")
        }
    }
}

// --- Domain Payload Parsing ---
fn parse_domain_payload<R: Read>(reader: &mut R) -> Result<RuleContent> {
    let version = reader
        .read_u8()
        .context("Failed to read DomainSet version")?;
    if version != DOMAIN_SET_VERSION {
        bail!(
            "Unsupported DomainSet version: expected {}, got {}",
            DOMAIN_SET_VERSION,
            version
        );
    }

    let leaves_len = read_u64_length(reader, "Leaves")?;
    let leaves = read_u64_vec(reader, leaves_len, "Leaves")?;

    let label_bitmap_len = read_u64_length(reader, "LabelBitmap")?;
    let label_bitmap = read_u64_vec(reader, label_bitmap_len, "LabelBitmap")?;

    let labels_len = read_u64_length(reader, "Labels")?;
    let labels = read_byte_vec(reader, labels_len, "Labels")?;

    let domain_set = DomainSet::from_mrs_parts(leaves, label_bitmap, labels);
    Ok(RuleContent::Domain(domain_set))
}

// --- IPCIDR Payload Parsing ---
fn parse_ipcidr_payload<R: Read>(reader: &mut R) -> Result<RuleContent> {
    let version = reader
        .read_u8()
        .context("Failed to read IpCidrSet version")?;
    if version != IP_CIDR_SET_VERSION {
        bail!(
            "Unsupported IpCidrSet version: expected {}, got {}",
            IP_CIDR_SET_VERSION,
            version
        );
    }

    let ranges_len = read_u64_length(reader, "Ranges")?;
    debug!("Expecting {} IP ranges", ranges_len);

    let mut ranges = IpRangeSet::default();

    for i in 0..ranges_len {
        let mut range_buf = [0u8; 32];
        reader
            .read_exact(&mut range_buf)
            .with_context(|| format!("Failed to read IP range #{i}"))?;

        let from_ip_bytes: [u8; 16] = range_buf[0..16].try_into().unwrap();
        let to_ip_bytes: [u8; 16] = range_buf[16..32].try_into().unwrap();
        let from_ip = IpAddr::from(from_ip_bytes);
        let to_ip = IpAddr::from(to_ip_bytes);

        if !ranges.insert(from_ip, to_ip) {
            bail!("Invalid IP range #{i}: {from_ip} - {to_ip}");
        }
    }

    ranges.finalize();
    debug!("Successfully parsed {ranges_len} IP ranges");
    Ok(RuleContent::Ipcidr(IpCidrContent::Ranges(ranges)))
}

// --- Helper Functions for Reading Data ---
fn read_u64_length<R: Read>(reader: &mut R, field_name: &str) -> Result<usize> {
    let len = reader
        .read_i64::<BigEndian>()
        .with_context(|| format!("Failed to read MRS {field_name} length"))?;
    if len < 0 {
        bail!("Invalid negative length for {}: {}", field_name, len);
    }
    Ok(len as usize)
}

fn read_u64_vec<R: Read>(
    reader: &mut R,
    count: usize,
    field_name: &str,
) -> Result<Vec<u64>> {
    let mut vec = Vec::with_capacity(count);
    for i in 0..count {
        let val = reader.read_u64::<BigEndian>().with_context(|| {
            format!("Failed to read {field_name} data element #{i}")
        })?;
        vec.push(val);
    }
    Ok(vec)
}

fn read_byte_vec<R: Read>(
    reader: &mut R,
    len: usize,
    field_name: &str,
) -> Result<Vec<u8>> {
    const MAX_BYTE_VEC_LEN: usize = 512 * 1024 * 1024; // 512 MiB limit
    if len > MAX_BYTE_VEC_LEN {
        bail!(
            "{} data length ({}) exceeds maximum allowed size ({})",
            field_name,
            len,
            MAX_BYTE_VEC_LEN
        );
    }
    let mut vec = vec![0u8; len];
    reader.read_exact(&mut vec).with_context(|| {
        format!("Failed to read {field_name} data ({len} bytes)")
    })?;
    Ok(vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;

    #[test]
    fn mrs_ipcidr_keeps_native_ranges() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&MRS_MAGIC_BYTES);
        payload.push(BEHAVIOR_IPCIDR);
        payload.write_i64::<BigEndian>(1).unwrap();
        payload.write_i64::<BigEndian>(0).unwrap();
        payload.push(IP_CIDR_SET_VERSION);
        payload.write_i64::<BigEndian>(1).unwrap();
        payload.extend_from_slice(
            &"::ffff:192.0.2.1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        payload.extend_from_slice(
            &"::ffff:192.0.2.9"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        let compressed = zstd::encode_all(payload.as_slice(), 1).unwrap();

        let parsed = rules_mrs_parse(&compressed, RuleSetBehavior::Ipcidr).unwrap();
        let RuleContent::Ipcidr(IpCidrContent::Ranges(ranges)) = parsed else {
            panic!("MRS IPCIDR must keep its range representation");
        };
        assert_eq!(ranges.len(), 1);
        assert!(ranges.contains("192.0.2.5".parse().unwrap()));
        assert!(!ranges.contains("192.0.2.10".parse().unwrap()));
    }
}
