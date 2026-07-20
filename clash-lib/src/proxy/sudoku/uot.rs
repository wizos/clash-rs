//! Sudoku UDP-over-TCP ([`SudokuUdpAssoc`]).
//!
//! UoT reuses the exact same base tunnel as the TCP data plane (obfuscation +
//! AEAD record + KIP handshake, see [`super::establish_session`]); the only
//! difference is the control message written after the handshake: a single
//! empty `StartUoT` (`0x12`) request instead of `OpenTCP`. From then on the
//! stream carries UDP datagrams, one per frame:
//!
//! ```text
//! addr_len(u16 BE) | payload_len(u16 BE) | address | payload
//! ```
//!
//! `address` is the SOCKS5-style encoding shared with `OpenTCP`
//! ([`kip::encode_address`]). Client → server frames name the datagram's
//! destination; server → client frames name its source, which the egress
//! discards (the association already knows the target). One frame maps to
//! exactly one datagram, so packet boundaries survive the reliable stream.
//!
//! The stream is split so `send` and `recv` can run concurrently in the egress
//! `select!`, mirroring the other UDP-over-TCP associations (e.g. Snell).

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{proxy::AnyStream, session::SocksAddr};

use super::{
    SudokuOutboundConfig, establish_session,
    kip::{self, KIP_TYPE_START_UOT},
};

/// Upper bound on a UoT frame's address / payload field. The u16 length header
/// caps each at 65535 bytes, which comfortably covers any UDP datagram.
const MAX_UOT_LEN: usize = u16::MAX as usize;

/// A Sudoku UDP-over-TCP association (one per destination, matching the other
/// UDP egresses' `connect` / `send` / `recv` shape).
pub(crate) async fn start(
    config: &SudokuOutboundConfig,
    raw: AnyStream,
) -> Result<AnyStream> {
    let mut stream = establish_session(config, raw).await?;
    kip::write_message(&mut stream, KIP_TYPE_START_UOT, &[])
        .await
        .context("sudoku uot: write StartUoT")?;
    stream.flush().await.context("sudoku uot: flush StartUoT")?;
    Ok(stream)
}

pub(crate) async fn write_packet<W>(
    writer: &mut W,
    target: &SocksAddr,
    payload: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let addr = kip::encode_address(target)?;
    if addr.len() > MAX_UOT_LEN {
        bail!("sudoku uot: address too long: {}", addr.len());
    }
    if payload.len() > MAX_UOT_LEN {
        bail!("sudoku uot: payload too large: {}", payload.len());
    }
    let mut frame = Vec::with_capacity(4 + addr.len() + payload.len());
    frame.extend_from_slice(&(addr.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&addr);
    frame.extend_from_slice(payload);

    writer
        .write_all(&frame)
        .await
        .context("sudoku uot: write datagram")?;
    writer.flush().await.context("sudoku uot: flush datagram")?;
    Ok(())
}

pub(crate) async fn read_packet<R>(reader: &mut R) -> Result<(SocksAddr, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .context("sudoku uot: read header")?;
    let addr_len = u16::from_be_bytes([header[0], header[1]]) as usize;
    let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if addr_len == 0 {
        bail!("sudoku uot: empty address in reply");
    }

    // The reply carries the datagram's source address; the egress already
    // knows the target, but Clash still needs it as `src_addr`.
    let mut addr = vec![0u8; addr_len];
    reader
        .read_exact(&mut addr)
        .await
        .context("sudoku uot: read address")?;
    let source =
        SocksAddr::peek_read(&addr).context("sudoku uot: decode source address")?;
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .context("sudoku uot: read payload")?;
    Ok((source, payload))
}
