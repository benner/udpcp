// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

//! Wire format and helpers shared by the sender and receiver.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::report::TransferReporter;

pub(crate) const SHA256_DIGEST_SIZE: usize = 32;
pub const DEFAULT_CHUNK_SIZE: u32 = 1400;
pub(crate) const HEADER_SIZE: usize = 7; // typ(1) | seq(4) | pay_len(2)
pub(crate) const MAX_UDP_PAYLOAD: usize = 65507;
pub(crate) const MAX_CHUNK_SIZE: u32 = (MAX_UDP_PAYLOAD - HEADER_SIZE) as u32;
pub(crate) const SEQUENCE_BYTES: usize = 4;
pub(crate) const MAX_NACKS_PER_PACKET: usize = (MAX_UDP_PAYLOAD - HEADER_SIZE) / SEQUENCE_BYTES;

// INIT payload: version(u8) | size(u64) | chunk_sz(u32) | hash(32) | name(NUL)
pub(crate) const SIZE_OFFSET: usize = size_of::<u8>();
pub(crate) const CHUNK_SIZE_OFFSET: usize = SIZE_OFFSET + size_of::<u64>();
pub(crate) const HASH_OFFSET: usize = CHUNK_SIZE_OFFSET + size_of::<u32>();
pub(crate) const NAME_OFFSET: usize = HASH_OFFSET + SHA256_DIGEST_SIZE;

pub(crate) const MAX_TOTAL_CHUNKS: u64 = 1 << 24; // 16 M chunks ≈ 1 TB at max chunk size
pub(crate) const BITMAP_BITS_PER_WORD: u32 = u64::BITS;
pub(crate) const HASH_READ_BUFFER: usize = 65536;
pub(crate) const BYTES_PER_KIB: u64 = 1024;

pub(crate) const RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const LINGER_RETRANSMIT_CYCLES: u64 = 5;
pub const DEFAULT_LINGER_SECONDS: u64 = RETRANSMIT_TIMEOUT.as_secs() * LINGER_RETRANSMIT_CYCLES;
pub(crate) const NACK_COLLECTION_TIMEOUT: Duration = Duration::from_millis(500);
// Hold off NACKing a gap this long so brief reordering isn't read as loss.
pub(crate) const NACK_HOLDOFF: Duration = Duration::from_millis(20);
// Re-NACK an unfilled gap no sooner than this, leaving room for a retransmit.
pub(crate) const NACK_REISSUE_INTERVAL: Duration = RETRANSMIT_TIMEOUT;
pub(crate) const MAX_RETRANSMIT_PASSES: usize = 60;
pub(crate) const MAX_HANDSHAKE_ATTEMPTS: usize = 60;
pub(crate) const RECEIVER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Tunable sender retry and timeout limits, defaulting to the module
/// constants. Threaded into the send path so the CLI can override them and
/// tests can shrink them to keep timeout paths fast.
#[derive(Clone, Copy)]
pub struct SendLimits {
    pub handshake_attempts: usize,
    pub retransmit_passes: usize,
    pub retransmit_timeout: Duration,
    pub nack_collection_timeout: Duration,
}

impl Default for SendLimits {
    fn default() -> Self {
        SendLimits {
            handshake_attempts: MAX_HANDSHAKE_ATTEMPTS,
            retransmit_passes: MAX_RETRANSMIT_PASSES,
            retransmit_timeout: RETRANSMIT_TIMEOUT,
            nack_collection_timeout: NACK_COLLECTION_TIMEOUT,
        }
    }
}

/// Tunable receiver timeout limits, defaulting to the module constants.
/// Threaded into the receive path for the same reasons as [`SendLimits`].
#[derive(Clone, Copy)]
pub struct RecvLimits {
    pub idle_timeout: Duration,
    pub nack_holdoff: Duration,
}

impl Default for RecvLimits {
    fn default() -> Self {
        RecvLimits {
            idle_timeout: RECEIVER_IDLE_TIMEOUT,
            nack_holdoff: NACK_HOLDOFF,
        }
    }
}

/// Everything a single send needs beyond the file path and target address.
#[derive(Clone, Copy)]
pub struct SendConfig<'a> {
    pub chunk_size: u32,
    pub delay: Option<Duration>,
    pub version: ProtocolVersion,
    pub reporter: &'a dyn TransferReporter,
    pub limits: SendLimits,
}

/// Everything a receiver needs beyond the bind port and output path.
#[derive(Clone, Copy)]
pub struct RecvConfig<'a> {
    pub serve: bool,
    pub linger_timeout: Duration,
    pub reporter: &'a dyn TransferReporter,
    pub limits: RecvLimits,
}

// Wire protocol

macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident { $($variant:ident = $value:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[repr(u8)]
        $vis enum $name { $($variant = $value),+ }

        impl TryFrom<u8> for $name {
            type Error = ();

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok($name::$variant),)+
                    _ => Err(()),
                }
            }
        }
    };
}

wire_enum! {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum PacketType {
        Init = 1,
        Ack = 2,
        Data = 3,
        Done = 4,
        Nack = 5,
        Fin = 6,
        FinAck = 7,
    }
}

wire_enum! {
    /// Version byte carried in the INIT payload; v2 adds per-chunk SHA-256.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum ProtocolVersion {
        V1 = 1,
        V2 = 2,
    }
}

impl ProtocolVersion {
    /// The wire version selected by a sender's `--verify` choice.
    pub fn for_verify(verify: bool) -> Self {
        if verify {
            ProtocolVersion::V2
        } else {
            ProtocolVersion::V1
        }
    }

    /// Whether this version prefixes each DATA chunk with its SHA-256.
    pub fn verifies(self) -> bool {
        self == ProtocolVersion::V2
    }
}

pub(crate) struct PacketHeader {
    pub(crate) packet_type: PacketType,
    pub(crate) seq: u32,
    pub(crate) payload_len: u16,
}

fn encode_header(header: &PacketHeader, buf: &mut [u8]) {
    buf[0] = header.packet_type as u8;
    buf[1..5].copy_from_slice(&header.seq.to_be_bytes());
    buf[5..7].copy_from_slice(&header.payload_len.to_be_bytes());
}

/// Returns `None` when the buffer is shorter than a header or the type byte
/// is not a known packet type.
pub(crate) fn decode_header(buf: &[u8]) -> Option<PacketHeader> {
    if buf.len() < HEADER_SIZE {
        return None;
    }

    Some(PacketHeader {
        packet_type: PacketType::try_from(buf[0]).ok()?,
        seq: u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
        payload_len: u16::from_be_bytes([buf[5], buf[6]]),
    })
}

pub(crate) fn parse_packet(buf: &[u8], n: usize) -> Option<(PacketHeader, usize)> {
    let header = decode_header(&buf[..n])?;
    let payload_end = HEADER_SIZE + header.payload_len as usize;
    if payload_end > n {
        return None;
    }

    Some((header, payload_end))
}

pub(crate) fn send_packet(
    sock: &UdpSocket,
    addr: SocketAddr,
    header: &PacketHeader,
    payload: &[u8],
) -> io::Result<()> {
    let mut head = [0u8; HEADER_SIZE];
    encode_header(header, &mut head);

    let mut datagram = Vec::with_capacity(HEADER_SIZE + payload.len());
    datagram.extend_from_slice(&head);
    datagram.extend_from_slice(payload);

    sock.send_to(&datagram, addr)?;
    Ok(())
}

/// Send a header-only control packet; ACK, DONE, and FIN carry no payload.
pub(crate) fn send_control(
    sock: &UdpSocket,
    addr: SocketAddr,
    packet_type: PacketType,
    seq: u32,
) -> io::Result<()> {
    send_packet(
        sock,
        addr,
        &PacketHeader {
            packet_type,
            seq,
            payload_len: 0,
        },
        &[],
    )
}

pub(crate) fn encode_nack_payload(seqs: &[u32]) -> Vec<u8> {
    seqs.iter().flat_map(|seq| seq.to_be_bytes()).collect()
}

pub(crate) fn decode_nack_payload(count: usize, payload: &[u8], out: &mut Vec<u32>) {
    for seq in payload.chunks_exact(SEQUENCE_BYTES).take(count) {
        out.push(u32::from_be_bytes(seq.try_into().unwrap()));
    }
}

pub(crate) fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

// Shared helpers

pub fn validate_chunk_size(chunk_size: u32, version: ProtocolVersion) -> Result<(), String> {
    let max = if version.verifies() {
        MAX_CHUNK_SIZE - SHA256_DIGEST_SIZE as u32
    } else {
        MAX_CHUNK_SIZE
    };

    if chunk_size == 0 || chunk_size > max {
        return Err(format!("chunk size must be in [1, {}]", max));
    }

    Ok(())
}

pub(crate) fn file_hash(f: &mut File) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
    f.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_READ_BUFFER];

    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }

        hasher.update(&buf[..n]);
    }

    Ok(hasher.finalize().into())
}

/// Loops on short reads; the returned count is below `buf.len()` only at EOF.
pub(crate) fn read_chunk(f: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut pos = 0;

    while pos < buf.len() {
        match f.read(&mut buf[pos..])? {
            0 => break,
            n => pos += n,
        }
    }

    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_buffer_decodes_to_no_header() {
        assert!(decode_header(&[]).is_none());
        assert!(decode_header(&[PacketType::Init as u8; HEADER_SIZE - 1]).is_none());
    }

    #[test]
    fn chunk_size_zero_rejected() {
        assert!(validate_chunk_size(0, ProtocolVersion::V1).is_err());
    }

    #[test]
    fn chunk_size_one_accepted() {
        assert!(validate_chunk_size(1, ProtocolVersion::V1).is_ok());
    }

    #[test]
    fn chunk_size_max_accepted() {
        assert!(validate_chunk_size(MAX_CHUNK_SIZE, ProtocolVersion::V1).is_ok());
    }

    #[test]
    fn chunk_size_above_max_rejected() {
        assert!(validate_chunk_size(MAX_CHUNK_SIZE + 1, ProtocolVersion::V1).is_err());
    }

    #[test]
    fn chunk_size_v2_reserves_hash_room() {
        let max_v2 = MAX_CHUNK_SIZE - SHA256_DIGEST_SIZE as u32;
        assert!(validate_chunk_size(max_v2, ProtocolVersion::V2).is_ok());
        assert!(validate_chunk_size(max_v2 + 1, ProtocolVersion::V2).is_err());
    }
}
