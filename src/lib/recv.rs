// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

//! Receiver: assemble chunks to disk, NACK gaps, verify SHA-256, FIN.

use std::fs::{self, File};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::protocol::*;
use crate::report::{TransferEvent, TransferReporter};

struct ReceiveState<'a> {
    file: File,
    tmp_path: PathBuf,
    final_path: PathBuf,
    received: Vec<u64>,
    total: u32,
    size: u64,
    chunk_size: u32,
    hash: [u8; SHA256_DIGEST_SIZE],
    count: u32,
    start: Instant,
    reporter: &'a dyn TransferReporter,
    version: ProtocolVersion,
    frontier: u32,
    oldest_gap_at: Option<Instant>,
}

struct InitHeader {
    version: ProtocolVersion,
    size: u64,
    chunk_size: u32,
    total: u32,
    hash: [u8; SHA256_DIGEST_SIZE],
    final_path: PathBuf,
}

fn parse_init(payload: &[u8], out: Option<&str>) -> Result<InitHeader, String> {
    if payload.len() < NAME_OFFSET {
        return Err(format!("init payload too short: {} bytes", payload.len()));
    }

    let version = ProtocolVersion::try_from(payload[0]).map_err(|_| {
        format!(
            "protocol version mismatch: got {}, want {} or {}",
            payload[0],
            ProtocolVersion::V1 as u8,
            ProtocolVersion::V2 as u8
        )
    })?;
    let size = u64::from_be_bytes(
        payload[SIZE_OFFSET..CHUNK_SIZE_OFFSET]
            .try_into()
            .map_err(|_| "init payload: bad size field".to_string())?,
    );
    let chunk_size = u32::from_be_bytes(
        payload[CHUNK_SIZE_OFFSET..HASH_OFFSET]
            .try_into()
            .map_err(|_| "init payload: bad chunk_size field".to_string())?,
    );
    validate_chunk_size(chunk_size, version)?;

    let mut hash = [0u8; SHA256_DIGEST_SIZE];
    hash.copy_from_slice(&payload[HASH_OFFSET..HASH_OFFSET + SHA256_DIGEST_SIZE]);

    let total_u64 = size.div_ceil(chunk_size as u64);
    if total_u64 > MAX_TOTAL_CHUNKS {
        return Err(format!(
            "transfer too large: {} chunks exceeds limit {}",
            total_u64, MAX_TOTAL_CHUNKS
        ));
    }
    let total = total_u64 as u32;

    let name_bytes = &payload[NAME_OFFSET..];
    let end = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());
    let final_path: PathBuf = if let Some(out) = out {
        PathBuf::from(out)
    } else {
        let raw = std::str::from_utf8(&name_bytes[..end])
            .map_err(|e| format!("invalid filename: {}", e))?;
        let candidate_file_name = Path::new(raw)
            .file_name()
            .and_then(|component| component.to_str())
            .unwrap_or("");
        if candidate_file_name.is_empty()
            || candidate_file_name == "."
            || candidate_file_name == ".."
        {
            return Err("invalid filename in init packet".to_string());
        }
        // Reject control characters: ESC, newline, etc. would be forwarded
        // to the user's terminal by the "receiving {name}" println.
        if candidate_file_name.chars().any(|c| c.is_control()) {
            return Err("filename contains control characters".to_string());
        }
        PathBuf::from(candidate_file_name)
    };

    Ok(InitHeader {
        version,
        size,
        chunk_size,
        total,
        hash,
        final_path,
    })
}

impl<'a> ReceiveState<'a> {
    fn new(
        payload: &[u8],
        out: Option<&str>,
        reporter: &'a dyn TransferReporter,
    ) -> Result<Self, String> {
        let InitHeader {
            version,
            size,
            chunk_size,
            total,
            hash,
            final_path,
        } = parse_init(payload, out)?;

        // Sibling tmp keeps the rename within one directory (and one filesystem).
        let mut tmp_name = final_path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        tmp_name.push(".tmp");
        let tmp_path = final_path.with_file_name(tmp_name);

        let file =
            File::create(&tmp_path).map_err(|e| format!("create {}: {}", tmp_path.display(), e))?;
        file.set_len(size)
            .map_err(|e| format!("set_len {}: {}", tmp_path.display(), e))?;

        let bitmap_words = total.div_ceil(BITMAP_BITS_PER_WORD) as usize;
        let received = vec![0u64; bitmap_words];

        reporter.report(TransferEvent::Receiving {
            path: final_path.as_path(),
            bytes: size,
            chunks: total,
            chunk_size,
        });

        Ok(ReceiveState {
            file,
            tmp_path,
            final_path,
            received,
            total,
            size,
            chunk_size,
            hash,
            count: 0,
            start: Instant::now(),
            reporter,
            version,
            frontier: 0,
            oldest_gap_at: None,
        })
    }

    fn is_received(&self, seq: u32) -> bool {
        self.received[(seq / BITMAP_BITS_PER_WORD) as usize]
            & (1u64 << (seq % BITMAP_BITS_PER_WORD))
            != 0
    }

    fn mark_received(&mut self, seq: u32) {
        self.received[(seq / BITMAP_BITS_PER_WORD) as usize] |=
            1u64 << (seq % BITMAP_BITS_PER_WORD);
    }

    fn store(&mut self, seq: u32, data: &[u8]) -> io::Result<()> {
        if seq >= self.total || self.is_received(seq) {
            return Ok(());
        }

        let offset = seq as u64 * self.chunk_size as u64;
        let expected = (self.size - offset).min(self.chunk_size as u64) as usize;
        if data.len() != expected {
            return Ok(());
        }

        self.file.write_all_at(data, offset)?;

        self.mark_received(seq);
        self.count += 1;
        self.frontier = self.frontier.max(seq + 1);
        self.refresh_gap_clock();

        self.reporter.report(TransferEvent::Progress {
            done: self.count,
            total: self.total,
            chunk_size: self.chunk_size,
            elapsed: self.start.elapsed(),
        });

        Ok(())
    }

    fn refresh_gap_clock(&mut self) {
        self.oldest_gap_at = self
            .has_open_gap()
            .then(|| self.oldest_gap_at.unwrap_or_else(Instant::now));
    }

    fn accept_data(&mut self, seq: u32, payload: &[u8]) -> io::Result<()> {
        match self.verified_body(payload) {
            Some(body) => self.store(seq, body),
            None => Ok(()),
        }
    }

    fn verified_body<'p>(&self, payload: &'p [u8]) -> Option<&'p [u8]> {
        if !self.version.verifies() {
            return Some(payload);
        }

        let (want, body) = payload.split_at_checked(SHA256_DIGEST_SIZE)?;
        let got: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(body).into();
        (got.as_slice() == want).then_some(body)
    }

    fn full(&self) -> bool {
        self.count == self.total
    }

    // Every stored chunk sits below the frontier, so a shortfall there is a gap.
    fn has_open_gap(&self) -> bool {
        self.count < self.frontier
    }

    fn collect_missing(&self, upto: u32) -> Vec<u32> {
        let upto = upto.min(self.total);
        let mut missing = Vec::new();

        for seq in 0..upto {
            if !self.is_received(seq) {
                missing.push(seq);
            }
        }

        missing
    }

    fn emit_nacks(&self, sock: &UdpSocket, addr: SocketAddr, missing: &[u32]) -> io::Result<()> {
        for batch in missing.chunks(MAX_NACKS_PER_PACKET) {
            let payload = encode_nack_payload(batch);
            send_packet(
                sock,
                addr,
                &PacketHeader {
                    packet_type: PacketType::Nack,
                    seq: batch.len() as u32,
                    payload_len: payload.len() as u16,
                },
                &payload,
            )?;
        }

        Ok(())
    }

    fn send_nacks(&self, sock: &UdpSocket, addr: SocketAddr) -> io::Result<()> {
        let missing = self.collect_missing(self.total);
        self.reporter.report(TransferEvent::MissingChunks {
            count: missing.len(),
        });

        self.emit_nacks(sock, addr, missing.as_slice())
    }

    fn next_nack_deadline(
        &self,
        holdoff: Duration,
        last_nack_at: Option<Instant>,
    ) -> Option<Instant> {
        let mut at = self.oldest_gap_at? + holdoff;
        if let Some(last) = last_nack_at {
            at = at.max(last + NACK_REISSUE_INTERVAL);
        }

        Some(at)
    }

    fn nack_gaps(&self, sock: &UdpSocket, addr: SocketAddr) -> io::Result<()> {
        let missing = self.collect_missing(self.frontier);
        if missing.is_empty() {
            return Ok(());
        }

        self.emit_nacks(sock, addr, missing.as_slice())
    }

    fn read_timeout(
        &self,
        last_data_at: Instant,
        last_nack_at: Option<Instant>,
        limits: RecvLimits,
    ) -> Duration {
        let mut deadline = last_data_at + limits.idle_timeout;
        if let Some(nack_at) = self.next_nack_deadline(limits.nack_holdoff, last_nack_at) {
            deadline = deadline.min(nack_at);
        }

        deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1))
    }

    fn on_idle_tick(
        &self,
        sock: &UdpSocket,
        addr: SocketAddr,
        last_data_at: Instant,
        last_nack_at: Option<Instant>,
        limits: RecvLimits,
    ) -> io::Result<TickOutcome> {
        let now = Instant::now();

        if now.duration_since(last_data_at) >= limits.idle_timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "idle timeout: sender disappeared",
            ));
        }

        if self
            .next_nack_deadline(limits.nack_holdoff, last_nack_at)
            .is_some_and(|d| now >= d)
        {
            self.nack_gaps(sock, addr)?;
            return Ok(TickOutcome::Nacked(now));
        }

        Ok(TickOutcome::Waiting)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.finalize().inspect_err(|_| {
            let _ = fs::remove_file(&self.tmp_path);
        })
    }

    fn finalize(&mut self) -> io::Result<()> {
        self.file.sync_all()?;

        let got = file_hash(&mut File::open(&self.tmp_path)?)?;
        if got != self.hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "integrity check failed: SHA-256 mismatch",
            ));
        }

        fs::rename(&self.tmp_path, &self.final_path)?;

        self.reporter.report(TransferEvent::Saved {
            path: self.final_path.as_path(),
            bytes: self.size,
            elapsed: self.start.elapsed(),
        });

        Ok(())
    }

    fn handle_done(&mut self, sock: &UdpSocket, addr: SocketAddr) -> io::Result<DoneOutcome> {
        if !self.full() {
            self.send_nacks(sock, addr)?;
            return Ok(DoneOutcome::Incomplete);
        }

        self.flush()?;
        Ok(DoneOutcome::Complete)
    }
}

enum DoneOutcome {
    Incomplete,
    Complete,
}

enum TickOutcome {
    Waiting,
    Nacked(Instant),
}

impl Drop for ReceiveState<'_> {
    fn drop(&mut self) {
        // Clean up the sibling tmp on abandoned receives (idle timeout, error).
        // After finalize() the tmp has already been renamed, so this is a no-op.
        let _ = fs::remove_file(&self.tmp_path);
    }
}

fn linger(
    sock: &UdpSocket,
    sender: SocketAddr,
    linger_timeout: Duration,
    buf: &mut [u8],
) -> io::Result<()> {
    let mut linger_deadline = Instant::now() + linger_timeout;

    loop {
        let now = Instant::now();
        if now >= linger_deadline {
            break;
        }

        sock.set_read_timeout(Some(linger_deadline - now))?;
        match sock.recv_from(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
            Ok((_, from)) if from != sender => {}
            Ok((n, _)) => match parse_packet(buf, n).map(|(h, _)| h.packet_type) {
                // The sender confirmed it received our FIN; no need to wait out
                // the grace window for a retransmitted DONE that won't come.
                Some(PacketType::FinAck) => break,
                Some(PacketType::Done) => {
                    let _ = send_control(sock, sender, PacketType::Fin, 0);
                    linger_deadline = Instant::now() + linger_timeout;
                }
                _ => {}
            },
        }
    }

    Ok(())
}

fn reset_listening<'a>(
    sock: &UdpSocket,
    reporter: &dyn TransferReporter,
    state: &mut Option<ReceiveState<'a>>,
    sender: &mut Option<SocketAddr>,
    last_nack_at: &mut Option<Instant>,
) -> io::Result<()> {
    *state = None;
    *sender = None;
    *last_nack_at = None;
    sock.set_read_timeout(None)?;

    reporter.report(TransferEvent::Listening {
        addr: sock.local_addr()?,
    });

    Ok(())
}

fn abandon_transfer<'a>(
    error: io::Error,
    serve: bool,
    reporter: &dyn TransferReporter,
    sock: &UdpSocket,
    state: &mut Option<ReceiveState<'a>>,
    sender: &mut Option<SocketAddr>,
    last_nack_at: &mut Option<Instant>,
) -> io::Result<()> {
    if !serve {
        return Err(error);
    }

    reporter.report(TransferEvent::Failed {
        reason: &error.to_string(),
    });

    reset_listening(sock, reporter, state, sender, last_nack_at)
}

pub fn receive_loop(sock: &UdpSocket, out: Option<&str>, config: RecvConfig<'_>) -> io::Result<()> {
    let RecvConfig {
        serve,
        linger_timeout,
        reporter,
        limits,
    } = config;

    reporter.report(TransferEvent::Listening {
        addr: sock.local_addr()?,
    });

    let mut buf = [0u8; MAX_UDP_PAYLOAD];
    let mut state: Option<ReceiveState<'_>> = None;
    let mut sender: Option<SocketAddr> = None;
    let mut last_data_at = Instant::now();
    let mut last_nack_at: Option<Instant> = None;

    'transfer: loop {
        if let Some(ctx) = &state {
            let timeout = ctx.read_timeout(last_data_at, last_nack_at, limits);
            sock.set_read_timeout(Some(timeout))?;
        }

        let (n, from) = match sock.recv_from(&mut buf) {
            Err(e) if is_timeout(&e) => {
                let tick = match (&state, sender) {
                    (Some(ctx), Some(sndr)) => {
                        ctx.on_idle_tick(sock, sndr, last_data_at, last_nack_at, limits)
                    }
                    _ => Ok(TickOutcome::Waiting),
                };
                match tick {
                    Ok(TickOutcome::Nacked(at)) => last_nack_at = Some(at),
                    Ok(TickOutcome::Waiting) => {}
                    Err(e) => abandon_transfer(
                        e,
                        serve,
                        reporter,
                        sock,
                        &mut state,
                        &mut sender,
                        &mut last_nack_at,
                    )?,
                }
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
            Ok(r) => r,
        };

        if let Some(s) = sender
            && from != s
        {
            continue;
        }

        last_data_at = Instant::now();
        let Some((header, payload_end)) = parse_packet(&buf, n) else {
            continue;
        };

        match header.packet_type {
            PacketType::Init => {
                if state.is_none() {
                    let payload = &buf[HEADER_SIZE..payload_end];
                    match ReceiveState::new(payload, out, reporter) {
                        Err(e) => {
                            reporter.report(TransferEvent::BadInit { reason: &e });
                            continue;
                        }
                        Ok(ctx) => {
                            sender = Some(from);
                            state = Some(ctx);
                            last_nack_at = None;
                        }
                    }
                }

                send_control(sock, from, PacketType::Ack, 0)?;
            }
            PacketType::Data => {
                let stored = match &mut state {
                    Some(ctx) => ctx.accept_data(header.seq, &buf[HEADER_SIZE..payload_end]),
                    None => Ok(()),
                };
                if let Err(e) = stored {
                    abandon_transfer(
                        e,
                        serve,
                        reporter,
                        sock,
                        &mut state,
                        &mut sender,
                        &mut last_nack_at,
                    )?;
                }
            }
            PacketType::Done => {
                let Some(sndr) = sender else { continue };
                let Some(ctx) = state.as_mut() else { continue };

                match ctx.handle_done(sock, sndr) {
                    Ok(DoneOutcome::Incomplete) => {
                        last_nack_at = Some(Instant::now());
                        continue;
                    }
                    Ok(DoneOutcome::Complete) => {}
                    Err(e) => {
                        abandon_transfer(
                            e,
                            serve,
                            reporter,
                            sock,
                            &mut state,
                            &mut sender,
                            &mut last_nack_at,
                        )?;
                        continue;
                    }
                }

                state.take();
                send_control(sock, sndr, PacketType::Fin, 0)?;
                linger(sock, sndr, linger_timeout, &mut buf)?;

                if !serve {
                    return Ok(());
                }

                reset_listening(sock, reporter, &mut state, &mut sender, &mut last_nack_at)?;
                continue 'transfer;
            }
            _ => {}
        }
    }
}

pub fn run_receive(port: &str, out: Option<&str>, config: RecvConfig<'_>) -> io::Result<()> {
    // Bind IPv6 wildcard to accept both IPv4 and IPv6 senders. Linux's default
    // bindv6only=0 makes the socket dual-stack.
    let sock = UdpSocket::bind(format!("[::]:{}", port))?;
    install_shutdown_handler(&sock)?;

    let result = receive_loop(&sock, out, config);

    // The error that ended receive_loop was our own socket shutdown; re-raise
    // the signal so the exit status reads killed-by-signal, not socket error.
    let signal = SHUTDOWN_SIGNAL.load(Ordering::SeqCst);
    if signal != 0 {
        let _ = signal_hook::low_level::emulate_default_handler(signal);
    }

    result
}

static SHUTDOWN_SIGNAL: AtomicI32 = AtomicI32::new(0);

// On SIGINT/SIGTERM, shut down the socket so the blocked recv_from in
// receive_loop returns; the loop exits and ReceiveState's Drop removes the
// .tmp file. shutdown(2) is async-signal-safe, but we still route it through
// a signal-hook thread rather than call it from the handler.
fn install_shutdown_handler(sock: &UdpSocket) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let mut signals = Signals::new([SIGINT, SIGTERM])?;

    std::thread::spawn(move || {
        if let Some(signal) = signals.forever().next() {
            SHUTDOWN_SIGNAL.store(signal, Ordering::SeqCst);
            unsafe {
                libc::shutdown(fd, libc::SHUT_RDWR);
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::NullReporter;
    use crate::send::run_send;
    use std::time::Duration;
    use tempfile::tempdir;

    const OVERSIZED_PAYLOAD_LEN: u16 = 9999;

    fn make_init_payload(filename_bytes: &[u8]) -> Vec<u8> {
        let mut payload = vec![0u8; NAME_OFFSET + filename_bytes.len() + 1];
        payload[0] = ProtocolVersion::V1 as u8;
        payload[9..13].copy_from_slice(&DEFAULT_CHUNK_SIZE.to_be_bytes());
        payload[NAME_OFFSET..NAME_OFFSET + filename_bytes.len()].copy_from_slice(filename_bytes);

        payload
    }

    #[test]
    fn version_mismatch_rejected() {
        let mut payload = vec![0u8; NAME_OFFSET + 2];
        payload[0] = 255; // unsupported version
        payload[9..13].copy_from_slice(&DEFAULT_CHUNK_SIZE.to_be_bytes());
        payload[NAME_OFFSET] = b'x';

        let err = ReceiveState::new(&payload, None, &NullReporter)
            .err()
            .unwrap();

        assert!(
            err.contains("version mismatch"),
            "expected version mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn filename_with_escape_sequence_rejected() {
        let payload = make_init_payload(b"\x1b[2Jevil");

        let err = ReceiveState::new(&payload, None, &NullReporter)
            .err()
            .unwrap();

        assert!(
            err.contains("control characters"),
            "expected control-characters error, got: {}",
            err
        );
    }

    #[test]
    fn filename_with_newline_rejected() {
        let payload = make_init_payload(b"foo\nbar");

        let err = ReceiveState::new(&payload, None, &NullReporter)
            .err()
            .unwrap();

        assert!(
            err.contains("control characters"),
            "expected control-characters error, got: {}",
            err
        );
    }

    #[test]
    fn init_payload_too_short_rejected() {
        let err = ReceiveState::new(&[ProtocolVersion::V1 as u8; 10], None, &NullReporter)
            .err()
            .unwrap();

        assert!(err.contains("too short"), "got: {}", err);
    }

    #[test]
    fn init_chunk_size_zero_rejected() {
        let mut payload = vec![0u8; NAME_OFFSET + 2];
        payload[0] = ProtocolVersion::V1 as u8;
        payload[NAME_OFFSET] = b'x';

        let err = ReceiveState::new(&payload, None, &NullReporter)
            .err()
            .unwrap();

        assert!(err.contains("chunk size must be in"), "got: {}", err);
    }

    #[test]
    fn init_chunk_size_over_max_rejected() {
        let mut payload = vec![0u8; NAME_OFFSET + 2];
        payload[0] = ProtocolVersion::V1 as u8;
        payload[CHUNK_SIZE_OFFSET..HASH_OFFSET]
            .copy_from_slice(&(MAX_CHUNK_SIZE + 1).to_be_bytes());
        payload[NAME_OFFSET] = b'x';

        let err = ReceiveState::new(&payload, None, &NullReporter)
            .err()
            .unwrap();

        assert!(err.contains("chunk size must be in"), "got: {}", err);
    }

    #[test]
    fn init_v2_chunk_size_over_verify_max_rejected() {
        // MAX_CHUNK_SIZE is valid in v1 but leaves no room for the 32-byte
        // per-chunk hash in v2, so the receiver must reject it like the sender.
        let mut payload = vec![0u8; NAME_OFFSET + 2];
        payload[0] = ProtocolVersion::V2 as u8;
        payload[CHUNK_SIZE_OFFSET..HASH_OFFSET].copy_from_slice(&MAX_CHUNK_SIZE.to_be_bytes());
        payload[NAME_OFFSET] = b'x';

        let err = ReceiveState::new(&payload, None, &NullReporter)
            .err()
            .unwrap();

        assert!(err.contains("chunk size must be in"), "got: {}", err);
    }

    #[test]
    fn init_transfer_too_large_rejected() {
        let mut payload = vec![0u8; NAME_OFFSET + 2];
        payload[0] = ProtocolVersion::V1 as u8;
        payload[SIZE_OFFSET..CHUNK_SIZE_OFFSET]
            .copy_from_slice(&(MAX_TOTAL_CHUNKS + 1).to_be_bytes());
        payload[CHUNK_SIZE_OFFSET..HASH_OFFSET].copy_from_slice(&1u32.to_be_bytes());
        payload[NAME_OFFSET] = b'x';

        let err = ReceiveState::new(&payload, None, &NullReporter)
            .err()
            .unwrap();

        assert!(err.contains("transfer too large"), "got: {}", err);
    }

    #[test]
    fn init_traversal_filename_rejected() {
        // ".." has no final path component, so the derived output name is empty.
        let payload = make_init_payload(b"..");

        let err = ReceiveState::new(&payload, None, &NullReporter)
            .err()
            .unwrap();

        assert!(err.contains("invalid filename"), "got: {}", err);
    }

    #[test]
    fn finalize_rejects_hash_mismatch_and_removes_tmp() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("out.bin");
        let tmp = dir.path().join("out.bin.tmp");
        let data = b"hello world";

        // INIT hash field is left zeroed, which no real content hashes to.
        let mut payload = vec![0u8; NAME_OFFSET + 8];
        payload[0] = ProtocolVersion::V1 as u8;
        payload[SIZE_OFFSET..CHUNK_SIZE_OFFSET].copy_from_slice(&(data.len() as u64).to_be_bytes());
        payload[CHUNK_SIZE_OFFSET..HASH_OFFSET].copy_from_slice(&DEFAULT_CHUNK_SIZE.to_be_bytes());
        payload[NAME_OFFSET..NAME_OFFSET + 7].copy_from_slice(b"out.bin");

        let mut state =
            ReceiveState::new(&payload, Some(out.to_str().unwrap()), &NullReporter).unwrap();
        state.store(0, data).unwrap();

        let err = state.flush().unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!tmp.exists(), "tmp must be removed when integrity fails");
    }

    #[test]
    fn wrong_size_payload_is_ignored_and_chunk_stays_requestable() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("out.bin");
        let content = b"AAAABBBB";
        let chunk_size: u32 = 4;
        let hash: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(content).into();

        let mut payload = vec![0u8; NAME_OFFSET + 8];
        payload[0] = ProtocolVersion::V1 as u8;
        payload[SIZE_OFFSET..CHUNK_SIZE_OFFSET]
            .copy_from_slice(&(content.len() as u64).to_be_bytes());
        payload[CHUNK_SIZE_OFFSET..HASH_OFFSET].copy_from_slice(&chunk_size.to_be_bytes());
        payload[HASH_OFFSET..HASH_OFFSET + SHA256_DIGEST_SIZE].copy_from_slice(&hash);
        payload[NAME_OFFSET..NAME_OFFSET + 7].copy_from_slice(b"out.bin");

        let mut state =
            ReceiveState::new(&payload, Some(out.to_str().unwrap()), &NullReporter).unwrap();

        // Oversized would clobber chunk 1's slot; truncated would otherwise be
        // marked received and never re-requested.
        state.store(0, b"AAAAXXXX").unwrap();
        state.store(1, b"BB").unwrap();

        assert_eq!(state.count, 0, "wrong-size payloads must not be stored");

        state.store(0, b"AAAA").unwrap();
        state.store(1, b"BBBB").unwrap();
        state.flush().unwrap();

        assert_eq!(std::fs::read(&out).unwrap(), content);
    }

    #[test]
    fn linger_returns_at_once_on_fin_ack() {
        let recv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = sender.local_addr().unwrap();

        // The sender confirms the close; UDP buffers it until linger reads it.
        let mut fin_ack = [0u8; HEADER_SIZE];
        fin_ack[0] = PacketType::FinAck as u8;
        sender.send_to(&fin_ack, recv_addr).unwrap();

        let mut buf = [0u8; MAX_UDP_PAYLOAD];
        let start = Instant::now();
        linger(&recv_sock, sender_addr, Duration::from_secs(5), &mut buf).unwrap();

        assert!(
            start.elapsed() < Duration::from_secs(1),
            "FIN-ACK should end linger immediately, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn receiver_ignores_malformed_packets() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("s.bin");
        let dst = dir.path().join("d.bin");
        let want = vec![7u8; 2000];
        std::fs::write(&src, &want).unwrap();

        let recv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let dst_str = dst.to_str().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            receive_loop(
                &recv_sock,
                Some(&dst_str),
                RecvConfig {
                    serve: false,
                    linger_timeout: Duration::from_secs(5),
                    reporter: &NullReporter,
                    limits: RecvLimits::default(),
                },
            )
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.send_to(&[1, 2, 3], recv_addr).unwrap();

        let mut overrun = vec![0u8; HEADER_SIZE];
        overrun[0] = PacketType::Data as u8;
        overrun[5..7].copy_from_slice(&OVERSIZED_PAYLOAD_LEN.to_be_bytes());
        client.send_to(&overrun, recv_addr).unwrap();

        let mut bad_init = vec![0u8; HEADER_SIZE + NAME_OFFSET + 2];
        bad_init[0] = PacketType::Init as u8;
        bad_init[5..7].copy_from_slice(&((NAME_OFFSET + 2) as u16).to_be_bytes());
        bad_init[HEADER_SIZE] = 99;
        client.send_to(&bad_init, recv_addr).unwrap();

        // Let the receiver drain the junk before the real transfer arrives, so
        // the bad INIT is processed while no transfer is in progress.
        std::thread::sleep(Duration::from_millis(50));
        run_send(
            src.to_str().unwrap(),
            &recv_addr.to_string(),
            SendConfig {
                chunk_size: 1400,
                delay: None,
                version: ProtocolVersion::V1,
                reporter: &NullReporter,
                limits: SendLimits::default(),
            },
        )
        .unwrap();

        handle.join().unwrap().unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), want);
    }

    #[test]
    fn receiver_times_out_when_sender_disappears() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("d.bin");
        let recv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let dst_str = dst.to_str().unwrap().to_string();
        let config = RecvConfig {
            serve: false,
            linger_timeout: Duration::from_secs(5),
            reporter: &NullReporter,
            limits: RecvLimits {
                idle_timeout: Duration::from_millis(150),
                nack_holdoff: NACK_HOLDOFF,
            },
        };
        let handle = std::thread::spawn(move || receive_loop(&recv_sock, Some(&dst_str), config));

        // Complete only the INIT handshake, then go silent so the idle timer fires.
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut init = vec![0u8; HEADER_SIZE + NAME_OFFSET + 2];
        init[0] = PacketType::Init as u8;
        init[5..7].copy_from_slice(&((NAME_OFFSET + 2) as u16).to_be_bytes());
        let p = HEADER_SIZE;
        init[p] = ProtocolVersion::V1 as u8;
        init[p + SIZE_OFFSET..p + CHUNK_SIZE_OFFSET].copy_from_slice(&1400u64.to_be_bytes());
        init[p + CHUNK_SIZE_OFFSET..p + HASH_OFFSET]
            .copy_from_slice(&DEFAULT_CHUNK_SIZE.to_be_bytes());
        init[p + NAME_OFFSET] = b'd';
        client.send_to(&init, recv_addr).unwrap();

        let err = handle.join().unwrap().unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("idle timeout"), "got: {}", err);
    }

    #[test]
    fn serve_mode_resets_after_hash_mismatch() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("d.bin");
        let recv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let dst_str = dst.to_str().unwrap().to_string();
        let config = RecvConfig {
            serve: true,
            linger_timeout: Duration::from_millis(200),
            reporter: &NullReporter,
            limits: RecvLimits::default(),
        };
        std::thread::spawn(move || {
            let _ = receive_loop(&recv_sock, Some(&dst_str), config);
        });

        // A complete transfer whose INIT declared a zero hash: the receiver
        // accepts every chunk, then fails the final integrity check.
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; MAX_UDP_PAYLOAD];
        let data = b"data";

        let mut init = vec![0u8; NAME_OFFSET + 1];
        init[0] = ProtocolVersion::V1 as u8;
        init[SIZE_OFFSET..CHUNK_SIZE_OFFSET].copy_from_slice(&(data.len() as u64).to_be_bytes());
        init[CHUNK_SIZE_OFFSET..HASH_OFFSET].copy_from_slice(&DEFAULT_CHUNK_SIZE.to_be_bytes());
        init[NAME_OFFSET] = b'd';
        send_packet(
            &client,
            recv_addr,
            &PacketHeader {
                packet_type: PacketType::Init,
                seq: 0,
                payload_len: init.len() as u16,
            },
            &init,
        )
        .unwrap();
        let (n, _) = client.recv_from(&mut buf).unwrap();
        assert!(decode_header(&buf[..n]).unwrap().packet_type == PacketType::Ack);

        send_packet(
            &client,
            recv_addr,
            &PacketHeader {
                packet_type: PacketType::Data,
                seq: 0,
                payload_len: data.len() as u16,
            },
            data,
        )
        .unwrap();
        send_control(&client, recv_addr, PacketType::Done, 1).unwrap();
        std::thread::sleep(Duration::from_millis(100));

        // The receiver must have reset instead of exiting: a well-formed
        // transfer right after must still land.
        let src = dir.path().join("s.bin");
        let want = vec![9u8; 3000];
        std::fs::write(&src, &want).unwrap();
        run_send(
            src.to_str().unwrap(),
            &recv_addr.to_string(),
            SendConfig {
                chunk_size: 1400,
                delay: None,
                version: ProtocolVersion::V1,
                reporter: &NullReporter,
                limits: SendLimits::default(),
            },
        )
        .unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), want);
        assert!(
            !dir.path().join("d.bin.tmp").exists(),
            "abandoned transfer must not leave a .tmp behind"
        );
    }

    #[test]
    fn serve_mode_resets_after_idle_timeout() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("d.bin");
        let recv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let dst_str = dst.to_str().unwrap().to_string();
        let config = RecvConfig {
            serve: true,
            linger_timeout: Duration::from_millis(200),
            reporter: &NullReporter,
            limits: RecvLimits {
                idle_timeout: Duration::from_millis(150),
                nack_holdoff: NACK_HOLDOFF,
            },
        };
        std::thread::spawn(move || {
            let _ = receive_loop(&recv_sock, Some(&dst_str), config);
        });

        // Open a transfer, then go silent until the idle timer fires.
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let payload = make_init_payload(b"d");
        let mut init = vec![0u8; HEADER_SIZE + payload.len()];
        init[0] = PacketType::Init as u8;
        init[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        init[HEADER_SIZE..].copy_from_slice(&payload);
        client.send_to(&init, recv_addr).unwrap();
        std::thread::sleep(Duration::from_millis(400));

        let src = dir.path().join("s.bin");
        let want = vec![3u8; 2000];
        std::fs::write(&src, &want).unwrap();
        run_send(
            src.to_str().unwrap(),
            &recv_addr.to_string(),
            SendConfig {
                chunk_size: 1400,
                delay: None,
                version: ProtocolVersion::V1,
                reporter: &NullReporter,
                limits: SendLimits::default(),
            },
        )
        .unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), want);
    }

    #[test]
    fn done_nacks_start_the_reissue_clock() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("d.bin");
        let data = b"abcde";
        let chunk_size: u32 = 2;
        let total: u32 = (data.len() as u32).div_ceil(chunk_size);
        let hash: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(data).into();

        let recv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let dst_str = dst.to_str().unwrap().to_string();
        let config = RecvConfig {
            serve: false,
            linger_timeout: Duration::from_millis(200),
            reporter: &NullReporter,
            limits: RecvLimits {
                idle_timeout: Duration::from_secs(5),
                nack_holdoff: Duration::from_millis(50),
            },
        };
        let handle = std::thread::spawn(move || receive_loop(&recv_sock, Some(&dst_str), config));

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; MAX_UDP_PAYLOAD];

        let mut init = vec![0u8; NAME_OFFSET + 1];
        init[0] = ProtocolVersion::V1 as u8;
        init[SIZE_OFFSET..CHUNK_SIZE_OFFSET].copy_from_slice(&(data.len() as u64).to_be_bytes());
        init[CHUNK_SIZE_OFFSET..HASH_OFFSET].copy_from_slice(&chunk_size.to_be_bytes());
        init[HASH_OFFSET..HASH_OFFSET + SHA256_DIGEST_SIZE].copy_from_slice(&hash);
        init[NAME_OFFSET] = b'd';
        send_packet(
            &client,
            recv_addr,
            &PacketHeader {
                packet_type: PacketType::Init,
                seq: 0,
                payload_len: init.len() as u16,
            },
            &init,
        )
        .unwrap();
        let (n, _) = client.recv_from(&mut buf).unwrap();
        assert!(decode_header(&buf[..n]).unwrap().packet_type == PacketType::Ack);

        let send_data = |seq: u32| {
            let start = seq as usize * chunk_size as usize;
            let end = (start + chunk_size as usize).min(data.len());
            send_packet(
                &client,
                recv_addr,
                &PacketHeader {
                    packet_type: PacketType::Data,
                    seq,
                    payload_len: (end - start) as u16,
                },
                &data[start..end],
            )
            .unwrap();
        };

        // Leave a gap at seq 1 and declare DONE before the holdoff elapses,
        // so the DONE-triggered NACK is the first one out.
        send_data(0);
        send_data(2);
        send_control(&client, recv_addr, PacketType::Done, total).unwrap();

        let (n, _) = client.recv_from(&mut buf).unwrap();
        assert!(decode_header(&buf[..n]).unwrap().packet_type == PacketType::Nack);

        // The gap clock (holdoff 50 ms) must not re-NACK right after the
        // DONE-triggered batch; the next reissue is a full interval away.
        client
            .set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        let duplicate = client.recv_from(&mut buf);
        assert!(
            duplicate.is_err(),
            "expected silence after the DONE-triggered NACK, got a duplicate"
        );

        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        send_data(1);
        send_control(&client, recv_addr, PacketType::Done, total).unwrap();

        loop {
            let (n, _) = client.recv_from(&mut buf).unwrap();
            if decode_header(&buf[..n]).unwrap().packet_type == PacketType::Fin {
                break;
            }
        }

        handle.join().unwrap().unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), data);
    }

    #[test]
    fn streaming_nack_requests_gap_before_done() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("d.bin");
        let data = b"abcdefg";
        let chunk_size: u32 = 2;
        let total: u32 = (data.len() as u32).div_ceil(chunk_size);
        let hash: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(data).into();

        let recv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let dst_str = dst.to_str().unwrap().to_string();
        let config = RecvConfig {
            serve: false,
            linger_timeout: Duration::from_millis(200),
            reporter: &NullReporter,
            limits: RecvLimits {
                idle_timeout: Duration::from_secs(5),
                nack_holdoff: Duration::from_millis(10),
            },
        };
        let handle = std::thread::spawn(move || receive_loop(&recv_sock, Some(&dst_str), config));

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; MAX_UDP_PAYLOAD];

        let mut init = vec![0u8; NAME_OFFSET + 1];
        init[0] = ProtocolVersion::V1 as u8;
        init[SIZE_OFFSET..CHUNK_SIZE_OFFSET].copy_from_slice(&(data.len() as u64).to_be_bytes());
        init[CHUNK_SIZE_OFFSET..HASH_OFFSET].copy_from_slice(&chunk_size.to_be_bytes());
        init[HASH_OFFSET..HASH_OFFSET + SHA256_DIGEST_SIZE].copy_from_slice(&hash);
        init[NAME_OFFSET] = b'd';
        send_packet(
            &client,
            recv_addr,
            &PacketHeader {
                packet_type: PacketType::Init,
                seq: 0,
                payload_len: init.len() as u16,
            },
            &init,
        )
        .unwrap();

        let (n, _) = client.recv_from(&mut buf).unwrap();
        assert!(decode_header(&buf[..n]).unwrap().packet_type == PacketType::Ack);

        let send_data = |seq: u32| {
            let start = seq as usize * chunk_size as usize;
            let end = (start + chunk_size as usize).min(data.len());
            send_packet(
                &client,
                recv_addr,
                &PacketHeader {
                    packet_type: PacketType::Data,
                    seq,
                    payload_len: (end - start) as u16,
                },
                &data[start..end],
            )
            .unwrap();
        };

        send_data(0);
        send_data(1);
        send_data(3);

        let (n, _) = client.recv_from(&mut buf).unwrap();
        let header = decode_header(&buf[..n]).unwrap();
        assert!(header.packet_type == PacketType::Nack);

        let nacked: Vec<u32> = (0..header.seq as usize)
            .map(|i| {
                let off = HEADER_SIZE + i * SEQUENCE_BYTES;
                u32::from_be_bytes(buf[off..off + SEQUENCE_BYTES].try_into().unwrap())
            })
            .collect();
        assert_eq!(
            nacked,
            vec![2],
            "streaming NACK should ask only for the open gap"
        );

        send_data(2);
        send_control(&client, recv_addr, PacketType::Done, total).unwrap();

        loop {
            let (n, _) = client.recv_from(&mut buf).unwrap();
            if decode_header(&buf[..n]).unwrap().packet_type == PacketType::Fin {
                break;
            }
        }

        handle.join().unwrap().unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), data);
    }
}
