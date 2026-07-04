// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

//! Sender: handshake, blast chunks, collect NACK/FIN feedback.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::protocol::*;
use crate::report::{TransferEvent, TransferReporter};

const FEEDBACK_DRAIN_INTERVAL: usize = 16;

struct SendSession<'a> {
    sock: &'a UdpSocket,
    target: SocketAddr,
    chunk_size: u32,
    total_chunks: u32,
    delay: Option<Duration>,
    version: ProtocolVersion,
    limits: SendLimits,
}

struct Blast {
    pending: VecDeque<u32>,
    queued: HashSet<u32>,
    chunk_buf: Vec<u8>,
    verify_buf: Vec<u8>,
    drain_buf: Vec<u8>,
    progress_done: u32,
}

impl Blast {
    fn new(chunk_size: u32, version: ProtocolVersion, total_chunks: u32) -> Self {
        let pending: VecDeque<u32> = (0..total_chunks).collect();
        let queued: HashSet<u32> = pending.iter().copied().collect();

        Blast {
            pending,
            queued,
            chunk_buf: vec![0u8; chunk_size as usize],
            verify_buf: if version.verifies() {
                vec![0u8; SHA256_DIGEST_SIZE + chunk_size as usize]
            } else {
                Vec::new()
            },
            drain_buf: vec![0u8; MAX_UDP_PAYLOAD],
            progress_done: 0,
        }
    }

    fn enqueue(&mut self, missing: Vec<u32>) {
        for seq in missing {
            if self.queued.insert(seq) {
                self.pending.push_back(seq);
            }
        }
    }
}

impl SendSession<'_> {
    fn handshake(
        &self,
        name: &str,
        size: u64,
        hash: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<SocketAddr> {
        let mut payload = vec![0u8; NAME_OFFSET + name.len() + 1];
        payload[0] = self.version as u8;
        payload[SIZE_OFFSET..CHUNK_SIZE_OFFSET].copy_from_slice(&size.to_be_bytes());
        payload[CHUNK_SIZE_OFFSET..HASH_OFFSET].copy_from_slice(&self.chunk_size.to_be_bytes());
        payload[HASH_OFFSET..HASH_OFFSET + SHA256_DIGEST_SIZE].copy_from_slice(hash);
        payload[NAME_OFFSET..NAME_OFFSET + name.len()].copy_from_slice(name.as_bytes());

        let mut buf = [0u8; MAX_UDP_PAYLOAD];

        for _ in 0..self.limits.handshake_attempts {
            send_packet(
                self.sock,
                self.target,
                &PacketHeader {
                    packet_type: PacketType::Init,
                    seq: 0,
                    payload_len: payload.len() as u16,
                },
                &payload,
            )?;

            let attempt_deadline = Instant::now() + self.limits.retransmit_timeout;
            loop {
                let now = Instant::now();
                if now >= attempt_deadline {
                    break;
                }

                self.sock.set_read_timeout(Some(attempt_deadline - now))?;
                match self.sock.recv_from(&mut buf) {
                    Ok((n, from))
                        if decode_header(&buf[..n])
                            .is_some_and(|h| h.packet_type == PacketType::Ack) =>
                    {
                        return Ok(from);
                    }
                    Ok(_) => {}
                    Err(e) if is_timeout(&e) => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }

        Err(io::Error::new(io::ErrorKind::TimedOut, "handshake timeout"))
    }

    fn send_one(
        &self,
        f: &mut File,
        seq: u32,
        buf: &mut [u8],
        verify_buf: &mut [u8],
    ) -> io::Result<()> {
        f.seek(SeekFrom::Start(seq as u64 * self.chunk_size as u64))?;
        let n = read_chunk(f, buf)?;

        let payload: &[u8] = if self.version.verifies() {
            let hash: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(&buf[..n]).into();
            verify_buf[..SHA256_DIGEST_SIZE].copy_from_slice(&hash);
            verify_buf[SHA256_DIGEST_SIZE..SHA256_DIGEST_SIZE + n].copy_from_slice(&buf[..n]);
            &verify_buf[..SHA256_DIGEST_SIZE + n]
        } else {
            &buf[..n]
        };

        send_packet(
            self.sock,
            self.target,
            &PacketHeader {
                packet_type: PacketType::Data,
                seq,
                payload_len: payload.len() as u16,
            },
            payload,
        )
    }

    fn send_pending(
        &self,
        f: &mut File,
        blast: &mut Blast,
        reporter: &dyn TransferReporter,
        receiver_addr: SocketAddr,
        start: Instant,
    ) -> io::Result<bool> {
        let mut since_drain = 0;

        while let Some(seq) = blast.pending.pop_front() {
            blast.queued.remove(&seq);
            self.send_one(f, seq, &mut blast.chunk_buf, &mut blast.verify_buf)?;

            blast.progress_done = blast
                .progress_done
                .max(self.total_chunks - blast.pending.len() as u32);
            reporter.report(TransferEvent::Progress {
                done: blast.progress_done,
                total: self.total_chunks,
                chunk_size: self.chunk_size,
                elapsed: start.elapsed(),
            });

            if let Some(d) = self.delay
                && !blast.pending.is_empty()
            {
                std::thread::sleep(d);
            }

            since_drain += 1;
            if since_drain >= FEEDBACK_DRAIN_INTERVAL {
                since_drain = 0;
                if drain_feedback(
                    self.sock,
                    receiver_addr,
                    &mut blast.drain_buf,
                    &mut blast.pending,
                    &mut blast.queued,
                )? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

fn dedup(seqs: &mut Vec<u32>) {
    let mut seen = HashSet::with_capacity(seqs.len());
    seqs.retain(|s| seen.insert(*s));
}

enum Feedback {
    Complete,
    Retransmit(Vec<u32>),
}

fn collect_feedback(
    sock: &UdpSocket,
    receiver_addr: SocketAddr,
    limits: SendLimits,
) -> io::Result<Feedback> {
    let mut missing: Vec<u32> = Vec::new();
    let mut buf = [0u8; MAX_UDP_PAYLOAD];
    sock.set_read_timeout(Some(limits.retransmit_timeout))?;

    loop {
        match sock.recv_from(&mut buf) {
            Err(e) if is_timeout(&e) => {
                dedup(&mut missing);
                return Ok(Feedback::Retransmit(missing));
            }
            Err(e) => return Err(e),
            Ok((n, from)) => {
                if from != receiver_addr {
                    continue;
                }
                let Some((header, payload_end)) = parse_packet(&buf, n) else {
                    continue;
                };
                match header.packet_type {
                    PacketType::Fin => return Ok(Feedback::Complete),
                    PacketType::Nack => {
                        decode_nack_payload(
                            header.seq as usize,
                            &buf[HEADER_SIZE..payload_end],
                            &mut missing,
                        );
                        sock.set_read_timeout(Some(limits.nack_collection_timeout))?;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn drain_feedback(
    sock: &UdpSocket,
    receiver_addr: SocketAddr,
    buf: &mut [u8],
    pending: &mut VecDeque<u32>,
    queued: &mut HashSet<u32>,
) -> io::Result<bool> {
    sock.set_nonblocking(true)?;
    let mut nacks = Vec::new();
    let mut saw_fin = false;

    loop {
        match sock.recv_from(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => {
                sock.set_nonblocking(false)?;
                return Err(e);
            }
            Ok((n, from)) => {
                if from != receiver_addr {
                    continue;
                }
                let Some((header, payload_end)) = parse_packet(buf, n) else {
                    continue;
                };
                match header.packet_type {
                    PacketType::Fin => {
                        saw_fin = true;
                        break;
                    }
                    PacketType::Nack => {
                        nacks.clear();
                        decode_nack_payload(
                            header.seq as usize,
                            &buf[HEADER_SIZE..payload_end],
                            &mut nacks,
                        );
                        for &seq in &nacks {
                            if queued.insert(seq) {
                                pending.push_back(seq);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    sock.set_nonblocking(false)?;
    Ok(saw_fin)
}

/// Convert a `--bw` limit in KiB/s into the per-packet send delay.
/// `bw == 0` means unlimited. The packet rate is clamped to `[1, u32::MAX]`
/// so the `Duration` division can never see a zero divisor.
pub fn send_delay(bw: u64, chunk_size: u32) -> Option<Duration> {
    if bw == 0 {
        return None;
    }

    let packets_per_second =
        (bw.saturating_mul(BYTES_PER_KIB) / chunk_size as u64).clamp(1, u32::MAX as u64) as u32;

    Some(Duration::from_secs(1) / packets_per_second)
}

fn connect_to(target: &str) -> io::Result<(UdpSocket, SocketAddr)> {
    let addr = target
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "could not resolve address"))?;

    // Match the bind family to the resolved target so we can reach IPv6 hosts.
    let bind_addr = match addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    Ok((UdpSocket::bind(bind_addr)?, addr))
}

pub fn run_send(file: &str, target: &str, config: SendConfig) -> io::Result<()> {
    let SendConfig {
        chunk_size,
        delay,
        version,
        reporter,
        limits,
    } = config;

    validate_chunk_size(chunk_size, version)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let mut f = File::open(file)?;
    let size = f.metadata()?.len();
    let total_chunks_u64 = size.div_ceil(chunk_size as u64);
    if total_chunks_u64 > MAX_TOTAL_CHUNKS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "file too large: {} chunks exceeds limit {}",
                total_chunks_u64, MAX_TOTAL_CHUNKS
            ),
        ));
    }
    let total_chunks = total_chunks_u64 as u32;

    let hash = file_hash(&mut f)?;

    let (sock, addr) = connect_to(target)?;

    let name = Path::new(file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file);

    let session = SendSession {
        sock: &sock,
        target: addr,
        chunk_size,
        total_chunks,
        delay,
        version,
        limits,
    };

    let receiver_addr = session.handshake(name, size, &hash)?;
    reporter.report(TransferEvent::Sending {
        name,
        bytes: size,
        chunks: total_chunks,
    });

    // Best-effort FIN-ACK so the receiver stops lingering immediately.
    let complete = || -> io::Result<()> {
        send_control(&sock, receiver_addr, PacketType::FinAck, 0)?;
        reporter.report(TransferEvent::Completed);
        Ok(())
    };

    let announce_pass = |pass, chunks: usize| {
        if chunks > 0 {
            reporter.report(TransferEvent::PassStarted { pass, chunks });
        }
    };

    let mut blast = Blast::new(chunk_size, version, total_chunks);
    let start = Instant::now();
    let mut pass = 1;
    announce_pass(pass, blast.pending.len());

    loop {
        if session.send_pending(&mut f, &mut blast, reporter, receiver_addr, start)? {
            return complete();
        }

        send_control(&sock, addr, PacketType::Done, total_chunks)?;
        match collect_feedback(&sock, receiver_addr, limits)? {
            Feedback::Complete => return complete(),
            Feedback::Retransmit(missing) => {
                pass += 1;
                if pass > limits.retransmit_passes {
                    return Err(io::Error::other(format!(
                        "gave up after {} passes",
                        limits.retransmit_passes
                    )));
                }
                blast.enqueue(missing);
                announce_pass(pass, blast.pending.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::NullReporter;
    use tempfile::tempdir;

    #[test]
    fn zero_bw_is_unlimited() {
        assert_eq!(send_delay(0, 1400), None);
    }

    #[test]
    fn typical_bw_matches_manual_rate() {
        // 512 KiB/s over 1400 B chunks = 374 pkt/s.
        assert_eq!(send_delay(512, 1400), Some(Duration::from_secs(1) / 374));
    }

    #[test]
    fn rate_below_one_packet_floors_at_one() {
        // 1 KiB/s with a 65500 B chunk rounds to 0 pkt/s; must floor to 1.
        assert_eq!(send_delay(1, 65500), Some(Duration::from_secs(1)));
    }

    #[test]
    fn pathological_rate_does_not_divide_by_zero() {
        // bw*1024/chunk == 2^32 here, which truncated to 0u32 and panicked on
        // Duration / 0 before the clamp. Now it caps at u32::MAX.
        assert_eq!(
            send_delay(4_194_304, 1),
            Some(Duration::from_secs(1) / u32::MAX)
        );
    }

    #[test]
    fn run_send_rejects_oversize_verify_chunk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"hello").unwrap();

        // MAX_CHUNK_SIZE leaves no room for the 32-byte per-chunk hash in v2.
        let err = run_send(
            path.to_str().unwrap(),
            "127.0.0.1:1",
            SendConfig {
                chunk_size: MAX_CHUNK_SIZE,
                delay: None,
                version: ProtocolVersion::V2,
                reporter: &NullReporter,
                limits: SendLimits::default(),
            },
        )
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("chunk size must be in"),
            "got: {}",
            err
        );
    }

    #[test]
    fn run_send_rejects_too_many_chunks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("big.bin");

        // Sparse: set_len reports the size without allocating blocks, and the
        // chunk-count check runs before the file is hashed, so nothing is read.
        let f = File::create(&path).unwrap();
        f.set_len(MAX_TOTAL_CHUNKS + 1).unwrap();
        drop(f);

        let err = run_send(
            path.to_str().unwrap(),
            "127.0.0.1:1",
            SendConfig {
                chunk_size: 1,
                delay: None,
                version: ProtocolVersion::V1,
                reporter: &NullReporter,
                limits: SendLimits::default(),
            },
        )
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("too large"), "got: {}", err);
    }

    #[test]
    fn collect_feedback_tolerates_malformed_feedback() {
        let sender_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let other_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = sender_sock.local_addr().unwrap();
        let receiver_addr = receiver_sock.local_addr().unwrap();

        receiver_sock.send_to(&[1, 2, 3], sender_addr).unwrap();
        other_sock
            .send_to(&[0u8; HEADER_SIZE], sender_addr)
            .unwrap();

        let mut overrun = vec![0u8; HEADER_SIZE];
        overrun[5..7].copy_from_slice(&9999u16.to_be_bytes());
        receiver_sock.send_to(&overrun, sender_addr).unwrap();

        // Header claims 5 NACK entries but carries only one, exercising the
        // truncated-batch break.
        let mut nack = vec![0u8; HEADER_SIZE + SEQUENCE_BYTES];
        nack[0] = PacketType::Nack as u8;
        nack[1..5].copy_from_slice(&5u32.to_be_bytes());
        nack[5..7].copy_from_slice(&(SEQUENCE_BYTES as u16).to_be_bytes());
        receiver_sock.send_to(&nack, sender_addr).unwrap();

        let mut fin = vec![0u8; HEADER_SIZE];
        fin[0] = PacketType::Fin as u8;
        receiver_sock.send_to(&fin, sender_addr).unwrap();

        let feedback =
            collect_feedback(&sender_sock, receiver_addr, SendLimits::default()).unwrap();
        assert!(
            matches!(feedback, Feedback::Complete),
            "FIN should end collection"
        );
    }

    #[test]
    fn handshake_survives_junk_before_ack() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = sock.local_addr().unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        receiver.send_to(&[9, 9, 9], sender_addr).unwrap();
        send_control(&receiver, sender_addr, PacketType::Ack, 0).unwrap();

        let session = SendSession {
            sock: &sock,
            target: receiver_addr,
            chunk_size: 1400,
            total_chunks: 1,
            delay: None,
            version: ProtocolVersion::V1,
            limits: SendLimits {
                handshake_attempts: 1,
                retransmit_timeout: Duration::from_millis(500),
                ..SendLimits::default()
            },
        };

        let from = session
            .handshake("f", 4, &[0u8; SHA256_DIGEST_SIZE])
            .unwrap();

        assert_eq!(from, receiver_addr);
    }

    #[test]
    fn handshake_aborts_on_socket_error() {
        use std::os::unix::io::AsRawFd;

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();

        let fd = sock.as_raw_fd();
        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
        });

        let session = SendSession {
            sock: &sock,
            target: target.local_addr().unwrap(),
            chunk_size: 1400,
            total_chunks: 1,
            delay: None,
            version: ProtocolVersion::V1,
            limits: SendLimits::default(),
        };

        let err = session
            .handshake("f", 4, &[0u8; SHA256_DIGEST_SIZE])
            .unwrap_err();
        killer.join().unwrap();

        assert_ne!(err.kind(), io::ErrorKind::TimedOut, "got: {}", err);
    }

    #[test]
    fn handshake_times_out_without_receiver() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"data").unwrap();

        // A bound socket that never answers: INITs are buffered, never ACKed.
        let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = blackhole.local_addr().unwrap();
        let config = SendConfig {
            chunk_size: 1400,
            delay: None,
            version: ProtocolVersion::V1,
            reporter: &NullReporter,
            limits: SendLimits {
                handshake_attempts: 2,
                retransmit_timeout: Duration::from_millis(50),
                ..SendLimits::default()
            },
        };

        let err = run_send(path.to_str().unwrap(), &dead_addr.to_string(), config).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            err.to_string().contains("handshake timeout"),
            "got: {}",
            err
        );
    }

    #[test]
    fn run_send_gives_up_after_passes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, vec![0u8; 1400]).unwrap();

        // Fake receiver: ACK the handshake, then NACK chunk 0 on every DONE and
        // never FIN, so the sender can never complete.
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; MAX_UDP_PAYLOAD];
            while let Ok((n, from)) = server.recv_from(&mut buf) {
                let Some(header) = decode_header(&buf[..n]) else {
                    continue;
                };
                match header.packet_type {
                    PacketType::Init => {
                        let ack = PacketHeader {
                            packet_type: PacketType::Ack,
                            seq: 0,
                            payload_len: 0,
                        };
                        let _ = send_packet(&server, from, &ack, &[]);
                    }
                    PacketType::Done => {
                        let nack = PacketHeader {
                            packet_type: PacketType::Nack,
                            seq: 1,
                            payload_len: SEQUENCE_BYTES as u16,
                        };
                        let _ = send_packet(&server, from, &nack, &0u32.to_be_bytes());
                    }
                    _ => {}
                }
            }
        });

        let config = SendConfig {
            chunk_size: 1400,
            delay: None,
            version: ProtocolVersion::V1,
            reporter: &NullReporter,
            limits: SendLimits {
                handshake_attempts: 5,
                retransmit_passes: 2,
                retransmit_timeout: Duration::from_millis(100),
                nack_collection_timeout: Duration::from_millis(50),
            },
        };

        let err = run_send(path.to_str().unwrap(), &server_addr.to_string(), config).unwrap_err();

        assert!(
            err.to_string().contains("gave up after 2 passes"),
            "got: {}",
            err
        );
        handle.join().unwrap();
    }

    #[test]
    fn drain_feedback_enqueues_nacked_chunks() {
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&3u32.to_be_bytes());
        send_packet(
            &receiver,
            sender_addr,
            &PacketHeader {
                packet_type: PacketType::Nack,
                seq: 2,
                payload_len: payload.len() as u16,
            },
            &payload,
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(20));

        let mut pending: VecDeque<u32> = VecDeque::new();
        let mut queued: HashSet<u32> = HashSet::new();
        let mut buf = [0u8; MAX_UDP_PAYLOAD];

        let fin =
            drain_feedback(&sender, receiver_addr, &mut buf, &mut pending, &mut queued).unwrap();

        assert!(!fin, "no FIN was sent");
        assert_eq!(pending.iter().copied().collect::<Vec<_>>(), vec![1, 3]);

        // A repeat NACK for an already-queued chunk must not double-enqueue it.
        send_packet(
            &receiver,
            sender_addr,
            &PacketHeader {
                packet_type: PacketType::Nack,
                seq: 1,
                payload_len: SEQUENCE_BYTES as u16,
            },
            &1u32.to_be_bytes(),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(20));
        drain_feedback(&sender, receiver_addr, &mut buf, &mut pending, &mut queued).unwrap();

        assert_eq!(pending.iter().copied().collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn drain_feedback_detects_fin() {
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        send_control(&receiver, sender_addr, PacketType::Fin, 0).unwrap();
        std::thread::sleep(Duration::from_millis(20));

        let mut pending: VecDeque<u32> = VecDeque::new();
        let mut queued: HashSet<u32> = HashSet::new();
        let mut buf = [0u8; MAX_UDP_PAYLOAD];

        let fin =
            drain_feedback(&sender, receiver_addr, &mut buf, &mut pending, &mut queued).unwrap();

        assert!(fin, "FIN should be detected");
    }
}
