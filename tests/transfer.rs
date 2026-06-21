// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rand::{RngExt, SeedableRng};
use rand_pcg::Pcg64Mcg;

use tempfile::tempdir;
use udpcp::{
    NullReporter, ProtocolVersion, RecvConfig, RecvLimits, SendConfig, SendLimits, receive_loop,
    run_send,
};

const REORDER_DELAY: Duration = Duration::from_millis(20);
// Shorter linger than the 15 s production default to keep the suite fast. 5 s
// covers one RETRANSMIT_TIMEOUT (3 s) above the sender's DONE-retry gap, so a
// dropped FIN under 15% loss still recovers; 500 ms flaked loss_15pct in CI.
const TEST_LINGER: Duration = Duration::from_secs(5);

/// A UDP relay that injects packet loss, latency, reordering, duplication, and
/// corruption between a sender and a receiver to simulate real network
/// conditions in tests.
struct ChaosProxy {
    addr: SocketAddr,
    _sock: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
}

impl ChaosProxy {
    fn new(
        target: SocketAddr,
        loss: f64,
        latency: Duration,
        reorder: f64,
        duplicate: f64,
        corrupt: f64,
    ) -> io::Result<Self> {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0")?);
        // Short poll interval so the stop flag is checked promptly after the test.
        sock.set_read_timeout(Some(Duration::from_millis(100)))?;
        let addr = sock.local_addr()?;
        let sock2 = Arc::clone(&sock);
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let client2 = Arc::clone(&client);

        thread::spawn(move || {
            let mut buf = vec![0u8; 65507];
            let mut rng = Pcg64Mcg::seed_from_u64(42);
            loop {
                if stop2.load(Ordering::Relaxed) {
                    return;
                }
                let (n, from) = match sock2.recv_from(&mut buf) {
                    Ok(r) => r,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => return,
                };
                let mut pkt: Vec<u8> = buf[..n].to_vec();

                let mut cl = client2.lock().unwrap();
                if cl.is_none() {
                    *cl = Some(from);
                }
                let client_addr = cl.unwrap();
                drop(cl);

                let dst = if from == target { client_addr } else { target };

                if rng.random::<f64>() < loss {
                    continue;
                }

                if rng.random::<f64>() < corrupt && !pkt.is_empty() {
                    let byte_idx = rng.random_range(0..pkt.len());
                    let bit_idx: u8 = rng.random_range(0..8);
                    pkt[byte_idx] ^= 1 << bit_idx;
                }

                if rng.random::<f64>() < duplicate {
                    let sock_dup = Arc::clone(&sock2);
                    let pkt_dup = pkt.clone();
                    thread::spawn(move || {
                        let _ = sock_dup.send_to(&pkt_dup, dst);
                    });
                }

                let mut delay = if latency > Duration::ZERO {
                    latency
                        + Duration::from_millis(
                            rng.random_range(0..=latency.as_millis() as u64 / 2),
                        )
                } else {
                    Duration::ZERO
                };
                if rng.random::<f64>() < reorder {
                    delay += REORDER_DELAY;
                }
                let sock3 = Arc::clone(&sock2);
                thread::spawn(move || {
                    if delay > Duration::ZERO {
                        thread::sleep(delay);
                    }
                    let _ = sock3.send_to(&pkt, dst);
                });
            }
        });

        Ok(ChaosProxy {
            addr,
            _sock: sock,
            stop,
        })
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for ChaosProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn run_transfer(
    file_size: usize,
    loss: f64,
    latency: Duration,
    reorder: f64,
    duplicate: f64,
    verify: bool,
    corrupt: f64,
) -> io::Result<()> {
    run_transfer_inner(
        file_size, loss, latency, reorder, duplicate, verify, corrupt,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_transfer_inner(
    file_size: usize,
    loss: f64,
    latency: Duration,
    reorder: f64,
    duplicate: f64,
    verify: bool,
    corrupt: f64,
) -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let src = dir.path().join("src.bin");
    let dst = dir.path().join("dst.bin");

    let want: Vec<u8> = (0..file_size)
        .map(|i| (i.wrapping_mul(7).wrapping_add(13)) as u8)
        .collect();
    std::fs::write(&src, &want)?;

    let recv_sock = UdpSocket::bind("127.0.0.1:0")?;
    let recv_addr = recv_sock.local_addr()?;
    let dst_path = dst.clone();

    let recv_handle = thread::spawn(move || {
        receive_loop(
            &recv_sock,
            Some(dst_path.to_str().unwrap()),
            RecvConfig {
                serve: false,
                linger_timeout: TEST_LINGER,
                reporter: &NullReporter,
                limits: RecvLimits::default(),
            },
        )
    });

    let proxy = ChaosProxy::new(recv_addr, loss, latency, reorder, duplicate, corrupt)?;
    run_send(
        src.to_str().unwrap(),
        &proxy.addr().to_string(),
        SendConfig {
            chunk_size: 1400,
            delay: None,
            version: ProtocolVersion::for_verify(verify),
            reporter: &NullReporter,
            limits: SendLimits::default(),
        },
    )?;
    recv_handle.join().unwrap()?;

    let got = std::fs::read(&dst)?;
    if got != want {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "content mismatch: got {} bytes, want {}",
                got.len(),
                want.len()
            ),
        ));
    }
    Ok(())
}

#[test]
fn empty_file() {
    run_transfer(0, 0.0, Duration::ZERO, 0.0, 0.0, false, 0.0).unwrap();
}

#[test]
fn single_byte() {
    run_transfer(1, 0.0, Duration::ZERO, 0.0, 0.0, false, 0.0).unwrap();
}

#[test]
fn sub_chunk() {
    run_transfer(512, 0.0, Duration::ZERO, 0.0, 0.0, false, 0.0).unwrap();
}

#[test]
fn exact_chunk() {
    run_transfer(1400, 0.0, Duration::ZERO, 0.0, 0.0, false, 0.0).unwrap();
}

#[test]
fn multi_chunk() {
    run_transfer(10 * 1400, 0.0, Duration::ZERO, 0.0, 0.0, false, 0.0).unwrap();
}

#[test]
fn large() {
    run_transfer(100 * 1400, 0.0, Duration::ZERO, 0.0, 0.0, false, 0.0).unwrap();
}

#[test]
fn loss_5pct() {
    run_transfer(20 * 1400, 0.05, Duration::ZERO, 0.0, 0.0, false, 0.0).unwrap();
}

#[test]
fn loss_15pct() {
    run_transfer(20 * 1400, 0.15, Duration::ZERO, 0.0, 0.0, false, 0.0).unwrap();
}

#[test]
fn latency_10ms() {
    run_transfer(
        10 * 1400,
        0.0,
        Duration::from_millis(10),
        0.0,
        0.0,
        false,
        0.0,
    )
    .unwrap();
}

#[test]
fn latency_50ms() {
    run_transfer(
        5 * 1400,
        0.0,
        Duration::from_millis(50),
        0.0,
        0.0,
        false,
        0.0,
    )
    .unwrap();
}

#[test]
fn loss_10pct_latency_20ms() {
    run_transfer(
        10 * 1400,
        0.10,
        Duration::from_millis(20),
        0.0,
        0.0,
        false,
        0.0,
    )
    .unwrap();
}

#[test]
fn reorder_10pct() {
    run_transfer(10 * 1400, 0.0, Duration::ZERO, 0.10, 0.0, false, 0.0).unwrap();
}

#[test]
fn duplicate_5pct() {
    run_transfer(10 * 1400, 0.0, Duration::ZERO, 0.0, 0.05, false, 0.0).unwrap();
}

#[test]
fn verify_no_fault() {
    run_transfer(10 * 1400, 0.0, Duration::ZERO, 0.0, 0.0, true, 0.0).unwrap();
}

#[test]
fn verify_corrupt_5pct() {
    run_transfer(10 * 1400, 0.0, Duration::ZERO, 0.0, 0.0, true, 0.05).unwrap();
}

#[test]
fn ipv6_loopback_transfer() {
    // Exercises the sender's IPv6 bind-family branch; all other tests target
    // 127.0.0.1 and only reach the IPv4 arm.
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.bin");
    let dst = dir.path().join("dst.bin");
    let want: Vec<u8> = (0..3000).map(|i| (i * 5 + 2) as u8).collect();
    std::fs::write(&src, &want).unwrap();

    let recv_sock = UdpSocket::bind("[::1]:0").unwrap();
    let recv_addr = recv_sock.local_addr().unwrap();
    let dst_path = dst.clone();
    let recv = thread::spawn(move || {
        receive_loop(
            &recv_sock,
            Some(dst_path.to_str().unwrap()),
            RecvConfig {
                serve: false,
                linger_timeout: TEST_LINGER,
                reporter: &NullReporter,
                limits: RecvLimits::default(),
            },
        )
    });

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
    recv.join().unwrap().unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), want);
}

#[test]
fn serve_mode_two_transfers() {
    let dir = tempdir().unwrap();
    let src1 = dir.path().join("src1.bin");
    let src2 = dir.path().join("src2.bin");
    let dst = dir.path().join("dst.bin");

    let want1: Vec<u8> = (0..1400).map(|i| i as u8).collect();
    let want2: Vec<u8> = (0..2800).map(|i| (i * 7) as u8).collect();
    std::fs::write(&src1, &want1).unwrap();
    std::fs::write(&src2, &want2).unwrap();

    let recv_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let recv_addr = recv_sock.local_addr().unwrap();
    let dst_str = dst.to_str().unwrap().to_string();

    thread::spawn(move || {
        let _ = receive_loop(
            &recv_sock,
            Some(&dst_str),
            RecvConfig {
                serve: true,
                linger_timeout: TEST_LINGER,
                reporter: &NullReporter,
                limits: RecvLimits::default(),
            },
        );
    });

    let send_config = SendConfig {
        chunk_size: 1400,
        delay: None,
        version: ProtocolVersion::V1,
        reporter: &NullReporter,
        limits: SendLimits::default(),
    };
    run_send(src1.to_str().unwrap(), &recv_addr.to_string(), send_config).unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), want1);

    run_send(src2.to_str().unwrap(), &recv_addr.to_string(), send_config).unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), want2);
}
