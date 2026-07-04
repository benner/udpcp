// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

// Integration test: verify that SIGTERM during an in-progress receive cleans
// up the sibling .tmp file. Lives in tests/ so cargo gives us the binary path
// via the CARGO_BIN_EXE_udpcp env var.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[test]
fn sigterm_cleans_up_tmp_file() {
    let bin = env!("CARGO_BIN_EXE_udpcp");
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.bin");
    let dst = dir.path().join("dst.bin");
    let tmp = dir.path().join("dst.bin.tmp");

    // 8 MiB at --bw 16 KiB/s runs for minutes, long enough that the receiver is
    // reliably mid-transfer when we signal it.
    std::fs::write(&src, vec![0xab; 8 * 1024 * 1024]).unwrap();

    // Receiver on port 0: the kernel picks one and we read it back from the
    // "listening on" line, keeping the test parallel-safe.
    let mut recv = Command::new(bin)
        .args(["recv", "0", dst.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let stdout = recv.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let port = line
        .trim()
        .rsplit(':')
        .next()
        .expect("listening line")
        .to_string();

    // Drain remaining stdout so the pipe never fills.
    std::thread::spawn(move || {
        let mut sink = String::new();
        while reader.read_line(&mut sink).unwrap_or(0) > 0 {
            sink.clear();
        }
    });

    let mut send = Command::new(bin)
        .args([
            "send",
            src.to_str().unwrap(),
            &format!("127.0.0.1:{}", port),
            "--bw",
            "16",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !tmp.exists() {
        sleep(Duration::from_millis(50));
    }
    assert!(tmp.exists(), "expected .tmp to be created within 10 s");

    let kill_ok = Command::new("kill")
        .args(["-TERM", &recv.id().to_string()])
        .status()
        .unwrap()
        .success();
    assert!(kill_ok, "kill -TERM failed");

    let mut recv_stderr = recv.stderr.take().unwrap();
    let status = recv.wait().unwrap();
    let _ = send.kill();
    let _ = send.wait();

    assert!(
        !tmp.exists(),
        ".tmp still present after receiver caught SIGTERM"
    );
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "receiver should die by SIGTERM's default disposition, got {:?}",
        status
    );

    let mut stderr = String::new();
    recv_stderr.read_to_string(&mut stderr).unwrap();
    assert!(
        stderr.is_empty(),
        "interrupt must not report an error, got: {}",
        stderr
    );
}
