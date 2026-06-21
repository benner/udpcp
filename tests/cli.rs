// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

// Integration tests that drive the compiled binary so the CLI shell in
// main.rs (argument validation, error-exit codes, dispatch) and the
// run_receive/install_shutdown_handler entry points are exercised. cargo
// llvm-cov captures spawned children that exit normally, including via
// std::process::exit, so these count toward coverage.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_udpcp")
}

#[test]
fn rejects_zero_chunk_size() {
    let out = Command::new(bin())
        .args(["send", "--chunk", "0", "/no/such/udpcp/file", "127.0.0.1:9"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("chunk size must be in"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn send_missing_file_reports_error() {
    let out = Command::new(bin())
        .args(["send", "/no/such/udpcp/file", "127.0.0.1:9"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("error:"), "stderr: {}", stderr);
}

#[test]
fn round_trip_via_binary() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.bin");
    let dst = dir.path().join("dst.bin");
    let want: Vec<u8> = (0..4000).map(|i| (i * 3 + 1) as u8).collect();
    std::fs::write(&src, &want).unwrap();

    // Receiver on port 0: the kernel picks one, read back from "listening on".
    // Short linger so the receiver returns promptly once the sender exits,
    // instead of holding the default 15 s FIN-resend window.
    let mut recv = Command::new(bin())
        .args(["recv", "0", dst.to_str().unwrap(), "--linger", "1s"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
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

    // Drain the rest so the pipe never blocks the receiver on a full buffer.
    std::thread::spawn(move || {
        let mut sink = String::new();
        while reader.read_line(&mut sink).unwrap_or(0) > 0 {
            sink.clear();
        }
    });

    let send = Command::new(bin())
        .args([
            "send",
            src.to_str().unwrap(),
            &format!("127.0.0.1:{}", port),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(send.success(), "sender exited with {:?}", send.code());

    let recv_status = recv.wait().unwrap();
    assert!(
        recv_status.success(),
        "receiver exited with {:?}",
        recv_status.code()
    );
    assert_eq!(std::fs::read(&dst).unwrap(), want);
}
