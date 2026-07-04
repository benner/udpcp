// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

//! Output channel for transfer progress and status.
//!
//! The library emits semantic [`TransferEvent`]s and never writes to stdout
//! itself; the caller supplies a [`TransferReporter`] that decides where the
//! events go, how they are formatted, and whether to act on them.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

/// A fact the transfer wants to surface to its caller. Carries raw values
/// (bytes, chunk counts, elapsed time); any percentage or rate is the
/// reporter's to compute.
pub enum TransferEvent<'a> {
    /// Handshake done; the blast is about to start.
    Sending {
        name: &'a str,
        bytes: u64,
        chunks: u32,
    },

    /// A blast/retransmit pass over the listed number of pending chunks.
    PassStarted { pass: usize, chunks: usize },

    /// One chunk has just been sent or stored.
    Progress {
        done: u32,
        total: u32,
        chunk_size: u32,
        elapsed: Duration,
    },

    /// The receiver FINed: every chunk is in.
    Completed,

    /// The receiver is bound and waiting for an INIT.
    Listening { addr: SocketAddr },

    /// An INIT was accepted; chunks will follow.
    Receiving {
        path: &'a Path,
        bytes: u64,
        chunks: u32,
        chunk_size: u32,
    },

    /// A DONE arrived before every chunk did; this many are still missing.
    MissingChunks { count: usize },

    /// The file passed its SHA-256 check and was renamed into place.
    Saved {
        path: &'a Path,
        bytes: u64,
        elapsed: Duration,
    },

    /// An INIT could not be parsed; the receiver keeps waiting.
    BadInit { reason: &'a str },

    /// The transfer was abandoned — write failure, integrity mismatch, or
    /// idle timeout; a serving receiver resets and keeps listening.
    Failed { reason: &'a str },
}

/// Sink for [`TransferEvent`]s. Implementors own formatting, the output
/// destination, and any side effects. `Sync` so a `&dyn TransferReporter` can
/// ride along in a config moved onto a transfer thread.
pub trait TransferReporter: Sync {
    fn report(&self, event: TransferEvent<'_>);
}

/// A reporter that discards every event — the default for embedders and tests
/// that only care about the transferred bytes.
pub struct NullReporter;

impl TransferReporter for NullReporter {
    fn report(&self, _event: TransferEvent<'_>) {}
}
