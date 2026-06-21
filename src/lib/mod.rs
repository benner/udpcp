// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

//! UDP file copy — blast-and-NACK protocol with SHA-256 integrity.

mod protocol;
mod recv;
mod report;
mod send;

pub use protocol::{
    DEFAULT_CHUNK_SIZE, DEFAULT_LINGER_SECONDS, ProtocolVersion, RecvConfig, RecvLimits,
    SendConfig, SendLimits, validate_chunk_size,
};
pub use recv::{receive_loop, run_receive};
pub use report::{NullReporter, TransferEvent, TransferReporter};
pub use send::{run_send, send_delay};
