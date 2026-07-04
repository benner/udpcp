// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

use std::io;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use udpcp::{
    DEFAULT_CHUNK_SIZE, DEFAULT_LINGER_SECONDS, ProtocolVersion, RecvConfig, RecvLimits,
    SendConfig, SendLimits, TransferReporter, run_receive, run_send, send_delay,
    validate_chunk_size,
};

use crate::jsonl_reporter::JsonlReporter;
use crate::text_reporter::TextReporter;

fn make_reporter(jsonl: bool, progress: bool) -> Box<dyn TransferReporter> {
    if jsonl {
        Box::new(JsonlReporter::new(progress))
    } else {
        Box::new(TextReporter::new(progress))
    }
}

#[derive(Parser)]
#[command(name = "udpcp", about = "UDP file copy — blast-and-NACK protocol")]
pub struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Send a file to a remote receiver
    Send {
        file: String,
        target: String,
        #[command(flatten)]
        args: SendArgs,
    },

    /// Receive a file on a local port
    Recv {
        port: u16,
        outfile: Option<String>,
        #[command(flatten)]
        args: RecvArgs,
    },
}

#[derive(Args)]
struct SendArgs {
    /// Bandwidth limit (0 = unlimited)
    #[arg(long, value_name = "KIB/S", default_value_t = 512)]
    bw: u64,

    /// Chunk size (1–65500; max 65468 with --verify)
    #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_CHUNK_SIZE)]
    chunk: u32,

    /// Show transfer progress bar
    #[arg(long)]
    progress: bool,

    /// Emit one JSON object per line (JSON Lines) instead of human output
    #[arg(long)]
    jsonl: bool,

    /// Prepend SHA-256 to each DATA chunk so the receiver can detect and
    /// retransmit corrupt packets (protocol v2)
    #[arg(long)]
    verify: bool,

    /// INIT handshake attempts before giving up
    #[arg(long, value_name = "COUNT", default_value_t = SendLimits::default().handshake_attempts)]
    handshake_attempts: usize,

    /// Blast/NACK passes before giving up
    #[arg(long, value_name = "COUNT", default_value_t = SendLimits::default().retransmit_passes)]
    retransmit_passes: usize,

    /// Per-attempt wait for ACK/feedback
    #[arg(long, value_name = "DURATION", default_value_t = SendLimits::default().retransmit_timeout.into())]
    retransmit_timeout: humantime::Duration,

    /// Extra wait after the first NACK to batch more
    #[arg(long, value_name = "DURATION", default_value_t = SendLimits::default().nack_collection_timeout.into())]
    nack_timeout: humantime::Duration,
}

#[derive(Args)]
struct RecvArgs {
    /// Show transfer progress bar
    #[arg(long)]
    progress: bool,

    /// Emit one JSON object per line (JSON Lines) instead of human output
    #[arg(long)]
    jsonl: bool,

    /// Keep listening after each transfer completes
    #[arg(long)]
    serve: bool,

    /// Re-send FIN after transfer in case the sender missed it
    #[arg(long, value_name = "DURATION", default_value_t = Duration::from_secs(DEFAULT_LINGER_SECONDS).into())]
    linger: humantime::Duration,

    /// Wait for the next packet before declaring the sender gone
    #[arg(long, value_name = "DURATION", default_value_t = RecvLimits::default().idle_timeout.into())]
    idle_timeout: humantime::Duration,

    /// Gap persistence before it is NACKed, to absorb reordering
    #[arg(long, value_name = "DURATION", default_value_t = RecvLimits::default().nack_holdoff.into())]
    nack_holdoff: humantime::Duration,
}

impl SendArgs {
    fn into_config(self, reporter: &dyn TransferReporter) -> SendConfig<'_> {
        SendConfig {
            chunk_size: self.chunk,
            delay: send_delay(self.bw, self.chunk),
            version: ProtocolVersion::for_verify(self.verify),
            reporter,
            limits: SendLimits {
                handshake_attempts: self.handshake_attempts,
                retransmit_passes: self.retransmit_passes,
                retransmit_timeout: self.retransmit_timeout.into(),
                nack_collection_timeout: self.nack_timeout.into(),
            },
        }
    }
}

impl RecvArgs {
    fn into_config(self, reporter: &dyn TransferReporter) -> RecvConfig<'_> {
        RecvConfig {
            serve: self.serve,
            linger_timeout: self.linger.into(),
            reporter,
            limits: RecvLimits {
                idle_timeout: self.idle_timeout.into(),
                nack_holdoff: self.nack_holdoff.into(),
            },
        }
    }
}

impl Cli {
    /// Validate the parsed arguments and dispatch to the matching transfer.
    pub fn run(self) -> io::Result<()> {
        match self.cmd {
            Cmd::Send { file, target, args } => {
                // Guard the chunk size before `into_config` runs `send_delay`,
                // which divides by it.
                validate_chunk_size(args.chunk, ProtocolVersion::for_verify(args.verify))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

                let reporter = make_reporter(args.jsonl, args.progress);
                run_send(&file, &target, args.into_config(reporter.as_ref()))
            }
            Cmd::Recv {
                port,
                outfile,
                args,
            } => {
                let reporter = make_reporter(args.jsonl, args.progress);
                run_receive(
                    port,
                    outfile.as_deref(),
                    args.into_config(reporter.as_ref()),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn send_flags_map_to_limits() {
        let cli = Cli::try_parse_from([
            "udpcp",
            "send",
            "file.bin",
            "host:9999",
            "--handshake-attempts",
            "9",
            "--retransmit-passes",
            "4",
            "--retransmit-timeout",
            "250ms",
            "--nack-timeout",
            "30ms",
        ])
        .unwrap();

        match cli.cmd {
            Cmd::Send { args, .. } => {
                assert_eq!(args.handshake_attempts, 9);
                assert_eq!(args.retransmit_passes, 4);
                assert_eq!(*args.retransmit_timeout, Duration::from_millis(250));
                assert_eq!(*args.nack_timeout, Duration::from_millis(30));
            }
            Cmd::Recv { .. } => panic!("expected send subcommand"),
        }
    }

    #[test]
    fn send_flags_default_to_module_constants() {
        let cli = Cli::try_parse_from(["udpcp", "send", "file.bin", "host:9999"]).unwrap();
        let defaults = SendLimits::default();

        match cli.cmd {
            Cmd::Send { args, .. } => {
                assert_eq!(args.handshake_attempts, defaults.handshake_attempts);
                assert_eq!(args.retransmit_passes, defaults.retransmit_passes);
                assert_eq!(*args.retransmit_timeout, defaults.retransmit_timeout);
                assert_eq!(*args.nack_timeout, defaults.nack_collection_timeout);
            }
            Cmd::Recv { .. } => panic!("expected send subcommand"),
        }
    }

    #[test]
    fn recv_idle_timeout_defaults_to_module_constant() {
        let cli = Cli::try_parse_from(["udpcp", "recv", "9999"]).unwrap();

        match cli.cmd {
            Cmd::Recv { args, .. } => {
                assert_eq!(*args.idle_timeout, RecvLimits::default().idle_timeout);
            }
            Cmd::Send { .. } => panic!("expected recv subcommand"),
        }
    }

    #[test]
    fn recv_rejects_non_port_values() {
        assert!(Cli::try_parse_from(["udpcp", "recv", "70000"]).is_err());
        assert!(Cli::try_parse_from(["udpcp", "recv", "abc"]).is_err());
    }

    #[test]
    fn send_subcommand_parses_positionals() {
        let cli = Cli::try_parse_from(["udpcp", "send", "file.bin", "host:9999"]).unwrap();

        match cli.cmd {
            Cmd::Send { file, target, .. } => {
                assert_eq!(file, "file.bin");
                assert_eq!(target, "host:9999");
            }
            Cmd::Recv { .. } => panic!("expected send subcommand"),
        }
    }
}
