// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

//! Terminal rendering of [`TransferEvent`]s for the `udpcp` binary.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use udpcp::{TransferEvent, TransferReporter};

const PROGRESS_BAR_WIDTH: usize = 50;
const BYTES_PER_KIB: f64 = 1024.0;

/// Renders events to stdout (status lines and the progress bar) and stderr
/// (diagnostics). `progress` gates the per-chunk bar and the pass/missing
/// lines; `bar_active` tracks whether the in-place bar still owns the current
/// line so the next status line starts cleanly.
pub struct TextReporter {
    progress: bool,
    bar_active: AtomicBool,
}

impl TextReporter {
    pub fn new(progress: bool) -> Self {
        TextReporter {
            progress,
            bar_active: AtomicBool::new(false),
        }
    }

    fn draw_progress_bar(
        &self,
        done: u32,
        total: u32,
        chunk_size: u32,
        elapsed: Duration,
        out: &mut impl Write,
    ) {
        if !self.progress || total == 0 {
            return;
        }

        let pct = done as f64 / total as f64 * 100.0;
        let secs = elapsed.as_secs_f64().max(0.001);
        let kib_per_s = done as f64 * chunk_size as f64 / secs / BYTES_PER_KIB;
        let filled = ((pct / 2.0) as usize).min(PROGRESS_BAR_WIDTH);
        let bar = "#".repeat(filled) + &".".repeat(PROGRESS_BAR_WIDTH - filled);

        let _ = write!(
            out,
            "\r[{}] {:5.1}%  {}/{}  {:.0} KiB/s",
            bar, pct, done, total, kib_per_s
        );

        let _ = out.flush();
        self.bar_active.store(true, Ordering::Relaxed);
    }

    fn render(&self, event: TransferEvent<'_>, out: &mut impl Write, err: &mut impl Write) {
        if let TransferEvent::Progress {
            done,
            total,
            chunk_size,
            elapsed,
        } = event
        {
            self.draw_progress_bar(done, total, chunk_size, elapsed, out);
            return;
        }

        // Any non-progress line must start fresh, so close a pending bar first.
        if self.bar_active.swap(false, Ordering::Relaxed) {
            let _ = writeln!(out);
        }

        match event {
            TransferEvent::Sending {
                name,
                bytes,
                chunks,
            } => {
                let _ = writeln!(out, "sending {}  {} bytes  {} chunks", name, bytes, chunks);
            }
            TransferEvent::PassStarted { pass, chunks } => {
                if self.progress {
                    let _ = writeln!(out, "pass {}  {} chunks", pass, chunks);
                }
            }
            TransferEvent::Completed => {
                let _ = writeln!(out, "✓ transfer complete");
            }
            TransferEvent::Listening { addr } => {
                let _ = writeln!(out, "listening on {}", addr);
            }
            TransferEvent::Receiving {
                path,
                bytes,
                chunks,
                chunk_size,
            } => {
                let _ = writeln!(
                    out,
                    "receiving {}  {} bytes  {} chunks  chunk={}",
                    path.display(),
                    bytes,
                    chunks,
                    chunk_size
                );
            }
            TransferEvent::MissingChunks { count } => {
                if self.progress {
                    let _ = writeln!(out, "  {} missing", count);
                }
            }
            TransferEvent::Saved {
                path,
                bytes,
                elapsed,
            } => {
                let secs = elapsed.as_secs_f64().max(0.001);
                let mib_per_s = bytes as f64 / secs / BYTES_PER_KIB / BYTES_PER_KIB;

                let _ = writeln!(
                    out,
                    "✓ saved {}  {:.2} MiB/s avg",
                    path.display(),
                    mib_per_s
                );
            }
            TransferEvent::BadInit { reason } => {
                let _ = writeln!(err, "bad init packet: {}", reason);
            }
            TransferEvent::Progress { .. } => unreachable!("handled above"),
        }
    }
}

impl TransferReporter for TextReporter {
    fn report(&self, event: TransferEvent<'_>) {
        let stdout = io::stdout();
        let stderr = io::stderr();

        self.render(event, &mut stdout.lock(), &mut stderr.lock());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::Duration;

    fn render(reporter: &TextReporter, event: TransferEvent<'_>) -> (String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();

        reporter.render(event, &mut out, &mut err);

        (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn status_lines_render_without_progress() {
        let r = TextReporter::new(false);

        assert_eq!(
            render(
                &r,
                TransferEvent::Sending {
                    name: "f.bin",
                    bytes: 5000,
                    chunks: 4
                }
            )
            .0,
            "sending f.bin  5000 bytes  4 chunks\n"
        );
        assert_eq!(
            render(&r, TransferEvent::Completed).0,
            "✓ transfer complete\n"
        );
        assert_eq!(
            render(
                &r,
                TransferEvent::Receiving {
                    path: Path::new("out.bin"),
                    bytes: 5000,
                    chunks: 4,
                    chunk_size: 1400
                }
            )
            .0,
            "receiving out.bin  5000 bytes  4 chunks  chunk=1400\n"
        );
        assert_eq!(
            render(
                &r,
                TransferEvent::Saved {
                    path: Path::new("out.bin"),
                    bytes: 2 * 1024 * 1024,
                    elapsed: Duration::from_secs(1)
                }
            )
            .0,
            "✓ saved out.bin  2.00 MiB/s avg\n"
        );
    }

    #[test]
    fn bad_init_goes_to_stderr() {
        let r = TextReporter::new(false);
        let (out, err) = render(&r, TransferEvent::BadInit { reason: "boom" });

        assert!(out.is_empty());
        assert_eq!(err, "bad init packet: boom\n");
    }

    #[test]
    fn pass_and_missing_lines_are_progress_gated() {
        let quiet = TextReporter::new(false);

        assert!(
            render(&quiet, TransferEvent::PassStarted { pass: 1, chunks: 4 })
                .0
                .is_empty()
        );
        assert!(
            render(&quiet, TransferEvent::MissingChunks { count: 3 })
                .0
                .is_empty()
        );

        let loud = TextReporter::new(true);

        assert_eq!(
            render(&loud, TransferEvent::PassStarted { pass: 2, chunks: 4 }).0,
            "pass 2  4 chunks\n"
        );
        assert_eq!(
            render(&loud, TransferEvent::MissingChunks { count: 3 }).0,
            "  3 missing\n"
        );
    }

    #[test]
    fn progress_bar_renders_only_when_enabled() {
        let quiet = TextReporter::new(false);

        assert!(
            render(
                &quiet,
                TransferEvent::Progress {
                    done: 2,
                    total: 4,
                    chunk_size: 1400,
                    elapsed: Duration::from_secs(1)
                }
            )
            .0
            .is_empty()
        );

        let loud = TextReporter::new(true);
        let bar = render(
            &loud,
            TransferEvent::Progress {
                done: 2,
                total: 4,
                chunk_size: 1400,
                elapsed: Duration::from_secs(1),
            },
        )
        .0;

        assert!(bar.starts_with("\r["), "got: {:?}", bar);
        assert!(bar.contains("50.0%"), "got: {:?}", bar);
    }

    #[test]
    fn zero_total_progress_does_not_panic() {
        let loud = TextReporter::new(true);

        assert!(
            render(
                &loud,
                TransferEvent::Progress {
                    done: 0,
                    total: 0,
                    chunk_size: 1400,
                    elapsed: Duration::from_secs(1)
                }
            )
            .0
            .is_empty()
        );
    }

    #[test]
    fn active_bar_is_closed_before_the_next_line() {
        let loud = TextReporter::new(true);
        render(
            &loud,
            TransferEvent::Progress {
                done: 4,
                total: 4,
                chunk_size: 1400,
                elapsed: Duration::from_secs(1),
            },
        );

        // The bar left the cursor mid-line, so the next status line is newline-prefixed.
        assert_eq!(
            render(&loud, TransferEvent::Completed).0,
            "\n✓ transfer complete\n"
        );
    }
}
