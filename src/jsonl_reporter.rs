// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

//! JSON Lines rendering of [`TransferEvent`]s: one JSON object per line on
//! stdout, for machine consumption.

use std::io::{self, Write};
use std::sync::atomic::{AtomicI32, Ordering};

use serde_json::{Value, json};
use udpcp::{TransferEvent, TransferReporter};

pub struct JsonlReporter {
    progress: bool,
    last_pct: AtomicI32,
}

impl JsonlReporter {
    pub fn new(progress: bool) -> Self {
        JsonlReporter {
            progress,
            last_pct: AtomicI32::new(-1),
        }
    }

    fn event_value(&self, event: TransferEvent<'_>) -> Option<Value> {
        let value = match event {
            TransferEvent::Sending {
                name,
                bytes,
                chunks,
            } => json!({"event": "sending", "name": name, "bytes": bytes, "chunks": chunks}),
            TransferEvent::PassStarted { pass, chunks } => {
                if !self.progress {
                    return None;
                }

                json!({"event": "pass", "pass": pass, "chunks": chunks})
            }
            TransferEvent::Progress {
                done,
                total,
                elapsed,
                ..
            } => {
                if !self.progress || total == 0 {
                    return None;
                }

                let pct = (done as u64 * 100 / total as u64) as i32;
                // Throttle to one line per whole-percent change.
                if self.last_pct.swap(pct, Ordering::Relaxed) == pct {
                    return None;
                }

                json!({
                    "event": "progress",
                    "done": done,
                    "total": total,
                    "pct": pct,
                    "elapsed_ms": elapsed.as_millis() as u64,
                })
            }
            TransferEvent::Completed => json!({"event": "completed"}),
            TransferEvent::Listening { addr } => {
                json!({"event": "listening", "addr": addr.to_string()})
            }
            TransferEvent::Receiving {
                path,
                bytes,
                chunks,
                chunk_size,
            } => json!({
                "event": "receiving",
                "path": path.display().to_string(),
                "bytes": bytes,
                "chunks": chunks,
                "chunk_size": chunk_size,
            }),
            TransferEvent::MissingChunks { count } => {
                if !self.progress {
                    return None;
                }

                json!({"event": "missing", "count": count})
            }
            TransferEvent::Saved {
                path,
                bytes,
                elapsed,
            } => json!({
                "event": "saved",
                "path": path.display().to_string(),
                "bytes": bytes,
                "elapsed_ms": elapsed.as_millis() as u64,
            }),
            TransferEvent::BadInit { reason } => json!({"event": "bad_init", "reason": reason}),
            TransferEvent::Failed { reason } => json!({"event": "failed", "reason": reason}),
        };

        Some(value)
    }

    fn render(&self, event: TransferEvent<'_>, out: &mut impl Write) {
        if let Some(value) = self.event_value(event) {
            let _ = writeln!(out, "{}", value);
        }
    }
}

impl TransferReporter for JsonlReporter {
    fn report(&self, event: TransferEvent<'_>) {
        let stdout = io::stdout();
        self.render(event, &mut stdout.lock());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::Duration;

    fn line(reporter: &JsonlReporter, event: TransferEvent<'_>) -> String {
        let mut out = Vec::new();
        reporter.render(event, &mut out);

        String::from_utf8(out).unwrap()
    }

    fn parse(s: &str) -> Value {
        serde_json::from_str(s.trim_end()).unwrap()
    }

    #[test]
    fn milestones_render_one_object_per_line() {
        let r = JsonlReporter::new(false);
        let v = parse(&line(
            &r,
            TransferEvent::Sending {
                name: "f.bin",
                bytes: 5000,
                chunks: 4,
            },
        ));

        assert_eq!(v["event"], "sending");
        assert_eq!(v["name"], "f.bin");
        assert_eq!(v["bytes"], 5000);
        assert_eq!(v["chunks"], 4);

        let saved = parse(&line(
            &r,
            TransferEvent::Saved {
                path: Path::new("out.bin"),
                bytes: 2048,
                elapsed: Duration::from_millis(500),
            },
        ));

        assert_eq!(saved["event"], "saved");
        assert_eq!(saved["path"], "out.bin");
        assert_eq!(saved["elapsed_ms"], 500);
    }

    #[test]
    fn bad_init_reason_is_escaped() {
        let r = JsonlReporter::new(false);
        let out = line(
            &r,
            TransferEvent::BadInit {
                reason: "weird \"name\"\twith ctrl",
            },
        );

        // Valid JSON despite quotes and a tab in the string.
        let v = parse(&out);

        assert_eq!(v["event"], "bad_init");
        assert_eq!(v["reason"], "weird \"name\"\twith ctrl");
    }

    #[test]
    fn failed_event_renders_reason() {
        let r = JsonlReporter::new(false);
        let v = parse(&line(
            &r,
            TransferEvent::Failed {
                reason: "integrity check failed: SHA-256 mismatch",
            },
        ));

        assert_eq!(v["event"], "failed");
        assert_eq!(v["reason"], "integrity check failed: SHA-256 mismatch");
    }

    #[test]
    fn progress_throttles_to_whole_percent() {
        let r = JsonlReporter::new(true);
        let ev = |done| TransferEvent::Progress {
            done,
            total: 200,
            chunk_size: 1400,
            elapsed: Duration::from_secs(1),
        };

        assert!(!line(&r, ev(0)).is_empty()); // 0% — first
        assert!(line(&r, ev(1)).is_empty()); // still 0% — throttled
        assert!(!line(&r, ev(2)).is_empty()); // 1% — emitted
        assert!(line(&r, ev(3)).is_empty()); // still 1% — throttled
    }

    #[test]
    fn progress_pass_and_missing_are_gated_by_progress_flag() {
        let quiet = JsonlReporter::new(false);

        assert!(
            line(&quiet, TransferEvent::PassStarted { pass: 1, chunks: 4 }).is_empty(),
            "pass should be silent without --progress"
        );
        assert!(
            line(&quiet, TransferEvent::MissingChunks { count: 3 }).is_empty(),
            "missing should be silent without --progress"
        );
        assert!(
            line(
                &quiet,
                TransferEvent::Progress {
                    done: 1,
                    total: 4,
                    chunk_size: 1400,
                    elapsed: Duration::from_secs(1),
                },
            )
            .is_empty(),
            "progress should be silent without --progress"
        );

        assert!(!line(&quiet, TransferEvent::Completed).is_empty());
    }

    #[test]
    fn zero_total_progress_is_silent() {
        let r = JsonlReporter::new(true);

        assert!(
            line(
                &r,
                TransferEvent::Progress {
                    done: 0,
                    total: 0,
                    chunk_size: 1400,
                    elapsed: Duration::from_secs(1),
                },
            )
            .is_empty()
        );
    }
}
