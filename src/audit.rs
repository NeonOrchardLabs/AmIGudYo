use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;
const REDACTED_MESSAGE: &str = "[redacted: credential-like content]";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub sequence: u64,
    pub elapsed_ms: u128,
    pub level: String,
    pub message: String,
}

#[derive(Clone)]
pub struct Audit {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    enabled: bool,
    log_path: Option<PathBuf>,
    writer: Option<BufWriter<File>>,
    bytes_written: u64,
    stopped: Option<StopReason>,
    events: Vec<Event>,
    next_sequence: u64,
    started: Instant,
}

#[derive(Clone, Copy)]
enum StopReason {
    SizeLimit,
    AppendFailure,
}

impl Audit {
    /// Creates a memory-backed audit log. `None` never touches the filesystem.
    /// A persistent JSONL log is opened only when logging is enabled and a path is supplied.
    pub fn new(enabled: bool, log_path: Option<PathBuf>) -> Result<Self> {
        let mut inner = Inner {
            enabled,
            log_path,
            writer: None,
            bytes_written: 0,
            stopped: None,
            events: Vec::new(),
            next_sequence: 0,
            started: Instant::now(),
        };

        if enabled {
            inner.open_persistent_log()?;
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Records an event in memory and, when configured, as one JSONL record.
    /// Message redaction is a conservative heuristic, not a guarantee that arbitrary text
    /// can never contain sensitive information.
    pub fn log(&mut self, level: &str, message: impl Into<String>) {
        let level = redact_if_credential_like(level);
        let message = redact_if_credential_like(&message.into());
        let mut inner = self.lock_inner();
        if !inner.enabled {
            return;
        }

        let event = inner.push_event(level, message);
        inner.append_event(&event);
    }

    pub fn events(&self) -> Vec<Event> {
        self.lock_inner().events.clone()
    }

    pub fn enabled(&self) -> bool {
        self.lock_inner().enabled
    }

    /// Disabling clears in-memory events and stops future writes. Existing log files are
    /// preserved; they are not deleted or modified while disabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        let mut inner = self.lock_inner();
        if inner.enabled == enabled {
            return;
        }

        inner.writer.take();
        inner.enabled = enabled;
        inner.events.clear();
        inner.next_sequence = 0;
        inner.started = Instant::now();
        inner.bytes_written = 0;
        inner.stopped = None;

        if enabled {
            if inner.open_persistent_log().is_err() {
                inner.stop_persistence(StopReason::AppendFailure);
                inner.push_event(
                    "ERROR".to_owned(),
                    "Persistent audit log could not be opened; continuing in memory only."
                        .to_owned(),
                );
            }
        }
    }

    fn lock_inner(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => {
                let mut inner = poisoned.into_inner();
                self.inner.clear_poison();
                if inner.enabled {
                    inner.stop_persistence(StopReason::AppendFailure);
                    inner.push_event(
                        "ERROR".to_owned(),
                        "Audit state was recovered after a lock failure; file logging stopped."
                            .to_owned(),
                    );
                } else {
                    inner.events.clear();
                }
                inner
            }
        }
    }
}

impl Inner {
    fn open_persistent_log(&mut self) -> Result<()> {
        let Some(path) = self.log_path.as_deref() else {
            return Ok(());
        };

        if let Some(parent) = nonempty_parent(path) {
            fs::create_dir_all(parent)
                .map_err(|_| anyhow!("Unable to create audit log directory"))?;
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
        }
        let file = options
            .open(path)
            .map_err(|_| anyhow!("Unable to open audit log"))?;
        crate::policy::reject_link(path)?;
        let length = file
            .metadata()
            .map_err(|_| anyhow!("Unable to inspect audit log"))?
            .len();
        self.bytes_written = length;

        if length >= MAX_LOG_BYTES {
            self.stop_persistence(StopReason::SizeLimit);
            self.push_event(
                "WARN".to_owned(),
                "Persistent audit log reached the 8 MiB limit; new events remain in memory."
                    .to_owned(),
            );
        } else {
            self.writer = Some(BufWriter::new(file));
        }
        Ok(())
    }

    fn push_event(&mut self, level: String, message: String) -> Event {
        self.next_sequence = self.next_sequence.saturating_add(1);
        let event = Event {
            sequence: self.next_sequence,
            elapsed_ms: self.started.elapsed().as_millis(),
            level,
            message,
        };
        self.events.push(event.clone());
        event
    }

    fn append_event(&mut self, event: &Event) {
        if self.stopped.is_some() {
            return;
        }
        let Some(writer) = self.writer.as_mut() else {
            return;
        };

        let mut line = match serde_json::to_vec(event) {
            Ok(line) => line,
            Err(_) => {
                self.stop_persistence(StopReason::AppendFailure);
                self.push_event(
                    "ERROR".to_owned(),
                    "Persistent audit serialization failed; continuing in memory only.".to_owned(),
                );
                return;
            }
        };
        line.push(b'\n');

        if self.bytes_written.saturating_add(line.len() as u64) > MAX_LOG_BYTES {
            self.stop_persistence(StopReason::SizeLimit);
            self.push_event(
                "WARN".to_owned(),
                "Persistent audit log reached the 8 MiB limit; new events remain in memory."
                    .to_owned(),
            );
            return;
        }

        let result = writer.write_all(&line).and_then(|()| writer.flush());
        if result.is_err() {
            self.stop_persistence(StopReason::AppendFailure);
            self.push_event(
                "ERROR".to_owned(),
                "Persistent audit append failed; continuing in memory only.".to_owned(),
            );
        } else {
            self.bytes_written += line.len() as u64;
        }
    }

    fn stop_persistence(&mut self, reason: StopReason) {
        self.writer.take();
        self.stopped = Some(reason);
    }
}

fn nonempty_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn redact_if_credential_like(text: &str) -> String {
    let normalized: String = text
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    let markers = [
        "password",
        "passphrase",
        "credential",
        "authorization",
        "authheader",
        "bearer",
        "token",
        "apikey",
        "accesskey",
        "privatekey",
        "clientsecret",
        "secret",
        "cookie",
        "sessionid",
    ];
    if markers.iter().any(|marker| normalized.contains(marker)) {
        REDACTED_MESSAGE.to_owned()
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("amigood-audit-test-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn no_path_keeps_events_in_memory_without_creating_files() {
        let dir = temp_dir();
        let mut audit = Audit::new(true, None).unwrap();
        audit.log("INFO", "scan started");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(audit.events().len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn disabled_audit_does_not_create_paths_or_retain_events() {
        let dir = temp_dir();
        fs::remove_dir_all(&dir).unwrap();
        let path = dir.join("logs").join("audit.jsonl");
        let mut audit = Audit::new(false, Some(path)).unwrap();
        audit.log("INFO", "must not be retained");
        assert!(!audit.enabled());
        assert!(audit.events().is_empty());
        assert!(!dir.exists());
    }

    #[test]
    fn credential_like_messages_are_redacted_before_memory_and_disk() {
        let dir = temp_dir();
        let path = dir.join("audit.jsonl");
        let mut audit = Audit::new(true, Some(path.clone())).unwrap();
        audit.log("INFO", "Authorization: Bearer very-secret-value");

        let events = audit.events();
        assert!(!events[0].message.contains("very-secret-value"));
        assert!(!events[0].message.contains("Authorization"));
        let file_text = fs::read_to_string(path).unwrap();
        assert!(!file_text.contains("very-secret-value"));
        assert!(file_text.contains(REDACTED_MESSAGE));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn newlines_are_escaped_as_one_jsonl_record_and_clones_share_events() {
        let dir = temp_dir();
        let path = dir.join("audit.jsonl");
        let mut audit = Audit::new(true, Some(path.clone())).unwrap();
        let mut clone = audit.clone();
        clone.log("INFO", "one\n{\"level\":\"ERROR\"}\r\nthree");

        let file_text = fs::read_to_string(path).unwrap();
        assert_eq!(file_text.lines().count(), 1);
        let parsed: Event = serde_json::from_str(file_text.trim_end()).unwrap();
        assert!(parsed.message.contains("\n"));
        assert_eq!(audit.events(), clone.events());
        fs::remove_dir_all(dir).unwrap();
    }
}
