mod webhook;

use rd_common::{AuditLogEntry, Incident, Severity};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};
use webhook::WebhookClient;

/// The audit logger stores a tamper-evident record of everything the agent sees or does
/// and can push real-time notifications to a webhook.
///
/// In the first slice it logs to stdout/tracing and optionally appends JSON Lines to a
/// local directory. Later it will write to an append-only storage with integrity checks.
#[derive(Debug, Clone)]
pub struct AuditLogger {
    log_dir: Option<PathBuf>,
    // Shared handle so the logger can be used from multiple threads (for example the
    // watcher thread and async response tasks later on).
    writer: Arc<Mutex<Option<BufWriter<std::fs::File>>>>,
    webhook: Option<WebhookClient>,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            log_dir: None,
            writer: Arc::new(Mutex::new(None)),
            webhook: None,
        }
    }

    /// Create a logger that also persists every entry as a JSON Line file in `log_dir`.
    ///
    /// The directory is created on first write. Entries are appended to `audit.jsonl`.
    pub fn with_log_dir<P: AsRef<Path>>(log_dir: P) -> Self {
        Self {
            log_dir: Some(log_dir.as_ref().to_path_buf()),
            writer: Arc::new(Mutex::new(None)),
            webhook: None,
        }
    }

    /// Configure a webhook URL that will receive a JSON POST for every incident.
    ///
    /// The POST is best-effort: a delivery failure is logged but never blocks detection.
    pub fn with_webhook<S: Into<String>>(mut self, url: S) -> Self {
        self.webhook = Some(WebhookClient::new(url));
        self
    }

    /// Log a generic event.
    pub fn log(&self, severity: Severity, category: &str, message: &str, source: &str) {
        let entry = AuditLogEntry::new(
            severity,
            category.to_string(),
            message.to_string(),
            source.to_string(),
            None,
        );
        self.emit(entry);
    }

    /// Log an incident creation.
    pub fn log_incident(&self, incident: &Incident) {
        let entry = AuditLogEntry::new(
            severity_from_level(incident.level),
            "incident",
            format!("Incident {} created with score {}", incident.incident_id, incident.score),
            "rd-detection",
            Some(incident.incident_id),
        );
        self.emit(entry);

        if let Some(webhook) = &self.webhook {
            webhook.send(incident);
        }
    }

    fn emit(&self, entry: AuditLogEntry) {
        // In the first slice we use the tracing crate so logs can be captured by tests.
        let json = serde_json::to_string(&entry).unwrap_or_default();
        match entry.severity {
            Severity::Info => info!(target: "rd-audit", %json),
            Severity::Warning => warn!(target: "rd-audit", %json),
            Severity::Critical => error!(target: "rd-audit", %json),
        }

        if let Err(e) = self.append_jsonl(&json) {
            warn!(target: "rd-audit", "Failed to append audit entry to file: {}", e);
        }
    }

    /// Append one JSON Lines record, opening the file only when necessary.
    ///
    /// The operation is best-effort; errors are returned so callers can log them but
    /// never break detection.
    fn append_jsonl(&self, json: &str) -> std::io::Result<()> {
        let log_dir = match &self.log_dir {
            Some(dir) => dir,
            None => return Ok(()),
        };

        fs::create_dir_all(log_dir)?;
        let path = log_dir.join("audit.jsonl");

        let mut guard = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(&path)?;
            *guard = Some(BufWriter::new(file));
        }

        let writer = guard.as_mut().expect("writer was just initialised");
        writeln!(writer, "{}", json)?;
        writer.flush()?;
        Ok(())
    }
}

fn severity_from_level(level: rd_common::ResponseLevel) -> Severity {
    match level {
        rd_common::ResponseLevel::Monitor => Severity::Info,
        rd_common::ResponseLevel::Restrict => Severity::Warning,
        rd_common::ResponseLevel::Contain => Severity::Critical,
    }
}
