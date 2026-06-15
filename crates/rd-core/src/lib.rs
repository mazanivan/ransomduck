pub mod config;

use notify::{Config, Event as NotifyEvent, RecommendedWatcher, RecursiveMode, Watcher};
use rd_audit::AuditLogger;
use rd_common::{Event, EventType, Incident, Platform, ProcessInfo, Signal, SignalType};
use rd_detection::build_incident;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{mpsc::channel, Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::info;

#[cfg(target_os = "linux")]
mod process_linux;

/// Try to identify the process that is currently holding `path` open.
///
/// On Linux this uses `/proc/*/fd` scanning with a small retry window.
/// On other platforms it returns `None` and the caller should fall back to
/// an unknown-process placeholder.
#[cfg(target_os = "linux")]
fn resolve_process_for_path(path: &PathBuf) -> Option<ProcessInfo> {
    use process_linux::{find_process_for_file_with_retry, process_info_from_pid};
    let id = find_process_for_file_with_retry(path, 15, 30)?;

    if let Some(info) = process_info_from_pid(id.pid) {
        return Some(info);
    }

    // We know the PID but could not enrich it from /proc; fall back to the
    // basic data we already have.
    tracing::warn!(
        "Found PID {} holding {} but failed to read full process metadata; using partial info",
        id.pid,
        path.display()
    );
    Some(ProcessInfo {
        pid: id.pid,
        parent_pid: None,
        image_path: id.exe.unwrap_or_else(|| PathBuf::from(&id.name)),
        command_line: id.name.clone(),
        user: std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()),
    })
}

#[cfg(not(target_os = "linux"))]
fn resolve_process_for_path(_path: &PathBuf) -> Option<ProcessInfo> {
    None
}

/// The agent coordinates the file monitor, detection engine, and audit logger.
#[derive(Debug)]
pub struct Agent {
    logger: AuditLogger,
    protected_path: PathBuf,
    /// Recently created incidents keyed by `PID@path`. Used to suppress duplicate
    /// detections that happen in quick succession (e.g. multiple write flushes).
    recent_incidents: Arc<Mutex<HashMap<String, Instant>>>,
    cooldown: Duration,
}

impl Agent {
    pub fn new(protected_path: PathBuf) -> Self {
        Self {
            logger: AuditLogger::new(),
            protected_path,
            recent_incidents: Arc::new(Mutex::new(HashMap::new())),
            cooldown: Duration::from_secs(5),
        }
    }

    /// Create an agent that writes audit entries to `log_dir` in addition to tracing.
    pub fn with_log_dir<P: AsRef<std::path::Path>>(protected_path: PathBuf, log_dir: P) -> Self {
        Self {
            logger: AuditLogger::with_log_dir(log_dir),
            protected_path,
            recent_incidents: Arc::new(Mutex::new(HashMap::new())),
            cooldown: Duration::from_secs(5),
        }
    }

    /// Override the duplicate-suppression cooldown.
    pub fn set_cooldown(&mut self, cooldown: Duration) {
        self.cooldown = cooldown;
    }

    /// Return the cooldown used for duplicate incident suppression.
    pub fn cooldown(&self) -> Duration {
        self.cooldown
    }

    /// Handle a single file-system event.
    ///
    /// In this first slice the agent only logs and creates incidents; it does not
    /// kill processes or isolate the network.
    ///
    /// Returns the incident if one was created, so callers and tests can inspect it.
    pub fn handle_event(&self, event: Event, known_canaries: &[PathBuf]) -> Option<Incident> {
        info!("Observed event: {:?} at {:?}", event.event_type, event.path);

        let is_canary = event
            .path
            .as_ref()
            .map(|p| known_canaries.contains(p))
            .unwrap_or(false);

        if is_canary && matches!(event.event_type, EventType::FileModified) {
            if self.is_recent_duplicate(event.process.pid, event.path.as_ref()) {
                tracing::debug!(
                    "Suppressing duplicate canary event for PID {} at {:?}",
                    event.process.pid,
                    event.path
                );
                return None;
            }

            let signal = Signal::new(
                event.event_id,
                "canary_modified",
                SignalType::CanaryModified,
                0.40,
                1.00,
                "A known canary file was modified",
            );

            let incident = build_incident(
                event.process.clone(),
                event.path.into_iter().collect(),
                vec![signal],
                1.10, // unknown process multiplier
            );

            self.logger.log(
                rd_common::Severity::Warning,
                "detection",
                &format!("Canary modified by {} (PID {})", event.process.image_path.display(), event.process.pid),
                "rd-core",
            );
            self.logger.log_incident(&incident);
            return Some(incident);
        }

        None
    }

    pub fn protected_path(&self) -> &PathBuf {
        &self.protected_path
    }
}

impl Agent {
    /// Check whether we already created an incident for this PID + path recently.
    ///
    /// Multiple `notify` events can fire for a single logical modification (close,
    /// flush, attribute change), so a short cooldown keeps the incident log clean.
    ///
    /// As a side effect this method also prunes stale entries.
    fn is_recent_duplicate(&self, pid: u32, path: Option<&PathBuf>) -> bool {
        let key = match path {
            Some(p) => format!("{}@{}", pid, p.display()),
            None => format!("{}@no-path", pid),
        };

        let mut recent = self
            .recent_incidents
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();

        // Remove entries that are older than the cooldown window.
        recent.retain(|_, t| now.duration_since(*t) < self.cooldown);

        if let Some(last) = recent.get(&key) {
            let elapsed = now.duration_since(*last);
            if elapsed < self.cooldown {
                tracing::debug!(
                    "Duplicate incident key {} suppressed; last seen {:?} ago",
                    key,
                    elapsed
                );
                return true;
            }
        }

        recent.insert(key, now);
        false
    }
}

/// Create a fake process record for testing when we cannot yet query the OS.
pub fn fake_process_info(name: &str, pid: u32) -> ProcessInfo {
    ProcessInfo {
        pid,
        parent_pid: None,
        image_path: PathBuf::from(name),
        command_line: name.to_string(),
        user: std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()),
    }
}

/// Watch the protected path in real time and feed canary events to the agent.
///
/// This implementation uses the `notify` crate, which chooses the best
/// underlying OS mechanism (inotify on Linux, ReadDirectoryChangesW on Windows,
/// FSEvents on macOS). In later slices we may switch to lower-level APIs for
/// richer process information.
pub fn watch_path(agent: &Agent, canaries: &[PathBuf]) -> notify::Result<()> {
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<NotifyEvent>| {
            let _ = tx.send(res);
        },
        Config::default(),
    )?;

    watcher.watch(agent.protected_path(), RecursiveMode::NonRecursive)?;

    info!(
        "Watching {:?} for canary changes. Press Ctrl+C to stop.",
        agent.protected_path()
    );

    loop {
        match rx.recv() {
            Ok(Ok(event)) => handle_notify_event(agent, &event, canaries),
            Ok(Err(e)) => tracing::error!("watch error: {:?}", e),
            Err(_) => break,
        }
    }

    Ok(())
}

fn handle_notify_event(agent: &Agent, event: &NotifyEvent, canaries: &[PathBuf]) {
    use notify::event::{EventKind, ModifyKind};

    let event_type = match &event.kind {
        EventKind::Modify(ModifyKind::Any) | EventKind::Modify(ModifyKind::Data(_)) => {
            Some(EventType::FileModified)
        }
        EventKind::Remove(_) => Some(EventType::FileDeleted),
        _ => None,
    };

    if let Some(event_type) = event_type {
        for path in &event.paths {
            if canaries.contains(path) {
                let process = resolve_process_for_path(path)
                    .unwrap_or_else(|| fake_process_info("unknown-process", 0));

                if process.pid == 0 {
                    tracing::warn!(
                        "Could not identify process for canary change at {}",
                        path.display()
                    );
                }

                let event = Event::new(Platform::Linux, event_type, Some(path.clone()), process);
                agent.handle_event(event, canaries);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rd_common::{EventType, Platform};
    use std::fs;

    #[test]
    fn canary_modification_creates_incident() {
        let dir = tempfile::tempdir().unwrap();
        let canary = dir.path().join("invoice_Q2_2026.docx");
        fs::write(&canary, b"sensitive-looking data").unwrap();

        let agent = Agent::new(dir.path().to_path_buf());
        let event = Event::new(
            Platform::Linux,
            EventType::FileModified,
            Some(canary.clone()),
            fake_process_info("fake-ransomware", 12345),
        );

        let incident = agent.handle_event(event, &[canary]);

        assert!(incident.is_some());
        let incident = incident.unwrap();
        assert_eq!(incident.score, 44);
        assert_eq!(incident.level, rd_common::ResponseLevel::Restrict);
        assert_eq!(incident.signals.len(), 1);
        assert_eq!(incident.process.pid, 12345);
    }

    #[test]
    fn normal_file_modification_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let normal = dir.path().join("some-pdf.pdf");
        fs::write(&normal, b"regular document").unwrap();

        let agent = Agent::new(dir.path().to_path_buf());
        let event = Event::new(
            Platform::Linux,
            EventType::FileModified,
            Some(normal),
            fake_process_info("legit-app", 9999),
        );

        let canary = dir.path().join("invoice_Q2_2026.docx");
        let incident = agent.handle_event(event, &[canary]);

        assert!(incident.is_none());
    }
}
