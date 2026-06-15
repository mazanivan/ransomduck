use rd_common::Incident;
use serde::Serialize;
use std::time::Duration;
use tracing::warn;

/// Synchronous HTTP client that pushes incident notifications to a webhook URL.
///
/// The client is intentionally simple: it serialises a structured payload and
/// performs a `POST` with a short timeout. Delivery is best-effort; failures
/// are logged but never block detection.
#[derive(Debug, Clone)]
pub struct WebhookClient {
    url: String,
    timeout: Duration,
}

impl WebhookClient {
    pub fn new<S: Into<String>>(url: S) -> Self {
        Self {
            url: url.into(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Send `incident` as a JSON POST to the configured webhook URL.
    pub fn send(&self, incident: &Incident) {
        let payload = WebhookPayload::from(incident);

        if let Err(e) = self.send_payload(&payload) {
            warn!(target: "rd-audit", "Webhook delivery to {} failed: {}", self.url, e);
        }
    }

    fn send_payload(&self, payload: &WebhookPayload) -> Result<(), ureq::Error> {
        ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .timeout(self.timeout)
            .send_json(payload)?;
        Ok(())
    }
}

/// Serializable webhook payload.
///
/// The schema is designed to be easy to consume by services like Discord,
/// Slack, ntfy.sh, or a custom server. Paths are normalised to UTF-8 strings
/// because webhook endpoints usually expect strings, not path objects.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub source: &'static str,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub severity: String,
    pub category: &'static str,
    pub message: String,
    pub score: u8,
    pub level: String,
    pub incident_id: String,
    pub process: ProcessSummary,
    pub affected_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSummary {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image_path: String,
    pub command_line: String,
    pub user: String,
}

impl From<&Incident> for WebhookPayload {
    fn from(incident: &Incident) -> Self {
        let process = &incident.process;
        Self {
            source: "RansomDuck",
            timestamp: incident.created_at,
            severity: format!("{:?}", severity_from_level(incident.level)),
            category: "incident",
            message: format!(
                "Canary modified by {} (PID {})",
                process.image_path.display(),
                process.pid
            ),
            score: incident.score,
            level: format!("{:?}", incident.level),
            incident_id: incident.incident_id.to_string(),
            process: ProcessSummary {
                pid: process.pid,
                parent_pid: process.parent_pid,
                image_path: process.image_path.display().to_string(),
                command_line: process.command_line.clone(),
                user: process.user.clone(),
            },
            affected_paths: incident
                .affected_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
        }
    }
}

fn severity_from_level(level: rd_common::ResponseLevel) -> rd_common::Severity {
    match level {
        rd_common::ResponseLevel::Monitor => rd_common::Severity::Info,
        rd_common::ResponseLevel::Restrict => rd_common::Severity::Warning,
        rd_common::ResponseLevel::Contain => rd_common::Severity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rd_common::{
        Action, ActionType, Incident, ProcessInfo, ResponseLevel, Signal, SignalType,
    };
    use std::path::PathBuf;
    use uuid::Uuid;

    fn sample_incident() -> Incident {
        let process = ProcessInfo {
            pid: 1234,
            parent_pid: Some(1),
            image_path: PathBuf::from("/usr/bin/fake-ransomware"),
            command_line: "fake-ransomware /tmp/test".into(),
            user: "diego".into(),
        };
        let signal = Signal::new(
            Uuid::new_v4(),
            "canary_modified",
            SignalType::CanaryModified,
            0.40,
            1.0,
            "A canary file was modified",
        );
        Incident::new(
            44,
            ResponseLevel::Restrict,
            vec![signal],
            vec![PathBuf::from("/tmp/test/invoice.docx")],
            process,
            vec![Action::new(Uuid::new_v4(), ActionType::Alert, true, None)],
        )
    }

    #[test]
    fn payload_serialises_to_json() {
        let incident = sample_incident();
        let payload = WebhookPayload::from(&incident);
        let json = serde_json::to_string(&payload).expect("payload should serialise");

        assert!(json.contains("RansomDuck"));
        assert!(json.contains("fake-ransomware"));
        assert!(json.contains("invoice.docx"));
        assert!(json.contains("\"score\":44"));
        assert!(json.contains("Restrict"));
    }
}
