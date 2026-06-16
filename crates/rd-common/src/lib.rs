use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Operating-system platform supported by RansomDuck.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
}

/// Type of a security-relevant event observed by the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    FileModified,
    FileDeleted,
    FileCreated,
    FileRenamed,
    VssAccessed,
    ProcessCreated,
    ProcessTerminated,
}

/// Information about the process that triggered an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image_path: PathBuf,
    pub command_line: String,
    pub user: String,
}

/// A single observable happening, normalized across platforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub platform: Platform,
    pub event_type: EventType,
    pub path: Option<PathBuf>,
    pub process: ProcessInfo,
}

impl Event {
    pub fn new(
        platform: Platform,
        event_type: EventType,
        path: Option<PathBuf>,
        process: ProcessInfo,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            platform,
            event_type,
            path,
            process,
        }
    }
}

/// Kind of suspicious signal produced by a detection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalType {
    CanaryModified,
    CanaryDeleted,
    HighWriteRate,
    SuspiciousExtension,
    VssShadowDeletion,
    VssAdminInvoked,
    RegistryRunChanged,
    DnsC2Query,
}

/// A detection rule match that contributes to an incident score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub signal_id: Uuid,
    pub event_id: Uuid,
    pub rule_id: String,
    pub signal_type: SignalType,
    pub weight: f64,
    pub confidence: f64,
    pub description: String,
}

impl Signal {
    pub fn new(
        event_id: Uuid,
        rule_id: impl Into<String>,
        signal_type: SignalType,
        weight: f64,
        confidence: f64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            signal_id: Uuid::new_v4(),
            event_id,
            rule_id: rule_id.into(),
            signal_type,
            weight,
            confidence,
            description: description.into(),
        }
    }
}

/// Response level chosen by the agent based on the risk score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseLevel {
    Monitor,
    Restrict,
    #[default]
    Contain,
}

/// Current status of an incident in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Closed,
    Suppressed,
}

/// Type of action executed by the response orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Log,
    Alert,
    Throttle,
    SuspendProcess,
    KillProcess,
    IsolateNetwork,
}

/// A single executed response action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action_id: Uuid,
    pub incident_id: Uuid,
    pub action_type: ActionType,
    pub executed_at: DateTime<Utc>,
    pub success: bool,
    pub error_message: Option<String>,
}

impl Action {
    pub fn new(
        incident_id: Uuid,
        action_type: ActionType,
        success: bool,
        error_message: Option<String>,
    ) -> Self {
        Self {
            action_id: Uuid::new_v4(),
            incident_id,
            action_type,
            executed_at: Utc::now(),
            success,
            error_message,
        }
    }
}

/// Full incident record aggregating signals, affected files, and taken actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub score: u8,
    pub level: ResponseLevel,
    pub signals: Vec<Signal>,
    pub affected_paths: Vec<PathBuf>,
    pub process: ProcessInfo,
    pub actions_taken: Vec<Action>,
    pub status: IncidentStatus,
}

impl Incident {
    pub fn new(
        score: u8,
        level: ResponseLevel,
        signals: Vec<Signal>,
        affected_paths: Vec<PathBuf>,
        process: ProcessInfo,
        actions_taken: Vec<Action>,
    ) -> Self {
        Self {
            incident_id: Uuid::new_v4(),
            created_at: Utc::now(),
            score,
            level,
            signals,
            affected_paths,
            process,
            actions_taken,
            status: IncidentStatus::Open,
        }
    }
}

/// Severity for an audit-log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Immutable audit-log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub entry_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub source: String,
    pub related_incident_id: Option<Uuid>,
}

impl AuditLogEntry {
    pub fn new(
        severity: Severity,
        category: impl Into<String>,
        message: impl Into<String>,
        source: impl Into<String>,
        related_incident_id: Option<Uuid>,
    ) -> Self {
        Self {
            entry_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category: category.into(),
            message: message.into(),
            source: source.into(),
            related_incident_id,
        }
    }
}

/// Outbound alert payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: Uuid,
    pub incident_id: Uuid,
    pub channel: String,
    pub sent_at: DateTime<Utc>,
    pub payload: serde_json::Value,
}
