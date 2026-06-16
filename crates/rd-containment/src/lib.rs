//! Process containment actions for RansomDuck.
//!
//! This crate executes response actions such as suspending or killing a
//! process identified as the source of a security incident. Platform-specific
//! implementations live behind a small trait so non-Linux targets can start
//! with a no-op backend.

use rd_common::{Action, ActionType, ProcessInfo};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Containment action selected by the user or policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainmentAction {
    /// Do nothing beyond logging/alerting.
    #[default]
    None,
    /// Suspend the process (SIGSTOP on Linux).
    Suspend,
    /// Terminate the process (SIGKILL on Linux).
    Kill,
}

impl fmt::Display for ContainmentAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContainmentAction::None => write!(f, "none"),
            ContainmentAction::Suspend => write!(f, "suspend"),
            ContainmentAction::Kill => write!(f, "kill"),
        }
    }
}

impl std::str::FromStr for ContainmentAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(ContainmentAction::None),
            "suspend" | "sigstop" => Ok(ContainmentAction::Suspend),
            "kill" | "sigkill" => Ok(ContainmentAction::Kill),
            _ => Err(format!("unknown containment action: {s}")),
        }
    }
}

/// Convert the user-facing containment action to the common action type.
pub fn action_type(action: ContainmentAction) -> ActionType {
    match action {
        ContainmentAction::None => ActionType::Log,
        ContainmentAction::Suspend => ActionType::SuspendProcess,
        ContainmentAction::Kill => ActionType::KillProcess,
    }
}

/// Execute the requested containment action against `process`.
///
/// `incident_id` is the incident that triggered the action and is stored in the
/// returned `Action` record. The caller is responsible for attaching the action
/// to the incident.
pub fn execute(action: ContainmentAction, incident_id: Uuid, process: &ProcessInfo) -> Action {
    match action {
        ContainmentAction::None => Action::new(
            incident_id,
            ActionType::Log,
            true,
            Some("containment disabled".to_string()),
        ),
        ContainmentAction::Suspend => suspend_process(incident_id, process),
        ContainmentAction::Kill => kill_process(incident_id, process),
    }
}

#[cfg(target_os = "linux")]
fn suspend_process(incident_id: Uuid, process: &ProcessInfo) -> Action {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let pid = Pid::from_raw(process.pid as i32);
    match kill(pid, Signal::SIGSTOP) {
        Ok(()) => Action::new(incident_id, ActionType::SuspendProcess, true, None),
        Err(e) => Action::new(
            incident_id,
            ActionType::SuspendProcess,
            false,
            Some(format!("SIGSTOP failed: {e}")),
        ),
    }
}

#[cfg(target_os = "linux")]
fn kill_process(incident_id: Uuid, process: &ProcessInfo) -> Action {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let pid = Pid::from_raw(process.pid as i32);
    match kill(pid, Signal::SIGKILL) {
        Ok(()) => Action::new(incident_id, ActionType::KillProcess, true, None),
        Err(e) => Action::new(
            incident_id,
            ActionType::KillProcess,
            false,
            Some(format!("SIGKILL failed: {e}")),
        ),
    }
}

#[cfg(not(target_os = "linux"))]
fn suspend_process(incident_id: Uuid, process: &ProcessInfo) -> Action {
    Action::new(
        incident_id,
        ActionType::SuspendProcess,
        false,
        Some(format!(
            "suspend not implemented on this platform for PID {}",
            process.pid
        )),
    )
}

#[cfg(not(target_os = "linux"))]
fn kill_process(incident_id: Uuid, process: &ProcessInfo) -> Action {
    Action::new(
        incident_id,
        ActionType::KillProcess,
        false,
        Some(format!(
            "kill not implemented on this platform for PID {}",
            process.pid
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fake_process(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid: None,
            image_path: PathBuf::from("/bin/fake"),
            command_line: "fake".to_string(),
            user: "test".to_string(),
        }
    }

    #[test]
    fn none_action_is_always_successful() {
        let incident_id = Uuid::new_v4();
        let action = execute(ContainmentAction::None, incident_id, &fake_process(1));
        assert!(action.success);
        assert_eq!(action.action_type, ActionType::Log);
        assert_eq!(action.incident_id, incident_id);
    }

    #[test]
    fn containment_action_parses_from_string() {
        assert_eq!(
            "suspend".parse::<ContainmentAction>().unwrap(),
            ContainmentAction::Suspend
        );
        assert_eq!(
            "kill".parse::<ContainmentAction>().unwrap(),
            ContainmentAction::Kill
        );
        assert_eq!(
            "none".parse::<ContainmentAction>().unwrap(),
            ContainmentAction::None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kill_action_terminates_real_process() {
        use std::process::{Command, Stdio};
        use std::time::Duration;
        use std::thread;

        let mut child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep command is required for this test");

        let pid = child.id();
        let incident_id = Uuid::new_v4();
        let action = execute(ContainmentAction::Kill, incident_id, &fake_process(pid));

        assert!(action.success, "kill should succeed: {:?}", action.error_message);
        assert_eq!(action.action_type, ActionType::KillProcess);
        assert_eq!(action.incident_id, incident_id);

        // Give the kernel a moment to reap the process, then verify it exited.
        thread::sleep(Duration::from_millis(100));
        match child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = child.kill();
                panic!("process was still alive after SIGKILL");
            }
        }
    }
}
