use rd_common::ProcessInfo;
use std::fs;
use std::path::{Path, PathBuf};

/// Details about a process that has a particular file open.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProcessIdentifier {
    pub pid: u32,
    pub name: String,
    pub exe: Option<PathBuf>,
}

/// Convert a PID into the shared [`ProcessInfo`] by reading `/proc`.
///
/// Returns `None` if the process exits before we can read its metadata or if
/// required fields are missing.
pub fn process_info_from_pid(pid: u32) -> Option<ProcessInfo> {
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let command_line = fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string();
    let parent_pid = read_parent_pid(pid).ok();
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());

    Some(ProcessInfo {
        pid,
        parent_pid,
        image_path: exe,
        command_line,
        user,
    })
}

fn read_parent_pid(pid: u32) -> std::io::Result<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // Format: pid (comm with spaces) state ppid ...
    // Use rsplit on ") " to safely skip spaces inside comm.
    let after_comm = stat
        .rsplitn(2, ") ")
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad stat"))?;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let ppid = fields
        .get(1)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing ppid"))?
        .parse::<u32>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(ppid)
}

/// Scan `/proc` to find a process that currently has `target` open.
///
/// This only works for processes owned by the same user unless the agent runs
/// as root. It is a best-effort fallback when higher-precision mechanisms like
/// fanotify or audit are not available.
pub fn find_process_for_file(target: &Path) -> Option<ProcessIdentifier> {
    // Use canonical path for comparison because /proc/<pid>/fd entries are
    // absolute symlinks.
    let target = fs::canonicalize(target).ok()?;

    for entry in fs::read_dir("/proc").ok()? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let file_name = entry.file_name();
        let pid_str = match file_name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let pid = match pid_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Skip kernel threads and processes whose fd directory we cannot read.
        let fd_dir = entry.path().join("fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd in fds {
            let fd = match fd {
                Ok(f) => f,
                Err(_) => continue,
            };
            if let Ok(link) = fs::read_link(fd.path()) {
                if link == target {
                    let name = fs::read_to_string(entry.path().join("comm"))
                        .unwrap_or_else(|_| "unknown".to_string())
                        .trim()
                        .to_string();
                    let exe = fs::read_link(entry.path().join("exe")).ok();
                    return Some(ProcessIdentifier { pid, name, exe });
                }
            }
        }
    }

    None
}

/// Retry `find_process_for_file` a few times with a short delay.
///
/// File operations can be very short, so the process may already have closed
/// the descriptor when the event reaches us. Retrying gives us a small window
/// to catch processes that keep files open for longer, which ransomware often
/// does while iterating a folder.
pub fn find_process_for_file_with_retry(
    target: &Path,
    attempts: u32,
    delay_ms: u64,
) -> Option<ProcessIdentifier> {
    let delay = std::time::Duration::from_millis(delay_ms);
    for _ in 0..attempts {
        if let Some(proc) = find_process_for_file(target) {
            return Some(proc);
        }
        std::thread::sleep(delay);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn finds_a_process_holding_a_file_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("holder.txt");
        fs::write(&path, b"canary content").unwrap();

        // Spawn a child process that opens the file and keeps it open.
        let script = format!(
            "import time\nf=open('{}')\nprint('HOLDER_PID', __import__('os').getpid())\ntime.sleep(2)\n",
            path.to_str().unwrap()
        );
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(&script)
            .stdout(Stdio::piped())
            .spawn()
            .expect("python3 is required for this test");

        // Give the child a moment to open the file.
        thread::sleep(Duration::from_millis(100));

        let found = find_process_for_file_with_retry(&path, 20, 50)
            .expect("should find the process holding the file open");

        assert_eq!(found.pid, child.id());

        let _ = child.kill();
    }
}
