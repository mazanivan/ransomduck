use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// RansomDuck agent configuration.
///
/// The file is intentionally small and human-editable. Missing fields use the
/// defaults defined in `Config::default_for` so a minimal TOML can contain just
/// the `watch_path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub watch_path: PathBuf,
    pub log_dir: Option<PathBuf>,
    #[serde(default = "default_cooldown_seconds")]
    pub cooldown_seconds: u64,
    #[serde(default = "default_canaries")]
    pub canaries: Vec<String>,
}

fn default_cooldown_seconds() -> u64 {
    5
}

fn default_canaries() -> Vec<String> {
    vec!["invoice_Q2_2026.docx".into()]
}

impl Config {
    /// Default configuration for a given watch directory.
    pub fn default_for<P: AsRef<Path>>(watch_path: P) -> Self {
        Self {
            watch_path: watch_path.as_ref().to_path_buf(),
            log_dir: None,
            cooldown_seconds: default_cooldown_seconds(),
            canaries: default_canaries(),
        }
    }

    /// Load configuration from a TOML file.
    ///
    /// Returns an error if the file exists but cannot be parsed. Missing files
    /// are treated as an error so the caller can decide whether to fall back to
    /// defaults.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path.as_ref())?;
        let mut config: Config = toml::from_str(&contents)?;

        // If the TOML did not specify a watch path, derive it from the directory
        // containing the config file. This makes it convenient to drop a config
        // next to the directory you want to protect.
        if config.watch_path.as_os_str().is_empty() {
            if let Some(parent) = path.as_ref().parent() {
                config.watch_path = parent.to_path_buf();
            }
        }

        Ok(config)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_minimal_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ransomduck.toml");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "watch_path = \"/tmp/important\"").unwrap();

        let config = Config::from_file(&path).unwrap();
        assert_eq!(config.watch_path, PathBuf::from("/tmp/important"));
        assert_eq!(config.cooldown_seconds, 5);
        assert_eq!(config.canaries, vec!["invoice_Q2_2026.docx"]);
    }

    #[test]
    fn loads_full_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ransomduck.toml");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(
            file,
            r#"watch_path = "/tmp/important"
log_dir = "/var/log/ransomduck"
cooldown_seconds = 10
canaries = ["salary_2026.xlsx", "budget.docx"]
"#
        )
        .unwrap();

        let config = Config::from_file(&path).unwrap();
        assert_eq!(config.cooldown_seconds, 10);
        assert_eq!(
            config.log_dir,
            Some(PathBuf::from("/var/log/ransomduck"))
        );
        assert_eq!(
            config.canaries,
            vec!["salary_2026.xlsx", "budget.docx"]
        );
    }
}
