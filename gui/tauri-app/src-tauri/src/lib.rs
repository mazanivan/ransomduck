use rd_common::Severity;
use rd_core::config::Config;
use rd_core::{Agent, watch_path_with_callback_until};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager, RunEvent, State, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use tracing::info;

fn default_config_dir() -> PathBuf {
    directories::BaseDirs::new()
        .map(|b| b.config_dir().join("RansomDuck"))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn default_config_path() -> PathBuf {
    default_config_dir().join("ransomduck.toml")
}

fn default_log_dir() -> PathBuf {
    default_config_dir().join("logs")
}

fn generate_canary_names(count: usize) -> Vec<String> {
    let prefixes = [
        "invoice",
        "salary",
        "budget",
        "payroll",
        "contract",
        "confidential",
        "project",
        "statement",
    ];
    let extensions = ["docx", "xlsx", "pdf"];
    let mut names = Vec::with_capacity(count);
    let mut rng = rand::thread_rng();
    use rand::Rng;

    for _ in 0..count {
        let prefix = prefixes[rng.gen_range(0..prefixes.len())];
        let ext = extensions[rng.gen_range(0..extensions.len())];
        let number: u32 = rng.gen_range(1000..9999);
        let month: u8 = rng.gen_range(1..13);
        let year: u32 = rng.gen_range(2025..2027);
        names.push(format!("{}_{:02}_{}_{}.{}.", prefix, month, year, number, ext));
    }

    names
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub watch_path: PathBuf,
    #[serde(default = "default_canary_count")]
    pub canary_count: usize,
    pub webhook_url: Option<String>,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,
}

fn default_canary_count() -> usize {
    5
}

fn default_cooldown() -> u64 {
    5
}

impl AppConfig {
    fn to_agent_config(&self, canaries: Vec<String>) -> Config {
        Config {
            watch_path: self.watch_path.clone(),
            log_dir: Some(default_log_dir()),
            webhook_url: self.webhook_url.clone(),
            cooldown_seconds: self.cooldown_seconds,
            canaries,
        }
    }

    fn save(&self) -> Result<(), String> {
        let dir = default_config_dir();
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

        // Persist only the count; actual names are generated at runtime.
        let persisted = PersistedConfig {
            watch_path: self.watch_path.clone(),
            canary_count: self.canary_count,
            webhook_url: self.webhook_url.clone(),
            cooldown_seconds: self.cooldown_seconds,
        };
        let toml = toml::to_string(&persisted).map_err(|e| e.to_string())?;
        std::fs::write(default_config_path(), toml).map_err(|e| e.to_string())
    }

    fn load() -> Option<Self> {
        let path = default_config_path();
        let contents = std::fs::read_to_string(&path).ok()?;
        let persisted: PersistedConfig = toml::from_str(&contents).ok()?;
        Some(Self {
            watch_path: persisted.watch_path,
            canary_count: persisted.canary_count,
            webhook_url: persisted.webhook_url,
            cooldown_seconds: persisted.cooldown_seconds,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedConfig {
    pub watch_path: PathBuf,
    #[serde(default = "default_canary_count")]
    pub canary_count: usize,
    pub webhook_url: Option<String>,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionState {
    pub running: bool,
    pub watch_path: Option<String>,
    pub log_dir: Option<String>,
    pub canary_names: Vec<String>,
    pub incident_count: usize,
}

struct AgentRunner {
    agent: Option<Arc<Agent>>,
    handle: Option<JoinHandle<()>>,
    stop_flag: Arc<Mutex<bool>>,
    incidents: Arc<Mutex<Vec<IncidentSummary>>>,
    active_canaries: Arc<Mutex<Vec<PathBuf>>>,
}

#[derive(Debug, Clone, Serialize)]
struct IncidentSummary {
    incident_id: String,
    timestamp: String,
    severity: String,
    score: u8,
    level: String,
    message: String,
    process_path: String,
    process_pid: u32,
    affected_paths: Vec<String>,
}

impl AgentRunner {
    fn new() -> Self {
        Self {
            agent: None,
            handle: None,
            stop_flag: Arc::new(Mutex::new(false)),
            incidents: Arc::new(Mutex::new(Vec::new())),
            active_canaries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn is_running(&self) -> bool {
        self.handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }

    fn cleanup_canaries(&self) {
        let paths = {
            let mut list = self.active_canaries.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *list)
        };
        for path in paths {
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!("Failed to remove canary {}: {}", path.display(), e);
            } else {
                info!("Removed canary {}", path.display());
            }
        }
    }

    fn start(
        &mut self,
        app_handle: tauri::AppHandle,
        config: &AppConfig,
    ) -> Result<ProtectionState, String> {
        if self.is_running() {
            return Err("Protection is already running".into());
        }

        std::fs::create_dir_all(&config.watch_path).map_err(|e| e.to_string())?;

        // Remove any stale canaries from a previous run.
        self.cleanup_canaries();

        let canary_names = generate_canary_names(config.canary_count.max(1));

        // Ensure default log dir exists.
        std::fs::create_dir_all(default_log_dir()).map_err(|e| e.to_string())?;

        let agent_config = config.to_agent_config(canary_names.clone());
        let agent = Arc::new(Agent::from_config(&agent_config));

        // Deploy canaries on disk.
        let mut canary_paths = Vec::new();
        for name in &canary_names {
            match rd_simulator::deploy_canary(&agent_config.watch_path, name, 4096) {
                Ok(c) => canary_paths.push(c.path),
                Err(e) => tracing::warn!("Failed to deploy canary {}: {}", name, e),
            }
        }

        if canary_paths.is_empty() {
            return Err("No canary files could be deployed".into());
        }

        {
            let mut list = self
                .active_canaries
                .lock()
                .map_err(|e| e.to_string())?;
            *list = canary_paths.clone();
        }

        let watch_path = agent.protected_path().clone();
        let agent_for_thread = Arc::clone(&agent);
        let stop_flag = Arc::clone(&self.stop_flag);
        let incidents = Arc::clone(&self.incidents);
        let app_handle_for_thread = app_handle.clone();

        *stop_flag.lock().map_err(|e| e.to_string())? = false;

        let handle = thread::spawn(move || {
            let _ = watch_path_with_callback_until(
                &agent_for_thread,
                &canary_paths,
                stop_flag,
                |incident| {
                    let summary = IncidentSummary {
                        incident_id: incident.incident_id.to_string(),
                        timestamp: incident.created_at.to_rfc3339(),
                        severity: format!("{:?}", severity_from_level(incident.level)),
                        score: incident.score,
                        level: format!("{:?}", incident.level),
                        message: format!(
                            "Canary modified by {} (PID {})",
                            incident.process.image_path.display(),
                            incident.process.pid
                        ),
                        process_path: incident.process.image_path.display().to_string(),
                        process_pid: incident.process.pid,
                        affected_paths: incident
                            .affected_paths
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect(),
                    };

                    let payload = serde_json::to_value(&summary).unwrap_or_default();
                    if let Some(window) = app_handle_for_thread.get_webview_window("main") {
                        let _ = window.emit("incident", payload);
                    }

                    if let Ok(mut list) = incidents.lock() {
                        list.push(summary);
                    }
                },
            );
            info!("Watcher thread for {:?} stopped", watch_path);
        });

        self.agent = Some(agent);
        self.handle = Some(handle);

        Ok(self.state(config, &canary_names))
    }

    fn stop(&mut self, config: &AppConfig) -> ProtectionState {
        if let Ok(mut flag) = self.stop_flag.lock() {
            *flag = true;
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.agent = None;
        self.cleanup_canaries();
        self.state(config, &[])
    }

    fn state(&self, config: &AppConfig, canary_names: &[String]) -> ProtectionState {
        let incident_count = self.incidents.lock().map(|v| v.len()).unwrap_or(0);
        let names = if canary_names.is_empty() {
            self.active_canaries
                .lock()
                .map(|v| {
                    v.iter()
                        .map(|p| {
                            p.file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default()
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            canary_names.to_vec()
        };

        ProtectionState {
            running: self.is_running(),
            watch_path: Some(config.watch_path.display().to_string()),
            log_dir: Some(default_log_dir().display().to_string()),
            canary_names: names,
            incident_count,
        }
    }

    fn incidents(&self, limit: usize) -> Vec<IncidentSummary> {
        let list = self.incidents.lock().unwrap_or_else(|e| e.into_inner());
        list.iter().rev().take(limit).cloned().collect()
    }
}

struct AppState {
    runner: Mutex<AgentRunner>,
    config: Mutex<AppConfig>,
}

#[tauri::command]
fn load_config(state: State<AppState>) -> Result<AppConfig, String> {
    let cfg = state.config.lock().map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn save_config(state: State<AppState>, config: AppConfig) -> Result<AppConfig, String> {
    config.save()?;
    let mut cfg = state.config.lock().map_err(|e| e.to_string())?;
    *cfg = config.clone();
    Ok(config)
}

#[tauri::command]
fn start_protection(
    app: tauri::AppHandle,
    state: State<AppState>,
) -> Result<ProtectionState, String> {
    let config = state.config.lock().map_err(|e| e.to_string())?.clone();
    let mut runner = state.runner.lock().map_err(|e| e.to_string())?;
    runner.start(app, &config)
}

#[tauri::command]
fn stop_protection(state: State<AppState>) -> Result<ProtectionState, String> {
    let config = state.config.lock().map_err(|e| e.to_string())?.clone();
    let mut runner = state.runner.lock().map_err(|e| e.to_string())?;
    Ok(runner.stop(&config))
}

#[tauri::command]
fn get_status(state: State<AppState>) -> Result<ProtectionState, String> {
    let config = state.config.lock().map_err(|e| e.to_string())?.clone();
    let runner = state.runner.lock().map_err(|e| e.to_string())?;
    Ok(runner.state(&config, &[]))
}

#[tauri::command]
fn get_incidents(state: State<AppState>, limit: usize) -> Result<Vec<IncidentSummary>, String> {
    let runner = state.runner.lock().map_err(|e| e.to_string())?;
    Ok(runner.incidents(limit))
}

#[tauri::command]
fn select_directory(app: tauri::AppHandle) -> Result<Option<String>, String> {
    match app.dialog().file().blocking_pick_folder() {
        Some(path) => Ok(Some(path.to_string())),
        None => Ok(None),
    }
}

fn severity_from_level(level: rd_common::ResponseLevel) -> Severity {
    match level {
        rd_common::ResponseLevel::Monitor => Severity::Info,
        rd_common::ResponseLevel::Restrict => Severity::Warning,
        rd_common::ResponseLevel::Contain => Severity::Critical,
    }
}

fn build_tray_menu(app: &tauri::App) -> tauri::Result<()> {
    let show_i = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
    let hide_i = MenuItem::with_id(app, "hide", "Hide", true, None::<&str>)?;
    let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show_i, &hide_i, &quit_i])?;

    let _tray = TrayIconBuilder::new()
        .icon(app.default_window_icon().unwrap().clone())
        .tooltip("RansomDuck")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "hide" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click { .. } = event {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    if window.is_visible().unwrap_or(true) {
                        let _ = window.hide();
                    } else {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            }
        })
        .build(app)?;

    Ok(())
}

pub fn build_app() -> tauri::App {
    tracing_subscriber::fmt::init();

    let config = AppConfig::load().unwrap_or_else(|| {
        let mut home = PathBuf::from("/tmp");
        if let Some(dirs) = directories::BaseDirs::new() {
            home = dirs.home_dir().to_path_buf();
        }
        AppConfig {
            watch_path: home.join("RansomDuck"),
            canary_count: default_canary_count(),
            webhook_url: None,
            cooldown_seconds: default_cooldown(),
        }
    });

    tauri::Builder::default()
        .manage(AppState {
            runner: Mutex::new(AgentRunner::new()),
            config: Mutex::new(config),
        })
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            load_config,
            save_config,
            start_protection,
            stop_protection,
            get_status,
            get_incidents,
            select_directory
        ])
        .setup(|app| {
            build_tray_menu(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("Failed to build Tauri application")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = build_app();
    app.run(|app_handle, event| {
        if let RunEvent::ExitRequested { .. } = event {
            if let Ok(state) = app_handle.state::<AppState>().inner().runner.lock() {
                state.cleanup_canaries();
            }
        }
    });
}
