use clap::Parser;
use rd_core::config::Config;
use rd_core::{watch_path, Agent};
use rd_simulator::deploy_canary;
use std::fs;
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "ransomduck", about = "RansomDuck local canary agent")]
struct Args {
    /// Path to a TOML configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Directory to watch. Optional if provided via config file.
    watch_directory: Option<PathBuf>,
}

fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Load configuration, applying CLI overrides for the watch directory.
    let mut config = match (&args.config, &args.watch_directory) {
        (Some(path), _) => match Config::from_file(path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to load config: {}", e);
                std::process::exit(1);
            }
        },
        (None, Some(path)) => Config::default_for(path),
        (None, None) => {
            eprintln!("Usage: ransomduck [--config <file>] [watch-directory]");
            eprintln!();
            eprintln!("Either provide a TOML config file or a directory to watch.");
            std::process::exit(1);
        }
    };

    if let Some(override_path) = args.watch_directory {
        config.watch_path = override_path;
    }

    if let Err(e) = fs::create_dir_all(&config.watch_path) {
        error!(
            "Failed to create directory {}: {}",
            config.watch_path.display(),
            e
        );
        std::process::exit(1);
    }

    info!(
        "RansomDuck agent starting for: {}",
        config.watch_path.display()
    );

    // Deploy all configured canary files.
    let mut canary_paths = Vec::new();
    for name in &config.canaries {
        info!("Deploying canary file: {}", name);
        match deploy_canary(&config.watch_path, name, 4096) {
            Ok(c) => canary_paths.push(c.path),
            Err(e) => {
                error!("Failed to deploy canary '{}': {}", name, e);
                std::process::exit(1);
            }
        }
    }

    if canary_paths.is_empty() {
        error!("No canary files configured; nothing to protect.");
        std::process::exit(1);
    }

    // Build the agent from config: it will use the configured log dir, webhook,
    // and cooldown automatically.
    let agent = Agent::from_config(&config);

    info!(
        "Starting file watcher (cooldown={}s). Press Ctrl+C to stop.",
        config.cooldown_seconds
    );

    if let Err(e) = watch_path(&agent, &canary_paths) {
        error!("Watcher failed: {}", e);
        std::process::exit(1);
    }
}
