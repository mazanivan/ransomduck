use rd_simulator::{deploy_canary, deploy_test_file, encrypt_file_with_hold};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use tracing::{info, warn};

fn main() {
    tracing_subscriber::fmt::init();

    let mut skip_confirm = false;
    let mut hold_open_ms: u64 = 0;
    let mut path_arg: Option<String> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--yes" {
            skip_confirm = true;
        } else if arg == "--hold-open-ms" {
            let Some(value) = args.next() else {
                eprintln!("Usage: fake-ransomware [--yes] [--hold-open-ms <ms>] <test-directory>");
                eprintln!("--hold-open-ms requires a numeric value in milliseconds.");
                std::process::exit(1);
            };
            hold_open_ms = match value.parse() {
                Ok(ms) => ms,
                Err(_) => {
                    eprintln!("Invalid --hold-open-ms value: {}", value);
                    std::process::exit(1);
                }
            };
        } else if path_arg.is_none() {
            path_arg = Some(arg);
        } else {
            eprintln!("Usage: fake-ransomware [--yes] [--hold-open-ms <ms>] <test-directory>");
            std::process::exit(1);
        }
    }

    let Some(path_arg) = path_arg else {
        eprintln!("Usage: fake-ransomware [--yes] [--hold-open-ms <ms>] <test-directory>");
        eprintln!();
        eprintln!("This simulator only touches files inside the given directory.");
        eprintln!("It will refuse system folders, user home directories, and any path");
        eprintln!("that does not look like a dedicated temporary test directory.");
        std::process::exit(1);
    };

    let target = PathBuf::from(path_arg);
    if !is_acceptable_test_directory(&target) {
        warn!(
            "Refusing to run on a non-test directory. Choose a path under the system temp folder with a name like '/tmp/rd-test' or '/tmp/ransomduck-sandbox'.",
        );
        eprintln!("Refusing directory: {}", target.display());
        std::process::exit(2);
    }

    fs::create_dir_all(&target).expect("failed to create test directory");

    let canary_path = target.join("invoice_Q2_2026.docx");
    let normal_path = target.join("project_notes.txt");

    if !skip_confirm {
        eprintln!();
        eprintln!("WARNING: fake-ransomware is a test-only simulator.");
        eprintln!("It will create and overwrite these files in the target directory:");
        eprintln!("  - {}", canary_path.display());
        eprintln!("  - {}", normal_path.display());
        eprintln!();
        eprintln!("Do NOT run this on your real documents, pictures, or projects.");
        eprint!("Continue? [y/N]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            eprintln!("Cancelled.");
            std::process::exit(0);
        }
    }

    info!("Deploying bait files in {}...", target.display());
    let canary = deploy_canary(&target, "invoice_Q2_2026.docx", 4096)
        .expect("failed to deploy canary");

    info!("Deploying normal test files...");
    let normal = deploy_test_file(&target, "project_notes.txt", 2048)
        .expect("failed to deploy test file");

    info!("Simulating encryption (hold-open={}ms)...", hold_open_ms);
    encrypt_file_with_hold(&normal, hold_open_ms).expect("failed to encrypt normal file");
    encrypt_file_with_hold(&canary.path, hold_open_ms).expect("failed to encrypt canary file");

    info!("Done. The canary hash is now different.");
}

/// Accept only paths that are clearly temporary test directories.
fn is_acceptable_test_directory(path: &std::path::Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();

    let forbidden = [
        "/", "/home", "/root", "/etc", "/usr", "/bin", "/lib", "/sys", "/dev",
        "c:\\", "c:\\users", "c:\\windows",
    ];
    for bad in &forbidden {
        if path_str == *bad {
            return false;
        }
    }

    // Must be under the system temp folder.
    let under_temp = path.starts_with(std::env::temp_dir());

    // The directory name should make it obvious it is a test/sandbox.
    let name_ok = path_str.contains("rd-")
        || path_str.contains("ransomduck")
        || path_str.contains("test")
        || path_str.contains("sandbox");

    under_temp && name_ok
}
