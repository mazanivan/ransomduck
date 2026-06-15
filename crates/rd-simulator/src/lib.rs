use rand::Rng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

/// A canary file looks attractive to ransomware but is known to the agent.
#[derive(Debug, Clone)]
pub struct Canary {
    pub path: PathBuf,
    pub original_hash: Vec<u8>,
}

/// Deploy a realistic-looking canary file and return its hash.
pub fn deploy_canary(directory: &Path, name: &str, size_bytes: usize) -> std::io::Result<Canary> {
    let path = directory.join(name);
    let content = generate_random_content(size_bytes);

    let mut file = fs::File::create(&path)?;
    file.write_all(&content)?;

    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hasher.finalize().to_vec();

    Ok(Canary { path, original_hash: hash })
}

/// Deploy a normal-looking test file used by the simulator.
pub fn deploy_test_file(directory: &Path, name: &str, size_bytes: usize) -> std::io::Result<PathBuf> {
    let path = directory.join(name);
    let content = generate_random_content(size_bytes);
    let mut file = fs::File::create(&path)?;
    file.write_all(&content)?;
    Ok(path)
}

/// Simulate ransomware encryption of a single file by overwriting its contents
/// with random bytes. The file is modified in-place.
pub fn encrypt_file(path: &Path) -> std::io::Result<()> {
    encrypt_file_with_hold(path, 0)
}

/// Simulate encryption while keeping the file open for `hold_ms` milliseconds.
///
/// This gives a watcher that relies on `/proc/*/fd` scanning a realistic chance
/// to attribute the modification to this process before the descriptor closes.
pub fn encrypt_file_with_hold(path: &Path, hold_ms: u64) -> std::io::Result<()> {
    let size = fs::metadata(path)?.len() as usize;
    let encrypted = generate_random_content(size);
    let mut file = fs::OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(&encrypted)?;
    file.flush()?;
    thread::sleep(Duration::from_millis(hold_ms));
    Ok(())
}

fn generate_random_content(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}
