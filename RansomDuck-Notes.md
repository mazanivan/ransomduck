# RansomDuck — Development Notes

## Session handoff — current state

Use this section when picking up the project after a break. Below is the minimal context needed to continue.

### What RansomDuck does today

- Local canary detection on Linux via the `notify` crate.
- Best-effort `/proc/*/fd` process attribution (Linux only; timing-sensitive).
- Transparent scoring model with signals and response levels (`Monitor` / `Restrict` / `Contain`).
- Append-only JSON Lines audit log.
- Duplicate-suppression per `PID@path` with configurable cooldown.
- TOML configuration: `watch_path`, `log_dir`, `webhook_url`, `cooldown_seconds`, `canaries`.
- Webhook notifications on every incident (tested with ntfy.sh; works on phone).
- GitHub repo at https://github.com/mazanivan/ransomduck.

### Open decisions / next steps

Choose one of these when the next session starts:

1. **Tauri tray GUI** — system-tray application showing status and recent incidents.
2. **Discord/Slack webhook adapters** — format payload for specific services instead of generic JSON.
3. **Containment** — suspend or kill a suspicious process after detection.
4. **Windows process attribution** — ETW/Handle-based PID attribution for the Windows adapter.
5. **Repository cleanup** — decide whether to keep `RansomDuck-Design.md` and `RansomDuck-Notes.md` in repo root, move them to a `docs/` folder, or remove them from the public repository.

### How to run the agent

```bash
cd /home/diego/Documents/Projects/interesting-ideas/ransomduck
cargo build --release
./target/release/ransomduck --config /path/to/ransomduck.toml
```

Example `ransomduck.toml`:

```toml
watch_path = "/tmp/rd-demo"
log_dir = "/tmp/rd-demo/logs"
webhook_url = "https://ntfy.sh/your-secret-topic-xyz"
cooldown_seconds = 5
canaries = ["invoice_Q2_2026.docx"]
```

---

## 2026-06-15 — Real PID attribution on Linux via `/proc` scan

### Goal
Wire the canary watcher to the existing `/proc/*/fd` scanner so that a detected ransomware simulation is attributed to the real process, not to `unknown-process (PID 0)`.

### What changed
1. **`rd-core/src/process_linux.rs`**
   - Added `process_info_from_pid()` to turn a PID into the shared `ProcessInfo` struct by reading `/proc/<pid>/exe`, `cmdline`, and `stat`.
   - Fixed a subtle Rust bug: the original `find_process_for_file()` used `?` inside `for` loops over `/proc` entries. `?` returns from the *function*, so the first unreadable `/proc` entry or broken fd symlink aborted the whole scan instead of being skipped. Replaced with `match`/ `continue`.
   - Added an integration test `finds_a_process_holding_a_file_open` that starts a Python child holding a temp file open and verifies the scanner finds it.

2. **`rd-core/src/lib.rs`**
   - Added `process_linux` module (Linux only).
   - Added `resolve_process_for_path()` with a small retry window (15 attempts, 30 ms).
   - `handle_notify_event()` now calls the resolver for canary modifications and falls back to an unknown-process placeholder only if attribution fails.

3. **`rd-simulator/src/lib.rs` & `src/main.rs`**
   - Added `encrypt_file_with_hold(path, hold_ms)` that keeps the file descriptor open after writing.
   - Added CLI flag `--hold-open-ms <ms>` to `fake-ransomware`.

### Results
- `cargo test` passes (7 tests).
- End-to-end demo:
  ```text
  Canary modified by /home/diego/.../ransomduck/target/debug/fake-ransomware (PID 1157213)
  Incident ... created with score 44
  ```
- The canary deployment event from the simulator is still reported as `unknown-process (PID 0)` because that process has already closed the file by the time the watcher sees the event. The encryption event(s) during the hold window are now correctly attributed.

### Key lesson
`?` inside a loop body does **not** skip the current iteration; it returns from the enclosing function. Infallible-looking helpers like `DirEntry::ok()` must be handled with `match`/`continue` when scanning external, partial filesystems such as `/proc`.

### Known limitations
- `/proc` attribution is best-effort and timing-sensitive. It only works while the process still holds the file open.
- Multiple rapid events can create duplicate incidents for the same attack; deduplication is not yet implemented.
- Works only for same-user processes on Linux unless the agent runs as root.

### Next steps (obsolete)
1. ~~Add event deduplication / incident coalescing~~ done below.
2. ~~Write a structured incident JSON file in addition to the tracing/audit log~~ done below.
3. Start the Windows ETW/Handle-based process attribution adapter.

---

## 2026-06-15 — Incident persistence, deduplication, and TOML config

### Goal
Make the agent usable beyond a terminal demo: it should keep a durable audit log, suppress duplicate detections, and read its settings from a TOML file.

### What changed
1. **`rd-audit/src/lib.rs`**
   - `AuditLogger` can now write every entry to a JSON Lines file (`audit.jsonl`) in a user-defined directory.
   - The file handle is kept open in a `BufWriter` wrapped by `Arc<Mutex<>>` so multiple threads can append safely.

2. **`rd-core/src/lib.rs`**
   - `Agent` now tracks recent incidents using a `HashMap<String, Instant>` keyed by `PID@path`.
   - A configurable cooldown (default 5 s) suppresses follow-up `notify` events caused by the same process flushing/closing the file.
   - Added `with_log_dir()` and `set_cooldown()` constructors.

3. **`rd-core/src/config.rs`** (new)
   - Added `Config` struct loaded from TOML: `watch_path`, `log_dir`, `cooldown_seconds`, `canaries`.
   - Minimal configs work because missing fields use defaults.
   - Two unit tests cover minimal and full TOML parsing.

4. **`rd-cli/src/main.rs`**
   - Switched to `clap` derive parser.
   - Supports `ransomduck [--config <file>] [watch-directory]`.
   - Deploys all canary files listed in config and initializes logging/dedup from it.

### How it works
- When a canary changes, the watcher still calls `/proc` attribution as before.
- Before creating an incident, the agent asks: “Did I already create an incident for this PID + path within the cooldown window?”
  - If yes, the event is ignored.
  - If no, an incident is created, logged to tracing, and appended to `audit.jsonl`.
- The JSON Lines file is append-only and created on first write, so it survives agent restarts.

### Results
- `cargo test` passes (9 tests).
- End-to-end run with config:
  ```bash
  ./target/debug/ransomduck --config /tmp/rd-test-e2e/ransomduck.toml
  ./target/debug/fake-ransomware --yes --hold-open-ms 1000 /tmp/rd-test-e2e
  ```
  Produces:
  - a detection entry with the real `fake-ransomware` PID,
  - no duplicate incidents from rapid follow-up events,
  - an `audit.jsonl` entry like:
    ```json
    {"entry_id":"...","timestamp":"...","severity":"warning","category":"detection","message":"Canary modified by .../fake-ransomware (PID 1160344)","source":"rd-core","related_incident_id":null}
    ```

### Configuration example (`ransomduck.toml`)
```toml
watch_path = "/tmp/rd-test-e2e"
log_dir = "/tmp/rd-test-e2e/logs"
cooldown_seconds = 5
canaries = ["invoice_Q2_2026.docx"]
```

### Known limitations
- `/proc` attribution remains timing-sensitive (explained in the previous section).
- The audit file is plain JSONL with no integrity checks yet.
- ~~Webhook/desktop notifications are not implemented yet.~~ webhook done below.

### Next steps
1. ~~Add webhook or desktop notification on incident creation.~~ done below.
2. Add a minimal Tauri tray GUI to show status and recent incidents.
3. Begin the Windows process-attribution adapter (ETW / Handle info).

---

## 2026-06-15 — Webhook notifications on incident creation

### Goal
Send a real-time HTTP POST to a user-configurable URL every time an incident is created, so the agent can notify external services like Discord, Slack, ntfy.sh, or a custom server.

### What changed
1. **`crates/rd-audit/src/webhook.rs`** (new)
   - Added `WebhookClient`, a thin synchronus HTTP wrapper around `ureq`.
   - Added `WebhookPayload` serialisable to JSON; it contains source, timestamp, severity, score, level, process summary, and affected paths.
   - Delivery is best-effort: errors are logged but never block detection.
   - Unit test `payload_serialises_to_json` checks the JSON schema.

2. **`crates/rd-audit/src/lib.rs`**
   - Added `webhook_url` support to `AuditLogger` via `with_webhook()`.
   - `log_incident()` now also forwards the incident to the webhook client.

3. **`crates/rd-core/src/config.rs`**
   - Added `webhook_url: Option<String>` to `Config`.
   - Updated TOML tests for the new field.

4. **`crates/rd-core/src/lib.rs`**
   - Added `Agent::from_config()` as a single constructor that wires log dir, webhook, and cooldown from the config file.

5. **`crates/rd-cli/src/main.rs`**
   - Replaced manual agent setup with `Agent::from_config(&config)`.

6. **`README.md`**
   - Updated config example with a `webhook_url`.
   - Documented the JSON payload schema.

### How it works
- When `log_incident()` is called, the `AuditLogger`:
  1. writes the entry to tracing,
  2. appends the entry to `audit.jsonl`,
  3. serialises the incident into a `WebhookPayload`, and
  4. POSTs it to the configured URL with a 5-second timeout.
- If the POST fails, only a warning is emitted; detection and logging continue.

### Configuration example
```toml
watch_path = "/tmp/rd-demo"
log_dir = "/tmp/rd-demo/logs"
webhook_url = "https://ntfy.sh/your-secret-topic-xyz"
cooldown_seconds = 5
canaries = ["invoice_Q2_2026.docx"]
```

### Results
- `cargo test` passes (10 tests).
- Feature pushed to GitHub at `https://github.com/mazanivan/ransomduck`.

### Known limitations
- The webhook client is synchronous. If the endpoint is extremely slow, it can briefly delay the watcher thread. Later slices can move it to a background channel/worker.
- There is no retry logic yet.
- No built-in signature/authentication for verifying webhook origin.

### Next steps
1. ~~Add a minimal Tauri tray GUI to show status and recent incidents.~~ done below.
2. Combine the agent and GUI into a single binary for easier end-user use.
3. Begin the Windows process-attribution adapter (ETW / Handle info).
4. Optional: add retry/backoff or async webhook queue.

---

## 2026-06-15 — Tauri system-tray GUI

### Goal
Provide a minimal desktop GUI that can start/stop the agent and display recent incidents, accessible from the system tray.

### What changed
1. **`gui/tauri-app/`** (new)
   - Tauri v2 project with a vanilla HTML/CSS/JS frontend.
   - System-tray icon with **Show** and **Quit** menu items.
   - Main window shows agent status, config path, log directory, and a list of recent incidents.
   - `start_agent` / `stop_agent` / `get_status` / `get_recent_incidents` Tauri commands in `src-tauri/src/lib.rs`.
   - GUI locates the `ransomduck` binary next to itself first, then falls back to `PATH`.
   - Reads incident entries from `audit.jsonl` in the configured log directory.

2. **`Cargo.toml`** (workspace root)
   - Added `gui/tauri-app/src-tauri` to workspace members.

3. **`README.md`**
   - Added "Tauri tray GUI" section with prerequisites, dev/build/run instructions, and usage notes.

4. **`.gitignore`**
   - Ignored `.node/`, `node_modules/`, `dist/`, `.tauri/`.

### How to run
```bash
cargo build --release --bin ransomduck
cd gui/tauri-app
export PATH=/home/diego/Documents/Projects/interesting-ideas/ransomduck/target/release:$PATH
npm install
npm run tauri dev
```

### Results
- `cargo test --workspace` passes.
- `npm run tauri build` produces `target/release/ransomduck-tray` successfully.
- `.deb`/`.rpm` bundling is disabled by default (`"bundle": { "active": false }`); enable it in `tauri.conf.json` when packaging is needed.

### Known limitations
- Tray menu is static (Show / Quit only). Dynamic items such as "Start agent" / "Stop agent" from the tray are not implemented yet.
- Incident list is read on demand; live updates require clicking Refresh or restarting the agent/window.
- The GUI assumes the agent writes to `audit.jsonl`; if `log_dir` is not configured, it defaults to `<watch_path>/logs`.

### Next steps
1. Embed agent logic inside Tauri GUI for a single-app experience.
2. Add containment actions (suspend/kill) and surface them in the GUI.
3. Windows process-attribution adapter (ETW / Handle info).

---

## 2026-06-16 — Agent embedded in Tauri GUI + playful UI

### Goal
Make RansomDuck a single, easy-to-run desktop app with an engaging interface, instead of two separate binaries.

### What changed
1. **`crates/rd-core/src/lib.rs`**
   - Added `watch_path_with_callback` and `watch_path_with_callback_until`, which call a user-provided closure for every incident.
   - The `_until` variant accepts a stop flag so the watcher thread can be shut down cleanly.
   - `handle_notify_event` now returns the created `Incident`.

2. **`gui/tauri-app/src-tauri/src/lib.rs`**
   - Removed external `ransomduck` process spawning.
   - `AgentRunner` now owns the agent and runs the file watcher on a background thread.
   - Incidents are emitted to the frontend in real time via Tauri events.
   - Config is loaded from and saved to `~/.config/RansomDuck/ransomduck.toml`.
   - Added `start_protection`, `stop_protection`, `get_status`, `get_incidents`, `load_config`, `save_config` Tauri commands.
   - Tray menu has **Show / Hide / Quit** and left-click toggles the window.
   - Canary file names are generated randomly at runtime (`invoice_05_2026_4821.docx`, ...).
   - Deployed canary files are tracked and automatically removed when protection stops or the app exits.

3. **`gui/tauri-app/src/` frontend**
   - Redesigned with a duck mascot, gradients, animations, and a dark playful theme.
   - Settings are edited directly in the GUI (protected folder, canaries, webhook, cooldown).
   - Incident list updates in real time and shows score, severity, process path, and timestamp.
   - Added a test hint pointing users to `fake-ransomware`.

4. **Build setup**
   - Added Vite 5 as the dev server/build tool for Tauri.
   - `tauri.conf.json` uses `beforeDevCommand` and `beforeBuildCommand`.

5. **Cargo.toml dependencies**
   - `ransomduck-tray` now depends on `rd-core`, `rd-audit`, `rd-simulator`, `directories`, `tracing-subscriber`, and `toml`.

6. **End-user install scripts**
   - Added `install.sh` and `uninstall.sh` in the repo root.
   - `install.sh` copies the release binary to `~/.local/bin` and registers a `.desktop` menu entry with a duck icon.
   - `uninstall.sh` removes the binary, menu entry, and icon.

### How to run
```bash
cd /home/diego/Documents/Projects/interesting-ideas/ransomduck
cd gui/tauri-app
PATH=/home/diego/Documents/Projects/interesting-ideas/ransomduck/.node/bin:$PATH npm install
PATH=/home/diego/Documents/Projects/interesting-ideas/ransomduck/.node/bin:$PATH npm run tauri dev
```

### Results
- `cargo test --workspace` passes.
- `npm run tauri build` produces `target/release/ransomduck-tray` successfully.
- The resulting binary is self-contained and no longer needs a separate `ransomduck` executable.

### Known limitations
- Folder selection still uses a text input; a native folder picker would improve UX.
- No process containment yet (kill/suspend) – detection only.
- `/proc/*/fd` attribution is still timing-sensitive.
- Linux only; Windows/macOS adapters are on the roadmap.
- Canary cleanup relies on graceful shutdown; SIGKILL can leave decoy files behind.

### Next steps
1. Add native folder picker dialog.
2. Implement containment: kill/suspend suspicious process.
3. Improve Linux attribution with `fanotify`.
4. Build `.rpm` installer for Fedora.
5. Windows process-attribution adapter.

