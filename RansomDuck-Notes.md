# RansomDuck — Development Notes

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
webhook_url = "https://ntfy.sh/moj-ransomduck-r56x"
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
1. Add a minimal Tauri tray GUI to show status and recent incidents.
2. Begin the Windows process-attribution adapter (ETW / Handle info).
3. Optional: add retry/backoff or async webhook queue.

