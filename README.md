# RansomDuck

A local, explainable anti-ransomware canary agent for small businesses, freelancers, schools, and anyone who wants an extra layer of detection on their own machines.

> **Status:** early MVP. Detection works on Linux today; Windows and macOS process attribution are on the roadmap.

## What it does

RansomDuck places decoy files (canaries) in directories you want to protect. If something modifies a canary, it immediately builds an **explainable incident** with a risk score, logs it, tries to identify the responsible process, and can optionally suspend or kill it. The score is built from transparent signals and thresholds, not a black-box ML model.

```text
Canary modified by /home/you/.../fake-ransomware (PID 1160344)
Incident 9f1a9f78-... created with score 44
```

## Quick start

### Build

```bash
cargo build --release
```

### Run

Create a minimal config file:

```toml
# /tmp/rd-demo/ransomduck.toml
watch_path = "/tmp/rd-demo"
log_dir = "/tmp/rd-demo/logs"
webhook_url = "https://ntfy.sh/your-secret-topic-xyz"
cooldown_seconds = 5
canaries = ["invoice_Q2_2026.docx"]
# Optional: "none" (default), "suspend", or "kill".
containment_action = "kill"
# Optional: "contain" (default) or "restrict". Set to "restrict" to react on lower scores.
containment_threshold = "restrict"
```

Replace `your-secret-topic-xyz` with your own topic on ntfy.sh or use Discord/Slack/Telegram webhook URL.

Start the agent:

```bash
./target/release/ransomduck --config /tmp/rd-demo/ransomduck.toml
```

In another terminal, trigger the test simulator:

```bash
./target/release/fake-ransomware --yes --hold-open-ms 1000 /tmp/rd-demo
```

Watch `/tmp/rd-demo/logs/audit.jsonl` for JSON Lines output.

If you configured `webhook_url`, the agent will also POST a JSON payload to that URL every time an incident is created:

```json
{
  "source": "RansomDuck",
  "timestamp": "2026-06-15T18:34:00.123456789Z",
  "severity": "Warning",
  "category": "incident",
  "message": "Canary modified by /.../fake-ransomware (PID 1160344)",
  "score": 44,
  "level": "Restrict",
  "incident_id": "...",
  "process": { "pid": 1160344, "image_path": "...", "command_line": "...", ... },
  "affected_paths": ["/tmp/rd-demo/invoice_Q2_2026.docx"]
}
```

## Webhook setup (notification on your phone/PC)

The agent sends the JSON above as a `POST` with `Content-Type: application/json` and a 5-second timeout. You can use any service that accepts JSON POST requests.

### ntfy.sh (recommended — works without registration)

1. Pick a unique topic name, e.g. `your-secret-topic-xyz`.
2. In your phone/browser subscribe to `https://ntfy.sh/your-secret-topic-xyz`.
3. Set in `ransomduck.toml`:
   ```toml
   webhook_url = "https://ntfy.sh/your-secret-topic-xyz"
   ```
4. Trigger an incident with `fake-ransomware`. The notification appears immediately.

### Discord

1. In your Discord server, go to **Server Settings → Integrations → Webhooks → New Webhook**.
2. Copy the webhook URL and paste it into `ransomduck.toml`:
   ```toml
   webhook_url = "https://discord.com/api/webhooks/..."
   ```
3. Discord will post a raw JSON message. For a cleaner embed you would need a small adapter later.

### Telegram or Slack

- **Slack:** create an Incoming Webhook and use its URL.
- **Telegram:** the generic JSON payload is not directly compatible with Telegram Bot API; a small translator would be needed.

For quick personal testing, **ntfy.sh** is the easiest.

### Test

```bash
cargo test
```

## Tauri tray GUI

A native system-tray application is available in `gui/tauri-app/`. It embeds the RansomDuck agent directly, so the user only needs to run **one** application. It displays protection status and incidents in real time.

### Prerequisites

- Node.js 20+ (the GUI ships its own copy under `.node/` for convenience, or you can use your system Node.js).
- Linux system libraries for Tauri. On Fedora install:
  ```bash
  sudo dnf install webkit2gtk4.1-devel openssl-devel curl wget file libappindicator-gtk3-devel librsvg2-devel gtk3-devel patchelf
  ```

### Run in development mode

```bash
# 1. Install npm dependencies
cd gui/tauri-app
npm install

# 2. Start the GUI with hot-reload
#    This starts a Vite dev server and opens the native Tauri window.
PATH=/home/diego/Documents/Projects/interesting-ideas/ransomduck/.node/bin:$PATH npm run tauri dev
```

The `npm run tauri dev` command starts a small local dev server used only during development, but the actual window is a native desktop application, not a browser tab.

### Build a release binary

```bash
cd gui/tauri-app
npm run tauri build
```

The compiled binary is written to `target/release/ransomduck-tray`.

### Usage

1. Run `ransomduck-tray` from the build output or system menu.
2. Click **Browse** to pick the folder you want to protect, set the number of canary files, and optionally a webhook URL.
3. Choose a **Containment** action: `none` (log only), `suspend`, or `kill`, and a **Threshold**: `contain` (default) or `restrict`.
4. Click **Save settings**, then **Start protection**. Canary file names are generated randomly each run.
5. The duck icon in the system tray shows the current status; left-click the icon to show or hide the window.
6. Incidents appear in the GUI in real time and are still written to `~/.config/RansomDuck/logs/audit.jsonl`.

To enable bundling of `.deb`/`.rpm`/AppImage packages, set `"bundle": { "active": true }` in `gui/tauri-app/src-tauri/tauri.conf.json`.

## Install and run as a normal user

After building the release binary you can install it like any other desktop app:

```bash
cd /home/diego/Documents/Projects/interesting-ideas/ransomduck
./install.sh
```

This copies `ransomduck-tray` to `~/.local/bin` and creates an entry in your application menu. You can then:

1. Open your system menu and launch **RansomDuck** (look for the duck icon 🦆).
2. Or run it from the terminal:
   ```bash
   ransomduck-tray
   ```

To remove it later:

```bash
./uninstall.sh
```

## Architecture

```text
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│ file watcher│────▶│   Agent      │────▶│ audit logger │
│  (notify)   │     │  + scoring   │     │  tracing/    │
└─────────────┘     └──────────────┘     │  JSONL file  │
                                         └──────────────┘
```

- **rd-core:** agent, file watcher, Linux `/proc` process attribution, configuration.
- **rd-detection:** scoring and response levels.
- **rd-containment:** process suspend/kill actions (Linux via `SIGSTOP`/`SIGKILL`).
- **rd-audit:** structured audit log and webhook notifications.
- **rd-simulator:** `fake-ransomware` test binary.
- **rd-cli:** `ransomduck` headless binary.
- **rd-common:** shared data models.
- **ransomduck-tray:** native system-tray GUI that embeds the agent (`gui/tauri-app/`).

## Current limitations

- Process attribution on Linux relies on scanning `/proc/*/fd`, which only works while the file is still open. Real, fast-closing ransomware is better attributed through `fanotify`/`auditd`/eBPF on Linux or ETW on Windows.
- Containment (suspend/kill) is implemented on Linux; Windows and macOS currently return a not-implemented action record.
- Windows and macOS process attribution and containment are planned.

## License

MIT OR Apache-2.0
