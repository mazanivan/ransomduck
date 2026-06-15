# RansomDuck

A local, explainable anti-ransomware canary agent for small businesses, freelancers, schools, and anyone who wants an extra layer of detection on their own machines.

> **Status:** early MVP. Detection works on Linux today; Windows and macOS process attribution are on the roadmap.

## What it does

RansomDuck places decoy files (canaries) in directories you want to protect. If something modifies a canary, it immediately builds an **explainable incident** with a risk score, logs it, and tries to identify the responsible process. The score is built from transparent signals and thresholds, not a black-box ML model.

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
webhook_url = "https://ntfy.sh/moj-ransomduck-r56x"
cooldown_seconds = 5
canaries = ["invoice_Q2_2026.docx"]
```

Replace `moj-ransomduck-r56x` with your own topic on ntfy.sh or use Discord/Slack/Telegram webhook URL.

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

### Test

```bash
cargo test
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
- **rd-audit:** structured audit log and webhook notifications.
- **rd-simulator:** `fake-ransomware` test binary.
- **rd-cli:** `ransomduck` binary.
- **rd-common:** shared data models.

See [`RansomDuck-Design.md`](RansomDuck-Design.md) for the full design and threat model, and [`RansomDuck-Notes.md`](RansomDuck-Notes.md) for day-to-day development notes.

## Current limitations

- Process attribution on Linux relies on scanning `/proc/*/fd`, which only works while the file is still open. Real, fast-closing ransomware is better attributed through `fanotify`/`auditd`/eBPF on Linux or ETW on Windows.
- Containment (suspend/kill) is not implemented yet.
- Windows and macOS support is planned.

## License

MIT OR Apache-2.0
