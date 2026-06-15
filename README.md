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
cooldown_seconds = 5
canaries = ["invoice_Q2_2026.docx"]
```

Start the agent:

```bash
./target/release/ransomduck --config /tmp/rd-demo/ransomduck.toml
```

In another terminal, trigger the test simulator:

```bash
./target/release/fake-ransomware --yes --hold-open-ms 1000 /tmp/rd-demo
```

Watch `/tmp/rd-demo/logs/audit.jsonl` for JSON Lines output.

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
- **rd-audit:** structured audit log.
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
