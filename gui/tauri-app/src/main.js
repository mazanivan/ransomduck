const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let config = {
  watchPath: "",
  canaryCount: 5,
  webhookUrl: "",
  cooldownSeconds: 5,
};

const els = {
  statusDot: document.querySelector("#status-dot"),
  statusText: document.querySelector("#status-text"),
  watchPath: document.querySelector("#watch-path"),
  cooldown: document.querySelector("#cooldown"),
  canaryCount: document.querySelector("#canary-count"),
  canaryNames: document.querySelector("#canary-names"),
  webhook: document.querySelector("#webhook"),
  saveBtn: document.querySelector("#save-btn"),
  startBtn: document.querySelector("#start-btn"),
  stopBtn: document.querySelector("#stop-btn"),
  info: document.querySelector("#info"),
  incidentCount: document.querySelector("#incident-count"),
  incidentList: document.querySelector("#incident-list"),
};

function renderStatus(state) {
  const running = state.running;
  els.statusDot.className = "status-dot " + (running ? "running" : "stopped");
  els.statusText.textContent = running
    ? "Protection is running"
    : "Protection is stopped";

  els.startBtn.disabled = running;
  els.stopBtn.disabled = !running;

  if (state.canaryNames && state.canaryNames.length > 0) {
    els.canaryNames.textContent = state.canaryNames.join(", ");
  } else {
    els.canaryNames.textContent = "(none yet)";
  }

  if (state.watchPath) {
    els.info.textContent = `Watching: ${state.watchPath} • Incidents: ${state.incidentCount}`;
  } else {
    els.info.textContent = running
      ? "Protection is active."
      : "Configure the folder and press Start protection.";
  }
}

function renderIncidents(incidents) {
  const all = [...(window.__rd_incidents || []), ...incidents];
  window.__rd_incidents = all;

  els.incidentCount.textContent = all.length;

  if (all.length === 0) {
    els.incidentList.innerHTML =
      '<li class="empty">No incidents yet. Start protection and try the simulator!</li>';
    return;
  }

  const list = [...all].reverse();
  els.incidentList.innerHTML = list
    .map((inc) => {
      const time = new Date(inc.timestamp).toLocaleString();
      const severityClass = inc.severity.toLowerCase();
      return `
        <li class="incident ${severityClass}">
          <div class="incident-title">
            <span class="severity">${escapeHtml(inc.severity)}</span>
            <span class="score">score ${inc.score}</span>
            <span class="time">${escapeHtml(time)}</span>
          </div>
          <div class="incident-process">${escapeHtml(inc.processPath)} (PID ${inc.processPid})</div>
          <div class="incident-message">${escapeHtml(inc.message)}</div>
        </li>
      `;
    })
    .join("");
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function getConfigFromForm() {
  return {
    watchPath: els.watchPath.value.trim(),
    canaryCount: parseInt(els.canaryCount.value, 10) || 5,
    webhookUrl: els.webhook.value.trim() || null,
    cooldownSeconds: parseInt(els.cooldown.value, 10) || 5,
  };
}

function fillForm(cfg) {
  els.watchPath.value = cfg.watchPath || "";
  els.cooldown.value = cfg.cooldownSeconds || 5;
  els.canaryCount.value = cfg.canaryCount || 5;
  els.webhook.value = cfg.webhookUrl || "";
}

async function refreshStatus() {
  try {
    const state = await invoke("get_status");
    renderStatus(state);
  } catch (e) {
    els.info.textContent = "Error: " + e;
  }
}

async function saveConfig() {
  const cfg = getConfigFromForm();
  try {
    const saved = await invoke("save_config", { config: cfg });
    config = saved;
    fillForm(config);
    els.info.textContent = "Settings saved.";
  } catch (e) {
    els.info.textContent = "Failed to save settings: " + e;
  }
}

async function startProtection() {
  els.startBtn.disabled = true;
  try {
    const state = await invoke("start_protection");
    renderStatus(state);
    const incidents = await invoke("get_incidents", { limit: 50 });
    renderIncidents(incidents);
  } catch (e) {
    els.info.textContent = "Failed to start protection: " + e;
    els.startBtn.disabled = false;
  }
}

async function stopProtection() {
  els.stopBtn.disabled = true;
  try {
    const state = await invoke("stop_protection");
    renderStatus(state);
  } catch (e) {
    els.info.textContent = "Failed to stop protection: " + e;
  }
}

window.addEventListener("DOMContentLoaded", async () => {
  try {
    const loaded = await invoke("load_config");
    config = loaded;
    fillForm(config);
  } catch (e) {
    console.error("Failed to load config", e);
  }

  await refreshStatus();

  try {
    const incidents = await invoke("get_incidents", { limit: 50 });
    renderIncidents(incidents);
  } catch (e) {
    console.error("Failed to load incidents", e);
  }

  listen("incident", (event) => {
    const incident = event.payload;
    renderIncidents([incident]);
  }).then(() => {
    console.log("Listening for real-time incidents");
  });

  els.saveBtn.addEventListener("click", saveConfig);
  els.startBtn.addEventListener("click", startProtection);
  els.stopBtn.addEventListener("click", stopProtection);
});

window.__rd_incidents = window.__rd_incidents || [];
