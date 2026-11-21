// LocalEDR Browser Shield popup UI controller (async/await, zero inline handlers).

function formatTimestamp(ms) {
  if (typeof ms !== "number" || !Number.isFinite(ms)) {
    return "-";
  }
  return new Date(ms).toLocaleTimeString();
}

function renderState(state) {
  const pillEl = document.getElementById("status-pill");
  const daemonInfoEl = document.getElementById("daemon-info");
  const dnrEl = document.getElementById("stat-dnr");
  const clickfixEl = document.getElementById("stat-clickfix");
  const domainEl = document.getElementById("stat-domain");
  const downloadsEl = document.getElementById("stat-downloads");
  const lastPingEl = document.getElementById("last-ping");
  const extIdEl = document.getElementById("ext-id");

  const diag = state?.diagnostics;
  const online = Boolean(diag?.daemonOnline);

  pillEl.className = online ? "pill pill-online" : "pill pill-offline";
  pillEl.textContent = online ? "Connected" : "Offline";

  if (online) {
    const ver = diag.daemonVersion || "0.1.0";
    const proto = diag.protocolVersion ?? 1;
    daemonInfoEl.textContent = `v${ver} (proto v${proto})`;
  } else {
    daemonInfoEl.textContent = diag?.lastError || "Daemon offline";
  }

  dnrEl.textContent = String(state?.dnr?.totalRuleCount ?? 0);
  clickfixEl.textContent = String(diag?.counters?.clickfixBlocked ?? 0);
  domainEl.textContent = String(diag?.counters?.domainWarnings ?? 0);
  downloadsEl.textContent = String(diag?.counters?.downloadsTracked ?? 0);

  lastPingEl.textContent = `Last ping: ${formatTimestamp(diag?.lastPingAtMs)}`;
  extIdEl.textContent = state?.extensionId ? `ID: ${state.extensionId}` : "-";
}

async function sendAction(type) {
  try {
    return await chrome.runtime.sendMessage({ type });
  } catch (err) {
    return {
      ok: false,
      diagnostics: {
        daemonOnline: false,
        lastError: err instanceof Error ? err.message : String(err),
        counters: {},
      },
    };
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const pingBtn = document.getElementById("ping-btn");

  pingBtn.addEventListener("click", async () => {
    pingBtn.disabled = true;
    try {
      const state = await sendAction("PING_DAEMON");
      renderState(state);
    } finally {
      pingBtn.disabled = false;
    }
  });

  const initial = await sendAction("GET_POPUP_STATE");
  renderState(initial);
});
