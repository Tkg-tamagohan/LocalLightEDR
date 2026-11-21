// Native Messaging bridge client wrapper and `chrome.storage.local` diagnostics helper.

export const NATIVE_HOST_NAME = "com.localedr.bridge";
export const BRIDGE_DIAGNOSTICS_KEY = "ledr_bridge_diagnostics";

export function defaultDiagnostics() {
  return {
    daemonOnline: false,
    daemonVersion: null,
    protocolVersion: null,
    lastPingAtMs: null,
    lastSuccessAtMs: null,
    lastError: null,
    counters: {
      clickfixBlocked: 0,
      domainWarnings: 0,
      dnrMatched: 0,
      downloadsTracked: 0,
    },
  };
}

function mergeDiagnostics(raw) {
  const base = defaultDiagnostics();
  if (!raw || typeof raw !== "object") {
    return base;
  }
  return {
    ...base,
    ...raw,
    counters: {
      ...base.counters,
      ...(raw.counters && typeof raw.counters === "object" ? raw.counters : {}),
    },
  };
}

export function buildPingRequest() {
  return { type: "Ping" };
}

export function buildCheckDomainRiskRequest(domain) {
  return {
    type: "CheckDomainRisk",
    payload: { domain },
  };
}

export function buildReportDownloadOriginRequest({
  filePath,
  tabUrl,
  frameUrl = null,
  referrerUrl = null,
  downloadedAtMs = Date.now(),
}) {
  return {
    type: "ReportDownloadOrigin",
    payload: {
      file_path: filePath,
      tab_url: tabUrl,
      frame_url: frameUrl,
      referrer_url: referrerUrl,
      downloaded_at_ms: downloadedAtMs,
    },
  };
}

export function buildReportBrowserEventRequest({
  eventType,
  url,
  details = null,
  timestampMs = Date.now(),
}) {
  return {
    type: "ReportBrowserEvent",
    payload: {
      event_type: eventType,
      url,
      details,
      timestamp_ms: timestampMs,
    },
  };
}

export async function getDiagnostics(storageLocal) {
  const data = await storageLocal.get([BRIDGE_DIAGNOSTICS_KEY]);
  return mergeDiagnostics(data?.[BRIDGE_DIAGNOSTICS_KEY]);
}

export async function incrementCounter(storageLocal, counterName, delta = 1) {
  const diag = await getDiagnostics(storageLocal);
  const current = Number(diag.counters[counterName] ?? 0);
  diag.counters[counterName] = Math.max(0, current + delta);
  await storageLocal.set({ [BRIDGE_DIAGNOSTICS_KEY]: diag });
  return diag;
}

/**
 * Sends a single IPC request through `chrome.runtime.sendNativeMessage("com.localedr.bridge", ...)`,
 * updating `chrome.storage.local` diagnostics without ever throwing out of the Service Worker.
 */
export async function sendNativeRequest(request, deps) {
  const { runtimeApi, storageLocal, nowFn = () => Date.now() } = deps;
  const now = nowFn();
  const diag = await getDiagnostics(storageLocal);
  if (request?.type === "Ping") {
    diag.lastPingAtMs = now;
  }

  let response;
  try {
    response = await runtimeApi.sendNativeMessage(NATIVE_HOST_NAME, request);
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    diag.daemonOnline = false;
    diag.lastError = errMsg || "Native Messaging host unreachable";
    await storageLocal.set({ [BRIDGE_DIAGNOSTICS_KEY]: diag });
    return {
      ok: false,
      response: null,
      error: diag.lastError,
      diagnostics: diag,
    };
  }

  if (!response || typeof response !== "object") {
    diag.daemonOnline = false;
    diag.lastError = "Empty response from Native Messaging bridge";
    await storageLocal.set({ [BRIDGE_DIAGNOSTICS_KEY]: diag });
    return {
      ok: false,
      response: null,
      error: diag.lastError,
      diagnostics: diag,
    };
  }

  if (response.type === "Error") {
    const code = response.payload?.code || "ERROR";
    const msg = response.payload?.message || "Unknown daemon/bridge error";
    const bridgeDown = code === "DAEMON_OFFLINE" || code === "BRIDGE_TRANSPORT_ERROR";
    diag.daemonOnline = !bridgeDown;
    diag.lastError = `[${code}] ${msg}`;
    await storageLocal.set({ [BRIDGE_DIAGNOSTICS_KEY]: diag });
    return {
      ok: false,
      response,
      error: diag.lastError,
      diagnostics: diag,
    };
  }

  diag.daemonOnline = true;
  diag.lastSuccessAtMs = now;
  diag.lastError = null;
  if (response.type === "Pong") {
    diag.daemonVersion = response.payload?.daemon_version ?? diag.daemonVersion;
    diag.protocolVersion = response.payload?.protocol_version ?? diag.protocolVersion;
  }

  await storageLocal.set({ [BRIDGE_DIAGNOSTICS_KEY]: diag });
  return {
    ok: true,
    response,
    error: null,
    diagnostics: diag,
  };
}
