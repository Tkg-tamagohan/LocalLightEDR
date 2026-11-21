// LocalEDR Browser Shield MV3 Service Worker (stateless across restarts; uses chrome.storage).

import { analyzeClipboardPayload } from "./lib/clickfix.js";
import { buildDynamicDnrUpdatePlan } from "./lib/dnr.js";
import { assessLocalDomainRisk, mergeDomainRisk } from "./lib/domain_risk.js";
import {
  handleDownloadChanged,
  handleDownloadCreated,
  pruneStaleDownloadClickHints,
  pruneStalePendingDownloads,
  recordDownloadClickHint,
} from "./lib/downloads.js";
import {
  buildCheckDomainRiskRequest,
  buildPingRequest,
  buildReportBrowserEventRequest,
  getDiagnostics,
  incrementCounter,
  sendNativeRequest,
} from "./lib/native_bridge.js";

const DOMAIN_CACHE_KEY = "ledr_domain_cache";
const DOMAIN_CACHE_TTL_MS = 5 * 60 * 1000;
const DOMAIN_CACHE_MAX_ENTRIES = 512;

const EVENT_DEDUP_KEY = "ledr_event_dedup";
const EVENT_DEDUP_TTL_MS = 30 * 1000;
const EVENT_DEDUP_MAX_ENTRIES = 256;

const CLEANUP_ALARM_NAME = "ledr-cleanup";
const STATIC_RULESET_ID = "ruleset_static";
const STATIC_RULESET_RULE_COUNT = 2;

function extractOriginSafe(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    return "";
  }
  try {
    return new URL(rawUrl).origin;
  } catch {
    return rawUrl.trim().slice(0, 256);
  }
}

async function readBoundedMap(storageSession, key) {
  const res = await storageSession.get([key]);
  const map = res?.[key];
  return map && typeof map === "object" && !Array.isArray(map) ? map : {};
}

async function pruneAndTrimMap(map, ttlMs, maxEntries, now) {
  const entries = Object.entries(map).filter(
    ([, val]) => val && typeof val.ts === "number" && now - val.ts < ttlMs
  );
  entries.sort((a, b) => a[1].ts - b[1].ts);
  const kept = entries.length > maxEntries ? entries.slice(entries.length - maxEntries) : entries;
  return Object.fromEntries(kept);
}

async function getCachedDomainRisk(domain, now) {
  const map = await readBoundedMap(chrome.storage.session, DOMAIN_CACHE_KEY);
  const entry = map[domain];
  if (entry && typeof entry.ts === "number" && now - entry.ts < DOMAIN_CACHE_TTL_MS) {
    return entry.daemonPayload || null;
  }
  return null;
}

async function putCachedDomainRisk(domain, daemonPayload, now) {
  const map = await readBoundedMap(chrome.storage.session, DOMAIN_CACHE_KEY);
  map[domain] = { ts: now, daemonPayload };
  const trimmed = await pruneAndTrimMap(map, DOMAIN_CACHE_TTL_MS, DOMAIN_CACHE_MAX_ENTRIES, now);
  await chrome.storage.session.set({ [DOMAIN_CACHE_KEY]: trimmed });
}

async function isDuplicateBrowserEvent(tabId, url, eventType, now) {
  const origin = extractOriginSafe(url);
  const key = `${tabId}|${origin}|${eventType}`;
  const map = await readBoundedMap(chrome.storage.session, EVENT_DEDUP_KEY);
  const existing = map[key];
  if (existing && typeof existing.ts === "number" && now - existing.ts < EVENT_DEDUP_TTL_MS) {
    return true;
  }
  map[key] = { ts: now };
  const trimmed = await pruneAndTrimMap(map, EVENT_DEDUP_TTL_MS, EVENT_DEDUP_MAX_ENTRIES, now);
  await chrome.storage.session.set({ [EVENT_DEDUP_KEY]: trimmed });
  return false;
}

async function incrementTabAlertBadge(tabId) {
  if (typeof tabId !== "number" || tabId < 0 || !chrome.action) {
    return;
  }
  try {
    const current = await chrome.action.getBadgeText({ tabId });
    const count = Number.parseInt(current || "0", 10);
    const next = Number.isFinite(count) ? Math.min(count + 1, 99) : 1;
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#B91C1C" });
    await chrome.action.setBadgeText({ tabId, text: String(next) });
  } catch {
    // Tab may have closed before badge update ran.
  }
}

function counterForEventType(eventType) {
  switch (eventType) {
    case "ClickFixPastejacking":
      return "clickfixBlocked";
    case "NrdPasswordWarning":
    case "HomographWarning":
      return "domainWarnings";
    case "DnrBlockedRequest":
      return "dnrMatched";
    default:
      return null;
  }
}

async function reportBrowserEvent({ eventType, url, details = null, tabId = -1 }) {
  const now = Date.now();
  const safeUrl = typeof url === "string" && url.trim() ? url.trim() : "about:blank";
  if (await isDuplicateBrowserEvent(tabId, safeUrl, eventType, now)) {
    return { ok: true, deduplicated: true };
  }

  const counterKey = counterForEventType(eventType);
  if (counterKey) {
    await incrementCounter(chrome.storage.local, counterKey, 1);
  }
  if (eventType !== "DnrBlockedRequest") {
    await incrementTabAlertBadge(tabId);
  }

  const request = buildReportBrowserEventRequest({
    eventType,
    url: safeUrl,
    details,
    timestampMs: now,
  });
  const res = await sendNativeRequest(request, {
    runtimeApi: chrome.runtime,
    storageLocal: chrome.storage.local,
    nowFn: () => now,
  });
  return { ok: true, deduplicated: false, bridgeOk: res.ok, error: res.error };
}

async function checkDomainRisk(urlOrHost) {
  const local = assessLocalDomainRisk(urlOrHost);
  if (!local.inspectable) {
    return { ok: true, risk: mergeDomainRisk(local, null), fromCache: false };
  }

  const now = Date.now();
  const cached = await getCachedDomainRisk(local.domain, now);
  if (cached) {
    return { ok: true, risk: mergeDomainRisk(local, cached), fromCache: true };
  }

  const res = await sendNativeRequest(buildCheckDomainRiskRequest(local.domain), {
    runtimeApi: chrome.runtime,
    storageLocal: chrome.storage.local,
    nowFn: () => now,
  });

  let daemonPayload = null;
  if (res.ok && res.response?.type === "DomainRisk") {
    daemonPayload = res.response.payload;
    await putCachedDomainRisk(local.domain, daemonPayload, now);
  }

  return {
    ok: true,
    risk: mergeDomainRisk(local, daemonPayload),
    fromCache: false,
    daemonOnline: res.diagnostics.daemonOnline,
  };
}

async function updateDynamicDnrRules(blockDomains) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const { removeRuleIds, addRules } = buildDynamicDnrUpdatePlan(existing, blockDomains);

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules,
  });
  return { removed: removeRuleIds.length, added: addRules.length };
}

async function buildPopupState() {
  const diagnostics = await getDiagnostics(chrome.storage.local);
  const [enabledRulesets, dynamicRules] = await Promise.all([
    chrome.declarativeNetRequest.getEnabledRulesets(),
    chrome.declarativeNetRequest.getDynamicRules(),
  ]);
  const staticEnabled = enabledRulesets.includes(STATIC_RULESET_ID);
  const staticRuleCount = staticEnabled ? STATIC_RULESET_RULE_COUNT : 0;
  return {
    ok: true,
    extensionId: chrome.runtime.id,
    diagnostics,
    dnr: {
      staticEnabled,
      staticRuleCount,
      dynamicRuleCount: dynamicRules.length,
      totalRuleCount: staticRuleCount + dynamicRules.length,
    },
  };
}

// --- Top-level synchronous MV3 listener registrations ---

chrome.runtime.onInstalled.addListener(async () => {
  await getDiagnostics(chrome.storage.local);
  await chrome.alarms.create(CLEANUP_ALARM_NAME, { periodInMinutes: 10 });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm?.name !== CLEANUP_ALARM_NAME) {
    return;
  }
  const now = Date.now();
  const [domainMap, dedupMap] = await Promise.all([
    readBoundedMap(chrome.storage.session, DOMAIN_CACHE_KEY),
    readBoundedMap(chrome.storage.session, EVENT_DEDUP_KEY),
  ]);
  const prunedDomains = await pruneAndTrimMap(
    domainMap,
    DOMAIN_CACHE_TTL_MS,
    DOMAIN_CACHE_MAX_ENTRIES,
    now
  );
  const prunedDedup = await pruneAndTrimMap(
    dedupMap,
    EVENT_DEDUP_TTL_MS,
    EVENT_DEDUP_MAX_ENTRIES,
    now
  );
  await chrome.storage.session.set({
    [DOMAIN_CACHE_KEY]: prunedDomains,
    [EVENT_DEDUP_KEY]: prunedDedup,
  });
  await pruneStalePendingDownloads(chrome.storage.session);
  await pruneStaleDownloadClickHints(chrome.storage.session);
});

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  await handleDownloadCreated(downloadItem, {
    storageSession: chrome.storage.session,
    tabsApi: chrome.tabs,
  });
});

chrome.downloads.onChanged.addListener(async (delta) => {
  const ipcRequest = await handleDownloadChanged(delta, {
    storageSession: chrome.storage.session,
    downloadsApi: chrome.downloads,
  });
  if (!ipcRequest) {
    return;
  }
  await incrementCounter(chrome.storage.local, "downloadsTracked", 1);
  await sendNativeRequest(ipcRequest, {
    runtimeApi: chrome.runtime,
    storageLocal: chrome.storage.local,
  });
});

if (typeof chrome.declarativeNetRequest?.onRuleMatchedDebug?.addListener === "function") {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(async (info) => {
    const reqUrl = info?.request?.url || "";
    const ruleId = info?.rule?.ruleId ?? "unknown";
    const tabId = typeof info?.request?.tabId === "number" ? info.request.tabId : -1;
    await reportBrowserEvent({
      eventType: "DnrBlockedRequest",
      url: reqUrl,
      details: `Blocked by DNR rule ${ruleId}`,
      tabId,
    });
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      const tabId = typeof sender?.tab?.id === "number" ? sender.tab.id : -1;
      const isExtensionPage =
        !sender?.tab &&
        (!sender?.url || sender.url.startsWith(chrome.runtime.getURL("")));

      switch (message?.type) {
        case "ANALYZE_CLIPBOARD": {
          const verdict = analyzeClipboardPayload({
            copiedText: message.copiedText,
            selectionText: message.selectionText,
            trigger: message.trigger,
          });
          sendResponse({ ok: true, verdict });
          return;
        }
        case "CHECK_DOMAIN_RISK": {
          const res = await checkDomainRisk(message.urlOrHost || "");
          sendResponse(res);
          return;
        }
        case "REPORT_BROWSER_EVENT": {
          const res = await reportBrowserEvent({
            eventType: message.eventType,
            url: message.url,
            details: message.details ?? null,
            tabId,
          });
          sendResponse(res);
          return;
        }
        case "RECORD_DOWNLOAD_CLICK_HINT": {
          if (!sender?.tab) {
            sendResponse({ ok: false, error: "Forbidden sender context" });
            return;
          }
          const senderTabUrl =
            typeof sender?.tab?.url === "string" && sender.tab.url.trim()
              ? sender.tab.url.trim()
              : typeof message.pageUrl === "string"
                ? message.pageUrl.trim()
                : "";
          const recorded = await recordDownloadClickHint(
            {
              targetUrl: message.targetUrl,
              tabUrl: senderTabUrl,
            },
            { storageSession: chrome.storage.session }
          );
          sendResponse({ ok: true, recorded: Boolean(recorded) });
          return;
        }
        case "GET_POPUP_STATE": {
          if (!isExtensionPage) {
            sendResponse({ ok: false, error: "Forbidden sender context" });
            return;
          }
          sendResponse(await buildPopupState());
          return;
        }
        case "PING_DAEMON": {
          if (!isExtensionPage) {
            sendResponse({ ok: false, error: "Forbidden sender context" });
            return;
          }
          await sendNativeRequest(buildPingRequest(), {
            runtimeApi: chrome.runtime,
            storageLocal: chrome.storage.local,
          });
          sendResponse(await buildPopupState());
          return;
        }
        case "UPDATE_DYNAMIC_DNR_RULES": {
          if (!isExtensionPage) {
            sendResponse({ ok: false, error: "Forbidden sender context" });
            return;
          }
          const updated = await updateDynamicDnrRules(message.blockDomains);
          sendResponse({ ok: true, ...updated });
          return;
        }
        default: {
          sendResponse({ ok: false, error: "Unsupported message type" });
        }
      }
    } catch (err) {
      sendResponse({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  })();
  return true;
});
