// MV3 download origin tracking using `chrome.storage.session` (bounded FIFO, 512 entries)
// and short-TTL `<a href>` click hints (15s TTL, 32 entries) without assuming `DownloadItem.tabId`.

import { buildReportDownloadOriginRequest } from "./native_bridge.js";

export const PENDING_DOWNLOADS_STORAGE_KEY = "ledr_pending_downloads";
export const MAX_PENDING_DOWNLOADS = 512;

export const DOWNLOAD_CLICK_HINTS_STORAGE_KEY = "ledr_download_click_hints";
export const DOWNLOAD_CLICK_HINT_TTL_MS = 15 * 1000;
export const MAX_DOWNLOAD_CLICK_HINTS = 32;

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function normalizeHttpUrl(rawUrl, { stripHash = false } = {}) {
  const value = nonEmptyString(rawUrl);
  if (!value || value.startsWith("chrome://downloads")) {
    return null;
  }
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    if (stripHash) {
      parsed.hash = "";
    }
    return parsed.href;
  } catch {
    return null;
  }
}

async function readPendingList(storageSession) {
  const result = await storageSession.get([PENDING_DOWNLOADS_STORAGE_KEY]);
  const list = result?.[PENDING_DOWNLOADS_STORAGE_KEY];
  return Array.isArray(list) ? list : [];
}

async function writePendingList(storageSession, entries) {
  const bounded =
    entries.length > MAX_PENDING_DOWNLOADS
      ? entries.slice(entries.length - MAX_PENDING_DOWNLOADS)
      : entries;
  await storageSession.set({ [PENDING_DOWNLOADS_STORAGE_KEY]: bounded });
  return bounded;
}

async function readClickHintList(storageSession) {
  const result = await storageSession.get([DOWNLOAD_CLICK_HINTS_STORAGE_KEY]);
  const list = result?.[DOWNLOAD_CLICK_HINTS_STORAGE_KEY];
  return Array.isArray(list) ? list : [];
}

async function writeClickHintList(storageSession, entries) {
  const bounded =
    entries.length > MAX_DOWNLOAD_CLICK_HINTS
      ? entries.slice(entries.length - MAX_DOWNLOAD_CLICK_HINTS)
      : entries;
  await storageSession.set({ [DOWNLOAD_CLICK_HINTS_STORAGE_KEY]: bounded });
  return bounded;
}

function extractOrigin(rawUrl) {
  const value = nonEmptyString(rawUrl);
  if (!value) {
    return null;
  }
  try {
    const parsed = new URL(value);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return parsed.origin;
    }
  } catch {
    return null;
  }
  return null;
}

async function queryActiveTabUrl(tabsApi) {
  if (!tabsApi || typeof tabsApi.query !== "function") {
    return null;
  }
  try {
    const tabs = await tabsApi.query({ active: true, lastFocusedWindow: true });
    const url = nonEmptyString(tabs?.[0]?.url);
    if (url && !url.startsWith("chrome://downloads")) {
      return url;
    }
  } catch {
    return null;
  }
  return null;
}

function findMatchingClickHint(hints, candidateUrls, now) {
  const targets = new Set();
  for (const raw of candidateUrls) {
    const norm = normalizeHttpUrl(raw, { stripHash: true });
    if (norm) {
      targets.add(norm);
    }
  }
  if (targets.size === 0 || !Array.isArray(hints) || hints.length === 0) {
    return null;
  }
  for (let i = hints.length - 1; i >= 0; i--) {
    const hint = hints[i];
    if (!hint || typeof hint.clickedAtMs !== "number") {
      continue;
    }
    const ageMs = now - hint.clickedAtMs;
    if (ageMs < 0 || ageMs >= DOWNLOAD_CLICK_HINT_TTL_MS) {
      continue;
    }
    const hintTarget = normalizeHttpUrl(hint.targetUrl, { stripHash: true });
    const hintTab = normalizeHttpUrl(hint.tabUrl);
    if (hintTarget && hintTab && targets.has(hintTarget)) {
      return hintTab;
    }
  }
  return null;
}

/**
 * Records a short-TTL `<a href>` click hint into `chrome.storage.session` (15s TTL, capped at 32).
 */
export async function recordDownloadClickHint({ targetUrl, tabUrl }, deps) {
  const normTarget = normalizeHttpUrl(targetUrl, { stripHash: true });
  const normTab = normalizeHttpUrl(tabUrl);
  if (!normTarget || !normTab) {
    return null;
  }
  const { storageSession, nowFn = () => Date.now() } = deps;
  const now = nowFn();
  const existing = await readClickHintList(storageSession);
  const fresh = existing.filter(
    (entry) =>
      entry &&
      typeof entry.clickedAtMs === "number" &&
      now - entry.clickedAtMs < DOWNLOAD_CLICK_HINT_TTL_MS
  );
  const entry = {
    targetUrl: normTarget,
    tabUrl: normTab,
    clickedAtMs: now,
  };
  fresh.push(entry);
  await writeClickHintList(storageSession, fresh);
  return entry;
}

/**
 * Removes expired click hints older than `maxAgeMs` from `chrome.storage.session`.
 */
export async function pruneStaleDownloadClickHints(
  storageSession,
  maxAgeMs = DOWNLOAD_CLICK_HINT_TTL_MS,
  nowFn = () => Date.now()
) {
  const now = nowFn();
  const existing = await readClickHintList(storageSession);
  const kept = existing.filter(
    (entry) => entry && typeof entry.clickedAtMs === "number" && now - entry.clickedAtMs < maxAgeMs
  );
  if (kept.length !== existing.length) {
    await writeClickHintList(storageSession, kept);
  }
  return existing.length - kept.length;
}

/**
 * Records download creation metadata into `chrome.storage.session` (FIFO capped at 512).
 *
 * Resolves `tabUrl` without assuming `DownloadItem.tabId`:
 * 1. Fresh `<a href>` click hint matching `url` or `finalUrl` (15s TTL)
 * 2. `referrer` (enriched with active tab URL if same origin)
 * 3. Active tab URL if same origin as the download URL
 * 4. Empty string `""` when cross-origin initiation tab cannot be determined
 */
export async function handleDownloadCreated(downloadItem, deps) {
  if (!downloadItem || typeof downloadItem.id !== "number") {
    return null;
  }
  const { storageSession, tabsApi, nowFn = () => Date.now() } = deps;
  const now = nowFn();
  const url = nonEmptyString(downloadItem.url) || "";
  const finalUrl = nonEmptyString(downloadItem.finalUrl) || url;
  const referrer = nonEmptyString(downloadItem.referrer);
  const downloadSourceUrl = finalUrl || url;

  const clickHints = await readClickHintList(storageSession);
  let tabUrl = findMatchingClickHint(clickHints, [url, finalUrl], now) || "";

  if (!tabUrl) {
    const activeTabUrl = await queryActiveTabUrl(tabsApi);
    const activeOrigin = extractOrigin(activeTabUrl);
    if (referrer) {
      const referrerOrigin = extractOrigin(referrer);
      if (activeTabUrl && activeOrigin && referrerOrigin && activeOrigin === referrerOrigin) {
        tabUrl = activeTabUrl;
      } else {
        tabUrl = referrer;
      }
    } else if (activeTabUrl && activeOrigin) {
      const sourceOrigin = extractOrigin(downloadSourceUrl);
      if (sourceOrigin && activeOrigin === sourceOrigin) {
        tabUrl = activeTabUrl;
      }
    }
  }

  const entry = {
    id: downloadItem.id,
    url,
    finalUrl,
    referrer,
    tabUrl,
    createdAtMs: now,
  };

  const existing = await readPendingList(storageSession);
  const filtered = existing.filter((item) => item && item.id !== downloadItem.id);
  filtered.push(entry);
  await writePendingList(storageSession, filtered);
  return entry;
}

/**
 * Handles `chrome.downloads.onChanged`: cleans up interrupted downloads and builds
 * `IpcRequest::ReportDownloadOrigin` upon completion.
 */
export async function handleDownloadChanged(delta, deps) {
  const nextState = delta?.state?.current;
  if (!delta || typeof delta.id !== "number" || (nextState !== "complete" && nextState !== "interrupted")) {
    return null;
  }

  const { storageSession, downloadsApi, nowFn = () => Date.now() } = deps;
  const existing = await readPendingList(storageSession);
  const pending = existing.find((item) => item && item.id === delta.id) || null;
  const remaining = existing.filter((item) => item && item.id !== delta.id);
  await writePendingList(storageSession, remaining);

  if (nextState === "interrupted") {
    return null;
  }

  const items = await downloadsApi.search({ id: delta.id });
  const item = Array.isArray(items) ? items[0] : null;
  const filePath = nonEmptyString(item?.filename);
  if (!filePath) {
    return null;
  }

  const referrerUrl = nonEmptyString(item?.referrer) || nonEmptyString(pending?.referrer);
  const downloadSourceUrl =
    nonEmptyString(item?.finalUrl) ||
    nonEmptyString(item?.url) ||
    nonEmptyString(pending?.finalUrl) ||
    nonEmptyString(pending?.url);
  const tabUrl = nonEmptyString(pending?.tabUrl) || referrerUrl || "";
  if (!tabUrl && !downloadSourceUrl) {
    return null;
  }

  const frameUrl =
    downloadSourceUrl && downloadSourceUrl !== tabUrl ? downloadSourceUrl : null;
  const parsedEndTime =
    typeof item?.endTime === "string" ? Date.parse(item.endTime) : Number.NaN;
  const downloadedAtMs = Number.isFinite(parsedEndTime) ? Math.trunc(parsedEndTime) : nowFn();

  return buildReportDownloadOriginRequest({
    filePath,
    tabUrl,
    frameUrl,
    referrerUrl,
    downloadedAtMs,
  });
}

/**
 * Removes pending session download entries older than `maxAgeMs`.
 */
export async function pruneStalePendingDownloads(
  storageSession,
  maxAgeMs = 24 * 60 * 60 * 1000,
  nowFn = () => Date.now()
) {
  const cutoff = nowFn() - maxAgeMs;
  const existing = await readPendingList(storageSession);
  const kept = existing.filter((entry) => entry && Number(entry.createdAtMs) >= cutoff);
  if (kept.length !== existing.length) {
    await writePendingList(storageSession, kept);
  }
  return existing.length - kept.length;
}
