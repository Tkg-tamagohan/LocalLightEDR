// MV3 download origin tracking using `chrome.storage.session` (bounded FIFO, 512 entries).

import { buildReportDownloadOriginRequest } from "./native_bridge.js";

export const PENDING_DOWNLOADS_STORAGE_KEY = "ledr_pending_downloads";
export const MAX_PENDING_DOWNLOADS = 512;

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
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

/**
 * Records download creation metadata into `chrome.storage.session` (FIFO capped at 512).
 */
export async function handleDownloadCreated(downloadItem, deps) {
  if (!downloadItem || typeof downloadItem.id !== "number") {
    return null;
  }
  const { storageSession, tabsApi, nowFn = () => Date.now() } = deps;
  const activeTabUrl = await queryActiveTabUrl(tabsApi);
  const url = nonEmptyString(downloadItem.url) || "";
  const finalUrl = nonEmptyString(downloadItem.finalUrl) || url;
  const referrer = nonEmptyString(downloadItem.referrer);
  const tabUrl = activeTabUrl || referrer || finalUrl || url;

  const entry = {
    id: downloadItem.id,
    url,
    finalUrl,
    referrer,
    tabUrl,
    createdAtMs: nowFn(),
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
  const tabUrl = nonEmptyString(pending?.tabUrl) || referrerUrl || downloadSourceUrl || "";
  if (!tabUrl) {
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
