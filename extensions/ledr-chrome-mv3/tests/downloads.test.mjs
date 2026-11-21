import test from "node:test";
import assert from "node:assert/strict";
import {
  DOWNLOAD_CLICK_HINTS_STORAGE_KEY,
  DOWNLOAD_CLICK_HINT_TTL_MS,
  MAX_DOWNLOAD_CLICK_HINTS,
  MAX_PENDING_DOWNLOADS,
  PENDING_DOWNLOADS_STORAGE_KEY,
  handleDownloadChanged,
  handleDownloadCreated,
  pruneStaleDownloadClickHints,
  recordDownloadClickHint,
} from "../lib/downloads.js";
import {
  BRIDGE_DIAGNOSTICS_KEY,
  NATIVE_HOST_NAME,
  buildPingRequest,
  getDiagnostics,
  incrementCounter,
  sendNativeRequest,
} from "../lib/native_bridge.js";

function createMemoryStorageArea(initial = {}) {
  let backing = structuredClone(initial);
  return {
    async get(keys) {
      if (keys === undefined || keys === null) {
        return structuredClone(backing);
      }
      const list = Array.isArray(keys) ? keys : [keys];
      const out = {};
      for (const k of list) {
        if (Object.hasOwn(backing, k)) {
          out[k] = structuredClone(backing[k]);
        }
      }
      return out;
    },
    async set(obj) {
      for (const [k, v] of Object.entries(obj)) {
        backing[k] = structuredClone(v);
      }
    },
    dump() {
      return structuredClone(backing);
    },
  };
}

test("EXT-08: tracks download onCreated -> onChanged(complete) across simulated SW restart", async () => {
  // Simulate SW start #1 saving into storage.session
  const sessionStorage = createMemoryStorageArea();
  await handleDownloadCreated(
    {
      id: 42,
      url: "https://cdn.localedr.invalid/tools/payload.exe",
      finalUrl: "https://cdn.localedr.invalid/tools/payload.exe",
      referrer: "https://portal.localedr.invalid/",
    },
    {
      storageSession: sessionStorage,
      tabsApi: {
        async query() {
          return [{ url: "https://portal.localedr.invalid/download.html" }];
        },
      },
      nowFn: () => 1700000000000,
    }
  );

  // Simulate SW restart: deserialize raw session snapshot into a fresh storage wrapper
  const restartedSession = createMemoryStorageArea(sessionStorage.dump());
  const ipcReq = await handleDownloadChanged(
    { id: 42, state: { current: "complete" } },
    {
      storageSession: restartedSession,
      downloadsApi: {
        async search({ id }) {
          assert.equal(id, 42);
          return [
            {
              id: 42,
              filename: "C:\\Users\\alice\\Downloads\\payload.exe",
              url: "https://cdn.localedr.invalid/tools/payload.exe",
              finalUrl: "https://cdn.localedr.invalid/tools/payload.exe",
              referrer: "https://portal.localedr.invalid/",
              endTime: "2026-11-21T00:00:05.000Z",
            },
          ];
        },
      },
    }
  );

  assert.deepEqual(ipcReq, {
    type: "ReportDownloadOrigin",
    payload: {
      file_path: "C:\\Users\\alice\\Downloads\\payload.exe",
      tab_url: "https://portal.localedr.invalid/download.html",
      frame_url: "https://cdn.localedr.invalid/tools/payload.exe",
      referrer_url: "https://portal.localedr.invalid/",
      downloaded_at_ms: Date.parse("2026-11-21T00:00:05.000Z"),
    },
  });

  const after = await restartedSession.get([PENDING_DOWNLOADS_STORAGE_KEY]);
  assert.deepEqual(after[PENDING_DOWNLOADS_STORAGE_KEY], []);
});

test("EXT-09: removes interrupted downloads and caps pending storage at 512 FIFO entries", async () => {
  const sessionStorage = createMemoryStorageArea();
  const tabsApi = {
    async query() {
      return [{ url: "https://example.localedr.invalid/" }];
    },
  };

  for (let id = 1; id <= MAX_PENDING_DOWNLOADS + 10; id++) {
    await handleDownloadCreated(
      {
        id,
        url: `https://example.localedr.invalid/file-${id}.bin`,
        referrer: "",
      },
      { storageSession: sessionStorage, tabsApi, nowFn: () => 1000 + id }
    );
  }

  const stored = (await sessionStorage.get([PENDING_DOWNLOADS_STORAGE_KEY]))[
    PENDING_DOWNLOADS_STORAGE_KEY
  ];
  assert.equal(stored.length, MAX_PENDING_DOWNLOADS);
  assert.equal(stored[0].id, 11);
  assert.equal(stored[stored.length - 1].id, MAX_PENDING_DOWNLOADS + 10);

  // Interrupted download removes entry without emitting ReportDownloadOrigin
  const res = await handleDownloadChanged(
    { id: 15, state: { current: "interrupted" } },
    {
      storageSession: sessionStorage,
      downloadsApi: {
        async search() {
          throw new Error("should not search interrupted downloads");
        },
      },
    }
  );
  assert.equal(res, null);
  const afterInterrupt = (await sessionStorage.get([PENDING_DOWNLOADS_STORAGE_KEY]))[
    PENDING_DOWNLOADS_STORAGE_KEY
  ];
  assert.equal(afterInterrupt.some((e) => e.id === 15), false);
});

test("EXT-10: native_bridge updates diagnostics cleanly across online, offline, and exception states", async () => {
  const localStorage = createMemoryStorageArea();

  // 1. Online Pong response
  const okRes = await sendNativeRequest(buildPingRequest(), {
    storageLocal: localStorage,
    nowFn: () => 5000,
    runtimeApi: {
      async sendNativeMessage(host, req) {
        assert.equal(host, NATIVE_HOST_NAME);
        assert.deepEqual(req, { type: "Ping" });
        return {
          type: "Pong",
          payload: { daemon_version: "0.1.0", protocol_version: 1 },
        };
      },
    },
  });
  assert.equal(okRes.ok, true);
  assert.equal(okRes.diagnostics.daemonOnline, true);
  assert.equal(okRes.diagnostics.daemonVersion, "0.1.0");
  assert.equal(okRes.diagnostics.protocolVersion, 1);
  assert.equal(okRes.diagnostics.lastPingAtMs, 5000);
  assert.equal(okRes.diagnostics.lastError, null);

  // 2. DAEMON_OFFLINE frame from ledr-bridge-nm
  const offlineRes = await sendNativeRequest(buildPingRequest(), {
    storageLocal: localStorage,
    nowFn: () => 6000,
    runtimeApi: {
      async sendNativeMessage() {
        return {
          type: "Error",
          payload: { code: "DAEMON_OFFLINE", message: "pipe not found" },
        };
      },
    },
  });
  assert.equal(offlineRes.ok, false);
  assert.equal(offlineRes.diagnostics.daemonOnline, false);
  assert.match(offlineRes.diagnostics.lastError, /DAEMON_OFFLINE/);

  // 3. Native host launch failure exception does not throw
  const throwRes = await sendNativeRequest(buildPingRequest(), {
    storageLocal: localStorage,
    nowFn: () => 7000,
    runtimeApi: {
      async sendNativeMessage() {
        throw new Error("Specified native messaging host not found.");
      },
    },
  });
  assert.equal(throwRes.ok, false);
  assert.equal(throwRes.diagnostics.daemonOnline, false);
  assert.match(throwRes.error, /not found/);

  // 4. Counters persist in storage.local
  await incrementCounter(localStorage, "clickfixBlocked", 1);
  await incrementCounter(localStorage, "downloadsTracked", 2);
  const diag = await getDiagnostics(localStorage);
  assert.equal(diag.counters.clickfixBlocked, 1);
  assert.equal(diag.counters.downloadsTracked, 2);
  assert.ok(localStorage.dump()[BRIDGE_DIAGNOSTICS_KEY]);
});

test("EXT-13: background download does not adopt unrelated foreground activeTabUrl (BUG_0003)", async () => {
  const sessionStorage = createMemoryStorageArea();

  // Case 1: Background download with a referrer on a different origin keeps its referrer URL
  const bgEntry = await handleDownloadCreated(
    {
      id: 101,
      url: "https://cdn.evil.localedr.invalid/dropper.exe",
      finalUrl: "https://cdn.evil.localedr.invalid/dropper.exe",
      referrer: "https://portal.evil.localedr.invalid/landing",
    },
    {
      storageSession: sessionStorage,
      tabsApi: {
        async query() {
          return [{ url: "https://unrelated-bank.localedr.invalid/dashboard" }];
        },
      },
      nowFn: () => 2000,
    }
  );
  assert.equal(bgEntry.tabUrl, "https://portal.evil.localedr.invalid/landing");

  // Case 2: Cross-origin background download without referrer or click hint (no DownloadItem.tabId)
  // must neither adopt the unrelated active tab nor promote the CDN URL into tab_url.
  const unknownTabEntry = await handleDownloadCreated(
    {
      id: 102,
      url: "https://cdn.evil.localedr.invalid/stage2.zip",
      finalUrl: "https://cdn.evil.localedr.invalid/stage2.zip",
      referrer: "",
    },
    {
      storageSession: sessionStorage,
      tabsApi: {
        async query() {
          return [{ url: "https://unrelated-foreground.localedr.invalid/" }];
        },
      },
      nowFn: () => 2001,
    }
  );
  assert.equal(unknownTabEntry.tabUrl, "");
});

test("EXT-17: real DownloadItem without tabId resolves click hints, expires stale hints, and preserves unknown tab_url as empty string", async () => {
  const sessionStorage = createMemoryStorageArea();

  // 1. Fresh click hint matches cross-origin download (even after HTTP redirect and tab switch)
  await recordDownloadClickHint(
    {
      targetUrl: "https://redir.localedr.invalid/go?file=setup#download",
      tabUrl: "https://portal.localedr.invalid/releases",
    },
    { storageSession: sessionStorage, nowFn: () => 10_000 }
  );

  const matchedEntry = await handleDownloadCreated(
    {
      id: 201,
      url: "https://redir.localedr.invalid/go?file=setup",
      finalUrl: "https://cdn.localedr.invalid/bin/setup.exe",
      referrer: "",
    },
    {
      storageSession: sessionStorage,
      tabsApi: {
        async query() {
          return [{ url: "https://other-tab.localedr.invalid/inbox" }];
        },
      },
      nowFn: () => 12_500,
    }
  );
  assert.equal(matchedEntry.tabUrl, "https://portal.localedr.invalid/releases");

  const matchedReq = await handleDownloadChanged(
    { id: 201, state: { current: "complete" } },
    {
      storageSession: sessionStorage,
      downloadsApi: {
        async search({ id }) {
          assert.equal(id, 201);
          return [
            {
              id: 201,
              filename: "C:\\Users\\alice\\Downloads\\setup.exe",
              url: "https://redir.localedr.invalid/go?file=setup",
              finalUrl: "https://cdn.localedr.invalid/bin/setup.exe",
              referrer: "",
              endTime: "2026-11-21T01:00:00.000Z",
            },
          ];
        },
      },
    }
  );
  assert.deepEqual(matchedReq, {
    type: "ReportDownloadOrigin",
    payload: {
      file_path: "C:\\Users\\alice\\Downloads\\setup.exe",
      tab_url: "https://portal.localedr.invalid/releases",
      frame_url: "https://cdn.localedr.invalid/bin/setup.exe",
      referrer_url: null,
      downloaded_at_ms: Date.parse("2026-11-21T01:00:00.000Z"),
    },
  });

  // 2. Expired click hint (>= 15s TTL) is ignored; cross-origin download without referrer reports tab_url: "" and frame_url
  const expiredEntry = await handleDownloadCreated(
    {
      id: 202,
      url: "https://redir.localedr.invalid/go?file=setup",
      finalUrl: "https://cdn.localedr.invalid/bin/setup.exe",
      referrer: "",
    },
    {
      storageSession: sessionStorage,
      tabsApi: {
        async query() {
          return [{ url: "https://portal.localedr.invalid/releases" }];
        },
      },
      nowFn: () => 10_000 + DOWNLOAD_CLICK_HINT_TTL_MS,
    }
  );
  assert.equal(expiredEntry.tabUrl, "");

  const expiredReq = await handleDownloadChanged(
    { id: 202, state: { current: "complete" } },
    {
      storageSession: sessionStorage,
      downloadsApi: {
        async search() {
          return [
            {
              id: 202,
              filename: "C:\\Users\\alice\\Downloads\\setup-2.exe",
              url: "https://redir.localedr.invalid/go?file=setup",
              finalUrl: "https://cdn.localedr.invalid/bin/setup.exe",
              referrer: "",
              endTime: "2026-11-21T01:01:00.000Z",
            },
          ];
        },
      },
    }
  );
  assert.deepEqual(expiredReq, {
    type: "ReportDownloadOrigin",
    payload: {
      file_path: "C:\\Users\\alice\\Downloads\\setup-2.exe",
      tab_url: "",
      frame_url: "https://cdn.localedr.invalid/bin/setup.exe",
      referrer_url: null,
      downloaded_at_ms: Date.parse("2026-11-21T01:01:00.000Z"),
    },
  });

  // 3. Cross-origin download with no click hint and no referrer keeps tab_url empty and preserves downloadSourceUrl in frame_url
  const noHintEntry = await handleDownloadCreated(
    {
      id: 203,
      url: "https://cdn.other.localedr.invalid/installer.msi",
      finalUrl: "https://cdn.other.localedr.invalid/installer.msi",
      referrer: "",
    },
    {
      storageSession: sessionStorage,
      tabsApi: {
        async query() {
          return [{ url: "https://portal.localedr.invalid/releases" }];
        },
      },
      nowFn: () => 30_000,
    }
  );
  assert.equal(noHintEntry.tabUrl, "");

  const noHintReq = await handleDownloadChanged(
    { id: 203, state: { current: "complete" } },
    {
      storageSession: sessionStorage,
      downloadsApi: {
        async search() {
          return [
            {
              id: 203,
              filename: "C:\\Users\\alice\\Downloads\\installer.msi",
              url: "https://cdn.other.localedr.invalid/installer.msi",
              finalUrl: "https://cdn.other.localedr.invalid/installer.msi",
              referrer: "",
              endTime: "2026-11-21T01:02:00.000Z",
            },
          ];
        },
      },
    }
  );
  assert.deepEqual(noHintReq, {
    type: "ReportDownloadOrigin",
    payload: {
      file_path: "C:\\Users\\alice\\Downloads\\installer.msi",
      tab_url: "",
      frame_url: "https://cdn.other.localedr.invalid/installer.msi",
      referrer_url: null,
      downloaded_at_ms: Date.parse("2026-11-21T01:02:00.000Z"),
    },
  });

  // 4. Completion with both empty tabUrl and empty downloadSourceUrl is discarded
  const emptyReq = await handleDownloadChanged(
    { id: 999, state: { current: "complete" } },
    {
      storageSession: sessionStorage,
      downloadsApi: {
        async search() {
          return [
            {
              id: 999,
              filename: "C:\\Users\\alice\\Downloads\\orphan.bin",
              url: "",
              finalUrl: "",
              referrer: "",
            },
          ];
        },
      },
    }
  );
  assert.equal(emptyReq, null);

  // 5. Click hint list is bounded to MAX_DOWNLOAD_CLICK_HINTS (32) and pruned on expiry
  const capStorage = createMemoryStorageArea();
  for (let i = 1; i <= MAX_DOWNLOAD_CLICK_HINTS + 8; i++) {
    await recordDownloadClickHint(
      {
        targetUrl: `https://cdn.localedr.invalid/pkg-${i}.exe`,
        tabUrl: "https://portal.localedr.invalid/list",
      },
      { storageSession: capStorage, nowFn: () => 50_000 + i }
    );
  }
  const storedHints = (await capStorage.get([DOWNLOAD_CLICK_HINTS_STORAGE_KEY]))[
    DOWNLOAD_CLICK_HINTS_STORAGE_KEY
  ];
  assert.equal(storedHints.length, MAX_DOWNLOAD_CLICK_HINTS);
  assert.equal(storedHints[0].targetUrl, "https://cdn.localedr.invalid/pkg-9.exe");
  assert.equal(
    storedHints[storedHints.length - 1].targetUrl,
    `https://cdn.localedr.invalid/pkg-${MAX_DOWNLOAD_CLICK_HINTS + 8}.exe`
  );

  const removed = await pruneStaleDownloadClickHints(
    capStorage,
    DOWNLOAD_CLICK_HINT_TTL_MS,
    () => 50_000 + MAX_DOWNLOAD_CLICK_HINTS + 8 + DOWNLOAD_CLICK_HINT_TTL_MS
  );
  assert.equal(removed, MAX_DOWNLOAD_CLICK_HINTS);
  const afterPrune = (await capStorage.get([DOWNLOAD_CLICK_HINTS_STORAGE_KEY]))[
    DOWNLOAD_CLICK_HINTS_STORAGE_KEY
  ];
  assert.deepEqual(afterPrune, []);
});

test("EXT-19: click hints enforce referrer origin consistency, iframe frameUrl matching, and completion-time correction (BUG_0001)", async () => {
  const sessionStorage = createMemoryStorageArea();
  const targetUrl = "https://cdn.localedr.invalid/release/app.exe";

  // 1. Stale click hint from docs tab is rejected when download starts with a contradicting referrer from portal tab.
  await recordDownloadClickHint(
    {
      targetUrl,
      tabUrl: "https://docs.localedr.invalid/guide",
    },
    { storageSession: sessionStorage, nowFn: () => 100_000 }
  );

  const portalEntry = await handleDownloadCreated(
    {
      id: 301,
      url: targetUrl,
      finalUrl: targetUrl,
      referrer: "https://portal.localedr.invalid/",
    },
    {
      storageSession: sessionStorage,
      tabsApi: {
        async query() {
          return [{ url: "https://portal.localedr.invalid/downloads/latest" }];
        },
      },
      nowFn: () => 102_000,
    }
  );
  assert.equal(portalEntry.tabUrl, "https://portal.localedr.invalid/downloads/latest");
  assert.equal(portalEntry.tabUrlSource, "active_tab_referrer");

  const portalReq = await handleDownloadChanged(
    { id: 301, state: { current: "complete" } },
    {
      storageSession: sessionStorage,
      downloadsApi: {
        async search() {
          return [
            {
              id: 301,
              filename: "C:\\Users\\alice\\Downloads\\app.exe",
              url: targetUrl,
              finalUrl: targetUrl,
              referrer: "https://portal.localedr.invalid/",
              endTime: "2026-11-21T02:00:00.000Z",
            },
          ];
        },
      },
    }
  );
  assert.deepEqual(portalReq, {
    type: "ReportDownloadOrigin",
    payload: {
      file_path: "C:\\Users\\alice\\Downloads\\app.exe",
      tab_url: "https://portal.localedr.invalid/downloads/latest",
      frame_url: targetUrl,
      referrer_url: "https://portal.localedr.invalid/",
      downloaded_at_ms: Date.parse("2026-11-21T02:00:00.000Z"),
    },
  });

  // 2. Cross-origin iframe click hint matches referrer against frameUrl and preserves top-level tabUrl.
  const iframeStorage = createMemoryStorageArea();
  await recordDownloadClickHint(
    {
      targetUrl,
      tabUrl: "https://portal.localedr.invalid/product-page",
      frameUrl: "https://embed.localedr.invalid/download-widget",
    },
    { storageSession: iframeStorage, nowFn: () => 200_000 }
  );
  // Newer click on another tab with contradicting origin must be skipped in favor of matching iframe hint.
  await recordDownloadClickHint(
    {
      targetUrl,
      tabUrl: "https://docs.localedr.invalid/unrelated",
      frameUrl: "https://docs.localedr.invalid/unrelated",
    },
    { storageSession: iframeStorage, nowFn: () => 201_000 }
  );

  const iframeEntry = await handleDownloadCreated(
    {
      id: 302,
      url: targetUrl,
      finalUrl: targetUrl,
      referrer: "https://embed.localedr.invalid/",
    },
    {
      storageSession: iframeStorage,
      tabsApi: {
        async query() {
          return [{ url: "https://other-tab.localedr.invalid/mail" }];
        },
      },
      nowFn: () => 202_000,
    }
  );
  assert.equal(iframeEntry.tabUrl, "https://portal.localedr.invalid/product-page");
  assert.equal(iframeEntry.tabUrlSource, "click_hint");
  assert.equal(iframeEntry.clickHintFrameUrl, "https://embed.localedr.invalid/download-widget");

  const iframeReq = await handleDownloadChanged(
    { id: 302, state: { current: "complete" } },
    {
      storageSession: iframeStorage,
      downloadsApi: {
        async search() {
          return [
            {
              id: 302,
              filename: "C:\\Users\\alice\\Downloads\\app-iframe.exe",
              url: targetUrl,
              finalUrl: targetUrl,
              referrer: "https://embed.localedr.invalid/",
              endTime: "2026-11-21T02:01:00.000Z",
            },
          ];
        },
      },
    }
  );
  assert.deepEqual(iframeReq, {
    type: "ReportDownloadOrigin",
    payload: {
      file_path: "C:\\Users\\alice\\Downloads\\app-iframe.exe",
      tab_url: "https://portal.localedr.invalid/product-page",
      frame_url: targetUrl,
      referrer_url: "https://embed.localedr.invalid/",
      downloaded_at_ms: Date.parse("2026-11-21T02:01:00.000Z"),
    },
  });

  // 3. onCreated had empty referrer (adopted click hint), but onChanged(complete) reveals a contradicting
  // item.referrer: completion handler must discard the click-hint tabUrl and use referrerUrl instead.
  const lateRefStorage = createMemoryStorageArea();
  await recordDownloadClickHint(
    {
      targetUrl,
      tabUrl: "https://docs.localedr.invalid/guide",
    },
    { storageSession: lateRefStorage, nowFn: () => 300_000 }
  );

  const tentativeEntry = await handleDownloadCreated(
    {
      id: 303,
      url: targetUrl,
      finalUrl: targetUrl,
      referrer: "",
    },
    {
      storageSession: lateRefStorage,
      tabsApi: {
        async query() {
          return [{ url: "https://other.localedr.invalid/" }];
        },
      },
      nowFn: () => 301_000,
    }
  );
  assert.equal(tentativeEntry.tabUrl, "https://docs.localedr.invalid/guide");
  assert.equal(tentativeEntry.tabUrlSource, "click_hint");

  const correctedReq = await handleDownloadChanged(
    { id: 303, state: { current: "complete" } },
    {
      storageSession: lateRefStorage,
      downloadsApi: {
        async search() {
          return [
            {
              id: 303,
              filename: "C:\\Users\\alice\\Downloads\\app-corrected.exe",
              url: targetUrl,
              finalUrl: targetUrl,
              referrer: "https://portal.localedr.invalid/releases",
              endTime: "2026-11-21T02:02:00.000Z",
            },
          ];
        },
      },
    }
  );
  assert.deepEqual(correctedReq, {
    type: "ReportDownloadOrigin",
    payload: {
      file_path: "C:\\Users\\alice\\Downloads\\app-corrected.exe",
      tab_url: "https://portal.localedr.invalid/releases",
      frame_url: targetUrl,
      referrer_url: "https://portal.localedr.invalid/releases",
      downloaded_at_ms: Date.parse("2026-11-21T02:02:00.000Z"),
    },
  });

  // 4. Non-HTTP(S) referrer must not adopt an HTTP(S) click hint.
  const nonHttpEntry = await handleDownloadCreated(
    {
      id: 304,
      url: targetUrl,
      finalUrl: targetUrl,
      referrer: "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/downloader.html",
    },
    {
      storageSession: lateRefStorage,
      tabsApi: {
        async query() {
          return [{ url: "https://docs.localedr.invalid/guide" }];
        },
      },
      nowFn: () => 302_000,
    }
  );
  assert.equal(
    nonHttpEntry.tabUrl,
    "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/downloader.html"
  );
  assert.equal(nonHttpEntry.tabUrlSource, "referrer");
});
