import test from "node:test";
import assert from "node:assert/strict";
import {
  MAX_PENDING_DOWNLOADS,
  PENDING_DOWNLOADS_STORAGE_KEY,
  handleDownloadChanged,
  handleDownloadCreated,
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

  // Case 1: Background download with a referrer on a different origin must keep its own context URL
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

  // Case 2: When downloadItem.tabId is provided, tabsApi.get(tabId) takes precedence over foreground active tab
  const byTabIdEntry = await handleDownloadCreated(
    {
      id: 102,
      tabId: 77,
      url: "https://cdn.evil.localedr.invalid/stage2.zip",
      finalUrl: "https://cdn.evil.localedr.invalid/stage2.zip",
      referrer: "",
    },
    {
      storageSession: sessionStorage,
      tabsApi: {
        async get(tabId) {
          assert.equal(tabId, 77);
          return { id: 77, url: "https://source-tab.localedr.invalid/page.html" };
        },
        async query() {
          return [{ url: "https://unrelated-foreground.localedr.invalid/" }];
        },
      },
      nowFn: () => 2001,
    }
  );
  assert.equal(byTabIdEntry.tabUrl, "https://source-tab.localedr.invalid/page.html");
});
