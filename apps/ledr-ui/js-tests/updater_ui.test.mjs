import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const appJsPath = path.join(repoRoot, "apps/ledr-ui/ui/app.js");
const indexHtmlPath = path.join(repoRoot, "apps/ledr-ui/ui/index.html");
const tauriConfPath = path.join(repoRoot, "apps/ledr-ui/tauri.conf.json");

function createMockElement(id = "", initialDataset = {}) {
  const classes = new Set();
  const attrs = new Map();
  const listeners = new Map();
  return {
    id,
    innerHTML: "",
    textContent: "",
    value: "",
    placeholder: "",
    title: "",
    checked: false,
    disabled: false,
    dataset: { ...initialDataset },
    classList: {
      add(...tokens) {
        for (const t of tokens) classes.add(t);
      },
      remove(...tokens) {
        for (const t of tokens) classes.delete(t);
      },
      toggle(token, force) {
        if (force === undefined) {
          if (classes.has(token)) {
            classes.delete(token);
            return false;
          }
          classes.add(token);
          return true;
        }
        if (force) classes.add(token);
        else classes.delete(token);
        return Boolean(force);
      },
      contains(token) {
        return classes.has(token);
      },
    },
    setAttribute(name, val) {
      attrs.set(name, String(val));
    },
    getAttribute(name) {
      return attrs.has(name) ? attrs.get(name) : null;
    },
    removeAttribute(name) {
      attrs.delete(name);
    },
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
    getListeners(type) {
      return listeners.get(type) || [];
    },
    reset() {
      this.value = "";
    },
  };
}

function loadAppHarness(mockInvoke = null) {
  const elements = new Map();
  const getEl = (id) => {
    if (!elements.has(id)) {
      const el = createMockElement(id);
      if (id === "rule-scope-input") el.value = "NetworkBlock";
      elements.set(id, el);
    }
    return elements.get(id);
  };

  const navTabs = ["triage", "lineage", "policy"].map((view) =>
    createMockElement(`nav-${view}`, { view }),
  );
  const tabBtns = ["all", "dns", "network", "canary"].map((tab) =>
    createMockElement(`tab-${tab}`, { tab }),
  );
  const policyScopeBtns = [
    "all",
    "NetworkBlock",
    "NetworkAllow",
    "FileCanaryAllow",
    "ProcessAllow",
  ].map((scope) => createMockElement(`scope-${scope}`, { scope }));

  const mockDocument = {
    title: "LocalEDR",
    getElementById: getEl,
    querySelectorAll(selector) {
      if (selector === ".nav-tab") return navTabs;
      if (selector === ".tab-btn") return tabBtns;
      if (selector === ".policy-scope-btn") return policyScopeBtns;
      return [];
    },
    addEventListener() {},
  };

  const mockWindow = {
    __TAURI__: mockInvoke ? { core: { invoke: mockInvoke } } : undefined,
  };

  const sandbox = {
    console,
    Date,
    Math,
    JSON,
    Map,
    Set,
    Array,
    Object,
    String,
    Number,
    Boolean,
    RegExp,
    Error,
    URL,
    Promise,
    setTimeout,
    clearTimeout,
    document: mockDocument,
    window: mockWindow,
    __LEDR_UI_TEST_MODE__: true,
  };
  sandbox.globalThis = sandbox;

  const source = fs.readFileSync(appJsPath, "utf8");
  vm.runInNewContext(source, sandbox, { filename: "app.js" });
  return sandbox.__LEDR_UI_EXPORTS__;
}

function sampleManifest(version = "0.2.0", minUpdaterVersion = "0.1.0") {
  return {
    schema_version: 1,
    product: "LocalEDR",
    version,
    tag: `v${version}`,
    released_at: "2026-11-24T00:00:00Z",
    min_updater_version: minUpdaterVersion,
    filename: `LocalEDR-Setup-v${version}-win-x64.exe`,
    download_url: `https://github.com/Tkg-tamagohan/LocalLightEDR/releases/download/v${version}/LocalEDR-Setup-v${version}-win-x64.exe`,
    sha256: "a".repeat(64),
    size_bytes: 102400,
    release_notes_url: `https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v${version}`,
    chrome_extension: {
      extension_id: "ecelachfiiiiiibpjeomfncgpegbpanh",
      version,
      download_url: null,
      sha256: null,
    },
  };
}

function makeStatus(overrides = {}) {
  return {
    phase: "idle",
    app_version: "0.1.0",
    install_kind: "standard_installed",
    can_auto_apply: true,
    last_checked_at_ms: 1700000000000,
    latest_version: null,
    min_updater_version: null,
    release_notes_url: null,
    manifest: null,
    bytes_downloaded: 0,
    total_bytes: null,
    error_message: null,
    notice_message: null,
    ...overrides,
  };
}

test("UI-UPD-01: #update-banner visibility, actions, and version-scoped dismissal", () => {
  const ui = loadAppHarness(async () => null);

  ui.renderUpdateBanner();
  assert.ok(ui.el.updateBanner.classList.contains("hidden"));

  for (const phase of [
    "idle",
    "checking",
    "up_to_date",
    "downloading",
    "verifying",
    "launching_updater",
    "error",
  ]) {
    ui.applyUpdaterStatusPayload(makeStatus({ phase, latest_version: "0.2.0" }));
    assert.ok(
      ui.el.updateBanner.classList.contains("hidden"),
      `banner must stay hidden in phase '${phase}'`,
    );
  }

  // Standard installed + update_available -> visible with apply & notes buttons
  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "update_available",
      install_kind: "standard_installed",
      can_auto_apply: true,
      latest_version: "0.2.0",
      release_notes_url: "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v0.2.0",
      manifest: sampleManifest("0.2.0"),
    }),
  );
  assert.ok(!ui.el.updateBanner.classList.contains("hidden"));
  assert.ok(!ui.el.updateBanner.classList.contains("is-manual"));
  assert.match(ui.el.updateBannerTitle.textContent, /0\.2\.0/);
  assert.ok(!ui.el.updateBannerApplyBtn.classList.contains("hidden"));
  assert.ok(!ui.el.updateBannerNotesBtn.classList.contains("hidden"));

  // Dismiss for 0.2.0 stays hidden for 0.2.0, re-appears for 0.3.0
  ui.dismissUpdateBanner();
  assert.ok(ui.el.updateBanner.classList.contains("hidden"));

  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "update_available",
      install_kind: "portable_or_dev",
      can_auto_apply: false,
      latest_version: "0.2.0",
      manifest: sampleManifest("0.2.0"),
    }),
  );
  assert.ok(ui.el.updateBanner.classList.contains("hidden"));

  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "update_available",
      install_kind: "portable_or_dev",
      can_auto_apply: false,
      latest_version: "0.3.0",
      release_notes_url: "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v0.3.0",
      manifest: sampleManifest("0.3.0"),
    }),
  );
  assert.ok(!ui.el.updateBanner.classList.contains("hidden"));
  assert.ok(ui.el.updateBannerApplyBtn.classList.contains("hidden"));

  // ManualUpdateRequired -> .is-manual, apply button hidden, notes visible
  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "manual_update_required",
      latest_version: "1.0.0",
      min_updater_version: "0.5.0",
      release_notes_url: "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v1.0.0",
    }),
  );
  assert.ok(!ui.el.updateBanner.classList.contains("hidden"));
  assert.ok(ui.el.updateBanner.classList.contains("is-manual"));
  assert.ok(ui.el.updateBannerApplyBtn.classList.contains("hidden"));
  assert.ok(!ui.el.updateBannerNotesBtn.classList.contains("hidden"));
});

test("UI-UPD-02: View 3 panel renders all 9 UpdaterPhase states and progress modes", () => {
  const ui = loadAppHarness(async () => null);

  ui.applyUpdaterStatusPayload(makeStatus({ phase: "idle" }));
  assert.equal(ui.el.updateStateBadge.textContent, "未確認");
  assert.ok(!ui.el.updateCheckBtn.disabled);
  assert.ok(ui.el.updateProgressWrap.classList.contains("hidden"));

  ui.applyUpdaterStatusPayload(makeStatus({ phase: "checking" }));
  assert.equal(ui.el.updateStateBadge.textContent, "確認中");
  assert.ok(ui.el.updateCheckBtn.disabled);

  ui.applyUpdaterStatusPayload(makeStatus({ phase: "up_to_date", latest_version: "0.1.0" }));
  assert.equal(ui.el.updateStateBadge.textContent, "最新");

  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "update_available",
      latest_version: "0.2.0",
      release_notes_url: "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v0.2.0",
      manifest: sampleManifest("0.2.0"),
      notice_message: "UAC 昇格がキャンセルされました",
    }),
  );
  assert.equal(ui.el.updateStateBadge.textContent, "更新あり");
  assert.ok(!ui.el.updateApplyBtn.classList.contains("hidden"));
  assert.ok(!ui.el.updateReleaseNotesBtn.classList.contains("hidden"));
  assert.ok(!ui.el.updateFeedback.classList.contains("hidden"));
  assert.match(ui.el.updateFeedback.textContent, /UAC/);

  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "manual_update_required",
      latest_version: "1.0.0",
      min_updater_version: "0.5.0",
      release_notes_url: "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v1.0.0",
    }),
  );
  assert.equal(ui.el.updateStateBadge.textContent, "手動更新必須");
  assert.ok(ui.el.updateApplyBtn.classList.contains("hidden"));
  assert.ok(!ui.el.updateReleaseNotesBtn.classList.contains("hidden"));

  // Determinate progress
  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "downloading",
      latest_version: "0.2.0",
      bytes_downloaded: 51200,
      total_bytes: 102400,
    }),
  );
  assert.equal(ui.el.updateStateBadge.textContent, "ダウンロード中");
  assert.ok(!ui.el.updateProgressWrap.classList.contains("hidden"));
  assert.equal(ui.el.updateProgressBar.getAttribute("value"), "50");
  assert.match(ui.el.updateProgressText.textContent, /50%/);
  assert.ok(!ui.el.updateCancelBtn.classList.contains("hidden"));
  assert.ok(ui.el.updateCheckBtn.disabled);

  // Indeterminate progress when total_bytes is null
  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "downloading",
      latest_version: "0.2.0",
      bytes_downloaded: 2048,
      total_bytes: null,
    }),
  );
  assert.equal(ui.el.updateProgressBar.getAttribute("value"), null);
  assert.match(ui.el.updateProgressText.textContent, /2\.0 KiB/);

  ui.applyUpdaterStatusPayload(makeStatus({ phase: "verifying" }));
  assert.equal(ui.el.updateStateBadge.textContent, "検証中");
  assert.ok(ui.el.updateProgressWrap.classList.contains("hidden"));

  ui.applyUpdaterStatusPayload(makeStatus({ phase: "launching_updater" }));
  assert.equal(ui.el.updateStateBadge.textContent, "インストーラー起動中");

  ui.applyUpdaterStatusPayload(
    makeStatus({ phase: "error", error_message: "signature verification failed" }),
  );
  assert.equal(ui.el.updateStateBadge.textContent, "エラー");
  assert.ok(ui.el.updateFeedback.classList.contains("is-error"));
  assert.match(ui.el.updateFeedback.textContent, /signature verification failed/);
});

test("UI-UPD-03: UI vs Daemon version parsing and mismatch alert", () => {
  const ui = loadAppHarness(async () => null);

  assert.equal(ui.parseDaemonVersionFromPing("ledr-daemon v0.1.0 (proto v1)"), "0.1.0");
  assert.equal(
    ui.parseDaemonVersionFromPing({ daemon_version: "0.2.5", protocol_version: 1 }),
    "0.2.5",
  );
  assert.equal(ui.parseDaemonVersionFromPing(null), null);

  // Equal versions -> mismatch alert hidden
  ui.state.isDaemonOnline = true;
  ui.state.daemonVersion = "0.1.0";
  ui.applyUpdaterStatusPayload(makeStatus({ app_version: "0.1.0" }));
  assert.ok(ui.el.updateVersionMismatch.classList.contains("hidden"));

  // Unequal while online -> mismatch alert visible with both versions
  ui.state.daemonVersion = "0.2.0";
  ui.renderAppUpdatePanel();
  assert.ok(!ui.el.updateVersionMismatch.classList.contains("hidden"));
  assert.match(ui.el.updateVersionMismatch.textContent, /v0\.1\.0/);
  assert.match(ui.el.updateVersionMismatch.textContent, /v0\.2\.0/);

  // Daemon offline -> mismatch alert hidden
  ui.state.isDaemonOnline = false;
  ui.renderAppUpdatePanel();
  assert.ok(ui.el.updateVersionMismatch.classList.contains("hidden"));
});

test("UI-UPD-04: PortableOrDev guard prevents apply_update invocation", async () => {
  const invoked = [];
  const ui = loadAppHarness(async (cmd) => {
    invoked.push(cmd);
    return makeStatus({ phase: "launching_updater" });
  });

  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "update_available",
      install_kind: "portable_or_dev",
      can_auto_apply: false,
      latest_version: "0.2.0",
      manifest: sampleManifest("0.2.0"),
    }),
  );
  assert.ok(ui.el.updateApplyBtn.classList.contains("hidden"));
  assert.ok(ui.el.updateApplyBtn.disabled);
  await ui.handleApplyUpdate();
  assert.deepEqual(invoked, []);

  // Standard installed allows apply_update
  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "update_available",
      install_kind: "standard_installed",
      can_auto_apply: true,
      latest_version: "0.2.0",
      manifest: sampleManifest("0.2.0"),
    }),
  );
  assert.ok(!ui.el.updateApplyBtn.classList.contains("hidden"));
  assert.ok(!ui.el.updateApplyBtn.disabled);
  await ui.handleApplyUpdate();
  assert.deepEqual(invoked, ["apply_update"]);
});

test("UI-UPD-05: Chrome extension guidance & isolation from #browser-shield-dl", () => {
  const ui = loadAppHarness(async () => null);
  ui.applyUpdaterStatusPayload(
    makeStatus({
      phase: "update_available",
      latest_version: "0.2.0",
      manifest: sampleManifest("0.2.0"),
    }),
  );
  ui.renderPolicyView();

  assert.match(ui.el.appUpdateDl.innerHTML, /ecelachfiiiiiibpjeomfncgpegbpanh/);
  assert.match(ui.el.appUpdateDl.innerHTML, /v0\.2\.0/);
  assert.match(ui.el.appUpdateDl.innerHTML, /自動更新対象外/);
  assert.equal(ui.el.browserShieldDl.innerHTML.includes("browser-detail-row"), false);
  assert.equal(ui.el.appUpdateDl.innerHTML.includes("browser-detail-row"), false);
});

test("UI-UPD-06: IPC check, UPDATE_IN_PROGRESS, cancel, release notes & refreshAll", async () => {
  const calls = [];
  let failNextCheck = false;
  const ui = loadAppHarness(async (cmd, args) => {
    calls.push({ cmd, args });
    if (cmd === "ping_daemon") return "ledr-daemon v0.2.0 (proto v1)";
    if (cmd === "fetch_flight_recorder") {
      return {
        processes: [],
        dns_queries: [],
        network_events: [],
        file_canary_events: [],
        download_origins: [],
      };
    }
    if (cmd === "fetch_alerts" || cmd === "fetch_rules") return [];
    if (cmd === "get_updater_status") {
      return makeStatus({
        phase: "update_available",
        app_version: "0.1.0",
        latest_version: "0.2.0",
        release_notes_url: "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v0.2.0",
        manifest: sampleManifest("0.2.0"),
      });
    }
    if (cmd === "check_for_updates") {
      if (failNextCheck) {
        throw new Error("UPDATE_IN_PROGRESS: 更新確認または適用が進行中です。");
      }
      return makeStatus({
        phase: "update_available",
        latest_version: "0.2.0",
        release_notes_url: "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v0.2.0",
        manifest: sampleManifest("0.2.0"),
      });
    }
    if (cmd === "cancel_update_download") {
      return makeStatus({
        phase: "update_available",
        latest_version: "0.2.0",
        release_notes_url: "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v0.2.0",
        manifest: sampleManifest("0.2.0"),
        notice_message: "ダウンロードをキャンセルしました",
      });
    }
    if (cmd === "open_release_notes_url") return null;
    return null;
  });

  await ui.refreshAll();
  assert.equal(ui.state.daemonVersion, "0.2.0");
  assert.equal(ui.state.updaterStatus.phase, "update_available");
  assert.ok(!ui.el.updateVersionMismatch.classList.contains("hidden"));

  await ui.handleCheckForUpdates();
  assert.ok(calls.some((c) => c.cmd === "check_for_updates"));

  failNextCheck = true;
  await ui.handleCheckForUpdates();
  assert.ok(ui.el.updateFeedback.classList.contains("is-error"));
  assert.match(ui.el.updateFeedback.textContent, /UPDATE_IN_PROGRESS/);

  await ui.handleCancelUpdate();
  assert.ok(calls.some((c) => c.cmd === "cancel_update_download"));

  await ui.handleOpenReleaseNotes();
  const openCall = calls.find((c) => c.cmd === "open_release_notes_url");
  assert.ok(openCall);
  assert.equal(
    openCall.args.url,
    "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v0.2.0",
  );

  ui.loadSamplePreview();
  assert.equal(ui.state.daemonVersion, null);
  assert.ok(ui.el.updateVersionMismatch.classList.contains("hidden"));
});

test("UI-UPD-07: index.html updater elements and strict CSP compliance", () => {
  const html = fs.readFileSync(indexHtmlPath, "utf8");
  const tauriConf = JSON.parse(fs.readFileSync(tauriConfPath, "utf8"));

  assert.equal(
    tauriConf.app.security.csp,
    "default-src 'self'; connect-src ipc: http://ipc.localhost; style-src 'self'; script-src 'self'",
  );
  assert.ok(html.includes('id="update-banner"'));
  assert.ok(html.includes('id="app-update-panel"'));
  assert.ok(html.includes('id="update-progress-bar"'));
  assert.equal(/\son[a-z]+\s*=/i.test(html), false, "no inline event handlers allowed");
  assert.equal(/\sstyle\s*=/i.test(html), false, "no inline style attributes allowed");
  assert.equal(/<script(?![^>]*\bsrc=)/i.test(html), false, "no inline script tags allowed");
});
