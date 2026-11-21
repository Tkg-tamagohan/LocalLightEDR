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
    __TAURI__: mockInvoke
      ? { core: { invoke: mockInvoke } }
      : undefined,
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

test("UI-P4-05: Windows path normalization, LAYER_4_BROWSER extraction, MOTW fields & View 1 cards", () => {
  const ui = loadAppHarness();

  assert.equal(
    ui.normalizeWindowsPath("\\\\?\\C:/Users/Alice//Downloads\\tool.exe\\"),
    "c:\\users\\alice\\downloads\\tool.exe",
  );
  assert.equal(
    ui.normalizeWindowsPath("\\\\?\\UNC\\fileserver\\share\\drop.exe"),
    "\\\\fileserver\\share\\drop.exe",
  );
  assert.equal(
    ui.normalizeWindowsPath("\\\\?\\Volume{abc-123}\\bin\\app.exe"),
    "\\\\?\\volume{abc-123}\\bin\\app.exe",
  );
  assert.equal(ui.normalizeWindowsPath("C:\\"), "c:\\");
  assert.equal(ui.normalizeWindowsPath(null), "");
  assert.equal(ui.normalizeWindowsPath("   "), "");

  assert.equal(
    ui.formatShortSha256("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"),
    "abcdef012345...",
  );
  assert.equal(ui.formatShortSha256(""), null);
  assert.equal(ui.formatMotwSourceLabel("download_path"), "Path");
  assert.equal(ui.formatMotwSourceLabel("download_sha256"), "SHA-256");
  assert.equal(ui.formatMotwSourceLabel("zone_identifier_ads"), "Zone.Identifier");
  assert.equal(ui.formatMotwZoneLabel(3), "Zone 3 (Internet)");

  const dlSha = "a".repeat(64);
  ui.state.snapshot = {
    processes: [
      {
        process_instance_id: "500:100",
        pid: 500,
        ppid: 4,
        exe_path: "C:\\Users\\Alice\\Temp\\moved.exe",
        sha256: dlSha,
        origin_url: "https://drop.localedr.invalid/file",
      },
    ],
    dns_queries: [],
    network_events: [],
    file_canary_events: [],
    download_origins: [
      {
        id: 1,
        file_path: "C:/Users/Alice/Downloads/tool.exe",
        sha256: dlSha,
        tab_url: "https://drop.localedr.invalid/file",
        frame_url: "https://cdn.localedr.invalid/frame",
        referrer_url: "https://portal.localedr.invalid/",
        downloaded_at_ms: 1_732_000_000_000,
      },
    ],
  };

  const { byId } = ui.buildHierarchy(ui.state.snapshot);

  // Process alert with MOTW context fields
  const motwAlert = {
    alert_id: "motw-1",
    timestamp_ms: 1_732_000_010_000,
    severity: "High",
    source_layer: "LAYER_1_CANARY",
    rule_id: "CANARY-COOKIE-DB",
    title: "Canary Read",
    process_instance_id: "500:100",
    process_suspended: true,
    status: "Pending",
    context_json: JSON.stringify({
      exe_path: "\\\\?\\C:/Users/Alice/Temp/moved.exe",
      sha256: dlSha,
      origin_url: "https://drop.localedr.invalid/file",
      motw_source: "download_sha256",
      motw_zone_id: 3,
      motw_referrer: "https://portal.localedr.invalid/",
      motw_frame_url: "https://cdn.localedr.invalid/frame",
    }),
  };
  const motwDetails = ui.extractAlertDetails(motwAlert, byId);
  assert.equal(motwDetails.isBrowserAlert, false);
  assert.equal(motwDetails.motwSource, "download_sha256");
  assert.equal(motwDetails.motwZoneId, 3);
  assert.equal(motwDetails.motwReferrer, "https://portal.localedr.invalid/");
  assert.equal(motwDetails.motwFrameUrl, "https://cdn.localedr.invalid/frame");
  assert.equal(motwDetails.downloadOrigins.length, 1);

  ui.renderMotwCard(motwDetails);
  assert.match(ui.el.triageMotwBody.innerHTML, /SHA-256/);
  assert.match(ui.el.triageMotwBody.innerHTML, /Zone 3 \(Internet\)/);
  assert.match(ui.el.triageMotwBody.innerHTML, /portal\.localedr\.invalid/);
  assert.match(ui.el.triageMotwBody.innerHTML, /cdn\.localedr\.invalid\/frame/);
  assert.match(ui.el.triageMotwBody.innerHTML, /aaaaaaaaaaaa\.\.\./);

  // Browser alert with malformed JSON must not crash
  const malformedBrowser = {
    alert_id: "br-bad",
    timestamp_ms: 1_732_000_020_000,
    severity: "High",
    source_layer: "LAYER_4_BROWSER",
    rule_id: "BROWSER-ClickFixPastejacking",
    title: "ClickFix",
    process_instance_id: null,
    process_suspended: false,
    status: "Pending",
    context_json: "{broken json",
  };
  const badDetails = ui.extractAlertDetails(malformedBrowser, byId);
  assert.equal(badDetails.isBrowserAlert, true);
  assert.equal(badDetails.browserEventType, null);
  assert.equal(badDetails.motwZoneId, null);

  // Browser alert with full context_json
  const browserAlert = {
    alert_id: "br-1",
    timestamp_ms: 1_732_000_030_000,
    severity: "High",
    source_layer: "LAYER_4_BROWSER",
    rule_id: "BROWSER-ClickFixPastejacking",
    title: "Browser ClickFix / Pastejacking Detected",
    process_instance_id: null,
    process_suspended: false,
    status: "Pending",
    context_json: JSON.stringify({
      event_type: "ClickFixPastejacking",
      url: "https://verify.localedr.invalid/check",
      details: "powershell -EncodedCommand ...",
      details_truncated: true,
    }),
  };
  const browserDetails = ui.extractAlertDetails(browserAlert, byId);
  ui.renderSuspendBanner(browserAlert, browserDetails);
  assert.match(
    ui.el.triageSuspendBanner.innerHTML,
    /Browser shield event — no local process attached/,
  );
  ui.renderDetectionCard(browserAlert, browserDetails);
  assert.match(ui.el.triageDetectionDl.innerHTML, /ClickFixPastejacking/);
  assert.match(ui.el.triageDetectionDl.innerHTML, /verify\.localedr\.invalid/);
  assert.match(ui.el.triageDetectionDl.innerHTML, /Truncated/);

  ui.renderLineageCard(browserAlert, browserDetails, byId);
  assert.equal(ui.el.inspectInView2Btn.classList.contains("hidden"), true);
  assert.match(ui.el.triageLineageDl.innerHTML, /LAYER_4_BROWSER/);
  assert.match(ui.el.triageLineageDl.innerHTML, /None \(browser extension event\)/);
});

test("UI-P4-06: Processless LAYER_4_BROWSER resolution constraints, control restoration & sample preview", async () => {
  const ui = loadAppHarness();
  const sample = ui.buildSampleData();
  const browserSample = sample.alerts.find(
    (a) => a.source_layer === "LAYER_4_BROWSER",
  );
  assert.ok(browserSample, "buildSampleData must include LAYER_4_BROWSER alert");
  const browserCtx = JSON.parse(browserSample.context_json);
  assert.equal(browserCtx.event_type, "ClickFixPastejacking");

  ui.loadSamplePreview();
  const liveBrowserSample = ui.state.alerts.find(
    (a) => a.alert_id === browserSample.alert_id,
  );
  assert.ok(liveBrowserSample);
  const { byId } = ui.buildHierarchy(ui.state.snapshot);
  const normalSample = ui.state.alerts.find((a) => a.alert_id === "sample-cookie-001");
  assert.ok(normalSample);

  // 1. Select processless browser alert
  ui.state.selectedAlertId = liveBrowserSample.alert_id;
  ui.syncResolutionControls(
    liveBrowserSample,
    ui.extractAlertDetails(liveBrowserSample, byId),
  );
  assert.equal(ui.el.btnAllowOnce.textContent, "Acknowledge");
  assert.equal(ui.el.btnAllowOnce.disabled, false);
  assert.equal(ui.el.btnTerminateBlock.disabled, true);
  assert.equal(ui.el.optAddBlockRule.disabled, true);
  assert.equal(ui.el.optAddBlockRule.checked, false);
  assert.equal(ui.el.btnAllowPermanent.disabled, true);
  assert.equal(ui.el.optUseSigner.disabled, true);
  assert.equal(ui.el.optAllowDest.disabled, true);
  assert.equal(ui.el.allowOnceConstraintNote.textContent, "Resolves browser alert");

  // Guard: calling terminate on processless browser alert must be ignored
  await ui.handleResolveAlert("terminate");
  assert.equal(liveBrowserSample.status, "Pending");

  // Acknowledge via allow_once succeeds in Sample Preview
  ui.state.alertQueueFilter = "all";
  await ui.handleResolveAlert("allow_once");
  assert.equal(liveBrowserSample.status, "ApprovedOnce");
  assert.match(ui.el.triageActionStatus.textContent, /acknowledged/);
  assert.match(
    ui.state.triageFeedbackByAlert.get(liveBrowserSample.alert_id)?.message || "",
    /acknowledged/,
  );

  // 2. Switch back to normal process alert -> labels & controls must restore completely
  ui.state.selectedAlertId = normalSample.alert_id;
  ui.syncResolutionControls(normalSample, ui.extractAlertDetails(normalSample, byId));
  assert.equal(ui.el.btnAllowOnce.textContent, "Allow Once");
  assert.equal(ui.el.btnAllowOnce.disabled, false);
  assert.equal(ui.el.btnTerminateBlock.disabled, false);
  assert.equal(ui.el.optAddBlockRule.disabled, false);
  assert.equal(ui.el.optAddBlockRule.checked, true);
  assert.equal(ui.el.btnAllowPermanent.disabled, false);
  assert.equal(ui.el.optAllowDest.disabled, false);
  assert.equal(ui.el.allowOnceConstraintNote.textContent, "Resumes process without rule");
  assert.equal(
    ui.el.terminateConstraintNote.textContent,
    "Terminates process tree and applies dynamic WFP block",
  );
});

test("UI-P4-07: View 2 scoped download_origins, MOTW badge, origin_url filter & sha256 collision guard", () => {
  const ui = loadAppHarness();
  const shaA = "1".repeat(64);
  const shaB = "2".repeat(64);

  ui.state.snapshot = {
    processes: [
      {
        process_instance_id: "100:1",
        pid: 100,
        ppid: 4,
        exe_path: "C:\\Users\\Alice\\Temp\\alpha.exe",
        command_line: "alpha.exe",
        created_at_ms: 1_732_000_000_000,
        exited_at_ms: null,
        is_trusted_os: false,
        signer_subject: null,
        sha256: shaA,
        origin_url: "https://releases.localedr.invalid/page",
      },
      {
        process_instance_id: "200:2",
        pid: 200,
        ppid: 4,
        exe_path: "C:\\Windows\\System32\\notepad.exe",
        command_line: "notepad.exe",
        created_at_ms: 1_732_000_001_000,
        exited_at_ms: null,
        is_trusted_os: true,
        signer_subject: "Microsoft Windows",
        sha256: "3".repeat(64),
        origin_url: null,
      },
    ],
    dns_queries: [],
    network_events: [],
    file_canary_events: [],
    download_origins: [
      {
        id: 1,
        file_path: "C:\\Users\\Alice\\Downloads\\alpha.exe",
        sha256: shaA,
        tab_url: "https://releases.localedr.invalid/page",
        frame_url: "https://cdn.localedr.invalid/frame",
        referrer_url: "https://search.localedr.invalid/",
        downloaded_at_ms: 1_732_000_000_500,
      },
      {
        id: 2,
        file_path: "C:\\Users\\Alice\\Downloads\\beta.exe",
        sha256: shaB,
        tab_url: "https://releases.localedr.invalid/page",
        frame_url: null,
        referrer_url: "https://other.localedr.invalid/",
        downloaded_at_ms: 1_732_000_000_600,
      },
    ],
  };

  assert.equal(
    ui.matchesFilter(ui.state.snapshot.processes[0], "releases.localedr.invalid"),
    true,
  );
  assert.equal(
    ui.matchesFilter(ui.state.snapshot.processes[1], "releases.localedr.invalid"),
    false,
  );

  // Scoped to alpha.exe: must include alpha.exe download only, NOT beta.exe from same tab_url
  ui.state.selectedProcessId = "100:1";
  ui.state.activeTab = "all";
  const { byId } = ui.buildHierarchy(ui.state.snapshot);
  ui.renderTree();
  assert.match(ui.el.processTree.innerHTML, /badge-motw">MOTW</);
  assert.match(ui.el.processInspector.innerHTML, /search\.localedr\.invalid/);
  assert.match(ui.el.processInspector.innerHTML, /111111111111\.\.\./);
  assert.match(ui.el.telemetryBody.innerHTML, /alpha\.exe/);
  assert.match(ui.el.telemetryBody.innerHTML, /ref: https:\/\/search\.localedr\.invalid\//);
  assert.match(ui.el.telemetryBody.innerHTML, /sha256: 111111111111\.\.\./);
  assert.doesNotMatch(ui.el.telemetryBody.innerHTML, /beta\.exe/);

  // Scoped to unrelated notepad.exe: must return zero download rows
  ui.state.selectedProcessId = "200:2";
  ui.renderTelemetry(byId);
  assert.match(ui.el.telemetryBody.innerHTML, /No telemetry recorded for this scope/);
});

test("UI-P4-08: View 3 Browser Shield scopes, browsers, manifest diagnostics & stats", () => {
  const ui = loadAppHarness();
  ui.state.isDaemonOnline = true;
  ui.state.alerts = [
    { alert_id: "b1", source_layer: "LAYER_4_BROWSER", status: "Pending" },
    { alert_id: "b2", source_layer: "LAYER_4_BROWSER", status: "ApprovedOnce" },
    { alert_id: "c1", source_layer: "LAYER_1_CANARY", status: "Pending" },
  ];
  ui.state.snapshot = {
    processes: [],
    dns_queries: [],
    network_events: [],
    file_canary_events: [],
    download_origins: [{ id: 1 }, { id: 2 }, { id: 3 }],
  };
  ui.state.localDefenseStatus = {
    honeypots: [],
    protected_paths: [],
    browser_shield: {
      bridge_binary_path: "C:\\Program Files\\LocalEDR\\ledr-bridge-nm.exe",
      bridge_binary_present: true,
      native_host_registered: true,
      uri_scheme_registered: true,
      native_host_scope: "HKCU+HKLM",
      registered_browsers: ["Chrome", "Edge", "Brave"],
      manifest_path: "C:\\ProgramData\\LocalEDR\\native-messaging\\com.localedr.bridge.machine.edge.json",
      manifest_valid: false,
      manifest_error: "Edge: invalid manifest JSON",
      uri_scheme_scope: "HKLM",
      expected_extension_id: "ecelachfiiiiiibpjeomfncgpegbpanh",
      browsers: [
        {
          browser: "Chrome",
          effective_scope: "HKCU",
          hkcu_registered: true,
          hklm_registered: true,
          manifest_path: "C:\\Users\\Alice\\AppData\\Local\\LocalEDR\\native-messaging\\com.localedr.bridge.user.chrome.json",
          manifest_valid: true,
          manifest_error: null,
        },
        {
          browser: "Edge",
          effective_scope: "HKLM",
          hkcu_registered: false,
          hklm_registered: true,
          manifest_path: "C:\\ProgramData\\LocalEDR\\native-messaging\\com.localedr.bridge.machine.edge.json",
          manifest_valid: false,
          manifest_error: "invalid manifest JSON",
        },
      ],
    },
  };

  ui.renderPolicyView();
  const html = ui.el.browserShieldDl.innerHTML;
  assert.match(html, /Registered \(HKCU\+HKLM\)/);
  assert.match(html, />Chrome</);
  assert.match(html, />Edge</);
  assert.match(html, />Brave</);
  assert.match(html, />Invalid</);
  assert.match(html, /Edge: invalid manifest JSON/);
  assert.match(html, /ecelachfiiiiiibpjeomfncgpegbpanh/);
  assert.match(html, /ledr:\/\/ \(HKLM\)/);
  assert.match(html, /2 \(1 unresolved\)/);
  assert.match(html, /<dd class="mono">3<\/dd>/);

  // Custom `--manifest-dir` outside default 2 directories renders as `Unverified` (distinct from red `Invalid`)
  // and keeps each browser's manifest_path visible alongside the unverified note.
  const customUnverifiedNote =
    "manifest path is outside default LocalEDR manifest directories (unverified by UI; inspect the listed manifest file directly or run 'ledr-bridge-nm status' — note: CLI status checks only the 64-bit default registry view, not HKLM WOW64 32-bit view)";
  const chromeCustomPath = "D:\\CustomChrome\\com.localedr.bridge.user.chrome.json";
  const edgeCustomPath = "D:\\CustomEdge\\com.localedr.bridge.machine.edge.json";
  ui.state.localDefenseStatus.browser_shield.manifest_path = chromeCustomPath;
  ui.state.localDefenseStatus.browser_shield.manifest_status = "unverified";
  ui.state.localDefenseStatus.browser_shield.manifest_error = `Chrome: ${customUnverifiedNote}; Edge: ${customUnverifiedNote}`;
  ui.state.localDefenseStatus.browser_shield.browsers[0].manifest_path = chromeCustomPath;
  ui.state.localDefenseStatus.browser_shield.browsers[0].manifest_valid = false;
  ui.state.localDefenseStatus.browser_shield.browsers[0].manifest_status = "unverified";
  ui.state.localDefenseStatus.browser_shield.browsers[0].manifest_error = customUnverifiedNote;
  ui.state.localDefenseStatus.browser_shield.browsers[1].manifest_path = edgeCustomPath;
  ui.state.localDefenseStatus.browser_shield.browsers[1].manifest_status = "unverified";
  ui.state.localDefenseStatus.browser_shield.browsers[1].manifest_error = customUnverifiedNote;
  ui.renderPolicyView();
  const unverifiedHtml = ui.el.browserShieldDl.innerHTML;
  assert.match(unverifiedHtml, /badge-unsigned">Unverified</);
  assert.match(unverifiedHtml, /badge-unsigned">HKCU Unverified</);
  assert.match(unverifiedHtml, /badge-unsigned">HKLM Unverified</);
  assert.doesNotMatch(unverifiedHtml, />Invalid</);
  assert.match(unverifiedHtml, /CustomChrome\\com\.localedr\.bridge\.user\.chrome\.json/);
  assert.match(unverifiedHtml, /CustomEdge\\com\.localedr\.bridge\.machine\.edge\.json/);
  assert.match(unverifiedHtml, /ledr-bridge-nm status/);
  assert.match(unverifiedHtml, /WOW64 32-bit/);
});

test("UI-P4-09: Same-path download with different SHA-256 is excluded without path fallback", () => {
  const ui = loadAppHarness();
  const shaV1 = "a".repeat(64);
  const shaV2 = "b".repeat(64);
  const sharedPath = "C:\\Users\\Alice\\Downloads\\tool.exe";

  const procV1 = {
    process_instance_id: "300:1",
    pid: 300,
    ppid: 4,
    exe_path: sharedPath,
    command_line: "tool.exe",
    created_at_ms: 1_732_000_000_000,
    exited_at_ms: null,
    is_trusted_os: false,
    signer_subject: null,
    sha256: shaV1,
    origin_url: null,
  };
  const dlV2SamePath = {
    id: 10,
    file_path: sharedPath,
    sha256: shaV2,
    tab_url: "https://mirror-v2.localedr.invalid/dl",
    frame_url: "https://mirror-v2.localedr.invalid/frame",
    referrer_url: "https://mirror-v2.localedr.invalid/ref",
    downloaded_at_ms: 1_732_000_005_000,
  };
  const dlNoShaSamePath = {
    id: 11,
    file_path: sharedPath,
    sha256: "",
    tab_url: "https://unhashed.localedr.invalid/dl",
    frame_url: null,
    referrer_url: null,
    downloaded_at_ms: 1_732_000_001_000,
  };
  const dlV1MovedOrig = {
    id: 12,
    file_path: "C:\\Users\\Alice\\Downloads\\tool-orig.exe",
    sha256: shaV1,
    tab_url: "https://orig-v1.localedr.invalid/dl",
    frame_url: null,
    referrer_url: null,
    downloaded_at_ms: 1_732_000_000_500,
  };

  // Both SHA-256 present and unequal -> must NOT fall back to path match
  assert.deepEqual(Array.from(ui.matchDownloadOriginsForProcess(procV1, [dlV2SamePath])), []);

  // Missing SHA-256 on either side -> path match fallback remains allowed
  assert.deepEqual(
    Array.from(ui.matchDownloadOriginsForProcess({ ...procV1, sha256: null }, [dlV2SamePath]), (d) => d.id),
    [dlV2SamePath.id],
  );
  assert.deepEqual(
    Array.from(ui.matchDownloadOriginsForProcess(procV1, [dlNoShaSamePath]), (d) => d.id),
    [dlNoShaSamePath.id],
  );

  // Equal SHA-256 after move -> matches regardless of path difference
  assert.deepEqual(
    Array.from(ui.matchDownloadOriginsForProcess(procV1, [dlV2SamePath, dlV1MovedOrig]), (d) => d.id),
    [dlV1MovedOrig.id],
  );

  // View 2 must not attach MOTW badge or v2 download telemetry to v1 process
  ui.state.snapshot = {
    processes: [procV1],
    dns_queries: [],
    network_events: [],
    file_canary_events: [],
    download_origins: [dlV2SamePath],
  };
  ui.state.selectedProcessId = procV1.process_instance_id;
  ui.state.activeTab = "all";
  ui.renderTree();
  assert.doesNotMatch(ui.el.processTree.innerHTML, /badge-motw">MOTW</);
  assert.doesNotMatch(ui.el.processInspector.innerHTML, /mirror-v2\.localedr\.invalid/);
  assert.match(ui.el.telemetryBody.innerHTML, /No telemetry recorded for this scope/);
});

test("UI-P4-10: Process inspector prevents cross-site origin/referrer/frame mixing for identical SHA-256", () => {
  const ui = loadAppHarness();
  const shaSame = "c".repeat(64);

  const procSiteA = {
    process_instance_id: "400:1",
    pid: 400,
    ppid: 4,
    exe_path: "C:\\Users\\Alice\\Downloads\\tool-a.exe",
    command_line: "tool-a.exe",
    created_at_ms: 1_732_000_000_000,
    exited_at_ms: null,
    is_trusted_os: false,
    signer_subject: null,
    sha256: shaSame,
    origin_url: "https://site-a.localedr.invalid/release",
  };
  const dlSiteBNewer = {
    id: 22,
    file_path: "C:\\Users\\Alice\\Downloads\\tool-b.exe",
    sha256: shaSame,
    tab_url: "https://site-b.localedr.invalid/mirror",
    frame_url: "https://frame-b.localedr.invalid/embed",
    referrer_url: "https://ref-b.localedr.invalid/landing",
    downloaded_at_ms: 1_732_000_010_000,
  };
  const dlSiteAOlder = {
    id: 21,
    file_path: "C:\\Users\\Alice\\Downloads\\tool-a.exe",
    sha256: shaSame,
    tab_url: "https://site-a.localedr.invalid/release",
    frame_url: "https://frame-a.localedr.invalid/embed",
    referrer_url: "https://ref-a.localedr.invalid/landing",
    downloaded_at_ms: 1_732_000_001_000,
  };

  // Case 1: Both Site B (newest) and Site A (older) match by SHA-256 -> inspector must enrich from Site A only
  ui.state.snapshot = {
    processes: [procSiteA],
    dns_queries: [],
    network_events: [],
    file_canary_events: [],
    download_origins: [dlSiteBNewer, dlSiteAOlder],
  };
  ui.state.selectedProcessId = procSiteA.process_instance_id;
  const matchedBoth = ui.matchDownloadOriginsForProcess(
    procSiteA,
    ui.state.snapshot.download_origins,
  );
  assert.equal(ui.selectPrimaryDownloadOrigin(procSiteA, matchedBoth)?.id, dlSiteAOlder.id);
  ui.renderTree();
  assert.match(ui.el.processInspector.innerHTML, /site-a\.localedr\.invalid\/release/);
  assert.match(ui.el.processInspector.innerHTML, /ref-a\.localedr\.invalid\/landing/);
  assert.match(ui.el.processInspector.innerHTML, /frame-a\.localedr\.invalid\/embed/);
  assert.doesNotMatch(ui.el.processInspector.innerHTML, /ref-b\.localedr\.invalid/);
  assert.doesNotMatch(ui.el.processInspector.innerHTML, /frame-b\.localedr\.invalid/);

  // Case 2: Only Site B row exists in snapshot while procSiteA.origin_url is Site A -> do NOT borrow Site B referrer/frame
  ui.state.snapshot.download_origins = [dlSiteBNewer];
  const matchedBOnly = ui.matchDownloadOriginsForProcess(
    procSiteA,
    ui.state.snapshot.download_origins,
  );
  assert.equal(ui.selectPrimaryDownloadOrigin(procSiteA, matchedBOnly), null);
  ui.renderTree();
  assert.match(ui.el.processInspector.innerHTML, /site-a\.localedr\.invalid\/release/);
  assert.doesNotMatch(ui.el.processInspector.innerHTML, /Referrer URL/);
  assert.doesNotMatch(ui.el.processInspector.innerHTML, /Frame URL/);
  assert.doesNotMatch(ui.el.processInspector.innerHTML, /ref-b\.localedr\.invalid/);
  assert.doesNotMatch(ui.el.processInspector.innerHTML, /frame-b\.localedr\.invalid/);

  // Case 3: When proc.origin_url is unset, prefer matching exe_path if present, else newest matched row
  const procNoOrigin = { ...procSiteA, process_instance_id: "400:2", origin_url: null };
  ui.state.snapshot.processes = [procNoOrigin];
  ui.state.selectedProcessId = procNoOrigin.process_instance_id;
  assert.equal(ui.selectPrimaryDownloadOrigin(procNoOrigin, matchedBoth)?.id, dlSiteAOlder.id);
  assert.equal(ui.selectPrimaryDownloadOrigin(procNoOrigin, matchedBOnly)?.id, dlSiteBNewer.id);
  ui.renderTree();
  assert.match(ui.el.processInspector.innerHTML, /site-b\.localedr\.invalid\/mirror/);
  assert.match(ui.el.processInspector.innerHTML, /ref-b\.localedr\.invalid\/landing/);
  assert.match(ui.el.processInspector.innerHTML, /frame-b\.localedr\.invalid\/embed/);
});

test("PR27-REG-01: Sample Preview partial recovery clears synthetic state and preserves live feedback", async () => {
  const ui = loadAppHarness(async (cmd) => {
    if (cmd === "fetch_local_defense_status") {
      return ui.buildSampleData().localDefenseStatus;
    }
    if (cmd === "fetch_flight_recorder") {
      return {
        processes: [],
        dns_queries: [],
        network_events: [],
        file_canary_events: [],
        download_origins: [],
      };
    }
    if (cmd === "fetch_metrics") {
      return {
        events_received: 0,
        high_priority_dropped: 0,
        telemetry_dropped: 0,
        alerts_emitted: 0,
      };
    }
    if (cmd === "fetch_alerts") {
      throw new Error("alerts pipe read timeout");
    }
    if (cmd === "fetch_rules") {
      return [];
    }
    return null;
  });

  ui.loadSamplePreview();
  assert.equal(ui.state.isSamplePreview, true);
  assert.ok(ui.state.alerts.length > 0);
  assert.ok(ui.state.rules.length > 0);

  await ui.refreshAll();
  assert.equal(ui.state.isSamplePreview, false);
  assert.equal(ui.state.isDaemonOnline, true);
  assert.equal(ui.state.alerts.length, 0);
  assert.equal(ui.state.rules.length, 0);
  assert.equal(ui.state.selectedAlertId, null);
  assert.match(ui.state.triageFeedback?.message || "", /Failed to refresh alerts/);
});

test("CSP-01: index.html and tauri.conf.json maintain strict CSP without inline scripts or handlers", () => {
  const html = fs.readFileSync(indexHtmlPath, "utf8");
  assert.equal(/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), false);
  assert.equal(/\son[a-z]+\s*=/i.test(html), false);

  const conf = JSON.parse(fs.readFileSync(tauriConfPath, "utf8"));
  assert.equal(
    conf.app.security.csp,
    "default-src 'self'; connect-src ipc: http://ipc.localhost; style-src 'self'; script-src 'self'",
  );
});
