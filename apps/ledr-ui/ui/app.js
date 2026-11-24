(() => {
  "use strict";

  const VIEW_TITLES = {
    triage: "Alert Triage | LocalEDR",
    lineage: "Flight Recorder | LocalEDR",
    policy: "Policy & Shield | LocalEDR",
  };

  const state = {
    snapshot: {
      processes: [],
      dns_queries: [],
      network_events: [],
      file_canary_events: [],
      download_origins: [],
    },
    alerts: [],
    rules: [],
    localDefenseStatus: null,
    metrics: null,
    selectedProcessId: null,
    selectedAlertId: null,
    lastSyncedAlertId: null,
    launchFocusAlertId: null,
    alertQueueFilter: "unresolved",
    alertFilterText: "",
    filterText: "",
    policyScopeFilter: "all",
    policyFilterText: "",
    policyFeedback: null,
    isMutatingRule: false,
    domainRiskResult: null,
    domainRiskError: null,
    isCheckingDomain: false,
    activeTab: "all",
    activeView: "lineage",
    collapsedIds: new Set(),
    isSamplePreview: false,
    isDaemonOnline: false,
    isResolvingAlert: false,
    selectedAlertIsNetwork: false,
    triageFeedback: null,
    triageFeedbackByAlert: new Map(),
    triageValidationFeedback: null,
    daemonVersion: null,
    updaterStatus: null,
    updaterActionFeedback: null,
    updateBannerDismissedVersion: null,
    isCheckingUpdate: false,
    isApplyingUpdate: false,
  };

  const MAX_TRIAGE_FEEDBACK_ENTRIES = 64;

  const el = {
    navTabs: Array.from(document.querySelectorAll(".nav-tab")),
    views: {
      triage: document.getElementById("view-triage"),
      lineage: document.getElementById("view-lineage"),
      policy: document.getElementById("view-policy"),
    },
    triageUnresolvedBadge: document.getElementById("triage-unresolved-badge"),
    launchModePill: document.getElementById("launch-mode-pill"),
    daemonStatusPill: document.getElementById("daemon-status-pill"),
    metricsPill: document.getElementById("metrics-pill"),
    refreshBtn: document.getElementById("refresh-btn"),
    statusBanner: document.getElementById("status-banner"),
    bannerTitle: document.getElementById("banner-title"),
    bannerDetail: document.getElementById("banner-detail"),
    retryBtn: document.getElementById("retry-btn"),
    sampleBtn: document.getElementById("sample-btn"),
    // View 1 elements
    alertQueueSummary: document.getElementById("alert-queue-summary"),
    filterUnresolvedBtn: document.getElementById("filter-unresolved-btn"),
    filterAllBtn: document.getElementById("filter-all-btn"),
    filterUnresolvedCount: document.getElementById("filter-unresolved-count"),
    filterAllCount: document.getElementById("filter-all-count"),
    alertFilter: document.getElementById("alert-filter"),
    alertQueue: document.getElementById("alert-queue"),
    triageEmpty: document.getElementById("triage-empty"),
    triageEmptyLabel: document.getElementById("triage-empty-label"),
    triageEmptyFeedback: document.getElementById("triage-empty-feedback"),
    triageShowAllBtn: document.getElementById("triage-show-all-btn"),
    triageSampleBtn: document.getElementById("triage-sample-btn"),
    triageDetail: document.getElementById("triage-detail"),
    triageSuspendBanner: document.getElementById("triage-suspend-banner"),
    triageDetectionDl: document.getElementById("triage-detection-dl"),
    triageLineageDl: document.getElementById("triage-lineage-dl"),
    inspectInView2Btn: document.getElementById("inspect-in-view2-btn"),
    triageMotwBody: document.getElementById("triage-motw-body"),
    triageNetBody: document.getElementById("triage-net-body"),
    triageActionStatus: document.getElementById("triage-action-status"),
    btnTerminateBlock: document.getElementById("btn-terminate-block"),
    optAddBlockRule: document.getElementById("opt-add-block-rule"),
    terminateConstraintNote: document.getElementById("terminate-constraint-note"),
    btnAllowOnce: document.getElementById("btn-allow-once"),
    allowOnceConstraintNote: document.getElementById("allow-once-constraint-note"),
    btnAllowPermanent: document.getElementById("btn-allow-permanent"),
    optUseSigner: document.getElementById("opt-use-signer"),
    signerConstraintNote: document.getElementById("signer-constraint-note"),
    optAllowDest: document.getElementById("opt-allow-dest"),
    targetScopeNote: document.getElementById("target-scope-note"),
    // View 2 elements
    treeSummary: document.getElementById("tree-summary"),
    processFilter: document.getElementById("process-filter"),
    processTree: document.getElementById("process-tree"),
    allProcsBtn: document.getElementById("all-procs-btn"),
    expandAllBtn: document.getElementById("expand-all-btn"),
    collapseAllBtn: document.getElementById("collapse-all-btn"),
    processInspector: document.getElementById("process-inspector"),
    tabBtns: Array.from(document.querySelectorAll(".tab-btn")),
    countAll: document.getElementById("count-all"),
    countDns: document.getElementById("count-dns"),
    countNetwork: document.getElementById("count-network"),
    countCanary: document.getElementById("count-canary"),
    scopeIndicator: document.getElementById("scope-indicator"),
    telemetryBody: document.getElementById("telemetry-body"),
    // View 3 elements
    policyRulesSummary: document.getElementById("policy-rules-summary"),
    policyScopeBtns: Array.from(document.querySelectorAll(".policy-scope-btn")),
    scopeCountAll: document.getElementById("scope-count-all"),
    scopeCountBlock: document.getElementById("scope-count-block"),
    scopeCountAllow: document.getElementById("scope-count-allow"),
    scopeCountCanary: document.getElementById("scope-count-canary"),
    scopeCountProcess: document.getElementById("scope-count-process"),
    policyFilter: document.getElementById("policy-filter"),
    toggleAddRuleBtn: document.getElementById("toggle-add-rule-btn"),
    policyAddForm: document.getElementById("policy-add-form"),
    ruleScopeInput: document.getElementById("rule-scope-input"),
    ruleExeInput: document.getElementById("rule-exe-input"),
    ruleTargetInput: document.getElementById("rule-target-input"),
    ruleSha256Input: document.getElementById("rule-sha256-input"),
    ruleSignerInput: document.getElementById("rule-signer-input"),
    ruleThumbprintInput: document.getElementById("rule-thumbprint-input"),
    policyScopeNote: document.getElementById("policy-scope-note"),
    cancelAddRuleBtn: document.getElementById("cancel-add-rule-btn"),
    submitAddRuleBtn: document.getElementById("submit-add-rule-btn"),
    policyFeedback: document.getElementById("policy-feedback"),
    policyRulesBody: document.getElementById("policy-rules-body"),
    honeypotSummary: document.getElementById("honeypot-summary"),
    honeypotStatusList: document.getElementById("honeypot-status-list"),
    protectedPathsList: document.getElementById("protected-paths-list"),
    browserShieldDl: document.getElementById("browser-shield-dl"),
    domainCheckForm: document.getElementById("domain-check-form"),
    domainCheckInput: document.getElementById("domain-check-input"),
    domainCheckBtn: document.getElementById("domain-check-btn"),
    domainCheckResult: document.getElementById("domain-check-result"),
    // Updater banner & View 3 panel elements
    updateBanner: document.getElementById("update-banner"),
    updateBannerTitle: document.getElementById("update-banner-title"),
    updateBannerDetail: document.getElementById("update-banner-detail"),
    updateBannerApplyBtn: document.getElementById("update-banner-apply-btn"),
    updateBannerNotesBtn: document.getElementById("update-banner-notes-btn"),
    updateBannerViewBtn: document.getElementById("update-banner-view-btn"),
    updateBannerDismissBtn: document.getElementById("update-banner-dismiss-btn"),
    appUpdatePanel: document.getElementById("app-update-panel"),
    updateStateBadge: document.getElementById("update-state-badge"),
    updateCheckBtn: document.getElementById("update-check-btn"),
    updateVersionMismatch: document.getElementById("update-version-mismatch"),
    updateFeedback: document.getElementById("update-feedback"),
    updateProgressWrap: document.getElementById("update-progress-wrap"),
    updateProgressBar: document.getElementById("update-progress-bar"),
    updateProgressText: document.getElementById("update-progress-text"),
    updateApplyBtn: document.getElementById("update-apply-btn"),
    updateCancelBtn: document.getElementById("update-cancel-btn"),
    updateReleaseNotesBtn: document.getElementById("update-release-notes-btn"),
    appUpdateDl: document.getElementById("app-update-dl"),
  };

  function getInvoke() {
    if (
      window.__TAURI__ &&
      window.__TAURI__.core &&
      typeof window.__TAURI__.core.invoke === "function"
    ) {
      return window.__TAURI__.core.invoke;
    }
    return null;
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function safeJsonParse(raw) {
    if (!raw || typeof raw !== "string") return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  function baseName(exePath) {
    if (!exePath) return "<unknown>";
    const parts = exePath.split(/[\\/]/);
    return parts[parts.length - 1] || exePath;
  }

  function formatTime(ms) {
    if (ms === null || ms === undefined) return "-";
    const date = new Date(ms);
    if (Number.isNaN(date.getTime())) return String(ms);
    return date.toISOString().replace("T", " ").replace("Z", "");
  }

  function formatProtocol(proto) {
    if (proto === 6) return "TCP";
    if (proto === 17) return "UDP";
    if (proto === 1) return "ICMP";
    return `P${proto}`;
  }

  function formatAccessMask(mask) {
    if (mask === null || mask === undefined) return "-";
    if (typeof mask === "number" && Number.isFinite(mask)) {
      return `0x${(mask >>> 0).toString(16).padStart(8, "0")}`;
    }
    return String(mask);
  }

  function parsePidFromInstanceId(instanceId) {
    if (!instanceId || typeof instanceId !== "string") return null;
    const colonIdx = instanceId.indexOf(":");
    if (colonIdx <= 0) return null;
    const pid = Number(instanceId.slice(0, colonIdx));
    return Number.isFinite(pid) ? pid : null;
  }

  function isUnresolvedAlert(alert) {
    return alert && (alert.status === "Pending" || alert.status === "ExpiredSuspended");
  }

  function isValidIpv4(ip) {
    if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(ip)) {
      return false;
    }
    return ip.split(".").every((octet) => Number(octet) <= 255);
  }

  function isValidIpv6(ip) {
    if (!ip || !ip.includes(":") || /[^0-9a-fA-F:.]/.test(ip)) {
      return false;
    }
    try {
      const url = new URL(`http://[${ip}]/`);
      return url.hostname.startsWith("[") && url.hostname.endsWith("]");
    } catch {
      return false;
    }
  }

  function isLiteralIpOrCidr(raw) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) return false;
    const slashIdx = trimmed.indexOf("/");
    if (slashIdx === -1) {
      return isValidIpv4(trimmed) || isValidIpv6(trimmed);
    }
    if (trimmed.indexOf("/", slashIdx + 1) !== -1) {
      return false;
    }
    const addr = trimmed.slice(0, slashIdx);
    const prefixStr = trimmed.slice(slashIdx + 1);
    if (!/^(?:0|[1-9]\d{0,2})$/.test(prefixStr)) {
      return false;
    }
    const prefix = Number(prefixStr);
    if (isValidIpv4(addr)) return prefix <= 32;
    if (isValidIpv6(addr)) return prefix <= 128;
    return false;
  }

  function isNetworkDomainTarget(scope, allowedTarget) {
    if (scope !== "NetworkBlock" && scope !== "NetworkAllow") return false;
    const trimmed = String(allowedTarget || "").trim();
    if (!trimmed) return false;
    return !isLiteralIpOrCidr(trimmed);
  }

  function formatBackendError(err) {
    if (err && typeof err === "object" && typeof err.message === "string") {
      return err.message;
    }
    return String(err ?? "Unknown error");
  }

  function normalizeWindowsPath(value) {
    if (typeof value !== "string") return "";
    let s = value.trim().replaceAll("/", "\\");
    if (!s) return "";
    let prefix = "";
    if (/^\\\\\?\\unc\\/i.test(s)) {
      s = "\\\\" + s.slice(8);
    } else if (/^\\\\\?\\[a-z]:\\/i.test(s)) {
      s = s.slice(4);
    } else if (/^\\\\\?\\volume\{/i.test(s)) {
      prefix = "\\\\?\\";
      s = s.slice(4);
    }
    if (!prefix && s.startsWith("\\\\")) {
      prefix = "\\\\";
      s = s.replace(/^\\+/, "");
    }
    s = s.replace(/\\{2,}/g, "\\");
    let out = prefix + s;
    if (out.length > 1 && !/^(?:[a-z]:\\|\\\\)$/i.test(out)) {
      out = out.replace(/\\+$/, "");
    }
    return out.toLowerCase();
  }

  function formatShortSha256(hex) {
    if (typeof hex !== "string") return null;
    const clean = hex.trim().toLowerCase();
    if (!clean) return null;
    return clean.length <= 12 ? clean : `${clean.slice(0, 12)}...`;
  }

  function formatMotwSourceLabel(source) {
    if (typeof source !== "string") return null;
    const clean = source.trim();
    if (!clean) return null;
    if (clean === "download_path") return "Path";
    if (clean === "download_sha256") return "SHA-256";
    if (clean === "zone_identifier_ads") return "Zone.Identifier";
    return clean;
  }

  function formatMotwZoneLabel(zoneId) {
    if (!Number.isInteger(zoneId) || zoneId < 0) return null;
    if (zoneId === 0) return "Zone 0 (Local Machine)";
    if (zoneId === 1) return "Zone 1 (Local Intranet)";
    if (zoneId === 2) return "Zone 2 (Trusted Sites)";
    if (zoneId === 3) return "Zone 3 (Internet)";
    if (zoneId === 4) return "Zone 4 (Restricted Sites)";
    return `Zone ${zoneId}`;
  }

  function matchDownloadOriginsForProcess(proc, downloadOrigins) {
    if (!proc || !Array.isArray(downloadOrigins) || downloadOrigins.length === 0) {
      return [];
    }
    const procSha =
      typeof proc.sha256 === "string" ? proc.sha256.trim().toLowerCase() : "";
    const procPath = normalizeWindowsPath(proc.exe_path);
    const procOrigin =
      typeof proc.origin_url === "string" ? proc.origin_url.trim() : "";

    const primaryMatches = downloadOrigins.filter((d) => {
      if (!d) return false;
      const dSha = typeof d.sha256 === "string" ? d.sha256.trim().toLowerCase() : "";
      if (procSha && dSha) return procSha === dSha;
      const dPath = normalizeWindowsPath(d.file_path);
      if (procPath && dPath && procPath === dPath) return true;
      return false;
    });
    if (primaryMatches.length > 0) {
      return primaryMatches;
    }
    if (!procOrigin) {
      return [];
    }
    return downloadOrigins.filter((d) => {
      if (!d) return false;
      const dTab = typeof d.tab_url === "string" ? d.tab_url.trim() : "";
      if (!dTab || dTab !== procOrigin) return false;
      const dSha = typeof d.sha256 === "string" ? d.sha256.trim().toLowerCase() : "";
      if (procSha && dSha && procSha !== dSha) return false;
      return true;
    });
  }

  function selectPrimaryDownloadOrigin(proc, matchedDownloads) {
    if (!Array.isArray(matchedDownloads) || matchedDownloads.length === 0) {
      return null;
    }
    const procPath = normalizeWindowsPath(proc?.exe_path);
    const procOrigin =
      typeof proc?.origin_url === "string" ? proc.origin_url.trim() : "";
    if (!procOrigin) {
      if (procPath) {
        const pathMatch = matchedDownloads.find(
          (d) => normalizeWindowsPath(d?.file_path) === procPath,
        );
        if (pathMatch) {
          return pathMatch;
        }
      }
      return matchedDownloads[0] || null;
    }
    const originMatches = matchedDownloads.filter((d) => {
      const dTab = typeof d?.tab_url === "string" ? d.tab_url.trim() : "";
      return dTab !== "" && dTab === procOrigin;
    });
    if (originMatches.length === 0) {
      return null;
    }
    if (procPath) {
      const pathMatch = originMatches.find(
        (d) => normalizeWindowsPath(d?.file_path) === procPath,
      );
      if (pathMatch) {
        return pathMatch;
      }
    }
    return originMatches[0];
  }

  function getBrowserAlertResolutionPolicy(alert, details) {
    const isBrowser = Boolean(
      details?.isBrowserAlert ?? alert?.source_layer === "LAYER_4_BROWSER",
    );
    const hasProc = Boolean(details?.processInstanceId ?? alert?.process_instance_id);
    const isProcesslessBrowser = isBrowser && !hasProc;
    if (isProcesslessBrowser) {
      return {
        isProcesslessBrowser: true,
        allowOnceLabel: "Acknowledge",
        allowOnceConstraint: "Resolves browser alert",
        terminateDisabled: true,
        terminateConstraint: "No local process attached",
        addBlockRuleDisabled: true,
        allowPermanentDisabled: true,
        allowPermanentConstraint: "No local process attached",
      };
    }
    return {
      isProcesslessBrowser: false,
      allowOnceLabel: "Allow Once",
      allowOnceConstraint: "Resumes process without rule",
      terminateDisabled: false,
      terminateConstraint: "Terminates process tree and applies dynamic WFP block",
      addBlockRuleDisabled: false,
      allowPermanentDisabled: false,
      allowPermanentConstraint: "",
    };
  }

  function computeBrowserShieldStats(alerts, snapshot) {
    const list = Array.isArray(alerts) ? alerts : [];
    const browserAlerts = list.filter((a) => a && a.source_layer === "LAYER_4_BROWSER");
    const browserAlertsUnresolved = browserAlerts.filter((a) =>
      isUnresolvedAlert(a),
    ).length;
    const trackedDownloadsCount = Array.isArray(snapshot?.download_origins)
      ? snapshot.download_origins.length
      : 0;
    return {
      browserAlertsTotal: browserAlerts.length,
      browserAlertsUnresolved,
      trackedDownloadsCount,
    };
  }

  function buildSampleData() {
    const now = Date.now();
    const explorerId = "4120:133765432100000000";
    const cmdId = "5380:133765432105000000";
    const psId = "6912:133765432108000000";
    const stealerId = "7412:133765432110000000";
    const syncId = "8104:133765432102000000";

    const cookiesTarget =
      "C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies";
    const honeypotTarget =
      "C:\\Users\\user\\Documents\\!00_LocalEDR_Canary_DoNotEdit.docx";
    const stealerExe = "C:\\Users\\user\\AppData\\Local\\Temp\\cred-audit.exe";
    const stealerSha =
      "a3f1c8d4e9b2017f55210a3b948c67e12d0f4a8b6c3e19d70a5b2c4e8f1092a1";
    const syncExe = "C:\\Program Files\\ExampleSync\\doc-sync.exe";
    const syncSha =
      "b72e9011f4c83029a1e64509b8c7d231e4a5f60718293a4b5c6d7e8f90123456";
    const syncSigner = "CN=Example Sync Tools Inc., O=Example Sync LLC, C=US";
    const syncThumbprint = "4A8F19C203B1D7E54690AB12CD34EF5678901234";

    const snapshot = {
      processes: [
        {
          process_instance_id: explorerId,
          pid: 4120,
          parent_instance_id: null,
          ppid: 1024,
          exe_path: "C:\\Windows\\explorer.exe",
          command_line: "C:\\Windows\\Explorer.EXE",
          sha256: null,
          signer_subject: "Microsoft Windows",
          is_trusted_os: true,
          user_sid: "S-1-5-21-1000",
          origin_url: null,
          created_at_ms: now - 120_000,
          exited_at_ms: null,
        },
        {
          process_instance_id: cmdId,
          pid: 5380,
          parent_instance_id: explorerId,
          ppid: 4120,
          exe_path: "C:\\Windows\\System32\\cmd.exe",
          command_line:
            "cmd.exe /c powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEwAbwBjAGEAbABFAEQAUgAiAA==",
          sha256: null,
          signer_subject: "Microsoft Windows",
          is_trusted_os: true,
          user_sid: "S-1-5-21-1000",
          origin_url: null,
          created_at_ms: now - 35_000,
          exited_at_ms: now - 25_000,
        },
        {
          process_instance_id: psId,
          pid: 6912,
          parent_instance_id: cmdId,
          ppid: 5380,
          exe_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line:
            "powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEwAbwBjAGEAbABFAEQAUgAiAA==",
          sha256: null,
          signer_subject: "Microsoft Windows",
          is_trusted_os: true,
          user_sid: "S-1-5-21-1000",
          origin_url: "https://example-download.invalid/payload.ps1",
          created_at_ms: now - 24_000,
          exited_at_ms: null,
        },
        {
          process_instance_id: stealerId,
          pid: 7412,
          parent_instance_id: psId,
          ppid: 6912,
          exe_path: stealerExe,
          command_line: `"${stealerExe}" --export-browser --silent`,
          sha256: stealerSha,
          signer_subject: null,
          is_trusted_os: false,
          user_sid: "S-1-5-21-1000",
          origin_url: "https://cdn-drop.nrd-sample.invalid/tools/cred-audit.zip",
          created_at_ms: now - 16_000,
          exited_at_ms: null,
        },
        {
          process_instance_id: syncId,
          pid: 8104,
          parent_instance_id: explorerId,
          ppid: 4120,
          exe_path: syncExe,
          command_line: `"${syncExe}" --backup-docs "C:\\Users\\user\\Documents"`,
          sha256: syncSha,
          signer_subject: syncSigner,
          is_trusted_os: false,
          user_sid: "S-1-5-21-1000",
          origin_url: null,
          created_at_ms: now - 90_000,
          exited_at_ms: null,
        },
      ],
      dns_queries: [
        {
          id: 1,
          timestamp_ms: now - 15_200,
          process_instance_id: stealerId,
          query_name: "exfil-gate.nrd-sample.invalid",
          query_type: 1,
          resolved_ips: ["203.0.113.77"],
          is_nrd: true,
        },
        {
          id: 2,
          timestamp_ms: now - 14_000,
          process_instance_id: psId,
          query_name: "telemetry-check.nrd-sample.invalid",
          query_type: 1,
          resolved_ips: ["203.0.113.42"],
          is_nrd: true,
        },
        {
          id: 3,
          timestamp_ms: now - 12_000,
          process_instance_id: explorerId,
          query_name: "settings-win.data.microsoft.com",
          query_type: 1,
          resolved_ips: ["13.107.42.14"],
          is_nrd: false,
        },
      ],
      network_events: [
        {
          id: 1,
          timestamp_ms: now - 15_000,
          process_instance_id: stealerId,
          protocol: 6,
          dst_ip: "203.0.113.77",
          dst_port: 443,
          domain_hint: "exfil-gate.nrd-sample.invalid",
          action: "SUSPENDED_BLOCKED",
        },
        {
          id: 2,
          timestamp_ms: now - 13_800,
          process_instance_id: psId,
          protocol: 6,
          dst_ip: "203.0.113.42",
          dst_port: 443,
          domain_hint: "telemetry-check.nrd-sample.invalid",
          action: "BLOCKED",
        },
        {
          id: 3,
          timestamp_ms: now - 11_900,
          process_instance_id: explorerId,
          protocol: 6,
          dst_ip: "13.107.42.14",
          dst_port: 443,
          domain_hint: "settings-win.data.microsoft.com",
          action: "ALLOWED",
        },
      ],
      file_canary_events: [
        {
          id: 1,
          timestamp_ms: now - 12_500,
          process_instance_id: stealerId,
          target_path: cookiesTarget,
          category: "CookieDb",
          access_mask: 0x00120089,
          action_taken: "SUSPENDED",
        },
        {
          id: 2,
          timestamp_ms: now - 75_000,
          process_instance_id: syncId,
          target_path: honeypotTarget,
          category: "Honeypot",
          access_mask: 0x00120116,
          action_taken: "SUSPENDED",
        },
      ],
      download_origins: [
        {
          id: 1,
          file_path: stealerExe,
          sha256: stealerSha,
          tab_url: "https://cdn-drop.nrd-sample.invalid/tools/cred-audit.zip",
          frame_url: "https://cdn-drop.nrd-sample.invalid/embed/dl",
          referrer_url: "https://search-portal.invalid/",
          downloaded_at_ms: now - 40_000,
        },
        {
          id: 2,
          file_path: "C:\\Users\\user\\Downloads\\script.ps1",
          sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          tab_url: "https://example-download.invalid/setup",
          frame_url: null,
          referrer_url: "https://search.invalid/",
          downloaded_at_ms: now - 45_000,
        },
      ],
    };

    const alerts = [
      {
        alert_id: "sample-cookie-001",
        timestamp_ms: now - 12_500,
        severity: "High",
        source_layer: "LAYER_1_CANARY",
        rule_id: "CANARY-COOKIE-DB",
        title: "Chrome Cookies Read by Unsigned Binary",
        process_instance_id: stealerId,
        process_suspended: true,
        status: "Pending",
        context_json: JSON.stringify({
          target_path: cookiesTarget,
          category: "cookie_db",
          access_mask: 0x00120089,
          is_write_or_delete: false,
          include_children: false,
          exe_path: stealerExe,
          command_line: `"${stealerExe}" --export-browser --silent`,
          parent_exe_path:
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          parent_command_line:
            "powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEwAbwBjAGEAbABFAEQAUgAiAA==",
          sha256: stealerSha,
          signer_subject: null,
          root_thumbprint: null,
          origin_url: "https://cdn-drop.nrd-sample.invalid/tools/cred-audit.zip",
          motw_source: "download_sha256",
          motw_zone_id: 3,
          motw_referrer: "https://search-portal.invalid/",
          motw_frame_url: "https://cdn-drop.nrd-sample.invalid/embed/dl",
        }),
        resolved_at_ms: null,
      },
      {
        alert_id: "sample-honeypot-002",
        timestamp_ms: now - 75_000,
        severity: "Critical",
        source_layer: "LAYER_1_CANARY",
        rule_id: "CANARY-HONEYPOT",
        title: "Honeypot Decoy File Write (60s Timeout)",
        process_instance_id: syncId,
        process_suspended: true,
        status: "ExpiredSuspended",
        context_json: JSON.stringify({
          target_path: honeypotTarget,
          category: "honeypot",
          access_mask: 0x00120116,
          is_write_or_delete: true,
          include_children: true,
          exe_path: syncExe,
          command_line: `"${syncExe}" --backup-docs "C:\\Users\\user\\Documents"`,
          parent_exe_path: "C:\\Windows\\explorer.exe",
          parent_command_line: "C:\\Windows\\Explorer.EXE",
          sha256: syncSha,
          signer_subject: syncSigner,
          root_thumbprint: syncThumbprint,
        }),
        resolved_at_ms: null,
      },
      {
        alert_id: "sample-net-004",
        timestamp_ms: now - 15_000,
        severity: "High",
        source_layer: "LAYER_3_NETWORK",
        rule_id: "LEDR-NET-HIGH-RISK-PATH",
        title: "High-Risk Path Outbound Connection: cred-audit.exe -> exfil-gate.nrd-sample.invalid (203.0.113.77:443)",
        process_instance_id: stealerId,
        process_suspended: true,
        status: "Pending",
        context_json: JSON.stringify({
          dst_ip: "203.0.113.77",
          dst_port: 443,
          protocol: 6,
          domain_hint: "exfil-gate.nrd-sample.invalid",
          risk_class: "HighRiskPath",
          wfp_blocked: true,
          wfp_filter_id: 1042,
          is_nrd: true,
          is_homograph: false,
          is_first_seen_domain: true,
          matched_brand: null,
          exe_path: stealerExe,
          command_line: `"${stealerExe}" --export-browser --silent`,
          parent_exe_path:
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          parent_command_line:
            "powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEwAbwBjAGEAbABFAEQAUgAiAA==",
          sha256: stealerSha,
          signer_subject: null,
          root_thumbprint: null,
          origin_url: "https://cdn-drop.nrd-sample.invalid/tools/cred-audit.zip",
          motw_source: "download_sha256",
          motw_zone_id: 3,
          motw_referrer: "https://search-portal.invalid/",
          motw_frame_url: "https://cdn-drop.nrd-sample.invalid/embed/dl",
        }),
        resolved_at_ms: null,
      },
      {
        alert_id: "sample-browser-004",
        timestamp_ms: now - 8_000,
        severity: "High",
        source_layer: "LAYER_4_BROWSER",
        rule_id: "BROWSER-ClickFixPastejacking",
        title: "Browser ClickFix / Pastejacking Detected",
        process_instance_id: null,
        process_suspended: false,
        status: "Pending",
        context_json: JSON.stringify({
          event_type: "ClickFixPastejacking",
          url: "https://verify-human.localedr.invalid/captcha",
          details: "Clipboard writeText matched LOTL pattern (powershell -EncodedCommand)",
          details_truncated: false,
        }),
        resolved_at_ms: null,
      },
      {
        alert_id: "sample-lotl-003",
        timestamp_ms: now - 35_000,
        severity: "Medium",
        source_layer: "LAYER_2_RULES",
        rule_id: "LEDR-LOTL-001",
        title: "Cmd Spawning Encoded PowerShell",
        process_instance_id: psId,
        process_suspended: false,
        status: "TerminatedBlocked",
        context_json: JSON.stringify({
          exe_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line:
            "powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEwAbwBjAGEAbABFAEQAUgAiAA==",
          parent_exe_path: "C:\\Windows\\System32\\cmd.exe",
          parent_command_line:
            "cmd.exe /c powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEwAbwBjAGEAbABFAEQAUgAiAA==",
          matched_fields: ["ParentImage", "Image", "CommandLine"],
        }),
        resolved_at_ms: now - 30_000,
      },
    ];

    const rules = [
      {
        rule_id: "SAMPLE-BLOCK-001",
        scope: "NetworkBlock",
        exe_path_pattern: stealerExe,
        sha256: stealerSha,
        signer_subject: null,
        root_thumbprint: null,
        allowed_target: null,
        created_at_ms: now - 10_000,
        created_by: "user_quarantine",
      },
      {
        rule_id: "SAMPLE-ALLOW-001",
        scope: "NetworkAllow",
        exe_path_pattern: syncExe,
        sha256: null,
        signer_subject: syncSigner,
        root_thumbprint: syncThumbprint,
        allowed_target: "*.examplesync.invalid",
        created_at_ms: now - 50_000,
        created_by: "user_triage",
      },
      {
        rule_id: "SAMPLE-CANARY-001",
        scope: "FileCanaryAllow",
        exe_path_pattern: syncExe,
        sha256: null,
        signer_subject: syncSigner,
        root_thumbprint: syncThumbprint,
        allowed_target: "C:\\Users\\user\\Documents\\*",
        created_at_ms: now - 60_000,
        created_by: "user_triage",
      },
    ];

    const localDefenseStatus = {
      honeypots: [
        {
          folder: "Documents",
          path: honeypotTarget,
          deployed: true,
          size_bytes: 14336,
        },
        {
          folder: "Desktop",
          path: "C:\\Users\\user\\Desktop\\!00_LocalEDR_Canary_DoNotEdit.docx",
          deployed: true,
          size_bytes: 14336,
        },
        {
          folder: "Pictures",
          path: "C:\\Users\\user\\Pictures\\!00_LocalEDR_Canary_DoNotEdit.docx",
          deployed: false,
          size_bytes: null,
        },
      ],
      protected_paths: [
        {
          category: "CookieDb",
          label: "Browser Cookies, Login Data & Local State",
          path_template:
            "%LOCALAPPDATA%\\{Google\\Chrome,Microsoft\\Edge,BraveSoftware\\Brave-Browser}\\User Data\\*\\(Cookies|Login Data|Local State), %APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\(cookies.sqlite|logins.json|key4.db)",
        },
        {
          category: "SshKey",
          label: "SSH Private Keys",
          path_template: "%USERPROFILE%\\.ssh\\*",
        },
        {
          category: "CloudCreds",
          label: "AWS / GCP Credentials",
          path_template:
            "%USERPROFILE%\\.aws\\{credentials,config}, %USERPROFILE%\\.config\\gcloud\\*",
        },
        {
          category: "EnvFile",
          label: "Project .env Secrets (Registered Dev Roots)",
          path_template: "<DevRoots>\\**\\.env*",
        },
        {
          category: "Honeypot",
          label: "Ransomware Decoy Files (Write/Delete)",
          path_template:
            "%USERPROFILE%\\{Documents,Desktop,Pictures}\\!00_LocalEDR_Canary_DoNotEdit.docx",
        },
        {
          category: "AutorunRegistry",
          label: "Windows Autorun Registry Keys",
          path_template:
            "{HKCU,HKLM}\\Software\\Microsoft\\Windows\\CurrentVersion\\{Run,RunOnce}",
        },
      ],
      browser_shield: {
        bridge_binary_path: "C:\\Program Files\\LocalEDR\\ledr-bridge-nm.exe",
        bridge_binary_present: true,
        native_host_registered: true,
        uri_scheme_registered: true,
        native_host_scope: "HKCU",
        registered_browsers: ["Chrome", "Edge"],
        manifest_path:
          "C:\\Users\\user\\AppData\\Local\\LocalEDR\\native-messaging\\com.localedr.bridge.user.chrome.json",
        manifest_valid: true,
        manifest_status: "valid",
        manifest_error: null,
        uri_scheme_scope: "HKCU",
        expected_extension_id: "ecelachfiiiiiibpjeomfncgpegbpanh",
        browsers: [
          {
            browser: "Chrome",
            effective_scope: "HKCU",
            hkcu_registered: true,
            hklm_registered: false,
            manifest_path:
              "C:\\Users\\user\\AppData\\Local\\LocalEDR\\native-messaging\\com.localedr.bridge.user.chrome.json",
            manifest_valid: true,
            manifest_status: "valid",
            manifest_error: null,
          },
          {
            browser: "Edge",
            effective_scope: "HKCU",
            hkcu_registered: true,
            hklm_registered: false,
            manifest_path:
              "C:\\Users\\user\\AppData\\Local\\LocalEDR\\native-messaging\\com.localedr.bridge.user.edge.json",
            manifest_valid: true,
            manifest_status: "valid",
            manifest_error: null,
          },
          {
            browser: "Brave",
            effective_scope: null,
            hkcu_registered: false,
            hklm_registered: false,
            manifest_path: null,
            manifest_valid: false,
            manifest_status: "not_registered",
            manifest_error: null,
          },
        ],
      },
    };

    return { snapshot, alerts, rules, localDefenseStatus };
  }

  function buildHierarchy(snapshot) {
    const processes = Array.isArray(snapshot.processes) ? snapshot.processes : [];
    const byId = new Map();
    const byPid = new Map();
    for (const p of processes) {
      if (!byId.has(p.process_instance_id)) {
        byId.set(p.process_instance_id, p);
        if (!byPid.has(p.pid)) byPid.set(p.pid, []);
        byPid.get(p.pid).push(p);
      }
    }

    const dnsCounts = new Map();
    for (const q of snapshot.dns_queries || []) {
      dnsCounts.set(q.process_instance_id, (dnsCounts.get(q.process_instance_id) || 0) + 1);
    }
    const netCounts = new Map();
    for (const n of snapshot.network_events || []) {
      netCounts.set(n.process_instance_id, (netCounts.get(n.process_instance_id) || 0) + 1);
    }
    const canaryCounts = new Map();
    for (const c of snapshot.file_canary_events || []) {
      canaryCounts.set(c.process_instance_id, (canaryCounts.get(c.process_instance_id) || 0) + 1);
    }

    const ordered = Array.from(byId.values()).sort(
      (a, b) =>
        a.created_at_ms - b.created_at_ms ||
        a.pid - b.pid ||
        a.process_instance_id.localeCompare(b.process_instance_id),
    );

    const parentOf = new Map();
    const orphanOf = new Map();
    for (const p of ordered) {
      if (p.parent_instance_id) {
        if (
          p.parent_instance_id !== p.process_instance_id &&
          byId.has(p.parent_instance_id)
        ) {
          parentOf.set(p.process_instance_id, p.parent_instance_id);
          orphanOf.set(p.process_instance_id, false);
        } else {
          parentOf.set(p.process_instance_id, null);
          orphanOf.set(p.process_instance_id, true);
        }
      } else if (!p.ppid || p.ppid === p.pid) {
        parentOf.set(p.process_instance_id, null);
        orphanOf.set(p.process_instance_id, false);
      } else {
        const cands = (byPid.get(p.ppid) || []).filter(
          (c) =>
            c.process_instance_id !== p.process_instance_id &&
            c.created_at_ms <= p.created_at_ms &&
            (c.exited_at_ms === null ||
              c.exited_at_ms === undefined ||
              c.exited_at_ms >= p.created_at_ms),
        );
        if (cands.length > 0) {
          cands.sort((a, b) => a.created_at_ms - b.created_at_ms);
          parentOf.set(p.process_instance_id, cands[cands.length - 1].process_instance_id);
          orphanOf.set(p.process_instance_id, false);
        } else {
          parentOf.set(p.process_instance_id, null);
          orphanOf.set(p.process_instance_id, true);
        }
      }
    }

    const settled = new Set();
    for (const p of ordered) {
      const startId = p.process_instance_id;
      if (settled.has(startId)) continue;
      const chain = [];
      const inChain = new Set();
      let cur = startId;
      while (cur && !settled.has(cur)) {
        if (inChain.has(cur)) {
          const breaker = chain[chain.length - 1];
          if (breaker) {
            parentOf.set(breaker, null);
            orphanOf.set(breaker, true);
          }
          break;
        }
        inChain.add(cur);
        chain.push(cur);
        cur = parentOf.get(cur) || null;
      }
      for (const id of chain) settled.add(id);
    }

    const childrenMap = new Map();
    const roots = [];
    for (const p of ordered) {
      const pid = parentOf.get(p.process_instance_id);
      if (pid) {
        if (!childrenMap.has(pid)) childrenMap.set(pid, []);
        childrenMap.get(pid).push(p.process_instance_id);
      } else {
        roots.push(p.process_instance_id);
      }
    }

    function toNode(id) {
      const proc = byId.get(id);
      const childIds = childrenMap.get(id) || [];
      return {
        process: proc,
        is_orphan_root: orphanOf.get(id) || false,
        dns_count: dnsCounts.get(id) || 0,
        network_count: netCounts.get(id) || 0,
        canary_count: canaryCounts.get(id) || 0,
        children: childIds.map(toNode),
      };
    }

    return { roots: roots.map(toNode), byId };
  }

  function extractAlertDetails(alert, byId) {
    const ctx = safeJsonParse(alert.context_json) || {};
    const procId = alert.process_instance_id || null;
    const proc = procId ? byId.get(procId) || null : null;
    const parentProc =
      proc && proc.parent_instance_id ? byId.get(proc.parent_instance_id) || null : null;

    const matchingCanary = (state.snapshot.file_canary_events || []).find(
      (c) => procId && c.process_instance_id === procId,
    );

    const netEvt = ctx.event?.NetworkConnect || null;
    const isBrowserAlert = alert.source_layer === "LAYER_4_BROWSER";
    const browserEventType = typeof ctx.event_type === "string" ? ctx.event_type : null;
    const browserUrl = typeof ctx.url === "string" ? ctx.url : null;
    const browserDetails = typeof ctx.details === "string" ? ctx.details : null;
    const browserDetailsTruncated = Boolean(ctx.details_truncated);
    const isNetworkAlert =
      alert.source_layer === "LAYER_3_NETWORK" || Boolean(netEvt) || Boolean(ctx.dst_ip);
    const dstIp = ctx.dst_ip || netEvt?.dst_ip || null;
    const dstPort = ctx.dst_port ?? netEvt?.dst_port ?? null;
    const protocol = ctx.protocol ?? netEvt?.protocol ?? null;
    const domainHint = ctx.domain_hint || netEvt?.domain_hint || null;
    const riskClass = ctx.risk_class || null;
    const wfpBlocked = Boolean(ctx.wfp_blocked);
    const wfpFilterId = ctx.wfp_filter_id ?? null;
    const attribution = ctx.attribution || null;
    const candidatePids = Array.isArray(ctx.candidate_pids)
      ? ctx.candidate_pids
      : [];
    const candidateInstanceIds = Array.isArray(ctx.candidate_instance_ids)
      ? ctx.candidate_instance_ids
      : [];
    const isNrd = Boolean(ctx.is_nrd);
    const isHomograph = Boolean(ctx.is_homograph);
    const isFirstSeenDomain = Boolean(ctx.is_first_seen_domain);
    const matchedBrand = ctx.matched_brand || null;
    const matchedRuleId = ctx.matched_rule_id || null;

    const networkTarget = dstIp
      ? domainHint
        ? `${domainHint} (${dstIp}${dstPort !== null ? `:${dstPort}` : ""})`
        : `${dstIp}${dstPort !== null ? `:${dstPort}` : ""}`
      : null;

    const targetPath =
      ctx.target_path ||
      ctx.event?.CanaryFileAccess?.target_path ||
      networkTarget ||
      ctx.event?.DnsQuery?.query_name ||
      ctx.url ||
      matchingCanary?.target_path ||
      null;

    const category =
      ctx.category ||
      ctx.event?.CanaryFileAccess?.category ||
      riskClass ||
      (isNetworkAlert ? "OutboundNetwork" : null) ||
      ctx.event_type ||
      matchingCanary?.category ||
      null;

    const accessMask =
      ctx.access_mask ??
      ctx.event?.CanaryFileAccess?.access_mask ??
      matchingCanary?.access_mask ??
      null;

    const isWriteOrDelete =
      ctx.is_write_or_delete ??
      ctx.event?.CanaryFileAccess?.is_write_or_delete ??
      null;

    const includeChildren = Boolean(ctx.include_children);

    const exePath =
      ctx.exe_path ||
      ctx.event?.ProcessStart?.exe_path ||
      ctx.process_exe_path ||
      proc?.exe_path ||
      null;

    const pid =
      ctx.pid ??
      ctx.event?.ProcessStart?.identity?.pid ??
      proc?.pid ??
      parsePidFromInstanceId(procId);

    const commandLine =
      ctx.command_line ||
      ctx.event?.ProcessStart?.command_line ||
      proc?.command_line ||
      null;

    const sha256 = ctx.sha256 || proc?.sha256 || null;
    const signerSubject = ctx.signer_subject || proc?.signer_subject || null;
    const rootThumbprint = ctx.root_thumbprint || null;

    const parentExePath = ctx.parent_exe_path || parentProc?.exe_path || null;
    const parentCommandLine =
      ctx.parent_command_line || parentProc?.command_line || null;

    const originUrl = ctx.origin_url || proc?.origin_url || null;
    const motwSource = typeof ctx.motw_source === "string" ? ctx.motw_source : null;
    const motwReferrer = typeof ctx.motw_referrer === "string" ? ctx.motw_referrer : null;
    const motwFrameUrl = typeof ctx.motw_frame_url === "string" ? ctx.motw_frame_url : null;
    const motwZoneId =
      Number.isInteger(ctx.motw_zone_id) && ctx.motw_zone_id >= 0
        ? ctx.motw_zone_id
        : null;
    const downloadOrigins = matchDownloadOriginsForProcess(
      { exe_path: exePath, sha256, origin_url: originUrl },
      state.snapshot.download_origins,
    );

    const dnsQueries = [
      ...(Array.isArray(ctx.recent_dns) ? ctx.recent_dns : []),
      ...(state.snapshot.dns_queries || []).filter(
        (q) => procId && q.process_instance_id === procId,
      ),
    ];

    const networkEvents = [
      ...(Array.isArray(ctx.recent_network) ? ctx.recent_network : []),
      ...(state.snapshot.network_events || []).filter(
        (n) => procId && n.process_instance_id === procId,
      ),
    ];

    return {
      isBrowserAlert,
      browserEventType,
      browserUrl,
      browserDetails,
      browserDetailsTruncated,
      isNetworkAlert,
      dstIp,
      dstPort,
      protocol,
      domainHint,
      riskClass,
      wfpBlocked,
      wfpFilterId,
      attribution,
      candidatePids,
      candidateInstanceIds,
      isNrd,
      isHomograph,
      isFirstSeenDomain,
      matchedBrand,
      matchedRuleId,
      targetPath,
      category,
      accessMask,
      isWriteOrDelete,
      includeChildren,
      exePath,
      pid,
      processInstanceId: procId,
      commandLine,
      sha256,
      signerSubject,
      rootThumbprint,
      parentExePath,
      parentCommandLine,
      originUrl,
      motwSource,
      motwReferrer,
      motwFrameUrl,
      motwZoneId,
      downloadOrigins,
      dnsQueries,
      networkEvents,
    };
  }

  function renderSeverityPill(severity) {
    const label = String(severity || "MEDIUM").toUpperCase();
    const cls =
      label === "CRITICAL"
        ? "sev-critical"
        : label === "HIGH"
          ? "sev-high"
          : label === "LOW"
            ? "sev-low"
            : "sev-medium";
    return `<span class="sev-pill ${cls}">${escapeHtml(label)}</span>`;
  }

  function getAlertSuspensionState(alert) {
    const ctx = safeJsonParse(alert?.context_json) || {};
    const suspendedChildren = Array.isArray(ctx.suspended_children)
      ? ctx.suspended_children
      : [];
    const shutdownResumedIds = Array.isArray(ctx.shutdown_resumed_identities)
      ? ctx.shutdown_resumed_identities.filter((id) => typeof id === "string")
      : [];
    const shutdownGoneIds = Array.isArray(ctx.shutdown_gone_identities)
      ? ctx.shutdown_gone_identities.filter((id) => typeof id === "string")
      : [];
    const shutdownResumedAtMs =
      typeof ctx.shutdown_resumed_at_ms === "number"
        ? ctx.shutdown_resumed_at_ms
        : null;
    const shutdownClearedAtMs =
      typeof ctx.shutdown_cleared_at_ms === "number"
        ? ctx.shutdown_cleared_at_ms
        : null;
    const parentSuspended = Boolean(alert?.process_suspended);
    const parentId =
      typeof alert?.process_instance_id === "string" &&
      alert.process_instance_id.length > 0
        ? alert.process_instance_id
        : null;

    let parentShutdownOutcome = null;
    if (!parentSuspended) {
      if (parentId && shutdownGoneIds.includes(parentId)) {
        parentShutdownOutcome = "gone";
      } else if (parentId && shutdownResumedIds.includes(parentId)) {
        parentShutdownOutcome = "resumed";
      } else if (
        shutdownGoneIds.length === 0 &&
        shutdownResumedIds.length === 0
      ) {
        if (shutdownClearedAtMs !== null && shutdownResumedAtMs === null) {
          parentShutdownOutcome = "gone";
        } else if (
          shutdownResumedAtMs !== null &&
          shutdownClearedAtMs === null
        ) {
          parentShutdownOutcome = "resumed";
        }
      }
    }

    const remainingChildren = suspendedChildren.length;
    const stillFrozen = parentSuspended || remainingChildren > 0;
    return {
      parentSuspended,
      parentShutdownOutcome,
      remainingChildren,
      stillFrozen,
      shutdownResumedAtMs,
      shutdownClearedAtMs,
    };
  }

  function renderAlertStatePills(alert) {
    if (alert.status === "ExpiredSuspended") {
      const susp = getAlertSuspensionState(alert);
      if (susp.stillFrozen && susp.parentSuspended) {
        return `<span class="state-pill state-expired">EXPIRED_SUSPENDED (60s)</span>`;
      }
      if (susp.stillFrozen) {
        return `<span class="state-pill state-expired">EXPIRED_SUSPENDED (${susp.remainingChildren} CHILD FROZEN)</span>`;
      }
      if (susp.shutdownClearedAtMs !== null) {
        return `<span class="state-pill state-pending">EXPIRED (CLEARED)</span>`;
      }
      if (susp.shutdownResumedAtMs !== null) {
        return `<span class="state-pill state-pending">EXPIRED (RESUMED)</span>`;
      }
      return `<span class="state-pill state-pending">EXPIRED (60s)</span>`;
    }
    if (alert.status === "Pending") {
      const susp = getAlertSuspensionState(alert);
      if (susp.stillFrozen) {
        return `<span class="state-pill state-frozen">FROZEN</span>`;
      }
      return `<span class="state-pill state-pending">PENDING</span>`;
    }
    if (alert.status === "TerminatedBlocked") {
      return `<span class="state-pill state-terminated">TERMINATED_BLOCKED</span>`;
    }
    if (alert.status === "ApprovedOnce") {
      return `<span class="state-pill state-approved">APPROVED_ONCE</span>`;
    }
    if (alert.status === "ApprovedRule") {
      return `<span class="state-pill state-approved">APPROVED_RULE</span>`;
    }
    return `<span class="state-pill state-dismissed">${escapeHtml(alert.status)}</span>`;
  }

  function syncAlertSelection(visibleAlerts) {
    if (state.launchFocusAlertId) {
      const focused = state.alerts.find(
        (a) => a.alert_id === state.launchFocusAlertId,
      );
      if (focused) {
        if (!isUnresolvedAlert(focused) && state.alertQueueFilter === "unresolved") {
          state.alertQueueFilter = "all";
        }
        state.selectedAlertId = focused.alert_id;
        return;
      }
    }

    if (
      state.selectedAlertId &&
      visibleAlerts.some((a) => a.alert_id === state.selectedAlertId)
    ) {
      return;
    }

    state.selectedAlertId = visibleAlerts.length > 0 ? visibleAlerts[0].alert_id : null;
  }

  function renderTriageView() {
    const { byId } = buildHierarchy(state.snapshot);
    const allAlerts = Array.isArray(state.alerts) ? state.alerts : [];
    const unresolvedAlerts = allAlerts.filter(isUnresolvedAlert);

    el.triageUnresolvedBadge.textContent = String(unresolvedAlerts.length);
    el.triageUnresolvedBadge.classList.toggle("is-urgent", unresolvedAlerts.length > 0);
    el.filterUnresolvedCount.textContent = String(unresolvedAlerts.length);
    el.filterAllCount.textContent = String(allAlerts.length);
    el.alertQueueSummary.textContent = `${unresolvedAlerts.length} unresolved`;

    el.filterUnresolvedBtn.classList.toggle(
      "is-selected",
      state.alertQueueFilter === "unresolved",
    );
    el.filterUnresolvedBtn.setAttribute(
      "aria-pressed",
      state.alertQueueFilter === "unresolved" ? "true" : "false",
    );
    el.filterAllBtn.classList.toggle("is-selected", state.alertQueueFilter === "all");
    el.filterAllBtn.setAttribute(
      "aria-pressed",
      state.alertQueueFilter === "all" ? "true" : "false",
    );

    // If a focused alert exists in allAlerts but is resolved, expand queue filter automatically.
    if (state.launchFocusAlertId) {
      const focused = allAlerts.find((a) => a.alert_id === state.launchFocusAlertId);
      if (focused && !isUnresolvedAlert(focused) && state.alertQueueFilter === "unresolved") {
        state.alertQueueFilter = "all";
        el.filterUnresolvedBtn.classList.remove("is-selected");
        el.filterUnresolvedBtn.setAttribute("aria-pressed", "false");
        el.filterAllBtn.classList.add("is-selected");
        el.filterAllBtn.setAttribute("aria-pressed", "true");
      }
    }

    const baseList =
      state.alertQueueFilter === "unresolved" ? unresolvedAlerts : allAlerts;
    const query = state.alertFilterText.trim().toLowerCase();
    const visibleAlerts = query
      ? baseList.filter((a) => {
          const d = extractAlertDetails(a, byId);
          return [
            a.alert_id,
            a.rule_id,
            a.title,
            d.targetPath || "",
            d.exePath || "",
            d.category || "",
            d.browserUrl || "",
            d.browserEventType || "",
            d.browserDetails || "",
            d.originUrl || "",
            d.motwReferrer || "",
          ].some((v) => String(v).toLowerCase().includes(query));
        })
      : baseList;

    syncAlertSelection(visibleAlerts);

    if (visibleAlerts.length === 0) {
      el.alertQueue.innerHTML = `<div class="inspector-empty pad-md">${
        query
          ? "No alerts match filter"
          : state.alertQueueFilter === "unresolved"
            ? "No unresolved alerts"
            : "No alerts recorded"
      }</div>`;
    } else {
      const itemsHtml = visibleAlerts
        .map((alert) => {
          const d = extractAlertDetails(alert, byId);
          const isSelected = state.selectedAlertId === alert.alert_id;
          const targetSummary = d.targetPath || d.exePath || alert.alert_id;
          return `
            <li>
              <button
                type="button"
                class="queue-item ${isSelected ? "is-selected" : ""}"
                data-alert-id="${escapeHtml(alert.alert_id)}"
                aria-current="${isSelected ? "true" : "false"}"
              >
                <div class="queue-item-top">
                  ${renderSeverityPill(alert.severity)}
                  ${renderAlertStatePills(alert)}
                  <span class="queue-rule">${escapeHtml(alert.rule_id)}</span>
                </div>
                <div class="queue-title">${escapeHtml(alert.title)}</div>
                <div class="queue-meta">
                  <span class="queue-target" title="${escapeHtml(targetSummary)}">${escapeHtml(
                    targetSummary,
                  )}</span>
                  <span class="queue-time">${escapeHtml(formatTime(alert.timestamp_ms))}</span>
                </div>
              </button>
            </li>
          `;
        })
        .join("");
      el.alertQueue.innerHTML = `<ul class="queue-list">${itemsHtml}</ul>`;
    }

    const selected =
      allAlerts.find((a) => a.alert_id === state.selectedAlertId) || null;
    if (!selected) {
      state.selectedAlertIsNetwork = false;
      // Keep lastSyncedAlertId so temporary empty filter results preserve in-progress form edits
      // when returning to the same alert; only clear transient validation feedback.
      state.triageValidationFeedback = null;
      el.triageDetail.classList.add("hidden");
      el.triageEmpty.classList.remove("hidden");

      if (state.alertQueueFilter === "unresolved" && allAlerts.length > 0) {
        el.triageEmptyLabel.textContent = "No unresolved alerts";
      } else {
        el.triageEmptyLabel.textContent = state.isDaemonOnline
          ? "No alerts recorded"
          : "Daemon offline — no alerts loaded";
      }

      if (state.triageFeedback && state.triageFeedback.message) {
        el.triageEmptyFeedback.textContent = state.triageFeedback.message;
        el.triageEmptyFeedback.className = `triage-feedback ${
          state.triageFeedback.ok ? "is-ok" : "is-error"
        }`;
        el.triageEmptyFeedback.setAttribute("role", state.triageFeedback.ok ? "status" : "alert");
        el.triageEmptyFeedback.classList.remove("hidden");
      } else {
        el.triageEmptyFeedback.classList.add("hidden");
      }

      el.triageShowAllBtn.classList.toggle(
        "hidden",
        !(state.alertQueueFilter === "unresolved" && allAlerts.length > 0),
      );
      el.triageSampleBtn.classList.toggle(
        "hidden",
        state.isDaemonOnline || state.isSamplePreview,
      );
      return;
    }

    el.triageEmptyFeedback.classList.add("hidden");
    el.triageEmpty.classList.add("hidden");
    el.triageDetail.classList.remove("hidden");

    const details = extractAlertDetails(selected, byId);
    renderSuspendBanner(selected, details);
    renderDetectionCard(selected, details);
    renderLineageCard(selected, details, byId);
    renderMotwCard(details);
    renderNetworkDnsCard(details);
    syncResolutionControls(selected, details);
  }

  function networkActionBadgeClass(actionUpper) {
    if (
      actionUpper === "BLOCK" ||
      actionUpper === "BLOCKED" ||
      actionUpper === "SUSPENDED_BLOCKED"
    ) {
      return "badge-action-block";
    }
    if (actionUpper === "ALLOW" || actionUpper === "ALLOWED") {
      return "badge-action-allow";
    }
    if (actionUpper === "SUSPENDED" || actionUpper === "ALERTED") {
      return "badge-nrd";
    }
    return "badge-action-log";
  }

  function renderSuspendBanner(alert, details) {
    let bannerClass = "suspend-banner";
    let headline = alert.title;
    let subline = "";

    if (alert.status === "ExpiredSuspended") {
      const susp = getAlertSuspensionState(alert);
      if (susp.stillFrozen) {
        bannerClass += " is-expired";
        if (!susp.parentSuspended && susp.remainingChildren > 0) {
          if (susp.parentShutdownOutcome === "gone") {
            subline = `60s timeout elapsed — parent already exited or PID reused before daemon shutdown, ${susp.remainingChildren} child process(es) still frozen`;
          } else if (susp.parentShutdownOutcome === "resumed") {
            subline = `60s timeout elapsed — parent resumed on daemon shutdown, ${susp.remainingChildren} child process(es) still frozen`;
          } else {
            subline = `60s timeout elapsed — parent not currently suspended, ${susp.remainingChildren} child process(es) still frozen`;
          }
        } else {
          subline = details.wfpBlocked
            ? "60s timeout elapsed — process frozen and dynamic WFP block retained"
            : details.includeChildren
              ? "60s timeout elapsed — process tree remains frozen without data loss"
              : "60s timeout elapsed — process remains frozen without data loss";
        }
      } else if (
        susp.shutdownResumedAtMs !== null &&
        susp.shutdownClearedAtMs !== null
      ) {
        const clearedTs = Math.max(
          susp.shutdownResumedAtMs,
          susp.shutdownClearedAtMs,
        );
        subline = `60s timeout elapsed — suspension cleared on daemon shutdown at ${formatTime(clearedTs)} (active target resumed; others already exited or PID reused; awaiting triage)`;
      } else if (susp.shutdownClearedAtMs !== null) {
        subline = `60s timeout elapsed — suspended process already exited or PID reused before daemon shutdown at ${formatTime(susp.shutdownClearedAtMs)} (awaiting triage)`;
      } else if (susp.shutdownResumedAtMs !== null) {
        subline = `60s timeout elapsed — process resumed on daemon shutdown at ${formatTime(susp.shutdownResumedAtMs)} (awaiting triage)`;
      } else {
        subline = "60s timeout elapsed — process not currently suspended (awaiting triage)";
      }
    } else if (alert.status === "Pending") {
      const susp = getAlertSuspensionState(alert);
      if (susp.stillFrozen) {
        bannerClass += " is-frozen";
        if (!susp.parentSuspended && susp.remainingChildren > 0) {
          if (susp.parentShutdownOutcome === "gone") {
            subline = `Parent already exited or PID reused before daemon shutdown; ${susp.remainingChildren} child process(es) still frozen — awaiting decision`;
          } else if (susp.parentShutdownOutcome === "resumed") {
            subline = `Parent resumed on daemon shutdown; ${susp.remainingChildren} child process(es) still frozen — awaiting decision`;
          } else {
            subline = `${susp.remainingChildren} child process(es) still frozen (NtSuspendProcess) — awaiting decision`;
          }
        } else {
          subline = details.wfpBlocked
            ? "Process frozen + dynamic WFP outbound block active — awaiting decision"
            : details.includeChildren
              ? "Process tree frozen (NtSuspendProcess) — awaiting decision"
              : "Process frozen (NtSuspendProcess) — awaiting decision";
        }
      } else {
        subline =
          details.isBrowserAlert && !details.processInstanceId
            ? "Browser shield event — no local process attached"
            : details.attribution === "app_level_ambiguous"
              ? "Dynamic WFP block active (multi-instance PID ambiguous — no process suspended)"
              : details.wfpBlocked
                ? "Dynamic WFP outbound block active — awaiting decision"
                : "Active alert — process not suspended";
      }
    } else if (alert.status === "TerminatedBlocked") {
      bannerClass += " is-terminated";
      subline = alert.resolved_at_ms
        ? `Terminated at ${formatTime(alert.resolved_at_ms)}`
        : "Terminated";
    } else {
      bannerClass += " is-resolved";
      subline = alert.resolved_at_ms
        ? `Resolved at ${formatTime(alert.resolved_at_ms)}`
        : "Resolved";
    }

    el.triageSuspendBanner.className = bannerClass;
    el.triageSuspendBanner.innerHTML = `
      <div class="suspend-main">
        ${renderSeverityPill(alert.severity)}
        ${renderAlertStatePills(alert)}
        <div>
          <div class="suspend-headline">${escapeHtml(headline)}</div>
          <div class="suspend-sub">${escapeHtml(subline)}</div>
        </div>
      </div>
      <div class="suspend-meta">
        <span>${escapeHtml(alert.source_layer)}</span>
        <span>|</span>
        <span>${escapeHtml(alert.alert_id)}</span>
        <span>|</span>
        <span>${escapeHtml(formatTime(alert.timestamp_ms))}</span>
      </div>
    `;
  }

  function renderDetectionCard(alert, details) {
    if (details.isNetworkAlert) {
      const endpoint = details.dstIp
        ? `${details.dstIp}${details.dstPort !== null ? `:${details.dstPort}` : ""}`
        : "-";
      const protoBadge =
        details.protocol !== null && details.protocol !== undefined
          ? `<span class="badge badge-metric">${escapeHtml(formatProtocol(details.protocol))}</span>`
          : "";
      const riskBadges = [];
      if (details.isNrd) riskBadges.push(`<span class="badge badge-nrd">NRD</span>`);
      if (details.isFirstSeenDomain) {
        riskBadges.push(`<span class="badge badge-unsigned">First-Seen</span>`);
      }
      if (details.isHomograph) {
        riskBadges.push(
          `<span class="badge badge-nrd">Homograph${
            details.matchedBrand ? `: ${escapeHtml(details.matchedBrand)}` : ""
          }</span>`,
        );
      }
      const wfpBadge = details.wfpBlocked
        ? `<span class="badge badge-action-block">WFP Blocked${
            details.wfpFilterId !== null ? ` (#${escapeHtml(details.wfpFilterId)})` : ""
          }</span>`
        : `<span class="badge badge-orphan">WFP Inactive</span>`;
      const riskClassBadge = details.riskClass
        ? `<span class="badge badge-metric">${escapeHtml(details.riskClass)}</span>`
        : "";
      const attributionBadge =
        details.attribution === "app_level_ambiguous"
          ? `<span class="badge badge-unsigned" title="Multiple concurrent instances matched WFP executable path; no individual PID was suspended">App-Level (Ambiguous PID)</span>`
          : "";

      el.triageDetectionDl.innerHTML = `
        <dt>Destination</dt>
        <dd class="mono-wrap">${protoBadge} ${escapeHtml(endpoint)}</dd>
        <dt>Domain / Risk</dt>
        <dd class="mono-wrap">${escapeHtml(details.domainHint || "-")} ${riskBadges.join(" ")}</dd>
        <dt>Containment</dt>
        <dd>${wfpBadge} ${riskClassBadge} ${attributionBadge}</dd>
        <dt>Rule ID</dt>
        <dd class="mono-wrap">${escapeHtml(alert.rule_id)}${
          details.matchedRuleId
            ? ` (policy: ${escapeHtml(details.matchedRuleId)})`
            : ""
        }</dd>
      `;
      return;
    }

    if (details.isBrowserAlert) {
      const eventBadge = `<span class="badge badge-browser">${escapeHtml(
        details.browserEventType || details.category || "BrowserEvent",
      )}</span>`;
      const truncBadge = details.browserDetailsTruncated
        ? ` <span class="badge badge-unsigned">Truncated</span>`
        : "";
      el.triageDetectionDl.innerHTML = `
        <dt>Event Type</dt>
        <dd>${eventBadge}</dd>
        <dt>Target URL</dt>
        <dd class="mono-wrap">${escapeHtml(details.browserUrl || details.targetPath || "-")}</dd>
        <dt>Details</dt>
        <dd class="mono-wrap">${escapeHtml(details.browserDetails || "-")}${truncBadge}</dd>
        <dt>Rule ID</dt>
        <dd class="mono-wrap">${escapeHtml(alert.rule_id)}</dd>
      `;
      return;
    }

    const opBadge =
      details.isWriteOrDelete === true
        ? `<span class="badge badge-nrd">Write / Delete</span>`
        : details.isWriteOrDelete === false
          ? `<span class="badge badge-unsigned">Read / Open</span>`
          : `<span class="badge badge-orphan">Observed</span>`;
    const treeBadge = details.includeChildren
      ? `<span class="badge badge-nrd">Tree Containment</span>`
      : "";

    el.triageDetectionDl.innerHTML = `
      <dt>Target Path</dt>
      <dd class="mono-wrap">${escapeHtml(details.targetPath || "-")}</dd>
      <dt>Category</dt>
      <dd><span class="badge badge-metric">${escapeHtml(details.category || "-")}</span> ${treeBadge}</dd>
      <dt>Access Mask</dt>
      <dd class="mono">${escapeHtml(formatAccessMask(details.accessMask))} ${opBadge}</dd>
      <dt>Rule ID</dt>
      <dd class="mono-wrap">${escapeHtml(alert.rule_id)}</dd>
    `;
  }

  function renderLineageCard(alert, details, byId) {
    if (details.isBrowserAlert && !details.processInstanceId) {
      el.inspectInView2Btn.classList.add("hidden");
      el.inspectInView2Btn.dataset.procId = "";
      el.triageLineageDl.innerHTML = `
        <dt>Source Layer</dt>
        <dd><span class="badge badge-browser">${escapeHtml(alert.source_layer)}</span></dd>
        <dt>Process</dt>
        <dd class="mono-wrap">None (browser extension event)</dd>
        <dt>Origin URL</dt>
        <dd class="mono-wrap">${escapeHtml(details.browserUrl || "-")}</dd>
      `;
      return;
    }

    const hasProcInTree = Boolean(
      details.processInstanceId && byId.has(details.processInstanceId),
    );
    el.inspectInView2Btn.classList.toggle("hidden", !hasProcInTree);
    el.inspectInView2Btn.dataset.procId = details.processInstanceId || "";

    const signerHtml = details.signerSubject
      ? `<span class="badge badge-signed">${escapeHtml(details.signerSubject)}</span>${
          details.rootThumbprint
            ? ` <span class="mono-wrap">(${escapeHtml(details.rootThumbprint)})</span>`
            : ""
        }`
      : `<span class="badge badge-unsigned">Unsigned</span>`;

    const pidInstanceLabel =
      details.attribution === "app_level_ambiguous"
        ? `Ambiguous (candidates: ${
            details.candidatePids.length > 0 ? details.candidatePids.join(", ") : "none"
          }) | app-level`
        : `${
            details.pid !== null && details.pid !== undefined ? String(details.pid) : "-"
          } | ${details.processInstanceId || "-"}`;

    el.triageLineageDl.innerHTML = `
      <dt>Executable</dt>
      <dd class="mono-wrap">${escapeHtml(details.exePath || "-")}</dd>
      <dt>PID / Instance</dt>
      <dd class="mono-wrap">${escapeHtml(pidInstanceLabel)}</dd>
      <dt>Signer</dt>
      <dd>${signerHtml}</dd>
      <dt>SHA-256</dt>
      <dd class="mono-wrap">${escapeHtml(details.sha256 || "-")}</dd>
      <dt>Command Line</dt>
      <dd class="mono-wrap">${escapeHtml(details.commandLine || "-")}</dd>
      <dt>Parent Exe</dt>
      <dd class="mono-wrap">${escapeHtml(details.parentExePath || "-")}</dd>
      <dt>Parent Cmd</dt>
      <dd class="mono-wrap">${escapeHtml(details.parentCommandLine || "-")}</dd>
    `;
  }

  function renderMotwCard(details) {
    const origins = details.downloadOrigins || [];
    const sourceLabel = formatMotwSourceLabel(details.motwSource);
    const zoneLabel = formatMotwZoneLabel(details.motwZoneId);
    const hasSummary = Boolean(
      sourceLabel ||
        zoneLabel ||
        details.originUrl ||
        details.motwReferrer ||
        details.motwFrameUrl,
    );

    if (!hasSummary && origins.length === 0) {
      el.triageMotwBody.innerHTML = `<span class="panel-meta">None recorded</span>`;
      return;
    }

    const items = [];
    if (hasSummary) {
      const summaryRows = [];
      if (sourceLabel) {
        summaryRows.push(
          `<dt>Source</dt><dd><span class="badge badge-motw">${escapeHtml(sourceLabel)}</span></dd>`,
        );
      }
      if (zoneLabel) {
        summaryRows.push(
          `<dt>Zone</dt><dd><span class="badge badge-metric">${escapeHtml(zoneLabel)}</span></dd>`,
        );
      }
      if (details.originUrl) {
        summaryRows.push(
          `<dt>Origin URL</dt><dd class="mono-wrap">${escapeHtml(details.originUrl)}</dd>`,
        );
      }
      if (details.motwReferrer) {
        summaryRows.push(
          `<dt>Referrer</dt><dd class="mono-wrap">${escapeHtml(details.motwReferrer)}</dd>`,
        );
      }
      if (details.motwFrameUrl) {
        summaryRows.push(
          `<dt>Frame URL</dt><dd class="mono-wrap">${escapeHtml(details.motwFrameUrl)}</dd>`,
        );
      }
      items.push(`<dl class="kv-list">${summaryRows.join("")}</dl>`);
    }

    for (const d of origins) {
      const dlRows = [];
      const showTabUrl =
        d.tab_url && (origins.length > 1 || d.tab_url !== details.originUrl);
      const showReferrer =
        d.referrer_url &&
        (origins.length > 1 || d.referrer_url !== details.motwReferrer);
      const showFrameUrl =
        d.frame_url && (origins.length > 1 || d.frame_url !== details.motwFrameUrl);

      if (showTabUrl) {
        dlRows.push(`<dt>Tab URL</dt><dd class="mono-wrap">${escapeHtml(d.tab_url)}</dd>`);
      }
      if (showReferrer) {
        dlRows.push(
          `<dt>Referrer</dt><dd class="mono-wrap">${escapeHtml(d.referrer_url)}</dd>`,
        );
      }
      if (showFrameUrl) {
        dlRows.push(
          `<dt>Frame URL</dt><dd class="mono-wrap">${escapeHtml(d.frame_url)}</dd>`,
        );
      }
      if (d.file_path) {
        dlRows.push(
          `<dt>File Path</dt><dd class="mono-wrap">${escapeHtml(d.file_path)}</dd>`,
        );
      }
      const shortSha = formatShortSha256(d.sha256);
      if (shortSha) {
        dlRows.push(
          `<dt>SHA-256</dt><dd class="mono-wrap" title="${escapeHtml(d.sha256)}">${escapeHtml(shortSha)}</dd>`,
        );
      }
      dlRows.push(
        `<dt>Downloaded</dt><dd class="mono">${escapeHtml(formatTime(d.downloaded_at_ms))}</dd>`,
      );
      items.push(`<dl class="kv-list">${dlRows.join("")}</dl>`);
    }
    el.triageMotwBody.innerHTML = items.join("");
  }

  function renderNetworkDnsCard(details) {
    const dns = details.dnsQueries || [];
    const net = details.networkEvents || [];
    if (dns.length === 0 && net.length === 0) {
      el.triageNetBody.innerHTML = `<span class="panel-meta">No network/DNS activity recorded</span>`;
      return;
    }

    const rows = [];
    for (const q of dns.slice(0, 8)) {
      const ips = (q.resolved_ips || []).join(", ") || "Pending";
      rows.push(`
        <li class="mini-event-row">
          <span class="badge ${q.is_nrd ? "badge-nrd" : "badge-signed"}">${
            q.is_nrd ? "NRD" : "DNS"
          }</span>
          <span class="mono-wrap">${escapeHtml(q.query_name)}</span>
          <span class="panel-meta">${escapeHtml(ips)}</span>
        </li>
      `);
    }
    for (const n of net.slice(0, 8)) {
      const actionUpper = String(n.action || "LOG").toUpperCase();
      const actionClass = networkActionBadgeClass(actionUpper);
      rows.push(`
        <li class="mini-event-row">
          <span class="badge badge-metric">${escapeHtml(formatProtocol(n.protocol))}</span>
          <span class="mono-wrap">${escapeHtml(n.dst_ip)}:${escapeHtml(n.dst_port)}</span>
          ${
            n.domain_hint
              ? `<span class="panel-meta mono-wrap">(${escapeHtml(n.domain_hint)})</span>`
              : ""
          }
          <span class="badge ${actionClass}">${escapeHtml(actionUpper)}</span>
        </li>
      `);
    }

    el.triageNetBody.innerHTML = `<ul class="mini-events-list">${rows.join("")}</ul>`;
  }

  function syncTriageTargetScopeNote(isNetworkAlert) {
    if (!isNetworkAlert) {
      el.targetScopeNote.textContent = "";
      el.targetScopeNote.className = "tier-constraint hidden";
      return;
    }
    const domainEntered = isNetworkDomainTarget("NetworkAllow", el.optAllowDest.value);
    el.targetScopeNote.textContent =
      "Accepts literal IP, CIDR (e.g. 198.51.100.0/24), or domain/wildcard (WFP enforces matched IPs; Deny wins).";
    el.targetScopeNote.className = domainEntered
      ? "tier-constraint is-warn"
      : "tier-constraint";
    el.targetScopeNote.classList.remove("hidden");
  }

  function setAlertTriageFeedback(alertId, ok, message) {
    const feedback = { ok: Boolean(ok), message, alertId };
    state.triageFeedback = feedback;
    if (
      state.triageValidationFeedback &&
      (alertId === null ||
        alertId === undefined ||
        state.triageValidationFeedback.alertId === alertId)
    ) {
      state.triageValidationFeedback = null;
    }
    if (alertId !== null && alertId !== undefined) {
      state.triageFeedbackByAlert.delete(alertId);
      state.triageFeedbackByAlert.set(alertId, feedback);
      while (state.triageFeedbackByAlert.size > MAX_TRIAGE_FEEDBACK_ENTRIES) {
        const oldestKey = state.triageFeedbackByAlert.keys().next().value;
        state.triageFeedbackByAlert.delete(oldestKey);
      }
    }
  }

  function setTransientTriageFeedback(alertId, message) {
    state.triageValidationFeedback = { ok: false, message, alertId };
  }

  function clearAlertTriageFeedback(alertId) {
    if (alertId !== null && alertId !== undefined) {
      state.triageFeedbackByAlert.delete(alertId);
    }
    if (state.triageFeedback && state.triageFeedback.alertId === alertId) {
      state.triageFeedback = null;
    }
    if (
      state.triageValidationFeedback &&
      state.triageValidationFeedback.alertId === alertId
    ) {
      state.triageValidationFeedback = null;
    }
  }

  function resolvePersistedDetailTriageFeedback(alertId) {
    const perAlert =
      state.triageFeedbackByAlert.get(alertId) ||
      (state.triageFeedback && state.triageFeedback.alertId === alertId
        ? state.triageFeedback
        : null);
    const globalFeedback =
      state.triageFeedback &&
      (state.triageFeedback.alertId === null || state.triageFeedback.alertId === undefined)
        ? state.triageFeedback
        : null;
    if (perAlert && !perAlert.ok) {
      return perAlert;
    }
    return globalFeedback || perAlert;
  }

  function resolveDetailTriageFeedback(alertId) {
    if (
      state.triageValidationFeedback &&
      state.triageValidationFeedback.alertId === alertId
    ) {
      return state.triageValidationFeedback;
    }
    return resolvePersistedDetailTriageFeedback(alertId);
  }

  function renderDetailTriageFeedback(alertId) {
    const detailFeedback = resolveDetailTriageFeedback(alertId);
    if (detailFeedback && detailFeedback.message) {
      el.triageActionStatus.textContent = detailFeedback.message;
      el.triageActionStatus.className = `triage-feedback ${
        detailFeedback.ok ? "is-ok" : "is-error"
      }`;
      el.triageActionStatus.setAttribute("role", detailFeedback.ok ? "status" : "alert");
      el.triageActionStatus.classList.remove("hidden");
    } else {
      el.triageActionStatus.classList.add("hidden");
    }
  }

  function syncResolutionControls(alert, details) {
    const unresolved = isUnresolvedAlert(alert);
    const hasSigner = Boolean(details.signerSubject);
    const policy = getBrowserAlertResolutionPolicy(alert, details);
    state.selectedAlertIsNetwork = Boolean(details.isNetworkAlert);

    if (state.lastSyncedAlertId !== alert.alert_id) {
      state.lastSyncedAlertId = alert.alert_id;
      state.triageValidationFeedback = null;
      if (
        state.triageFeedback &&
        state.triageFeedback.alertId !== null &&
        state.triageFeedback.alertId !== undefined &&
        state.triageFeedback.alertId !== alert.alert_id
      ) {
        state.triageFeedback = null;
      }
      el.optAddBlockRule.checked = !policy.addBlockRuleDisabled;
      el.optUseSigner.checked = !policy.allowPermanentDisabled && hasSigner;
      el.optAllowDest.value = "";
    }
    if (
      !unresolved &&
      state.triageValidationFeedback &&
      state.triageValidationFeedback.alertId === alert.alert_id
    ) {
      state.triageValidationFeedback = null;
    }

    el.btnAllowOnce.textContent = policy.allowOnceLabel;
    if (el.allowOnceConstraintNote) {
      el.allowOnceConstraintNote.textContent = policy.allowOnceConstraint;
    }
    if (el.terminateConstraintNote) {
      el.terminateConstraintNote.textContent = policy.terminateConstraint;
    }

    if (policy.isProcesslessBrowser) {
      el.optAddBlockRule.checked = false;
      el.optAddBlockRule.disabled = true;
      el.btnTerminateBlock.disabled = true;
      el.optUseSigner.checked = false;
      el.optUseSigner.disabled = true;
      el.optAllowDest.disabled = true;
      el.btnAllowPermanent.disabled = true;
      el.signerConstraintNote.textContent = policy.allowPermanentConstraint;
      el.targetScopeNote.classList.add("hidden");
      el.btnAllowOnce.disabled = !unresolved || state.isResolvingAlert;
      renderDetailTriageFeedback(alert.alert_id);
      return;
    }

    el.optUseSigner.disabled = !unresolved || !hasSigner || state.isResolvingAlert;
    if (!hasSigner) {
      el.optUseSigner.checked = false;
      el.signerConstraintNote.textContent = "Unsigned binary: SHA-256 required";
    } else if (!details.rootThumbprint) {
      el.signerConstraintNote.textContent =
        "Root thumbprint verified on save (fallback: SHA-256)";
    } else {
      el.signerConstraintNote.textContent = "";
    }

    el.optAddBlockRule.disabled = !unresolved || state.isResolvingAlert;
    el.optAllowDest.disabled = !unresolved || state.isResolvingAlert;
    el.optAllowDest.placeholder = details.isNetworkAlert
      ? "e.g. 93.184.216.34, 198.51.100.0/24, or *.example.com"
      : "e.g. C:\\Users\\*\\Cookies";
    el.optAllowDest.title = details.isNetworkAlert
      ? "Literal IP, CIDR prefix, or domain/wildcard (WFP enforces matched IPs; shared CDN IPs inherit rule; Deny wins)"
      : "Optional file path pattern (e.g. C:\\Users\\*\\Cookies)";
    syncTriageTargetScopeNote(details.isNetworkAlert);
    el.btnTerminateBlock.disabled = !unresolved || state.isResolvingAlert;
    el.btnAllowOnce.disabled = !unresolved || state.isResolvingAlert;
    el.btnAllowPermanent.disabled = !unresolved || state.isResolvingAlert;

    renderDetailTriageFeedback(alert.alert_id);
  }

  async function handleResolveAlert(kind) {
    const alert = state.alerts.find((a) => a.alert_id === state.selectedAlertId);
    if (!alert || !isUnresolvedAlert(alert) || state.isResolvingAlert) {
      return;
    }
    const details = extractAlertDetails(alert, buildHierarchy(state.snapshot).byId);
    const policy = getBrowserAlertResolutionPolicy(alert, details);
    if (policy.isProcesslessBrowser && kind !== "allow_once") {
      return;
    }

    let decision;
    let previewStatus;
    const addBlockRule = Boolean(el.optAddBlockRule.checked);
    if (kind === "terminate") {
      decision = {
        TerminateAndBlock: {
          add_block_rule: addBlockRule,
        },
      };
      previewStatus = "TerminatedBlocked";
    } else if (kind === "allow_once") {
      decision = "AllowOnce";
      previewStatus = "ApprovedOnce";
    } else {
      const allowDestRaw = el.optAllowDest.value.trim();
      if (details.isNetworkAlert && allowDestRaw.includes("/") && !isLiteralIpOrCidr(allowDestRaw)) {
        setTransientTriageFeedback(
          alert.alert_id,
          "CIDR target must be valid IPv4/prefix (0..32) or IPv6/prefix (0..128).",
        );
        renderTriageView();
        return;
      }
      decision = {
        AllowPermanent: {
          use_signer_if_available:
            !el.optUseSigner.disabled && Boolean(el.optUseSigner.checked),
          allow_dest: allowDestRaw.length > 0 ? allowDestRaw : null,
        },
      };
      previewStatus = "ApprovedRule";
    }

    if (state.isSamplePreview) {
      alert.status = previewStatus;
      alert.process_suspended = false;
      alert.resolved_at_ms = Date.now();
      const previewMessage =
        kind === "terminate"
          ? `Preview: ${alert.alert_id} → ${previewStatus} — process tree terminated; ${
              addBlockRule
                ? "NetworkBlock rule saved & WFP dynamic block active"
                : "no NetworkBlock rule saved"
            }`
          : `Preview: ${alert.alert_id} → ${previewStatus}${
              policy.isProcesslessBrowser ? " (acknowledged)" : ""
            }`;
      setAlertTriageFeedback(alert.alert_id, true, previewMessage);
      renderTriageView();
      return;
    }

    const invoke = getInvoke();
    if (!invoke) {
      setTransientTriageFeedback(
        alert.alert_id,
        "Tauri IPC bridge unavailable outside Tauri runtime.",
      );
      renderTriageView();
      return;
    }

    state.isResolvingAlert = true;
    clearAlertTriageFeedback(alert.alert_id);
    renderTriageView();

    try {
      const ackMessage = await invoke("resolve_alert_action", {
        alertId: alert.alert_id,
        decision,
      });
      // The daemon's Ack message already reports whether the requested rule was
      // actually saved; do not re-derive it from the checkbox state (ANALYSIS_0001).
      setAlertTriageFeedback(alert.alert_id, true, ackMessage);
      await refreshAll();
    } catch (err) {
      setAlertTriageFeedback(alert.alert_id, false, formatBackendError(err));
      await refreshAll();
    } finally {
      state.isResolvingAlert = false;
      renderTriageView();
    }
  }

  function matchesFilter(proc, query) {
    if (!query) return true;
    const fields = [
      proc.exe_path,
      String(proc.pid),
      String(proc.ppid),
      proc.command_line || "",
      proc.signer_subject || "",
      proc.process_instance_id,
      proc.origin_url || "",
    ];
    return fields.some((f) => f.toLowerCase().includes(query));
  }

  function filterNodes(nodes, query) {
    if (!query) return nodes;
    const kept = [];
    for (const node of nodes) {
      const filteredChildren = filterNodes(node.children, query);
      if (matchesFilter(node.process, query) || filteredChildren.length > 0) {
        kept.push({ ...node, children: filteredChildren });
      }
    }
    return kept;
  }

  function resolveEffectiveProcessScope(byId) {
    return state.selectedProcessId && byId && byId.has(state.selectedProcessId)
      ? state.selectedProcessId
      : null;
  }

  function renderTree() {
    const { roots, byId } = buildHierarchy(state.snapshot);
    const effectiveScopeId = resolveEffectiveProcessScope(byId);
    const query = state.filterText.trim().toLowerCase();
    const visibleRoots = filterNodes(roots, query);

    el.treeSummary.textContent = `${state.snapshot.processes.length} processes`;
    el.allProcsBtn.classList.toggle("is-selected", effectiveScopeId === null);

    if (visibleRoots.length === 0) {
      el.processTree.innerHTML = `<div class="inspector-empty pad-md">No processes match current snapshot/filter.</div>`;
      renderInspector(byId);
      renderTelemetry(byId);
      return;
    }

    function renderNodeHtml(node) {
      const p = node.process;
      const id = p.process_instance_id;
      const hasChildren = node.children.length > 0;
      const isCollapsed = !query && state.collapsedIds.has(id);
      const isSelected = effectiveScopeId === id;

      const badges = [];
      if (p.is_trusted_os) {
        badges.push(`<span class="badge badge-trusted">Trusted OS</span>`);
      } else if (p.signer_subject) {
        badges.push(`<span class="badge badge-signed">${escapeHtml(p.signer_subject)}</span>`);
      } else {
        badges.push(`<span class="badge badge-unsigned">Unsigned</span>`);
      }

      if (node.is_orphan_root) {
        badges.push(`<span class="badge badge-orphan">Orphan</span>`);
      }
      if (p.exited_at_ms !== null && p.exited_at_ms !== undefined) {
        badges.push(`<span class="badge badge-exited">Exited</span>`);
      }
      if (node.dns_count > 0) {
        badges.push(`<span class="badge badge-metric">DNS ${node.dns_count}</span>`);
      }
      if (node.network_count > 0) {
        badges.push(`<span class="badge badge-metric">NET ${node.network_count}</span>`);
      }
      if (node.canary_count > 0) {
        badges.push(`<span class="badge badge-nrd">CANARY ${node.canary_count}</span>`);
      }
      const hasMotw =
        Boolean(p.origin_url) ||
        matchDownloadOriginsForProcess(p, state.snapshot.download_origins).length > 0;
      if (hasMotw) {
        badges.push(`<span class="badge badge-motw">MOTW</span>`);
      }

      const subline = p.command_line || p.exe_path;
      const toggleChar = hasChildren ? (isCollapsed ? "▶" : "▼") : "•";
      const childrenHtml =
        hasChildren && !isCollapsed
          ? `<ul class="tree-children">${node.children.map(renderNodeHtml).join("")}</ul>`
          : "";

      return `
        <li>
          <div class="tree-row ${isSelected ? "is-selected" : ""}" data-proc-id="${escapeHtml(id)}" role="treeitem" aria-selected="${isSelected ? "true" : "false"}">
            <button type="button" class="tree-toggle ${hasChildren ? "" : "is-leaf"}" data-toggle-id="${escapeHtml(id)}" aria-label="Toggle children">${toggleChar}</button>
            <div class="tree-main">
              <div class="tree-title-line">
                <span class="proc-name">${escapeHtml(baseName(p.exe_path))}</span>
                <span class="proc-ids">PID ${p.pid} / PPID ${p.ppid}</span>
                ${badges.join("")}
              </div>
              <div class="tree-subline" title="${escapeHtml(subline)}">${escapeHtml(subline)}</div>
            </div>
          </div>
          ${childrenHtml}
        </li>
      `;
    }

    el.processTree.innerHTML = `<ul class="tree-list">${visibleRoots.map(renderNodeHtml).join("")}</ul>`;
    renderInspector(byId);
    renderTelemetry(byId);
  }

  function renderInspector(byId) {
    const effectiveScopeId = resolveEffectiveProcessScope(byId);
    if (!effectiveScopeId) {
      const dnsCount = (state.snapshot.dns_queries || []).length;
      const netCount = (state.snapshot.network_events || []).length;
      const canaryCount = (state.snapshot.file_canary_events || []).length;
      const downloadCount = (state.snapshot.download_origins || []).length;
      el.processInspector.innerHTML = `
        <div class="inspector-grid">
          <div class="inspector-item">
            <div class="inspector-label">Selection</div>
            <div class="inspector-val">All Processes (${state.snapshot.processes.length})</div>
          </div>
          <div class="inspector-item">
            <div class="inspector-label">Captured Events</div>
            <div class="inspector-val">DNS ${dnsCount} | Network ${netCount} | Canary ${canaryCount} | Downloads ${downloadCount}</div>
          </div>
        </div>
      `;
      el.scopeIndicator.textContent = "Scope: All Processes";
      return;
    }

    const p = byId.get(effectiveScopeId);
    const signer = p.is_trusted_os
      ? `${p.signer_subject || "Windows"} (Trusted OS)`
      : p.signer_subject || "Unsigned";
    const matchedDownloads = matchDownloadOriginsForProcess(
      p,
      state.snapshot.download_origins,
    );
    const primaryDl = selectPrimaryDownloadOrigin(p, matchedDownloads);
    const procOrigin =
      typeof p.origin_url === "string" ? p.origin_url.trim() : "";
    const effectiveOrigin = procOrigin || primaryDl?.tab_url || null;
    const effectiveReferrer = primaryDl?.referrer_url || null;
    const effectiveFrameUrl = primaryDl?.frame_url || null;
    const effectiveSha = p.sha256 || primaryDl?.sha256 || null;
    const shortSha = formatShortSha256(effectiveSha);

    el.scopeIndicator.textContent = `Scope: ${baseName(p.exe_path)} (${p.process_instance_id})`;
    el.processInspector.innerHTML = `
      <div class="inspector-grid">
        <div class="inspector-item">
          <div class="inspector-label">Executable</div>
          <div class="inspector-val">${escapeHtml(p.exe_path)}</div>
        </div>
        <div class="inspector-item">
          <div class="inspector-label">Identity / Lineage</div>
          <div class="inspector-val">${escapeHtml(p.process_instance_id)} (PPID ${p.ppid})</div>
        </div>
        <div class="inspector-item">
          <div class="inspector-label">Trust / Signer</div>
          <div class="inspector-val">${escapeHtml(signer)}</div>
        </div>
        <div class="inspector-item">
          <div class="inspector-label">Lifecycle</div>
          <div class="inspector-val">${escapeHtml(formatTime(p.created_at_ms))} → ${escapeHtml(p.exited_at_ms ? formatTime(p.exited_at_ms) : "Running")}</div>
        </div>
        <div class="inspector-item span-full">
          <div class="inspector-label">Command Line</div>
          <div class="inspector-val">${escapeHtml(p.command_line || "-")}</div>
        </div>
        ${
          shortSha
            ? `<div class="inspector-item">
                 <div class="inspector-label">SHA-256</div>
                 <div class="inspector-val" title="${escapeHtml(effectiveSha)}">${escapeHtml(shortSha)}</div>
               </div>`
            : ""
        }
        ${
          effectiveOrigin
            ? `<div class="inspector-item span-full">
                 <div class="inspector-label">Origin URL (MOTW)</div>
                 <div class="inspector-val">${escapeHtml(effectiveOrigin)}</div>
               </div>`
            : ""
        }
        ${
          effectiveReferrer
            ? `<div class="inspector-item span-full">
                 <div class="inspector-label">Referrer URL</div>
                 <div class="inspector-val">${escapeHtml(effectiveReferrer)}</div>
               </div>`
            : ""
        }
        ${
          effectiveFrameUrl
            ? `<div class="inspector-item span-full">
                 <div class="inspector-label">Frame URL</div>
                 <div class="inspector-val">${escapeHtml(effectiveFrameUrl)}</div>
               </div>`
            : ""
        }
      </div>
    `;
  }

  function renderTelemetry(byId) {
    const scopeId = resolveEffectiveProcessScope(byId);
    const filterProc = (item) => !scopeId || item.process_instance_id === scopeId;

    const dns = (state.snapshot.dns_queries || []).filter(filterProc);
    const net = (state.snapshot.network_events || []).filter(filterProc);
    const canary = (state.snapshot.file_canary_events || []).filter(filterProc);
    const scopedProc = scopeId ? byId.get(scopeId) || null : null;
    const downloads = scopeId
      ? matchDownloadOriginsForProcess(scopedProc, state.snapshot.download_origins)
      : state.snapshot.download_origins || [];

    el.countDns.textContent = String(dns.length);
    el.countNetwork.textContent = String(net.length);
    el.countCanary.textContent = String(canary.length + downloads.length);
    el.countAll.textContent = String(dns.length + net.length + canary.length + downloads.length);

    const rows = [];

    if (state.activeTab === "all" || state.activeTab === "dns") {
      for (const q of dns) {
        const proc = byId.get(q.process_instance_id);
        const procLabel = proc ? `${baseName(proc.exe_path)} (${proc.pid})` : q.process_instance_id;
        const ips = (q.resolved_ips || []).join(", ") || "NXDOMAIN / Pending";
        const badge = q.is_nrd
          ? `<span class="badge badge-nrd">NRD</span>`
          : `<span class="badge badge-signed">DNS</span>`;
        rows.push({
          ts: q.timestamp_ms,
          html: `
            <tr>
              <td class="mono">${escapeHtml(formatTime(q.timestamp_ms))}</td>
              <td><span class="badge badge-signed">DNS</span></td>
              <td class="mono">${escapeHtml(procLabel)}</td>
              <td class="mono">${escapeHtml(q.query_name)}</td>
              <td class="mono">${escapeHtml(ips)} (type ${q.query_type})</td>
              <td>${badge}</td>
            </tr>
          `,
        });
      }
    }

    if (state.activeTab === "all" || state.activeTab === "network") {
      for (const n of net) {
        const proc = byId.get(n.process_instance_id);
        const procLabel = proc ? `${baseName(proc.exe_path)} (${proc.pid})` : n.process_instance_id;
        const actionUpper = String(n.action || "LOG").toUpperCase();
        const actionClass = networkActionBadgeClass(actionUpper);
        rows.push({
          ts: n.timestamp_ms,
          html: `
            <tr>
              <td class="mono">${escapeHtml(formatTime(n.timestamp_ms))}</td>
              <td><span class="badge badge-metric">${escapeHtml(formatProtocol(n.protocol))}</span></td>
              <td class="mono">${escapeHtml(procLabel)}</td>
              <td class="mono">${escapeHtml(n.dst_ip)}:${n.dst_port}</td>
              <td class="mono">${escapeHtml(n.domain_hint || "-")}</td>
              <td><span class="badge ${actionClass}">${escapeHtml(actionUpper)}</span></td>
            </tr>
          `,
        });
      }
    }

    if (state.activeTab === "all" || state.activeTab === "canary") {
      for (const c of canary) {
        const proc = byId.get(c.process_instance_id);
        const procLabel = proc ? `${baseName(proc.exe_path)} (${proc.pid})` : c.process_instance_id;
        rows.push({
          ts: c.timestamp_ms,
          html: `
            <tr>
              <td class="mono">${escapeHtml(formatTime(c.timestamp_ms))}</td>
              <td><span class="badge badge-nrd">CANARY</span></td>
              <td class="mono">${escapeHtml(procLabel)}</td>
              <td class="mono">${escapeHtml(c.target_path)}</td>
              <td class="mono">${escapeHtml(c.category)} (mask ${escapeHtml(formatAccessMask(c.access_mask))})</td>
              <td><span class="badge badge-nrd">${escapeHtml(c.action_taken)}</span></td>
            </tr>
          `,
        });
      }
      for (const d of downloads) {
        const shortSha = formatShortSha256(d.sha256);
        const detailParts = [escapeHtml(d.tab_url)];
        if (d.referrer_url) {
          detailParts.push(`ref: ${escapeHtml(d.referrer_url)}`);
        }
        if (shortSha) {
          detailParts.push(
            `<span title="${escapeHtml(d.sha256)}">sha256: ${escapeHtml(shortSha)}</span>`,
          );
        }
        rows.push({
          ts: d.downloaded_at_ms,
          html: `
            <tr>
              <td class="mono">${escapeHtml(formatTime(d.downloaded_at_ms))}</td>
              <td><span class="badge badge-motw">MOTW</span></td>
              <td class="mono">Browser Download</td>
              <td class="mono">${escapeHtml(d.file_path)}</td>
              <td class="mono">${detailParts.join(" | ")}</td>
              <td><span class="badge badge-orphan">ORIGIN</span></td>
            </tr>
          `,
        });
      }
    }

    rows.sort((a, b) => b.ts - a.ts);

    if (rows.length === 0) {
      el.telemetryBody.innerHTML = `<tr><td colspan="6" class="empty-row">No telemetry recorded for this scope.</td></tr>`;
      return;
    }

    el.telemetryBody.innerHTML = rows.map((r) => r.html).join("");
  }

  function showOfflineBanner(message) {
    el.statusBanner.classList.remove("hidden", "is-sample");
    el.bannerTitle.textContent = "Daemon Offline";
    el.bannerDetail.textContent = message;
  }

  function showSampleBanner() {
    el.statusBanner.classList.remove("hidden");
    el.statusBanner.classList.add("is-sample");
    el.bannerTitle.textContent = "SAMPLE PREVIEW — DAEMON OFFLINE";
    el.bannerDetail.textContent =
      "Synthetic triage alerts and flight recorder data loaded.";
  }

  function hideBanner() {
    el.statusBanner.classList.add("hidden");
    el.statusBanner.classList.remove("is-sample");
  }

  function updateDaemonHeader(connectedLabel, metrics) {
    if (connectedLabel) {
      el.daemonStatusPill.textContent = connectedLabel;
      el.daemonStatusPill.className = "pill pill-ok";
    } else {
      el.daemonStatusPill.textContent = "Daemon: Offline";
      el.daemonStatusPill.className = "pill pill-danger";
    }

    if (metrics) {
      el.metricsPill.textContent = `Procs: ${metrics.active_processes} | Alerts: ${metrics.pending_alerts} | Drops: ${metrics.telemetry_dropped}`;
    } else {
      el.metricsPill.textContent = "Procs: - | Alerts: - | Drops: -";
    }
  }

  function scopeBadgeHtml(scope) {
    if (scope === "NetworkBlock") {
      return `<span class="badge badge-action-block">NetworkBlock</span>`;
    }
    if (scope === "NetworkAllow") {
      return `<span class="badge badge-action-allow">NetworkAllow</span>`;
    }
    if (scope === "FileCanaryAllow") {
      return `<span class="badge badge-signed">FileCanaryAllow</span>`;
    }
    if (scope === "ProcessAllow") {
      return `<span class="badge badge-metric">ProcessAllow</span>`;
    }
    return `<span class="badge badge-orphan">${escapeHtml(scope)}</span>`;
  }

  function renderPolicyView() {
    const allRules = Array.isArray(state.rules) ? state.rules : [];
    const blockCount = allRules.filter((r) => r.scope === "NetworkBlock").length;
    const allowCount = allRules.filter((r) => r.scope === "NetworkAllow").length;
    const canaryCount = allRules.filter((r) => r.scope === "FileCanaryAllow").length;
    const processCount = allRules.filter((r) => r.scope === "ProcessAllow").length;

    el.policyRulesSummary.textContent = `${allRules.length} rules`;
    el.scopeCountAll.textContent = String(allRules.length);
    el.scopeCountBlock.textContent = String(blockCount);
    el.scopeCountAllow.textContent = String(allowCount);
    el.scopeCountCanary.textContent = String(canaryCount);
    el.scopeCountProcess.textContent = String(processCount);

    for (const btn of el.policyScopeBtns) {
      const selected = btn.dataset.scope === state.policyScopeFilter;
      btn.classList.toggle("is-selected", selected);
      btn.setAttribute("aria-pressed", selected ? "true" : "false");
    }

    if (state.policyFeedback && state.policyFeedback.message) {
      el.policyFeedback.textContent = state.policyFeedback.message;
      el.policyFeedback.className = `triage-feedback policy-feedback ${
        state.policyFeedback.ok ? "is-ok" : "is-error"
      }`;
      el.policyFeedback.setAttribute("role", state.policyFeedback.ok ? "status" : "alert");
      el.policyFeedback.classList.remove("hidden");
    } else {
      el.policyFeedback.classList.add("hidden");
    }

    const query = state.policyFilterText.trim().toLowerCase();
    const visibleRules = allRules.filter((rule) => {
      if (state.policyScopeFilter !== "all" && rule.scope !== state.policyScopeFilter) {
        return false;
      }
      if (!query) return true;
      return [
        rule.rule_id,
        rule.scope,
        rule.exe_path_pattern,
        rule.allowed_target || "",
        rule.sha256 || "",
        rule.signer_subject || "",
        rule.created_by || "",
      ].some((v) => String(v).toLowerCase().includes(query));
    });

    if (visibleRules.length === 0) {
      el.policyRulesBody.innerHTML = `<tr><td colspan="6" class="empty-row">${
        query
          ? "No rules match filter."
          : state.isDaemonOnline || state.isSamplePreview
            ? "No policy rules in this scope."
            : "Daemon offline — no rules loaded."
      }</td></tr>`;
    } else {
      el.policyRulesBody.innerHTML = visibleRules
        .map((rule) => {
          const identityParts = [];
          if (rule.signer_subject) {
            identityParts.push(
              `<span class="badge badge-signed">${escapeHtml(rule.signer_subject)}</span>`,
            );
          }
          if (rule.sha256) {
            const shortSha =
              rule.sha256.length > 16 ? `${rule.sha256.slice(0, 16)}…` : rule.sha256;
            identityParts.push(
              `<span class="mono" title="${escapeHtml(rule.sha256)}">sha256:${escapeHtml(shortSha)}</span>`,
            );
          }
          if (identityParts.length === 0) {
            identityParts.push(`<span class="panel-meta">Path only</span>`);
          }
          const targetText = rule.allowed_target || "All targets";
          const domainIpBadge = isNetworkDomainTarget(rule.scope, rule.allowed_target)
            ? `<span class="badge badge-domain-ip" title="WFP enforces resolved IPs; shared CDN/proxy IPs are also affected (deny overrides allow)">IP-resolved</span>`
            : "";
          return `
            <tr>
              <td>${scopeBadgeHtml(rule.scope)}</td>
              <td class="mono-wrap" title="${escapeHtml(rule.rule_id)}">${escapeHtml(
                rule.exe_path_pattern,
              )}</td>
              <td>
                <div class="policy-target-cell">
                  <span class="mono-wrap">${escapeHtml(targetText)}</span>
                  ${domainIpBadge}
                </div>
              </td>
              <td>${identityParts.join(" ")}</td>
              <td class="mono">${escapeHtml(formatTime(rule.created_at_ms))}</td>
              <td>
                <button
                  type="button"
                  class="btn btn-danger-xs"
                  data-delete-rule-id="${escapeHtml(rule.rule_id)}"
                  ${state.isMutatingRule ? "disabled" : ""}
                >Delete</button>
              </td>
            </tr>
          `;
        })
        .join("");
    }

    el.submitAddRuleBtn.disabled = state.isMutatingRule;

    // Right column 1: Canary & Honeypot Status
    const localStatus = state.localDefenseStatus;
    const honeypots = localStatus?.honeypots || [];
    const deployedCount = honeypots.filter((h) => h.deployed).length;
    el.honeypotSummary.textContent = `${deployedCount}/${honeypots.length || 3} deployed`;

    if (honeypots.length === 0) {
      el.honeypotStatusList.innerHTML = `<div class="panel-meta">Local honeypot probe unavailable outside Tauri runtime.</div>`;
    } else {
      el.honeypotStatusList.innerHTML = honeypots
        .map((h) => {
          const badge = h.deployed
            ? `<span class="badge badge-action-allow">Deployed (${escapeHtml(
                h.size_bytes ?? 0,
              )} B)</span>`
            : `<span class="badge badge-unsigned">Not Deployed</span>`;
          return `
            <div class="status-item">
              <div class="status-item-top">
                <span class="status-item-title">${escapeHtml(h.folder)}</span>
                ${badge}
              </div>
              <div class="status-item-path">${escapeHtml(h.path)}</div>
            </div>
          `;
        })
        .join("");
    }

    const templates = localStatus?.protected_paths || [];
    if (templates.length === 0) {
      el.protectedPathsList.innerHTML = `<div class="panel-meta">No templates loaded.</div>`;
    } else {
      el.protectedPathsList.innerHTML = templates
        .map(
          (t) => `
            <div class="status-item">
              <div class="status-item-top">
                <span class="status-item-title">${escapeHtml(t.label)}</span>
                <span class="badge badge-metric">${escapeHtml(t.category)}</span>
              </div>
              <div class="status-item-path">${escapeHtml(t.path_template)}</div>
            </div>
          `,
        )
        .join("");
    }

    // Right column 2: Browser Shield & Domain Risk Check
    const shield = localStatus?.browser_shield || null;
    const shieldStats = computeBrowserShieldStats(state.alerts, state.snapshot);
    const statusPill = (ok, yesText, noText) =>
      ok
        ? `<span class="badge badge-action-allow">${escapeHtml(yesText)}</span>`
        : `<span class="badge badge-unsigned">${escapeHtml(noText)}</span>`;

    const nativeHostHtml = (() => {
      if (!shield) return `<span class="panel-meta">Unknown</span>`;
      if (!shield.native_host_registered) {
        return statusPill(false, "Registered", "Not Registered");
      }
      const scopeLabel = shield.native_host_scope || "HKCU";
      const browserBadges = (shield.registered_browsers || [])
        .map((b) => `<span class="badge badge-metric">${escapeHtml(b)}</span>`)
        .join(" ");
      return `${statusPill(true, `Registered (${scopeLabel})`, "Not Registered")} ${browserBadges}`;
    })();

    const manifestHtml = (() => {
      if (!shield) return `<span class="panel-meta">Unknown</span>`;
      if (!shield.native_host_registered) {
        return `<span class="badge badge-orphan">Not Registered</span>`;
      }
      const overallStatus =
        shield.manifest_status || (shield.manifest_valid ? "valid" : "invalid");
      const badge =
        overallStatus === "valid"
          ? `<span class="badge badge-action-allow">Valid</span>`
          : overallStatus === "unverified"
            ? `<span class="badge badge-unsigned">Unverified</span>`
            : `<span class="badge badge-action-block">Invalid</span>`;
      const pathHtml = shield.manifest_path
        ? ` <span class="mono-wrap">${escapeHtml(shield.manifest_path)}</span>`
        : "";
      const errHtml =
        overallStatus !== "valid" && shield.manifest_error
          ? `<div class="mono-wrap">${escapeHtml(shield.manifest_error)}</div>`
          : "";
      const registeredDetails = (shield.browsers || []).filter(
        (b) => b.hkcu_registered || b.hklm_registered,
      );
      const detailRows =
        registeredDetails.length > 0
          ? `<div class="browser-detail-list">${registeredDetails
              .map((b) => {
                const bStatus =
                  b.manifest_status || (b.manifest_valid ? "valid" : "invalid");
                const bBadge =
                  bStatus === "valid"
                    ? `<span class="badge badge-action-allow">${escapeHtml(b.effective_scope || "")} Valid</span>`
                    : bStatus === "unverified"
                      ? `<span class="badge badge-unsigned">${escapeHtml(b.effective_scope || "")} Unverified</span>`
                      : `<span class="badge badge-action-block">${escapeHtml(b.effective_scope || "")} Invalid</span>`;
                const bPath = b.manifest_path
                  ? ` <span class="mono-wrap">${escapeHtml(b.manifest_path)}</span>`
                  : "";
                const bErr =
                  bStatus !== "valid" && b.manifest_error
                    ? ` <span class="mono-wrap">${escapeHtml(b.manifest_error)}</span>`
                    : "";
                return `<div class="browser-detail-row"><span class="badge badge-metric">${escapeHtml(
                  b.browser,
                )}</span> ${bBadge}${bPath}${bErr}</div>`;
              })
              .join("")}</div>`
          : "";
      return `${badge}${pathHtml}${errHtml}${detailRows}`;
    })();

    const uriScopeLabel = shield?.uri_scheme_scope || "HKCU";
    const expectedExtId =
      shield?.expected_extension_id || "ecelachfiiiiiibpjeomfncgpegbpanh";

    el.browserShieldDl.innerHTML = `
      <dt>Daemon IPC</dt>
      <dd>${
        state.isDaemonOnline
          ? statusPill(true, "Connected", "Offline")
          : state.isSamplePreview
            ? `<span class="badge badge-orphan">Sample Preview</span>`
            : statusPill(false, "Connected", "Offline")
      }</dd>
      <dt>Bridge Binary</dt>
      <dd>${
        shield
          ? `${statusPill(shield.bridge_binary_present, "Installed", "Not Found")} <span class="mono-wrap">${escapeHtml(
              shield.bridge_binary_path,
            )}</span>`
          : `<span class="panel-meta">Unknown</span>`
      }</dd>
      <dt>Native Messaging</dt>
      <dd>${nativeHostHtml}</dd>
      <dt>Manifest</dt>
      <dd>${manifestHtml}</dd>
      <dt>Extension ID</dt>
      <dd class="mono-wrap">${escapeHtml(expectedExtId)}</dd>
      <dt>URI Protocol</dt>
      <dd>${
        shield
          ? statusPill(
              shield.uri_scheme_registered,
              `ledr:// (${uriScopeLabel})`,
              "Not Registered",
            )
          : `<span class="panel-meta">Unknown</span>`
      }</dd>
      <dt>Browser Alerts</dt>
      <dd class="mono">${shieldStats.browserAlertsTotal} (${shieldStats.browserAlertsUnresolved} unresolved)</dd>
      <dt>Tracked Downloads</dt>
      <dd class="mono">${shieldStats.trackedDownloadsCount}</dd>
    `;

    el.domainCheckBtn.disabled = state.isCheckingDomain;
    if (state.domainRiskError) {
      el.domainCheckResult.innerHTML = `<span class="badge badge-action-block">Error</span> <span class="mono-wrap">${escapeHtml(
        state.domainRiskError,
      )}</span>`;
      el.domainCheckResult.classList.remove("hidden");
    } else if (state.domainRiskResult) {
      const r = state.domainRiskResult;
      const badges = [];
      badges.push(
        r.is_nrd
          ? `<span class="badge badge-nrd">NRD (&lt;=14d)</span>`
          : `<span class="badge badge-action-allow">Not in NRD</span>`,
      );
      badges.push(
        r.is_homograph
          ? `<span class="badge badge-action-block">Homograph${
              r.matched_brand ? `: ${escapeHtml(r.matched_brand)}` : ""
            }</span>`
          : `<span class="badge badge-action-allow">No Homograph</span>`,
      );
      el.domainCheckResult.innerHTML = `
        <div class="mono-wrap">${escapeHtml(r.domain)}</div>
        <div class="domain-check-badges">${badges.join("")}</div>
      `;
      el.domainCheckResult.classList.remove("hidden");
    } else {
      el.domainCheckResult.classList.add("hidden");
    }

    renderAppUpdatePanel();
  }

  const EXPECTED_CHROME_EXT_ID_FALLBACK = "ecelachfiiiiiibpjeomfncgpegbpanh";

  function parseDaemonVersionFromPing(pingResult) {
    if (!pingResult) return null;
    if (typeof pingResult === "object") {
      const raw = pingResult.daemon_version;
      return typeof raw === "string" && raw.trim() ? raw.trim() : null;
    }
    if (typeof pingResult === "string") {
      const m = pingResult.match(/ledr-daemon\s+v([^\s()]+)/i);
      if (m && m[1]) return m[1].trim();
    }
    return null;
  }

  function normalizeUpdaterPhase(raw) {
    if (!raw || typeof raw !== "string") return "idle";
    const s = raw.trim();
    const map = {
      Idle: "idle",
      Checking: "checking",
      UpToDate: "up_to_date",
      UpdateAvailable: "update_available",
      ManualUpdateRequired: "manual_update_required",
      Downloading: "downloading",
      Verifying: "verifying",
      LaunchingUpdater: "launching_updater",
      Error: "error",
    };
    return map[s] || s.toLowerCase();
  }

  function normalizeVersionTag(v) {
    if (typeof v !== "string") return "";
    return v.trim().replace(/^v/i, "");
  }

  function formatBytes(bytes) {
    if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes < 0) return "0 B";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  }

  function formatInstallKindLabel(kind) {
    if (kind === "standard_installed") return "標準インストール";
    if (kind === "portable_or_dev") return "Portable / Dev";
    return "不明";
  }

  function updaterTargetVersion(status) {
    return status?.manifest?.version || status?.latest_version || null;
  }

  function applyUpdaterStatusPayload(status) {
    if (!status || typeof status !== "object") return;
    const prevTarget = updaterTargetVersion(state.updaterStatus);
    const nextTarget = updaterTargetVersion(status);
    if (nextTarget && nextTarget !== prevTarget && nextTarget !== state.updateBannerDismissedVersion) {
      state.updateBannerDismissedVersion = null;
    }
    state.updaterStatus = status;
    const phase = normalizeUpdaterPhase(status.phase);
    state.isCheckingUpdate = phase === "checking";
    state.isApplyingUpdate =
      phase === "downloading" || phase === "verifying" || phase === "launching_updater";
    if (status.error_message) {
      state.updaterActionFeedback = { ok: false, message: status.error_message };
    } else if (status.notice_message) {
      state.updaterActionFeedback = { ok: true, message: status.notice_message };
    }
    renderUpdateBanner();
    renderAppUpdatePanel();
  }

  function renderUpdateBanner() {
    if (!el.updateBanner) return;
    const status = state.updaterStatus;
    if (!status) {
      el.updateBanner.classList.add("hidden");
      el.updateBanner.classList.remove("is-manual");
      return;
    }

    const phase = normalizeUpdaterPhase(status.phase);
    const targetVersion = updaterTargetVersion(status);
    const isBannerPhase = phase === "update_available" || phase === "manual_update_required";
    if (
      !isBannerPhase ||
      (targetVersion && state.updateBannerDismissedVersion === targetVersion)
    ) {
      el.updateBanner.classList.add("hidden");
      el.updateBanner.classList.remove("is-manual");
      return;
    }

    const appVer = normalizeVersionTag(status.app_version || "") || "-";
    const latestVer = normalizeVersionTag(targetVersion || "") || "-";
    const notesUrl = status.release_notes_url || status.manifest?.release_notes_url || null;
    const canAutoApply =
      phase === "update_available" &&
      status.install_kind === "standard_installed" &&
      status.can_auto_apply !== false;

    el.updateBanner.classList.remove("hidden");
    el.updateBanner.classList.toggle("is-manual", phase === "manual_update_required");

    if (phase === "manual_update_required") {
      const minVer = normalizeVersionTag(status.min_updater_version || "") || "-";
      el.updateBannerTitle.textContent = `手動更新が必要: v${latestVer}`;
      el.updateBannerDetail.textContent = `現在 v${appVer} / 最小対応 v${minVer}`;
    } else if (canAutoApply) {
      el.updateBannerTitle.textContent = `更新あり: v${latestVer}`;
      el.updateBannerDetail.textContent = `現在 v${appVer}（UAC 昇格後、アプリを終了して更新を適用）`;
    } else {
      el.updateBannerTitle.textContent = `更新あり: v${latestVer}（手動更新）`;
      el.updateBannerDetail.textContent = `Portable / Dev は自動適用不可（現在 v${appVer}）`;
    }

    el.updateBannerApplyBtn?.classList.toggle("hidden", !canAutoApply);
    if (el.updateBannerApplyBtn) {
      el.updateBannerApplyBtn.disabled = state.isApplyingUpdate;
    }
    el.updateBannerNotesBtn?.classList.toggle("hidden", !notesUrl);
  }

  function renderAppUpdatePanel() {
    if (!el.appUpdateDl) return;
    const invoke = getInvoke();
    const status = state.updaterStatus;
    const phase = status ? normalizeUpdaterPhase(status.phase) : "idle";
    const isBusy =
      state.isCheckingUpdate ||
      state.isApplyingUpdate ||
      phase === "checking" ||
      phase === "downloading" ||
      phase === "verifying" ||
      phase === "launching_updater";

    const uiVersionRaw = status?.app_version || null;
    const uiVer = uiVersionRaw ? normalizeVersionTag(uiVersionRaw) : null;
    const daemonVer = state.isDaemonOnline && state.daemonVersion
      ? normalizeVersionTag(state.daemonVersion)
      : null;

    if (el.updateVersionMismatch) {
      if (state.isDaemonOnline && uiVer && daemonVer && uiVer !== daemonVer) {
        el.updateVersionMismatch.textContent =
          `バージョン不一致: UI v${uiVer} / Daemon v${daemonVer}（サービス再起動または再インストールが必要）`;
        el.updateVersionMismatch.classList.remove("hidden");
      } else {
        el.updateVersionMismatch.textContent = "";
        el.updateVersionMismatch.classList.add("hidden");
      }
    }

    if (el.updateStateBadge) {
      const badgeMap = {
        idle: { text: "未確認", cls: "badge badge-metric" },
        checking: { text: "確認中", cls: "badge badge-metric" },
        up_to_date: { text: "最新", cls: "badge badge-action-allow" },
        update_available: { text: "更新あり", cls: "badge badge-nrd" },
        manual_update_required: { text: "手動更新必須", cls: "badge badge-action-block" },
        downloading: { text: "ダウンロード中", cls: "badge badge-metric" },
        verifying: { text: "検証中", cls: "badge badge-metric" },
        launching_updater: { text: "インストーラー起動中", cls: "badge badge-metric" },
        error: { text: "エラー", cls: "badge badge-action-block" },
      };
      const badgeInfo = badgeMap[phase] || badgeMap.idle;
      el.updateStateBadge.textContent = badgeInfo.text;
      el.updateStateBadge.className = badgeInfo.cls;
    }

    if (el.updateFeedback) {
      const feedbackMsg =
        status?.error_message ||
        status?.notice_message ||
        state.updaterActionFeedback?.message ||
        null;
      const isOk = !status?.error_message && (state.updaterActionFeedback ? state.updaterActionFeedback.ok : true);
      if (feedbackMsg) {
        el.updateFeedback.textContent = feedbackMsg;
        el.updateFeedback.className = `triage-feedback ${isOk ? "is-ok" : "is-error"}`;
        el.updateFeedback.classList.remove("hidden", "is-ok", "is-error");
        el.updateFeedback.classList.add(isOk ? "is-ok" : "is-error");
      } else {
        el.updateFeedback.textContent = "";
        el.updateFeedback.className = "triage-feedback hidden";
        el.updateFeedback.classList.remove("is-ok", "is-error");
        el.updateFeedback.classList.add("hidden");
      }
    }

    if (el.updateProgressWrap && el.updateProgressBar && el.updateProgressText) {
      if (phase === "downloading") {
        const downloaded = Number(status?.bytes_downloaded || 0);
        const total = status?.total_bytes;
        el.updateProgressWrap.classList.remove("hidden");
        if (typeof total === "number" && total > 0) {
          const pct = Math.min(100, Math.max(0, Math.round((downloaded / total) * 100)));
          el.updateProgressBar.setAttribute("value", String(pct));
          el.updateProgressBar.value = pct;
          el.updateProgressText.textContent = `${pct}% (${formatBytes(downloaded)} / ${formatBytes(total)})`;
        } else {
          el.updateProgressBar.removeAttribute("value");
          el.updateProgressText.textContent = formatBytes(downloaded);
        }
      } else {
        el.updateProgressWrap.classList.add("hidden");
      }
    }

    if (el.updateCheckBtn) {
      el.updateCheckBtn.disabled = !invoke || isBusy;
    }

    const canAutoApply =
      phase === "update_available" &&
      status?.install_kind === "standard_installed" &&
      status?.can_auto_apply !== false;
    if (el.updateApplyBtn) {
      el.updateApplyBtn.classList.toggle("hidden", !canAutoApply);
      el.updateApplyBtn.disabled = !invoke || isBusy || !canAutoApply;
    }
    if (el.updateCancelBtn) {
      el.updateCancelBtn.classList.toggle("hidden", phase !== "downloading");
      el.updateCancelBtn.disabled = !invoke || phase !== "downloading";
    }
    const notesUrl = status?.release_notes_url || status?.manifest?.release_notes_url || null;
    if (el.updateReleaseNotesBtn) {
      const showNotes = Boolean(notesUrl) && (phase === "update_available" || phase === "manual_update_required");
      el.updateReleaseNotesBtn.classList.toggle("hidden", !showNotes);
      el.updateReleaseNotesBtn.disabled = !invoke || !showNotes;
    }

    const targetVer = updaterTargetVersion(status);
    const latestDisplay = targetVer ? `v${normalizeVersionTag(targetVer)}` : "-";
    const lastCheckedDisplay = status?.last_checked_at_ms ? formatTime(status.last_checked_at_ms) : "未確認";
    const daemonDisplay = state.isDaemonOnline
      ? (daemonVer ? `v${daemonVer}` : "接続中")
      : state.isSamplePreview
        ? "Sample Preview"
        : "未接続";

    let stateDetail = "未確認";
    if (phase === "checking") stateDetail = "リリース確認中";
    else if (phase === "up_to_date") stateDetail = `最新 (${latestDisplay})`;
    else if (phase === "update_available") {
      stateDetail = canAutoApply
        ? `v${normalizeVersionTag(targetVer || "")} 利用可能（UAC 昇格後、アプリを終了して更新を適用）`
        : `v${normalizeVersionTag(targetVer || "")} 利用可能（Portable / Dev は手動更新のみ）`;
    } else if (phase === "manual_update_required") {
      const minVer = normalizeVersionTag(status?.min_updater_version || "") || "-";
      stateDetail = `最小対応 v${minVer} 以上への手動更新が必要`;
    } else if (phase === "downloading") stateDetail = "インストーラーを取得中";
    else if (phase === "verifying") stateDetail = "署名と SHA-256 を検証中";
    else if (phase === "launching_updater") stateDetail = "昇格アップデータを起動中";
    else if (phase === "error") stateDetail = status?.error_message || "エラー";

    const expectedExtId =
      status?.manifest?.chrome_extension?.extension_id ||
      state.localDefenseStatus?.browser_shield?.expected_extension_id ||
      EXPECTED_CHROME_EXT_ID_FALLBACK;
    const extVer = status?.manifest?.chrome_extension?.version
      ? `v${normalizeVersionTag(status.manifest.chrome_extension.version)}`
      : null;
    const extDisplay = `${escapeHtml(expectedExtId)}${extVer ? ` (${escapeHtml(extVer)})` : ""} — Chrome 拡張は自動更新対象外（手動更新）`;

    el.appUpdateDl.innerHTML = `
      <dt>UI バージョン</dt>
      <dd class="mono">${uiVer ? `v${escapeHtml(uiVer)}` : "-"}</dd>
      <dt>Daemon バージョン</dt>
      <dd class="mono">${escapeHtml(daemonDisplay)}</dd>
      <dt>導入形態</dt>
      <dd>${escapeHtml(formatInstallKindLabel(status?.install_kind))}</dd>
      <dt>更新状態</dt>
      <dd>${escapeHtml(stateDetail)}</dd>
      <dt>最新バージョン</dt>
      <dd class="mono">${escapeHtml(latestDisplay)}</dd>
      <dt>最終確認</dt>
      <dd class="mono">${escapeHtml(lastCheckedDisplay)}</dd>
      <dt>Chrome 拡張</dt>
      <dd class="mono-wrap">${extDisplay}</dd>
    `;
  }

  function dismissUpdateBanner() {
    const target = updaterTargetVersion(state.updaterStatus);
    if (target) {
      state.updateBannerDismissedVersion = target;
    }
    renderUpdateBanner();
  }

  async function handleCheckForUpdates() {
    const invoke = getInvoke();
    if (!invoke || state.isCheckingUpdate || state.isApplyingUpdate) return;
    state.isCheckingUpdate = true;
    state.updaterActionFeedback = null;
    renderAppUpdatePanel();
    try {
      const view = await invoke("check_for_updates");
      if (view) {
        applyUpdaterStatusPayload(view);
      }
    } catch (err) {
      state.updaterActionFeedback = { ok: false, message: formatBackendError(err) };
      const latest = await invoke("get_updater_status").catch(() => null);
      if (latest) {
        state.updaterStatus = latest;
      }
    } finally {
      state.isCheckingUpdate = false;
      renderUpdateBanner();
      renderAppUpdatePanel();
    }
  }

  async function handleApplyUpdate() {
    const invoke = getInvoke();
    const status = state.updaterStatus;
    if (!invoke || !status) return;
    const phase = normalizeUpdaterPhase(status.phase);
    if (
      phase !== "update_available" ||
      status.install_kind !== "standard_installed" ||
      status.can_auto_apply === false ||
      state.isApplyingUpdate
    ) {
      return;
    }
    state.isApplyingUpdate = true;
    state.updaterActionFeedback = null;
    renderAppUpdatePanel();
    try {
      const view = await invoke("apply_update");
      if (view) {
        applyUpdaterStatusPayload(view);
      }
    } catch (err) {
      state.updaterActionFeedback = { ok: false, message: formatBackendError(err) };
      const latest = await invoke("get_updater_status").catch(() => null);
      if (latest) {
        state.updaterStatus = latest;
      }
    } finally {
      state.isApplyingUpdate = false;
      renderUpdateBanner();
      renderAppUpdatePanel();
    }
  }

  async function handleCancelUpdate() {
    const invoke = getInvoke();
    if (!invoke) return;
    try {
      const view = await invoke("cancel_update_download");
      if (view) {
        applyUpdaterStatusPayload(view);
      }
    } catch (err) {
      state.updaterActionFeedback = { ok: false, message: formatBackendError(err) };
      renderAppUpdatePanel();
    }
  }

  async function handleOpenReleaseNotes() {
    const invoke = getInvoke();
    const url =
      state.updaterStatus?.release_notes_url ||
      state.updaterStatus?.manifest?.release_notes_url ||
      null;
    if (!invoke || !url) return;
    try {
      await invoke("open_release_notes_url", { url });
    } catch (err) {
      state.updaterActionFeedback = { ok: false, message: formatBackendError(err) };
      renderAppUpdatePanel();
    }
  }

  function syncPolicyFormHints() {
    const scope = el.ruleScopeInput.value;
    if (scope === "NetworkBlock" || scope === "NetworkAllow") {
      el.ruleTargetInput.placeholder = "e.g. 93.184.216.34, 198.51.100.0/24, or *.example.com";
      el.ruleTargetInput.title =
        "Literal IP, CIDR prefix, or domain/wildcard (WFP enforces matched/resolved IPs; shared CDN IPs affected)";
      const domainEntered = isNetworkDomainTarget(scope, el.ruleTargetInput.value);
      el.policyScopeNote.textContent =
        "Accepts literal IP, CIDR (e.g. 198.51.100.0/24), or domain/wildcard (WFP enforces matched IPs; Deny overrides Allow).";
      el.policyScopeNote.className = domainEntered
        ? "tier-constraint is-warn"
        : "tier-constraint";
    } else if (scope === "FileCanaryAllow") {
      el.ruleTargetInput.placeholder = "e.g. C:\\Users\\*\\Documents\\*";
      el.ruleTargetInput.title = "Optional canary file path glob pattern";
      el.policyScopeNote.textContent =
        "Canary rule: file path glob pattern scoped to protected files.";
      el.policyScopeNote.className = "tier-constraint";
    } else {
      el.ruleTargetInput.placeholder = "(unused for ProcessAllow)";
      el.ruleTargetInput.title = "Leave blank for ProcessAllow rules";
      el.policyScopeNote.textContent =
        "Process rule: requires SHA-256 or Signer + Root Thumbprint (L-04).";
      el.policyScopeNote.className = "tier-constraint";
    }
  }

  function setAddRuleFormVisible(visible) {
    el.policyAddForm.classList.toggle("hidden", !visible);
    el.toggleAddRuleBtn.setAttribute("aria-expanded", visible ? "true" : "false");
    if (visible) {
      syncPolicyFormHints();
      el.ruleExeInput.focus();
    }
  }

  async function handleUpsertRule(event) {
    event.preventDefault();
    if (state.isMutatingRule) return;

    const scope = el.ruleScopeInput.value;
    const exePath = el.ruleExeInput.value.trim();
    const target = el.ruleTargetInput.value.trim();
    const sha256 = el.ruleSha256Input.value.trim();
    const signer = el.ruleSignerInput.value.trim();
    const thumbprint = el.ruleThumbprintInput.value.trim();

    if (!exePath) {
      state.policyFeedback = { ok: false, message: "Executable Path is required." };
      renderPolicyView();
      return;
    }

    if (sha256 && !/^[0-9a-fA-F]{64}$/.test(sha256)) {
      state.policyFeedback = {
        ok: false,
        message: "SHA-256 must be a 64-character hexadecimal digest.",
      };
      renderPolicyView();
      return;
    }

    if (thumbprint && /^0+$/.test(thumbprint)) {
      state.policyFeedback = {
        ok: false,
        message: "Root Thumbprint cannot be all zeros (L-04).",
      };
      renderPolicyView();
      return;
    }

    if ((signer && !thumbprint) || (!signer && thumbprint)) {
      state.policyFeedback = {
        ok: false,
        message: "Signer Subject and Root Thumbprint must be provided together (L-04).",
      };
      renderPolicyView();
      return;
    }

    const isAllowScope = scope !== "NetworkBlock";
    if (isAllowScope && !sha256 && !(signer && thumbprint)) {
      state.policyFeedback = {
        ok: false,
        message: "Allow rules require SHA-256 or Signer Subject + Root Thumbprint (L-04).",
      };
      renderPolicyView();
      return;
    }

    if (
      (scope === "NetworkBlock" || scope === "NetworkAllow") &&
      target.includes("/") &&
      !isLiteralIpOrCidr(target)
    ) {
      state.policyFeedback = {
        ok: false,
        message: "CIDR target must be valid IPv4/prefix (0..32) or IPv6/prefix (0..128).",
      };
      renderPolicyView();
      return;
    }

    const rule = {
      rule_id: `RULE-UI-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
      scope,
      exe_path_pattern: exePath,
      sha256: sha256 || null,
      signer_subject: signer || null,
      root_thumbprint: thumbprint || null,
      allowed_target: target || null,
      created_at_ms: Date.now(),
      created_by: "user_policy",
    };

    if (state.isSamplePreview) {
      state.rules = [rule, ...state.rules];
      state.policyFeedback = {
        ok: true,
        message: `Preview: saved ${rule.scope} rule (${rule.exe_path_pattern})`,
      };
      el.policyAddForm.reset();
      syncPolicyFormHints();
      setAddRuleFormVisible(false);
      renderPolicyView();
      return;
    }

    const invoke = getInvoke();
    if (!invoke) {
      state.policyFeedback = {
        ok: false,
        message: "Tauri IPC bridge unavailable outside Tauri runtime.",
      };
      renderPolicyView();
      return;
    }

    state.isMutatingRule = true;
    state.policyFeedback = null;
    renderPolicyView();
    try {
      const ack = await invoke("upsert_rule_action", { rule });
      state.policyFeedback = { ok: true, message: ack };
      el.policyAddForm.reset();
      syncPolicyFormHints();
      setAddRuleFormVisible(false);
      await refreshAll();
    } catch (err) {
      state.policyFeedback = { ok: false, message: formatBackendError(err) };
      await refreshAll();
    } finally {
      state.isMutatingRule = false;
      renderPolicyView();
    }
  }

  async function handleDeleteRule(ruleId) {
    if (!ruleId || state.isMutatingRule) return;

    if (state.isSamplePreview) {
      state.rules = state.rules.filter((r) => r.rule_id !== ruleId);
      state.policyFeedback = {
        ok: true,
        message: `Preview: deleted rule ${ruleId}`,
      };
      renderPolicyView();
      return;
    }

    const invoke = getInvoke();
    if (!invoke) {
      state.policyFeedback = {
        ok: false,
        message: "Tauri IPC bridge unavailable outside Tauri runtime.",
      };
      renderPolicyView();
      return;
    }

    state.isMutatingRule = true;
    state.policyFeedback = null;
    renderPolicyView();
    try {
      const ack = await invoke("delete_rule_action", { ruleId });
      state.policyFeedback = { ok: true, message: ack };
      await refreshAll();
    } catch (err) {
      state.policyFeedback = { ok: false, message: formatBackendError(err) };
      await refreshAll();
    } finally {
      state.isMutatingRule = false;
      renderPolicyView();
    }
  }

  async function handleCheckDomainRisk(event) {
    event.preventDefault();
    const domain = el.domainCheckInput.value.trim();
    if (!domain || state.isCheckingDomain) return;

    if (state.isSamplePreview) {
      const lower = domain.toLowerCase();
      const isNrd = lower.endsWith(".nrd-sample.invalid") || lower.includes("nrd");
      const isHomograph = lower.includes("xn--") || lower.includes("paypa1");
      state.domainRiskError = null;
      state.domainRiskResult = {
        domain,
        is_nrd: isNrd,
        is_homograph: isHomograph,
        matched_brand: isHomograph ? "paypal.com" : null,
      };
      renderPolicyView();
      return;
    }

    const invoke = getInvoke();
    if (!invoke) {
      state.domainRiskError = "Tauri IPC bridge unavailable outside Tauri runtime.";
      state.domainRiskResult = null;
      renderPolicyView();
      return;
    }

    state.isCheckingDomain = true;
    state.domainRiskError = null;
    renderPolicyView();
    try {
      state.domainRiskResult = await invoke("check_domain_risk_action", { domain });
    } catch (err) {
      state.domainRiskResult = null;
      state.domainRiskError = String(err);
    } finally {
      state.isCheckingDomain = false;
      renderPolicyView();
    }
  }

  function renderAllViews() {
    renderTriageView();
    renderTree();
    renderPolicyView();
    renderUpdateBanner();
  }

  async function refreshAll() {
    const invoke = getInvoke();
    if (!invoke) {
      state.isDaemonOnline = false;
      state.daemonVersion = null;
      updateDaemonHeader(null, null);
      showOfflineBanner("Tauri IPC bridge unavailable outside Tauri runtime.");
      renderAllViews();
      return;
    }

    el.refreshBtn.disabled = true;
    try {
      // Local defense status (honeypot metadata & HKCU readiness) works even when daemon is offline.
      const localStatusPromise = invoke("fetch_local_defense_status").catch(() => null);
      const updaterStatusPromise = invoke("get_updater_status").catch(() => null);

      const [localStatus, updaterStatus, pingSummary, snapshot, metrics, alertsRes, rulesRes] =
        await Promise.all([
          localStatusPromise,
          updaterStatusPromise,
          invoke("ping_daemon"),
          invoke("fetch_flight_recorder", {
            limit: 250,
            processInstanceId: null,
          }),
          invoke("fetch_pipeline_metrics").catch(() => null),
          invoke("fetch_alerts", {
            status: null,
            limit: 200,
          })
            .then((data) => ({ ok: true, data }))
            .catch((err) => ({ ok: false, error: String(err) })),
          invoke("fetch_rules", {
            scope: null,
          })
            .then((data) => ({ ok: true, data }))
            .catch((err) => ({ ok: false, error: String(err) })),
        ]);

      const wasSamplePreview = state.isSamplePreview;
      state.localDefenseStatus = localStatus;
      if (updaterStatus) {
        state.updaterStatus = updaterStatus;
      }
      state.daemonVersion = parseDaemonVersionFromPing(pingSummary);
      state.isDaemonOnline = true;
      state.isSamplePreview = false;
      if (wasSamplePreview) {
        state.selectedAlertId = null;
        state.lastSyncedAlertId = null;
        state.triageFeedback = null;
        state.triageFeedbackByAlert.clear();
        state.triageValidationFeedback = null;
        state.alerts = [];
        state.rules = [];
        state.policyFeedback = null;
      }
      state.snapshot = snapshot;
      if (
        state.selectedProcessId &&
        Array.isArray(snapshot?.processes) &&
        !snapshot.processes.some((p) => p.process_instance_id === state.selectedProcessId)
      ) {
        state.selectedProcessId = null;
      }
      state.metrics = metrics;
      if (alertsRes.ok) {
        state.alerts = Array.isArray(alertsRes.data) ? alertsRes.data : [];
        const liveAlertIds = new Set(state.alerts.map((a) => a.alert_id));
        for (const cachedId of state.triageFeedbackByAlert.keys()) {
          if (!liveAlertIds.has(cachedId)) {
            state.triageFeedbackByAlert.delete(cachedId);
          }
        }
        if (
          state.triageValidationFeedback &&
          !liveAlertIds.has(state.triageValidationFeedback.alertId)
        ) {
          state.triageValidationFeedback = null;
        }
        if (
          state.triageFeedback &&
          ((state.triageFeedback.alertId === null && !state.triageFeedback.ok) ||
            (state.triageFeedback.alertId !== null &&
              state.triageFeedback.alertId !== undefined &&
              !liveAlertIds.has(state.triageFeedback.alertId)))
        ) {
          state.triageFeedback = null;
        }
      } else {
        const persistedVisibleFeedback = state.selectedAlertId
          ? resolvePersistedDetailTriageFeedback(state.selectedAlertId)
          : state.triageFeedback;
        if (!(persistedVisibleFeedback && !persistedVisibleFeedback.ok)) {
          setAlertTriageFeedback(null, false, `Failed to refresh alerts: ${alertsRes.error}`);
        }
      }
      if (rulesRes.ok) {
        state.rules = Array.isArray(rulesRes.data) ? rulesRes.data : [];
      } else if (!(state.policyFeedback && !state.policyFeedback.ok)) {
        state.policyFeedback = {
          ok: false,
          message: `Failed to refresh policy rules: ${rulesRes.error}`,
        };
      }
      hideBanner();
      updateDaemonHeader(`Connected: ${pingSummary}`, metrics);
      renderAllViews();
    } catch (err) {
      state.localDefenseStatus = await invoke("fetch_local_defense_status").catch(
        () => state.localDefenseStatus,
      );
      state.updaterStatus = await invoke("get_updater_status").catch(
        () => state.updaterStatus,
      );
      state.isDaemonOnline = false;
      state.daemonVersion = null;
      updateDaemonHeader(null, null);
      showOfflineBanner(String(err));
      renderAllViews();
    } finally {
      el.refreshBtn.disabled = false;
    }
  }

  async function loadLaunchMode() {
    const invoke = getInvoke();
    if (!invoke) return null;
    try {
      const mode = await invoke("get_launch_mode");
      if (mode && mode.mode === "alert_focus" && mode.alert_id) {
        state.launchFocusAlertId = mode.alert_id;
        state.selectedAlertId = mode.alert_id;
        el.launchModePill.textContent = `Alert Focus: ${mode.alert_id}`;
        el.launchModePill.classList.remove("hidden");
        switchView("triage");
      }
      return mode?.mode || null;
    } catch {
      return null;
    }
  }

  function switchView(viewName) {
    state.activeView = viewName;
    document.title = VIEW_TITLES[viewName] || "LocalEDR";
    for (const tab of el.navTabs) {
      const active = tab.dataset.view === viewName;
      tab.classList.toggle("is-active", active);
      if (active) {
        tab.setAttribute("aria-current", "page");
      } else {
        tab.removeAttribute("aria-current");
      }
    }
    for (const [name, pane] of Object.entries(el.views)) {
      pane.classList.toggle("hidden", name !== viewName);
    }
    if (viewName === "triage") {
      renderTriageView();
    } else if (viewName === "policy") {
      renderPolicyView();
    }
  }

  function loadSamplePreview() {
    const sample = buildSampleData();
    state.isSamplePreview = true;
    state.isDaemonOnline = false;
    state.daemonVersion = null;
    state.selectedProcessId = null;
    state.lastSyncedAlertId = null;
    state.triageFeedback = null;
    state.triageFeedbackByAlert.clear();
    state.triageValidationFeedback = null;
    state.policyFeedback = null;
    state.domainRiskResult = null;
    state.domainRiskError = null;
    state.snapshot = sample.snapshot;
    state.alerts = sample.alerts;
    state.rules = sample.rules;
    state.localDefenseStatus = sample.localDefenseStatus;
    if (!state.selectedAlertId || !sample.alerts.some((a) => a.alert_id === state.selectedAlertId)) {
      state.selectedAlertId = sample.alerts[0]?.alert_id || null;
    }
    showSampleBanner();
    renderAllViews();
  }

  el.navTabs.forEach((tab) => {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  });

  el.refreshBtn.addEventListener("click", refreshAll);
  el.retryBtn.addEventListener("click", refreshAll);
  el.sampleBtn.addEventListener("click", loadSamplePreview);
  el.triageSampleBtn.addEventListener("click", loadSamplePreview);

  el.policyScopeBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      state.policyScopeFilter = btn.dataset.scope;
      renderPolicyView();
    });
  });

  el.policyFilter.addEventListener("input", (event) => {
    state.policyFilterText = event.target.value || "";
    renderPolicyView();
  });

  el.toggleAddRuleBtn.addEventListener("click", () => {
    const currentlyHidden = el.policyAddForm.classList.contains("hidden");
    setAddRuleFormVisible(currentlyHidden);
  });

  el.cancelAddRuleBtn.addEventListener("click", () => {
    el.policyAddForm.reset();
    syncPolicyFormHints();
    setAddRuleFormVisible(false);
  });

  el.ruleScopeInput.addEventListener("change", syncPolicyFormHints);
  el.ruleTargetInput.addEventListener("input", syncPolicyFormHints);

  el.policyAddForm.addEventListener("submit", handleUpsertRule);

  el.policyRulesBody.addEventListener("click", (event) => {
    const delBtn = event.target.closest("[data-delete-rule-id]");
    if (!delBtn) return;
    handleDeleteRule(delBtn.dataset.deleteRuleId);
  });

  el.domainCheckForm.addEventListener("submit", handleCheckDomainRisk);

  el.filterUnresolvedBtn.addEventListener("click", () => {
    state.alertQueueFilter = "unresolved";
    state.launchFocusAlertId = null;
    renderTriageView();
  });

  el.filterAllBtn.addEventListener("click", () => {
    state.alertQueueFilter = "all";
    renderTriageView();
  });

  el.triageShowAllBtn.addEventListener("click", () => {
    state.alertQueueFilter = "all";
    renderTriageView();
  });

  el.alertFilter.addEventListener("input", (event) => {
    state.alertFilterText = event.target.value || "";
    renderTriageView();
  });

  el.alertQueue.addEventListener("click", (event) => {
    const btn = event.target.closest("[data-alert-id]");
    if (!btn) return;
    const nextAlertId = btn.dataset.alertId;
    state.launchFocusAlertId = null;
    if (state.selectedAlertId !== nextAlertId) {
      state.triageValidationFeedback = null;
      if (state.triageFeedback && state.triageFeedback.alertId !== null) {
        state.triageFeedback = null;
      }
    }
    state.selectedAlertId = nextAlertId;
    renderTriageView();
  });

  el.optAllowDest.addEventListener("input", () => {
    syncTriageTargetScopeNote(state.selectedAlertIsNetwork);
    if (state.triageValidationFeedback) {
      state.triageValidationFeedback = null;
      if (state.selectedAlertId) {
        renderDetailTriageFeedback(state.selectedAlertId);
      }
    }
  });

  el.inspectInView2Btn.addEventListener("click", () => {
    const procId = el.inspectInView2Btn.dataset.procId;
    if (!procId) return;
    state.selectedProcessId = procId;
    switchView("lineage");
    renderTree();
  });

  el.btnTerminateBlock.addEventListener("click", () => handleResolveAlert("terminate"));
  el.btnAllowOnce.addEventListener("click", () => handleResolveAlert("allow_once"));
  el.btnAllowPermanent.addEventListener("click", () => handleResolveAlert("allow_permanent"));

  el.processFilter.addEventListener("input", (event) => {
    state.filterText = event.target.value || "";
    renderTree();
  });

  el.allProcsBtn.addEventListener("click", () => {
    state.selectedProcessId = null;
    renderTree();
  });

  el.expandAllBtn.addEventListener("click", () => {
    state.collapsedIds.clear();
    renderTree();
  });

  el.collapseAllBtn.addEventListener("click", () => {
    for (const p of state.snapshot.processes || []) {
      state.collapsedIds.add(p.process_instance_id);
    }
    renderTree();
  });

  el.processTree.addEventListener("click", (event) => {
    const toggle = event.target.closest("[data-toggle-id]");
    if (toggle && !toggle.classList.contains("is-leaf")) {
      const id = toggle.dataset.toggleId;
      if (state.collapsedIds.has(id)) {
        state.collapsedIds.delete(id);
      } else {
        state.collapsedIds.add(id);
      }
      renderTree();
      return;
    }

    const row = event.target.closest("[data-proc-id]");
    if (row) {
      state.selectedProcessId = row.dataset.procId;
      renderTree();
    }
  });

  el.tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      state.activeTab = btn.dataset.tab;
      for (const b of el.tabBtns) {
        const isActive = b === btn;
        b.classList.toggle("is-active", isActive);
        b.setAttribute("aria-selected", isActive ? "true" : "false");
      }
      const { byId } = buildHierarchy(state.snapshot);
      renderTelemetry(byId);
    });
  });

  el.updateBannerApplyBtn?.addEventListener("click", handleApplyUpdate);
  el.updateBannerNotesBtn?.addEventListener("click", handleOpenReleaseNotes);
  el.updateBannerViewBtn?.addEventListener("click", () => {
    switchView("policy");
    el.appUpdatePanel?.scrollIntoView?.({ block: "nearest" });
  });
  el.updateBannerDismissBtn?.addEventListener("click", dismissUpdateBanner);
  el.updateCheckBtn?.addEventListener("click", handleCheckForUpdates);
  el.updateApplyBtn?.addEventListener("click", handleApplyUpdate);
  el.updateCancelBtn?.addEventListener("click", handleCancelUpdate);
  el.updateReleaseNotesBtn?.addEventListener("click", handleOpenReleaseNotes);

  if (typeof globalThis !== "undefined" && globalThis.__LEDR_UI_TEST_MODE__) {
    globalThis.__LEDR_UI_EXPORTS__ = {
      normalizeWindowsPath,
      formatShortSha256,
      formatMotwSourceLabel,
      formatMotwZoneLabel,
      matchDownloadOriginsForProcess,
      selectPrimaryDownloadOrigin,
      getBrowserAlertResolutionPolicy,
      computeBrowserShieldStats,
      extractAlertDetails,
      buildSampleData,
      matchesFilter,
      buildHierarchy,
      renderDetectionCard,
      renderLineageCard,
      renderMotwCard,
      renderSuspendBanner,
      syncResolutionControls,
      handleResolveAlert,
      resolveEffectiveProcessScope,
      renderTree,
      renderInspector,
      renderTelemetry,
      renderPolicyView,
      refreshAll,
      loadSamplePreview,
      parseDaemonVersionFromPing,
      normalizeUpdaterPhase,
      normalizeVersionTag,
      formatBytes,
      applyUpdaterStatusPayload,
      renderUpdateBanner,
      renderAppUpdatePanel,
      dismissUpdateBanner,
      handleCheckForUpdates,
      handleApplyUpdate,
      handleCancelUpdate,
      handleOpenReleaseNotes,
      state,
      el,
    };
  } else {
    document.addEventListener("DOMContentLoaded", async () => {
      syncPolicyFormHints();
      const mode = await loadLaunchMode();
      await refreshAll();
      if (window.__TAURI__?.event?.listen) {
        try {
          await window.__TAURI__.event.listen("updater://status-changed", (event) => {
            if (event?.payload) {
              applyUpdaterStatusPayload(event.payload);
            }
          });
        } catch {
          // Ignore event subscription error outside runtime
        }
      }
      if (mode === "normal") {
        const invoke = getInvoke();
        invoke?.("trigger_startup_update_check").catch(() => null);
      }
    });
  }
})();
