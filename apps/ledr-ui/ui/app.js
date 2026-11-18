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
    metrics: null,
    selectedProcessId: null,
    selectedAlertId: null,
    lastSyncedAlertId: null,
    launchFocusAlertId: null,
    alertQueueFilter: "unresolved",
    alertFilterText: "",
    filterText: "",
    activeTab: "all",
    activeView: "lineage",
    collapsedIds: new Set(),
    isSamplePreview: false,
    isDaemonOnline: false,
    isResolvingAlert: false,
    triageFeedback: null,
  };

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
    btnAllowOnce: document.getElementById("btn-allow-once"),
    btnAllowPermanent: document.getElementById("btn-allow-permanent"),
    optUseSigner: document.getElementById("opt-use-signer"),
    signerConstraintNote: document.getElementById("signer-constraint-note"),
    optAllowDest: document.getElementById("opt-allow-dest"),
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
          action: "LOG",
        },
        {
          id: 2,
          timestamp_ms: now - 13_800,
          process_instance_id: psId,
          protocol: 6,
          dst_ip: "203.0.113.42",
          dst_port: 443,
          domain_hint: "telemetry-check.nrd-sample.invalid",
          action: "LOG",
        },
        {
          id: 3,
          timestamp_ms: now - 11_900,
          process_instance_id: explorerId,
          protocol: 6,
          dst_ip: "13.107.42.14",
          dst_port: 443,
          domain_hint: "settings-win.data.microsoft.com",
          action: "ALLOW",
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

    return { snapshot, alerts };
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

    const targetPath =
      ctx.target_path ||
      ctx.event?.CanaryFileAccess?.target_path ||
      ctx.event?.DnsQuery?.query_name ||
      ctx.url ||
      matchingCanary?.target_path ||
      null;

    const category =
      ctx.category ||
      ctx.event?.CanaryFileAccess?.category ||
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
    const exeLower = exePath ? exePath.toLowerCase() : null;
    const shaLower = sha256 ? sha256.toLowerCase() : null;
    const downloadOrigins = (state.snapshot.download_origins || []).filter((d) => {
      if (shaLower && d.sha256 && d.sha256.toLowerCase() === shaLower) return true;
      if (exeLower && d.file_path && d.file_path.toLowerCase() === exeLower) return true;
      if (originUrl && d.tab_url === originUrl) return true;
      return false;
    });

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

  function renderAlertStatePills(alert) {
    if (alert.status === "ExpiredSuspended") {
      return `<span class="state-pill state-expired">EXPIRED_SUSPENDED (60s)</span>`;
    }
    if (alert.status === "Pending") {
      if (alert.process_suspended) {
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
      el.triageDetail.classList.add("hidden");
      el.triageEmpty.classList.remove("hidden");

      if (state.triageFeedback && state.triageFeedback.message) {
        el.triageEmptyLabel.textContent = state.triageFeedback.message;
      } else if (state.alertQueueFilter === "unresolved" && allAlerts.length > 0) {
        el.triageEmptyLabel.textContent = "No unresolved alerts";
      } else {
        el.triageEmptyLabel.textContent = state.isDaemonOnline
          ? "No alerts recorded"
          : "Daemon offline — no alerts loaded";
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

  function renderSuspendBanner(alert, details) {
    let bannerClass = "suspend-banner";
    let headline = alert.title;
    let subline = "";

    if (alert.status === "ExpiredSuspended") {
      bannerClass += " is-expired";
      subline = details.includeChildren
        ? "60s timeout elapsed — process tree remains frozen without data loss"
        : "60s timeout elapsed — process remains frozen without data loss";
    } else if (alert.status === "Pending" && alert.process_suspended) {
      bannerClass += " is-frozen";
      subline = details.includeChildren
        ? "Process tree frozen (NtSuspendProcess) — awaiting decision"
        : "Process frozen (NtSuspendProcess) — awaiting decision";
    } else if (alert.status === "Pending") {
      subline = "Active alert — process not suspended";
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

    el.triageLineageDl.innerHTML = `
      <dt>Executable</dt>
      <dd class="mono-wrap">${escapeHtml(details.exePath || "-")}</dd>
      <dt>PID / Instance</dt>
      <dd class="mono-wrap">${escapeHtml(
        details.pid !== null && details.pid !== undefined ? String(details.pid) : "-",
      )} | ${escapeHtml(details.processInstanceId || "-")}</dd>
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
    if (!details.originUrl && origins.length === 0) {
      el.triageMotwBody.innerHTML = `<span class="panel-meta">None recorded</span>`;
      return;
    }

    const items = [];
    if (details.originUrl && origins.length === 0) {
      items.push(`
        <dl class="kv-list">
          <dt>Origin URL</dt>
          <dd class="mono-wrap">${escapeHtml(details.originUrl)}</dd>
        </dl>
      `);
    }
    for (const d of origins) {
      items.push(`
        <dl class="kv-list">
          <dt>Tab URL</dt>
          <dd class="mono-wrap">${escapeHtml(d.tab_url)}</dd>
          ${
            d.referrer_url
              ? `<dt>Referrer</dt><dd class="mono-wrap">${escapeHtml(d.referrer_url)}</dd>`
              : ""
          }
          ${
            d.frame_url
              ? `<dt>Frame URL</dt><dd class="mono-wrap">${escapeHtml(d.frame_url)}</dd>`
              : ""
          }
          <dt>Downloaded</dt>
          <dd class="mono">${escapeHtml(formatTime(d.downloaded_at_ms))}</dd>
        </dl>
      `);
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
      const actionClass =
        actionUpper === "BLOCK"
          ? "badge-action-block"
          : actionUpper === "ALLOW"
            ? "badge-action-allow"
            : "badge-action-log";
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

  function syncResolutionControls(alert, details) {
    const unresolved = isUnresolvedAlert(alert);
    const hasSigner = Boolean(details.signerSubject);

    if (state.lastSyncedAlertId !== alert.alert_id) {
      state.lastSyncedAlertId = alert.alert_id;
      el.optAddBlockRule.checked = true;
      el.optUseSigner.checked = hasSigner;
      el.optAllowDest.value = "";
    }

    el.optUseSigner.disabled = !unresolved || !hasSigner || state.isResolvingAlert;
    if (!hasSigner) {
      el.optUseSigner.checked = false;
      el.signerConstraintNote.textContent = "Unsigned binary: SHA-256 required";
    } else {
      el.signerConstraintNote.textContent = "";
    }

    el.optAddBlockRule.disabled = !unresolved || state.isResolvingAlert;
    el.optAllowDest.disabled = !unresolved || state.isResolvingAlert;
    el.btnTerminateBlock.disabled = !unresolved || state.isResolvingAlert;
    el.btnAllowOnce.disabled = !unresolved || state.isResolvingAlert;
    el.btnAllowPermanent.disabled = !unresolved || state.isResolvingAlert;

    if (state.triageFeedback && state.triageFeedback.message) {
      el.triageActionStatus.textContent = state.triageFeedback.message;
      el.triageActionStatus.className = `triage-feedback ${
        state.triageFeedback.ok ? "is-ok" : "is-error"
      }`;
      el.triageActionStatus.classList.remove("hidden");
    } else {
      el.triageActionStatus.classList.add("hidden");
    }
  }

  async function handleResolveAlert(kind) {
    const alert = state.alerts.find((a) => a.alert_id === state.selectedAlertId);
    if (!alert || !isUnresolvedAlert(alert) || state.isResolvingAlert) {
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
                ? "NetworkBlock rule saved, WFP applies in Phase 3"
                : "no NetworkBlock rule saved"
            }`
          : `Preview: ${alert.alert_id} → ${previewStatus}`;
      state.triageFeedback = {
        ok: true,
        message: previewMessage,
      };
      renderTriageView();
      return;
    }

    const invoke = getInvoke();
    if (!invoke) {
      state.triageFeedback = {
        ok: false,
        message: "Tauri IPC bridge unavailable outside Tauri runtime.",
      };
      renderTriageView();
      return;
    }

    state.isResolvingAlert = true;
    state.triageFeedback = null;
    renderTriageView();

    try {
      const ackMessage = await invoke("resolve_alert_action", {
        alertId: alert.alert_id,
        decision,
      });
      const feedbackMessage =
        kind === "terminate"
          ? `${ackMessage} — process tree terminated; ${
              addBlockRule
                ? "NetworkBlock rule saved, WFP applies in Phase 3"
                : "no NetworkBlock rule saved"
            }`
          : ackMessage;
      state.triageFeedback = { ok: true, message: feedbackMessage };
      await refreshAll();
    } catch (err) {
      state.triageFeedback = { ok: false, message: String(err) };
      renderTriageView();
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

  function renderTree() {
    const { roots, byId } = buildHierarchy(state.snapshot);
    const query = state.filterText.trim().toLowerCase();
    const visibleRoots = filterNodes(roots, query);

    el.treeSummary.textContent = `${state.snapshot.processes.length} processes`;
    el.allProcsBtn.classList.toggle("is-selected", state.selectedProcessId === null);

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
      const isSelected = state.selectedProcessId === id;

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
    if (!state.selectedProcessId || !byId.has(state.selectedProcessId)) {
      const dnsCount = (state.snapshot.dns_queries || []).length;
      const netCount = (state.snapshot.network_events || []).length;
      const canaryCount = (state.snapshot.file_canary_events || []).length;
      el.processInspector.innerHTML = `
        <div class="inspector-grid">
          <div class="inspector-item">
            <div class="inspector-label">Selection</div>
            <div class="inspector-val">All Processes (${state.snapshot.processes.length})</div>
          </div>
          <div class="inspector-item">
            <div class="inspector-label">Captured Events</div>
            <div class="inspector-val">DNS ${dnsCount} | Network ${netCount} | Canary ${canaryCount}</div>
          </div>
        </div>
      `;
      el.scopeIndicator.textContent = "Scope: All Processes";
      return;
    }

    const p = byId.get(state.selectedProcessId);
    const signer = p.is_trusted_os
      ? `${p.signer_subject || "Windows"} (Trusted OS)`
      : p.signer_subject || "Unsigned";
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
          p.origin_url
            ? `<div class="inspector-item span-full">
                 <div class="inspector-label">Origin URL (MOTW)</div>
                 <div class="inspector-val">${escapeHtml(p.origin_url)}</div>
               </div>`
            : ""
        }
      </div>
    `;
  }

  function renderTelemetry(byId) {
    const scopeId = state.selectedProcessId;
    const filterProc = (item) => !scopeId || item.process_instance_id === scopeId;

    const dns = (state.snapshot.dns_queries || []).filter(filterProc);
    const net = (state.snapshot.network_events || []).filter(filterProc);
    const canary = (state.snapshot.file_canary_events || []).filter(filterProc);
    const downloads = scopeId ? [] : state.snapshot.download_origins || [];

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
        const actionClass =
          actionUpper === "BLOCK"
            ? "badge-action-block"
            : actionUpper === "ALLOW"
              ? "badge-action-allow"
              : "badge-action-log";
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
        rows.push({
          ts: d.downloaded_at_ms,
          html: `
            <tr>
              <td class="mono">${escapeHtml(formatTime(d.downloaded_at_ms))}</td>
              <td><span class="badge badge-unsigned">MOTW</span></td>
              <td class="mono">Browser Download</td>
              <td class="mono">${escapeHtml(d.file_path)}</td>
              <td class="mono">${escapeHtml(d.tab_url)}</td>
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

  function renderAllViews() {
    renderTriageView();
    renderTree();
  }

  async function refreshAll() {
    const invoke = getInvoke();
    if (!invoke) {
      state.isDaemonOnline = false;
      updateDaemonHeader(null, null);
      showOfflineBanner("Tauri IPC bridge unavailable outside Tauri runtime.");
      renderAllViews();
      return;
    }

    el.refreshBtn.disabled = true;
    try {
      const [pingSummary, snapshot, metrics, alerts] = await Promise.all([
        invoke("ping_daemon"),
        invoke("fetch_flight_recorder", {
          limit: 250,
          processInstanceId: null,
        }),
        invoke("fetch_pipeline_metrics").catch(() => null),
        invoke("fetch_alerts", {
          status: null,
          limit: 200,
        }).catch(() => []),
      ]);

      state.isDaemonOnline = true;
      state.isSamplePreview = false;
      state.snapshot = snapshot;
      state.metrics = metrics;
      state.alerts = Array.isArray(alerts) ? alerts : [];
      hideBanner();
      updateDaemonHeader(`Connected: ${pingSummary}`, metrics);
      renderAllViews();
    } catch (err) {
      state.isDaemonOnline = false;
      updateDaemonHeader(null, null);
      showOfflineBanner(String(err));
      renderAllViews();
    } finally {
      el.refreshBtn.disabled = false;
    }
  }

  async function loadLaunchMode() {
    const invoke = getInvoke();
    if (!invoke) return;
    try {
      const mode = await invoke("get_launch_mode");
      if (mode && mode.mode === "alert_focus" && mode.alert_id) {
        state.launchFocusAlertId = mode.alert_id;
        state.selectedAlertId = mode.alert_id;
        el.launchModePill.textContent = `Alert Focus: ${mode.alert_id}`;
        el.launchModePill.classList.remove("hidden");
        switchView("triage");
      }
    } catch {
      // Ignore launch mode probe error
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
    }
  }

  function loadSamplePreview() {
    const sample = buildSampleData();
    state.isSamplePreview = true;
    state.isDaemonOnline = false;
    state.selectedProcessId = null;
    state.triageFeedback = null;
    state.snapshot = sample.snapshot;
    state.alerts = sample.alerts;
    if (!state.selectedAlertId || !sample.alerts.some((a) => a.alert_id === state.selectedAlertId)) {
      state.selectedAlertId = sample.alerts[0]?.alert_id || null;
    }
    showSampleBanner();
    renderAllViews();
  }

  el.navTabs.forEach((tab) => {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  });
  document.querySelectorAll(".back-to-view2").forEach((btn) => {
    btn.addEventListener("click", () => switchView("lineage"));
  });

  el.refreshBtn.addEventListener("click", refreshAll);
  el.retryBtn.addEventListener("click", refreshAll);
  el.sampleBtn.addEventListener("click", loadSamplePreview);
  el.triageSampleBtn.addEventListener("click", loadSamplePreview);

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
    state.launchFocusAlertId = null;
    state.selectedAlertId = btn.dataset.alertId;
    state.triageFeedback = null;
    renderTriageView();
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

  document.addEventListener("DOMContentLoaded", async () => {
    await loadLaunchMode();
    await refreshAll();
  });
})();
