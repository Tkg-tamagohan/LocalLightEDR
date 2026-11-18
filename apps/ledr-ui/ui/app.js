(() => {
  "use strict";

  const state = {
    snapshot: {
      processes: [],
      dns_queries: [],
      network_events: [],
      file_canary_events: [],
      download_origins: [],
    },
    metrics: null,
    selectedProcessId: null,
    filterText: "",
    activeTab: "all",
    activeView: "lineage",
    collapsedIds: new Set(),
    isSamplePreview: false,
  };

  const el = {
    navTabs: Array.from(document.querySelectorAll(".nav-tab")),
    views: {
      triage: document.getElementById("view-triage"),
      lineage: document.getElementById("view-lineage"),
      policy: document.getElementById("view-policy"),
    },
    launchModePill: document.getElementById("launch-mode-pill"),
    daemonStatusPill: document.getElementById("daemon-status-pill"),
    metricsPill: document.getElementById("metrics-pill"),
    refreshBtn: document.getElementById("refresh-btn"),
    statusBanner: document.getElementById("status-banner"),
    bannerTitle: document.getElementById("banner-title"),
    bannerDetail: document.getElementById("banner-detail"),
    retryBtn: document.getElementById("retry-btn"),
    sampleBtn: document.getElementById("sample-btn"),
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

  function buildSampleSnapshot() {
    const now = Date.now();
    const explorerId = "4120:133765432100000000";
    const cmdId = "5380:133765432105000000";
    const psId = "6912:133765432108000000";
    return {
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
          created_at_ms: now - 60_000,
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
          created_at_ms: now - 15_000,
          exited_at_ms: now - 10_000,
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
          created_at_ms: now - 14_500,
          exited_at_ms: null,
        },
      ],
      dns_queries: [
        {
          id: 1,
          timestamp_ms: now - 14_000,
          process_instance_id: psId,
          query_name: "telemetry-check.nrd-sample.invalid",
          query_type: 1,
          resolved_ips: ["203.0.113.42"],
          is_nrd: true,
        },
        {
          id: 2,
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
          timestamp_ms: now - 13_800,
          process_instance_id: psId,
          protocol: 6,
          dst_ip: "203.0.113.42",
          dst_port: 443,
          domain_hint: "telemetry-check.nrd-sample.invalid",
          action: "LOG",
        },
        {
          id: 2,
          timestamp_ms: now - 11_900,
          process_instance_id: explorerId,
          protocol: 6,
          dst_ip: "13.107.42.14",
          dst_port: 443,
          domain_hint: "settings-win.data.microsoft.com",
          action: "ALLOW",
        },
      ],
      file_canary_events: [],
      download_origins: [
        {
          id: 1,
          file_path: "C:\\Users\\user\\Downloads\\script.ps1",
          sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          tab_url: "https://example-download.invalid/setup",
          frame_url: null,
          referrer_url: "https://search.invalid/",
          downloaded_at_ms: now - 25_000,
        },
      ],
    };
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

    // Cycle break guard
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
      el.processTree.innerHTML = `<div class="inspector-empty" style="padding: 16px;">No processes match current snapshot/filter.</div>`;
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
          <div class="tree-row ${isSelected ? "is-selected" : ""}" data-proc-id="${escapeHtml(id)}" role="treeitem">
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
        <div class="inspector-item" style="grid-column: 1 / -1;">
          <div class="inspector-label">Command Line</div>
          <div class="inspector-val">${escapeHtml(p.command_line || "-")}</div>
        </div>
        ${
          p.origin_url
            ? `<div class="inspector-item" style="grid-column: 1 / -1;">
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
              <td class="mono">${escapeHtml(c.category)} (mask 0x${c.access_mask.toString(16)})</td>
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
      "Displaying synthetic preview telemetry. Start ledr-daemon and click Retry IPC for live data.";
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

  async function refreshAll() {
    const invoke = getInvoke();
    if (!invoke) {
      updateDaemonHeader(null, null);
      showOfflineBanner("Tauri IPC bridge unavailable outside Tauri runtime.");
      renderTree();
      return;
    }

    el.refreshBtn.disabled = true;
    try {
      const [pingSummary, snapshot, metrics] = await Promise.all([
        invoke("ping_daemon"),
        invoke("fetch_flight_recorder", {
          limit: 250,
          processInstanceId: null,
        }),
        invoke("fetch_pipeline_metrics").catch(() => null),
      ]);

      state.isSamplePreview = false;
      state.snapshot = snapshot;
      state.metrics = metrics;
      hideBanner();
      updateDaemonHeader(`Connected: ${pingSummary}`, metrics);
      renderTree();
    } catch (err) {
      updateDaemonHeader(null, null);
      showOfflineBanner(String(err));
      renderTree();
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
        el.launchModePill.textContent = `Alert Focus: ${mode.alert_id}`;
        el.launchModePill.classList.remove("hidden");
      }
    } catch {
      // Ignore launch mode probe error
    }
  }

  function switchView(viewName) {
    state.activeView = viewName;
    for (const tab of el.navTabs) {
      tab.classList.toggle("is-active", tab.dataset.view === viewName);
    }
    for (const [name, pane] of Object.entries(el.views)) {
      pane.classList.toggle("hidden", name !== viewName);
    }
  }

  el.navTabs.forEach((tab) => {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  });
  document.querySelectorAll(".back-to-view2").forEach((btn) => {
    btn.addEventListener("click", () => switchView("lineage"));
  });

  el.refreshBtn.addEventListener("click", refreshAll);
  el.retryBtn.addEventListener("click", refreshAll);
  el.sampleBtn.addEventListener("click", () => {
    state.isSamplePreview = true;
    state.selectedProcessId = null;
    state.snapshot = buildSampleSnapshot();
    showSampleBanner();
    renderTree();
  });

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
        b.classList.toggle("is-active", b === btn);
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
