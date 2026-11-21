(() => {
  "use strict";

  // ISOLATED-world content script (document_start): ClickFix/Pastejacking (L-15),
  // NRD/homograph password warnings (L-14), and closed Shadow DOM alert banners.

  const OBSERVE_CHANNEL_ATTR = "data-ledr-obs-ch";
  const CLICKFIX_HOST_ID = "ledr-clickfix-warning-host";
  const PASSWORD_HOST_ID = "ledr-domain-warning-host";
  const PASSWORD_INPUT_DEBOUNCE_MS = 2000;

  function createObserveChannelName() {
    if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") {
      return null;
    }
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return `__ledr_obs_${hex}`;
  }

  const OBSERVE_EVENT = createObserveChannelName();

  let lastMainCopyTimestampMs = 0;
  let pendingPasswordCheckHost = null;
  let pendingPasswordCheckPromise = null;
  let lastPasswordInputHost = null;
  let lastPasswordInputCheckAtMs = 0;
  let dismissedPasswordHost = null;

  function readActiveSelection() {
    try {
      const el = document.activeElement;
      if (
        el &&
        (el.tagName === "TEXTAREA" ||
          (el.tagName === "INPUT" && typeof el.selectionStart === "number"))
      ) {
        const start = el.selectionStart ?? 0;
        const end = el.selectionEnd ?? 0;
        if (end > start && typeof el.value === "string") {
          return el.value.slice(start, end);
        }
      }
      const sel = typeof window.getSelection === "function" ? window.getSelection() : null;
      return sel ? String(sel.toString()) : "";
    } catch {
      return "";
    }
  }

  function mountBanner({
    hostId,
    badgeText,
    titleText,
    detailText,
    excerptText,
    primaryLabel,
    onPrimary,
    onDismiss,
    anchorRect,
  }) {
    const existing = document.getElementById(hostId);
    if (existing) {
      existing.remove();
    }

    const host = document.createElement("div");
    host.id = hostId;
    const supportsPopover =
      typeof HTMLElement === "function" &&
      HTMLElement.prototype &&
      Object.hasOwn(HTMLElement.prototype, "popover");
    if (supportsPopover) {
      host.setAttribute("popover", "manual");
      host.style.cssText =
        "margin:0;padding:0;border:none;background:transparent;overflow:visible;inset:auto;";
    } else {
      host.style.cssText =
        "position:fixed;z-index:2147483647;margin:0;padding:0;border:none;background:transparent;";
    }

    if (anchorRect) {
      const margin = 12;
      const cardWidth = Math.min(368, Math.max(240, window.innerWidth - margin * 2));
      const left = Math.max(margin, Math.min(anchorRect.left, window.innerWidth - cardWidth - margin));
      const preferBelow = anchorRect.bottom + 8 + 180 <= window.innerHeight;
      const top = preferBelow
        ? anchorRect.bottom + 8
        : Math.max(margin, anchorRect.top - 172);
      host.style.position = "fixed";
      host.style.left = `${Math.round(left)}px`;
      host.style.top = `${Math.round(top)}px`;
      host.style.right = "auto";
    } else {
      host.style.position = "fixed";
      host.style.top = "12px";
      host.style.right = "12px";
      host.style.left = "auto";
    }

    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host {
        all: initial;
      }
      .card {
        box-sizing: border-box;
        width: min(368px, calc(100vw - 24px));
        background: #14171f;
        color: #f8fafc;
        border: 1px solid #dc2626;
        border-radius: 10px;
        box-shadow: 0 14px 36px rgba(0, 0, 0, 0.48);
        padding: 12px 14px;
        font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
        font-size: 13px;
        line-height: 1.45;
      }
      .header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        margin-bottom: 6px;
      }
      .badge {
        display: inline-block;
        padding: 2px 7px;
        border-radius: 4px;
        background: #dc2626;
        color: #ffffff;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.04em;
      }
      .title {
        font-size: 14px;
        font-weight: 700;
        color: #ffffff;
        margin: 0 0 4px 0;
      }
      .detail {
        margin: 0;
        color: #e2e8f0;
        font-size: 12.5px;
        overflow-wrap: anywhere;
      }
      .excerpt {
        margin: 8px 0 0 0;
        padding: 7px 9px;
        border-radius: 6px;
        background: #0b0d13;
        border: 1px solid #334155;
        color: #fca5a5;
        font-family: ui-monospace, Consolas, monospace;
        font-size: 11.5px;
        overflow-wrap: anywhere;
        max-height: 68px;
        overflow: hidden;
      }
      .actions {
        display: flex;
        justify-content: flex-end;
        align-items: center;
        gap: 8px;
        margin-top: 10px;
        flex-wrap: wrap;
      }
      button {
        font-family: inherit;
        font-size: 12px;
        font-weight: 600;
        border-radius: 6px;
        padding: 6px 12px;
        cursor: pointer;
      }
      .btn-primary {
        background: #dc2626;
        color: #ffffff;
        border: 1px solid #ef4444;
      }
      .btn-primary:hover {
        background: #b91c1c;
      }
      .btn-secondary {
        background: transparent;
        color: #cbd5e1;
        border: 1px solid #475569;
      }
      .btn-secondary:hover {
        background: #1e293b;
        color: #ffffff;
      }
      button:focus-visible {
        outline: 2px solid #93c5fd;
        outline-offset: 2px;
      }
      .status-error {
        margin-top: 8px;
        font-size: 12px;
        color: #fecaca;
        line-height: 1.4;
      }
      .status-error[hidden] {
        display: none;
      }
      @media (prefers-reduced-motion: reduce) {
        * {
          transition: none !important;
          animation: none !important;
        }
      }
    `;

    const card = document.createElement("div");
    card.className = "card";
    card.setAttribute("role", "alert");
    card.setAttribute("aria-live", "assertive");

    const header = document.createElement("div");
    header.className = "header";
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = badgeText;
    header.appendChild(badge);
    card.appendChild(header);

    const title = document.createElement("div");
    title.className = "title";
    title.textContent = titleText;
    card.appendChild(title);

    const detail = document.createElement("p");
    detail.className = "detail";
    detail.textContent = detailText;
    card.appendChild(detail);

    if (excerptText) {
      const excerpt = document.createElement("pre");
      excerpt.className = "excerpt";
      excerpt.textContent = excerptText;
      card.appendChild(excerpt);
    }

    const actions = document.createElement("div");
    actions.className = "actions";

    const dismissBtn = document.createElement("button");
    dismissBtn.type = "button";
    dismissBtn.className = "btn-secondary";
    dismissBtn.textContent = "Dismiss";
    dismissBtn.addEventListener("click", () => {
      host.remove();
      if (typeof onDismiss === "function") {
        onDismiss();
      }
    });

    const statusErrorEl = document.createElement("div");
    statusErrorEl.className = "status-error";
    statusErrorEl.hidden = true;

    const primaryBtn = document.createElement("button");
    primaryBtn.type = "button";
    primaryBtn.className = "btn-primary";
    primaryBtn.textContent = primaryLabel;
    primaryBtn.addEventListener("click", async () => {
      statusErrorEl.hidden = true;
      statusErrorEl.textContent = "";
      if (typeof onPrimary === "function") {
        const res = await onPrimary();
        if (res && res.ok === false) {
          statusErrorEl.textContent =
            res.message || "Could not clear clipboard automatically; copy safe text manually.";
          statusErrorEl.hidden = false;
          return;
        }
      }
      host.remove();
    });

    actions.appendChild(dismissBtn);
    actions.appendChild(primaryBtn);
    card.appendChild(actions);
    card.appendChild(statusErrorEl);

    shadow.appendChild(style);
    shadow.appendChild(card);

    requestAnimationFrame(() => {
      const root = document.body || document.documentElement;
      if (!root) return;
      root.appendChild(host);
      if (supportsPopover && typeof host.showPopover === "function") {
        try {
          host.showPopover();
        } catch {
          // Fallback fixed positioning already set.
        }
      }
    });
  }

  async function sendRuntimeMessage(payload) {
    try {
      return await chrome.runtime.sendMessage(payload);
    } catch {
      return null;
    }
  }

  async function evaluateClipboardObservation({ trigger, copiedText, selectionText }) {
    if (typeof copiedText !== "string" || copiedText.length === 0) {
      return;
    }
    const res = await sendRuntimeMessage({
      type: "ANALYZE_CLIPBOARD",
      trigger,
      copiedText,
      selectionText,
    });
    const verdict = res?.verdict;
    if (!verdict || !verdict.suspicious) {
      return;
    }

    const reasonTags = Array.isArray(verdict.indicators) ? verdict.indicators.join(", ") : "";
    const details = `${verdict.summary}${reasonTags ? ` [${reasonTags}]` : ""}`;

    mountBanner({
      hostId: CLICKFIX_HOST_ID,
      badgeText: "CLICKFIX / PASTEJACKING",
      titleText: "Suspicious Clipboard Command",
      detailText: details,
      excerptText: verdict.excerpt,
      primaryLabel: "Clear Clipboard",
      onPrimary: async () => {
        try {
          if (!navigator?.clipboard || typeof navigator.clipboard.writeText !== "function") {
            return {
              ok: false,
              message: "Clipboard API unavailable on this page; copy safe text manually.",
            };
          }
          await navigator.clipboard.writeText("");
          return { ok: true };
        } catch {
          return {
            ok: false,
            message: "Could not clear clipboard automatically; copy safe text manually.",
          };
        }
      },
      onDismiss: null,
      anchorRect: null,
    });

    void sendRuntimeMessage({
      type: "REPORT_BROWSER_EVENT",
      eventType: "ClickFixPastejacking",
      url: window.location.href,
      details: `${details} | ${verdict.excerpt}`,
    });
  }

  if (OBSERVE_EVENT) {
    document.addEventListener(
      OBSERVE_EVENT,
      async (event) => {
        let parsed = null;
        try {
          parsed = typeof event?.detail === "string" ? JSON.parse(event.detail) : null;
        } catch {
          return;
        }
        if (!parsed) return;
        if (parsed.trigger === "copy") {
          lastMainCopyTimestampMs = Date.now();
        }
        await evaluateClipboardObservation(parsed);
      },
      true
    );

    const channelHost = document.documentElement || document;
    if (channelHost && typeof channelHost.setAttribute === "function") {
      channelHost.setAttribute(OBSERVE_CHANNEL_ATTR, OBSERVE_EVENT);
      setTimeout(() => {
        try {
          if (
            typeof channelHost.getAttribute === "function" &&
            channelHost.getAttribute(OBSERVE_CHANNEL_ATTR) === OBSERVE_EVENT &&
            typeof channelHost.removeAttribute === "function"
          ) {
            channelHost.removeAttribute(OBSERVE_CHANNEL_ATTR);
          }
        } catch {
          // Ignore detached document cleanup errors.
        }
      }, 0);
    }
  }

  document.addEventListener(
    "copy",
    async (event) => {
      if (Date.now() - lastMainCopyTimestampMs < 50) {
        return;
      }
      const selectionText = readActiveSelection();
      let copiedText = "";
      try {
        copiedText = event.clipboardData?.getData("text/plain") || "";
      } catch {
        copiedText = "";
      }
      if (!copiedText) {
        copiedText = selectionText;
      }
      await evaluateClipboardObservation({
        trigger: "copy",
        copiedText,
        selectionText,
      });
    },
    false
  );

  function isPasswordInputElement(node) {
    return Boolean(
      node &&
        typeof node === "object" &&
        typeof node.tagName === "string" &&
        node.tagName.toUpperCase() === "INPUT" &&
        String(node.type || "").toLowerCase() === "password"
    );
  }

  function findPasswordInputFromEvent(event) {
    const path = typeof event?.composedPath === "function" ? event.composedPath() : [event?.target];
    if (!Array.isArray(path)) {
      return isPasswordInputElement(event?.target) ? event.target : null;
    }
    for (const node of path) {
      if (isPasswordInputElement(node)) {
        return node;
      }
    }
    return null;
  }

  async function checkDomainRiskCoalesced(host) {
    if (pendingPasswordCheckHost === host && pendingPasswordCheckPromise) {
      return await pendingPasswordCheckPromise;
    }
    pendingPasswordCheckHost = host;
    const promise = sendRuntimeMessage({
      type: "CHECK_DOMAIN_RISK",
      urlOrHost: window.location.href,
    });
    pendingPasswordCheckPromise = promise;
    try {
      return await promise;
    } finally {
      if (pendingPasswordCheckPromise === promise) {
        pendingPasswordCheckHost = null;
        pendingPasswordCheckPromise = null;
      }
    }
  }

  async function inspectPasswordTarget(inputEl, source = "focusin") {
    if (!isPasswordInputElement(inputEl)) {
      return;
    }

    const host = window.location.hostname || "";
    if (!host || dismissedPasswordHost === host) {
      return;
    }

    if (source === "input") {
      const now = Date.now();
      if (
        lastPasswordInputHost === host &&
        now - lastPasswordInputCheckAtMs < PASSWORD_INPUT_DEBOUNCE_MS
      ) {
        return;
      }
      lastPasswordInputHost = host;
      lastPasswordInputCheckAtMs = now;
    }

    const res = await checkDomainRiskCoalesced(host);
    const risk = res?.risk || null;
    if (!risk || !risk.risky) {
      return;
    }

    const reasons = [];
    if (risk.isHomograph) {
      if (risk.matchedBrand) {
        reasons.push(`resembles '${risk.matchedBrand}'`);
      } else if (risk.hasPunycode) {
        reasons.push("uses Punycode (xn--)");
      } else {
        reasons.push("homograph risk");
      }
    }
    if (risk.isNrd) {
      reasons.push("newly registered domain (NRD)");
    }

    const eventType = risk.isHomograph ? "HomographWarning" : "NrdPasswordWarning";
    const detailText = `${risk.domain}: ${reasons.join(" + ")}`;

    if (!document.getElementById(PASSWORD_HOST_ID)) {
      const rect =
        typeof inputEl.getBoundingClientRect === "function"
          ? inputEl.getBoundingClientRect()
          : { width: 0, height: 0 };
      mountBanner({
        hostId: PASSWORD_HOST_ID,
        badgeText: risk.isHomograph ? "HOMOGRAPH RISK" : "NRD PASSWORD RISK",
        titleText: risk.isHomograph ? "Suspicious Login Domain" : "Newly Registered Domain",
        detailText,
        excerptText: null,
        primaryLabel: "Clear Password",
        onPrimary: async () => {
          inputEl.value = "";
          if (typeof inputEl.blur === "function") {
            inputEl.blur();
          }
          return { ok: true };
        },
        onDismiss: () => {
          dismissedPasswordHost = host;
        },
        anchorRect: rect.width > 0 && rect.height > 0 ? rect : null,
      });
    }

    void sendRuntimeMessage({
      type: "REPORT_BROWSER_EVENT",
      eventType,
      url: window.location.href,
      details: detailText,
    });
  }

  function isAnchorElement(node) {
    return Boolean(
      node &&
        typeof node === "object" &&
        typeof node.tagName === "string" &&
        node.tagName.toUpperCase() === "A"
    );
  }

  function findAnchorFromEvent(event) {
    const path = typeof event?.composedPath === "function" ? event.composedPath() : null;
    if (Array.isArray(path)) {
      for (const node of path) {
        if (isAnchorElement(node)) {
          return node;
        }
      }
    }
    let current = event?.target || null;
    while (current && typeof current === "object") {
      if (isAnchorElement(current)) {
        return current;
      }
      current = current.parentNode || null;
    }
    return null;
  }

  function extractRawHref(anchor) {
    if (typeof anchor.getAttribute === "function") {
      const attr = anchor.getAttribute("href");
      if (typeof attr === "string") {
        return attr.trim();
      }
    }
    if (typeof anchor.href === "string") {
      return anchor.href.trim();
    }
    return "";
  }

  function resolveDownloadHintHref(anchor) {
    const rawHref = extractRawHref(anchor);
    if (!rawHref || rawHref.startsWith("#")) {
      return null;
    }
    try {
      const parsed = new URL(rawHref, window.location.href);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return null;
      }
      parsed.hash = "";
      return parsed.href;
    } catch {
      return null;
    }
  }

  document.addEventListener(
    "click",
    (event) => {
      const anchor = findAnchorFromEvent(event);
      if (!anchor) {
        return;
      }
      const targetUrl = resolveDownloadHintHref(anchor);
      if (!targetUrl) {
        return;
      }
      void sendRuntimeMessage({
        type: "RECORD_DOWNLOAD_CLICK_HINT",
        targetUrl,
        pageUrl: window.location.href,
      });
    },
    true
  );

  document.addEventListener(
    "focusin",
    async (event) => {
      const passwordInput = findPasswordInputFromEvent(event);
      if (passwordInput) {
        await inspectPasswordTarget(passwordInput, "focusin");
      }
    },
    true
  );

  document.addEventListener(
    "input",
    async (event) => {
      const passwordInput = findPasswordInputFromEvent(event);
      if (passwordInput) {
        await inspectPasswordTarget(passwordInput, "input");
      }
    },
    true
  );
})();
