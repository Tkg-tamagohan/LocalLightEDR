(() => {
  "use strict";

  // ISOLATED-world content script (document_start): ClickFix/Pastejacking (L-15),
  // NRD/homograph password warnings (L-14), and closed Shadow DOM alert banners.

  const OBSERVE_EVENT = "__ledr_clipboard_observe__";
  const CLICKFIX_HOST_ID = "ledr-clickfix-warning-host";
  const PASSWORD_HOST_ID = "ledr-domain-warning-host";

  let lastMainCopyTimestampMs = 0;
  let lastPasswordCheckHost = null;
  let lastPasswordRiskResult = null;
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
    const supportsPopover = Object.hasOwn(HTMLElement.prototype, "popover");
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

    const primaryBtn = document.createElement("button");
    primaryBtn.type = "button";
    primaryBtn.className = "btn-primary";
    primaryBtn.textContent = primaryLabel;
    primaryBtn.addEventListener("click", async () => {
      if (typeof onPrimary === "function") {
        await onPrimary();
      }
      host.remove();
    });

    actions.appendChild(dismissBtn);
    actions.appendChild(primaryBtn);
    card.appendChild(actions);

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
    await sendRuntimeMessage({
      type: "REPORT_BROWSER_EVENT",
      eventType: "ClickFixPastejacking",
      url: window.location.href,
      details: `${details} | ${verdict.excerpt}`,
    });

    mountBanner({
      hostId: CLICKFIX_HOST_ID,
      badgeText: "CLICKFIX / PASTEJACKING",
      titleText: "Suspicious Clipboard Command",
      detailText: details,
      excerptText: verdict.excerpt,
      primaryLabel: "Clear Clipboard",
      onPrimary: async () => {
        try {
          await navigator.clipboard.writeText("");
        } catch {
          // Page/user permission may deny programmatic clipboard clear outside gesture.
        }
      },
      onDismiss: null,
      anchorRect: null,
    });
  }

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

  async function inspectPasswordTarget(inputEl) {
    if (!(inputEl instanceof HTMLInputElement)) {
      return;
    }
    if ((inputEl.type || "").toLowerCase() !== "password") {
      return;
    }

    const host = window.location.hostname || "";
    if (!host || dismissedPasswordHost === host) {
      return;
    }

    let risk = null;
    if (lastPasswordCheckHost === host && lastPasswordRiskResult) {
      risk = lastPasswordRiskResult;
    } else {
      const res = await sendRuntimeMessage({
        type: "CHECK_DOMAIN_RISK",
        urlOrHost: window.location.href,
      });
      risk = res?.risk || null;
      if (risk) {
        lastPasswordCheckHost = host;
        lastPasswordRiskResult = risk;
      }
    }

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

    await sendRuntimeMessage({
      type: "REPORT_BROWSER_EVENT",
      eventType,
      url: window.location.href,
      details: detailText,
    });

    if (document.getElementById(PASSWORD_HOST_ID)) {
      return;
    }

    const rect = inputEl.getBoundingClientRect();
    mountBanner({
      hostId: PASSWORD_HOST_ID,
      badgeText: risk.isHomograph ? "HOMOGRAPH RISK" : "NRD PASSWORD RISK",
      titleText: risk.isHomograph ? "Suspicious Login Domain" : "Newly Registered Domain",
      detailText,
      excerptText: null,
      primaryLabel: "Clear Password",
      onPrimary: async () => {
        inputEl.value = "";
        inputEl.blur();
      },
      onDismiss: () => {
        dismissedPasswordHost = host;
      },
      anchorRect: rect.width > 0 && rect.height > 0 ? rect : null,
    });
  }

  document.addEventListener(
    "focusin",
    async (event) => {
      if (event.target instanceof HTMLInputElement && event.target.type.toLowerCase() === "password") {
        await inspectPasswordTarget(event.target);
      }
    },
    true
  );

  document.addEventListener(
    "input",
    async (event) => {
      if (event.target instanceof HTMLInputElement && event.target.type.toLowerCase() === "password") {
        await inspectPasswordTarget(event.target);
      }
    },
    true
  );
})();
