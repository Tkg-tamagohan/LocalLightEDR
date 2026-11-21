(() => {
  "use strict";

  // MAIN-world lightweight clipboard observer (Decision Record L-21).
  // Observes writes/copies and emits primitive JSON details to the ISOLATED world content script
  // without altering return values, Promise behavior, or throwing into host pages.

  if (window.__LEDR_CLIPBOARD_HOOKED__) {
    return;
  }

  const OBSERVE_CHANNEL_ATTR = "data-ledr-obs-ch";
  const CHANNEL_TOKEN_RE = /^__ledr_obs_[0-9a-f]{32}$/;

  const NativeCustomEvent = typeof CustomEvent === "function" ? CustomEvent : null;
  const nativeDispatchEvent =
    typeof Document === "function" &&
    Document.prototype &&
    typeof Document.prototype.dispatchEvent === "function"
      ? Document.prototype.dispatchEvent
      : typeof document.dispatchEvent === "function"
        ? document.dispatchEvent
        : null;
  const nativeJsonStringify = JSON.stringify;
  const nativeArrayFrom = Array.from;
  const nativeIsArray = Array.isArray;
  const NativeWeakSet = typeof WeakSet === "function" ? WeakSet : Set;
  const nativeGetAttribute =
    typeof Element === "function" &&
    Element.prototype &&
    typeof Element.prototype.getAttribute === "function"
      ? Element.prototype.getAttribute
      : null;
  const nativeRemoveAttribute =
    typeof Element === "function" &&
    Element.prototype &&
    typeof Element.prototype.removeAttribute === "function"
      ? Element.prototype.removeAttribute
      : null;

  const channelHost = document.documentElement || document;
  const OBSERVE_EVENT =
    channelHost && nativeGetAttribute
      ? nativeGetAttribute.call(channelHost, OBSERVE_CHANNEL_ATTR)
      : channelHost && typeof channelHost.getAttribute === "function"
        ? channelHost.getAttribute(OBSERVE_CHANNEL_ATTR)
        : null;
  if (channelHost) {
    try {
      if (nativeRemoveAttribute) {
        nativeRemoveAttribute.call(channelHost, OBSERVE_CHANNEL_ATTR);
      } else if (typeof channelHost.removeAttribute === "function") {
        channelHost.removeAttribute(OBSERVE_CHANNEL_ATTR);
      }
    } catch {
      // Ignore attribute cleanup errors.
    }
  }
  if (typeof OBSERVE_EVENT !== "string" || !CHANNEL_TOKEN_RE.test(OBSERVE_EVENT)) {
    return;
  }

  try {
    Object.defineProperty(window, "__LEDR_CLIPBOARD_HOOKED__", {
      value: true,
      configurable: false,
      enumerable: false,
    });
  } catch {
    window.__LEDR_CLIPBOARD_HOOKED__ = true;
  }

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

  function emitObservation(trigger, copiedText, selectionText) {
    try {
      if (!NativeCustomEvent || !nativeDispatchEvent) {
        return;
      }
      const detail = nativeJsonStringify({
        trigger: String(trigger || "copy"),
        copiedText: typeof copiedText === "string" ? copiedText : String(copiedText ?? ""),
        selectionText: typeof selectionText === "string" ? selectionText : "",
      });
      nativeDispatchEvent.call(document, new NativeCustomEvent(OBSERVE_EVENT, { detail }));
    } catch {
      // Never propagate hook errors into host page execution.
    }
  }

  try {
    const clipboardProto =
      typeof Clipboard === "function" ? Clipboard.prototype : navigator?.clipboard && Object.getPrototypeOf(navigator.clipboard);
    if (clipboardProto && typeof clipboardProto.writeText === "function") {
      const origWriteText = clipboardProto.writeText;
      clipboardProto.writeText = function ledrWriteText(text) {
        emitObservation("writeText", text, readActiveSelection());
        return origWriteText.apply(this, arguments);
      };
    }

    if (clipboardProto && typeof clipboardProto.write === "function") {
      const origWrite = clipboardProto.write;
      clipboardProto.write = function ledrWrite(items) {
        const selectionSnapshot = readActiveSelection();
        if (items != null && typeof items[Symbol.iterator] === "function") {
          const snapshot = nativeIsArray(items) ? items.slice() : nativeArrayFrom(items);
          void inspectClipboardItems(snapshot, selectionSnapshot);
          return origWrite.call(this, snapshot);
        }
        return origWrite.apply(this, arguments);
      };
    }
  } catch {
    // Clipboard API may be unavailable on insecure contexts.
  }

  async function inspectClipboardItems(items, selectionSnapshot) {
    try {
      if (!items || typeof items[Symbol.iterator] !== "function") {
        return;
      }
      for (const item of items) {
        if (!item || typeof item.getType !== "function") {
          continue;
        }
        const types = nativeIsArray(item.types) ? item.types : [];
        if (types.includes("text/plain")) {
          const blob = await item.getType("text/plain");
          const text = await blob.text();
          emitObservation("write", text, selectionSnapshot);
        }
      }
    } catch {
      // Ignore non-text blobs or revoked ClipboardItem reads.
    }
  }

  try {
    const copyDataTransfers = new NativeWeakSet();
    window.addEventListener(
      "copy",
      (event) => {
        if (event?.clipboardData) {
          copyDataTransfers.add(event.clipboardData);
        }
      },
      true
    );

    if (typeof DataTransfer === "function" && typeof DataTransfer.prototype.setData === "function") {
      const origSetData = DataTransfer.prototype.setData;
      DataTransfer.prototype.setData = function ledrSetData(format, data) {
        const fmt = String(format || "").toLowerCase();
        if (copyDataTransfers.has(this) && (fmt === "text/plain" || fmt === "text")) {
          emitObservation("copy", data, readActiveSelection());
        }
        return origSetData.apply(this, arguments);
      };
    }
  } catch {
    // Ignore read-only prototypes.
  }

  try {
    if (typeof Document === "function" && typeof Document.prototype.execCommand === "function") {
      const origExecCommand = Document.prototype.execCommand;
      Document.prototype.execCommand = function ledrExecCommand(commandId) {
        const cmd = String(commandId || "").toLowerCase();
        const selectionBefore = cmd === "copy" ? readActiveSelection() : "";
        const result = origExecCommand.apply(this, arguments);
        if (cmd === "copy" && result && selectionBefore) {
          emitObservation("execCommand", selectionBefore, selectionBefore);
        }
        return result;
      };
    }
  } catch {
    // Ignore read-only prototypes.
  }
})();
