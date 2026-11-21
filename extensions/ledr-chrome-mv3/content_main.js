(() => {
  "use strict";

  // MAIN-world lightweight clipboard observer (Decision Record L-21).
  // Observes writes/copies and emits primitive JSON details to the ISOLATED world content script
  // without altering return values, Promise behavior, or throwing into host pages.

  if (window.__LEDR_CLIPBOARD_HOOKED__) {
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

  const OBSERVE_EVENT = "__ledr_clipboard_observe__";

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
      const detail = JSON.stringify({
        trigger: String(trigger || "copy"),
        copiedText: typeof copiedText === "string" ? copiedText : String(copiedText ?? ""),
        selectionText: typeof selectionText === "string" ? selectionText : "",
      });
      document.dispatchEvent(new CustomEvent(OBSERVE_EVENT, { detail }));
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
        void inspectClipboardItems(items, selectionSnapshot);
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
        const types = Array.isArray(item.types) ? item.types : [];
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
    let activeCopyClipboardData = null;
    window.addEventListener(
      "copy",
      (event) => {
        activeCopyClipboardData = event?.clipboardData || null;
        queueMicrotask(() => {
          activeCopyClipboardData = null;
        });
      },
      true
    );

    if (typeof DataTransfer === "function" && typeof DataTransfer.prototype.setData === "function") {
      const origSetData = DataTransfer.prototype.setData;
      DataTransfer.prototype.setData = function ledrSetData(format, data) {
        const fmt = String(format || "").toLowerCase();
        if (this === activeCopyClipboardData && (fmt === "text/plain" || fmt === "text")) {
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
