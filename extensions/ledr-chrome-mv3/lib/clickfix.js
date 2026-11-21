// Pure ClickFix / Pastejacking clipboard payload analyzer (Decision Record L-15).

const POWERSHELL_EXEC_RE =
  /\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b(?=\s+(?:-(?:enc(?:odedcommand)?|ec?|c(?:ommand)?|w(?:indowstyle)?|nop(?:rofile)?|noni(?:nteractive)?|ep|executionpolicy|f(?:ile)?)|\/[a-z]+|\b(?:iex|invoke-expression|irm|iwr|downloadstring|start-process|new-object)\b))/i;

const ENCODED_CMD_RE = /(?:^|\s)-(?:enc|encodedcommand|ec)\s+[A-Za-z0-9+/=]{12,}/i;

const IEX_EVAL_RE =
  /\binvoke-expression\b|(?:\|\s*iex\b|;\s*iex\b|^\s*iex\s*\(|^\s*iex\s+\$|\biex\s*\(\s*(?:irm|iwr|new-object|invoke-webrequest))/i;

const CMD_EXEC_RE = /\bcmd(?:\.exe)?\s+\/[ck]\b/i;

const MSHTA_EXEC_RE =
  /\bmshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:|about:|\\\\|[a-z]:\\|[^\s]+\.(?:hta|vbs|js|jse|wsf)\b)/i;

const CERTUTIL_ABUSE_RE =
  /\bcertutil(?:\.exe)?\b(?=[^\r\n]*\s[-/](?:urlcache|decode(?:hex)?|split|verifyctl|f)\b)/i;

const CURL_WGET_PIPE_SHELL_RE =
  /\b(?:curl|wget)\b[^\r\n]*\|\s*(?:env\s+)?(?:sudo\s+)?(?:(?:\/[^\s]*\/)?(?:sh|bash|zsh|dash|ksh)|powershell(?:\.exe)?|pwsh(?:\.exe)?|iex|invoke-expression|cmd(?:\.exe)?)\b/i;

const INVISIBLE_OR_CONTROL_RE =
  /[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;

const SHELL_LINE_START_RE =
  /^\s*(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|mshta(?:\.exe)?|certutil(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|bitsadmin(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|bash|sh)\b/i;

const SHELL_CHAINING_RE =
  /(?:&&|\|\||\|)\s*(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|mshta|sh|bash|iex|rundll32|regsvr32)\b/i;

const FAKE_CAPTCHA_COMMENT_RE =
  /^\s*(?:powershell|pwsh|cmd|mshta|curl|wget|certutil|rundll32|regsvr32)\b[^\r\n]*\s+#\s*[^\r\n]+/i;

/**
 * Normalizes line endings and outer whitespace before comparing copied vs selected text.
 * @param {string} text
 * @returns {string}
 */
export function normalizeClipboardText(text) {
  if (typeof text !== "string") {
    return "";
  }
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
}

/**
 * Formats a clipboard excerpt safely for UI rendering without executing or hiding control bytes.
 * @param {string} text
 * @param {number} [maxLen=160]
 * @returns {string}
 */
export function sanitizeExcerpt(text, maxLen = 160) {
  if (typeof text !== "string" || text.length === 0) {
    return "";
  }
  const escaped = text
    .replace(/\r\n/g, "\\n")
    .replace(/[\r\n]/g, "\\n")
    .replace(
      /[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g,
      (ch) => `[U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}]`
    )
    .replace(/\s+/g, " ")
    .trim();

  if (escaped.length <= maxLen) {
    return escaped;
  }
  return `${escaped.slice(0, Math.max(0, maxLen - 3))}...`;
}

function hasTrailingNewline(text) {
  return text.endsWith("\n") || text.endsWith("\r");
}

function hasShellExecutionOrChaining(text) {
  return (
    SHELL_LINE_START_RE.test(text) ||
    SHELL_CHAINING_RE.test(text) ||
    FAKE_CAPTCHA_COMMENT_RE.test(text)
  );
}

/**
 * Evaluates clipboard write/copy events for ClickFix LOTL indicators or Pastejacking selection mismatch (`L-15`).
 * @param {{ copiedText: string, selectionText?: string, trigger?: string }} params
 */
export function analyzeClipboardPayload({
  copiedText,
  selectionText = "",
  trigger = "copy",
}) {
  const rawCopied = typeof copiedText === "string" ? copiedText : "";
  const rawSelection = typeof selectionText === "string" ? selectionText : "";

  if (!rawCopied) {
    return {
      suspicious: false,
      indicators: [],
      lotlIndicators: [],
      selectionMismatch: false,
      severity: "none",
      summary: "",
      excerpt: "",
    };
  }

  const lotlIndicators = [];
  if (POWERSHELL_EXEC_RE.test(rawCopied)) {
    lotlIndicators.push("powershell_exec");
  }
  if (ENCODED_CMD_RE.test(rawCopied)) {
    lotlIndicators.push("encoded_command");
  }
  if (IEX_EVAL_RE.test(rawCopied)) {
    lotlIndicators.push("iex_eval");
  }
  if (CMD_EXEC_RE.test(rawCopied)) {
    lotlIndicators.push("cmd_exec");
  }
  if (MSHTA_EXEC_RE.test(rawCopied)) {
    lotlIndicators.push("mshta_exec");
  }
  if (CERTUTIL_ABUSE_RE.test(rawCopied)) {
    lotlIndicators.push("certutil_abuse");
  }
  if (CURL_WGET_PIPE_SHELL_RE.test(rawCopied)) {
    lotlIndicators.push("curl_wget_pipe_shell");
  }
  if (INVISIBLE_OR_CONTROL_RE.test(rawCopied)) {
    lotlIndicators.push("hidden_control_chars");
  }

  const selectionTrimmed = rawSelection.trim();
  const trailingNewlineInjected =
    hasTrailingNewline(rawCopied) &&
    (selectionTrimmed.length > 0
      ? trigger === "copy" && !hasTrailingNewline(rawSelection)
      : hasShellExecutionOrChaining(rawCopied));

  if (trailingNewlineInjected) {
    lotlIndicators.push("trailing_newline_injection");
  }

  const normalizedCopied = normalizeClipboardText(rawCopied);
  const normalizedSelection = normalizeClipboardText(rawSelection);
  const selectionMismatch =
    trigger === "copy" &&
    normalizedSelection.length > 0 &&
    normalizedCopied !== normalizedSelection;

  const indicators = selectionMismatch
    ? [...lotlIndicators, "selection_mismatch"]
    : [...lotlIndicators];

  const suspicious = indicators.length > 0;
  let summary = "";
  if (selectionMismatch && lotlIndicators.length > 0) {
    summary = "Copied text was silently replaced with a dangerous command.";
  } else if (selectionMismatch) {
    summary = "Copied text differs from your page selection.";
  } else if (lotlIndicators.length > 0) {
    summary = "Suspicious shell or LOTL command was written to clipboard.";
  }

  return {
    suspicious,
    indicators,
    lotlIndicators,
    selectionMismatch,
    severity: suspicious ? "high" : "none",
    summary,
    excerpt: suspicious ? sanitizeExcerpt(rawCopied) : "",
  };
}
