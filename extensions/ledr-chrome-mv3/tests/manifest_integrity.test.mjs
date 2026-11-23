import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXT_DIR = path.resolve(__dirname, "..");
const REPO_ROOT = path.resolve(EXT_DIR, "..", "..");

function deriveChromeExtensionIdFromBase64Key(keyB64) {
  const der = Buffer.from(keyB64, "base64");
  const digest = crypto.createHash("sha256").update(der).digest();
  let id = "";
  for (let i = 0; i < 16; i++) {
    id += String.fromCharCode(97 + (digest[i] >> 4));
    id += String.fromCharCode(97 + (digest[i] & 0x0f));
  }
  return id;
}

test("EXT-11: MV3 manifest, DNR rules, popup CSP, and offline privacy checks hold", () => {
  const manifestPath = path.join(EXT_DIR, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

  assert.equal(manifest.manifest_version, 3);
  assert.equal(typeof manifest.key, "string");
  assert.ok(manifest.key.length > 100);

  for (const perm of [
    "declarativeNetRequest",
    "declarativeNetRequestFeedback",
    "downloads",
    "nativeMessaging",
    "storage",
    "tabs",
    "alarms",
  ]) {
    assert.ok(manifest.permissions.includes(perm), `missing permission ${perm}`);
  }

  assert.ok(manifest.action, "manifest must declare 'action'");
  assert.equal(manifest.action.default_popup, "popup.html");
  assert.equal(manifest.icons, undefined, "must not reference nonexistent icons");
  assert.equal(manifest.action.default_icon, undefined, "must not reference nonexistent action icons");

  assert.equal(manifest.background.service_worker, "background.js");
  assert.equal(manifest.background.type, "module");
  assert.ok(fs.existsSync(path.join(EXT_DIR, manifest.background.service_worker)));

  assert.equal(manifest.content_scripts.length, 2);
  const mainIndex = manifest.content_scripts.findIndex((c) => c.world === "MAIN");
  const isoIndex = manifest.content_scripts.findIndex((c) => !c.world || c.world === "ISOLATED");
  assert.ok(mainIndex >= 0, "MAIN world content script must be configured (L-21)");
  assert.ok(isoIndex >= 0, "ISOLATED world content script must be configured");
  assert.ok(
    isoIndex < mainIndex,
    "ISOLATED world content.js must execute before MAIN world content_main.js for SEC_0002 channel handshake"
  );
  for (const cs of manifest.content_scripts) {
    assert.equal(cs.run_at, "document_start");
    for (const file of cs.js) {
      assert.ok(fs.existsSync(path.join(EXT_DIR, file)), `missing content script ${file}`);
      const content = fs.readFileSync(path.join(EXT_DIR, file), "utf8");
      assert.doesNotMatch(
        content,
        /^\s*(import|export)\s/m,
        `classic content script ${file} must not use top-level ES module syntax`
      );
    }
  }

  // DNR static rules must target only verification `.localedr.invalid` domains (L-21)
  const ruleset = manifest.declarative_net_request.rule_resources[0];
  const dnrPath = path.join(EXT_DIR, ruleset.path);
  const dnrRules = JSON.parse(fs.readFileSync(dnrPath, "utf8"));
  assert.ok(Array.isArray(dnrRules) && dnrRules.length >= 1);
  const seenIds = new Set();
  for (const rule of dnrRules) {
    assert.ok(Number.isInteger(rule.id) && rule.id > 0);
    assert.equal(seenIds.has(rule.id), false);
    seenIds.add(rule.id);
    assert.equal(rule.action?.type, "block");
    assert.match(rule.condition?.urlFilter || "", /\.localedr\.invalid/);
  }

  // Popup HTML strict MV3 CSP + DOM ID integrity
  const popupHtml = fs.readFileSync(path.join(EXT_DIR, "popup.html"), "utf8");
  const popupJs = fs.readFileSync(path.join(EXT_DIR, "popup.js"), "utf8");
  assert.ok(fs.existsSync(path.join(EXT_DIR, "popup.css")));
  assert.doesNotMatch(popupHtml, /<script(?![^>]*\bsrc=)[^>]*>/i, "no inline <script> allowed");
  assert.doesNotMatch(popupHtml, /\son[a-z]+\s*=/i, "no inline event handlers allowed");
  assert.doesNotMatch(popupHtml, /javascript:/i);
  for (const idMatch of popupJs.matchAll(/getElementById\(\s*["']([^"']+)["']\s*\)/g)) {
    assert.ok(
      popupHtml.includes(`id="${idMatch[1]}"`),
      `popup.html missing DOM id="${idMatch[1]}" referenced in popup.js`
    );
  }

  // Ensure no extension JS file performs external HTTP requests or uses `.then(` promise chains
  const jsFiles = [
    "background.js",
    "content.js",
    "content_main.js",
    "popup.js",
    "lib/clickfix.js",
    "lib/dnr.js",
    "lib/domain_risk.js",
    "lib/downloads.js",
    "lib/native_bridge.js",
  ];
  for (const rel of jsFiles) {
    const src = fs.readFileSync(path.join(EXT_DIR, rel), "utf8");
    assert.doesNotMatch(src, /\bfetch\s*\(/, `${rel} must not use fetch()`);
    assert.doesNotMatch(src, /\bXMLHttpRequest\b/, `${rel} must not use XMLHttpRequest`);
    assert.doesNotMatch(src, /\.then\s*\(/, `${rel} must use async/await instead of .then()`);
  }

  // Node 18/20 LTS ESM compatibility: package.json must declare private=true, type=module, and zero dependencies
  const pkgPath = path.join(EXT_DIR, "package.json");
  assert.ok(fs.existsSync(pkgPath), "package.json must exist in extensions/ledr-chrome-mv3");
  const pkgBytes = fs.readFileSync(pkgPath);
  assert.equal(
    pkgBytes.length >= 3 && pkgBytes[0] === 0xef && pkgBytes[1] === 0xbb && pkgBytes[2] === 0xbf,
    false,
    "package.json must be UTF-8 without BOM"
  );
  const pkg = JSON.parse(pkgBytes.toString("utf8"));
  assert.equal(pkg.private, true);
  assert.equal(pkg.type, "module");
  for (const depField of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    const deps = pkg[depField];
    assert.ok(
      deps === undefined ||
        (typeof deps === "object" &&
          deps !== null &&
          !Array.isArray(deps) &&
          Object.keys(deps).length === 0),
      `package.json ${depField} must be absent or empty`
    );
  }
});

test("EXT-12: manifest.json public key matches Rust DEFAULT_CHROME_EXTENSION_ID", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const derivedId = deriveChromeExtensionIdFromBase64Key(manifest.key);
  assert.match(derivedId, /^[a-p]{32}$/);

  const extIdRs = fs.readFileSync(
    path.join(REPO_ROOT, "crates", "ledr-bridge-nm", "src", "extension_id.rs"),
    "utf8"
  );
  const match = extIdRs.match(
    /pub const DEFAULT_CHROME_EXTENSION_ID:\s*&str\s*=\s*"([a-p]{32})";/
  );
  assert.ok(match, "failed to parse DEFAULT_CHROME_EXTENSION_ID from extension_id.rs");
  assert.equal(derivedId, match[1]);
});
