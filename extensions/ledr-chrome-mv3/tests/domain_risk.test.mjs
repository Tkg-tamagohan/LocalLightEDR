import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  PROTECTED_BRANDS,
  assessLocalDomainRisk,
  extractInspectableDomain,
  levenshteinDistance,
  mergeDomainRisk,
} from "../lib/domain_risk.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

test("EXT-05: detects Punycode and brand homographs (edit distance 1..2)", () => {
  assert.equal(levenshteinDistance("paypa1", "paypal"), 1);
  assert.equal(levenshteinDistance("rnicrosoft", "microsoft"), 2);

  const puny = assessLocalDomainRisk("https://xn--pple-43d.com/login");
  assert.equal(puny.inspectable, true);
  assert.equal(puny.isHomograph, true);
  assert.equal(puny.hasPunycode, true);

  const typoSld = assessLocalDomainRisk("https://secure.paypa1.com/signin");
  assert.equal(typoSld.isHomograph, true);
  assert.equal(typoSld.matchedBrand, "paypal");

  const typoSubToken = assessLocalDomainRisk("https://login-paypa1.localedr.invalid/");
  assert.equal(typoSubToken.isHomograph, true);
  assert.equal(typoSubToken.matchedBrand, "paypal");

  const msTypo = assessLocalDomainRisk("https://login.rnicrosoft.com/");
  assert.equal(msTypo.isHomograph, true);
  assert.equal(msTypo.matchedBrand, "microsoft");
});

test("EXT-06: PROTECTED_BRANDS matches crates/ledr-rules/src/domain.rs exactly", () => {
  const domainRs = fs.readFileSync(
    path.join(REPO_ROOT, "crates", "ledr-rules", "src", "domain.rs"),
    "utf8"
  );
  const match = domainRs.match(/const PROTECTED_BRANDS:\s*&\[&str\]\s*=\s*&\[([\s\S]*?)\];/);
  assert.ok(match, "failed to locate PROTECTED_BRANDS in crates/ledr-rules/src/domain.rs");
  const rustBrands = [...match[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  assert.equal(rustBrands.length, 10);
  assert.deepEqual([...PROTECTED_BRANDS], rustBrands);
});

test("EXT-07: excludes localhost/IP/local schemes/exact brands, merges daemon NRD, and stays offline", () => {
  for (const ignored of [
    "http://localhost:8080/login",
    "https://dev.localhost/auth",
    "http://127.0.0.1:3000/signin",
    "http://[::1]:8000/",
    "chrome://settings/passwords",
    "file:///C:/Users/dev/test.html",
    "about:blank",
  ]) {
    assert.equal(extractInspectableDomain(ignored), null, `expected null for ${ignored}`);
    const risk = assessLocalDomainRisk(ignored);
    assert.equal(risk.inspectable, false);
    assert.equal(risk.isHomograph, false);
  }

  for (const exact of [
    "https://accounts.google.com/",
    "https://login.microsoft.com/",
    "https://github.com/login",
    "https://www.paypal.com/signin",
  ]) {
    const risk = assessLocalDomainRisk(exact);
    assert.equal(risk.inspectable, true);
    assert.equal(risk.isHomograph, false, `legitimate ${exact} must not trigger homograph`);
    assert.equal(risk.matchedBrand, null);
  }

  // Ordinary unrelated domain with short word should not false-positive
  const benign = assessLocalDomainRisk("https://apply.example.com/careers");
  assert.equal(benign.isHomograph, false);

  // Merge daemon NRD risk with local non-homograph domain
  const nrdLocal = assessLocalDomainRisk("https://fresh-portal.localedr.invalid/login");
  assert.equal(nrdLocal.isHomograph, false);
  const merged = mergeDomainRisk(nrdLocal, {
    domain: "fresh-portal.localedr.invalid",
    is_nrd: true,
    is_homograph: false,
    matched_brand: null,
  });
  assert.equal(merged.isNrd, true);
  assert.equal(merged.isHomograph, false);
  assert.equal(merged.risky, true);

  // Privacy invariant: domain_risk.js must contain zero network APIs
  const src = fs.readFileSync(path.join(__dirname, "..", "lib", "domain_risk.js"), "utf8");
  assert.doesNotMatch(src, /\bfetch\s*\(/);
  assert.doesNotMatch(src, /\bXMLHttpRequest\b/);
  assert.doesNotMatch(src, /\bWebSocket\b/);
});
