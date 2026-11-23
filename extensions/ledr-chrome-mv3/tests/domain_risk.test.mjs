import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  BENIGN_BRAND_NEIGHBORS,
  COMPOUND_PUBLIC_SUFFIXES,
  PROTECTED_BRANDS,
  assessLocalDomainRisk,
  extractInspectableDomain,
  levenshteinDistance,
  mergeDomainRisk,
} from "../lib/domain_risk.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

function extractRustConstStringList(rustSrc, constName) {
  const re = new RegExp(
    `const ${constName}:\\s*&\\[&str\\]\\s*=\\s*&\\[([\\s\\S]*?)\\];`
  );
  const match = rustSrc.match(re);
  assert.ok(match, `failed to locate ${constName} in crates/ledr-rules/src/domain.rs`);
  return [...match[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

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

test("EXT-06: constants and domain risk parity match crates/ledr-rules/src/domain.rs exactly", () => {
  const domainRs = fs.readFileSync(
    path.join(REPO_ROOT, "crates", "ledr-rules", "src", "domain.rs"),
    "utf8"
  );

  const rustBrands = extractRustConstStringList(domainRs, "PROTECTED_BRANDS");
  assert.equal(rustBrands.length, 10);
  assert.deepEqual([...PROTECTED_BRANDS], rustBrands);

  const rustSuffixes = extractRustConstStringList(domainRs, "COMPOUND_PUBLIC_SUFFIXES");
  assert.equal(rustSuffixes.length, 51);
  assert.deepEqual([...COMPOUND_PUBLIC_SUFFIXES], rustSuffixes);

  const rustNeighbors = extractRustConstStringList(domainRs, "BENIGN_BRAND_NEIGHBORS");
  assert.equal(rustNeighbors.length, 7);
  assert.deepEqual([...BENIGN_BRAND_NEIGHBORS], rustNeighbors);

  const sharedParityVectors = [
    // 2-level ccTLDs (exact + typo + subdomain)
    ["google.co.jp", false, null],
    ["login.microsoft.co.uk", false, null],
    ["paypa1.co.jp", true, "paypal"],
    ["secure.app1e.co.uk", true, "apple"],
    ["dr0pb0x.com.au", true, "dropbox"],
    ["githbu.co.nz", true, "github"],
    ["amaz0n.com.br", true, "amazon"],
    ["rnicrosoft.co.kr", true, "microsoft"],
    ["0pena1.com.cn", true, "openai"],
    // Bare compound public suffixes (no SLD)
    ["co.jp", false, null],
    ["co.uk", false, null],
    ["com.au", false, null],
    // Benign brand neighbors
    ["amaze.com", false, null],
    ["ample.co.uk", false, null],
    ["apply.com", false, null],
    ["apply.example.com", false, null],
    ["boggle.com.au", false, null],
    ["maple.co.nz", false, null],
    ["openal.org", false, null],
    ["papal.com", false, null],
    ["login-papal.localedr.invalid", false, null],
    // Skeleton equality
    ["g00g1e.com", true, "google"],
    ["rnlcr0s0ft.com", true, "microsoft"],
    ["c10udf1are.com", true, "cloudflare"],
    ["glthub.com", true, "github"],
    ["0pena1.com", true, "openai"],
    ["arnaz0n.com", true, "amazon"],
    // Single adjacent transposition
    ["goolge.com", true, "google"],
    ["amzaon.com", true, "amazon"],
    ["paypla.com", true, "paypal"],
    ["aplpe.com", true, "apple"],
    ["opneai.com", true, "openai"],
    ["dorpbox.com", true, "dropbox"],
    // Length-tiered Levenshtein distance
    ["aple.com", true, "apple"],
    ["app.com", false, null],
    ["axpxe.com", false, null],
    ["foofle.com", false, null],
    ["dropb.com", true, "dropbox"],
    ["drop.com", false, null],
    ["microzoff.com", true, "microsoft"],
    ["cloudflre.com", true, "cloudflare"],
    ["anthropk.com", true, "anthropic"],
    // Hyphen-split tokens on non-suffix labels
    ["login-paypa1.co.jp", true, "paypal"],
    ["auth-g00g1e.com", true, "google"],
    ["login-rnicrosoft.localedr.invalid", true, "microsoft"],
    ["login-paypal.localedr.invalid", false, null],
    ["login-paypal.com", false, null],
    ["web1-apples.com", false, null],
    ["co-jp.com", false, null],
    // Punycode
    ["xn--pple-43d.com", true, null],
    ["xn--pple-43d.google.com", true, "google"],
    ["xn--pple-43d.google.co.jp", true, "google"],
  ];

  for (const [domain, expectedHomograph, expectedBrand] of sharedParityVectors) {
    const res = assessLocalDomainRisk(`https://${domain}/`);
    assert.equal(res.inspectable, true, `expected inspectable=true for ${domain}`);
    assert.equal(
      res.isHomograph,
      expectedHomograph,
      `unexpected isHomograph for ${domain}: got ${res.isHomograph}, expected ${expectedHomograph}`
    );
    assert.equal(
      res.matchedBrand,
      expectedBrand,
      `unexpected matchedBrand for ${domain}: got ${res.matchedBrand}, expected ${expectedBrand}`
    );
  }
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
