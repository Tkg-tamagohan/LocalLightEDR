// Local-only domain normalization and Punycode/brand homograph assessment (Decision Record L-14).
// Matches `PROTECTED_BRANDS`, `COMPOUND_PUBLIC_SUFFIXES`, and `BENIGN_BRAND_NEIGHBORS`
// in `crates/ledr-rules/src/domain.rs`.

export const PROTECTED_BRANDS = Object.freeze([
  "google",
  "microsoft",
  "github",
  "paypal",
  "amazon",
  "apple",
  "cloudflare",
  "openai",
  "anthropic",
  "dropbox",
]);

export const COMPOUND_PUBLIC_SUFFIXES = Object.freeze([
  // .jp (9)
  "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ed.jp", "gr.jp", "ad.jp", "lg.jp",
  // .uk (6)
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
  // .au (7)
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  // .nz (5)
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  // .br (5)
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  // .kr (5)
  "co.kr", "ne.kr", "or.kr", "go.kr", "ac.kr",
  // Other (14)
  "com.cn", "net.cn", "org.cn", "com.tw", "org.tw", "com.hk", "com.sg", "co.in", "net.in",
  "org.in", "co.za", "com.mx", "com.tr", "co.il",
]);

export const BENIGN_BRAND_NEIGHBORS = Object.freeze([
  "amaze",
  "ample",
  "apply",
  "boggle",
  "maple",
  "openal",
  "papal",
]);

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * Extracts a normalized public-style hostname from an `http:`/`https:` URL or raw host string.
 * Excludes `localhost`, IPv4/IPv6 literals, single-label hosts, and browser/local schemes.
 * @param {string} urlOrHost
 * @returns {string | null}
 */
export function extractInspectableDomain(urlOrHost) {
  if (typeof urlOrHost !== "string") {
    return null;
  }
  const trimmed = urlOrHost.trim();
  if (!trimmed) {
    return null;
  }

  let hostname = trimmed;
  if (trimmed.includes("://")) {
    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch {
      return null;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    hostname = parsed.hostname;
  } else {
    // Reject non-network schemes like `about:blank` or `chrome:settings`.
    const schemeMatch = /^([a-z][a-z0-9+.-]*):/i.exec(trimmed);
    if (schemeMatch && !/^\d+$/.test(trimmed.slice(schemeMatch[0].length))) {
      return null;
    }
    if (trimmed.startsWith("[")) {
      return null;
    }
    const colonIdx = trimmed.indexOf(":");
    if (colonIdx !== -1) {
      const rest = trimmed.slice(colonIdx + 1);
      if (!/^\d+$/.test(rest)) {
        return null;
      }
      hostname = trimmed.slice(0, colonIdx);
    }
  }

  const normalized = hostname.trim().replace(/\.+$/, "").toLowerCase();
  if (!normalized || normalized.includes("/") || /\s/.test(normalized)) {
    return null;
  }
  if (normalized === "localhost" || normalized.endsWith(".localhost")) {
    return null;
  }
  if (normalized.includes(":") || IPV4_RE.test(normalized)) {
    return null;
  }
  if (!normalized.includes(".")) {
    return null;
  }
  return normalized;
}

/**
 * Computes exact Levenshtein edit distance between two strings.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function levenshteinDistance(a, b) {
  if (a === b) {
    return 0;
  }
  const lenA = a.length;
  const lenB = b.length;
  if (lenA === 0) {
    return lenB;
  }
  if (lenB === 0) {
    return lenA;
  }

  let prev = new Array(lenB + 1);
  let curr = new Array(lenB + 1);
  for (let j = 0; j <= lenB; j++) {
    prev[j] = j;
  }

  for (let i = 1; i <= lenA; i++) {
    curr[0] = i;
    const chA = a.charCodeAt(i - 1);
    for (let j = 1; j <= lenB; j++) {
      const cost = chA === b.charCodeAt(j - 1) ? 0 : 1;
      const del = prev[j] + 1;
      const ins = curr[j - 1] + 1;
      const sub = prev[j - 1] + cost;
      curr[j] = Math.min(del, ins, sub);
    }
    [prev, curr] = [curr, prev];
  }

  return prev[lenB];
}

function homographSkeleton(s) {
  return s
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/0/g, "o")
    .replace(/[1i]/g, "l");
}

function isSingleAdjacentTransposition(a, b) {
  const aChars = Array.from(a);
  const bChars = Array.from(b);
  if (aChars.length !== bChars.length || aChars.length < 2) {
    return false;
  }
  let i = 0;
  while (i < aChars.length && aChars[i] === bChars[i]) {
    i++;
  }
  if (i + 1 >= aChars.length) {
    return false;
  }
  if (aChars[i] !== bChars[i + 1] || aChars[i + 1] !== bChars[i]) {
    return false;
  }
  for (let k = i + 2; k < aChars.length; k++) {
    if (aChars[k] !== bChars[k]) {
      return false;
    }
  }
  return true;
}

function isCompoundPublicSuffix(penult, last) {
  return COMPOUND_PUBLIC_SUFFIXES.includes(`${penult}.${last}`);
}

function splitDomainLabels(labels) {
  const len = labels.length;
  if (len < 2) {
    return { sld: "", nonSuffixLabels: [] };
  }
  if (isCompoundPublicSuffix(labels[len - 2], labels[len - 1])) {
    if (len === 2) {
      return { sld: "", nonSuffixLabels: [] };
    }
    return { sld: labels[len - 3], nonSuffixLabels: labels.slice(0, -2) };
  }
  return { sld: labels[len - 2], nonSuffixLabels: labels.slice(0, -1) };
}

function matchBrandTypo(label) {
  if (!label || label.length < 4) {
    return { exact: false, typoBrand: null };
  }
  if (PROTECTED_BRANDS.includes(label)) {
    return { exact: true, typoBrand: null };
  }
  if (BENIGN_BRAND_NEIGHBORS.includes(label)) {
    return { exact: false, typoBrand: null };
  }

  const labelSkeleton = homographSkeleton(label);
  for (const brand of PROTECTED_BRANDS) {
    if (labelSkeleton === homographSkeleton(brand)) {
      return { exact: false, typoBrand: brand };
    }
    if (isSingleAdjacentTransposition(label, brand)) {
      return { exact: false, typoBrand: brand };
    }
    const dist = levenshteinDistance(label, brand);
    const matchesLenTier =
      brand.length >= 7
        ? dist >= 1 && dist <= 2 && label.length >= 5
        : dist === 1 && label.length >= 4;
    if (matchesLenTier) {
      return { exact: false, typoBrand: brand };
    }
  }
  return { exact: false, typoBrand: null };
}

/**
 * Performs strictly local Punycode + protected brand typosquatting/homograph checks (`L-14`).
 * Never makes external network requests.
 * @param {string} domainOrUrl
 */
export function assessLocalDomainRisk(domainOrUrl) {
  const domain = extractInspectableDomain(domainOrUrl);
  if (!domain) {
    return {
      inspectable: false,
      domain: "",
      isNrd: false,
      isHomograph: false,
      hasPunycode: false,
      matchedBrand: null,
    };
  }

  const labels = domain.split(".");
  const hasPunycode = labels.some((label) => label.startsWith("xn--"));
  const { sld, nonSuffixLabels } = splitDomainLabels(labels);

  let matchedBrand = null;
  let looksLikeBrandTypo = false;

  const sldCheck = matchBrandTypo(sld);
  if (sldCheck.exact) {
    // Legitimate domain's SLD exactly equals the protected brand (only suspicious if Punycode).
    matchedBrand = hasPunycode ? sld : null;
  } else if (sldCheck.typoBrand) {
    matchedBrand = sldCheck.typoBrand;
    looksLikeBrandTypo = true;
  } else {
    const isLocalTestDomain = domain.endsWith(".localedr.invalid");
    outer: for (const label of nonSuffixLabels) {
      for (const token of label.split("-")) {
        if (token.length < 4) {
          continue;
        }
        if (!isLocalTestDomain && !/[0-9]/.test(token)) {
          continue;
        }
        const tokenCheck = matchBrandTypo(token);
        if (tokenCheck.typoBrand) {
          matchedBrand = tokenCheck.typoBrand;
          looksLikeBrandTypo = true;
          break outer;
        }
      }
    }
  }

  const isHomograph = hasPunycode || looksLikeBrandTypo;
  return {
    inspectable: true,
    domain,
    isNrd: false,
    isHomograph,
    hasPunycode,
    matchedBrand: isHomograph ? matchedBrand : null,
  };
}

/**
 * Merges browser-local homograph output with `ledr-daemon` `CheckDomainRisk` IPC response.
 */
export function mergeDomainRisk(localResult, daemonPayload) {
  const domain = daemonPayload?.domain || localResult?.domain || "";
  const isNrd = Boolean(daemonPayload?.is_nrd);
  const isHomograph = Boolean(localResult?.isHomograph || daemonPayload?.is_homograph);
  const hasPunycode = Boolean(localResult?.hasPunycode);
  const matchedBrand =
    localResult?.matchedBrand || daemonPayload?.matched_brand || null;

  return {
    inspectable: Boolean(localResult?.inspectable || domain),
    domain,
    isNrd,
    isHomograph,
    hasPunycode,
    matchedBrand,
    risky: isNrd || isHomograph,
  };
}
