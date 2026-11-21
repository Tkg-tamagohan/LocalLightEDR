// Local-only domain normalization and Punycode/brand homograph assessment (Decision Record L-14).
// Matches `PROTECTED_BRANDS` in `crates/ledr-rules/src/domain.rs`.

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

function matchBrandTypo(label) {
  if (!label || label.length < 4) {
    return { exact: PROTECTED_BRANDS.includes(label), typoBrand: null };
  }
  for (const brand of PROTECTED_BRANDS) {
    if (label === brand) {
      return { exact: true, typoBrand: null };
    }
    const dist = levenshteinDistance(label, brand);
    if (dist >= 1 && dist <= 2) {
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
  const sld = labels.length >= 2 ? labels[labels.length - 2] : "";

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
    const nonTldLabels = labels.slice(0, -1);
    outer: for (const label of nonTldLabels) {
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
