// LocalEDR MV3 — Dynamic declarativeNetRequest helper utilities.

export const DYNAMIC_RULE_ID_START = 10000;
export const DYNAMIC_RULE_ID_MAX = 39999;

export const DYNAMIC_RESOURCE_TYPES = [
  "main_frame",
  "sub_frame",
  "script",
  "xmlhttprequest",
  "image",
  "websocket",
  "ping",
  "other",
];

const HOSTNAME_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;

export function normalizeDynamicBlockDomains(
  blockDomains,
  limit = DYNAMIC_RULE_ID_MAX - DYNAMIC_RULE_ID_START + 1
) {
  if (!Array.isArray(blockDomains) || blockDomains.length === 0 || limit <= 0) {
    return [];
  }
  const normalized = [];
  const seen = new Set();
  for (const raw of blockDomains) {
    if (typeof raw !== "string") {
      continue;
    }
    const cleaned = raw.trim().replace(/^\.+|\.+$/g, "").toLowerCase();
    if (!cleaned || !HOSTNAME_RE.test(cleaned) || seen.has(cleaned)) {
      continue;
    }
    seen.add(cleaned);
    normalized.push(cleaned);
    if (normalized.length >= limit) {
      break;
    }
  }
  return normalized;
}

export function buildDynamicBlockRules(
  blockDomains,
  startId = DYNAMIC_RULE_ID_START,
  maxId = DYNAMIC_RULE_ID_MAX
) {
  const limit = Math.max(0, maxId - startId + 1);
  const domains = normalizeDynamicBlockDomains(blockDomains, limit);
  return domains.map((domain, idx) => ({
    id: startId + idx,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: `||${domain}^`,
      resourceTypes: [...DYNAMIC_RESOURCE_TYPES],
    },
  }));
}

export function buildDynamicDnrUpdatePlan(
  existingRules,
  blockDomains,
  startId = DYNAMIC_RULE_ID_START,
  maxId = DYNAMIC_RULE_ID_MAX
) {
  const removeRuleIds = Array.isArray(existingRules)
    ? existingRules
        .map((r) => r?.id)
        .filter((id) => Number.isInteger(id) && id >= startId && id <= maxId)
    : [];
  const addRules = buildDynamicBlockRules(blockDomains, startId, maxId);
  return { removeRuleIds, addRules };
}
