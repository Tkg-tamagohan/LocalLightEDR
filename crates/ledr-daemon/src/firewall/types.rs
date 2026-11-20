//! Public data types, constants, and literal IP target parsing for the WFP rule manager.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[cfg(doc)]
use ledr_proto::ActiveDefenseController;
use ledr_rules::canonical_ip;

/// Upper bound on dynamically materialized domain-derived IP WFP filters to keep BFE handle
/// usage strictly bounded.
pub const MAX_DOMAIN_POLICY_FILTERS: usize = 512;

/// Upper bound on normalized domain hints retained per [`WfpFilterOrigin::DomainPolicy`] filter
/// to keep per-filter metadata strictly bounded (`L-10`).
pub const MAX_DOMAIN_HINTS_PER_FILTER: usize = 32;

/// Origin tracking why a dynamic WFP filter is currently installed in BFE.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WfpFilterOrigin {
    /// Installed directly to enforce a persisted concrete/IP `NetworkBlock` or `NetworkAllow` rule.
    PersistedPolicy,
    /// Installed for a concrete resolved IP matched by persisted domain-scoped `NetworkBlock`
    /// or `NetworkAllow` rules (`domain_hints` retains the normalized, deduplicated, bounded set
    /// of domains backing this IP filter so shared-IP reconciliation and DNS migration cleanup
    /// stay accurate even across DNS history eviction).
    DomainPolicy { domain_hints: Vec<String> },
    /// Installed proactively on `ProcessStart` for high-risk paths (`Downloads`/`Temp`) or
    /// script interpreters (`powershell`, `node`, `python`, etc.) (`L-03`).
    Preemptive,
    /// Installed dynamically during unknown-process first-connect containment (`NtSuspendProcess`
    /// + WFP block) while waiting for operator triage (`L-03`).
    TransientContainment,
}

/// Composite key identifying a concrete WFP filter target managed by the daemon (canonical IP).
pub type WfpTargetKey = (String, Option<IpAddr>);

/// Metadata for a live WFP rule handle registered via [`ActiveDefenseController`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledWfpFilter {
    pub handle: u64,
    pub exe_path: String,
    pub allow: bool,
    pub origin: WfpFilterOrigin,
}

/// Snapshot of a temporarily removed block filter used to compensate if alert resolution fails
/// during process resume or alert status persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedBlockSnapshot {
    pub key: WfpTargetKey,
    pub exe_path: String,
    pub origin: WfpFilterOrigin,
}

/// Individual WFP filter operation failure captured during reconciliation (`#4`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFailedOp {
    pub exe_key: String,
    pub remote_ip: Option<IpAddr>,
    pub is_remove: bool,
    pub is_startup_preemptive: bool,
    pub newly_required: bool,
    pub source_rule_ids: Vec<String>,
    pub domain_hints: Vec<String>,
    pub error: String,
}

/// Snapshot of a filter origin promoted/demoted during reconciliation (plus any alert containment
/// bindings cleared on promotion) so SQLite rollback can restore the exact pre-reconcile state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotedFilterSnapshot {
    pub key: WfpTargetKey,
    pub prev_origin: WfpFilterOrigin,
    pub bound_alert_ids: Vec<String>,
}

/// Snapshot of a [`WfpFilterOrigin::DomainPolicy`] filter removed during reconciliation so
/// SQLite rollback can re-install it in BFE (since `reconcile_persisted_rules` only rebuilds
/// static [`WfpFilterOrigin::PersistedPolicy`] filters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedDomainFilterSnapshot {
    pub exe_path: String,
    pub remote_ip: IpAddr,
    pub allow: bool,
    pub domain_hints: Vec<String>,
}

/// Optional live DNS history context supplied during persisted-rule reconciliation so existing
/// [`WfpFilterOrigin::DomainPolicy`] Blocks retain active blocked domains added after DNS
/// resolution and [`WfpFilterOrigin::DomainPolicy`] Permits prune migrated/superseded hints
/// (`#1`, `#4`).
#[derive(Debug, Default)]
pub struct WfpReconcileDnsContext {
    /// Non-superseded active DNS domains per `(exe_key, canonical_ip)` for currently installed
    /// `DomainPolicy` Blocks.
    pub active_block_domains: HashMap<(String, IpAddr), Vec<String>>,
    /// Normalized `(exe_key, canonical_ip, domain_hint)` tuples known to be superseded in
    /// `ProcessDnsHistory` for currently installed `DomainPolicy` Permits.
    pub superseded_permit_hints: HashSet<(String, IpAddr, String)>,
}

/// Summary of a persisted-rule reconciliation pass against [`ActiveDefenseController`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WfpReconcileReport {
    pub applied: usize,
    pub removed: usize,
    pub promoted: usize,
    pub skipped_wildcard: usize,
    pub failed: usize,
    pub failed_ops: Vec<WfpFailedOp>,
    pub promoted_backups: Vec<PromotedFilterSnapshot>,
    pub removed_domain_filters: Vec<RemovedDomainFilterSnapshot>,
}

/// Parses an optional `allowed_target` string into a canonical [`IpAddr`] when applicable
/// (unwrapping IPv4-mapped IPv6 addresses into IPv4).
pub fn parse_literal_target_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('*') {
        return None;
    }
    trimmed.parse::<IpAddr>().ok().map(canonical_ip)
}
