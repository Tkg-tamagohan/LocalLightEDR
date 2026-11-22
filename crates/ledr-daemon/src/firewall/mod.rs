//! Dynamic WFP firewall rule manager with deny-overrides-allow reconciliation (`L-03`, `L-04`,
//! `AUTO-02`, `AUTO-04`).

mod containment;
mod domain_policy;
mod hints;
mod manager;
mod reconcile;
mod reconcile_plan;
mod types;

pub use manager::WfpRuleManager;
pub use types::{
    parse_literal_target_ip, InstalledWfpFilter, PromotedFilterSnapshot, RemovedAppBlockSnapshot,
    RemovedBlockSnapshot, RemovedDomainFilterSnapshot, WfpFailedOp, WfpFilterOrigin,
    WfpReconcileDnsContext, WfpReconcileReport, WfpTargetKey, MAX_DOMAIN_HINTS_PER_FILTER,
    MAX_DOMAIN_POLICY_FILTERS,
};

#[cfg(test)]
mod tests;
