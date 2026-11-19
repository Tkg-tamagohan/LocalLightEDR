//! Outbound firewall risk classification and deny-overrides-allow policy evaluation
//! (`決定記録 L-03`, `決定記録 L-04`, `AUTO-02`).

mod classifier;
mod ip_target;
mod policy;

pub use classifier::{
    classify_outbound_risk, discover_default_prerestricted_interpreters,
    is_high_risk_executable_path, is_script_interpreter,
};
#[cfg(test)]
pub(crate) use classifier::discover_prerestricted_interpreters_from;
pub use ip_target::{canonical_ip, is_external_ip, matches_network_target, parse_cidr_target};
pub use policy::{
    evaluate_outbound_policy, matches_app_wide_network_allow, matches_app_wide_network_block,
    matches_network_allow_rule, matches_network_block_rule, validate_policy_rule,
};

/// Risk classification of an executable initiating outbound network traffic (`L-03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundRiskClass {
    /// Protected Windows OS or LocalEDR binary (`AUTO-02`): never blocked or suspended.
    ProtectedOs,
    /// Executable located under `Downloads`, `Temp`, or `Tmp` directories (`L-03`).
    HighRiskPath,
    /// Script interpreter (`powershell`, `pwsh`, `node`, `python`, `wscript`, etc., `L-03`).
    ScriptInterpreter,
    /// General-path binary requiring first-connect containment unless allowlisted (`L-03`).
    GeneralUnknown,
}

/// Effective outbound policy decision evaluated with deny-overrides-allow precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundDecision {
    ProtectedOs,
    BlockedByRule { rule_id: String },
    AllowedByRule { rule_id: String },
    PreemptiveRestrict(OutboundRiskClass),
    UnknownFirstConnect,
}
