//! Windows Filtering Platform (WFP) dynamic SubLayer and outbound rule engine (`L-03`, `AUTO-04`).
//!
//! Uses `FWPM_SESSION_FLAG_DYNAMIC` with a dedicated LocalEDR provider and SubLayer so that
//! closing the engine handle or an unexpected daemon termination automatically purges all
//! dynamic outbound filters from the Windows Base Filtering Engine (BFE) without leaving
//! permanent network lockouts.

mod backend;
mod engine;
mod net_events;
mod spec;

pub use backend::{LiveWfpBackend, WfpBackend};
pub use engine::WfpDynamicEngine;
pub use net_events::{
    WfpDropEvent, WfpDropSinkFn, WfpFilterMeta, parse_wfp_classify_drop_fields,
};
pub use spec::{
    LEDR_WFP_PROVIDER_GUID, LEDR_WFP_SUBLAYER_GUID, LEDR_WFP_SUBLAYER_WEIGHT,
    WFP_WEIGHT_BLOCK_APP, WFP_WEIGHT_BLOCK_SPECIFIC, WFP_WEIGHT_LOOPBACK_PERMIT,
    WFP_WEIGHT_PERMIT_APP, WFP_WEIGHT_PERMIT_SPECIFIC, WfpFilterAction, WfpFilterSpec, WfpLayer,
    WfpLoopbackCondition, WfpLoopbackFilterSpec, WfpRemoteAddress,
    build_loopback_permit_filter_specs, build_wfp_filter_specs, canonical_wfp_ip,
    compute_filter_weight, ipv4_to_wfp_host_order, ipv6_to_wfp_network_order,
    normalize_wfp_exe_path, validate_wfp_rule_request,
};

#[cfg(test)]
mod tests;
