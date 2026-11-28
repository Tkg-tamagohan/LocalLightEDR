//! Pure WFP filter specifications, constants, and path/IP validation (`L-03`, `AUTO-02`, `AUTO-04`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ledr_proto::is_never_suspend_process;
use windows::core::GUID;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
};

/// Dedicated WFP provider GUID owned by LocalEDR.
pub const LEDR_WFP_PROVIDER_GUID: GUID = GUID::from_u128(0x8d5b3a72_4c1e_4f9b_9a23_7e61b50c3d11);

/// Dedicated WFP SubLayer GUID owned by LocalEDR (`AUTO-04`).
pub const LEDR_WFP_SUBLAYER_GUID: GUID = GUID::from_u128(0x2f4a8e19_7b3c_4d5e_8f12_6c9a0b3e4f22);

/// SubLayer priority weight registered in BFE.
pub const LEDR_WFP_SUBLAYER_WEIGHT: u16 = 0x8000;

/// Filter weight for loopback Permit filters (`127.0.0.0/8` and `::1/128`) — highest priority
/// within LocalEDR's SubLayer so app-wide outbound blocks never break localhost IPC/dev servers
/// (registered without `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` so other sublayers keep veto rights).
pub const WFP_WEIGHT_LOOPBACK_PERMIT: u8 = 15;

/// Filter weight for an explicit remote-IP Block filter (and package-wide Block filters so
/// `deny-overrides-allow` holds even when explicit remote-IP Permits exist for the shared host).
pub const WFP_WEIGHT_BLOCK_SPECIFIC: u8 = 14;

/// Filter weight for a package-scoped (`ALE_APP_ID` + `ALE_PACKAGE_ID`) Block filter (`14`,
/// co-equal with explicit remote-IP Block and strictly above IP/package Permits).
pub const WFP_WEIGHT_BLOCK_PACKAGE: u8 = 14;

/// Filter weight for an explicit remote-IP Permit filter (overrides package-wide Permit and
/// pre-emptive app-wide block while explicit app-wide `NetworkBlock` rules suppress Permits).
pub const WFP_WEIGHT_PERMIT_SPECIFIC: u8 = 13;

/// Filter weight for a package-scoped (`ALE_APP_ID` + `ALE_PACKAGE_ID`) Permit filter (`12`,
/// above app-wide `TransientContainment` / `Preemptive` Block `11` so another package's transient
/// containment on a shared host never breaks already-allowed packages, while explicit app-wide
/// `NetworkBlock` reconciliation/enforcement removes conflicting scoped Permits).
pub const WFP_WEIGHT_PERMIT_PACKAGE: u8 = 12;

/// Filter weight for an app-wide Block filter (overrides app-wide Permit).
pub const WFP_WEIGHT_BLOCK_APP: u8 = 11;

/// Filter weight for an app-wide Permit filter.
pub const WFP_WEIGHT_PERMIT_APP: u8 = 10;

/// WFP ALE outbound connect layer targeted by a single OS filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpLayer {
    AleAuthConnectV4,
    AleAuthConnectV6,
}

impl WfpLayer {
    /// Returns the Win32 WFP layer GUID for this layer.
    pub const fn layer_guid(self) -> GUID {
        match self {
            Self::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Self::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        }
    }
}

/// Action applied by a WFP filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpFilterAction {
    Block,
    Permit,
}

/// Remote IP condition encoded in WFP native representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpRemoteAddress {
    /// IPv4 address stored in host byte order (`FWP_UINT32`).
    V4HostOrder(u32),
    /// IPv6 address stored in network byte order (`FWP_BYTE_ARRAY16_TYPE`).
    V6NetworkOrder([u8; 16]),
}

/// Canonicalizes an [`IpAddr`] for WFP layer routing by unwrapping IPv4-mapped IPv6 addresses
/// (`::ffff:a.b.c.d`) into [`IpAddr::V4`], matching Windows BFE dual-stack ALE classification.
pub fn canonical_wfp_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

impl WfpRemoteAddress {
    /// Converts a standard [`IpAddr`] into its WFP condition representation.
    pub fn from_ip(ip: IpAddr) -> Self {
        match canonical_wfp_ip(ip) {
            IpAddr::V4(v4) => Self::V4HostOrder(u32::from(v4)),
            IpAddr::V6(v6) => Self::V6NetworkOrder(v6.octets()),
        }
    }
}

/// Complete, pure specification of a single WFP dynamic filter before Win32 marshaling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilterSpec {
    pub layer: WfpLayer,
    pub sublayer_guid: GUID,
    pub provider_guid: GUID,
    pub exe_path: String,
    pub package_sid: Option<String>,
    pub remote_addr: Option<WfpRemoteAddress>,
    pub action: WfpFilterAction,
    pub weight: u8,
    pub dynamic_session_required: bool,
}

/// Masked remote-address condition for a SubLayer-wide loopback Permit filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpLoopbackCondition {
    /// IPv4 address + netmask in host byte order (`FWP_V4_ADDR_MASK`).
    V4AddrMask { addr: u32, mask: u32 },
    /// IPv6 address in network byte order + prefix length (`FWP_V6_ADDR_MASK`).
    V6AddrMask { addr: [u8; 16], prefix_length: u8 },
}

/// Complete, pure specification of a non-persistent loopback Permit filter registered during
/// dynamic WFP session initialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpLoopbackFilterSpec {
    pub layer: WfpLayer,
    pub sublayer_guid: GUID,
    pub provider_guid: GUID,
    pub condition: WfpLoopbackCondition,
    pub action: WfpFilterAction,
    pub weight: u8,
    pub persistent: bool,
    pub clear_action_right: bool,
    pub dynamic_session_required: bool,
}

/// Builds the two non-persistent IPv4 (`127.0.0.0/8`) and IPv6 (`::1/128`) loopback Permit
/// filter specs registered inside LocalEDR's dynamic WFP SubLayer (`L-03`, `AUTO-04`).
pub fn build_loopback_permit_filter_specs() -> [WfpLoopbackFilterSpec; 2] {
    [
        WfpLoopbackFilterSpec {
            layer: WfpLayer::AleAuthConnectV4,
            sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
            provider_guid: LEDR_WFP_PROVIDER_GUID,
            condition: WfpLoopbackCondition::V4AddrMask {
                addr: 0x7F00_0000,
                mask: 0xFF00_0000,
            },
            action: WfpFilterAction::Permit,
            weight: WFP_WEIGHT_LOOPBACK_PERMIT,
            persistent: false,
            clear_action_right: false,
            dynamic_session_required: true,
        },
        WfpLoopbackFilterSpec {
            layer: WfpLayer::AleAuthConnectV6,
            sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
            provider_guid: LEDR_WFP_PROVIDER_GUID,
            condition: WfpLoopbackCondition::V6AddrMask {
                addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                prefix_length: 128,
            },
            action: WfpFilterAction::Permit,
            weight: WFP_WEIGHT_LOOPBACK_PERMIT,
            persistent: false,
            clear_action_right: false,
            dynamic_session_required: true,
        },
    ]
}

/// Computes the deterministic `FWP_UINT8` filter weight (`0..=15`) for `(remote_ip, allow)`.
pub const fn compute_filter_weight(has_remote_ip: bool, allow: bool) -> u8 {
    compute_scoped_filter_weight(has_remote_ip, false, allow)
}

/// Computes the deterministic `FWP_UINT8` filter weight (`0..=15`) for
/// `(has_remote_ip, has_package_sid, allow)`.
pub const fn compute_scoped_filter_weight(
    has_remote_ip: bool,
    has_package_sid: bool,
    allow: bool,
) -> u8 {
    match (has_remote_ip, has_package_sid, allow) {
        (true, _, false) => WFP_WEIGHT_BLOCK_SPECIFIC,
        (false, true, false) => WFP_WEIGHT_BLOCK_PACKAGE,
        (true, _, true) => WFP_WEIGHT_PERMIT_SPECIFIC,
        (false, true, true) => WFP_WEIGHT_PERMIT_PACKAGE,
        (false, false, false) => WFP_WEIGHT_BLOCK_APP,
        (false, false, true) => WFP_WEIGHT_PERMIT_APP,
    }
}

/// Validates and canonicalizes an AppContainer package SID (`S-1-15-2-...`) for WFP
/// `FWPM_CONDITION_ALE_PACKAGE_ID` (`FWP_SID`) filtering (`FU-P4-03`).
pub fn validate_wfp_package_sid(package_sid: &str) -> Result<String, String> {
    let trimmed = package_sid.trim();
    if trimmed.is_empty()
        || trimmed != package_sid
        || trimmed.len() > 256
        || !trimmed.is_ascii()
    {
        return Err(format!(
            "refusing WFP scoped rule: invalid AppContainer SID `{package_sid}`"
        ));
    }
    let Some(rest) = trimmed
        .get(..9)
        .filter(|prefix| prefix.eq_ignore_ascii_case("S-1-15-2-"))
        .map(|_| &trimmed[9..])
    else {
        return Err(format!(
            "refusing WFP scoped rule: SID `{package_sid}` is not an AppContainer S-1-15-2-* SID"
        ));
    };
    if rest.is_empty()
        || !rest
            .split('-')
            .all(|sub| !sub.is_empty() && sub.bytes().all(|b| b.is_ascii_digit()) && sub.parse::<u32>().is_ok())
    {
        return Err(format!(
            "refusing WFP scoped rule: malformed AppContainer SID `{package_sid}`"
        ));
    }
    Ok(trimmed.to_string())
}

/// Normalizes a Windows path for `FwpmGetAppIdFromFileName0` (stripping extended-length `\\?\`
/// prefixes and unifying `/` to `\`).
pub fn normalize_wfp_exe_path(exe_path: &Path) -> String {
    let raw = exe_path.to_string_lossy();
    let trimmed = raw.trim().replace('/', "\\");
    if let Some(rest) = trimmed
        .get(..8)
        .filter(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
        .map(|_| format!(r"\\{}", &trimmed[8..]))
    {
        rest
    } else if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\"))
    {
        trimmed[4..].to_string()
    } else {
        trimmed
    }
}

/// Validates that `exe_path` is safe and eligible for a WFP app-ID filter (`AUTO-02`).
pub fn validate_wfp_rule_request(exe_path: &Path, allow: bool) -> Result<String, String> {
    let normalized = normalize_wfp_exe_path(exe_path);
    if normalized.is_empty() {
        return Err("refusing WFP rule: executable path is empty".to_string());
    }
    if normalized.contains('*') || normalized.contains('?') {
        return Err(format!(
            "refusing WFP rule for wildcard path `{normalized}`: FwpmGetAppIdFromFileName0 requires a concrete file path"
        ));
    }
    let guard_check = normalized.trim_end_matches(['.', ' ']);
    if !allow && (is_never_suspend_process(&normalized) || is_never_suspend_process(guard_check)) {
        return Err(format!(
            "refusing WFP block rule for protected process `{normalized}` (AUTO-02)"
        ));
    }
    Ok(normalized)
}

/// Builds the 1 (single-stack remote IP) or 2 (dual-stack app-wide) [`WfpFilterSpec`] items
/// registered atomically under one opaque `u64` rule handle.
pub fn build_wfp_filter_specs(
    exe_path: &Path,
    remote_ip: Option<IpAddr>,
    allow: bool,
) -> Result<Vec<WfpFilterSpec>, String> {
    build_wfp_scoped_filter_specs(exe_path, None, remote_ip, allow)
}

/// Builds 1 or 2 [`WfpFilterSpec`] items optionally scoped by `FWPM_CONDITION_ALE_PACKAGE_ID`
/// (`package_sid`) for atomic registration under one opaque `u64` rule handle (`FU-P4-03`).
pub fn build_wfp_scoped_filter_specs(
    exe_path: &Path,
    package_sid: Option<&str>,
    remote_ip: Option<IpAddr>,
    allow: bool,
) -> Result<Vec<WfpFilterSpec>, String> {
    let normalized = validate_wfp_rule_request(exe_path, allow)?;
    let validated_sid = package_sid.map(validate_wfp_package_sid).transpose()?;
    let action = if allow {
        WfpFilterAction::Permit
    } else {
        WfpFilterAction::Block
    };
    let canonical_remote = remote_ip.map(canonical_wfp_ip);
    let weight = compute_scoped_filter_weight(
        canonical_remote.is_some(),
        validated_sid.is_some(),
        allow,
    );

    let specs = match canonical_remote {
        Some(IpAddr::V4(v4)) => vec![WfpFilterSpec {
            layer: WfpLayer::AleAuthConnectV4,
            sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
            provider_guid: LEDR_WFP_PROVIDER_GUID,
            exe_path: normalized,
            package_sid: validated_sid,
            remote_addr: Some(WfpRemoteAddress::from_ip(IpAddr::V4(v4))),
            action,
            weight,
            dynamic_session_required: true,
        }],
        Some(IpAddr::V6(v6)) => vec![WfpFilterSpec {
            layer: WfpLayer::AleAuthConnectV6,
            sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
            provider_guid: LEDR_WFP_PROVIDER_GUID,
            exe_path: normalized,
            package_sid: validated_sid,
            remote_addr: Some(WfpRemoteAddress::from_ip(IpAddr::V6(v6))),
            action,
            weight,
            dynamic_session_required: true,
        }],
        None => vec![
            WfpFilterSpec {
                layer: WfpLayer::AleAuthConnectV4,
                sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
                provider_guid: LEDR_WFP_PROVIDER_GUID,
                exe_path: normalized.clone(),
                package_sid: validated_sid.clone(),
                remote_addr: None,
                action,
                weight,
                dynamic_session_required: true,
            },
            WfpFilterSpec {
                layer: WfpLayer::AleAuthConnectV6,
                sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
                provider_guid: LEDR_WFP_PROVIDER_GUID,
                exe_path: normalized,
                package_sid: validated_sid,
                remote_addr: None,
                action,
                weight,
                dynamic_session_required: true,
            },
        ],
    };

    Ok(specs)
}

/// Helper converting an IPv4 address into WFP host-order `u32` (for diagnostics/tests).
pub const fn ipv4_to_wfp_host_order(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

/// Helper converting an IPv6 address into WFP network-order bytes (for diagnostics/tests).
pub const fn ipv6_to_wfp_network_order(ip: Ipv6Addr) -> [u8; 16] {
    ip.octets()
}
