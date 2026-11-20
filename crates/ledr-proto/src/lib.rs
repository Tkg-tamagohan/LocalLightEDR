//! Shared core data types, IPC protocol, framing helpers, and layer boundary traits
//! for LocalEDR (`crates/ledr-proto`).
//!
//! This crate intentionally has minimal dependencies (`serde`, `serde_json`, `thiserror`)
//! so that all workspace layers and non-privileged unit tests can depend on it cleanly.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;

/// Named Pipe endpoint shared by `ledr-daemon`, `ledr-ui`, and `ledr-bridge-nm` (`L-09`, `AUTO-11`).
pub const IPC_PIPE_NAME: &str = r"\\.\pipe\localedr-ipc";

/// Maximum IPC / Native Messaging frame payload size in bytes (1 MiB, `AUTO-11`).
pub const IPC_MAX_FRAME_BYTES: usize = 1_048_576;

/// Protocol version advertised in IPC `Pong` handshakes.
pub const IPC_PROTOCOL_VERSION: u32 = 1;

/// Bounded capacity of the non-dropping high-priority event lane (`L-10`).
pub const HIGH_PRIORITY_CHANNEL_CAPACITY: usize = 1024;

/// Bounded capacity of the drop-oldest telemetry event lane (`L-10`).
pub const TELEMETRY_CHANNEL_CAPACITY: usize = 8192;

/// Maximum number of active processes kept in the in-memory `ActiveProcessTable`.
pub const ACTIVE_PROCESS_TABLE_CAPACITY: usize = 4096;

/// Maximum number of DNS entries retained in the in-memory `DnsResolutionCache` (`AUTO-05`).
pub const DNS_RESOLUTION_CACHE_CAPACITY: usize = 4096;

/// Default timeout in seconds before an unanswered alert transitions to `EXPIRED_SUSPENDED` (`L-07`).
pub const DEFAULT_ALERT_TIMEOUT_SECS: u64 = 60;

/// Default SQLite retention window in days (`L-11`).
pub const DEFAULT_TTL_RETENTION_DAYS: u32 = 14;

/// Minimum configurable SQLite retention window in days (`L-11`).
pub const MIN_TTL_RETENTION_DAYS: u32 = 7;

/// Maximum configurable SQLite retention window in days (`L-11`).
pub const MAX_TTL_RETENTION_DAYS: u32 = 30;

/// Maximum rows deleted per background TTL purge batch (`L-11`).
pub const TTL_PURGE_BATCH_LIMIT: usize = 500;

/// Maximum events buffered before flushing a SQLite write transaction (`AUTO-09`).
pub const STORE_BATCH_MAX_EVENTS: usize = 500;

/// Maximum interval in milliseconds between SQLite batch flushes (`AUTO-09`).
pub const STORE_BATCH_FLUSH_INTERVAL_MS: u64 = 1000;

/// Maximum graceful shutdown flush and `wal_checkpoint(TRUNCATE)` timeout in milliseconds (`AUTO-10`).
pub const SHUTDOWN_FLUSH_TIMEOUT_MS: u64 = 3000;

/// Protected data directory for daemon configuration, rules, and SQLite database (`L-16`).
pub const PROGRAM_DATA_DIR: &str = r"C:\ProgramData\LocalEDR";

/// Authorized install path for the interactive UI executable verified over IPC (`L-09`).
pub const AUTHORIZED_UI_EXE_PATH: &str = r"C:\Program Files\LocalEDR\ledr-ui.exe";

/// Authorized install path for the Chrome Native Messaging bridge executable verified over IPC (`L-09`).
pub const AUTHORIZED_BRIDGE_EXE_PATH: &str = r"C:\Program Files\LocalEDR\ledr-bridge-nm.exe";

/// Default lexicographically-first honeypot filename placed in protected user folders (`L-06`).
pub const HONEYPOT_DEFAULT_FILENAME: &str = "!00_LocalEDR_Canary_DoNotEdit.docx";

/// Critical Windows OS and LocalEDR process names that must never be suspended or terminated (`AUTO-02`).
pub const NEVER_SUSPEND_PROCESS_NAMES: &[&str] = &[
    "System",
    "Registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "MsMpEng.exe",
    "ledr-daemon.exe",
    "ledr-ui.exe",
    "ledr-bridge-nm.exe",
];

/// Returns `true` if `exe_name_or_path` matches a protected OS or LocalEDR binary in
/// [`NEVER_SUSPEND_PROCESS_NAMES`] (ASCII case-insensitive, matching on filename component).
pub fn is_never_suspend_process(exe_name_or_path: &str) -> bool {
    let file_name = exe_name_or_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(exe_name_or_path);
    NEVER_SUSPEND_PROCESS_NAMES
        .iter()
        .any(|protected| file_name.eq_ignore_ascii_case(protected))
}

/// Composite unique process identifier preventing PID reuse collisions (`AUTO-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub create_time_100ns: u64,
}

impl ProcessIdentity {
    /// Creates a new [`ProcessIdentity`] from a PID and 100ns Windows `FILETIME` creation timestamp.
    pub const fn new(pid: u32, create_time_100ns: u64) -> Self {
        Self {
            pid,
            create_time_100ns,
        }
    }

    /// Formats the composite identity as `"{pid}:{create_time_100ns}"`.
    pub fn instance_id(&self) -> String {
        format!("{}:{}", self.pid, self.create_time_100ns)
    }

    /// Parses a `"{pid}:{create_time_100ns}"` instance identifier back into a [`ProcessIdentity`].
    pub fn from_instance_id(s: &str) -> Option<Self> {
        let (pid_str, time_str) = s.split_once(':')?;
        let pid = pid_str.parse::<u32>().ok()?;
        let create_time_100ns = time_str.parse::<u64>().ok()?;
        Some(Self {
            pid,
            create_time_100ns,
        })
    }
}

impl fmt::Display for ProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.pid, self.create_time_100ns)
    }
}

/// Protected sensitive file or persistence location category (`L-05`, `L-06`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanaryCategory {
    CookieDb,
    LoginData,
    SshKey,
    CloudCredential,
    EnvFile,
    Honeypot,
    AutorunRegistry,
}

impl CanaryCategory {
    /// Returns the canonical database/log string representation of this category.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CookieDb => "cookie_db",
            Self::LoginData => "login_data",
            Self::SshKey => "ssh_key",
            Self::CloudCredential => "cloud_credential",
            Self::EnvFile => "env_file",
            Self::Honeypot => "honeypot",
            Self::AutorunRegistry => "autorun_registry",
        }
    }

    /// Parses a [`CanaryCategory`] from its canonical or PascalCase representation.
    pub fn parse_category(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cookie_db" | "cookiedb" => Some(Self::CookieDb),
            "login_data" | "logindata" => Some(Self::LoginData),
            "ssh_key" | "sshkey" => Some(Self::SshKey),
            "cloud_credential" | "cloudcredential" => Some(Self::CloudCredential),
            "env_file" | "envfile" => Some(Self::EnvFile),
            "honeypot" => Some(Self::Honeypot),
            "autorun_registry" | "autorunregistry" => Some(Self::AutorunRegistry),
            _ => None,
        }
    }
}

/// Telemetry source for evaluated script content (`AUTO-06`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScriptSource {
    Amsi,
    PowerShell4104,
}

impl ScriptSource {
    /// Returns the canonical string identifier for this script source.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Amsi => "amsi",
            Self::PowerShell4104 => "powershell_4104",
        }
    }
}

/// Bounded pipeline lane assignment for daemon event ingestion (`L-10`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventLane {
    HighPriority,
    Telemetry,
}

/// Normalized sensor event emitted from Layer 1 to Layer 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensorEvent {
    ProcessStart {
        identity: ProcessIdentity,
        parent_pid: u32,
        exe_path: String,
        command_line: String,
        user_sid: Option<String>,
    },
    ProcessStop {
        pid: u32,
        exit_time_100ns: u64,
        exit_code: u32,
    },
    DnsQuery {
        pid: u32,
        query_name: String,
        query_type: u16,
        resolved_ips: Vec<IpAddr>,
        timestamp_ms: i64,
    },
    NetworkConnect {
        pid: u32,
        protocol: u8,
        dst_ip: IpAddr,
        dst_port: u16,
        domain_hint: Option<String>,
        timestamp_ms: i64,
    },
    CanaryFileAccess {
        pid: u32,
        target_path: String,
        category: CanaryCategory,
        access_mask: u32,
        is_write_or_delete: bool,
        timestamp_ms: i64,
    },
    ScriptEvaluated {
        pid: u32,
        source: ScriptSource,
        script_content: String,
        timestamp_ms: i64,
    },
}

impl SensorEvent {
    /// Returns the OS process ID associated with this event.
    pub const fn pid(&self) -> u32 {
        match self {
            Self::ProcessStart { identity, .. } => identity.pid,
            Self::ProcessStop { pid, .. }
            | Self::DnsQuery { pid, .. }
            | Self::NetworkConnect { pid, .. }
            | Self::CanaryFileAccess { pid, .. }
            | Self::ScriptEvaluated { pid, .. } => *pid,
        }
    }

    /// Returns the default pipeline lane for this event before rule-based escalation (`L-10`).
    pub const fn default_lane(&self) -> EventLane {
        match self {
            Self::DnsQuery { .. } | Self::NetworkConnect { .. } => EventLane::Telemetry,
            Self::ProcessStart { .. }
            | Self::ProcessStop { .. }
            | Self::CanaryFileAccess { .. }
            | Self::ScriptEvaluated { .. } => EventLane::HighPriority,
        }
    }
}

/// Lifecycle state transitions for an alert (`L-07`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertStatus {
    Pending,
    ExpiredSuspended,
    ApprovedOnce,
    ApprovedRule,
    TerminatedBlocked,
    Dismissed,
}

impl AlertStatus {
    /// Returns the SQLite `status` column string representation.
    pub const fn as_db_str(&self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::ExpiredSuspended => "EXPIRED_SUSPENDED",
            Self::ApprovedOnce => "APPROVED_ONCE",
            Self::ApprovedRule => "APPROVED_RULE",
            Self::TerminatedBlocked => "TERMINATED_BLOCKED",
            Self::Dismissed => "DISMISSED",
        }
    }

    /// Parses an [`AlertStatus`] from its SQLite `status` column value.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "PENDING" => Some(Self::Pending),
            "EXPIRED_SUSPENDED" => Some(Self::ExpiredSuspended),
            "APPROVED_ONCE" => Some(Self::ApprovedOnce),
            "APPROVED_RULE" => Some(Self::ApprovedRule),
            "TERMINATED_BLOCKED" => Some(Self::TerminatedBlocked),
            "DISMISSED" => Some(Self::Dismissed),
            _ => None,
        }
    }

    /// Returns `true` if the alert has not yet been resolved by the user (`L-11`).
    pub const fn is_unresolved(&self) -> bool {
        matches!(self, Self::Pending | Self::ExpiredSuspended)
    }
}

/// Severity classification assigned to an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    /// Returns the SQLite `severity` column string representation.
    pub const fn as_db_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    /// Parses an [`AlertSeverity`] from its SQLite `severity` column value.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// User resolution action applied to an active or expired alert (`L-07`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertDecision {
    AllowOnce,
    AllowPermanent {
        use_signer_if_available: bool,
        allow_dest: Option<String>,
    },
    TerminateAndBlock {
        add_block_rule: bool,
    },
}

impl AlertDecision {
    /// Returns the terminal [`AlertStatus`] produced by applying this decision.
    pub const fn resulting_status(&self) -> AlertStatus {
        match self {
            Self::AllowOnce => AlertStatus::ApprovedOnce,
            Self::AllowPermanent { .. } => AlertStatus::ApprovedRule,
            Self::TerminateAndBlock { .. } => AlertStatus::TerminatedBlocked,
        }
    }
}

/// Scope of a persisted allowlist or blocklist policy rule (`L-04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleScope {
    FileCanaryAllow,
    NetworkAllow,
    NetworkBlock,
    ProcessAllow,
}

impl RuleScope {
    /// Returns the SQLite `scope` column string representation.
    pub const fn as_db_str(&self) -> &'static str {
        match self {
            Self::FileCanaryAllow => "FILE_CANARY_ALLOW",
            Self::NetworkAllow => "NETWORK_ALLOW",
            Self::NetworkBlock => "NETWORK_BLOCK",
            Self::ProcessAllow => "PROCESS_ALLOW",
        }
    }

    /// Parses a [`RuleScope`] from its SQLite `scope` column value.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "FILE_CANARY_ALLOW" => Some(Self::FileCanaryAllow),
            "NETWORK_ALLOW" => Some(Self::NetworkAllow),
            "NETWORK_BLOCK" => Some(Self::NetworkBlock),
            "PROCESS_ALLOW" => Some(Self::ProcessAllow),
            _ => None,
        }
    }
}

/// Authenticode signer identity extracted from a signed PE binary (`L-04`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthenticodeInfo {
    pub signer_subject: String,
    pub root_thumbprint: String,
}

/// Row representation for the SQLite `processes` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub process_instance_id: String,
    pub pid: u32,
    pub parent_instance_id: Option<String>,
    pub ppid: u32,
    pub exe_path: String,
    pub command_line: Option<String>,
    pub sha256: Option<String>,
    pub signer_subject: Option<String>,
    pub is_trusted_os: bool,
    pub user_sid: Option<String>,
    pub origin_url: Option<String>,
    pub created_at_ms: i64,
    pub exited_at_ms: Option<i64>,
}

/// Row representation for the SQLite `dns_queries` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryRecord {
    pub id: Option<i64>,
    pub timestamp_ms: i64,
    pub process_instance_id: String,
    pub query_name: String,
    pub query_type: u16,
    #[serde(default)]
    pub resolved_ips: Vec<String>,
    pub is_nrd: bool,
}

/// Row representation for the SQLite `network_events` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEventRecord {
    pub id: Option<i64>,
    pub timestamp_ms: i64,
    pub process_instance_id: String,
    pub protocol: u8,
    pub dst_ip: String,
    pub dst_port: u16,
    pub domain_hint: Option<String>,
    pub action: String,
}

/// Row representation for the SQLite `file_canary_events` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCanaryEventRecord {
    pub id: Option<i64>,
    pub timestamp_ms: i64,
    pub process_instance_id: String,
    pub target_path: String,
    pub category: CanaryCategory,
    pub access_mask: u32,
    pub action_taken: String,
}

/// Row representation for the SQLite `alerts` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRecord {
    pub alert_id: String,
    pub timestamp_ms: i64,
    pub severity: AlertSeverity,
    pub source_layer: String,
    pub rule_id: String,
    pub title: String,
    pub process_instance_id: Option<String>,
    pub process_suspended: bool,
    pub status: AlertStatus,
    pub context_json: String,
    pub resolved_at_ms: Option<i64>,
}

/// Row representation for the SQLite `allowlist_rules` table (`L-04`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistRuleRecord {
    pub rule_id: String,
    pub scope: RuleScope,
    pub exe_path_pattern: String,
    pub sha256: Option<String>,
    pub signer_subject: Option<String>,
    pub root_thumbprint: Option<String>,
    pub allowed_target: Option<String>,
    pub created_at_ms: i64,
    pub created_by: String,
}

/// Row representation for the SQLite `download_origins` table (`AUTO-12`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadOriginRecord {
    pub id: Option<i64>,
    pub file_path: String,
    pub sha256: Option<String>,
    pub tab_url: String,
    pub frame_url: Option<String>,
    pub referrer_url: Option<String>,
    pub downloaded_at_ms: i64,
}

/// Aggregated timeline snapshot served to the UI Flight Recorder view (`L-13`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderSnapshot {
    pub processes: Vec<ProcessRecord>,
    pub dns_queries: Vec<DnsQueryRecord>,
    pub network_events: Vec<NetworkEventRecord>,
    pub file_canary_events: Vec<FileCanaryEventRecord>,
    pub download_origins: Vec<DownloadOriginRecord>,
}

/// Runtime telemetry and channel saturation counters exposed by the daemon (`L-10`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineMetrics {
    pub high_priority_depth: usize,
    pub high_priority_capacity: usize,
    pub high_priority_processed: u64,
    pub telemetry_depth: usize,
    pub telemetry_capacity: usize,
    pub telemetry_processed: u64,
    pub telemetry_dropped: u64,
    pub active_processes: usize,
    pub pending_alerts: usize,
    pub uptime_secs: u64,
}

/// Abstraction boundary invoked by Layer 2 to drive Layer 1 OS containment actions (`L-01`).
pub trait ActiveDefenseController: Send + Sync {
    fn suspend_process(&self, target: &ProcessIdentity, include_children: bool) -> Result<(), String>;
    fn resume_process(&self, target: &ProcessIdentity) -> Result<(), String>;
    fn terminate_process(&self, target: &ProcessIdentity, include_children: bool) -> Result<(), String>;
    fn add_wfp_app_rule(
        &self,
        exe_path: &Path,
        remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> Result<u64, String>;
    fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String>;
}

/// Lifecycle trait implemented by platform-specific sensor backends (`L-01`).
pub trait SensorBackend: Send + Sync {
    fn start(&mut self) -> Result<(), String>;
    fn stop(&mut self) -> Result<(), String>;
}

/// Security event types reported by the Chrome Manifest V3 extension (`L-14`, `L-15`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrowserSecurityEventType {
    ClickFixPastejacking,
    NrdPasswordWarning,
    HomographWarning,
    DnrBlockedRequest,
}

/// Request messages exchanged over the `\\.\pipe\localedr-ipc` Named Pipe and Native Messaging bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcRequest {
    Ping,
    GetFlightRecorder {
        limit: usize,
        process_instance_id: Option<String>,
    },
    GetAlerts {
        status: Option<AlertStatus>,
        limit: usize,
    },
    ResolveAlert {
        alert_id: String,
        decision: AlertDecision,
    },
    UpsertRule {
        rule: AllowlistRuleRecord,
    },
    DeleteRule {
        rule_id: String,
    },
    ListRules {
        scope: Option<RuleScope>,
    },
    ReportDownloadOrigin {
        file_path: String,
        tab_url: String,
        frame_url: Option<String>,
        referrer_url: Option<String>,
        downloaded_at_ms: i64,
    },
    ReportBrowserEvent {
        event_type: BrowserSecurityEventType,
        url: String,
        details: Option<String>,
        timestamp_ms: i64,
    },
    GetPipelineMetrics,
    CheckDomainRisk {
        domain: String,
    },
}

impl IpcRequest {
    /// Returns `true` if this request mutates daemon state or security policy and therefore
    /// requires caller verification against [`AUTHORIZED_UI_EXE_PATH`] (`L-09`).
    pub const fn requires_ui_authorization(&self) -> bool {
        matches!(
            self,
            Self::ResolveAlert { .. } | Self::UpsertRule { .. } | Self::DeleteRule { .. }
        )
    }
}

/// Response messages returned by `ledr-daemon` over the Named Pipe IPC channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcResponse {
    Pong {
        daemon_version: String,
        protocol_version: u32,
    },
    FlightRecorder(FlightRecorderSnapshot),
    Alerts(Vec<AlertRecord>),
    Rules(Vec<AllowlistRuleRecord>),
    Metrics(PipelineMetrics),
    DomainRisk {
        domain: String,
        is_nrd: bool,
        is_homograph: bool,
        matched_brand: Option<String>,
    },
    Ack {
        message: String,
    },
    Error {
        code: String,
        message: String,
    },
}

/// Errors encountered while encoding, decoding, reading, or writing 4-byte LE IPC frames.
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("IPC frame size {size} bytes exceeds maximum allowed {max} bytes")]
    FrameTooLarge { size: usize, max: usize },
    #[error("empty IPC frame (0 bytes payload)")]
    EmptyFrame,
    #[error("truncated IPC frame: expected {expected} bytes, got {actual} bytes")]
    TruncatedFrame { expected: usize, actual: usize },
    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Encodes `msg` into a 4-byte little-endian length-prefixed UTF-8 JSON frame (`L-09`, `AUTO-11`).
pub fn encode_ipc_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    let json = serde_json::to_vec(msg)?;
    if json.len() > IPC_MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge {
            size: json.len(),
            max: IPC_MAX_FRAME_BYTES,
        });
    }
    let len = u32::try_from(json.len()).map_err(|_| FrameError::FrameTooLarge {
        size: json.len(),
        max: IPC_MAX_FRAME_BYTES,
    })?;
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

/// Decodes a single 4-byte little-endian length-prefixed UTF-8 JSON frame from `frame`.
pub fn decode_ipc_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, FrameError> {
    if frame.len() < 4 {
        return Err(FrameError::TruncatedFrame {
            expected: 4,
            actual: frame.len(),
        });
    }
    let len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len == 0 {
        return Err(FrameError::EmptyFrame);
    }
    if len > IPC_MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge {
            size: len,
            max: IPC_MAX_FRAME_BYTES,
        });
    }
    let payload = &frame[4..];
    if payload.len() < len {
        return Err(FrameError::TruncatedFrame {
            expected: 4 + len,
            actual: frame.len(),
        });
    }
    serde_json::from_slice(&payload[..len]).map_err(FrameError::from)
}

/// Reads and deserializes one 4-byte little-endian length-prefixed IPC frame from `reader`.
pub fn read_ipc_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, FrameError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Err(FrameError::EmptyFrame);
    }
    if len > IPC_MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge {
            size: len,
            max: IPC_MAX_FRAME_BYTES,
        });
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(FrameError::from)
}

/// Encodes `msg` and writes the complete frame to `writer`, flushing immediately.
pub fn write_ipc_frame<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> Result<(), FrameError> {
    let frame = encode_ipc_frame(msg)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn proto_01_process_identity_roundtrip() {
        let ident = ProcessIdentity::new(4242, 133_765_432_101_234_567);
        let id = ident.instance_id();
        assert_eq!(id, "4242:133765432101234567");
        assert_eq!(ident.to_string(), id);
        assert_eq!(ProcessIdentity::from_instance_id(&id), Some(ident));

        let json = serde_json::to_string(&ident).expect("serialize ProcessIdentity");
        let parsed: ProcessIdentity =
            serde_json::from_str(&json).expect("deserialize ProcessIdentity");
        assert_eq!(parsed, ident);

        for invalid in ["", "4242", "abc:123", "4242:xyz", "1:2:3", "-1:100"] {
            assert_eq!(ProcessIdentity::from_instance_id(invalid), None);
        }
    }

    #[test]
    fn proto_02_sensor_event_json_and_lane() {
        let events = [
            (
                SensorEvent::ProcessStart {
                    identity: ProcessIdentity::new(100, 999),
                    parent_pid: 4,
                    exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
                    command_line: "cmd.exe /c whoami".to_string(),
                    user_sid: Some("S-1-5-21-1000".to_string()),
                },
                100,
                EventLane::HighPriority,
            ),
            (
                SensorEvent::ProcessStop {
                    pid: 100,
                    exit_time_100ns: 1200,
                    exit_code: 0,
                },
                100,
                EventLane::HighPriority,
            ),
            (
                SensorEvent::DnsQuery {
                    pid: 200,
                    query_name: "example.com".to_string(),
                    query_type: 1,
                    resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                    timestamp_ms: 1_700_000_000_000,
                },
                200,
                EventLane::Telemetry,
            ),
            (
                SensorEvent::NetworkConnect {
                    pid: 201,
                    protocol: 6,
                    dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                    dst_port: 443,
                    domain_hint: Some("example.com".to_string()),
                    timestamp_ms: 1_700_000_000_100,
                },
                201,
                EventLane::Telemetry,
            ),
            (
                SensorEvent::CanaryFileAccess {
                    pid: 300,
                    target_path: r"C:\Users\dev\.ssh\id_ed25519".to_string(),
                    category: CanaryCategory::SshKey,
                    access_mask: 0x0012_0089,
                    is_write_or_delete: false,
                    timestamp_ms: 1_700_000_000_200,
                },
                300,
                EventLane::HighPriority,
            ),
            (
                SensorEvent::ScriptEvaluated {
                    pid: 400,
                    source: ScriptSource::PowerShell4104,
                    script_content: "Write-Host 'test'".to_string(),
                    timestamp_ms: 1_700_000_000_300,
                },
                400,
                EventLane::HighPriority,
            ),
        ];

        for (event, expected_pid, expected_lane) in events {
            assert_eq!(event.pid(), expected_pid);
            assert_eq!(event.default_lane(), expected_lane);
            let json = serde_json::to_string(&event).expect("serialize SensorEvent");
            let roundtrip: SensorEvent =
                serde_json::from_str(&json).expect("deserialize SensorEvent");
            assert_eq!(roundtrip, event);
        }

        let categories = [
            CanaryCategory::CookieDb,
            CanaryCategory::LoginData,
            CanaryCategory::SshKey,
            CanaryCategory::CloudCredential,
            CanaryCategory::EnvFile,
            CanaryCategory::Honeypot,
            CanaryCategory::AutorunRegistry,
        ];
        for cat in categories {
            assert_eq!(CanaryCategory::parse_category(cat.as_str()), Some(cat));
        }
        assert_eq!(CanaryCategory::parse_category("unknown_cat"), None);
    }

    #[test]
    fn proto_03_alert_status_and_decision() {
        let statuses = [
            (AlertStatus::Pending, "PENDING", true),
            (AlertStatus::ExpiredSuspended, "EXPIRED_SUSPENDED", true),
            (AlertStatus::ApprovedOnce, "APPROVED_ONCE", false),
            (AlertStatus::ApprovedRule, "APPROVED_RULE", false),
            (AlertStatus::TerminatedBlocked, "TERMINATED_BLOCKED", false),
            (AlertStatus::Dismissed, "DISMISSED", false),
        ];
        for (status, db_str, unresolved) in statuses {
            assert_eq!(status.as_db_str(), db_str);
            assert_eq!(AlertStatus::from_db_str(db_str), Some(status));
            assert_eq!(status.is_unresolved(), unresolved);
        }
        assert_eq!(AlertStatus::from_db_str("UNKNOWN"), None);

        for sev in [
            AlertSeverity::Low,
            AlertSeverity::Medium,
            AlertSeverity::High,
            AlertSeverity::Critical,
        ] {
            assert_eq!(AlertSeverity::from_db_str(sev.as_db_str()), Some(sev));
        }

        for scope in [
            RuleScope::FileCanaryAllow,
            RuleScope::NetworkAllow,
            RuleScope::NetworkBlock,
            RuleScope::ProcessAllow,
        ] {
            assert_eq!(RuleScope::from_db_str(scope.as_db_str()), Some(scope));
        }

        let decisions = [
            (AlertDecision::AllowOnce, AlertStatus::ApprovedOnce),
            (
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: Some("api.example.com".to_string()),
                },
                AlertStatus::ApprovedRule,
            ),
            (
                AlertDecision::TerminateAndBlock {
                    add_block_rule: true,
                },
                AlertStatus::TerminatedBlocked,
            ),
        ];
        for (decision, expected_status) in decisions {
            assert_eq!(decision.resulting_status(), expected_status);
            let json = serde_json::to_string(&decision).expect("serialize AlertDecision");
            let parsed: AlertDecision =
                serde_json::from_str(&json).expect("deserialize AlertDecision");
            assert_eq!(parsed, decision);
        }

        let snapshot = FlightRecorderSnapshot {
            processes: vec![ProcessRecord {
                process_instance_id: "1234:5678".to_string(),
                pid: 1234,
                parent_instance_id: Some("4:1".to_string()),
                ppid: 4,
                exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                    .to_string(),
                command_line: Some("powershell -NoP -W Hidden".to_string()),
                sha256: Some("deadbeef".to_string()),
                signer_subject: Some("Microsoft Windows".to_string()),
                is_trusted_os: true,
                user_sid: Some("S-1-5-18".to_string()),
                origin_url: None,
                created_at_ms: 1_700_000_000_000,
                exited_at_ms: None,
            }],
            dns_queries: vec![DnsQueryRecord {
                id: Some(1),
                timestamp_ms: 1_700_000_000_010,
                process_instance_id: "1234:5678".to_string(),
                query_name: "example.org".to_string(),
                query_type: 1,
                resolved_ips: vec!["93.184.216.34".to_string()],
                is_nrd: false,
            }],
            network_events: vec![NetworkEventRecord {
                id: Some(1),
                timestamp_ms: 1_700_000_000_020,
                process_instance_id: "1234:5678".to_string(),
                protocol: 6,
                dst_ip: "93.184.216.34".to_string(),
                dst_port: 443,
                domain_hint: Some("example.org".to_string()),
                action: "ALLOW".to_string(),
            }],
            file_canary_events: vec![FileCanaryEventRecord {
                id: Some(1),
                timestamp_ms: 1_700_000_000_030,
                process_instance_id: "1234:5678".to_string(),
                target_path: r"C:\Users\dev\.ssh\id_rsa".to_string(),
                category: CanaryCategory::SshKey,
                access_mask: 0x0012_0089,
                action_taken: "SUSPEND".to_string(),
            }],
            download_origins: vec![DownloadOriginRecord {
                id: Some(1),
                file_path: r"C:\Users\dev\Downloads\tool.exe".to_string(),
                sha256: Some("cafe".to_string()),
                tab_url: "https://example.org/download".to_string(),
                frame_url: None,
                referrer_url: Some("https://example.org/".to_string()),
                downloaded_at_ms: 1_699_999_999_000,
            }],
        };
        let snap_json = serde_json::to_string(&snapshot).expect("serialize snapshot");
        let snap_parsed: FlightRecorderSnapshot =
            serde_json::from_str(&snap_json).expect("deserialize snapshot");
        assert_eq!(snap_parsed, snapshot);

        let alert = AlertRecord {
            alert_id: "alrt-1".to_string(),
            timestamp_ms: 1_700_000_000_030,
            severity: AlertSeverity::Critical,
            source_layer: "layer1".to_string(),
            rule_id: "canary_ssh".to_string(),
            title: "SSH key access".to_string(),
            process_instance_id: Some("1234:5678".to_string()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: "{}".to_string(),
            resolved_at_ms: None,
        };
        let rule = AllowlistRuleRecord {
            rule_id: "rule-1".to_string(),
            scope: RuleScope::ProcessAllow,
            exe_path_pattern: r"C:\Program Files\Example\app.exe".to_string(),
            sha256: None,
            signer_subject: Some("Example Corp".to_string()),
            root_thumbprint: Some("00112233".to_string()),
            allowed_target: None,
            created_at_ms: 1_700_000_000_050,
            created_by: "user".to_string(),
        };
        let auth = AuthenticodeInfo {
            signer_subject: "Example Corp".to_string(),
            root_thumbprint: "00112233".to_string(),
        };
        let metrics = PipelineMetrics {
            high_priority_capacity: HIGH_PRIORITY_CHANNEL_CAPACITY,
            telemetry_capacity: TELEMETRY_CHANNEL_CAPACITY,
            ..PipelineMetrics::default()
        };
        assert_eq!(
            serde_json::from_str::<AlertRecord>(&serde_json::to_string(&alert).unwrap()).unwrap(),
            alert
        );
        assert_eq!(
            serde_json::from_str::<AllowlistRuleRecord>(&serde_json::to_string(&rule).unwrap())
                .unwrap(),
            rule
        );
        assert_eq!(
            serde_json::from_str::<AuthenticodeInfo>(&serde_json::to_string(&auth).unwrap())
                .unwrap(),
            auth
        );
        assert_eq!(
            serde_json::from_str::<PipelineMetrics>(&serde_json::to_string(&metrics).unwrap())
                .unwrap(),
            metrics
        );
    }

    #[test]
    fn proto_04_ipc_frame_roundtrip_and_limit() {
        let req = IpcRequest::ResolveAlert {
            alert_id: "alert-001".to_string(),
            decision: AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        };
        assert!(req.requires_ui_authorization());
        assert!(!IpcRequest::Ping.requires_ui_authorization());

        let frame = encode_ipc_frame(&req).expect("encode IPC request");
        let len_prefix = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(len_prefix, frame.len() - 4);
        let decoded_req: IpcRequest = decode_ipc_frame(&frame).expect("decode IPC request");
        assert_eq!(decoded_req, req);

        let resp = IpcResponse::Pong {
            daemon_version: "0.1.0".to_string(),
            protocol_version: IPC_PROTOCOL_VERSION,
        };
        let mut buf = Vec::new();
        write_ipc_frame(&mut buf, &resp).expect("write IPC response");
        let mut cursor = Cursor::new(buf);
        let read_resp: IpcResponse = read_ipc_frame(&mut cursor).expect("read IPC response");
        assert_eq!(read_resp, resp);

        // Enforce 1 MiB limit on encode
        let oversized = IpcRequest::ReportBrowserEvent {
            event_type: BrowserSecurityEventType::ClickFixPastejacking,
            url: "https://example.invalid/".to_string(),
            details: Some("A".repeat(IPC_MAX_FRAME_BYTES + 1)),
            timestamp_ms: 1_700_000_000_000,
        };
        assert!(matches!(
            encode_ipc_frame(&oversized),
            Err(FrameError::FrameTooLarge { .. })
        ));

        // Enforce 1 MiB limit on decode/read without allocating oversized buffer
        let too_large_len = (IPC_MAX_FRAME_BYTES as u32 + 1).to_le_bytes();
        assert!(matches!(
            decode_ipc_frame::<IpcRequest>(&too_large_len),
            Err(FrameError::FrameTooLarge { .. })
        ));
        let mut bad_reader = Cursor::new(too_large_len.to_vec());
        assert!(matches!(
            read_ipc_frame::<_, IpcRequest>(&mut bad_reader),
            Err(FrameError::FrameTooLarge { .. })
        ));

        // Reject 0-byte and truncated frames
        assert!(matches!(
            decode_ipc_frame::<IpcRequest>(&0u32.to_le_bytes()),
            Err(FrameError::EmptyFrame)
        ));
        assert!(matches!(
            decode_ipc_frame::<IpcRequest>(&[1, 2]),
            Err(FrameError::TruncatedFrame {
                expected: 4,
                actual: 2
            })
        ));
    }

    #[test]
    fn proto_05_never_suspend_process_names() {
        for required in [
            "System",
            "Registry",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
            "svchost.exe",
            "dwm.exe",
            "explorer.exe",
            "MsMpEng.exe",
            "ledr-daemon.exe",
            "ledr-ui.exe",
            "ledr-bridge-nm.exe",
        ] {
            assert!(
                NEVER_SUSPEND_PROCESS_NAMES.contains(&required),
                "missing protected process {required}"
            );
            assert!(is_never_suspend_process(required));
        }

        assert!(is_never_suspend_process("LSASS.EXE"));
        assert!(is_never_suspend_process(r"C:\Windows\System32\csrss.exe"));
        assert!(is_never_suspend_process(AUTHORIZED_UI_EXE_PATH));
        assert!(is_never_suspend_process(AUTHORIZED_BRIDGE_EXE_PATH));
        assert!(!is_never_suspend_process("ledr-sim.exe"));
        assert!(!is_never_suspend_process(r"C:\Users\test\Downloads\evil.exe"));
    }
}
