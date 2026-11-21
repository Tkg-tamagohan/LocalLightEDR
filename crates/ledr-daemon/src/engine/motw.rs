//! Mark-of-the-Web (MOTW) 3-stage process attribution, download origin recording,
//! and `LAYER_4_BROWSER` security event ingestion with bounded deduplication (`Phase 4A`).

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::Ordering;

use ledr_proto::{
    AlertRecord, AlertSeverity, AlertStatus, BrowserSecurityEventType, DownloadOriginRecord,
};
use ledr_rules::{classify_outbound_risk, OutboundRiskClass};
use ledr_sensor_win::MotwZoneInfo;
use ledr_store::StoreError;
use uuid::Uuid;

use super::{current_unix_ms, DaemonEngine};

/// Maximum file size (128 MiB) hashed with SHA-256 on `ReportDownloadOrigin` and Stage 2 lookup.
pub const MAX_DOWNLOAD_HASH_BYTES: u64 = 128 * 1024 * 1024;

/// Maximum byte length retained for `ReportBrowserEvent` `details` payload (8 KiB).
pub const MAX_BROWSER_EVENT_DETAILS_BYTES: usize = 8 * 1024;

pub(super) const BROWSER_EVENT_DEDUP_CAPACITY: usize = 256;
pub(super) const BROWSER_EVENT_DEDUP_WINDOW_MS: i64 = 30_000;

/// Abstraction for reading NTFS `:Zone.Identifier` MOTW metadata (`Phase 4A` DI boundary).
pub trait MotwInspector: Send + Sync {
    fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo>;
}

/// Default Windows MOTW inspector backed by [`ledr_sensor_win::read_zone_identifier`].
#[derive(Debug, Default)]
pub struct WindowsMotwInspector;

impl WindowsMotwInspector {
    pub fn new() -> Self {
        Self
    }
}

impl MotwInspector for WindowsMotwInspector {
    fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
        ledr_sensor_win::read_zone_identifier(path)
    }
}

/// Attribution stage that matched a launched binary to a browser/Internet download origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotwMatchStage {
    DownloadPath,
    DownloadSha256,
    ZoneIdentifierAds,
}

impl MotwMatchStage {
    /// Returns the canonical snake_case tag recorded in `alerts.context_json.motw_source`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DownloadPath => "download_path",
            Self::DownloadSha256 => "download_sha256",
            Self::ZoneIdentifierAds => "zone_identifier_ads",
        }
    }
}

/// Resolved MOTW provenance metadata for a launched process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MotwAttribution {
    pub origin_url: String,
    pub referrer_url: Option<String>,
    pub frame_url: Option<String>,
    pub sha256: Option<String>,
    pub zone_id: Option<u32>,
    pub stage: MotwMatchStage,
}

/// Result of reporting a `LAYER_4_BROWSER` security event via [`DaemonEngine::record_browser_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserEventOutcome {
    Recorded(AlertRecord),
    Deduplicated,
}

/// Errors returned when validating or persisting browser download origins or browser events.
#[derive(Debug)]
pub enum BrowserReportError {
    Invalid(String),
    Store(StoreError),
}

impl std::fmt::Display for BrowserReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(msg) => f.write_str(msg),
            Self::Store(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BrowserReportError {}

impl From<StoreError> for BrowserReportError {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

/// Bounded FIFO deduplication cache suppressing repeated `(BrowserSecurityEventType, normalized_url)`
/// reports within `window_ms` (30 seconds, max 256 keys).
#[derive(Debug, Default)]
pub(super) struct BrowserEventDedupCache {
    capacity: usize,
    window_ms: i64,
    last_seen: HashMap<(BrowserSecurityEventType, String), i64>,
    insertion_order: VecDeque<(BrowserSecurityEventType, String)>,
}

impl BrowserEventDedupCache {
    pub(super) fn new(capacity: usize, window_ms: i64) -> Self {
        Self {
            capacity: capacity.max(1),
            window_ms: window_ms.max(1),
            last_seen: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    pub(super) fn should_emit(
        &mut self,
        event_type: BrowserSecurityEventType,
        norm_url: &str,
        ts_ms: i64,
    ) -> bool {
        let key = (event_type, norm_url.to_string());
        if let Some(&prev_ts) = self.last_seen.get(&key) {
            if ts_ms >= prev_ts {
                if ts_ms.saturating_sub(prev_ts) < self.window_ms {
                    return false;
                }
                self.last_seen.insert(key, ts_ms);
                return true;
            }
            if prev_ts.saturating_sub(ts_ms) < self.window_ms {
                return false;
            }
            return true;
        }
        while self.last_seen.len() >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                self.last_seen.clear();
                break;
            };
            self.last_seen.remove(&oldest);
        }
        self.insertion_order.push_back(key.clone());
        self.last_seen.insert(key, ts_ms);
        true
    }

    pub(super) fn remove_key(&mut self, event_type: BrowserSecurityEventType, norm_url: &str) {
        let key = (event_type, norm_url.to_string());
        if self.last_seen.remove(&key).is_some() {
            self.insertion_order.retain(|existing| existing != &key);
        }
    }
}

pub(super) fn normalize_windows_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let body = if trimmed
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\") || p.eq_ignore_ascii_case("//?/UNC/"))
    {
        format!(r"\\{}", &trimmed[8..])
    } else if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\") || p.eq_ignore_ascii_case("//?/"))
    {
        trimmed[4..].to_string()
    } else {
        trimmed.to_string()
    };
    body.replace('/', "\\")
}

fn normalize_browser_event_url(raw: &str) -> String {
    let trimmed = raw.trim();
    let before_frag = trimmed.split('#').next().unwrap_or(trimmed);
    if let Some(scheme_end) = before_frag.find("://") {
        let scheme = &before_frag[..scheme_end];
        let after_scheme = &before_frag[scheme_end + 3..];
        let auth_end = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
        let authority = &after_scheme[..auth_end];
        let rest = &after_scheme[auth_end..];
        format!(
            "{}://{}{}",
            scheme.to_ascii_lowercase(),
            authority.to_ascii_lowercase(),
            rest
        )
    } else {
        before_frag.to_ascii_lowercase()
    }
}

fn truncate_utf8_bytes(raw: &str, max_bytes: usize) -> (&str, bool) {
    if raw.len() <= max_bytes {
        return (raw, false);
    }
    let mut end = max_bytes;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    (&raw[..end], true)
}

impl DaemonEngine {
    /// Records a completed browser download's origin metadata (`ReportDownloadOrigin`), computing
    /// SHA-256 when the file is at or below `download_hash_max_bytes` (default 128 MiB) and
    /// enriching missing `referrer_url` / `frame_url` from `:Zone.Identifier` ADS when present.
    pub fn record_browser_download_origin(
        &self,
        file_path: &str,
        tab_url: &str,
        frame_url: Option<&str>,
        referrer_url: Option<&str>,
        downloaded_at_ms: i64,
    ) -> Result<DownloadOriginRecord, BrowserReportError> {
        let normalized_path = normalize_windows_path(file_path);
        if normalized_path.is_empty() {
            return Err(BrowserReportError::Invalid(
                "download file_path cannot be empty".to_string(),
            ));
        }
        let clean_tab_url = tab_url.trim().to_string();
        if clean_tab_url.is_empty() {
            return Err(BrowserReportError::Invalid(
                "download tab_url cannot be empty".to_string(),
            ));
        }
        let mut clean_frame_url = frame_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let mut clean_referrer_url = referrer_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let effective_ts = if downloaded_at_ms > 0 {
            downloaded_at_ms
        } else {
            current_unix_ms()
        };

        let path = Path::new(&normalized_path);
        let sha256 = match std::fs::metadata(path) {
            Ok(meta) if meta.is_file() && meta.len() <= self.config.download_hash_max_bytes => {
                match ledr_rules::compute_file_sha256_hex(path) {
                    Ok(hex) => Some(hex.to_ascii_lowercase()),
                    Err(err) => {
                        tracing::debug!(
                            file_path = %normalized_path,
                            error = %err,
                            "failed computing SHA-256 for downloaded file; recording origin without hash"
                        );
                        None
                    }
                }
            }
            Ok(meta) if meta.is_file() => {
                tracing::debug!(
                    file_path = %normalized_path,
                    file_bytes = meta.len(),
                    max_hash_bytes = self.config.download_hash_max_bytes,
                    "skipping SHA-256 for oversized download (exceeds hash limit)"
                );
                None
            }
            _ => None,
        };

        if let Some(zone) = self.motw_inspector.read_zone_identifier(path) {
            if clean_referrer_url.is_none() {
                clean_referrer_url = zone.referrer_url;
            }
            if clean_frame_url.is_none() {
                clean_frame_url = zone
                    .host_url
                    .filter(|host| !host.eq_ignore_ascii_case(&clean_tab_url));
            }
        }

        let record = DownloadOriginRecord {
            id: None,
            file_path: normalized_path,
            sha256,
            tab_url: clean_tab_url,
            frame_url: clean_frame_url,
            referrer_url: clean_referrer_url,
            downloaded_at_ms: effective_ts,
        };
        self.store.record_download_origin(&record)?;
        self.has_download_origins.store(true, Ordering::Release);
        Ok(record)
    }

    /// Resolves MOTW provenance for a starting process in 3 stages:
    /// 1. Exact case-insensitive `download_origins.file_path`
    /// 2. `download_origins.sha256` (when file size `<= download_hash_max_bytes`)
    /// 3. NTFS `:Zone.Identifier` ADS (`ZoneId >= 3`)
    ///
    /// Skips exited snapshots, `skip_store_ingest` absorbs, empty paths, and `ProtectedOs` binaries.
    pub fn resolve_process_motw(
        &self,
        exe_path: &str,
        exited_at_ms: Option<i64>,
        skip_store_ingest: bool,
    ) -> Option<MotwAttribution> {
        if exited_at_ms.is_some() || skip_store_ingest {
            return None;
        }
        let normalized_exe = normalize_windows_path(exe_path);
        if normalized_exe.is_empty()
            || classify_outbound_risk(&normalized_exe) == OutboundRiskClass::ProtectedOs
        {
            return None;
        }

        let path = Path::new(&normalized_exe);
        let has_downloads = self.has_download_origins.load(Ordering::Acquire);

        if has_downloads {
            match self.store.find_download_origin_by_path(&normalized_exe) {
                Ok(Some(rec)) => {
                    let zone = self.motw_inspector.read_zone_identifier(path);
                    let zone_id = zone.as_ref().map(|z| z.zone_id);
                    let referrer_url = rec
                        .referrer_url
                        .or_else(|| zone.and_then(|z| z.referrer_url));
                    return Some(MotwAttribution {
                        origin_url: rec.tab_url,
                        referrer_url,
                        frame_url: rec.frame_url,
                        sha256: rec.sha256,
                        zone_id,
                        stage: MotwMatchStage::DownloadPath,
                    });
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::warn!(
                        exe_path = %normalized_exe,
                        error = %err,
                        "Stage 1 download origin path lookup failed"
                    );
                }
            }

            let can_hash_for_stage2 = match std::fs::metadata(path) {
                Ok(meta) => meta.is_file() && meta.len() <= self.config.download_hash_max_bytes,
                // Allow mocked BinaryInspector tests that do not create a backing file on disk,
                // while skipping real oversized or non-regular files.
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
            if can_hash_for_stage2 {
                if let Some(raw_hash) = self.inspector.inspect(&normalized_exe).sha256 {
                    let clean_hash = raw_hash.trim().to_ascii_lowercase();
                    if !clean_hash.is_empty() {
                        match self.store.find_download_origin_by_sha256(&clean_hash) {
                            Ok(Some(rec)) => {
                                let zone = self.motw_inspector.read_zone_identifier(path);
                                let zone_id = zone.as_ref().map(|z| z.zone_id);
                                let referrer_url = rec
                                    .referrer_url
                                    .or_else(|| zone.and_then(|z| z.referrer_url));
                                return Some(MotwAttribution {
                                    origin_url: rec.tab_url,
                                    referrer_url,
                                    frame_url: rec.frame_url,
                                    sha256: rec.sha256.or(Some(clean_hash)),
                                    zone_id,
                                    stage: MotwMatchStage::DownloadSha256,
                                });
                            }
                            Ok(None) => {}
                            Err(err) => {
                                tracing::warn!(
                                    exe_path = %normalized_exe,
                                    error = %err,
                                    "Stage 2 download origin SHA-256 lookup failed"
                                );
                            }
                        }
                    }
                }
            }
        }

        if let Some(zone) = self.motw_inspector.read_zone_identifier(path) {
            if zone.is_internet_origin() {
                if let Some(origin_url) = zone.preferred_origin_url() {
                    let frame_url = zone
                        .host_url
                        .filter(|h| !h.eq_ignore_ascii_case(&origin_url));
                    return Some(MotwAttribution {
                        origin_url,
                        referrer_url: zone.referrer_url,
                        frame_url,
                        sha256: None,
                        zone_id: Some(zone.zone_id),
                        stage: MotwMatchStage::ZoneIdentifierAds,
                    });
                }
            }
        }

        None
    }

    /// Validates, deduplicates (30 s window, max 256 entries), and persists a `LAYER_4_BROWSER`
    /// security alert (`ReportBrowserEvent`). By default (`L-19`), suppresses OS toast notices.
    pub fn record_browser_event(
        &self,
        event_type: BrowserSecurityEventType,
        url: &str,
        details: Option<&str>,
        timestamp_ms: i64,
    ) -> Result<BrowserEventOutcome, BrowserReportError> {
        let clean_url = url.trim();
        if clean_url.is_empty() {
            return Err(BrowserReportError::Invalid(
                "browser event url cannot be empty".to_string(),
            ));
        }

        let (truncated_details, details_truncated) =
            match details.map(str::trim).filter(|s| !s.is_empty()) {
                Some(raw) => {
                    let (slice, truncated) =
                        truncate_utf8_bytes(raw, MAX_BROWSER_EVENT_DETAILS_BYTES);
                    (Some(slice.to_string()), truncated)
                }
                None => (None, false),
            };

        let effective_ts = if timestamp_ms > 0 {
            timestamp_ms
        } else {
            current_unix_ms()
        };
        let norm_url = normalize_browser_event_url(clean_url);

        {
            let mut dedup = self
                .browser_event_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !dedup.should_emit(event_type, &norm_url, effective_ts) {
                return Ok(BrowserEventOutcome::Deduplicated);
            }
        }

        let (severity, title) = match event_type {
            BrowserSecurityEventType::ClickFixPastejacking => (
                AlertSeverity::High,
                "Browser ClickFix / Pastejacking Detected",
            ),
            BrowserSecurityEventType::NrdPasswordWarning => (
                AlertSeverity::High,
                "Password Entry on Newly Registered Domain",
            ),
            BrowserSecurityEventType::HomographWarning => (
                AlertSeverity::High,
                "Password Entry on Homograph / Lookalike Domain",
            ),
            BrowserSecurityEventType::DnrBlockedRequest => (
                AlertSeverity::Medium,
                "Browser Blocked Request to Malicious Domain",
            ),
        };

        let context_json = serde_json::json!({
            "event_type": event_type,
            "url": clean_url,
            "details": truncated_details,
            "details_truncated": details_truncated,
        })
        .to_string();

        let alert = AlertRecord {
            alert_id: Uuid::new_v4().to_string(),
            timestamp_ms: effective_ts,
            severity,
            source_layer: "LAYER_4_BROWSER".to_string(),
            rule_id: format!("BROWSER-{event_type:?}"),
            title: title.to_string(),
            process_instance_id: None,
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json,
            resolved_at_ms: None,
        };

        if let Err(err) = self.record_alert_checked(&alert) {
            self.browser_event_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove_key(event_type, &norm_url);
            return Err(BrowserReportError::Store(err));
        }

        self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        if self.config.notify_browser_events {
            if let Err(err) = self.notifier.notify_alert(&alert) {
                tracing::warn!(
                    alert_id = %alert.alert_id,
                    error = %err,
                    "failed to dispatch toast notification for browser event alert"
                );
            }
        }

        Ok(BrowserEventOutcome::Recorded(alert))
    }
}
