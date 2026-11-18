//! Fast early pruning and standard OS allowlist configuration (`default_allowlist.json`).

use std::fs;
use std::path::Path;

use ledr_proto::{AllowlistRuleRecord, SensorEvent};
use serde::{Deserialize, Serialize};

use crate::sigma::EventContext;
use crate::RulesError;

/// Configuration driving [`EarlyPruner`] benign OS noise suppression before Sigma evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EarlyPrunerConfig {
    #[serde(default = "default_true")]
    pub prune_loopback_network: bool,
    #[serde(default)]
    pub ignored_dns_names: Vec<String>,
    #[serde(default)]
    pub ignored_dns_suffixes: Vec<String>,
    #[serde(default)]
    pub trusted_telemetry_images: Vec<String>,
    #[serde(default)]
    pub trusted_os_noise_images: Vec<String>,
}

const fn default_true() -> bool {
    true
}

impl Default for EarlyPrunerConfig {
    fn default() -> Self {
        Self {
            prune_loopback_network: true,
            ignored_dns_names: vec![
                "localhost".to_string(),
                "wpad".to_string(),
                "isatap".to_string(),
            ],
            ignored_dns_suffixes: vec![
                ".local".to_string(),
                ".arpa".to_string(),
                ".internal".to_string(),
            ],
            trusted_telemetry_images: vec![
                r"C:\Windows\System32\svchost.exe".to_string(),
                r"C:\Windows\System32\SearchIndexer.exe".to_string(),
                r"C:\Windows\System32\SearchProtocolHost.exe".to_string(),
                r"C:\Program Files\Windows Defender\MsMpEng.exe".to_string(),
            ],
            trusted_os_noise_images: vec![
                r"C:\Windows\System32\SearchProtocolHost.exe".to_string(),
                r"C:\Windows\System32\backgroundTaskHost.exe".to_string(),
                r"C:\Windows\System32\conhost.exe".to_string(),
            ],
        }
    }
}

/// Top-level JSON structure of `rules/default_allowlist.json` (`決定記録 L-04`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub allowlist_rules: Vec<AllowlistRuleRecord>,
    #[serde(default)]
    pub early_pruner: EarlyPrunerConfig,
}

impl AllowlistConfig {
    /// Parses an [`AllowlistConfig`] from a JSON string.
    pub fn from_json_str(json: &str) -> Result<Self, RulesError> {
        Ok(serde_json::from_str(json)?)
    }

    /// Reads an [`AllowlistConfig`] from a JSON file on disk.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, RulesError> {
        let raw = fs::read_to_string(path)?;
        Self::from_json_str(&raw)
    }
}

/// Fast pre-Sigma filter suppressing noisy/benign OS telemetry while never dropping
/// high-signal security telemetry (`CanaryFileAccess` and `ScriptEvaluated`).
#[derive(Debug, Clone, Default)]
pub struct EarlyPruner {
    config: EarlyPrunerConfig,
}

impl EarlyPruner {
    /// Creates an [`EarlyPruner`] from an [`EarlyPrunerConfig`].
    pub fn new(config: EarlyPrunerConfig) -> Self {
        Self { config }
    }

    /// Parses an [`EarlyPruner`] from either an [`AllowlistConfig`] JSON or a bare [`EarlyPrunerConfig`] JSON.
    pub fn from_json_str(json: &str) -> Result<Self, RulesError> {
        let val: serde_json::Value = serde_json::from_str(json)?;
        if val.get("early_pruner").is_some() || val.get("allowlist_rules").is_some() {
            let full: AllowlistConfig = serde_json::from_value(val)?;
            Ok(Self::new(full.early_pruner))
        } else {
            let cfg: EarlyPrunerConfig = serde_json::from_value(val)?;
            Ok(Self::new(cfg))
        }
    }

    /// Loads an [`EarlyPruner`] from a JSON file on disk.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, RulesError> {
        let raw = fs::read_to_string(path)?;
        Self::from_json_str(&raw)
    }

    /// Returns the underlying [`EarlyPrunerConfig`].
    pub fn config(&self) -> &EarlyPrunerConfig {
        &self.config
    }

    /// Returns `true` if `ctx` represents benign OS noise that can skip Sigma evaluation.
    /// Never returns `true` for [`SensorEvent::CanaryFileAccess`] or [`SensorEvent::ScriptEvaluated`].
    pub fn should_prune(&self, ctx: &EventContext<'_>) -> bool {
        self.should_prune_with_image(ctx, None)
    }

    /// Like [`EarlyPruner::should_prune`], additionally considering `process_exe_path`
    /// resolved from the daemon's active process table for non-`ProcessStart` events.
    pub fn should_prune_with_image(
        &self,
        ctx: &EventContext<'_>,
        process_exe_path: Option<&str>,
    ) -> bool {
        match ctx.event {
            SensorEvent::CanaryFileAccess { .. } | SensorEvent::ScriptEvaluated { .. } => false,
            SensorEvent::ProcessStop { .. } => false,
            SensorEvent::NetworkConnect { dst_ip, .. } => {
                if self.config.prune_loopback_network && dst_ip.is_loopback() {
                    return true;
                }
                process_exe_path
                    .is_some_and(|img| matches_any_image(img, &self.config.trusted_telemetry_images))
            }
            SensorEvent::DnsQuery { query_name, .. } => {
                let normalized = query_name.trim().trim_end_matches('.');
                if self
                    .config
                    .ignored_dns_names
                    .iter()
                    .any(|name| normalized.eq_ignore_ascii_case(name))
                {
                    return true;
                }
                if self
                    .config
                    .ignored_dns_suffixes
                    .iter()
                    .any(|suffix| ends_with_ascii_ci(normalized, suffix))
                {
                    return true;
                }
                process_exe_path
                    .is_some_and(|img| matches_any_image(img, &self.config.trusted_telemetry_images))
            }
            SensorEvent::ProcessStart { exe_path, .. } => {
                matches_any_image(exe_path, &self.config.trusted_os_noise_images)
            }
        }
    }
}

fn matches_any_image(exe_path: &str, configured: &[String]) -> bool {
    configured
        .iter()
        .any(|pat| exe_path.eq_ignore_ascii_case(pat))
}

fn ends_with_ascii_ci(haystack: &str, suffix: &str) -> bool {
    let h = haystack.as_bytes();
    let s = suffix.as_bytes();
    h.len()
        .checked_sub(s.len())
        .and_then(|idx| h.get(idx..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(s))
}
