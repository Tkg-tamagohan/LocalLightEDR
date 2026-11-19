//! Bounded in-memory and atomic disk-persisted NRD cache.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::RulesError;

use super::parser::{matches_domain_or_parent_in_set, normalize_nrd_domain, parse_nrd_line};
use super::NRD_MAX_RESPONSE_BYTES;

static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

const NRD_CACHE_HEADER: &str = "# LocalEDR NRD Cache";
const NRD_UPDATED_PREFIX: &str = "# updated_at_ms=";

/// Bounded in-memory + disk-persisted cache of newly registered domains (`L-14`).
#[derive(Debug, Clone, Default)]
pub struct NrdCache {
    pub(super) domains: HashSet<String>,
    pub(super) updated_at_ms: Option<i64>,
    pub(super) truncated: bool,
}

/// Summary metrics produced by [`refresh_nrd_cache`](super::refresh_nrd_cache).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NrdRefreshStats {
    pub feeds_succeeded: usize,
    pub feeds_failed: usize,
    pub total_entries: usize,
    pub truncated: bool,
    pub errors: Vec<String>,
}

impl NrdCache {
    /// Creates a new empty [`NrdCache`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an [`NrdCache`] directly from normalized domain entries (capped at `max_entries`).
    pub fn from_domains<I, S>(domains: I, updated_at_ms: Option<i64>, max_entries: usize) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let cap = max_entries.max(1);
        let mut set = HashSet::new();
        let mut truncated = false;
        for item in domains {
            if let Some(norm) = normalize_nrd_domain(item.as_ref()) {
                if set.len() >= cap && !set.contains(&norm) {
                    truncated = true;
                    break;
                }
                set.insert(norm);
            }
        }
        Self {
            domains: set,
            updated_at_ms,
            truncated,
        }
    }

    /// Returns the number of cached NRD domains.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Returns `true` when the cache contains no domains.
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Returns the backing normalized lowercase domain set for [`crate::assess_domain_risk`].
    pub fn domains(&self) -> &HashSet<String> {
        &self.domains
    }

    /// Returns the Unix epoch timestamp (milliseconds) of the last successful refresh.
    pub fn updated_at_ms(&self) -> Option<i64> {
        self.updated_at_ms
    }

    /// Returns `true` if parsing or loading hit the entry or byte cap.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns `true` if `updated_at_ms` is absent or older than `refresh_interval_ms`.
    pub fn is_stale(&self, now_ms: i64, refresh_interval_ms: u64) -> bool {
        let Some(updated) = self.updated_at_ms else {
            return true;
        };
        let interval = i64::try_from(refresh_interval_ms).unwrap_or(i64::MAX);
        now_ms.saturating_sub(updated) >= interval
    }

    /// Returns `true` if `domain` or any multi-label parent suffix of `domain` is in the cache.
    pub fn contains(&self, domain: &str) -> bool {
        matches_domain_or_parent_in_set(domain, &self.domains)
    }

    /// Loads an [`NrdCache`] from a local cache file, enforcing `max_entries` and
    /// [`NRD_MAX_RESPONSE_BYTES`].
    pub fn load_from_file(path: &Path, max_entries: usize) -> Result<Self, RulesError> {
        let file = File::open(path)?;
        let fallback_mtime_ms = file
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| i64::try_from(d.as_millis()).ok());

        let cap = max_entries.max(1);
        let limited = file.take(NRD_MAX_RESPONSE_BYTES as u64 + 1);
        let mut reader = BufReader::new(limited);
        let mut line = String::new();
        let mut updated_at_ms = None;
        let mut domains = HashSet::new();
        let mut truncated = false;
        let mut bytes_read = 0usize;

        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            bytes_read = bytes_read.saturating_add(n);
            if bytes_read > NRD_MAX_RESPONSE_BYTES {
                truncated = true;
                break;
            }
            let trimmed = line.trim();
            if let Some(ts_str) = trimmed.strip_prefix(NRD_UPDATED_PREFIX) {
                if let Ok(ts) = ts_str.trim().parse::<i64>() {
                    updated_at_ms = Some(ts);
                }
                continue;
            }
            if let Some(domain) = parse_nrd_line(trimmed) {
                if domains.len() >= cap && !domains.contains(&domain) {
                    truncated = true;
                    break;
                }
                domains.insert(domain);
            }
        }

        Ok(Self {
            domains,
            updated_at_ms: updated_at_ms.or(fallback_mtime_ms),
            truncated,
        })
    }

    /// Atomically persists the cache to `path` (sorted for deterministic diffs/inspection).
    pub fn save_to_file(&self, path: &Path) -> Result<(), RulesError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("nrd-cache.txt");
        let seq = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = path.with_file_name(format!(
            "{file_name}.tmp.{}.{seq}",
            std::process::id()
        ));

        let write_res = (|| -> Result<(), std::io::Error> {
            let mut file = File::create(&tmp_path)?;
            writeln!(file, "{NRD_CACHE_HEADER}")?;
            if let Some(ts) = self.updated_at_ms {
                writeln!(file, "{NRD_UPDATED_PREFIX}{ts}")?;
            }
            let mut sorted: Vec<&str> = self.domains.iter().map(String::as_str).collect();
            sorted.sort_unstable();
            for domain in sorted {
                writeln!(file, "{domain}")?;
            }
            file.flush()?;
            Ok(())
        })();
        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(RulesError::Io(err));
        }

        replace_file_atomically(&tmp_path, path)?;
        Ok(())
    }
}

#[cfg(windows)]
fn replace_file_atomically(tmp_path: &Path, dest_path: &Path) -> Result<(), std::io::Error> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }

    let src_w: Vec<u16> = tmp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dst_w: Vec<u16> = dest_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `src_w` and `dst_w` are valid NUL-terminated UTF-16 paths.
    let ok = unsafe {
        MoveFileExW(
            src_w.as_ptr(),
            dst_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        let _ = fs::remove_file(tmp_path);
        return Err(err);
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_file_atomically(tmp_path: &Path, dest_path: &Path) -> Result<(), std::io::Error> {
    fs::rename(tmp_path, dest_path)
}
