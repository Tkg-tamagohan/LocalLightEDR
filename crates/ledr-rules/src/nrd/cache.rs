//! Bounded in-memory and atomic disk-persisted NRD cache backed by a compact flat sorted arena.

use std::cmp::Ordering as CmpOrdering;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::RulesError;

use super::parser::{
    matches_domain_or_parent, normalize_nrd_domain_into, parse_nrd_line_into,
};
use super::NRD_MAX_RESPONSE_BYTES;

static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

const NRD_CACHE_HEADER: &str = "# LocalEDR NRD Cache";
const NRD_UPDATED_PREFIX: &str = "# updated_at_ms=";

/// Bounded in-memory + disk-persisted cache of newly registered domains (`L-14`).
///
/// Stores all normalized ASCII lowercase domains in two contiguous heap allocations:
/// a sorted flat byte arena (`data`) and a `len + 1` offset index (`offsets`) searched
/// via binary search. At `NRD_MAX_ENTRIES` (`50,000`), this reduces heap allocations
/// from ~50,001 (`HashSet<String>`) to exactly 2 and keeps RSS well below 2 MiB.
#[derive(Debug, Clone, Default)]
pub struct NrdCache {
    pub(super) data: Box<[u8]>,
    pub(super) offsets: Box<[u32]>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InsertOutcome {
    Inserted,
    Duplicate,
    CapReached,
}

/// Staging builder that deduplicates normalized domains into a single flat byte arena without
/// allocating per-domain `String`s, then compacts into a sorted [`NrdCache`].
pub(super) struct FlatDomainSet {
    data: Vec<u8>,
    offsets: Vec<u32>,
    /// Open-addressed hash table storing `entry_idx + 1` (`0` = empty slot), allocated lazily
    /// only when out-of-order domains appear so sorted cache loads incur zero hash overhead.
    buckets: Vec<u32>,
    sorted_so_far: bool,
}

impl FlatDomainSet {
    pub(super) fn new() -> Self {
        Self {
            data: Vec::new(),
            offsets: vec![0],
            buckets: Vec::new(),
            sorted_so_far: true,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    #[inline]
    fn entry_bytes(&self, idx: usize) -> &[u8] {
        let start = self.offsets[idx] as usize;
        let end = self.offsets[idx + 1] as usize;
        &self.data[start..end]
    }

    pub(super) fn insert_bounded(&mut self, domain: &str, cap: usize) -> InsertOutcome {
        let bytes = domain.as_bytes();
        let count = self.len();

        if self.sorted_so_far && self.buckets.is_empty() {
            if count > 0 {
                let last = self.entry_bytes(count - 1);
                match bytes.cmp(last) {
                    CmpOrdering::Equal => return InsertOutcome::Duplicate,
                    CmpOrdering::Greater => {
                        if count >= cap {
                            return InsertOutcome::CapReached;
                        }
                        return self.append_unchecked(bytes);
                    }
                    CmpOrdering::Less => {
                        self.sorted_so_far = false;
                        self.build_buckets(count);
                    }
                }
            } else {
                if count >= cap {
                    return InsertOutcome::CapReached;
                }
                return self.append_unchecked(bytes);
            }
        }

        if self.contains_in_buckets(bytes) {
            return InsertOutcome::Duplicate;
        }
        if count >= cap {
            return InsertOutcome::CapReached;
        }
        if (count + 1).saturating_mul(2) > self.buckets.len() {
            self.grow_buckets(count + 1);
        }
        let outcome = self.append_unchecked(bytes);
        if outcome == InsertOutcome::Inserted {
            let new_idx = count as u32;
            self.insert_bucket_index(new_idx, bytes);
        }
        outcome
    }

    fn append_unchecked(&mut self, bytes: &[u8]) -> InsertOutcome {
        let count = self.len();
        let Some(next_end) = self
            .data
            .len()
            .checked_add(bytes.len())
            .and_then(|n| u32::try_from(n).ok())
        else {
            return InsertOutcome::CapReached;
        };
        if u32::try_from(count + 1).is_err() {
            return InsertOutcome::CapReached;
        }
        self.data.extend_from_slice(bytes);
        self.offsets.push(next_end);
        InsertOutcome::Inserted
    }

    fn build_buckets(&mut self, count: usize) {
        let min_slots = count.saturating_mul(2).max(16).next_power_of_two();
        self.buckets.clear();
        self.buckets.resize(min_slots, 0);
        for idx in 0..count {
            let entry_hash = fnv1a_64(self.entry_bytes(idx));
            self.insert_bucket_hashed(idx as u32, entry_hash);
        }
    }

    fn grow_buckets(&mut self, needed_entries: usize) {
        let count = self.len();
        let min_slots = needed_entries
            .saturating_mul(2)
            .max(self.buckets.len().saturating_mul(2))
            .max(16)
            .next_power_of_two();
        self.buckets.clear();
        self.buckets.resize(min_slots, 0);
        for idx in 0..count {
            let entry_hash = fnv1a_64(self.entry_bytes(idx));
            self.insert_bucket_hashed(idx as u32, entry_hash);
        }
    }

    fn contains_in_buckets(&self, needle: &[u8]) -> bool {
        if self.buckets.is_empty() {
            return false;
        }
        let mask = self.buckets.len() - 1;
        let mut slot = (fnv1a_64(needle) as usize) & mask;
        loop {
            let stored = self.buckets[slot];
            if stored == 0 {
                return false;
            }
            if self.entry_bytes((stored - 1) as usize) == needle {
                return true;
            }
            slot = (slot + 1) & mask;
        }
    }

    fn insert_bucket_index(&mut self, idx: u32, bytes: &[u8]) {
        self.insert_bucket_hashed(idx, fnv1a_64(bytes));
    }

    fn insert_bucket_hashed(&mut self, idx: u32, hash: u64) {
        let mask = self.buckets.len() - 1;
        let mut slot = (hash as usize) & mask;
        while self.buckets[slot] != 0 {
            slot = (slot + 1) & mask;
        }
        self.buckets[slot] = idx + 1;
    }

    pub(super) fn into_nrd_cache(mut self, updated_at_ms: Option<i64>, truncated: bool) -> NrdCache {
        self.buckets = Vec::new();
        let count = self.len();
        if count == 0 {
            return NrdCache {
                data: Box::default(),
                offsets: Box::default(),
                updated_at_ms,
                truncated,
            };
        }
        if self.sorted_so_far {
            return NrdCache {
                data: self.data.into_boxed_slice(),
                offsets: self.offsets.into_boxed_slice(),
                updated_at_ms,
                truncated,
            };
        }

        let mut order: Vec<u32> = (0..count as u32).collect();
        order.sort_unstable_by(|&a, &b| {
            self.entry_bytes(a as usize)
                .cmp(self.entry_bytes(b as usize))
        });

        let mut sorted_data = Vec::with_capacity(self.data.len());
        let mut sorted_offsets = Vec::with_capacity(count + 1);
        sorted_offsets.push(0u32);
        for idx in order {
            sorted_data.extend_from_slice(self.entry_bytes(idx as usize));
            sorted_offsets.push(sorted_data.len() as u32);
        }

        NrdCache {
            data: sorted_data.into_boxed_slice(),
            offsets: sorted_offsets.into_boxed_slice(),
            updated_at_ms,
            truncated,
        }
    }
}

#[inline]
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
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
        let mut builder = FlatDomainSet::new();
        let mut norm_buf = String::new();
        let mut truncated = false;
        for item in domains {
            if normalize_nrd_domain_into(item.as_ref(), &mut norm_buf)
                && builder.insert_bounded(&norm_buf, cap) == InsertOutcome::CapReached
            {
                truncated = true;
                break;
            }
        }
        builder.into_nrd_cache(updated_at_ms, truncated)
    }

    /// Returns the number of cached NRD domains.
    pub fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    /// Returns `true` when the cache contains no domains.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over all cached normalized lowercase domains in ascending sorted order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        (0..self.len()).map(|idx| {
            std::str::from_utf8(self.entry_bytes(idx))
                .expect("NrdCache arena contains only validated ASCII domains")
        })
    }

    /// Returns the total heap bytes owned by the flat sorted arena (`data` + `offsets`).
    pub fn heap_bytes(&self) -> usize {
        self.data.len() + self.offsets.len() * std::mem::size_of::<u32>()
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

    #[inline]
    fn entry_bytes(&self, idx: usize) -> &[u8] {
        let start = self.offsets[idx] as usize;
        let end = self.offsets[idx + 1] as usize;
        &self.data[start..end]
    }

    fn contains_exact_normalized(&self, normalized: &str) -> bool {
        let count = self.len();
        if count == 0 {
            return false;
        }
        let needle = normalized.as_bytes();
        let mut lo = 0usize;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.entry_bytes(mid).cmp(needle) {
                CmpOrdering::Less => lo = mid + 1,
                CmpOrdering::Greater => hi = mid,
                CmpOrdering::Equal => return true,
            }
        }
        false
    }

    /// Returns `true` if `domain` or any multi-label parent suffix of `domain` is in the cache.
    pub fn contains(&self, domain: &str) -> bool {
        if self.is_empty() {
            return false;
        }
        matches_domain_or_parent(domain, |candidate| self.contains_exact_normalized(candidate))
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
        let mut norm_buf = String::new();
        let mut updated_at_ms = None;
        let mut builder = FlatDomainSet::new();
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
            if parse_nrd_line_into(trimmed, &mut norm_buf)
                && builder.insert_bounded(&norm_buf, cap) == InsertOutcome::CapReached
            {
                truncated = true;
                break;
            }
        }

        Ok(builder.into_nrd_cache(updated_at_ms.or(fallback_mtime_ms), truncated))
    }

    /// Atomically persists the cache to `path` (already sorted for deterministic diffs/inspection).
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
            let file = File::create(&tmp_path)?;
            let mut writer = BufWriter::new(file);
            writeln!(writer, "{NRD_CACHE_HEADER}")?;
            if let Some(ts) = self.updated_at_ms {
                writeln!(writer, "{NRD_UPDATED_PREFIX}{ts}")?;
            }
            for domain in self.iter() {
                writeln!(writer, "{domain}")?;
            }
            writer.flush()?;
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
