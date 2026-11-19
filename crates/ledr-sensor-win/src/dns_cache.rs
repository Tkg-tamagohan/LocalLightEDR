//! Bounded LRU cache correlating `DNS-Client` queries with outbound network events (`AUTO-05`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;

use ledr_proto::DNS_RESOLUTION_CACHE_CAPACITY;

#[derive(Debug, Clone)]
struct CacheEntry {
    domain: String,
    timestamp_ms: i64,
    seq: u64,
}

#[derive(Debug, Clone)]
struct LruTable<K> {
    next_seq: u64,
    entries: HashMap<K, CacheEntry>,
    lru_order: BTreeMap<u64, K>,
}

impl<K: Eq + Hash + Copy> LruTable<K> {
    fn new(initial_capacity: usize) -> Self {
        Self {
            next_seq: 0,
            entries: HashMap::with_capacity(initial_capacity),
            lru_order: BTreeMap::new(),
        }
    }

    fn alloc_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    fn insert_or_update<F>(
        &mut self,
        capacity: usize,
        key: K,
        domain: &str,
        timestamp_ms: i64,
        mut on_evict: F,
    ) where
        F: FnMut(K),
    {
        let seq = self.alloc_seq();
        if let Some(existing) = self.entries.get_mut(&key) {
            self.lru_order.remove(&existing.seq);
            existing.domain = domain.to_string();
            existing.timestamp_ms = timestamp_ms;
            existing.seq = seq;
            self.lru_order.insert(seq, key);
            return;
        }

        while self.entries.len() >= capacity {
            let Some((_, oldest_key)) = self.lru_order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest_key);
            on_evict(oldest_key);
        }

        self.entries.insert(
            key,
            CacheEntry {
                domain: domain.to_string(),
                timestamp_ms,
                seq,
            },
        );
        self.lru_order.insert(seq, key);
    }

    fn lookup_entry(&mut self, key: &K) -> Option<(String, i64)> {
        let new_seq = self.alloc_seq();
        let entry = self.entries.get_mut(key)?;
        self.lru_order.remove(&entry.seq);
        entry.seq = new_seq;
        self.lru_order.insert(new_seq, *key);
        Some((entry.domain.clone(), entry.timestamp_ms))
    }

    fn remove(&mut self, key: &K) -> bool {
        let Some(removed) = self.entries.remove(key) else {
            return false;
        };
        self.lru_order.remove(&removed.seq);
        true
    }
}

/// Bounded LRU cache mapping resolved IP addresses back to queried domain names (`AUTO-05`).
#[derive(Debug, Clone)]
pub struct DnsResolutionCache {
    capacity: usize,
    global: LruTable<IpAddr>,
    per_pid: LruTable<(u32, IpAddr)>,
    ips_by_pid: HashMap<u32, HashSet<IpAddr>>,
}

impl Default for DnsResolutionCache {
    fn default() -> Self {
        Self::new(DNS_RESOLUTION_CACHE_CAPACITY)
    }
}

impl DnsResolutionCache {
    /// Creates an empty DNS resolution cache bounded to `capacity` entries.
    ///
    /// Callers typically pass [`ledr_proto::DNS_RESOLUTION_CACHE_CAPACITY`] (4,096).
    pub fn new(capacity: usize) -> Self {
        let initial_cap = capacity.min(DNS_RESOLUTION_CACHE_CAPACITY);
        Self {
            capacity,
            global: LruTable::new(initial_cap),
            per_pid: LruTable::new(initial_cap),
            ips_by_pid: HashMap::new(),
        }
    }

    /// Returns the configured maximum number of cached entries.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the current number of cached IP-to-domain entries.
    pub fn len(&self) -> usize {
        self.global.entries.len() + self.per_pid.entries.len()
    }

    /// Returns `true` if no entries are currently cached.
    pub fn is_empty(&self) -> bool {
        self.global.entries.is_empty() && self.per_pid.entries.is_empty()
    }

    /// Inserts or refreshes mappings from each IP in `ips` to `query_name`,
    /// evicting the least-recently-used entries if capacity would be exceeded.
    pub fn insert_resolution(&mut self, query_name: &str, ips: &[IpAddr], timestamp_ms: i64) {
        let Some(domain) = normalize_query_domain(self.capacity, query_name) else {
            return;
        };
        for &ip in ips {
            self.global
                .insert_or_update(self.capacity, ip, domain, timestamp_ms, |_| {});
        }
    }

    /// Looks up the most recently resolved domain name for `ip` and refreshes its LRU recency.
    pub fn lookup_domain(&mut self, ip: &IpAddr) -> Option<String> {
        self.lookup_entry(ip).map(|(domain, _)| domain)
    }

    /// Looks up `(domain, timestamp_ms)` for `ip` and refreshes its LRU recency.
    pub fn lookup_entry(&mut self, ip: &IpAddr) -> Option<(String, i64)> {
        self.global.lookup_entry(ip)
    }

    /// Inserts or refreshes per-PID mappings `(pid, ip) -> query_name`, evicting the
    /// least-recently-used `(pid, ip)` entries if `capacity` would be exceeded (`SEC_0002`).
    pub fn insert_resolution_for_pid(
        &mut self,
        pid: u32,
        query_name: &str,
        ips: &[IpAddr],
        timestamp_ms: i64,
    ) {
        let Some(domain) = normalize_query_domain(self.capacity, query_name) else {
            return;
        };
        let ips_by_pid = &mut self.ips_by_pid;
        for &ip in ips {
            self.per_pid
                .insert_or_update(self.capacity, (pid, ip), domain, timestamp_ms, |(ev_pid, ev_ip)| {
                    if let Some(set) = ips_by_pid.get_mut(&ev_pid) {
                        set.remove(&ev_ip);
                        if set.is_empty() {
                            ips_by_pid.remove(&ev_pid);
                        }
                    }
                });
            ips_by_pid.entry(pid).or_default().insert(ip);
        }
    }

    /// Looks up the most recently resolved domain name for `(pid, ip)` and refreshes LRU recency.
    pub fn lookup_domain_for_pid(&mut self, pid: u32, ip: &IpAddr) -> Option<String> {
        self.lookup_entry_for_pid(pid, ip).map(|(domain, _)| domain)
    }

    /// Looks up `(domain, timestamp_ms)` for `(pid, ip)` and refreshes LRU recency.
    pub fn lookup_entry_for_pid(&mut self, pid: u32, ip: &IpAddr) -> Option<(String, i64)> {
        self.per_pid.lookup_entry(&(pid, *ip))
    }

    /// Removes all cached DNS resolutions owned by `pid` (e.g. on process start/stop to prevent
    /// stale attribution across PID reuse).
    pub fn remove_pid(&mut self, pid: u32) {
        let Some(ips) = self.ips_by_pid.remove(&pid) else {
            return;
        };
        for ip in ips {
            self.per_pid.remove(&(pid, ip));
        }
    }
}

fn normalize_query_domain(capacity: usize, query_name: &str) -> Option<&str> {
    if capacity == 0 {
        return None;
    }
    let domain = query_name.trim().trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }
    Some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn sens_02_dns_cache_insert_lookup_and_lru_eviction() {
        let default_cache = DnsResolutionCache::default();
        assert_eq!(default_cache.capacity(), 4096);
        assert!(default_cache.is_empty());

        let ip1 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let ip2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip3 = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

        let mut cache = DnsResolutionCache::new(2);
        assert!(cache.is_empty());

        cache.insert_resolution("example.com.", &[ip1], 1000);
        cache.insert_resolution("one.one.one.one", &[ip2], 1001);
        assert_eq!(cache.len(), 2);
        assert!(!cache.is_empty());

        // Refresh `ip1` so `ip2` becomes the least recently used entry.
        assert_eq!(cache.lookup_domain(&ip1), Some("example.com".to_string()));

        // Inserting `ip3` must evict `ip2` while retaining `ip1`.
        cache.insert_resolution("dns.cloudflare.com", &[ip3], 1002);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.lookup_domain(&ip2), None);
        assert_eq!(cache.lookup_domain(&ip1), Some("example.com".to_string()));
        assert_eq!(
            cache.lookup_entry(&ip3),
            Some(("dns.cloudflare.com".to_string(), 1002))
        );

        // Updating an existing IP does not evict the other entry.
        cache.insert_resolution("updated.example.com", &[ip1], 1003);
        assert_eq!(cache.len(), 2);
        assert_eq!(
            cache.lookup_domain(&ip1),
            Some("updated.example.com".to_string())
        );
        assert_eq!(
            cache.lookup_domain(&ip3),
            Some("dns.cloudflare.com".to_string())
        );
    }

    #[test]
    fn sens_p3_07_per_pid_dns_cache_isolation_lru_and_pid_eviction() {
        let shared_cdn_ip = IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229));
        let other_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

        let mut cache = DnsResolutionCache::new(2);
        assert!(cache.is_empty());

        // PID 100 resolves `allowed.example` -> shared CDN IP.
        cache.insert_resolution_for_pid(100, "allowed.example.", &[shared_cdn_ip], 1000);
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.lookup_domain_for_pid(100, &shared_cdn_ip),
            Some("allowed.example".to_string())
        );

        // Cross-PID isolation: PID 200 has NOT resolved `shared_cdn_ip` -> must return None!
        assert_eq!(cache.lookup_domain_for_pid(200, &shared_cdn_ip), None);
        assert_eq!(cache.lookup_entry_for_pid(200, &shared_cdn_ip), None);

        // PID 200 resolving the same shared IP to a different domain does NOT clobber PID 100.
        cache.insert_resolution_for_pid(200, "evil.example", &[shared_cdn_ip], 1005);
        assert_eq!(cache.len(), 2);
        assert_eq!(
            cache.lookup_domain_for_pid(100, &shared_cdn_ip),
            Some("allowed.example".to_string())
        );
        assert_eq!(
            cache.lookup_entry_for_pid(200, &shared_cdn_ip),
            Some(("evil.example".to_string(), 1005))
        );

        // Refresh `(100, shared_cdn_ip)` so `(200, shared_cdn_ip)` is LRU, then insert a 3rd entry
        // at capacity=2 -> `(200, shared_cdn_ip)` is evicted while `(100, shared_cdn_ip)` stays.
        assert_eq!(
            cache.lookup_domain_for_pid(100, &shared_cdn_ip),
            Some("allowed.example".to_string())
        );
        cache.insert_resolution_for_pid(300, "third.example", &[other_ip], 1010);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.lookup_domain_for_pid(200, &shared_cdn_ip), None);
        assert_eq!(
            cache.lookup_domain_for_pid(100, &shared_cdn_ip),
            Some("allowed.example".to_string())
        );
        assert_eq!(
            cache.lookup_domain_for_pid(300, &other_ip),
            Some("third.example".to_string())
        );

        // `remove_pid` removes only the specified PID's entries and keeps other PIDs intact.
        cache.insert_resolution_for_pid(100, "second-for-100.example", &[other_ip], 1020);
        assert_eq!(cache.len(), 2);
        cache.remove_pid(100);
        assert_eq!(cache.lookup_domain_for_pid(100, &shared_cdn_ip), None);
        assert_eq!(cache.lookup_domain_for_pid(100, &other_ip), None);
        assert_eq!(
            cache.lookup_domain_for_pid(300, &other_ip),
            Some("third.example".to_string())
        );

        // Removing an absent or already-removed PID is a safe no-op.
        cache.remove_pid(100);
        cache.remove_pid(9999);
        assert_eq!(cache.len(), 1);
        cache.remove_pid(300);
        assert!(cache.is_empty());
    }
}
