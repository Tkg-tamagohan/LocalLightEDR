//! Bounded LRU cache correlating `DNS-Client` queries with outbound network events (`AUTO-05`).

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use ledr_proto::DNS_RESOLUTION_CACHE_CAPACITY;

#[derive(Debug, Clone)]
struct CacheEntry {
    domain: String,
    timestamp_ms: i64,
    seq: u64,
}

/// Bounded LRU cache mapping resolved IP addresses back to queried domain names (`AUTO-05`).
#[derive(Debug, Clone)]
pub struct DnsResolutionCache {
    capacity: usize,
    next_seq: u64,
    entries: HashMap<IpAddr, CacheEntry>,
    lru_order: BTreeMap<u64, IpAddr>,
}

impl Default for DnsResolutionCache {
    fn default() -> Self {
        Self::new(DNS_RESOLUTION_CACHE_CAPACITY)
    }
}

impl DnsResolutionCache {
    /// Creates an empty DNS resolution cache bounded to `capacity` IP entries.
    ///
    /// Callers typically pass [`ledr_proto::DNS_RESOLUTION_CACHE_CAPACITY`] (4,096).
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            next_seq: 0,
            entries: HashMap::with_capacity(capacity.min(DNS_RESOLUTION_CACHE_CAPACITY)),
            lru_order: BTreeMap::new(),
        }
    }

    /// Returns the configured maximum number of cached IP-to-domain entries.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the current number of cached IP-to-domain entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries are currently cached.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Inserts or refreshes mappings from each IP in `ips` to `query_name`,
    /// evicting the least-recently-used entries if capacity would be exceeded.
    pub fn insert_resolution(&mut self, query_name: &str, ips: &[IpAddr], timestamp_ms: i64) {
        if self.capacity == 0 {
            return;
        }
        let domain = query_name.trim().trim_end_matches('.');
        if domain.is_empty() {
            return;
        }

        for &ip in ips {
            let seq = self.alloc_seq();
            if let Some(existing) = self.entries.get_mut(&ip) {
                self.lru_order.remove(&existing.seq);
                existing.domain = domain.to_string();
                existing.timestamp_ms = timestamp_ms;
                existing.seq = seq;
                self.lru_order.insert(seq, ip);
                continue;
            }

            while self.entries.len() >= self.capacity {
                let Some((_, oldest_ip)) = self.lru_order.pop_first() else {
                    break;
                };
                self.entries.remove(&oldest_ip);
            }

            self.entries.insert(
                ip,
                CacheEntry {
                    domain: domain.to_string(),
                    timestamp_ms,
                    seq,
                },
            );
            self.lru_order.insert(seq, ip);
        }
    }

    /// Looks up the most recently resolved domain name for `ip` and refreshes its LRU recency.
    pub fn lookup_domain(&mut self, ip: &IpAddr) -> Option<String> {
        self.lookup_entry(ip).map(|(domain, _)| domain)
    }

    /// Looks up `(domain, timestamp_ms)` for `ip` and refreshes its LRU recency.
    pub fn lookup_entry(&mut self, ip: &IpAddr) -> Option<(String, i64)> {
        let new_seq = self.alloc_seq();
        let entry = self.entries.get_mut(ip)?;
        self.lru_order.remove(&entry.seq);
        entry.seq = new_seq;
        self.lru_order.insert(new_seq, *ip);
        Some((entry.domain.clone(), entry.timestamp_ms))
    }

    fn alloc_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }
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
}
