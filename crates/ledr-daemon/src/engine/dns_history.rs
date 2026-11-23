use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use ledr_rules::{canonical_ip, matches_network_target};

use crate::firewall::parse_literal_target_ip;
use crate::process_table::{PathInterner, PATH_INTERNER_MAX_ENTRIES};

pub(super) const MAX_DOMAINS_PER_PROCESS_IP: usize = 16;

const CROSS_PROCESS_DNS_CONFLICT_WINDOW_MS: i64 = 3_600_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DomainTimestamp {
    pub(super) domain: Arc<str>,
    pub(super) timestamp_ms: i64,
}

#[derive(Debug, Clone)]
pub(super) struct DnsHistoryEntry {
    pub(super) exe_key: Arc<str>,
    pub(super) domains: Vec<DomainTimestamp>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct LatestDomainIps {
    pub(super) ipv4: Option<(Vec<IpAddr>, i64)>,
    ipv6: Option<(Vec<IpAddr>, i64)>,
}

impl LatestDomainIps {
    fn family(&self, ip: IpAddr) -> Option<&(Vec<IpAddr>, i64)> {
        if canonical_ip(ip).is_ipv4() {
            self.ipv4.as_ref()
        } else {
            self.ipv6.as_ref()
        }
    }
}

const MAX_RESOLVERS_PER_EXE_IP: usize = 8;

#[derive(Debug, Clone)]
pub(super) struct ExeIpResolverRecord {
    pub(super) instance_id: String,
    pub(super) dns_timestamp_ms: i64,
    pub(super) process_created_at_ms: Option<i64>,
}

#[derive(Debug, Default)]
pub(super) struct ProcessDnsHistory {
    capacity: usize,
    interner: PathInterner,
    pub(super) entries: HashMap<(String, IpAddr), DnsHistoryEntry>,
    insertion_order: VecDeque<(String, IpAddr)>,
    pub(super) latest_domain_by_exe: HashMap<(Arc<str>, Arc<str>), LatestDomainIps>,
    latest_domain_order: VecDeque<(Arc<str>, Arc<str>)>,
    recent_exe_ip_resolvers: HashMap<(Arc<str>, IpAddr), Vec<ExeIpResolverRecord>>,
    recent_exe_ip_order: VecDeque<(Arc<str>, IpAddr)>,
}

impl ProcessDnsHistory {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            interner: PathInterner::new(PATH_INTERNER_MAX_ENTRIES),
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            latest_domain_by_exe: HashMap::new(),
            latest_domain_order: VecDeque::new(),
            recent_exe_ip_resolvers: HashMap::new(),
            recent_exe_ip_order: VecDeque::new(),
        }
    }

    fn shrink_map<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>) {
        let target = map.len().saturating_mul(2).max(64);
        if map.capacity() > target {
            map.shrink_to(target);
        }
    }

    fn shrink_deque<T>(deque: &mut VecDeque<T>) {
        let target = deque.len().saturating_mul(2).max(64);
        if deque.capacity() > target {
            deque.shrink_to(target);
        }
    }

    pub(super) fn maybe_shrink_capacities(&mut self) {
        Self::shrink_map(&mut self.entries);
        Self::shrink_deque(&mut self.insertion_order);
        Self::shrink_map(&mut self.latest_domain_by_exe);
        Self::shrink_deque(&mut self.latest_domain_order);
        Self::shrink_map(&mut self.recent_exe_ip_resolvers);
        Self::shrink_deque(&mut self.recent_exe_ip_order);
    }

    pub(super) fn sweep_interner_and_shrink(&mut self) -> usize {
        self.maybe_shrink_capacities();
        self.interner.sweep_dead()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn record(
        &mut self,
        process_instance_id: &str,
        query_name: &str,
        resolved_ips: &[IpAddr],
        timestamp_ms: i64,
    ) {
        self.record_for_exe(process_instance_id, "", query_name, resolved_ips, timestamp_ms);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn record_for_exe(
        &mut self,
        process_instance_id: &str,
        exe_key: &str,
        query_name: &str,
        resolved_ips: &[IpAddr],
        timestamp_ms: i64,
    ) -> Vec<IpAddr> {
        self.record_for_exe_with_created_at(
            process_instance_id,
            exe_key,
            query_name,
            resolved_ips,
            timestamp_ms,
            None,
        )
    }

    pub(super) fn record_for_exe_with_created_at(
        &mut self,
        process_instance_id: &str,
        exe_key: &str,
        query_name: &str,
        resolved_ips: &[IpAddr],
        timestamp_ms: i64,
        process_created_at_ms: Option<i64>,
    ) -> Vec<IpAddr> {
        let norm_domain_str = query_name.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm_domain_str.is_empty() || resolved_ips.is_empty() {
            return Vec::new();
        }
        let exe_norm_str = exe_key.trim().to_ascii_lowercase();
        let norm_domain = self.interner.intern(&norm_domain_str);
        let exe_norm = self.interner.intern(&exe_norm_str);
        let mut pruned_or_evicted = false;
        let mut canon_ips: Vec<IpAddr> = Vec::with_capacity(resolved_ips.len());
        let mut v4_ips: Vec<IpAddr> = Vec::new();
        let mut v6_ips: Vec<IpAddr> = Vec::new();
        for &ip in resolved_ips {
            let c = canonical_ip(ip);
            if !canon_ips.contains(&c) {
                canon_ips.push(c);
                if c.is_ipv4() {
                    v4_ips.push(c);
                } else {
                    v6_ips.push(c);
                }
            }
        }

        let mut updated_v4 = false;
        let mut updated_v6 = false;
        let accepted_v4: Vec<IpAddr>;
        let accepted_v6: Vec<IpAddr>;

        if !exe_norm.is_empty() {
            let domain_key = (Arc::clone(&exe_norm), Arc::clone(&norm_domain));
            if let Some(latest) = self.latest_domain_by_exe.get_mut(&domain_key) {
                accepted_v4 = if v4_ips.is_empty() {
                    Vec::new()
                } else {
                    match &latest.ipv4 {
                        Some((prev_ips, prev_ts)) if timestamp_ms < *prev_ts => v4_ips
                            .into_iter()
                            .filter(|ip| prev_ips.contains(ip))
                            .collect(),
                        _ => {
                            latest.ipv4 = Some((v4_ips.clone(), timestamp_ms));
                            updated_v4 = true;
                            v4_ips
                        }
                    }
                };
                accepted_v6 = if v6_ips.is_empty() {
                    Vec::new()
                } else {
                    match &latest.ipv6 {
                        Some((prev_ips, prev_ts)) if timestamp_ms < *prev_ts => v6_ips
                            .into_iter()
                            .filter(|ip| prev_ips.contains(ip))
                            .collect(),
                        _ => {
                            latest.ipv6 = Some((v6_ips.clone(), timestamp_ms));
                            updated_v6 = true;
                            v6_ips
                        }
                    }
                };
            } else {
                let domain_cap = self.capacity.max(1);
                while self.latest_domain_by_exe.len() >= domain_cap {
                    let Some(oldest) = self.latest_domain_order.pop_front() else {
                        break;
                    };
                    if self.latest_domain_by_exe.remove(&oldest).is_some() {
                        pruned_or_evicted = true;
                    }
                }
                let mut latest = LatestDomainIps::default();
                if !v4_ips.is_empty() {
                    latest.ipv4 = Some((v4_ips.clone(), timestamp_ms));
                    updated_v4 = true;
                }
                if !v6_ips.is_empty() {
                    latest.ipv6 = Some((v6_ips.clone(), timestamp_ms));
                    updated_v6 = true;
                }
                self.latest_domain_order.push_back(domain_key.clone());
                self.latest_domain_by_exe.insert(domain_key, latest);
                accepted_v4 = v4_ips;
                accepted_v6 = v6_ips;
            }
        } else {
            updated_v4 = !v4_ips.is_empty();
            updated_v6 = !v6_ips.is_empty();
            accepted_v4 = v4_ips;
            accepted_v6 = v6_ips;
        }

        let accepted_ips: Vec<IpAddr> = canon_ips
            .into_iter()
            .filter(|ip| {
                if ip.is_ipv4() {
                    accepted_v4.contains(ip)
                } else {
                    accepted_v6.contains(ip)
                }
            })
            .collect();
        if accepted_ips.is_empty() {
            return Vec::new();
        }

        if updated_v4 || updated_v6 {
            let mut removed_keys: Vec<(String, IpAddr)> = Vec::new();
            self.entries.retain(|(inst_id, entry_ip), entry| {
                let same_scope = inst_id == process_instance_id
                    || (!exe_norm.is_empty() && entry.exe_key == exe_norm);
                let family_updated =
                    (updated_v4 && entry_ip.is_ipv4()) || (updated_v6 && entry_ip.is_ipv6());
                if same_scope && family_updated && !accepted_ips.contains(entry_ip) {
                    entry.domains.retain(|d| {
                        !(d.domain == norm_domain && d.timestamp_ms <= timestamp_ms)
                    });
                }
                let keep = !entry.domains.is_empty();
                if !keep {
                    removed_keys.push((inst_id.clone(), *entry_ip));
                }
                keep
            });
            if !removed_keys.is_empty() {
                self.insertion_order.retain(|k| !removed_keys.contains(k));
                pruned_or_evicted = true;
            }
        }

        for &canon in &accepted_ips {
            let key = (process_instance_id.to_string(), canon);
            if let Some(existing) = self.entries.get_mut(&key) {
                if existing.exe_key.is_empty() && !exe_norm.is_empty() {
                    existing.exe_key = Arc::clone(&exe_norm);
                }
                if let Some(cur) = existing
                    .domains
                    .iter_mut()
                    .find(|d| d.domain == norm_domain)
                {
                    cur.timestamp_ms = cur.timestamp_ms.max(timestamp_ms);
                } else {
                    let latest_map = &self.latest_domain_by_exe;
                    let entry_exe = &existing.exe_key;
                    if existing.domains.len() >= MAX_DOMAINS_PER_PROCESS_IP {
                        existing.domains.retain(|d| {
                            !Self::is_domain_superseded_in_map(
                                latest_map,
                                entry_exe,
                                &d.domain,
                                d.timestamp_ms,
                                canon,
                            )
                        });
                    }
                    while existing.domains.len() >= MAX_DOMAINS_PER_PROCESS_IP {
                        if let Some((oldest_idx, _)) = existing
                            .domains
                            .iter()
                            .enumerate()
                            .min_by_key(|(idx, d)| (d.timestamp_ms, *idx))
                        {
                            existing.domains.remove(oldest_idx);
                        } else {
                            break;
                        }
                    }
                    existing.domains.push(DomainTimestamp {
                        domain: Arc::clone(&norm_domain),
                        timestamp_ms,
                    });
                }
            } else {
                while self.entries.len() >= self.capacity {
                    let Some(oldest) = self.insertion_order.pop_front() else {
                        break;
                    };
                    if self.entries.remove(&oldest).is_some() {
                        pruned_or_evicted = true;
                    }
                }
                self.insertion_order.push_back(key.clone());
                self.entries.insert(
                    key,
                    DnsHistoryEntry {
                        exe_key: Arc::clone(&exe_norm),
                        domains: vec![DomainTimestamp {
                            domain: Arc::clone(&norm_domain),
                            timestamp_ms,
                        }],
                    },
                );
            }

            if !exe_norm.is_empty() {
                let resolver_key = (Arc::clone(&exe_norm), canon);
                if let Some(resolvers) = self.recent_exe_ip_resolvers.get_mut(&resolver_key) {
                    if let Some(existing) = resolvers
                        .iter_mut()
                        .find(|r| r.instance_id == process_instance_id)
                    {
                        existing.dns_timestamp_ms = existing.dns_timestamp_ms.max(timestamp_ms);
                        if existing.process_created_at_ms.is_none() {
                            existing.process_created_at_ms = process_created_at_ms;
                        }
                    } else {
                        while resolvers.len() >= MAX_RESOLVERS_PER_EXE_IP {
                            if let Some((oldest_idx, _)) = resolvers
                                .iter()
                                .enumerate()
                                .min_by_key(|(idx, r)| (r.dns_timestamp_ms, *idx))
                            {
                                resolvers.remove(oldest_idx);
                            } else {
                                break;
                            }
                        }
                        resolvers.push(ExeIpResolverRecord {
                            instance_id: process_instance_id.to_string(),
                            dns_timestamp_ms: timestamp_ms,
                            process_created_at_ms,
                        });
                    }
                } else {
                    while self.recent_exe_ip_resolvers.len() >= self.capacity {
                        let Some(oldest) = self.recent_exe_ip_order.pop_front() else {
                            break;
                        };
                        if self.recent_exe_ip_resolvers.remove(&oldest).is_some() {
                            pruned_or_evicted = true;
                        }
                    }
                    self.recent_exe_ip_order.push_back(resolver_key.clone());
                    self.recent_exe_ip_resolvers.insert(
                        resolver_key,
                        vec![ExeIpResolverRecord {
                            instance_id: process_instance_id.to_string(),
                            dns_timestamp_ms: timestamp_ms,
                            process_created_at_ms,
                        }],
                    );
                }
            }
        }
        if pruned_or_evicted {
            self.maybe_shrink_capacities();
        }
        accepted_ips
    }

    pub(super) fn current_domains_by_ip_for_exe(
        &self,
        exe_key: &str,
        candidate_ips: &[IpAddr],
    ) -> Vec<(IpAddr, String)> {
        let exe_norm = exe_key.trim().to_ascii_lowercase();
        if exe_norm.is_empty() || candidate_ips.is_empty() {
            return Vec::new();
        }
        let canon_cands: Vec<IpAddr> = candidate_ips.iter().map(|ip| canonical_ip(*ip)).collect();
        let mut out: Vec<(IpAddr, String)> = Vec::new();
        for ((k_exe, dom), latest) in &self.latest_domain_by_exe {
            if k_exe.as_ref() != exe_norm {
                continue;
            }
            for &cand in &canon_cands {
                if latest
                    .family(cand)
                    .is_some_and(|(latest_ips, _)| latest_ips.contains(&cand))
                {
                    out.push((cand, dom.to_string()));
                }
            }
        }
        out
    }

    pub(super) fn is_domain_ip_superseded(&self, exe_key: &str, domain_hint: &str, ip: IpAddr) -> bool {
        let exe_norm = exe_key.trim().to_ascii_lowercase();
        let dom_norm = domain_hint.trim().trim_end_matches('.').to_ascii_lowercase();
        if exe_norm.is_empty() || dom_norm.is_empty() {
            return false;
        }
        let canon = canonical_ip(ip);
        let Some(latest) = self
            .latest_domain_by_exe
            .get(&(Arc::from(exe_norm), Arc::from(dom_norm)))
        else {
            return false;
        };
        let Some((latest_ips, _)) = latest.family(canon) else {
            return false;
        };
        !latest_ips.contains(&canon)
    }

    pub(super) fn has_fresh_domain_record_for_family(
        &self,
        exe_key: &str,
        domain_hint: &str,
        ip: IpAddr,
        event_ts_ms: i64,
        max_age_ms: i64,
        mut wildcard_domain_allowed: impl FnMut(&str) -> bool,
    ) -> bool {
        let exe_norm = exe_key.trim().to_ascii_lowercase();
        let dom_norm = domain_hint.trim().trim_end_matches('.').to_ascii_lowercase();
        if exe_norm.is_empty() || dom_norm.is_empty() {
            return false;
        }
        let canon = canonical_ip(ip);
        let is_fresh = |latest: &LatestDomainIps| {
            latest.family(canon).is_some_and(|(_, latest_ts)| {
                event_ts_ms.saturating_sub(*latest_ts) <= max_age_ms
                    && *latest_ts <= event_ts_ms.saturating_add(60_000)
            })
        };
        if let Some(latest) = self
            .latest_domain_by_exe
            .get(&(Arc::from(exe_norm.as_str()), Arc::from(dom_norm.as_str())))
        {
            if is_fresh(latest) {
                return true;
            }
        }
        if dom_norm.contains('*')
            && !dom_norm.contains('/')
            && parse_literal_target_ip(&dom_norm).is_none()
            && !matches_network_target(&dom_norm, canon, None)
        {
            return self
                .latest_domain_by_exe
                .iter()
                .any(|((k_exe, k_dom), latest)| {
                    k_exe.as_ref() == exe_norm
                        && matches_network_target(&dom_norm, canon, Some(k_dom))
                        && is_fresh(latest)
                        && wildcard_domain_allowed(k_dom)
                });
        }
        false
    }

    pub(super) fn is_domain_ip_superseded_at_or_before(
        &self,
        exe_key: &str,
        domain_hint: &str,
        ip: IpAddr,
        event_ts_ms: i64,
    ) -> bool {
        let exe_norm = exe_key.trim().to_ascii_lowercase();
        let dom_norm = domain_hint.trim().trim_end_matches('.').to_ascii_lowercase();
        if exe_norm.is_empty() || dom_norm.is_empty() {
            return false;
        }
        let canon = canonical_ip(ip);
        let Some(latest) = self
            .latest_domain_by_exe
            .get(&(Arc::from(exe_norm), Arc::from(dom_norm)))
        else {
            return false;
        };
        let Some((latest_ips, latest_ts)) = latest.family(canon) else {
            return false;
        };
        *latest_ts <= event_ts_ms && !latest_ips.contains(&canon)
    }

    fn is_domain_superseded_in_map(
        latest_domain_by_exe: &HashMap<(Arc<str>, Arc<str>), LatestDomainIps>,
        exe_key: &Arc<str>,
        domain: &Arc<str>,
        timestamp_ms: i64,
        ip: IpAddr,
    ) -> bool {
        if exe_key.is_empty() {
            return false;
        }
        let canon = canonical_ip(ip);
        let Some(latest) =
            latest_domain_by_exe.get(&(Arc::clone(exe_key), Arc::clone(domain)))
        else {
            return false;
        };
        let Some((latest_ips, latest_ts)) = latest.family(canon) else {
            return false;
        };
        *latest_ts >= timestamp_ms && !latest_ips.contains(&canon)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn is_entry_superseded(&self, entry: &DnsHistoryEntry, ip: IpAddr) -> bool {
        !entry.domains.is_empty()
            && entry.domains.iter().all(|d| {
                Self::is_domain_superseded_in_map(
                    &self.latest_domain_by_exe,
                    &entry.exe_key,
                    &d.domain,
                    d.timestamp_ms,
                    ip,
                )
            })
    }

    pub(super) fn remove_process(&mut self, process_instance_id: &str) {
        let before = self.entries.len();
        self.entries
            .retain(|(inst_id, _), _| inst_id != process_instance_id);
        self.insertion_order
            .retain(|(inst_id, _)| inst_id != process_instance_id);
        if self.entries.len() < before {
            self.maybe_shrink_capacities();
        }
    }

    pub(super) fn lookup_domains_for_process(
        &self,
        process_instance_id: &str,
        ip: IpAddr,
    ) -> Vec<(String, i64)> {
        let canon = canonical_ip(ip);
        let Some(entry) = self
            .entries
            .get(&(process_instance_id.to_string(), canon))
        else {
            return Vec::new();
        };
        let mut out: Vec<(String, i64)> = entry
            .domains
            .iter()
            .filter(|d| {
                !Self::is_domain_superseded_in_map(
                    &self.latest_domain_by_exe,
                    &entry.exe_key,
                    &d.domain,
                    d.timestamp_ms,
                    canon,
                )
            })
            .map(|d| (d.domain.to_string(), d.timestamp_ms))
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }

    pub(super) fn lookup_fresh_domains_for_process(
        &self,
        process_instance_id: &str,
        ip: IpAddr,
        event_ts_ms: i64,
        max_age_ms: i64,
    ) -> Vec<(String, i64)> {
        self.lookup_domains_for_process(process_instance_id, ip)
            .into_iter()
            .filter(|(_, ts_ms)| {
                event_ts_ms.saturating_sub(*ts_ms) <= max_age_ms
                    && *ts_ms <= event_ts_ms.saturating_add(60_000)
            })
            .collect()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn lookup_for_process(&self, process_instance_id: &str, ip: IpAddr) -> Option<(String, i64)> {
        self.lookup_domains_for_process(process_instance_id, ip)
            .into_iter()
            .next()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn lookup_fresh_for_process(
        &self,
        process_instance_id: &str,
        ip: IpAddr,
        event_ts_ms: i64,
        max_age_ms: i64,
    ) -> Option<(String, i64)> {
        self.lookup_fresh_domains_for_process(process_instance_id, ip, event_ts_ms, max_age_ms)
            .into_iter()
            .next()
    }

    pub(super) fn domains_for_exe_ip(&self, exe_key: &str, ip: IpAddr) -> Vec<String> {
        let canon = canonical_ip(ip);
        let exe_norm = exe_key.trim().to_ascii_lowercase();
        if exe_norm.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<String> = Vec::new();
        for ((_, entry_ip), entry) in &self.entries {
            if *entry_ip != canon || entry.exe_key.as_ref() != exe_norm {
                continue;
            }
            for d in &entry.domains {
                if !Self::is_domain_superseded_in_map(
                    &self.latest_domain_by_exe,
                    &entry.exe_key,
                    &d.domain,
                    d.timestamp_ms,
                    canon,
                ) {
                    out.push(d.domain.to_string());
                }
            }
        }
        for (_, dom) in self.current_domains_by_ip_for_exe(&exe_norm, &[canon]) {
            out.push(dom);
        }
        out.sort();
        out.dedup();
        out
    }

    pub(super) fn active_domains_by_ip_for_exe(&self, exe_key: &str) -> Vec<(IpAddr, String)> {
        let exe_norm = exe_key.trim().to_ascii_lowercase();
        if exe_norm.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<(IpAddr, String)> = Vec::new();
        for ((_, entry_ip), entry) in &self.entries {
            if entry.exe_key.as_ref() != exe_norm {
                continue;
            }
            for d in &entry.domains {
                if !Self::is_domain_superseded_in_map(
                    &self.latest_domain_by_exe,
                    &entry.exe_key,
                    &d.domain,
                    d.timestamp_ms,
                    *entry_ip,
                ) {
                    out.push((*entry_ip, d.domain.to_string()));
                }
            }
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn has_fresh_ip_record_for_other_instance(
        &self,
        exe_key: &str,
        exclude_instance_id: &str,
        ip: IpAddr,
        event_ts_ms: i64,
        max_age_ms: i64,
        max_process_created_at_ms: i64,
        max_post_event_skew_ms: i64,
    ) -> bool {
        let exe_norm = exe_key.trim().to_ascii_lowercase();
        if exe_norm.is_empty() || max_age_ms < 0 {
            return false;
        }
        let canon = canonical_ip(ip);
        let Some(resolvers) = self
            .recent_exe_ip_resolvers
            .get(&(Arc::from(exe_norm), canon))
        else {
            return false;
        };
        let max_dns_ts = event_ts_ms.saturating_add(max_post_event_skew_ms.max(0));
        resolvers.iter().any(|rec| {
            rec.instance_id != exclude_instance_id
                && event_ts_ms.saturating_sub(rec.dns_timestamp_ms) <= max_age_ms
                && rec.dns_timestamp_ms <= max_dns_ts
                && rec
                    .process_created_at_ms
                    .is_some_and(|created_ms| created_ms <= max_process_created_at_ms)
        })
    }

    pub(super) fn another_process_resolved(
        &self,
        current_inst_id: Option<&str>,
        domain: &str,
        ip: IpAddr,
        event_ts_ms: i64,
    ) -> bool {
        let norm_domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm_domain.is_empty() {
            return false;
        }
        let canon = canonical_ip(ip);
        self.entries.iter().any(|((inst_id, entry_ip), entry)| {
            Some(inst_id.as_str()) != current_inst_id
                && *entry_ip == canon
                && entry.domains.iter().any(|d| {
                    d.domain.as_ref() == norm_domain
                        && !Self::is_domain_superseded_in_map(
                            &self.latest_domain_by_exe,
                            &entry.exe_key,
                            &d.domain,
                            d.timestamp_ms,
                            canon,
                        )
                        && event_ts_ms.saturating_sub(d.timestamp_ms)
                            <= CROSS_PROCESS_DNS_CONFLICT_WINDOW_MS
                        && d.timestamp_ms <= event_ts_ms.saturating_add(60_000)
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn dns_mem_01_interns_strings_and_shrinks_capacities_on_prune() {
        let mut hist = ProcessDnsHistory::new(1_024);
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        for i in 0..500u32 {
            hist.record_for_exe(
                &format!("{i}:100"),
                r"C:\Program Files\Browser\browser.exe",
                "shared.example",
                &[ip],
                1_000 + i64::from(i),
            );
        }
        assert_eq!(hist.entries.len(), 500);
        let first = hist
            .entries
            .get(&("0:100".to_string(), ip))
            .expect("first entry");
        let second = hist
            .entries
            .get(&("1:100".to_string(), ip))
            .expect("second entry");
        assert!(Arc::ptr_eq(&first.exe_key, &second.exe_key));
        assert!(Arc::ptr_eq(&first.domains[0].domain, &second.domains[0].domain));

        let peak_cap = hist.entries.capacity();
        assert!(peak_cap >= 500);

        for i in 0..490u32 {
            hist.remove_process(&format!("{i}:100"));
        }
        assert_eq!(hist.entries.len(), 10);
        assert!(
            hist.entries.capacity() < peak_cap,
            "entries capacity {} should shrink below peak {}",
            hist.entries.capacity(),
            peak_cap
        );
        assert!(
            hist.insertion_order.capacity() <= 128,
            "insertion_order capacity {} should shrink",
            hist.insertion_order.capacity()
        );
        let _ = hist.sweep_interner_and_shrink();
    }
}
