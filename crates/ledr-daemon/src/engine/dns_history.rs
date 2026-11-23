use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use ledr_rules::{canonical_ip, matches_network_target};

use crate::firewall::parse_literal_target_ip;

pub(super) const MAX_DOMAINS_PER_PROCESS_IP: usize = 16;

const CROSS_PROCESS_DNS_CONFLICT_WINDOW_MS: i64 = 3_600_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DomainTimestamp {
    pub(super) domain: String,
    pub(super) timestamp_ms: i64,
}

#[derive(Debug, Clone)]
pub(super) struct DnsHistoryEntry {
    pub(super) exe_key: String,
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
    pub(super) entries: HashMap<(String, IpAddr), DnsHistoryEntry>,
    insertion_order: VecDeque<(String, IpAddr)>,
    pub(super) latest_domain_by_exe: HashMap<(String, String), LatestDomainIps>,
    latest_domain_order: VecDeque<(String, String)>,
    recent_exe_ip_resolvers: HashMap<(String, IpAddr), Vec<ExeIpResolverRecord>>,
    recent_exe_ip_order: VecDeque<(String, IpAddr)>,
}

impl ProcessDnsHistory {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            latest_domain_by_exe: HashMap::new(),
            latest_domain_order: VecDeque::new(),
            recent_exe_ip_resolvers: HashMap::new(),
            recent_exe_ip_order: VecDeque::new(),
        }
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
        let norm_domain = query_name.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm_domain.is_empty() || resolved_ips.is_empty() {
            return Vec::new();
        }
        let exe_norm = exe_key.trim().to_ascii_lowercase();
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
            let domain_key = (exe_norm.clone(), norm_domain.clone());
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
                    self.latest_domain_by_exe.remove(&oldest);
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
            }
        }

        for &canon in &accepted_ips {
            let key = (process_instance_id.to_string(), canon);
            if let Some(existing) = self.entries.get_mut(&key) {
                if existing.exe_key.is_empty() && !exe_norm.is_empty() {
                    existing.exe_key = exe_norm.clone();
                }
                if let Some(cur) = existing
                    .domains
                    .iter_mut()
                    .find(|d| d.domain == norm_domain)
                {
                    cur.timestamp_ms = cur.timestamp_ms.max(timestamp_ms);
                } else {
                    let latest_map = &self.latest_domain_by_exe;
                    let entry_exe = existing.exe_key.as_str();
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
                        domain: norm_domain.clone(),
                        timestamp_ms,
                    });
                }
            } else {
                while self.entries.len() >= self.capacity {
                    let Some(oldest) = self.insertion_order.pop_front() else {
                        break;
                    };
                    self.entries.remove(&oldest);
                }
                self.insertion_order.push_back(key.clone());
                self.entries.insert(
                    key,
                    DnsHistoryEntry {
                        exe_key: exe_norm.clone(),
                        domains: vec![DomainTimestamp {
                            domain: norm_domain.clone(),
                            timestamp_ms,
                        }],
                    },
                );
            }

            if !exe_norm.is_empty() {
                let resolver_key = (exe_norm.clone(), canon);
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
                        self.recent_exe_ip_resolvers.remove(&oldest);
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
            if k_exe != &exe_norm {
                continue;
            }
            for &cand in &canon_cands {
                if latest
                    .family(cand)
                    .is_some_and(|(latest_ips, _)| latest_ips.contains(&cand))
                {
                    out.push((cand, dom.clone()));
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
        let Some(latest) = self.latest_domain_by_exe.get(&(exe_norm, dom_norm)) else {
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
            .get(&(exe_norm.clone(), dom_norm.clone()))
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
                    k_exe == &exe_norm
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
        let Some(latest) = self.latest_domain_by_exe.get(&(exe_norm, dom_norm)) else {
            return false;
        };
        let Some((latest_ips, latest_ts)) = latest.family(canon) else {
            return false;
        };
        *latest_ts <= event_ts_ms && !latest_ips.contains(&canon)
    }

    fn is_domain_superseded_in_map(
        latest_domain_by_exe: &HashMap<(String, String), LatestDomainIps>,
        exe_key: &str,
        domain: &str,
        timestamp_ms: i64,
        ip: IpAddr,
    ) -> bool {
        if exe_key.is_empty() {
            return false;
        }
        let canon = canonical_ip(ip);
        let Some(latest) = latest_domain_by_exe.get(&(exe_key.to_string(), domain.to_string()))
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
        self.entries
            .retain(|(inst_id, _), _| inst_id != process_instance_id);
        self.insertion_order
            .retain(|(inst_id, _)| inst_id != process_instance_id);
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
            .map(|d| (d.domain.clone(), d.timestamp_ms))
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
            if *entry_ip != canon || entry.exe_key != exe_norm {
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
                    out.push(d.domain.clone());
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
            if entry.exe_key != exe_norm {
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
                    out.push((*entry_ip, d.domain.clone()));
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
        let Some(resolvers) = self.recent_exe_ip_resolvers.get(&(exe_norm, canon)) else {
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
                    d.domain == norm_domain
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
