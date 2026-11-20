//! Domain-derived IP WFP filter management, hint pruning, staleness invalidation, and eviction.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use ledr_proto::{is_never_suspend_process, ActiveDefenseController, AllowlistRuleRecord};
use ledr_rules::{
    canonical_ip, evaluate_outbound_policy, matches_network_target, BinaryIdentity,
    OutboundDecision,
};

use super::hints::{
    compute_pruned_permit_hints, merge_domain_hint, merge_domain_hints_prioritized,
    normalize_domain_hint,
};
use super::manager::WfpRuleManager;
#[cfg(doc)]
use super::types::MAX_DOMAIN_HINTS_PER_FILTER;
use super::types::{
    parse_literal_target_ip, InstalledWfpFilter, RemovedDomainFilterSnapshot, WfpFilterOrigin,
    WfpTargetKey, MAX_DOMAIN_POLICY_FILTERS,
};

impl WfpRuleManager {
    /// Materializes a domain-scoped persisted `NetworkBlock` rule onto a resolved destination IP
    /// so reconciliation preserves it while the backing domain block rule exists and removes it
    /// immediately once deleted. When reusing an existing `DomainPolicy` Block filter on a shared
    /// IP, merges `domain_hint` into its bounded `domain_hints` set (`#4`).
    pub fn ensure_domain_policy_block(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        domain_hint: &str,
        defense: &dyn ActiveDefenseController,
    ) -> Result<u64, String> {
        self.ensure_domain_policy_block_hints(exe_path, dst_ip, &[domain_hint], defense)
    }

    /// Like [`WfpRuleManager::ensure_domain_policy_block`], merging all non-empty
    /// `domain_hints` into the `DomainPolicy` Block metadata (deduplicated and bounded by
    /// [`MAX_DOMAIN_HINTS_PER_FILTER`]). Passing an empty slice creates or reuses an untagged
    /// (`domain_hints: []`) static/CIDR-backed `DomainPolicy` Block without polluting hints.
    pub fn ensure_domain_policy_block_hints<S: AsRef<str>>(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        domain_hints: &[S],
        defense: &dyn ActiveDefenseController,
    ) -> Result<u64, String> {
        let clean = exe_path.trim().trim_end_matches(['.', ' ']);
        if is_never_suspend_process(exe_path) || is_never_suspend_process(clean) {
            return Err(format!(
                "refusing WFP block for protected process `{exe_path}`"
            ));
        }
        let canon_ip = canonical_ip(dst_ip);
        let mut normalized_hints = Vec::new();
        for raw in domain_hints {
            merge_domain_hint(&mut normalized_hints, raw.as_ref());
        }
        let key = (Self::exe_key(exe_path), Some(canon_ip));
        if let Some(existing) = self.installed.get_mut(&key) {
            if !existing.allow {
                if let WfpFilterOrigin::DomainPolicy {
                    domain_hints: ref mut cur_hints,
                } = existing.origin
                {
                    for hint in &normalized_hints {
                        merge_domain_hint(cur_hints, hint);
                    }
                }
                return Ok(existing.handle);
            }
            let old_handle = existing.handle;
            defense.remove_wfp_rule(old_handle)?;
            self.installed.remove(&key);
        }

        self.evict_domain_policy_if_full(defense);
        let handle = defense.add_wfp_app_rule(Path::new(exe_path), Some(canon_ip), false)?;
        self.installed.insert(
            key,
            InstalledWfpFilter {
                handle,
                exe_path: exe_path.to_string(),
                allow: false,
                origin: WfpFilterOrigin::DomainPolicy {
                    domain_hints: normalized_hints,
                },
            },
        );
        Ok(handle)
    }

    /// Installs an IP-specific Permit filter when a domain-scoped `NetworkAllow` rule authorizes
    /// `(dst_ip, domain_hint)` while an app-wide pre-emptive block is active (weight 13 > weight 11).
    /// Tagged with [`WfpFilterOrigin::DomainPolicy`] so unrelated rule reconciliations preserve it
    /// while rule deletion or a conflicting `NetworkBlock` removes it immediately.
    pub fn ensure_ip_permit_for_domain_rule(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        domain_hint: &str,
        defense: &dyn ActiveDefenseController,
    ) -> Result<Option<u64>, String> {
        self.ensure_ip_permit_for_domain_hints(exe_path, dst_ip, &[domain_hint], defense)
    }

    /// Like [`WfpRuleManager::ensure_ip_permit_for_domain_rule`], merging all non-empty
    /// `domain_hints` into the `DomainPolicy` Permit metadata (deduplicated and bounded by
    /// [`MAX_DOMAIN_HINTS_PER_FILTER`]).
    pub fn ensure_ip_permit_for_domain_hints<S: AsRef<str>>(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        domain_hints: &[S],
        defense: &dyn ActiveDefenseController,
    ) -> Result<Option<u64>, String> {
        self.ensure_ip_permit_for_domain_hints_prioritized(
            exe_path,
            dst_ip,
            &[] as &[&str],
            domain_hints,
            defense,
        )
    }

    /// Like [`WfpRuleManager::ensure_ip_permit_for_domain_hints`], protecting `authorizing_hints`
    /// from FIFO eviction by `cohosted_hints` when [`MAX_DOMAIN_HINTS_PER_FILTER`] is reached
    /// (`AUD-P3-02`). Within the 32-hint cap, preserves insertion order (`authorizing_hints`
    /// followed by `cohosted_hints`).
    pub fn ensure_ip_permit_for_domain_hints_prioritized<S1: AsRef<str>, S2: AsRef<str>>(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        authorizing_hints: &[S1],
        cohosted_hints: &[S2],
        defense: &dyn ActiveDefenseController,
    ) -> Result<Option<u64>, String> {
        let canon_ip = canonical_ip(dst_ip);
        let mut norm_auth = Vec::new();
        for raw in authorizing_hints {
            merge_domain_hint(&mut norm_auth, raw.as_ref());
        }
        let mut norm_cohost = Vec::new();
        for raw in cohosted_hints {
            let Some(norm) = normalize_domain_hint(raw.as_ref()) else {
                continue;
            };
            if !norm_auth.iter().any(|h| h == &norm) && !norm_cohost.iter().any(|h| h == &norm) {
                norm_cohost.push(norm);
            }
        }

        let ip_key = (Self::exe_key(exe_path), Some(canon_ip));
        if let Some(existing) = self.installed.get_mut(&ip_key) {
            if existing.allow {
                if let WfpFilterOrigin::DomainPolicy {
                    domain_hints: ref mut cur_hints,
                } = existing.origin
                {
                    merge_domain_hints_prioritized(cur_hints, &norm_auth, &norm_cohost);
                }
                return Ok(Some(existing.handle));
            }
            // Do not override an explicit/domain IP-specific Block filter (deny-overrides-allow).
            let mut log_hints = Vec::new();
            merge_domain_hints_prioritized(&mut log_hints, &norm_auth, &norm_cohost);
            tracing::warn!(
                exe_path = %exe_path,
                dst_ip = %canon_ip,
                allowed_domain_hints = ?log_hints,
                existing_origin = ?existing.origin,
                "suppressing IP-level WFP Permit for allowed domain because an existing IP Block shares this destination IP (deny-overrides-allow)"
            );
            return Ok(None);
        }

        let mut normalized_hints = Vec::new();
        merge_domain_hints_prioritized(&mut normalized_hints, &norm_auth, &norm_cohost);
        self.evict_domain_policy_if_full(defense);
        let handle = defense.add_wfp_app_rule(Path::new(exe_path), Some(canon_ip), true)?;
        self.installed.insert(
            ip_key,
            InstalledWfpFilter {
                handle,
                exe_path: exe_path.to_string(),
                allow: true,
                origin: WfpFilterOrigin::DomainPolicy {
                    domain_hints: normalized_hints,
                },
            },
        );
        Ok(Some(handle))
    }

    /// Lists active `DomainPolicy` Permit filters whose `domain_hints` was empty at installation
    /// time (e.g., CIDR permits created without inline DNS hints) so reconciliation can cross-check
    /// later DNS history against newly added domain block rules (`SEC_0001`).
    pub fn unnamed_domain_permits(&self) -> Vec<(String, String, IpAddr)> {
        self.installed
            .iter()
            .filter_map(|((exe_k, ip_opt), entry)| {
                let ip = (*ip_opt)?;
                if entry.allow
                    && matches!(
                        &entry.origin,
                        WfpFilterOrigin::DomainPolicy { domain_hints } if domain_hints.is_empty()
                    )
                {
                    Some((exe_k.clone(), entry.exe_path.clone(), ip))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Lists all active `DomainPolicy` Permit filters `(exe_key, exe_path, remote_ip)` so
    /// reconciliation can cross-check live DNS history against newly added domain block rules,
    /// including shared-IP permits tagged with another domain name (`#1`, `#4`).
    pub fn domain_policy_permits(&self) -> Vec<(String, String, IpAddr)> {
        self.installed
            .iter()
            .filter_map(|((exe_k, ip_opt), entry)| {
                let ip = (*ip_opt)?;
                if entry.allow && matches!(&entry.origin, WfpFilterOrigin::DomainPolicy { .. }) {
                    Some((exe_k.clone(), entry.exe_path.clone(), ip))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Lists all active `DomainPolicy` Block filters `(exe_key, remote_ip)` across all executables
    /// so reconciliation can synchronize live DNS-history domains against newly added block rules.
    pub fn all_domain_policy_blocks(&self) -> Vec<(String, IpAddr)> {
        self.installed
            .iter()
            .filter_map(|((exe_k, ip_opt), entry)| {
                let ip = (*ip_opt)?;
                if !entry.allow && matches!(&entry.origin, WfpFilterOrigin::DomainPolicy { .. }) {
                    Some((exe_k.clone(), ip))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Lists all active `DomainPolicy` Permit filters with non-empty `domain_hints` across all
    /// executables so reconciliation can prune migrated/superseded hints before evaluating blocks.
    pub fn all_domain_policy_permits_with_hints(&self) -> Vec<(String, IpAddr, Vec<String>)> {
        self.installed
            .iter()
            .filter_map(|((exe_k, ip_opt), entry)| {
                let ip = (*ip_opt)?;
                if !entry.allow {
                    return None;
                }
                let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin else {
                    return None;
                };
                if domain_hints.is_empty() {
                    return None;
                }
                Some((exe_k.clone(), ip, domain_hints.clone()))
            })
            .collect()
    }

    /// Lists active `DomainPolicy` Permit filters with non-empty `domain_hints` for `exe_path`.
    pub fn domain_policy_permits_with_hints(&self, exe_path: &str) -> Vec<(IpAddr, Vec<String>)> {
        let exe_k = Self::exe_key(exe_path);
        let mut out: Vec<(IpAddr, Vec<String>)> = self
            .installed
            .iter()
            .filter_map(|((k_exe, ip_opt), entry)| {
                if k_exe != &exe_k || !entry.allow {
                    return None;
                }
                let ip = (*ip_opt)?;
                let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin else {
                    return None;
                };
                if domain_hints.is_empty() {
                    return None;
                }
                Some((ip, domain_hints.clone()))
            })
            .collect();
        out.sort_by_key(|a| a.0.to_string());
        out
    }

    /// Returns the `domain_hints` of a live [`WfpFilterOrigin::DomainPolicy`] IP Permit filter
    /// for `(exe_path, remote_ip)` (canonicalizing `remote_ip`), or `None` when no live
    /// `DomainPolicy` IP Permit exists for that target (`AUD-P3-01`).
    pub fn domain_policy_permit_hints(
        &self,
        exe_path: &str,
        remote_ip: IpAddr,
    ) -> Option<Vec<String>> {
        let key = (Self::exe_key(exe_path), Some(canonical_ip(remote_ip)));
        let entry = self.installed.get(&key)?;
        if !entry.allow {
            return None;
        }
        match &entry.origin {
            WfpFilterOrigin::DomainPolicy { domain_hints } => Some(domain_hints.clone()),
            _ => None,
        }
    }

    /// Prunes migrated/superseded domains from [`WfpFilterOrigin::DomainPolicy`] IP Permit filters
    /// for `exe_path` using [`compute_pruned_permit_hints`]:
    /// - When surviving hints or static policy still satisfy `AllowedByRule`, prunes all migrated/
    ///   superseded hints so later blocks on a migrated domain cannot falsely revoke an active
    ///   shared-IP or CIDR Permit.
    /// - Otherwise prunes migrated unallowed co-hosted hints while retaining migrated authorizing
    ///   hints that match a persisted `NetworkAllow` rule so unrelated reconciliations do not
    ///   drop a cached-IP Permit (`PRRT_kwDOVyjVyM65e5kL`).
    /// - Never transitions a non-static Permit into an untagged `domain_hints: []` Permit.
    pub fn prune_migrated_domain_permit_hints_for_query(
        &mut self,
        exe_path: &str,
        query_name: &str,
        new_ips: &[IpAddr],
        identity: &BinaryIdentity,
        rules: &[AllowlistRuleRecord],
        superseded_pairs: &HashSet<(IpAddr, String)>,
    ) -> usize {
        let exe_k = Self::exe_key(exe_path);
        let Some(norm_query) = normalize_domain_hint(query_name) else {
            return 0;
        };
        let new_canon: HashSet<IpAddr> = new_ips.iter().map(|ip| canonical_ip(*ip)).collect();
        let has_v4 = new_canon.iter().any(IpAddr::is_ipv4);
        let has_v6 = new_canon.iter().any(IpAddr::is_ipv6);
        let norm_superseded: HashSet<(IpAddr, String)> = superseded_pairs
            .iter()
            .filter_map(|(ip, dom)| {
                normalize_domain_hint(dom).map(|norm| (canonical_ip(*ip), norm))
            })
            .collect();

        let mut updated_hints: Vec<(WfpTargetKey, Vec<String>)> = Vec::new();
        for (k, entry) in &self.installed {
            if k.0 != exe_k || !entry.allow {
                continue;
            }
            let Some(ip) = k.1 else {
                continue;
            };
            let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin else {
                continue;
            };
            if domain_hints.is_empty() {
                continue;
            }
            let same_family = (has_v4 && ip.is_ipv4()) || (has_v6 && ip.is_ipv6());
            let static_allowed = matches!(
                evaluate_outbound_policy(identity, ip, None, rules),
                OutboundDecision::AllowedByRule { .. }
            );
            let next_hints = compute_pruned_permit_hints(
                domain_hints,
                identity,
                ip,
                rules,
                static_allowed,
                |hint_norm| {
                    let is_domain_hint =
                        !hint_norm.contains('/') && parse_literal_target_ip(hint_norm).is_none();
                    let matches_migrated_query = !new_canon.contains(&ip)
                        && same_family
                        && is_domain_hint
                        && (hint_norm == norm_query
                            || (hint_norm.contains('*')
                                && matches_network_target(hint_norm, ip, Some(&norm_query))));
                    matches_migrated_query
                        || norm_superseded.contains(&(ip, hint_norm.to_string()))
                },
            );
            if &next_hints != domain_hints {
                updated_hints.push((k.clone(), next_hints));
            }
        }

        let updated = updated_hints.len();
        for (key, next_hints) in updated_hints {
            if let Some(entry) = self.installed.get_mut(&key) {
                entry.origin = WfpFilterOrigin::DomainPolicy {
                    domain_hints: next_hints,
                };
            }
        }
        updated
    }

    /// Removes a specific `DomainPolicy` Permit filter from BFE and local tracking, returning a
    /// rollback snapshot when removed.
    pub fn remove_domain_policy_permit(
        &mut self,
        exe_path: &str,
        ip: IpAddr,
        defense: &dyn ActiveDefenseController,
    ) -> Result<Option<RemovedDomainFilterSnapshot>, String> {
        let key = (Self::exe_key(exe_path), Some(canonical_ip(ip)));
        let Some(entry) = self.installed.get(&key).cloned() else {
            return Ok(None);
        };
        let WfpFilterOrigin::DomainPolicy { domain_hints } = entry.origin else {
            return Ok(None);
        };
        if !entry.allow {
            return Ok(None);
        }
        defense.remove_wfp_rule(entry.handle)?;
        self.installed.remove(&key);
        self.bound_alerts.retain(|_, k| k != &key);
        Ok(Some(RemovedDomainFilterSnapshot {
            exe_path: entry.exe_path,
            remote_ip: key.1.unwrap_or(ip),
            allow: true,
            domain_hints,
        }))
    }

    /// Prunes migrated/superseded domains from [`WfpFilterOrigin::DomainPolicy`] IP Block filters
    /// for `exe_path`, synchronizes active blocking reason domains from
    /// `active_blocking_domains_by_ip`, and removes any non-static domain block whose remaining
    /// `domain_hints` becomes empty (`BUG_..._0003`, `#4`).
    #[allow(clippy::too_many_arguments)]
    pub fn invalidate_stale_domain_blocks_for_query(
        &mut self,
        exe_path: &str,
        query_name: &str,
        new_ips: &[IpAddr],
        static_blocked_ips: &HashSet<IpAddr>,
        active_blocking_domains_by_ip: &HashMap<IpAddr, Vec<String>>,
        superseded_pairs: &HashSet<(IpAddr, String)>,
        defense: &dyn ActiveDefenseController,
    ) -> usize {
        let exe_k = Self::exe_key(exe_path);
        let Some(norm_query) = normalize_domain_hint(query_name) else {
            return 0;
        };
        let new_canon: HashSet<IpAddr> = new_ips.iter().map(|ip| canonical_ip(*ip)).collect();
        let has_v4 = new_canon.iter().any(IpAddr::is_ipv4);
        let has_v6 = new_canon.iter().any(IpAddr::is_ipv6);
        let static_blocked_canon: HashSet<IpAddr> = static_blocked_ips
            .iter()
            .map(|ip| canonical_ip(*ip))
            .collect();
        let mut active_by_ip_canon: HashMap<IpAddr, Vec<String>> =
            HashMap::with_capacity(active_blocking_domains_by_ip.len());
        for (ip, doms) in active_blocking_domains_by_ip {
            let entry = active_by_ip_canon.entry(canonical_ip(*ip)).or_default();
            for dom in doms {
                merge_domain_hint(entry, dom);
            }
        }
        let norm_superseded: HashSet<(IpAddr, String)> = superseded_pairs
            .iter()
            .filter_map(|(ip, dom)| {
                normalize_domain_hint(dom).map(|norm| (canonical_ip(*ip), norm))
            })
            .collect();

        let mut stale_keys: Vec<WfpTargetKey> = Vec::new();
        let mut updated_hints: Vec<(WfpTargetKey, Vec<String>)> = Vec::new();

        for (k, entry) in &self.installed {
            if k.0 != exe_k || entry.allow {
                continue;
            }
            let Some(ip) = k.1 else {
                continue;
            };
            let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin else {
                continue;
            };

            let had_non_empty_hints = !domain_hints.is_empty();
            let same_family = (has_v4 && ip.is_ipv4()) || (has_v6 && ip.is_ipv6());
            let mut next_hints: Vec<String> = Vec::with_capacity(domain_hints.len());

            // 1. Prune hints that migrated away in this query or are superseded in DNS history.
            if had_non_empty_hints {
                for raw_hint in domain_hints {
                    let Some(hint_norm) = normalize_domain_hint(raw_hint) else {
                        continue;
                    };
                    let is_domain_hint =
                        !hint_norm.contains('/') && parse_literal_target_ip(&hint_norm).is_none();
                    let matches_migrated_query = !new_canon.contains(&ip)
                        && same_family
                        && is_domain_hint
                        && (hint_norm == norm_query
                            || (hint_norm.contains('*')
                                && matches_network_target(&hint_norm, ip, Some(&norm_query))));
                    let is_superseded = norm_superseded.contains(&(ip, hint_norm.clone()));
                    if !matches_migrated_query && !is_superseded {
                        merge_domain_hint(&mut next_hints, &hint_norm);
                    }
                }
            }

            // 2. Synchronize currently active blocking domains so filter metadata tracks live
            //    blocking reasons even if the original domain later evicts from DNS history FIFO.
            if let Some(active_doms) = active_by_ip_canon.get(&ip) {
                for dom in active_doms {
                    merge_domain_hint(&mut next_hints, dom);
                }
            }

            // 3. Keep the filter if the IP is statically blocked, has any active blocking domain,
            //    originally had no domain hints (CIDR/untagged), or retains at least one
            //    non-migrated, non-superseded domain hint. Do NOT keep solely on
            //    `new_canon.contains(&ip)` because a non-blocked query resolving to an IP whose
            //    previous blocking hints are all superseded must remove the stale block rather
            //    than corrupting its origin to an untagged `domain_hints: []` block.
            let keep = static_blocked_canon.contains(&ip)
                || active_by_ip_canon.contains_key(&ip)
                || !had_non_empty_hints
                || !next_hints.is_empty();

            if keep {
                if &next_hints != domain_hints {
                    updated_hints.push((k.clone(), next_hints));
                }
            } else {
                stale_keys.push(k.clone());
            }
        }

        for (key, next_hints) in updated_hints {
            if let Some(entry) = self.installed.get_mut(&key) {
                entry.origin = WfpFilterOrigin::DomainPolicy {
                    domain_hints: next_hints,
                };
            }
        }

        let mut removed = 0usize;
        for key in stale_keys {
            if let Some(entry) = self.installed.get(&key).cloned() {
                match defense.remove_wfp_rule(entry.handle) {
                    Ok(()) => {
                        self.installed.remove(&key);
                        self.bound_alerts.retain(|_, k| k != &key);
                        removed += 1;
                    }
                    Err(err) => {
                        tracing::warn!(
                            exe_path = %entry.exe_path,
                            remote_ip = ?key.1,
                            wfp_handle = entry.handle,
                            error = %err,
                            "failed removing stale DomainPolicy WFP block filter after domain IP migration"
                        );
                    }
                }
            }
        }
        removed
    }

    pub fn domain_policy_blocks(&self, exe_path: &str) -> Vec<(IpAddr, Vec<String>)> {
        let exe_k = Self::exe_key(exe_path);
        let mut out: Vec<(IpAddr, Vec<String>)> = self
            .installed
            .iter()
            .filter_map(|(k, entry)| {
                if k.0 != exe_k || entry.allow {
                    return None;
                }
                let ip = k.1?;
                let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin else {
                    return None;
                };
                Some((ip, domain_hints.clone()))
            })
            .collect();
        out.sort_by_key(|a| a.0.to_string());
        out
    }

    pub fn domain_policy_block_ips(&self, exe_path: &str) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = self
            .domain_policy_blocks(exe_path)
            .into_iter()
            .map(|(ip, _)| ip)
            .collect();
        out.dedup();
        out
    }

    fn evict_domain_policy_if_full(&mut self, defense: &dyn ActiveDefenseController) {
        let domain_count = self
            .installed
            .values()
            .filter(|e| matches!(e.origin, WfpFilterOrigin::DomainPolicy { .. }))
            .count();
        if domain_count < MAX_DOMAIN_POLICY_FILTERS {
            return;
        }
        // Prefer evicting an older DomainPolicy Permit before touching DomainPolicy Blocks.
        let victim = self
            .installed
            .iter()
            .find(|(_, e)| e.allow && matches!(e.origin, WfpFilterOrigin::DomainPolicy { .. }))
            .or_else(|| {
                self.installed
                    .iter()
                    .find(|(_, e)| matches!(e.origin, WfpFilterOrigin::DomainPolicy { .. }))
            })
            .map(|(k, e)| (k.clone(), e.handle));
        if let Some((key, handle)) = victim {
            if let Err(err) = defense.remove_wfp_rule(handle) {
                tracing::debug!(
                    wfp_handle = handle,
                    error = %err,
                    "failed removing evicted DomainPolicy WFP filter"
                );
            } else {
                self.installed.remove(&key);
            }
        }
    }
}
