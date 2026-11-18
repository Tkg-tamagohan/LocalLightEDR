//! Pure Rust hierarchy builder for View 2 (Process Lineage & Flight Recorder).

use ledr_proto::{FlightRecorderSnapshot, ProcessRecord};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Tree node representing one process and its child processes in View 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTreeNode {
    pub process: ProcessRecord,
    pub is_orphan_root: bool,
    pub dns_count: usize,
    pub network_count: usize,
    pub canary_count: usize,
    pub children: Vec<ProcessTreeNode>,
}

/// Builds a deterministic forest of [`ProcessTreeNode`] values from a [`FlightRecorderSnapshot`].
///
/// Parent links prefer `parent_instance_id` and fall back to a matching active `ppid` candidate
/// only when `parent_instance_id` is `None`. Missing parents or cycles are promoted cleanly to
/// orphan roots (`is_orphan_root = true`) so UI rendering never drops processes or loops.
pub fn build_process_tree(snapshot: &FlightRecorderSnapshot) -> Vec<ProcessTreeNode> {
    let dns_counts = count_by_process(
        snapshot
            .dns_queries
            .iter()
            .map(|q| q.process_instance_id.as_str()),
    );
    let network_counts = count_by_process(
        snapshot
            .network_events
            .iter()
            .map(|n| n.process_instance_id.as_str()),
    );
    let canary_counts = count_by_process(
        snapshot
            .file_canary_events
            .iter()
            .map(|c| c.process_instance_id.as_str()),
    );

    let mut by_id: HashMap<&str, &ProcessRecord> = HashMap::new();
    let mut pid_candidates: HashMap<u32, Vec<&ProcessRecord>> = HashMap::new();
    for proc_rec in &snapshot.processes {
        let id = proc_rec.process_instance_id.as_str();
        if by_id.insert(id, proc_rec).is_none() {
            pid_candidates.entry(proc_rec.pid).or_default().push(proc_rec);
        }
    }

    let mut ordered_ids: Vec<&str> = by_id.keys().copied().collect();
    ordered_ids.sort_by(|a, b| compare_records(by_id[a], by_id[b]));

    let mut parent_map: HashMap<&str, Option<&str>> = HashMap::with_capacity(ordered_ids.len());
    let mut orphan_map: HashMap<&str, bool> = HashMap::with_capacity(ordered_ids.len());

    for &id in &ordered_ids {
        let proc_rec = by_id[id];
        let (parent_id, is_orphan) = resolve_parent(proc_rec, &by_id, &pid_candidates);
        parent_map.insert(id, parent_id);
        orphan_map.insert(id, is_orphan);
    }

    break_cycles(&ordered_ids, &mut parent_map, &mut orphan_map);

    let mut children_map: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut root_ids: Vec<&str> = Vec::new();
    for &id in &ordered_ids {
        match parent_map.get(id).copied().flatten() {
            Some(parent_id) => children_map.entry(parent_id).or_default().push(id),
            None => root_ids.push(id),
        }
    }

    let counts = TelemetryCounts {
        dns: &dns_counts,
        network: &network_counts,
        canary: &canary_counts,
    };

    root_ids
        .into_iter()
        .map(|root_id| assemble_node(root_id, &by_id, &orphan_map, &children_map, &counts))
        .collect()
}

struct TelemetryCounts<'a> {
    dns: &'a HashMap<&'a str, usize>,
    network: &'a HashMap<&'a str, usize>,
    canary: &'a HashMap<&'a str, usize>,
}

fn count_by_process<'a, I>(ids: I) -> HashMap<&'a str, usize>
where
    I: Iterator<Item = &'a str>,
{
    let mut counts = HashMap::new();
    for id in ids {
        *counts.entry(id).or_insert(0) += 1;
    }
    counts
}

fn compare_records(a: &ProcessRecord, b: &ProcessRecord) -> std::cmp::Ordering {
    (a.created_at_ms, a.pid, a.process_instance_id.as_str()).cmp(&(
        b.created_at_ms,
        b.pid,
        b.process_instance_id.as_str(),
    ))
}

fn resolve_parent<'a>(
    proc_rec: &ProcessRecord,
    by_id: &HashMap<&'a str, &'a ProcessRecord>,
    pid_candidates: &HashMap<u32, Vec<&'a ProcessRecord>>,
) -> (Option<&'a str>, bool) {
    if let Some(parent_id) = proc_rec.parent_instance_id.as_deref() {
        if parent_id != proc_rec.process_instance_id {
            if let Some(parent_rec) = by_id.get(parent_id) {
                return (Some(parent_rec.process_instance_id.as_str()), false);
            }
        }
        return (None, true);
    }

    if proc_rec.ppid == 0 || proc_rec.ppid == proc_rec.pid {
        return (None, false);
    }

    if let Some(candidates) = pid_candidates.get(&proc_rec.ppid) {
        if let Some(best) = candidates
            .iter()
            .copied()
            .filter(|cand| {
                cand.process_instance_id != proc_rec.process_instance_id
                    && cand.created_at_ms <= proc_rec.created_at_ms
                    && cand
                        .exited_at_ms
                        .is_none_or(|exit_ms| exit_ms >= proc_rec.created_at_ms)
            })
            .max_by(|a, b| compare_records(a, b))
        {
            return (Some(best.process_instance_id.as_str()), false);
        }
    }

    (None, true)
}

fn break_cycles<'a>(
    ordered_ids: &[&'a str],
    parent_map: &mut HashMap<&'a str, Option<&'a str>>,
    orphan_map: &mut HashMap<&'a str, bool>,
) {
    let mut settled: HashSet<&'a str> = HashSet::with_capacity(ordered_ids.len());
    for &start_id in ordered_ids {
        if settled.contains(start_id) {
            continue;
        }
        let mut chain = Vec::new();
        let mut in_chain = HashSet::new();
        let mut current = Some(start_id);

        while let Some(node_id) = current {
            if settled.contains(node_id) {
                break;
            }
            if !in_chain.insert(node_id) {
                if let Some(&breaker_id) = chain.last() {
                    parent_map.insert(breaker_id, None);
                    orphan_map.insert(breaker_id, true);
                }
                break;
            }
            chain.push(node_id);
            current = parent_map.get(node_id).copied().flatten();
        }

        settled.extend(chain);
    }
}

fn assemble_node(
    id: &str,
    by_id: &HashMap<&str, &ProcessRecord>,
    orphan_map: &HashMap<&str, bool>,
    children_map: &HashMap<&str, Vec<&str>>,
    counts: &TelemetryCounts<'_>,
) -> ProcessTreeNode {
    let proc_rec = by_id[id];
    let children = children_map
        .get(id)
        .map(|child_ids| {
            child_ids
                .iter()
                .map(|&child_id| assemble_node(child_id, by_id, orphan_map, children_map, counts))
                .collect()
        })
        .unwrap_or_default();

    ProcessTreeNode {
        process: proc_rec.clone(),
        is_orphan_root: orphan_map.get(id).copied().unwrap_or(false),
        dns_count: counts.dns.get(id).copied().unwrap_or(0),
        network_count: counts.network.get(id).copied().unwrap_or(0),
        canary_count: counts.canary.get(id).copied().unwrap_or(0),
        children,
    }
}
