//! Lightweight Sigma subset engine backed by an Aho-Corasick prefilter (`決定記録 L-12`).

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use aho_corasick::{AhoCorasick, MatchKind};
use ledr_proto::{AlertSeverity, SensorEvent};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::RulesError;

const MAX_REGEX_COMPILED_SIZE_BYTES: usize = 256 * 1024;

/// Supported event and immediate-parent fields in the lightweight Sigma subset (`L-12`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigmaField {
    Image,
    ParentImage,
    CommandLine,
    ParentCommandLine,
    DestinationIp,
    QueryName,
    TargetFilename,
    ScriptContent,
}

impl SigmaField {
    const ALL: [Self; 8] = [
        Self::Image,
        Self::ParentImage,
        Self::CommandLine,
        Self::ParentCommandLine,
        Self::DestinationIp,
        Self::QueryName,
        Self::TargetFilename,
        Self::ScriptContent,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Image => 0,
            Self::ParentImage => 1,
            Self::CommandLine => 2,
            Self::ParentCommandLine => 3,
            Self::DestinationIp => 4,
            Self::QueryName => 5,
            Self::TargetFilename => 6,
            Self::ScriptContent => 7,
        }
    }
}

/// Supported matching modifiers for a [`FieldCondition`] (`L-12`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MatchModifier {
    Exact,
    StartsWith,
    EndsWith,
    Contains,
    ContainsAll,
    Regex,
}

/// Single field matching condition inside a [`SigmaRule`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldCondition {
    pub field: SigmaField,
    pub modifier: MatchModifier,
    pub values: Vec<String>,
}

/// Lightweight Sigma detection rule targeting single-event and immediate-parent context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub severity: AlertSeverity,
    #[serde(default)]
    pub description: Option<String>,
    pub conditions: Vec<FieldCondition>,
}

/// Evaluation context combining a normalized [`SensorEvent`] with immediate parent process metadata.
#[derive(Debug, Clone, Copy)]
pub struct EventContext<'a> {
    pub event: &'a SensorEvent,
    pub parent_exe_path: Option<&'a str>,
    pub parent_command_line: Option<&'a str>,
}

impl<'a> EventContext<'a> {
    /// Creates an [`EventContext`] without parent metadata.
    pub const fn new(event: &'a SensorEvent) -> Self {
        Self {
            event,
            parent_exe_path: None,
            parent_command_line: None,
        }
    }

    /// Creates an [`EventContext`] populated with parent process metadata.
    pub const fn with_parent(
        event: &'a SensorEvent,
        parent_exe_path: Option<&'a str>,
        parent_command_line: Option<&'a str>,
    ) -> Self {
        Self {
            event,
            parent_exe_path,
            parent_command_line,
        }
    }
}

/// Match result produced by [`SigmaEngine::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigmaMatch {
    pub rule_id: String,
    pub title: String,
    pub severity: AlertSeverity,
    pub matched_fields: Vec<SigmaField>,
}

#[derive(Debug, Deserialize)]
struct SigmaRuleFile {
    rules: Vec<SigmaRule>,
}

#[derive(Debug)]
enum CompiledConditionKind {
    Literal(Vec<String>),
    Regex(Vec<Regex>),
}

#[derive(Debug)]
struct CompiledCondition {
    field: SigmaField,
    modifier: MatchModifier,
    kind: CompiledConditionKind,
}

#[derive(Debug)]
struct CompiledRule {
    rule: SigmaRule,
    conditions: Vec<CompiledCondition>,
}

/// Compiled lightweight Sigma subset evaluator using an ASCII case-insensitive Aho-Corasick prefilter.
#[derive(Debug, Default)]
pub struct SigmaEngine {
    compiled_rules: Vec<CompiledRule>,
    ac: Option<AhoCorasick>,
    pattern_targets: Vec<Vec<(usize, SigmaField)>>,
    fallback_rule_indices: Vec<usize>,
}

impl SigmaEngine {
    /// Compiles `rules` into an Aho-Corasick prefilter and precompiled bounded regexes.
    pub fn from_rules(rules: Vec<SigmaRule>) -> Result<Self, RulesError> {
        let mut seen_ids = HashSet::with_capacity(rules.len());
        let mut compiled_rules = Vec::with_capacity(rules.len());
        let mut patterns: Vec<String> = Vec::new();
        let mut pattern_index: HashMap<String, usize> = HashMap::new();
        let mut pattern_targets: Vec<Vec<(usize, SigmaField)>> = Vec::new();
        let mut fallback_rule_indices = Vec::new();

        for (rule_idx, rule) in rules.into_iter().enumerate() {
            if rule.id.trim().is_empty() {
                return Err(RulesError::InvalidRule {
                    rule_id: "<empty>".to_string(),
                    reason: "rule id must not be empty".to_string(),
                });
            }
            if !seen_ids.insert(rule.id.clone()) {
                return Err(RulesError::InvalidRule {
                    rule_id: rule.id,
                    reason: "duplicate rule id".to_string(),
                });
            }
            if rule.conditions.is_empty() {
                return Err(RulesError::InvalidRule {
                    rule_id: rule.id,
                    reason: "rule must contain at least one condition".to_string(),
                });
            }

            let mut compiled_conditions = Vec::with_capacity(rule.conditions.len());
            for cond in &rule.conditions {
                if cond.values.is_empty() {
                    return Err(RulesError::InvalidRule {
                        rule_id: rule.id,
                        reason: format!("condition on {:?} must have at least one value", cond.field),
                    });
                }
                let kind = if cond.modifier == MatchModifier::Regex {
                    let mut regexes = Vec::with_capacity(cond.values.len());
                    for pat in &cond.values {
                        let re = RegexBuilder::new(pat)
                            .size_limit(MAX_REGEX_COMPILED_SIZE_BYTES)
                            .dfa_size_limit(MAX_REGEX_COMPILED_SIZE_BYTES)
                            .build()
                            .map_err(|source| RulesError::InvalidRegex {
                                rule_id: rule.id.clone(),
                                source,
                            })?;
                        regexes.push(re);
                    }
                    CompiledConditionKind::Regex(regexes)
                } else {
                    CompiledConditionKind::Literal(cond.values.clone())
                };
                compiled_conditions.push(CompiledCondition {
                    field: cond.field,
                    modifier: cond.modifier,
                    kind,
                });
            }

            if let Some(anchor_idx) = select_anchor_condition(&rule.conditions) {
                let anchor = &rule.conditions[anchor_idx];
                if anchor.modifier == MatchModifier::ContainsAll {
                    if let Some(best_lit) = anchor.values.iter().max_by_key(|v| v.len()) {
                        register_pattern(
                            best_lit,
                            rule_idx,
                            anchor.field,
                            &mut patterns,
                            &mut pattern_index,
                            &mut pattern_targets,
                        );
                    }
                } else {
                    for lit in &anchor.values {
                        register_pattern(
                            lit,
                            rule_idx,
                            anchor.field,
                            &mut patterns,
                            &mut pattern_index,
                            &mut pattern_targets,
                        );
                    }
                }
            } else {
                fallback_rule_indices.push(rule_idx);
            }

            compiled_rules.push(CompiledRule {
                rule,
                conditions: compiled_conditions,
            });
        }

        let ac = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::Standard)
                    .build(&patterns)?,
            )
        };

        Ok(Self {
            compiled_rules,
            ac,
            pattern_targets,
            fallback_rule_indices,
        })
    }

    /// Parses rules from JSON (`{ "rules": [...] }` or `[...]`) and compiles the engine.
    pub fn from_json_str(json: &str) -> Result<Self, RulesError> {
        let rules = parse_sigma_rules_json(json)?;
        Self::from_rules(rules)
    }

    /// Reads a JSON rule file from disk and compiles the engine.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, RulesError> {
        let raw = fs::read_to_string(path)?;
        Self::from_json_str(&raw)
    }

    /// Returns the number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.compiled_rules.len()
    }

    /// Returns the number of distinct literal patterns compiled into the Aho-Corasick automaton.
    pub fn aho_corasick_pattern_count(&self) -> usize {
        self.pattern_targets.len()
    }

    /// Returns an iterator over the loaded [`SigmaRule`] definitions.
    pub fn rules(&self) -> impl Iterator<Item = &SigmaRule> {
        self.compiled_rules.iter().map(|c| &c.rule)
    }

    /// Evaluates `ctx` against compiled rules and returns all matching rules.
    pub fn evaluate(&self, ctx: &EventContext<'_>) -> Vec<SigmaMatch> {
        self.evaluate_with_image(ctx, None)
    }

    /// Evaluates `ctx` with an optional resolved `process_exe_path` for non-`ProcessStart` events.
    pub fn evaluate_with_image(
        &self,
        ctx: &EventContext<'_>,
        process_exe_path: Option<&str>,
    ) -> Vec<SigmaMatch> {
        if self.compiled_rules.is_empty() {
            return Vec::new();
        }

        let mut ip_buf = String::new();
        let fields = extract_fields(ctx, process_exe_path, &mut ip_buf);

        let mut candidate_flags = vec![false; self.compiled_rules.len()];
        let mut candidates = Vec::new();

        if let Some(ac) = &self.ac {
            for field in SigmaField::ALL {
                let Some(value) = fields[field.index()] else {
                    continue;
                };
                if value.is_empty() {
                    continue;
                }
                for mat in ac.find_overlapping_iter(value) {
                    let targets = &self.pattern_targets[mat.pattern().as_usize()];
                    for &(rule_idx, expected_field) in targets {
                        if expected_field == field && !candidate_flags[rule_idx] {
                            candidate_flags[rule_idx] = true;
                            candidates.push(rule_idx);
                        }
                    }
                }
            }
        }

        for &rule_idx in &self.fallback_rule_indices {
            if !candidate_flags[rule_idx] {
                candidate_flags[rule_idx] = true;
                candidates.push(rule_idx);
            }
        }

        candidates.sort_unstable();

        let mut matches = Vec::new();
        for rule_idx in candidates {
            let compiled = &self.compiled_rules[rule_idx];
            if compiled
                .conditions
                .iter()
                .all(|cond| eval_condition(cond, fields[cond.field.index()]))
            {
                let matched_fields = compiled.conditions.iter().map(|c| c.field).collect();
                matches.push(SigmaMatch {
                    rule_id: compiled.rule.id.clone(),
                    title: compiled.rule.title.clone(),
                    severity: compiled.rule.severity,
                    matched_fields,
                });
            }
        }

        matches
    }
}

pub(crate) fn parse_sigma_rules_json(json: &str) -> Result<Vec<SigmaRule>, RulesError> {
    let trimmed = json.trim_start();
    if trimmed.starts_with('[') {
        Ok(serde_json::from_str::<Vec<SigmaRule>>(json)?)
    } else {
        Ok(serde_json::from_str::<SigmaRuleFile>(json)?.rules)
    }
}

fn select_anchor_condition(conditions: &[FieldCondition]) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    for (idx, cond) in conditions.iter().enumerate() {
        if cond.modifier == MatchModifier::Regex {
            continue;
        }
        if cond.values.iter().any(|v| v.is_empty()) {
            continue;
        }
        let score = if cond.modifier == MatchModifier::ContainsAll {
            cond.values.iter().map(String::len).max().unwrap_or(0) * 10
        } else {
            let min_len = cond.values.iter().map(String::len).min().unwrap_or(0);
            (min_len * 10).saturating_sub(cond.values.len())
        };
        if best.is_none_or(|(_, best_score)| score > best_score) {
            best = Some((idx, score));
        }
    }
    best.map(|(idx, _)| idx)
}

fn register_pattern(
    literal: &str,
    rule_idx: usize,
    field: SigmaField,
    patterns: &mut Vec<String>,
    pattern_index: &mut HashMap<String, usize>,
    pattern_targets: &mut Vec<Vec<(usize, SigmaField)>>,
) {
    let key = literal.to_ascii_lowercase();
    let pat_id = if let Some(&existing) = pattern_index.get(&key) {
        existing
    } else {
        let id = patterns.len();
        patterns.push(key.clone());
        pattern_index.insert(key, id);
        pattern_targets.push(Vec::new());
        id
    };
    let targets = &mut pattern_targets[pat_id];
    if !targets.contains(&(rule_idx, field)) {
        targets.push((rule_idx, field));
    }
}

fn extract_fields<'a>(
    ctx: &'a EventContext<'a>,
    process_exe_path: Option<&'a str>,
    ip_buf: &'a mut String,
) -> [Option<&'a str>; 8] {
    let mut out = [None; 8];
    out[SigmaField::ParentImage.index()] = ctx.parent_exe_path;
    out[SigmaField::ParentCommandLine.index()] = ctx.parent_command_line;

    match ctx.event {
        SensorEvent::ProcessStart {
            exe_path,
            command_line,
            ..
        } => {
            out[SigmaField::Image.index()] = Some(exe_path.as_str());
            out[SigmaField::CommandLine.index()] = Some(command_line.as_str());
        }
        SensorEvent::ProcessStop { .. } => {
            out[SigmaField::Image.index()] = process_exe_path;
        }
        SensorEvent::DnsQuery { query_name, .. } => {
            out[SigmaField::Image.index()] = process_exe_path;
            out[SigmaField::QueryName.index()] = Some(query_name.as_str());
        }
        SensorEvent::NetworkConnect { dst_ip, .. } => {
            out[SigmaField::Image.index()] = process_exe_path;
            ip_buf.clear();
            let _ = write!(ip_buf, "{dst_ip}");
            out[SigmaField::DestinationIp.index()] = Some(ip_buf.as_str());
        }
        SensorEvent::CanaryFileAccess { target_path, .. } => {
            out[SigmaField::Image.index()] = process_exe_path;
            out[SigmaField::TargetFilename.index()] = Some(target_path.as_str());
        }
        SensorEvent::ScriptEvaluated { script_content, .. } => {
            out[SigmaField::Image.index()] = process_exe_path;
            out[SigmaField::ScriptContent.index()] = Some(script_content.as_str());
        }
    }

    out
}

fn eval_condition(cond: &CompiledCondition, field_val: Option<&str>) -> bool {
    let Some(value) = field_val else {
        return false;
    };

    match &cond.kind {
        CompiledConditionKind::Literal(patterns) => match cond.modifier {
            MatchModifier::Exact => patterns.iter().any(|p| value.eq_ignore_ascii_case(p)),
            MatchModifier::StartsWith => patterns
                .iter()
                .any(|p| starts_with_ignore_ascii_case(value, p)),
            MatchModifier::EndsWith => patterns
                .iter()
                .any(|p| ends_with_ignore_ascii_case(value, p)),
            MatchModifier::Contains => patterns
                .iter()
                .any(|p| contains_ignore_ascii_case(value, p)),
            MatchModifier::ContainsAll => patterns
                .iter()
                .all(|p| contains_ignore_ascii_case(value, p)),
            MatchModifier::Regex => false,
        },
        CompiledConditionKind::Regex(regexes) => regexes.iter().any(|re| re.is_match(value)),
    }
}

#[inline]
fn starts_with_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    h.get(..n.len()).is_some_and(|s| s.eq_ignore_ascii_case(n))
}

#[inline]
fn ends_with_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    h.len()
        .checked_sub(n.len())
        .and_then(|start| h.get(start..))
        .is_some_and(|s| s.eq_ignore_ascii_case(n))
}

#[inline]
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}
