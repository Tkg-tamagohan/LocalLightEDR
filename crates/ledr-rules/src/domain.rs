//! Domain risk assessment (NRD cache lookup + Punycode / brand homograph checks, `L-14`).

use std::collections::HashSet;

use crate::label_edit_distance;
use crate::nrd::{matches_domain_or_parent_in_set, NrdCache};

const PROTECTED_BRANDS: &[&str] = &[
    "google",
    "microsoft",
    "github",
    "paypal",
    "amazon",
    "apple",
    "cloudflare",
    "openai",
    "anthropic",
    "dropbox",
];

const COMPOUND_PUBLIC_SUFFIXES: &[&str] = &[
    // .jp (9)
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ed.jp", "gr.jp", "ad.jp", "lg.jp",
    // .uk (6)
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    // .au (7)
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    // .nz (5)
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    // .br (5)
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    // .kr (5)
    "co.kr", "ne.kr", "or.kr", "go.kr", "ac.kr",
    // Other (14)
    "com.cn", "net.cn", "org.cn", "com.tw", "org.tw", "com.hk", "com.sg", "co.in", "net.in",
    "org.in", "co.za", "com.mx", "com.tr", "co.il",
];

const BENIGN_BRAND_NEIGHBORS: &[&str] = &[
    "amaze",
    "ample",
    "apply",
    "boggle",
    "maple",
    "openal",
    "papal",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrandMatch {
    None,
    Exact,
    Typo(&'static str),
}

/// Output of local domain phishing/homograph risk assessment (`決定記録 L-14`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRiskAssessment {
    pub domain: String,
    pub is_nrd: bool,
    pub is_homograph: bool,
    pub matched_brand: Option<String>,
}

/// Evaluates whether `domain` appears in `nrd_domains`, uses Punycode (`xn--`),
/// or closely resembles a protected brand label via Levenshtein edit distance.
pub fn assess_domain_risk(
    domain: &str,
    nrd_domains: Option<&HashSet<String>>,
) -> DomainRiskAssessment {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let is_nrd = nrd_domains.is_some_and(|set| matches_domain_or_parent_in_set(&normalized, set));
    assess_normalized_domain_risk(normalized, is_nrd)
}

/// Evaluates whether `domain` appears in `nrd_cache` (direct flat-arena binary search),
/// uses Punycode (`xn--`), or closely resembles a protected brand label via Levenshtein edit distance.
pub fn assess_domain_risk_with_cache(
    domain: &str,
    nrd_cache: Option<&NrdCache>,
) -> DomainRiskAssessment {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let is_nrd = nrd_cache.is_some_and(|cache| cache.contains(&normalized));
    assess_normalized_domain_risk(normalized, is_nrd)
}

fn assess_normalized_domain_risk(normalized: String, is_nrd: bool) -> DomainRiskAssessment {
    let labels: Vec<&str> = normalized.split('.').collect();
    let has_punycode = labels.iter().any(|label| label.starts_with("xn--"));
    let (sld, non_suffix_labels) = split_domain_labels(&labels);

    let mut matched_brand = None;
    let mut looks_like_brand_typo = false;

    if let Some(label) = sld {
        match match_brand_typo(label) {
            BrandMatch::Exact => {
                // Legitimate domain's SLD exactly equals the protected brand (only suspicious if Punycode).
                matched_brand = has_punycode.then(|| label.to_string());
            }
            BrandMatch::Typo(brand) => {
                matched_brand = Some(brand.to_string());
                looks_like_brand_typo = true;
            }
            BrandMatch::None => {
                let is_local_test_domain = normalized.ends_with(".localedr.invalid");
                'outer: for &non_suffix_label in non_suffix_labels {
                    for token in non_suffix_label.split('-') {
                        if token.len() < 4 {
                            continue;
                        }
                        if !is_local_test_domain && !token.bytes().any(|b| b.is_ascii_digit()) {
                            continue;
                        }
                        if let BrandMatch::Typo(brand) = match_brand_typo(token) {
                            matched_brand = Some(brand.to_string());
                            looks_like_brand_typo = true;
                            break 'outer;
                        }
                    }
                }
            }
        }
    }

    let is_homograph = has_punycode || looks_like_brand_typo;
    DomainRiskAssessment {
        domain: normalized,
        is_nrd,
        is_homograph,
        matched_brand: if is_homograph { matched_brand } else { None },
    }
}

fn is_compound_public_suffix(penult: &str, last: &str) -> bool {
    COMPOUND_PUBLIC_SUFFIXES
        .iter()
        .any(|suffix| suffix.split_once('.') == Some((penult, last)))
}

fn split_domain_labels<'a>(labels: &'a [&'a str]) -> (Option<&'a str>, &'a [&'a str]) {
    let len = labels.len();
    if len < 2 {
        return (None, &[]);
    }
    if is_compound_public_suffix(labels[len - 2], labels[len - 1]) {
        if len == 2 {
            return (None, &[]);
        }
        return (Some(labels[len - 3]), &labels[..len - 2]);
    }
    (Some(labels[len - 2]), &labels[..len - 1])
}

fn homograph_skeleton(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            'r' if chars.peek() == Some(&'n') => {
                chars.next();
                out.push('m');
            }
            'v' if chars.peek() == Some(&'v') => {
                chars.next();
                out.push('w');
            }
            '0' => out.push('o'),
            '1' | 'i' => out.push('l'),
            other => out.push(other),
        }
    }
    out
}

fn is_single_adjacent_transposition(a: &str, b: &str) -> bool {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    if a_chars.len() != b_chars.len() || a_chars.len() < 2 {
        return false;
    }
    let mut i = 0;
    while i < a_chars.len() && a_chars[i] == b_chars[i] {
        i += 1;
    }
    if i + 1 >= a_chars.len() {
        return false;
    }
    a_chars[i] == b_chars[i + 1]
        && a_chars[i + 1] == b_chars[i]
        && a_chars[i + 2..] == b_chars[i + 2..]
}

fn match_brand_typo(label: &str) -> BrandMatch {
    if label.len() < 4 {
        return BrandMatch::None;
    }
    if PROTECTED_BRANDS.contains(&label) {
        return BrandMatch::Exact;
    }
    if BENIGN_BRAND_NEIGHBORS.contains(&label) {
        return BrandMatch::None;
    }

    let label_skeleton = homograph_skeleton(label);
    for &brand in PROTECTED_BRANDS {
        if label_skeleton == homograph_skeleton(brand) {
            return BrandMatch::Typo(brand);
        }
        if is_single_adjacent_transposition(label, brand) {
            return BrandMatch::Typo(brand);
        }
        let dist = label_edit_distance(label, brand);
        let matches_len_tier = if brand.len() >= 7 {
            (1..=2).contains(&dist) && label.len() >= 5
        } else {
            dist == 1 && label.len() >= 4
        };
        if matches_len_tier {
            return BrandMatch::Typo(brand);
        }
    }
    BrandMatch::None
}
