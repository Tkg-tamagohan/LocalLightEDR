//! Domain risk assessment (NRD cache lookup + Punycode / brand homograph checks, `L-14`).

use std::collections::HashSet;

use crate::label_edit_distance;

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
    let is_nrd = nrd_domains.is_some_and(|set| set.contains(&normalized));

    let has_punycode = normalized
        .split('.')
        .any(|label| label.starts_with("xn--"));

    let sld = extract_second_level_label(&normalized);
    let mut matched_brand = None;
    let mut looks_like_brand_typo = false;

    if let Some(label) = sld {
        for &brand in PROTECTED_BRANDS {
            if label == brand {
                matched_brand = Some(brand.to_string());
                looks_like_brand_typo = false;
                break;
            }
            let dist = label_edit_distance(label, brand);
            if (1..=2).contains(&dist) && label.len() >= 4 {
                matched_brand = Some(brand.to_string());
                looks_like_brand_typo = true;
                break;
            }
        }
    }

    DomainRiskAssessment {
        domain: normalized,
        is_nrd,
        is_homograph: has_punycode || looks_like_brand_typo,
        matched_brand: if has_punycode || looks_like_brand_typo {
            matched_brand
        } else {
            None
        },
    }
}

fn extract_second_level_label(domain: &str) -> Option<&str> {
    let mut parts = domain.rsplit('.');
    let _tld = parts.next()?;
    parts.next()
}
