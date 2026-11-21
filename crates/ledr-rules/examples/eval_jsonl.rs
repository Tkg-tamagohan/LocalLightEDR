//! Headless JSONL batch evaluator for `ledr-rules` (designed for Google Colab / offline CI).
//!
//! Usage:
//!   cargo run --release -p ledr-rules --example eval_jsonl -- \
//!     --rules-dir rules \
//!     --input datasets/synth_v2.jsonl \
//!     --nrd-feed datasets/synth_v2_nrd_feed.txt \
//!     --output reports/eval_out.jsonl

use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use ledr_proto::{ProcessIdentity, ScriptSource, SensorEvent};
use ledr_rules::{
    assess_domain_risk, load_rules_dir, parse_nrd_feed_bytes, EarlyPruner, EventContext,
    SigmaEngine, NRD_MAX_ENTRIES,
};
use serde::{Deserialize, Serialize};

struct CliArgs {
    rules_dir: PathBuf,
    input: PathBuf,
    nrd_feed: Option<PathBuf>,
    output: PathBuf,
}

#[derive(Debug, Deserialize)]
struct EvalInputRecord {
    id: String,
    kind: String,
    #[serde(default)]
    parent_image: Option<String>,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    cmdline: Option<String>,
    #[serde(default)]
    script_content: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

#[derive(Debug, Serialize)]
struct EvalOutputRecord {
    id: String,
    alert: bool,
    matched_rules: Vec<String>,
    pruned: bool,
    elapsed_us: u64,
}

fn parse_args() -> Result<CliArgs, Box<dyn Error>> {
    let mut rules_dir: Option<PathBuf> = None;
    let mut input: Option<PathBuf> = None;
    let mut nrd_feed: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rules-dir" => {
                let val = args.next().ok_or("missing value for --rules-dir")?;
                rules_dir = Some(PathBuf::from(val));
            }
            "--input" => {
                let val = args.next().ok_or("missing value for --input")?;
                input = Some(PathBuf::from(val));
            }
            "--nrd-feed" => {
                let val = args.next().ok_or("missing value for --nrd-feed")?;
                nrd_feed = Some(PathBuf::from(val));
            }
            "--output" => {
                let val = args.next().ok_or("missing value for --output")?;
                output = Some(PathBuf::from(val));
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: eval_jsonl --rules-dir <DIR> --input <JSONL> [--nrd-feed <TXT>] --output <JSONL>"
                );
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {other}").into());
            }
        }
    }

    Ok(CliArgs {
        rules_dir: rules_dir.unwrap_or_else(|| PathBuf::from("rules")),
        input: input.ok_or("missing required argument: --input")?,
        nrd_feed,
        output: output.ok_or("missing required argument: --output")?,
    })
}

fn load_nrd_set(path: Option<&PathBuf>) -> Result<HashSet<String>, Box<dyn Error>> {
    let mut set = HashSet::new();
    let Some(feed_path) = path else {
        return Ok(set);
    };
    if !feed_path.exists() {
        return Ok(set);
    }
    let bytes = fs::read(feed_path)?;
    let _ = parse_nrd_feed_bytes(&bytes, &mut set, NRD_MAX_ENTRIES);
    Ok(set)
}

fn evaluate_record(
    rec: &EvalInputRecord,
    sigma: &SigmaEngine,
    pruner: &EarlyPruner,
    nrd_set: &HashSet<String>,
    seq: u32,
) -> EvalOutputRecord {
    let started = Instant::now();
    let mut matched_rules = Vec::new();
    let mut pruned = false;

    match rec.kind.as_str() {
        "cmdline" => {
            let exe_path = rec.image.clone().unwrap_or_default();
            let command_line = rec.cmdline.clone().unwrap_or_default();
            let event = SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(10_000 + seq, 1_000 + u64::from(seq)),
                parent_pid: 4_000,
                exe_path,
                command_line,
                user_sid: None,
            };
            let ctx = EventContext::with_parent(&event, rec.parent_image.as_deref(), None);
            if pruner.should_prune(&ctx) {
                pruned = true;
            } else {
                for m in sigma.evaluate(&ctx) {
                    matched_rules.push(m.rule_id);
                }
            }
        }
        "script" => {
            let script_content = rec.script_content.clone().unwrap_or_default();
            let event = SensorEvent::ScriptEvaluated {
                pid: 20_000 + seq,
                source: ScriptSource::Amsi,
                script_content,
                timestamp_ms: 1_700_000_000_000 + i64::from(seq),
            };
            let ctx = EventContext::new(&event);
            if pruner.should_prune(&ctx) {
                pruned = true;
            } else {
                for m in sigma.evaluate(&ctx) {
                    matched_rules.push(m.rule_id);
                }
            }
        }
        "domain" => {
            if let Some(domain) = rec.domain.as_deref() {
                let risk = assess_domain_risk(domain, Some(nrd_set));
                if risk.is_nrd {
                    matched_rules.push("LEDR-DOMAIN-NRD".to_string());
                }
                if risk.is_homograph {
                    if let Some(brand) = risk.matched_brand {
                        matched_rules.push(format!("LEDR-DOMAIN-HOMOGRAPH:{brand}"));
                    } else {
                        matched_rules.push("LEDR-DOMAIN-HOMOGRAPH".to_string());
                    }
                }
            }
        }
        _ => {}
    }

    let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    EvalOutputRecord {
        id: rec.id.clone(),
        alert: !matched_rules.is_empty(),
        matched_rules,
        pruned,
        elapsed_us,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let loaded = load_rules_dir(&args.rules_dir)?;
    let nrd_set = load_nrd_set(args.nrd_feed.as_ref())?;

    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let reader = BufReader::new(File::open(&args.input)?);
    let mut writer = BufWriter::new(File::create(&args.output)?);

    let mut total = 0u32;
    let mut alerts = 0u32;

    for (idx, line_res) in reader.lines().enumerate() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let rec: EvalInputRecord = serde_json::from_str(trimmed)
            .map_err(|err| format!("line {} JSON parse error: {err}", idx + 1))?;
        let out = evaluate_record(&rec, &loaded.sigma, &loaded.pruner, &nrd_set, total);
        if out.alert {
            alerts += 1;
        }
        serde_json::to_writer(&mut writer, &out)?;
        writer.write_all(b"\n")?;
        total += 1;
    }

    writer.flush()?;
    eprintln!(
        "eval_jsonl: evaluated {total} records ({alerts} alerts) using {} sigma rules and {} NRD entries.",
        loaded.sigma.rule_count(),
        nrd_set.len()
    );
    Ok(())
}
