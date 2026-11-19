//! Outbound executable risk classification and pre-restricted interpreter discovery.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use ledr_proto::is_never_suspend_process;

use super::OutboundRiskClass;

const SCRIPT_INTERPRETER_EXES: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "node.exe",
    "deno.exe",
    "bun.exe",
    "python.exe",
    "pythonw.exe",
    "python3.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "ruby.exe",
    "perl.exe",
    "php.exe",
];

/// Returns `true` when `exe_path` resides beneath a high-risk user-writable directory segment
/// (`Downloads`, `Temp`, or `Tmp`, `L-03`).
pub fn is_high_risk_executable_path(exe_path: &str) -> bool {
    let trimmed = exe_path.trim();
    if trimmed.is_empty() {
        return false;
    }
    let normalized = strip_extended_prefix(trimmed);
    let mut parts: Vec<&str> = normalized
        .split(['\\', '/'])
        .filter(|seg| !seg.is_empty())
        .collect();
    // Ignore the final filename segment so `C:\Tools\downloader.exe` or `C:\Tools\template.exe`
    // is never misclassified as residing inside `Downloads` or `Temp`.
    if parts.len() <= 1 {
        return false;
    }
    parts.pop();
    parts.into_iter().any(|dir| {
        dir.eq_ignore_ascii_case("downloads")
            || dir.eq_ignore_ascii_case("temp")
            || dir.eq_ignore_ascii_case("tmp")
    })
}

/// Returns `true` when the filename component of `exe_path` is a known script interpreter
/// (`powershell`, `pwsh`, `node`, `python` including versioned names, `wscript`, `cscript`,
/// `mshta`, `ruby`, `perl`, `php`, `deno`, `bun`) (`L-03`).
pub fn is_script_interpreter(exe_path: &str) -> bool {
    let file_name = exe_path
        .trim()
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .trim();
    if file_name.is_empty() {
        return false;
    }
    if SCRIPT_INTERPRETER_EXES
        .iter()
        .any(|name| file_name.eq_ignore_ascii_case(name))
    {
        return true;
    }
    is_versioned_python_exe(file_name)
}

fn is_versioned_python_exe(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    let Some(stem) = lower.strip_suffix(".exe") else {
        return false;
    };
    let rest = if let Some(r) = stem.strip_prefix("pythonw") {
        r
    } else if let Some(r) = stem.strip_prefix("python") {
        r
    } else {
        return false;
    };
    !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && rest.bytes().any(|b| b.is_ascii_digit())
}

const SYSTEM_ROOT_PRERESTRICTED_INTERPRETERS: &[&str] = &[
    r"System32\WindowsPowerShell\v1.0\powershell.exe",
    r"SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
    r"System32\wscript.exe",
    r"System32\cscript.exe",
    r"System32\mshta.exe",
];

const PATH_PRERESTRICTED_INTERPRETERS: &[&str] = &[
    "pwsh.exe",
    "node.exe",
    "python.exe",
    "python3.exe",
];

/// Discovers existing concrete Windows script interpreter executables to pre-restrict at daemon
/// startup (`L-03`, `AUTO-02`).
///
/// Checks standard Windows built-in interpreters under `%SystemRoot%` (`powershell.exe` 64-bit
/// and 32-bit, `wscript.exe`, `cscript.exe`, `mshta.exe`) plus existing `pwsh.exe`, `node.exe`,
/// `python.exe`, and `python3.exe` discovered via `PATH`. Results are deduplicated
/// case-insensitively and exclude any `AUTO-02` protected process.
pub fn discover_default_prerestricted_interpreters() -> Vec<String> {
    let system_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let path_env = std::env::var_os("PATH");
    discover_prerestricted_interpreters_from(Some(system_root.as_path()), path_env.as_deref())
}

pub(crate) fn discover_prerestricted_interpreters_from(
    system_root: Option<&Path>,
    path_env: Option<&OsStr>,
) -> Vec<String> {
    let mut results = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut push_if_eligible = |candidate: PathBuf| {
        if !candidate.is_file() {
            return;
        }
        let raw = candidate.to_string_lossy();
        let trimmed = raw.trim().replace('/', "\\");
        let normalized = if trimmed
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
        {
            format!(r"\\{}", &trimmed[8..])
        } else if trimmed
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\"))
        {
            trimmed[4..].to_string()
        } else {
            trimmed
        };
        if normalized.is_empty() || normalized.contains('*') || normalized.contains('?') {
            return;
        }
        let clean = normalized.trim_end_matches(['.', ' ']);
        if is_never_suspend_process(&normalized) || is_never_suspend_process(clean) {
            return;
        }
        let key = normalized.to_ascii_lowercase();
        if seen.insert(key) {
            results.push(normalized);
        }
    };

    if let Some(root) = system_root {
        if !root.as_os_str().is_empty() {
            for rel in SYSTEM_ROOT_PRERESTRICTED_INTERPRETERS {
                push_if_eligible(root.join(rel));
            }
        }
    }

    if let Some(raw_path) = path_env {
        for dir in std::env::split_paths(raw_path) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            for exe_name in PATH_PRERESTRICTED_INTERPRETERS {
                push_if_eligible(dir.join(exe_name));
            }
        }
    }

    results
}

/// Classifies `exe_path` into its outbound firewall risk tier (`L-03`, `AUTO-02`).
pub fn classify_outbound_risk(exe_path: &str) -> OutboundRiskClass {
    if is_never_suspend_process(exe_path) {
        return OutboundRiskClass::ProtectedOs;
    }
    if is_high_risk_executable_path(exe_path) {
        return OutboundRiskClass::HighRiskPath;
    }
    if is_script_interpreter(exe_path) {
        return OutboundRiskClass::ScriptInterpreter;
    }
    OutboundRiskClass::GeneralUnknown
}

fn strip_extended_prefix(path: &str) -> &str {
    if path
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
    {
        &path[8..]
    } else if path.get(..4).is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\")) {
        &path[4..]
    } else {
        path
    }
}
