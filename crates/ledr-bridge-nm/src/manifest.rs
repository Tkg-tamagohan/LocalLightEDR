//! Native Messaging Host manifest (`com.localedr.bridge.json`) generation, atomic write, and validation.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::extension_id::{chrome_extension_origin, NATIVE_HOST_NAME};

/// Filename of the Chrome / Edge / Brave Native Messaging Host manifest.
pub const MANIFEST_FILENAME: &str = "com.localedr.bridge.json";

/// Description written into the Native Messaging Host manifest.
pub const MANIFEST_DESCRIPTION: &str = "LocalEDR Browser Shield Native Messaging Bridge";

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Chrome Native Messaging Host manifest schema (`AUTO-14`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMessagingManifest {
    pub name: String,
    pub description: String,
    pub path: String,
    #[serde(rename = "type")]
    pub host_type: String,
    pub allowed_origins: Vec<String>,
}

/// Validation status for an on-disk Native Messaging Host manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestValidation {
    pub exists: bool,
    pub valid: bool,
    pub bridge_exe_exists: bool,
    pub extension_id_matched: bool,
    pub path: String,
    pub error: Option<String>,
}

/// Strips Windows extended-length prefixes (`\\?\` / `\\?\UNC\`) for manifest display/storage.
pub fn normalize_display_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        raw.into_owned()
    }
}

/// Builds a [`NativeMessagingManifest`] targeting `bridge_exe` and `extension_id`.
pub fn build_manifest(bridge_exe: &Path, extension_id: &str) -> Result<NativeMessagingManifest> {
    let path_str = normalize_display_path(bridge_exe);
    if path_str.trim().is_empty() {
        bail!("bridge executable path must not be empty");
    }
    if !bridge_exe.is_absolute() {
        bail!("bridge executable path '{path_str}' must be absolute");
    }
    let origin = chrome_extension_origin(extension_id)?;
    Ok(NativeMessagingManifest {
        name: NATIVE_HOST_NAME.to_string(),
        description: MANIFEST_DESCRIPTION.to_string(),
        path: path_str,
        host_type: "stdio".to_string(),
        allowed_origins: vec![origin],
    })
}

/// Writes `manifest` atomically via a unique sibling temporary file + `rename`, returning
/// `Ok(true)` if the file changed or was created, and `Ok(false)` if identical bytes already exist.
pub fn write_manifest_atomic(
    manifest_path: &Path,
    manifest: &NativeMessagingManifest,
) -> Result<bool> {
    let mut rendered =
        serde_json::to_string_pretty(manifest).context("serialize Native Messaging manifest")?;
    rendered.push('\n');
    let desired_bytes = rendered.as_bytes();

    if let Ok(existing) = fs::read(manifest_path) {
        if existing == desired_bytes {
            return Ok(false);
        }
    }

    let parent = manifest_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "manifest path '{}' must include a parent directory",
                manifest_path.display()
            )
        })?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create Native Messaging manifest directory '{}'",
            parent.display()
        )
    })?;

    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = manifest_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(MANIFEST_FILENAME);
    let temp_path = parent.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));

    let mut temp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .with_context(|| format!("failed to create temp manifest '{}'", temp_path.display()))?;

    let write_res = (|| -> Result<()> {
        temp_file.write_all(desired_bytes)?;
        temp_file.sync_all()?;
        Ok(())
    })();
    drop(temp_file);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&temp_path);
        return Err(err).context("failed while writing temporary Native Messaging manifest");
    }

    if let Err(err) = fs::rename(&temp_path, manifest_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err).with_context(|| {
            format!(
                "failed to replace Native Messaging manifest '{}'",
                manifest_path.display()
            )
        });
    }

    Ok(true)
}

/// Validates an on-disk Native Messaging manifest file against structural rules and `expected_extension_id`.
pub fn validate_manifest_file(
    manifest_path: &Path,
    expected_extension_id: &str,
) -> ManifestValidation {
    let path_str = normalize_display_path(manifest_path);
    let bytes = match fs::read(manifest_path) {
        Ok(b) => b,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return ManifestValidation {
                exists: false,
                valid: false,
                bridge_exe_exists: false,
                extension_id_matched: false,
                path: path_str,
                error: Some("manifest file does not exist".to_string()),
            };
        }
        Err(err) => {
            return ManifestValidation {
                exists: false,
                valid: false,
                bridge_exe_exists: false,
                extension_id_matched: false,
                path: path_str,
                error: Some(format!("failed to read manifest: {err}")),
            };
        }
    };

    let parsed: NativeMessagingManifest = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(err) => {
            return ManifestValidation {
                exists: true,
                valid: false,
                bridge_exe_exists: false,
                extension_id_matched: false,
                path: path_str,
                error: Some(format!("invalid manifest JSON: {err}")),
            };
        }
    };

    let expected_origin = format!("chrome-extension://{expected_extension_id}/");
    let extension_id_matched = parsed
        .allowed_origins
        .iter()
        .any(|origin| origin.eq_ignore_ascii_case(&expected_origin));
    let bridge_exe_exists = !parsed.path.trim().is_empty() && Path::new(&parsed.path).is_file();

    let mut problems = Vec::new();
    if parsed.name != NATIVE_HOST_NAME {
        problems.push(format!(
            "manifest 'name' is '{}', expected '{NATIVE_HOST_NAME}'",
            parsed.name
        ));
    }
    if parsed.host_type != "stdio" {
        problems.push(format!(
            "manifest 'type' is '{}', expected 'stdio'",
            parsed.host_type
        ));
    }
    if !bridge_exe_exists {
        problems.push(format!("bridge executable '{}' not found", parsed.path));
    }
    if !extension_id_matched {
        problems.push(format!(
            "allowed_origins does not contain '{expected_origin}'"
        ));
    }

    let valid = problems.is_empty();
    ManifestValidation {
        exists: true,
        valid,
        bridge_exe_exists,
        extension_id_matched,
        path: path_str,
        error: (!valid).then(|| problems.join("; ")),
    }
}
