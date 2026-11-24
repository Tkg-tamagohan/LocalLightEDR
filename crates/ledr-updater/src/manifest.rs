//! Release manifest validation and version comparison logic.

use crate::{
    fs_safe, http, SemVer, UpdateManifest, UpdateVerificationOutcome, UpdaterError,
    EXPECTED_CHROME_EXTENSION_ID, EXPECTED_PRODUCT_NAME, MANIFEST_SCHEMA_VERSION,
    MAX_INSTALLER_BYTES, MAX_MANIFEST_BYTES, RELEASE_URL_PREFIX,
};

const EXPECTED_GITHUB_RELEASE_PATH_PREFIX: &str = "/Tkg-tamagohan/LocalLightEDR/releases/";

pub(crate) fn is_valid_lowercase_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_manifest_download_url(url: &str) -> Result<(), UpdaterError> {
    http::validate_download_url(url, false)?;
    let parsed = http::parse_http_url(url)?;
    if parsed.host.eq_ignore_ascii_case("github.com") {
        let path_only = parsed
            .path_and_query
            .split('?')
            .next()
            .unwrap_or(&parsed.path_and_query);
        if !path_only.starts_with(EXPECTED_GITHUB_RELEASE_PATH_PREFIX) {
            return Err(UpdaterError::UnsafeUrl(format!(
                "github.com download_url must start with {EXPECTED_GITHUB_RELEASE_PATH_PREFIX}: {url}"
            )));
        }
    }
    Ok(())
}

fn is_valid_chrome_extension_version(version: &str) -> bool {
    if version.is_empty()
        || version
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return false;
    }
    if SemVer::parse(version).is_ok() {
        return true;
    }
    // Chrome MV3 manifest versions allow 1..=4 dot-separated non-negative integers (0..=65535).
    let parts: Vec<&str> = version.split('.').collect();
    if !(1..=4).contains(&parts.len()) {
        return false;
    }
    parts.iter().all(|part| {
        !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && !(part.len() > 1 && part.starts_with('0'))
            && part.parse::<u16>().is_ok()
    })
}

/// Parses and structurally validates `update-manifest.json` bytes.
pub(crate) fn parse_and_validate_manifest(
    manifest_bytes: &[u8],
) -> Result<UpdateManifest, UpdaterError> {
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(UpdaterError::ResponseTooLarge {
            kind: "manifest",
            limit_bytes: MAX_MANIFEST_BYTES,
            actual_bytes: manifest_bytes.len(),
        });
    }

    let manifest: UpdateManifest = serde_json::from_slice(manifest_bytes)?;

    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(UpdaterError::InvalidManifest(format!(
            "unsupported schema_version {} (expected {})",
            manifest.schema_version, MANIFEST_SCHEMA_VERSION
        )));
    }
    if manifest.product != EXPECTED_PRODUCT_NAME {
        return Err(UpdaterError::InvalidManifest(format!(
            "unexpected product {:?} (expected {:?})",
            manifest.product, EXPECTED_PRODUCT_NAME
        )));
    }

    let ver = SemVer::parse(&manifest.version)?;
    if ver.is_prerelease() {
        return Err(UpdaterError::InvalidManifest(format!(
            "manifest version '{}' must not be a prerelease",
            manifest.version
        )));
    }

    let expected_tag = format!("v{}", manifest.version);
    if manifest.tag != expected_tag {
        return Err(UpdaterError::InvalidManifest(format!(
            "tag {:?} does not match expected {:?}",
            manifest.tag, expected_tag
        )));
    }

    if let Some(released_at) = &manifest.released_at {
        if released_at.trim().is_empty()
            || released_at.bytes().any(|b| b.is_ascii_control())
        {
            return Err(UpdaterError::InvalidManifest(
                "released_at must not be empty or contain control characters".to_string(),
            ));
        }
    }

    let _min_updater_ver = SemVer::parse(&manifest.min_updater_version)?;
    fs_safe::validate_single_segment_filename(&manifest.filename)?;
    validate_manifest_download_url(&manifest.download_url)?;

    if !is_valid_lowercase_sha256_hex(&manifest.sha256) {
        return Err(UpdaterError::InvalidManifest(
            "sha256 must be 64 lowercase hexadecimal characters".to_string(),
        ));
    }

    if manifest.size_bytes == 0 || manifest.size_bytes > MAX_INSTALLER_BYTES {
        return Err(UpdaterError::InvalidManifest(format!(
            "size_bytes {} out of allowed range 1..={MAX_INSTALLER_BYTES}",
            manifest.size_bytes
        )));
    }

    http::validate_initial_release_url(&manifest.release_notes_url, false)?;
    if !manifest.release_notes_url.starts_with(RELEASE_URL_PREFIX) {
        return Err(UpdaterError::UnsafeUrl(format!(
            "release_notes_url must start with {RELEASE_URL_PREFIX}"
        )));
    }

    if manifest.chrome_extension.extension_id != EXPECTED_CHROME_EXTENSION_ID {
        return Err(UpdaterError::InvalidManifest(format!(
            "chrome_extension.extension_id {:?} does not match expected {:?}",
            manifest.chrome_extension.extension_id, EXPECTED_CHROME_EXTENSION_ID
        )));
    }
    if !is_valid_chrome_extension_version(&manifest.chrome_extension.version) {
        return Err(UpdaterError::InvalidManifest(format!(
            "invalid chrome_extension.version {:?}",
            manifest.chrome_extension.version
        )));
    }
    if let Some(ext_url) = &manifest.chrome_extension.download_url {
        validate_manifest_download_url(ext_url)?;
    }
    if let Some(ext_sha) = &manifest.chrome_extension.sha256 {
        if !is_valid_lowercase_sha256_hex(ext_sha) {
            return Err(UpdaterError::InvalidManifest(
                "chrome_extension.sha256 must be 64 lowercase hexadecimal characters".to_string(),
            ));
        }
    }

    Ok(manifest)
}

/// Compares a validated [`UpdateManifest`] against `current_version`.
pub(crate) fn evaluate_manifest_for_version(
    manifest: &UpdateManifest,
    current_version: &str,
) -> Result<UpdateVerificationOutcome, UpdaterError> {
    let current_ver = SemVer::parse(current_version)?;
    let manifest_ver = SemVer::parse(&manifest.version)?;
    if manifest_ver.is_prerelease() {
        return Err(UpdaterError::InvalidManifest(format!(
            "manifest version '{}' must not be a prerelease",
            manifest.version
        )));
    }
    let min_updater_ver = SemVer::parse(&manifest.min_updater_version)?;

    if manifest_ver <= current_ver {
        Ok(UpdateVerificationOutcome::UpToDate {
            current_version: current_version.to_string(),
            latest_version: manifest.version.clone(),
        })
    } else if current_ver < min_updater_ver {
        Ok(UpdateVerificationOutcome::ManualUpdateRequired {
            current_version: current_version.to_string(),
            min_updater_version: manifest.min_updater_version.clone(),
            latest_version: manifest.version.clone(),
            release_notes_url: manifest.release_notes_url.clone(),
        })
    } else {
        Ok(UpdateVerificationOutcome::UpdateAvailable {
            current_version: current_version.to_string(),
            manifest: Box::new(manifest.clone()),
        })
    }
}
