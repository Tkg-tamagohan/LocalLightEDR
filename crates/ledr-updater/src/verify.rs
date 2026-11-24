//! Ed25519 signature verification and reparse-safe installer SHA-256 verification.

use std::io::Read;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    base64, fs_safe, manifest, ManifestSignatureEnvelope, PublicKeyRing, UpdateManifest,
    UpdateVerificationOutcome, UpdaterError, MAX_INSTALLER_BYTES, MAX_SIG_BYTES,
    SIGNATURE_ALGORITHM_ED25519, SIGNATURE_SCHEMA_VERSION,
};

const HASH_CHUNK_BYTES: usize = 64 * 1024;

/// Verifies `manifest_bytes` against `sig_bytes` using `key_ring` via strict Ed25519.
pub(crate) fn verify_manifest_signature(
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
    key_ring: &PublicKeyRing,
) -> Result<ManifestSignatureEnvelope, UpdaterError> {
    if sig_bytes.len() > MAX_SIG_BYTES {
        return Err(UpdaterError::ResponseTooLarge {
            kind: "signature",
            limit_bytes: MAX_SIG_BYTES,
            actual_bytes: sig_bytes.len(),
        });
    }
    if !key_ring.has_active_keys() {
        return Err(UpdaterError::UnconfiguredPublicKeyRing);
    }

    let envelope: ManifestSignatureEnvelope = serde_json::from_slice(sig_bytes)?;
    if envelope.schema_version != SIGNATURE_SCHEMA_VERSION {
        return Err(UpdaterError::InvalidSignatureEnvelope(format!(
            "unsupported schema_version {} (expected {})",
            envelope.schema_version, SIGNATURE_SCHEMA_VERSION
        )));
    }
    if envelope.algorithm != SIGNATURE_ALGORITHM_ED25519 {
        return Err(UpdaterError::InvalidSignatureEnvelope(format!(
            "unsupported signature algorithm {:?}",
            envelope.algorithm
        )));
    }
    if envelope.key_id.is_empty()
        || envelope
            .key_id
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(UpdaterError::InvalidSignatureEnvelope(format!(
            "invalid key_id {:?}",
            envelope.key_id
        )));
    }

    let key_bytes = key_ring.active_verifying_key(&envelope.key_id)?;
    let sig_raw = base64::decode(&envelope.signature_b64)?;
    let sig_64: [u8; 64] = sig_raw.try_into().map_err(|v: Vec<u8>| {
        UpdaterError::InvalidSignatureEnvelope(format!(
            "Ed25519 signature must decode to 64 bytes, got {} bytes",
            v.len()
        ))
    })?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|err| UpdaterError::InvalidKeyRing(err.to_string()))?;
    let signature = Signature::from_bytes(&sig_64);

    verifying_key
        .verify_strict(manifest_bytes, &signature)
        .map_err(|err| UpdaterError::SignatureVerificationFailed(err.to_string()))?;

    tracing::debug!(key_id = %envelope.key_id, "verified update manifest Ed25519 signature");
    Ok(envelope)
}

/// Verifies Ed25519 signature BEFORE parsing or evaluating `manifest_bytes`.
pub(crate) fn verify_and_evaluate_manifest(
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
    key_ring: &PublicKeyRing,
    current_version: &str,
) -> Result<UpdateVerificationOutcome, UpdaterError> {
    let _envelope = verify_manifest_signature(manifest_bytes, sig_bytes, key_ring)?;
    let parsed_manifest = manifest::parse_and_validate_manifest(manifest_bytes)?;
    manifest::evaluate_manifest_for_version(&parsed_manifest, current_version)
}

/// Computes lowercase hex SHA-256 of the reparse-verified regular file at `path`.
pub(crate) fn sha256_file_hex(path: &Path) -> Result<String, UpdaterError> {
    let mut file = fs_safe::open_verified_read_file(path, u64::MAX)?;
    let (digest, _) = hash_reader_bounded(&mut file, u64::MAX)?;
    Ok(digest)
}

/// Verifies that the installer file at `path` matches `manifest.size_bytes` and `manifest.sha256`.
pub(crate) fn verify_installer_file(path: &Path, manifest: &UpdateManifest) -> Result<(), UpdaterError> {
    if manifest.size_bytes == 0 || manifest.size_bytes > MAX_INSTALLER_BYTES {
        return Err(UpdaterError::InvalidManifest(format!(
            "manifest size_bytes {} out of allowed range 1..={MAX_INSTALLER_BYTES}",
            manifest.size_bytes
        )));
    }
    if !manifest::is_valid_lowercase_sha256_hex(&manifest.sha256) {
        return Err(UpdaterError::InvalidManifest(
            "manifest sha256 must be 64 lowercase hexadecimal characters".to_string(),
        ));
    }
    fs_safe::validate_single_segment_filename(&manifest.filename)?;

    let mut file = fs_safe::open_verified_read_file(path, u64::MAX)?;
    let (actual_hex, total_bytes) = hash_reader_bounded(&mut file, MAX_INSTALLER_BYTES)?;

    if total_bytes != manifest.size_bytes {
        return Err(UpdaterError::SizeMismatch {
            expected: manifest.size_bytes,
            actual: total_bytes,
        });
    }
    if actual_hex != manifest.sha256 {
        return Err(UpdaterError::HashMismatch {
            expected: manifest.sha256.clone(),
            actual: actual_hex,
        });
    }

    tracing::info!(
        version = %manifest.version,
        size_bytes = total_bytes,
        "verified installer SHA-256 and byte length"
    );
    Ok(())
}

fn hash_reader_bounded(
    reader: &mut impl Read,
    max_bytes: u64,
) -> Result<(String, u64), UpdaterError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK_BYTES];
    let mut total_bytes: u64 = 0;

    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(UpdaterError::Io(err)),
        };
        total_bytes = total_bytes
            .checked_add(n as u64)
            .ok_or_else(|| UpdaterError::InvalidManifest("file size overflow".to_string()))?;
        if total_bytes > max_bytes {
            return Err(UpdaterError::ResponseTooLarge {
                kind: "installer",
                limit_bytes: max_bytes.min(usize::MAX as u64) as usize,
                actual_bytes: total_bytes.min(usize::MAX as u64) as usize,
            });
        }
        hasher.update(&buf[..n]);
    }

    Ok((hex::encode(hasher.finalize()), total_bytes))
}
