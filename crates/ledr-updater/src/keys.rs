//! Fail-closed Ed25519 public key ring loading and validation.

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;

use crate::{base64, KeyStatus, PublicKeyRing, UpdaterError, KEY_RING_SCHEMA_VERSION};

const UNCONFIGURED_PLACEHOLDER: &str = "UNCONFIGURED_PLACEHOLDER";

/// Parses and validates a key ring JSON document, failing closed with
/// [`UpdaterError::UnconfiguredPublicKeyRing`] if no active key is configured.
pub(crate) fn from_json_str(json: &str) -> Result<PublicKeyRing, UpdaterError> {
    let ring: PublicKeyRing = serde_json::from_str(json)?;
    if ring.schema_version != KEY_RING_SCHEMA_VERSION {
        return Err(UpdaterError::InvalidKeyRing(format!(
            "unsupported schema_version {} (expected {})",
            ring.schema_version, KEY_RING_SCHEMA_VERSION
        )));
    }

    let mut seen_ids = HashSet::with_capacity(ring.keys.len());
    for entry in &ring.keys {
        if entry.key_id.is_empty()
            || entry
                .key_id
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(UpdaterError::InvalidKeyRing(format!(
                "invalid key_id {:?}",
                entry.key_id
            )));
        }
        if !seen_ids.insert(entry.key_id.as_str()) {
            return Err(UpdaterError::InvalidKeyRing(format!(
                "duplicate key_id '{}'",
                entry.key_id
            )));
        }

        if entry.status == KeyStatus::Disabled && entry.public_key_b64 == UNCONFIGURED_PLACEHOLDER
        {
            continue;
        }

        let _ = decode_and_validate_verifying_key(&entry.key_id, &entry.public_key_b64)?;
    }

    if !ring.has_active_keys() {
        return Err(UpdaterError::UnconfiguredPublicKeyRing);
    }

    Ok(ring)
}

/// Looks up an active 32-byte Ed25519 verifying key by `key_id`.
pub(crate) fn active_verifying_key(
    ring: &PublicKeyRing,
    key_id: &str,
) -> Result<[u8; 32], UpdaterError> {
    let Some(entry) = ring.keys.iter().find(|entry| entry.key_id == key_id) else {
        return Err(UpdaterError::UnknownOrInactiveKeyId(key_id.to_string()));
    };
    if entry.status != KeyStatus::Active {
        return Err(UpdaterError::UnknownOrInactiveKeyId(key_id.to_string()));
    }
    decode_and_validate_verifying_key(&entry.key_id, &entry.public_key_b64)
}

fn decode_and_validate_verifying_key(
    key_id: &str,
    public_key_b64: &str,
) -> Result<[u8; 32], UpdaterError> {
    let raw = base64::decode(public_key_b64)?;
    let key_bytes: [u8; 32] = raw.try_into().map_err(|v: Vec<u8>| {
        UpdaterError::InvalidKeyRing(format!(
            "key '{key_id}' must decode to 32 bytes, got {} bytes",
            v.len()
        ))
    })?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|err| {
        UpdaterError::InvalidKeyRing(format!("key '{key_id}' is not a valid Ed25519 point: {err}"))
    })?;
    Ok(key_bytes)
}
