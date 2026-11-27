use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    atomic_write_file, cleanup_stale_staging_dirs, create_exclusive_file,
    create_staging_session_dir, create_verified_session_dir, decode_base64, encode_base64,
    ensure_no_reparse_points, evaluate_manifest_for_version, parse_and_validate_manifest,
    sha256_file_hex, validate_download_url, validate_initial_release_url,
    validate_single_segment_filename, verify_and_evaluate_manifest, verify_installer_file,
    verify_manifest_signature, CancelToken, ChromeExtensionUpdateInfo, DownloadProgress,
    HttpClientConfig, KeyStatus, ManifestSignatureEnvelope, PublicKeyEntry, PublicKeyRing, SemVer,
    UpdateManifest, UpdateVerificationOutcome, UpdaterError, UpdaterHttpClient,
    ALLOWED_DOWNLOAD_HOSTS, EXPECTED_CHROME_EXTENSION_ID, EXPECTED_PRODUCT_NAME,
    LATEST_MANIFEST_URL, LATEST_SIG_URL, MAX_INSTALLER_BYTES, MAX_MANIFEST_BYTES, MAX_SIG_BYTES,
};

fn test_signing_key(seed_byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed_byte; 32])
}

fn test_key_ring(key_id: &str, sk: &SigningKey, status: KeyStatus) -> PublicKeyRing {
    PublicKeyRing {
        schema_version: 1,
        keys: vec![PublicKeyEntry {
            key_id: key_id.to_string(),
            public_key_b64: encode_base64(sk.verifying_key().as_bytes()),
            status,
        }],
    }
}

fn sample_manifest(version: &str, min_updater_version: &str, sha256: &str, size_bytes: u64) -> UpdateManifest {
    UpdateManifest {
        schema_version: 1,
        product: EXPECTED_PRODUCT_NAME.to_string(),
        version: version.to_string(),
        tag: format!("v{version}"),
        released_at: Some("2026-11-24T00:00:00Z".to_string()),
        min_updater_version: min_updater_version.to_string(),
        filename: format!("LocalEDR-Setup-v{version}-win-x64.exe"),
        download_url: format!(
            "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/download/v{version}/LocalEDR-Setup-v{version}-win-x64.exe"
        ),
        sha256: sha256.to_string(),
        size_bytes,
        release_notes_url: format!(
            "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/tag/v{version}"
        ),
        chrome_extension: ChromeExtensionUpdateInfo {
            extension_id: EXPECTED_CHROME_EXTENSION_ID.to_string(),
            version: version.to_string(),
            download_url: None,
            sha256: None,
        },
    }
}

fn sign_manifest_bytes(manifest_bytes: &[u8], key_id: &str, sk: &SigningKey) -> Vec<u8> {
    let sig = sk.sign(manifest_bytes);
    let envelope = ManifestSignatureEnvelope {
        schema_version: 1,
        key_id: key_id.to_string(),
        algorithm: "ed25519".to_string(),
        signature_b64: encode_base64(&sig.to_bytes()),
    };
    serde_json::to_vec(&envelope).expect("serialize signature envelope")
}

// ---------------------------------------------------------------------------
// UPD-KEY-01..03: KeyRing & fail-closed embedded keys
// ---------------------------------------------------------------------------

#[test]
fn upd_key_01_embedded_ring_loads_active_key() {
    let ring = PublicKeyRing::from_embedded().expect("embedded key ring should load active key");
    assert!(ring.has_active_keys());
    let active_entries: Vec<_> = ring
        .keys
        .iter()
        .filter(|entry| entry.status == KeyStatus::Active)
        .collect();
    assert!(
        !active_entries.is_empty(),
        "embedded key ring should contain at least one active key"
    );
    for entry in active_entries {
        let key_bytes = ring
            .active_verifying_key(&entry.key_id)
            .expect("active embedded key should resolve as verifying key");
        assert_eq!(key_bytes.len(), 32);
    }
}

#[test]
fn upd_key_02_valid_active_key_loads_and_resolves() {
    let sk = test_signing_key(0x11);
    let expected_vk = *sk.verifying_key().as_bytes();
    let ring = test_key_ring("prod-2026-11", &sk, KeyStatus::Active);
    let json = serde_json::to_string(&ring).unwrap();

    let parsed = PublicKeyRing::from_json_str(&json).expect("valid ring should load");
    assert!(parsed.has_active_keys());
    assert_eq!(
        parsed.active_verifying_key("prod-2026-11").unwrap(),
        expected_vk
    );
}

#[test]
fn upd_key_03_rejects_invalid_and_inactive_key_rings() {
    let sk = test_signing_key(0x22);
    let valid_b64 = encode_base64(sk.verifying_key().as_bytes());

    // Wrong schema_version
    let bad_schema = format!(
        r#"{{"schema_version":2,"keys":[{{"key_id":"k1","public_key_b64":"{valid_b64}","status":"active"}}]}}"#
    );
    assert!(matches!(
        PublicKeyRing::from_json_str(&bad_schema),
        Err(UpdaterError::InvalidKeyRing(_))
    ));

    // Empty keys -> UnconfiguredPublicKeyRing
    assert!(matches!(
        PublicKeyRing::from_json_str(r#"{"schema_version":1,"keys":[]}"#),
        Err(UpdaterError::UnconfiguredPublicKeyRing)
    ));

    // Only disabled / revoked keys -> UnconfiguredPublicKeyRing
    let only_disabled = format!(
        r#"{{"schema_version":1,"keys":[{{"key_id":"k1","public_key_b64":"{valid_b64}","status":"disabled"}},{{"key_id":"k2","public_key_b64":"{valid_b64}","status":"revoked"}}]}}"#
    );
    assert!(matches!(
        PublicKeyRing::from_json_str(&only_disabled),
        Err(UpdaterError::UnconfiguredPublicKeyRing)
    ));

    // Placeholder unconfigured entry -> UnconfiguredPublicKeyRing
    let placeholder_only = r#"{"schema_version":1,"keys":[{"key_id":"placeholder-unconfigured","public_key_b64":"UNCONFIGURED_PLACEHOLDER","status":"disabled"}]}"#;
    assert!(matches!(
        PublicKeyRing::from_json_str(placeholder_only),
        Err(UpdaterError::UnconfiguredPublicKeyRing)
    ));

    // Duplicate key_id
    let dup = format!(
        r#"{{"schema_version":1,"keys":[{{"key_id":"k1","public_key_b64":"{valid_b64}","status":"active"}},{{"key_id":"k1","public_key_b64":"{valid_b64}","status":"disabled"}}]}}"#
    );
    assert!(matches!(
        PublicKeyRing::from_json_str(&dup),
        Err(UpdaterError::InvalidKeyRing(_))
    ));

    // Empty / whitespace / control key_id
    for bad_id in ["", " ", "k 1", "k\n1"] {
        let ring = PublicKeyRing {
            schema_version: 1,
            keys: vec![PublicKeyEntry {
                key_id: bad_id.to_string(),
                public_key_b64: valid_b64.clone(),
                status: KeyStatus::Active,
            }],
        };
        let json = serde_json::to_string(&ring).unwrap();
        assert!(matches!(
            PublicKeyRing::from_json_str(&json),
            Err(UpdaterError::InvalidKeyRing(_))
        ));
    }

    // Invalid Base64
    let bad_b64 = r#"{"schema_version":1,"keys":[{"key_id":"k1","public_key_b64":"not!b64","status":"active"}]}"#;
    assert!(matches!(
        PublicKeyRing::from_json_str(bad_b64),
        Err(UpdaterError::InvalidBase64(_))
    ));

    // Non-32-byte key
    let short_b64 = encode_base64(&[1u8; 31]);
    let short_json = format!(
        r#"{{"schema_version":1,"keys":[{{"key_id":"k1","public_key_b64":"{short_b64}","status":"active"}}]}}"#
    );
    assert!(matches!(
        PublicKeyRing::from_json_str(&short_json),
        Err(UpdaterError::InvalidKeyRing(_))
    ));

    // Invalid 32-byte Ed25519 curve point (not on curve)
    let bad_point = (1u8..=255)
        .map(|b| {
            let mut buf = [0u8; 32];
            buf[0] = b;
            buf
        })
        .find(|buf| ed25519_dalek::VerifyingKey::from_bytes(buf).is_err())
        .expect("must find at least one non-curve 32-byte value");
    let bad_point_b64 = encode_base64(&bad_point);
    let bad_point_json = format!(
        r#"{{"schema_version":1,"keys":[{{"key_id":"k1","public_key_b64":"{bad_point_b64}","status":"active"}}]}}"#
    );
    assert!(matches!(
        PublicKeyRing::from_json_str(&bad_point_json),
        Err(UpdaterError::InvalidKeyRing(_))
    ));

    // Active vs Disabled/Revoked/Unknown lookup
    let sk2 = test_signing_key(0x23);
    let mixed = PublicKeyRing {
        schema_version: 1,
        keys: vec![
            PublicKeyEntry {
                key_id: "active-1".into(),
                public_key_b64: valid_b64,
                status: KeyStatus::Active,
            },
            PublicKeyEntry {
                key_id: "disabled-1".into(),
                public_key_b64: encode_base64(sk2.verifying_key().as_bytes()),
                status: KeyStatus::Disabled,
            },
            PublicKeyEntry {
                key_id: "revoked-1".into(),
                public_key_b64: encode_base64(sk2.verifying_key().as_bytes()),
                status: KeyStatus::Revoked,
            },
        ],
    };
    let parsed = PublicKeyRing::from_json_str(&serde_json::to_string(&mixed).unwrap()).unwrap();
    assert!(matches!(
        parsed.active_verifying_key("disabled-1"),
        Err(UpdaterError::UnknownOrInactiveKeyId(_))
    ));
    assert!(matches!(
        parsed.active_verifying_key("revoked-1"),
        Err(UpdaterError::UnknownOrInactiveKeyId(_))
    ));
    assert!(matches!(
        parsed.active_verifying_key("missing"),
        Err(UpdaterError::UnknownOrInactiveKeyId(_))
    ));
}

// ---------------------------------------------------------------------------
// UPD-B64-01..02: RFC 4648 Base64
// ---------------------------------------------------------------------------

#[test]
fn upd_b64_01_rfc4648_vectors_and_roundtrip() {
    let vectors = [
        (b"".as_slice(), ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ];
    for (raw, expected_b64) in vectors {
        assert_eq!(encode_base64(raw), expected_b64);
        assert_eq!(decode_base64(expected_b64).unwrap(), raw);
    }

    let all_bytes: Vec<u8> = (0..=255).collect();
    let encoded = encode_base64(&all_bytes);
    assert_eq!(decode_base64(&encoded).unwrap(), all_bytes);
}

#[test]
fn upd_b64_02_rejects_malformed_and_non_canonical_padding() {
    let invalid = [
        "Z",        // len % 4 != 0
        "Zg",       // missing ==
        "Zm8",      // missing =
        "Zg==",     // wait - control sanity check below
        "Zm8-",     // URL-safe '-'
        "Zm8_",     // URL-safe '_'
        "Zm9v\n",   // newline
        " Zm9v",    // whitespace
        "Zg==Zm9v", // mid-string '='
        "Z===",     // triple '='
        "====",     // quad '='
        "Zm=v",     // '=' in pos 2 without pos 3 '='
        "Zh==",     // non-canonical trailing bits for 'f' ("Zg==" has 0x06, "Zh==" sets bit 0)
        "Zm9vYh==", // non-canonical trailing bits for 2-byte quantum ("Zm9vYg==" is canonical)
    ];

    for case in invalid {
        if case == "Zg==" {
            assert_eq!(decode_base64(case).unwrap(), b"f");
            continue;
        }
        assert!(
            matches!(decode_base64(case), Err(UpdaterError::InvalidBase64(_))),
            "expected InvalidBase64 for {case:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// UPD-VER-01..02: Strict SemVer
// ---------------------------------------------------------------------------

#[test]
fn upd_ver_01_valid_parsing_and_semver2_ordering() {
    let v0 = SemVer::parse("0.0.0").unwrap();
    assert_eq!(v0.to_string(), "0.0.0");
    assert!(!v0.is_prerelease());

    let v123 = SemVer::parse("1.2.3").unwrap();
    let v1100 = SemVer::parse("1.10.0").unwrap();
    assert!(v1100 > v123);

    // SemVer 2.0.0 §11.4 precedence chain
    let chain = [
        "1.0.0-1",
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.2",
        "1.0.0-alpha.10",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ];
    let parsed: Vec<SemVer> = chain.iter().map(|s| SemVer::parse(s).unwrap()).collect();
    for pair in parsed.windows(2) {
        assert!(
            pair[0] < pair[1],
            "expected {} < {}",
            pair[0],
            pair[1]
        );
    }
    assert!(parsed[0].is_prerelease());
    assert!(!parsed.last().unwrap().is_prerelease());
}

#[test]
fn upd_ver_02_rejects_invalid_semver() {
    let invalid = [
        "",
        " ",
        "1.2.3 ",
        " 1.2.3",
        "v1.2.3",
        "V1.2.3",
        "01.0.0",
        "1.02.0",
        "1.0.03",
        "1.2",
        "1.2.3.4",
        "1.2.3+build1",
        "1.2.3-alpha+build1",
        "1.0.0-",
        "1.0.0-alpha..1",
        "1.0.0-.alpha",
        "1.0.0-alpha.",
        "1.0.0-01",
        "1.0.0-alpha_1",
        "a.b.c",
    ];
    for s in invalid {
        assert!(
            matches!(SemVer::parse(s), Err(UpdaterError::InvalidSemVer(_))),
            "expected InvalidSemVer for {s:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// UPD-SIG-01..03: Signature verification & verify-before-parse pipeline
// ---------------------------------------------------------------------------

#[test]
fn upd_sig_01_valid_signature_succeeds() {
    let sk = test_signing_key(0x33);
    let ring = test_key_ring("release-2026", &sk, KeyStatus::Active);
    let manifest = sample_manifest("0.2.0", "0.1.0", &"a".repeat(64), 1024);
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let sig_bytes = sign_manifest_bytes(&manifest_bytes, "release-2026", &sk);

    let env = verify_manifest_signature(&manifest_bytes, &sig_bytes, &ring).unwrap();
    assert_eq!(env.key_id, "release-2026");
    assert_eq!(env.algorithm, "ed25519");
}

#[test]
fn upd_sig_02_rejects_tampered_and_invalid_envelopes() {
    let sk = test_signing_key(0x44);
    let wrong_sk = test_signing_key(0x45);
    let ring = PublicKeyRing {
        schema_version: 1,
        keys: vec![
            PublicKeyEntry {
                key_id: "active".into(),
                public_key_b64: encode_base64(sk.verifying_key().as_bytes()),
                status: KeyStatus::Active,
            },
            PublicKeyEntry {
                key_id: "disabled".into(),
                public_key_b64: encode_base64(wrong_sk.verifying_key().as_bytes()),
                status: KeyStatus::Disabled,
            },
            PublicKeyEntry {
                key_id: "revoked".into(),
                public_key_b64: encode_base64(wrong_sk.verifying_key().as_bytes()),
                status: KeyStatus::Revoked,
            },
        ],
    };

    let manifest = sample_manifest("0.2.0", "0.1.0", &"b".repeat(64), 1024);
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let sig_bytes = sign_manifest_bytes(&manifest_bytes, "active", &sk);

    // Tampered manifest
    let mut tampered = manifest_bytes.clone();
    tampered[0] ^= 0x01;
    assert!(matches!(
        verify_manifest_signature(&tampered, &sig_bytes, &ring),
        Err(UpdaterError::SignatureVerificationFailed(_))
    ));

    // Wrong signing key
    let wrong_sig = sign_manifest_bytes(&manifest_bytes, "active", &wrong_sk);
    assert!(matches!(
        verify_manifest_signature(&manifest_bytes, &wrong_sig, &ring),
        Err(UpdaterError::SignatureVerificationFailed(_))
    ));

    // Disabled / revoked / unknown key_id
    for bad_key in ["disabled", "revoked", "unknown"] {
        let sig = sign_manifest_bytes(&manifest_bytes, bad_key, &wrong_sk);
        assert!(matches!(
            verify_manifest_signature(&manifest_bytes, &sig, &ring),
            Err(UpdaterError::UnknownOrInactiveKeyId(_))
        ));
    }

    // Wrong schema_version & wrong algorithm & non-64-byte sig & oversized sig
    let bad_schema = serde_json::to_vec(&ManifestSignatureEnvelope {
        schema_version: 9,
        key_id: "active".into(),
        algorithm: "ed25519".into(),
        signature_b64: encode_base64(&[0u8; 64]),
    })
    .unwrap();
    assert!(matches!(
        verify_manifest_signature(&manifest_bytes, &bad_schema, &ring),
        Err(UpdaterError::InvalidSignatureEnvelope(_))
    ));

    let bad_alg = serde_json::to_vec(&ManifestSignatureEnvelope {
        schema_version: 1,
        key_id: "active".into(),
        algorithm: "rsa".into(),
        signature_b64: encode_base64(&[0u8; 64]),
    })
    .unwrap();
    assert!(matches!(
        verify_manifest_signature(&manifest_bytes, &bad_alg, &ring),
        Err(UpdaterError::InvalidSignatureEnvelope(_))
    ));

    let short_sig = serde_json::to_vec(&ManifestSignatureEnvelope {
        schema_version: 1,
        key_id: "active".into(),
        algorithm: "ed25519".into(),
        signature_b64: encode_base64(&[0u8; 63]),
    })
    .unwrap();
    assert!(matches!(
        verify_manifest_signature(&manifest_bytes, &short_sig, &ring),
        Err(UpdaterError::InvalidSignatureEnvelope(_))
    ));

    let huge_sig = vec![b' '; MAX_SIG_BYTES + 1];
    assert!(matches!(
        verify_manifest_signature(&manifest_bytes, &huge_sig, &ring),
        Err(UpdaterError::ResponseTooLarge { kind: "signature", .. })
    ));
}

#[test]
fn upd_sig_03_verifies_signature_before_parsing_untrusted_manifest_json() {
    let sk = test_signing_key(0x55);
    let wrong_sk = test_signing_key(0x56);
    let ring = test_key_ring("release", &sk, KeyStatus::Active);

    let invalid_json_bytes = b"{not valid json at all";
    let bad_sig_bytes = sign_manifest_bytes(invalid_json_bytes, "release", &wrong_sk);

    let err = verify_and_evaluate_manifest(invalid_json_bytes, &bad_sig_bytes, &ring, "0.1.0")
        .expect_err("must reject invalid signature before JSON parsing");
    assert!(
        matches!(err, UpdaterError::SignatureVerificationFailed(_)),
        "expected SignatureVerificationFailed before JSON parse, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// UPD-MAN-01..03: Manifest validation & version outcomes
// ---------------------------------------------------------------------------

#[test]
fn upd_man_01_valid_manifest_and_update_outcomes() {
    let sk = test_signing_key(0x66);
    let ring = test_key_ring("release", &sk, KeyStatus::Active);
    let manifest = sample_manifest("0.2.0", "0.1.0", &"c".repeat(64), 4096);
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let sig_bytes = sign_manifest_bytes(&manifest_bytes, "release", &sk);

    let parsed = parse_and_validate_manifest(&manifest_bytes).unwrap();
    assert_eq!(parsed, manifest);

    // UpToDate when equal or newer
    assert!(matches!(
        verify_and_evaluate_manifest(&manifest_bytes, &sig_bytes, &ring, "0.2.0").unwrap(),
        UpdateVerificationOutcome::UpToDate { .. }
    ));
    assert!(matches!(
        verify_and_evaluate_manifest(&manifest_bytes, &sig_bytes, &ring, "0.3.0").unwrap(),
        UpdateVerificationOutcome::UpToDate { .. }
    ));

    // UpdateAvailable when newer and current >= min_updater_version
    match verify_and_evaluate_manifest(&manifest_bytes, &sig_bytes, &ring, "0.1.0").unwrap() {
        UpdateVerificationOutcome::UpdateAvailable {
            current_version,
            manifest: m,
        } => {
            assert_eq!(current_version, "0.1.0");
            assert_eq!(*m, manifest);
        }
        other => panic!("expected UpdateAvailable, got {other:?}"),
    }
}

#[test]
fn upd_man_02_min_updater_version_requires_manual_update() {
    let manifest = sample_manifest("1.0.0", "0.5.0", &"d".repeat(64), 8192);
    let outcome = evaluate_manifest_for_version(&manifest, "0.4.9").unwrap();
    match outcome {
        UpdateVerificationOutcome::ManualUpdateRequired {
            current_version,
            min_updater_version,
            latest_version,
            release_notes_url,
        } => {
            assert_eq!(current_version, "0.4.9");
            assert_eq!(min_updater_version, "0.5.0");
            assert_eq!(latest_version, "1.0.0");
            assert_eq!(release_notes_url, manifest.release_notes_url);
        }
        other => panic!("expected ManualUpdateRequired, got {other:?}"),
    }
}

#[test]
fn upd_man_03_rejects_invalid_manifest_fields() {
    let base = sample_manifest("0.2.0", "0.1.0", &"e".repeat(64), 1024);

    let cases: Vec<(&str, UpdateManifest)> = vec![
        ("schema", {
            let mut m = base.clone();
            m.schema_version = 2;
            m
        }),
        ("product", {
            let mut m = base.clone();
            m.product = "OtherEDR".into();
            m
        }),
        ("prerelease", {
            let mut m = base.clone();
            m.version = "0.2.0-rc.1".into();
            m.tag = "v0.2.0-rc.1".into();
            m
        }),
        ("tag_mismatch", {
            let mut m = base.clone();
            m.tag = "0.2.0".into();
            m
        }),
        ("bad_min_ver", {
            let mut m = base.clone();
            m.min_updater_version = "v0.1.0".into();
            m
        }),
        ("traversal_filename", {
            let mut m = base.clone();
            m.filename = "../evil.exe".into();
            m
        }),
        ("slash_filename", {
            let mut m = base.clone();
            m.filename = "sub/evil.exe".into();
            m
        }),
        ("backslash_filename", {
            let mut m = base.clone();
            m.filename = r"sub\evil.exe".into();
            m
        }),
        ("bad_download_host", {
            let mut m = base.clone();
            m.download_url = "https://evil.example/setup.exe".into();
            m
        }),
        ("github_wrong_repo", {
            let mut m = base.clone();
            m.download_url = "https://github.com/other/repo/releases/download/v0.2.0/setup.exe".into();
            m
        }),
        ("http_download", {
            let mut m = base.clone();
            m.download_url = "http://github.com/Tkg-tamagohan/LocalLightEDR/releases/download/v0.2.0/setup.exe".into();
            m
        }),
        ("bad_sha_len", {
            let mut m = base.clone();
            m.sha256 = "abcd".into();
            m
        }),
        ("bad_sha_upper", {
            let mut m = base.clone();
            m.sha256 = "E".repeat(64);
            m
        }),
        ("zero_size", {
            let mut m = base.clone();
            m.size_bytes = 0;
            m
        }),
        ("oversized_installer", {
            let mut m = base.clone();
            m.size_bytes = MAX_INSTALLER_BYTES + 1;
            m
        }),
        ("bad_release_notes", {
            let mut m = base.clone();
            m.release_notes_url = "https://github.com/other/repo/releases/tag/v0.2.0".into();
            m
        }),
        ("bad_ext_id", {
            let mut m = base.clone();
            m.chrome_extension.extension_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
            m
        }),
        ("bad_ext_url", {
            let mut m = base.clone();
            m.chrome_extension.download_url = Some("https://evil.example/ext.zip".into());
            m
        }),
        ("bad_ext_sha", {
            let mut m = base.clone();
            m.chrome_extension.sha256 = Some("not-sha256".into());
            m
        }),
    ];

    for (label, m) in cases {
        let bytes = serde_json::to_vec(&m).unwrap();
        assert!(
            parse_and_validate_manifest(&bytes).is_err(),
            "expected manifest rejection for case {label}"
        );
    }

    let huge = vec![b' '; MAX_MANIFEST_BYTES + 1];
    assert!(matches!(
        parse_and_validate_manifest(&huge),
        Err(UpdaterError::ResponseTooLarge { kind: "manifest", .. })
    ));
}

// ---------------------------------------------------------------------------
// UPD-URL-01: URL policy checks
// ---------------------------------------------------------------------------

#[test]
fn upd_url_01_initial_and_download_url_policy() {
    assert!(validate_initial_release_url(LATEST_MANIFEST_URL, false).is_ok());
    assert!(validate_initial_release_url(LATEST_SIG_URL, false).is_ok());

    for host in ALLOWED_DOWNLOAD_HOSTS {
        let url = format!("https://{host}/some/asset.exe");
        assert!(
            validate_download_url(&url, false).is_ok(),
            "expected allowed host {host}"
        );
    }

    let bad_initial = [
        "http://github.com/Tkg-tamagohan/LocalLightEDR/releases/latest/download/update-manifest.json",
        "https://github.com/other/repo/releases/latest/download/update-manifest.json",
        "https://objects.githubusercontent.com/some/file",
        "https://user@github.com/Tkg-tamagohan/LocalLightEDR/releases/latest/download/update-manifest.json",
        "https://github.com/Tkg-tamagohan/LocalLightEDR/releases/../../other/repo",
        "http://127.0.0.1:8080/update-manifest.json",
    ];
    for url in bad_initial {
        assert!(
            matches!(
                validate_initial_release_url(url, false),
                Err(UpdaterError::UnsafeUrl(_))
            ),
            "expected UnsafeUrl for initial URL {url}"
        );
    }

    let bad_download = [
        "http://github.com/Tkg-tamagohan/LocalLightEDR/releases/download/v0.2.0/a.exe",
        "https://github.com.evil.com/a.exe",
        "https://evilgithub.com/a.exe",
        "https://user:pass@github.com/a.exe",
        "https://github.com:8443/a.exe",
        "https://objects.githubusercontent.com/a/%2e%2e/b",
        "http://192.0.2.1/a.exe",
    ];
    for url in bad_download {
        assert!(
            matches!(
                validate_download_url(url, true),
                Err(UpdaterError::UnsafeUrl(_))
            ),
            "expected UnsafeUrl even with test loopback flag for {url}"
        );
    }

    assert!(validate_initial_release_url("http://127.0.0.1:12345/manifest.json", true).is_ok());
    assert!(validate_download_url("http://localhost:12345/setup.exe", true).is_ok());
    assert!(validate_download_url("http://[::1]:12345/setup.exe", true).is_ok());
    assert!(validate_download_url("http://[::ffff:127.0.0.1]:12345/setup.exe", true).is_ok());
}

// ---------------------------------------------------------------------------
// UPD-HTTP-01..04: Real loopback WinHTTP tests
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod http_loopback_tests {
    use super::*;

    fn read_http_request_path(stream: &mut std::net::TcpStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        let _ = reader.read_line(&mut request_line);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) if line == "\r\n" || line == "\n" => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_string()
    }

    fn test_client() -> UpdaterHttpClient {
        UpdaterHttpClient::new(HttpClientConfig {
            allow_loopback_http_for_tests: true,
            ..HttpClientConfig::default()
        })
    }

    #[test]
    fn upd_http_01_loopback_fetch_manifest_and_sig_ok() {
        let sk = test_signing_key(0x71);
        let manifest = sample_manifest("0.2.0", "0.1.0", &"1".repeat(64), 1024);
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let sig_bytes = sign_manifest_bytes(&manifest_bytes, "k1", &sk);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let m_clone = manifest_bytes.clone();
        let s_clone = sig_bytes.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let path = read_http_request_path(&mut stream);
                let body = if path == "/update-manifest.json" {
                    &m_clone
                } else {
                    &s_clone
                };
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(hdr.as_bytes()).unwrap();
                stream.write_all(body).unwrap();
                stream.flush().unwrap();
            }
        });

        let cancel = CancelToken::new();
        let m_url = format!("http://127.0.0.1:{}/update-manifest.json", addr.port());
        let s_url = format!("http://127.0.0.1:{}/update-manifest.json.sig", addr.port());

        // Strict default client must reject loopback http
        let strict_client = UpdaterHttpClient::default();
        assert!(matches!(
            strict_client.fetch_manifest(&m_url, &cancel),
            Err(UpdaterError::UnsafeUrl(_))
        ));

        let client = test_client();
        let got_manifest = client.fetch_manifest(&m_url, &cancel).unwrap();
        let got_sig = client.fetch_signature(&s_url, &cancel).unwrap();
        assert_eq!(got_manifest, manifest_bytes);
        assert_eq!(got_sig, sig_bytes);

        handle.join().unwrap();
    }

    #[test]
    fn upd_http_02_manual_redirects_and_policy_guards() {
        // 5-hop redirect succeeds; 6-hop fails; disallowed redirect host fails.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            // Request 1: 5 hops -> 200 OK (6 connections)
            for _ in 0..6 {
                let (mut stream, _) = listener.accept().unwrap();
                let path = read_http_request_path(&mut stream);
                let resp = match path.as_str() {
                    "/hop0" => "HTTP/1.1 302 Found\r\nLocation: /hop1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/hop1" => format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{}/hop2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", addr.port()),
                    "/hop2" => "HTTP/1.1 308 Permanent Redirect\r\nLocation: /hop3\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/hop3" => "HTTP/1.1 302 Found\r\nLocation: /hop4\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/hop4" => "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/final" => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_string(),
                    other => panic!("unexpected path {other}"),
                };
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }

            // Request 2: 6th hop exceeds limit (6 connections -> final 302 rejected)
            for _ in 0..6 {
                let (mut stream, _) = listener.accept().unwrap();
                let path = read_http_request_path(&mut stream);
                let resp = match path.as_str() {
                    "/too-many-0" => "HTTP/1.1 302 Found\r\nLocation: /too-many-1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    "/too-many-1" => "HTTP/1.1 302 Found\r\nLocation: /too-many-2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    "/too-many-2" => "HTTP/1.1 302 Found\r\nLocation: /too-many-3\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    "/too-many-3" => "HTTP/1.1 302 Found\r\nLocation: /too-many-4\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    "/too-many-4" => "HTTP/1.1 302 Found\r\nLocation: /too-many-5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    "/too-many-5" => "HTTP/1.1 302 Found\r\nLocation: /too-many-6\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    other => panic!("unexpected path {other}"),
                };
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }

            // Request 3: redirect to disallowed host
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_http_request_path(&mut stream);
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/payload.exe\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });

        let client = test_client();
        let cancel = CancelToken::new();

        let ok_bytes = client
            .fetch_manifest(&format!("http://127.0.0.1:{}/hop0", addr.port()), &cancel)
            .unwrap();
        assert_eq!(ok_bytes, b"{}");

        let too_many_err = client
            .fetch_manifest(
                &format!("http://127.0.0.1:{}/too-many-0", addr.port()),
                &cancel,
            )
            .expect_err("6th redirect hop must fail");
        assert!(matches!(too_many_err, UpdaterError::HttpError(_)));

        let evil_err = client
            .fetch_manifest(&format!("http://127.0.0.1:{}/evil", addr.port()), &cancel)
            .expect_err("disallowed redirect host must fail");
        assert!(matches!(evil_err, UpdaterError::UnsafeUrl(_)));

        // Direct HTTPS -> HTTP downgrade guard check
        let https_origin = crate::http::ParsedHttpUrl {
            is_https: true,
            host: "github.com".into(),
            port: 443,
            path_and_query: "/Tkg-tamagohan/LocalLightEDR/releases/latest/download/update-manifest.json".into(),
        };
        let downgrade = crate::http::resolve_redirect_location(
            &https_origin,
            "http://objects.githubusercontent.com/asset.exe",
        );
        assert!(matches!(downgrade, Err(UpdaterError::UnsafeUrl(_))));

        handle.join().unwrap();
    }

    #[test]
    fn upd_http_03_bounds_truncation_and_status_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            // 1. Manifest > 64 KiB via Content-Length
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request_path(&mut s);
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    MAX_MANIFEST_BYTES + 1
                );
                s.write_all(hdr.as_bytes()).unwrap();
                s.flush().unwrap();
            }
            // 2. Manifest > 64 KiB via chunked encoding (no Content-Length)
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request_path(&mut s);
                s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
                let payload = vec![b'a'; MAX_MANIFEST_BYTES + 10];
                let chunk_hdr = format!("{:x}\r\n", payload.len());
                let _ = s.write_all(chunk_hdr.as_bytes());
                let _ = s.write_all(&payload);
                let _ = s.write_all(b"\r\n0\r\n\r\n");
                let _ = s.flush();
            }
            // 3. Signature > 4 KiB
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request_path(&mut s);
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    MAX_SIG_BYTES + 1
                );
                s.write_all(hdr.as_bytes()).unwrap();
                s.flush().unwrap();
            }
            // 4. HTTP 404
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request_path(&mut s);
                s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                s.flush().unwrap();
            }
            // 5. Truncated installer (Content-Length: 1024, closes after 256 bytes)
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request_path(&mut s);
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n").unwrap();
                s.write_all(&vec![b'x'; 256]).unwrap();
                s.flush().unwrap();
            }
            // 6. Installer with Content-Length: 512 when expected_size_bytes is Some(1024)
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request_path(&mut s);
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\nConnection: close\r\n\r\n").unwrap();
                s.write_all(&vec![b'y'; 512]).unwrap();
                s.flush().unwrap();
            }
            // 7. Chunked installer sending 512 bytes when expected_size_bytes is Some(1024)
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request_path(&mut s);
                s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
                s.write_all(b"200\r\n").unwrap();
                s.write_all(&vec![b'z'; 512]).unwrap();
                s.write_all(b"\r\n0\r\n\r\n").unwrap();
                s.flush().unwrap();
            }
            // 8. Chunked installer sending 1024 bytes when expected_size_bytes is Some(512)
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request_path(&mut s);
                s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
                s.write_all(b"400\r\n").unwrap();
                s.write_all(&vec![b'w'; 1024]).unwrap();
                s.write_all(b"\r\n0\r\n\r\n").unwrap();
                s.flush().unwrap();
            }
        });

        let client = test_client();
        let cancel = CancelToken::new();
        let base = format!("http://127.0.0.1:{}", addr.port());

        assert!(matches!(
            client.fetch_manifest(&format!("{base}/m1"), &cancel),
            Err(UpdaterError::ResponseTooLarge { kind: "manifest", .. })
        ));
        assert!(matches!(
            client.fetch_manifest(&format!("{base}/m2"), &cancel),
            Err(UpdaterError::ResponseTooLarge { kind: "manifest", .. })
        ));
        assert!(matches!(
            client.fetch_signature(&format!("{base}/s1"), &cancel),
            Err(UpdaterError::ResponseTooLarge { kind: "signature", .. })
        ));
        assert!(matches!(
            client.fetch_manifest(&format!("{base}/404"), &cancel),
            Err(UpdaterError::HttpError(_))
        ));

        let tmp = TempDir::new().unwrap();
        let trunc_path = tmp.path().join("trunc.exe");
        assert!(matches!(
            client.download_installer_to_file(
                &format!("{base}/trunc"),
                Some(1024),
                &trunc_path,
                &cancel,
                &mut |_| {}
            ),
            Err(UpdaterError::HttpError(_))
        ));
        assert!(!trunc_path.exists(), "partial truncated file must be removed");

        let size_cl_path = tmp.path().join("size_cl.exe");
        assert!(matches!(
            client.download_installer_to_file(
                &format!("{base}/size_cl"),
                Some(1024),
                &size_cl_path,
                &cancel,
                &mut |_| {}
            ),
            Err(UpdaterError::SizeMismatch { expected: 1024, actual: 512 })
        ));
        assert!(!size_cl_path.exists(), "mismatched file must be removed");

        let size_chunk_path = tmp.path().join("size_chunk.exe");
        assert!(matches!(
            client.download_installer_to_file(
                &format!("{base}/size_chunk"),
                Some(1024),
                &size_chunk_path,
                &cancel,
                &mut |_| {}
            ),
            Err(UpdaterError::SizeMismatch { expected: 1024, actual: 512 })
        ));
        assert!(!size_chunk_path.exists(), "mismatched chunked file must be removed");

        let size_over_path = tmp.path().join("size_over.exe");
        assert!(matches!(
            client.download_installer_to_file(
                &format!("{base}/size_over"),
                Some(512),
                &size_over_path,
                &cancel,
                &mut |_| {}
            ),
            Err(UpdaterError::SizeMismatch { expected: 512, actual: 1024 })
        ));
        assert!(!size_over_path.exists(), "oversized chunked file must be removed");

        handle.join().unwrap();
    }

    #[test]
    fn upd_http_04_deterministic_cancel_and_progress() {
        let client = test_client();
        let pre_cancel = CancelToken::new();
        pre_cancel.cancel();
        let tmp = TempDir::new().unwrap();
        let pre_path = tmp.path().join("pre_cancelled.exe");
        assert!(matches!(
            client.download_installer_to_file(
                "http://127.0.0.1:9/never.exe",
                Some(1024),
                &pre_path,
                &pre_cancel,
                &mut |_| {}
            ),
            Err(UpdaterError::Cancelled)
        ));
        assert!(!pre_path.exists());

        // Mid-body stall with deterministic mpsc sync (zero sleep race)
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_tx, release_rx) = mpsc::channel::<()>();

        let server = std::thread::spawn(move || {
            // 1. Stalled transfer interrupted by CancelToken
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request_path(&mut s);
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16384\r\nConnection: close\r\n\r\n")
                    .unwrap();
                s.write_all(&vec![0x5Au8; 4096]).unwrap();
                s.flush().unwrap();
                // Hold connection open until client signals cancellation observed.
                let _ = release_rx.recv_timeout(Duration::from_secs(10));
            }
            // 2. Successful multi-chunk transfer verifying monotonic progress
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request_path(&mut s);
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8192\r\nConnection: close\r\n\r\n")
                    .unwrap();
                s.write_all(&vec![0xAAu8; 4096]).unwrap();
                s.flush().unwrap();
                s.write_all(&vec![0xBBu8; 4096]).unwrap();
                s.flush().unwrap();
            }
        });

        let cancel = CancelToken::new();
        let partial_path = tmp.path().join("partial_cancel.exe");
        let cancel_clone = cancel.clone();
        let mut saw_first_chunk = false;
        let started = Instant::now();
        let err = client
            .download_installer_to_file(
                &format!("http://127.0.0.1:{}/stall.exe", addr.port()),
                Some(16384),
                &partial_path,
                &cancel,
                &mut |p| {
                    if !saw_first_chunk && p.bytes_downloaded > 0 {
                        saw_first_chunk = true;
                        cancel_clone.cancel();
                    }
                },
            )
            .expect_err("mid-body cancel must abort download");
        let elapsed = started.elapsed();
        let _ = release_tx.send(());

        assert!(matches!(err, UpdaterError::Cancelled), "got {err:?}");
        assert!(saw_first_chunk, "expected first chunk progress before cancel");
        assert!(
            elapsed < Duration::from_secs(5),
            "Condvar cancel should abort promptly, took {elapsed:?}"
        );
        assert!(
            !partial_path.exists(),
            "partial file must be deleted on cancel"
        );

        // Success path with monotonic DownloadProgress
        let ok_path = tmp.path().join("ok_installer.exe");
        let ok_cancel = CancelToken::new();
        let mut events: Vec<DownloadProgress> = Vec::new();
        let total = client
            .download_installer_to_file(
                &format!("http://127.0.0.1:{}/ok.exe", addr.port()),
                Some(8192),
                &ok_path,
                &ok_cancel,
                &mut |p| events.push(p),
            )
            .unwrap();
        assert_eq!(total, 8192);
        assert!(!events.is_empty());
        assert_eq!(events.last().unwrap().bytes_downloaded, 8192);
        assert_eq!(events.last().unwrap().total_bytes, Some(8192));
        for pair in events.windows(2) {
            assert!(pair[1].bytes_downloaded >= pair[0].bytes_downloaded);
        }

        server.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// UPD-FS-01..04: Safe filesystem, hashing, junctions & staging GC
// ---------------------------------------------------------------------------

#[test]
fn upd_fs_01_filename_validation_and_file_hashing() {
    let valid_names = [
        "LocalEDR-Setup-v0.1.0-win-x64.exe",
        "update-state.json",
        "CON1",
    ];
    for name in valid_names {
        assert!(
            validate_single_segment_filename(name).is_ok(),
            "expected valid filename {name:?}"
        );
    }

    let invalid_names = [
        "",
        ".",
        "..",
        "a/b",
        r"a\b",
        "C:foo",
        "CON",
        "con.txt",
        "NUL",
        "COM1",
        "LPT9.exe",
        "bad.",
        "bad ",
        "bad\0name",
        "bad:stream",
        "bad*name",
    ];
    for name in invalid_names {
        assert!(
            matches!(
                validate_single_segment_filename(name),
                Err(UpdaterError::UnsafePath(_))
            ),
            "expected UnsafePath for {name:?}"
        );
    }

    let tmp = TempDir::new().unwrap();
    let file_path = tmp.path().join("LocalEDR-Setup-v0.2.0-win-x64.exe");
    let payload = b"synthetic-installer-payload-bytes";
    {
        let mut f = create_exclusive_file(&file_path).unwrap();
        f.write_all(payload).unwrap();
        f.sync_all().unwrap();
    }

    let expected_sha = hex::encode(Sha256::digest(payload));
    assert_eq!(sha256_file_hex(&file_path).unwrap(), expected_sha);

    let manifest = sample_manifest("0.2.0", "0.1.0", &expected_sha, payload.len() as u64);
    verify_installer_file(&file_path, &manifest).unwrap();

    let mut bad_hash = manifest.clone();
    bad_hash.sha256 = "0".repeat(64);
    assert!(matches!(
        verify_installer_file(&file_path, &bad_hash),
        Err(UpdaterError::HashMismatch { .. })
    ));

    let mut bad_size = manifest;
    bad_size.size_bytes = payload.len() as u64 + 1;
    assert!(matches!(
        verify_installer_file(&file_path, &bad_size),
        Err(UpdaterError::SizeMismatch { .. })
    ));
}

#[cfg(windows)]
struct JunctionGuard(PathBuf);

#[cfg(windows)]
impl JunctionGuard {
    fn create(link: PathBuf, target: &Path) -> Self {
        let output = std::process::Command::new("cmd.exe")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(target)
            .output()
            .expect("spawn cmd.exe /c mklink /J");
        assert!(
            output.status.success(),
            "mklink /J failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self(link)
    }
}

#[cfg(windows)]
impl Drop for JunctionGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[cfg(windows)]
#[test]
fn upd_fs_02_junction_reparse_point_rejection() {
    let tmp = TempDir::new().unwrap();
    let real_target = tmp.path().join("real_target");
    std::fs::create_dir(&real_target).unwrap();
    let victim_file = real_target.join("keep.txt");
    std::fs::write(&victim_file, b"must-not-be-touched").unwrap();

    let junction_path = tmp.path().join("junction_dir");
    let _guard = JunctionGuard::create(junction_path.clone(), &real_target);

    // Leaf & ancestor junction rejection in ensure_no_reparse_points
    assert!(matches!(
        ensure_no_reparse_points(&junction_path),
        Err(UpdaterError::UnsafePath(_))
    ));
    assert!(matches!(
        ensure_no_reparse_points(&junction_path.join("child.txt")),
        Err(UpdaterError::UnsafePath(_))
    ));

    // Reject staging / verified session creation through a junction root
    assert!(matches!(
        create_staging_session_dir(&junction_path),
        Err(UpdaterError::UnsafePath(_))
    ));
    assert!(matches!(
        create_verified_session_dir(&junction_path),
        Err(UpdaterError::UnsafePath(_))
    ));

    // Reject exclusive create, atomic write, and verified read through junction
    assert!(matches!(
        create_exclusive_file(&junction_path.join("new.bin")),
        Err(UpdaterError::UnsafePath(_))
    ));
    assert!(matches!(
        atomic_write_file(&junction_path.join("state.json"), b"{}"),
        Err(UpdaterError::UnsafePath(_))
    ));
    assert!(matches!(
        sha256_file_hex(&junction_path.join("keep.txt")),
        Err(UpdaterError::UnsafePath(_))
    ));

    // cleanup_stale_staging_dirs must skip a UUID-named junction inside staging_root
    let staging_root = tmp.path().join("staging");
    std::fs::create_dir(&staging_root).unwrap();
    let uuid_junction = staging_root.join(Uuid::new_v4().to_string());
    let _staging_junc_guard = JunctionGuard::create(uuid_junction, &real_target);

    let removed = cleanup_stale_staging_dirs(&staging_root, Duration::ZERO).unwrap();
    assert_eq!(removed, 0);
    assert!(
        victim_file.exists(),
        "staging GC must never follow a junction to delete target files"
    );
}

#[test]
fn upd_fs_03_exclusive_create_and_atomic_write() {
    let tmp = TempDir::new().unwrap();
    let exclusive = tmp.path().join("exclusive.bin");

    let mut f = create_exclusive_file(&exclusive).unwrap();
    f.write_all(b"first").unwrap();
    drop(f);

    let err = create_exclusive_file(&exclusive).expect_err("second exclusive create must fail");
    assert!(matches!(err, UpdaterError::Io(_)));

    let nested_dest = tmp.path().join("nested").join("dir").join("update-state.json");
    atomic_write_file(&nested_dest, br#"{"step":1}"#).unwrap();
    assert_eq!(std::fs::read(&nested_dest).unwrap(), br#"{"step":1}"#);

    atomic_write_file(&nested_dest, br#"{"step":2}"#).unwrap();
    assert_eq!(std::fs::read(&nested_dest).unwrap(), br#"{"step":2}"#);

    let parent_entries: Vec<_> = std::fs::read_dir(nested_dest.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        parent_entries,
        vec!["update-state.json".to_string()],
        "no leftover temp files should remain after atomic_write_file"
    );
}

#[cfg(windows)]
fn set_dir_modified_time(dir: &Path, time: SystemTime) {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let dir_handle = std::fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .expect("open directory for FILE_WRITE_ATTRIBUTES");
    dir_handle
        .set_modified(time)
        .expect("set directory modified timestamp");
}

#[test]
fn upd_fs_04_staging_cleanup_age_and_safety() {
    let tmp = TempDir::new().unwrap();
    let missing_root = tmp.path().join("does-not-exist");
    assert_eq!(
        cleanup_stale_staging_dirs(&missing_root, Duration::from_secs(60)).unwrap(),
        0
    );

    let staging_root = tmp.path().join("staging");
    let (stale_id, stale_dir) = create_staging_session_dir(&staging_root).unwrap();
    let (_fresh_id, fresh_dir) = create_staging_session_dir(&staging_root).unwrap();
    let (_future_id, future_dir) = create_staging_session_dir(&staging_root).unwrap();

    // Write a file inside stale_dir to verify recursive cleanups work.
    std::fs::write(stale_dir.join("installer.exe"), b"stale").unwrap();

    // Non-UUID directory inside staging_root must be preserved.
    let non_uuid_dir = staging_root.join("keep-non-uuid");
    std::fs::create_dir(&non_uuid_dir).unwrap();

    #[cfg(windows)]
    {
        let now = SystemTime::now();
        set_dir_modified_time(&stale_dir, now - Duration::from_secs(3600));
        set_dir_modified_time(&future_dir, now + Duration::from_secs(3600));
        set_dir_modified_time(&non_uuid_dir, now - Duration::from_secs(3600));

        let removed = cleanup_stale_staging_dirs(&staging_root, Duration::from_secs(600)).unwrap();
        assert_eq!(removed, 1, "only stale UUID dir {stale_id} should be removed");
        assert!(!stale_dir.exists());
        assert!(fresh_dir.exists());
        assert!(future_dir.exists());
        assert!(non_uuid_dir.exists());
    }

    #[cfg(not(windows))]
    {
        let _ = (stale_id, fresh_dir, future_dir);
    }
}
