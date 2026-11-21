//! NTFS `:Zone.Identifier` Alternate Data Stream (MOTW) parsing, safe reading, and writing.

use std::borrow::Cow;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;

/// Maximum number of bytes read from or written to a `:Zone.Identifier` ADS (16 KiB).
pub const MAX_ZONE_IDENTIFIER_BYTES: usize = 16 * 1024;

/// Windows URLZONE threshold representing the Internet Zone (`URLZONE_INTERNET = 3`).
pub const ZONE_ID_INTERNET: u32 = 3;

/// Parsed contents of an NTFS `:Zone.Identifier` `[ZoneTransfer]` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MotwZoneInfo {
    pub zone_id: u32,
    pub host_url: Option<String>,
    pub referrer_url: Option<String>,
}

impl MotwZoneInfo {
    /// Returns `true` when `zone_id >= ZONE_ID_INTERNET` (Internet or Restricted Sites zone).
    pub const fn is_internet_origin(&self) -> bool {
        self.zone_id >= ZONE_ID_INTERNET
    }

    /// Returns the preferred usable origin URL (`HostUrl`, else `ReferrerUrl`, else `"motw:zone<N>"`
    /// when `is_internet_origin()` holds).
    pub fn preferred_origin_url(&self) -> Option<String> {
        if let Some(host) = self.host_url.as_deref().filter(|s| is_usable_origin_url(s)) {
            return Some(host.to_string());
        }
        if let Some(ref_url) = self
            .referrer_url
            .as_deref()
            .filter(|s| is_usable_origin_url(s))
        {
            return Some(ref_url.to_string());
        }
        self.is_internet_origin()
            .then(|| format!("motw:zone{}", self.zone_id))
    }
}

fn is_usable_origin_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && !trimmed.eq_ignore_ascii_case("about:internet")
        && !trimmed.eq_ignore_ascii_case("about:blank")
}

/// Parses the INI content of a `:Zone.Identifier` ADS (`[ZoneTransfer]` section).
pub fn parse_zone_identifier(content: &str) -> Option<MotwZoneInfo> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut in_zone_transfer = false;
    let mut zone_id: Option<u32> = None;
    let mut host_url: Option<String> = None;
    let mut referrer_url: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_zone_transfer = line.eq_ignore_ascii_case("[ZoneTransfer]");
            continue;
        }
        if !in_zone_transfer {
            continue;
        }
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();
        if key.eq_ignore_ascii_case("ZoneId") {
            if let Ok(parsed) = val.parse::<u32>() {
                zone_id = Some(parsed);
            }
        } else if key.eq_ignore_ascii_case("HostUrl") {
            host_url = is_usable_origin_url(val).then(|| val.to_string());
        } else if key.eq_ignore_ascii_case("ReferrerUrl") {
            referrer_url = is_usable_origin_url(val).then(|| val.to_string());
        }
    }

    Some(MotwZoneInfo {
        zone_id: zone_id?,
        host_url,
        referrer_url,
    })
}

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, msg)
}

fn validate_and_build_ads_path(path: &Path) -> io::Result<OsString> {
    let raw = path
        .as_os_str()
        .to_str()
        .ok_or_else(|| invalid_input("MOTW path must be valid UTF-8"))?;
    if raw.trim().is_empty() || raw.contains('\0') {
        return Err(invalid_input("MOTW path cannot be empty or contain NUL"));
    }
    if raw.ends_with('\\') || raw.ends_with('/') {
        return Err(invalid_input("MOTW path cannot end with a directory separator"));
    }

    // Reject Win32 device namespace (`\\.\`) and NT object namespace (`\??\`).
    if raw.starts_with(r"\\.\")
        || raw.starts_with("//./")
        || raw == r"\\."
        || raw == "//."
        || raw.starts_with(r"\??\")
        || raw.starts_with("/??/")
        || raw == r"\??"
        || raw == "/??"
    {
        return Err(invalid_input("MOTW path rejects Win32/NT device namespace prefixes"));
    }

    if raw.starts_with(r"\\?\") || raw.starts_with("//?/") {
        let rest = &raw[4..];
        if rest.len() >= 4
            && (rest[..4].eq_ignore_ascii_case(r"UNC\") || rest[..4].eq_ignore_ascii_case("UNC/"))
        {
            let unc_tail = &rest[4..];
            if unc_tail.is_empty() || unc_tail.contains(':') {
                return Err(invalid_input(
                    "MOTW extended UNC path is empty or contains an ADS suffix",
                ));
            }
        } else {
            let rb = rest.as_bytes();
            let valid_drive_root = rb.len() >= 4
                && rb[0].is_ascii_alphabetic()
                && rb[1] == b':'
                && (rb[2] == b'\\' || rb[2] == b'/');
            if !valid_drive_root || rest[3..].contains(':') {
                return Err(invalid_input(
                    "MOTW extended-length path must target a drive file without existing ADS",
                ));
            }
        }
    } else if raw == r"\\?" || raw == "//?" {
        return Err(invalid_input("incomplete extended-length prefix"));
    } else {
        let rb = raw.as_bytes();
        if rb.len() >= 2 && rb[0].is_ascii_alphabetic() && rb[1] == b':' {
            if raw.len() == 2 || raw[2..].contains(':') {
                return Err(invalid_input(
                    "MOTW drive path cannot be bare drive or include an existing ADS suffix",
                ));
            }
        } else if raw.contains(':') {
            return Err(invalid_input("MOTW path cannot include an existing ADS suffix"));
        }
    }

    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(invalid_input("MOTW target path must be an existing regular file"));
    }

    let mut ads = OsString::from(path.as_os_str());
    ads.push(":Zone.Identifier");
    Ok(ads)
}

/// Safely reads and parses up to [`MAX_ZONE_IDENTIFIER_BYTES`] (16 KiB) from `path`'s
/// `:Zone.Identifier` NTFS Alternate Data Stream. Returns `None` if validation fails, the ADS
/// does not exist, or the content lacks a valid `[ZoneTransfer]` `ZoneId`.
pub fn read_zone_identifier(path: &Path) -> Option<MotwZoneInfo> {
    let ads_path = validate_and_build_ads_path(path).ok()?;
    let file = File::open(&ads_path).ok()?;
    let mut buf = Vec::with_capacity(512);
    file.take(MAX_ZONE_IDENTIFIER_BYTES as u64)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.is_empty() {
        return None;
    }

    let text: Cow<'_, str> = if buf.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = buf[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        Cow::Owned(String::from_utf16_lossy(&units))
    } else {
        String::from_utf8_lossy(&buf)
    };

    parse_zone_identifier(&text)
}

fn validate_ads_field_value(value: &str) -> io::Result<&str> {
    if value.contains(['\r', '\n', '\0']) {
        return Err(invalid_input(
            "MOTW URL field cannot contain CR, LF, or NUL characters",
        ));
    }
    Ok(value.trim())
}

/// Writes `[ZoneTransfer]` metadata to `path`'s `:Zone.Identifier` NTFS Alternate Data Stream.
pub fn write_zone_identifier(path: &Path, info: &MotwZoneInfo) -> io::Result<()> {
    let ads_path = validate_and_build_ads_path(path)?;

    let mut content = format!("[ZoneTransfer]\r\nZoneId={}\r\n", info.zone_id);
    if let Some(ref_url) = info.referrer_url.as_deref() {
        let clean = validate_ads_field_value(ref_url)?;
        if !clean.is_empty() {
            content.push_str(&format!("ReferrerUrl={clean}\r\n"));
        }
    }
    if let Some(host_url) = info.host_url.as_deref() {
        let clean = validate_ads_field_value(host_url)?;
        if !clean.is_empty() {
            content.push_str(&format!("HostUrl={clean}\r\n"));
        }
    }

    if content.len() > MAX_ZONE_IDENTIFIER_BYTES {
        return Err(invalid_input(
            "formatted :Zone.Identifier content exceeds 16 KiB limit",
        ));
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&ads_path)?;
    file.write_all(content.as_bytes())?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempMotwDir(PathBuf);

    impl TempMotwDir {
        fn new(label: &str) -> Self {
            let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "ledr-motw-test-{label}-{}-{seq}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir for motw tests");
            Self(dir)
        }
    }

    impl Drop for TempMotwDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn motw_01_parse_zone_transfer_crlf_and_lf() {
        let crlf = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://ref.example.test/page\r\nHostUrl=https://cdn.example.test/tool.exe\r\n";
        let parsed_crlf = parse_zone_identifier(crlf).expect("parse CRLF");
        assert_eq!(
            parsed_crlf,
            MotwZoneInfo {
                zone_id: 3,
                host_url: Some("https://cdn.example.test/tool.exe".to_string()),
                referrer_url: Some("https://ref.example.test/page".to_string()),
            }
        );
        assert!(parsed_crlf.is_internet_origin());

        let lf = "[ZoneTransfer]\nZoneId=4\nHostUrl=https://untrusted.example.test/drop.exe\n";
        let parsed_lf = parse_zone_identifier(lf).expect("parse LF");
        assert_eq!(
            parsed_lf,
            MotwZoneInfo {
                zone_id: 4,
                host_url: Some("https://untrusted.example.test/drop.exe".to_string()),
                referrer_url: None,
            }
        );
        assert!(parsed_lf.is_internet_origin());
    }

    #[test]
    fn motw_02_parse_case_insensitive_bom_comments_and_other_sections() {
        let raw = "\u{feff}; leading comment\r\n[Other]\r\nZoneId=0\r\nHostUrl=https://ignored.invalid/\r\n[zonetransfer]\r\n# inline comment\r\nzoneid = 3 \r\nhosturl = https://dl.example.test/app.exe\r\nreferrerurl = https://portal.example.test/\r\n[AnotherSection]\r\nZoneId=1\r\nHostUrl=https://trailing.invalid/\r\n";
        let parsed = parse_zone_identifier(raw).expect("parse case-insensitive section");
        assert_eq!(parsed.zone_id, 3);
        assert_eq!(
            parsed.host_url.as_deref(),
            Some("https://dl.example.test/app.exe")
        );
        assert_eq!(
            parsed.referrer_url.as_deref(),
            Some("https://portal.example.test/")
        );
    }

    #[test]
    fn motw_03_about_internet_excluded_and_preferred_origin_fallback() {
        let only_about_internet =
            "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=about:internet\r\n";
        let parsed = parse_zone_identifier(only_about_internet).expect("parse zone 3");
        assert_eq!(parsed.host_url, None);
        assert_eq!(parsed.referrer_url, None);
        assert_eq!(
            parsed.preferred_origin_url().as_deref(),
            Some("motw:zone3")
        );

        let referrer_fallback =
            "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://ref.example.test/\r\nHostUrl=ABOUT:INTERNET\r\n";
        let parsed_ref = parse_zone_identifier(referrer_fallback).expect("parse ref fallback");
        assert_eq!(parsed_ref.host_url, None);
        assert_eq!(
            parsed_ref.preferred_origin_url().as_deref(),
            Some("https://ref.example.test/")
        );

        let local_zone = parse_zone_identifier("[ZoneTransfer]\nZoneId=2\nHostUrl=about:blank\n")
            .expect("parse zone 2");
        assert!(!local_zone.is_internet_origin());
        assert_eq!(local_zone.preferred_origin_url(), None);
    }

    #[test]
    fn motw_04_missing_section_or_invalid_zone_id_returns_none() {
        assert_eq!(parse_zone_identifier(""), None);
        assert_eq!(parse_zone_identifier("ZoneId=3\n"), None);
        assert_eq!(parse_zone_identifier("[ZoneTransfer]\nHostUrl=https://x\n"), None);
        assert_eq!(parse_zone_identifier("[ZoneTransfer]\nZoneId=abc\n"), None);
    }

    #[test]
    fn motw_05_ntfs_ads_write_read_roundtrip_and_absent_ads() {
        let dir = TempMotwDir::new("roundtrip");
        let file_path = dir.0.join("sample-installer.exe");
        std::fs::write(&file_path, b"MZ-dummy-payload").expect("write target file");

        assert_eq!(read_zone_identifier(&file_path), None);

        let info = MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://download.example.invalid/sample-installer.exe".to_string()),
            referrer_url: Some("https://portal.example.invalid/".to_string()),
        };
        write_zone_identifier(&file_path, &info).expect("write :Zone.Identifier ADS");

        let read_back = read_zone_identifier(&file_path).expect("read back :Zone.Identifier ADS");
        assert_eq!(read_back, info);

        // Verify extended-length `\\?\` drive paths also round-trip safely.
        let ext_path = PathBuf::from(format!(r"\\?\{}", file_path.display()));
        let read_ext = read_zone_identifier(&ext_path).expect("read via extended path");
        assert_eq!(read_ext, info);
    }

    #[test]
    fn motw_06_read_enforces_16kib_cap_cutoff() {
        let dir = TempMotwDir::new("cap");

        // Case A: >16 KiB leading comments push `[ZoneTransfer]` past the 16 KiB cap -> None.
        let file_beyond = dir.0.join("beyond_cap.exe");
        std::fs::write(&file_beyond, b"dummy").expect("write target");
        let ads_beyond = format!("{}:Zone.Identifier", file_beyond.display());
        let mut big_leading = "; ".to_string();
        big_leading.push_str(&"A".repeat(MAX_ZONE_IDENTIFIER_BYTES + 256));
        big_leading.push_str("\r\n[ZoneTransfer]\r\nZoneId=3\r\n");
        std::fs::write(&ads_beyond, big_leading.as_bytes()).expect("write oversized leading ADS");
        assert_eq!(
            read_zone_identifier(&file_beyond),
            None,
            "data past 16 KiB cap must not be read"
        );

        // Case B: valid header within first 16 KiB + >16 KiB trailing padding -> still parses header.
        let file_prefix = dir.0.join("prefix_within_cap.exe");
        std::fs::write(&file_prefix, b"dummy").expect("write target");
        let ads_prefix = format!("{}:Zone.Identifier", file_prefix.display());
        let mut big_trailing =
            "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://bounded.example.invalid/bin.exe\r\n; "
                .to_string();
        big_trailing.push_str(&"B".repeat(MAX_ZONE_IDENTIFIER_BYTES + 512));
        std::fs::write(&ads_prefix, big_trailing.as_bytes()).expect("write oversized trailing ADS");
        let parsed = read_zone_identifier(&file_prefix).expect("parse header within 16 KiB cap");
        assert_eq!(parsed.zone_id, 3);
        assert_eq!(
            parsed.host_url.as_deref(),
            Some("https://bounded.example.invalid/bin.exe")
        );
    }

    #[test]
    fn motw_07_rejects_empty_device_and_existing_ads_paths() {
        let dir = TempMotwDir::new("reject");
        let file_path = dir.0.join("tool.exe");
        std::fs::write(&file_path, b"dummy").expect("write target");

        let existing_ads = PathBuf::from(format!("{}:Zone.Identifier", file_path.display()));
        let other_ads = PathBuf::from(format!("{}:custom", file_path.display()));
        let ext_ads = PathBuf::from(format!(r"\\?\{}:Zone.Identifier", file_path.display()));

        let info = MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://example.invalid/".to_string()),
            referrer_url: None,
        };

        let invalid_paths = [
            PathBuf::from(""),
            PathBuf::from("   "),
            PathBuf::from(r"\\.\PhysicalDrive0"),
            PathBuf::from(r"\\.\pipe\localedr-ipc"),
            PathBuf::from("//./pipe/localedr-ipc"),
            PathBuf::from(r"\??\C:\Windows\System32\cmd.exe"),
            PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolume1\a.exe"),
            PathBuf::from(r"\\?\Volume{00000000-0000-0000-0000-000000000000}\a.exe"),
            PathBuf::from(r"\\?\pipe\localedr-ipc"),
            PathBuf::from("C:"),
            PathBuf::from(format!(r"{}\", dir.0.display())),
            existing_ads,
            other_ads,
            ext_ads,
            PathBuf::from("relative.exe:Zone.Identifier"),
        ];

        for bad in &invalid_paths {
            assert!(
                write_zone_identifier(bad, &info).is_err(),
                "write_zone_identifier must reject {}",
                bad.display()
            );
            assert_eq!(
                read_zone_identifier(bad),
                None,
                "read_zone_identifier must return None for {}",
                bad.display()
            );
        }
    }

    #[test]
    fn motw_08_rejects_non_file_and_crlf_injection() {
        let dir = TempMotwDir::new("nonfile");
        let info = MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://example.invalid/a.exe".to_string()),
            referrer_url: None,
        };
        assert!(write_zone_identifier(&dir.0, &info).is_err());
        assert_eq!(read_zone_identifier(&dir.0), None);

        let missing = dir.0.join("does_not_exist.exe");
        assert!(write_zone_identifier(&missing, &info).is_err());
        assert_eq!(read_zone_identifier(&missing), None);

        let real_file = dir.0.join("real.exe");
        std::fs::write(&real_file, b"dummy").expect("write target");
        let injected = MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://good.invalid/a\r\nZoneId=0".to_string()),
            referrer_url: None,
        };
        assert!(write_zone_identifier(&real_file, &injected).is_err());
        let injected_ref = MotwZoneInfo {
            zone_id: 3,
            host_url: None,
            referrer_url: Some("https://good.invalid/b\nZoneId=0".to_string()),
        };
        assert!(write_zone_identifier(&real_file, &injected_ref).is_err());
    }
}
