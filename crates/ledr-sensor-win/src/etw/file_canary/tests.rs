use super::*;
use std::path::PathBuf;

fn test_volume_map() -> DosVolumeMap {
    DosVolumeMap::with_mappings(vec![
        (
            r"\Device\HarddiskVolume3".encode_utf16().collect(),
            "C:".to_string(),
        ),
        (
            r"\Device\HarddiskVolume4".encode_utf16().collect(),
            "D:".to_string(),
        ),
    ])
}

#[test]
fn sens_p2_01_utf16_prefilter_and_volume_translation() {
    let vmap = test_volume_map();
    let matcher = CanaryMatcher::new([PathBuf::from(r"D:\Workspace\secret-app")], Vec::<PathBuf>::new());

    // Non-protected Windows system and build artifacts are rejected cleanly.
    for benign in [
        r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll",
        r"\Device\HarddiskVolume3\Users\Alice\AppData\Local\Temp\cargo_build.obj",
        r"\Device\HarddiskVolume3\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Cookies-journal",
        r"\Device\HarddiskVolume3\Users\Alice\.ssh",
        r"\Device\HarddiskVolume3\Users\Alice\.ssh\",
        r"\Device\HarddiskVolume3\Users\Alice\.aws\cli_cache.json",
        r"\Device\HarddiskVolume4\Workspace\secret-app-other\.env",
        "",
    ] {
        let u16_path: Vec<u16> = benign.encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(
            prefilter_and_classify_canary_u16(&matcher, &u16_path, &vmap, false),
            None,
            "expected None for benign path `{benign}`"
        );
        assert_eq!(
            prefilter_and_classify_canary(&matcher, benign, &vmap, true),
            None,
            "expected None on write for benign path `{benign}`"
        );
    }

    // Verify NT device translation + case-insensitive UTF-16 slice classification.
    let nt_cookie: Vec<u16> =
        r"\device\harddiskvolume3\USERS\Alice\AppData\Local\Google\Chrome\User Data\Default\Network\COOKIES"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
    assert_eq!(
        prefilter_and_classify_canary_u16(&matcher, &nt_cookie, &vmap, false),
        Some(CanaryCategory::CookieDb)
    );

    let nt_env: Vec<u16> = r"\Device\HarddiskVolume4\Workspace\secret-app\api\.ENV.PRODUCTION"
        .encode_utf16()
        .collect();
    assert_eq!(
        prefilter_and_classify_canary_u16(&matcher, &nt_env, &vmap, false),
        Some(CanaryCategory::EnvFile)
    );
}

#[test]
fn sens_p2_02_folder_canary_two_tiers_and_honeypot_write_gate() {
    let vmap = test_volume_map();
    let matcher = CanaryMatcher::new(
        [PathBuf::from(r"C:\dev\my-project")],
        [PathBuf::from(r"D:\Traps\custom_trap.docx")],
    )
    .with_user_profiles([PathBuf::from(r"E:\Profiles\customuser")]);

    // Tier 1: CookieDb across Chrome, Edge, Brave, Firefox.
    for cookie_path in [
        r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies",
        r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Profile 2\Network\Cookies",
        r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies",
        r"C:\Users\alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cookies",
        r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release\cookies.sqlite",
    ] {
        assert_eq!(
            matcher.classify_str(cookie_path, &vmap, false),
            Some(CanaryCategory::CookieDb),
            "expected CookieDb for `{cookie_path}`"
        );
    }

    // Tier 1: LoginData across Chrome, Edge, Brave, Firefox.
    for login_path in [
        r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default\Login Data For Account",
        r"C:\Users\alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State",
        r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default\logins.json",
        r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default\key4.db",
    ] {
        assert_eq!(
            matcher.classify_str(login_path, &vmap, false),
            Some(CanaryCategory::LoginData),
            "expected LoginData for `{login_path}`"
        );
    }

    // Tier 1: SshKey & CloudCredential.
    assert_eq!(
        matcher.classify_str(r"C:\Users\alice\.ssh\id_ed25519", &vmap, false),
        Some(CanaryCategory::SshKey)
    );
    assert_eq!(
        matcher.classify_str(r"E:\Profiles\customuser\.ssh\id_rsa", &vmap, false),
        Some(CanaryCategory::SshKey)
    );
    assert_eq!(
        matcher.classify_str(r"C:\Users\alice\.aws\credentials", &vmap, false),
        Some(CanaryCategory::CloudCredential)
    );
    assert_eq!(
        matcher.classify_str(r"C:\Users\alice\.aws\config", &vmap, false),
        Some(CanaryCategory::CloudCredential)
    );
    assert_eq!(
        matcher.classify_str(
            r"C:\Users\alice\.config\gcloud\application_default_credentials.json",
            &vmap,
            false
        ),
        Some(CanaryCategory::CloudCredential)
    );

    // Tier 2: Registered dev_roots `.env` / `.env.*`, skipping sample templates.
    assert_eq!(
        matcher.classify_str(r"C:\dev\my-project\.env", &vmap, false),
        Some(CanaryCategory::EnvFile)
    );
    assert_eq!(
        matcher.classify_str(r"C:\dev\my-project\sub\.env.local", &vmap, true),
        Some(CanaryCategory::EnvFile)
    );
    for skipped in [
        r"C:\dev\my-project\.env.example",
        r"C:\dev\my-project\.env.sample",
        r"C:\dev\my-project\.env.template",
        r"C:\dev\my-project\.ENV.EXAMPLE",
        r"C:\dev\my-project\.envrc",
        r"C:\other\.env",
    ] {
        assert_eq!(
            matcher.classify_str(skipped, &vmap, true),
            None,
            "expected None for `{skipped}`"
        );
    }

    // Honeypot (L-06): read-only open MUST return None; write/delete MUST return Some(Honeypot).
    let default_hp = format!(r"C:\Users\alice\Documents\{HONEYPOT_DEFAULT_FILENAME}");
    assert_eq!(matcher.classify_str(&default_hp, &vmap, false), None);
    assert_eq!(
        matcher.classify_str(&default_hp, &vmap, true),
        Some(CanaryCategory::Honeypot)
    );
    assert_eq!(
        matcher.classify_str(r"D:\Traps\custom_trap.docx", &vmap, false),
        None
    );
    assert_eq!(
        matcher.classify_str(r"D:\Traps\custom_trap.docx", &vmap, true),
        Some(CanaryCategory::Honeypot)
    );
}

#[test]
fn sens_p2_03_autorun_registry_key_matching() {
    for matched in [
        r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"\REGISTRY\USER\S-1-5-21-123\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"\registry\machine\software\microsoft\windows nt\currentversion\winlogon",
        r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\EvilPersistence",
    ] {
        assert!(
            is_autorun_registry_key(matched),
            "expected autorun match for `{matched}`"
        );
    }

    for benign in [
        r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunMRU",
        r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\App",
        r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services",
        r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\",
        "",
    ] {
        assert!(
            !is_autorun_registry_key(benign),
            "expected no autorun match for `{benign}`"
        );
    }
}

#[test]
fn sens_p2_04_autorun_registry_value_target_excludes_services() {
    for target in [
        r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"\REGISTRY\USER\S-1-5-21-123\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ] {
        assert!(
            is_autorun_registry_value_target(target),
            "expected value-target match for `{target}`"
        );
    }

    for non_target in [
        r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\EvilPersistence",
        r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunMRU",
        "",
    ] {
        assert!(
            !is_autorun_registry_value_target(non_target),
            "expected no value-target match for `{non_target}`"
        );
    }
}
