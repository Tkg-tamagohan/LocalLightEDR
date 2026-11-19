use super::*;
use super::fs_scenarios::{TempSimDir, dummy_cookie_path, dummy_honeypot_path};
use super::net::{exchange_ping_ack, handle_ping_server};
use std::path::{Path, PathBuf};
use ledr_proto::HONEYPOT_DEFAULT_FILENAME;

fn base64_decode(input: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let vals: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=')
        .map(|b| match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64 byte: {b}"),
        })
        .collect();

    for chunk in vals.chunks(4) {
        if chunk.len() >= 2 {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
        }
        if chunk.len() >= 3 {
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() == 4 {
            out.push((chunk[2] << 6) | chunk[3]);
        }
    }
    out
}

#[test]
fn sim_01_cli_arg_parsing() {
    assert_eq!(parse_cli_args::<[&str; 0], &str>([]).unwrap(), CliAction::Help);
    assert_eq!(parse_cli_args(["--help"]).unwrap(), CliAction::Help);

    assert_eq!(
        parse_cli_args(["lotl"]).unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::Lotl,
            ..SimConfig::default()
        })
    );
    assert_eq!(
        parse_cli_args(["dns-tcp", "--domain", "example.org", "--port", "8443", "--loopback"])
            .unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::DnsTcp,
            domain: "example.org".to_string(),
            port: 8443,
            loopback: true,
            json_output: false,
            hold_ms: 0,
            prepare_dir: None,
            base_dir: None,
        })
    );
    assert_eq!(
        parse_cli_args(["cookies-open", "--hold-ms", "1500"]).unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::CookiesOpen,
            hold_ms: 1500,
            ..SimConfig::default()
        })
    );
    assert_eq!(
        parse_cli_args(["honeypot-write", "--hold-ms=250"]).unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::HoneypotWrite,
            hold_ms: 250,
            ..SimConfig::default()
        })
    );
    assert_eq!(
        parse_cli_args(["--scenario", "all", "--json"]).unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::All,
            json_output: true,
            ..SimConfig::default()
        })
    );
    assert_eq!(
        parse_cli_args(["run-all"]).unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::All,
            ..SimConfig::default()
        })
    );
    assert_eq!(
        parse_cli_args(["cookies-open", "--json"]).unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::CookiesOpen,
            json_output: true,
            ..SimConfig::default()
        })
    );
    assert_eq!(
        parse_cli_args(["--scenario=honeypot-write"]).unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::HoneypotWrite,
            ..SimConfig::default()
        })
    );

    assert!(parse_cli_args(["--scenario"]).is_err());
    assert!(parse_cli_args(["--scenario", "unknown"]).is_err());
    assert!(parse_cli_args(["--port", "0"]).is_err());
    assert!(parse_cli_args(["--unknown-flag"]).is_err());
}

#[tokio::test]
async fn sim_02_loopback_tcp_and_encoded_command() {
    let args = build_lotl_cmd_args();
    assert_eq!(args[0], "/c");
    assert_eq!(args[1], "powershell.exe");
    assert_eq!(args[2], "-NoProfile");
    assert_eq!(args[3], "-NonInteractive");
    assert_eq!(args[4], "-EncodedCommand");

    let decoded_bytes = base64_decode(&args[5]);
    let decoded_u16: Vec<u16> = decoded_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .collect();
    let decoded_script = String::from_utf16(&decoded_u16).expect("valid UTF-16LE");
    assert_eq!(decoded_script, LOTL_HARMLESS_SCRIPT);

    let (mut client_dup, mut server_dup) = tokio::io::duplex(128);
    let srv = tokio::spawn(async move { handle_ping_server(&mut server_dup).await });
    let ack = exchange_ping_ack(&mut client_dup)
        .await
        .expect("duplex ping/ack exchange should succeed");
    let ping = srv.await.expect("server task").expect("server read/write");
    assert_eq!(ping, "LocalEDR-Sim-Ping\n");
    assert_eq!(ack, "LocalEDR-Sim-Ack\n");

    match run_dns_tcp_scenario("example.com", 80, true).await {
        Ok(outcome) => {
            assert!(outcome.used_loopback);
            assert!(outcome.connected);
            assert!(!outcome.resolved_ips.is_empty());
            assert!(
                outcome
                    .connected_addr
                    .as_deref()
                    .is_some_and(|a| a.starts_with("127.0.0.1:"))
            );
        }
        Err(err) => {
            // Restricted Windows AppContainer sandboxes block Winsock connect() with WSAEACCES (10013).
            let is_sandbox_socket_block = err.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io_err| {
                        io_err.kind() == std::io::ErrorKind::PermissionDenied
                            || io_err.raw_os_error() == Some(10013)
                    })
            });
            assert!(
                is_sandbox_socket_block,
                "unexpected loopback dns-tcp failure: {err:#}"
            );
        }
    }
}

#[tokio::test]
async fn sim_p2_01_cookies_open_scenario() {
    let outcome = run_cookies_open_scenario()
        .await
        .expect("cookies-open scenario should succeed");
    assert!(outcome.opened);
    assert!(outcome.bytes_read > 0);
    assert!(
        outcome
            .target_path
            .ends_with(r"Google\Chrome\User Data\Default\Cookies")
            || outcome
                .target_path
                .ends_with("Google/Chrome/User Data/Default/Cookies"),
        "unexpected cookie path: {}",
        outcome.target_path
    );
    // Temporary scenario file must have been cleaned up on completion.
    assert!(
        !Path::new(&outcome.target_path).exists(),
        "temp cookie path should be cleaned up"
    );

    let temp = TempSimDir::new("test-cookies").expect("temp dir");
    let in_dir = run_cookies_open_scenario_in(temp.path()).expect("cookies-open in temp dir");
    assert!(in_dir.opened);
    assert!(in_dir.bytes_read > 0);
    assert!(Path::new(&in_dir.target_path).is_file());
}

#[tokio::test]
async fn sim_p2_02_honeypot_write_scenario() {
    let outcome = run_honeypot_write_scenario()
        .await
        .expect("honeypot-write scenario should succeed");
    assert_eq!(outcome.appended_bytes, 1);
    assert_eq!(outcome.final_bytes, outcome.initial_bytes + 1);
    assert!(
        outcome.target_path.ends_with(HONEYPOT_DEFAULT_FILENAME),
        "unexpected honeypot path: {}",
        outcome.target_path
    );
    // Temporary scenario file must have been cleaned up on completion.
    assert!(
        !Path::new(&outcome.target_path).exists(),
        "temp honeypot path should be cleaned up"
    );

    let temp = TempSimDir::new("test-honeypot").expect("temp dir");
    let in_dir =
        run_honeypot_write_scenario_in(temp.path()).expect("honeypot-write in temp dir");
    assert_eq!(in_dir.appended_bytes, 1);
    assert_eq!(in_dir.final_bytes, in_dir.initial_bytes + 1);
    assert_eq!(
        std::fs::metadata(&in_dir.target_path)
            .expect("honeypot metadata")
            .len() as usize,
        in_dir.final_bytes
    );
}

#[tokio::test]
async fn sim_p2_03_hold_ms_keeps_scenario_clean() {
    let cookie_res = run_cookies_open_scenario_with_hold(30)
        .await
        .expect("cookies-open with short hold should succeed");
    assert!(cookie_res.opened);
    assert!(!Path::new(&cookie_res.target_path).exists());

    let honeypot_res = run_honeypot_write_scenario_with_hold(30)
        .await
        .expect("honeypot-write with short hold should succeed");
    assert_eq!(honeypot_res.appended_bytes, 1);
    assert!(!Path::new(&honeypot_res.target_path).exists());
}

#[tokio::test]
async fn sim_p2_04_preprepared_dir_cookies_open_is_readonly_and_parses_cli() {
    assert_eq!(
        parse_cli_args(["--prepare-dir", r"C:\Temp\sim-prep", "--json"]).unwrap(),
        CliAction::Run(SimConfig {
            prepare_dir: Some(PathBuf::from(r"C:\Temp\sim-prep")),
            json_output: true,
            ..SimConfig::default()
        })
    );
    assert_eq!(
        parse_cli_args(["--prepare-dir=C:\\Temp\\sim-prep"]).unwrap(),
        CliAction::Run(SimConfig {
            prepare_dir: Some(PathBuf::from(r"C:\Temp\sim-prep")),
            ..SimConfig::default()
        })
    );
    assert_eq!(
        parse_cli_args(["cookies-open", "--base-dir", r"C:\Temp\sim-base"]).unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::CookiesOpen,
            base_dir: Some(PathBuf::from(r"C:\Temp\sim-base")),
            ..SimConfig::default()
        })
    );
    assert_eq!(
        parse_cli_args(["honeypot-write", "--base-dir=C:\\Temp\\sim-base"]).unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::HoneypotWrite,
            base_dir: Some(PathBuf::from(r"C:\Temp\sim-base")),
            ..SimConfig::default()
        })
    );
    assert!(parse_cli_args(["--prepare-dir"]).is_err());
    assert!(parse_cli_args(["--prepare-dir="]).is_err());
    assert!(parse_cli_args(["--base-dir"]).is_err());
    assert!(parse_cli_args(["--base-dir", "   "]).is_err());

    let temp = TempSimDir::new("preprepared").expect("temp dir");
    let prep = prepare_sim_dir(temp.path()).expect("prepare_sim_dir");
    let cookies_path = PathBuf::from(&prep.cookies_path);
    let honeypot_path = PathBuf::from(&prep.honeypot_path);
    assert!(cookies_path.is_file());
    assert!(honeypot_path.is_file());

    // Write custom sentinel bytes and mark Cookies read-only so any accidental File::create
    // would fail with PermissionDenied and overwrite contents.
    const SENTINEL_COOKIES: &[u8] = b"SQLite format 3\0PrePrepared-ReadOnly-Sentinel";
    std::fs::write(&cookies_path, SENTINEL_COOKIES).expect("write sentinel cookies");
    let mtime_before = std::fs::metadata(&cookies_path)
        .expect("cookies metadata before")
        .modified()
        .expect("cookies mtime before");
    let orig_perms = std::fs::metadata(&cookies_path)
        .expect("cookies permissions")
        .permissions();
    let mut readonly_perms = orig_perms.clone();
    readonly_perms.set_readonly(true);
    std::fs::set_permissions(&cookies_path, readonly_perms)
        .expect("set cookies readonly");

    let cookies_outcome =
        run_cookies_open_scenario_with_options(Some(temp.path().to_path_buf()), 0)
            .await
            .expect("cookies-open with preprepared dir must only issue read-only File::open");
    assert!(cookies_outcome.opened);
    assert_eq!(cookies_outcome.bytes_read, SENTINEL_COOKIES.len());
    assert!(temp.path().is_dir(), "--base-dir must not delete directory");
    assert_eq!(
        std::fs::read(&cookies_path).expect("read sentinel cookies"),
        SENTINEL_COOKIES
    );
    let mtime_after = std::fs::metadata(&cookies_path)
        .expect("cookies metadata after")
        .modified()
        .expect("cookies mtime after");
    assert_eq!(mtime_before, mtime_after);

    // Restore original permissions so TempSimDir Drop cleans up cleanly.
    std::fs::set_permissions(&cookies_path, orig_perms).expect("restore cookies permissions");

    // BUG_0003: --prepare-dir must refuse to overwrite existing fixture files
    // instead of truncating them (create_new semantics).
    const SENTINEL_PREP: &[u8] = b"SQLite format 3\0RealUserCookiesDb";
    std::fs::write(&cookies_path, SENTINEL_PREP).expect("seed real cookies");
    std::fs::write(&honeypot_path, SENTINEL_HONEYPOT).expect("seed real honeypot");
    assert!(
        prepare_sim_dir(temp.path()).is_err(),
        "prepare_sim_dir must fail when the Cookies file already exists"
    );
    assert_eq!(
        std::fs::read(&cookies_path).expect("read preserved cookies"),
        SENTINEL_PREP,
        "existing Cookies content must be preserved"
    );
    std::fs::remove_file(&cookies_path).expect("remove cookies for honeypot check");
    assert!(
        prepare_sim_dir(temp.path()).is_err(),
        "prepare_sim_dir must fail when the honeypot already exists"
    );
    assert_eq!(
        std::fs::read(&honeypot_path).expect("read preserved honeypot"),
        SENTINEL_HONEYPOT,
        "existing honeypot content must be preserved"
    );

    // Pre-prepared honeypot must also append directly without File::create overwriting it.
    const SENTINEL_HONEYPOT: &[u8] = b"CustomHoneypotHeader\n";
    std::fs::write(&honeypot_path, SENTINEL_HONEYPOT).expect("write sentinel honeypot");
    let hp_outcome =
        run_honeypot_write_scenario_with_options(Some(temp.path().to_path_buf()), 0)
            .await
            .expect("honeypot-write with preprepared dir must append in place");
    assert_eq!(hp_outcome.initial_bytes, SENTINEL_HONEYPOT.len());
    assert_eq!(hp_outcome.appended_bytes, 1);
    assert_eq!(hp_outcome.final_bytes, SENTINEL_HONEYPOT.len() + 1);
    let mut expected_hp = SENTINEL_HONEYPOT.to_vec();
    expected_hp.push(b'!');
    assert_eq!(
        std::fs::read(&honeypot_path).expect("read appended honeypot"),
        expected_hp
    );
}

#[test]
fn sim_p2_05_prepare_dir_rolls_back_created_files() {
    let temp = TempSimDir::new("prep-retry").expect("temp dir");
    let base = temp.path();

    // A leftover honeypot conflicts with exclusive creation; the dummy Cookies
    // written first by this run must be removed so a retry is not self-blocked.
    let honeypot_path = dummy_honeypot_path(base);
    std::fs::write(&honeypot_path, b"pre-existing").expect("seed leftover honeypot");
    assert!(
        prepare_sim_dir(base).is_err(),
        "conflicting honeypot must fail prepare"
    );
    assert!(
        !dummy_cookie_path(base).exists(),
        "failed prepare must remove the Cookies file it created"
    );
    std::fs::remove_file(&honeypot_path).expect("clear honeypot conflict");
    let retried = prepare_sim_dir(base).expect("retry after conflict cleanup");
    assert!(Path::new(&retried.cookies_path).is_file());
    assert!(Path::new(&retried.honeypot_path).is_file());
}
