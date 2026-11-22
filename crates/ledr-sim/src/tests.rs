use super::*;
use super::fs_scenarios::{
    TempSimDir, dummy_cookie_path, dummy_honeypot_path, run_motw_download_scenario_with_ads_writer,
};
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

#[test]
fn sim_p4_01_cli_parses_motw_download_scenario() {
    assert_eq!(
        parse_cli_args(["motw-download"]).unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::MotwDownload,
            ..SimConfig::default()
        })
    );
    assert_eq!(
        parse_cli_args([
            "--scenario=motw-download",
            "--base-dir",
            r"C:\Temp\motw-base",
            "--hold-ms",
            "150",
            "--json"
        ])
        .unwrap(),
        CliAction::Run(SimConfig {
            scenario: Scenario::MotwDownload,
            base_dir: Some(PathBuf::from(r"C:\Temp\motw-base")),
            hold_ms: 150,
            json_output: true,
            ..SimConfig::default()
        })
    );
}

#[tokio::test]
async fn sim_p4_02_motw_download_writes_verifies_ads_and_sha256() {
    let outcome = run_motw_download_scenario()
        .await
        .expect("motw-download temp scenario should succeed");
    assert!(outcome.verified_roundtrip);
    assert_eq!(outcome.zone_id, 3);
    assert_eq!(outcome.host_url, SIM_MOTW_HOST_URL);
    assert_eq!(outcome.referrer_url, SIM_MOTW_REFERRER_URL);
    assert_eq!(outcome.sha256.len(), 64);
    assert!(
        outcome.target_path.ends_with(SIM_MOTW_FILENAME),
        "unexpected target path: {}",
        outcome.target_path
    );
    assert!(
        !Path::new(&outcome.target_path).exists(),
        "temp MOTW simulation file must be cleaned up"
    );

    let temp = TempSimDir::new("test-motw").expect("temp dir");
    let in_dir = run_motw_download_scenario_with_options(Some(temp.path().to_path_buf()), 10)
        .await
        .expect("motw-download with --base-dir");
    assert!(in_dir.verified_roundtrip);
    let target = PathBuf::from(&in_dir.target_path);
    assert!(target.is_file(), "--base-dir file must remain on disk");
    let zone = ledr_sensor_win::read_zone_identifier(&target).expect("read written ADS");
    assert_eq!(zone.zone_id, 3);
    assert_eq!(zone.host_url.as_deref(), Some(SIM_MOTW_HOST_URL));
    assert_eq!(zone.referrer_url.as_deref(), Some(SIM_MOTW_REFERRER_URL));
}

#[tokio::test]
async fn sim_p4_03_run_all_report_includes_motw_download_json() {
    let temp = TempSimDir::new("run-all-motw").expect("temp dir");
    let cookies_open =
        run_cookies_open_scenario_with_options(Some(temp.path().to_path_buf()), 0)
            .await
            .expect("cookies-open");
    let honeypot_write =
        run_honeypot_write_scenario_with_options(Some(temp.path().to_path_buf()), 0)
            .await
            .expect("honeypot-write");
    let motw_download =
        run_motw_download_scenario_with_options(Some(temp.path().to_path_buf()), 0)
            .await
            .expect("motw-download");

    let report = SimReport {
        target_pipe: ledr_proto::IPC_PIPE_NAME.to_string(),
        scenario: Scenario::All,
        lotl: None,
        dns_tcp: None,
        cookies_open: Some(cookies_open),
        honeypot_write: Some(honeypot_write),
        motw_download: Some(motw_download.clone()),
    };

    let json = serde_json::to_string_pretty(&report).expect("serialize SimReport JSON");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse SimReport JSON");
    assert_eq!(
        parsed.pointer("/scenario").and_then(|v| v.as_str()),
        Some("all")
    );
    assert_eq!(
        parsed
            .pointer("/motw_download/verified_roundtrip")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        parsed
            .pointer("/motw_download/zone_id")
            .and_then(|v| v.as_u64()),
        Some(3)
    );
    assert_eq!(
        parsed
            .pointer("/motw_download/sha256")
            .and_then(|v| v.as_str()),
        Some(motw_download.sha256.as_str())
    );
    assert!(print_report(&report, true).is_ok());
    assert!(print_report(&report, false).is_ok());
}

#[test]
fn sim_p4_04_motw_download_refuses_overwrite_and_cleans_up_new_file_on_failure() {
    let existing_dir = TempSimDir::new("motw-existing").expect("temp existing dir");
    let existing_file = existing_dir.path().join(SIM_MOTW_FILENAME);
    let sentinel = b"EXISTING-DO-NOT-CLOBBER-SENTINEL";
    std::fs::write(&existing_file, sentinel).expect("write existing file");

    let err = run_motw_download_scenario_in(existing_dir.path())
        .expect_err("must refuse overwriting existing sample-tool.exe");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("exclusively create") || msg.contains("exists"),
        "unexpected error message: {msg}"
    );
    assert_eq!(
        std::fs::read(&existing_file).expect("existing sentinel intact"),
        sentinel
    );

    let fail_dir = TempSimDir::new("motw-fail-cleanup").expect("temp fail cleanup dir");
    let created_path = fail_dir.path().join(SIM_MOTW_FILENAME);
    let hook_err = run_motw_download_scenario_with_ads_writer(fail_dir.path(), |_, _| {
        anyhow::bail!("simulated ADS write failure")
    })
    .expect_err("simulated ADS failure must error");
    assert!(format!("{hook_err:#}").contains("simulated ADS write failure"));
    assert!(
        !created_path.exists(),
        "newly created dummy file must be removed when ADS write fails"
    );
}

#[tokio::test]
async fn sim_p4_05_dns_tcp_hold_ms_and_pre_sleep_socket_close() {
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;

    // 0. CLI parses `--hold-ms` cleanly for `dns-tcp`.
    assert_eq!(
        parse_cli_args([
            "--scenario",
            "dns-tcp",
            "--domain",
            "example.com",
            "--port",
            "443",
            "--hold-ms",
            "120000",
            "--json",
        ])
        .expect("parse dns-tcp with --hold-ms"),
        CliAction::Run(SimConfig {
            scenario: Scenario::DnsTcp,
            domain: "example.com".to_string(),
            port: 443,
            loopback: false,
            json_output: true,
            hold_ms: 120_000,
            prepare_dir: None,
            base_dir: None,
        })
    );

    // 1. hold_ms = 0 returns promptly in loopback mode.
    let fast_start = Instant::now();
    let fast_out = run_dns_tcp_scenario_with_hold("example.com", 443, true, 0)
        .await
        .expect("loopback dns-tcp with hold_ms=0");
    assert!(fast_out.used_loopback);
    assert!(fast_out.connected);
    assert!(
        fast_start.elapsed() < Duration::from_millis(2_000),
        "hold_ms=0 should return promptly, took {:?}",
        fast_start.elapsed()
    );

    // 2. hold_ms = 120 waits >= 100 ms and succeeds in loopback mode.
    let hold_start = Instant::now();
    let hold_out = run_dns_tcp_scenario_with_hold("example.com", 443, true, 120)
        .await
        .expect("loopback dns-tcp with hold_ms=120");
    let hold_elapsed = hold_start.elapsed();
    assert!(hold_out.used_loopback);
    assert!(hold_out.connected);
    assert!(
        hold_elapsed >= Duration::from_millis(100),
        "expected hold_ms=120 to sleep at least 100ms, elapsed={hold_elapsed:?}"
    );

    // 3. External TCP connect path against a local TcpListener: peer must observe EOF
    // BEFORE hold_ms elapses, proving stream.shutdown() + drop(stream) ran prior to sleeping.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local test listener");
    let bound_port = listener.local_addr().expect("listener local_addr").port();
    let (eof_tx, eof_rx) = tokio::sync::oneshot::channel::<Instant>();
    let server = tokio::spawn(async move {
        let (mut sock, _peer) = listener.accept().await.expect("accept client");
        let mut buf = [0u8; 16];
        let n = sock.read(&mut buf).await.expect("read until EOF");
        assert_eq!(n, 0, "expected clean EOF from closed client socket");
        let _ = eof_tx.send(Instant::now());
    });

    let hold_ms = 300;
    let connect_start = Instant::now();
    let direct_out = run_dns_tcp_scenario_with_hold("127.0.0.1", bound_port, false, hold_ms)
        .await
        .expect("direct TCP connect with hold_ms");
    let total_elapsed = connect_start.elapsed();
    let eof_at = eof_rx.await.expect("receive peer EOF timestamp");
    server.await.expect("server task join");

    let eof_elapsed = eof_at.saturating_duration_since(connect_start);
    assert!(!direct_out.used_loopback);
    assert!(direct_out.connected);
    assert_eq!(
        direct_out.connected_addr.as_deref(),
        Some(format!("127.0.0.1:{bound_port}").as_str())
    );
    assert!(
        total_elapsed >= Duration::from_millis(250),
        "expected total duration to honor hold_ms={hold_ms}, got {total_elapsed:?}"
    );
    assert!(
        eof_elapsed + Duration::from_millis(100) < total_elapsed,
        "peer must observe EOF well before hold_ms finishes (eof={eof_elapsed:?}, total={total_elapsed:?})"
    );
}

struct HoldCancelProbe {
    entered_tx: Option<tokio::sync::oneshot::Sender<()>>,
    trigger_rx: tokio::sync::oneshot::Receiver<()>,
}

impl HoldCancelProbe {
    fn new() -> (
        Self,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (trigger_tx, trigger_rx) = tokio::sync::oneshot::channel();
        (
            Self {
                entered_tx: Some(entered_tx),
                trigger_rx,
            },
            entered_rx,
            trigger_tx,
        )
    }
}

impl std::future::Future for HoldCancelProbe {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if let Some(tx) = self.entered_tx.take() {
            let _ = tx.send(());
        }
        match std::pin::Pin::new(&mut self.trigger_rx).poll(cx) {
            std::task::Poll::Ready(_) => std::task::Poll::Ready(()),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

fn find_temp_sim_dirs(prefix: &str) -> Vec<PathBuf> {
    let expected = format!("ledr-sim-{prefix}-{}-", std::process::id());
    std::fs::read_dir(std::env::temp_dir())
        .expect("read temp dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| name.starts_with(&expected))
        })
        .collect()
}

#[tokio::test]
async fn sim_p4_06_fs_scenarios_cancel_hold_promptly_and_drop_guards() {
    use std::time::{Duration, Instant};

    const LONG_HOLD_MS: u64 = 60_000;
    const CANCEL_BUDGET: Duration = Duration::from_secs(5);

    // 1. cookies-open: TempSimDir stays alive during hold and is cleaned up promptly on cancel.
    {
        let (probe, entered_rx, trigger_tx) = HoldCancelProbe::new();
        let start = Instant::now();
        let task = tokio::spawn(run_cookies_open_scenario_with_cancel(
            None,
            LONG_HOLD_MS,
            probe,
        ));

        tokio::time::timeout(CANCEL_BUDGET, entered_rx)
            .await
            .expect("cookies-open should enter async hold")
            .expect("entered_tx dropped unexpectedly");
        let dirs_during_hold = find_temp_sim_dirs("cookies");

        let _ = trigger_tx.send(());
        let (outcome, hold) = tokio::time::timeout(CANCEL_BUDGET, task)
            .await
            .expect("cookies-open should exit promptly after cancel")
            .expect("cookies-open task join")
            .expect("cookies-open result");
        assert_eq!(hold, HoldOutcome::Interrupted);
        assert!(start.elapsed() < CANCEL_BUDGET);
        let target_path = Path::new(&outcome.target_path);
        let held_dir = dirs_during_hold
            .iter()
            .find(|dir| target_path.starts_with(dir))
            .expect("TempSimDir must stay alive while cookies-open is in async hold");
        assert!(
            !target_path.exists() && !held_dir.exists(),
            "temp cookie dir must be cleaned up after interrupted hold"
        );
    }

    // 2. honeypot-write: ChildGuard + TempSimDir stay alive during hold and clean up on cancel.
    {
        let (probe, entered_rx, trigger_tx) = HoldCancelProbe::new();
        let start = Instant::now();
        let task = tokio::spawn(run_honeypot_write_scenario_with_cancel(
            None,
            LONG_HOLD_MS,
            probe,
        ));

        tokio::time::timeout(CANCEL_BUDGET, entered_rx)
            .await
            .expect("honeypot-write should enter async hold")
            .expect("entered_tx dropped unexpectedly");
        let dirs_during_hold = find_temp_sim_dirs("honeypot");

        let _ = trigger_tx.send(());
        let (outcome, hold) = tokio::time::timeout(CANCEL_BUDGET, task)
            .await
            .expect("honeypot-write should exit promptly after cancel")
            .expect("honeypot-write task join")
            .expect("honeypot-write result");
        assert_eq!(hold, HoldOutcome::Interrupted);
        assert!(start.elapsed() < CANCEL_BUDGET);
        let target_path = Path::new(&outcome.target_path);
        let held_dir = dirs_during_hold
            .iter()
            .find(|dir| target_path.starts_with(dir))
            .expect("TempSimDir must stay alive while honeypot-write is in async hold");
        assert!(
            !target_path.exists() && !held_dir.exists(),
            "temp honeypot dir must be cleaned up after interrupted hold"
        );
    }

    // 3. motw-download: TempSimDir stays alive during hold and is cleaned up promptly on cancel.
    {
        let (probe, entered_rx, trigger_tx) = HoldCancelProbe::new();
        let start = Instant::now();
        let task = tokio::spawn(run_motw_download_scenario_with_cancel(
            None,
            LONG_HOLD_MS,
            probe,
        ));

        tokio::time::timeout(CANCEL_BUDGET, entered_rx)
            .await
            .expect("motw-download should enter async hold")
            .expect("entered_tx dropped unexpectedly");
        let dirs_during_hold = find_temp_sim_dirs("motw");

        let _ = trigger_tx.send(());
        let (outcome, hold) = tokio::time::timeout(CANCEL_BUDGET, task)
            .await
            .expect("motw-download should exit promptly after cancel")
            .expect("motw-download task join")
            .expect("motw-download result");
        assert_eq!(hold, HoldOutcome::Interrupted);
        assert!(start.elapsed() < CANCEL_BUDGET);
        let target_path = Path::new(&outcome.target_path);
        let held_dir = dirs_during_hold
            .iter()
            .find(|dir| target_path.starts_with(dir))
            .expect("TempSimDir must stay alive while motw-download is in async hold");
        assert!(
            !target_path.exists() && !held_dir.exists(),
            "temp motw dir must be cleaned up after interrupted hold"
        );
    }

    // 4. Aborting an async hold and dropping a Tokio Runtime must not hang on spawn_blocking.
    let drop_elapsed = tokio::task::spawn_blocking(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build isolated runtime");
        let (probe, entered_rx, _trigger_tx) = HoldCancelProbe::new();
        let handle = rt.spawn(run_honeypot_write_scenario_with_cancel(
            None,
            LONG_HOLD_MS,
            probe,
        ));
        rt.block_on(async {
            tokio::time::timeout(CANCEL_BUDGET, entered_rx)
                .await
                .expect("isolated honeypot-write should enter async hold")
                .expect("entered_tx dropped");
            handle.abort();
            let _ = handle.await;
        });
        let drop_start = Instant::now();
        drop(rt);
        drop_start.elapsed()
    })
    .await
    .expect("runtime drop check join");
    assert!(
        drop_elapsed < CANCEL_BUDGET,
        "Runtime::drop hung instead of returning promptly: {drop_elapsed:?}"
    );
}

#[tokio::test]
async fn sim_p4_07_scenario_all_stops_early_on_hold_interrupt() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    // Case A: Interrupt during `dns-tcp` stops `Scenario::All` before FS scenarios run.
    {
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let calls_ref = Arc::clone(&cancel_calls);
        let config = SimConfig {
            scenario: Scenario::All,
            loopback: true,
            hold_ms: 60_000,
            ..SimConfig::default()
        };
        let start = Instant::now();
        let report = execute_sim_report(&config, move || {
            calls_ref.fetch_add(1, Ordering::SeqCst);
            async {}
        })
        .await
        .expect("Scenario::All with dns-tcp interrupt");

        assert!(
            start.elapsed() < Duration::from_secs(25),
            "interrupted Scenario::All must not wait for 60s hold"
        );
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        assert!(report.lotl.is_some());
        assert!(report.dns_tcp.is_some());
        assert!(report.cookies_open.is_none());
        assert!(report.honeypot_write.is_none());
        assert!(report.motw_download.is_none());
    }

    // Case B: `dns-tcp` hold completes, then `cookies-open` hold is interrupted;
    // `honeypot-write` and `motw-download` must not launch.
    {
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let calls_ref = Arc::clone(&cancel_calls);
        let config = SimConfig {
            scenario: Scenario::All,
            loopback: true,
            hold_ms: 30,
            ..SimConfig::default()
        };
        let report = execute_sim_report(&config, move || {
            let idx = calls_ref.fetch_add(1, Ordering::SeqCst);
            async move {
                if idx == 0 {
                    std::future::pending::<()>().await;
                }
            }
        })
        .await
        .expect("Scenario::All with cookies-open interrupt");

        assert_eq!(cancel_calls.load(Ordering::SeqCst), 2);
        assert!(report.lotl.is_some());
        assert!(report.dns_tcp.is_some());
        assert!(report.cookies_open.is_some());
        assert!(report.honeypot_write.is_none());
        assert!(report.motw_download.is_none());
    }
}
