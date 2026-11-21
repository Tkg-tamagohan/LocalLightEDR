//! Integration tests for Phase 4A `ledr-store` download origin persistence, indexes,
//! and process MOTW metadata (`STORE-P4-01`..`STORE-P4-06`).

use ledr_proto::{DownloadOriginRecord, ProcessIdentity, ProcessRecord, SensorEvent};
use ledr_store::LedrStore;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;

fn unix_ms_to_filetime(unix_ms: i64) -> u64 {
    u64::try_from(unix_ms).expect("positive unix_ms") * TICKS_PER_MS + WINDOWS_TO_UNIX_EPOCH_100NS
}

#[test]
fn store_p4_01_record_download_origin_normalizes_path_and_sha256_and_tracks_existence() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    assert!(!store.has_any_download_origins().expect("initial empty"));

    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: r"  \\?\C:/Users/Alice/Downloads/Tool.exe  ".to_string(),
            sha256: Some("  AABBCCDD00112233  ".to_string()),
            tab_url: "https://cdn.example.invalid/tool.exe".to_string(),
            frame_url: Some("https://frame.example.invalid/".to_string()),
            referrer_url: Some("https://portal.example.invalid/".to_string()),
            downloaded_at_ms: 1_760_000_001_000,
        })
        .expect("record download origin");

    assert!(store.has_any_download_origins().expect("non-empty after insert"));

    let snap = store
        .query_flight_recorder(10, None)
        .expect("query flight recorder");
    assert_eq!(snap.download_origins.len(), 1);
    assert_eq!(
        snap.download_origins[0].file_path,
        r"C:\Users\Alice\Downloads\Tool.exe"
    );
    assert_eq!(
        snap.download_origins[0].sha256.as_deref(),
        Some("aabbccdd00112233")
    );

    // Also verify `\\?\UNC\` normalization.
    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: r"\\?\UNC\fileserver/share/drop.exe".to_string(),
            sha256: Some("   ".to_string()),
            tab_url: "https://cdn.example.invalid/drop.exe".to_string(),
            frame_url: None,
            referrer_url: None,
            downloaded_at_ms: 1_760_000_002_000,
        })
        .expect("record UNC download origin");

    let unc_hit = store
        .find_download_origin_by_path(r"\\FILESERVER\Share\DROP.EXE")
        .expect("find normalized UNC")
        .expect("UNC hit present");
    assert_eq!(unc_hit.file_path, r"\\fileserver\share\drop.exe");
    assert_eq!(unc_hit.sha256, None);
}

#[test]
fn store_p4_02_find_download_origin_by_path_case_insensitive_newest_and_uses_index() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    let path = r"C:\Users\Alice\Downloads\Setup.exe";
    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: path.to_string(),
            sha256: Some("1111".to_string()),
            tab_url: "https://old.example.invalid/setup.exe".to_string(),
            frame_url: None,
            referrer_url: None,
            downloaded_at_ms: 1_760_000_000_100,
        })
        .expect("insert older");
    // Same downloaded_at_ms tie should pick higher auto-increment id.
    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: path.to_string(),
            sha256: Some("2222".to_string()),
            tab_url: "https://newer-tie-1.example.invalid/setup.exe".to_string(),
            frame_url: None,
            referrer_url: None,
            downloaded_at_ms: 1_760_000_000_500,
        })
        .expect("insert tie 1");
    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: path.to_string(),
            sha256: Some("3333".to_string()),
            tab_url: "https://newest-tie-2.example.invalid/setup.exe".to_string(),
            frame_url: None,
            referrer_url: None,
            downloaded_at_ms: 1_760_000_000_500,
        })
        .expect("insert tie 2");

    let found = store
        .find_download_origin_by_path(r"//?/c:/users/ALICE/downloads/SETUP.EXE")
        .expect("find by path")
        .expect("match found");
    assert_eq!(found.tab_url, "https://newest-tie-2.example.invalid/setup.exe");
    assert_eq!(found.sha256.as_deref(), Some("3333"));
    assert_eq!(store.find_download_origin_by_path("   ").expect("blank"), None);

    let plan = store
        .explain_download_path_lookup_plan()
        .expect("explain path lookup plan");
    let joined = plan.join(" | ");
    assert!(
        joined.contains("idx_dl_path_nocase"),
        "expected idx_dl_path_nocase in query plan, got: {joined}"
    );
    assert!(
        !joined.contains("USE TEMP B-TREE"),
        "expected index-ordered lookup without temp B-tree sort, got: {joined}"
    );
}

#[test]
fn store_p4_03_find_download_origin_by_sha256_case_insensitive_newest_and_uses_index() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let digest = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";

    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: r"C:\Users\Alice\Downloads\first.exe".to_string(),
            sha256: Some(digest.to_string()),
            tab_url: "https://first.example.invalid/first.exe".to_string(),
            frame_url: None,
            referrer_url: None,
            downloaded_at_ms: 1_760_000_001_000,
        })
        .expect("insert older hash");
    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: r"C:\Users\Alice\Downloads\second.exe".to_string(),
            sha256: Some(digest.to_ascii_lowercase()),
            tab_url: "https://second.example.invalid/second.exe".to_string(),
            frame_url: None,
            referrer_url: Some("https://portal.example.invalid/".to_string()),
            downloaded_at_ms: 1_760_000_002_000,
        })
        .expect("insert newer hash");

    let found = store
        .find_download_origin_by_sha256(&format!("  {digest}  "))
        .expect("find by sha256")
        .expect("hash match");
    assert_eq!(found.tab_url, "https://second.example.invalid/second.exe");
    assert_eq!(found.sha256.as_deref(), Some(digest.to_ascii_lowercase().as_str()));
    assert_eq!(
        store.find_download_origin_by_sha256("   ").expect("empty hash"),
        None
    );

    let plan = store
        .explain_download_sha256_lookup_plan()
        .expect("explain sha256 lookup plan");
    let joined = plan.join(" | ");
    assert!(
        joined.contains("idx_dl_sha256_nocase"),
        "expected idx_dl_sha256_nocase in query plan, got: {joined}"
    );
    assert!(
        !joined.contains("USE TEMP B-TREE"),
        "expected index-ordered SHA-256 lookup without temp B-tree sort, got: {joined}"
    );
}

#[test]
fn store_p4_04_ingest_event_with_process_metadata_persists_origin_and_sha256() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let t0 = 1_760_000_010_000i64;
    let ident = ProcessIdentity::new(4100, unix_ms_to_filetime(t0));

    let ev = SensorEvent::ProcessStart {
        identity: ident,
        parent_pid: 4,
        exe_path: r"C:\Users\Alice\Desktop\moved-tool.exe".to_string(),
        command_line: "moved-tool.exe".to_string(),
        user_sid: Some("S-1-5-21-100".to_string()),
    };
    store
        .ingest_event_with_process_metadata(
            &ev,
            None,
            None,
            None,
            Some("  https://origin.example.invalid/moved-tool.exe  "),
            Some("  DEADBEEF0123  "),
            false,
            "OBSERVED",
        )
        .expect("buffer ProcessStart with metadata");
    store.flush_batch().expect("flush batch");

    let snap = store
        .query_flight_recorder(10, Some(&ident.instance_id()))
        .expect("query process");
    assert_eq!(snap.processes.len(), 1);
    let proc_row = &snap.processes[0];
    assert_eq!(
        proc_row.origin_url.as_deref(),
        Some("https://origin.example.invalid/moved-tool.exe")
    );
    assert_eq!(proc_row.sha256.as_deref(), Some("deadbeef0123"));
}

#[test]
fn store_p4_05_upsert_process_row_preserves_origin_url_sha256_and_exit_via_coalesce() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let t0 = 1_760_000_020_000i64;
    let ident = ProcessIdentity::new(4200, unix_ms_to_filetime(t0));
    let inst_id = ident.instance_id();

    let ev = SensorEvent::ProcessStart {
        identity: ident,
        parent_pid: 4,
        exe_path: r"C:\Users\Alice\Downloads\payload.exe".to_string(),
        command_line: "payload.exe".to_string(),
        user_sid: None,
    };
    store
        .ingest_event_with_process_metadata(
            &ev,
            None,
            Some(t0 + 500),
            None,
            Some("https://origin.example.invalid/payload.exe"),
            Some("cafebabe1234"),
            false,
            "OBSERVED",
        )
        .expect("ingest initial ProcessStart with origin and exit");
    store.flush_batch().expect("flush initial batch");

    // Subsequent partial ProcessStart update (origin_url=None, sha256=None, exited_at_ms=None)
    // must preserve existing origin_url, sha256, and exited_at_ms via COALESCE.
    store
        .ingest_event(&ev, None, false, "OBSERVED")
        .expect("ingest subsequent partial ProcessStart");
    store.flush_batch().expect("flush second batch");

    // Explicit upsert_process_record with None fields must also preserve existing metadata/exit.
    store
        .upsert_process_record(&ProcessRecord {
            process_instance_id: inst_id.clone(),
            pid: ident.pid,
            parent_instance_id: None,
            ppid: 4,
            exe_path: r"C:\Users\Alice\Downloads\payload.exe".to_string(),
            command_line: Some("payload.exe --enriched".to_string()),
            sha256: None,
            signer_subject: Some("CN=Test Signer".to_string()),
            is_trusted_os: false,
            user_sid: None,
            origin_url: None,
            created_at_ms: t0,
            exited_at_ms: None,
        })
        .expect("upsert partial enrichment");

    let snap = store
        .query_flight_recorder(10, Some(&inst_id))
        .expect("query process");
    assert_eq!(snap.processes.len(), 1);
    let row = &snap.processes[0];
    assert_eq!(
        row.origin_url.as_deref(),
        Some("https://origin.example.invalid/payload.exe")
    );
    assert_eq!(row.sha256.as_deref(), Some("cafebabe1234"));
    assert_eq!(row.exited_at_ms, Some(t0 + 500));
    assert_eq!(row.signer_subject.as_deref(), Some("CN=Test Signer"));
}

#[test]
fn store_p4_06_query_flight_recorder_joins_process_downloads_case_insensitively() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let t0 = 1_760_000_030_000i64;
    let ident_by_path = ProcessIdentity::new(4300, unix_ms_to_filetime(t0));
    let ident_by_sha = ProcessIdentity::new(4301, unix_ms_to_filetime(t0 + 10));

    // Download saved with lowercase/forward-slash variation.
    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: r"C:\Users\Alice\Downloads\PathMatch.exe".to_string(),
            sha256: Some("00001111".to_string()),
            tab_url: "https://dl.example.invalid/pathmatch.exe".to_string(),
            frame_url: None,
            referrer_url: Some("https://search.example.invalid/".to_string()),
            downloaded_at_ms: t0 - 1000,
        })
        .expect("record path download");

    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: r"C:\Users\Alice\Downloads\OriginalName.exe".to_string(),
            sha256: Some("9999AAAA".to_string()),
            tab_url: "https://dl.example.invalid/moved.exe".to_string(),
            frame_url: None,
            referrer_url: None,
            downloaded_at_ms: t0 - 500,
        })
        .expect("record sha download");

    // Process 1 started from differently-cased/extended path without origin_url/sha256 set.
    store
        .ingest_event(
            &SensorEvent::ProcessStart {
                identity: ident_by_path,
                parent_pid: 4,
                exe_path: r"\\?\c:/users/alice/downloads/pathmatch.exe".to_string(),
                command_line: "pathmatch.exe".to_string(),
                user_sid: None,
            },
            None,
            false,
            "OBSERVED",
        )
        .expect("ingest path-matched proc");

    // Process 2 moved to Desktop and matched via sha256 (uppercase) without origin_url.
    store
        .ingest_event_with_process_metadata(
            &SensorEvent::ProcessStart {
                identity: ident_by_sha,
                parent_pid: 4,
                exe_path: r"C:\Users\Alice\Desktop\Renamed.exe".to_string(),
                command_line: "Renamed.exe".to_string(),
                user_sid: None,
            },
            None,
            None,
            None,
            None,
            Some("9999aaaa"),
            false,
            "OBSERVED",
        )
        .expect("ingest sha-matched proc");
    store.flush_batch().expect("flush procs");

    let snap_path = store
        .query_flight_recorder(10, Some(&ident_by_path.instance_id()))
        .expect("query proc 1");
    assert_eq!(snap_path.download_origins.len(), 1);
    assert_eq!(
        snap_path.download_origins[0].tab_url,
        "https://dl.example.invalid/pathmatch.exe"
    );

    let snap_sha = store
        .query_flight_recorder(10, Some(&ident_by_sha.instance_id()))
        .expect("query proc 2");
    assert_eq!(snap_sha.download_origins.len(), 1);
    assert_eq!(
        snap_sha.download_origins[0].tab_url,
        "https://dl.example.invalid/moved.exe"
    );
}
