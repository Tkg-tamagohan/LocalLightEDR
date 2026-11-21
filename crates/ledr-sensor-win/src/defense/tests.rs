use super::*;
use super::guard::{
    TargetValidationError, validate_and_inspect_target_detailed, validate_process_metadata,
};
use super::process_probe::{
    open_process_checked, query_process_creation_time, snapshot_process_entries,
};
use super::tree::is_valid_descendant_timestamp;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use ledr_proto::{ActiveDefenseController, HONEYPOT_DEFAULT_FILENAME, ProcessIdentity};
use windows::Win32::System::Threading::{
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
};
use crate::OwnedHandle;
use crate::wfp::WfpDynamicEngine;

static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempTestDir(PathBuf);

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ledr-sensor-test-{prefix}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn sens_p2_09_never_suspend_guard_rejects_system_self_and_explorer() {
    let controller = WindowsDefenseController::new();

    // PID 0, PID 4, and self PID must be rejected by both validator and controller.
    for forbidden_pid in [0u32, 4u32, std::process::id()] {
        let ident = ProcessIdentity::new(forbidden_pid, 0);
        assert!(
            validate_target_process(&ident).is_err(),
            "expected validate_target_process to reject PID {forbidden_pid}"
        );
        assert!(
            controller.suspend_process(&ident, false).is_err(),
            "expected suspend_process to reject PID {forbidden_pid}"
        );
        assert!(
            controller.terminate_process(&ident, false).is_err(),
            "expected terminate_process to reject PID {forbidden_pid}"
        );
    }

    // Verify metadata guard rejects all NEVER_SUSPEND_PROCESS_NAMES entries.
    for protected in ledr_proto::NEVER_SUSPEND_PROCESS_NAMES {
        let path = format!(r"C:\Windows\System32\{protected}");
        assert!(
            validate_process_metadata(9999, std::process::id(), Some(&path), 100, Some(100))
                .is_err(),
            "expected Never-Suspend rejection for `{path}`"
        );
    }

    // If `explorer.exe` is running in this session, verify live validation rejects it too.
    if let Ok(entries) = snapshot_process_entries() {
        if let Some(explorer) = entries
            .into_iter()
            .find(|e| e.exe_name.eq_ignore_ascii_case("explorer.exe"))
        {
            let ident = ProcessIdentity::new(explorer.pid, 0);
            let err = validate_target_process(&ident)
                .expect_err("live explorer.exe MUST be rejected by Never-Suspend guard");
            assert!(
                err.contains("protected process"),
                "unexpected explorer.exe error message: {err}"
            );
            assert!(controller.suspend_process(&ident, true).is_err());
        }
    }
}

#[test]
fn sens_p2_10_creation_time_mismatch_and_tree_containment() {
    let controller = WindowsDefenseController::new();

    // Spawn a harmless two-level process tree (`cmd.exe` -> `findstr.exe`) blocked on stdin.
    let mut child = Command::new("cmd.exe")
        .args(["/c", "echo ready & findstr .*"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn harmless cmd.exe child for defense tests");
    let _stdin_keepalive = child.stdin.take();

    let child_pid = child.id();
    let handle = open_process_checked(child_pid, PROCESS_QUERY_LIMITED_INFORMATION)
        .expect("open spawned test child");
    let real_create_time = query_process_creation_time(handle.as_raw())
        .expect("query spawned child CreationTime");
    drop(handle);

    // Give cmd.exe a moment to spawn its grandchild `findstr.exe` when testing tree containment.
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert!(
        child.try_wait().expect("poll child status").is_none(),
        "test child must still be running before suspend/terminate checks"
    );

    // 1. CreationTime mismatch MUST be rejected (PID reuse guard, AUTO-03).
    let stale_ident = ProcessIdentity::new(child_pid, real_create_time.saturating_add(1));
    let mismatch_err = validate_target_process(&stale_ident)
        .expect_err("CreationTime mismatch must reject target");
    assert!(
        mismatch_err.contains("CreationTime mismatch"),
        "unexpected mismatch error: {mismatch_err}"
    );
    assert!(controller.suspend_process(&stale_ident, false).is_err());
    assert!(controller.terminate_process(&stale_ident, false).is_err());

    // 2. Exact CreationTime passes validation and supports suspend -> resume -> terminate.
    let valid_ident = ProcessIdentity::new(child_pid, real_create_time);
    assert_eq!(validate_target_process(&valid_ident), Ok(()));
    assert!(!is_valid_descendant_timestamp(real_create_time, real_create_time.saturating_sub(1)));
    assert!(is_valid_descendant_timestamp(real_create_time, real_create_time));

    let had_live_grandchild = snapshot_process_entries()
        .unwrap_or_default()
        .iter()
        .any(|e| e.ppid == child_pid);

    controller
        .suspend_process(&valid_ident, true)
        .expect("suspend harmless child tree");
    if had_live_grandchild {
        assert!(
            !controller.tracked_suspended_children(&valid_ident).is_empty(),
            "expected descendant process to be tracked while tree is suspended"
        );
    }
    controller
        .resume_process(&valid_ident)
        .expect("resume harmless child tree");
    assert!(
        controller.tracked_suspended_children(&valid_ident).is_empty(),
        "expected tracked suspended children to clear after resume"
    );
    controller
        .terminate_process(&valid_ident, true)
        .expect("terminate harmless child tree");

    let status = child.wait().expect("wait terminated child");
    assert!(!status.success());
}

#[test]
fn sens_p2_11_honeypot_manager_deploy_and_remove_lifecycle() {
    let temp = TempTestDir::new("honeypot");
    let docs = temp.path().join("Documents");
    let desktop = temp.path().join("Desktop");
    let pics = temp.path().join("Pictures");

    let mut manager =
        HoneypotManager::with_roots(vec![docs.clone(), desktop.clone(), pics.clone()]);
    let deployed = manager.deploy_honeypots().expect("deploy honeypots");
    assert_eq!(deployed.len(), 3);
    assert_eq!(manager.deployed_paths().len(), 3);

    for path in &deployed {
        assert!(path.is_file(), "expected honeypot file at {}", path.display());
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some(HONEYPOT_DEFAULT_FILENAME)
        );
        let bytes = std::fs::read(path).expect("read deployed honeypot");
        assert!(!bytes.is_empty());
    }

    // Re-deploying should not duplicate tracked entries.
    let redeployed = manager.deploy_honeypots().expect("idempotent redeploy");
    assert_eq!(redeployed.len(), 3);
    assert_eq!(manager.deployed_paths().len(), 3);

    // Removing deletes all tracked decoy files and resets tracked state.
    let removed = manager.remove_honeypots().expect("remove honeypots");
    assert_eq!(removed, 3);
    assert!(manager.deployed_paths().is_empty());
    for path in &deployed {
        assert!(
            !path.exists(),
            "expected honeypot {} to be removed",
            path.display()
        );
    }

    // Second removal is a clean no-op returning 0.
    assert_eq!(manager.remove_honeypots().expect("idempotent remove"), 0);

    // Default constructor uses %USERPROFILE%\Documents, Desktop, Pictures when present.
    let default_mgr = HoneypotManager::new();
    if std::env::var_os("USERPROFILE").is_some() {
        assert_eq!(default_mgr.roots().len(), 3);
    }
}

#[test]
fn sens_p2_12_idempotent_double_suspend_single_resume() {
    let controller = WindowsDefenseController::new();
    let mut child = Command::new("cmd.exe")
        .args(["/c", "findstr .*"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn harmless cmd.exe child for idempotent suspend test");
    let stdin_pipe = child.stdin.take();

    let child_pid = child.id();
    let handle = open_process_checked(child_pid, PROCESS_QUERY_LIMITED_INFORMATION)
        .expect("open child for CreationTime");
    let real_create_time =
        query_process_creation_time(handle.as_raw()).expect("query child CreationTime");
    drop(handle);

    let ident = ProcessIdentity::new(child_pid, real_create_time);
    controller
        .suspend_process(&ident, false)
        .expect("first suspend");
    controller
        .suspend_process(&ident, false)
        .expect("idempotent second suspend");

    // Drop stdin EOF while suspended: process must stay paused until a single resume_process.
    drop(stdin_pipe);
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert!(
        child.try_wait().expect("poll suspended child").is_none(),
        "child must remain suspended despite stdin EOF"
    );

    controller
        .resume_process(&ident)
        .expect("single resume must clear suspension completely");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Some(_status) = child.try_wait().expect("poll resumed child") {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child remained frozen after single resume_process (double suspend leaked suspend count)");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn spawn_cmd_findstr_tree() -> (
    std::process::Child,
    Option<std::process::ChildStdin>,
    ProcessIdentity,
    ProcessIdentity,
    OwnedHandle,
) {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;

    let mut parent = Command::new("cmd.exe")
        .args(["/c", "echo ready & findstr .*"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn harmless cmd.exe -> findstr.exe tree");
    let stdin_pipe = parent.stdin.take();

    let parent_pid = parent.id();
    let parent_handle = open_process_checked(parent_pid, PROCESS_QUERY_LIMITED_INFORMATION)
        .expect("open spawned parent for CreationTime");
    let parent_ct =
        query_process_creation_time(parent_handle.as_raw()).expect("query parent CreationTime");
    drop(parent_handle);

    let parent_ident = ProcessIdentity::new(parent_pid, parent_ct);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let grandchild_ident = loop {
        let live = collect_live_descendants(&parent_ident);
        if let Some(first) = live.into_iter().next() {
            break first;
        }
        if std::time::Instant::now() >= deadline {
            let _ = parent.kill();
            let _ = parent.wait();
            panic!("timed out waiting for grandchild findstr.exe under PID {parent_pid}");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };

    let grandchild_handle = open_process_checked(
        grandchild_ident.pid,
        PROCESS_SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
    )
    .expect("open grandchild handle for synchronization");

    (
        parent,
        stdin_pipe,
        parent_ident,
        grandchild_ident,
        grandchild_handle,
    )
}

fn wait_process_exited(handle: &OwnedHandle, timeout_ms: u32) -> bool {
    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::System::Threading::WaitForSingleObject;

    // SAFETY: `handle` is an open handle with `PROCESS_SYNCHRONIZE`.
    unsafe { WaitForSingleObject(handle.as_raw(), timeout_ms) == WAIT_OBJECT_0 }
}

#[test]
fn sens_p2_13_zero_create_time_rejected_and_orphan_descendant_resume() {
    let controller = WindowsDefenseController::new();

    // 1. Metadata guard must reject create_time_100ns == 0 on non-protected executables.
    let meta_err = validate_process_metadata(
        9999,
        std::process::id(),
        Some(r"C:\Temp\benign.exe"),
        0,
        Some(100),
    )
    .expect_err("zero expected create_time_100ns must be rejected");
    assert!(
        meta_err.contains("create_time_100ns is 0"),
        "unexpected zero create_time error: {meta_err}"
    );
    assert!(!is_valid_descendant_timestamp(0, 100));

    // 2. Live child with create_time_100ns == 0 must be rejected across all actuators and helpers.
    let (mut parent1, stdin1, valid_ident1, grandchild1, grandchild1_handle) =
        spawn_cmd_findstr_tree();
    let zero_ident = ProcessIdentity::new(valid_ident1.pid, 0);

    let val_err = validate_target_process(&zero_ident)
        .expect_err("validate_target_process must reject create_time_100ns == 0");
    assert!(
        val_err.contains("create_time_100ns is 0"),
        "unexpected validate_target_process error: {val_err}"
    );
    assert!(controller.suspend_process(&zero_ident, true).is_err());
    assert!(controller.resume_process(&zero_ident).is_err());
    assert!(controller.terminate_process(&zero_ident, true).is_err());
    assert!(collect_live_descendants(&zero_ident).is_empty());

    // 3. Fresh WindowsDefenseController (empty suspended_children) must still discover and
    //    resume suspended live descendants before resuming the parent.
    controller
        .suspend_process(&valid_ident1, true)
        .expect("suspend parent1 + grandchild1");
    assert!(!controller.tracked_suspended_children(&valid_ident1).is_empty());

    drop(stdin1);
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert!(
        parent1.try_wait().expect("poll suspended parent1").is_none()
            && !wait_process_exited(&grandchild1_handle, 0),
        "parent1 and grandchild1 must stay frozen while suspended despite stdin EOF"
    );

    let fresh_controller = WindowsDefenseController::new();
    assert!(fresh_controller.tracked_suspended_children(&valid_ident1).is_empty());
    fresh_controller
        .resume_process(&valid_ident1)
        .expect("fresh controller must resume live descendant + parent");

    assert!(
        wait_process_exited(&grandchild1_handle, 3000),
        "grandchild1 ({}) remained suspended after fresh controller resume",
        grandchild1
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while parent1.try_wait().expect("poll resumed parent1").is_none() {
        if std::time::Instant::now() >= deadline {
            let _ = parent1.kill();
            let _ = parent1.wait();
            panic!("parent1 remained frozen after fresh controller resume");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // 4. Parent exits before resume_process: tracked suspended child must STILL be resumed
    //    even though resume_process returns Err for the exited parent.
    let (mut parent2, stdin2, valid_ident2, grandchild2, grandchild2_handle) =
        spawn_cmd_findstr_tree();
    controller
        .suspend_process(&valid_ident2, true)
        .expect("suspend parent2 + grandchild2");
    assert!(!controller.tracked_suspended_children(&valid_ident2).is_empty());

    let _ = parent2.kill();
    let _ = parent2.wait();
    drop(parent2);

    let dead_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while open_process_checked(valid_ident2.pid, PROCESS_QUERY_LIMITED_INFORMATION).is_ok()
        && std::time::Instant::now() < dead_deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    drop(stdin2);
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert!(
        !wait_process_exited(&grandchild2_handle, 0),
        "orphan grandchild2 must stay suspended despite stdin EOF before resume_process"
    );

    let orphan_resume = controller.resume_process(&valid_ident2);
    assert!(
        orphan_resume.is_err(),
        "resume_process on exited parent2 should report parent unavailability"
    );
    assert!(controller.tracked_suspended_children(&valid_ident2).is_empty());
    assert!(
        wait_process_exited(&grandchild2_handle, 3000),
        "orphan grandchild2 ({}) must be resumed and exit after parent2 exited",
        grandchild2
    );

    // 5. Parent exits before terminate_process(include_children=true): tracked suspended child
    //    must STILL be terminated even though terminate_process returns Err for the exited parent.
    let (mut parent3, stdin3, valid_ident3, grandchild3, grandchild3_handle) =
        spawn_cmd_findstr_tree();
    controller
        .suspend_process(&valid_ident3, true)
        .expect("suspend parent3 + grandchild3");
    let _ = parent3.kill();
    let _ = parent3.wait();
    drop(parent3);

    let dead_deadline3 = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while open_process_checked(valid_ident3.pid, PROCESS_QUERY_LIMITED_INFORMATION).is_ok()
        && std::time::Instant::now() < dead_deadline3
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    assert!(
        !wait_process_exited(&grandchild3_handle, 0),
        "orphan grandchild3 should still be alive before terminate_process"
    );
    let orphan_term = controller.terminate_process(&valid_ident3, true);
    assert!(
        orphan_term.is_err(),
        "terminate_process on exited parent3 should report parent unavailability"
    );
    assert!(controller.tracked_suspended_children(&valid_ident3).is_empty());
    let exited = wait_process_exited(&grandchild3_handle, 3000);
    if !exited {
        // SAFETY: fallback cleanup in test failure path.
        let _ = unsafe { TerminateProcess(grandchild3_handle.as_raw(), 1) };
    }
    drop(stdin3);
    assert!(
        exited,
        "orphan grandchild3 ({}) must be terminated even after parent3 exited",
        grandchild3
    );
}

#[test]
fn sens_p3_04_defense_controller_wfp_delegation_and_guards() {
    use crate::wfp::{WfpBackend, WfpFilterSpec};
    use std::net::Ipv4Addr;

    struct StubDynamicBackend {
        next_id: u64,
        active: HashMap<u64, WfpFilterSpec>,
    }
    impl WfpBackend for StubDynamicBackend {
        fn begin_transaction(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn commit_transaction(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn abort_transaction(&mut self) {}
        fn add_filter(&mut self, spec: &WfpFilterSpec) -> Result<u64, String> {
            self.next_id += 1;
            self.active.insert(self.next_id, spec.clone());
            Ok(self.next_id)
        }
        fn delete_filter(&mut self, os_filter_id: u64) -> Result<(), String> {
            self.active.remove(&os_filter_id);
            Ok(())
        }
        fn is_dynamic_session(&self) -> bool {
            true
        }
    }

    // Uninitialized controller still enforces Never-Block before opening WFP.
    let uninit = WindowsDefenseController::new();
    let err = uninit
        .add_wfp_app_rule(Path::new(r"C:\Windows\System32\svchost.exe"), None, false)
        .expect_err("protected process must be rejected before WFP open");
    assert!(err.contains("protected process"), "{err}");
    assert!(uninit.remove_wfp_rule(1).is_err());

    // Configured controller delegates add/remove cleanly through ActiveDefenseController.
    let wfp = WfpDynamicEngine::from_backend(Box::new(StubDynamicBackend {
        next_id: 0,
        active: HashMap::new(),
    }))
    .expect("dynamic engine");
    let controller = WindowsDefenseController::with_wfp_engine(wfp);
    let h1 = controller
        .add_wfp_app_rule(Path::new(r"C:\Temp\sim.exe"), None, false)
        .expect("add dual-stack block");
    let h2 = controller
        .add_wfp_app_rule(
            Path::new(r"C:\Temp\sim.exe"),
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            true,
        )
        .expect("add single-stack permit");
    assert_ne!(h1, h2);
    controller.remove_wfp_rule(h1).expect("remove h1");
    controller.remove_wfp_rule(h2).expect("remove h2");
    assert!(controller.remove_wfp_rule(h1).is_err());
}

#[test]
fn sens_p3_11_defense_controller_wfp_drop_sink_before_and_after_init() {
    use crate::wfp::{WfpBackend, WfpDropSinkFn, WfpFilterMeta, WfpFilterSpec};
    use std::sync::RwLock;

    // 1. Pre-init registration succeeds before lazy WFP open and can be cleared cleanly.
    let lazy_controller = WindowsDefenseController::new();
    let sink: WfpDropSinkFn = Arc::new(|_| {});
    lazy_controller
        .set_wfp_drop_sink(Arc::clone(&sink))
        .expect("pre-init set_wfp_drop_sink");
    assert!(lazy_controller.wfp_drop_sink.lock().unwrap().is_some());
    lazy_controller.clear_wfp_drop_sink();
    assert!(lazy_controller.wfp_drop_sink.lock().unwrap().is_none());

    // 2. Post-init registration forwards `filter_index` and `Some/None` sink to backend.
    #[derive(Default)]
    struct SinkStubBackend {
        next_id: u64,
        sink_set_count: usize,
        sink_clear_count: usize,
        has_sink: bool,
        captured_index: Option<Arc<RwLock<HashMap<u64, WfpFilterMeta>>>>,
    }
    struct SharedStub(Arc<Mutex<SinkStubBackend>>);
    impl WfpBackend for SharedStub {
        fn begin_transaction(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn commit_transaction(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn abort_transaction(&mut self) {}
        fn add_filter(&mut self, _spec: &WfpFilterSpec) -> Result<u64, String> {
            let mut s = self.0.lock().unwrap();
            s.next_id += 1;
            Ok(s.next_id)
        }
        fn delete_filter(&mut self, _os_filter_id: u64) -> Result<(), String> {
            Ok(())
        }
        fn is_dynamic_session(&self) -> bool {
            true
        }
        fn set_drop_sink(
            &mut self,
            filter_index: Arc<RwLock<HashMap<u64, WfpFilterMeta>>>,
            sink: Option<WfpDropSinkFn>,
        ) -> Result<(), String> {
            let mut s = self.0.lock().unwrap();
            s.captured_index = Some(filter_index);
            if sink.is_some() {
                s.sink_set_count += 1;
                s.has_sink = true;
            } else {
                s.sink_clear_count += 1;
                s.has_sink = false;
            }
            Ok(())
        }
    }

    let shared = Arc::new(Mutex::new(SinkStubBackend::default()));
    let wfp = WfpDynamicEngine::from_backend(Box::new(SharedStub(Arc::clone(&shared))))
        .expect("dynamic engine");
    let controller = WindowsDefenseController::with_wfp_engine(wfp);

    controller
        .set_wfp_drop_sink(sink)
        .expect("set_wfp_drop_sink on active engine");
    {
        let s = shared.lock().unwrap();
        assert_eq!(s.sink_set_count, 1);
        assert!(s.has_sink);
        assert!(s.captured_index.is_some());
    }

    controller.clear_wfp_drop_sink();
    {
        let s = shared.lock().unwrap();
        assert_eq!(s.sink_clear_count, 1);
        assert!(!s.has_sink);
    }
}

#[test]
fn sens_p3_14_open_process_and_guard_reject_low_bit_pid_aliases() {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;

    assert!(
        open_process_checked(0, PROCESS_QUERY_LIMITED_INFORMATION).is_err(),
        "open_process_checked must refuse PID 0"
    );

    let self_pid = std::process::id();
    let self_handle = open_process_checked(self_pid, PROCESS_QUERY_LIMITED_INFORMATION)
        .expect("open_process_checked must open the exact current process PID");
    let self_create_time = query_process_creation_time(self_handle.as_raw())
        .expect("query current process CreationTime");
    drop(self_handle);
    assert!(self_create_time > 0);

    // Calling open_process_checked without PROCESS_QUERY_LIMITED_INFORMATION /
    // PROCESS_QUERY_INFORMATION must fail closed when GetProcessId returns 0.
    let no_query_err = match open_process_checked(self_pid, PROCESS_SYNCHRONIZE) {
        Ok(_) => panic!("open_process_checked without query rights must fail closed"),
        Err(err) => err,
    };
    assert!(
        no_query_err.contains("GetProcessId"),
        "expected GetProcessId failure without query rights, got: {no_query_err}"
    );

    let controller = WindowsDefenseController::new();
    for offset in 1..=3u32 {
        // Idle (PID 0) aliases: 1..=3 must be PolicyRejected.
        let idle_alias = ProcessIdentity::new(offset, 12_345);
        match validate_and_inspect_target_detailed(&idle_alias) {
            Err(TargetValidationError::PolicyRejected(msg)) => {
                assert!(
                    msg.contains("refusing to act on"),
                    "Idle alias must carry refusal prefix: {msg}"
                );
            }
            other => panic!("expected PolicyRejected for Idle alias {offset}, got: {other:?}"),
        }
        assert!(collect_live_descendants(&idle_alias).is_empty());

        // Self-PID aliases: self_pid + 1..=3.
        let alias_pid = self_pid.saturating_add(offset);
        let err = match open_process_checked(alias_pid, PROCESS_QUERY_LIMITED_INFORMATION) {
            Ok(_) => panic!("open_process_checked must reject low-bit PID alias {alias_pid}"),
            Err(err) => err,
        };
        assert!(
            err.contains("mismatched PID"),
            "expected mismatched PID error for alias {alias_pid}, got: {err}"
        );

        let alias_ident = ProcessIdentity::new(alias_pid, self_create_time);
        match validate_and_inspect_target_detailed(&alias_ident) {
            Err(TargetValidationError::PolicyRejected(msg)) => {
                assert!(
                    msg.contains("refusing to act on"),
                    "self-PID alias must carry refusal prefix: {msg}"
                );
            }
            other => {
                panic!("expected PolicyRejected for self-PID alias {alias_pid}, got: {other:?}")
            }
        }
        assert!(
            controller
                .suspend_process(&alias_ident, false)
                .is_err_and(|e| e.contains("refusing to act on")),
            "suspend_process must PolicyReject self-PID alias {alias_pid}"
        );
        assert!(
            controller
                .resume_process(&alias_ident)
                .is_err_and(|e| e.contains("refusing to act on")),
            "resume_process must PolicyReject self-PID alias {alias_pid}"
        );
        assert!(
            controller
                .terminate_process(&alias_ident, true)
                .is_err_and(|e| e.contains("refusing to act on")),
            "terminate_process must PolicyReject self-PID alias {alias_pid}"
        );
        assert!(collect_live_descendants(&alias_ident).is_empty());

        // System (PID 4) aliases: 5..=7 must be PolicyRejected even when non-elevated.
        let system_alias = ProcessIdentity::new(4 + offset, 12_345);
        match validate_and_inspect_target_detailed(&system_alias) {
            Err(TargetValidationError::PolicyRejected(msg)) => {
                assert!(
                    msg.contains("refusing to act on"),
                    "System alias must carry refusal prefix: {msg}"
                );
            }
            other => {
                panic!(
                    "expected PolicyRejected for System PID alias {}, got: {other:?}",
                    system_alias.pid
                )
            }
        }
        assert!(collect_live_descendants(&system_alias).is_empty());
    }

    // Spawn a real non-self child process to exercise OpenProcessError::PidMismatch ->
    // TargetValidationError::PolicyRejected directly (bypassing the self/System shortcut).
    let mut child = Command::new("cmd.exe")
        .args(["/c", "findstr .*"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn harmless cmd.exe child for PID alias guard test");
    let _stdin_keepalive = child.stdin.take();
    let child_pid = child.id();
    let child_handle = open_process_checked(child_pid, PROCESS_QUERY_LIMITED_INFORMATION)
        .expect("open spawned child");
    let child_ct =
        query_process_creation_time(child_handle.as_raw()).expect("query child CreationTime");
    drop(child_handle);

    for offset in 1..=3u32 {
        let child_alias = ProcessIdentity::new(child_pid.saturating_add(offset), child_ct);
        match validate_and_inspect_target_detailed(&child_alias) {
            Err(TargetValidationError::PolicyRejected(msg)) => {
                assert!(
                    msg.contains("refusing to act on") && msg.contains("mismatched PID"),
                    "live child alias must fail with PolicyRejected + mismatched PID: {msg}"
                );
            }
            other => panic!(
                "expected PolicyRejected for live child PID alias {}, got: {other:?}",
                child_alias.pid
            ),
        }
        assert!(
            controller
                .suspend_process(&child_alias, false)
                .is_err_and(|e| e.contains("refusing to act on")),
            "suspend_process must PolicyReject live child alias {}",
            child_alias.pid
        );
        assert!(
            controller
                .resume_process(&child_alias)
                .is_err_and(|e| e.contains("refusing to act on")),
            "resume_process must PolicyReject live child alias {}",
            child_alias.pid
        );
        assert!(
            controller
                .terminate_process(&child_alias, true)
                .is_err_and(|e| e.contains("refusing to act on")),
            "terminate_process must PolicyReject live child alias {}",
            child_alias.pid
        );
        assert!(
            child.try_wait().expect("poll child").is_none(),
            "live child PID {child_pid} must remain untouched after alias {} refusal",
            child_alias.pid
        );
        assert!(collect_live_descendants(&child_alias).is_empty());
    }

    let _ = child.kill();
    let _ = child.wait();
}

/// `SENS-P2-RUNDOWN-01`: Terminated zombie processes (whose handles are still held open during
/// Windows asynchronous kernel rundown) must be classified as [`ProcessLiveness::Gone`] via
/// `GetProcessTimes` (`lpExitTime != 0`) / `SYNCHRONIZE` (`WaitForSingleObject`), and
/// `terminate_process` must succeed cleanly for an already-exited validated zombie while still
/// keeping suspended processes `Running` and enforcing `CreationTime` mismatch checks.
#[test]
fn sens_p2_rundown_01_zombie_process_liveness_and_terminate_accept_exited_rundown() {
    use super::process_probe::{
        is_process_handle_exited, probe_snapshot_present_pid_liveness, query_process_exit_time,
    };
    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::System::Threading::{PROCESS_SYNCHRONIZE, WaitForSingleObject};

    let controller = WindowsDefenseController::new();

    // 1. Live & suspended process must report `ProcessLiveness::Running`.
    let mut child = Command::new("cmd.exe")
        .args(["/c", "findstr .*"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn harmless cmd.exe child for rundown test");
    let _stdin_keepalive = child.stdin.take();
    let child_pid = child.id();

    let zombie_keepalive = open_process_checked(
        child_pid,
        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
    )
    .expect("open child handle to keep zombie object alive");
    let child_ct = query_process_creation_time(zombie_keepalive.as_raw())
        .expect("query child CreationTime");
    let valid_ident = ProcessIdentity::new(child_pid, child_ct);

    assert_eq!(
        process_liveness(child_pid),
        ProcessLiveness::Running,
        "live child must report Running"
    );
    assert_eq!(
        probe_snapshot_present_pid_liveness(child_pid),
        ProcessLiveness::Running,
        "snapshot-present probe on live child must report Running"
    );
    assert!(
        !is_process_handle_exited(zombie_keepalive.as_raw(), true, 0),
        "live child handle must not be marked exited"
    );
    assert_eq!(
        query_process_exit_time(zombie_keepalive.as_raw()),
        Some(0),
        "live child must report lpExitTime == 0"
    );

    controller
        .suspend_process(&valid_ident, false)
        .expect("suspend child");
    assert_eq!(
        process_liveness(child_pid),
        ProcessLiveness::Running,
        "suspended (non-exited) child must still report Running, never Gone"
    );
    assert_eq!(
        probe_snapshot_present_pid_liveness(child_pid),
        ProcessLiveness::Running,
        "snapshot-present probe on suspended child must still report Running"
    );
    assert!(
        !is_process_handle_exited(zombie_keepalive.as_raw(), true, 0),
        "suspended (non-exited) child handle must not be marked exited"
    );

    // 2. Terminate while holding `zombie_keepalive` + `Child` open so the kernel process object
    // remains addressable as a zombie even after exit completes.
    // SAFETY: `zombie_keepalive` is our spawned test child opened with `PROCESS_TERMINATE`.
    unsafe { TerminateProcess(zombie_keepalive.as_raw(), 1) }.expect("terminate test child");
    // SAFETY: `zombie_keepalive` has `PROCESS_SYNCHRONIZE`.
    let wait_res = unsafe { WaitForSingleObject(zombie_keepalive.as_raw(), 2_000) };
    assert_eq!(
        wait_res, WAIT_OBJECT_0,
        "terminated child handle must become signaled"
    );
    assert!(
        query_process_exit_time(zombie_keepalive.as_raw()).is_some_and(|t| t != 0),
        "terminated zombie child must report non-zero lpExitTime"
    );
    assert!(
        is_process_handle_exited(zombie_keepalive.as_raw(), true, 0),
        "terminated zombie handle must be confirmed exited"
    );

    // Even when a Toolhelp32 snapshot still includes the zombie PID during rundown,
    // `probe_snapshot_present_pid_liveness` (and `process_liveness`) must classify it as `Gone`.
    assert_eq!(
        probe_snapshot_present_pid_liveness(child_pid),
        ProcessLiveness::Gone,
        "snapshot-present probe must classify exited zombie with open handle as Gone"
    );
    assert_eq!(
        process_liveness(child_pid),
        ProcessLiveness::Gone,
        "terminated zombie process with open handles must report Gone"
    );

    // `CreationTime` mismatch against a zombie PID must still fail closed.
    let wrong_ct_ident = ProcessIdentity::new(child_pid, child_ct.saturating_add(1));
    let mismatch_err = controller
        .terminate_process(&wrong_ct_ident, false)
        .expect_err("CreationTime mismatch on zombie PID must still be rejected");
    assert!(
        mismatch_err.contains("CreationTime mismatch")
            || mismatch_err.contains("unable to resolve image name"),
        "unexpected zombie mismatch error: {mismatch_err}"
    );

    // Re-terminating an already-exited zombie must either succeed directly (when Toolhelp32
    // still retains its image name during rundown) or fail closed with `process_liveness == Gone`
    // once Windows tears down the zombie's image metadata — never surfacing an unresolvable
    // `Running` error (`RESOLVE_ERROR`).
    if let Err(err) = controller.terminate_process(&valid_ident, false) {
        assert!(
            err.contains("unable to resolve image name") || err.contains("OpenProcess"),
            "unexpected error when re-terminating exited zombie: {err}"
        );
        assert_eq!(
            process_liveness(child_pid),
            ProcessLiveness::Gone,
            "exited zombie that failed image lookup must still report ProcessLiveness::Gone"
        );
    }

    drop(zombie_keepalive);
    let _ = child.wait();
    assert_eq!(
        process_liveness(child_pid),
        ProcessLiveness::Gone,
        "reaped child PID must report Gone"
    );

    // 3. Tree suspend + terminate (`cmd.exe` -> `findstr.exe`) must leave parent and recorded
    // descendants immediately observable as `ProcessLiveness::Gone` after terminate returns.
    let mut tree_root = Command::new("cmd.exe")
        .args(["/c", "echo ready & findstr .*"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn two-level process tree");
    let _tree_stdin = tree_root.stdin.take();
    let root_pid = tree_root.id();
    let root_handle = open_process_checked(root_pid, PROCESS_QUERY_LIMITED_INFORMATION)
        .expect("open tree root");
    let root_ct =
        query_process_creation_time(root_handle.as_raw()).expect("query tree root CreationTime");
    drop(root_handle);
    let root_ident = ProcessIdentity::new(root_pid, root_ct);

    // Wait briefly (bounded) for `cmd.exe` to spawn its `findstr.exe` child before suspending.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    while std::time::Instant::now() < deadline {
        let has_child = snapshot_process_entries()
            .unwrap_or_default()
            .iter()
            .any(|e| e.ppid == root_pid);
        if has_child {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
    }

    controller
        .suspend_process(&root_ident, true)
        .expect("suspend tree");
    let recorded_kids = controller.tracked_suspended_children(&root_ident);
    controller
        .terminate_process(&root_ident, true)
        .expect("terminate suspended tree");

    assert_eq!(
        process_liveness(root_pid),
        ProcessLiveness::Gone,
        "terminated tree root must immediately report Gone even before Child::wait()"
    );
    for kid in &recorded_kids {
        assert_eq!(
            process_liveness(kid.pid),
            ProcessLiveness::Gone,
            "terminated tree descendant PID {} must immediately report Gone",
            kid.pid
        );
    }

    let _ = tree_root.wait();
}
