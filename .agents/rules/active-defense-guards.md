---
trigger: model_decision
description: LocalEDR の防御アクチュエータ（サスペンド、TerminateAndBlock、ProcessLiveness、rollback_saved_rule）、おとりファイル（L-06 自動削除）、ETW レジストリ CloseKey 監視、Session 0 通知、IPC 認可と dev_bypass_auth、--prepare-dir、WFP 動的フィルタとドメイン由来フィルタ、デュアルスタック DNS 履歴、BFE ドロップ有界キュー、アンインストール前検査、インストーラ ACL 保護、アップデータ署名状態検証、および Win32 HRESULT エラー変換を実装またはレビューするとき
---

# 能動防御と特権境界の安全制約を遵守する

LocalEDR の Layer 1 から Layer 4 にわたる能動防御処理と特権境界（サービス配置、アンインストール、インストーラ ACL、アップデータ、Win32 ハンドル検証）は、誤動作や権限悪用時に OS 操作不能、通信遮断、リパースポイント/TOCTOU 誘導、ユーザー文書誤削除、ACL 破壊、またはアップデータ改ざんを招くため、設計上の安全境界を無条件で強制する。

## 手順

1. サスペンドと終了：`NtSuspendProcess` とプロセス終了の前に、`crates/ledr-proto` の `is_never_suspend_process` 判定と `ProcessIdentity.create_time_100ns` 一致を必ず検証する。
   スナップショット経由で終了済み非保護中間子プロセス越しの孫探索を継続するときは、`NtQuerySystemInformation(SystemProcessInformation)` で得た中間子自身の `create_time_100ns` に対し、ルート直下（`parent.pid == root.pid`）に限って `recycled_cutoff_100ns`（初回照会後にスナップショットで補完したカットオフを含む）を適用し、各階層で直接の親との `is_valid_descendant_timestamp` を検証してから子自身の `create_time_100ns` でキューに積み、親の作成時刻の代用と作成時刻未確認（`None`）時の走査継続（フェイルオープン）を禁止する。
2. おとりとタイムアウト：おとりファイルは書き込み、削除、リネームのみで発火させ読み取りでは発火させない。
   未応答 60 秒到達時は `EXPIRED_SUSPENDED`（`AlertStatus::ExpiredSuspended`）へ遷移させ、自動再開しない。
   LocalSystem サービス時のおとり配置は `USERPROFILE` へ依存せず WTS と `ProfileList` から 60 秒周期で対象プロファイルを更新し、リパースポイント、UNC パス、未作成ルートを拒否する。
   配置および検証は `CreateFileW`（`FILE_FLAG_OPEN_REPARSE_POINT`）による親ディレクトリ検査と、`NtCreateFile`（`FILE_OPEN_REPARSE_POINT`）・`ReOpenFile`・`SetFileInformationByHandle` を用いたファイルハンドル上検証（`nNumberOfLinks == 1` および `GetFinalPathNameByHandleW` による閉じ込め確認）で TOCTOU を遮断する。
   おとり自己抑止は `GetProcessTimes` による厳格な `(pid, create_time_100ns != 0)` 一致のみを許可する。
   `L-06` 自動削除のため `FILE_CREATE` または `HONEYPOT_DECOY_CONTENT` 一致時のみ `(volume_serial, file_index)` を `honeypot_files` へ記録し、再配置時に同期したうえで、アンインストール時は同一ハンドル上で `(volume_serial, file_index)` が記録済みなら識別子一致、ファイル ID 未記録（旧形式の追跡行を含む）なら `HONEYPOT_DECOY_CONTENT` 一致を確認できたファイルのみを削除し、不一致の同名ユーザー文書や置換ファイルは `SkippedNotOwned` で保護する。
3. Session 0 と UI 終了：`--notify` 起動は `WTSQueryUserToken` と `CreateProcessAsUser` で非 SYSTEM のユーザー権限を用い、ウィンドウ閉鎖時は `ledr-ui` と関連 WebView2 プロセスを 0 件にする。
   通知先 `ledr-ui.exe` の同フォルダ UI 優先は `--foreground` かつ `--dev-bypass-auth` 有効時に限定し、それ以外（認可強制時および非 `--foreground` 起動時）は同フォルダや別フォルダを問わず `AUTHORIZED_UI_EXE_PATH` へ統一して `L-25` の IPC 認可と乖離させない。
4. IPC 認可とタイムアウト：`Ping` を除く全 IPC コマンドは `CallerAuthPolicy` に従い（`UiOnly`: `ResolveAlert`・`ResolveAlertWithOptions`・`UpsertRule`・`DeleteRule`・`GetFlightRecorder`・`GetAlerts`・`ListRules`・`GetPipelineMetrics` は `AUTHORIZED_UI_EXE_PATH`、`BridgeOnly`: `ReportDownloadOrigin`・`ReportBrowserEvent` は `AUTHORIZED_BRIDGE_EXE_PATH`、`UiOrBridge`: `CheckDomainRisk` は `AUTHORIZED_UI_EXE_PATH` または `AUTHORIZED_BRIDGE_EXE_PATH`）、開発バイパス無効時に `GetNamedPipeClientProcessId` で呼び出し元バイナリを検証し、読み取りと書き込み双方へタイムアウトを設定する。
   これらの IPC 呼び出し元検証（開発バイパス無効かつ SHA-256 ピン単独で完結しない Authenticode 検証経路）ではキャッシュを迂回する `inspect_uncached` を使い、アプリ内のキャッシュ済み判定を再利用せず毎回検証する（`ledr-auth-helper` は `WTD_REVOCATION_CHECK_NONE` を用いるためオンライン CRL/OCSP の失効確認は行わない）。
5. WFP 動的フィルタ：Phase 3 の WFP エンジンは `FWPM_SESSION_FLAG_DYNAMIC` と独自 SubLayer を必ず使い、異常終了時に恒久ブロックを残さない。
   サスペンドとフィルタ追加の片系失敗時は孤立状態を残さず復元する。
6. 防御アクチュエータ記録、ロールバック、および `ProcessLiveness` / `TerminateAndBlock`：状態記録は防御アクチュエータで確認できた分だけを記録し、`suspended_children` には凍結確認済みの子のみを含める。
   ルール保存（永続許可や遮断ルール）のあとに再開や状態更新が失敗したときは、保存済みルールに対して `rollback_saved_rule` による補償削除をベストエフォートで試み、削除にも失敗した場合は警告ログを記録して元のエラーを返す（取り消しの成功までは保証しない）。
   凍結済み対象（`process_suspended` が真の親プロセスおよび記録済み `suspended_children`）の再開や終了の失敗における存否判定は `ProcessLiveness`（`Running`、`Gone`、`Unknown`）の三値で扱い、スナップショット列挙の失敗（`Unknown`）を消失とみなさず、消失の許容は `CreationTime mismatch` または `Gone` の確認に限る。
   一方、凍結記録のない親プロセスの終了失敗は、保護対象の拒否を除き存否確認を行わず警告ログを出して続行する。
   `TerminateAndBlock` では、親プロセスの保護対象拒否と凍結済み親の識別子欠落は、記録済みの子を試行せず即時にエラーを返して打ち切る。
   保護対象拒否以外の理由で凍結済み親の終了に失敗し、消失や PID 再利用を確認できない場合は、記録済みの子を全員終了試行したうえで子の成否にかかわらず親の終了エラーを返す。
   それ以外の経路（親の終了成功、失敗許容、または非凍結親の識別子欠落）で記録済み子プロセスの終了ループへ進んだ場合に限り、保護対象拒否または消失や PID 再利用を確認できない実エラーが起きても途中で打ち切らず残りの子も全員試行し、最初の実エラーを保持してループ後に返す。
7. ETW レジストリ監視、`--prepare-dir`、および `dev_bypass_auth`：ETW レジストリ監視は `CloseKey`（キーワード `0x0001`）を購読し、NTSTATUS 系 `Status` に非ゼロ値が明示された失敗イベントだけを除外し、`Status` が `0` または欠落している場合は処理を継続して `KeyObject` キャッシュの更新や無効化およびアラート発行を判定する。
   監視外と判明した `KeyObject` はキャッシュから除去し、`DeleteKey` と `CloseKey` で無効化する。
   `--prepare-dir` は `create_new(true)` でファイルを排他作成し、失敗時は今回作成分のファイルだけを削除対象にしてベストエフォートで削除を試みる（既存ファイルは削除せず、削除エラーは無視して準備エラーを返す）。
   `dev_bypass_auth` は実行時呼び出し元認証の迂回であり、使用しない署名設定の要求をスキップする。
8. デュアルスタック DNS 履歴と共有 IP 遮断優先：デュアルスタック DNS 履歴（`ProcessDnsHistory`）は `LatestDomainIps` で IPv4 と IPv6 の最新 IP 集合と時刻を独立管理し、`canonical_ip` により IPv4 射影 IPv6 を参照時に正規化し、遅延応答で既存エントリのより新しい時刻を後退させない。
   各 `(process_instance_id, IpAddr)` エントリは複数ドメイン候補（上限 `MAX_DOMAINS_PER_PROCESS_IP = 16`）を保持し、複数候補の評価は `select_outbound_decision_for_domains` の優先順位（`ProtectedOs`、`BlockedByRule`、`AllowedByRule`、最新候補の順）へ統一する。
   プロセス終了後や容量退避後でも `domains_for_exe_ip` と `current_domains_by_ip_for_exe` で全ドメイン横断の最新履歴を照合し、共有 IP の遮断優先（deny-overrides-allow）を維持する。
9. WFP ドメイン由来フィルタと BFE ドロップ有界キュー：WFP のドメイン由来フィルタ（`WfpFilterOrigin::DomainPolicy { domain_hints }`）は複数ドメイン集合（上限 `MAX_DOMAIN_HINTS_PER_FILTER = 32`）を保持し、アプリ全体、リテラル IP、CIDR、ワイルドカード IP のように `domain_hint` なしで静的に一致するルールではヒントを空のまま保ち、ドメイン固有ルールのみ `collect_domain_specific_blocked_hints` と `ensure_domain_policy_block_hints` で付与する。
   ポリシー変更時の `reconcile_persisted_rules_with_baseline` は、変更前後比較で新規に必要となったフィルタ追加失敗へ `newly_required = true` を付与し、削除、縮小、上書きされたドメインルールの失敗も `removal_sources` で元ルール ID へ帰属させて補償ロールバックを漏らさない。
   BFE コールバック経路の `ingest_wfp_drop_event` は非ブロッキングかつ同期 `tracing` 出力を持たず、チャネル満杯時は一次 FIFO と満杯時 `coalesced_by_exe` の二段有界キュー `WfpDropOverflowQueue`（一次キュー部分ドレイン時も両層横断で重複判定）へ退避する。
   同一実行ファイルの別宛先上書き回数は `wfp_drop_overflow_coalesced` で計測し、非同期ワーカー側の `maybe_log_wfp_drop_overflow_coalesced` からべき乗間引きで警告ログを出す。
   `on_wfp_drop_dequeued`、`flush_ready_pending_wfp_drops`、`handle_ambiguous_wfp_drop` では、単一候補時は `lookup_domains_for_process`、複数候補時は 60 秒鮮度窓付きの `lookup_fresh_domains_for_process`（`AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS = 60_000`）を用い、猶予保留、早期解除、最終評価の鮮度条件を対称に保つ。
10. アンインストール、インストーラ、アップデータ特権境界：アンインストール前段は読み取り専用（`--check-unresolved-suspended`）で未解決凍結アラートを検査し、`ProcessLiveness` と `CreationTime` 照合に加えハンドル上で `PROCESS_SYNCHRONIZE` 取得時は `WaitForSingleObject(0) == WAIT_OBJECT_0`、権限拒否時の `PROCESS_QUERY_LIMITED_INFORMATION` フォールバックでは `GetExitCodeProcess != STILL_ACTIVE` により終了済みゾンビハンドルを `Gone`（続行可）として区別し、PID 不明・生存残存・`Unknown`・作成時刻欠損かつ消失未確認（PID 再利用を排除不能）・検査失敗時はフェイルクローズで中断する。
    再インストール時の ACL 保護は明示 ACE を削除したうえで、対象ツリー内のリパースポイント不在を事前検証（`Assert-NoReparsePointsInTree`）してから `icacls /reset /T` を適用し、復元失敗時は管理者専用バックアップを保全する。
    `update-state.json` へ更新マニフェストをキャッシュ永続化するときは署名付きマニフェストと署名エンベロープを併記し（最新版確認のみの保存では確認時刻とバージョンのみ保持）、起動時にキャッシュが存在する場合はサイズ上限・Ed25519 署名・SemVer・ファイル名を再検証して不正時は `Idle` へフェイルクローズする。
11. Win32 `HRESULT` エラー種別変換：`windows::core::Error` の `HRESULT_FROM_WIN32`（`0x8007xxxx`）を `std::io::Error::from` へ直接渡すと `ErrorKind::Uncategorized` になるため、エラー種別を判定する経路では `(hresult & 0xFFFF_0000) == 0x8007_0000` を満たす場合のみ下位 16 ビットを `std::io::Error::from_raw_os_error` へ変換し、それ以外の `HRESULT` は元の `std::io::Error::from` として扱う。
12. 実機 E2E 検証境界：実機依存の挙動（ツリー終了の非同期性、実 BFE カーネル WFP フィルタ登録、`FwpmNetEventSubscribe1` 実イベント捕捉、および実 ETW `DNS-Client`）は合成ユニットテストでは検証済みと扱わず、Windows 10/11 クライアント SKU の実機 E2E 対象として残す。

## 対象外

- 境界チェックに関与しない UI の見た目やログ文言のみの調整
- テスト用モック定数やドキュメント誤字のみの修正
