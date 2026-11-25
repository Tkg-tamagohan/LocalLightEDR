---
trigger: model_decision
description: LocalEDR の防御アクチュエータ（サスペンド、終了）、おとりファイル（サービス配置と L-06 自動削除）、Session 0 通知、IPC 認可と Authenticode 署名検証キャッシュ、WFP 動的フィルタ、ブラウザ拡張と MOTW 連携、View 3 マニフェスト検証、ledr-bridge-nm の Native Messaging レジストリプローブとマニフェスト削除保護、アンインストール前検査、インストーラ ACL 保護、アップデータ署名状態検証、および Win32 HRESULT エラー変換を実装またはレビューするとき
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
4. IPC 認可とタイムアウト：`Ping` を除く全 IPC コマンドは `CallerAuthPolicy` に従い（`UiOnly`: `ResolveAlert`・`UpsertRule`・`DeleteRule`・`GetFlightRecorder`・`GetAlerts`・`ListRules`・`GetPipelineMetrics` は `AUTHORIZED_UI_EXE_PATH`、`BridgeOnly`: `ReportDownloadOrigin`・`ReportBrowserEvent` は `AUTHORIZED_BRIDGE_EXE_PATH`、`UiOrBridge`: `CheckDomainRisk` は `AUTHORIZED_UI_EXE_PATH` または `AUTHORIZED_BRIDGE_EXE_PATH`）、開発バイパス無効時に `GetNamedPipeClientProcessId` で呼び出し元バイナリを検証し、読み取りと書き込み双方へタイムアウトを設定する。
   これらの IPC 呼び出し元検証（開発バイパス無効かつ SHA-256 ピン単独で完結しない Authenticode 検証経路）ではキャッシュを迂回する `inspect_uncached` を使い、アプリ内のキャッシュ済み判定を再利用せず毎回検証する（`ledr-auth-helper` は `WTD_REVOCATION_CHECK_NONE` を用いるためオンライン CRL/OCSP の失効確認は行わない）。
5. WFP 動的フィルタ：Phase 3 の WFP エンジンは `FWPM_SESSION_FLAG_DYNAMIC` と独自 SubLayer を必ず使い、異常終了時に恒久ブロックを残さない。
   サスペンドとフィルタ追加の片系失敗時は孤立状態を残さず復元する。
6. Chrome と MOTW：Phase 4 の NRD 判定は外部へ閲覧ドメインを送信せずローカル完結に保ち、ダウンロード起源はパス、SHA-256、`:Zone.Identifier` の 3 段階で紐付ける。
7. View 3 マニフェスト検証：Native Messaging マニフェストの読み取りは既定 2 ディレクトリのホワイトリスト配下だけに限定し、カスタム配置パスに対してはファイル I/O を行わない。
   ホワイトリスト配下でもリパースポイントを拒否し、`FILE_FLAG_OPEN_REPARSE_POINT` と `FILE_READ_ATTRIBUTES` で先行検査して `nNumberOfLinks == 1` および `GetFinalPathNameByHandleW` によるディレクトリ閉じ込めを確認してから、`ReOpenFile` で読み取りハンドルへ昇格して読み取る。
8. CLI Native Messaging レジストリプローブとマニフェスト削除保護：`crates/ledr-bridge-nm/src/setup.rs` の `HKLM` Native Messaging 操作は `setup --scope machine` で 32 ビットおよび 64 ビット両ビューへ冪等に登録し、レジストリ文字列プローブは Chromium 互換で `REG_SZ` と `REG_EXPAND_SZ` の双方を扱い、空白トリム前の生値（2,048 バイト時の末尾 UTF-16 NUL 終端必須を含む `exceeds_chromium_raw_limit`）および空白トリム前の展開結果に対して 1,024 UTF-16 コード単位上限（`CHROMIUM_READ_VALUE_MAX_UTF16_UNITS`）を判定する。
   上限内かつ未解決の環境変数（展開後も `%TOKEN%` が残存する `has_unresolved_env_token` 検出）を含む `REG_EXPAND_SZ` は `UnresolvableExpandSz` として 32 ビット優先打ち切りとし、上限超過または `ExpandEnvironmentStringsW` 失敗は `ChromiumReadFallback` として `HKLM` 診断のみ 64 ビットビューへフォールバックする。
   `HKLM` の WOW64 診断（`run_status_with_ops`）は 32 ビットビューで `stops_wow64_fallback()`（`Present`、`EmptyString`、`UnresolvableExpandSz`）が成立した時点で 64 ビットビューを読まずに短絡終了する（`HKCU`、URI スキーム、AUMID、グループポリシーはフラグなしの既定ビューのみを維持する）。
   `unregister` では両ビューのレジストリキーを冪等に削除したうえで、共有マニフェストファイル削除前の参照検査（`any_browser_references_manifest_with`）では、マニフェスト一致またはフェイルクローズ対象（`UnresolvableExpandSz` と `ChromiumReadFallback { resolved_path: None }`）検出時の削除抑止の早期リターン（`Ok(true)`）を維持しつつ、`stops_wow64_fallback()`（`EmptyString` や非一致の `Present` 等）で 64 ビットビューをスキップせず全ブラウザの 32 ビットおよび 64 ビット両ビューをすべて検査してから削除許可（`Ok(false)`）を判定し、最大 32,768 UTF-16 コード単位まで保守的に展開した `ChromiumReadFallback { resolved_path: Some(..) }` を保護対象に含め、ブラウザ別 `manifest_removed` は 32 ビットおよび 64 ビット両ビューの全登録パスを `normalize_display_path` と大文字小文字無視の正規化比較で照合する。
9. アンインストール・インストーラ・アップデータ特権境界：アンインストール前段は読み取り専用（`--check-unresolved-suspended`）で未解決凍結アラートを検査し、`ProcessLiveness` と `CreationTime` 照合に加えハンドル上で `PROCESS_SYNCHRONIZE` 取得時は `WaitForSingleObject(0) == WAIT_OBJECT_0`、権限拒否時の `PROCESS_QUERY_LIMITED_INFORMATION` フォールバックでは `GetExitCodeProcess != STILL_ACTIVE` により終了済みゾンビハンドルを `Gone`（続行可）として区別し、PID 不明・生存残存・`Unknown`・作成時刻欠損かつ消失未確認（PID 再利用を排除不能）・検査失敗時はフェイルクローズで中断する。
   再インストール時の ACL 保護は明示 ACE を削除したうえで、対象ツリー内のリパースポイント不在を事前検証（`Assert-NoReparsePointsInTree`）してから `icacls /reset /T` を適用し、復元失敗時は管理者専用バックアップを保全する。
   `update-state.json` へ更新マニフェストをキャッシュ永続化するときは署名付きマニフェストと署名エンベロープを併記し（最新版確認のみの保存では確認時刻とバージョンのみ保持）、起動時にキャッシュが存在する場合はサイズ上限・Ed25519 署名・SemVer・ファイル名を再検証して不正時は `Idle` へフェイルクローズする。
10. Win32 `HRESULT` エラー種別変換：`windows::core::Error` の `HRESULT_FROM_WIN32`（`0x8007xxxx`）を `std::io::Error::from` へ直接渡すと `ErrorKind::Uncategorized` になるため、エラー種別を判定する経路では `(hresult & 0xFFFF_0000) == 0x8007_0000` を満たす場合のみ下位 16 ビットを `std::io::Error::from_raw_os_error` へ変換し、それ以外の `HRESULT` は元の `std::io::Error::from` として扱う。

## 対象外

- 境界チェックに関与しない UI の見た目やログ文言のみの調整
- テスト用モック定数やドキュメント誤字のみの修正
