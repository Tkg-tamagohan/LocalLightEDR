---
trigger: model_decision
description: LocalEDR の防御アクチュエータ（サスペンド、終了）、おとりファイル、Session 0 通知、IPC 認可と Authenticode 署名検証キャッシュ、WFP 動的フィルタ、ブラウザ拡張と MOTW 連携、View 3 マニフェスト検証を実装またはレビューするとき
---

# 能動防御と特権境界の安全制約を遵守する

LocalEDR の Layer 1 から Layer 4 にわたる能動防御処理は、誤動作時に OS 操作不能や通信遮断を招くため、設計上の安全境界を無条件で強制する。

## 手順

1. サスペンドと終了：`NtSuspendProcess` とプロセス終了の前に、`crates/ledr-proto` の `is_never_suspend_process` 判定と `ProcessIdentity.create_time_100ns` 一致を必ず検証する。
   スナップショット経由で終了済み非保護中間子プロセス越しの孫探索を継続するときは、`NtQuerySystemInformation(SystemProcessInformation)` で得た中間子自身の `create_time_100ns` に対し、ルート直下（`parent.pid == root.pid`）に限って `recycled_cutoff_100ns`（初回照会後にスナップショットで補完したカットオフを含む）を適用し、各階層で直接の親との `is_valid_descendant_timestamp` を検証してから子自身の `create_time_100ns` でキューに積み、親の作成時刻の代用と作成時刻未確認（`None`）時の走査継続（フェイルオープン）を禁止する。
2. おとりとタイムアウト：おとりファイルは書き込み、削除、リネームのみで発火させ読み取りでは発火させない。
   未応答 60 秒到達時は `EXPIRED_SUSPENDED`（`AlertStatus::ExpiredSuspended`）へ遷移させ、自動再開しない。
3. Session 0 と UI 終了：`--notify` 起動は `WTSQueryUserToken` と `CreateProcessAsUser` で非 SYSTEM のユーザー権限を用い、ウィンドウ閉鎖時は `ledr-ui` と関連 WebView2 プロセスを 0 件にする。
   `--foreground` 起動時の通知先 `ledr-ui.exe` 選択は `--dev-bypass-auth` 有効時に限定して同フォルダ UI を優先し、認可強制時は `AUTHORIZED_UI_EXE_PATH` へ統一して `L-25` の IPC 認可と乖離させない。
4. IPC 認可とタイムアウト：`Ping` を除く全 IPC コマンドは `CallerAuthPolicy` に従い（`UiOnly`: `ResolveAlert`・`UpsertRule`・`DeleteRule`・`GetFlightRecorder`・`GetAlerts`・`ListRules`・`GetPipelineMetrics` は `AUTHORIZED_UI_EXE_PATH`、`BridgeOnly`: `ReportDownloadOrigin`・`ReportBrowserEvent` は `AUTHORIZED_BRIDGE_EXE_PATH`、`UiOrBridge`: `CheckDomainRisk` は `AUTHORIZED_UI_EXE_PATH` または `AUTHORIZED_BRIDGE_EXE_PATH`）、開発バイパス無効時に `GetNamedPipeClientProcessId` で呼び出し元バイナリを検証し、読み取りと書き込み双方へタイムアウトを設定する。
   これらの IPC 呼び出し元検証（開発バイパス無効かつ SHA-256 ピン単独で完結しない Authenticode 検証経路）ではキャッシュを迂回する `inspect_uncached` を使い、アプリ内のキャッシュ済み判定を再利用せず毎回検証する（`ledr-auth-helper` は `WTD_REVOCATION_CHECK_NONE` を用いるためオンライン CRL/OCSP の失効確認は行わない）。
5. WFP 動的フィルタ：Phase 3 の WFP エンジンは `FWPM_SESSION_FLAG_DYNAMIC` と独自 SubLayer を必ず使い、異常終了時に恒久ブロックを残さない。
   サスペンドとフィルタ追加の片系失敗時は孤立状態を残さず復元する。
6. Chrome と MOTW：Phase 4 の NRD 判定は外部へ閲覧ドメインを送信せずローカル完結に保ち、ダウンロード起源はパス、SHA-256、`:Zone.Identifier` の 3 段階で紐付ける。
7. View 3 マニフェスト検証：Native Messaging マニフェストの読み取りは既定 2 ディレクトリのホワイトリスト配下だけに限定し、カスタム配置パスに対してはファイル I/O を行わない。
   ホワイトリスト配下でもリパースポイントを拒否し、`FILE_FLAG_OPEN_REPARSE_POINT` と `FILE_READ_ATTRIBUTES` で先行検査して `nNumberOfLinks == 1` および `GetFinalPathNameByHandleW` によるディレクトリ閉じ込めを確認してから、`ReOpenFile` で読み取りハンドルへ昇格して読み取る。

## 対象外

- 境界チェックに関与しない UI の見た目やログ文言のみの調整
- テスト用モック定数やドキュメント誤字のみの修正
