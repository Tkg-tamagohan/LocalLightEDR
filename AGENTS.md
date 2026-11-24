# LocalEDR リポジトリ開発規約

本リポジトリで設計、実装、レビュー、検証を行うエージェントと Swarm ワーカーは以下に従う。

## 仕様の正と進行規則

- 仕様の正は `docs/implementation-plan.md`、`docs/decision-records.md`（L-01 から L-29）、および凍結済みの `crates/ledr-proto/src/lib.rs` に置く。
- 作業は Phase 単位（1 Phase 1 PR）で進め、`docs/implementation-plan.md` のチェックリスト `[x]` は `main` へのマージ完了後にのみ更新する。
- `crates/ledr-proto` の既存公開型とシグネチャは後方互換なく変更しない。
- 文書同期時の整合原則：仕様書、実装計画、フォローアップ記録等を更新する際は以下の 3 点を徹底する。
  - 仕様参照表の反映先へ記述のない層を案内しない。
  - 代替手順書の案内先に旧基準が残っている場合は現行の正本基準（`L-24` 等）で合否判定する旨を明記し、現行完了基準と将来の見直し論点を分離する。
  - 接続時処理とリクエスト別認可のような実行順序は実コード（例：`crates/ledr-daemon/src/ipc/server.rs` の `handle_pipe_client`）と 1 対 1 で揃える。

## Phase 1 で確立した構造不変条件

- センサーから `DaemonEngine` への供給は `TwoLaneSender`（`HIGH_PRIORITY_CHANNEL_CAPACITY = 1024` / `TELEMETRY_CHANNEL_CAPACITY = 8192`）直結とし、前段へ無制限チャネルを挟まない。
- デーモン起動順序は「`prior_running_candidates` の事前取得、ETW 開始、`try_capture_running_processes`（取得失敗と空を `Result` で区別）、親やコマンドライン補完時の `should_evaluate_sigma` 再評価付き統合、`reconcile_stale_running_processes` の実行」の順を崩さない。
- PID 解決は時間窓と `create_time_100ns` 降順タイブレーク（`idx_processes_pid_created`）を維持し、先着新プロセスより古いスナップショットには `exited_at_ms` を推定記録し、`upsert_process_row` の既設定終了時刻維持を守る。
- 停止処理は通常終了時に `ControlTraceW` 後の残余 ETW バッファを回収してからドレインし、`purge_expired` はバッチ間で書き込みロックを解放して停止要求時に 3 秒予算内チェックポイントへ譲る。
- ホットパスのテレメトリ解決では `emitted_rule_ids` 等を含むエントリ全体を `.clone()` せず必要フィールドだけを抽出する。

## Phase 2 で確立した不変条件

- 状態記録は防御アクチュエータで確認できた分だけを記録し、`suspended_children` には凍結確認済みの子のみを含める。
- ルール保存（永続許可や遮断ルール）のあとに再開や状態更新が失敗したときは、保存済みルールに対して `rollback_saved_rule` による補償削除をベストエフォートで試み、削除にも失敗した場合は警告ログを記録して元のエラーを返す（取り消しの成功までは保証しない）。
- 凍結済み対象（`process_suspended` が真の親プロセスおよび記録済み `suspended_children`）の再開や終了の失敗における存否判定は `ProcessLiveness`（`Running`、`Gone`、`Unknown`）の三値で扱い、スナップショット列挙の失敗（`Unknown`）を消失とみなさず、消失の許容は `CreationTime mismatch` または `Gone` の確認に限る。
  一方、凍結記録のない親プロセスの終了失敗は、保護対象の拒否を除き存否確認を行わず警告ログを出して続行する。
- `TerminateAndBlock` では、親プロセスの保護対象拒否と凍結済み親の識別子欠落は、記録済みの子を試行せず即時にエラーを返して打ち切る。
  保護対象拒否以外の理由で凍結済み親の終了に失敗し、消失や PID 再利用を確認できない場合は、記録済みの子を全員終了試行したうえで子の成否にかかわらず親の終了エラーを返す。
  それ以外の経路（親の終了成功、失敗許容、または非凍結親の識別子欠落）で記録済み子プロセスの終了ループへ進んだ場合に限り、保護対象拒否または消失や PID 再利用を確認できない実エラーが起きても途中で打ち切らず残りの子も全員試行し、最初の実エラーを保持してループ後に返す。
- ETW レジストリ監視は `CloseKey`（キーワード `0x0001`）を購読し、NTSTATUS 系 `Status` に非ゼロ値が明示された失敗イベントだけを除外し、`Status` が `0` または欠落している場合は処理を継続して `KeyObject` キャッシュの更新や無効化およびアラート発行を判定する。
  監視外と判明した `KeyObject` はキャッシュから除去し、`DeleteKey` と `CloseKey` で無効化する。
- `--prepare-dir` は `create_new(true)` でファイルを排他作成し、失敗時は今回作成分のファイルだけを削除対象にしてベストエフォートで削除を試みる（既存ファイルは削除せず、削除エラーは無視して準備エラーを返す）。
- `dev_bypass_auth` は実行時呼び出し元認証の迂回であり、使用しない署名設定の要求をスキップする。
- 実機依存の挙動（ツリー終了の非同期性など）は合成ユニットテストでは検証済みと扱わず、Windows 10/11 クライアント SKU の実機 E2E 対象として残す。

## Phase 3 で確立した不変条件

- デュアルスタック DNS 履歴（`ProcessDnsHistory`）は `LatestDomainIps` で IPv4 と IPv6 の最新 IP 集合と時刻を独立管理し、`canonical_ip` により IPv4 射影 IPv6 を参照時に正規化し、遅延応答で既存エントリのより新しい時刻を後退させない。
  各 `(process_instance_id, IpAddr)` エントリは複数ドメイン候補（上限 `MAX_DOMAINS_PER_PROCESS_IP = 16`）を保持し、複数候補の評価は `select_outbound_decision_for_domains` の優先順位（`ProtectedOs`、`BlockedByRule`、`AllowedByRule`、最新候補の順）へ統一する。
  プロセス終了後や容量退避後でも `domains_for_exe_ip` と `current_domains_by_ip_for_exe` で全ドメイン横断の最新履歴を照合し、共有 IP の遮断優先（deny-overrides-allow）を維持する。
- WFP のドメイン由来フィルタ（`WfpFilterOrigin::DomainPolicy { domain_hints }`）は複数ドメイン集合（上限 `MAX_DOMAIN_HINTS_PER_FILTER = 32`）を保持し、アプリ全体、リテラル IP、CIDR、ワイルドカード IP のように `domain_hint` なしで静的に一致するルールではヒントを空のまま保ち、ドメイン固有ルールのみ `collect_domain_specific_blocked_hints` と `ensure_domain_policy_block_hints` で付与する。
  ポリシー変更時の `reconcile_persisted_rules_with_baseline` は、変更前後比較で新規に必要となったフィルタ追加失敗へ `newly_required = true` を付与し、削除、縮小、上書きされたドメインルールの失敗も `removal_sources` で元ルール ID へ帰属させて補償ロールバックを漏らさない。
- BFE コールバック経路の `ingest_wfp_drop_event` は非ブロッキングかつ同期 `tracing` 出力を持たず、チャネル満杯時は一次 FIFO と満杯時 `coalesced_by_exe` の二段有界キュー `WfpDropOverflowQueue`（一次キュー部分ドレイン時も両層横断で重複判定）へ退避する。
  同一実行ファイルの別宛先上書き回数は `wfp_drop_overflow_coalesced` で計測し、非同期ワーカー側の `maybe_log_wfp_drop_overflow_coalesced` からべき乗間引きで警告ログを出す。
- `on_wfp_drop_dequeued`、`flush_ready_pending_wfp_drops`、`handle_ambiguous_wfp_drop` では、単一候補時は `lookup_domains_for_process`、複数候補時は 60 秒鮮度窓付きの `lookup_fresh_domains_for_process`（`AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS = 60_000`）を用い、猶予保留、早期解除、最終評価の鮮度条件を対称に保つ。
- NRD 更新スレッドの停止は `spawn_blocking` を使わず `NrdThreadHandle`（`oneshot` と `InFlightGuard::drop`）で非ブロッキング待機し、ワーカー未チェックポイント時は待機前に `checkpoint_truncate` を優先実行し、予算超過時はデタッチして Tokio `Runtime::drop` のハングを防ぐ。
  ファイル形式 NRD は `read_bounded_reader_cancellable`（`NRD_FILE_READ_CHUNK_BYTES = 64 * 1024`）で各チャンク前後および `ErrorKind::Interrupted` 再試行前にキャンセルを確認し、`NrdCancelToken::enter_blocking_read()` によりブロッキング読み取り突入を壁時計スリープなしで観測可能に保つ。
- 統合テストでは優先度レーン分離をまたぐ異レーン完了バリアおよび終了済み込み `active_process_table_len()` による同期を禁止し、`GateBinaryInspector` のようなマルチスレッド Tokio 上の同期ブロッキングモックには `RuntimeFlavor::MultiThread` ガード付き `block_in_place` を使う。
- 実 BFE カーネル WFP フィルタ登録、`FwpmNetEventSubscribe1` 実イベント捕捉、実 ETW `DNS-Client`、および応答しない実 UNC/SMB 共有での NRD 挙動は合成テストでは検証済みと扱わず、Windows 10/11 クライアント SKU の実機 E2E 対象として残す。

## Phase 4 で確立した不変条件

- MOTW 帰属はパス一致、`<= 128 MiB` の SHA-256 一致、`:Zone.Identifier` ADS 読み取り（`ZoneId >= 3`）の 3 段階評価を専用 OS スレッド MOTW I/O ワーカープール経由で実行し、遅延 MOTW バックフィルは既存の `origin_url` を上書きしない。
- Stage 2 または Stage 3 で MOTW が確認された未許可バイナリ（`ProtectedOs` および既存 `NetworkAllow` 一致を除く）には、フォルダ移動による回避を防ぐため `HighRiskPath` と同じく起動時事前 WFP ブロックを適用する（`outbound_enforcement_mode != Audit` 時、`L-18`）。
- `LAYER_4_BROWSER` イベント記録（`record_browser_event`）は非空 URL 検証、`details` の 8 KiB 切詰め、30 秒かつ上限 256 件の有界重複抑止を行い、既定では OS トーストを発火しない（`L-19`）。
  プロセス紐付きのない `LAYER_4_BROWSER` アラートは `AllowOnce`（UI では `Acknowledge`）および `TerminateAndBlock { add_block_rule: false }` のみ許可し、`AllowPermanent` 等は拒否する。
- `ledr-bridge-nm` は 4 バイト LE ゼロパース中継（上限 1 MiB）、1 リクエスト 1 Named Pipe 接続、`GetNamedPipeServerProcessId` によるサーバーバイナリ検証（`SEC_0003`）、`stderr` 専用ログ（`stdout` 汚染禁止）を維持し、固定公開鍵由来の拡張 ID `ecelachfiiiiiibpjeomfncgpegbpanh` のみを `allowed_origins` に許可する（`L-20`）。
- Chrome MV3 拡張（`extensions/ledr-chrome-mv3`）はグローバル変数へ状態を保持せず `chrome.storage.session` と `chrome.storage.local` を使い、NRD とホモグラフ判定で閲覧ドメインを外部へ送信せず、ClickFix 観測は `"world": "MAIN"` の `content_main.js` から `ISOLATED` world へ受け渡す（`L-21`）。
- `apps/ledr-ui/src/defense_status.rs` はユーザーの機密ファイル（`Cookies`、`.ssh` 等）へ一切アクセスせず、おとりファイル、ブリッジバイナリ、`HKCU` および `HKLM` の読み取り専用レジストリ参照とマニフェスト検証のみを行い、ウィンドウ閉鎖時は `ledr-ui` と WebView2 を 0 プロセスで終了する（`L-08`）。
  マニフェスト検証は既定 2 ディレクトリのホワイトリスト配下だけに限定し、リパースポイント拒否、`FILE_FLAG_OPEN_REPARSE_POINT` と `FILE_READ_ATTRIBUTES` の先行検査、`nNumberOfLinks == 1`、`GetFinalPathNameByHandleW` 閉じ込め、`ReOpenFile` 昇格を経て読み取り、`description` を必須項目として検証する。
  カスタム配置パスに対してはファイル I/O を行わず、`unverified` として検証済み状態と区別する。
- View 3（`apps/ledr-ui/src/defense_status.rs`）の Native Messaging レジストリ診断では、WOW64 参照を `KEY_WOW64_32KEY -> KEY_WOW64_64KEY` の順で探索し、32 ビット側で `EmptyString` を検出した場合は 64 ビット側へフォールバックせず 32 ビット側で打ち切る。
  CLI `ledr-bridge-nm` の `HKLM` Native Messaging 操作も同様に WOW64 32 ビット・64 ビット両ビューに対応し、`setup --scope machine` は 32 ビット・64 ビット両ビューへ冪等に登録、`status` は View 3 と一致する順（32 ビット先行、32 ビット側 `EmptyString` で打ち切り）で探索、`unregister` は両ビューを冪等に削除したうえで両ビューの残存参照を確認してからマニフェストファイルを削除する（`HKCU`、URI スキーム、AUMID、グループポリシーは既定ビューのみを維持する）。
- View 3 のブラウザ別詳細行（`.browser-detail-row`）には各ブラウザの `manifest_path` と診断表示を併記し、`UI-P4-08` 等の UI 回帰テストではコンテナ全体検索だけで済ませず、ブラウザ単位で詳細行要素を抽出して期待する値が併記されていることと他ブラウザの情報が混入していないことを検証する。
- 実 Chrome 拡張ロード、実 Native Messaging ホスト起動、実ダウンロードの `:Zone.Identifier` 付与と移動後紐付け、および実 WebView2 終了計測は合成テストでは検証済みと扱わず、Windows 10/11 クライアント SKU の実機 E2E（`FU-E2E-02`）対象として残す。

## 標準検証コマンド

- 静的検査：`cargo clippy --workspace --all-targets --locked -- -D warnings`
- 全体テスト：`cargo test --workspace --locked`
- 負荷と TTL 回帰：`cargo test -p ledr-daemon --test burst_budget --locked -- --nocapture` と `cargo test -p ledr-store --test ttl_purge_lineage --locked`
- Chrome MV3 拡張テスト（Node 22、PowerShell 5.1 互換）：`$extTests = @(Get-ChildItem extensions\ledr-chrome-mv3\tests\*.test.mjs | Select-Object -ExpandProperty FullName); if ($extTests.Count -eq 0) { throw "No Chrome MV3 extension test files matched." }; node --test $extTests`
- UI モック DOM テスト（Node 22、PowerShell 5.1 互換）：`$uiTests = @(Get-ChildItem apps\ledr-ui\js-tests\*.test.mjs | Select-Object -ExpandProperty FullName); if ($uiTests.Count -eq 0) { throw "No Tauri UI test files matched." }; node --test $uiTests`（単体実行：`node --test apps/ledr-ui/js-tests/phase4_ui.test.mjs`）
- 実機 E2E：ターゲット基準は Windows 10 または 11（x86_64）クライアント SKU であり、Server SKU で代替検証した場合は未検証差異として明記する。
- 検証記録の区別：文書（`docs/follow-up-notes.md`、`docs/implementation-plan.md` 等）や PR 本文へテスト合格を記録する際は、`.github/workflows/ci.yml` で実際に実行されるジョブ範囲（`changes` によるパス別スキップを含む）とローカル別途実行範囲を混同せず、常に「ローカルでも再実行した CI 相当項目」と「CI 対象外のローカル別途実行項目」（実機計測、PE インポート検査、`scripts/test_check_invariants.py`、不変条件ゲート、実機 E2E 等）を分離して記載し、CI 未実行またはスキップされたスイートには別途の実行コマンド、環境、結果記録を明記する。
