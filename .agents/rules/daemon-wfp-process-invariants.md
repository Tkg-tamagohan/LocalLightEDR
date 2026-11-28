---
trigger: model_decision
description: LocalEDR のデーモン起動および停止順序、TwoLaneSender 有界チャネル、PID 解決、ActiveProcessTable、事前 WFP ブロック、deferred_preemptive_removals 保護と deploy_persisted_network_rules_with_baseline、WindowsApps バージョンワイルドカード照合（matches_path_pattern）、ポリシーロールバック、定期保守、有界チャネル付きワーカーの停止（NRD 更新スレッドの非ブロッキング停止とキャンセルを含む）、補助 SystemTrace ETW セッション、または統合および並行ロック競合回帰テストを設計、実装、レビューするとき
---

# デーモン基盤、プロセス追跡、および NRD 停止の不変条件

`ledr-daemon` および関連クレート（`ledr-sensor-win`、`ledr-store`、`ledr-rules`、`ledr-auth-helper` 等）の Phase 1〜3 および実機 E2E 是正（`FU-E2E-03`、`FU-E2E-04`、`FU-E2E-05` 等）で確立した構造不変条件を定める。

## 不変条件

- センサーから `DaemonEngine` への供給は `TwoLaneSender`（`HIGH_PRIORITY_CHANNEL_CAPACITY = 1024` / `TELEMETRY_CHANNEL_CAPACITY = 8192`）直結とし、前段へ無制限チャネルを挟まない。
- デーモン起動順序は「`prior_running_candidates` の事前取得、ETW 開始、`try_capture_running_processes`（取得失敗と空を `Result` で区別）、親やコマンドライン補完時の `should_evaluate_sigma` 再評価付き統合、`reconcile_stale_running_processes` の実行」の順を崩さない。
- PID 解決は時間窓と `create_time_100ns` 降順タイブレーク（`idx_processes_pid_created`）を維持し、先着新プロセスより古いスナップショットには `exited_at_ms` を推定記録し、`upsert_process_row` の既設定終了時刻維持を守る。
- 停止処理は通常終了時に `ControlTraceW` 後の残余 ETW バッファを回収してからドレインし、`purge_expired` はバッチ間で書き込みロックを解放して停止要求時に 3 秒予算内チェックポイントへ譲る。
- ホットパスのテレメトリ解決では `emitted_rule_ids` 等を含むエントリ全体を `.clone()` せず必要フィールドだけを抽出する。
- NRD 更新スレッドの停止は `spawn_blocking` を使わず `NrdThreadHandle`（`oneshot` と `InFlightGuard::drop`）で非ブロッキング待機し、ワーカー未チェックポイント時は待機前に `checkpoint_truncate` を優先実行し、予算超過時はデタッチして Tokio `Runtime::drop` のハングを防ぐ。
  ファイル形式 NRD は `read_bounded_reader_cancellable`（`NRD_FILE_READ_CHUNK_BYTES = 64 * 1024`）で各チャンク前後および `ErrorKind::Interrupted` 再試行前にキャンセルを確認し、`NrdCancelToken::enter_blocking_read()` によりブロッキング読み取り突入を壁時計スリープなしで観測可能に保つ。
  応答しない実 UNC/SMB 共有での NRD 挙動は合成テストでは検証済みと扱わず、Windows 10/11 クライアント SKU の実機 E2E 対象として残す。
- 統合テストでは優先度レーン分離をまたぐ異レーン完了バリアおよび終了済み込み `active_process_table_len()` による同期を禁止し、`GateBinaryInspector` のようなマルチスレッド Tokio 上の同期ブロッキングモックには `RuntimeFlavor::MultiThread` ガード付き `block_in_place` を使う。

- 補助 `SystemTrace` セッション（`{session_name}-SysProc`）は主 ETW セッションのプロバイダ有効化より先に起動を試行し（失敗時は PEB 検査へフォールバックして主セッション起動を続行する）、起動成功後に主セッション起動の任意ステップが失敗したときは RAII ガード（`AuxStartupGuard`）で停止とコンシューマスレッド join をロールバックする。
- `ProcessStart` 以外の登録経路（おとり先行バックフィル等）から `ActiveProcessTable` へ登録する場合も起動時防御（`apply_process_launch_guards`）を即時適用し、呼び出し側の起動時防御と MOTW の適用省略判定は `skip_store_ingest` ではなく `skip_launch_guards`（`launch_guards_applied && !upgraded_exe` が真なら省略）で行う。
  `apply_process_launch_guards` 自身の入口判定は稼働中インスタンスのみを通過させ（`launch_guards_applied` では遮断しない）、`upgraded_exe` と `L-18` の遅延 MOTW 昇格を維持する。
  終了済みの識別済みプロセス（`create_time_100ns != 0`）を `evicted_exited` へ退避する際は UTF-8 で 4 KiB 以内（`<= 4096` バイト）の完全な `command_line` のみ保持し、超過時は切り詰め断片を返さず欠損扱い（`EvictedCommandLine::Oversized`）として末尾一致等の誤検知を防ぐ。
- 事前 WFP ブロックの登録、解除、終了時クリーンアップのロック順序は `firewall -> process_table` へ統一し、`maybe_apply_preemptive_wfp_block_with_motw` 内の自動事前遮断（`Preemptive`）の直接 `add_wfp_app_rule` 登録では `firewall` と `process_table` のいずれのロックも保持せず、永続 `NetworkBlock` 登録（`ensure_policy_block`）、ロールバック復元時の再登録、および `remove_wfp_rule` 呼び出し中は `firewall` ロック保持下で `process_table` ロックを非保持とする。
  この自動事前遮断（`Preemptive`）の直接登録では `add_wfp_app_rule` 実行前と登録コミット直前に `firewall -> process_table` 順で起動時固定（startup-pinned）または要件を満たす稼働中プロセス（静的リスクありなら稼働中プロセス、静的リスクなしなら MOTW 付きの稼働中プロセス `has_active_motw_for_exe_key`）の存否を再検証し、実行前に不要なら登録を中断し、コミット直前に不要なら `process_table` 解放後に即時解放（`discard_obsolete_preemptive_block`）して削除失敗ハンドルだけを `pending_preemptive_removals` へ積む。
  定期スイープ（`sweep_unused_preemptive_blocks`）は `pending_preemptive_removals` のみを対象に毎スイープ確認し、再稼働した実行ファイルは削除せず解除待ちから取り消し、引き続き解除対象となるブロックのみ毎スイープ再試行して警告ログだけ連続失敗回数が 2 の累乗の回に間引く。
- 未解決アラート参照により見送った非起動時 `Preemptive` ブロックの削除要求は `deferred_preemptive_removals` へ分離記録し、最終アラート解除時に `firewall -> process_table` 順（`remove_wfp_rule` 呼び出し中は `process_table` 非保持）で再試行する。
  あわせて `wfp_premat.rs`（`maybe_apply_preemptive_wfp_block_with_motw`）の既存フィルタ早期リターン経路では必ず早期リターン前に `clear_pending_preemptive_removal` で解除待ちを取り消し、`policy.rs` の `deploy_persisted_network_rules_with_baseline` は必ず `firewall -> process_table` 順で `active_exe_liveness_snapshot()` を取得して `process_table` ロックを即時解放する（`process_table` を `firewall` より先に取得するとスナップショット取得と `firewall` ロック取得の間に `ProcessStop` が割り込み `deferred_preemptive_removals` を消失させる TOCTOU が生じるため禁止）。
  さらに `reconcile.rs` の `reconcile_persisted_rules_with_baseline` は、生存プロセスまたはオーバーフロー時フェイルクローズ（`live_exe_overflow_any` / `overflow_live_exe_keys`）に該当する実行ファイルについて、`deferred_preemptive_removals` を理由とする非起動時 `Preemptive` ブロックフィルタの撤去を抑止する（稼働確認時にフィルタを維持したまま古い `deferred_preemptive_removals` フラグのみを取り消す処理は正当として許容する）。
  定期アラート期限切れと残留事前遮断スイープ（`run_periodic_expiry_and_sweep`）は `pipeline.rs` の Tier 2c（Tier 1〜2b 後、Tier 3 テレメトリ前）でデーモン停止未要求時（`!nrd_cancel.is_cancelled()`）にのみ実行し、停止要求後（`nrd_cancel.is_cancelled()`）は抑止して 3 秒終了予算を守る。
  60 秒周期の読取メモリ解放（`L-22`）などの低頻度定期保守も `select!` 単独に置かず、非タイマ起床で次回期限（`last_mem_maintenance_at` 基準）を先送りしない形で `Tier 2c` 後かつ Tier 3 テレメトリ受信前の期限チェック（`Tier 2c-mem`）とアイドル待機時の `sleep_until` の双方で駆動し、停止要求およびドレイン打ち切り開始時（`nrd_cancel.is_cancelled()`、`store.is_shutdown_requested()`、または `is_shutdown_drain_cutoff()`）は抑止する。
- `crates/ledr-rules/src/allowlist/matcher.rs` の `matches_path_pattern` は、非 UNC `\\?\` を除去したうえで `is_windows_apps_version_wildcard_pattern` に一致する `C:\Program Files\WindowsApps\<Name>_*_<Arch>_<ResourceId>_<PublisherId>\<RelPath>` 形式のパターンに限定して `*` の `\` 跨ぎを禁止する。
  `c:\program files\windowsapps\` 始まりパターン全般へ一律に `\` 跨ぎ禁止を拡大してはならない（View 3 で手動登録された汎用パターン `C:\Program Files\WindowsApps\*\App.exe` 等のサブフォルダ一致互換性を破壊するため）。
- ポリシー更新のロールバックでは、昇格フィルタの解除待ち状態（`pending_preemptive_removals` の連続失敗回数と `deferred_preemptive_removals`）をスナップショット（`PromotedFilterSnapshot`）から復元（`restore_promoted_filter_states`）する。
  また撤去済みアプリブロックの解除待ち状態と紐付けアラートをスナップショット（`RemovedBlockSnapshot`、`RemovedAppBlockSnapshot` の `removed_app_blocks`）へ保持し、復元時（`restore_lifted_block`、`restore_removed_app_blocks`）に非起動時 `Preemptive` の新規登録ハンドルへは解除待ち状態（未紐付き時は削除失敗回数と直後のアラート再紐付けを含む遅延解除、紐付き時は遅延解除へ統合）を引き継ぐ一方、既存の非起動時 `Preemptive` ハンドルが残存して新規登録を省略する早期リターン経路では遅延解除フラグ（`prev_deferred_preemptive_removal` および再紐付け時の昇格分）のみを引き継ぎ削除失敗回数は復元しない。
- 撤去済み非起動時 `Preemptive` ブロックをロールバック復元（`restore_removed_app_blocks`）する際は、`firewall -> process_table` 順（`firewall` ロック保持下の BFE 再登録前に `process_table` ロックを解放）で対象実行ファイルの稼働状況を再確認し、未紐付きかつ終了済みなら復元を抑止し、アラート紐付きかつ終了済みなら遅延解除フラグを付与して最終アラート解除時に回収する。
- `ActiveProcessTable` の容量退避で押し出された未終了プロセスは `evicted_live` で生存追跡し、二次溢れ時は一般稼働照会用のフェイルクローズ集合（`overflowed_evicted_live_exes`、`evicted_live_overflow_any`）と MOTW 稼働照会用の専用フェイルクローズ集合（`overflowed_evicted_live_motw_exes`、`evicted_live_motw_overflow_any`）を分けて保持し、稼働照会（`has_active_exe_key`、`has_active_motw_for_exe_key`）と終了処理（`on_process_stop_with_exe`）で終了済みプロセスと区別してライブ `Preemptive` ブロックの誤解除を防ぐ。
  退避キュー（`evicted_live_fifo`）の各要素には単調増加世代（`evicted_live_seq`）を付けて世代不一致項目は溢れ退避と圧縮で破棄して世代一致項目のみを対象に残し、PID 照会は線形走査を避け `evicted_live_by_pid` 索引で O(1) に保つ。
- 新規起動（`on_process_start`）で PID 再利用により終了扱いとした旧インスタンス（`entries` と `evicted_live`）は実行ファイルパス付き（`superseded_exited_processes`）で返し、新インスタンス登録後かつ `process_table` ロック解放後に `ProcessStop` と同一のクリーンアップ（`cleanup_firewall_for_stopped_instance`）で未使用 `Preemptive` ブロック回収と未解決アラート参照時の遅延解除記録（`deferred_preemptive_removals`）を行う。
- `ActiveProcessTable::collect_unexited_descendants` は `root.create_time_100ns == 0` または保護対象 `root`（現行実装では `entries` と `evicted_exited` を参照）で空を返し、PID 再利用の 100ns カットオフ（`create_time_100ns < next_cutoff`）を未検証 `ppid` フォールバック（`by_ppid`）だけでなく検証済み `by_parent_id` リンクにも統一適用する。
  カットオフ解決は `entries`、`evicted_exited`、および `evicted_live_by_pid` 経由の `evicted_live`（`pid == 0` と `create_time_100ns == 0` を除外）の 3 ソースから単一パスで事前索引（現行は `create_times_by_pid` を PID ごとに 1 回ソート）を構築し、対数時間以下の検索（`partition_point` による `O(log k_pid)`）で行い、親ごとの線形再走査を行わない。
  また `is_never_suspend_process("") == false` により未識別の保護プロセス配下へ展開されるのを防ぐため、空または空白のみの `exe_path`（`child.exe_path.trim().is_empty()`）を持つ中間親は BFS キューへ積まずに展開を止める。
- 受信側が消費やドレインを打ち切って停止または強制終了する経路で有界チャネル（`sync_channel` 等）へ送信する専用ワーカースレッドやリーダースレッドを `join()` する前は、送信側の満杯ブロックによるデッドロックを防ぐため必ず受信端（例として `auth_worker.rs` の `resp_rx`）を先にドロップまたはクローズする（通常終了時に残余要素のドレインが必要なチャネルではドレイン完了後に閉じる）。
- ブロッキングフック（`add_wfp_app_rule` 等）や同期バリアで停止中のスレッドと並行して非保持であるべき共有ロック（`firewall`、`process_table`）を検査する回帰テストでは、無期限の `.lock()` ではなく有界タイムアウト付きの `try_lock()` ヘルパ（`try_has_active_wfp_filter` 等）を用い、ロック範囲退行をハングではなくタイムアウト失敗として検出する。
- `ActiveProcessTable` の `ppid` フォールバック経路を検証するユニットテストでは、全フォールバック子に `parent_instance_id == None` を明示アサートして検証済み `by_parent_id` リンクへのすり替わりを防ぐ。
  そのため既定では対象子プロセスを親および後継再誕生プロセスより先に登録する（`PROC-DESC-05` のように、生存中の親を残す目的で後継プロセスを先に `evicted_exited` へ退避したうえで子登録時に `parent_instance_id == None` を確認できる境界ケースを除く）。
