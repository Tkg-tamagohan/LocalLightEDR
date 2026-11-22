---
trigger: model_decision
description: LocalEDR の ActiveProcessTable、事前 WFP ブロック、ポリシーロールバック、イベントループ定期スイープ、補助 SystemTrace ETW セッション、または並行ロック競合回帰テストを設計、実装、レビューするとき
---

# デーモン境界とプロセス追跡の不変条件（FU-E2E-04 以降）

`ledr-daemon` と `ledr-sensor-win` の実機 E2E 是正（`FU-E2E-04` 等）で確立したモジュール間構造不変条件を定める。

## 不変条件

- 補助 `SystemTrace` セッション（`{session_name}-SysProc`）は主 ETW セッションのプロバイダ有効化より先に起動を試行し（失敗時は PEB 検査へフォールバックして主セッション起動を続行する）、起動成功後に主セッション起動の任意ステップが失敗したときは RAII ガード（`AuxStartupGuard`）で停止とコンシューマスレッド join をロールバックする。
- `ProcessStart` 以外の登録経路（おとり先行バックフィル等）から `ActiveProcessTable` へ登録する場合も起動時防御（`apply_process_launch_guards`）を即時適用し、呼び出し側の起動時防御と MOTW の適用省略判定は `skip_store_ingest` ではなく `skip_launch_guards`（`launch_guards_applied && !upgraded_exe` が真なら省略）で行う。
  `apply_process_launch_guards` 自身の入口判定は稼働中インスタンスのみを通過させ（`launch_guards_applied` では遮断しない）、`upgraded_exe` と `L-18` の遅延 MOTW 昇格を維持する。
  終了済みの識別済みプロセス（`create_time_100ns != 0`）を `evicted_exited` へ退避する際は UTF-8 で 4 KiB 以内（`<= 4096` バイト）の完全な `command_line` のみ保持し、超過時は切り詰め断片を返さず欠損扱い（`EvictedCommandLine::Oversized`）として末尾一致等の誤検知を防ぐ。
- 事前 WFP ブロックの登録、解除、終了時クリーンアップのロック順序は `firewall -> process_table` へ統一し、起動時の新規登録における `add_wfp_app_rule` 呼び出し中は `firewall` と `process_table` のいずれのロックも保持せず、ロールバック復元時の再登録および `remove_wfp_rule` 呼び出し中は `firewall` ロック保持下で `process_table` ロックを非保持とする。
  起動時の新規登録では `add_wfp_app_rule` 実行前と登録コミット直前に `firewall -> process_table` 順で起動時固定（startup-pinned）または要件を満たす稼働中プロセス（静的リスクありなら稼働中プロセス、静的リスクなしなら MOTW 付きの稼働中プロセス `has_active_motw_for_exe_key`）の存否を再検証し、実行前に不要なら登録を中断し、コミット直前に不要なら `process_table` 解放後に即時解放（`discard_obsolete_preemptive_block`）して削除失敗ハンドルだけを `pending_preemptive_removals` へ積む。
  定期スイープ（`sweep_unused_preemptive_blocks`）は `pending_preemptive_removals` のみを対象に毎スイープ確認し、再稼働した実行ファイルは削除せず解除待ちから取り消し、引き続き解除対象となるブロックのみ毎スイープ再試行して警告ログだけ連続失敗回数が 2 の累乗の回に間引く。
- 未解決アラート参照により見送った非起動時 `Preemptive` ブロックの削除要求は `deferred_preemptive_removals` へ分離記録し、最終アラート解除時に `firewall -> process_table` 順（`remove_wfp_rule` 呼び出し中は `process_table` 非保持）で再試行する。
  定期アラート期限切れと残留事前遮断スイープ（`run_periodic_expiry_and_sweep`）は `pipeline.rs` の Tier 2c（Tier 1〜2b 後、Tier 3 テレメトリ前）でデーモン停止未要求時（`!nrd_cancel.is_cancelled()`）にのみ実行し、停止要求後（`nrd_cancel.is_cancelled()`）は抑止して 3 秒終了予算を守る。
- ポリシー更新のロールバックでは、昇格フィルタの解除待ち状態（`pending_preemptive_removals` の連続失敗回数と `deferred_preemptive_removals`）をスナップショット（`PromotedFilterSnapshot`）から復元（`restore_promoted_filter_states`）する。
  また撤去済みアプリブロックの解除待ち状態と紐付けアラートをスナップショット（`RemovedBlockSnapshot`、`RemovedAppBlockSnapshot` の `removed_app_blocks`）へ保持し、復元時（`restore_lifted_block`、`restore_removed_app_blocks`）に非起動時 `Preemptive` の新規登録ハンドルへは解除待ち状態（未紐付き時は削除失敗回数と直後のアラート再紐付けを含む遅延解除、紐付き時は遅延解除へ統合）を引き継ぐ一方、既存の非起動時 `Preemptive` ハンドルが残存して新規登録を省略する早期リターン経路では遅延解除フラグ（`prev_deferred_preemptive_removal` および再紐付け時の昇格分）のみを引き継ぎ削除失敗回数は復元しない。
- 撤去済み非起動時 `Preemptive` ブロックをロールバック復元（`restore_removed_app_blocks`）する際は、`firewall -> process_table` 順（`firewall` ロック保持下の BFE 再登録前に `process_table` ロックを解放）で対象実行ファイルの稼働状況を再確認し、未紐付きかつ終了済みなら復元を抑止し、アラート紐付きかつ終了済みなら遅延解除フラグを付与して最終アラート解除時に回収する。
- `ActiveProcessTable` の容量退避で押し出された未終了プロセスは `evicted_live`（二次溢れ時は `overflowed_evicted_live_exes` と `evicted_live_overflow_any` のフェイルクローズ集合）で生存追跡し、稼働照会（`has_active_exe_key`、`has_active_motw_for_exe_key`）と終了処理（`on_process_stop_with_exe`）で終了済みプロセスと区別してライブ `Preemptive` ブロックの誤解除を防ぐ。
  退避キュー（`evicted_live_fifo`）の各要素には単調増加世代（`evicted_live_seq`）を付けて世代不一致項目は溢れ退避と圧縮で破棄して世代一致項目のみを対象に残し、PID 照会は線形走査を避け `evicted_live_by_pid` 索引で O(1) に保つ。
- 新規起動（`on_process_start`）で PID 再利用により終了扱いとした旧インスタンス（`entries` と `evicted_live`）は実行ファイルパス付き（`superseded_exited_processes`）で返し、新インスタンス登録後かつ `process_table` ロック解放後に `ProcessStop` と同一のクリーンアップ（`cleanup_firewall_for_stopped_instance`）で未使用 `Preemptive` ブロック回収と未解決アラート参照時の遅延解除記録（`deferred_preemptive_removals`）を行う。
- ブロッキングフック（`add_wfp_app_rule` 等）や同期バリアで停止中のスレッドと並行して非保持であるべき共有ロック（`firewall`、`process_table`）を検査する回帰テストでは、無期限の `.lock()` ではなく有界タイムアウト付きの `try_lock()` ヘルパ（`try_has_active_wfp_filter` 等）を用い、ロック範囲退行をハングではなくタイムアウト失敗として検出する。
