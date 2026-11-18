# LocalEDR リポジトリ開発規約

本リポジトリで設計、実装、レビュー、検証を行うエージェントと Swarm ワーカーは以下に従う。

## 仕様の正と進行規則

- 仕様の正は `docs/implementation-plan.md`、`docs/decision-records.md`（L-01 から L-16）、および凍結済みの `crates/ledr-proto/src/lib.rs` に置く。
- 作業は Phase 単位（1 Phase 1 PR）で進め、`docs/implementation-plan.md` のチェックリスト `[x]` は `main` へのマージ完了後にのみ更新する。
- `crates/ledr-proto` の既存公開型とシグネチャは後方互換なく変更しない。

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
- `TerminateAndBlock` では、親プロセスの保護対象拒否は即時にエラーを返して打ち切る。
  一方、記録済み子プロセスの終了ループでは保護対象拒否や未消失などの実エラーが起きても途中で打ち切らず残りの子も全員試行し、最初の実エラーを保持してループ後に返す。
- ETW レジストリ監視は `CloseKey`（キーワード `0x0001`）を購読し、NTSTATUS 系 `Status` に非ゼロ値が明示された失敗イベントだけを除外し、`Status` が `0` または欠落している場合は処理を継続して `KeyObject` キャッシュの更新や無効化およびアラート発行を判定する。
  監視外と判明した `KeyObject` はキャッシュから除去し、`DeleteKey` と `CloseKey` で無効化する。
- `--prepare-dir` は `create_new(true)` でファイルを排他作成し、失敗時は今回作成分のファイルだけを削除対象にしてベストエフォートで削除を試みる（既存ファイルは削除せず、削除エラーは無視して準備エラーを返す）。
- `dev_bypass_auth` は実行時呼び出し元認証の迂回であり、使用しない署名設定の要求をスキップする。
- 実機依存の挙動（ツリー終了の非同期性など）は合成ユニットテストでは検証済みと扱わず、Windows 10/11 クライアント SKU の実機 E2E 対象として残す。

## 標準検証コマンド

- 静的検査：`cargo clippy --workspace --all-targets --locked -- -D warnings`
- 全体テスト：`cargo test --workspace --locked`
- 負荷と TTL 回帰：`cargo test -p ledr-daemon --test burst_budget --locked -- --nocapture` と `cargo test -p ledr-store --test ttl_purge_lineage --locked`
- 実機 E2E：ターゲット基準は Windows 10 または 11（x86_64）クライアント SKU であり、Server SKU で代替検証した場合は未検証差異として明記する。
