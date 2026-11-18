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
- ルール保存や許可リスト登録のあとに後続処理が失敗したときは、保存済みの副作用を補償処理で取り消す。
- プロセス存否は `ProcessLiveness`（Running/Gone/Unknown）の三値で扱い、スナップショット列挙の失敗（Unknown）を消失とみなさない。消失の許容は `CreationTime mismatch` または `Gone` の確認に限る。
- 記録済み子プロセスの終了は個別の失敗で打ち切らず全員を試行し、最初の実エラーを保持してループ後に返す（保護対象の拒否は即時エラー）。
- ETW レジストリ監視は `CloseKey`（キーワード `0x0001`）を購読し、NTSTATUS 系 `Status` の成功を確認したイベントだけで `KeyObject` キャッシュの更新とアラート発行を行う。監視外と判明した `KeyObject` はキャッシュから除去し、`DeleteKey` と `CloseKey` で無効化する。
- `--prepare-dir` が排他的に作成したファイルは、失敗時に今回作成分だけを除去する。
- `dev_bypass_auth` は実行時呼び出し元認証の迂回であり、使用しない署名設定の要求をスキップする。
- 実機依存の挙動（ツリー終了の非同期性など）は合成ユニットテストでは検証済みと扱わず、Windows 10/11 クライアント SKU の実機 E2E 対象として残す。

## 標準検証コマンド

- 静的検査：`cargo clippy --workspace --all-targets --locked -- -D warnings`
- 全体テスト：`cargo test --workspace --locked`
- 負荷と TTL 回帰：`cargo test -p ledr-daemon --test burst_budget --locked -- --nocapture` と `cargo test -p ledr-store --test ttl_purge_lineage --locked`
- 実機 E2E：ターゲット基準は Windows 10 または 11（x86_64）クライアント SKU であり、Server SKU で代替検証した場合は未検証差異として明記する。
