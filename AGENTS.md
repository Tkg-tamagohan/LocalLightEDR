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

## 標準検証コマンド

- 静的検査：`cargo clippy --workspace --all-targets --locked -- -D warnings`
- 全体テスト：`cargo test --workspace --locked`
- 負荷と TTL 回帰：`cargo test -p ledr-daemon --test burst_budget --locked -- --nocapture` と `cargo test -p ledr-store --test ttl_purge_lineage --locked`
- 実機 E2E：ターゲット基準は Windows 10 または 11（x86_64）クライアント SKU であり、Server SKU で代替検証した場合は未検証差異として明記する。
