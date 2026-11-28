# LocalEDR リポジトリ開発規約

本リポジトリで設計、実装、レビュー、検証を行うエージェントと Swarm ワーカーは以下に従う。

## 仕様の正と進行規則

- 仕様の正は `docs/implementation-plan.md`、`docs/decision-records.md`（`L-01` から `L-29`、および `L-30` 以降の追記専用 ADR）、および凍結済みの `crates/ledr-proto/src/lib.rs` に置く。
- 作業は Phase 単位（1 Phase 1 PR）で進め、`docs/implementation-plan.md` のチェックリスト `[x]` は `main` へのマージ完了後にのみ更新する。
- `crates/ledr-proto` の既存公開型とシグネチャは後方互換なく変更しない。
- 文書同期時の整合原則：仕様書、実装計画、フォローアップ記録等を更新する際は以下の 3 点を徹底する。
  - 仕様参照表の反映先へ記述のない層を案内しない。
  - 代替手順書の案内先に旧基準が残っている場合は現行の正本基準（`L-24` 等）で合否判定する旨を明記し、現行完了基準と将来の見直し論点を分離する。
  - 接続時処理とリクエスト別認可のような実行順序は実コード（例：`crates/ledr-daemon/src/ipc/server.rs` の `handle_pipe_client`）と 1 対 1 で揃える。

## サブシステム別不変条件ルール

各層の詳細な構造不変条件は `.agents/rules/` 配下の `model_decision` ルールへ分離して管理する。
該当領域の設計、実装、レビュー時は必ず対応するルールを参照する。

- **デーモン基盤、プロセス追跡、NRD 停止、統合テスト同期**：`.agents/rules/daemon-wfp-process-invariants.md`（`TwoLaneSender` 有界チャネル、起動および停止順序、PID 解決、`ActiveProcessTable`、事前 WFP ブロック、ポリシーロールバック、定期保守、補助 `SystemTrace` ETW、NRD 非ブロッキング停止とキャンセル）
- **能動防御、WFP/DNS/BFE、および特権境界**：`.agents/rules/active-defense-guards.md`（サスペンドや `TerminateAndBlock` と `ProcessLiveness` と `rollback_saved_rule`、おとりファイル、ETW レジストリ `CloseKey` 監視、Session 0 通知、IPC 認可と `dev_bypass_auth`、`--prepare-dir`、WFP 動的フィルタとドメイン由来フィルタ、デュアルスタック DNS 履歴、BFE 有界キュー、インストーラとアンインストールとアップデータ、`HRESULT` 変換）
- **ブラウザ連携、MOTW、ブリッジ、および UI 診断**：`.agents/rules/browser-ui-invariants.md`（MOTW 3 段階帰属と移動後事前 WFP ブロック、`LAYER_4_BROWSER`、`ledr-bridge-nm` 中継と `HKLM` WOW64 プローブと削除保護、Chrome MV3 拡張、`apps/ledr-ui` View 3 マニフェスト検証と WOW64 診断と `.browser-detail-row` 回帰規約）

## 標準検証コマンド

- 静的検査：`cargo clippy --workspace --all-targets --locked -- -D warnings`
- 全体テスト：`cargo test --workspace --locked`（`#[ignore]` 0 件のため、`burst_budget` および `ttl_purge_lineage` も `.github/workflows/ci.yml` の `rust-windows` と `.github/workflows/release.yml` の `verify` では本コマンド内で実行する）
- 負荷と TTL 回帰（ローカル個別再実行用）：`cargo test -p ledr-daemon --test burst_budget --locked -- --nocapture` と `cargo test -p ledr-store --test ttl_purge_lineage --locked`（CI では重複実行と `windows` クレート feature 集合変化による再コンパイルを防ぐため個別ステップを置かない）
- Chrome MV3 拡張テスト（Node 22、PowerShell 5.1 互換）：`$extTests = @(Get-ChildItem extensions\ledr-chrome-mv3\tests\*.test.mjs | Select-Object -ExpandProperty FullName); if ($extTests.Count -eq 0) { throw "No Chrome MV3 extension test files matched." }; node --test $extTests`
- UI モック DOM テスト（Node 22、PowerShell 5.1 互換）：`$uiTests = @(Get-ChildItem apps\ledr-ui\js-tests\*.test.mjs | Select-Object -ExpandProperty FullName); if ($uiTests.Count -eq 0) { throw "No Tauri UI test files matched." }; node --test $uiTests`（単体実行：`node --test apps/ledr-ui/js-tests/phase4_ui.test.mjs`）
- 実機 E2E：OS カーネル、実サービス、実ブラウザ拡張、実 UNC 共有等に依存する挙動は合成テストだけでは検証済みと扱わず、各サブシステム別ルールに定めた実機 E2E 対象として残す。
  ターゲット基準は Windows 10 または 11（x86_64）クライアント SKU であり、Server SKU で代替検証した場合は未検証差異として明記する。
- 検証記録の区別：文書（`docs/follow-up-notes.md`、`docs/implementation-plan.md` 等）や PR 本文へテスト合格を記録する際は、`.github/workflows/ci.yml` で実際に実行されるジョブ範囲（`changes` によるパス別スキップを含む）とローカル別途実行範囲を混同せず、常に「ローカルでも再実行した CI 相当項目」と「CI 対象外のローカル別途実行項目」（実機計測、PE インポート検査、`scripts/test_check_invariants.py`、不変条件ゲート、実機 E2E 等）を分離して記載し、CI 未実行またはスキップされたスイートには別途の実行コマンド、環境、結果記録を明記する。
