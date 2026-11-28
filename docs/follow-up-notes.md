# LocalEDR 申し送り事項と実機検証計画

本書は LocalEDR の各 Phase を `main` ブランチへマージした後に残した副次的な改善余地と、合成自動テストでは検証済みと扱わない実機 E2E 検証の対象を管理する。
仕様の正は [implementation-plan.md](implementation-plan.md)、[decision-records.md](decision-records.md)（L-01 から L-29）、および凍結済みの [crates/ledr-proto/src/lib.rs](../crates/ledr-proto/src/lib.rs) に置き、本書では後続作業へ引き継ぐ個別項目を ID ごとに記録する。

## 項目一覧

| ID | 種別 | 関連 Phase | 概要 | 対応予定 |
| :--- | :--- | :--- | :--- | :--- |
| `FU-P3-01` | 副次最適化 | Phase 3 | `merge_domain_hints_prioritized` の満杯 32 件時に起きる非許可同居ヒントの再挿入抑制 | 実装および単体境界テスト完了済み（本ブランチで対応、`main` マージ待ち） |
| `FU-P4-01` | 副次改善 | Phase 4 | `ledr-bridge-nm` の `HKLM` 登録および確認における 32 ビットおよび 64 ビットレジストリビュー（`KEY_WOW64_32KEY` / `KEY_WOW64_64KEY`）対応 | 実装および非特権単体テスト完了済み（実 `HKLM` 書込と削除および実ブラウザ読込は `FU-E2E-02` 実機 E2E 対象） |
| `FU-E2E-01` | 実機 E2E 検証 | Phase 2、Phase 3 | Windows 10 または Windows 11 クライアント SKU 管理者環境での実機検証 | 最新 `main` 上の最終実機 E2E 検証 PR（PR #34、#35、#36、#38、#39、#41、#44 マージ済み） |
| `FU-E2E-02` | 実機 E2E 検証 | Phase 4 | Windows 10 または Windows 11 クライアント SKU 上での Chrome 拡張、Native Messaging、MOTW、および UI 終了の実機検証 | 最新 `main` 上の最終実機 E2E 検証 PR（PR #34、#39、#41 マージ済み） |
| `FU-E2E-03` | 性能最適化 | Phase 3、Phase 4 | `E2E-PERF-01` 超過に対する Stage 1〜3 最適化（`ledr-auth-helper` 分離、LRU 上限、非系譜解放、SQLite reader 縮小、`PrivateWorkingSetSize <= 20.0 MB` 基準併記） | PR #39（`7cdb445`）で `main` マージ済み、PR #40（`9e4a3a8`）でルール昇格済み（最終実機 E2E で再確認） |
| `FU-E2E-04` | 検知改善 | Phase 1、Phase 3 | 短命プロセス（約 40 ms）での PEB 補完欠落による `command_line` 欠落と `LEDR-LOTL-001`（正規管理ツール悪用検知ルール）未発火の解消 | PR #35（`ed9ae3f`）および PR #36（`1540a1f`）で `main` マージ済み、PR #37（`fac1022`）でルール昇格済み（最終実機 E2E で再確認） |
| `FU-E2E-05` | 境界改善 | Phase 3 | WFP ドロップの終了済み兄弟プロセス由来の誤帰属抑止および `E2E-P3-06` 停止予算超過時の残余書き込みによる `-wal` 再生成の整理 | PR #38（`b8d9c66`）で `main` マージ済み（最終実機 E2E で再確認） |
| `FU-P5-01` | ワークフロー検証と残余実機対象 | Phase 5 | `Release`（`dry_run: true`）および `Security Audit` の手動検証、PR #51 修正後の `main` 最終合格、ならびに本番公開と実機インストーラ E2E の残余管理 | PR #51（`10e357f`）で修正を `main` マージ済み、マージ後 `main` 手動検証合格済み（実機 NSIS E2E はリリース前実機検証、本番 `publish` は初回本番リリース時、本番鍵実更新は本番リリース前後の実機確認対象） |
| `FU-R0-01` | ビルド最適化基準計測 | Phase R0 | リリースビルドおよび CI 高速化改修前のベースライン計測値（`main` `b9bb76a` / CI `10e357f`）の固定と実機未検証境界の分離記録 | Phase R0 計測完了済み（Phase R1 から Phase R3 までの比較基準として固定、`b9bb76a` 上の `L-24` と `L-08` は管理者および対話デスクトップ検証待ち） |
| `FU-R1-01` | ビルド最適化統合と最終判定 | Phase R1〜R3-4 | Phase R1〜R2B の統合受け入れ結果（`main` `3f92057`）、Phase R3-1〜R3-4 の検証と採否判定（`d9c3fdd`）、および実機未検証項目の分離記録 | Phase R1〜R3-4 完了済み（PR #53、#54、#56、#58 マージ済み、PR #55、#57 不採用クローズ、R3-4 `Win32_System_Time` 削除見送りおよび分割不採用、`c4acf22` 実機一括検証の結果と残課題は `FU-R1-02` へ引き継ぎ） |
| `FU-R1-02` | `main` `c4acf22` 実機一括検証と残課題 | Phase R1〜R3-4 統合後 | `main`（`c4acf22`）上の `L-08`、`L-23`、および `L-24` 実機検証結果、原因切り分け、および静穏環境再計測と ETW/AMSI 調査の残課題 | `L-08` と `L-23` は合格、`L-24` `-Mode load` はプロセス起動負荷未発生のため未検証（参考値）、`-Mode idle` は未達（静穏環境での `L-24` 再計測と再現時 ETW/AMSI バッファ調査待ち） |
| `FU-P4-02` | 機能追加と実機検証対象 | Phase 4 | View 1 の WindowsApps バージョン部ワイルドカード永続許可仕様と実機確認対象 | 実装および自動テストは本ブランチで対応（実ストアアプリ更新前後の通信許可継続と `AppExecutionAlias` 除外は Windows 10 または 11 クライアント SKU 実機確認待ち） |
| `FU-P4-03` | 後続拡張設計 | Phase 4 | 汎用ホストプロセス（`backgroundTaskHost.exe` 等）向け後方互換プロトコル、ルール、および WFP 拡張設計 | 単一設計として確定記録済み（事前 API スパイク約 1 日および Track B-1 から Track B-3 の 3 本の後続 PR へ分離して実装予定） |

### 現在地、推奨着手順、および用語の補足

2026 年 11 月 22 日の暫定実機 E2E で抽出した 3 件の課題（`FU-E2E-03` から `FU-E2E-05`）および関連する基盤修正と強化策は、以下の順ですべて `main` へマージ済みである。

1. 検知と停止の正確性に直結する `FU-E2E-04`（PR #35 `ed9ae3f`、フォローアップ PR #36 `1540a1f`、ルール昇格 PR #37 `fac1022`）および `FU-E2E-05`（PR #38 `b8d9c66`）を解消した。
2. 続いて `FU-E2E-03`（PR #39 `7cdb445`、ルール昇格 PR #40 `9e4a3a8`）で `ledr-auth-helper` 分離とメモリ削減を実施し、`L-24` の基準併記を確定した。
3. あわせて、暫定実測の基盤だった Named Pipe DACL 修正（PR #34 `d8f4e7e`）および監査後の強化と安定化（PR #41 `ddfce96`、PR #42 `7ddc153`、PR #43 `26ee76b`、PR #44 `c78571c`、PR #45 `dcfb0af`）を `main` へ統合した。

残る必須工程は最新 `main` 上で統合実機 E2E（[e2e-test-runbook.md](e2e-test-runbook.md) のルート 1：`FU-E2E-01` および `FU-E2E-02`、ホスト ETW 競合を解消した状態での `E2E-P3-01`、`E2E-P3-03`、および終了済み中間親越しの孫プロセス凍結確認を含む）を実施することである。
全必須項目の通過を確認した後に、[implementation-plan.md](implementation-plan.md) の未完了チェックリスト 3 件を `[x]` へ更新する。
なお、副次改善 2 件（`FU-P3-01` と `FU-P4-01`）は本ブランチでコード改修および合成自動テストまで完了しており、実 `HKLM\SOFTWARE\WOW6432Node\...` への管理者権限書込と削除および実ブラウザでの Native Messaging 読み込み確認のみを `FU-E2E-02` 実機 E2E の対象として残している。

本書で参照する主な識別子と用語の意味を以下に補う。

- **ルート 1**：[e2e-test-runbook.md](e2e-test-runbook.md) に定める、Phase 2 から Phase 4 の全項目と性能計測を 1 台の検証機で通し実施する統合検証ルート。
- **`L-08` と `L-17`**：[decision-records.md](decision-records.md) の決定記録 ID であり、`L-08` はウィンドウ閉鎖時に `ledr-ui` と WebView2 を 0 プロセスで終了させる制約、`L-17` は Phase 4 を PR 4A、4B、4C の 3 本へ分割する計画を指す。
- **`SEC_0001` から `SEC_0003`**：各レビューと実装で付けたセキュリティ不変条件 ID であり、WFP 許可キャッシュではバイナリ差し替えやルール削除時の古い Permit 失効（`SEC_0001`）と別実行ファイル間の Permit 非継承（`SEC_0002`）を、Named Pipe IPC ではセッション時間上限（`SEC_0001`）、クライアントバイナリ検証（`SEC_0002`）、およびブリッジ側のサーババイナリ検証（`SEC_0003`）を指す。
- **`LEDR-LOTL-001`**：`powershell.exe` 等の正規管理ツールが難読化引数や危険なパターンで起動された挙動を検知する Sigma ルール ID。
- **`exe_key`**：実行ファイルパスを大文字小文字や区切り文字の違いを除いて正規化した識別子。

## FU-P3-01 満杯 32 件時の非許可同居ヒント再挿入の抑制

### 対象ファイル

- 実装箇所：[firewall/hints.rs](../crates/ledr-daemon/src/firewall/hints.rs#L45-L88)（`merge_domain_hints_prioritized`）
- 境界テスト：[firewall/tests.rs](../crates/ledr-daemon/src/firewall/tests.rs#L2221-L2287)（`FU-P3-01-01` および `FU-P3-01-02`）
- 主訴を解消した保護ヘルパ：[domain_policy.rs](../crates/ledr-daemon/src/engine/domain_policy.rs#L198-L221)（`extend_authorizing_hints_from_existing_permit`）
- 保護ヘルパの呼び出し 4 経路：[resolve_alert_with_outcome](../crates/ledr-daemon/src/engine/alerts.rs#L579-L586)（`AllowPermanent`）、[prematerialize_domain_wfp_filters](../crates/ledr-daemon/src/engine/wfp_premat.rs#L354-L361)、[handle_ambiguous_wfp_drop](../crates/ledr-daemon/src/engine/wfp_drops.rs#L1172-L1179)、および [evaluate_and_handle_outbound_connect](../crates/ledr-daemon/src/engine/outbound.rs#L729-L736)
- 関連する回帰テスト：[cached_permit.rs](../crates/ledr-daemon/src/engine/tests/cached_permit.rs#L383-L541)（`DAEMON-P3-49A` §7）と [phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L8136-L8648)（`DAEMON-P3-48`）

### 背景と出典

本件は Phase 3 の PR #5（ブランチ `phase-3-wfp-firewall`、マージコミット `3fe1031` / `3fe1031fc3692beab77e0eeb531f27e6e56c888e`）に対する Review #40 で指摘された事項から切り出した副次申し送りである。
出典のレビュースレッドは `PRRT_kwDOVyjVyM65hO2j`（指摘 ID `BUG_pr-review-job-23fb353b86b648aaa95062ec74d199a4_0001`、指摘対象コミット `4e11596`）であり、満杯の 32 件 Permit フィルタを更新する際のヒント退避順序が論点となった。

### 実装内容と保証範囲

#### 主訴の先行解消（PR #5 内コミット `3666680`）

Review #40 の主訴だった「満杯 32 件の Permit フィルタを更新するときに有効な既存許可根拠が消える問題」は、コミット `3666680`（`366668061c4ddd06a6a269d40a0b1c5860d7af51`）で解消した。
具体的には [domain_policy.rs](../crates/ledr-daemon/src/engine/domain_policy.rs#L198-L221) に `extend_authorizing_hints_from_existing_permit` を追加し、Permit の登録と更新を行う 4 経路すべてで既存の有効な許可ドメインを事前に保護集合へ組み込んだ。
一方、許可ヒント単体で 32 件を超過した場合は上限維持のため古い許可ヒントが保護対象から外れて先入れ先出しで退避される。

#### 残存していた同居ヒント再挿入の解消（`FU-P3-01` 完了）

`merge_domain_hints_prioritized`（[firewall/hints.rs](../crates/ledr-daemon/src/firewall/hints.rs#L45-L88)）の Loop 1（`authorizing_hints`）実行中に `target` から退避した要素を `evicted_in_batch: HashSet<String>` へ記録し、同一バッチの Loop 2（`cohosted_hints`）では `evicted_in_batch` に含まれるヒントの再挿入をスキップするように修正した。
退避が発生しない通常経路では `evicted_in_batch` はヒープ確保を行わずに通過する。

- **境界テスト `FU-P3-01-01`**（[firewall/tests.rs](../crates/ledr-daemon/src/firewall/tests.rs#L2264-L2271)）：満杯 32 件の `target`（`auth0` と `c00`〜`c30`）へ `authorizing_hints = ["auth0", "auth1"]` と `cohosted_hints = ["c00", "c01"]` を渡したとき、`c00` が再挿入されず `c01`〜`c30` の 30 件がすべて保持されることを直接呼び出しおよび `WfpRuleManager::ensure_ip_permit_for_domain_hints_prioritized` 経由で検証した。
- **境界テスト `FU-P3-01-02`**（[firewall/tests.rs](../crates/ledr-daemon/src/firewall/tests.rs#L2277-L2287)）：同じ満杯条件で `cohosted_hints = ["c00", "c99"]` を渡したとき、`c00` は再挿入されず、新規の `c99` だけが `c01` を 1 件押し出して末尾へ追加されることを検証した。
- 既存の `DAEMON-P3-48`、`DAEMON-P3-49A`、保護ヒント 32 件以内の維持、`deny-overrides-allow`、`SEC_0001`、および `SEC_0002` はすべて影響なく維持される。

### 残課題

本件に関するコード上の残課題はない。

## FU-E2E-01 Windows 10 または Windows 11 クライアント SKU での実機 E2E 検証

### 対象ファイルと手順書

- 実機検証手順書（統合版）：[e2e-test-runbook.md](e2e-test-runbook.md)（Track A および Track C）
- 実機検証手順書（Phase 2・3 個別版）：[phase2-3-e2e-runbook.md](phase2-3-e2e-runbook.md)
- Phase 2 の ETW 監視対象：[etw/handlers.rs](../crates/ledr-sensor-win/src/etw/handlers.rs#L45-L48)（プロバイダ GUID）、[etw/session.rs](../crates/ledr-sensor-win/src/etw/session.rs#L598-L610)（購読登録）、[etw/registry.rs](../crates/ledr-sensor-win/src/etw/registry.rs#L18-L39)（`handle_kernel_registry`）、[etw/registry.rs](../crates/ledr-sensor-win/src/etw/registry.rs#L121-L246)（`CloseKey` 無効化を含む `decide_registry_event`）、および [file_canary/mod.rs](../crates/ledr-sensor-win/src/etw/file_canary/mod.rs#L272-L305)（`prefilter_and_classify_canary_u16`）
- Phase 2 のプロセス制御と通知対象：[defense/controller.rs](../crates/ledr-sensor-win/src/defense/controller.rs#L172-L192)（`NtSuspendProcess`）、[defense/controller.rs](../crates/ledr-sensor-win/src/defense/controller.rs#L475-L520)（`terminate_process`）、[notify.rs](../crates/ledr-daemon/src/notify.rs#L109-L255)（`notify_alert_with_session` と `try_launch_in_active_session`）、[apps/ledr-ui/src/cli.rs](../apps/ledr-ui/src/cli.rs#L74-L104)（`parse_launch_mode`）、[apps/ledr-ui/src/uri_reg.rs](../apps/ledr-ui/src/uri_reg.rs#L479-L492)（`ensure_hkcu_ledr_uri_registered`）、および [apps/ledr-ui/src/notify.rs](../apps/ledr-ui/src/notify.rs#L437)（`dispatch_notify_oneshot`）
- Phase 3 の WFP 制御対象：[wfp/backend.rs](../crates/ledr-sensor-win/src/wfp/backend.rs#L129-L172)（`open_dynamic`）と [wfp/backend.rs](../crates/ledr-sensor-win/src/wfp/backend.rs#L626-L647)（`FwpmNetEventSubscribe1` 購読）
- Phase 3 のネットワーク ETW と NRD 対象：[etw/handlers.rs](../crates/ledr-sensor-win/src/etw/handlers.rs#L49-L51)（プロバイダ GUID）、[etw/session.rs](../crates/ledr-sensor-win/src/etw/session.rs#L612-L624)（購読登録）、[nrd/cancel.rs](../crates/ledr-rules/src/nrd/cancel.rs#L62-L86)（`NrdCancelToken` のブロッキング読み取り観測）、[nrd/url.rs](../crates/ledr-rules/src/nrd/url.rs#L98-L135)（`parse_file_url`）、[nrd/reader.rs](../crates/ledr-rules/src/nrd/reader.rs#L15-L114)（`read_bounded_file` と `read_bounded_reader_cancellable`）、[crates/ledr-daemon/src/main.rs](../crates/ledr-daemon/src/main.rs#L449)（`RUST_LOG` による `EnvFilter` 初期化）、[crates/ledr-store/src/lib.rs](../crates/ledr-store/src/lib.rs#L464-L500)（`LedrStore::checkpoint_truncate_with_deadline` の `completed wal_checkpoint(TRUNCATE)` ログ）、[nrd.rs](../crates/ledr-daemon/src/engine/nrd.rs#L18-L26)（`is_nrd_refresh_in_flight` と `nrd_cancel_token`）、[lifecycle.rs](../crates/ledr-daemon/src/engine/lifecycle.rs#L561-L613)（停止時チェックポイント優先と NRD デタッチ、デタッチ警告ログは [L608-L611](../crates/ledr-daemon/src/engine/lifecycle.rs#L608-L611)）、および [pipeline.rs](../crates/ledr-daemon/src/engine/pipeline.rs#L356-L420)（`ledr-nrd-refresh` スレッド）

### 背景と出典

Phase 2 は PR #3（ブランチ `phase-2-canary-suspend`、マージコミット `a68bce5` / `a68bce5eb73922a0ebcfb6c052a430c620050958`）で、Phase 3 は PR #5（ブランチ `phase-3-wfp-firewall`、マージコミット `3fe1031` / `3fe1031fc3692beab77e0eeb531f27e6e56c888e`）で `main` へマージした。
[AGENTS.md](../AGENTS.md) の標準検証コマンド、および [.agents/rules/active-defense-guards.md](../.agents/rules/active-defense-guards.md) と [.agents/rules/daemon-wfp-process-invariants.md](../.agents/rules/daemon-wfp-process-invariants.md) の不変条件の定めにより、OS カーネルや実サービス環境に依存する挙動は合成テストだけでは検証済みとみなさない。

### 現行の保証範囲

#### 確認済み事項

Phase 2 と Phase 3 の実装は静的検査（`cargo clippy --workspace --all-targets --locked -- -D warnings`）、ワークスペース全体の単体および統合テスト（`cargo test --workspace --locked`）、バースト負荷テスト（`burst_budget`）、および TTL 回帰テスト（`ttl_purge_lineage`）に合格して `main` へマージ済みである。

2026 年 11 月 22 日に `Windows 11 Home`（`10.0.26300`、`ProductType = 1`、基盤コミット `9c8373e` に当時未マージだった PR #34 ブランチ `fix/e2e-pipe-dacl-dev-bypass` の Named Pipe DACL 修正を加えた暫定構成）で [e2e-test-runbook.md](e2e-test-runbook.md) のルート 1（全 Phase 統合ルート）を実施し、Track A の以下を確認した。
なお、PR #34（`d8f4e7e`）、`FU-E2E-03` から `FU-E2E-05`（PR #35 `ed9ae3f`、PR #36 `1540a1f`、PR #38 `b8d9c66`、PR #39 `7cdb445`）、および後続の強化 PR（PR #41 `ddfce96`、PR #43 `26ee76b`、PR #44 `c78571c`、PR #45 `dcfb0af`）は現在すべて `main` へマージ済みであり、以下の 2026 年 11 月 22 日の暫定結果は最新 `main` 上で再検証する前提とする。

- **通過項目**：`PREP-01` から `PREP-04`、`E2E-P2-01` から `E2E-P2-06`、`E2E-P3-01`、`E2E-P3-02`、`E2E-P3-04`、`E2E-P3-05`（公開 2 フィード `feeds_succeeded = 2`、`feeds_failed = 0`、`entries = 50000`）、`E2E-P3-07`（`taskkill /F` 後の WFP フィルタ 0 件消去）、および `E2E-UI-01`（0 プロセス終了）が実機で通過した。
- **部分確認項目**：`E2E-P3-06` は `wal_checkpoint(TRUNCATE)` の NRD デタッチ先行完了とマーカー行の永続化のみを確認した（約 3 秒でのシェル復帰と停止後の `-wal == 0` 維持は未達のため全体合格とは区別し、`FU-E2E-05` へ切り出した）。
- **定常 CPU 基準**：`E2E-PERF-01` の定常 CPU 使用率はアイドル 600 秒で `0.2876%`、高負荷 60 秒で `0.3076%` となり、0.5% 未満の基準を満たした。

#### 未検証および残存の課題

- `E2E-PERF-01` の `WorkingSet64` が 20 MB 以下の基準を超過したため、`FU-E2E-03` へ切り出した（PR #39 `7cdb445` で対策と `L-24` 基準併記を `main` マージ済み、最新 `main` 上で最終 E2E 再確認待ち）。
- `E2E-P3-03` の `ledr-sim.exe --scenario lotl`（約 40 ms の短命プロセス）で親子系譜と `example.com` DNS 相関は通過した一方、`command_line` が `None` となり `LEDR-LOTL-001`（正規管理ツール悪用検知ルール）が発火しなかったため、`FU-E2E-04` へ切り出した（PR #35 `ed9ae3f` および PR #36 `1540a1f` で対策を `main` マージ済み、ホスト ETW 競合を解消した環境で最終 E2E 再確認待ち）。
- `E2E-P3-06` で 3 秒停止予算を超過した後に残余パイプラインが 2 件書き込み、終了後の `-wal` に `111,272` バイトが再生成された点（シェル復帰まで計約 8 秒）と、WFP ドロップが終了済み兄弟由来の生存 `python.exe` へ単一帰属された実機エッジケースを `FU-E2E-05` へ切り出した（PR #38 `b8d9c66` で対策を `main` マージ済み、実無応答 UNC 共有下での最終 E2E 再確認待ち）。
- 開発ホスト PC 上での実施のため、専用環境向けの任意項目（`E2E-OPT-01` から `E2E-OPT-03`）は未実施である。
- PR #41 および PR #44 で追加した、生存中の発火元プロセスがおとり発火を起こした際に終了済み非保護中間親越しで生存中の孫プロセスへ `NtSuspendProcess` を適用するライブ動作（`ActiveProcessTable` 経路とスナップショット経路の統合、同一ミリ秒 PID 再利用カットオフ、および保護対象非停止を含む）は合成テストのみで確認しており、Windows 10/11 クライアント SKU の実機 E2E 対象として残している。
- 上記の最新 `main`（PR #34 から PR #45 まで統合済み）上での最終再検証が未実施であるため、[implementation-plan.md](implementation-plan.md) の `[x]` チェックリストは未更新としている（`[x]` 更新は最新 `main` 上の再検証合格後に行う）。

### 検証内容

検証環境は Windows 10 または Windows 11（x86_64）クライアント SKU の管理者昇格セッションを基準とする。
Windows Server SKU で代替検証を行う場合は、クライアント SKU との未検証差異を検証報告へ明記する（[AGENTS.md](../AGENTS.md) 準拠）。

#### Phase 2 実機検証項目

- 実 ETW `Microsoft-Windows-Kernel-File` と `Microsoft-Windows-Kernel-Registry` を購読し、ダミー `Cookies` の Open、おとりファイルへの 1 バイト書込、自動起動レジストリ更新、および `CloseKey` による `KeyObject` キャッシュ無効化が実イベントで動作することを検証する。
- 実 `NtSuspendProcess` で対象プロセスと子孫プロセスを凍結でき、`explorer.exe` などの Never-Suspend 対象が一切停止しないこと、および `TerminateAndBlock` 実行時の子プロセスツリー終了の非同期挙動に破綻がないことを確かめる。
- 生存中の発火元プロセスがおとり発火を起こし（`engine/events.rs` の本番凍結経路）、すでに終了済みの非保護中間親プロセス越しに生存中の孫プロセスへ `NtSuspendProcess` が適用されること、および保護対象プロセスや同一ミリ秒 PID 再利用後の後継プロセス配下が誤停止されないことを確認する（既存のツリー凍結手順である [e2e-test-runbook.md](e2e-test-runbook.md) の `E2E-P2-03` および [phase2-3-e2e-runbook.md](phase2-3-e2e-runbook.md) のセクション 5 は発火前の中間親終了を確認しないため、既存の `E2E-P2-03` 合格記録と区別できるよう、後続の実機検証 PR で専用手順と結果欄を追加して実施する）。
- 機密ファイル Open またはおとりファイル書込の検知と即時サスペンドに続いて、Session 0 の `LocalSystem` サービスから `WTSQueryUserToken` と `CreateProcessAsUser` により `ledr-ui.exe --notify <alert_id>` が対話セッションで起動し、検知から 1 秒以内にトースト通知が表示されること、および `HKCU\Software\Classes\ledr` 登録済みの `ledr://alert/<id>` クリック後 1,000 ms 以内に View 1 が開いて 5 秒以内に強制終了または再開が完了することを確認する。

#### Phase 3 実機検証項目

- 実カーネル BFE へ `FWPM_SESSION_FLAG_DYNAMIC` 付き動的セッションと LocalEDR 専用 SubLayer を登録し、未許可の `ledr-sim` またはスクリプトインタプリタの外部通信が遮断されるとともに該当プロセスが凍結され、View 1 で許可登録した後に再開および通信が成立すること、View 3 でルールの参照と削除ができること、およびデーモン強制終了時に動的フィルタが自動消去されて通信不能にならないことを検証する。
- `FwpmNetEventSubscribe1` による実ドロップイベント捕捉と、実 ETW `Microsoft-Windows-DNS-Client` および `Microsoft-Windows-Kernel-Network` の結合により、解決済みドメイン相関と動的 Permit 維持が動作することを確かめる。
- 応答しない実 UNC パスまたは SMB 共有を `file://` 形式の NRD フィード元（`--nrd-feed-url file://server/share/...`、期限内の `nrd-cache.txt` がない状態）へ指定して起動し、既存の統合テスト `DAEMON-P3-45`（[phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L6868)）と同様に読み取り処理がブロック中であることを確認する。
  停止前の待機確認ではインプロセス検証の `read_bounded_reader_cancellable` 待機時に `DaemonEngine::is_nrd_refresh_in_flight`、`NrdCancelToken::is_blocking_read_active`、および `NrdCancelToken::blocking_read_entries`（1 以上）を確かめ、`File::open` 段階で待機する共有や `ledr-daemon.exe` 単体起動時は `ledr-nrd-refresh` スレッドが I/O 待機中かつ更新完了または失敗ログが未出力であること（インプロセス検証では `is_nrd_refresh_in_flight` が真であること）を確かめる。
  NRD のブロックを確認した後、`DAEMON-P3-45`（[phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L6868)）にならってマーカー用のプロセス起動イベントなどで SQLite WAL への事前書き込みを発生させ、停止実行前に `-wal` ファイルサイズが 0 バイト超（`-wal > 0`）であることを確かめてからデーモン停止を実行する。
  単体バイナリ実行（`ledr-daemon.exe`）では `RUST_LOG=ledr_store=debug,ledr_daemon=info`（[crates/ledr-daemon/src/main.rs](../crates/ledr-daemon/src/main.rs#L449)）付きで起動しておき、3 秒予算内の停止処理で `LedrStore::checkpoint_truncate_with_deadline`（[crates/ledr-store/src/lib.rs](../crates/ledr-store/src/lib.rs#L464-L500)）が出力する時刻付き `completed wal_checkpoint(TRUNCATE)` ログが [lifecycle.rs](../crates/ledr-daemon/src/engine/lifecycle.rs#L608-L611) のデタッチ警告ログ（`shutdown budget exhausted waiting for background NRD refresh thread; detaching thread`）より前の時刻で記録されること、および停止後にマーカー行の永続化、`-wal` の 0 バイト化、`Runtime::drop` の非ハング終了が成立することを検証する。
  インプロセス検証では `DAEMON-P3-45A`（[overflow_and_lifecycle.rs](../crates/ledr-daemon/src/engine/tests/overflow_and_lifecycle.rs#L287)）にならい、`shutdown_and_flush` が `nrd.done_rx` 待機で未完了（`!shutdown_task.is_finished()`）の時点で既に `-wal == 0` であること、復帰直後も `is_nrd_refresh_in_flight` が真であること、マーカー行が永続化されていること、および `Runtime::drop` がハングせず終了することを確認する。

### 対応予定タイミング

Phase 2 と Phase 3 の実機検証をまとめて扱う独立した別 PR で [e2e-test-runbook.md](e2e-test-runbook.md)（Track A および Track C、または [phase2-3-e2e-runbook.md](phase2-3-e2e-runbook.md)）を実施し、確認結果と必要に応じた調整を記録したうえで [implementation-plan.md](implementation-plan.md) の該当する実機 E2E 受け入れ検証項目を `[x]` へ更新して完了とする。
なお、一般パス未知プロセスの初発凍結（`E2E-OPT-01`）、`Program Files` 配置での本番 IPC 認可（`E2E-OPT-02`）、および Session 0 代替起動（`E2E-OPT-03`）は専用 VM 向けの任意項目として扱い、開発ホスト PC 上で未実施の場合は残る未検証差異として本表および PR 本文へ切り分けて記録する。

## FU-E2E-02 Windows 10 または Windows 11 クライアント SKU での Phase 4 実機 Chrome E2E 検証

### 対象ファイルと手順書

- 実機検証手順書（統合版）：[e2e-test-runbook.md](e2e-test-runbook.md)（Track B および Track C）
- 実機検証手順書（Phase 4 個別版）：[phase4-e2e-runbook.md](phase4-e2e-runbook.md)
- ローカル検証用 HTML フィクスチャ：[phase4-browser-test.html](fixtures/phase4-browser-test.html)
- 対象コンポーネント：[crates/ledr-bridge-nm](../crates/ledr-bridge-nm/src/main.rs)、[extensions/ledr-chrome-mv3](../extensions/ledr-chrome-mv3/manifest.json)、[crates/ledr-daemon/src/engine/motw.rs](../crates/ledr-daemon/src/engine/motw.rs)、[apps/ledr-ui/src/defense_status.rs](../apps/ledr-ui/src/defense_status.rs)、および [apps/ledr-ui/ui/app.js](../apps/ledr-ui/ui/app.js)

### 背景と出典

Phase 4 は [decision-records.md](decision-records.md) の `L-17`（3 PR 分割計画）に従い、PR 4A（PR #25、`cf7e866`）、PR 4B（PR #26、`6bb8bd3`）、および PR 4C（PR #28、`331602d`、`apps/ledr-ui` View 1〜3 統合、検証用フィクスチャと手順書、文書同期）の 3 本へ分割した。
実ブラウザ上での Chrome 拡張ロード、実際の Windows レジストリ経由による Native Messaging ホスト起動、実ダウンロードの `:Zone.Identifier` 付与とフォルダ移動後起動の 3 段階紐付け、および WebView2 ウィンドウ閉鎖後の完全終了は、合成ユニットテストでは検証済みとみなさない。

### 現行の保証範囲

#### 確認済み事項

- PR 4A の MOTW 解析（`:Zone.Identifier`）、3 段階紐付け、事前 WFP ブロック、`ReportBrowserEvent`、および `ledr-sim motw-download` の合成テストとワークスペース負荷および TTL 回帰は `main` 上で合格済みである。
- PR 4B の `ledr-bridge-nm`（ゼロパース中継、`SEC_0003` のパイプサーババイナリ検証、`setup`、`status`、`unregister`）と `extensions/ledr-chrome-mv3`（固定拡張 ID `ecelachfiiiiiibpjeomfncgpegbpanh`、ClickFix、NRD とホモグラフ判定、`storage.session` ダウンロード追跡）の Rust および Node テストは `main` 上で合格済みである。
- PR 4C の `apps/ledr-ui`（`HKCU` と `HKLM` 両プローブ、WOW64 32 ビット優先探索、ホワイトリストによるマニフェスト検証、View 1〜3 の表示と操作制約）のうち、Rust 単体テスト（`UI-P4-01` から `UI-P4-04`、`UI-P4-11` から `UI-P4-13`）と JS 構文検査（`node --check`）は PR #28（`331602d`）の CI で合格を確認した。
  PR #28（`331602d`）および PR #29 時点の `static-checks` ジョブは Node テストとして `extensions/ledr-chrome-mv3/tests/*.test.mjs` のみを実行していたため、Node モック DOM テスト（`apps/ledr-ui/js-tests/phase4_ui.test.mjs` の `UI-P4-05` から `UI-P4-10`、`PR27-REG-01`、`CSP-01`）はローカルの Node 22 で別途実行し、PR #28 最終コミット `4513044` の検証記録および PR #29 の再実行（Node `v22.18.0`、8/8 合格）にて合格を確認した。
  現在は `.github/workflows/ci.yml` の `static-checks` ジョブでも `apps/ledr-ui/js-tests/*.test.mjs` を自動実行する構成へ拡張している。
- 2026 年 11 月 22 日に `Windows 11 Home`（`10.0.26300`、`ProductType = 1`、Chrome `157.0.8103.79`、基盤コミット `9c8373e` に当時未マージだった PR #34 ブランチ `fix/e2e-pipe-dacl-dev-bypass` の Named Pipe DACL 修正を加えた暫定構成）でルート 1 の Track B および Track C を実施し、`E2E-P4-00`（`--scope user`、Chrome）から `E2E-P4-07`（`LAYER_4_BROWSER` 6 件すべて `APPROVED_ONCE` へ遷移、`download_origins = 1`、移動後の MOTW 起因事前 WFP 遮断および SHA-256 と Zone 3 の紐付け）と `E2E-UI-01`（`ledr-ui` 1 件から 0 件、`msedgewebview2.exe` 6 件から 0 件）の通過を確認した。
  現在 PR #34（`d8f4e7e`）、PR #39（`7cdb445`）、PR #41（`ddfce96`）等はすべて `main` へマージ済みであり、本暫定結果は最新 `main` 上で再確認する前提とする。

#### 未検証および残存の課題

- `--scope machine` の登録および復元、Microsoft Edge 実ブラウザでの拡張動作確認、および専用環境向けの任意項目（`E2E-OPT-01` から `E2E-OPT-03`）は未実施である。
- Phase 4 機能追加後の常駐性能回帰確認（`E2E-PERF-01`）は `WorkingSet64` 基準を超過したため `FU-E2E-03` へ切り出し、PR #39（`7cdb445`）でメモリ削減と `L-24` 基準併記を `main` へマージ済みである。
  ただし最新 `main`（PR #34 から PR #45 まで統合済み）上での最終再検証が未実施であるため、[implementation-plan.md](implementation-plan.md) の `[x]` チェックリストは未更新としている。

#### 現行の完了基準と将来の見直し論点

- **現行基準**：[e2e-test-runbook.md](e2e-test-runbook.md#L1847-L1848) のルート別完了判定基準では、`--scope machine`（`HKLM` 登録と復元）および Microsoft Edge 実ブラウザでの拡張動作確認は未実施差異として PR 本文へ切り分け記録できる任意扱いとしている。
- **将来の見直し論点**：独立した実機 E2E 検証 PR の着手時にこれらを [implementation-plan.md](implementation-plan.md) の `[x]` 更新必須条件へ引き上げる方針変更を行う場合は、実 `HKLM\SOFTWARE\WOW6432Node\...` への登録と削除および実ブラウザでの Native Messaging 読み込み確認（`FU-P4-01` の実装に対する実機検証）を必須項目へ組み込むかどうかを判断する。

### 対応予定タイミング

PR 4C は PR #28（`331602d`）で `main` へマージ済みであり、PR #34、`FU-E2E-03` から `FU-E2E-05`、および後続の強化 PR（PR #41 から PR #45）もすべて `main` へマージ済みである。
独立した実機 E2E 検証作業として [e2e-test-runbook.md](e2e-test-runbook.md)（Track B および Track C：`L-08` の UI 0 プロセス終了確認および Phase 4 追加後の `E2E-PERF-01` 性能回帰確認、または [phase4-e2e-runbook.md](phase4-e2e-runbook.md)）を最新 `main` 上で再実施し、合否記録をまとめて [implementation-plan.md](implementation-plan.md) の Phase 4 実機 Chrome E2E 検証項目を `[x]` へ更新する。
なお、代替手順書として [phase4-e2e-runbook.md](phase4-e2e-runbook.md) を用いる場合でも、性能の合否は同書記載の旧基準（`PeakWorkingSetMB <= 20.0`）に代えて [e2e-test-runbook.md](e2e-test-runbook.md#L1381) の Track C に定める `L-24` 基準（`PrivateWorkingSetSize <= 20.0 MB` 必須および `WorkingSet64` 監視基準）で判定する。

## FU-P4-01 crates/ledr-bridge-nm の HKLM 登録と確認における 32 ビットビュー対応

### 対象ファイル

- CLI 実装箇所：[setup.rs](../crates/ledr-bridge-nm/src/setup.rs#L136-L2721)（`RegWow64View`、`CHROMIUM_READ_VALUE_MAX_UTF16_UNITS`、`NativeHostRegProbe`、`select_effective_hklm_probe`、`RegistryViewOps`、`win_reg_ops::delete_subkey_tree_idempotent`、`win_reg_ops::exceeds_chromium_raw_limit`、`expand_env_strings_win32`、および `run_setup_with_ops` / `run_unregister_with_ops` / `run_status_with_ops`）
- 単体テスト箇所：[crates/ledr-bridge-nm/src/tests.rs](../crates/ledr-bridge-nm/src/tests.rs#L2703-L4901)（`bridge_19` から `bridge_27`）
- UI 診断注記同期：[defense_status.rs](../apps/ledr-ui/src/defense_status.rs#L109)、[apps/ledr-ui/src/tests.rs](../apps/ledr-ui/src/tests.rs#L2270-L2274)、および [phase4_ui.test.mjs](../apps/ledr-ui/js-tests/phase4_ui.test.mjs#L578-L638)

### 背景と出典

本件は PR #28（ブランチ `phase-4c-ui-browser-integration`、コミット `41f12a0`）に対する Devin Review スレッド `PRRT_kwDOVyjVyM66W9C2`（`apps/ledr-ui` 診断側の `KEY_WOW64_32KEY` 未対応指摘）を一次照合した際に確認した PR 4C 排他範囲外の残件である。
`crates/ledr-bridge-nm` は PR #26（`6bb8bd3`）で `main` へマージ済みのため、PR 4C の排他境界を保って本書へ切り出していた。

### 実装内容と保証範囲

- **WOW64 対象境界の分離**：`KEY_WOW64_32KEY` と `KEY_WOW64_64KEY` の両ビュー操作は `Scope::Machine`（`HKLM`）の Native Messaging Host キー（`CHROME_NMH_SUBKEY`、`EDGE_NMH_SUBKEY`、`BRAVE_NMH_SUBKEY`）に限定し、`Scope::User`（`HKCU`）、`ledr://` URI スキーム（`Software\Classes\ledr`）、AUMID（`Software\Classes\AppUserModelId\LocalEDR.AlertUI`）、およびグループポリシー（`Software\Policies\...`）は従来どおり既定ビューのみを維持した。
- **Win32 明示ビュー削除 FFI**：`winreg::RegKey::delete_subkey_all` が `KEY_WOW64_32KEY` を保持しない罠を避けるため、`advapi32.dll`（`kind = "raw-dylib"`、`modifiers = "+verbatim"`）から `RegOpenKeyExW`、`RegDeleteTreeW`、`RegDeleteKeyExW`、および `RegCloseKey` を直接呼び出して明示ビュー単位で冪等削除する構成とした。
- **3 操作と View 3 の整合**：`status`、`setup --scope machine`、および `unregister --scope machine` を以下のとおり更新した。
  - `status`：`NativeHostRegProbe`（`REG_SZ` および `REG_EXPAND_SZ` の `ExpandEnvironmentStringsW` 展開、未解決環境変数検出 `UnresolvableExpandSz`、Chromium 1,024 UTF-16 単位上限超過と展開 API 失敗を表す `ChromiumReadFallback` を含む）と `select_effective_hklm_probe` を導入し、[defense_status.rs](../apps/ledr-ui/src/defense_status.rs#L1278-L1351) と同じく 32 ビットビュー優先かつ `stops_wow64_fallback()`（`Present`、`EmptyString`、`UnresolvableExpandSz`）成立時は 64 ビットビューを読まずに打ち切り、`ChromiumReadFallback` 時は Chromium と同じく 64 ビットビューへフォールバックする判定を実装して後方互換の任意フィールド `registry_view`（`wow64-32` または `wow64-64`）を出力するようにした。
  - `setup --scope machine`：32 ビットビューと 64 ビットビューの双方へ同一マニフェストパスを冪等登録し、32 ビット側に残存した旧パスや空文字シャドーも修復する（案 A1）。
  - `unregister --scope machine`：両ビューから既存登録パスを収集してサブキーを冪等削除し、共有マニフェスト削除前の参照検査（`any_browser_references_manifest_with`）では最大 32,768 UTF-16 単位まで保守的に展開して `ChromiumReadFallback { resolved_path: Some(..) }` も保護対象に含め（展開失敗や未解決 `REG_EXPAND_SZ` は削除抑止へフェイルクローズ）、ブラウザ別 `manifest_removed` も両ビューの登録パスを照合するようにした。
- **CLI と View 3 における診断境界の違い**：`ledr-bridge-nm status` は `REG_EXPAND_SZ` に対応しつつ、Chromium が持つ 1,024 UTF-16 コード単位の読み取りおよび展開上限を再現しており、`HKLM`（マシン登録）の 32 ビットビュー診断ではトリム前の生値や展開後の値が 1,024 単位を超える場合、または `ExpandEnvironmentStringsW` が失敗する場合に 64 ビットビューへフォールバックする（`HKCU` のユーザー登録は既定ビューのみを読むためフォールバックしない）。
  対照的に、View 3 側の [uri_reg.rs](../apps/ledr-ui/src/uri_reg.rs#L197-L317) は `HKLM` の 32 ビットビュー参照を含む `REG_SZ` 読み取りで 1,024 単位の上限を設けず `ERROR_MORE_DATA` に応じてバッファを動的に拡張し、`REG_EXPAND_SZ` を `MissingOrInvalidType` として扱う。
  そのため、1,024 単位を超えるエントリや `REG_EXPAND_SZ` エントリを含む非標準の環境では CLI と View 3 の診断結果が異なり得るが、標準の `ledr-bridge-nm setup` は短いリテラルの `REG_SZ` パスを書き込むため通常構成では発生せず、View 3 側を揃える調整は必要に応じた将来の任意改善として残している。
- **UI 注記の同期**：[defense_status.rs](../apps/ledr-ui/src/defense_status.rs#L109) の `UNVERIFIED_CUSTOM_MANIFEST_MSG` および関連テストから、CLI `status` が 64 ビット既定ビューのみ参照する旨の旧注記を削除した。
- **非特権自動テスト**：`RegistryViewOps` トレイトと `MockRegistryViewOps` を導入し、`select_effective_hklm_probe` 全境界組み合わせ（`bridge_19`）、`Scope::Machine` の登録、修復、レガシー削除、および他ブラウザ参照保護のモック検証（`bridge_20`）、`Scope::User` 隔離プレフィックス上の実 Win32 FFI 明示ビュー往復回帰（`bridge_21`）、`status` の 32 ビット短絡終了検証（`bridge_22`）、未解決 `REG_EXPAND_SZ` 保護と両ビューカスタムパス個別削除時の `manifest_removed` 検証（`bridge_23`）、隔離 `HKCU` 実 Win32 `REG_EXPAND_SZ` 往復検証（`bridge_24`）、1,024 UTF-16 単位超過時の `status` 64 ビットフォールバックと `unregister` 保護のモック検証（`bridge_25`）、実 Win32 `1,024` UTF-16 境界と `>1,050` 文字 `REG_EXPAND_SZ` 保護検証（`bridge_26`）、ならびにトリム前空白境界と 2,048 バイト非 NUL 終端データの境界検証（`bridge_27`）を追加した。

### 未検証範囲と実機確認先

非特権の単体テストおよびモックレジストリ検証では、Windows 10/11 クライアント SKU の管理者権限下における実 `HKLM\SOFTWARE\WOW6432Node\...` への書込と削除、および実 Chrome / Edge での `HKLM` 経由 Native Messaging 起動は検証済みとみなさない。
これらは後続の統合実機 E2E（`FU-E2E-02`、[e2e-test-runbook.md](e2e-test-runbook.md) の `E2E-P4-00`）にて、`ledr-bridge-nm setup --scope machine` 後の両ビュー登録確認（`reg query HKLM\SOFTWARE\WOW6432Node\...` と `HKLM\SOFTWARE\...`）、`ledr-bridge-nm status --scope machine`、および `ledr-bridge-nm unregister --scope machine` 後の両ビュー消去として実機確認する。
なお、Chrome と Edge は Native Messaging ホスト探索で `HKLM` より `HKCU` を優先するため、`HKLM` 経由の実ブラウザ起動確認では `HKCU` に登録が存在しない状態（`--scope user` 登録前、または一時 `unregister --scope user` 後）で拡張ポップアップの `Ping` 応答を検証する。
また、`ledr-bridge-nm setup` 自体はリテラルの `REG_SZ` パスを書き込むが、既存の `HKLM` エントリに `%LOCALAPPDATA%` や `%USERPROFILE%` などユーザー固有環境変数を参照する `REG_EXPAND_SZ` パスが含まれる場合、`ExpandEnvironmentStringsW` は呼び出し元の昇格シェルが持つ環境変数で解決する。
そのため、実機検証（`FU-E2E-02`）や運用時のクリーンアップでは、管理者シェルで展開された結果がブラウザ実行ユーザーのマニフェストパスと一致するかを確認する。

## FU-E2E-03 E2E-PERF-01 の WorkingSet64 超過に対する原因分析とメモリ削減

### 対象ファイル

- Authenticode ワーカー分離（`Option 2-A` + `案 X`）：[crates/ledr-auth-helper/src/lib.rs](../crates/ledr-auth-helper/src/lib.rs)、[authenticode.rs](../crates/ledr-auth-helper/src/authenticode.rs)、[ffi.rs](../crates/ledr-auth-helper/src/ffi.rs)、[auth_worker.rs](../crates/ledr-daemon/src/engine/auth_worker.rs)、および [binary_inspector.rs](../crates/ledr-daemon/src/engine/binary_inspector.rs)（旧 `crates/ledr-rules/src/allowlist/{authenticode.rs,ffi.rs}` は移行後に削除）
- 永続化接続縮小と保守フック：[crates/ledr-store/src/schema.rs](../crates/ledr-store/src/schema.rs)、[crates/ledr-store/src/lib.rs](../crates/ledr-store/src/lib.rs)、および [pipeline.rs](../crates/ledr-daemon/src/engine/pipeline.rs)
- チャネル、プロセス表、DNS 履歴の縮約：[channel.rs](../crates/ledr-daemon/src/channel.rs)、[process_table.rs](../crates/ledr-daemon/src/process_table.rs)、[dns_history.rs](../crates/ledr-daemon/src/engine/dns_history.rs)、および [outbound.rs](../crates/ledr-daemon/src/engine/outbound.rs)
- 実機メモリプロファイラ：[profile_daemon_memory.ps1](../scripts/profile_daemon_memory.ps1)

### 背景と出典

2026 年 11 月 22 日に実施したルート 1 実機 E2E（[e2e-test-runbook.md](e2e-test-runbook.md)、`E2E-PERF-01`、公開 2 フィード 50,000 件の実 NRD キャッシュ読み込み時、PR #34 暫定構成上の実測）で、Release 版 `ledr-daemon.exe` の `WorkingSet64` が目標上限の 20.0 MB 以下を超過した（`LatestWorkingSetMB = 28.59 MB`、`PeakWorkingSetMB = 108.71 MB`、直後 `PrivateMemorySize64 = 17.15 MB`）。
2026 年 11 月 23 日に PR #38 マージ済み `main`（`b8d9c66`）上で Stage 1 実機プロファイリングを実施し、人間決裁チェックポイント（`B-1` と `B-2`）の承認を得て Track 1a〜1d と Track 2 を実装した（統合コミット `87be6d5`、単位はすべて `1 MB = 1 MiB = 1,048,576` バイト）。
さらに Stage 3 実機再計測で OS 共有ページ（`Shared == 1`）下限による `WorkingSet64 <= 20.0 MB` の物理的達成不能を数値証明した上で、`Track 3` 仕様協議（`PrivateWorkingSetSize <= 20.0 MB` 必須と `WorkingSet64` 監視基準の併記、`決定記録 L-24`）のユーザー承認を受け、PR #39（`7cdb445`）で `main` へマージした（再発防止策のルール昇格は PR #40 `9e4a3a8`）。

### 実装内容（Track 1a〜1d および Track 2）

- **Track 1a（`決定記録 L-22` / `B-1`）**：`crates/ledr-store` の書込専用接続は `PRAGMA cache_size = -2048;`（2 MiB 上限）を維持し、読取専用接続（`reader`）のみ `PRAGMA cache_size = -512;`（512 KiB 上限）へ縮小した。
  また `DaemonEngine` の 60 秒定期保守ティックから `!is_shutdown_requested()` かつ 30 秒以上無アクセス時に限り `shrink_reader_memory_if_idle(30s)`（`PRAGMA shrink_memory`）を実行し、回帰テスト `STORE-MEM-01` を追加した。
- **Track 1b**：`TelemetryRing`（[channel.rs](../crates/ledr-daemon/src/channel.rs)）について、容量 1,024 超過の最終時刻から 30 秒以上経過し、かつキューが空で容量が 1,024 超のときのみ `shrink_to(1024)` を実行し、`L-10` の高優先度 1,024 件ドロップ禁止と 8,192 件再バースト耐性を維持した（`CHAN-MEM-01`）。
- **Track 1c**：`ActiveProcessTable::compact_exited_older_than` で終了 60 秒後の非系譜 5 フィールド（`user_sid`、`motw_referrer`、`motw_frame_url`、`motw_source`、`motw_zone_id`）のみを解放し、親系譜、`evicted_live`、および `EvictedCommandLine::Oversized` を保持した。
  あわせて弱参照 8,192 件上限の `PathInterner`（末端ロック順序 `firewall -> process_table -> path_interner`）と、DNS 履歴および `VerifiedAppWideAllowCache` の文字列インターンと容量縮小を実装した（`PROC-MEM-01`、`DNS-MEM-01`）。
- **Track 1d**：`authenticode_cache` を 512 件上限の `BoundedLruCache` 化し、呼び出しごとのファイル SHA-256 再計算（`SEC_0005`）を維持したまま一時エラー、タイムアウト、およびキャンセルの非キャッシュ化を徹底した（`BIN-MEM-01`）。
- **Track 2（`決定記録 L-23` / `B-2` / `Option 2-A` + `案 X`）**：`WinVerifyTrust` 等の Authenticode 検証を専用軽量バイナリ `crates/ledr-auth-helper`（`Option 2-A`）へ分離した。
  親デーモン側は `FILE_FLAG_OPEN_REPARSE_POINT` と `GetFinalPathNameByHandleW` による同一ディレクトリ閉じ込め、リパースポイントおよびハードリンク（`nNumberOfLinks == 1`）拒否、64 KiB ストリーミング SHA-256 検証、匿名パイプと `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` と `JobObject`（`KILL_ON_JOB_CLOSE`）、15 秒アイドル自己終了、6,000 ms 予算内 1 回自動リトライ、5,000 ms タイムアウト、停止要求時 50 ms 以内中断、30 秒内 3 連続失敗時の 30 秒サーキットブレーカ、および自ワーカー PID 再帰防止を実装した（`AUTH-WORKER-01`、`helper_protocol`）。
  1 回リトライ後も失敗した場合は親プロセス内フォールバックを行わず、フェイルクローズ（`authenticode: None` と警告ログ、`案 X`）で処理する。
- **PE 静的および遅延インポート検証**：`target\release\ledr-daemon.exe`（`7,414,784` バイト）の静的インポート（21 DLL）および遅延ロードインポート（0 件）のいずれにも `wintrust.dll` と `crypt32.dll` が含まれず、`target\release\ledr-auth-helper.exe`（`312,832` バイト）へ完全に分離されたことを実機 PE パーサで確認した。

### Stage 1 と Stage 3 の実機計測比較

同一ホスト（Windows 11 x64、16 論理コア、管理者 PowerShell）、同一の公開 2 フィード 50,000 件 `nrd-cache.txt`（`--disable-nrd-refresh`）、同一起動フラグ（`--foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown`）、および同一手順（600 秒アイドルと 60 秒ブラウザ 5 タブ＋`cargo build --locked` 負荷と 60 秒クールダウン）で比較計測した結果を以下に示す。
なお、Track 1e（`PrivateMemorySize64` が PR #34 実測 `17.15 MB` 比で `-0.6266 MB` かつプロセス増分 0 件のため未発動）と Track 1f（`ledr-daemon.exe` の `MEM_IMAGE` が `3.8750 MB < 4.0 MB` のため未発動）は Stage 1 採否基準の判定に基づき見送った。

| 計測項目（`1 MB = 1 MiB = 1,048,576 B`） | Stage 1 改変前（`b8d9c66`） | Stage 3 改変後（`87be6d5`） | 変化と判定 |
| :--- | ---: | ---: | :--- |
| 600s アイドル定常 `WorkingSet64` 中央値（`t=60..600s`） | `28.7617 MB` | `27.6250 MB` | `-1.1367 MB` |
| 600s アイドル定常 `PrivateWorkingSetSize` 中央値（`t=60..600s`） | `12.1484 MB` | `13.0234 MB` | `+0.8750 MB`（`<= 20.0 MB` 合格、背景通信 `+4,813` vs `+2,747`） |
| 600s アイドル終了時 `LatestWorkingSetMB`（`t=600s`） | `29.6172 MB` | `27.2227 MB` | `-2.3945 MB`（`Shared == 1` 下限により参考値） |
| 600s アイドル終了時 `latest_private_ws_mb`（`t=600s`） | `13.0039 MB` | `12.5508 MB` | `-0.4531 MB`（`<= 20.0 MB` 合格） |
| 600s アイドル `t=60s -> 600s` `PrivateWorkingSet` 増分 | `+1.5586 MB` | `-1.1680 MB` | `-2.7266 MB`（増加から縮小へ反転） |
| 600s アイドル後半前半中央値差（`WS` / `PrivateWS`） | `+0.9062 / +0.8008 MB` | `+0.4375 / +0.3281 MB` | 両方 `<= +1.0 MB` 合格 |
| 600s アイドル区間ピーク `WorkingSet64` | `50.3398 MB` | `43.4648 MB` | `-6.8750 MB` |
| 600s アイドル `AvgCpuPercent` | `0.0723%` | `0.2054%` | `< 0.5%` 合格 |
| 60s 高負荷ピーク `WorkingSet64`（2 秒以降） | `45.1758 MB`（`42.5430 MB`） | `36.9727 MB`（`36.9727 MB`） | `-8.2031 MB`（`< 64.34 MB` 合格） |
| 60s 高負荷ピーク `PrivateWorkingSetSize` | `28.5625 MB` | `22.2734 MB` | `-6.2891 MB` |
| 60s 高負荷 `AvgCpuPercent` | `0.5475%` | `0.5952%` | `+0.0477%`（`< 1%` 負荷基準内かつ環境変動範囲） |
| `>= 100.0 MB` スパイク回数（全区間） | `0` 回 | `0` 回 | 合格 |
| クールダウン終了時 `PrivateWS` 対定常残留 | `+2.4102 MB`（`14.5586 MB`） | `+1.2852 MB`（`14.3086 MB`） | `< +2.0 MB` 合格 |
| `Shared == 1`（OS 共有ページ下限） | `16.49–16.65 MB` | `14.5117–14.6992 MB` | 約 `1.95 MB` 低減も 20 MB 下限を物理制約 |
| アイドル時 `authenticode_dlls` 占有量 | `1.3906–1.3984 MB` | `0.2969–0.3125 MB` | `-77.7%`（`wintrust.dll` と `cryptnet.dll` 消滅） |
| Authenticode 起因 `MEM_MAPPED` ピーク | `10.0000 MB` | `0.0000 MB` | `-10.0000 MB`（`100%` 解消） |

### Track 2 実機レイテンシと Windows 11 Authenticode 一致確認

- **キャッシュヒット（SHA-256 ファイル I/O 除く `Mutex<BoundedLruCache>` 512 件、n=10,000）**：平均 `0.000139 ms`、p50 `0.000100 ms`、p95 `0.000200 ms`、最大 `0.011400 ms`（基準 `< 5 ms` 合格）。
- **ワーカーミス（温態常駐 `ledr-auth-helper.exe`、Windows 11 バイナリ 31 件）**：最小 `5.262 ms`、中央値 `6.973 ms`、平均 `8.061 ms`、p95 `11.050 ms`、最大 `33.075 ms`（基準 `< 150 ms` p95 合格）。
- **ワーカーミス（冷態プロセス起動込み 12 回）**：最小 `35.814 ms`、中央値 `38.747 ms`、平均 `40.666 ms`、p95 `59.785 ms`、最大 `59.785 ms`（基準 `< 300 ms` p95 合格）。
- **Windows 11 Authenticode 判定一致（31 件）**：29 件は `Get-AuthenticodeSignature`＋`X509Chain` と `signer_subject` および `root_thumbprint` が完全一致し、デュアル署名の 2 件（`svchost.exe`、`wininit.exe`）も `[X509Certificate2]` で埋め込み署名（`CN=Microsoft Windows Publisher`、ルートサムプリント `3b1efd3a66ea28b16697394703a72ca340a05bd5`）が `WinVerifyTrust(WTD_CHOICE_FILE)` 優先の旧実装と一致し、不一致は `0` 件だった。

### Track 3 数値証明と仕様改定（`決定記録 L-24`）

Stage 3 の全 34 スナップショット（`QueryWorkingSetEx` 失敗チャンク 0 件）において、`Shared == 1` ページ合計は **`14.5117–14.6992 MB`** で推移した（内訳は `other_os_dlls` `s1 = 9.55–9.65 MB`、`ledr-daemon.exe` `s1 = 3.97–4.05 MB`、`other_mapped` `0.46–0.47 MB`、`wtsapi32.dll` が静的参照する `crypt32.dll` `s1 = 0.25–0.27 MB`、`MpOAV.dll` `s1 = 0.23 MB`、SQLite 共有マップ `0.03 MB`）。
実測最小の `PrivateWorkingSetSize`（`10.6602 MB`）と最小の `Shared == 1` 下限（`14.5117 MB`）を合算しても `25.1719 MB > 20.0 MB` となり、総 `WorkingSet64 <= 20.0 MB` を達成するには 50,000 件の `NrdCache`、2 レーンチャネル、`ActiveProcessTable`、SQLite WAL、および Sigma Aho-Corasick を抱えたまま `PrivateWorkingSetSize <= 5.33–5.49 MB` を恒常維持する必要があり、物理的に達成不能であると数値証明された。
これを受け、2026 年 11 月 23 日の人間決裁で [implementation-plan.md](implementation-plan.md)、[decision-records.md](decision-records.md)（`L-24`）、および [e2e-test-runbook.md](e2e-test-runbook.md) へ **`PrivateWorkingSetSize <= 20.0 MB`（必須）＋ `WorkingSet64` スパイクおよび単調増加監視基準** を併記する改定を承認した。

### 実機運用注記、制約、および検証範囲の区分

- **Cargo ハードリンク運用注記**：`target\release\ledr-auth-helper.exe` は Cargo ビルドキャッシュとハードリンクされており `nNumberOfLinks == 2` を持つため、`nNumberOfLinks == 1` 検査を維持したまま Release 版を直接起動する場合は別ディレクトリへ `Copy-Item` ステージング（`Links = 1`）して起動する（[e2e-test-runbook.md](e2e-test-runbook.md) 第 5 章へ追記済み）。
- **実機機能回帰とホスト ETW 競合制約**：`87be6d5` 上のステージングバイナリで `E2E-P4-07`（PASS、Live IPC と UI モック DOM テスト `10/10`）と 3 秒停止予算（`377.05 ms` および `393.19 ms`、`WAL = 0`、`CLEAN-01` PASS）を確認した。
  一方、`E2E-P3-01` と `E2E-P3-03` は WFP フィルタ、通信遮断、事前凍結済み `python.exe` への `WfpDrop` と `NtSuspendProcess`、および `DnsQuery` と `NetworkConnect` を確認したものの、検証ホスト上で `AcePldTraceSession_28364` と 2 本の `NT Kernel Logger` が稼働していた影響により LocalEDR 停止下の独立 `logman` 測定でも `Microsoft-Windows-Kernel-Process` `0x10` が `0` イベントとなり、起動後 `ProcessStart` 帰属のみ未確認の「部分 PASS（ホスト ETW 0 イベント制約付き）」となった（`main` マージ後の最終 E2E 検証対象）。
- **`.github/workflows/ci.yml` 自動実行範囲（PR #39 で検証済み）**：`changes` ジョブは `Cargo.toml`、`Cargo.lock`、`crates/`、`docs/implementation-plan.md`、`docs/decision-records.md` の変更により `rust=true` かつ `web=true` と判定し、`static-checks`（`ubuntu-latest`、Node 22：`node --check`、Chrome MV3 拡張テスト 19 件、Tauri UI モック DOM テスト 10 件、固定拡張 ID 検証、および JSON、UTF-8、U+FFFD、競合マーカー検査）と `rust-windows`（`windows-latest`：`cargo check`、`clippy -- -D warnings`、`cargo test --workspace --locked`、`burst_budget`、`ttl_purge_lineage`、`cargo doc -D rustdoc::broken_intra_doc_links`）を実行した。
- **ローカルでも再実行した CI 相当項目（Windows 11 x64 環境で PR #39 の `87be6d5` に対し実行済み）**：`cargo clippy`、`cargo test --workspace --locked`（415 件合格）、`burst_budget`（11 件合格）、`ttl_purge_lineage`（12 件合格）、Chrome 拡張 Node テスト（19 件合格）、および UI モック DOM テスト（10 件合格）。
- **CI 対象外のローカル別途実行範囲（Windows 11 x64 環境で PR #39 の `87be6d5` に対し実行済み）**：`python scripts/test_check_invariants.py`（8 件合格）、`cargo build --release --locked` と PE インポート検査（`wintrust.dll` と `crypt32.dll` が 0 件）、`scripts/profile_daemon_memory.ps1` による Stage 1 および Stage 3 実機計測、Track 2 実機レイテンシと `31/31` Authenticode 一致確認、および実機 E2E 回帰（`E2E-P3-01`、`E2E-P3-03`、`E2E-P4-07`、3 秒停止予算）。

### 対応予定タイミング

PR #39（`7cdb445`）を含む `FU-E2E-03` から `FU-E2E-05`、PR #34、および後続の強化 PR（PR #41 から PR #45）はすべて `main` へマージ済みである。
最新 `main` 上の最終実機 E2E（`FU-E2E-01`、`FU-E2E-02`、およびホスト ETW 競合を解消した状態での `E2E-P3-01` と `E2E-P3-03` を含む）で再確認した上で、[implementation-plan.md](implementation-plan.md) の `[ ]` チェックリストを更新する。

## FU-E2E-04 短命プロセスでの PEB 補完欠落による command_line 欠落と LEDR-LOTL-001 未発火

### 対象ファイル

- ETW ProcessStart と相関処理：[handlers.rs](../crates/ledr-sensor-win/src/etw/handlers.rs#L197-L345)（`build_process_start_event`）および [L621-L668](../crates/ledr-sensor-win/src/etw/handlers.rs#L621-L668)（`dispatch_process_start_with_correlator`）
- 補助システムロガー起動とロールバック：[session.rs](../crates/ledr-sensor-win/src/etw/session.rs#L415-L539)（`AuxStartupGuard` と `stop_with_mode`）
- 有界双方向相関器：[cmdline_correlator.rs](../crates/ledr-sensor-win/src/etw/cmdline_correlator.rs#L1-L45)（`ProcessCommandLineCorrelator`）
- ライブプロセス PEB 参照：[process.rs](../crates/ledr-sensor-win/src/etw/tdh/process.rs#L92-L167)（`inspect_process_by_pid`）
- 退避プロセス保持と起動時防御分離：[process_table.rs](../crates/ledr-daemon/src/process_table.rs#L250-L284)（`evicted_exited`）および [events.rs](../crates/ledr-daemon/src/engine/events.rs#L797-L860)（`apply_process_launch_guards` と `skip_launch_guards`）
- 事前 WFP ブロック定期スイープ（PR #36）：[manager.rs](../crates/ledr-daemon/src/firewall/manager.rs#L343)（`sweep_unused_preemptive_blocks`）および [pipeline.rs](../crates/ledr-daemon/src/engine/pipeline.rs#L519)（`run_periodic_expiry_and_sweep`）

### 背景と出典

2026 年 11 月 22 日に実施したルート 1 実機 E2E の `E2E-P3-03`（`ledr-sim.exe --scenario lotl`、初回および再試行の計 2 回、当時未マージだった PR #34 ブランチ `fix/e2e-pipe-dacl-dev-bypass` 上での暫定実測）で、親子系譜（`powershell.exe` から `ledr-sim.exe`、`cmd.exe`、`powershell.exe` への連鎖）は記録された一方、`command_line` が欠落して `LEDR-LOTL-001`（難読化 PowerShell 等の正規管理ツール悪用を検知する Sigma ルール）が発火しなかった。
本件は PR #35（`ed9ae3f`）およびフォローアップ PR #36（`1540a1f`）で実装を `main` へマージし、再発防止策を PR #37（`fac1022`）で恒久ルール文書へ昇格した。

### 課題発生時の実測値と原因（Step 1 調査結果）

- 2026 年 11 月 22 日の `e2e.db` 確認で、短命終了した `ledr-sim.exe`（初回 PID `31720`、再試行 PID `32996`、生存時間約 40 ms）、`cmd.exe`（PID `19680`）、および `powershell.exe`（PID `31672`）の `command_line` がいずれも `None` であり、`LEDR-LOTL-001` アラートが 0 件となった。
- 一方、60 秒間待機した `E2E-P3-01` の `powershell.exe`（PID `17296`）では `Command Line` が欠落せず取得できた。
- Windows 11 Build 26300 上の `Microsoft-Windows-Kernel-Process` マニフェスト（イベント 1 version 0 から 4 を含む全体）には `CommandLine` フィールドが存在せず、`EVENT_TRACE_PROPERTIES.FlushTimer = 1` 秒がリアルタイムモードの最小値であるため、配送遅延の間に終了した短命プロセスでは `OpenProcess` と `NtQueryInformationProcess` によるライブ PEB 補完が間に合わなかった。
- また Windows 11 Home 既定では監査イベント 4688（`ProcessCreationIncludeCmdLine_Enabled`）が未設定であり、`NT Kernel Logger` も稼働済みであったため、ユーザー空間限定（`L-01`）かつ OS 監査設定無変更でカーネル採取済み `CommandLine` を取得できる候補 B の補助システムロガー併用を採用した。

### 採用方針と実装内容（PR #35 および PR #36 で `main` マージ済み）

- **補助システムロガーの先行起動とグレースフルフォールバック（PR #35）**：主 ETW セッションの `StartTraceW` および `EnableTraceEx2` より先に `{session_name}-SysProc`（`EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE`、`EVENT_TRACE_FLAG_PROCESS`、`FlushTimer = 1`、`ClientContext = 2`）を起動し、主セッション起動失敗時は `AuxStartupGuard` で補助セッション停止とコンシューマスレッド `join()` をロールバックする。
  補助セッションのシステムロガー 8 枠上限（`ERROR_NO_SYSTEM_RESOURCES = 1450`）等の起動失敗時は `aux_active = false` として既存主セッションと PEB 補完のみの構成へフォールバックし、通常停止時は主セッションを先に停止して `join()` した後に補助セッションを停止する。
- **有界双方向相関と起動時防御分離（PR #35）**：`ProcessCommandLineCorrelator`（件数上限 2,048 / 1,024、総バイト予算 4 MiB、単一 PID 上限 16、単調時計 15 秒 TTL、UTF-8 境界切り詰め 32,768 バイト）で PID、`parent_pid`、`[-500ms, +5000ms]` 閉区間、および画像ベース名の一致を照合する。
  デーモン側では `ActiveProcessTable` へ容量退避済み終了プロセスの `evicted_exited`（上限 1,024、4 KiB 超は `EvictedCommandLine::Oversized`）を追加し、遅延 `command_line` 補完時は `skip_launch_guards == true` により Sigma 再評価と SQLite 更新のみを実行して重複 WFP ブロック投入を防ぐ。
- **未使用 Preemptive WFP ブロック定期スイープと `try_lock` 化（PR #36）**：`WfpRuleManager::sweep_unused_preemptive_blocks`（削除失敗ハンドル `pending_preemptive_removals` のみを対象とし、通常時は `O(1)` 高速パス、`firewall -> process_table` ロック順序、2 の累乗バックオフ警告間引き）を `pipeline.rs` の Tier 2c（テレメトリ処理前、停止要求後は抑止）へ配置し、関連回帰テストへ期限付き `try_has_active_wfp_filter` を導入した。

### 検証結果と未検証範囲

- **ローカル自動検証（PR #35 `317836a` および PR #36 `e5c8312` 時点）**：PR #35 で `cargo clippy --workspace --all-targets --locked -- -D warnings`、ワークスペース全体テスト 376 件、`burst_budget` 11 件、`ttl_purge_lineage` 10 件、および `invariant-gate`（85 ルール）に合格した。
  続く PR #36 ではワークスペース全体テスト 381 件（新規単体テスト 2 件と結合テスト `DAEMON-P4-CMD-09`、`DAEMON-P4-CMD-10`、`try_has_active_wfp_filter_times_out_when_firewall_lock_is_held` を含む）、`burst_budget` 11 件、`ttl_purge_lineage` 10 件、および `invariant-gate`（87 ルール）に合格した。
- **Windows 11 実機検証（PR #35 初版実装、Build 26300 / x86_64）**：`E2E-P3-03`（`ledr-sim.exe --scenario lotl`）で `ledr-sim.exe`（PID `28988`）、`cmd.exe`（PID `27724`）、および `powershell.exe`（PID `23432`）の 3 プロセスすべてで完全な `command_line` と `exited_at_ms` が `e2e.db` へ保存され、`LEDR-LOTL-001`（Cmd Spawning Encoded PowerShell）が `23432:134398166832334507` に対して発火すること、および Release 版 `ledr-daemon.exe` の 60 秒アイドル計測で `AvgCpuPercent = 0.0212%` となることを確認した。
- **未検証範囲（最新 `main` 上の実機 E2E 対象）**：補助 ETW セッション先行起動および主セッション起動失敗時のカーネルロールバック（フォールバック後に `logman query -ets` で補助セッション残留 0 件であること）、実 BFE での WFP 削除失敗時スイープ挙動、および PR #39 のホスト ETW 競合制約（`AcePldTraceSession_28364` 等による 0 イベント事象）を解消した環境での最新 `main` 上 `E2E-P3-03` 再確認は、最終実機 E2E 検証対象として残している。

### 対応予定タイミング

PR #35、PR #36、および PR #37 はすべて `main` へマージ済みのため、今後は最新 `main` 上の最終実機 E2E（ホスト ETW 競合を解消した環境での `E2E-P3-03` および補助セッションロールバック確認を含む）で再確認する。

## FU-E2E-05 WFP ドロップ誤帰属抑止と停止予算超過時の残余書き込み整理

### 対象ファイル

- OS 実プロセス生存照会：[snapshot.rs](../crates/ledr-sensor-win/src/etw/snapshot.rs#L45-L120)（`find_other_live_processes_for_exe_key`）および [process.rs](../crates/ledr-sensor-win/src/etw/tdh/process.rs#L171-L215)（`inspect_process_basic_by_pid`）
- WFP ドロップ帰属と猶予制御：[wfp_drops.rs](../crates/ledr-daemon/src/engine/wfp_drops.rs#L994-L1060)（`handle_wfp_drop_event_now`）、[process_table.rs](../crates/ledr-daemon/src/process_table.rs#L1049-L1109)（`candidates_by_exe_key_for_wfp`）、および [dns_history.rs](../crates/ledr-daemon/src/engine/dns_history.rs#L59-L378)（`recent_exe_ip_resolvers`）
- 停止時ドレイン打ち切りと WAL 制御：[binary_inspector.rs](../crates/ledr-daemon/src/engine/binary_inspector.rs#L36-L485)（`inspect_cancellable` と `WindowsLiveProcessInspector`）、[lifecycle.rs](../crates/ledr-daemon/src/engine/lifecycle.rs#L465-L625)（`shutdown_and_flush`）、および [crates/ledr-store/src/lib.rs](../crates/ledr-store/src/lib.rs#L464-L515)（`checkpoint_truncate_with_deadline`）
- 関連する回帰テスト：[wfp_attribution_and_shutdown.rs](../crates/ledr-daemon/src/engine/tests/wfp_attribution_and_shutdown.rs#L119)（`DAEMON-P3-51` 等）および [phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L8926)（`DAEMON-P3-50`、`53`、`54`、`55`、`56`）

### 背景と出典

2026 年 11 月 22 日に実施したルート 1 実機 E2E（当時未マージだった PR #34 ブランチ `fix/e2e-pipe-dacl-dev-bypass` 上での暫定実測）において、Track B 中にローカル HTTP サーバの `python.exe` が凍結した事象と、`E2E-P3-06` の停止時に `-wal` が再生成された事象の 2 点を観測した。
本件は PR #38（`b8d9c66`）で両課題の修正と回帰テストを `main` へマージした。

### 課題発生時の実測値（2026 年 11 月 22 日暫定実測）

- **WFP ドロップ帰属**：`E2E-P4-03` と `E2E-P4-04` の実行中、ローカル HTTP サーバ用の `python.exe`（PID `17004`）が、背景で動いて終了した別 `python.exe` インスタンス由来の `2001:4860:4840:400:::443` 宛てドロップによって単一生存候補と判定され、`NtSuspendProcess` で凍結された。
  `WfpDropEvent` 自体は OS 仕様上 PID を持たず実行ファイル単位で帰属するため、短命の兄弟プロセスが直前に終了して同一 `exe_key`（正規化済み実行ファイルパス識別子）の生存候補が 1 件だけ残った場合に他インスタンスへ帰属される状態だった。
- **停止時残余書き込み**：`E2E-P3-06`（`nrd_hang.db`）で `Ctrl+C` 受信後 3 秒の予算内に `completed wal_checkpoint(TRUNCATE)` と NRD スレッドのデタッチまでは完了したものの、予算超過により切り離されたパイプラインタスクがデタッチ直後に 2 件のアウトバウンド観測を書き込み、シェル復帰まで計約 8 秒かかり、終了後の `nrd_hang.db-wal` に `111,272` バイトが再生成された。

### 採用方針と実装内容（PR #38 で `main` マージ済み）

- **課題 1（WFP ドロップ誤帰属の抑止）**：Toolhelp32 の `szExeFile` 事前絞り込みと `PROCESS_QUERY_LIMITED_INFORMATION` のみによる `find_other_live_processes_for_exe_key`（`WindowsLiveProcessInspector`、`main.rs` では `wfp_drop_live_sibling_os_check = true`）をロック非保持下で実行し、BFE 先着かつ ETW 遅延中の並行生存兄弟を検出するようにした。
  さらに `candidates_by_exe_key_for_wfp` へ `entries`、`evicted_live`、および `evicted_exited` を統合（`recent_exit_window_ms` 既定 `1,000 ms`、`WFP_DROP_LATE_SIBLING_CREATE_SKEW_MS = 250 ms`）し、`recent_exe_ip_resolvers`（既定 `10,000 ms`）による他インスタンス宛先 DNS の負例相関と、`AttributionGrace`（`main.rs` では `1,200 ms`）による ETW 帰属安定化猶予を組み合わせた。
  また複数候補時の 60 秒鮮度窓（`AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS = 60_000`）の対称性、および単一悪性プロセスの初回外部接続凍結を維持した。
- **課題 2（停止予算超過時の残余書き込み停止と WAL 0 バイト維持）**：64 KiB チャンク単位で中断できる `BinaryInspector::inspect_cancellable`（停止時はコールド検査をスキップ）と `signal_early_shutdown()` を追加し、`shutdown_and_flush` では予算超過時に `shutdown_drain_cutoff` 通知および `h.abort()` により停止時凍結と新規 WFP ブロックを抑止するようにした。
  その上でエンジン専用の `store_write_gate` を閉じて他ロック非保持下で `checkpoint_truncate_with_deadline` を実行した後に、`NrdThreadHandle` の非ブロッキング待機およびデタッチへ進む順序へ統一し、停止後の `-wal` 再生成を遮断した（起動時は `store.clear_shutdown_flag()` で `LedrStore` 再利用性を維持）。

### 検証結果と未検証範囲

- **ローカル自動検証（PR #38 時点）**：`cargo clippy --workspace --all-targets --locked -- -D warnings`、ワークスペース全体テスト 398 件（新規回帰テスト `DAEMON-P3-50` から `DAEMON-P3-55` を含む）、`burst_budget` 11 件、`ttl_purge_lineage` 10 件、`cargo doc`（警告 0 件）、および `invariant-gate`（94/94 ルール）に合格した。
- **実機停止予算の回帰実測（PR #39 Stage 3、`87be6d5`）**：ステージングバイナリでの 3 秒停止予算計測は `377.05 ms` および `393.19 ms` で完了し、`WAL = 0` および `CLEAN-01` 合格を確認した。
- **未検証範囲（最新 `main` 上の実機 E2E 対象）**：実 BFE カーネルの `FwpmNetEventSubscribe1` 実ドロップ配送、実 ETW 遅延と Toolhelp32 実スナップショット照合（`E2E-P3-01`、`E2E-P3-02`）、実無応答 UNC または SMB 共有に対する `E2E-P3-06` の即時回復と `-wal` 0 バイト維持、および実 Chrome 拡張との連携（`E2E-P4-03`、`E2E-P4-04`）は、最新 `main` 上の最終実機 E2E 検証対象として残している。

### 対応予定タイミング

PR #38 は `main` へマージ済みのため、今後は最新 `main` 上の最終実機 E2E（実無応答 UNC 共有での `E2E-P3-06` および `E2E-P4-03` と `E2E-P4-04` を含む）で再確認する。

## FU-P5-01 Release ドライランおよび Security Audit ワークフロー手動検証と残余実機対象

### 対象ファイル

- リリースワークフロー：[.github/workflows/release.yml](../.github/workflows/release.yml#L163-L224)（`Ensure NSIS (makensis) is installed`）
- セキュリティ監査ワークフロー：[.github/workflows/security.yml](../.github/workflows/security.yml#L1-L25)（`cargo audit`）
- リリーススクリプト単体テスト：[scripts/test_release_scripts.py](../scripts/test_release_scripts.py#L684-L692)（`test_rel_08`）および [L1249-L1433](../scripts/test_release_scripts.py#L1249-L1433)（`test_rel_11`）
- 依存関係定義：[Cargo.toml](../Cargo.toml#L36) および [Cargo.lock](../Cargo.lock)
- ストレージ診断：[crates/ledr-store/src/diagnostics.rs](../crates/ledr-store/src/diagnostics.rs#L4-L28)（`MAIN_DB`）
- 運用ランブック：[release-runbook.md](release-runbook.md#L70-L95)

### 背景と初回手動検証での障害（PR #49 マージ後 `877a472`）

PR #49 の `main` マージ後に `Release`（`dry_run: true`, Run `#45512573149`）および `Security Audit`（Run `#45512576612`）を `workflow_dispatch` で初めて実機実行したところ、両ワークフローが失敗した。

- **`Release` の失敗（Run `#45512573149`）**：`Ensure NSIS (makensis) is installed` で `choco install nsis -y --no-progress` が Chocolatey V2 フィードから `504 (Gateway Timeout)` を受けて 0 パッケージのまま終了コード `0` で抜けた。
  導入後の `makensis.exe` 実在確認がなかったため、後続の Rust テストと `--release` ビルド（約 23 分）を経過した後の `Compile NSIS Windows installer` で `makensis` 未認識エラーとなった。
- **`Security Audit` の失敗（Run `#45512576612`）**：`Cargo.lock` の 456 クレートに対し `cookie 0.18.2`（`RUSTSEC-2026-0594`）、`libsqlite3-sys 0.30.1`（`RUSTSEC-2026-0459`）、および `url 2.5.8`（`RUSTSEC-2026-0592`）の脆弱性 3 件と、`tokio 1.53.2`（`RUSTSEC-2026-0386`）を含む警告 4 件が検出された。

### PR #51（`10e357f`、`main` マージ済み）での対処内容

- **NSIS 導入のフェイルファスト化と動作回帰テスト**：`.github/workflows/release.yml` の `Ensure NSIS (makensis) is installed` へ `Resolve-MakeNsis`（`PATH` および候補パス検索）、Chocolatey 最大 3 回リトライ、未導入時の `winget install --id NSIS.NSIS` フォールバック、導入後の `makensis.exe` 実在確認と `& $makensisPath /VERSION` 検証を追加し、未導入時は終了コード `1` で即座に停止するようにした。
  あわせて `scripts/test_release_scripts.py` に `test_rel_11_ensure_nsis_retry_fallback_and_fail_fast` を追加し、モック `choco`（終了コード `0` で未生成）とモック `winget` を使って `powershell.exe` と `pwsh` の双方でリトライ、`winget` フォールバック、`PATH` 外候補パスの `GITHUB_PATH` 登録、および即停止を検証した。
- **依存更新とライセンス確認（`L-01`）**：`Cargo.toml` の `rusqlite` を `0.32` から `0.43`（`rusqlite 0.43.0` / `libsqlite3-sys 0.40.0`）へ更新し、`crates/ledr-store/src/diagnostics.rs` の `DatabaseName::Main` を `rusqlite::MAIN_DB` へ移行した。
  あわせて `cookie` を `0.18.3`、`url` を `2.5.9`、`tokio` を `1.53.3` へ更新し、`cargo metadata` により追加および更新された 9 クレートすべてが `MIT` または `MIT OR Apache-2.0` であることを確認した。

### マージ後 `main`（`10e357f`）上での最終手動検証結果

CI 自動実行とローカル別途実行および手動 `workflow_dispatch` 実行の範囲を区別した検証結果は次のとおりである。

- **PR #51 時点の CI 自動実行範囲（`.github/workflows/ci.yml`, コミット `aadc918`, Run `#45532586790`）**：`changes`、`static-checks`（Node 22 テスト 19 件 + 18 件および Python 検査）、`windows-packaging-tests`（Windows 上の Python `test_release_scripts.py` 11 件、`test_check_invariants.py` 8 件、`release_verify.py preflight`）、`rust-windows`（`cargo check`、`clippy`、`cargo test --workspace --locked`、`burst_budget`、`ttl_purge_lineage`、`cargo doc`）、および `ci-gate` の 5/5 ジョブに合格した。
- **ローカル別途実行範囲（Windows 11, `rustc 1.100.0`, Node 22）**：コミット `129e019` 時点で `cargo test --workspace --locked`（28 スイート、520 passed / 0 failed）、`burst_budget`（12 passed）、`ttl_purge_lineage`（12 passed）、`cargo clippy`、`cargo doc`、Chrome MV3 テスト（19 passed）、Tauri UI テスト（18 passed）、および `cargo metadata` ライセンス走査を実施して合格し、最終コミット `aadc918` 時点で `test_release_scripts.py`（11 passed）、`test_check_invariants.py`（8 passed）、および `release_verify.py preflight` の再実行合格を確認した。
  ローカル環境には `makensis` と `cargo-audit` が未導入のため、両ツールの実動作検証は下記の `workflow_dispatch` 手動実行で補完した。
- **マージ後 `main`（`10e357f`）上の `Security Audit`（`workflow_dispatch`, Run `#45557335593`）**：`cargo audit` が 454 クレートを検査し、**脆弱性 0 件**（exit code `0`）で合格した。
  残る許可警告 3 件は Tauri 上流および Linux GTK 依存に由来する `chrono 0.4.45`（`RUSTSEC-2026-0543`、`unmaintained`）、`proc-macro-error 1.0.4`（`RUSTSEC-2024-0370`、`unmaintained`）、および `glib 0.18.5`（`RUSTSEC-2024-0429`、`unsound`、Windows ビルド未使用）である。
- **マージ後 `main`（`10e357f`）上の `Release`（`workflow_dispatch`, `dry_run: true`, Run `#45557332849`）**：`preflight`（5 秒、出力 `tag=v0.1.0`, `version=0.1.0`, `dry_run=true`）と `build`（20 分 13 秒、`makensis v3.13` 導入確認、NSIS 生成、一時鍵 `dry-run-test` 署名、`verify-dist`、`release-dist` アップロード）が成功し、`publish` はスキップされ、GitHub Release が作成されないことを確認した。
  取得した `release-dist` の 6 点について、配布本体 3 点（`LocalEDR-Setup-v0.1.0-win-x64.exe` `4,941,467` bytes、`LocalEDR-v0.1.0-win-x64.zip` `7,029,060` bytes / 8 エントリ、`LocalEDR-chrome-ext-v0.1.0.zip` `25,248` bytes / 13 エントリ）は SHA-256 再計算値と `SHA256SUMS.txt`（`291` bytes）の記載値が全件一致することを確認した。
  あわせてメタデータおよび署名 2 点について、`update-manifest.json`（`859` bytes）の各項目（`version=0.1.0`、`tag=v0.1.0`、インストーラの `sha256` と `size_bytes`、および `chrome_extension` の `extension_id=ecelachfiiiiiibpjeomfncgpegbpanh` と `sha256`）が実ファイルと一致すること、ならびに `update-manifest.json.sig`（`191` bytes）が非空の署名形式（`key_id=dry-run-test`、`algorithm=ed25519`）であり `build` ジョブ内の `release_verify.verify_dist` で一時公開鍵による署名検証を通過していることを確認した。

### 未検証範囲と対応予定タイミング

- `publish` ジョブ本体（`gh release create --draft`、2 段階アップロード、公開切替の原子的順序 `L-27`）は `dry_run: true` の対象外であり、本番タグ（`vX.Y.Z`）発行と `LEDR_UPDATE_SIGNING_PRIVATE_KEY` 登録時の初回本番リリースで検証する。
- ドライラン時の `ledr-ui.exe` はコンパイル時にリポジトリの `packaging/update-public-keys.json` を埋め込むため一時鍵 `dry-run-test` を信頼せず、本番署名鍵を用いた実更新の検証と適用は本番リリース前後に実機で確認する。
- Windows 10 または Windows 11 クライアント SKU 実機での NSIS インストーラ導入、アップグレード、およびアンインストール（`uninstall.ps1` のおとり掃除とサービス停止を含む）は、`FU-E2E-01` および `FU-E2E-02` とあわせて実機検証する。
- Tauri 上流依存に由来する残余許可警告 3 件（`chrono`、`proc-macro-error`、`glib`）は、週次 `Security Audit` スケジュール（`security.yml`）と今後の Tauri マイナーおよびメジャー更新追従で監視を継続する。

## FU-R0-01 Phase R0 ビルドおよび CI 最適化ベースライン計測記録

### 目的と検証範囲の区分

本節は、LocalLightEDR の自動リリースビルドおよび CI 所要時間短縮（Phase R1 から Phase R3）における比較基準（Phase R0）をコード変更なしの `main`（`b9bb76a`）上で固定した記録である。
GitHub Actions 上の CI 実測値（対象コミット `10e357f`）、ローカル実機上の別途実行値（対象コミット `b9bb76a`）、および管理者権限または対話デスクトップ環境を要するため未実施とした項目を区別して記録する。
なお、`10e357f..b9bb76a` の差分は本書の `FU-P5-01` 追記（47 行）のみであり、Rust ソース、`Cargo.toml`、`Cargo.lock`、NSIS スクリプト、およびワークフロー定義は同一である。

### CI 自動実行範囲の実測値（`10e357f`）

- **`Release` ドライラン（Run `#45557332849`、`workflow_dispatch`、`dry_run: true`）**：総経過 `1,225 s`（`20m 25s`）、`preflight` `5 s`、`build` `1,213 s`（`20m 13s`）、`publish` スキップとなった。
  `build` の内訳は、`rust-cache` 復元 `3 s`、Windows Python 検査 `22 s`、NSIS 導入 `27 s`、`clippy` と `cargo test` `542 s`（`9m 02s`）、Node テスト `2 s`、リリース 4 バイナリビルド `490 s`（`8m 10s`）、NSIS コンパイル `8 s`、署名とパッケージング `2 s`、成果物アップロード `2 s`、`rust-cache` 保存 `85 s`（`1m 25s`）である。
- **配布成果物 6 点の実バイト数（Artifact ID `14996444138`）**：`LocalEDR-Setup-v0.1.0-win-x64.exe` `4,941,467 B`（`4.7126 MiB`）、`LocalEDR-v0.1.0-win-x64.zip` `7,029,060 B`（`6.7034 MiB`）、`LocalEDR-chrome-ext-v0.1.0.zip` `25,248 B`（`24.656 KiB`）、`SHA256SUMS.txt` `291 B`、`update-manifest.json` `859 B`、および `update-manifest.json.sig` `191 B` である。
- **通常 CI（Run `#45554453166`、`push`）**：総経過 `738 s`（`12m 18s`）、`rust-windows` `722 s`（`12m 02s`：復元 `46 s`、`Cargo check` `114 s`、`Cargo clippy` `29 s`、`Cargo test` `259 s`、`burst_budget` `37 s`、`ttl_purge_lineage` `7 s`、`Cargo doc` `10 s`、保存 `192 s`）であり、30% 以上短縮の目安は `<= 505.4 s` である。
- **GitHub Actions キャッシュ棚卸し**：全 11 件の合計は `11,490,607,120 B`（`10.7015 GiB`）で既定の `10 GiB` 上限を超過しており、`main` 最新キャッシュは `rust-windows`（ID `11079175832`）が `1,209,659,349 B`（`1.1266 GiB`）、`build`（ID `11080219748`）が `948,156,404 B`（`904.23 MiB`）である。

### ローカル別途実行範囲の実測値（`b9bb76a`）

ローカル計測の実行環境は `Windows 11 Home`（Version `10.0.26300`、64-bit）、`AMD Ryzen 7 7800X3D`（8 物理コア / 16 論理スレッド）、非管理者 PowerShell 5.1（`IsAdmin = False`）、`rustc 1.100.0`、`cargo 1.100.0`、`Python 3.11.9`、`Node v22.18.0` であり、`makensis.exe` は未導入である。

- **リリースビルド時間（`cargo fetch --locked` 後に `cargo build --release --locked -p ledr-daemon -p ledr-ui -p ledr-bridge-nm -p ledr-auth-helper --timings`）**：コールド 1 回目が `178.41 s`（453 コンパイル単位）、ウォーム 3 回が `110.189 s` / `110.413 s` / `110.706 s`、ウォーム中央値が `110.413 s`（40% 以上短縮の目標は `<= 66.248 s`）である。
  ウォーム中央値の最大ボトルネックは `ledr-ui` バイナリ単体（`107.14 s`、全体の `97.0%`）である。
- **配布 4 バイナリのバイト数**：`ledr-daemon.exe` `7,740,928 B`（`7.3823 MiB`）、`ledr-ui.exe` `10,402,816 B`（`9.9209 MiB`）、`ledr-bridge-nm.exe` `1,044,992 B`（`0.9966 MiB`）、`ledr-auth-helper.exe` `312,832 B`（`305.50 KiB`）であり、4 バイナリ合計は `19,501,568 B`（`18.5981 MiB`、協議ライン `+2.0 MiB` 加算上限 `<= 21,598,720 B`）である。
  ローカル `makensis.exe` 未導入のため、NSIS インストーラの比較基準は Run `#45557332849` の `4,941,467 B`（`4.7126 MiB`、ハード上限 `<= 128 MiB` および `+10%` 基準 `<= 5,435,613 B`）を固定する。
- **`L-23` PE 解析（`scripts/profile_daemon_memory.ps1 -AnalyzePeOnly`）**：`DirectImports` 20 件中の `wintrust.dll` および `crypt32.dll` はいずれも `0` 件であり、推移的到達は Windows システム DLL（`wtsapi32.dll`、`advapi32.dll`、`kernelbase.dll` 等）由来のみであった。
- **自動検査とテスト実行**：`py_compile`（6 ファイル）、`test_check_invariants.py`（8/8）、`release_verify.py preflight`、Chrome MV3 拡張テスト（19/19）、UI モック DOM テスト（18/18）、`cargo clippy --workspace --all-targets --locked -- -D warnings`、および `burst_budget` 3 回連続（3/3 回とも 12/12）はすべて合格した。
  `test_release_scripts.py` は `10 PASS / 1 ERROR` となり、`test_rel_09` の `Set-Acl` のみが `IsAdmin = False` の `SeSecurityPrivilege` 不足で失敗した（管理者権限のある CI では 11/11 合格）。
  `cargo test --workspace --no-fail-fast --locked` は `517 PASS / 3 FAIL` となり、非管理者権限の DACL 制約による `ui_upd_07` および `ui_upd_09` の 2 件と、スイート連続実行時の `ledr-sensor-win` の `sens_p2_13`（`cargo test -p ledr-sensor-win --lib sens_p2_13 --locked` の単独実行では `1/1` 合格）の 1 件がローカル環境制約で失敗した（CI では全 520 件合格）。

### 管理者および対話デスクトップ検証待ちの項目

- **`b9bb76a` 上の `L-24` および `L-08`**：非管理者（`IsAdmin = False`）かつ非対話デスクトップ環境のため、`b9bb76a` 上での実機計測（600 秒アイドルおよび 60 秒高負荷の `L-24` 計測、ならびに `ledr-ui.exe` と WebView2 の閉鎖後 0 プロセス終了 `L-08`）は未実施である。
  Stage 3（`87be6d5`）の記録値（アイドル `PrivateWorkingSetSize` 中央値 `13.0234 MB`、CPU `0.2054%` 等）は `87be6d5..b9bb76a` 間の 48 ファイル変更を経ているため履歴参照値として区別し、`b9bb76a` の合格実績としては扱わない。

## FU-R1-01 Phase R1 から Phase R3-4 までの最適化統合と最終判定記録

### 目的と検証範囲の区分

本節では Phase R0（`b9bb76a` / `10e357f`、`FU-R0-01`）を基準として実施した Phase R1 から Phase R3-4 までのビルドおよび CI 高速化改修、最終統合受け入れ試験、ならびに不採用実験の検証結果を記録する。
GitHub Actions 上の CI 自動実行および手動 `workflow_dispatch` 実績、ローカル実機上の別途実行結果、および管理者権限や対話デスクトップを要する未実施項目を分離して示す。

### Phase R1 から Phase R3-4 までの施策別採否と検証概要

| Phase | 対象施策 | 対応 PR と状態 | 採否と根拠の要約 |
| :--- | :--- | :--- | :--- |
| Phase R1 | `release.yml` 5 ジョブ並列化、署名分離、キャッシュ分離、`[profile.dev]` 動的切替 | PR #53（`2f1be6e` マージ済み） | **採用**。`preflight`、並列 `verify` と `build`、`package`（`LEDR_UPDATE_SIGNING_PRIVATE_KEY` 隔離、`L-26` と `L-27`）、および `publish` へ分割し、`win-x64-dev` と `win-x64-release` を `main` 限定保存へ分離した。あわせて `ci.yml` の重複ステップ削除、`Cargo.toml` の `debug = "line-tables-only"` 導入、`test_release_scripts.py` 刷新、および `release-runbook.md` と `AGENTS.md` 同期を実施した。 |
| Phase R2A | 二層 `codegen-units = 16` 導入 | PR #54（`3f92057` マージ済み） | **採用**。`[profile.release.package."*"]` と `[profile.release.package.ledr-ui]` へ `codegen-units = 16` を適用し、配布コア 8 クレートと `ledr-sim` の計 9 クレートは `codegen-units = 1`、`strip = "symbols"`、および `panic = "unwind"`（`AUTO-10`）を維持した。 |
| Phase R2B | `.cargo/config.toml` による `rust-lld.exe` 検証 | PR #55（`58bfd5e` クローズ） | **不採用（ロールバック）**。PE 属性（`0x8160`）、`.rsrc`、PDB（`RSDS`）、`L-23`、`ci.yml`（Run `#45728742700` `5/5`）、および `release.yml`（Run `#45728748115`、NSIS `5,089,846 B`）はすべて合格した一方、ローカルウォーム中央値 `50.501 s`（R2A `48.723 s` 比 `+1.778 s`）および CI `Build release binaries` `586 s`（Run `#45728748115`、`.cargo/config.toml` 追加による `restore-key` `full match: false`、M5 キャッシュ再構築前の R2A `main` Run `#45723399380` `full match: true` の `576 s` 比 `+10 s`、`build` 合計 `698 s`、CI `rust-windows` `453 s`）となり、ローカルと CI の双方で `10 s` 以上短縮するロールバック基準を満たさなかった。 |
| Phase R3-1 | `verify` ジョブの 2 並列分割 | コード変更なし（見送り） | **不採用**。M5（`3f92057`）の全 3 ランで `verify`（`337 s` / `129 s` / `144 s`）が `build`（`475 s` / `210 s` / `270 s`）より `81 s` から `138 s` 速く、クリティカルパス上にないため分割効果を認めない。 |
| Phase R3-2 | `.github/workflows/release-warmup.yml` 導入 | PR #56（`d9c3fdd` マージ済み） | **採用**。`main` への `Cargo.toml`、`**/Cargo.toml`、`Cargo.lock`、`.cargo/config.toml` プッシュ、毎月 1 日基準の 6 日間隔 `schedule`（`0 3 */6 * *`、月末をまたぐ場合は 6 日より短くなる）、および `workflow_dispatch` で `win-x64-release` を事前温態化する構成を追加した（`ci-gate` 非組み込み、`test_rel_12` 追加、`release-runbook.md` 同期）。 |
| Phase R3-3 | Tauri 既定 feature 削減実験 | PR #57（`470ad70` クローズ） | **不採用**。`tauri` を `["wry", "common-controls-v6"]` へ縮小し `Cargo.lock` の `111` 行を削除したが、ローカルウォーム中央値は `53.480 s`（M5 `50.608 s` 比 `+2.872 s`）、CI `build` は `303.0 s`（クリティカルパス `315.0 s`）で短縮せず、並列終端は常に `ledr-daemon`（`CGU=1`、`53.29 s` から `54.11 s`）が支配していた。NSIS 削減幅 `-158,431 B`（`-3.10%`、`4,955,284 B`）もキャッシュキー無効化と既定機能喪失に見合わないためクローズした。 |
| Phase R3-4 | `windows` 0.62 整理と `build` 分割検討 | 本件（コード変更なし） | **削除見送りおよび分割不採用**。`crates/ledr-sensor-win/Cargo.toml` から `Win32_System_Time` を外して `cargo clippy --workspace --all-targets --locked -- -D warnings` を実行したところ、`Etw` モジュールの `EVENT_TRACE_LOGFILEW` と `OpenTraceW` が `#[cfg(feature = "Win32_System_Time")]` を要求して `E0432` で失敗したため、必須依存として保持を確定した。あわせて `build-core` と `build-ui` 分割および `ledr-ui` クレート分割も不採用とした。 |

Phase R3-4 の判断根拠として、`Win32_System_Time` の精査結果と分割検討の定量データを以下にまとめる。

- **`Win32_System_Time` 必須確認**：`crates/ledr-sensor-win/Cargo.toml` の `Win32_System_Time` を削除した状態で `cargo clippy --workspace --all-targets --locked -- -D warnings` を実行すると、`crates/ledr-sensor-win/src/etw/handlers.rs`（7 行目）、`session.rs`（17 行目と 19 行目）、および `tests.rs`（17 行目）が参照する `EVENT_TRACE_LOGFILEW` と `OpenTraceW` に対して `windows 0.62.2`（`src/Windows/Win32/System/Diagnostics/Etw/mod.rs` の 201 行目から 203 行目および 1566 行目から 1568 行目）が `#[cfg(feature = "Win32_System_Time")]` を付与しているため、`E0432`（終了コード `101`）で失敗した。
  `Win32_System_Rpc` も `crates/ledr-sensor-win/src/wfp/backend.rs`（25 行目）で使用中であるため `Cargo.toml` と `Cargo.lock` を無変更とし、既存の `Swatinem/rust-cache@v2` キャッシュキー（`fdf92e00`）を保全した（今後メンバー `Cargo.toml` を変更してハッシュが更新された場合も、`.github/workflows/release-warmup.yml` の `**/Cargo.toml` トリガが `main` マージ時に `win-x64-release` を自動再構築する）。
- **`build-core` と `build-ui` 分割の見送り根拠**：M5（`3f92057`）の `release.yml` が既にコールド `489 s <= 720 s` およびウォーム `227 s` と `289 s <= 360 s` を満たしており、目標超過時の分割条件に該当しない。
  あわせて `cargo tree --locked --target x86_64-pc-windows-msvc -e normal,build` を重複除去して集計すると、配布 4 バイナリ合計 `258` パッケージのうちコア 3 バイナリ（`84` 件）と `ledr-ui`（`235` 件）が **`61` 個の固有クレート**（重複記号 `(*)` 統合前の一意行交差 `74` 件、事前計画時の概算 `81` 件）を共有しているため、2 分割すると両ランナーでの二重ビルドと `win-x64-release` キャッシュ（`432,524,087 B` = `412.48 MiB`）の重複保存や競合を招く。
- **`ledr-ui` 内モジュール分割の見送り根拠**：ローカル `--timings` 実測において、`ledr-ui` バイナリ（`CGU=16`）は常に `ledr-daemon` バイナリ（`CGU=1`）より約 `15 s`（R2A で約 `15.2 s`、R3-3 で `14.54 s` から `16.25 s`）先に完了しているため、`defense_status` や `updater` を別クレートへ分離してもクリティカルパス上の短縮は `0 s` にとどまる（`apps/ledr-ui/tauri.conf.json` への `removeUnusedCommands` 不追加も継続）。

### CI 自動実行範囲および Release ドライランとウォームアップの実測値

PR #53（`2f1be6e`）では `Release` ウォーム Run `#45669523939` がクリティカルパス `403 s`（`6m 43s`：`preflight` `6 s`、`verify` `203 s`、`build` `388 s`、`package` `9 s`、`LocalEDR-Setup-v0.1.0-win-x64.exe` `4,940,323 B`）を記録し、`win-x64-dev`（`456,227,459 B`、R0 比 `-62.28%`）と `win-x64-release`（`428,970,983 B`、R0 比 `-54.76%`）を確立した。
続く Phase R2A マージ後の `main`（`3f92057`）および Phase R3-2 マージ後の `main`（`d9c3fdd`）で確認した公式 CI 実績は次のとおりである。

| 対象項目 | 実行識別子 | 実測値（`main` `3f92057` / `d9c3fdd`） | R0 基準と増減 | 基準判定 |
| :--- | :--- | :--- | :--- | :--- |
| 通常 CI `rust-windows` ウォーム時間 | Run `#45721565868`（`3f92057`） | **`224 s`（`3m 44s`）**（`520/520` 合格） | R0 `722 s` 比 **`-68.98%`** | **PASS**（目標 `-30%` 以上 `<= 505.4 s`） |
| `Release` コールド総壁時計時間 | Run `#45752007842`（`3f92057`、`dry_run: true`） | **`489 s`（`8m 09s`）**（`preflight` `5 s`、`verify` `337 s`、`build` `475 s`、`package` `9 s`） | R0 `1,225 s` 比 **`-60.08%`** | **PASS**（目標 `<= 720 s`） |
| `Release` ウォーム総壁時計時間（1 回目） | Run `#45752918412`（`3f92057`、`dry_run: true`） | **`227 s`（`3m 47s`）**（`preflight` `5 s`、`verify` `129 s`、`build` `210 s`、`package` `12 s`） | R0 `1,225 s` 比 **`-81.47%`** | **PASS**（目標 `<= 360 s`） |
| `Release` ウォーム総壁時計時間（2 回目） | Run `#45753387980`（`3f92057`、`dry_run: true`） | **`289 s`（`4m 49s`）**（`preflight` `5 s`、`verify` `144 s`、`build` `270 s`、`package` `14 s`） | R0 `1,225 s` 比 **`-76.41%`** | **PASS**（目標 `<= 360 s`） |
| `win-x64-dev` キャッシュ容量 | ID `11134347442`（`3f92057`） | **`456,448,071 B`（`435.30 MiB`）** | R0 `1,209,659,349 B` 比 **`-62.27%`** | **PASS**（目標 `-50%` 以上削減） |
| `win-x64-release` キャッシュ容量 | ID `11134406304`（`3f92057`） | **`432,524,087 B`（`412.48 MiB`）** | R0 `948,156,404 B` 比 **`-54.38%`** | **PASS**（目標 `-50%` 以上削減） |
| NSIS インストーラサイズ（`release-dist`） | Run `#45753387980`（`3f92057`） | **`5,113,715 B`（`4.8768 MiB`）** | R0 `4,941,467 B` 比 `+172,248 B`（**`+3.49%`**） | **PASS**（`<= 128 MiB` かつ `<= +10%`） |
| `release-warmup.yml` ライブ実行 | Run `#45760466868`（`d9c3fdd`） | **`3m 57s`**（`Warm release build cache` `197 s`、ID `11134406304` へ `full match: true`） | 該当なし | **PASS**（既存キャッシュ復元を確認。新規キー保存と後続 `release.yml` での引き継ぎは未実施、`ci-gate` 非組み込み） |

M5 の `gh cache delete`（`main` 上の `win-x64-dev`、`win-x64-release`、および旧 PR キャッシュ 4 件を削除）後に実行した Run `#45752007842` では、`verify`（`clippy + test` `280 s` + 保存 `29 s`）および `build`（`Build release binaries` `371 s` + 保存 `33 s`）が新規キャッシュを再生成し、続く Run `#45752918412` と `#45753387980` で双方が `full match: true` で復元された（`Build release binaries` `132 s` と `191 s`）。
Run `#45753387980` の `release-dist` 6 点は `LocalEDR-Setup-v0.1.0-win-x64.exe`（`5,113,715 B`）のほか、`LocalEDR-v0.1.0-win-x64.zip`（`7,268,348 B`）、`LocalEDR-chrome-ext-v0.1.0.zip`（`25,066 B`）、`SHA256SUMS.txt`（`291 B`）、`update-manifest.json`（`859 B`）、および `update-manifest.json.sig`（`191 B`、`dry-run-test`、`verify-dist OK`）すべてで整合を確認した。
また PR #56（head `2546154`、`main` マージ先 `d9c3fdd`）の最終 `ci.yml` Run `#45759151458` では `windows-packaging-tests`（`test_release_scripts.py` `13/13` を含む）を含む全 5 ジョブが合格した。
なお、本 PR（`docs/follow-up-notes.md` のみの変更）の `ci.yml` では `changes` のパス判定により `rust-windows` と `windows-packaging-tests` がスキップされ、`changes`、`static-checks`、および `ci-gate` のみが実行されるため、Rust と Windows パッケージ検査の検証は PR #56（Run `#45759151458`）、M5（Run `#45721565868`、Run `#45753387980`）、本ブランチの手動 `release.yml`（`dry_run: true`、Run `#45771821619` で `verify` `520/520`、`build`、および `package` 通過）、およびローカル再実行で補完している。

### ローカル別途実行範囲の実測値（M5、M6A/M6B、および M6C）

ローカル環境は `Windows 11 Home`（Version `10.0.26300`、64-bit）、`AMD Ryzen 7 7800X3D`（8 物理コア / 16 論理スレッド）、非管理者 PowerShell 5.1（`IsAdmin = False`）、`rustc 1.100.0`、`cargo 1.100.0`、`Python 3.11.9`、`Node v22.18.0` であり、`makensis.exe` は未導入である。

- **ローカルリリースビルド時間（`cargo build --release --locked -p ledr-daemon -p ledr-ui -p ledr-bridge-nm -p ledr-auth-helper --timings`、M5 `3f92057`）**：ワークスペース 10 クレートのみ削除したウォーム 3 回が `50.608 s`、`50.555 s`、`51.737 s`、中央値 **`50.608 s`** となり、R0 中央値 `110.413 s` 比 **`-54.16%`**（目標 `-40%` 以上 `<= 66.248 s` 達成）を記録した（R2A 単体計測時のコールドは `99.410 s`、ウォーム中央値は `48.723 s` で `-55.87%`）。
- **配布 4 バイナリのバイト数と PE 属性（M5 `3f92057`）**：`ledr-daemon.exe` `8,038,912 B`、`ledr-ui.exe` `11,136,000 B`、`ledr-bridge-nm.exe` `1,054,720 B`、`ledr-auth-helper.exe` `313,344 B`、合計 **`20,542,976 B`（`19.5913 MiB`）** となり、R0 `19,501,568 B` 比 `+1,041,408 B`（**`+0.9932 MiB`**、協議ライン `+2.0 MiB` 以内）に収まった。
  全 4 バイナリで `machine = 0x8664` と `dll_characteristics = 0x8160`、`ledr-ui.exe` で `.rsrc`（`RT_ICON`、`RT_GROUP_ICON`、`RT_VERSION`、`RT_MANIFEST`）、ならびに全 `Cargo.toml` で `panic = "abort"` 0 件（`AUTO-10`）を確認した。
- **`L-23` PE 解析（M5 `3f92057`、`scripts/profile_daemon_memory.ps1 -AnalyzePeOnly`）**：直接インポート 20 件中の `wintrust.dll` と `crypt32.dll` はいずれも `0` 件であり、`StaticPathsToWintrust` は `0` 件、`StaticPathsToCrypt32` は OS 側 `wtsapi32.dll -> CRYPT32.dll` の 1 件のみであった。
- **M5（`3f92057`）の非管理者環境（`IsAdmin = False`）自動検証スイート**：ローカルでも再実行した CI 相当項目として `cargo clippy --workspace --all-targets --locked -- -D warnings`（0 警告）、`cargo test --workspace --no-fail-fast --locked` `518 PASS / 2 FAIL`（非管理者 DACL 制約による `ui_upd_07` と `ui_upd_09` の `os error 5` のみ、CI では `520/520`）、`burst_budget` `3/3` 回（各 `12/12`）、Chrome MV3 拡張テスト `19/19`、UI モック DOM テスト `18/18`、`py_compile`、`test_check_invariants.py` `8/8`、`release_verify.py preflight`、および `test_release_scripts.py` `11 PASS / 1 ERROR`（非管理者 `SeSecurityPrivilege` 制約の `test_rel_09` のみ、CI では `12/12`）を確認し、CI 対象外のローカル固有検証としてライブ `check_invariants.py` `101/101` を通過した。
- **M6A（PR #56 `2546154` / `d9c3fdd`）および M6B クローズ後復元確認（`d9c3fdd`）**：ローカルでも再実行した CI 相当項目として `test_rel_12` 追加後の `test_release_scripts.py` `12 PASS / 1 ERROR`（CI `windows-packaging-tests` Run `#45759151458` では `13/13`）、ならびに M6B クローズ後の `d9c3fdd` 復元確認で `cargo clippy --workspace --all-targets --locked -- -D warnings`（0 警告）、`cargo test --workspace --no-fail-fast --locked` `518 PASS / 2 FAIL`、Chrome MV3 `19/19`、UI `18/18`、および `test_check_invariants.py` `8/8` を再確認した。
- **M6C ローカルでも再実行した CI および `release.yml` 相当項目（`docs/r3-4-follow-up-notes-sync`、Rust および Cargo 無変更、`IsAdmin = False`）**：`ci.yml` 相当として `py_compile`、`test_check_invariants.py` `8/8`（`static-checks` 実行対象）、`release_verify.py preflight`、Chrome MV3 `19/19`、UI `18/18`、`cargo clippy --workspace --all-targets --locked -- -D warnings`（0 警告）、`cargo test -p ledr-daemon --test burst_budget --locked -- --nocapture` `3/3` 回（各 `12/12`）、および `test_release_scripts.py` `12 PASS / 1 ERROR`（非管理者 `SeSecurityPrivilege` 制約の `test_rel_09` のみ）を通過した（本 PR は文書変更のみのため `ci.yml` では `rust-windows` と `windows-packaging-tests` がスキップされる）。
  なお `cargo test --workspace --no-fail-fast --locked` は `517 PASS / 3 FAIL`（`ui_upd_07` と `ui_upd_09` の `os error 5` に加え、既知の非管理者ローカル `findstr.exe` タイミング競合により `sens_p2_13` が `crates/ledr-sensor-win/src/defense/tests.rs:430` で失敗したものであり、本 PR に Rust コード変更はなく PR #56 CI、M5、および `57d10c6` の `release.yml` Run `#45771821619` では通過）となり、`release.yml` の `build` と同一コマンド `cargo build --release --locked -p ledr-daemon -p ledr-ui -p ledr-bridge-nm -p ledr-auth-helper` も通過した。
- **M6C CI 対象外のローカル固有計測と解析（`docs/r3-4-follow-up-notes-sync`）**：上記ローカルリリースビルドの所要時間（`54.141 s`）と 4 バイナリ合計サイズ（`20,542,976 B`）の測定、`L-23` PE 解析（`scripts/profile_daemon_memory.ps1 -AnalyzePeOnly`、直接インポート 20 件中 `wintrust.dll` `0` 件および `crypt32.dll` `0` 件）、`check_invariants.py --base main --paths docs/follow-up-notes.md`（`101` ルール合格、`Status: passed`、違反候補 0 件；既定パス `--base main` 単体は `skipped_empty_diff`）、および `slop_lint.py`（編集行の新規指摘 0 件）を実施した。

### 管理者および対話デスクトップ検証の引き継ぎ状態（`c4acf22` 実施後）

- **`c4acf22` 上の `L-24`、`L-23`、および `L-08` 実機一括検証**：2026 年 11 月 26 日に `main`（`c4acf22`）上で実施済みであり、`L-08` と `L-23` は合格、`L-24` は `-Mode idle` が未達、`-Mode load` はプロセス起動負荷未発生のため正式判定を未検証（計測値は参考値）とした。
  実測値、原因切り分け、および静穏環境での `L-24` 再計測を含む残課題は `FU-R1-02` へ記録した。
  Stage 3（`87be6d5`、2026 年 11 月 23 日時点）の記録値（アイドル `PrivateWorkingSetSize` 中央値 `13.0234 MB`、CPU `0.2054%` 等）は引き続き履歴参照値として区別し、`c4acf22` の合格実績としては扱わない。
- **ルート 1 機能 E2E、実機 NSIS インストーラ E2E、および本番公開**：`FU-E2E-01` と `FU-E2E-02` の統合機能検証、Windows 10 または Windows 11 クライアント SKU 実機での NSIS 導入とアンインストール、および本番タグ発行時の `publish` ジョブと実署名更新確認は、引き続き実機および本番リリース時の確認対象として残す。
  [implementation-plan.md](implementation-plan.md) の未完了チェックリスト 3 件（`[ ]`）は、`FU-E2E-01`、`FU-E2E-02`、および `L-24` の合格確認まで未更新のまま維持する。

## FU-R1-02 main（c4acf22）上の実機一括検証結果と L-24 残課題

### 対象と計測条件

2026 年 11 月 26 日に PR #58 マージ後の `main`（`c4acf22` / `c4acf22c90e55b723fcca476ae6169eb4fd7fb23`）に対して、管理者および対話デスクトップ環境で `L-08`、`L-23`、および `L-24` の実機一括検証を実施した。
検証証跡は `C:\Users\meshi\AppData\Local\Temp\ledr-l24-final-20261126-192444\`（`perf_load\`、`perf_idle\`、および `perf.db`）に保存されている（メモリ容量の単位規約は Stage 3 `87be6d5` と同じく `1 MB = 1 MiB = 1,048,576 bytes`）。
ただし本計測の `perf_idle` と `perf_load` は Stage 3（`87be6d5`）の静穏環境と異なり、多数の常駐デスクトップアプリ（`Discord.exe`、`Antigravity.exe`、`Devin.exe`、`Games.exe`、`steamwebhelper.exe`、`gamingservices.exe`、`GooglePlayGamesServices.exe`、`obs64.exe`、`chrome.exe` 等）が稼働する非アイドル実稼働環境で実施された。
なお、`perf.db` に記録された全 `19` 件のアラート（`EXPIRED_SUSPENDED` `18` 件、`PENDING` `1` 件）はすべて `wfp_blocked = False`、`wfp_filter_id = None`、かつ `process_suspended = 0` であった。
`outbound.rs`（`1284` 行目）で `AlertStatus::Pending` として作成されたレコードは `--outbound-mode preemptive-only` 稼働時でも `lifecycle.rs`（`429` 行目）で期限切れ遷移するため、`EXPIRED_SUSPENDED` の存在は `enforce` モードの証拠にならず、非アイドル環境における `preemptive-only` 稼働とも整合する。

### 実機検証結果（`c4acf22`）

| 検証項目 | 条件と対象 | 主な実測値 | 判定 |
| :--- | :--- | :--- | :--- |
| `L-08`（UI 完全終了） | `ledr-ui.exe` 閉鎖後の残存プロセス確認 | `Get-Process ledr-ui` が `0` 件、`msedgewebview2.exe`（`ledr-ui\|LocalEDR` 一致）が `0` 件 | **PASS** |
| `L-23`（PE 依存隔離） | 両サマリの `pe_transitive_dependencies` | `DirectImports` `20` 件（`wintrust.dll` `0` 件、`crypt32.dll` `0` 件）、`StaticPathsToWintrust` `0` 件、`StaticPathsToCrypt32` `1` 件（OS システム DLL のみ：`wtsapi32.dll -> CRYPT32.dll`）、`peak_authenticode_mapped_mb` `0` | **PASS** |
| `L-24` `-Mode load` | PID `2268`、`60.253 s` | `e2e_perf_01_mode_pass = true`、`avg_cpu_percent` `0.0487%`（`< 1.0%`）、`latest_working_set_mb` `25.0977 MB`、`interval_peak_working_set_mb` `37.6328 MB`、`os_peak_working_set_mb` `46.6055 MB`（`< 64.34 MB`）、`latest_private_ws_mb` `10.6094 MB`、`peak_private_ws_mb` `22.8867 MB`、`spikes_ge_100mb_count` `0` | **未検証（参考値）** |
| `L-24` `-Mode idle` | PID `22436`、`600.328 s` | `e2e_perf_01_mode_pass = false`、`latest_private_ws_mb` `11.2656 MB`、`median_private_ws_mb` `14.0898 MB`（`median_working_set_mb` `28.8926 MB`）、`avg_cpu_percent` `0.068%` は合格、一方 `half_diff_ws_mb` `+6.918 MB`、`half_diff_private_ws_mb` `+6.8399 MB`、`spikes_ge_100mb_count` `1`（`t=543.401s` で `100.5039 MB` WS / `85.6758 MB` PrivateWS）が未達 | **FAIL** |

`-Mode load` では [profile_daemon_memory.ps1](../scripts/profile_daemon_memory.ps1#L1654-L1662) の `e2e_perf_01_mode_pass` が CPU とメモリ閾値のみを評価し負荷発生の有無を判定しないため `true` を返したものの、`sqlite_interval_counts.delta` は `processes: 0`、`dns_queries: 39`、`network_events: 63`、`alerts: 2` であり、[e2e-test-runbook.md](e2e-test-runbook.md#L1422) 所定の `cargo build --locked` と複数ブラウザタブ相当のプロセス起動負荷を満たしていない。
そのため、上記実測値は参考値として残し、正式な `L-24` 高負荷試験の判定は未検証（再計測待ち）として区別する。

`-Mode idle` の各指標の詳細は次のとおりである。

- 合格した指標は `latest_private_ws_mb` `11.2656 MB`（`<= 20.0 MB`）、`median_private_ws_mb` `14.0898 MB`（`<= 20.0 MB`、`median_working_set_mb` `28.8926 MB`）、`avg_cpu_percent` `0.068%`（`< 0.5%`）、`peak_authenticode_mapped_mb` `0`、および `end_minus_60s_private_ws_mb` `-0.2461 MB` である。
- 未達となった指標は `steady_window_60s_to_end`（`2,494` サンプル）を `$midSec = 330.0s`（前半 `1,245` サンプル `< 330.0s`、後半 `1,249` サンプル `>= 330.0s`）で分割した `first_half_median_ws_mb` `25.7539 MB` と `second_half_median_ws_mb` `32.6719 MB` の差 `half_diff_ws_mb` `+6.918 MB`（基準 `<= +1.0 MB`）、`half_diff_private_ws_mb` `+6.8399 MB`（基準 `<= +1.0 MB`）、および `spikes_ge_100mb_count` `1`（`t=543.401s` で `interval_peak_working_set_mb` `100.5039 MB`、`os_peak_working_set_mb` `101.2578 MB`、`peak_private_ws_mb` `85.6758 MB`、`peak_private_commit_mb` `87.5938 MB`）である。
- `perf_idle` 区間内の `sqlite_interval_counts.delta` は `processes: 0`、`dns_queries: +376`、`network_events: +1059`、`alerts: +6` となり、`language_server_windows_x64.exe`、`language_server.exe`、`Antigravity.exe`、`Discord.exe`、`gamingservices.exe`、および `GooglePlayGamesServices.exe` が `LEDR-NET-UNKNOWN-OUTBOUND`（すべて `wfp_blocked = False`、かつ `process_suspended = 0` で `EXPIRED_SUSPENDED` へ遷移）を記録した。

### 原因の切り分けと未確認範囲

`perf_idle` の未達要因について、既存の記録から確認できた事実と未確認の仮説を区別して以下に整理する。

- **`crates/` の Rust ソース変更はなく、`ledr-daemon` 本体のリリース設定も不変（依存クレートの `codegen-units` 変更影響は未検証）**：`git diff --stat b9bb76a..c4acf22 -- crates/` は空（Rust ソース変更 `0` 件）であり、[Cargo.toml](../Cargo.toml#L68-L77) でも `ledr-daemon` 本体は `codegen-units = 1`、`lto = "thin"`、`strip = "symbols"`、および Cargo 既定値の `panic = "unwind"` を維持している。
  一方で、Phase R2A により `[profile.release.package."*"]` と `[profile.release.package.ledr-ui]` の `codegen-units` は `16` へ変更されており、`b9bb76a` との同一条件下 A/B 比較は未実施のため、ビルド設定変更による実行時メモリ影響の有無は未検証である。
- **採取済みスナップショット区間の内訳と終了尾部（主要ピーク時はスナップショット未採取）**：`perf_idle` の採取済み全 `20` スナップショット（`t=299.51s` の `snapshot_019` までと終了前 `t=600.178s` の `snapshot_020`）では、`MEM_IMAGE` が `14.9922〜15.1211 MB`（全 `20` 件で観測幅 `0.1289 MB`、定常区間 `snapshot_006`〜`020` では `14.9961〜15.1211 MB` で観測幅 `0.1250 MB`、かつ全 `20` 件で `authenticode_mapped_mb = 0`）、`MEM_MAPPED` が `0.4688 MB` 一定であり、採取済み時点の上昇分は実質的に `MEM_PRIVATE`（`PAGE_READWRITE`）であった。
  `t=440.631s` と `t=543.401s` の主要ピーク時は `QueryWorkingSetEx` スナップショットが未採取であるためページ種別内訳は直接確認できていないものの、`GetProcessMemoryInfo` 集計上の `peak_private_ws_mb` `85.6758 MB` がプライベート作業セット主体の急増を示唆している（確定内訳は未確認）。
  定常開始部（`t=60..240s`、`WS` 中央値 `25.63〜25.65 MB`）と終了尾部（`t=544.5..600.18s`、`WS` 中央値 `26.0938 MB`、`latest_private_ws_mb` `11.2656 MB`、`end_minus_60s_private_ws_mb` `-0.2461 MB`）はいずれも Stage 3（`87be6d5`：`WS` `27.6250 MB`、`PrivateWS` `13.0234 MB`）を下回った。
- **未達 3 指標の直接要因は `t=277.577s..544.269s`（`t=273..544.5s` 内）の一過性 `MEM_PRIVATE` バーストである**：`timeseries.csv` で `WS >= 40 MB` の急増が `t=277.577s..544.269s` に集中し、`t=440.631s` の `89.5312 MB` と `t=543.401s` の `100.5039 MB`（`PrivateWS` `85.6758 MB`）を記録した直後、2 秒以内に `27.2969 MB` へ解放された。
  この区間が前後半境界 `$midSec = 330.0s` の後半側に偏ったため、`half_diff` 2 指標と `spikes_ge_100mb_count` が基準を超過した。
- **非アイドル実稼働デスクトップ条件と外部同期の証拠**：`perf.db` には `Antigravity.exe`、`Devin.exe`、`Discord.exe`、`Games.exe`、`steamwebhelper.exe`、`gamingservices.exe`、`GooglePlayGamesServices.exe`、`obs64.exe`、`chrome.exe` 等が稼働する環境で `EXPIRED_SUSPENDED` アラートが記録された（全 19 件が `wfp_blocked = False`、かつ `process_suspended = 0` であり、`--outbound-mode preemptive-only` 稼働時のタイムアウト遷移と整合する）。
  さらに、別プロセスかつ別時刻に計測された `perf_idle`（PID `22436`）と `perf_load`（PID `2268`）の双方が時刻 `:x6.6s UTC` ごとの 10 秒周期バンプ（`+2.5〜+7.5 MB`）を示しており、ホストまたは OS 側の外部イベントに同期した挙動が確認された。
- **未確認範囲（`440s` および `543s` ピーク時の詳細未採取）**：[profile_daemon_memory.ps1](../scripts/profile_daemon_memory.ps1) の既定値 `MaxSnapshots = 20` が `t=299.51s`（`snapshot_019`、`WS` `46.6914 MB`）で上限に達したため、`t=440.631s` と `t=543.401s` のスナップショットおよびヒープスタックは取得できていない。
  `t=282..544.5s` の大量ページフォールトは `perf.db` の `alerts`（`t=282..600s` で `0` 件）、`file_canary_events`（`0` 件）、および `processes`（`svchost.exe` `1` 件）と相関していないため、未永続化の ETW（`AMSI`、`PowerShell`、`Kernel-File`、`Kernel-Registry` 等）または OS DLL 側バッファの一過性確保が関与した可能性があるものの、現行の証跡からは具体的な確保元を断定できない（未確認の仮説として扱う）。

### 検証範囲の区分と残課題

- **CI 自動実行範囲（`.github/workflows/ci.yml`）**：本書のみの更新 PR では `changes` のパス判定により `rust-windows` と `windows-packaging-tests` がスキップされ、`changes`、`static-checks`（Node 22 の拡張テストと UI モック DOM テスト、JS 構文検査、`manifest.json` 公開鍵と `DEFAULT_CHROME_EXTENSION_ID` の一致検査、JSON と UTF-8 と `U+FFFD` と競合マーカー検査、ならびに Python 検査の `py_compile`、`test_release_scripts.py`、`test_check_invariants.py`、および `release_verify.py preflight`）、および `ci-gate` のみが実行される。
  Rust 全体と Windows パッケージングの CI 検証は `c4acf22` 以前の既存マージ済みラン（M5 Run `#45721565868`、Run `#45753387980`、PR #56 Run `#45759151458`、および M6C 手動 `release.yml` Run `#45771821619`）で担保している。
- **ローカルでも再実行した CI 相当項目（`static-checks` 対象、非特権環境）**：`Windows 11 Home`（Version `10.0.26300`）、非管理者 PowerShell `5.1.26100.9818`、`Python 3.11.9`、および `Node v22.18.0` 上で、`py_compile`（終了コード `0`）、`test_release_scripts.py`（`12 PASS / 1 ERROR`、非管理者 `SeSecurityPrivilege` 制約の `test_rel_09` のみ）、`test_check_invariants.py`（`8/8` 合格）、`release_verify.py preflight`（`Preflight OK`）、Chrome MV3 拡張テスト（`19/19` 合格）、UI モック DOM テスト（`18/18` 合格）、JS 構文検査（`17` 件）、`manifest.json` 公開鍵一致検査、ならびに JSON（`11` 件）と UTF-8 と `U+FFFD` と競合マーカー検査を実行して確認した（非管理者制約の `test_rel_09` を除きすべて通過）。
- **CI 対象外のローカル固有検証**：同一ローカル環境で `python scripts\check_invariants.py --base main --paths docs/follow-up-notes.md`（`101` ルール合格、`Status: passed`）、`slop_lint.py --strict docs\follow-up-notes.md`（編集行の新規エラーと警告 `0` 件、ファイル全体では既存 `L83` の `warn 1件` により終了コード `1`、内訳は `error 0件、warn 1件、info 8件`）、および UTF-8（BOM なし）、CRLF、`U+FFFD` `0` 件、競合マーカー `0` 件の検査を確認した（`L-24` の実機再計測は本 PR では実施しない）。
- **実機残課題（Open Follow-up）**：次回の実機検証に向けて以下の 3 点を引き継ぐ。
  1. 常駐デスクトップアプリを閉じた静穏環境で、[e2e-test-runbook.md](e2e-test-runbook.md#L1358-L1361) に従い `E2E-P3-05` で `feeds_succeeded=2` かつ `feeds_failed=0` を確認済みの公開 2 フィード版実 `nrd-cache.txt` を用意したうえで、[Track C の Release 版配置と起動手順](e2e-test-runbook.md#L1321-L1349) に沿って `<runDir>\release-bin` へ複製して `ledr-auth-helper.exe` の `nNumberOfLinks == 1` を確認し、配置済み `ledr-daemon.exe` を `--foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --disable-nrd-refresh --db <runDir>\perf.db --nrd-cache <実キャッシュパス>` で起動し、[計測例](e2e-test-runbook.md#L1395-L1407) に沿って [profile_daemon_memory.ps1](../scripts/profile_daemon_memory.ps1#L21-L44) に `-DbPath <runDir>\perf.db -Mode idle -DurationSec 600 -MaxSnapshots 60` を指定して `L-24` `-Mode idle` を再実施する（公開 2 フィード未達時は参考値扱いとする）。
     あわせて `-Mode load`（`60 s`）中に実 `cargo build --locked` とブラウザ 5 タブ相当のプロセス起動負荷を発生させて再計測する。
  2. 静穏アイドル条件でも `t=273..544.5s` 型の一過性 `MEM_PRIVATE` バーストが再現する場合は、`ledr-sensor-win` と `ledr-daemon` における一時的な ETW や AMSI バッファの計測と対策を別 PR として切り出して調査する。
  3. 上記の `L-24` 再計測と `FU-E2E-01` および `FU-E2E-02` の統合実機 E2E が完了するまで、[implementation-plan.md](implementation-plan.md) の未完了チェックリスト 3 件（`[ ]`）は未更新のまま維持する。

## FU-P4-02 View 1 の WindowsApps バージョン部ワイルドカード永続許可と実機確認対象

### 対象ファイル

- プロトコルおよび共通テストベクタ：[crates/ledr-proto/src/lib.rs](../crates/ledr-proto/src/lib.rs)（`AllowPermanentPathMode`、`build_windows_apps_version_wildcard_pattern`、`IpcRequest::ResolveAlertWithOptions`）および [windows_apps_wildcard_vectors.json](../crates/ledr-proto/tests/fixtures/windows_apps_wildcard_vectors.json)
- ルール照合：[matcher.rs](../crates/ledr-rules/src/allowlist/matcher.rs) および [crates/ledr-rules/src/lib.rs](../crates/ledr-rules/src/lib.rs)（`matches_path_pattern` の非 UNC `\\?\` 正規化と `WindowsApps` パターンのセグメント内 `*` 閉じ込め、ならびに変換関数の再エクスポート）
- デーモン認可、解決、および WFP 整合：[dispatch.rs](../crates/ledr-daemon/src/ipc/dispatch.rs)（`ResolveAlertWithOptions` の `CallerAuthPolicy::UiOnly` 登録）、[alerts.rs](../crates/ledr-daemon/src/engine/alerts.rs)（`resolve_alert_with_options_and_outcome`）、および [reconcile.rs](../crates/ledr-daemon/src/firewall/reconcile.rs)（終了済み非起動ピン留め `Preemptive` ブロック解放）
- Tauri ブリッジおよび View 1 UI：[apps/ledr-ui/src/ipc.rs](../apps/ledr-ui/src/ipc.rs)、[apps/ledr-ui/src/commands.rs](../apps/ledr-ui/src/commands.rs)、[apps/ledr-ui/ui/index.html](../apps/ledr-ui/ui/index.html)、[apps/ledr-ui/ui/app.js](../apps/ledr-ui/ui/app.js)、および [phase4_ui.test.mjs](../apps/ledr-ui/js-tests/phase4_ui.test.mjs)

### 背景と実装仕様

`C:\Program Files\WindowsApps\<PackageFullName>\<RelPath>` 配下の署名済みストアアプリは `GeneralUnknown` として監視され、通信やファイル操作時にアラートが発生し得る。
従来の View 1 の「Allow Permanent Rule」は具体フルパスをそのまま `exe_path_pattern` として `allowlist_rules` テーブルへ保存するため、Microsoft Store の自動更新で `<PackageFullName>` 内のバージョン部が変化するたびに照合不一致となり、再アラートと一時遮断が繰り返されていた。

この運用負荷を解消しつつ最小権限を維持するため、バージョン部のみを `*` へ置換する永続許可を以下の境界条件で実装する。

- **29 バイトプレフィックス強制と `AppExecutionAlias` 除外**：入力パスは正規化後に先頭 29 バイトが `C:\Program Files\WindowsApps\`（ASCII 大文字小文字無視、システムドライブ `C:` 固定）へ一致する場合のみ対象とする。
  これにより `%LOCALAPPDATA%\Microsoft\WindowsApps\` 配下の 0 バイト `AppExecutionAlias` リパースポイントスタブや、非特権ユーザーが作成し得る非システムドライブおよび `subst` ドライブを除外する。
- **厳密な 7 ステップ変換仕様（Rust と JS の共通規則）**：前後の ASCII 空白除去と ASCII 制御文字（`0x00..=0x1F` と `0x7F`）拒否（ステップ 1）、`/` から `\` への置換および `\\?\UNC\`、UNC（`\\`）、`\\.\`、`\??\` を拒否した上での非 UNC `\\?\` 先頭 4 バイト除去（ステップ 2）、先頭 29 バイト一致確認（ステップ 3）、30 バイト目以降（`[29..]`）での `*`、`?`、`:`、末尾 `\`、空セグメント、`.`、`..` の拒否（ステップ 4）、`<PackageFullName>` と `<RelPath>` への分割および最終セグメントの 5 バイト以上かつ `.exe` 終端検証（ステップ 5）、`<PackageFullName>` の `_` 5 分割検証（`<Name>` が `1..=50` 文字 `[A-Za-z0-9.-]`、`<Version>` が `.` 4 要素の `0..=65535` ASCII 数字かつ `+` および先頭ゼロ不可、`<Arch>` が `x86`、`x64`、`arm`、`arm64`、`neutral` のいずれか、`<ResourceId>` が `0..=30` 文字 `[A-Za-z0-9.-]`、`<PublisherId>` が厳密 13 文字の Crockford Base32 `[0-9a-hjkmnp-tv-z]`）（ステップ 6）、ならびに固定プレフィックスと `<Version>` のみを `*` へ置換して残りの文字ケースを保持したパターン生成（ステップ 7）を実行する。
- **セグメント内 `*` 閉じ込め**：`matches_path_pattern` は非 UNC `\\?\` を除去した上で、正規化後パターンが `WindowsApps` バージョンワイルドカード形式（`c:\program files\windowsapps\<Name>_*_<Arch>_<ResourceId>_<PublisherId>\<RelPath>`）に一致する場合に限り `*` がパス区切り `\` を跨がない（`s[si] != '\\'`）制限を適用し、同一署名者の別パッケージ配下にある偽装サブパスとの誤一致を防止する。
  View 3 で手動登録された汎用パターン（`C:\Program Files\WindowsApps\*\App.exe` 等）や既存の `"*\Google\Chrome\User Data\*"` 等の互換性は変更せず維持する。
- **`L-04` 署名必須とフェイルクローズ**：View 1 の「Wildcard Store app version」チェックボックスは既定 OFF とし、`AllowPermanentPathMode::WindowsAppsVersionWildcard` 指定時は `use_signer_if_available == true`、非空 `signer_subject`、非空かつ非オールゼロ `root_thumbprint`（`L-04`）、および有効パターン生成をすべて必須とする。
  いずれか 1 つでも欠ける場合、またはプロセス紐付きのない `LAYER_4_BROWSER` や `AllowPermanent` 以外の決定が指定された場合は SHA-256 ルールへフォールバックせずエラーで拒否する（`LAYER_3_NETWORK` のアプリ単位 WFP アラートでは `process_instance_id` 未特定でも `exe_path` と検証済み署名が揃えば許可を作成でき、`NetworkAllow` と `FileCanaryAllow` の双方および宛先限定に対応して `AllowlistRuleRecord` の `sha256` は `None` とする）。
- **後方互換 IPC と WFP 解放**：既存の `AlertDecision` と `IpcRequest::ResolveAlert` は無変更のまま維持し、`Exact` 時は `ResolveAlert`、ワイルドカード選択時のみ `CallerAuthPolicy::UiOnly` の `ResolveAlertWithOptions` を送信する。
  `TransientContainment` は既存の解決経路で確実に解放し、終了済みプロセスの非起動ピン留め `Preemptive` ブロックは不要な `PersistedPolicy` Permit チャーンを起こさずに解放する（再起動済みの生存プロセスやオーバーフロー状態がある場合は `Preemptive` ブロックの削除を抑止する）。

### 実機未検証境界（Windows 10 または Windows 11 クライアント SKU 確認対象）

合成単体テストおよび UI モック DOM テストは実ストアアプリの更新やカーネル挙動を代替しないため、Windows 10 または Windows 11（x86_64）クライアント SKU 実機で以下の 3 点を別途検証する。

1. 実 Microsoft Store アプリ（例として `Microsoft.StartExperiencesApp`）のアラートに対し、View 1 で「Wildcard Store app version」を ON にして「Allow Permanent Rule」を実行したとき、View 3 に `C:\Program Files\WindowsApps\<Name>_*_<Arch>_<ResourceId>_<PublisherId>\<RelPath>` と Authenticode 署名付きルールが登録されて通信が許可されること。
2. ストアアプリ更新後（新バージョンディレクトリ配下のバイナリ起動および通信時）に、宛先無制限の `NetworkAllow` ルールではユーザー再アラートおよび遮断なしで通信許可が継続すること、ならびに宛先限定（IP、CIDR、またはドメイン）ルールかつ事前遮断対象（MOTW 等）では新版初回接続時の WFP ドロップ評価（`outbound.rs`）を経てユーザー再アラートなしに IP Permit が追加され通信が継続すること（初回接続の 1 パケットドロップを伴う境界を含む）。
3. `%LOCALAPPDATA%\Microsoft\WindowsApps\` 配下の `AppExecutionAlias` スタブ経由または該当パスでは、ワイルドカード対象外として View 1 に「Wildcard Store app version」チェックボックスが表示されないこと。

なお、個別ストアアプリごとの実機署名文字列（`signer_subject`）の棚卸しを要する `rules/default_allowlist.json` への既定ルール追加は、本件の対象外として分離する。

## FU-P4-03 汎用ホストプロセス（backgroundTaskHost.exe 等）向け後方互換プロトコル、ルール、および WFP 拡張設計

### 背景と確定した運用境界

`C:\Windows\System32\backgroundTaskHost.exe` 等の汎用ホストプロセスは、単一のシステムバイナリかつ同一の Microsoft Windows 署名を持ちながら、起動引数（`-ServerName:...`）や AppContainer パッケージコンテキストに応じて Microsoft 標準タスクとサードパーティ製ストアアプリタスクの双方を実行する。
現行の `AllowlistRuleRecord` は実行ファイルパス、ハッシュ、署名、および通信先しか保持しないため、宛先無制限（`allowed_target: null`）の許可を与えるとサードパーティ製タスクの通信まで全許可してしまう。

本項目では後続実装に向けた単一アーキテクチャ設計を以下のとおり確定し、未決の選択肢を残さない。

- **無条件許可の不採用**：`backgroundTaskHost.exe` 等に対する `allowed_target: null` の無条件 `NetworkAllow` は採用しない。
- **非 AppContainer タスクの Layer 3 境界**：拡張実装後も、AppContainer パッケージ SID を持たない非パッケージ型の `-ServerName:` タスクは Layer 3（WFP）でのパッケージ分離対象外と確定し、宛先ドメインまたは IP 限定ルールあるいは `AllowOnce` 運用を継続する。

### 識別軸と適用可能スコープの分離

- **AppContainer と Package 識別（`package_family_name` と `package_sid`）**：WFP の `FWPM_LAYER_ALE_AUTH_CONNECT_V4` および `FWPM_LAYER_ALE_AUTH_CONNECT_V6` は `FWPM_CONDITION_ALE_APP_ID` と `FWPM_CONDITION_ALE_PACKAGE_ID`（`FWP_SID`）の複合条件を持つ。
  そのため、Layer 3（`NetworkAllow` と `NetworkBlock`）のカーネル強制および Layer 1 と Layer 2（`ProcessAllow` と `FileCanaryAllow`）の全 4 スコープへ適用する。
  パッケージ単位の WFP フィルタ数はユーザーが明示登録したパッケージ数（想定数件から数十件）に有界となる。
- **コマンドライン引数識別（`command_line_pattern`）**：長さ `1..=512` 文字、ASCII 制御文字禁止、およびエスケープなしの `*` ワイルドカード（ASCII 大文字小文字無視）として定義する。
  WFP カーネルはコマンドライン条件を持たずユーザー空間 PEB には書き換え耐性がないため、Layer 3（`NetworkAllow` と `NetworkBlock`）での使用は禁止し、起動時 ETW 捕捉値を用いる Layer 1 と Layer 2（`ProcessAllow` と `FileCanaryAllow`）に限定する。

### 後方互換データモデル、IPC、および原子的解決設計

- **既存公開型と既存テーブルの凍結維持**：既存の `AllowlistRuleRecord`、`ProcessRecord`、`ActiveDefenseController::add_wfp_app_rule`、および SQLite の `allowlist_rules` テーブルは変更しない。
  `crates/ledr-store/src/schema.rs` の `row_to_rule` は未知の `scope` 文字列に対して `StoreError::InvalidValue` を返して `list_rules()` 全体を失敗させるほか、既存行の共有は旧コード参照時に汎用ホスト全許可へフェイルオープンする危険があるためである。
- **プロセス属性保存と UI 受け渡し**：`processes` テーブルへ nullable 列 `package_family_name TEXT` と `package_sid TEXT` を冪等な `ALTER TABLE` マイグレーションで追加し、アラート生成時に `alerts.context_json` へ両フィールドを埋め込む。
  これにより公開型 `ProcessRecord` を変更せずに View 1 へパッケージ情報を渡せる。
- **専用テーブル `scoped_policy_rules`**：全 4 スコープ（`RuleScope`）を格納する専用テーブル `scoped_policy_rules` を新設し、列は `rule_id`、`scope`、`exe_path_pattern`、`sha256`、`signer_subject`、`root_thumbprint`、`allowed_target`、`package_family_name`、`package_sid`、`command_line_pattern`、`created_at_ms`、`created_by` とする。
- **新規 IPC 型（すべて `CallerAuthPolicy::UiOnly`）**：新規型 `ScopedPolicyRuleRecord` と CRUD 用の `UpsertScopedRule`、`DeleteScopedRule`、および `ListScopedRules` に加え、View 1 でプロセス再開、終了、状態遷移、および補償ロールバックを原子的に実行する `ResolveAlertScoped { alert_id, decision, scope_to_package: bool }` を追加する。
  汎用ホストプロセスに対して `scope_to_package: true` で `TerminateAndBlock { add_block_rule: true }` を実行したとき、対象プロセスに `package_sid` があればパッケージ単位 `NetworkBlock` を `scoped_policy_rules` へ保存し、非 AppContainer の場合は OS 全体のホスト遮断を防ぐため永続ブロック保存をスキップする。
- **トレイト拡張**：`ActiveDefenseController` へデフォルト実装付きの `add_wfp_scoped_app_rule(&self, exe_path: &Path, package_sid: Option<&str>, remote_ip: Option<IpAddr>, allow: bool) -> Result<u64, String>` を追加し、`package_sid` が `None` のときは `add_wfp_app_rule` へ委譲し、`Some(_)` のときは既定実装として `Err`（フェイルクローズ）を返す。

### 事前 API スパイク（約 1 日）の合格基準と不合格時フォールバック

- **合格基準**：第 1 に、`windows` クレートで `FWPM_CONDITION_ALE_PACKAGE_ID` 付きフィルタが BFE に受理され、同一 `backgroundTaskHost.exe` の異なる AppContainer SID 間で通信許可と遮断が分離されることを確認する。
  第 2 に、`FwpmNetEventSubscribe1` の `FWPM_NET_EVENT_HEADER3`（取得不可ビルドではプロセス表のトークン `TokenAppContainerSid` へフォールバック）および起動時 `GetPackageFamilyName` の値が `DeriveAppContainerSidFromAppContainerName` で導出した SID と一致することを確認する。
- **不合格時フォールバック**：カーネルでの `FWPM_CONDITION_ALE_PACKAGE_ID` 事前フィルタ設置が環境制約により不成立の場合は、BFE へのアプリ全体 Permit 登録を行わず、プロセス起動時トークンから取得した `package_sid` を用いたデーモン空間 `evaluate_outbound_policy` 評価と通信先 IP 限定の一時 Permit 運用へ縮退する。

#### 事前 API スパイク実測結果（2026-11-28、合格）

- **検証環境と診断ツール**：Windows クライアント SKU（`DisplayVersion=26H2`、`Build=26300.9974`、`Edition=Core`、x86_64、管理者 PowerShell）上で、実機診断ツール [spike_wfp_package_id.rs](../crates/ledr-sensor-win/examples/spike_wfp_package_id.rs)（[Cargo.toml](../Cargo.toml) の `windows` 依存へ `Win32_Security_Isolation` と `Win32_Storage_Packaging_Appx` を追加）を用いて検証した。
- **合格基準 1（BFE 受理および同一バイナリ異 SID 分離）**：`C:\Windows\System32\backgroundTaskHost.exe` と `C:\Windows\System32\curl.exe` の双方で `FWPM_CONDITION_ALE_APP_ID` と `FWPM_CONDITION_ALE_PACKAGE_ID`（`FWP_SID`）の複合条件フィルタ（IPv4 と IPv6 の Permit と Block 計 4 本）がすべて `ERROR_SUCCESS` で受理され、動的セッション終了時に自動消去されることを確認した。
  `--self-test-wfp` で同一 `curl.exe` を 2 つの一時 AppContainer SID から `http://1.1.1.1/` へ接続させた結果、Permit 側 SID は `exit_code=0`（56ms）、Block 側 SID は `exit_code=7`（26ms）となり、SID 単位の通信分離を確認した。
- **合格基準 2（SID 導出一致および WFP ネットイベント `packageSid`）**：管理者権限による稼働中プロセス全件走査（`open_denied=0`、計 361〜363 プロセス、`backgroundTaskHost.exe` 2 本を含む）で、パッケージ付き AppContainer プロセス 12 件すべてについて `DeriveAppContainerSidFromAppContainerName(GetPackageFamilyName)` と `GetTokenInformation(TokenAppContainerSid)` の完全一致（`sid_mismatch=0`）を確認した。
  さらに `--self-test-wfp` の Block ドロップ時に、現行 [net_events.rs](../crates/ledr-sensor-win/src/wfp/net_events.rs) が使用する `FwpmNetEventSubscribe1`（`FWPM_NET_EVENT2` と `FWPM_NET_EVENT_HEADER2`）で `FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET`（`flag_pkg=true`）と Block 側 SID に一致する `header.packageSid` を捕捉した。
- **Track B-1〜B-3 へ反映する実測境界**：
  1. `FwpmNetEventSubscribe1`（`FWPM_NET_EVENT_HEADER2.packageSid`）のみで `packageSid` を取得できるため、`FwpmNetEventSubscribe2` への移行は不要とする。
  2. `RuntimeBroker.exe`、`MicrosoftStartFeedProvider.exe`、`StartMenuExperienceHost.exe`、`SnippingTool.exe`、`gamingservices.exe` 等は `GetPackageFamilyName` が非空でも `TokenAppContainerSid` が `None`（`PFN_ONLY_NON_APPCONTAINER`）であり、逆に `fontdrvhost.exe` や `DefenderAiPlatformHost.exe` は `TokenAppContainerSid` のみを持つ（`TOKEN_SID_ONLY`）。
     そのため Track B-1 と Track B-2 では `package_family_name` と `package_sid` をそれぞれ独立した `Option<String>` として取得し、`PFN_ONLY_NON_APPCONTAINER` に対して `DeriveAppContainerSidFromAppContainerName` で架空の `package_sid` を補完しない。
- **判定**：合格基準 1 と 2 の双方を満たしたため、フォールバック設計へ縮退せず、確定設計どおり Track B-1 の実装へ進む。

### 段階的な実装計画（計約 4.5〜5 日）と各 PR の受け入れ基準

本拡張は上記の事前 API スパイク（約 1 日）の完了後、以下の 3 本の独立した PR へ分割して進める。

1. **Track B-1（1 PR、約 1 日）**：プロセス起動時トークンおよび WFP イベントからの `package_family_name` と `package_sid` 収集、`processes` 補助列マイグレーション、ならびに `alerts.context_json` 出力を実装する。
   受け入れ基準は、既存 `ProcessRecord` 無変更のまま単体テストと実機ストアタスク起動の双方で両フィールドが記録されることとする。
2. **Track B-2（1 PR、約 1.5〜2 日）**：`scoped_policy_rules` ストア、バリデーション（`NetworkAllow` は `L-04` 署名、非空 `package_family_name`、および `package_sid` を必須とし、`command_line_pattern` 単独は不可）、ならびに `add_wfp_scoped_app_rule` と `ResolveAlertScoped` を実装する。
   受け入れ基準は、同一ホスト上の別 `package_sid` が通信許可されないこと、旧 `list_rules()` が影響を受けないこと、および WFP 同期失敗時に保存済みルールが補償ロールバックされることとする。
3. **Track B-3（1 PR、約 1 日）**：View 1（パッケージ単位の許可と遮断チェック）および View 3（スコープ付きルール一覧、作成、および削除）の UI 実装と実機 E2E を実施する。
   受け入れ基準は、UI モック DOM テスト全件合格、ならびに Windows 10 または Windows 11 実機で `backgroundTaskHost.exe` の特定パッケージのみを恒久許可できることとする。
