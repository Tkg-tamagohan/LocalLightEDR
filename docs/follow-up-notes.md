# LocalEDR 申し送り事項と実機検証計画

本書は LocalEDR の各 Phase を `main` ブランチへマージした後に残した副次的な改善余地と、合成自動テストでは検証済みと扱わない実機 E2E 検証の対象を管理する。
仕様の正は [implementation-plan.md](implementation-plan.md)、[decision-records.md](decision-records.md)（L-01 から L-24）、および凍結済みの [crates/ledr-proto/src/lib.rs](../crates/ledr-proto/src/lib.rs) に置き、本書では後続作業へ引き継ぐ個別項目を ID ごとに記録する。

## 項目一覧

| ID | 種別 | 関連 Phase | 概要 | 対応予定 |
| :--- | :--- | :--- | :--- | :--- |
| `FU-P3-01` | 副次最適化 | Phase 3 | `merge_domain_hints_prioritized` の満杯 32 件時に起きる非許可同居ヒントの再挿入抑制 | 次回 `crates/ledr-daemon/src/firewall/` 改修または後続整備 PR |
| `FU-P4-01` | 副次改善 | Phase 4 | `ledr-bridge-nm` の `HKLM` 登録および確認における 32 ビットレジストリビュー（`KEY_WOW64_32KEY`）対応 | 次回 `crates/ledr-bridge-nm/` 改修または後続整備 PR |
| `FU-E2E-01` | 実機 E2E 検証 | Phase 2、Phase 3 | Windows 10 または Windows 11 クライアント SKU 管理者環境での実機検証 | 独立した実機 E2E 検証 PR |
| `FU-E2E-02` | 実機 E2E 検証 | Phase 4 | Windows 10 または Windows 11 クライアント SKU 上での Chrome 拡張、Native Messaging、MOTW、および UI 終了の実機検証 | 独立した実機 E2E 検証 PR |
| `FU-E2E-03` | 性能最適化 | Phase 3、Phase 4 | `E2E-PERF-01` 超過に対する Stage 1〜3 最適化（`ledr-auth-helper` 分離、LRU 上限、非系譜解放、SQLite reader 縮小、`PrivateWorkingSetSize <= 20.0 MB` 基準併記） | 本作業ブランチ（`perf/fu-e2e-03-memory-reduction`）で実装と実機再計測を完了（マージ後の最終 E2E で再確認） |
| `FU-E2E-04` | 検知改善 | Phase 1、Phase 3 | 短命プロセス（約 40 ms）での PEB 補完欠落による `command_line` 欠落と `LEDR-LOTL-001`（正規管理ツール悪用検知ルール）未発火の解消 | 次回センサーおよび ETW 改善 PR |
| `FU-E2E-05` | 境界改善 | Phase 3 | WFP ドロップの終了済み兄弟プロセス由来の誤帰属抑止および `E2E-P3-06` 停止予算超過時の残余書き込みによる `-wal` 再生成の整理 | 次回デーモン境界改善 PR |

### 推奨着手順と用語の補足

実機 E2E で見つかった 3 件の課題（`FU-E2E-03` から `FU-E2E-05`）は、次の順で後続 PR を分割して進める。

1. まず検知と停止の正確性に直結する `FU-E2E-04`（短命プロセスの `command_line` 欠落）と `FU-E2E-05`（WFP ドロップ誤帰属と停止後 `-wal` 再生成）を解消する。
2. 次にセンサーとデーモンの挙動が確定した状態で `FU-E2E-03`（`WorkingSet64` の原因分析とメモリ削減）を実施し、機能改修によるメモリ消費の変化も含めて最適化する。
3. 上記 3 件と PR #34 を `main` へマージした後、`main` 上の実機再検証で `FU-E2E-01` と `FU-E2E-02` の全必須項目が通過したことを確認してから [implementation-plan.md](implementation-plan.md) の該当チェックリストを `[x]` へ更新する。

本書で参照する主な識別子と用語の意味を以下に補う。

- **ルート 1**：[e2e-test-runbook.md](e2e-test-runbook.md) に定める、Phase 2 から Phase 4 の全項目と性能計測を 1 台の検証機で通し実施する統合検証ルート。
- **`L-08` と `L-17`**：[decision-records.md](decision-records.md) の決定記録 ID であり、`L-08` はウィンドウ閉鎖時に `ledr-ui` と WebView2 を 0 プロセスで終了させる制約、`L-17` は Phase 4 を PR 4A、4B、4C の 3 本へ分割する計画を指す。
- **`SEC_0001` から `SEC_0003`**：各レビューと実装で付けたセキュリティ不変条件 ID であり、WFP 許可キャッシュではバイナリ差し替えやルール削除時の古い Permit 失効（`SEC_0001`）と別実行ファイル間の Permit 非継承（`SEC_0002`）を、Named Pipe IPC ではセッション時間上限（`SEC_0001`）、クライアントバイナリ検証（`SEC_0002`）、およびブリッジ側のサーババイナリ検証（`SEC_0003`）を指す。
- **`LEDR-LOTL-001`**：`powershell.exe` 等の正規管理ツールが難読化引数や危険なパターンで起動された挙動を検知する Sigma ルール ID。
- **`exe_key`**：実行ファイルパスを大文字小文字や区切り文字の違いを除いて正規化した識別子。

## FU-P3-01 満杯 32 件時の非許可同居ヒント再挿入の抑制

### 対象ファイル

- 残存挙動の実装箇所：[firewall/hints.rs](../crates/ledr-daemon/src/firewall/hints.rs#L45-L85)（`merge_domain_hints_prioritized`、Loop 1 は [L52-L67](../crates/ledr-daemon/src/firewall/hints.rs#L52-L67)、Loop 2 は [L69-L84](../crates/ledr-daemon/src/firewall/hints.rs#L69-L84)）
- 主訴を解消した保護ヘルパ：[domain_policy.rs](../crates/ledr-daemon/src/engine/domain_policy.rs#L198-L221)（`extend_authorizing_hints_from_existing_permit`）
- 保護ヘルパの呼び出し 4 経路：[resolve_alert_with_outcome](../crates/ledr-daemon/src/engine/alerts.rs#L544-L551)（`AllowPermanent`）、[prematerialize_domain_wfp_filters](../crates/ledr-daemon/src/engine/wfp_premat.rs#L340-L347)、[handle_ambiguous_wfp_drop](../crates/ledr-daemon/src/engine/wfp_drops.rs#L733-L740)、および [evaluate_and_handle_outbound_connect](../crates/ledr-daemon/src/engine/outbound.rs#L428-L435)
- 関連する回帰テスト：[cached_permit.rs](../crates/ledr-daemon/src/engine/tests/cached_permit.rs#L383-L541)（DNS 履歴退避後かつ非許可同居ヒントによる満杯 32 件超過時の既存許可根拠維持を検証する `DAEMON-P3-49A` §7）と [phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L8136-L8648)（共有 IP 移行時の Permit 維持と安全境界を E2E 検証する `DAEMON-P3-48`）

### 背景と出典

本件は Phase 3 の PR #5（ブランチ `phase-3-wfp-firewall`、マージコミット `3fe1031` / `3fe1031fc3692beab77e0eeb531f27e6e56c888e`）に対する Review #40 で指摘された事項から切り出した副次申し送りである。
出典のレビュースレッドは `PRRT_kwDOVyjVyM65hO2j`（指摘 ID `BUG_pr-review-job-23fb353b86b648aaa95062ec74d199a4_0001`、指摘対象コミット `4e11596`）であり、満杯の 32 件 Permit フィルタを更新する際のヒント退避順序が論点となった。

### 現行の保証範囲

解消済みの主訴と未変更の残存挙動を区別して以下に記す。

#### 解消済み事項

Review #40 の主訴だった「満杯 32 件の Permit フィルタを更新するときに有効な既存許可根拠が消える問題」は、コミット `3666680`（`366668061c4ddd06a6a269d40a0b1c5860d7af51`）で解消した。
具体的には [domain_policy.rs](../crates/ledr-daemon/src/engine/domain_policy.rs#L198-L221) に `extend_authorizing_hints_from_existing_permit` を追加し、Permit の登録と更新を行う 4 経路すべて（[alerts.rs#L544-L551](../crates/ledr-daemon/src/engine/alerts.rs#L544-L551)、[wfp_premat.rs#L340-L347](../crates/ledr-daemon/src/engine/wfp_premat.rs#L340-L347)、[wfp_drops.rs#L733-L740](../crates/ledr-daemon/src/engine/wfp_drops.rs#L733-L740)、[outbound.rs#L428-L435](../crates/ledr-daemon/src/engine/outbound.rs#L428-L435)）で既存の有効な許可ドメインを事前に保護集合へ組み込んだ。

この修正により、保護対象となる許可ヒントの総数が上限 `MAX_DOMAIN_HINTS_PER_FILTER`（32 件）以内である限り、非許可の同居ヒントによって上限を超過しても、DNS 履歴から退避された後の既存許可根拠は押し出されない。
一方、`ensure_ip_permit_for_domain_hints_prioritized` の許可ヒント正規化（[firewall/domain_policy.rs](../crates/ledr-daemon/src/firewall/domain_policy.rs#L142-L145) が呼ぶ `merge_domain_hint` の [firewall/hints.rs#L25-L36](../crates/ledr-daemon/src/firewall/hints.rs#L25-L36)）および `merge_domain_hints_prioritized` の Loop 1（[firewall/hints.rs#L56-L65](../crates/ledr-daemon/src/firewall/hints.rs#L56-L65)）では、許可ヒント単体で 32 件を超過した場合に上限維持のため古い許可ヒントが保護対象から外れて先入れ先出しで退避される。
非許可の同居ヒントによる満杯 32 件超過かつ DNS 履歴退避後に既存許可根拠が維持される条件は、単体結合テスト `DAEMON-P3-49A` §7（[cached_permit.rs](../crates/ledr-daemon/src/engine/tests/cached_permit.rs#L383-L541)）で検証済みである。
あわせて、コミット `2c05747`（`2c0574749db91ae07bbdc8782c6b07dd28127c2a`）では共有 IP 移行時の Permit 維持と安全境界（Review #38 / `AUD-P3-01`）を E2E 検証する統合回帰テスト `DAEMON-P3-48`（[phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L8136-L8648)）を追加した。
`3666680` に対する Devin Review #41（`2026-11-19T14:09:13Z`）および `2c05747` に対する最終 Devin Review（`2026-11-19T14:35:04Z`）はいずれも `0 new potential issues` を報告した。

#### 未変更の残存挙動

[firewall/hints.rs](../crates/ledr-daemon/src/firewall/hints.rs#L45-L85) の `merge_domain_hints_prioritized` では、`target` が上限 `MAX_DOMAIN_HINTS_PER_FILTER`（32 件）に達した状態で Loop 1（[L52-L67](../crates/ledr-daemon/src/firewall/hints.rs#L52-L67)）が新しい許可ヒントを追加するとき、先頭の非保護スロットに置かれた既存非許可同居ドメインを 1 件退避する。
同じ呼び出しの `cohosted_hints` にその退避済みドメインが含まれると、Loop 2（[L69-L84](../crates/ledr-daemon/src/firewall/hints.rs#L69-L84)）は更新後の `target` に該当要素がないため新規扱いとして末尾へ再挿入する。
この再挿入によって、同じバッチ内で別の非許可同居ヒントが 1 件余分に押し出される挙動が残っている。

呼び出し側の 4 経路が既存の有効な許可根拠を保護集合へ組み込み、Loop 2 は保護対象スロットを退避しないため、本挙動は許可ヒント上限 32 件以内の既存許可根拠保護、deny-overrides-allow、`SEC_0001`、および `SEC_0002` のセキュリティ境界へ影響しない。
非許可同居ヒント同士のローテーション効率にとどまる低優先度の内部改善余地として扱う。

### 改善方針

`merge_domain_hints_prioritized` の開始時点で `target` に含まれていた非保護ヒントの集合を保持し、Loop 1 で退避された既存非許可同居ヒントを同一バッチの Loop 2 で新規要素として再挿入しないように修正する。
あわせて、満杯 32 件の `target` へ新規許可ヒントと既存非許可同居ヒントを同時に渡したときに余分な 1 件の押し出しが起きないことを検証する単体境界テストを `crates/ledr-daemon/src/firewall/tests.rs` へ追加する。

### 対応予定タイミング

次回の `crates/ledr-daemon/src/firewall/` 改修時、または Phase 4 以降の保守整備 PR で対応する。

## FU-E2E-01 Windows 10 または Windows 11 クライアント SKU での実機 E2E 検証

### 対象ファイルと手順書

- 実機検証手順書（統合版）：[e2e-test-runbook.md](e2e-test-runbook.md)（Track A および Track C）
- 実機検証手順書（Phase 2・3 個別版）：[phase2-3-e2e-runbook.md](phase2-3-e2e-runbook.md)
- Phase 2 の ETW 監視対象：[etw/handlers.rs](../crates/ledr-sensor-win/src/etw/handlers.rs#L22-L25)（プロバイダ GUID）、[etw/session.rs](../crates/ledr-sensor-win/src/etw/session.rs#L443-L456)（購読登録）、[etw/registry.rs](../crates/ledr-sensor-win/src/etw/registry.rs#L18-L39)（`handle_kernel_registry`）、[etw/registry.rs](../crates/ledr-sensor-win/src/etw/registry.rs#L121-L246)（`CloseKey` 無効化を含む `decide_registry_event`）、および [file_canary/mod.rs](../crates/ledr-sensor-win/src/etw/file_canary/mod.rs#L266-L304)（`prefilter_and_classify_canary_u16`）
- Phase 2 のプロセス制御と通知対象：[defense/controller.rs](../crates/ledr-sensor-win/src/defense/controller.rs#L172-L188)（`NtSuspendProcess`）、[defense/controller.rs](../crates/ledr-sensor-win/src/defense/controller.rs#L392-L437)（`terminate_process`）、[notify.rs](../crates/ledr-daemon/src/notify.rs#L109-L255)（`notify_alert_with_session` と `try_launch_in_active_session`）、[apps/ledr-ui/src/cli.rs](../apps/ledr-ui/src/cli.rs#L68-L104)（`parse_launch_mode`）、[apps/ledr-ui/src/uri_reg.rs](../apps/ledr-ui/src/uri_reg.rs#L281-L291)（`ensure_hkcu_ledr_uri_registered`）、および [apps/ledr-ui/src/notify.rs](../apps/ledr-ui/src/notify.rs#L354-L372)（`dispatch_notify_oneshot`）
- Phase 3 の WFP 制御対象：[wfp/backend.rs](../crates/ledr-sensor-win/src/wfp/backend.rs#L129-L172)（`open_dynamic`）と [wfp/backend.rs](../crates/ledr-sensor-win/src/wfp/backend.rs#L626-L647)（`FwpmNetEventSubscribe1` 購読）
- Phase 3 のネットワーク ETW と NRD 対象：[etw/handlers.rs](../crates/ledr-sensor-win/src/etw/handlers.rs#L26-L29)（プロバイダ GUID）、[etw/session.rs](../crates/ledr-sensor-win/src/etw/session.rs#L457-L470)（購読登録）、[nrd/cancel.rs](../crates/ledr-rules/src/nrd/cancel.rs#L62-L86)（`NrdCancelToken` のブロッキング読み取り観測）、[nrd/url.rs](../crates/ledr-rules/src/nrd/url.rs#L98-L135)（`parse_file_url`）、[nrd/reader.rs](../crates/ledr-rules/src/nrd/reader.rs#L15-L114)（`read_bounded_file` と `read_bounded_reader_cancellable`）、[crates/ledr-daemon/src/main.rs](../crates/ledr-daemon/src/main.rs#L260-L261)（`RUST_LOG` による `EnvFilter` 初期化）、[crates/ledr-store/src/lib.rs](../crates/ledr-store/src/lib.rs#L222-L227)（`LedrStore::checkpoint_truncate` の `completed wal_checkpoint(TRUNCATE)` ログ）、[nrd.rs](../crates/ledr-daemon/src/engine/nrd.rs#L18-L26)（`is_nrd_refresh_in_flight` と `nrd_cancel_token`）、[lifecycle.rs](../crates/ledr-daemon/src/engine/lifecycle.rs#L316-L360)（停止時チェックポイント優先と NRD デタッチ、デタッチ警告ログは [L355-L358](../crates/ledr-daemon/src/engine/lifecycle.rs#L355-L358)）、および [pipeline.rs](../crates/ledr-daemon/src/engine/pipeline.rs#L217-L259)（`ledr-nrd-refresh` スレッド）

### 背景と出典

Phase 2 は PR #3（ブランチ `phase-2-canary-suspend`、マージコミット `a68bce5` / `a68bce5eb73922a0ebcfb6c052a430c620050958`）で、Phase 3 は PR #5（ブランチ `phase-3-wfp-firewall`、マージコミット `3fe1031` / `3fe1031fc3692beab77e0eeb531f27e6e56c888e`）で `main` へマージした。
[AGENTS.md](../AGENTS.md) の Phase 2 不変条件、Phase 3 不変条件、および標準検証コマンドの定めにより、OS カーネルや実サービス環境に依存する挙動は合成テストだけでは検証済みとみなさない。

### 現行の保証範囲

#### 確認済み事項

Phase 2 と Phase 3 の実装は静的検査（`cargo clippy --workspace --all-targets --locked -- -D warnings`）、ワークスペース全体の単体および統合テスト（`cargo test --workspace --locked`）、バースト負荷テスト（`burst_budget`）、および TTL 回帰テスト（`ttl_purge_lineage`）に合格して `main` へマージ済みである。

2026 年 11 月 22 日に `Windows 11 Home`（`10.0.26300`、`ProductType = 1`、基盤コミット `9c8373e` に未マージの PR #34 ブランチ `fix/e2e-pipe-dacl-dev-bypass` の Named Pipe DACL 修正を加えた検証構成）で [e2e-test-runbook.md](e2e-test-runbook.md) のルート 1（全 Phase 統合ルート）を実施し、Track A の以下を確認した。
なお、本実測は未マージの PR #34 を前提とした暫定結果であり、PR #34 および後続の改善 PR を `main` へマージした後に改めて `main` 上で再検証する前提とする。

- **通過項目**：`PREP-01` から `PREP-04`、`E2E-P2-01` から `E2E-P2-06`、`E2E-P3-01`、`E2E-P3-02`、`E2E-P3-04`、`E2E-P3-05`（公開 2 フィード `feeds_succeeded = 2`、`feeds_failed = 0`、`entries = 50000`）、`E2E-P3-07`（`taskkill /F` 後の WFP フィルタ 0 件消去）、および `E2E-UI-01`（0 プロセス終了）が実機で通過した。
- **部分確認項目**：`E2E-P3-06` は `wal_checkpoint(TRUNCATE)` の NRD デタッチ先行完了とマーカー行の永続化のみを確認した（約 3 秒でのシェル復帰と停止後の `-wal == 0` 維持は未達のため全体合格とは区別し、`FU-E2E-05` へ切り出した）。
- **定常 CPU 基準**：`E2E-PERF-01` の定常 CPU 使用率はアイドル 600 秒で `0.2876%`、高負荷 60 秒で `0.3076%` となり、0.5% 未満の基準を満たした。

#### 未検証および残存の課題

- `E2E-PERF-01` の `WorkingSet64` が 20 MB 以下の基準を超過したため、`FU-E2E-03` へ切り出した。
- `E2E-P3-03` の `ledr-sim.exe --scenario lotl`（約 40 ms の短命プロセス）で親子系譜と `example.com` DNS 相関は通過した一方、`command_line` が `None` となり `LEDR-LOTL-001`（正規管理ツール悪用検知ルール）が発火しなかったため、`FU-E2E-04` へ切り出した。
- `E2E-P3-06` で 3 秒停止予算を超過した後に残余パイプラインが 2 件書き込み、終了後の `-wal` に `111,272` バイトが再生成された点（シェル復帰まで計約 8 秒）と、WFP ドロップが終了済み兄弟由来の生存 `python.exe` へ単一帰属された実機エッジケースを `FU-E2E-05` へ切り出した。
- 開発ホスト PC 上での実施のため、専用環境向けの任意項目（`E2E-OPT-01` から `E2E-OPT-03`）は未実施である。
- PR #41 および PR #44 で追加した、生存中の発火元プロセスがおとり発火を起こした際に終了済み非保護中間親越しで生存中の孫プロセスへ `NtSuspendProcess` を適用するライブ動作（`ActiveProcessTable` 経路とスナップショット経路の統合、同一ミリ秒 PID 再利用カットオフ、および保護対象非停止を含む）は合成テストのみで確認しており、Windows 10/11 クライアント SKU の実機 E2E 対象として残している。
- 上記の基準未達および差異が残り、かつ実測基盤の PR #34 が未マージであるため、[implementation-plan.md](implementation-plan.md) の `[x]` チェックリストは未更新としている（`[x]` 更新は PR #34 と `FU-E2E-03` から `FU-E2E-05` の `main` マージおよび `main` 上の再検証合格後に行う）。

### 検証内容

検証環境は Windows 10 または Windows 11（x86_64）クライアント SKU の管理者昇格セッションを基準とする。
Windows Server SKU で代替検証を行う場合は、クライアント SKU との未検証差異を検証報告へ明記する（[AGENTS.md](../AGENTS.md) 準拠）。

#### Phase 2 実機検証項目

- 実 ETW `Microsoft-Windows-Kernel-File` と `Microsoft-Windows-Kernel-Registry` を購読し、ダミー `Cookies` の Open、おとりファイルへの 1 バイト書込、自動起動レジストリ更新、および `CloseKey` による `KeyObject` キャッシュ無効化が実イベントで動作することを検証する。
- 実 `NtSuspendProcess` で対象プロセスと子孫プロセスを凍結でき、`explorer.exe` などの Never-Suspend 対象が一切停止しないこと、および `TerminateAndBlock` 実行時の子プロセスツリー終了の非同期挙動に破綻がないことを確かめる。
- 生存中の発火元プロセスがおとり発火を起こし（`engine/events.rs` の本番凍結経路）、すでに終了済みの非保護中間親プロセス越しに生存中の孫プロセスへ `NtSuspendProcess` が適用されること、および保護対象プロセスや同一ミリ秒 PID 再利用後の後継プロセス配下が誤停止されないことを確認する。
- 機密ファイル Open またはおとりファイル書込の検知と即時サスペンドに続いて、Session 0 の `LocalSystem` サービスから `WTSQueryUserToken` と `CreateProcessAsUser` により `ledr-ui.exe --notify <alert_id>` が対話セッションで起動し、検知から 1 秒以内にトースト通知が表示されること、および `HKCU\Software\Classes\ledr` 登録済みの `ledr://alert/<id>` クリック後 1,000 ms 以内に View 1 が開いて 5 秒以内に強制終了または再開が完了することを確認する。

#### Phase 3 実機検証項目

- 実カーネル BFE へ `FWPM_SESSION_FLAG_DYNAMIC` 付き動的セッションと LocalEDR 専用 SubLayer を登録し、未許可の `ledr-sim` またはスクリプトインタプリタの外部通信が遮断されるとともに該当プロセスが凍結され、View 1 で許可登録した後に再開および通信が成立すること、View 3 でルールの参照と削除ができること、およびデーモン強制終了時に動的フィルタが自動消去されて通信不能にならないことを検証する。
- `FwpmNetEventSubscribe1` による実ドロップイベント捕捉と、実 ETW `Microsoft-Windows-DNS-Client` および `Microsoft-Windows-Kernel-Network` の結合により、解決済みドメイン相関と動的 Permit 維持が動作することを確かめる。
- 応答しない実 UNC パスまたは SMB 共有を `file://` 形式の NRD フィード元（`--nrd-feed-url file://server/share/...`、期限内の `nrd-cache.txt` がない状態）へ指定して起動し、既存の統合テスト `DAEMON-P3-45`（[phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L7017-L7026)）と同様に読み取り処理がブロック中であることを確認する。
  停止前の待機確認ではインプロセス検証の `read_bounded_reader_cancellable` 待機時に `DaemonEngine::is_nrd_refresh_in_flight`、`NrdCancelToken::is_blocking_read_active`、および `NrdCancelToken::blocking_read_entries`（1 以上）を確かめ、`File::open` 段階で待機する共有や `ledr-daemon.exe` 単体起動時は `ledr-nrd-refresh` スレッドが I/O 待機中かつ更新完了または失敗ログが未出力であること（インプロセス検証では `is_nrd_refresh_in_flight` が真であること）を確かめる。
  NRD のブロックを確認した後、`DAEMON-P3-45`（[phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L7028-L7050)）にならってマーカー用のプロセス起動イベントなどで SQLite WAL への事前書き込みを発生させ、停止実行前に `-wal` ファイルサイズが 0 バイト超（`-wal > 0`）であることを確かめてからデーモン停止を実行する。
  単体バイナリ実行（`ledr-daemon.exe`）では `RUST_LOG=ledr_store=debug,ledr_daemon=info`（[crates/ledr-daemon/src/main.rs](../crates/ledr-daemon/src/main.rs#L260-L261)）付きで起動しておき、3 秒予算内の停止処理で `LedrStore::checkpoint_truncate`（[crates/ledr-store/src/lib.rs](../crates/ledr-store/src/lib.rs#L222-L227)）が出力する時刻付き `completed wal_checkpoint(TRUNCATE)` ログが [lifecycle.rs](../crates/ledr-daemon/src/engine/lifecycle.rs#L355-L358) のデタッチ警告ログ（`shutdown budget exhausted waiting for background NRD refresh thread; detaching thread`）より前の時刻で記録されること、および停止後にマーカー行の永続化、`-wal` の 0 バイト化、`Runtime::drop` の非ハング終了が成立することを検証する。
  インプロセス検証では `DAEMON-P3-45A`（[overflow_and_lifecycle.rs](../crates/ledr-daemon/src/engine/tests/overflow_and_lifecycle.rs#L282-L408)）にならい、`shutdown_and_flush` が `nrd.done_rx` 待機で未完了（`!shutdown_task.is_finished()`）の時点で既に `-wal == 0` であること、復帰直後も `is_nrd_refresh_in_flight` が真であること、マーカー行が永続化されていること、および `Runtime::drop` がハングせず終了することを確認する。

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
- 2026 年 11 月 22 日に `Windows 11 Home`（`10.0.26300`、`ProductType = 1`、Chrome `157.0.8103.79`、基盤コミット `9c8373e` に未マージの PR #34 ブランチ `fix/e2e-pipe-dacl-dev-bypass` の Named Pipe DACL 修正を加えた検証構成）でルート 1 の Track B および Track C を実施し、`E2E-P4-00`（`--scope user`、Chrome）から `E2E-P4-07`（`LAYER_4_BROWSER` 6 件すべて `APPROVED_ONCE` へ遷移、`download_origins = 1`、移動後の MOTW 起因事前 WFP 遮断および SHA-256 と Zone 3 の紐付け）と `E2E-UI-01`（`ledr-ui` 1 件から 0 件、`msedgewebview2.exe` 6 件から 0 件）の通過を確認した。
  本実測は未マージの PR #34 を前提とした暫定結果であり、PR #34 の `main` マージ後に再確認する前提とする。

#### 未検証および残存の課題

- `--scope machine` の登録および復元、Microsoft Edge 実ブラウザでの拡張動作確認、および専用環境向けの任意項目（`E2E-OPT-01` から `E2E-OPT-03`）は未実施である。
- Phase 4 機能追加後の常駐性能回帰確認（`E2E-PERF-01`）は `WorkingSet64` 基準を超過したため `FU-E2E-03` へ切り出しており、かつ実測基盤の PR #34 が未マージであるため [implementation-plan.md](implementation-plan.md) の `[x]` チェックリストは未更新としている。

#### 後続 PR 着手時の未決判断事項

- `--scope machine`（`HKLM` 登録と復元）および Microsoft Edge 実ブラウザでの拡張動作確認を、[implementation-plan.md](implementation-plan.md) の Phase 4 実機 E2E チェックリスト `[x]` 更新の必須条件に含めるか、それとも未実施差異として切り分けて記録する任意項目にとどめるかは、PR #34 では確定せず後続の実機 E2E 検証 PR 着手時に合意する（`FU-P4-01` の 32 ビットレジストリビュー対応との前後関係もあわせて判断する）。

### 対応予定タイミング

PR 4C は PR #28（`331602d`）で `main` へマージ済みのため、PR #34 および `FU-E2E-03` から `FU-E2E-05` の `main` マージ後に独立した実機 E2E 検証作業として [e2e-test-runbook.md](e2e-test-runbook.md)（Track B および Track C：`L-08` の UI 0 プロセス終了確認および Phase 4 追加後の `E2E-PERF-01` 性能回帰確認、または [phase4-e2e-runbook.md](phase4-e2e-runbook.md)）を再実施し、合否記録をまとめて [implementation-plan.md](implementation-plan.md) の Phase 4 実機 Chrome E2E 検証項目を `[x]` へ更新する。

## FU-P4-01 crates/ledr-bridge-nm の HKLM 登録と確認における 32 ビットビュー対応

### 対象ファイル

- 該当実装箇所：[setup.rs](../crates/ledr-bridge-nm/src/setup.rs#L1230-L1402)（`root_key`、`ensure_default_sz`、`delete_subkey_tree_idempotent`、`read_default_sz`、`read_native_hosts_launch_directly_policy`）

### 背景と出典

本件は PR #28（ブランチ `phase-4c-ui-browser-integration`、コミット `41f12a0`）に対する Devin Review スレッド `PRRT_kwDOVyjVyM66W9C2`（`apps/ledr-ui` 診断側の `KEY_WOW64_32KEY` 未対応指摘）を一次照合した際に確認した PR 4C 排他範囲外の残件である。
`crates/ledr-bridge-nm` は PR #26（`6bb8bd3`）で `main` へマージ済みのため、PR 4C の排他境界を保って本書へ切り出した。

### 現行挙動と課題

x64 Windows 上の `ledr-bridge-nm` は `RegKey::predef(HKEY_LOCAL_MACHINE)` に対して既定ビュー（64 ビットビュー）のみで `open_subkey_with_flags(..., KEY_READ)`、`create_subkey`、および `delete_subkey_all` を実行している。
一方、Windows 上の Chrome は Native Messaging Host を探す際に 32 ビットビュー（`KEY_WOW64_32KEY`）も参照するため、既存環境で 32 ビットビュー側に旧登録が残る場合や 32 ビットビューを対象にする場合は、`status` 確認や `setup` と `unregister` の整合に抜けが生じる余地がある。

### 改善方針

`HKLM` スコープの Native Messaging Host 登録、確認（`status`）、および解除（`unregister`）について、対象ブラウザの検索順と整合するよう `KEY_WOW64_32KEY` と `KEY_WOW64_64KEY` の扱い（32 ビットビュー側の検出と必要に応じた登録または掃除）を設計し、単体テストを追加する。

### 対応予定タイミング

次回の `crates/ledr-bridge-nm/` 改修時、または Phase 4 以降の保守整備 PR で対応する。

## FU-E2E-03 E2E-PERF-01 の WorkingSet64 超過に対する原因分析とメモリ削減

### 対象ファイル

- Authenticode ワーカー分離（`Option 2-A` + `案 X`）：[crates/ledr-auth-helper/src/lib.rs](../crates/ledr-auth-helper/src/lib.rs)、[authenticode.rs](../crates/ledr-auth-helper/src/authenticode.rs)、[ffi.rs](../crates/ledr-auth-helper/src/ffi.rs)、[auth_worker.rs](../crates/ledr-daemon/src/engine/auth_worker.rs)、および [binary_inspector.rs](../crates/ledr-daemon/src/engine/binary_inspector.rs)（旧 `crates/ledr-rules/src/allowlist/{authenticode.rs,ffi.rs}` は移行後に削除）
- 永続化接続縮小と保守フック：[crates/ledr-store/src/schema.rs](../crates/ledr-store/src/schema.rs)、[crates/ledr-store/src/lib.rs](../crates/ledr-store/src/lib.rs)、および [pipeline.rs](../crates/ledr-daemon/src/engine/pipeline.rs)
- チャネル、プロセス表、DNS 履歴の縮約：[channel.rs](../crates/ledr-daemon/src/channel.rs)、[process_table.rs](../crates/ledr-daemon/src/process_table.rs)、[dns_history.rs](../crates/ledr-daemon/src/engine/dns_history.rs)、および [outbound.rs](../crates/ledr-daemon/src/engine/outbound.rs)
- 実機メモリプロファイラ：[profile_daemon_memory.ps1](../scripts/profile_daemon_memory.ps1)

### 背景と出典

2026 年 11 月 22 日に実施したルート 1 実機 E2E（[e2e-test-runbook.md](e2e-test-runbook.md)、`E2E-PERF-01`、公開 2 フィード 50,000 件の実 NRD キャッシュ読み込み時、PR #34 暫定構成上の実測）で、Release 版 `ledr-daemon.exe` の `WorkingSet64` が目標上限の 20.0 MB 以下を超過した（`LatestWorkingSetMB = 28.59 MB`、`PeakWorkingSetMB = 108.71 MB`、直後 `PrivateMemorySize64 = 17.15 MB`）。
2026 年 11 月 23 日に PR #38 マージ済み `main`（`b8d9c66`）上で Stage 1 実機プロファイリングを実施し、人間決裁チェックポイント（`B-1` と `B-2`）の承認を得て Track 1a〜1d と Track 2 を実装した（統合コミット `87be6d5`、単位はすべて `1 MB = 1 MiB = 1,048,576` バイト）。
さらに Stage 3 実機再計測で OS 共有ページ（`Shared == 1`）下限による `WorkingSet64 <= 20.0 MB` の物理的達成不能を数値証明した上で、`Track 3` 仕様協議（`PrivateWorkingSetSize <= 20.0 MB` 必須と `WorkingSet64` 監視基準の併記、`決定記録 L-24`）のユーザー承認を受けた。

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
- **`.github/workflows/ci.yml` 自動実行範囲（PR 作成後の CI で検証）**：`changes` ジョブは `Cargo.toml`、`Cargo.lock`、`crates/`、`docs/implementation-plan.md`、`docs/decision-records.md` の変更により `rust=true` かつ `web=true` と判定し、`static-checks`（`ubuntu-latest`、Node 22：`node --check`、Chrome MV3 拡張テスト 19 件、Tauri UI モック DOM テスト 10 件、固定拡張 ID 検証、および JSON、UTF-8、U+FFFD、競合マーカー検査）と `rust-windows`（`windows-latest`：`cargo check`、`clippy -- -D warnings`、`cargo test --workspace --locked`、`burst_budget`、`ttl_purge_lineage`、`cargo doc -D rustdoc::broken_intra_doc_links`）を実行する。
- **ローカル別途実行範囲（CI 対象外、Windows 11 x64 環境で `87be6d5` に対し実行済み）**：`cargo clippy`、`cargo test --workspace --locked`（415 件合格）、`burst_budget`（11 件合格）、`ttl_purge_lineage`（12 件合格）、Chrome 拡張 Node テスト（19 件合格）、UI モック DOM テスト（10 件合格）、`python scripts/test_check_invariants.py`（8 件合格）、`cargo build --release --locked` と PE インポート検査（`wintrust.dll` と `crypt32.dll` が 0 件）、`scripts/profile_daemon_memory.ps1` による Stage 1 および Stage 3 実機計測、Track 2 実機レイテンシと `31/31` Authenticode 一致確認、および実機 E2E 回帰（`E2E-P3-01`、`E2E-P3-03`、`E2E-P4-07`、3 秒停止予算）。

### 対応予定タイミング

本作業ブランチ（`perf/fu-e2e-03-memory-reduction`）の PR マージ後に、PR #34、`FU-E2E-04`、`FU-E2E-05` とあわせた `main` 上の最終実機 E2E（`FU-E2E-01`、`FU-E2E-02`、およびホスト ETW 競合を解消した `E2E-P3-01` / `E2E-P3-03` を含む）で再確認した上で [implementation-plan.md](implementation-plan.md) の `[ ]` チェックリストを更新する。

## FU-E2E-04 短命プロセスでの PEB 補完欠落による command_line 欠落と LEDR-LOTL-001 未発火

### 対象ファイル

- ETW ProcessStart 処理：[handlers.rs](../crates/ledr-sensor-win/src/etw/handlers.rs#L169-L309)（`build_process_start_event`）
- ライブプロセス PEB 参照：[process.rs](../crates/ledr-sensor-win/src/etw/tdh/process.rs#L82-L120)（`inspect_process_by_pid`）

### 背景と出典

2026 年 11 月 22 日に実施したルート 1 実機 E2E の `E2E-P3-03`（`ledr-sim.exe --scenario lotl`、初回および再試行の計 2 回、未マージの PR #34 ブランチ `fix/e2e-pipe-dacl-dev-bypass` 上での実測）で、親子系譜（`powershell.exe` から `ledr-sim.exe`、`cmd.exe`、`powershell.exe` への連鎖）は記録された一方、`command_line` が欠落して `LEDR-LOTL-001`（難読化 PowerShell 等の正規管理ツール悪用を検知する Sigma ルール）が発火しなかった。

### 現行挙動と実測値

- `e2e.db` 確認で、短命終了した `ledr-sim.exe`（初回 PID `31720`、再試行 PID `32996`、生存時間約 40 ms）、`cmd.exe`（PID `19680`）、および `powershell.exe`（PID `31672`）の `command_line` がいずれも `None` であり、`LEDR-LOTL-001` アラートが 0 件となった。
- 一方、60 秒間待機した `E2E-P3-01` の `powershell.exe`（PID `17296`）では `Command Line` が欠落せず取得できた。
- `Microsoft-Windows-Kernel-Process` のイベント 1 が環境やバージョンによって `CommandLine` を含まない場合、`build_process_start_event` が ETW 消費者スレッド上で `inspect_process_by_pid` による補完を試みるが、`FlushTimer = 1` 秒等の配送遅延の間に終了した短命プロセスでは、補完時点で既にプロセスが終了しており PEB を読めない可能性があると推測する。

### 利用者と運用上の影響

攻撃者が `cmd.exe` や `powershell.exe -EncodedCommand` を数十ミリ秒で終了するワンライナーとして実行した場合、親子系譜は残っても `command_line` が欠落して `LEDR-LOTL-001` 等のコマンドライン系 Sigma ルールが発火しない（検知漏れ：False Negative）。
また、事後調査で View 2 のフライトレコーダーを開いても実行引数が空になり、攻撃内容の追跡精度が落ちる。

### 想定リスクと維持する不変条件

- **定常 CPU 基準とバースト耐性の維持**：ETW フラッシュ間隔の短縮や追加プロバイダ購読によって定常 CPU 使用率 `0.5%` 未満や `TwoLaneSender` の有界バックプレッシャを破らないこと。
- **ユーザー空間限定（`L-01`）と ETW セッション上限の遵守**：カーネルドライバ導入へ逸脱せず、Windows の 1 プロバイダ 8 セッション上限を圧迫する過剰なセッション分割を行わないこと。
- **PID 再利用時の誤結合防止**：補完経路を追加しても、`create_time_100ns` 照合と時間窓タイブレーク（`idx_processes_pid_created`）および補完時の `should_evaluate_sigma` 再評価を崩さないこと。

### 改善方針と段階的進め方

1. **Step 1（調査フェーズ）**：実機 Windows 11 上で `Microsoft-Windows-Kernel-Process` イベント 1 の生 TDH プロパティ一覧（`CommandLine` フィールドの有無と属性）、`NT Kernel Logger` や `EventTrace` の別プロバイダ（`Microsoft-Windows-Security-Auditing` イベント 4688、`Microsoft-Windows-PowerShell` イベント 4104 等）の取得可否、および `FlushTimer` 短縮時の遅延分布を実測する。
2. **Step 2（実装フェーズ）**：Step 1 で確認した最小コストかつ確実に `command_line` を取得できる経路を実装し、遅延補完時も含め `should_evaluate_sigma` が再評価される単体および統合テストを追加する。
3. **受け入れ条件**：実機 `E2E-P3-03`（`ledr-sim.exe --scenario lotl`、約 40 ms の短命プロセス）で `command_line` が欠落せず記録され、`LEDR-LOTL-001` アラートが発火し、かつ `E2E-PERF-01` の定常 CPU `0.5%` 未満と `cargo test --workspace --locked` を満たすこと。

### 後続 PR 着手時の未決判断事項

以下は PR #34 では確定せず、Step 1 の実測後に後続 PR 着手時に決定する。

- **候補 A（ETW バッファと `FlushTimer` の調整）**：リアルタイム ETW セッションのバッファサイズとフラッシュ遅延を短縮し、プロセス終了前に PEB 補完が間に合う確率を高める。
  副次トレードオフは、約 40 ms 以下の極短命プロセスに対する完全保証が難しい点と、フラッシュ頻度上昇による CPU 負荷増である。
- **候補 B（`CommandLine` をカーネル側で内包するイベント経路の併用）**：`Microsoft-Windows-Kernel-Process` 以外のプロバイダまたは `SystemTraceControlGuid`（プロセス起動イベントに `CommandLine` を含む構成）、あるいは `Security` 監査ログ（4688）や PowerShell 4104 との相関を併用する。
  副次トレードオフは監査ポリシー有効化など環境前提の増加、イベント重複の排除設計、および ETW セッション枠の消費である。
- **候補 C（対象プロセスの段階的相関）**：`powershell.exe` 等の高リスクインタプリタ起動に限って別ログ相関を適用し、一般プロセスへの負荷を抑える。
  副次トレードオフは、対象外の短命バイナリでは依然として `command_line` が欠落する点である。

### 対応予定タイミング

推奨着手順の先頭として、次回センサーおよび ETW 改善 PR で対応する。

## FU-E2E-05 WFP ドロップ誤帰属抑止と停止予算超過時の残余書き込み整理

### 対象ファイル

- WFP ドロップ帰属：[wfp_drops.rs](../crates/ledr-daemon/src/engine/wfp_drops.rs#L607-L660)（`handle_wfp_drop_event_now`）
- 停止時ドレインとチェックポイント：[lifecycle.rs](../crates/ledr-daemon/src/engine/lifecycle.rs#L439-L510)（`shutdown_and_flush`）

### 背景と出典

2026 年 11 月 22 日に実施したルート 1 実機 E2E（未マージの PR #34 ブランチ `fix/e2e-pipe-dacl-dev-bypass` 上での実測）において、Track B 中にローカル HTTP サーバの `python.exe` が凍結した事象と、`E2E-P3-06` の停止時に `-wal` が再生成された事象の 2 点を観測した。

### 現行挙動と実測値

- **WFP ドロップ帰属**：`E2E-P4-03` と `E2E-P4-04` の実行中、ローカル HTTP サーバ用の `python.exe`（PID `17004`）が、背景で動いて終了した別 `python.exe` インスタンス由来の `2001:4860:4840:400:::443` 宛てドロップによって単一生存候補と判定され、`NtSuspendProcess` で凍結された。
  `WfpDropEvent` 自体は OS 仕様上 PID を持たず実行ファイル単位で帰属するため、短命の兄弟プロセスが直前に終了して同一 `exe_key`（正規化済み実行ファイルパス識別子）の生存候補が 1 件だけ残った場合に他インスタンスへ帰属される挙動となる。
- **停止時残余書き込み**：`E2E-P3-06`（`nrd_hang.db`）で `Ctrl+C` 受信後 3 秒の予算内に `completed wal_checkpoint(TRUNCATE)` と NRD スレッドのデタッチまでは完了したものの、予算超過により切り離されたパイプラインタスクがデタッチ直後に 2 件のアウトバウンド観測を書き込み、シェル復帰まで計約 8 秒かかり、終了後の `nrd_hang.db-wal` に `111,272` バイトが再生成された。

### 利用者と運用上の影響

- WFP ドロップの誤帰属が起きると、外部通信をしていない無関係な常駐 `python.exe` やスクリプトツール（開発サーバやビルド補助等）が誤って凍結され、利用者の作業が中断する（False Positive）。
- 停止予算超過後に残余書き込みが走ると、正常終了しても約 8 秒の遅延と `-wal` の残留が発生し、DB ファイルの単体保全や `E2E-P3-06` の 3 秒停止予算基準と不整合が生じる。

### 想定リスクと維持する不変条件

- **単一悪性プロセス凍結の維持（False Negative 防止）**：終了済み兄弟を考慮する曖昧性ウィンドウを広げすぎると、悪性プロセスが同一実行ファイルの短命子プロセスを直前に終了させてサスペンドを回避し得るため、時間窓と条件を厳格に設計すること。
- **Phase 3 鮮度条件と Never-Suspend 境界の維持**：複数候補時の 60 秒鮮度窓（`AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS = 60_000`）の対称性、`is_never_suspend_process`、`create_time_100ns` 一致、および `FWPM_SESSION_FLAG_DYNAMIC` を崩さないこと。
- **NRD 非ブロッキング停止とチェックポイント優先の維持**：`NrdThreadHandle` による非ブロッキング待機（`spawn_blocking` 不使用）、未応答 UNC 共有時のデタッチによる `Runtime::drop` ハング回避、および既存統合テスト `DAEMON-P3-45` と `DAEMON-P3-45A` の不変条件を壊さないこと。

### 改善方針と段階的進め方

1. **Step 1（調査フェーズ）** では次の 2 点を実ログと既存テストで確認する。
   - 課題 1 について、`WfpDropEvent` 到着時刻と直近終了兄弟の `exited_at_ms` の時間差、および `NetEvent` や ETW `Kernel-Network` 側の接続先タプルとの照合可否を確認する。
   - 課題 2 について、`shutdown_and_flush` の 3 秒予算超過後にシェル復帰まで約 8 秒を要した内訳（どの非同期タスクや ETW 後処理が `Runtime::drop` 前に残留したか）をトレースログで特定する。
2. **Step 2（実装フェーズ）** では次の 2 点を実装して回帰テストを追加する。
   - 課題 1 について、`collect_wfp_candidates` の曖昧性判定ウィンドウまたは接続先タプル相関を実装し、短命兄弟終了直後の生存無関係インスタンスが誤凍結されない統合テストと、悪性単一インスタンスが引き続き凍結される回帰テストを追加する。
   - 課題 2 について、停止予算超過時の残余書き込み停止と最終チェックポイント順序を整理し、`DAEMON-P3-45` および `DAEMON-P3-45A` と整合する回帰テストを追加する。
3. **受け入れ条件** は次の 2 点をともに満たすこととする。
   - 短命兄弟の終了直後に発生した `WfpDropEvent` で無関係な生存 `python.exe` が誤凍結されず、かつ単一悪性プロセスの初回外部接続凍結（`E2E-P3-01`）が維持されること。
   - `E2E-P3-06` で `Ctrl+C` から約 3 秒前後でシェルへ復帰し、`completed wal_checkpoint(TRUNCATE)` が NRD デタッチより前に記録され、マーカー行が永続化された状態で終了後の `-wal` が 0 バイト（または消去済み）になること。

### 後続 PR 着手時の未決判断事項

以下は PR #34 では確定せず、Step 1 の調査結果をもとに後続 PR 着手時に決定する。

- **課題 1 候補 A（直近終了兄弟を含む短時間曖昧性ウィンドウ）**：`WfpDropEvent` 発生直前（例：数秒以内）に終了した同一 `exe_key` プロセスも候補数へ算入し、複数候補時は `App-Level (Ambiguous PID)` として非凍結扱いにする。
  副次トレードオフは攻撃者が直前に短命な同一バイナリを終了させることで凍結回避を試み得る点（ウィンドウ幅の最小化が必要）である。
- **課題 1 候補 B（接続先 IP とポートのイベント相関）**：`WfpDropEvent` の宛先と ETW ネットワークまたは DNS 履歴のプロセス単位記録を照合し、一致根拠がある生存プロセスのみを凍結対象とする。
  副次トレードオフは IPv6 リテラル直結や ETW 配送遅延時に相関が取れず凍結判断が遅れるまたは見送られる可能性である。
- **課題 2 候補 A（停止予算到達時の書き込み打ち切りと最終チェックポイント）**：3 秒予算到達時点でパイプラインの DB 書き込みを停止（キャンセル）したうえで最終 `wal_checkpoint(TRUNCATE)` を実行し、NRD スレッドをデタッチする。
  副次トレードオフは停止直前の数件のテレメトリ書き込みを捨てる可能性がある点である。
- **課題 2 候補 B（有界ドレイン先行＋チェックポイント後置）**：ETW 供給を即座に閉じた後に残余バッファを短時間だけドレインし、書き込み完了を保証してからチェックポイントと NRD デタッチへ進む。
  副次トレードオフは高バースト時にドレイン時間が 3 秒停止予算へ食い込むリスクがある点である。

### 対応予定タイミング

推奨着手順の先頭として、`FU-E2E-04` と並行または前後する次回デーモン境界改善 PR で対応する。
