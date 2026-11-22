# LocalEDR 申し送り事項と実機検証計画

本書は LocalEDR の各 Phase を `main` ブランチへマージした後に残した副次的な改善余地と、合成自動テストでは検証済みと扱わない実機 E2E 検証の対象を管理する。
仕様の正は [implementation-plan.md](implementation-plan.md)、[decision-records.md](decision-records.md)（L-01 から L-21）、および凍結済みの [crates/ledr-proto/src/lib.rs](../crates/ledr-proto/src/lib.rs) に置き、本書では後続作業へ引き継ぐ個別項目を ID ごとに記録する。

## 項目一覧

| ID | 種別 | 関連 Phase | 概要 | 対応予定 |
| :--- | :--- | :--- | :--- | :--- |
| `FU-P3-01` | 副次最適化 | Phase 3 | `merge_domain_hints_prioritized` の満杯 32 件時に起きる非許可同居ヒントの再挿入抑制 | 次回 `crates/ledr-daemon/src/firewall/` 改修または後続整備 PR |
| `FU-P4-01` | 副次改善 | Phase 4 | `ledr-bridge-nm` の `HKLM` 登録および確認における 32 ビットレジストリビュー（`KEY_WOW64_32KEY`）対応 | 次回 `crates/ledr-bridge-nm/` 改修または後続整備 PR |
| `FU-E2E-01` | 実機 E2E 検証 | Phase 2、Phase 3 | Windows 10 および Windows 11 クライアント SKU 管理者環境での実機検証 | 独立した実機 E2E 検証 PR |
| `FU-E2E-02` | 実機 E2E 検証 | Phase 4 | Windows 10 および Windows 11 クライアント SKU 上での Chrome 拡張、Native Messaging、MOTW、および UI 終了の実機検証 | 独立した実機 E2E 検証 PR |
| `FU-E2E-03` | 性能最適化 | Phase 3、Phase 4 | `E2E-PERF-01` の `WorkingSet64` 基準（20 MB 以下）超過（アイドル最新 `28.59 MB`、ピーク `108.71 MB`、高負荷最新 `51.80 MB`、ピーク `64.34 MB`）の原因分析とメモリ削減 | 次回性能改善 PR |
| `FU-E2E-04` | 検知改善 | Phase 1、Phase 3 | 短命プロセス（約 40 ms）での PEB 補完欠落による `command_line` 欠落と `LEDR-LOTL-001` 未発火の解消 | 次回センサーおよび ETW 改善 PR |
| `FU-E2E-05` | 境界改善 | Phase 3 | WFP ドロップの終了済み兄弟プロセス由来の誤帰属抑止および `E2E-P3-06` 停止予算超過時の残余書き込みによる `-wal` 再生成の整理 | 次回デーモン境界改善 PR |

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

## FU-E2E-01 Windows 10 および Windows 11 クライアント SKU での実機 E2E 検証

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

2026 年 11 月 22 日に `Windows 11 Home`（`10.0.26300`、`ProductType = 1`、基盤コミット `9c8373e` に `fix/e2e-pipe-dacl-dev-bypass` の Named Pipe DACL 修正を加えた構成）で [e2e-test-runbook.md](e2e-test-runbook.md) のルート 1 を実施し、Track A の以下を確認した。

- `PREP-01` から `PREP-04`、`E2E-P2-01` から `E2E-P2-06`、`E2E-P3-01`、`E2E-P3-02`、`E2E-P3-04`、`E2E-P3-05`（公開 2 フィード `feeds_succeeded = 2`、`feeds_failed = 0`、`entries = 50000`）、`E2E-P3-06`（`wal_checkpoint(TRUNCATE)` の NRD デタッチ先行とマーカー行永続化）、`E2E-P3-07`（`taskkill /F` 後の WFP フィルタ 0 件消去）、および `E2E-UI-01`（0 プロセス終了）が実機で通過した。
- `E2E-PERF-01` の定常 CPU 使用率はアイドル 600 秒で `0.2876%`、高負荷 60 秒で `0.3076%` となり、0.5% 未満の基準を満たした。

#### 未検証および残存の課題

- `E2E-PERF-01` の `WorkingSet64` が 20 MB 以下の基準を超過したため、`FU-E2E-03` へ切り出した。
- `E2E-P3-03` の `ledr-sim.exe --scenario lotl`（約 40 ms の短命プロセス）で親子系譜と `example.com` DNS 相関は通過した一方、`command_line` が `None` となり `LEDR-LOTL-001` が発火しなかったため、`FU-E2E-04` へ切り出した。
- `E2E-P3-06` で 3 秒停止予算を超過した後に残余パイプラインが 2 件書き込み、終了後の `-wal` に `111,272` バイトが再生成された点（シェル復帰まで計約 8 秒）と、WFP ドロップが終了済み兄弟由来の生存 `python.exe` へ単一帰属された実機エッジケースを `FU-E2E-05` へ切り出した。
- 開発ホスト PC 上での実施のため、専用環境向けの任意項目（`E2E-OPT-01` から `E2E-OPT-03`）は未実施である。
- 上記の基準未達および差異が残るため、[implementation-plan.md](implementation-plan.md) の `[x]` チェックリストは未更新としている。

### 検証内容

検証環境は Windows 10 または Windows 11（x86_64）クライアント SKU の管理者昇格セッションを基準とする。
Windows Server SKU で代替検証を行う場合は、クライアント SKU との未検証差異を検証報告へ明記する（[AGENTS.md](../AGENTS.md) 準拠）。

#### Phase 2 実機検証項目

- 実 ETW `Microsoft-Windows-Kernel-File` と `Microsoft-Windows-Kernel-Registry` を購読し、ダミー `Cookies` の Open、おとりファイルへの 1 バイト書込、自動起動レジストリ更新、および `CloseKey` による `KeyObject` キャッシュ無効化が実イベントで動作することを検証する。
- 実 `NtSuspendProcess` で対象プロセスと子孫プロセスを凍結でき、`explorer.exe` などの Never-Suspend 対象が一切停止しないこと、および `TerminateAndBlock` 実行時の子プロセスツリー終了の非同期挙動に破綻がないことを確かめる。
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

## FU-E2E-02 Windows 10 および Windows 11 クライアント SKU での Phase 4 実機 Chrome E2E 検証

### 対象ファイルと手順書

- 実機検証手順書（統合版）：[e2e-test-runbook.md](e2e-test-runbook.md)（Track B および Track C）
- 実機検証手順書（Phase 4 個別版）：[phase4-e2e-runbook.md](phase4-e2e-runbook.md)
- ローカル検証用 HTML フィクスチャ：[phase4-browser-test.html](fixtures/phase4-browser-test.html)
- 対象コンポーネント：[crates/ledr-bridge-nm](../crates/ledr-bridge-nm/src/main.rs)、[extensions/ledr-chrome-mv3](../extensions/ledr-chrome-mv3/manifest.json)、[crates/ledr-daemon/src/engine/motw.rs](../crates/ledr-daemon/src/engine/motw.rs)、[apps/ledr-ui/src/defense_status.rs](../apps/ledr-ui/src/defense_status.rs)、および [apps/ledr-ui/ui/app.js](../apps/ledr-ui/ui/app.js)

### 背景と出典

Phase 4 は [decision-records.md](decision-records.md) の `L-17` に従い、PR 4A（PR #25、`cf7e866`）、PR 4B（PR #26、`6bb8bd3`）、および PR 4C（PR #28、`331602d`、`apps/ledr-ui` View 1〜3 統合、検証用フィクスチャと手順書、文書同期）の 3 本へ分割した。
実ブラウザ上での Chrome 拡張ロード、実際の Windows レジストリ経由による Native Messaging ホスト起動、実ダウンロードの `:Zone.Identifier` 付与とフォルダ移動後起動の 3 段階紐付け、および WebView2 ウィンドウ閉鎖後の完全終了は、合成ユニットテストでは検証済みとみなさない。

### 現行の保証範囲

#### 確認済み事項

- PR 4A の MOTW 解析（`:Zone.Identifier`）、3 段階紐付け、事前 WFP ブロック、`ReportBrowserEvent`、および `ledr-sim motw-download` の合成テストとワークスペース負荷および TTL 回帰は `main` 上で合格済みである。
- PR 4B の `ledr-bridge-nm`（ゼロパース中継、`SEC_0003` 検証、`setup`、`status`、`unregister`）と `extensions/ledr-chrome-mv3`（固定拡張 ID `ecelachfiiiiiibpjeomfncgpegbpanh`、ClickFix、NRD とホモグラフ判定、`storage.session` ダウンロード追跡）の Rust および Node テストは `main` 上で合格済みである。
- PR 4C の `apps/ledr-ui`（`HKCU` と `HKLM` 両プローブ、WOW64 32 ビット優先探索、ホワイトリストによるマニフェスト検証、View 1〜3 の表示と操作制約）のうち、Rust 単体テスト（`UI-P4-01` から `UI-P4-04`、`UI-P4-11` から `UI-P4-13`）と JS 構文検査（`node --check`）は PR #28（`331602d`）の CI で合格を確認した。
  PR #28（`331602d`）および PR #29 時点の `static-checks` ジョブは Node テストとして `extensions/ledr-chrome-mv3/tests/*.test.mjs` のみを実行していたため、Node モック DOM テスト（`apps/ledr-ui/js-tests/phase4_ui.test.mjs` の `UI-P4-05` から `UI-P4-10`、`PR27-REG-01`、`CSP-01`）はローカルの Node 22 で別途実行し、PR #28 最終コミット `4513044` の検証記録および PR #29 の再実行（Node `v22.18.0`、8/8 合格）にて合格を確認した。
  現在は `.github/workflows/ci.yml` の `static-checks` ジョブでも `apps/ledr-ui/js-tests/*.test.mjs` を自動実行する構成へ拡張している。
- 2026 年 11 月 22 日に `Windows 11 Home`（`10.0.26300`、`ProductType = 1`、Chrome `157.0.8103.79`、基盤コミット `9c8373e` に Named Pipe DACL 修正を加えた `fix/e2e-pipe-dacl-dev-bypass`）でルート 1 の Track B および Track C を実施し、`E2E-P4-00`（`--scope user`、Chrome）から `E2E-P4-07`（`LAYER_4_BROWSER` 6 件すべて `APPROVED_ONCE` へ遷移、`download_origins = 1`、移動後の MOTW 起因事前 WFP 遮断および SHA-256 と Zone 3 の紐付け）と `E2E-UI-01`（`ledr-ui` 1 件から 0 件、`msedgewebview2.exe` 6 件から 0 件）の通過を確認した。

#### 未検証および残存の課題

- `--scope machine` の登録および復元、Microsoft Edge 実ブラウザでの拡張動作確認、および専用環境向けの任意項目（`E2E-OPT-01` から `E2E-OPT-03`）は未実施である。
- Phase 4 機能追加後の常駐性能回帰確認（`E2E-PERF-01`）は `WorkingSet64` 基準を超過したため `FU-E2E-03` へ切り出しており、[implementation-plan.md](implementation-plan.md) の `[x]` チェックリストは未更新としている。

### 対応予定タイミング

PR 4C は PR #28（`331602d`）で `main` へマージ済みのため、独立した実機 E2E 検証作業として [e2e-test-runbook.md](e2e-test-runbook.md)（Track B および Track C：`L-08` UI 終了確認および Phase 4 追加後の `E2E-PERF-01` 性能回帰確認、または [phase4-e2e-runbook.md](phase4-e2e-runbook.md)）を実施し、合否記録をまとめて [implementation-plan.md](implementation-plan.md) の Phase 4 実機 Chrome E2E 検証項目を `[x]` へ更新する。

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

- Authenticode 署名検証経路：[authenticode.rs](../crates/ledr-rules/src/allowlist/authenticode.rs#L235-L246)（`WinVerifyTrust` 呼び出し）
- 永続化とバッチバッファ：[crates/ledr-store/src/lib.rs](../crates/ledr-store/src/lib.rs)
- NRD キャッシュとデーモン起動構成：[crates/ledr-daemon/src/engine/lifecycle.rs](../crates/ledr-daemon/src/engine/lifecycle.rs)

### 背景と出典

2026 年 11 月 22 日に実施したルート 1 実機 E2E（[e2e-test-runbook.md](e2e-test-runbook.md)、`E2E-PERF-01`、公開 2 フィード 50,000 件の実 NRD キャッシュ読み込み時）で、Release 版 `ledr-daemon.exe` の `WorkingSet64` が目標上限の 20.0 MB 以下を超過した。

### 現行挙動と実測値

- 600 秒アイドル計測（10 分間の開発ホスト背景負荷：`processes = 1,037`、`dns_queries = 563`、`network_events = 44,496`、`alerts = 15`）：`AvgCpuPercent = 0.2876%`（基準 `< 0.5%` 合格）、`LatestWorkingSetMB = 28.59 MB`、`PeakWorkingSetMB = 108.71 MB`、直後確認時の `PrivateMemorySize64 = 17.15 MB`。
- 60 秒高負荷計測（ブラウザ閲覧とビルド負荷併用）：`AvgCpuPercent = 0.3076%`、`LatestWorkingSetMB = 51.80 MB`、`PeakWorkingSetMB = 64.34 MB`。
- `PrivateMemorySize64` は 20 MB 以内に収まっていた一方、共有ページを含む `WorkingSet64` に一時的な 108.71 MB スパイクと定常 28 MB 以上の滞在が見られた。
  大容量バイナリやシステムカタログに対する `WinVerifyTrust` のファイルマッピング、SQLite ページキャッシュ、またはイベント受信時のバッファ保持が寄与している可能性があると推測するが、ヒープおよびページプロファイラによる内訳の切り分けは未実施である。

### 改善方針

Windows 実機上でメモリプロファイラ（VMMap や WPA 等）を用いて `WorkingSet64` の内訳（プライベート作業領域、メモリマップドファイル、共有 DLL）と `108.71 MB` ピークの発生契機を特定し、署名キャッシュの保持上限や SQLite `cache_size` 等の調整とあわせて実測再検証を行う。

### 対応予定タイミング

次回性能改善 PR で対応する。

## FU-E2E-04 短命プロセスでの PEB 補完欠落による command_line 欠落と LEDR-LOTL-001 未発火

### 対象ファイル

- ETW ProcessStart 処理：[handlers.rs](../crates/ledr-sensor-win/src/etw/handlers.rs#L169-L309)（`build_process_start_event`）
- ライブプロセス PEB 参照：[process.rs](../crates/ledr-sensor-win/src/etw/tdh/process.rs#L82-L120)（`inspect_process_by_pid`）

### 背景と出典

2026 年 11 月 22 日に実施したルート 1 実機 E2E の `E2E-P3-03`（`ledr-sim.exe --scenario lotl`、初回および再試行の計 2 回）で、親子系譜（`powershell.exe` から `ledr-sim.exe`、`cmd.exe`、`powershell.exe` への連鎖）は記録された一方、`command_line` が欠落して `LEDR-LOTL-001` が発火しなかった。

### 現行挙動と実測値

- `e2e.db` 確認で、短命終了した `ledr-sim.exe`（初回 PID `31720`、再試行 PID `32996`、生存時間約 40 ms）、`cmd.exe`（PID `19680`）、および `powershell.exe`（PID `31672`）の `command_line` がいずれも `None` であり、`LEDR-LOTL-001` アラートが 0 件となった。
- 一方、60 秒間待機した `E2E-P3-01` の `powershell.exe`（PID `17296`）では `Command Line` が欠落せず取得できた。
- `Microsoft-Windows-Kernel-Process` のイベント 1 が環境やバージョンによって `CommandLine` を含まない場合、`build_process_start_event` が ETW 消費者スレッド上で `inspect_process_by_pid` による補完を試みるが、`FlushTimer = 1` 秒等の配送遅延の間に終了した短命プロセスでは、補完時点で既にプロセスが終了しており PEB を読めない可能性があると推測する。

### 改善方針

`Microsoft-Windows-Kernel-Process` 実イベントの TDH プロパティ有無、ならびに `CommandLine` を取得可能な代替プロバイダ（カーネル監査ログや PowerShell 4104 との相関等）や ETW フラッシュ遅延の短縮余地を実機で計測し、短命 LOTL プロセスでも `LEDR-LOTL-001` が発火する取得経路を検討する。

### 対応予定タイミング

次回センサーおよび ETW 改善 PR で対応する。

## FU-E2E-05 WFP ドロップ誤帰属抑止と停止予算超過時の残余書き込み整理

### 対象ファイル

- WFP ドロップ帰属：[wfp_drops.rs](../crates/ledr-daemon/src/engine/wfp_drops.rs#L607-L660)（`handle_wfp_drop_event_now`）
- 停止時ドレインとチェックポイント：[lifecycle.rs](../crates/ledr-daemon/src/engine/lifecycle.rs#L439-L510)（`shutdown_and_flush`）

### 背景と出典

2026 年 11 月 22 日に実施したルート 1 実機 E2E において、Track B 中にローカル HTTP サーバの `python.exe` が凍結した事象と、`E2E-P3-06` の停止時に `-wal` が再生成された事象の 2 点を観測した。

### 現行挙動と実測値

- WFP ドロップ帰属：`E2E-P4-03` と `E2E-P4-04` の実行中、ローカル HTTP サーバ用の `python.exe`（PID `17004`）が、背景で動いて終了した別 `python.exe` インスタンス由来の `2001:4860:4840:400:::443` 宛てドロップによって単一生存候補と判定され、`NtSuspendProcess` で凍結された。
  `WfpDropEvent` 自体は OS 仕様上 PID を持たず実行ファイル単位で帰属するため、短命の兄弟プロセスが直前に終了して同一 `exe_key` の生存候補が 1 件だけ残った場合に他インスタンスへ帰属される挙動となる。
- 停止時残余書き込み：`E2E-P3-06`（`nrd_hang.db`）で `Ctrl+C` 受信後 3 秒の予算内に `completed wal_checkpoint(TRUNCATE)` と NRD スレッドのデタッチまでは完了したものの、予算超過により切り離されたパイプラインタスクがデタッチ直後に 2 件のアウトバウンド観測を書き込み、シェル復帰まで計約 8 秒かかり、終了後の `nrd_hang.db-wal` に `111,272` バイトが再生成された。

### 改善方針

1. `WfpDropEvent` 帰属時の候補抽出（`collect_wfp_candidates`）で、直近に終了した同一 `exe_key` プロセスを含めた曖昧性判定ウィンドウや `NetEvent` との相関条件を見直し、終了済み短命兄弟のドロップによる生存プロセスの誤凍結を抑止する。
2. `shutdown_and_flush` で 3 秒予算超過後に残余パイプラインタスクをそのまま生かして後続イベントを書き込ませるか、予算超過時点で書き込みを止めて最終チェックポイントの 0 バイト維持を優先するかを整理し、テストと整合させる。

### 対応予定タイミング

次回デーモン境界改善 PR で対応する。
