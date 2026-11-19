# LocalEDR 申し送り事項と実機検証計画

本書は LocalEDR の各 Phase を `main` ブランチへマージした後に残した副次的な改善余地と、合成自動テストでは検証済みと扱わない実機 E2E 検証の対象を管理する。
仕様の正は [implementation-plan.md](implementation-plan.md)、[decision-records.md](decision-records.md)（L-01 から L-16）、および凍結済みの [crates/ledr-proto/src/lib.rs](../crates/ledr-proto/src/lib.rs) に置き、本書では後続作業へ引き継ぐ個別項目を ID ごとに記録する。

## 項目一覧

| ID | 種別 | 関連 Phase | 概要 | 対応予定 |
| :--- | :--- | :--- | :--- | :--- |
| `FU-P3-01` | 副次最適化 | Phase 3 | `merge_domain_hints_prioritized` の満杯 32 件時に起きる非許可同居ヒントの再挿入抑制 | 次回 `firewall.rs` 改修または後続整備 PR |
| `FU-E2E-01` | 実機 E2E 検証 | Phase 2、Phase 3 | Windows 10 および Windows 11 クライアント SKU 管理者環境での実機検証 | 独立した実機 E2E 検証 PR |

## FU-P3-01 満杯 32 件時の非許可同居ヒント再挿入の抑制

### 対象ファイル

- 残存挙動の実装箇所：[firewall.rs](../crates/ledr-daemon/src/firewall.rs#L57-L97)（`merge_domain_hints_prioritized`、Loop 1 は [L64-L79](../crates/ledr-daemon/src/firewall.rs#L64-L79)、Loop 2 は [L81-L96](../crates/ledr-daemon/src/firewall.rs#L81-L96)）
- 主訴を解消した保護ヘルパ：[engine.rs](../crates/ledr-daemon/src/engine.rs#L6593-L6616)（`extend_authorizing_hints_from_existing_permit`）
- 保護ヘルパの呼び出し 4 経路：[resolve_alert_with_outcome](../crates/ledr-daemon/src/engine.rs#L1818-L1825)（`AllowPermanent`）、[prematerialize_domain_wfp_filters](../crates/ledr-daemon/src/engine.rs#L3383-L3390)、[handle_ambiguous_wfp_drop](../crates/ledr-daemon/src/engine.rs#L4059-L4066)、および [evaluate_and_handle_outbound_connect](../crates/ledr-daemon/src/engine.rs#L4689-L4696)
- 関連する回帰テスト：[engine.rs](../crates/ledr-daemon/src/engine.rs#L11156-L11340)（DNS 履歴退避後かつ非許可同居ヒントによる満杯 32 件超過時の既存許可根拠維持を検証する `DAEMON-P3-49A` §7）と [phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L8849-L9361)（共有 IP 移行時の Permit 維持と安全境界を E2E 検証する `DAEMON-P3-48`）

### 背景と出典

本件は Phase 3 の PR #5（ブランチ `phase-3-wfp-firewall`、マージコミット `3fe1031` / `3fe1031fc3692beab77e0eeb531f27e6e56c888e`）に対する Review #40 で指摘された事項から切り出した副次申し送りである。
出典のレビュースレッドは `PRRT_kwDOVyjVyM65hO2j`（指摘 ID `BUG_pr-review-job-23fb353b86b648aaa95062ec74d199a4_0001`、指摘対象コミット `4e11596`）であり、満杯の 32 件 Permit フィルタを更新する際のヒント退避順序が論点となった。

### 現行の保証範囲

解消済みの主訴と未変更の残存挙動を区別して以下に記す。

#### 解消済み事項

Review #40 の主訴だった「満杯 32 件の Permit フィルタを更新するときに有効な既存許可根拠が消える問題」は、コミット `3666680`（`366668061c4ddd06a6a269d40a0b1c5860d7af51`）で解消した。
具体的には [engine.rs](../crates/ledr-daemon/src/engine.rs#L6593-L6616) に `extend_authorizing_hints_from_existing_permit` を追加し、Permit の登録と更新を行う 4 経路すべて（[L1818-L1825](../crates/ledr-daemon/src/engine.rs#L1818-L1825)、[L3383-L3390](../crates/ledr-daemon/src/engine.rs#L3383-L3390)、[L4059-L4066](../crates/ledr-daemon/src/engine.rs#L4059-L4066)、[L4689-L4696](../crates/ledr-daemon/src/engine.rs#L4689-L4696)）で既存の有効な許可ドメインを事前に保護集合へ組み込んだ。

この修正により、保護対象となる許可ヒントの総数が上限 `MAX_DOMAIN_HINTS_PER_FILTER`（32 件）以内である限り、非許可の同居ヒントによって上限を超過しても、DNS 履歴から退避された後の既存許可根拠は押し出されない。
一方、`ensure_ip_permit_for_domain_hints_prioritized` の許可ヒント正規化（[firewall.rs](../crates/ledr-daemon/src/firewall.rs#L943-L946) が呼ぶ `merge_domain_hint` の [L37-L48](../crates/ledr-daemon/src/firewall.rs#L37-L48)）および `merge_domain_hints_prioritized` の Loop 1（[L68-L77](../crates/ledr-daemon/src/firewall.rs#L68-L77)）では、許可ヒント単体で 32 件を超過した場合に上限維持のため古い許可ヒントが保護対象から外れて先入れ先出しで退避される。
非許可の同居ヒントによる満杯 32 件超過かつ DNS 履歴退避後に既存許可根拠が維持される条件は、単体結合テスト `DAEMON-P3-49A` §7（[engine.rs](../crates/ledr-daemon/src/engine.rs#L11156-L11340)）で検証済みである。
あわせて、コミット `2c05747`（`2c0574749db91ae07bbdc8782c6b07dd28127c2a`）では共有 IP 移行時の Permit 維持と安全境界（Review #38 / `AUD-P3-01`）を E2E 検証する統合回帰テスト `DAEMON-P3-48`（[phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L8849-L9361)）を追加した。
`3666680` に対する Devin Review #41（`2026-11-19T14:09:13Z`）および `2c05747` に対する最終 Devin Review（`2026-11-19T14:35:04Z`）はいずれも `0 new potential issues` を報告した。

#### 未変更の残存挙動

[firewall.rs](../crates/ledr-daemon/src/firewall.rs#L57-L97) の `merge_domain_hints_prioritized` では、`target` が上限 `MAX_DOMAIN_HINTS_PER_FILTER`（32 件）に達した状態で Loop 1（[L64-L79](../crates/ledr-daemon/src/firewall.rs#L64-L79)）が新しい許可ヒントを追加するとき、先頭の非保護スロットに置かれた既存非許可同居ドメインを 1 件退避する。
同じ呼び出しの `cohosted_hints` にその退避済みドメインが含まれると、Loop 2（[L81-L96](../crates/ledr-daemon/src/firewall.rs#L81-L96)）は更新後の `target` に該当要素がないため新規扱いとして末尾へ再挿入する。
この再挿入によって、同じバッチ内で別の非許可同居ヒントが 1 件余分に押し出される挙動が残っている。

呼び出し側の 4 経路が既存の有効な許可根拠を保護集合へ組み込み、Loop 2 は保護対象スロットを退避しないため、本挙動は許可ヒント上限 32 件以内の既存許可根拠保護、deny-overrides-allow、`SEC_0001`、および `SEC_0002` のセキュリティ境界へ影響しない。
非許可同居ヒント同士のローテーション効率にとどまる低優先度の内部改善余地として扱う。

### 改善方針

`merge_domain_hints_prioritized` の開始時点で `target` に含まれていた非保護ヒントの集合を保持し、Loop 1 で退避された既存非許可同居ヒントを同一バッチの Loop 2 で新規要素として再挿入しないように修正する。
あわせて、満杯 32 件の `target` へ新規許可ヒントと既存非許可同居ヒントを同時に渡したときに余分な 1 件の押し出しが起きないことを検証する単体境界テストを `firewall.rs` のテスト群へ追加する。

### 対応予定タイミング

次回の `crates/ledr-daemon/src/firewall.rs` 改修時、または Phase 4 以降の保守整備 PR で対応する。

## FU-E2E-01 Windows 10 および Windows 11 クライアント SKU での実機 E2E 検証

### 対象ファイル

- Phase 2 の ETW 監視対象：[etw/mod.rs](../crates/ledr-sensor-win/src/etw/mod.rs#L66-L69)（プロバイダ GUID）、[etw/mod.rs](../crates/ledr-sensor-win/src/etw/mod.rs#L734-L747)（購読登録）、[etw/mod.rs](../crates/ledr-sensor-win/src/etw/mod.rs#L1171-L1192)（`handle_kernel_registry`）、[etw/mod.rs](../crates/ledr-sensor-win/src/etw/mod.rs#L1274-L1399)（`CloseKey` 無効化を含む `decide_registry_event`）、および [file_canary.rs](../crates/ledr-sensor-win/src/etw/file_canary.rs#L267-L305)（`prefilter_and_classify_canary_u16`）
- Phase 2 のプロセス制御と通知対象：[defense/mod.rs](../crates/ledr-sensor-win/src/defense/mod.rs#L450-L466)（`NtSuspendProcess`）、[defense/mod.rs](../crates/ledr-sensor-win/src/defense/mod.rs#L670-L715)（`terminate_process`）、[notify.rs](../crates/ledr-daemon/src/notify.rs#L109-L255)（`notify_alert_with_session` と `try_launch_in_active_session`）、[apps/ledr-ui/src/main.rs](../apps/ledr-ui/src/main.rs#L138-L174)（`parse_launch_mode`）、および [apps/ledr-ui/src/main.rs](../apps/ledr-ui/src/main.rs#L860-L913)（`ensure_hkcu_ledr_uri_registered` と `dispatch_notify_oneshot`）
- Phase 3 の WFP 制御対象：[wfp/mod.rs](../crates/ledr-sensor-win/src/wfp/mod.rs#L604-L647)（`open_dynamic`）と [wfp/mod.rs](../crates/ledr-sensor-win/src/wfp/mod.rs#L1101-L1122)（`FwpmNetEventSubscribe1` 購読）
- Phase 3 のネットワーク ETW と NRD 対象：[etw/mod.rs](../crates/ledr-sensor-win/src/etw/mod.rs#L70-L73)（プロバイダ GUID）、[etw/mod.rs](../crates/ledr-sensor-win/src/etw/mod.rs#L748-L761)（購読登録）、[nrd.rs](../crates/ledr-rules/src/nrd.rs#L71-L95)（`NrdCancelToken` のブロッキング読み取り観測）、[nrd.rs](../crates/ledr-rules/src/nrd.rs#L529-L566)（`parse_file_url`）、[nrd.rs](../crates/ledr-rules/src/nrd.rs#L685-L784)（`read_bounded_file` と `read_bounded_reader_cancellable`）、[engine.rs](../crates/ledr-daemon/src/engine.rs#L826-L834)（`is_nrd_refresh_in_flight` と `nrd_cancel_token`）、[engine.rs](../crates/ledr-daemon/src/engine.rs#L2448-L2492)（停止時チェックポイント優先と NRD デタッチ）、および [engine.rs](../crates/ledr-daemon/src/engine.rs#L2700-L2742)（`ledr-nrd-refresh` スレッド）

### 背景と出典

Phase 2 は PR #3（ブランチ `phase-2-canary-suspend`、マージコミット `a68bce5` / `a68bce5eb73922a0ebcfb6c052a430c620050958`）で、Phase 3 は PR #5（ブランチ `phase-3-wfp-firewall`、マージコミット `3fe1031` / `3fe1031fc3692beab77e0eeb531f27e6e56c888e`）で `main` へマージした。
[AGENTS.md](../AGENTS.md) の Phase 2 不変条件、Phase 3 不変条件、および標準検証コマンドの定めにより、OS カーネルや実サービス環境に依存する挙動は合成テストだけでは検証済みとみなさない。

### 現行の保証範囲

#### 確認済み事項

Phase 2 と Phase 3 の実装は静的検査（`cargo clippy --workspace --all-targets --locked -- -D warnings`）、ワークスペース全体の単体および統合テスト（`cargo test --workspace --locked`）、バースト負荷テスト（`burst_budget`）、および TTL 回帰テスト（`ttl_purge_lineage`）に合格して `main` へマージ済みである。

#### 未検証の残存範囲

管理者昇格した Windows 10 または Windows 11（x86_64）クライアント SKU 実機での実 ETW 配送、実カーネル BFE 動的フィルタ登録と強制終了時の自動消去、実プロセスの非同期ツリー終了、Session 0 から対話ユーザーセッションへのトースト起動、および応答しない実 UNC や SMB 共有での NRD 読み取り停止は未実施である。

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
- 応答しない実 UNC パスまたは SMB 共有を `file://` 形式の NRD フィード元（`--nrd-feed-url file://server/share/...`、期限内の `nrd-cache.txt` がない状態）へ指定し、既存の統合テスト `DAEMON-P3-45`（[phase3_daemon.rs](../crates/ledr-daemon/tests/phase3_daemon.rs#L7741-L7750)）と同様に読み取り処理がブロック中であることを確認してからデーモン停止を実行する。
  停止前の待機確認ではインプロセス検証の `read_bounded_reader_cancellable` 待機時に `DaemonEngine::is_nrd_refresh_in_flight`、`NrdCancelToken::is_blocking_read_active`、および `NrdCancelToken::blocking_read_entries`（1 以上）を確かめ、`File::open` 段階で待機する共有や `ledr-daemon.exe` 単体起動時は `ledr-nrd-refresh` スレッドが I/O 待機中かつ更新完了または失敗ログが未出力であること（インプロセス検証では `is_nrd_refresh_in_flight` が真であること）を確かめる。
  停止後は 3 秒予算内の SQLite WAL チェックポイント優先（`-wal` の 0 バイト化）、NRD 更新スレッドのデタッチ警告ログ出力（インプロセス検証では `shutdown_and_flush` 復帰直後も `is_nrd_refresh_in_flight` が真であること）、および `Runtime::drop` がハングせず終了することを確認する。

### 対応予定タイミング

Phase 2 と Phase 3 の実機検証をまとめて扱う独立した別 PR で実施し、確認結果と必要に応じた調整を記録したうえで [implementation-plan.md](implementation-plan.md) の該当する実機 E2E 受け入れ検証項目を `[x]` へ更新して完了とする。
