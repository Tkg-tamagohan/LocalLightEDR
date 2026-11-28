---
trigger: model_decision
description: LocalEDR の MOTW 3 段階帰属と移動後事前 WFP ブロック、LAYER_4_BROWSER イベント、ledr-bridge-nm（Named Pipe 中継、HKLM WOW64 Native Messaging レジストリプローブ、マニフェスト削除保護）、Chrome MV3 拡張（ClickFix、NRD、ホモグラフ）、または apps/ledr-ui の View 3 マニフェスト検証、WOW64 診断、および .browser-detail-row 回帰テストを実装またはレビューするとき
---

# ブラウザ連携と UI 診断の不変条件を遵守する

Phase 4 で確立したブラウザ拡張、Native Messaging ブリッジ、MOTW 帰属、および `apps/ledr-ui` View 3 診断の安全境界と回帰規約を定める。

## 手順

1. MOTW 3 段階帰属と移動後事前 WFP ブロック：MOTW 帰属はパス一致、`<= 128 MiB` の SHA-256 一致、`:Zone.Identifier` ADS 読み取り（`ZoneId >= 3`）の 3 段階評価を専用 OS スレッド MOTW I/O ワーカープール経由で実行し、遅延 MOTW バックフィルは既存の `origin_url` を上書きしない。
   Stage 2 または Stage 3 で MOTW が確認された未許可バイナリ（`ProtectedOs` および既存 `NetworkAllow` 一致を除く）には、フォルダ移動による回避を防ぐため `HighRiskPath` と同じく起動時事前 WFP ブロックを適用する（`outbound_enforcement_mode != Audit` 時、`L-18`）。
2. `LAYER_4_BROWSER` イベント記録と解決制限：`record_browser_event` は非空 URL 検証、`details` の 8 KiB 切詰め、30 秒かつ上限 256 件の有界重複抑止を行い、既定では OS トーストを発火しない（`L-19`）。
   プロセス紐付きのない `LAYER_4_BROWSER` アラートは `AllowOnce`（UI では `Acknowledge`）および `TerminateAndBlock { add_block_rule: false }` のみ許可し、`AllowPermanent` 等は拒否する。
3. `ledr-bridge-nm` 中継と固定拡張 ID：`ledr-bridge-nm` は 4 バイト LE ゼロパース中継（上限 1 MiB）、1 リクエスト 1 Named Pipe 接続、`GetNamedPipeServerProcessId` によるサーバーバイナリ検証（`SEC_0003`）、`stderr` 専用ログ（`stdout` 汚染禁止）を維持し、固定公開鍵由来の拡張 ID `ecelachfiiiiiibpjeomfncgpegbpanh` のみを `allowed_origins` に許可する（`L-20`）。
4. CLI Native Messaging レジストリプローブとマニフェスト削除保護：`crates/ledr-bridge-nm/src/setup.rs` の `HKLM` Native Messaging 操作は `setup --scope machine` で 32 ビットおよび 64 ビット両ビューへ冪等に登録し、レジストリ文字列プローブは Chromium 互換で `REG_SZ` と `REG_EXPAND_SZ` の双方を扱い、空白トリム前の生値（2,048 バイト時の末尾 UTF-16 NUL 終端必須を含む `exceeds_chromium_raw_limit`）および空白トリム前の展開結果に対して 1,024 UTF-16 コード単位上限（`CHROMIUM_READ_VALUE_MAX_UTF16_UNITS`）を判定する。
   上限内かつ未解決の環境変数（展開後も `%TOKEN%` が残存する `has_unresolved_env_token` 検出）を含む `REG_EXPAND_SZ` は `UnresolvableExpandSz` として 32 ビット優先打ち切りとし、上限超過または `ExpandEnvironmentStringsW` 失敗は `ChromiumReadFallback` として `HKLM` 診断のみ 64 ビットビューへフォールバックする。
   `HKLM` の WOW64 診断（`run_status_with_ops`）は 32 ビットビューで `stops_wow64_fallback()`（`Present`、`EmptyString`、`UnresolvableExpandSz`）が成立した時点で 64 ビットビューを読まずに短絡終了する（`HKCU`、URI スキーム、AUMID、グループポリシーはフラグなしの既定ビューのみを維持する）。
   `unregister` では両ビューのレジストリキーを冪等に削除したうえで、共有マニフェストファイル削除前の参照検査（`any_browser_references_manifest_with`）では、マニフェスト一致またはフェイルクローズ対象（`UnresolvableExpandSz` と `ChromiumReadFallback { resolved_path: None }`）検出時の削除抑止の早期リターン（`Ok(true)`）を維持しつつ、`stops_wow64_fallback()`（`EmptyString` や非一致の `Present` 等）で 64 ビットビューをスキップせず全ブラウザの 32 ビットおよび 64 ビット両ビューをすべて検査してから削除許可（`Ok(false)`）を判定し、最大 32,768 UTF-16 コード単位まで保守的に展開した `ChromiumReadFallback { resolved_path: Some(..) }` を保護対象に含め、ブラウザ別 `manifest_removed` は 32 ビットおよび 64 ビット両ビューの全登録パスを `normalize_display_path` と大文字小文字無視の正規化比較で照合する。
5. Chrome MV3 拡張：`extensions/ledr-chrome-mv3` はグローバル変数へ状態を保持せず `chrome.storage.session` と `chrome.storage.local` を使い、NRD とホモグラフ判定で閲覧ドメインを外部へ送信せずローカル完結に保ち、ClickFix 観測は `"world": "MAIN"` の `content_main.js` から `ISOLATED` world へ受け渡す（`L-21`）。
6. View 3 マニフェスト検証とゼロプロセス終了：`apps/ledr-ui/src/defense_status.rs` はユーザーの機密ファイル（`Cookies`、`.ssh` 等）へ一切アクセスせず、おとりファイル、ブリッジバイナリ、`HKCU` および `HKLM` の読み取り専用レジストリ参照とマニフェスト検証のみを行い、ウィンドウ閉鎖時は `ledr-ui` と WebView2 を 0 プロセスで終了する（`L-08`）。
   マニフェスト検証は既定 2 ディレクトリのホワイトリスト配下だけに限定し、カスタム配置パスに対してはファイル I/O を行わず `unverified` として検証済み状態と区別する。
   ホワイトリスト配下でもリパースポイントを拒否し、`FILE_FLAG_OPEN_REPARSE_POINT` と `FILE_READ_ATTRIBUTES` で先行検査して `nNumberOfLinks == 1` および `GetFinalPathNameByHandleW` によるディレクトリ閉じ込めを確認してから、`ReOpenFile` で読み取りハンドルへ昇格して読み取り、`description` を必須項目として検証する。
7. View 3 の WOW64 診断とブラウザ別詳細行回帰規約：View 3（`apps/ledr-ui/src/defense_status.rs`）の Native Messaging レジストリ診断では、WOW64 参照を `KEY_WOW64_32KEY -> KEY_WOW64_64KEY` の順で探索し、32 ビット側で `EmptyString` を検出した場合は 64 ビット側へフォールバックせず 32 ビット側で打ち切る（View 3 側の `apps/ledr-ui/src/uri_reg.rs` は `HKLM` 32 ビットビューを含め動的バッファ拡張かつ `REG_SZ` 限定であり、CLI 側との診断境界差異の正本は `docs/follow-up-notes.md` の `FU-P4-01` で管理する）。
   View 3 のブラウザ別詳細行（`.browser-detail-row`）には各ブラウザの `manifest_path` と診断表示を併記し、`UI-P4-08` 等の UI 回帰テストではコンテナ全体検索だけで済ませず、ブラウザ単位で詳細行要素を抽出して期待する値が併記されていることと他ブラウザの情報が混入していないことを検証する。
8. 実機 E2E 検証境界：実 Chrome 拡張ロード、実 Native Messaging ホスト起動、実ダウンロードの `:Zone.Identifier` 付与と移動後紐付け、および実 WebView2 終了計測は合成テストでは検証済みと扱わず、Windows 10/11 クライアント SKU の実機 E2E（`FU-E2E-02`）対象として残す。

## 対象外

- 境界チェックに関与しない UI の見た目やログ文言のみの調整
- テスト用モック定数やドキュメント誤字のみの修正
