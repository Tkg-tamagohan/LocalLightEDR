# Review Guidelines

本ファイルは Devin Review 向けの PR レビュー指針です。
共通のアーキテクチャ規約と標準検証コマンドは `AGENTS.md` に集約し、Phase 別およびサブシステム別の不変条件は `AGENTS.md` で案内する `.agents/rules/`（`daemon-wfp-process-invariants.md`、`active-defense-guards.md`、`browser-ui-invariants.md`）へ分離済みのため重複記載しません。
`AGENTS.md` および変更対象に対応する `.agents/rules/*.md` とあわせて参照し、バグ、セキュリティ欠陥、並行処理の不整合、後方互換破壊に焦点を絞ってください。

## レビュー言語

すべてのレビューコメント、指摘、要約、補足は日本語で出力してください。
ファイルパス、シンボル名、API 名、エラー型などの識別子はコード上の表記をそのまま使ってください。

## 重点チェック領域（Critical Areas）

- **IPC と認可境界**：`crates/ledr-proto/src/lib.rs`、`crates/ledr-daemon/src/ipc/`、`crates/ledr-daemon/src/notify.rs`、`crates/ledr-bridge-nm/src/`、`apps/ledr-ui/src/{defense_status,uri_reg,ipc}.rs`
- **署名分離と検証**：`crates/ledr-daemon/src/engine/auth_worker.rs`、`crates/ledr-auth-helper/src/`
- **能動防御、ETW、WFP、NRD**：`crates/ledr-sensor-win/src/{defense,wfp,etw}/`、`crates/ledr-rules/src/nrd/`
- **並行処理、状態機械、永続化**：`crates/ledr-daemon/src/{engine,firewall,process_table.rs,service_win.rs}`、`crates/ledr-store/src/`
- **自己更新と配布**：`crates/ledr-updater/src/`、`apps/ledr-ui/src/updater.rs`、`packaging/update-public-keys.json`、`packaging/windows/`、`scripts/{build_release_artifacts,release_verify}.py`
- **ブラウザ拡張と検知ルール**：`extensions/ledr-chrome-mv3/`、`rules/`

## 優先して指摘してほしい観点

- **diff 外への影響とモジュール間契約**：IPC 権限マトリクス、Named Pipe SDDL とクライアントアクセス権マスク（`0x0012_019B`）、View 3 の Rust 診断出力と UI 表示、固定拡張 ID、3 ファイル間のバージョン同期など、他モジュールへ波及する不整合を優先してください。
- **後方互換性の破壊**：`crates/ledr-proto/src/lib.rs` の公開型、列挙バリアント、フレーミング仕様の非互換変更を指摘してください。
- **権限、認可、署名分離、TOCTOU**：非 `Ping` IPC での `CallerAuthPolicy` と `inspect_uncached` 強制、`ledr-daemon.exe` への `wintrust.dll` や `crypt32.dll` 依存混入、Session 0 からの SYSTEM 権限 UI 起動、リパースポイントやハードリンク（`nNumberOfLinks == 1`）検査の抜け、アンインストール時の未解決サスペンド検査や ACL 設定前のリパース検査漏れを確認してください。
- **能動防御とカーネル境界の安全性**：`is_never_suspend_process` と `create_time_100ns` 照合の欠落、子孫追跡での PID 再利用境界、WFP 動的セッション（`FWPM_SESSION_FLAG_DYNAMIC`）外への永続フィルタ残留、BFE コールバック内のブロッキング処理、WinHTTP コールバックのライフタイム破綻を確認してください。
- **並行処理、ロック順序、停止とロールバック**：ロック順序 `firewall -> process_table` の逆転、自動事前遮断の直接 `add_wfp_app_rule` 呼び出しでの両ロック保持、その他の BFE 呼び出し（`ensure_policy_block`、ロールバック再登録、`remove_wfp_rule`）での `process_table` ロック保持（`firewall` 保持は正当）、部分失敗時のロールバック漏れ、有界チャネル受信端を閉じる前のスレッド `join()`、3 秒停止予算を阻む待機や定期保守の抑止漏れを確認してください。
- **アップデータのフェイルクローズ**：署名検証前のパース、許可ホストやリダイレクト上限およびサイズ上限の逸脱、起動時 `update-state.json` 再検証の抜けを指摘してください。
- **境界値とエラー処理漏れ**：Win32 `HRESULT`（`0x8007xxxx`）変換漏れ、エラーの握り潰し、空入力や上限超過時のフェイルオープンを指摘してください。

## 指摘を抑えてほしい観点・除外対象（Ignore）

### 指摘を抑える観点

- フォーマット、インデント、命名の好み、軽微なリファクタリング提案など主観的なスタイル指摘
- CI（`cargo clippy -D warnings`、`cargo test`、`cargo doc`、`node --check`、JSON 厳格検証、UTF-8 と競合マーカー検査、`release_verify.py preflight`）で機械検知する項目
- PR 内の既存スレッドで議論済み、または「意図的な設計」と明示された箇所への重複指摘

### 除外対象パス（Ignore）

- `Cargo.lock`（自動生成ロックファイル）
- `ledr_artifact.html`（初期設計メモの base64 画像を含む静的 HTML）
- `apps/ledr-ui/icons/**`（バイナリアイコン）
- `docs/fixtures/**`（手動 E2E 用 HTML フィクスチャ）
- `.agents/decision1/**`（ビジュアル評価プリセット JSON）

### 意図的な設計例外（必要に応じて追記）

- `crates/ledr-sim/**`：ローカル検証用の無害な攻撃シミュレータであり、悪性挙動や脆弱性として指摘しないでください。
- ユーザーモード完結設計：カーネルミニフィルタ、ELAM、WFP コールアウトドライバの導入を提案しないでください。
- `--dev-bypass-auth`：ローカル開発用オプションであり、`LocalSystem` 実行時は SYSTEM と Administrators 限定の SDDL へフェイルクローズします。
- `crates/ledr-auth-helper/src/authenticode.rs`：`WTD_REVOCATION_CHECK_NONE` と `WTD_CACHE_ONLY_URL_RETRIEVAL` によるオフライン検証は、遅延と外部通信を防ぐための意図的な設計です。
- `extensions/ledr-chrome-mv3/manifest.json` の `"key"` と `content_main.js`：公開鍵のみの固定 ID 用途、および ClickFix 検知のための `"world": "MAIN"` 観測です。
- `packaging/update-public-keys.json` のプレースホルダ鍵：リリース前に更新をフェイルクローズさせる既定値です。
- `crates/ledr-bridge-nm/src/relay.rs` の `stderr` 専用ログ：Chrome Native Messaging の `stdout` フレーミング保護のため必須です。
- `apps/ledr-ui/src/uri_reg.rs` と `crates/ledr-bridge-nm/src/setup.rs` の診断境界差：`REG_SZ` 限定と `REG_EXPAND_SZ` 対応の差異は `docs/follow-up-notes.md` の `FU-P4-01` で管理済みです。

## 指摘の書き方（トリアージ向け）

修正とトリアージは AGY App 側で行うため、各指摘は次の要素を簡潔に含めてください。

- **対象**：ファイルパスとシンボル名（関数、型、定数など）
- **発生条件と影響**：どの入力、状態、実行順序で問題が起き、何が壊れるか
- **根拠**：違反している不変条件や diff 外の依存先（該当箇所の参照があれば明記）
- **修正の方向性**：最小限の対応方針を 1 文から 2 文で記載（GitHub の Suggested change ブロックは不要）
