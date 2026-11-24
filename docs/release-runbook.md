# LocalEDR リリースおよび運用手順書

本書は LocalEDR の Windows x64 向けリリース配布（`vX.Y.Z`）、Ed25519 署名鍵の管理と 2 段階ローテーション、インストーラによる導入と復旧、およびアンインストール時のデータ保全境界を定める（`決定記録 L-26` 〜 `決定記録 L-29`）。

## 概要と前提条件

LocalEDR の配布物は Windows x64 環境を前提としており、リリースごとに次の 3 ファイルのバージョンを完全に揃える必要があります。

- **ワークスペース定義**：`Cargo.toml` の `[workspace.package].version`
- **Tauri UI 設定**：`apps/ledr-ui/tauri.conf.json` の `version`
- **Chrome MV3 拡張マニフェスト**：`extensions/ledr-chrome-mv3/manifest.json` の `version`

リリースの前後を通じて、次の不変条件は変更しません。

- **IPC と proto 互換**：`crates/ledr-proto` の公開型とシグネチャ、および `apps/ledr-ui/tauri.conf.json` の CSP 文字列は維持します。
- **固定 Chrome 拡張 ID**：`extensions/ledr-chrome-mv3/manifest.json` の `"key"` から導出される ID は `ecelachfiiiiiibpjeomfncgpegbpanh` に固定します（`L-20`）。
- **公開鍵の埋め込みとフェイルクローズ**：`crates/ledr-updater` は `packaging/update-public-keys.json` を `include_str!` でコンパイル時に埋め込みます。
  初期状態（`key_id: "placeholder-unconfigured"`、`status: "disabled"`）では有効鍵が 0 件のため、自動更新検証は `UnconfiguredPublicKeyRing` でフェイルクローズします。

## 初回署名鍵の発行と登録

本番リリースを公開する前に、作業端末のローカル環境で用途専用の Ed25519 署名鍵ペアを新規発行してください。
秘密鍵はリポジトリへ絶対にコミットせず、チャットやログにも出力しない運用を徹底します。

1. `scripts/release_verify.py keygen` を実行し、一時ファイルへ秘密鍵と公開鍵リングを出力します。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python scripts/release_verify.py keygen `
  --key-id "prod-2026-11" `
  --format b64 `
  --write-public-keys "$env:TEMP\update-public-keys.json" `
  --write-private-key-file "$env:TEMP\ledr-signing-private.key"
```

2. GitHub リポジトリの `Settings`、`Secrets and variables`、`Actions` の順に開き、`New repository secret` で秘密鍵のみを登録してください。
   登録する Secret 名と任意指定の鍵識別子は次のとおりです。

- **`LEDR_UPDATE_SIGNING_PRIVATE_KEY`（必須）**：`$env:TEMP\ledr-signing-private.key` の内容（32 バイト Base64 シード、または PKCS#8 PEM 形式）をそのまま登録します。
- **`LEDR_UPDATE_SIGNING_KEY_ID`（任意）**：公開鍵リングに複数の `active` 鍵を同時掲載するときに、署名へ使う `key_id` を明示する場合のみ登録します。

3. 登録後は端末上の一時秘密鍵ファイルを削除し、`packaging/update-public-keys.json` を更新します。
   `placeholder-unconfigured` のエントリは削除するか `disabled` のまま残し、新規鍵を `status: "active"` として追加してください。

```json
{
  "schema_version": 1,
  "keys": [
    {
      "key_id": "prod-2026-11",
      "public_key_b64": "<keygen が出力した 32 バイト公開鍵 Base64>",
      "status": "active"
    }
  ]
}
```

4. 公開鍵の更新後、署名検証と事前検査が通ることをローカルで確認します。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python scripts/release_verify.py preflight --require-active-key
cargo test -p ledr-updater --locked
```

## リリースタグ手順とドライラン

本番タグを押す前に、バージョン整合とドライランビルドを必ず通してください。

1. **リリース前検査**：3 ファイルのバージョンを目標の `X.Y.Z`（プレリリース識別子なし）へ更新し、タグ整合と単体テストを実行します。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python scripts/release_verify.py preflight --expect-tag v0.1.0 --require-active-key
python -m unittest scripts/test_release_scripts.py
python -m unittest scripts/test_check_invariants.py
```

2. **ドライラン実行（`workflow_dispatch`）**：GitHub Actions の `Release` ワークフロー（`.github/workflows/release.yml`）を手動実行し、`dry_run: true` を指定します。
   ドライランでは `preflight` と `build` が走り、ジョブ内の一時テスト鍵で `LocalEDR-Setup-vX.Y.Z-win-x64.exe`、`LocalEDR-vX.Y.Z-win-x64.zip`、`LocalEDR-chrome-ext-vX.Y.Z.zip`、`SHA256SUMS.txt`、`update-manifest.json`、および `update-manifest.json.sig` の 6 点を作成して `verify-dist` まで検証し、`publish` ジョブはスキップします。
   なお、ドライラン時にコンパイルされる `ledr-ui.exe` は一時テスト鍵（`dry-run-test`）を生成する前の段階でリポジトリ内の `packaging/update-public-keys.json` を埋め込んでビルドされます。
   そのため、ドライランで生成された `ledr-ui.exe` 自体は一時テスト鍵を信頼せず、ドライランが検証する範囲はパッケージング、一時鍵による署名、および `verify-dist` による配布物検証までです。

3. **本番タグリリース**：ドライランが成功したら、注釈付きタグを作成して `origin` へ push してください。

```powershell
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

4. **原子的公開順序の確認（`L-27`）**：`publish` ジョブは次の順序で GitHub Release を公開します。
   最初に `gh release create --draft` で下書きを作成し、インストーラ、ZIP 2 種、および `SHA256SUMS.txt` をアップロードした後に、最後に `update-manifest.json` と `update-manifest.json.sig` をアップロードし、末尾で `gh release edit --draft=false` により公開状態へ切り替えます。

5. **公開後の事後確認**：GitHub Release ページ上に 6 点すべてのアセットが揃っていること、および `update-manifest.json` の `version`、`tag`、`sha256`、`size_bytes`、`chrome_extension.extension_id` が期待値と一致していることを確認してください。

## 2 段階鍵ローテーション手順

インストール済みの `ledr-ui.exe` はコンパイル時の `packaging/update-public-keys.json` を内蔵しているため、旧鍵をいきなり `revoked` へ変えて新鍵だけで署名すると、旧版クライアントが自己更新できなくなります。
運用中の署名鍵を更新するときは、必ず次の 2 段階に分けて切り替えてください。

### 第 1 段階：新鍵の追加と移行版の配布

1. 新しい Ed25519 鍵ペア（例として `key_id: "prod-2027-01"`）を発行します。
2. `packaging/update-public-keys.json` で旧鍵を `"status": "active"` のまま残し、新鍵を `"status": "active"` として追加します。
3. この時点では GitHub Secret `LEDR_UPDATE_SIGNING_PRIVATE_KEY` を変更せず、旧秘密鍵のまま移行版リリース（例：`v0.2.0`）を作成して配布します。
   旧版クライアントは旧鍵で `v0.2.0` を検証して更新でき、更新後のバイナリは旧鍵と新鍵の両方を信頼するようになります。

### 第 2 段階：秘密鍵の切替と旧鍵の失効

1. 移行版 `v0.2.0` の展開が完了したら、GitHub Secret `LEDR_UPDATE_SIGNING_PRIVATE_KEY` を新秘密鍵へ更新します。
2. `packaging/update-public-keys.json` の旧鍵を `"status": "revoked"` へ変更します。
3. 次期リリース（例：`v0.2.1`）を新秘密鍵で署名して公開します。
   なお、`crates/ledr-updater` は `min_updater_version` 等を解析する `parse_and_validate_manifest` より前に `verify_manifest_signature` で Ed25519 署名を検証します。
   そのため、新鍵を持たない `v0.2.0` 未満の古いクライアントは署名検証の段階で失敗して `ManualUpdateRequired` を表示できないため、旧鍵の失効後に残存端末を更新するには新しい署名付きインストーラを手動配布してください（`min_updater_version` による `ManualUpdateRequired` の誘導は、署名鍵をすでに信頼している `v0.2.0` 以降のクライアントにのみ機能します）。

## ロールバック手順

障害の種別に応じて、公開済みリリースの停止とホスト側の復旧を切り分けます。

### 公開済みリリースに不具合が見つかった場合

`crates/ledr-updater` は `manifest.version > current_version` を厳密に強制するため、バージョン番号を下げる形での自動ダウングレードは行えません。
不具合のある公開リリースは速やかに下書きへ戻すか削除して新規ダウンロードを止め、修正後にパッチバージョン（`vX.Y.(Z+1)`）を新規リリースしてください。

### 署名秘密鍵の漏洩が疑われる場合

直ちに `packaging/update-public-keys.json` で漏洩した `key_id` を `"status": "revoked"` へ変更し、新規発行した `active` 鍵へ切り替えて `LEDR_UPDATE_SIGNING_PRIVATE_KEY` を差し替えてください。
改ざんされたリリース資産がある場合はそのリリースを削除し、修正済みパッチ版（`vX.Y.(Z+1)`）を公開します。
すでに旧版しか持たない端末に対しては、新しい署名付きインストーラの手動適用を案内してください。

### 端末上のインストール失敗とロールバック

`packaging/windows/localedr.nsi` と `install.ps1` は導入や更新の途中で失敗した際に次の順で自動ロールバックします。

1. 新規に開始した `LocalEDR` サービスを停止します（上限 15 秒）。
2. 新規導入時の失敗であれば `ledr-bridge-nm.exe unregister --scope machine` を試行し、アップグレード時の失敗であれば退避先の 4 バイナリと配布ルール 2 ファイル（`rules\lotl_core.json`、`rules\default_allowlist.json`）を復元します。
3. 新規作成したサービスは削除し、既存サービスは元の構成へ戻したうえで、更新前に起動していた場合のみ `LocalEDR` を再起動します。

障害解析時は `C:\ProgramData\LocalEDR\logs\installer.log` を確認してください。
手動でやり直す場合は、ZIP パッケージ展開先から管理者権限の 64 ビット PowerShell（Windows PowerShell 5.1 または PowerShell 7 以上）で `install.ps1`（更新時は `-UpdateMode`）を実行できます。

## アンインストールとデータ保全一覧

アンインストールは既定で監視履歴とルールを保全し、明示的に `/PURGE_DATA`（または `uninstall.ps1 -PurgeData`）を指定した場合のみ `C:\ProgramData\LocalEDR` を削除します。

| 対象パスまたは登録項目 | 既定のアンインストール | `/PURGE_DATA` 指定時 | 補足 |
| :--- | :--- | :--- | :--- |
| `C:\Program Files\LocalEDR\`（4 バイナリ、`uninstall.ps1`、`uninstall.exe`） | 削除 | 削除 | 終了待機上限は UI 10 秒、SCM 15 秒、ロック再試行 5 秒です。 |
| Windows Service `LocalEDR`（`sc.exe delete LocalEDR`） | 削除 | 削除 | 停止後にサービス登録を削除します。 |
| 各ユーザーのおとりファイル（`%USERPROFILE%\{Documents,Desktop,Pictures}\!00_LocalEDR_Canary_DoNotEdit.docx`） | 削除 | 削除 | SQLite `honeypot_files` 追跡記録（ボリュームおよびファイル識別子を含む）と各ユーザープロファイル一覧に基づき、サービス停止後に `ledr-daemon.exe --cleanup-honeypots` がリパースポイントとハードリンクを拒否しつつハンドル上で自動削除します（`L-06`）。誤削除防止のため、記録済み識別子に一致しない置換後ファイル、識別子を持たない旧形式のおとりで文面が書き換えられているファイル、および未記録かつ既知デコイ文面に一致しない同名のユーザー文書は削除せず残します（追跡行のみ解除するため、不要時は手動削除してください）。 |
| `HKLM` Native Messaging（`KEY_WOW64_32KEY` と `KEY_WOW64_64KEY`）、`ledr://`、AUMID | 削除 | 削除 | `ledr-bridge-nm.exe unregister --scope machine` で解除します。 |
| ARP 登録（`Uninstall\LocalEDR`） | 削除 | 削除 | 64 ビットレジストリビューから削除します。 |
| `C:\ProgramData\LocalEDR\localedr.db`（`-wal`、`-shm`） | 保全 | 削除 | 再インストール時の履歴引き継ぎのため既定で残します。 |
| `C:\ProgramData\LocalEDR\nrd-cache.txt` | 保全 | 削除 | ローカル NRD キャッシュです。 |
| `C:\ProgramData\LocalEDR\rules\`（配布 2 ファイルと独自ルール） | 保全 | 削除 | 通常アップグレードでは配布 2 ファイルのみ更新します。 |
| `C:\ProgramData\LocalEDR\logs\installer.log` と `logs\` | 保全 | 削除 | `/PURGE_DATA` 時はログハンドルを閉じてから削除します。 |
| `C:\ProgramData\LocalEDR\native-messaging\` | 参照なしマニフェストのみ削除（ディレクトリは保全） | 削除 | `HKCU` 参照が残る場合を除き未使用 JSON を削除します。 |
| `C:\ProgramData\LocalEDR\updates\verified\` | 保全 | 削除 | 更新適用完了後は昇格インストーラ側で一時ディレクトリを削除します。 |
| ユーザー別領域（`%LOCALAPPDATA%\LocalEDR\`、`HKCU` 登録） | 保全 | 保全（対象外） | マシン単位のアンインストール範囲外のため、必要時は各ユーザー環境で `ledr-bridge-nm.exe unregister --scope user` 等を実行してください。 |

### Native Messaging の検証表示に関する補足

UI の View 3（`apps/ledr-ui/src/defense_status.rs`）は、マニフェストファイルの読み取り対象を `%LOCALAPPDATA%\LocalEDR\native-messaging` と `C:\ProgramData\LocalEDR\native-messaging` の 2 ディレクトリだけに限定しています。
管理者やユーザーがそれ以外のカスタムパスへマニフェストを配置した場合、UI はセキュリティ境界保護のためファイル I/O を行わず `unverified` と表示します。
カスタムパスの状態を確認したい場合は、対象 JSON ファイルを直接確認するか、コマンドラインから `ledr-bridge-nm.exe status` を実行してください。
