# Phase 4 実機 Chrome E2E 検証手順書

本書は LocalEDR の Phase 4（Native Messaging ブリッジ、Chrome Manifest V3 拡張、MOTW 3 段階紐付け、`ledr-ui` View 1〜3 統合）を Windows 10 または Windows 11（x86_64）クライアント SKU 実機で検証する手順を定める。
作業は [follow-up-notes.md](follow-up-notes.md) の `FU-E2E-02` に対応し、外部ネットワークへ接続せずローカル環境のみで完結する。

## 作業分担

| 担当 | 対象作業 |
| :--- | :--- |
| ビルド済み検証資産（リポジトリ同梱） | `ledr-daemon.exe`、`ledr-bridge-nm.exe`、`ledr-ui.exe`、`ledr-sim.exe`、`extensions/ledr-chrome-mv3`、[phase4-browser-test.html](fixtures/phase4-browser-test.html) |
| 検証者（手作業） | レジストリ登録、Chrome デベロッパーモード読み込み、ローカル HTTP サーバ起動、検証画面操作、プロセス終了確認、後片付け |

## 準備物の棚卸し

作業ディレクトリ `e:\Documents\code\LocalEDR` で事前にデバッグビルドを実行し、次のバイナリと資産が揃っていることを確かめてください。

```powershell
cd e:\Documents\code\LocalEDR
cargo build --workspace --locked
```

- **検証用バイナリ**：`target\debug\ledr-daemon.exe`、`target\debug\ledr-bridge-nm.exe`、`target\debug\ledr-ui.exe`、`target\debug\ledr-sim.exe`
- **Chrome 拡張ディレクトリ**：`extensions\ledr-chrome-mv3`（固定拡張 ID `ecelachfiiiiiibpjeomfncgpegbpanh`）
- **ローカル検証ページ**：`docs\fixtures\phase4-browser-test.html`
- **ウィンドウ A（管理者 PowerShell）**：`ledr-daemon.exe` の起動と `--scope machine` 検証用
- **ウィンドウ B（通常ユーザー PowerShell）**：`ledr-bridge-nm.exe setup`、ローカル HTTP サーバ起動、Chrome 起動、`ledr-ui.exe` 起動、後片付け用

検証ごとに独立した一時フォルダを作成し、テスト用 NRD ドメインリストとダウンロード用無害実行ファイル（`ledr-sim.exe` のコピー）を配置してください。

```powershell
cd e:\Documents\code\LocalEDR
$runDir = "C:\Temp\ledr-p4-e2e-" + (Get-Date -Format "yyyyMMdd-HHmmss")
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
New-Item -ItemType Directory -Force -Path "$runDir\site\download" | Out-Null
New-Item -ItemType Directory -Force -Path "$runDir\chrome-profile" | Out-Null
Copy-Item "docs\fixtures\phase4-browser-test.html" "$runDir\site\phase4-browser-test.html"
Copy-Item "target\debug\ledr-sim.exe" "$runDir\site\download\localedr-e2e-sample.exe"
[System.IO.File]::WriteAllText("$runDir\site\download\localedr-e2e-sample.cmd", "@echo off`r`necho LocalEDR MOTW E2E`r`n", [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText("$runDir\nrd-test-feed.txt", "nrd-sim.localedr.invalid`r`n", [System.Text.UTF8Encoding]::new($false))
Write-Output ("RunDir=" + $runDir)
```

## 手順 1 Native Messaging と URI スキームの登録

ウィンドウ B（通常ユーザー権限）でユーザー単位の登録（`HKCU`）を実行し、`status` と `ledr-ui` View 3 の表示を確かめてください。

```powershell
cd e:\Documents\code\LocalEDR
.\target\debug\ledr-bridge-nm.exe setup --scope user --browsers chrome,edge --bridge-exe "$PWD\target\debug\ledr-bridge-nm.exe" --ui-exe "$PWD\target\debug\ledr-ui.exe"
.\target\debug\ledr-bridge-nm.exe status --scope all
```

必要に応じてウィンドウ A（管理者権限）でも `--scope machine` を実行し、`HKLM` 登録と解除が正常に動くことを確かめてください。

```powershell
cd e:\Documents\code\LocalEDR
.\target\debug\ledr-bridge-nm.exe setup --scope machine --browsers chrome,edge --bridge-exe "$PWD\target\debug\ledr-bridge-nm.exe" --ui-exe "$PWD\target\debug\ledr-ui.exe"
.\target\debug\ledr-bridge-nm.exe status --scope all
```

ウィンドウ A で `ledr-daemon.exe` を検証用設定で起動し、続けてウィンドウ B で `ledr-ui.exe` を開いて `View 3: 防御ポリシー・カナリア・ブラウザシールド` を確認してください。
ウィンドウ A の `$runDir` へ同じパスを設定してから起動してください。

```powershell
# ウィンドウ A（管理者 PowerShell）
$runDir = (Get-ChildItem C:\Temp -Directory -Filter "ledr-p4-e2e-*" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$nrdUrl = ([Uri]"$runDir\nrd-test-feed.txt").AbsoluteUri
.\target\debug\ledr-daemon.exe --foreground --dev-bypass-auth --db "$runDir\ledr.db" --nrd-feed-url $nrdUrl --nrd-cache "$runDir\nrd-cache.txt"
```

`View 3` のブラウザシールド欄に次の項目が表示されていれば登録確認は完了です。

- `Daemon IPC` が `Connected`
- `Native Messaging` が登録スコープ（`HKCU`、`HKLM`、または `HKCU+HKLM`）と登録ブラウザ（`Chrome`、`Edge`）を表示
- `Manifest` が `Valid` および対象 JSON パスを表示
- `Extension ID` が `ecelachfiiiiiibpjeomfncgpegbpanh` を表示
- `URI Protocol` が `ledr://` の登録スコープを表示

## 手順 2 Chrome 拡張の読み込みと疎通確認

ウィンドウ B でローカル HTTP サーバを起動し、隔離プロファイルと名前解決ルール付きで Chrome を起動してください。
非 `https` 環境でも `navigator.clipboard.writeText` を動作させるため、検証用オリジンへ `--unsafely-treat-insecure-origin-as-secure` を付与します。

```powershell
# ウィンドウ B（通常ユーザー PowerShell）
$serveScript = @"
import http.server, os, sys
root = sys.argv[1]
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=root, **kwargs)
    def do_GET(self):
        if self.path.split('?', 1)[0] == '/beacon':
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'ok')
            return
        super().do_GET()
http.server.ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
"@
$servePath = Join-Path $runDir "local_server.py"
[System.IO.File]::WriteAllText($servePath, $serveScript, [System.Text.UTF8Encoding]::new($false))
$serverProc = Start-Process -FilePath python -ArgumentList @($servePath, "$runDir\site") -PassThru -WindowStyle Minimized

$chromeExe = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
if (-not (Test-Path $chromeExe)) { $chromeExe = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe" }
& $chromeExe `
  --user-data-dir="$runDir\chrome-profile" `
  --host-resolver-rules="MAP *.localedr.invalid 127.0.0.1" `
  --unsafely-treat-insecure-origin-as-secure="http://clickfix-sim.localedr.invalid:8765,http://nrd-sim.localedr.invalid:8765,http://login-paypa1.localedr.invalid:8765" `
  "chrome://extensions"
```

1. Chrome の `chrome://extensions` でデベロッパーモードを有効にし、`パッケージ化されていない拡張機能を読み込む` から `e:\Documents\code\LocalEDR\extensions\ledr-chrome-mv3` を選択してください。
2. 読み込まれた拡張の ID が `ecelachfiiiiiibpjeomfncgpegbpanh` と一致することを確かめてください。
3. ツールバーの拡張アイコンからポップアップ `LocalEDR Browser Shield` を開き、`Ping` ボタンを押して `Daemon` がオンライン応答することを確かめてください。

## 手順 3 テストケースの実施

以下の順でローカル検証ページを開き、ブラウザ内警告と `ledr-ui` 側の記録を確かめてください。

| ID | 対象URLと操作 | 期待結果 |
| :--- | :--- | :--- |
| `E2E-P4-01` | `http://clickfix-sim.localedr.invalid:8765/phase4-browser-test.html` で `Copy Verification Command` を押下 | ブラウザ内 Shadow DOM に ClickFix 警告が表示され、`ledr-ui` View 1 に `LAYER_4_BROWSER`（`ClickFixPastejacking`）が記録され、`Acknowledge` のみ有効で解決できる |
| `E2E-P4-02` | 同ページの領域 2（`echo hello-localedr`）を選択して `Ctrl+C` | ブラウザ内に Pastejacking 警告が表示され、領域 3（`Copy Snippet` と通常選択コピー）では警告が発火しない |
| `E2E-P4-03` | `http://nrd-sim.localedr.invalid:8765/phase4-browser-test.html` の `Password` 欄へフォーカスして 1 文字入力 | ブラウザ内に NRD 警告が表示され、View 1 に `NrdPasswordWarning` が記録される |
| `E2E-P4-04` | `http://login-paypa1.localedr.invalid:8765/phase4-browser-test.html` の `Password` 欄へフォーカスして 1 文字入力 | ブラウザ内にホモグラフ警告（対象ブランド `paypal`）が表示され、View 1 に `HomographWarning` が記録される |
| `E2E-P4-05` | `Fetch safe-sim.localedr.invalid` と `Fetch c2-sim.localedr.invalid` を順に押下 | `safe-sim` は `HTTP 200` で成功し、`c2-sim` と `blocked-test` は DNR 静的ルールで即座に遮断され、`DnrBlockedRequest` が記録される |
| `E2E-P4-06` | `Download localedr-e2e-sample.exe` でファイルをダウンロードし、`Downloads` から `$runDir\moved\localedr-e2e-sample.exe` へ移動した上で `--help` 付きで 1 回起動 | View 3 の `Tracked Downloads` が増加し、View 2 のプロセスツリーに `MOTW` バッジと `Origin URL (MOTW)`、選択時の `download_origins` 行（`referrer_url` と短縮 `sha256`）が表示される |
| `E2E-P4-07` | View 1 の未解決 `LAYER_4_BROWSER` アラートを `Acknowledge` で解決後、`ledr-ui` ウィンドウを閉じる | View 1 で解決状態へ遷移し、ウィンドウ閉鎖後に `ledr-ui` と WebView2 の残留プロセスが 0 件になる |

## 手順 4 終了確認と性能計測

`ledr-ui` ウィンドウを閉じた後、ウィンドウ B で残留プロセスゼロとデーモン常駐負荷を確かめてください。

```powershell
Get-Process ledr-ui -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" | Where-Object { $_.CommandLine -like "*LocalEDR*" }
Get-Process ledr-daemon | Select-Object ProcessName, @{Name='WorkingSetMB';Expression={[math]::Round($_.WorkingSet64/1MB,2)}}, CPU
```

- `ledr-ui` が 0 件であり、LocalEDR 由来の `msedgewebview2.exe` が残っていないこと（`L-08`）。
- 10 分間のアイドル計測で `ledr-daemon` の Working Set が 20 MB 以下、CPU 平均使用率が 0.5% 未満であること。

## 後片付け

検証完了後、起動したローカルサーバと検証用登録をすべて片付けてください。

```powershell
if ($serverProc -and -not $serverProc.HasExited) { Stop-Process -Id $serverProc.Id -Force }
.\target\debug\ledr-bridge-nm.exe unregister --scope user --browsers chrome,edge
# 管理者ウィンドウ A で --scope machine を登録した場合のみ:
# .\target\debug\ledr-bridge-nm.exe unregister --scope machine --browsers chrome,edge
Remove-Item -Recurse -Force $runDir
```

## 合否記録テンプレート

実機 E2E 実施時は以下の表を埋めて PR または検証報告へ記録する。

| 項目 ID | 実施結果（Pass / Fail） | OS ビルド / Chrome 版 | 証跡メモ |
| :--- | :--- | :--- | :--- |
| `E2E-P4-01` | | | |
| `E2E-P4-02` | | | |
| `E2E-P4-03` | | | |
| `E2E-P4-04` | | | |
| `E2E-P4-05` | | | |
| `E2E-P4-06` | | | |
| `E2E-P4-07` | | | |
| `L-08` / 性能 | | | |
