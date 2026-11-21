# Phase 4 実機 Chrome E2E 検証手順書

本書は LocalEDR の Phase 4（Native Messaging ブリッジ、Chrome Manifest V3 拡張、MOTW 3 段階紐付け、`ledr-ui` View 1〜3 統合）を Windows 10 または Windows 11（x86_64）クライアント SKU 実機で検証する手順を定める。
作業は [follow-up-notes.md](follow-up-notes.md) の `FU-E2E-02` に対応し、外部ネットワークへ接続せずローカル環境のみで完結する。

## 作業分担

| 担当 | 対象作業 |
| :--- | :--- |
| ビルド済み検証資産（リポジトリ同梱） | `ledr-daemon.exe`、`ledr-bridge-nm.exe`、`ledr-ui.exe`、`ledr-sim.exe`、`extensions/ledr-chrome-mv3`、[phase4-browser-test.html](fixtures/phase4-browser-test.html) |
| 検証者（手作業） | 既存レジストリ退避、レジストリ登録、Chrome デベロッパーモード読み込み、ローカル HTTP サーバ起動、検証画面操作、性能計測、プロセス終了確認、後片付け |

## 準備物の棚卸し

作業ディレクトリ `e:\Documents\code\LocalEDR` で事前に機能検証用デバッグビルドを実行し、次のバイナリと資産が揃っていることを確かめてください。

```powershell
cd e:\Documents\code\LocalEDR
cargo build --workspace --locked
```

- **検証用バイナリ**：`target\debug\ledr-daemon.exe`、`target\debug\ledr-bridge-nm.exe`、`target\debug\ledr-ui.exe`、`target\debug\ledr-sim.exe`
- **Chrome 拡張ディレクトリ**：`extensions\ledr-chrome-mv3`（固定拡張 ID `ecelachfiiiiiibpjeomfncgpegbpanh`）
- **ローカル検証ページ**：`docs\fixtures\phase4-browser-test.html`
- **ウィンドウ A（管理者 PowerShell）**：`ledr-daemon.exe` の起動と停止、`--scope machine` 検証用
- **ウィンドウ B（通常ユーザー PowerShell）**：既存設定の退避、`ledr-bridge-nm.exe setup`、ローカル HTTP サーバ起動、Chrome 起動、`ledr-ui.exe` 起動、後片付け用

検証ごとに独立した一時フォルダを作成し、テスト用 NRD ドメインリスト、ダウンロード用無害実行ファイル（`ledr-sim.exe` のコピー）、および `E2E-P4-06` 用のダミーカナリアディレクトリを `ledr-daemon.exe` 起動前に準備してください。

```powershell
cd e:\Documents\code\LocalEDR
$runDir = "C:\Temp\ledr-p4-e2e-" + (Get-Date -Format "yyyyMMdd-HHmmss")
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
New-Item -ItemType Directory -Force -Path "$runDir\site\download" | Out-Null
New-Item -ItemType Directory -Force -Path "$runDir\chrome-profile" | Out-Null
New-Item -ItemType Directory -Force -Path "$runDir\canary_dir" | Out-Null
New-Item -ItemType Directory -Force -Path "$runDir\backup" | Out-Null
Copy-Item "docs\fixtures\phase4-browser-test.html" "$runDir\site\phase4-browser-test.html"
Copy-Item "target\debug\ledr-sim.exe" "$runDir\site\download\localedr-e2e-sample.exe"
[System.IO.File]::WriteAllText("$runDir\site\download\localedr-e2e-sample.cmd", "@echo off`r`necho LocalEDR MOTW E2E`r`n", [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText("$runDir\nrd-test-feed.txt", "nrd-sim.localedr.invalid`r`n", [System.Text.UTF8Encoding]::new($false))
.\target\debug\ledr-sim.exe --prepare-dir "$runDir\canary_dir" --json
Write-Output ("RunDir=" + $runDir)
```

## 手順 1 Native Messaging と URI スキームの登録

Chrome へ隔離プロファイル（`--user-data-dir`）を指定しても、Windows の Native Messaging Host と `ledr://` のレジストリ登録は同一ユーザーおよびマシン全体で共有される。
`ledr-bridge-nm.exe setup` は既存の登録値を上書きし、後片付けの `unregister` は元の設定へ戻さずに削除するため、本手順は検証専用の Windows 環境で実施するか、実行前に既存のレジストリキーとマニフェストを `$runDir\backup` へ退避してから進めてください。

```powershell
# ウィンドウ B（通常ユーザー権限）: 既存の HKCU 登録とマニフェストを退避（未登録キーはスキップ）
$hkcuBackups = @(
    @{ Key = "HKCU\Software\Google\Chrome\NativeMessagingHosts\com.localedr.bridge"; File = "hkcu_chrome_nmh.reg" },
    @{ Key = "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.localedr.bridge"; File = "hkcu_edge_nmh.reg" },
    @{ Key = "HKCU\Software\Classes\ledr"; File = "hkcu_ledr_uri.reg" },
    @{ Key = "HKCU\Software\Classes\AppUserModelId\LocalEDR.AlertUI"; File = "hkcu_aumid.reg" }
)
foreach ($item in $hkcuBackups) {
    if (Test-Path ("Registry::" + $item.Key)) {
        reg export $item.Key (Join-Path "$runDir\backup" $item.File) /y | Out-Null
    }
}
$userManifestDir = Join-Path $env:LOCALAPPDATA "LocalEDR\native-messaging"
if (Test-Path $userManifestDir) {
    Copy-Item -Recurse -Force $userManifestDir "$runDir\backup\user-native-messaging"
}
```

退避が完了したら、ウィンドウ B（通常ユーザー権限）でユーザー単位の登録（`HKCU`）を実行し、`status` と `ledr-ui` View 3 の表示を確かめてください。

```powershell
cd e:\Documents\code\LocalEDR
.\target\debug\ledr-bridge-nm.exe setup --scope user --browsers chrome,edge --bridge-exe "$PWD\target\debug\ledr-bridge-nm.exe" --ui-exe "$PWD\target\debug\ledr-ui.exe"
.\target\debug\ledr-bridge-nm.exe status --scope all
```

必要に応じてウィンドウ A（管理者権限）でも `--scope machine` を検証できます。
既存のマシン全体登録がある環境では、先に `HKLM` の該当キー（64 ビットビューと 32 ビットビューの双方）および `C:\ProgramData\LocalEDR\native-messaging` を `$runDir\backup` へ退避してから `setup` を実行してください。

```powershell
# ウィンドウ A（管理者 PowerShell）
cd e:\Documents\code\LocalEDR
$runDir = (Get-ChildItem C:\Temp -Directory -Filter "ledr-p4-e2e-*" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$hklmBackups = @(
    @{ Key = "HKLM\Software\Google\Chrome\NativeMessagingHosts\com.localedr.bridge"; File = "hklm_chrome_nmh_64.reg"; View = "/reg:64" },
    @{ Key = "HKLM\Software\Google\Chrome\NativeMessagingHosts\com.localedr.bridge"; File = "hklm_chrome_nmh_32.reg"; View = "/reg:32" },
    @{ Key = "HKLM\Software\Microsoft\Edge\NativeMessagingHosts\com.localedr.bridge"; File = "hklm_edge_nmh_64.reg"; View = "/reg:64" },
    @{ Key = "HKLM\Software\Microsoft\Edge\NativeMessagingHosts\com.localedr.bridge"; File = "hklm_edge_nmh_32.reg"; View = "/reg:32" },
    @{ Key = "HKLM\Software\Classes\ledr"; File = "hklm_ledr_uri.reg"; View = "/reg:64" }
)
foreach ($item in $hklmBackups) {
    reg query $item.Key $item.View *> $null
    if ($LASTEXITCODE -eq 0) {
        reg export $item.Key (Join-Path "$runDir\backup" $item.File) /y $item.View | Out-Null
    }
}
if (Test-Path "C:\ProgramData\LocalEDR\native-messaging") {
    Copy-Item -Recurse -Force "C:\ProgramData\LocalEDR\native-messaging" "$runDir\backup\machine-native-messaging"
}
.\target\debug\ledr-bridge-nm.exe setup --scope machine --browsers chrome,edge --bridge-exe "$PWD\target\debug\ledr-bridge-nm.exe" --ui-exe "$PWD\target\debug\ledr-ui.exe"
.\target\debug\ledr-bridge-nm.exe status --scope all
```

ウィンドウ A で `ledr-daemon.exe` を検証用設定で起動し、続けてウィンドウ B で `ledr-ui.exe` を開いて `View 3: 防御ポリシー・カナリア・ブラウザシールド` を確認してください。
起動前にウィンドウ A の `$runDir` へ同じ一時フォルダパスを設定します。

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

`ledr-ui` はタブを切り替えただけでは既取得データを再描画するため、各ブラウザ操作および `E2E-P4-06` の実行ファイル起動を終えたら、毎回 `ledr-ui` 上部バーの `Refresh` ボタンを押して最新のアラートとフライトレコーダー履歴を再取得してください。
以下の順でローカル検証ページを操作し、ブラウザ内警告と `ledr-ui` 側の記録を確かめます。

| ID | 対象URLと操作 | 期待結果 |
| :--- | :--- | :--- |
| `E2E-P4-01` | `http://clickfix-sim.localedr.invalid:8765/phase4-browser-test.html` で `Copy Verification Command` を押下し、`ledr-ui` で `Refresh` を押下 | ブラウザ内 Shadow DOM に ClickFix 警告が表示され、`ledr-ui` View 1 に `LAYER_4_BROWSER`（`ClickFixPastejacking`）が記録され、`Acknowledge` のみ有効で解決できる |
| `E2E-P4-02` | 同ページの領域 2（`echo hello-localedr`）を選択して `Ctrl+C` し、`ledr-ui` で `Refresh` を押下 | ブラウザ内に Pastejacking 警告が表示され、領域 3（`Copy Snippet` と通常選択コピー）では警告が発火しない |
| `E2E-P4-03` | `http://nrd-sim.localedr.invalid:8765/phase4-browser-test.html` の `Password` 欄へフォーカスして 1 文字入力し、`ledr-ui` で `Refresh` を押下 | ブラウザ内に NRD 警告が表示され、View 1 に `NrdPasswordWarning` が記録される |
| `E2E-P4-04` | `http://login-paypa1.localedr.invalid:8765/phase4-browser-test.html` の `Password` 欄へフォーカスして 1 文字入力し、`ledr-ui` で `Refresh` を押下 | ブラウザ内にホモグラフ警告（対象ブランド `paypal`）が表示され、View 1 に `HomographWarning` が記録される |
| `E2E-P4-05` | `Fetch safe-sim.localedr.invalid` と `Fetch c2-sim.localedr.invalid` を順に押下し、`ledr-ui` で `Refresh` を押下 | `safe-sim` は `HTTP 200` で成功し、`c2-sim` と `blocked-test` は DNR 静的ルールで即座に遮断され、`DnrBlockedRequest` が記録される |
| `E2E-P4-06` | `Download localedr-e2e-sample.exe` でダウンロード後、下記コマンドで `$runDir\moved\localedr-e2e-sample.exe` へ移動して `--scenario cookies-open` を実行し、`ledr-ui` で `Refresh` を押下 | View 1 に `localedr-e2e-sample.exe` の `LEDR-CANARY-COOKIE_DB` アラートと MOTW カード（`Origin URL`、`Source`、一致ダウンロード行）が表示され、`Allow Once` で再開できる。View 2 のプロセスツリーに `MOTW` バッジと `Origin URL (MOTW)`、選択時の `download_origins` 行（`referrer_url` と短縮 `sha256`）が表示され、View 3 の `Tracked Downloads` が増加する |
| `E2E-P4-07` | View 1 の未解決 `LAYER_4_BROWSER` アラートを `Acknowledge` で解決後、`ledr-ui` ウィンドウを閉じる | View 1 で解決状態へ遷移し、ウィンドウ閉鎖後に `ledr-ui` と WebView2 の残留プロセスが 0 件になる |

`E2E-P4-06` では、ダウンロード直後の移動とダミーカナリア起動をウィンドウ B で実行してください。
`localedr-e2e-sample.exe` は検知直後に凍結されるため、`Start-Process -PassThru` で別プロセスとして起動し、View 1 と View 2 の確認後に `Allow Once` で再開します。

```powershell
# ウィンドウ B（通常ユーザー PowerShell）: E2E-P4-06 移動後起動（View 1 MOTW カードと View 2 の双方を検証）
New-Item -ItemType Directory -Force -Path "$runDir\moved" | Out-Null
Move-Item "$env:USERPROFILE\Downloads\localedr-e2e-sample.exe" "$runDir\moved\localedr-e2e-sample.exe" -Force
$simMotw = Start-Process -FilePath "$runDir\moved\localedr-e2e-sample.exe" -ArgumentList "--scenario", "cookies-open", "--base-dir", "$runDir\canary_dir", "--hold-ms", "120000", "--json" -PassThru
```

## 手順 4 終了確認と性能計測

`ledr-ui` ウィンドウを閉じた直後に、ウィンドウ B で UI 本体と WebView2 子プロセスの残留ゼロ（`L-08`）を確かめてください。

```powershell
Get-Process ledr-ui -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" | Where-Object { $_.CommandLine -match 'ledr-ui|LocalEDR' } | Select-Object ProcessId, CommandLine
```

両方のコマンドで出力が 0 件であれば `L-08` は合格である。

続いて `ledr-daemon` の常駐メモリと CPU 使用率を計測する。
`Get-Process` の `CPU` は起動後の累積 CPU 秒であり、`WorkingSet64` も取得時点の単発値になるため、[phase2-3-e2e-runbook.md](phase2-3-e2e-runbook.md) と同じく `--release` ビルドを用いて測定区間の CPU 差分とピーク Working Set を取得してください。
まずウィンドウ A でデバッグ版 `ledr-daemon.exe` を `Ctrl+C` で終了し、リリースビルドを作成してリリース版 `ledr-daemon.exe` を起動します。

```powershell
# ウィンドウ A（管理者 PowerShell）: デバッグ版停止後にリリース版で起動
cd e:\Documents\code\LocalEDR
cargo build --workspace --release --locked
$nrdUrl = ([Uri]"$runDir\nrd-test-feed.txt").AbsoluteUri
.\target\release\ledr-daemon.exe --foreground --dev-bypass-auth --db "$runDir\ledr.db" --nrd-feed-url $nrdUrl --nrd-cache "$runDir\nrd-cache.txt"
```

ウィンドウ A のログに初期化完了と NRD キャッシュ読み込みが出力されたら、ウィンドウ B で次の計測スクリプトを実行してください。
10 分間アイドル基準の計測では `$sampleSec = 600`（簡易確認では `60`）を使用できます。

```powershell
# ウィンドウ B（通常ユーザー PowerShell）: 測定区間の CPU 差分とピーク Working Set 計測
$sampleSec = 600
$logicalCores = [int]$env:NUMBER_OF_PROCESSORS
$p0 = Get-Process ledr-daemon
$cpu0 = $p0.CPU
$wsMax = $p0.WorkingSet64
1..$sampleSec | ForEach-Object {
    Start-Sleep -Seconds 1
    $cur = Get-Process ledr-daemon -ErrorAction SilentlyContinue
    if ($cur -and $cur.WorkingSet64 -gt $wsMax) { $wsMax = $cur.WorkingSet64 }
}
$p1 = Get-Process ledr-daemon
$cpuPct = (($p1.CPU - $cpu0) / ($sampleSec * $logicalCores)) * 100.0
[PSCustomObject]@{
    SampleSeconds = $sampleSec
    LatestWorkingSetMB = [math]::Round($p1.WorkingSet64 / 1MB, 2)
    PeakWorkingSetMB = [math]::Round($wsMax / 1MB, 2)
    AvgCpuPercent = [math]::Round($cpuPct, 4)
} | Format-Table -AutoSize
```

- `ledr-ui` が 0 件であり、LocalEDR 由来の `msedgewebview2.exe` が残っていないこと（`L-08`）。
- 10 分間のアイドル計測（`--release`）で `PeakWorkingSetMB` が `20.0` 以下、`AvgCpuPercent` が `0.5` 未満であること。

## 後片付け

管理者権限で起動した `--dev-bypass-auth` 付き `ledr-daemon.exe` を残したままにすると、パイプへ接続できる対話ユーザーのプロセスがクライアント認証なしで防御ルールを変更できる状態が続く。
そのため後片付けの先頭で必ず `ledr-daemon.exe` を停止し、残存プロセスが 0 件であることを確認してください。

```powershell
# 1. ウィンドウ A（管理者 PowerShell）で Ctrl+C により ledr-daemon.exe を正常終了する
#    終了しない場合のみ、以下のフォールバックで強制終了して 0 件を確認する
Get-Process ledr-daemon, ledr-ui, localedr-e2e-sample -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process ledr-daemon -ErrorAction SilentlyContinue
```

`ledr-daemon` が 0 件であることを確認できたら、ローカル HTTP サーバと検証用登録を片付けてください。
手順 1 で既存設定を `$runDir\backup` へ退避していた場合は、一時フォルダを削除する前に `reg import` とマニフェスト書き戻しで元の登録を復元します。

```powershell
# 2. ウィンドウ B（通常ユーザー PowerShell）: ローカルサーバ停止、登録解除、既存設定復元
if ($serverProc -and -not $serverProc.HasExited) { Stop-Process -Id $serverProc.Id -Force }
if ($simMotw -and -not $simMotw.HasExited) { Stop-Process -Id $simMotw.Id -Force -ErrorAction SilentlyContinue }
.\target\debug\ledr-bridge-nm.exe unregister --scope user --browsers chrome,edge

# 手順 1 で既存 HKCU 設定を退避した場合のみ復元する
Get-ChildItem "$runDir\backup\hkcu_*.reg" -ErrorAction SilentlyContinue | ForEach-Object {
    reg import $_.FullName | Out-Null
}
if (Test-Path "$runDir\backup\user-native-messaging") {
    $userManifestDir = Join-Path $env:LOCALAPPDATA "LocalEDR\native-messaging"
    New-Item -ItemType Directory -Force -Path $userManifestDir | Out-Null
    Copy-Item -Recurse -Force "$runDir\backup\user-native-messaging\*" $userManifestDir
}
```

管理者ウィンドウ A で `--scope machine` を登録していた場合は、ウィンドウ A で解除と退避復元を実行してください。

```powershell
# 3. ウィンドウ A（管理者 PowerShell）: --scope machine を登録した場合のみ実施
.\target\debug\ledr-bridge-nm.exe unregister --scope machine --browsers chrome,edge
Get-ChildItem "$runDir\backup\hklm_*_64.reg" -ErrorAction SilentlyContinue | ForEach-Object {
    reg import $_.FullName /reg:64 | Out-Null
}
Get-ChildItem "$runDir\backup\hklm_*_32.reg" -ErrorAction SilentlyContinue | ForEach-Object {
    reg import $_.FullName /reg:32 | Out-Null
}
if (Test-Path "$runDir\backup\hklm_ledr_uri.reg") {
    reg import "$runDir\backup\hklm_ledr_uri.reg" /reg:64 | Out-Null
}
if (Test-Path "$runDir\backup\machine-native-messaging") {
    New-Item -ItemType Directory -Force -Path "C:\ProgramData\LocalEDR\native-messaging" | Out-Null
    Copy-Item -Recurse -Force "$runDir\backup\machine-native-messaging\*" "C:\ProgramData\LocalEDR\native-messaging"
}
```

最後に、復元結果に問題がないことを `.\target\debug\ledr-bridge-nm.exe status --scope all` で確認したうえで一時フォルダを削除してください。

```powershell
# 4. ウィンドウ B（通常ユーザー PowerShell）
.\target\debug\ledr-bridge-nm.exe status --scope all
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
