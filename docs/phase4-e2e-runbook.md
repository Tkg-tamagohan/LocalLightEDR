# Phase 4 実機 Chrome E2E 検証手順書

> [!NOTE]
> Phase 1 から Phase 4 までを一気通貫で実施する場合、および最新の統合版手順（Track B と Track C）を参照する場合は [e2e-test-runbook.md](e2e-test-runbook.md) を使用してください。

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
- **ウィンドウ A（64 ビット版管理者 PowerShell）**：`ledr-daemon.exe` の起動と停止、`--scope machine` 検証用
- **ウィンドウ B（64 ビット版通常ユーザー PowerShell）**：既存設定の退避、`ledr-bridge-nm.exe setup`、ローカル HTTP サーバ起動、Chrome 起動、`ledr-ui.exe` 起動、後片付け用

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
# ウィンドウ B（64 ビット版通常ユーザー権限）: 既存の HKCU 登録とマニフェストを退避（未登録キーはスキップ）
if (-not [Environment]::Is64BitProcess) {
    throw "32 ビット版 PowerShell では System32 がリダイレクトされるため、64 ビット版 PowerShell で実行してください。"
}
$reg64 = "$env:SystemRoot\System32\reg.exe"
$hkcuBackups = @(
    @{ Key = "HKCU\Software\Google\Chrome\NativeMessagingHosts\com.localedr.bridge"; File = "hkcu_chrome_nmh.reg" },
    @{ Key = "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.localedr.bridge"; File = "hkcu_edge_nmh.reg" },
    @{ Key = "HKCU\Software\Classes\ledr"; File = "hkcu_ledr_uri.reg" },
    @{ Key = "HKCU\Software\Classes\AppUserModelId\LocalEDR.AlertUI"; File = "hkcu_aumid.reg" }
)
foreach ($item in $hkcuBackups) {
    & $reg64 query $item.Key *> $null
    if ($LASTEXITCODE -eq 0) {
        $outFile = Join-Path "$runDir\backup" $item.File
        & $reg64 export $item.Key $outFile /y | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $outFile) -or (Get-Item $outFile).Length -eq 0) {
            throw "HKCU レジストリ退避に失敗したため setup を中止します: $($item.Key)"
        }
    }
}
$userManifestDir = Join-Path $env:LOCALAPPDATA "LocalEDR\native-messaging"
if (Test-Path $userManifestDir) {
    Copy-Item -Recurse -Force -ErrorAction Stop $userManifestDir "$runDir\backup\user-native-messaging"
}
```

退避が完了したら、ウィンドウ B（通常ユーザー権限）でユーザー単位の登録（`HKCU`）を実行し、`status` と `ledr-ui` View 3 の表示を確かめてください。

```powershell
cd e:\Documents\code\LocalEDR
.\target\debug\ledr-bridge-nm.exe setup --scope user --browsers chrome,edge --bridge-exe "$PWD\target\debug\ledr-bridge-nm.exe" --ui-exe "$PWD\target\debug\ledr-ui.exe"
.\target\debug\ledr-bridge-nm.exe status --scope all
```

必要に応じてウィンドウ A（管理者権限）でも `--scope machine` を検証できます。
既存のマシン全体登録がある環境では、通常ユーザーが書き込めない管理者専用の退避フォルダ（`Administrators` と `SYSTEM` のみ許可）を作成したうえで、64 ビット版 `reg.exe` と 32 ビット版 `SysWOW64\reg.exe` で `HKLM` の該当キー（`Chrome`、`Edge` の 64/32 ビット双方、`ledr` URI、および `AppUserModelId\LocalEDR.AlertUI`）と `C:\ProgramData\LocalEDR\native-messaging` を退避し、全退避の成功を確認してから `setup` を実行してください。
マシン単位で URI と AUMID を検証しない場合は、`setup` に `--skip-uri`、後片付けの `unregister` に `--keep-uri` を指定すると両キーを変更せずに検証できます。

```powershell
# ウィンドウ A（64 ビット版管理者 PowerShell）: 管理者専用の退避先へ HKLM とマシンマニフェストを退避
if (-not [Environment]::Is64BitProcess) {
    throw "32 ビット版 PowerShell では System32 がリダイレクトされ 64 ビットビューを退避できないため、64 ビット版 PowerShell で実行してください。"
}
cd e:\Documents\code\LocalEDR
$reg64 = "$env:SystemRoot\System32\reg.exe"
$reg32 = "$env:SystemRoot\SysWOW64\reg.exe"
$adminBackupDir = Join-Path $env:ProgramData ("LocalEDR-e2e-admin-backup-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $adminBackupDir -ErrorAction Stop | Out-Null
$backupItem = Get-Item -LiteralPath $adminBackupDir -Force
if (-not $backupItem.PSIsContainer -or ($backupItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "管理者専用退避フォルダがリパースポイントのため中止します: $adminBackupDir"
}
$ownerSid = (Get-Acl -LiteralPath $adminBackupDir).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($ownerSid -notin @("S-1-5-32-544", "S-1-5-18")) {
    throw "管理者専用退避フォルダの所有者が Administrators または SYSTEM ではないため中止します: $adminBackupDir (Owner=$ownerSid)"
}
icacls $adminBackupDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-18:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "管理者専用退避フォルダの ACL 設定に失敗したため中止します: $adminBackupDir"
}
$hklmBackups = @(
    @{ Key = "HKLM\Software\Google\Chrome\NativeMessagingHosts\com.localedr.bridge"; File = "hklm_chrome_nmh_64.reg"; RegExe = $reg64 },
    @{ Key = "HKLM\Software\Google\Chrome\NativeMessagingHosts\com.localedr.bridge"; File = "hklm_chrome_nmh_32.reg"; RegExe = $reg32 },
    @{ Key = "HKLM\Software\Microsoft\Edge\NativeMessagingHosts\com.localedr.bridge"; File = "hklm_edge_nmh_64.reg"; RegExe = $reg64 },
    @{ Key = "HKLM\Software\Microsoft\Edge\NativeMessagingHosts\com.localedr.bridge"; File = "hklm_edge_nmh_32.reg"; RegExe = $reg32 },
    @{ Key = "HKLM\Software\Classes\ledr"; File = "hklm_ledr_uri_64.reg"; RegExe = $reg64 },
    @{ Key = "HKLM\Software\Classes\AppUserModelId\LocalEDR.AlertUI"; File = "hklm_aumid_64.reg"; RegExe = $reg64 }
)
foreach ($item in $hklmBackups) {
    & $item.RegExe query $item.Key *> $null
    if ($LASTEXITCODE -eq 0) {
        $outFile = Join-Path $adminBackupDir $item.File
        & $item.RegExe export $item.Key $outFile /y | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $outFile) -or (Get-Item $outFile).Length -eq 0) {
            throw "HKLM レジストリ退避に失敗したため setup を中止します: $($item.Key) ($($item.RegExe))"
        }
    }
}
if (Test-Path "C:\ProgramData\LocalEDR\native-messaging") {
    Copy-Item -Recurse -Force -ErrorAction Stop "C:\ProgramData\LocalEDR\native-messaging" "$adminBackupDir\machine-native-messaging"
}
Write-Output ("AdminBackupDir=" + $adminBackupDir)
.\target\debug\ledr-bridge-nm.exe setup --scope machine --browsers chrome,edge --bridge-exe "$PWD\target\debug\ledr-bridge-nm.exe" --ui-exe "$PWD\target\debug\ledr-ui.exe"
.\target\debug\ledr-bridge-nm.exe status --scope all
```

ウィンドウ A で `ledr-daemon.exe` を検証用設定で起動し、続けてウィンドウ B で `ledr-ui.exe` を開いて `View 3: 防御ポリシー・カナリア・ブラウザシールド` を確認してください。
起動前に、ウィンドウ B で出力された `RunDir=...` のパスをウィンドウ A の `$runDir` へ明示的に設定します。

```powershell
# ウィンドウ A（管理者 PowerShell）
$runDir = "<ウィンドウ B で表示された RunDir の絶対パス>"
$nrdUrl = ([Uri]"$runDir\nrd-test-feed.txt").AbsoluteUri
.\target\debug\ledr-daemon.exe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --db "$runDir\ledr.db" --nrd-feed-url $nrdUrl --nrd-cache "$runDir\nrd-cache.txt"
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
$serverProc = Start-Process -FilePath python -ArgumentList @("`"$servePath`"", "`"$runDir\site`"") -PassThru -WindowStyle Minimized

$chromeCandidates = @(
    "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "${env:LOCALAPPDATA}\Google\Chrome\Application\chrome.exe"
)
$chromeExe = $chromeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $chromeExe) {
    throw "chrome.exe が見つかりません（Program Files / Program Files (x86) / LOCALAPPDATA を確認してください）。"
}
& $chromeExe `
  --user-data-dir="$runDir\chrome-profile" `
  --host-resolver-rules="MAP *.localedr.invalid 127.0.0.1" `
  --unsafely-treat-insecure-origin-as-secure="http://clickfix-sim.localedr.invalid:8765,http://pastejack-sim.localedr.invalid:8765,http://nrd-sim.localedr.invalid:8765,http://login-paypa1.localedr.invalid:8765,http://safe-sim.localedr.invalid:8765,http://c2-sim.localedr.invalid:8765,http://blocked-test.localedr.invalid:8765" `
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
| `E2E-P4-02` | `http://pastejack-sim.localedr.invalid:8765/phase4-browser-test.html` の領域 2（`echo hello-localedr`）を選択して `Ctrl+C` し、`ledr-ui` で `Refresh` を押下 | ブラウザ内に Pastejacking 警告が表示され（30 秒重複抑止を避け View 1 に記録され）、領域 3（`Copy Snippet` と通常選択コピー）では警告が発火しない |
| `E2E-P4-03` | `http://nrd-sim.localedr.invalid:8765/phase4-browser-test.html` の `Password` 欄へフォーカスして 1 文字入力し、`ledr-ui` で `Refresh` を押下 | ブラウザ内に NRD 警告が表示され、View 1 に `NrdPasswordWarning` が記録される |
| `E2E-P4-04` | `http://login-paypa1.localedr.invalid:8765/phase4-browser-test.html` の `Password` 欄へフォーカスして 1 文字入力し、`ledr-ui` で `Refresh` を押下 | ブラウザ内にホモグラフ警告（対象ブランド `paypal`）が表示され、View 1 に `HomographWarning` が記録される |
| `E2E-P4-05` | `Fetch safe-sim.localedr.invalid` と `Fetch c2-sim.localedr.invalid` を順に押下し、`ledr-ui` で `Refresh` を押下 | `safe-sim` は `HTTP 200` で成功し、`c2-sim` と `blocked-test` は DNR 静的ルールで即座に遮断され、`DnrBlockedRequest` が記録される |
| `E2E-P4-06` | `Download localedr-e2e-sample.exe` でダウンロード完了後、まず `ledr-ui` で `Refresh` を押下し、View 2（`Canary & Downloads` タブ・`Scope: All Processes`）に元パスと SHA-256 が記録されたことを確認してから、下記コマンドで高リスクパス外の排他ディレクトリ（`%LOCALAPPDATA%\LocalEDR-e2e-moved-<GUID>`）へ移動して `dns-tcp --hold-ms 30000` と `cookies-open` を実行し、再度 `ledr-ui` で `Refresh` を押下 | 移動前に View 2 の `Canary & Downloads` タブへ元パスと短縮 `sha256` が記録され、View 3 の `Tracked Downloads` 件数が増加している。移動後の起動により View 1 に `localedr-e2e-sample.exe` の `LEDR-NET-HIGH-RISK-PATH`（事前 WFP 遮断、`L-18`）と `LEDR-CANARY-COOKIE_DB` アラートおよび MOTW カード（`Origin URL`、`Source`、一致ダウンロード行）が表示され、`Allow Once` で再開できる。View 2 のプロセスツリーに `MOTW` バッジと `Origin URL (MOTW)`、選択時の `download_origins` 行（`referrer_url` と短縮 `sha256`）が表示される |
| `E2E-P4-07` | View 1 の未解決 `LAYER_4_BROWSER` アラートを `Acknowledge` で解決後、`ledr-ui` ウィンドウを閉じる | View 1 で解決状態へ遷移し、ウィンドウ閉鎖後に `ledr-ui` と WebView2 の残留プロセスが 0 件になる |

`E2E-P4-06` では、拡張機能のダウンロード完了通知とデーモン側の SHA-256 算出が非同期で走るため、**移動コマンドを実行する前に** `ledr-ui` 上部の `Refresh` を押し、View 2 の `Canary & Downloads` タブ（`Scope: All Processes`）に `Downloads\localedr-e2e-sample.exe` と短縮 `sha256` が記録されたことを確かめてください（View 3 の `Tracked Downloads` は件数表示のみのため、パスと `sha256` の確認は必ず View 2 で行います）。
記録を確認してから、ウィンドウ B で高リスクパス（`Downloads` や `Temp`）外となる `%LOCALAPPDATA%` 配下の排他ディレクトリへ移動し、起動時事前 WFP ブロック（`L-18`）およびダミーカナリア起動を実行します。
`localedr-e2e-sample.exe` は検知直後に凍結されるため、`Start-Process -PassThru` で別プロセスとして起動し、再度 `Refresh` を押して View 1 と View 2 を確認したあとに `Allow Once` で再開し、確認後に `$simNet`、`$simMotw`、および `$movedDir` を片付けてください。

```powershell
# ウィンドウ B（通常ユーザー PowerShell）: View 2 の Canary & Downloads タブで元パスと SHA-256 の記録を確認した後に実行
$movedDir = Join-Path $env:LOCALAPPDATA ("LocalEDR-e2e-moved-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $movedDir -ErrorAction Stop | Out-Null
$movedExe = Join-Path $movedDir "localedr-e2e-sample.exe"
Move-Item -LiteralPath "$env:USERPROFILE\Downloads\localedr-e2e-sample.exe" -Destination $movedExe -Force
# L-18 確認: 高リスクパス外へ移動後でも MOTW による事前 WFP ブロックで外部 TCP が遮断され、View 1 に LEDR-NET-HIGH-RISK-PATH と MOTW カードが記録される
$simNet = Start-Process -FilePath $movedExe -ArgumentList "--scenario", "dns-tcp", "--domain", "93.184.216.34", "--port", "80", "--hold-ms", "30000", "--json" -PassThru
Start-Sleep -Seconds 3
# View 1 で LEDR-NET-HIGH-RISK-PATH と MOTW カードを確認したら $simNet を停止する
Stop-Process -Id $simNet.Id -Force -ErrorAction SilentlyContinue

$simMotw = Start-Process -FilePath $movedExe -ArgumentList "--scenario", "cookies-open", "--base-dir", "`"$runDir\canary_dir`"", "--hold-ms", "120000", "--json" -PassThru
```

`View 1` と `View 2` で `LEDR-CANARY-COOKIE_DB` と MOTW 紐付けを確認し、`Allow Once` で再開したら、残待機中の `$simMotw` と一時移動ディレクトリ `$movedDir` を削除してください。

```powershell
# ウィンドウ B（通常ユーザー PowerShell）: E2E-P4-06 確認後の片付け
if ($simMotw -and -not $simMotw.HasExited) { Stop-Process -Id $simMotw.Id -Force -ErrorAction SilentlyContinue }
if ($movedDir -and (Test-Path -LiteralPath $movedDir)) { Remove-Item -Recurse -Force -LiteralPath $movedDir -ErrorAction SilentlyContinue }
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
`SEC_0003` の兄弟パス検証により Debug 版 `ledr-bridge-nm.exe` が登録されている状態では Release 版 `ledr-daemon.exe` への IPC が拒否されるため、手順 3 の Chrome 拡張操作をすべて終えて検証用 Chrome ウィンドウを閉じてから、ウィンドウ A でデバッグ版 `ledr-daemon.exe` を `Ctrl+C` で終了し、リリース版を起動します。

```powershell
# ウィンドウ A（管理者 PowerShell）: 検証用 Chrome 終了・デバッグ版停止後にリリース版で起動
cd e:\Documents\code\LocalEDR
cargo build --workspace --release --locked
$nrdUrl = ([Uri]"$runDir\nrd-test-feed.txt").AbsoluteUri
.\target\release\ledr-daemon.exe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --db "$runDir\ledr.db" --nrd-feed-url $nrdUrl --nrd-cache "$runDir\nrd-cache.txt"
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
# 2. ウィンドウ B（64 ビット版通常ユーザー PowerShell）: ローカルサーバ停止、登録解除、既存 HKCU 設定復元
if (-not [Environment]::Is64BitProcess) {
    throw "64 ビット版 PowerShell で実行してください。"
}
$reg64 = "$env:SystemRoot\System32\reg.exe"
if ($serverProc -and -not $serverProc.HasExited) { Stop-Process -Id $serverProc.Id -Force }
if ($simNet -and -not $simNet.HasExited) { Stop-Process -Id $simNet.Id -Force -ErrorAction SilentlyContinue }
if ($simMotw -and -not $simMotw.HasExited) { Stop-Process -Id $simMotw.Id -Force -ErrorAction SilentlyContinue }
if ($movedDir -and (Test-Path -LiteralPath $movedDir)) { Remove-Item -Recurse -Force -LiteralPath $movedDir -ErrorAction SilentlyContinue }
.\target\debug\ledr-bridge-nm.exe unregister --scope user --browsers chrome,edge

# 手順 1 で既存 HKCU 設定を退避した場合のみ復元し、失敗時は退避ファイルを消さずに停止する
Get-ChildItem "$runDir\backup\hkcu_*.reg" -ErrorAction SilentlyContinue | ForEach-Object {
    & $reg64 import $_.FullName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "HKCU レジストリ復元に失敗したため退避フォルダを削除せず中止します: $($_.FullName)"
    }
}
if (Test-Path "$runDir\backup\user-native-messaging") {
    $userManifestDir = Join-Path $env:LOCALAPPDATA "LocalEDR\native-messaging"
    New-Item -ItemType Directory -Force -Path $userManifestDir | Out-Null
    Copy-Item -Recurse -Force -ErrorAction Stop "$runDir\backup\user-native-messaging\*" $userManifestDir
}
```

管理者ウィンドウ A で `--scope machine` を登録していた場合は、ウィンドウ A で解除と管理者専用退避フォルダ（`$adminBackupDir`）からの復元を実行し、すべての復元成功を確認してから `$adminBackupDir` を削除してください。

```powershell
# 3. ウィンドウ A（64 ビット版管理者 PowerShell）: --scope machine を登録した場合のみ実施
if (-not [Environment]::Is64BitProcess) {
    throw "32 ビット版 PowerShell では 64 ビットビューを復元できないため、64 ビット版 PowerShell で実行してください。"
}
$reg64 = "$env:SystemRoot\System32\reg.exe"
$reg32 = "$env:SystemRoot\SysWOW64\reg.exe"
.\target\debug\ledr-bridge-nm.exe unregister --scope machine --browsers chrome,edge
if ($adminBackupDir -and (Test-Path $adminBackupDir)) {
    if ((Get-Item $adminBackupDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "管理者専用退避フォルダがリパースポイントのため復元を中止します: $adminBackupDir"
    }
    Get-ChildItem "$adminBackupDir\hklm_*_64.reg" -ErrorAction SilentlyContinue | ForEach-Object {
        & $reg64 import $_.FullName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "HKLM 64 ビットビューの復元に失敗したため退避フォルダを保持します: $($_.FullName)"
        }
    }
    Get-ChildItem "$adminBackupDir\hklm_*_32.reg" -ErrorAction SilentlyContinue | ForEach-Object {
        & $reg32 import $_.FullName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "HKLM 32 ビットビューの復元に失敗したため退避フォルダを保持します: $($_.FullName)"
        }
    }
    if (Test-Path "$adminBackupDir\machine-native-messaging") {
        New-Item -ItemType Directory -Force -Path "C:\ProgramData\LocalEDR\native-messaging" | Out-Null
        Copy-Item -Recurse -Force -ErrorAction Stop "$adminBackupDir\machine-native-messaging\*" "C:\ProgramData\LocalEDR\native-messaging"
    }
    .\target\debug\ledr-bridge-nm.exe status --scope all
    Remove-Item -Recurse -Force $adminBackupDir
}
```

最後に、復元結果に問題がないことを `.\target\debug\ledr-bridge-nm.exe status --scope all` で確認したうえで一時フォルダを削除してください。

```powershell
# 4. ウィンドウ B（通常ユーザー PowerShell）: 全復元成功を確認したうえで削除
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
