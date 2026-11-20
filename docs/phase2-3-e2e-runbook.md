# LocalEDR Phase 2 と Phase 3 実機 E2E 検証手順書

この手順書は、[follow-up-notes.md](follow-up-notes.md) の `FU-E2E-01` および [implementation-plan.md](implementation-plan.md) に基づき、Phase 2 と Phase 3 の実機受け入れ項目を Windows 10 または Windows 11（x86_64）クライアント SKU の管理者環境で検証するための手順をまとめたものである。

現在の作業ブランチ（`fix/e2e-blockers`、`main` `cbbb8c0` ベース）では、非管理者セッションで完結するビルド、Clippy 静的検査（警告 0 件）、ワークスペース自動テスト（`e2e_blockers` 回帰テスト、`burst_budget` 11/11、および `ttl_purge_lineage` 9/9 を含む）が通過している。
したがって、ここでは管理者権限または対話デスクトップ環境が必要なカーネル境界（実 ETW、実 `NtSuspendProcess` とツリー終了、実 BFE 動的 WFP フィルタと `FwpmNetEventSubscribe1`）、WinRT トースト通知と `ledr://` URI 起動、応答しない実 UNC 共有での NRD 更新と 3 秒停止予算、WebView2 上の対話操作、および常駐リソース計測を対象とする。

## 作業分担表

本手順はユーザーによる手動実行（管理者 PowerShell と通常デスクトップ上の `ledr-ui`）を主軸とする。
もし管理者権限で起動した Antigravity セッションへ一部を委任する場合は、CLI 実行と WFP、ETW、NRD、およびリソース計測の自動記録までをエージェント側で実行し、実 WebView2 ウィンドウ上のクリック操作と WinRT トースト通知の目視確認をユーザー側で補完できる。

| 担当 | 作業項目 | 実施状態 |
| :--- | :--- | :--- |
| エージェント | `fix/e2e-blockers` でのビルド（`ledr-daemon.exe`、`ledr-ui.exe`、`ledr-sim.exe`） | 完了済み |
| エージェント | `cargo clippy`（警告 0 件）、ワークスペース自動テスト、`burst_budget`（11/11）、`ttl_purge_lineage`（9/9）の確認 | 完了済み |
| エージェント | 実機の OS バージョンと SKU（`Microsoft Windows 11 Home`、`10.0.26300`、`ProductType=1`）および `BFE` 稼働状態の確認 | 完了済み |
| ユーザー（通常） | `ledr-ui.exe --register-uri` による `HKCU` プロトコル・AUMID 登録、`ToastEnabled` 確認、WebView2 上での View 1 から View 3 までの対話操作、通知クリック確認 | 本手順書で実施 |
| ユーザー（管理者） | Phase 2 実機検証（読み取り非発火、`Cookies` 凍結、おとりツリー凍結と一括終了、60 秒 `EXPIRED_SUSPENDED`、Never-Suspend、`Kernel-Registry` と `CloseKey`） | 本手順書で実施 |
| ユーザー（管理者） | Phase 3 実機検証（WFP 動的セッション、事前制限、`FwpmNetEventSubscribe1` と曖昧 PID、`ledr-sim` 相関、ドメイン許可と Deny 優先、NRD と 3 秒 WAL チェックポイント、`taskkill /F` 消去） | 本手順書で実施 |
| ユーザー（通常および管理者） | `ledr-ui` 閉鎖時のプロセス 0 件確認、`ledr-daemon` の常駐メモリと CPU 計測、後片付けと結果報告 | 本手順書で実施 |

## 実機仕様との差分と安全前提

作業を始める前に、現行コードの実装状況に基づく次の 4 点を確認してください。

1. **Windows Service の SCM エントリポイントは未実装である**：現行の [main.rs](../crates/ledr-daemon/src/main.rs) は `#[tokio::main]` のコンソールプロセス（`Ctrl+C` 待機）であり、`StartServiceCtrlDispatcherW` による Windows Service 制御ディスパッチを備えていない。
   そのため、`sc.exe create` で登録してサービス起動するとタイムアウトエラー（エラー 1053）になる。
   標準手順では `--foreground` 起動時のフォールバック経路（`ledr-ui.exe --notify <alert_id>`）で WinRT トーストと `ledr://alert/<id>` 連携を確認し、Session 0 境界（`WTSQueryUserToken` と `CreateProcessAsUserW`）まで実機確認する場合だけ末尾の補足手順（`PsExec` 等による `LocalSystem` 実行）を用い、Windows Service 登録自体は未実装差異として記録する。
2. **操作中の管理者 PowerShell ウィンドウを凍結させない**：`powershell.exe` は事前 WFP ブロックの対象であり、かつ `is_never_suspend_process` の保護対象に含まれない。
   したがって、ウィンドウ B 自身から `Cookies` 読み取りや自動起動レジストリ書込を直接実行すると操作中のシェル自体が凍結するため、必ず `ledr-sim.exe` または `Start-Process` で別の子プロセスを起動して試験する。
3. **検証専用の認証迂回フラグと安全なアウトバウンド制御モードを使う**：開発ビルドの未署名 `target\debug\ledr-ui.exe` から Named Pipe IPC の状態変更コマンドを送信するため、`ledr-daemon.exe` へ `--dev-bypass-auth` を指定する。
   また、開発ホスト PC 上での実機検証では未知の常駐デスクトップアプリの誤凍結を防ぐため、`--outbound-mode preemptive-only --resume-suspended-on-shutdown` を併用する（`--foreground` 起動時は終了時復帰も既定で有効になる）。日常運用では `--dev-bypass-auth` を外すこと。
4. **Windows 通知設定（`ToastEnabled`）を確認する**：OS 側で通知がオフ（`ToastEnabled = 0`）の場合、`ledr-ui.exe --notify` は JSON に `"status":"suppressed_by_os_settings"` を返してバナーを出さない。目視でトーストを確認する前に、Windows の「設定 > システム > 通知」がオンであることを確かめる。

## 準備物の棚卸し

作業ディレクトリ `e:\Documents\code\LocalEDR` 配下に次のバイナリが揃っており、PowerShell ウィンドウ 3 つを開ける状態にしてください。

- **ビルド済みバイナリ**：`target\debug\ledr-daemon.exe`、`target\debug\ledr-ui.exe`、`target\debug\ledr-sim.exe`
- **検証用一時フォルダ**：`C:\Temp\ledr-e2e`（SQLite DB、NRD キャッシュ、ダミーカナリア、および `netsh wfp` 出力 XML の格納先）
- **ウィンドウ A（管理者 PowerShell）**：`ledr-daemon.exe` のフォアグラウンド起動とログ監視用
- **ウィンドウ B（管理者 PowerShell）**：`ledr-sim.exe` 実行、`netsh wfp` 確認、TCP 接続試験、および `taskkill` 用
- **ウィンドウ C（通常ユーザー PowerShell）**：`ledr-ui.exe` 起動、URI スキーム・AUMID 登録、およびプロセス数確認用

## Phase 2 実機検証の実施手順

### 1. 一時フォルダ準備と URI スキーム・AUMID 登録（ウィンドウ B とウィンドウ C）

はじめに、ウィンドウ C（通常ユーザー権限）で `ledr://` プロトコルハンドラと専用 AUMID（`LocalEDR.AlertUI`）を現在のユーザーへ登録し、登録状態および Windows 通知設定（`ToastEnabled`）を確認してください。

```powershell
cd e:\Documents\code\LocalEDR
.\target\debug\ledr-ui.exe --register-uri
Get-ItemProperty "HKCU:\Software\Classes\ledr\shell\open\command"
Get-ItemProperty "HKCU:\Software\Classes\AppUserModelId\LocalEDR.AlertUI"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name ToastEnabled -ErrorAction SilentlyContinue
.\target\debug\ledr-ui.exe --notify test-alert-001
```

標準出力に `"status":"registered"`（または既存一致時は `"already_registered"`）が表示され、`ledr` コマンド値に `e:\Documents\code\LocalEDR\target\debug\ledr-ui.exe`、`LocalEDR.AlertUI` の `DisplayName` に `LocalEDR` が登録されていれば準備は完了である。
`ToastEnabled` が `0` の場合、`--notify test-alert-001` は `"status":"suppressed_by_os_settings"` を返すため、実機トーストを目視確認する前に Windows の「設定 > システム > 通知」をオン（`ToastEnabled = 1` または値なし）にしてから再実行し、`"status":"dispatched"` と通知バナー表示を確認する。

次に、ウィンドウ B（管理者権限）で検証用一時フォルダと Phase 2 用のダミーカナリア群を作成してください。

```powershell
cd e:\Documents\code\LocalEDR
Get-Process ledr-daemon, ledr-ui, ledr-sim -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -Recurse -Force C:\Temp\ledr-e2e -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path C:\Temp\ledr-e2e\canary_dir | Out-Null
.\target\debug\ledr-sim.exe --prepare-dir C:\Temp\ledr-e2e\canary_dir --json
```

この時点で `C:\Temp\ledr-e2e\canary_dir` 配下にダミーの `Google\Chrome\User Data\Default\Cookies` と `!00_LocalEDR_Canary_DoNotEdit.docx` が排他作成される。
同じ `--prepare-dir` コマンドをもう一度実行し、既存ファイルの上書きに失敗して終了コードが非ゼロになることを確認すれば、`create_new(true)` による既存保護もあわせて検証できる（再試行時は後続テスト前に元のダミーファイルが残っていることを確かめる）。

### 2. デーモン起動と初期化ログの確認（ウィンドウ A）

Phase 2 と Phase 3 前半の検証では外部通信や NRD 取得のノイズを分離し、かつホスト PC 上の未知アプリ誤凍結を避けるため、`--outbound-mode preemptive-only --resume-suspended-on-shutdown --disable-nrd-refresh` を付けて起動します。
ウィンドウ A（管理者権限）で次を実行してください。

```powershell
cd e:\Documents\code\LocalEDR
$env:RUST_LOG = "info,ledr_sensor_win=debug,ledr_store=debug"
.\target\debug\ledr-daemon.exe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --disable-nrd-refresh --db C:\Temp\ledr-e2e\e2e.db
```

標準出力に次のログが順番に出力されれば、特権有効化、WFP 動的セッション、おとりファイル 3 箇所配置、リアルタイム ETW、および IPC サーバの初期化に成功している。

1. `privilege enablement completed`（`system_profile=true`、`debug=true`、`security=true`、`error=None`）
2. `initialized WFP dynamic session, LocalEDR SubLayer, and loopback Permit filters`
3. `redeployed persisted firewall rules at engine startup`（環境上の全対象に成功した場合は `applied > 0, failed = 0`）
4. `deployed honeypot canary files`（`honeypots=3`）
5. `WindowsEtwSensor real-time ETW trace started`
6. `initialized ActiveProcessTable, WFP firewall rules, and SQLite WAL store`
7. `ledr-daemon listening on Named Pipe IPC; press Ctrl+C to shut down`

また、別プロセス起動時に `ledr_sensor_win` の debug ログへ `received Microsoft-Windows-Kernel-Process ETW event` および `emitted ProcessStart from Kernel-Process ETW` が出力されることも確認する。

> [!NOTE]
> `redeployed persisted firewall rules at engine startup` で `applied=8, failed=2`、続く `initialized ActiveProcessTable, WFP firewall rules, and SQLite WAL store` で `wfp_applied=0, wfp_failed=2` のように `failed` が出る場合があります。
> これは 1 回目（エンジン起動時）で実体バイナリ 8 件が登録されて 2 件が失敗し、2 回目（`main` 側の再呼び出し時）で登録済み 8 件がスキップされて未登録の 2 件だけが再試行されるためです。
> 実機 `PATH` 上に Microsoft Store の `AppExecutionAlias`（`WindowsApps\python.exe` 等の 0 バイト `ReparsePoint` スタブ）が存在すると、`FwpmGetAppIdFromFileName0` が `0x00000780` を返して事前ブロック対象から外れるためであり、`powershell.exe` 等の実体インタプリタが適用済みであれば検証に支障はありません。

> [!WARNING]
> `WFP dynamic session could not be initialized` または `WindowsEtwSensor could not start` が出力された場合は、ウィンドウ A が管理者として起動されていない。
> `Ctrl+C` で終了し、管理者権限で PowerShell を開き直してください。

### 3. おとりファイルの読み取り非発火確認（ウィンドウ B）

ウィンドウ B で、ダミーおとりファイルに対する読み取り専用のアクセスを実行してください。

```powershell
$p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "type C:\Temp\ledr-e2e\canary_dir\!00_LocalEDR_Canary_DoNotEdit.docx >nul" -Wait -PassThru
Write-Output ("ReadOnlyExitCode=" + $p.ExitCode)
```

終了コードが `0` で戻り、ウィンドウ A のログおよびウィンドウ C で開く `ledr-ui.exe` の `View 1: アラートトリアージ` に `LEDR-CANARY-HONEYPOT` アラートが 1 件も出ていなければ、読み取り誤検知の抑止が機能している。

### 4. ダミー `Cookies` 読み取りによる単体凍結と通知クリック復帰（ウィンドウ B とウィンドウ C）

ウィンドウ B で `ledr-sim.exe` を別プロセスとして起動し、ダミー `Cookies` の Open と 120 秒間の待機を行わせてください。

```powershell
$simCookie = Start-Process -FilePath ".\target\debug\ledr-sim.exe" -WorkingDirectory "e:\Documents\code\LocalEDR" -ArgumentList "--scenario", "cookies-open", "--base-dir", "C:\Temp\ledr-e2e\canary_dir", "--hold-ms", "120000", "--json" -PassThru
Start-Sleep -Seconds 2
(Get-Process -Id $simCookie.Id).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
```

次の 4 点を順番に確認してください。

1. 1 秒以内に画面右下へ `[LocalEDR] [SUSPENDED] HIGH Browser Cookie Store Access: Cookies` を含む WinRT トースト通知が表示されること（PowerShell 経由の自己誤検知アラートが出ないことも確認）。
2. スレッド状態の出力で `ThreadState` が `Wait` かつ `WaitReason` が `Suspended`（全スレッド凍結）になっていること。
3. 表示された WinRT トースト通知（または `Triage Alert` ボタン）をクリックし、1,000 ms 以内に `ledr-ui.exe` が画面遷移なしで `View 1: アラートトリアージ` を開くこと（通知が閉じていた場合はウィンドウ C から `.\target\debug\ledr-ui.exe` を起動して確認する）。
4. 詳細表示の `Rule ID` が `LEDR-CANARY-COOKIE_DB`、`Access Mask` 横に `Read / Open` バッジ、`Signer` に `Unsigned` が表示されていることを確認したうえで、**`Allow Once`** ボタンを押す。

**`Allow Once`** を押してから 5 秒以内に、ウィンドウ B で `Get-Process -Id $simCookie.Id -ErrorAction SilentlyContinue` を実行すると、`ledr-sim.exe` が再開されて残りの待機後に終了（または再開状態 `WaitReason != Suspended` へ復帰）したことを確認できる。
待機が残っている場合は `Stop-Process -Id $simCookie.Id -Force` で終了させて構いません。

### 5. おとり書込によるツリー凍結と `Terminate & Block` 終了確認（ウィンドウ B と `ledr-ui`）

次に、子プロセス（`cmd.exe` と `ping.exe`）を伴った状態でダミーおとりファイルへ 1 バイト追記するシナリオを実行し、プロセスツリー全体の凍結と一括終了を確認してください。

```powershell
$simHp = Start-Process -FilePath ".\target\debug\ledr-sim.exe" -WorkingDirectory "e:\Documents\code\LocalEDR" -ArgumentList "--scenario", "honeypot-write", "--base-dir", "C:\Temp\ledr-e2e\canary_dir", "--hold-ms", "120000", "--json" -PassThru
Start-Sleep -Seconds 2
$children = Get-CimInstance Win32_Process -Filter ("ParentProcessId=" + $simHp.Id) | Select-Object ProcessId, Name, CommandLine
$children | Format-Table -AutoSize
(Get-Process -Id $simHp.Id).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
foreach ($c in $children) { (Get-Process -Id $c.ProcessId).Threads | Select-Object @{n='Pid';e={$c.ProcessId}}, Id, ThreadState, WaitReason | Format-Table -AutoSize }
```

親の `ledr-sim.exe` と子の `cmd.exe`（および配下の `ping.exe` が存在する場合）の双方が `WaitReason: Suspended` になっていることを確認してください。
続いて `ledr-ui` の `View 1: アラートトリアージ` を開き、`LEDR-CANARY-HONEYPOT`（重要度 `CRITICAL`、`Write / Delete` および `Tree Containment` バッジ表示）を選択します。
`Save NetworkBlock policy rule (WFP)` のチェックボックスは後続テストの妨げにならないようここでは**オフ**にしてから **`Terminate & Block`** ボタンを押し、5 秒以内にウィンドウ B で親と子の両方が 0 件へ終了することを確かめてください。

```powershell
Get-Process -Id $simHp.Id -ErrorAction SilentlyContinue
foreach ($c in $children) { Get-Process -Id $c.ProcessId -ErrorAction SilentlyContinue }
```

もしオンのまま終了した場合は、後続のネットワーク手順へ進む前に `View 3: 防御ポリシー・カナリア・ブラウザシールド` から `ledr-sim.exe` の `NetworkBlock` ルールを **`Delete`** で削除してください。

### 6. 60 秒未応答時の `EXPIRED_SUSPENDED` 遷移確認（ウィンドウ B と `ledr-ui`）

未応答のまま 60 秒が経過したときに、対象プロセスが自動再開されず凍結を保つことを確認します。
ウィンドウ B で次のコマンドを実行し、トースト通知をクリックせずに **65 秒以上** 待機してください。

```powershell
$simExp = Start-Process -FilePath ".\target\debug\ledr-sim.exe" -WorkingDirectory "e:\Documents\code\LocalEDR" -ArgumentList "--scenario", "cookies-open", "--base-dir", "C:\Temp\ledr-e2e\canary_dir", "--hold-ms", "180000", "--json" -PassThru
Start-Sleep -Seconds 68
(Get-Process -Id $simExp.Id).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
```

68 秒経過後も `ledr-sim.exe` の全スレッドが `WaitReason: Suspended` のままであり、`ledr-ui` の **`Refresh`** を押したあとに `View 1: アラートトリアージ` のバナーが `EXPIRED_SUSPENDED (60s)`（説明 `60s timeout elapsed — process remains frozen without data loss`）へ遷移していれば合格である。
確認後、`Save NetworkBlock policy rule (WFP)` をオフにした **`Terminate & Block`**（または `Allow Once`）で処理し、残っていれば `Stop-Process -Id $simExp.Id -Force` で終了してください。

### 7. Never-Suspend 安全ガードの確認（エクスプローラとダミーおとり）

エクスプローラ（`explorer.exe`）などの保護対象プロセスがカナリアに触れても一切凍結しないことを確認します。
ウィンドウ B からダミーフォルダをエクスプローラで開き、**実プロファイルではなくテスト用の** `C:\Temp\ledr-e2e\canary_dir\!00_LocalEDR_Canary_DoNotEdit.docx` を手動で右クリックして一時的に別名（例として `!00_LocalEDR_Canary_DoNotEdit_renamed.docx`）へ変更してください。

```powershell
explorer.exe C:\Temp\ledr-e2e\canary_dir
```

変更操作の直後、以下を確かめてください。

1. `explorer.exe` およびデスクトップ画面がフリーズせず、引き続き操作できること。
2. ウィンドウ A のログに `never-suspend guard skipped suspension on canary alert` が出力されること。
3. `ledr-ui` の `View 1` 上で、対象アラート（`LEDR-CANARY-HONEYPOT`）が `FROZEN` ではなく `PENDING`（非サスペンド）として記録されていること。

> [!CAUTION]
> `View 1` 上の `explorer.exe` アラートに対して **`Terminate & Block`** を実行しないでください。
> 安全ガードで保護されていますが、手順上は **`Allow Once`** でアラートを閉じるだけにしてください。

確認が終わったら、リネームしたファイルを元の名前 `!00_LocalEDR_Canary_DoNotEdit.docx` に戻すか削除してください。

### 8. ETW `Kernel-Registry` 自動起動キー監視と `CloseKey` 無効化確認（ウィンドウ B と `ledr-ui`）

ウィンドウ B から直接 `reg` を実行するのではなく、`Start-Process` 経由で `reg.exe` を起動し、`CurrentVersion\Run` への書き込み検知と凍結を確認してください。

```powershell
$regAdd = Start-Process -FilePath "reg.exe" -ArgumentList "add", "HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "LocalEdrE2eProbe", "/t", "REG_SZ", "/d", "`"cmd.exe /c echo ok`"", "/f" -PassThru
Start-Sleep -Seconds 2
Get-Process -Id $regAdd.Id -ErrorAction SilentlyContinue | Select-Object Id, ProcessName
(Get-Process -Id $regAdd.Id -ErrorAction SilentlyContinue).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
```

`reg.exe` は書き込み速度によってサスペンドより先に終了する場合もありますが、`ledr-ui` の **`Refresh`** 後に `View 1` へ `LEDR-CANARY-AUTORUN_REGISTRY`（`Autorun Persistence Modification: LocalEdrE2eProbe`）が記録されていれば ETW `Kernel-Registry` 監視が動作している（凍結中の場合は **`Allow Once`** で解放する）。

続けて、テスト登録したレジストリ値を削除して元へ戻し、直後に無関係な一時キーを作成、更新、および削除して `CloseKey` 後のハンドル再利用誤検知が起きないことを確かめてください。

```powershell
Start-Process -FilePath "reg.exe" -ArgumentList "delete", "HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "LocalEdrE2eProbe", "/f" -Wait
$tmpKey = "HKCU:\Software\LocalEdrE2eTmp"
New-Item -Path $tmpKey -Force | Out-Null
Set-ItemProperty -Path $tmpKey -Name "Probe" -Value "ok"
Remove-Item -Path $tmpKey -Force
```

一時キー `HKCU\Software\LocalEdrE2eTmp` の操作で `LEDR-CANARY-AUTORUN_REGISTRY` アラートが新規追加されなければ、`CloseKey`（イベント ID 13）とキャッシュ無効化に破綻がないことを確かめられる（先ほどの `reg.exe delete` 由来のアラートが残っていれば **`Allow Once`** で整理する）。

## Phase 3 実機検証の実施手順

### 1. BFE 内の動的 SubLayer と事前制限フィルタ確認（ウィンドウ B）

ウィンドウ A で `ledr-daemon.exe` が稼働中のまま、ウィンドウ B で BFE に登録されている WFP フィルタを XML 出力して確認してください。

```powershell
cd e:\Documents\code\LocalEDR
netsh wfp show filters file=C:\Temp\ledr-e2e\filters_active.xml
Select-String -Path C:\Temp\ledr-e2e\filters_active.xml -Pattern "LocalEDR" | Select-Object -First 20
```

出力に `LocalEDR Outbound SubLayer`、`LocalEDR Loopback Permit (v4)`、`LocalEDR Loopback Permit (v6)`、および標準スクリプトインタプリタ（`powershell.exe` や環境上の `python.exe`、`node.exe` 等）に対する `LocalEDR Block` フィルタが含まれていれば、事前制限が有効になっている。

### 2. ループバック維持とスクリプトインタプリタの外部遮断確認（ウィンドウ B）

事前制限の対象になっているウィンドウ B（`powershell.exe`）自身で、ローカル宛て接続が通ることと外部宛て接続だけが WFP で遮断されることを確認します。
はじめに `127.0.0.1` の待受ポートへ接続してください。

```powershell
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$client = [System.Net.Sockets.TcpClient]::new()
$client.Connect("127.0.0.1", $port)
Write-Output ("Loopback Connected: " + $client.Connected)
$client.Close()
$listener.Stop()
```

`Loopback Connected: True` と出力されれば、重み 15 のループバック許可フィルタが機能している。

次に、同じウィンドウ B から外部アドレス（`93.184.216.34` ポート `80`）へ TCP 接続を試みてください。

```powershell
$ext = [System.Net.Sockets.TcpClient]::new()
try {
    $ar = $ext.BeginConnect("93.184.216.34", 80, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(3000)) {
        $ext.EndConnect($ar)
        Write-Output "External connect succeeded"
    } else {
        Write-Output "Blocked or timed out as expected"
    }
} catch {
    Write-Output ("Blocked by WFP: " + $_.Exception.InnerException.Message)
} finally {
    $ext.Close()
}
```

接続がソケットアクセス権限エラー等（`Blocked by WFP: ...`）で拒否され、`ledr-ui`（**`Refresh`** 後）の `View 1` に `powershell.exe` の `LEDR-NET-SCRIPT-INTERPRETER` アラート（`Containment` に `WFP Blocked` バッジ）が生成されていれば、`FwpmNetEventSubscribe1` による実ドロップ捕捉が動作している。

あわせて複数インスタンス時の誤凍結防止を確認する場合は、2 つ目の管理者または通常 PowerShell（別 `powershell.exe`）を開いた状態で、別ポートまたは 250 ms 以上空けて外部接続を試し、`View 1` 上に `App-Level (Ambiguous PID)` バッジ付きのアラート（`process_suspended = false`）が生成され、どちらの PowerShell ウィンドウも凍結しないことを確認してください（確認後に 2 つ目の PowerShell は閉じる）。

### 3. 一般パスバイナリ（`ledr-sim.exe`）による DNS 相関と通信記録確認（ウィンドウ B と `ledr-ui`）

`e:\Documents\code\LocalEDR\target\debug\ledr-sim.exe` は `Downloads` や `Temp` 配下ではない一般パスの実行ファイルである。
ウィンドウ B で次の 2 本を実行し、LOTL 検知と初発 DNS 解決および外部接続の記録を確認してください。

```powershell
.\target\debug\ledr-sim.exe --scenario lotl --json
.\target\debug\ledr-sim.exe --scenario dns-tcp --domain example.com --port 80 --json
```

`ledr-ui` で **`Refresh`** を押し、`View 1: アラートトリアージ` と `View 2: プロセス系譜・通信フライトレコーダー` を開くと、以下を確認できる。

- `View 2` 上に `ledr-sim.exe` → `cmd.exe` → `powershell.exe -NoProfile -NonInteractive -EncodedCommand ...` の親子系譜と、`example.com` の `DnsQuery` および `NetworkConnect` タイムラインが表示される。
- `View 1` 上に `LEDR-LOTL-001` と `LEDR-NET-UNKNOWN-OUTBOUND`（または `example.com` 接続結果に応じた通知）が記録されている。

`ledr-sim.exe --scenario dns-tcp` は `--outbound-mode preemptive-only` 起動時は観測アラートのみを記録し凍結は行わない。
一般パス実行ファイルの初発外部通信による凍結まで実測したい場合は、検証用 VM 等で `--outbound-mode enforce` を指定し、`e:\Documents\code\LocalEDR` 配下など一般パスへ置いた長時間待機プログラムまたは再接続ループを用いること。

### 4. `ledr-ui` の View 1 と View 3 による許可登録と Deny 優先と削除の WFP 連動

ウィンドウ C（通常ユーザー権限）で `.\target\debug\ledr-ui.exe` を開き（起動済みなら **`Refresh`**）、画面上のタブを切り替えて次の順に操作してください。

1. **`View 1: アラートトリアージ`** で、手順 2 で発生した単一インスタンス側の `powershell.exe` アラート（`LEDR-NET-SCRIPT-INTERPRETER`）を選択する。
2. 右下の **`Allow Permanent Rule`** カードで `Target scope (optional)` に `93.184.216.34` を入力し、`Match Authenticode signer` がオンの状態で **`Allow Permanent Rule`** ボタンを押す。
3. ウィンドウ B へ戻って手順 2 の外部接続コマンド（`93.184.216.34` ポート `80`）を再実行し、`External connect succeeded` が出力されて通信が成功することを確認する。
4. `ledr-ui` の **`View 3: 防御ポリシー・カナリア・ブラウザシールド`** を開き、作成した `NetworkAllow` ルールが一覧に表示されていることを確認する。
5. あわせて View 3 右側の **`カナリア・おとり配置状態`**（`3/3 deployed` と 3 箇所のファイルサイズ）および `Tier 1 Protected Templates` の表示を確認する。
6. ドメイン指定と Deny 優先（`NetworkBlock > NetworkAllow`）を確認するため、View 3 の **`+ Add Rule`** を押して次を 2 件順に登録して検証してください。
   - **検証 A（ドメイン許可）**：`Scope` を `NetworkAllow (WFP Permit)`、`Executable Path *` に `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`、`Target IP / Domain / Path` に `example.com` を入力し、ウィンドウ B で `(Get-FileHash C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe).Hash.ToLowerInvariant()` を取得して `SHA-256` 欄へ貼り付けてから **`Save Rule`** を押す（または先の手順で作成した署名付き `NetworkAllow` ルールの `Signer Subject` と `Root Thumbprint` を指定してもよい）。
     ルール行に `IP-resolved` バッジが表示されることを確認したうえで、ウィンドウ B から `(Invoke-WebRequest -UseBasicParsing http://example.com -TimeoutSec 5).StatusCode`（または `Test-NetConnection example.com -Port 80`）が成功することを確かめる。
   - **検証 B（Deny 優先）**：続けて **`+ Add Rule`** で同一 `Executable Path *` と `Target IP / Domain / Path`（`example.com`）に対し `Scope` を `NetworkBlock (WFP Deny)` として **`Save Rule`** を押し、再びウィンドウ B から `example.com` ポート `80` へ接続したとき遮断へ戻ること（`NetworkBlock > NetworkAllow`）を確かめる。
7. 検証で使った `NetworkBlock` と `NetworkAllow` の各ルール行の **`Delete`** ボタンをすべて押し、削除後にウィンドウ B から `93.184.216.34` ポート `80` へ接続すると再び `Blocked by WFP: ...` へ戻ることを確認する。

### 5. ライブ NRD 取得と応答しない UNC 共有での 3 秒停止予算確認（ウィンドウ A とウィンドウ B）

まずウィンドウ A の `ledr-daemon.exe` を `Ctrl+C` で一旦停止し（未解決の凍結プロセスがあれば自動再開されることも確認）、NRD リフレッシュ有効状態での動作と、応答しない実 UNC 共有に対する停止タイムアウト保護（`FU-E2E-01` / `DAEMON-P3-45`）を順番に検証してください。

#### A. 実 WinHTTP NRD 取得と View 3 ドメイン診断（オンライン環境向け）

オンライン環境がある場合は、`--disable-nrd-refresh` を外して起動し、公開 NRD フィード取得と View 3 の診断フォームを確認します。

```powershell
$env:RUST_LOG = "info,ledr_sensor_win=debug,ledr_store=debug"
.\target\debug\ledr-daemon.exe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --db C:\Temp\ledr-e2e\e2e.db --nrd-cache C:\Temp\ledr-e2e\nrd-cache.txt
```

ウィンドウ A に `refreshed daily NRD domain cache`（`entries` や `feeds_succeeded=2`）が出たら、`ledr-ui` の `View 3` 右下にある `NRD / Homograph Check` 入力欄へ `paypa1.com`（期待結果 `Not in NRD` と `Homograph: paypal`）、`google.com`（期待結果 `Not in NRD` と `No Homograph`）、および `Get-Content C:\Temp\ledr-e2e\nrd-cache.txt -TotalCount 5` に出た実ドメイン 1 件（期待結果 `NRD (<=14d)`）を入力して **`Check`** を押し、期待どおりに判定されることを確認してください。
確認後はウィンドウ A で `Ctrl+C` を押して停止します。

#### B. 応答しない実 UNC 共有での 3 秒停止予算と WAL チェックポイント確認

期限内の `nrd-cache.txt` がない状態で到達不能な UNC 共有（例として `file://198.51.100.1/share/nrd.txt`、または実環境で SYN/SMB 応答を返さず I/O ブロックする未応答ホストの共有パス）を指定し、ウィンドウ A で起動してください。
なお、環境上のルータが `198.51.100.1` へ即座に ICMP Unreachable を返す場合は、応答を返さない実 LAN 内の未応答 IP または停止中ホストの UNC 共有へ差し替えてください。

```powershell
$env:RUST_LOG = "info,ledr_sensor_win=debug,ledr_store=debug"
.\target\debug\ledr-daemon.exe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --db C:\Temp\ledr-e2e\nrd_hang.db --nrd-cache C:\Temp\ledr-e2e\nrd-hang-cache.txt --nrd-feed-url file://198.51.100.1/share/nrd.txt
```

次の手順で 3 秒停止予算と WAL トランケート先行完了を確認してください。

1. ウィンドウ A に `refreshed daily NRD domain cache` と `daily NRD feed refresh failed` の**どちらも出ていない**（`ledr-nrd-refresh` スレッドが I/O 待機中）状態を確かめる。
2. ウィンドウ B でマーカー用のイベント書き込みを発生させ、停止前に `-wal` ファイルサイズが 0 バイト超になっていることを確認する。

```powershell
.\target\debug\ledr-sim.exe --scenario lotl --json
Start-Sleep -Seconds 2
Get-Item C:\Temp\ledr-e2e\nrd_hang.db-wal -ErrorAction SilentlyContinue | Select-Object Name, Length
```

3. `Length > 0` を確認したら直ちにウィンドウ A で **`Ctrl+C`** を押し、約 3 秒前後でシェルプロンプトへ制御が戻ることを確認する。
4. ウィンドウ A の標準出力ログで、`completed wal_checkpoint(TRUNCATE)` の記録時刻が `shutdown budget exhausted waiting for background NRD refresh thread; detaching thread` の記録時刻より**前**に出力されていることを確認する。
5. 停止後に `-wal` が 0 バイト（または消去）になっており、別 DB ではなく `nrd_hang.db` を開いたとき停止直前のマーカー行が永続化されていることを確かめる。

```powershell
Get-Item C:\Temp\ledr-e2e\nrd_hang.db-wal -ErrorAction SilentlyContinue | Select-Object Name, Length
```

### 6. `taskkill /F` 強制終了時の動的 WFP フィルタ自動消去確認（ウィンドウ A とウィンドウ B）

ウィンドウ A で再び `--disable-nrd-refresh` 付きの `ledr-daemon.exe` を起動し、手順 1 と同様に動的フィルタが登録された状態を再現してください。

```powershell
$env:RUST_LOG = "info,ledr_sensor_win=debug,ledr_store=debug"
.\target\debug\ledr-daemon.exe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --disable-nrd-refresh --db C:\Temp\ledr-e2e\e2e.db
```

ウィンドウ B で `ledr-daemon.exe` を `taskkill /F` で強制終了させ、BFE のフィルタ一覧と外部通信の復旧を確認してください。

```powershell
$p = Get-Process ledr-daemon
taskkill /F /PID $p.Id
Start-Sleep -Seconds 1
netsh wfp show filters file=C:\Temp\ledr-e2e\filters_after_kill.xml
Select-String -Path C:\Temp\ledr-e2e\filters_after_kill.xml -Pattern "LocalEDR"
```

`Select-String` の一致件数が **0 件** になり、そのままウィンドウ B で手順 2 の外部接続コマンド（`93.184.216.34` ポート `80`）を再実行して `External connect succeeded` で通信が回復していれば、動的セッション（`FWPM_SESSION_FLAG_DYNAMIC`）による異常終了時フェイルセーフは合格である。

## リソース消費と UI 完全終了の確認

[implementation-plan.md](implementation-plan.md) のリソース基準を確認するため、ウィンドウ A で `ledr-daemon.exe` を起動した状態のまま以下を計測してください。

### 1. `ledr-ui` 閉鎖時のプロセス 0 件確認（`L-08`）

ウィンドウ C で `.\target\debug\ledr-ui.exe` を開いた状態で右上の閉じるボタンから終了し、直後にウィンドウ C で UI 本体と WebView2 子プロセスの残存がないことを確認してください。

```powershell
Get-Process ledr-ui -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" | Where-Object { $_.CommandLine -match 'ledr-ui|LocalEDR' } | Select-Object ProcessId, CommandLine
```

両方のコマンドで出力が 0 件であれば合格である。

### 2. `ledr-daemon` 常駐メモリ（20 MB 以下）と定常 CPU 使用率（0.5% 未満）の計測

ウィンドウ B で次の計測スクリプトを実行し、定常アイドル時（および必要に応じて別ウィンドウでの `cargo build` 負荷中）の Working Set と平均 CPU 使用率を計測してください。
標準の目標確認では `$sampleSec = 60`（厳密な計画基準に沿うアイドル計測では `600` 秒）として計測できます。

```powershell
$sampleSec = 60
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

`PeakWorkingSetMB` が `20.0` 以下、かつ定常時 `AvgCpuPercent` が `0.5` 未満であれば性能目標を満たしている。

## 補足手順（任意）：Session 0（`LocalSystem`）境界の代替確認

`ledr-daemon.exe` に Windows Service SCM エントリポイント（`StartServiceCtrlDispatcherW`）が未実装である段階でも、`PsExec`（Sysinternals）等を用いて `LocalSystem` 権限（Session 0）で起動し、`WTSQueryUserToken` と `CreateProcessAsUserW` による対話セッションへの `--notify` 起動を確認したい場合は、**本番配置に近い代替条件**としてのみ実行できます。
実施する場合は `ledr-ui.exe` を同じフォルダ（`--foreground` 併用）または `C:\Program Files\LocalEDR\ledr-ui.exe` へ配置して検証し、結果を記録する際は Windows Service SCM 自体が未実装である旨を「未検証差異」へ必ず切り分けて記載してください。

## 後片付けと検証結果の記録

### 環境の後片付け

すべての検証が終わったら、`ledr-daemon` と `ledr-ui` を停止し、検証用一時フォルダおよびおとりファイルを整理してください。
なお、現行の [main.rs](../crates/ledr-daemon/src/main.rs) では終了時におとりファイルを自動削除しないため、テスト終了後に環境へ残したくない場合は手動で削除します。

```powershell
Get-Process ledr-daemon, ledr-ui, ledr-sim -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -Recurse -Force C:\Temp\ledr-e2e -ErrorAction SilentlyContinue
# 必要に応じてユーザーフォルダに配置されたおとりファイル 3 件を削除する
Remove-Item "$env:USERPROFILE\Documents\!00_LocalEDR_Canary_DoNotEdit.docx","$env:USERPROFILE\Desktop\!00_LocalEDR_Canary_DoNotEdit.docx","$env:USERPROFILE\Pictures\!00_LocalEDR_Canary_DoNotEdit.docx" -ErrorAction SilentlyContinue
# 必要に応じて HKCU\Software\Classes\ledr と LocalEDR.AlertUI のテスト登録を削除する
# Remove-Item -Recurse -Force "HKCU:\Software\Classes\ledr","HKCU:\Software\Classes\AppUserModelId\LocalEDR.AlertUI" -ErrorAction SilentlyContinue
```

### 検証結果報告テンプレート（`FU-E2E-01` PR 用）

実機検証が完了したら、次の表へ実測結果（`PASS` / `FAIL` / `BLOCKED` / `未検証差異`）を記入して共有してください。
この結果に基づき、独立した実機 E2E 検証 PR で [implementation-plan.md](implementation-plan.md) の Phase 2 と Phase 3 の実機検証チェックリスト更新および必要な修正へ進みます。

| ID | Phase | 検証項目 | 判定 | 備考と実測値および差異 |
| :--- | :--- | :--- | :--- | :--- |
| `E2E-P2-01` | Phase 2 | おとりファイル読み取り非発火 | | |
| `E2E-P2-02` | Phase 2 | ダミー `Cookies` Open 凍結、1 秒以内通知（自己誤検知なし）、`ledr://` 起動、`Allow Once` 再開 | | |
| `E2E-P2-03` | Phase 2 | おとり書込ツリー凍結と `Terminate & Block` 親＋子一括終了 | | |
| `E2E-P2-04` | Phase 2 | 60 秒未応答時の `EXPIRED_SUSPENDED` 遷移と凍結維持 | | |
| `E2E-P2-05` | Phase 2 | `explorer.exe` に対する Never-Suspend ガード | | |
| `E2E-P2-06` | Phase 2 | ETW `Kernel-Registry` 自動起動キー検知と `CloseKey` 無効化 | | |
| `E2E-P3-01` | Phase 3 | BFE 動的 SubLayer、ループバック許可、事前制限と `FwpmNetEventSubscribe1` | | |
| `E2E-P3-02` | Phase 3 | 複数インスタンス時の `App-Level (Ambiguous PID)` 非凍結 | | |
| `E2E-P3-03` | Phase 3 | `ledr-sim` LOTL と一般パス DNS／外部 TCP 相関（View 1 と View 2） | | |
| `E2E-P3-04` | Phase 3 | View 1 と View 3 での許可保存、ドメイン `IP-resolved`、Deny 優先、削除連動 | | |
| `E2E-P3-05` | Phase 3 | 実 WinHTTP NRD 取得と View 3 `NRD / Homograph Check` | | |
| `E2E-P3-06` | Phase 3 | 未応答 UNC 共有での 3 秒停止予算、WAL 先行チェックポイント、非ハング終了 | | |
| `E2E-P3-07` | Phase 3 | `taskkill /F` 強制終了時の動的 WFP フィルタ 0 件消去と通信回復 | | |
| `E2E-PERF-01` | 共通 | `ledr-ui` 閉鎖後プロセス 0 件、`ledr-daemon` Working Set 20 MB 以下／CPU 0.5% 未満 | | |
| `E2E-SVC-01` | 共通 | Session 0 (`LocalSystem`) `CreateProcessAsUserW`（SCM 未実装差異の切り分け） | | |
