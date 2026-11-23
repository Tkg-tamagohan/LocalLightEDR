# LocalEDR 実機 E2E テスト詳細手順書

本書は LocalEDR の Phase 1 から Phase 4 までを対象に、Windows 10 または Windows 11（x86_64）クライアント SKU 実機で実行する E2E 検証の統合手順書である。
[follow-up-notes.md](follow-up-notes.md) の `FU-E2E-01` と `FU-E2E-02`、および [implementation-plan.md](implementation-plan.md) の実機受け入れ条件を一つの手順へ統合している。

## 1. 検証の目的、対象環境、実行ルートの選択

### 現行システムと本書の検証範囲

LocalEDR はカーネルドライバを書かず、Windows 標準のユーザモード機構（ETW、WFP 動的セッション、`NtSuspendProcess`、Named Pipe IPC）とオンデマンド起動の Tauri WebView2 UI（`ledr-ui`）、Native Messaging ブリッジ（`ledr-bridge-nm`）、および Chrome Manifest V3 拡張を組み合わせたエンドポイント防御ソフトウェアである。
バックグラウンドで稼働する `ledr-daemon` がプロセス生成、おとりファイルや自動起動レジストリへのアクセス（カナリア操作）、DNS 解決と外部通信、およびブラウザ拡張から通知されるイベントを監視し、異常検知時のみ `ledr-ui` でトリアージ操作を受け付ける。

Phase 0（基盤構築と共通型凍結）、Phase 1（プロセス系譜と通信記録）、Phase 2（機密ファイル保護とおとり監視）、Phase 3（WFP 通信制御と NRD）、および Phase 4（Chrome 拡張、Native Messaging、MOTW 紐付け、UI 統合、末尾の PR 4C）までの実装と合成自動テスト（高負荷 `burst_budget` や SQLite 寿命管理 `ttl_purge_lineage` を含む）は `main` ブランチへマージ済みである。
ただし、実 OS のカーネル ETW 配送、BFE 動的 WFP フィルタ登録、実プロセスの凍結とツリー終了、Session 0 からの通知起動、応答しない UNC 共有での読み取り停止、実 Chrome 上の拡張動作と `:Zone.Identifier` 紐付け、および WebView2 終了時のプロセス 0 件維持は合成テストで代替できないため、実機検証として本書で確かめる。

### 本書で使う主な用語と仕組み

初見の検証者が他文書を開かずに手順の意味を判断できるよう、本書で使う固有の語と設計決定（[decision-records.md](decision-records.md) の `L-01` から `L-24`）を整理する。

- **コンポーネント 4 バイナリと補助資産**：`ledr-daemon.exe` は監視と制御の中核常駐デーモン、`ledr-ui.exe` はトリアージと履歴表示を行うオンデマンド UI、`ledr-bridge-nm.exe` は Chrome 拡張とデーモンを仲介する Native Messaging ホスト、`ledr-sim.exe` は実マルウェアを使わずに各攻撃シナリオを擬似実行する無害なシミュレータである。
- **UI の 3 ビュー構成**：`View 1: アラートトリアージ` は検知確認と解決操作（`Terminate & Block`、`Allow Once`、`Allow Permanent Rule`、`Acknowledge`）、`View 2: プロセス系譜・通信フライトレコーダー` は親子関係や DNS、TCP、ダウンロードの履歴表示、`View 3: 防御ポリシー・カナリア・ブラウザシールド` は WFP ルール、おとり状態、拡張診断とドメイン検査を行う。
- **ETW、WFP、BFE、Named Pipe**：ETW（Event Tracing for Windows）はカーネルのプロセス、ファイル、レジストリ、および DNS イベント購読機構、WFP（Windows Filtering Platform）と BFE（Base Filtering Engine）は OS の通信遮断機構、Named Pipe（`\\.\pipe\localedr-ipc`）は UI やブリッジとデーモンを結ぶプロセス間通信（IPC）経路である。
- **2 レーン有界チャネル（`L-10`）**：`ledr-daemon` は高優先度レーン（容量 1,024、カナリアや未知外部通信などの防御イベントを扱いドロップしない）とテレメトリレーン（容量 8,192、通常通信ログを扱う）の 2 系統で負荷時も防御応答を保つ。
- **アウトバウンド制御モード（`L-03`）**：`enforce` は高リスクパス（`Downloads`、`Temp`、`Tmp`）とスクリプトインタプリタの事前 WFP 制限に加え、一般パスの未知プロセスによる初発外部通信も即時凍結して遮断する。
  一方 `preemptive-only` は事前制限対象と MOTW 付与バイナリの遮断だけを有効にし、一般パスの未知プロセスは観測アラートのみ記録して他アプリの誤凍結を防ぐ。
- **保護対象プロセス（`never-suspend`）と事前制限対象**：`PID 0`、システム、`csrss.exe`、`lsass.exe`、`svchost.exe`、`dwm.exe`、`explorer.exe`、`MsMpEng.exe`、および LocalEDR 自身は決してサスペンドされない。
  事前制限対象は `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`、`SysWOW64\WindowsPowerShell\v1.0\powershell.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、および `PATH` 上の実体 `pwsh.exe`、`node.exe`、`python.exe`、`python3.exe` となる。
- **Tier 1 Protected Templates とおとりファイル（`L-05`、`L-06`）**：認証ストア（Chrome、Edge、Brave、Firefox の `Cookies`、`Login Data`、`Local State`、`~/.ssh/*`、`~/.aws/credentials`、`~/.config/gcloud/*`）と開発秘密（`.env*`）をファイル名やパス規則で保護する。
  おとりファイル（`!00_LocalEDR_Canary_DoNotEdit.docx`）は `Documents`、`Desktop`、`Pictures` の 3 箇所へ自動配置され、ファイル名一致で書き込み、削除、およびリネーム時のみ発火し、読み取りでは発火しない。
- **60 秒タイムアウト遷移（`L-07`）**：サスペンドされたプロセスへユーザーが 60 秒間応答しない場合、自動再開による漏洩や自動終了によるデータ消失を防ぐため、凍結状態を保ったまま `EXPIRED_SUSPENDED` へ遷移する。
- **NRD、Homograph、ClickFix、Pastejacking、DNR（`L-14`、`L-15`、`L-21`）**：NRD（Newly Registered Domain）は登録 14 日以内の新規ドメイン（既定で公開 `hagezi/nrd` 2 フィードを 24 時間ごとにローカル取得）、Homograph は見た目類似ドメイン（`paypa1` 等）、ClickFix と Pastejacking（`L-15`）はクリップボードへの危険コマンド混入や選択文字列すり替え攻撃、DNR（Declarative Net Request）は Chrome 拡張の静的通信遮断ルールである。
- **MOTW 3 段階紐付けと事前遮断（`L-18`）**：ブラウザから保存された実行ファイルを（1）パス一致、（2）128 MiB 以下の SHA-256 一致、（3）NTFS 代替データストリーム（ADS）の `:Zone.Identifier`（`ZoneId >= 3`）の 3 段階で追跡し、Stage 2 または Stage 3 で確認された未許可バイナリはフォルダ移動後も起動時事前 WFP ブロックの対象にする。
- **ブラウザイベント抑止と固定拡張 ID（`L-19`、`L-20`）**：`LAYER_4_BROWSER` イベントはブラウザ内 Shadow DOM に警告を出し既定で OS トーストを発火せず、同じ `(種別, 正規化 URL)` は 30 秒間（上限 256 件）重複抑止する。
  拡張は公開鍵ピン留めにより固定 ID `ecelachfiiiiiibpjeomfncgpegbpanh` を持ち、ホスト名 `com.localedr.bridge` で通信する。
- **IPC 境界と不変条件（`L-08`、`L-09`、`SEC_0002`、`SEC_0003`）**：`L-08` は `ledr-ui` 閉鎖時の UI と WebView2 の 0 プロセス終了、`L-09` と `SEC_0002` は `GetNamedPipeClientProcessId` による保護パスと署名/ハッシュ検証、`SEC_0003` はブリッジ側での `GetNamedPipeServerProcessId` によるデーモンパス検証である。
- **未完了追跡 ID（[follow-up-notes.md](follow-up-notes.md)）**：`FU-E2E-01` は Phase 2 と 3 の実機検証、`FU-E2E-02` は Phase 4 実機 Chrome 検証、`FU-P4-01` は `ledr-bridge-nm` の `HKLM` 32 ビットレジストリビュー（`KEY_WOW64_32KEY`）未対応の残件を指す。

### 基準環境と必要な道具

- **OS**：Windows 10 または Windows 11（x86_64）クライアント SKU（`ProductType = 1`）。
  Windows Server SKU で代替実施した場合はクライアント SKU との未検証差異を報告へ明記する。
- **アカウント権限前提**：後述するウィンドウ A、B、C は同一ユーザーの UAC トークン分割環境（管理者トークンと標準ユーザートークンが同じユーザー SID と `$env:USERPROFILE` を共有する状態）を必須前提とする。
  `--dev-bypass-auth` 時の Named Pipe DACL は対話ユーザー全体（`IU`）へ開かず起動アカウントの現在ユーザー SID のみへ `0x12019B` を付与するため、標準ユーザーから別アカウントの管理者資格情報で UAC 昇格する環境では、ダウンロードパスを読み替えても通常ユーザー側の `ledr-ui.exe` と `ledr-bridge-nm.exe` が IPC 接続できない。
  別アカウント昇格しか使えない環境で検証する場合は、`--dev-bypass-auth` を使わず第 6 章 `E2E-OPT-02` と同じ `Program Files` 配置および `--ui-sha256` と `--bridge-sha256` 指定の本番認証モード（`SERVICE_PIPE_SDDL`＋`L-09` バイナリ検証）で起動し、ウィンドウ B 側のダウンロード参照パスをウィンドウ C の `$env:USERPROFILE\Downloads` へ読み替えること。
- **リポジトリパス変数（`$repoRoot`）**：本書では各シェルで変数 `$repoRoot`（例として `e:\Documents\code\LocalEDR`）を設定し、別ドライブや別フォルダへクローンした環境でもそのまま実行できるようにする。
- **シェル 3 枚とターゲット分離**：64 ビット版 PowerShell（`System32\WindowsPowerShell\v1.0\powershell.exe`）を 3 枚（管理者ウィンドウ A と B、通常ユーザーウィンドウ C）開いて操作用にする。
  `E2E-P3-01` と `E2E-P3-02` の WFP インタプリタ試験には操作用シェルと実行ファイルパスが衝突しない 32 ビット版 PowerShell（`SysWOW64\WindowsPowerShell\v1.0\powershell.exe`）を `Start-Process` で別起動して使う。
- **ツールチェインとランタイム**：Rust ツールチェイン（`cargo`）、Google Chrome（任意で Microsoft Edge）、Python 3（ローカル HTTP サーバおよび SQLite 確認用、Microsoft Store スタブではない実体）、Node.js 22（CI 相当の事前の JS テスト確認でのみ使用し、実機 E2E 本編では使用しない）。
- **専用環境向け任意ツール**：第 6 章の `E2E-OPT-03` を実施する場合のみ Sysinternals `PsExec64.exe` を使用する。

### 作業分担表

| 担当 | 対象作業 | 実施状態 |
| :--- | :--- | :--- |
| CI と自動テスト | 静的検査（`clippy`）、ワークスペース単体と統合テスト、`burst_budget`、`ttl_purge_lineage`、Chrome 拡張と UI モック DOM の Node テスト | 実施済み（`main`） |
| 検証者（手作業とスクリプト） | ウィンドウ A、B、C の起動、Debug と Release の両ビルド、OS SKU と `BFE` 確認、作業フォルダとダミーカナリア作成、既存レジストリとマニフェスト退避 | 本書 第 2 章 |
| 検証者（管理者 PowerShell） | Track A：Phase 1 から Phase 3 までのカーネル境界、ETW、WFP、NRD 停止予算、強制終了フェイルセーフの実機確認 | 本書 第 3 章 |
| 検証者（管理者と通常ユーザー） | Track B：Phase 4 の Native Messaging 登録、Chrome 拡張疎通、ローカル検証ページ操作、MOTW 3 段階紐付けと事前遮断確認 | 本書 第 4 章 |
| 検証者（通常ユーザーと管理者） | Track C：Release 版での `ledr-ui` 完全終了（`L-08`）と `ledr-daemon` 常駐リソース計測（`E2E-PERF-01`） | 本書 第 5 章 |
| 検証者（専用 VM 等、任意） | 追加検証：`Enforce` モード初発凍結と負荷計測、`Program Files` 配置での本番 IPC 認可、Session 0 トースト起動 | 本書 第 6 章 |
| 検証者（全ルート共通） | デーモン停止、WFP 残存確認、レジストリとマニフェスト復元、新規おとりのみ削除、合否記録 | 本書 第 7 章と第 8 章 |

### 実行ルートの選択

実施目的に応じて次の 3 ルートから選択してください。
第 6 章（専用環境向け追加検証）を実施する場合は、どのルートでも **第 5 章の直後かつ第 7 章の前** で実行してください（`PREP-01` と `PREP-02` の資産を使うため）。

| ルート | 対象 PR や目的 | 実施する章 | 所要の目安 |
| :--- | :--- | :--- | :--- |
| ルート 1（推奨、一気通貫） | Phase 1 から Phase 4 までを最小の手戻りで通し検証する | 第 2 章（`PREP-01` から `PREP-04`）→ 第 3 章 → 第 4 章 → 第 5 章 → （任意で第 6 章）→ 第 7 章 | ビルドと 10 分計測を含め約 45 分 |
| ルート 2（`FU-E2E-01` 単独） | Phase 2 と Phase 3 の実機検証 PR のみを実施する | 第 2 章（`PREP-01` から `PREP-04`）→ 第 3 章 → 第 5 章 → （任意で第 6 章）→ 第 7 章 | ビルドと 10 分計測を含め約 30 分 |
| ルート 3（`FU-E2E-02` 単独） | Phase 4 実機 Chrome E2E 検証 PR のみを実施する | 第 2 章（`PREP-01` から `PREP-03`、`PREP-04` は省略可）→ 第 4 章 → 第 5 章 → （任意で第 6 章）→ 第 7 章 | ビルドと 10 分計測を含め約 30 分 |

## 2. 安全制約と共通事前準備

### 作業前に確認する 7 つの安全前提

1. **Windows Service SCM エントリポイントは未実装である**：現行の [main.rs](../crates/ledr-daemon/src/main.rs) は `build_daemon_runtime()`（有界マルチスレッド Tokio ランタイム）上のコンソールプロセスであり、`StartServiceCtrlDispatcherW` を持たないため `sc.exe start` ではエラー 1053 で失敗する。
   本編では `--foreground` 起動時のフォールバック経路でトースト通知と `ledr://` 起動を確認し、Session 0 境界の確認は第 6 章（`E2E-OPT-03`）へ切り分ける。
2. **操作中の管理者 PowerShell ウィンドウを凍結させない**：`powershell.exe` は事前 WFP ブロック対象であり、`never-suspend` 保護対象に含まれない。
   ウィンドウ B から `Cookies` の開錠や自動起動レジストリ書込を直接実行すると操作中のシェル自体が凍結するため、試験アクセスには必ず `ledr-sim.exe` または `Start-Process` で別の子プロセスを起動する。
3. **検証用の認証迂回フラグと安全なアウトバウンド制御モードを併用する**：未署名の開発ビルドから Named Pipe IPC の状態変更コマンドを送信するため、`ledr-daemon.exe` へ `--dev-bypass-auth` を指定する。
   なお、`--dev-bypass-auth` 時の Named Pipe DACL は起動元アカウントの現在ユーザー SID のみに接続を限定し（`IU` を含めず、`LocalSystem` `S-1-5-18` では `SY` と `BA` のみへフェイルクローズする）、同一ユーザーでの UAC トークン分割昇格を前提とする。
   あわせて開発ホスト PC 上の未知常駐アプリの誤凍結を防ぐため、第 3 章から第 5 章までは `--outbound-mode preemptive-only --resume-suspended-on-shutdown` を常に付与する。
4. **Debug と Release の混在時は `SEC_0003` パイプサーバ照合に注意する**：`ledr-bridge-nm.exe` は接続先の Named Pipe サーバが `C:\Program Files\LocalEDR\ledr-daemon.exe` または（Debug ビルド時か同パス未存在時に限り）ブリッジと同一ディレクトリの兄弟 `ledr-daemon.exe` であることを検証する。
   そのため `$runDir\debug-bin\ledr-bridge-nm.exe` を登録している間は同一ディレクトリの `$runDir\debug-bin\ledr-daemon.exe`（ハードリンクなし・`Links = 1` でステージングしたもの）と組み合わせ、第 5 章で `$runDir\release-bin\ledr-daemon.exe` へ切り替える前に Chrome 拡張の操作をすべて終えて検証用 Chrome を閉じる。
   なお、`C:\Program Files\LocalEDR\ledr-daemon.exe` が既に存在する PC では兄弟パスへのフォールバックが無効になるため、本番導入済みのバイナリを退避するか検証専用 VM で実施してください。
5. **Windows 通知設定（`ToastEnabled`）をオンにする**：OS 側で通知がオフ（`ToastEnabled = 0`）の場合、`ledr-ui.exe --notify` は JSON に `"status":"suppressed_by_os_settings"` を返してバナーを表示しない。
   目視確認前に Windows の「設定」から「システム」の「通知」をオンにしてください。
6. **レジストリ共有と 64 ビット PowerShell 必須**：Chrome へ隔離プロファイル（`--user-data-dir`）を指定しても、Native Messaging Host と `ledr://` のレジストリ登録は同一ユーザーまたはマシン全体で共有される。
   32 ビット版 PowerShell では `System32` リダイレクトにより 64 ビットビューの退避と復元ができないため、必ず 64 ビット版 PowerShell を使い、登録前に既存キーを退避する。
7. **Windows Defender と SmartScreen の干渉に配慮する**：未署名の `ledr-sim.exe`（`EncodedCommand` 模擬や `Cookies` アクセス）および `:Zone.Identifier` が付いた `localedr-e2e-sample.exe` は Windows Defender リアルタイム保護や SmartScreen の警告対象になりやすい。
   実行時や移動時に「アクセスが拒否されました」または SmartScreen 確認が出た場合は、Defender の保護履歴でテスト用 `$runDir` とビルド出力の除外設定や一時許可を確認してください。

### 3 枚の操作用 PowerShell ウィンドウの準備

作業開始前に、次の 3 枚の 64 ビット版 PowerShell ウィンドウを開いて並べてください。

- **ウィンドウ A（64 ビット版管理者 PowerShell）**：スタートメニューで「Windows PowerShell」を右クリックして「管理者として実行」を選び、1 枚目を開く（`ledr-daemon.exe` の起動とログ監視用）。
- **ウィンドウ B（64 ビット版管理者 PowerShell）**：同じ手順でもう 1 枚を「管理者として実行」で開く（事前準備、`ledr-sim.exe` 実行、`netsh wfp` 確認、性能計測、後片付け用）。
- **ウィンドウ C（64 ビット版通常ユーザー PowerShell）**：通常の「Windows PowerShell」を 1 枚開く（`ledr-ui.exe`、Native Messaging 登録、ローカル HTTP サーバ、Chrome 起動用）。

### PREP-01：既存プロセス停止、OS と Python 確認、バイナリビルド（ウィンドウ B）

ウィンドウ B（管理者）でリポジトリルート `$repoRoot` を定義し（クローン先が異なる環境では 1 行目のパスを変更してください）、必要なランタイム、OS SKU、`BFE` サービスを確認したうえで Debug と Release の両バイナリをビルドしてください。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell）
if (-not [Environment]::Is64BitProcess) {
    throw "64 ビット版 PowerShell で実行してください。"
}
$repoRoot = "e:\Documents\code\LocalEDR"
if (-not (Test-Path (Join-Path $repoRoot "Cargo.toml"))) {
    throw "リポジトリルートが見つかりません: $repoRoot"
}
New-Item -ItemType Directory -Force -Path "C:\Temp" | Out-Null

# 共有参照ポインタ用と管理者専用ファイル用の 2 ディレクトリを C:\ProgramData 配下に準備し、
# icacls 適用前（および再利用時）にリパースポイントでないことと所有者が Administrators または SYSTEM であることを必ず検証する
$allowedOwnerSids = @("S-1-5-32-544", "S-1-5-18")
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
foreach ($dirSpec in @(
    @{ Path = $stateDir; IcaclsArgs = @("/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-545:(OI)(CI)RX") },
    @{ Path = $adminDir; IcaclsArgs = @("/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-18:(OI)(CI)F") }
)) {
    $targetDir = $dirSpec.Path
    if (-not (Test-Path -LiteralPath $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -ErrorAction Stop | Out-Null
    }
    $dirItem = Get-Item -LiteralPath $targetDir -Force
    if (-not $dirItem.PSIsContainer -or ($dirItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "リパースポイントまたは非ディレクトリを検出したため中止します: $targetDir"
    }
    $ownerSid = (Get-Acl -LiteralPath $targetDir).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -notin $allowedOwnerSids) {
        throw "所有者が Administrators または SYSTEM ではないため中止します: $targetDir (Owner=$ownerSid)"
    }
    & icacls $targetDir @($dirSpec.IcaclsArgs) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "ACL 設定に失敗しました: $targetDir" }
}
[System.IO.File]::WriteAllText((Join-Path $stateDir "repo.txt"), $repoRoot, [System.Text.UTF8Encoding]::new($false))
Set-Location $repoRoot

Get-Process ledr-daemon, ledr-ui, ledr-sim, ledr-bridge-nm -ErrorAction SilentlyContinue | Stop-Process -Force

$os = Get-CimInstance Win32_OperatingSystem
$bfe = Get-Service BFE
$pyCmd = Get-Command python -ErrorAction SilentlyContinue
$pyExe = if ($pyCmd -and $pyCmd.Source -notmatch '\\WindowsApps\\python\.exe$') { $pyCmd.Source } else { $null }
[PSCustomObject]@{
    Caption = $os.Caption
    Version = $os.Version
    ProductType = $os.ProductType
    BfeStatus = $bfe.Status
    PythonExe = $pyExe
} | Format-List

if ($os.ProductType -ne 1) {
    Write-Warning "ProductType が 1（クライアント SKU）ではありません。実施する場合は未検証差異として記録してください。"
}
if ($bfe.Status -ne 'Running') {
    throw "Base Filtering Engine (BFE) サービスが Running ではありません。"
}
if (-not $pyExe) {
    Write-Warning "実体 python.exe が PATH に見つかりません（WindowsApps スタブのみ）。Track B 用の HTTP サーバおよび DB 確認前に Python 3 を PATH へ通してください。"
}
if (Test-Path "C:\Program Files\LocalEDR\ledr-daemon.exe") {
    Write-Warning "C:\Program Files\LocalEDR\ledr-daemon.exe が存在します。Track B の Debug ブリッジは Program Files 以外のデーモンを拒否するため注意してください。"
}

# Phase 3 外部接続検証用の到達可能 IPv4 をデーモン停止中（WFP 事前遮断の適用前）に TCP:80 プローブで確定して保存する
$targetIpFile = Join-Path $adminDir "p3_target_ip.txt"
Remove-Item -LiteralPath $targetIpFile -ErrorAction SilentlyContinue
$targetIp = $null
try {
    $ipv4List = @([System.Net.Dns]::GetHostAddresses("example.com") | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
    foreach ($addr in $ipv4List) {
        $ipStr = $addr.IPAddressToString
        $probeClient = [System.Net.Sockets.TcpClient]::new()
        try {
            $ar = $probeClient.BeginConnect($ipStr, 80, $null, $null)
            if ($ar.AsyncWaitHandle.WaitOne(3000)) {
                $probeClient.EndConnect($ar)
                if ($probeClient.Connected) {
                    $targetIp = $ipStr
                    break
                }
            }
        } catch {
            # 次の IPv4 候補を試行する
        } finally {
            $probeClient.Close()
        }
    }
} catch {
    # オフライン環境では警告のみ出して継続する
}
if ($targetIp) {
    [System.IO.File]::WriteAllText($targetIpFile, $targetIp, [System.Text.UTF8Encoding]::new($false))
    Write-Output "Reachable example.com IPv4 (TCP:80): $targetIp"
} else {
    Write-Warning "example.com の TCP:80 到達可能な IPv4 アドレスを確定できませんでした（オフライン環境の場合は E2E-P3-01/02/04/07 を BLOCKED として記録してください）。"
}

cargo build --workspace --locked
if ($LASTEXITCODE -ne 0) { throw "Debug ビルドに失敗しました (exit code: $LASTEXITCODE)." }

cargo build --workspace --release --locked
if ($LASTEXITCODE -ne 0) { throw "Release ビルドに失敗しました (exit code: $LASTEXITCODE)." }
```

`BfeStatus` が `Running` であり、両方の `cargo build` が終了コード `0` で完了することを確認してください。
`target\debug\` と `target\release\` の双方に `ledr-daemon.exe`、`ledr-auth-helper.exe`、`ledr-ui.exe`、`ledr-sim.exe`、`ledr-bridge-nm.exe` が生成されます。

### PREP-02：作業フォルダ、ダミーカナリア、ローカル配信資産の作成（ウィンドウ B）

続けてウィンドウ B で、今回の実行専用のタイムスタンプ付きフォルダ `$runDir` を作成し、管理者 ACL 保護済みの `C:\ProgramData\LocalEDR-e2e-state\latest.txt` へ記録してください。
既存のおとりファイル一覧（`preexisting_honeypots.txt`）は、非管理者による改ざんを防ぐため管理者専用ディレクトリ `C:\ProgramData\LocalEDR-e2e-admin` へ保存します。
あわせて、過去テストの残存ダウンロードファイルがないよう `Downloads\localedr-e2e-sample*` を事前に整理し、ダミーカナリアが既存ファイル上書きを拒否することを確かめます。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
Set-Location $repoRoot
$runDir = "C:\Temp\ledr-e2e-" + (Get-Date -Format "yyyyMMdd-HHmmss")
foreach ($sub in @("canary_dir", "site\download", "chrome-profile", "backup", "debug-bin")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $runDir $sub) | Out-Null
}
foreach ($exeName in @("ledr-daemon.exe", "ledr-auth-helper.exe", "ledr-ui.exe", "ledr-bridge-nm.exe", "ledr-sim.exe")) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "target\debug\$exeName") -Destination (Join-Path $runDir "debug-bin\$exeName") -Force
}
[System.IO.File]::WriteAllText((Join-Path $stateDir "latest.txt"), $runDir, [System.Text.UTF8Encoding]::new($false))

# 検証前から存在するおとりファイルを管理者専用ディレクトリへ記録し、後片付けで今回作成分だけを削除できるようにする
$honeypotPaths = @(
    "$env:USERPROFILE\Documents\!00_LocalEDR_Canary_DoNotEdit.docx",
    "$env:USERPROFILE\Desktop\!00_LocalEDR_Canary_DoNotEdit.docx",
    "$env:USERPROFILE\Pictures\!00_LocalEDR_Canary_DoNotEdit.docx"
)
$preexistingHoneypots = @($honeypotPaths | Where-Object { Test-Path -LiteralPath $_ })
[System.IO.File]::WriteAllLines((Join-Path $adminDir "preexisting_honeypots.txt"), [string[]]$preexistingHoneypots, [System.Text.UTF8Encoding]::new($false))

# 過去の同名ダウンロードがあると Chrome が (1) を付けてリネーム保存するため事前掃除する
Get-Item "$env:USERPROFILE\Downloads\localedr-e2e-sample*.exe", "$env:USERPROFILE\Downloads\localedr-e2e-sample*.cmd" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# Phase 4 検証用ローカル配信ファイルと NRD フィードを配置する
Copy-Item "docs\fixtures\phase4-browser-test.html" (Join-Path $runDir "site\phase4-browser-test.html") -Force
Copy-Item "target\debug\ledr-sim.exe" (Join-Path $runDir "site\download\localedr-e2e-sample.exe") -Force
[System.IO.File]::WriteAllText((Join-Path $runDir "site\download\localedr-e2e-sample.cmd"), "@echo off`r`necho LocalEDR MOTW E2E`r`n", [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText((Join-Path $runDir "nrd-test-feed.txt"), "nrd-sim.localedr.invalid`r`n", [System.Text.UTF8Encoding]::new($false))

# ダミーカナリアを排他作成し、2 回目の上書き試行が拒否されることを確認する
.\target\debug\ledr-sim.exe --prepare-dir (Join-Path $runDir "canary_dir") --json
if ($LASTEXITCODE -ne 0) { throw "初回 --prepare-dir に失敗しました。" }

.\target\debug\ledr-sim.exe --prepare-dir (Join-Path $runDir "canary_dir") --json
if ($LASTEXITCODE -eq 0) { throw "2 回目の --prepare-dir が既存ファイルの上書きを拒否しませんでした。" }

Write-Output ("PREP-02 完了: RunDir=" + $runDir)
```

1 回目の `--prepare-dir` が成功して `canary_dir` 配下にダミーの `Google\Chrome\User Data\Default\Cookies` と `!00_LocalEDR_Canary_DoNotEdit.docx` が作成され、2 回目の再実行が既存ファイル保護（`create_new(true)`）により非ゼロ終了すれば合格です。

### PREP-03：既存 HKCU 退避と URI スキーム登録、トースト通知確認（ウィンドウ C）

ウィンドウ C（通常ユーザー 64 ビット）で既存の `HKCU` 設定とユーザーマニフェストを `$runDir\backup` へ退避したうえで、`ledr://` URI スキームと専用 AUMID（`LocalEDR.AlertUI`）を登録し、ワンショット通知の動作を確認してください。

```powershell
# ウィンドウ C（64 ビット版通常ユーザー PowerShell）
if (-not [Environment]::Is64BitProcess) {
    throw "64 ビット版 PowerShell で実行してください。"
}
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
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
        $outFile = Join-Path (Join-Path $runDir "backup") $item.File
        & $reg64 export $item.Key $outFile /y | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $outFile) -or (Get-Item $outFile).Length -eq 0) {
            throw "HKCU レジストリ退避に失敗したため中止します: $($item.Key)"
        }
    }
}
$userManifestDir = Join-Path $env:LOCALAPPDATA "LocalEDR\native-messaging"
if (Test-Path $userManifestDir) {
    Copy-Item -Recurse -Force -ErrorAction Stop $userManifestDir (Join-Path $runDir "backup\user-native-messaging")
}

$debugUiExe = Join-Path $runDir "debug-bin\ledr-ui.exe"
& $debugUiExe --register-uri
if ($LASTEXITCODE -ne 0) { throw "--register-uri に失敗しました。" }

Get-ItemProperty "HKCU:\Software\Classes\ledr\shell\open\command"
Get-ItemProperty "HKCU:\Software\Classes\AppUserModelId\LocalEDR.AlertUI"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name ToastEnabled -ErrorAction SilentlyContinue
& $debugUiExe --notify test-alert-001
```

次の 3 点を満たせば `PREP-03` は合格です。

1. `--register-uri` の標準出力に `"status":"registered"` または `"already_registered"` が表示される。
2. `ledr` コマンド値に `$runDir\debug-bin\ledr-ui.exe` が登録され、`LocalEDR.AlertUI` の `DisplayName` が `LocalEDR` である。
3. `--notify test-alert-001` が `"status":"dispatched"` を返し、画面右下にトースト通知が表示される（`suppressed_by_os_settings` が出た場合は Windows の通知設定をオンにして再実行してください）。

参考として、`--notify test-alert-001` の通知バナーをクリックすると `ledr://alert/test-alert-001` 経由で `ledr-ui.exe` が開きます（デーモン未起動中は `Daemon Offline` バナー付きで View 1 が開きます）。
新規ユーザーアカウントや既存 `LocalEDR.AlertUI` キー削除直後のクリーン環境での初回表示まで確認した場合は、その結果を `PREP-03` の備考欄へ記録してください。

### PREP-04：Debug 版 `ledr-daemon.exe` の起動と初期化ログ確認（ウィンドウ A）

ルート 1 またはルート 2 を実施する場合は、ウィンドウ A（管理者 64 ビット）で外部通信や NRD 取得のノイズを切り離した状態の Debug デーモンを `PREP-02` でステージングした `$runDir\debug-bin`（`ledr-auth-helper.exe` のハードリンク数 `nNumberOfLinks == 1` および兄弟バイナリ整合を満たす独立配置）から起動してください。
ルート 3（`FU-E2E-02` 単独）を実施する場合は本章の `PREP-04` を飛ばして第 4 章へ進んで構いません。

```powershell
# ウィンドウ A（64 ビット版管理者 PowerShell）
if (-not [Environment]::Is64BitProcess) {
    throw "64 ビット版 PowerShell で実行してください。"
}
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$env:RUST_LOG = "info,ledr_sensor_win=debug,ledr_store=debug"
$debugDaemonExe = Join-Path $runDir "debug-bin\ledr-daemon.exe"
& $debugDaemonExe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --disable-nrd-refresh --db (Join-Path $runDir "e2e.db")
```

標準出力に次の 7 つのログが順番に出力されれば初期化は完了です。

1. `privilege enablement completed`（`system_profile=true`、`debug=true`、`security=true`、`error=None`）
2. `initialized WFP dynamic session, LocalEDR SubLayer, and loopback Permit filters`
3. `redeployed persisted firewall rules at engine startup`（環境上の全対象に成功した場合は `applied > 0, failed = 0`）
4. `deployed honeypot canary files`（`honeypots=3`）
5. `WindowsEtwSensor real-time ETW trace started`
6. `initialized ActiveProcessTable, WFP firewall rules, and SQLite WAL store`
7. `ledr-daemon listening on Named Pipe IPC; press Ctrl+C to shut down`

> [!NOTE]
> `redeployed persisted firewall rules at engine startup` で少数の `failed` が出る場合があります。
> これは実機 `PATH` 上に Microsoft Store の `AppExecutionAlias`（`WindowsApps\python.exe` 等の 0 バイト `ReparsePoint` スタブ）が存在し、`FwpmGetAppIdFromFileName0` が `0x00000780` を返すためであり、`powershell.exe` 等の実体インタプリタが適用済みであれば検証に支障はありません。

> [!WARNING]
> `WFP dynamic session could not be initialized` または `WindowsEtwSensor could not start` が出力された場合は、ウィンドウ A が管理者権限で起動されていません。
> `Ctrl+C` で終了し、管理者権限で PowerShell を開き直してください。

## 3. Track A：Phase 1 から Phase 3 までのカーネル境界実機検証（FU-E2E-01）

Track A はウィンドウ A で `PREP-04` の Debug デーモンが稼働している状態で開始します。
最初に、ウィンドウ C（通常ユーザー）で常駐監視用の `ledr-ui.exe` を起動しておいてください（`Start-Process` を使うためウィンドウ C のシェルは占有されません）。

```powershell
# ウィンドウ C（64 ビット版通常ユーザー PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Start-Process -FilePath (Join-Path $runDir "debug-bin\ledr-ui.exe") -WorkingDirectory $repoRoot
```

`ledr-ui` は画面遷移やタブ切替だけでは最新データを再取得しないため、各テストケースを実行したあと毎回 `ledr-ui` 上部バーの `Refresh` ボタンを押して確認してください。

### E2E-P2-01：おとりファイルの読み取り非発火確認

ウィンドウ B（管理者）で、ダミーおとりファイルに対する読み取り専用のアクセスを実行してください。

```powershell
# ウィンドウ B（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "type `"$runDir\canary_dir\!00_LocalEDR_Canary_DoNotEdit.docx`" >nul" -Wait -PassThru
Write-Output ("ReadOnlyExitCode=" + $p.ExitCode)
```

終了コードが `0` で戻り、ウィンドウ A のログおよび `ledr-ui`（`Refresh` 後）の `View 1: アラートトリアージ` に `LEDR-CANARY-HONEYPOT` アラートが 1 件も出ていなければ合格です。

### E2E-P2-02：ダミー `Cookies` 開錠凍結、1 秒以内トースト、通知クリック復帰

ウィンドウ B で `ledr-sim.exe` を別プロセスとして起動し、ダミー `Cookies` の開錠と 120 秒間の待機を行わせてください。

```powershell
# ウィンドウ B（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$simCookie = Start-Process -FilePath ".\target\debug\ledr-sim.exe" -WorkingDirectory $repoRoot -ArgumentList "--scenario", "cookies-open", "--base-dir", "`"$(Join-Path $runDir 'canary_dir')`"", "--hold-ms", "120000", "--json" -PassThru
Start-Sleep -Seconds 2
(Get-Process -Id $simCookie.Id).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
```

次の 5 点を順番に確認してください（1 秒および 1,000 ms の応答は目視での即時応答、またはウィンドウ A の検知ログ時刻と UI 起動の差分で確認します）。

1. 実行開始から 1 秒以内に画面右下へ `[LocalEDR] [SUSPENDED] HIGH Browser Cookie Store Access: Cookies` を含む WinRT トースト通知が表示される（操作中の PowerShell 自身の誤検知アラートが出ていないことも確認する）。
2. ウィンドウ B のスレッド状態出力で `ThreadState` が `Wait` かつ `WaitReason` が `Suspended`（全スレッド凍結）になっている。
3. 表示された WinRT トースト通知（または `Triage Alert` ボタン）をクリックし、1,000 ms 以内に `ledr-ui.exe` が画面遷移なしで `View 1: アラートトリアージ` を開く（通知がすでに閉じていた場合は開いている `ledr-ui` の `Refresh` 後に確認する）。
4. 詳細表示の `Detection Context` にある `Rule ID` が `LEDR-CANARY-COOKIE_DB`、`Access Mask` 横に `Read / Open` バッジ、`Signer` に `Unsigned` が表示されていることを確かめたうえで、`Allow Once` ボタンを押す。
5. 押下から 5 秒以内にウィンドウ B で `Get-Process -Id $simCookie.Id -ErrorAction SilentlyContinue` を確認し、`ledr-sim.exe` が再開されて終了（または `WaitReason` が `Suspended` 以外に復帰）していれば合格です。

待機中のプロセスが残っていれば `Stop-Process -Id $simCookie.Id -Force` で終了させてから次に進んでください。

### E2E-P2-03：おとり書込によるツリー凍結と `Terminate & Block` 終了

子プロセス（`cmd.exe` と `ping.exe`）を伴った状態でダミーおとりファイルへ 1 バイト追記するシナリオを実行し、プロセスツリー全体の凍結と一括終了を確認してください。

```powershell
# ウィンドウ B（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$simHp = Start-Process -FilePath ".\target\debug\ledr-sim.exe" -WorkingDirectory $repoRoot -ArgumentList "--scenario", "honeypot-write", "--base-dir", "`"$(Join-Path $runDir 'canary_dir')`"", "--hold-ms", "120000", "--json" -PassThru
Start-Sleep -Seconds 2
$children = Get-CimInstance Win32_Process -Filter ("ParentProcessId=" + $simHp.Id) | Select-Object ProcessId, Name, CommandLine
$children | Format-Table -AutoSize
(Get-Process -Id $simHp.Id).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
foreach ($c in $children) {
    (Get-Process -Id $c.ProcessId -ErrorAction SilentlyContinue).Threads | Select-Object @{n='Pid';e={$c.ProcessId}}, Id, ThreadState, WaitReason | Format-Table -AutoSize
}
```

親の `ledr-sim.exe` と子の `cmd.exe`（および配下の `ping.exe` が存在する場合）の双方が `WaitReason: Suspended` になっていることを確認してください。
続いて `ledr-ui` の `View 1: アラートトリアージ` で `Refresh` を押し、`LEDR-CANARY-HONEYPOT`（重要度 `CRITICAL`、`Write / Delete` および `Tree Containment` バッジ表示）を選択します。

`Save NetworkBlock policy rule (WFP)` のチェックボックスは後続テストの妨げにならないようここでは**オフ**にしてから `Terminate & Block` ボタンを押し、5 秒以内にウィンドウ B で親と子の両方が **0 件へ完全終了** することを確かめてください（親または子が生存した場合は `FAIL` と判定します）。

```powershell
# ウィンドウ B（管理者 PowerShell）
Get-Process -Id $simHp.Id -ErrorAction SilentlyContinue
foreach ($c in $children) { Get-Process -Id $c.ProcessId -ErrorAction SilentlyContinue }
```

もしチェックがオンのまま終了した場合は、後続のネットワーク手順へ進む前に `View 3: 防御ポリシー・カナリア・ブラウザシールド` から `ledr-sim.exe` の `NetworkBlock` ルールを `Delete` で削除してください。

> [!NOTE]
> `Allow Once` や 60 秒タイムアウト（`E2E-P2-04`）では、Windows 実機の `resume_process` が親と同時に子孫の再開も試行します。
> もし再開経路で権限差やタイミング差により子が凍結残留する部分復帰に遭遇した場合は、`suspended_children` の残存記録と UI 上の `EXPIRED_SUSPENDED (... CHILD FROZEN)` 表示を確認して備考へ記録してください。

### E2E-P2-04：60 秒未応答時の `EXPIRED_SUSPENDED` 遷移と凍結維持

未応答のまま 60 秒が経過したときに、対象プロセスが自動再開されず凍結を保つことを確認します。
ウィンドウ B で次のコマンドを実行し、トースト通知をクリックせずに **65 秒以上** 待機してください。

```powershell
# ウィンドウ B（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$simExp = Start-Process -FilePath ".\target\debug\ledr-sim.exe" -WorkingDirectory $repoRoot -ArgumentList "--scenario", "cookies-open", "--base-dir", "`"$(Join-Path $runDir 'canary_dir')`"", "--hold-ms", "180000", "--json" -PassThru
Start-Sleep -Seconds 68
(Get-Process -Id $simExp.Id).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
```

68 秒経過後も `ledr-sim.exe` の全スレッドが `WaitReason: Suspended` のままであり、`ledr-ui` の `Refresh` を押したあとに `View 1: アラートトリアージ` のバナーが `EXPIRED_SUSPENDED (60s)`（説明 `60s timeout elapsed — process remains frozen without data loss`）へ遷移していれば合格です。
確認後、`Save NetworkBlock policy rule (WFP)` をオフにした `Terminate & Block`（または `Allow Once`）で解決し、残っていれば `Stop-Process -Id $simExp.Id -Force` で終了してください。

### E2E-P2-05：Never-Suspend 安全ガードの確認

エクスプローラ（`explorer.exe`）などの保護対象プロセスがカナリアに触れても凍結しないことを確認します。
UIPI（特権分離）の影響を避けるため、通常ユーザー権限の **ウィンドウ C** からダミーフォルダをエクスプローラで開き、**実プロファイルではなくテスト用の** `$runDir\canary_dir\!00_LocalEDR_Canary_DoNotEdit.docx` を手動で右クリックして一時的に別名（たとえば `!00_LocalEDR_Canary_DoNotEdit_renamed.docx`）へ変更してください。

```powershell
# ウィンドウ C（通常ユーザー PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
explorer.exe (Join-Path $runDir "canary_dir")
```

変更操作の直後、次の 3 点を確かめてください。

1. `explorer.exe` およびデスクトップ画面がフリーズせず、引き続き操作できる。
2. ウィンドウ A のログに `never-suspend guard skipped suspension on canary alert` が出力される。
3. `ledr-ui` で `Refresh` を押した `View 1: アラートトリアージ` 上で、対象アラート（`LEDR-CANARY-HONEYPOT`）が凍結状態ではなく `PENDING`（非サスペンド）として記録されている。

> [!CAUTION]
> `View 1` 上の `explorer.exe` アラートに対して `Terminate & Block` を実行しないでください。
> 安全ガードで保護されていますが、手順上は `Allow Once` でアラートを閉じるだけにしてください。

確認が終わったら、リネームしたファイルを元の名前 `!00_LocalEDR_Canary_DoNotEdit.docx` へ戻し、開いたエクスプローラウィンドウを閉じてください。
なお、PowerShell から `Rename-Item` を実行すると ETW 上の実行元が `powershell.exe` になりガード対象外として凍結するため、必ず対話デスクトップ上のエクスプローラから操作してください（非対話環境では未検証差異として記録します）。

### E2E-P2-06：ETW `Kernel-Registry` 自動起動キー監視と `CloseKey` 無効化

ウィンドウ B から直接 `reg` を実行するのではなく、`Start-Process` 経由で `reg.exe` を起動し、`CurrentVersion\Run` への書き込み検知を確認してください。

```powershell
# ウィンドウ B（管理者 PowerShell）
$regAdd = Start-Process -FilePath "reg.exe" -ArgumentList "add", "HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "LocalEdrE2eProbe", "/t", "REG_SZ", "/d", "`"cmd.exe /c echo ok`"", "/f" -PassThru
Start-Sleep -Seconds 2
Get-Process -Id $regAdd.Id -ErrorAction SilentlyContinue | Select-Object Id, ProcessName
(Get-Process -Id $regAdd.Id -ErrorAction SilentlyContinue).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
```

`reg.exe` は書き込み速度によってサスペンドより先に終了する場合もありますが、`ledr-ui` で `Refresh` を押したあとに `View 1` へ `LEDR-CANARY-AUTORUN_REGISTRY`（`Autorun Persistence Modification: LocalEdrE2eProbe`）が記録されていれば ETW `Kernel-Registry` 監視が動作しています（凍結中であれば `Allow Once` で解放してください）。

続けて、テスト登録したレジストリ値を別プロセス（`-PassThru`、`-Wait` なし）で削除して元へ戻します。
`DeleteValueKey` 監視で `reg.exe` が凍結した場合は `ledr-ui` で `Refresh` を押して該当アラートを `Allow Once` で再開し、終了を確認したうえで一時キーの作成、更新、削除を実行してください。

```powershell
# ウィンドウ B（管理者 PowerShell）
$regDel = Start-Process -FilePath "reg.exe" -ArgumentList "delete", "HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "LocalEdrE2eProbe", "/f" -PassThru
Start-Sleep -Seconds 2
Get-Process -Id $regDel.Id -ErrorAction SilentlyContinue | Select-Object Id, ProcessName
```

`reg.exe` の終了を確かめてから次の一時キー操作を実行します。

```powershell
# ウィンドウ B（管理者 PowerShell）
$tmpKey = "HKCU:\Software\LocalEdrE2eTmp"
New-Item -Path $tmpKey -Force | Out-Null
Set-ItemProperty -Path $tmpKey -Name "Probe" -Value "ok"
Remove-Item -Path $tmpKey -Force
```

一時キー `HKCU\Software\LocalEdrE2eTmp` の操作後に `ledr-ui` で `Refresh` を押し、`LEDR-CANARY-AUTORUN_REGISTRY` アラートが新規追加されていなければ `CloseKey`（イベント ID 13）とキャッシュ無効化は正常です（`reg.exe delete` 由来のアラートが残っていれば `Allow Once` で解決してください）。

### E2E-P3-01：BFE 動的 SubLayer、ループバック許可、単一インスタンス遮断と凍結

ウィンドウ A で `ledr-daemon.exe` が稼働中のまま、ウィンドウ B で BFE に登録されている WFP フィルタを XML 出力して確認してください。

```powershell
# ウィンドウ B（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$activeFiltersXml = Join-Path $runDir "filters_active.xml"
netsh wfp show filters "file=$activeFiltersXml"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $activeFiltersXml)) {
    throw "netsh wfp show filters に失敗しました。"
}
Select-String -Path $activeFiltersXml -Pattern "LocalEDR" -ErrorAction Stop | Select-Object -First 20
```

出力に `LocalEDR Outbound SubLayer`、`LocalEDR Loopback Permit (v4)`、`LocalEDR Loopback Permit (v6)`、および事前制限インタプリタ（`System32\WindowsPowerShell\v1.0\powershell.exe` と `SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 等）に対する `LocalEDR Block` フィルタが含まれていれば事前制限が有効です。

続けて、操作用のウィンドウ A/B/C（64 ビット版 `System32\...\powershell.exe`）と実行ファイルパスが重複しない **32 ビット版 PowerShell（`C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`）** を 1 インスタンスだけ別プロセスで起動し、ローカル接続（`127.0.0.1`）の成功と外部接続（`PREP-01` でデーモン停止中に TCP:80 到達性を確認して `$adminDir\p3_target_ip.txt` へ保存した `example.com` の IPv4 アドレス `$targetIp` のポート `80`）の遮断および単一インスタンス凍結を確認します。
続く `E2E-P3-02`、`E2E-P3-04`、および `E2E-P3-07` でも一貫してこの到達確認済み `$targetIp` を使います（デーモン稼働中は 64 ビット版 `powershell.exe` も WFP 事前遮断対象のため、到達性プローブは `PREP-01` 時点で済ませておく必要があります）。
もし外部への TCP 経路がない完全オフライン環境で `p3_target_ip.txt` が生成できなかった場合は、外部接続の代替条件がないため `BLOCKED（オフライン環境）` と記録してください。

```powershell
# ウィンドウ B（管理者 PowerShell）: 単一インスタンスの SysWOW64 powershell.exe でループバック許可と外部遮断を確認
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$ps32 = "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path -LiteralPath $ps32)) { throw "32 ビット版 PowerShell が見つかりません: $ps32" }

$targetIpFile = Join-Path $adminDir "p3_target_ip.txt"
if (-not (Test-Path -LiteralPath $targetIpFile)) {
    throw "到達確認済みの p3_target_ip.txt が見つかりません。ledr-daemon.exe 停止中に PREP-01 の TCP:80 プローブを実行するか、オフライン環境として BLOCKED を記録してください。"
}
$targetIp = (Get-Content -Encoding UTF8 $targetIpFile -Raw).Trim()
if (-not $targetIp) { throw "p3_target_ip.txt が空です。" }
Write-Output "Verified reachable IPv4 (example.com TCP:80): $targetIp"

$probeOut = Join-Path $adminDir "p3_01_probe.txt"
Remove-Item -LiteralPath $probeOut -ErrorAction SilentlyContinue
$probeScript = @'
param([string]$OutFile, [string]$TargetIp)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$client = [System.Net.Sockets.TcpClient]::new()
$client.Connect("127.0.0.1", $port)
[System.IO.File]::WriteAllText($OutFile, ("Loopback Connected: " + $client.Connected + "`r`n"), $utf8NoBom)
$client.Close()
$listener.Stop()

$ext = [System.Net.Sockets.TcpClient]::new()
$line2 = ""
try {
    $ar = $ext.BeginConnect($TargetIp, 80, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(3000)) {
        $ext.EndConnect($ar)
        $line2 = "External connect succeeded"
    } else {
        $line2 = "Blocked or timed out as expected"
    }
} catch {
    $line2 = "Blocked by WFP: " + $_.Exception.InnerException.Message
} finally {
    $ext.Close()
}
[System.IO.File]::AppendAllText($OutFile, ($line2 + "`r`n"), $utf8NoBom)
Start-Sleep -Seconds 60
'@
$probePath = Join-Path $adminDir "p3_01_probe.ps1"
[System.IO.File]::WriteAllText($probePath, $probeScript, [System.Text.UTF8Encoding]::new($false))

$ps32Proc1 = Start-Process -FilePath $ps32 -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$probePath`"", "-OutFile", "`"$probeOut`"", "-TargetIp", $targetIp -PassThru
Start-Sleep -Seconds 5
if (Test-Path -LiteralPath $probeOut) { Get-Content -Encoding UTF8 -LiteralPath $probeOut }
(Get-Process -Id $ps32Proc1.Id -ErrorAction SilentlyContinue).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
```

次の 3 点を満たせば `E2E-P3-01` は合格です（この `$ps32Proc1` とアラートは続く `E2E-P3-04` で永続許可して再開するため、終了させずそのまま次へ進みます）。

1. `p3_01_probe.txt` に `Loopback Connected: True` と `Blocked by WFP: ...`（または `Blocked or timed out`）が出力されている（外部接続直後に凍結して 2 行目の書き出し前にサスペンドされた場合は、`E2E-P3-04` の再開後に 2 行目が書き出されます）。
2. 単一インスタンスの `SysWOW64\...\powershell.exe`（`$ps32Proc1`）の全スレッドが `WaitReason: Suspended` になっている。
3. `ledr-ui`（`Refresh` 後）の `View 1` に `powershell.exe`（`SysWOW64` パス）の `LEDR-NET-SCRIPT-INTERPRETER` アラート（`WFP Blocked` バッジ付き）が生成されている。

### E2E-P3-02：複数インスタンス時の `App-Level (Ambiguous PID)` 非凍結確認

同じ `SysWOW64\WindowsPowerShell\v1.0\powershell.exe` の 2 インスタンス目が起動した状態を作り、複数インスタンス競合時に `NtSuspendProcess` が発動しない（誤凍結しない）ことを確認します。
前の `E2E-P3-01` の `$ps32Proc1` が生きている状態のまま（もし終了していた場合は `-Command "Start-Sleep -Seconds 90"` で 1 つ目を起動してから）、250 ms 以上間隔を空けて 2 つ目の `SysWOW64\...\powershell.exe` を起動して外部接続を試行させてください。

```powershell
# ウィンドウ B（管理者 PowerShell）
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$ps32 = "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
$targetIp = (Get-Content -Encoding UTF8 (Join-Path $adminDir "p3_target_ip.txt") -Raw).Trim()
$ambOut = Join-Path $adminDir "p3_02_ambig.txt"
Remove-Item -LiteralPath $ambOut -ErrorAction SilentlyContinue
$ambScript = @'
param([string]$OutFile, [string]$TargetIp)
$ext = [System.Net.Sockets.TcpClient]::new()
$msg = try {
    $ext.Connect($TargetIp, 80)
    "Succeeded"
} catch {
    "Blocked: " + $_.Exception.Message
} finally {
    $ext.Close()
}
[System.IO.File]::WriteAllText($OutFile, ($msg + "`r`n"), [System.Text.UTF8Encoding]::new($false))
Start-Sleep -Seconds 60
'@
$ambPath = Join-Path $adminDir "p3_02_ambig.ps1"
[System.IO.File]::WriteAllText($ambPath, $ambScript, [System.Text.UTF8Encoding]::new($false))

Start-Sleep -Milliseconds 400
$ps32Proc2 = Start-Process -FilePath $ps32 -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$ambPath`"", "-OutFile", "`"$ambOut`"", "-TargetIp", $targetIp -PassThru
Start-Sleep -Seconds 3
if (Test-Path -LiteralPath $ambOut) { Get-Content -Encoding UTF8 -LiteralPath $ambOut }
(Get-Process -Id $ps32Proc2.Id -ErrorAction SilentlyContinue).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
```

`p3_02_ambig.txt` が `Blocked: ...` であり、`$ps32Proc2` のスレッドが `Suspended` にならず、`ledr-ui`（`Refresh` 後）の `View 1` に `App-Level (Ambiguous PID)` バッジ付きアラート（非凍結）が追加されていれば合格です。
確認後、2 つ目の `$ps32Proc2` だけを `Stop-Process` で停止して整理し、`$ps32Proc1` は次の `E2E-P3-04` で永続許可の再開対象として使うため残しておいてください。

```powershell
# ウィンドウ B（管理者 PowerShell）
if ($ps32Proc2) { Stop-Process -Id $ps32Proc2.Id -Force -ErrorAction SilentlyContinue }
```

### E2E-P3-03：一般パス `ledr-sim.exe` による LOTL 検知、DNS 相関、ETW 補完

`$repoRoot\target\debug\ledr-sim.exe` は `Downloads` や `Temp` 配下ではない一般パスの実行ファイルです。
ウィンドウ B で次の 2 本を実行し、Phase 1 の受け入れ条件（1 秒以内の系譜描画、引数、解決ドメイン、IP 記録）と Phase 3 の通信相関を確認してください。

```powershell
# ウィンドウ B（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
Set-Location $repoRoot
.\target\debug\ledr-sim.exe --scenario lotl --json
.\target\debug\ledr-sim.exe --scenario dns-tcp --domain example.com --port 80 --json
```

実行後、ウィンドウ A の debug ログおよび `ledr-ui`（`Refresh` 後）で次の 3 点を確かめてください。

1. `` `View 2: プロセス系譜・通信フライトレコーダー` `` が 1 秒以内に描画され（`Refresh` 押下後に即座に描画が完了し）、`ledr-sim.exe` から `cmd.exe` を経て `powershell.exe -NoProfile -NonInteractive -EncodedCommand ...` へ至る親子系譜と、`example.com` の `DnsQuery` および `NetworkConnect` タイムラインが表示されている。
2. ウィンドウ A の `emitted ProcessStart from Kernel-Process ETW` ログで実 ETW の時刻比較（`inspected.create_time_100ns <= EventHeader.TimeStamp`：TDH から作成時刻が取れない場合でも API 補完時刻がイベント時刻以前であることを確認して同一プロセスと判定し、`parent_pid` と `command_line` を補完する処理）を通過し、両フィールドが埋まっている。
   もし時計粒度差等で `parent_pid = 0` または `command_line` 欠落が起きた場合は 1 回だけ再試行し、それでも再現する場合は Phase 1 引数記録要件との差異として「未検証差異」へ記録する。
3. `View 1` 上に `LEDR-LOTL-001` および `example.com` 接続結果に応じた通知が記録されている。

`ledr-sim.exe --scenario dns-tcp` は `--outbound-mode preemptive-only` 下では観測アラートのみを記録し凍結は行いません。
一般パス実行ファイルの初発通信凍結は第 6 章（`E2E-OPT-01`）で検証できます。

### E2E-P3-04：View 1 と View 3 の許可保存、ドメイン解決、Deny 優先、削除連動

ウィンドウ C の `ledr-ui.exe` で `Refresh` を押し、次の順で操作してください（標的は先ほど `E2E-P3-01` で使った 32 ビット版 `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` です）。

1. `View 1: アラートトリアージ` で、`E2E-P3-01` で発生した単一インスタンス側の `SysWOW64\...\powershell.exe` アラート（`LEDR-NET-SCRIPT-INTERPRETER`）を選択する。
2. 右下の `Allow Permanent Rule` カードで `Target scope (optional)` に `PREP-01` で到達確認して保存した IPv4 アドレス（`$targetIp`、確認する場合は `Get-Content -Encoding UTF8 "$env:ProgramData\LocalEDR-e2e-admin\p3_target_ip.txt"`）を入力し、`Match Authenticode signer` がオンの状態で `Allow Permanent Rule` ボタンを押す（5 秒以内に先ほどの凍結中 `$ps32Proc1` が再開して終了することを確認し、残っていれば `Stop-Process` で停止する）。
3. ウィンドウ B から 32 ビット版 PowerShell で `$targetIp` のポート `80` へ再接続し、`External connect succeeded`（終了コード `0`）が出力されて実通信が成立することを確認する。
   タイムアウト（`WSAETIMEDOUT`）は WFP 許可の証拠として扱わず、非ゼロ終了時は失敗とする。

```powershell
# ウィンドウ B（管理者 PowerShell）
if ($ps32Proc1) { Stop-Process -Id $ps32Proc1.Id -Force -ErrorAction SilentlyContinue }
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$targetIp = (Get-Content -Encoding UTF8 (Join-Path $adminDir "p3_target_ip.txt") -Raw).Trim()
$ps32 = "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
& $ps32 -NoProfile -Command "`$ErrorActionPreference = 'Stop'; `$c = [System.Net.Sockets.TcpClient]::new(); try { `$c.Connect('$targetIp', 80); Write-Output 'External connect succeeded' } finally { `$c.Close() }"
if ($LASTEXITCODE -ne 0) { throw "外部 TCP 接続に失敗しました (target=$targetIp, exit code: $LASTEXITCODE)." }
```

4. `` `View 3: 防御ポリシー・カナリア・ブラウザシールド` `` を開き、作成した `NetworkAllow` ルールが一覧にあること、右側の `カナリア・おとり配置状態` が `3/3 deployed`（3 箇所のファイルサイズ付き）であること、および `Tier 1 Protected Templates` が表示されていることを確認する。
5. **IP 許可ルールの削除と遮断復帰の確認（ドメイン許可検証との分離）**：手順 2 で作成した `$targetIp` 宛ての IP `NetworkAllow` ルールが残ったままだと、続く手順 7 の `example.com` 接続が残存 IP 許可だけで通過してしまうため、ここで手順 2 の IP `NetworkAllow` ルール行の `Delete` ボタンを押して削除する。
   削除後は単一インスタンスの 32 ビット版 PowerShell が WFP ドロップで凍結される可能性があるため、ウィンドウ B から `Start-Process -PassThru` で非同期に `$targetIp` ポート `80` へ接続試行させ、最大 6 秒待機（子側の接続タイムアウト 3 秒より長く設定）したうえで `Suspended` または `BLOCKED:AccessDenied`（`WSAEACCES`、タイムアウト `BLOCKED:TimedOut` は不可）を確認し、子プロセスを `Stop-Process -Force` で回収する。

```powershell
# ウィンドウ B（管理者 PowerShell）: 非同期起動で WFP 遮断復帰（Suspended または AccessDenied）を確認し、凍結子を回収
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$targetIp = (Get-Content -Encoding UTF8 -LiteralPath (Join-Path $adminDir "p3_target_ip.txt") -Raw).Trim()
$ps32 = "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
$chkPath = Join-Path $adminDir "p3_04_block_check.ps1"
$chkScript = @'
param([string]$OutFile, [string]$TargetHost, [string]$ResolveDomain = "")
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
if ($ResolveDomain) {
    try { [void][System.Net.Dns]::GetHostAddresses($ResolveDomain) } catch {}
}
$c = [System.Net.Sockets.TcpClient]::new()
$res = ""
try {
    $ar = $c.BeginConnect($TargetHost, 80, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(3000)) {
        $c.EndConnect($ar)
        $res = "UNEXPECTED_SUCCESS"
    } else {
        $res = "BLOCKED:TimedOut"
    }
} catch {
    $ex = $_.Exception
    while ($ex -and -not ($ex -is [System.Net.Sockets.SocketException])) { $ex = $ex.InnerException }
    $code = if ($ex -is [System.Net.Sockets.SocketException]) { $ex.SocketErrorCode.ToString() } else { $_.Exception.GetType().Name }
    $res = "BLOCKED:" + $code
} finally {
    $c.Close()
}
[System.IO.File]::WriteAllText($OutFile, $res, $utf8NoBom)
'@
[System.IO.File]::WriteAllText($chkPath, $chkScript, [System.Text.UTF8Encoding]::new($false))

$chkOut = Join-Path $adminDir "p3_04_step5_block.txt"
Remove-Item -LiteralPath $chkOut -ErrorAction SilentlyContinue
$chkProc = Start-Process -FilePath $ps32 -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$chkPath`"", "-OutFile", "`"$chkOut`"", "-TargetHost", $targetIp -PassThru
[void]$chkProc.WaitForExit(6000)
$isSuspended = $false
if (-not $chkProc.HasExited) {
    $liveProc = Get-Process -Id $chkProc.Id -ErrorAction SilentlyContinue
    if ($liveProc) {
        $isSuspended = [bool]($liveProc.Threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' })
    }
}
$rawOut = if (Test-Path -LiteralPath $chkOut) { Get-Content -Encoding UTF8 -LiteralPath $chkOut -Raw } else { $null }
$resultText = if ($rawOut) { $rawOut.Trim() } else { "" }
if (-not $chkProc.HasExited) { Stop-Process -Id $chkProc.Id -Force -ErrorAction SilentlyContinue }
Write-Output "Step5 Target=${targetIp}:80 Suspended=$isSuspended Result=$resultText"
if ($resultText -eq 'UNEXPECTED_SUCCESS') { throw "IP 許可ルール削除後に WFP 遮断へ戻りませんでした (target=$targetIp)." }
if (-not $isSuspended -and $resultText -ne 'BLOCKED:AccessDenied') { throw "WFP 拒否（Suspended または AccessDenied）を確認できませんでした (target=$targetIp, Result=$resultText)." }
```

6. ドメイン許可（検証 A）のため、View 3 の `+ Add Rule` を押して次の値を入力し `Save Rule` を押す（`Save Rule` 成功後は View 3 のルール一覧が自動再読込されるため手動 `Refresh` は不要）。
   - **Scope**：`NetworkAllow (WFP Permit)`
   - **Executable Path \***：`C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`
   - **Target IP / Domain / Path**：`example.com`
   - **SHA-256**：ウィンドウ B で `(Get-FileHash C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe).Hash.ToLowerInvariant()` を実行して得た値（または手順 4 で確認した署名ルールの `Signer Subject` と `Root Thumbprint` を控えて指定してもよい）
7. ルール行にドメイン由来ルールを示す静的な `IP-resolved` バッジ（解決済み IP を WFP へ適用するルールであることを示す表示）が付いていることを確認したうえで、ウィンドウ B から 32 ビット版 PowerShell を非同期起動して `example.com` の IPv4 候補を解決し（ETW `DNS-Client` の `FlushTimer = 1` 秒を見込んで 1.5 秒待機）、続けて各候補 IPv4 に対して 1 件ずつ非同期の直接 TCP ポート `80` 接続（プロキシ非経由、1 候補あたり最大 6 秒待機し未終了子は `Stop-Process -Force` で回収）を試行して接続成功した IPv4 を `$adminDir\p3_04_domain_ip.txt` へ記録する。

```powershell
# ウィンドウ B（管理者 PowerShell）: example.com を解決し、各 IPv4 候補へ非同期で直接 TCP:80 接続して成功 IPv4 を記録
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$targetIp = (Get-Content -Encoding UTF8 -LiteralPath (Join-Path $adminDir "p3_target_ip.txt") -Raw).Trim()
$candFile = Join-Path $adminDir "p3_04_domain_candidates.txt"
$domainIpFile = Join-Path $adminDir "p3_04_domain_ip.txt"
Remove-Item -LiteralPath $candFile, $domainIpFile -ErrorAction SilentlyContinue
$ps32 = "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"

$resolvePath = Join-Path $adminDir "p3_04_domain_resolve.ps1"
$resolveScript = @'
param([string]$OutFile)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$ipv4s = @([System.Net.Dns]::GetHostAddresses('example.com') |
    Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
    ForEach-Object { $_.IPAddressToString } | Select-Object -Unique)
if ($ipv4s.Count -gt 0) {
    [System.IO.File]::WriteAllText($OutFile, [string]::Join([Environment]::NewLine, $ipv4s), $utf8NoBom)
}
Start-Sleep -Milliseconds 1500
'@
[System.IO.File]::WriteAllText($resolvePath, $resolveScript, [System.Text.UTF8Encoding]::new($false))

$resProc = Start-Process -FilePath $ps32 -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$resolvePath`"", "-OutFile", "`"$candFile`"" -PassThru
[void]$resProc.WaitForExit(8000)
if (-not $resProc.HasExited) { Stop-Process -Id $resProc.Id -Force -ErrorAction SilentlyContinue }
$rawCands = if (Test-Path -LiteralPath $candFile) { Get-Content -Encoding UTF8 -LiteralPath $candFile -Raw } else { $null }
$ipv4s = @()
if ($rawCands) {
    $ipv4s = @($rawCands -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
}
if ($ipv4s.Count -eq 0) { throw "example.com の IPv4 アドレスを解決できませんでした。" }

$allowPath = Join-Path $adminDir "p3_04_domain_allow_check.ps1"
$allowScript = @'
param([string]$OutFile, [string]$TargetIp)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$c = [System.Net.Sockets.TcpClient]::new()
$res = ""
try {
    $ar = $c.BeginConnect($TargetIp, 80, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(3000)) {
        $c.EndConnect($ar)
        if ($c.Connected) { $res = "CONNECTED" } else { $res = "NOT_CONNECTED" }
    } else {
        $res = "TIMED_OUT"
    }
} catch {
    $ex = $_.Exception
    while ($ex -and -not ($ex -is [System.Net.Sockets.SocketException])) { $ex = $ex.InnerException }
    $code = if ($ex -is [System.Net.Sockets.SocketException]) { $ex.SocketErrorCode.ToString() } else { $_.Exception.GetType().Name }
    $res = "FAILED:" + $code
} finally {
    $c.Close()
}
[System.IO.File]::WriteAllText($OutFile, $res, $utf8NoBom)
'@
[System.IO.File]::WriteAllText($allowPath, $allowScript, [System.Text.UTF8Encoding]::new($false))

$ordered = @()
if ($targetIp -and ($ipv4s -contains $targetIp)) { $ordered += $targetIp }
$ordered += @($ipv4s | Where-Object { $_ -ne $targetIp })
$connectedIp = $null
$attempts = @()
foreach ($ip in $ordered) {
    $allowOut = Join-Path $adminDir "p3_04_step7_allow.txt"
    Remove-Item -LiteralPath $allowOut -ErrorAction SilentlyContinue
    $allowProc = Start-Process -FilePath $ps32 -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$allowPath`"", "-OutFile", "`"$allowOut`"", "-TargetIp", $ip -PassThru
    [void]$allowProc.WaitForExit(6000)
    $isSuspended = $false
    if (-not $allowProc.HasExited) {
        $liveProc = Get-Process -Id $allowProc.Id -ErrorAction SilentlyContinue
        if ($liveProc) {
            $isSuspended = [bool]($liveProc.Threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' })
        }
        Stop-Process -Id $allowProc.Id -Force -ErrorAction SilentlyContinue
    }
    $rawAllow = if (Test-Path -LiteralPath $allowOut) { Get-Content -Encoding UTF8 -LiteralPath $allowOut -Raw } else { $null }
    $allowResult = if ($rawAllow) { $rawAllow.Trim() } else { "" }
    $attempts += "${ip}:Suspended=$isSuspended,Result=$allowResult"
    if ($allowResult -eq 'CONNECTED') {
        $connectedIp = $ip
        break
    }
}
if (-not $connectedIp) {
    throw "example.com ドメイン許可下の直接 TCP:80 接続確認に失敗しました ($($attempts -join '; '))."
}
[System.IO.File]::WriteAllText($domainIpFile, $connectedIp, [System.Text.UTF8Encoding]::new($false))
Write-Output "Domain direct TCP connect succeeded: ${connectedIp}:80"
```

8. Deny 優先（検証 B）のため、再び `+ Add Rule` を押し、同じ `Executable Path *`（`C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`）と `Target IP / Domain / Path`（`example.com`）に対し `Scope` を `NetworkBlock (WFP Deny)` として `Save Rule` を押す。
9. ウィンドウ B から手順 5 で作成した `$chkPath` を使い、手順 7 で直接 TCP 接続成功を確認した同一の宛先 IPv4（`$adminDir\p3_04_domain_ip.txt`）のポート `80` へ非同期に接続試行させ（子側で `example.com` の DNS 解決も併せて実行）、`Suspended` または `BLOCKED:AccessDenied` で遮断へ戻る（`NetworkBlock > NetworkAllow`）ことを確かめ、子プロセスを回収する。

```powershell
# ウィンドウ B（管理者 PowerShell）: 手順 7 と同一 IPv4:80 に対する NetworkBlock > NetworkAllow の遮断復帰を確認（非同期）
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$domainIpFile = Join-Path $adminDir "p3_04_domain_ip.txt"
if (-not (Test-Path -LiteralPath $domainIpFile)) { throw "手順 7 で記録した p3_04_domain_ip.txt が見つかりません。" }
$domainIp = (Get-Content -Encoding UTF8 -LiteralPath $domainIpFile -Raw).Trim()
if (-not $domainIp) { throw "p3_04_domain_ip.txt が空です。" }
$ps32 = "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
$chkPath = Join-Path $adminDir "p3_04_block_check.ps1"
$chkOut = Join-Path $adminDir "p3_04_step9_block.txt"
Remove-Item -LiteralPath $chkOut -ErrorAction SilentlyContinue
$chkProc = Start-Process -FilePath $ps32 -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$chkPath`"", "-OutFile", "`"$chkOut`"", "-TargetHost", $domainIp, "-ResolveDomain", "example.com" -PassThru
[void]$chkProc.WaitForExit(6000)
$isSuspended = $false
if (-not $chkProc.HasExited) {
    $liveProc = Get-Process -Id $chkProc.Id -ErrorAction SilentlyContinue
    if ($liveProc) {
        $isSuspended = [bool]($liveProc.Threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' })
    }
}
$rawOut = if (Test-Path -LiteralPath $chkOut) { Get-Content -Encoding UTF8 -LiteralPath $chkOut -Raw } else { $null }
$resultText = if ($rawOut) { $rawOut.Trim() } else { "" }
if (-not $chkProc.HasExited) { Stop-Process -Id $chkProc.Id -Force -ErrorAction SilentlyContinue }
Write-Output "Step9 Target=${domainIp}:80 Suspended=$isSuspended Result=$resultText"
if ($resultText -eq 'UNEXPECTED_SUCCESS') { throw "NetworkBlock 追加後に WFP 遮断へ戻りませんでした (target=$domainIp)." }
if (-not $isSuspended -and $resultText -ne 'BLOCKED:AccessDenied') { throw "WFP 拒否（Suspended または AccessDenied）を確認できませんでした (target=$domainIp, Result=$resultText)." }
```

10. 最後に、検証で作成した `example.com` の `NetworkBlock` と `NetworkAllow` の各ルール行の `Delete` ボタンをすべて押し、ウィンドウ B から同じ `$chkPath` で手順 7 と同一の `$domainIp` ポート `80` へ非同期に接続試行させ、引き続き WFP 遮断（`Suspended` または `BLOCKED:AccessDenied`）が維持されることを確認して子プロセスを回収する。

```powershell
# ウィンドウ B（管理者 PowerShell）: ルール削除後に手順 7 と同一 IPv4:80 の WFP 遮断維持を確認（非同期）
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$domainIpFile = Join-Path $adminDir "p3_04_domain_ip.txt"
if (-not (Test-Path -LiteralPath $domainIpFile)) { throw "手順 7 で記録した p3_04_domain_ip.txt が見つかりません。" }
$domainIp = (Get-Content -Encoding UTF8 -LiteralPath $domainIpFile -Raw).Trim()
if (-not $domainIp) { throw "p3_04_domain_ip.txt が空です。" }
$ps32 = "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
$chkPath = Join-Path $adminDir "p3_04_block_check.ps1"
$chkOut = Join-Path $adminDir "p3_04_step10_block.txt"
Remove-Item -LiteralPath $chkOut -ErrorAction SilentlyContinue
$chkProc = Start-Process -FilePath $ps32 -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$chkPath`"", "-OutFile", "`"$chkOut`"", "-TargetHost", $domainIp -PassThru
[void]$chkProc.WaitForExit(6000)
$isSuspended = $false
if (-not $chkProc.HasExited) {
    $liveProc = Get-Process -Id $chkProc.Id -ErrorAction SilentlyContinue
    if ($liveProc) {
        $isSuspended = [bool]($liveProc.Threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' })
    }
}
$rawOut = if (Test-Path -LiteralPath $chkOut) { Get-Content -Encoding UTF8 -LiteralPath $chkOut -Raw } else { $null }
$resultText = if ($rawOut) { $rawOut.Trim() } else { "" }
if (-not $chkProc.HasExited) { Stop-Process -Id $chkProc.Id -Force -ErrorAction SilentlyContinue }
Write-Output "Step10 Target=${domainIp}:80 Suspended=$isSuspended Result=$resultText"
if ($resultText -eq 'UNEXPECTED_SUCCESS') { throw "ルール削除後に WFP 遮断へ戻りませんでした (target=$domainIp)." }
if (-not $isSuspended -and $resultText -ne 'BLOCKED:AccessDenied') { throw "WFP 拒否（Suspended または AccessDenied）を確認できませんでした (target=$domainIp, Result=$resultText)." }
```

### E2E-P3-05：実 WinHTTP NRD 取得と View 3 ドメイン診断

ウィンドウ A の `ledr-daemon.exe` を `Ctrl+C` で一旦停止し（未解決の凍結プロセスがあれば終了時に自動再開されることも確認できます）、オンライン環境がある場合は `--disable-nrd-refresh` を外して再起動してください。
オフライン環境のみで実施する場合は本項目を「未実施（オフライン環境）」と記録して `E2E-P3-06` へ進んでください。

```powershell
# ウィンドウ A（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$env:RUST_LOG = "info,ledr_sensor_win=debug,ledr_store=debug"
$debugDaemonExe = Join-Path $runDir "debug-bin\ledr-daemon.exe"
& $debugDaemonExe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --db (Join-Path $runDir "e2e.db") --nrd-cache (Join-Path $runDir "nrd-cache.txt")
```

ウィンドウ A に `refreshed daily NRD domain cache`（`feeds_succeeded >= 1` かつ `entries > 0`）が出力されたら、保存されたキャッシュを用いて `ledr-ui` の `View 3` 右下にある `NRD / Homograph Check` 欄へ次の 3 つを順に入力し、`Check` を押してドメイン診断を確認してください。
一方、後続の Track C（`E2E-PERF-01`）を正式な公開 2 フィード実測値として扱う条件は `feeds_succeeded=2` かつ `feeds_failed=0` であり、画面診断の確認条件とは分けて判定します。
公開 2 フィードのうち 1 件のみ成功した場合（`feeds_succeeded=1`、`feeds_failed=1`）でも期限内の `nrd-cache.txt` が保存され、デーモンの更新処理（`crates/ledr-daemon/src/engine/pipeline.rs`）は期限内キャッシュを再取得しないため、同じパスのまま再起動しても 2 フィード全体は再取得されません。
2 フィード取得を再試行する場合は、ウィンドウ A を `Ctrl+C` で停止してから既存の `Join-Path $runDir "nrd-cache.txt"` を削除して再起動するか、新しい `--nrd-cache` パスを指定して再起動してください（新しいパスで `feeds_succeeded=2` を得た場合、Track C で読み込ませるには `Join-Path $runDir "nrd-cache.txt"` へ上書き配置します）。
単一フィード成功のまま次へ進む場合は、合否記録表へ `feeds_succeeded=1` と `entries` 件数を明記し、Track C では「単一フィード参考値」として記録してください。

1. `paypa1.com`：期待結果は `Not in NRD` と `Homograph: paypal`
2. `google.com`：期待結果は `Not in NRD` と `No Homograph`
3. `(Get-Content -Encoding UTF8 (Join-Path $runDir "nrd-cache.txt") | Where-Object { $_ -and -not $_.StartsWith("#") } | Select-Object -First 5)` に出た実 NRD ドメイン 1 件：期待結果は `NRD (<=14d)`

確認後はウィンドウ A で `Ctrl+C` を押して停止してください。

### E2E-P3-06：応答しない実 UNC 共有での 3 秒停止予算と WAL チェックポイント

期限内の `nrd-cache.txt` が存在しない状態で、到達不能な UNC 共有（たとえば `file://198.51.100.1/share/nrd.txt`、ルータが即座に ICMP Unreachable を返す場合は応答を返さない実 LAN 内の未応答 IP または停止中ホストの共有パス）を指定してウィンドウ A で起動してください。

```powershell
# ウィンドウ A（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$env:RUST_LOG = "ledr_store=debug,ledr_daemon=info"
$debugDaemonExe = Join-Path $runDir "debug-bin\ledr-daemon.exe"
& $debugDaemonExe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --db (Join-Path $runDir "nrd_hang.db") --nrd-cache (Join-Path $runDir "nrd-hang-cache.txt") --nrd-feed-url file://198.51.100.1/share/nrd.txt
```

次の 5 ステップで 3 秒停止予算と WAL トランケート先行完了を確認してください。

1. ウィンドウ A に `refreshed daily NRD domain cache` と `daily NRD feed refresh failed` の**どちらも出ていない**（`ledr-nrd-refresh` スレッドが I/O 待機中）ことを確かめる。
2. ウィンドウ B でマーカー用のイベント書き込みを発生させ、停止前に `-wal` ファイルサイズが 0 バイト超になっていることを確認する。

```powershell
# ウィンドウ B（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
.\target\debug\ledr-sim.exe --scenario lotl --json
Start-Sleep -Seconds 2
Get-Item (Join-Path $runDir "nrd_hang.db-wal") -ErrorAction SilentlyContinue | Select-Object Name, Length
```

3. `Length > 0` を確認したら直ちにウィンドウ A で `Ctrl+C` を押し、約 3 秒前後でハングせずシェルプロンプトへ制御が戻ることを確認する。
4. ウィンドウ A の標準出力ログで、`completed wal_checkpoint(TRUNCATE)` の記録時刻が `shutdown budget exhausted waiting for background NRD refresh thread; detaching thread` の記録時刻より**前**に出力されていることを確認する。
5. 停止後にウィンドウ B で `-wal` が 0 バイト（または消去）になっており、終了直前の `lotl` マーカー行が `nrd_hang.db` へ永続化されていることを SQLite で直接確かめる。

```powershell
# ウィンドウ B（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Get-Item (Join-Path $runDir "nrd_hang.db-wal") -ErrorAction SilentlyContinue | Select-Object Name, Length
$nrdHangDb = Join-Path $runDir "nrd_hang.db"
python -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print('processes=', c.execute('SELECT count(*) FROM processes').fetchone()[0]); print(c.execute('SELECT pid, exe_path, command_line FROM processes ORDER BY created_at_ms DESC, process_instance_id DESC LIMIT 3').fetchall())" $nrdHangDb
```

### E2E-P3-07：`taskkill /F` 強制終了時の動的 WFP フィルタ 0 件自動消去

ウィンドウ A で再び `--disable-nrd-refresh` 付きの Debug デーモンを起動し、動的フィルタが登録された状態を再現してください。

```powershell
# ウィンドウ A（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$env:RUST_LOG = "info,ledr_sensor_win=debug,ledr_store=debug"
$debugDaemonExe = Join-Path $runDir "debug-bin\ledr-daemon.exe"
& $debugDaemonExe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --disable-nrd-refresh --db (Join-Path $runDir "e2e.db")
```

ログに初期化完了が出たら、ウィンドウ B で `ledr-daemon.exe` を `taskkill /F` で強制終了させ、BFE フィルタの自動消去と外部通信の復旧を確認してください。

```powershell
# ウィンドウ B（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$procs = @(Get-Process ledr-daemon -ErrorAction Stop)
if ($procs.Count -ne 1) { throw "期待と異なる ledr-daemon プロセス数です: $($procs.Count)" }
taskkill /F /PID $procs[0].Id
if ($LASTEXITCODE -ne 0) { throw "taskkill に失敗しました。" }
Start-Sleep -Seconds 1
$afterKillFiltersXml = Join-Path $runDir "filters_after_kill.xml"
netsh wfp show filters "file=$afterKillFiltersXml"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $afterKillFiltersXml)) {
    throw "netsh wfp show filters に失敗しました。"
}
Select-String -Path $afterKillFiltersXml -Pattern "LocalEDR" -ErrorAction Stop

$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$targetIpFile = Join-Path $adminDir "p3_target_ip.txt"
$targetIp = $null
if (Test-Path -LiteralPath $targetIpFile) {
    $targetIp = (Get-Content -Encoding UTF8 $targetIpFile -Raw).Trim()
}
if (-not $targetIp) {
    $ipv4List = @([System.Net.Dns]::GetHostAddresses("example.com") | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
    foreach ($addr in $ipv4List) {
        $ipStr = $addr.IPAddressToString
        $probeClient = [System.Net.Sockets.TcpClient]::new()
        try {
            $ar = $probeClient.BeginConnect($ipStr, 80, $null, $null)
            if ($ar.AsyncWaitHandle.WaitOne(3000)) {
                $probeClient.EndConnect($ar)
                if ($probeClient.Connected) { $targetIp = $ipStr; break }
            }
        } catch {} finally { $probeClient.Close() }
    }
    if (-not $targetIp) { throw "example.com の TCP:80 到達可能な IPv4 アドレスを解決できませんでした。" }
}
$ps32 = "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
& $ps32 -NoProfile -Command "`$ErrorActionPreference = 'Stop'; `$c = [System.Net.Sockets.TcpClient]::new(); try { `$c.Connect('$targetIp', 80); Write-Output 'External connect succeeded' } finally { `$c.Close() }"
if ($LASTEXITCODE -ne 0) { throw "強制終了後の外部 TCP 接続回復に失敗しました (target=$targetIp, exit code: $LASTEXITCODE)." }
```

`Select-String` の一致件数が **0 件** になり、そのまま 32 ビット版 PowerShell から到達可能な `$targetIp` ポート `80` へ `External connect succeeded`（終了コード `0`）で実接続できれば、動的セッション（`FWPM_SESSION_FLAG_DYNAMIC`）による異常終了時の通信不能回避は合格です（タイムアウトは許可または回復の証拠とみなしません）。

## 4. Track B：Phase 4 実機 Chrome E2E 検証（FU-E2E-02）

Track B はローカル HTTP サーバと隔離テストドメイン（`.localedr.invalid`）を使った確認を主軸とし、最後の `E2E-P4-06` の事前 WFP 遮断確認のみ `93.184.216.34:80`（オフライン環境ではその旨を明記してループバック代替）を使用する。
ウィンドウ A で先のデーモンが動いている場合は `Ctrl+C` で一旦停止したうえで、開発ホスト PC 上の他アプリを誤凍結しないよう `--outbound-mode preemptive-only --resume-suspended-on-shutdown` を付けて Phase 4 用の Debug デーモンを起動してください。

```powershell
# ウィンドウ A（64 ビット版管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$nrdUrl = ([Uri](Join-Path $runDir "nrd-test-feed.txt")).AbsoluteUri
$env:RUST_LOG = "info,ledr_sensor_win=debug,ledr_store=debug"
$debugDaemonExe = Join-Path $runDir "debug-bin\ledr-daemon.exe"
& $debugDaemonExe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --db (Join-Path $runDir "ledr-p4.db") --nrd-feed-url $nrdUrl --nrd-cache (Join-Path $runDir "nrd-test-cache.txt")
```

起動ログに初期化完了と `nrd-test-feed.txt` の読み込み（`entries=1`）が出たら次に進みます。

### E2E-P4-00：Native Messaging 登録、View 3 診断表示、Chrome 拡張疎通

まずウィンドウ C（通常ユーザー 64 ビット）でユーザー単位の Native Messaging 登録を実行し、`status` を確認してください。
ルート 3 でも第 2 章の `PREP-01` から `PREP-03` を事前に完了している前提です（`PREP-03` が未実施の場合は先に実行して既存 `HKCU` 設定を退避してください）。

```powershell
# ウィンドウ C（64 ビット版通常ユーザー PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$debugBridgeExe = Join-Path $runDir "debug-bin\ledr-bridge-nm.exe"
$debugUiExe = Join-Path $runDir "debug-bin\ledr-ui.exe"
Set-Location $repoRoot
& $debugBridgeExe setup --scope user --browsers chrome,edge --bridge-exe $debugBridgeExe --ui-exe $debugUiExe
if ($LASTEXITCODE -ne 0) { throw "ledr-bridge-nm setup --scope user に失敗しました。" }
& $debugBridgeExe status --scope all
if ($LASTEXITCODE -ne 0) { throw "ledr-bridge-nm status に失敗しました。" }
```

管理者権限での `--scope machine`（`HKLM`）登録も検証する場合は、ウィンドウ B（管理者 64 ビット）で既存の `HKLM` 64 ビットおよび 32 ビット両ビューと `C:\ProgramData\LocalEDR\native-messaging` を管理者専用 ACL フォルダへ退避したうえで登録してください。
スキップする場合は次のブロックを飛ばして構いません。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell・任意で --scope machine を検証する場合のみ）
if (-not [Environment]::Is64BitProcess) {
    throw "64 ビット版 PowerShell で実行してください。"
}
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
Set-Location $repoRoot
$reg64 = "$env:SystemRoot\System32\reg.exe"
$reg32 = "$env:SystemRoot\SysWOW64\reg.exe"
$adminBackupDir = Join-Path $env:ProgramData ("LocalEDR-e2e-admin-backup-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $adminBackupDir -ErrorAction Stop | Out-Null
$backupItem = Get-Item -LiteralPath $adminBackupDir -Force
if (-not $backupItem.PSIsContainer -or ($backupItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "管理者専用退避フォルダがリパースポイントのため中止します。"
}
$ownerSid = (Get-Acl -LiteralPath $adminBackupDir).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($ownerSid -notin @("S-1-5-32-544", "S-1-5-18")) {
    throw "管理者専用退避フォルダの所有者が Administrators または SYSTEM ではないため中止します: Owner=$ownerSid"
}
icacls $adminBackupDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-18:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "管理者専用退避フォルダの ACL 設定に失敗しました。" }
[System.IO.File]::WriteAllText((Join-Path $adminDir "admin-backup.txt"), $adminBackupDir, [System.Text.UTF8Encoding]::new($false))

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
            throw "HKLM レジストリ退避に失敗したため中止します: $($item.Key)"
        }
    }
}
if (Test-Path "C:\ProgramData\LocalEDR\native-messaging") {
    Copy-Item -Recurse -Force -ErrorAction Stop "C:\ProgramData\LocalEDR\native-messaging" (Join-Path $adminBackupDir "machine-native-messaging")
}
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$debugBridgeExe = Join-Path $runDir "debug-bin\ledr-bridge-nm.exe"
$debugUiExe = Join-Path $runDir "debug-bin\ledr-ui.exe"
& $debugBridgeExe setup --scope machine --browsers chrome,edge --bridge-exe $debugBridgeExe --ui-exe $debugUiExe
if ($LASTEXITCODE -ne 0) { throw "ledr-bridge-nm setup --scope machine に失敗しました。" }
& $debugBridgeExe status --scope all
```

次に、ウィンドウ C で `ledr-ui.exe` を開き（未起動なら `Start-Process (Join-Path $runDir "debug-bin\ledr-ui.exe")`、起動済みなら `Refresh`）、`` `View 3: 防御ポリシー・カナリア・ブラウザシールド` `` 右下のブラウザシールド欄を確認してください。

- `Daemon IPC` が `Connected` を表示している。
- `Native Messaging` が登録スコープ（`HKCU`、`HKLM`、または `HKCU+HKLM`）と登録ブラウザ（`Chrome`、`Edge`）を表示している。
- ブラウザ別詳細行（`.browser-detail-row`）の **Chrome 行と Edge 行のそれぞれ** に、対応する `manifest_path` と `Valid` が併記され、他ブラウザのパスが混入していない（既定 2 ディレクトリ `%LOCALAPPDATA%\LocalEDR\native-messaging` と `C:\ProgramData\LocalEDR\native-messaging` の外へ `--manifest-dir` で配置した場合は、仕様どおりファイル I/O を行わず `unverified` と表示される）。
- `Extension ID` が `ecelachfiiiiiibpjeomfncgpegbpanh` を表示し、`URI Protocol` が `ledr://` の登録スコープを表示している。

なお、現行の `ledr-bridge-nm` は `HKLM` の 32 ビットレジストリビュー（`KEY_WOW64_32KEY`）に対応していないため（`FU-P4-01`）、`HKLM` のみで 32 ビットビューに旧キーが先行存在すると View 3 側の診断は 32 ビット側を優先して検出します。

続いてウィンドウ C で既存の検証用 HTTP サーバを整理したうえでローカル HTTP サーバ（`127.0.0.1:8765`）を起動し、疎通確認後に隔離プロファイルと名前解決ルール付きで Chrome を `Start-Process` 起動してください（シェルを占有しません）。
非 `https` 環境でも `navigator.clipboard.writeText` を動作させ、かつオリジン間の Mixed Content 誤遮断を防ぐため、テストで使う全 7 つの `.localedr.invalid` オリジンを `--unsafely-treat-insecure-origin-as-secure` へ列挙します。

```powershell
# ウィンドウ C（64 ビット版通常ユーザー PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()

$serverPidFile = Join-Path $runDir "server-pid.txt"
if (Test-Path -LiteralPath $serverPidFile) {
    $oldPid = [int](Get-Content -Encoding UTF8 -LiteralPath $serverPidFile -Raw).Trim()
    Stop-Process -Id $oldPid -Force -ErrorAction SilentlyContinue
}
$pyCmd = Get-Command python -ErrorAction Stop
if ($pyCmd.Source -match '\\WindowsApps\\python\.exe$') {
    throw "Microsoft Store の python.exe スタブが優先されています。実体 Python 3 を PATH の先頭へ設定してください。"
}

$serveScript = @"
import http.server, sys
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
$serverProc = Start-Process -FilePath $pyCmd.Source -ArgumentList @("`"$servePath`"", "`"$(Join-Path $runDir 'site')`"") -PassThru -WindowStyle Minimized
[System.IO.File]::WriteAllText($serverPidFile, [string]$serverProc.Id, [System.Text.UTF8Encoding]::new($false))

Start-Sleep -Seconds 1
$beacon = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8765/beacon" -TimeoutSec 3
if ($beacon.StatusCode -ne 200) { throw "ローカル HTTP サーバの /beacon 応答が異常です: $($beacon.StatusCode)" }

$chromeCandidates = @(
    "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "${env:LOCALAPPDATA}\Google\Chrome\Application\chrome.exe"
)
$chromeExe = $chromeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $chromeExe) {
    throw "chrome.exe が見つかりません（Program Files / Program Files (x86) / LOCALAPPDATA を確認してください）。"
}

$secureOrigins = @(
    "http://clickfix-sim.localedr.invalid:8765",
    "http://pastejack-sim.localedr.invalid:8765",
    "http://nrd-sim.localedr.invalid:8765",
    "http://login-paypa1.localedr.invalid:8765",
    "http://safe-sim.localedr.invalid:8765",
    "http://c2-sim.localedr.invalid:8765",
    "http://blocked-test.localedr.invalid:8765"
) -join ","

Start-Process -FilePath $chromeExe -ArgumentList @(
    "--user-data-dir=`"$runDir\chrome-profile`"",
    "--host-resolver-rules=`"MAP *.localedr.invalid 127.0.0.1`"",
    "--unsafely-treat-insecure-origin-as-secure=`"$secureOrigins`"",
    "chrome://extensions"
)
```

開いた Chrome ウィンドウで次の 3 点を確かめてください。
なお、Microsoft Edge の実ブラウザ動作も任意で確認したい場合は、同じ手順で `edge://extensions` へ `extensions\ledr-chrome-mv3` を読み込んで `Ping` 疎通を確認できます。

1. `chrome://extensions` 右上のデベロッパーモードを有効にし、「パッケージ化されていない拡張機能を読み込む」から `$repoRoot\extensions\ledr-chrome-mv3` を選択する。
2. 読み込まれた拡張の ID が `ecelachfiiiiiibpjeomfncgpegbpanh` と完全に一致している。
3. ツールバーの拡張アイコンからポップアップ `LocalEDR Browser Shield` を開き、`Ping` ボタンを押して `Daemon` がオンライン応答する。

### E2E-P4-01 から E2E-P4-05：ブラウザ防御と検知アラートの検証

[phase4-browser-test.html](fixtures/phase4-browser-test.html) には領域 1 から 6 までが配置されている。
`ledr-ui` はタブを切り替えただけでは最新スナップショットを再取得しないため、各ケースを実行したあと毎回 `ledr-ui` 上部バーの `Refresh` ボタンを押して `View 1: アラートトリアージ` を確認してください。
また `E2E-P4-01` と `E2E-P4-02` は同じ `ClickFixPastejacking` イベント種別を送出するため、デーモン側の 30 秒重複抑止（`(BrowserSecurityEventType, normalized_url)`）に当たらないよう表の指定どおり別ホスト名（`clickfix-sim` と `pastejack-sim`）で開いてください。

| ID | Chrome で開く URL と操作 | 期待結果（ブラウザと `ledr-ui`） |
| :--- | :--- | :--- |
| `E2E-P4-01` | `http://clickfix-sim.localedr.invalid:8765/phase4-browser-test.html` を開き、領域 1 の `Copy Verification Command` を押下する | ブラウザ内 Shadow DOM に ClickFix 警告が表示され、OS トースト通知は発火せず（`L-19`）、`ledr-ui` の `Refresh` 後に View 1 へ `LAYER_4_BROWSER`（`ClickFixPastejacking`）が記録される |
| `E2E-P4-02` | `http://pastejack-sim.localedr.invalid:8765/phase4-browser-test.html` を開き、領域 2（`echo hello-localedr`）を選択して `Ctrl+C` を押し、続けて領域 3（`Copy Snippet` と通常選択コピー）を試す | 領域 2 では選択内容とクリップボード値の不一致により Pastejacking 警告が表示されて View 1 に記録され、領域 3 では一般開発コマンド（`cargo test`）のコピーが一致するためブラウザ警告もアラート記録も発火しない（`L-15`） |
| `E2E-P4-03` | `http://nrd-sim.localedr.invalid:8765/phase4-browser-test.html` を開き、領域 4 の `Password` 欄へフォーカスして 1 文字入力する | ブラウザ内に NRD 警告が表示され、View 1 に `NrdPasswordWarning` が記録される（外部へのドメイン問い合わせは行われない） |
| `E2E-P4-04` | `http://login-paypa1.localedr.invalid:8765/phase4-browser-test.html` を開き、領域 4 の `Password` 欄へフォーカスして 1 文字入力する | ブラウザ内にブランド `paypal` のホモグラフ警告が表示され、View 1 に `HomographWarning` が記録される |
| `E2E-P4-05` | 領域 5 の `Fetch safe-sim.localedr.invalid`、`Fetch c2-sim.localedr.invalid`、`Fetch blocked-test.localedr.invalid` を順に押下する | `safe-sim` は `HTTP 200` で成功し、静的ルール（`dnr_static.json`）に一致する `c2-sim` と `blocked-test` は即座に遮断されて View 1 に `DnrBlockedRequest` が記録される |

### E2E-P4-06：ダウンロード由来記録、移動後の事前 WFP 遮断（`L-18`）、3 段階 MOTW 紐付け

`E2E-P4-06` ではブラウザからのダウンロード完了通知とデーモン側の SHA-256 算出が非同期で動作するため、ファイルの移動前に必ず `ledr-ui` で記録完了を確認してください。
（領域 6 には `.cmd` サンプルリンク `localedr-e2e-sample.cmd` も用意されているため、必要に応じて同様にダウンロード記録だけ追加確認できます。）

1. Chrome 上の検証ページ領域 6 にある `Download localedr-e2e-sample.exe` をクリックし、ダウンロード完了を待つ。
2. ウィンドウ C でダウンロード先（既定は `$env:USERPROFILE\Downloads\localedr-e2e-sample.exe`）の `:Zone.Identifier` ADS を確認し、あわせて `ledr-ui` 上部の `Refresh` を押す。

```powershell
# ウィンドウ C（通常ユーザー PowerShell）
$downloadedExe = "$env:USERPROFILE\Downloads\localedr-e2e-sample.exe"
Get-Content -LiteralPath $downloadedExe -Stream Zone.Identifier
```

3. `ZoneId=3` が確認でき、`ledr-ui` の `` `View 2: プロセス系譜・通信フライトレコーダー` ``（左ペイン `All` 選択で `Scope: All Processes`）の `Canary & Downloads` タブへ元パスと短縮 `sha256` が記録され、View 3 の `Tracked Downloads` 件数が増えていることを確認してから、ウィンドウ B でファイルを `Downloads` や `Temp` 以外の非高リスクパス（`%LOCALAPPDATA%\LocalEDR-e2e-moved-<GUID>`）へ移動して起動試験を行う（`C:\Temp` 配下へ移動すると `HighRiskPath` 判定だけで遮断されてしまい、MOTW 起因の `L-18` 事前遮断を単独で検証できないため）。

```powershell
# ウィンドウ B（管理者 PowerShell）: View 2 での記録確認後に実行
$movedDir = Join-Path $env:LOCALAPPDATA ("LocalEDR-e2e-moved-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $movedDir -ErrorAction Stop | Out-Null
$movedExe = Join-Path $movedDir "localedr-e2e-sample.exe"
Move-Item -LiteralPath "$env:USERPROFILE\Downloads\localedr-e2e-sample.exe" -Destination $movedExe -Force

# L-18 確認: 高リスクパス外へ移動後でも MOTW により起動時事前 WFP ブロックが適用され、外部 TCP が遮断される
$simNet = Start-Process -FilePath $movedExe -ArgumentList "--scenario", "dns-tcp", "--domain", "93.184.216.34", "--port", "80", "--hold-ms", "30000", "--json" -PassThru
Start-Sleep -Seconds 3
Get-Process -Id $simNet.Id -ErrorAction SilentlyContinue | Select-Object Id, ProcessName
```

4. `ledr-ui` で `Refresh` を押し、`View 1: アラートトリアージ` に `localedr-e2e-sample.exe` の `LEDR-NET-HIGH-RISK-PATH`（外部 TCP 遮断）と `Browser Origin (MOTW)` カード（`Origin URL`、`Source`、一致ダウンロード行）が表示されていることを確認する（プロセスが凍結残留していれば `Allow Once` で解放し、確認後に `$simNet` を停止する）。

```powershell
# ウィンドウ B（管理者 PowerShell）: 手順 4 の確認後に $simNet を停止する
if ($simNet) { Stop-Process -Id $simNet.Id -Force -ErrorAction SilentlyContinue }
```

5. 続けて同じ移動後バイナリからカナリア開錠シナリオを起動し、3 段階 MOTW 紐付けによる View 1 と View 2 の表示を確認する。

```powershell
# ウィンドウ B（管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$simMotw = Start-Process -FilePath $movedExe -ArgumentList "--scenario", "cookies-open", "--base-dir", "`"$(Join-Path $runDir 'canary_dir')`"", "--hold-ms", "120000", "--json" -PassThru
Start-Sleep -Seconds 2
(Get-Process -Id $simMotw.Id).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
```

6. `ledr-ui` で `Refresh` を押し、次の 3 点をすべて確かめてから `Allow Once` で再開し、残待機中のプロセスと一時移動ディレクトリ `$movedDir` を削除する。
   - `View 1` に `localedr-e2e-sample.exe` の `LEDR-CANARY-COOKIE_DB` アラートと `Browser Origin (MOTW)` カードが表示されている。
   - `View 2` のプロセスツリー上に `MOTW` バッジが表示され、該当プロセスを選択するとインスペクタへ `Origin URL (MOTW)` と `download_origins` 行（`referrer_url` と短縮 `sha256`）が表示される。
   - `Allow Once` 押下から 5 秒以内に `localedr-e2e-sample.exe` が凍結解除される。

```powershell
# ウィンドウ B（管理者 PowerShell）: E2E-P4-06 確認後の片付け
if ($simMotw) { Stop-Process -Id $simMotw.Id -Force -ErrorAction SilentlyContinue }
if ($movedDir -and (Test-Path -LiteralPath $movedDir)) { Remove-Item -Recurse -Force -LiteralPath $movedDir -ErrorAction SilentlyContinue }
```

### E2E-P4-07：ブラウザアラートの解決操作制約確認

`View 1` で未解決の `LAYER_4_BROWSER` アラート（`E2E-P4-01` から `E2E-P4-05` のいずれか）を選択し、次の操作制約を確かめてください。

1. `Allow Permanent Rule` ボタンが無効化されている（プロセス紐付きのないブラウザイベントでは永続許可を作れない）。
2. `Terminate & Block` 側の `Save NetworkBlock policy rule (WFP)` も無効であり、`Acknowledge` ボタン（または `add_block_rule: false` の終了操作）のみが有効である。
3. 残っているすべての `LAYER_4_BROWSER` アラートを `Acknowledge` ボタンで解決状態へ遷移させる。

## 5. Track C：UI 完全終了（L-08）と Release 常駐性能計測（E2E-PERF-01）

Track C では性能基準（`PrivateWorkingSetSize <= 20.0 MB` 必須、`WorkingSet64` 後半前半差 `<= +1.0 MB`、100.0 MB 以上スパイク 0 回、高負荷ピーク `< 64.34 MB`、アイドル `AvgCpuPercent < 0.5%`、高負荷とバースト `< 1%`、`決定記録 L-24`）を正確に測るため、必ず Release ビルド（`target\release\`）を使います。
第 2 章の安全前提 4（`SEC_0003` パイプサーバ照合）で説明したとおり、先に検証用 Chrome ウィンドウと開いている `ledr-ui.exe` を閉じ、ウィンドウ A の Debug 版 `ledr-daemon.exe` を `Ctrl+C` で終了してから Release 版へ切り替えてください。
なお、Track C では `ledr-ui.exe` を直接起動するため `PREP-03` で登録した `ledr://`（Debug 版）は使用しませんが、Release 版 UI を URI 起動させたい場合は `.\target\release\ledr-ui.exe --register-uri` を実行してから進めます。

また、Track 2 の `ledr-auth-helper.exe` 分離（`決定記録 L-23`）ではハードリンク悪用を防ぐため `nNumberOfLinks == 1` を厳格に検証します。
一方、Cargo のビルド成果物 `target\release\ledr-auth-helper.exe` はビルドキャッシュ（`target\release\build\ledr-auth-helper\...\out\ledr_auth_helper.exe`）とハードリンクされており `nNumberOfLinks == 2` となるため、`target\release\` から `ledr-daemon.exe` を直実行するとワーカー起動が拒否され 30 秒サーキットブレーカが動作します。
Release 版を直接起動して検証する際は、以下のように新しいステージングディレクトリへ `Copy-Item` で複製し、ハードリンク数が `1`（`Links = 1`）であることを確認した上でステージング先から起動してください（`nNumberOfLinks == 1` の厳格検査自体は維持します）。

```powershell
# ウィンドウ A（64 ビット版管理者 PowerShell）: Chrome と Debug 版を終了したあとに実行
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$env:RUST_LOG = "info"

$stageBinDir = Join-Path $runDir "release-bin"
New-Item -ItemType Directory -Path $stageBinDir -Force | Out-Null
foreach ($exeName in @("ledr-daemon.exe", "ledr-auth-helper.exe", "ledr-ui.exe", "ledr-bridge-nm.exe", "ledr-sim.exe")) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "target\release\$exeName") -Destination (Join-Path $stageBinDir $exeName) -Force
}
# fsutil hardlink list (Join-Path $stageBinDir "ledr-auth-helper.exe") が 1 行のみであることを確認する
$daemonExe = Join-Path $stageBinDir "ledr-daemon.exe"

$realNrdCache = Join-Path $runDir "nrd-cache.txt"
if (Test-Path -LiteralPath $realNrdCache) {
    # ルート 1・ルート 2（オンライン実フィード）: --nrd-feed-url を渡すと実キャッシュが 1 件のテストフィードで上書きされるため、--disable-nrd-refresh で実キャッシュをそのまま読み込む
    $nrdEntryCount = @(Get-Content -Encoding UTF8 -LiteralPath $realNrdCache | Where-Object { $_ -and -not $_.StartsWith("#") }).Count
    Write-Output "実 NRD キャッシュを読み込んで E2E-PERF-01 を起動します: $realNrdCache (entries=$nrdEntryCount)"
    Write-Output "※ 正式な公開 2 フィード実測値とするには E2E-P3-05 ログで feeds_succeeded=2, feeds_failed=0 を確認済みであること（feeds_succeeded=1 の場合は単一フィード参考値として記録）。"
    & $daemonExe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --disable-nrd-refresh --db (Join-Path $runDir "perf.db") --nrd-cache $realNrdCache
} else {
    # ルート 3 単独またはオフライン環境: 1 件のテストキャッシュで起動し、合否記録表では「ルート 3 軽量参考値」または「オフライン参考値」として正式実測値と区別する
    Write-Warning "実 nrd-cache.txt が未作成のため 1 件のテスト NRD キャッシュで起動します。合否記録表にはルート 3 軽量参考値（またはオフライン参考値）として記録してください。"
    $nrdUrl = ([Uri](Join-Path $runDir "nrd-test-feed.txt")).AbsoluteUri
    & $daemonExe --foreground --dev-bypass-auth --outbound-mode preemptive-only --resume-suspended-on-shutdown --db (Join-Path $runDir "perf.db") --nrd-feed-url $nrdUrl --nrd-cache (Join-Path $runDir "nrd-test-cache.txt")
}
```

正式な `E2E-PERF-01`（`PrivateWorkingSetSize <= 20.0 MB` 必須および `WorkingSet64` スパイクと単調増加監視基準）は、`E2E-P3-05` の `refreshed daily NRD domain cache` ログで `feeds_succeeded=2` かつ `feeds_failed=0` を確認済みの実 `nrd-cache.txt` を `--disable-nrd-refresh` で読み込んだ状態で計測します。
公開フィードの片方が失敗した場合でも `nrd-cache.txt` 自体は `entries > 0` で保存されるため、`E2E-P3-05` が `feeds_succeeded=1` で終わったときは合否記録表へ「単一フィード参考値（`feeds_succeeded=1`、`entries=...`）」と明記してください。
ルート 3 単独やオフライン環境で `nrd-cache.txt` が未作成の場合は 1 件の `nrd-test-cache.txt` が使われるため、合否記録表には必ず「ルート 3 軽量参考値（NRD 1 件）」または「オフライン参考値」と明記して正式な公開 2 フィード実測値と区別してください。
計測を始める前に、ウィンドウ A のログへ `loaded local NRD cache from disk` または `refreshed daily NRD domain cache`（どちらも `entries > 0`）が出力されたことを確認します。

### E2E-UI-01：`ledr-ui` 閉鎖時の 0 プロセス終了（`L-08`）

ウィンドウ C で `Join-Path $runDir "release-bin\ledr-ui.exe"`（または `.\target\release\ledr-ui.exe`）を起動して `Daemon: Connected` と画面描画を確認したあと、ウィンドウ右上の閉じるボタンで終了し、直後にプロセス残存ゼロを確認してください。

```powershell
# ウィンドウ C（通常ユーザー PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$stageUiExe = Join-Path $runDir "release-bin\ledr-ui.exe"
if (Test-Path -LiteralPath $stageUiExe) { & $stageUiExe } else {
    $repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
    Set-Location $repoRoot
    .\target\release\ledr-ui.exe
}
# 画面表示を確認したらウィンドウ右上の閉じるボタンで終了し、以下を実行する
Get-Process ledr-ui -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" | Where-Object { $_.CommandLine -match 'ledr-ui|LocalEDR' } | Select-Object ProcessId, CommandLine
```

両方のコマンドで出力が 0 件であれば `L-08` は合格です。

### E2E-PERF-01：`ledr-daemon` 常駐メモリ（`PrivateWorkingSetSize` 20 MB 以下）と CPU 基準

ウィンドウ B でリポジトリ同梱のプロファイラ `scripts/profile_daemon_memory.ps1` を実行し、Release 版 `ledr-daemon.exe` の `PrivateWorkingSetSize`、`WorkingSet64`（`Shared == 0/1` ページ内訳とスナップショット）、および `AvgCpuPercent` を取得してください（単位は `1 MB = 1 MiB = 1,048,576` バイト）。
[implementation-plan.md](implementation-plan.md) の計画基準に沿う 10 分間アイドル計測では `-DurationSec 600`（高負荷確認では `-DurationSec 60`）を指定します。

```powershell
# ウィンドウ B（管理者 PowerShell）: 600 秒アイドル計測と 60 秒高負荷計測
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$daemonProc = Get-Process ledr-daemon -ErrorAction Stop
$dbPath = Join-Path $runDir "perf.db"

# 1. 600 秒アイドル計測
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\profile_daemon_memory.ps1 `
    -Pid $daemonProc.Id -DbPath $dbPath -DaemonExePath $daemonProc.Path `
    -Mode idle -DurationSec 600 -OutDir (Join-Path $runDir "perf_idle")

# 2. 60 秒高負荷計測（ブラウザ複数タブ閲覧と別ウィンドウでの cargo build --locked を併用）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\profile_daemon_memory.ps1 `
    -Pid $daemonProc.Id -DbPath $dbPath -DaemonExePath $daemonProc.Path `
    -Mode load -DurationSec 60 -OutDir (Join-Path $runDir "perf_load")
```

`profile_daemon_memory.ps1` は 200 ms 間隔の `GetProcessMemoryInfo` と `GetProcessTimes` ポーリングに加え、10 秒後、60 秒後、終了直前、ピーク `+2.0 MB` 更新時、および `+5.0 MB` 急増時に `QueryWorkingSetEx` で `Shared == 0/1` の 4 KiB ページ内訳スナップショットを保存し、`timeseries.csv`、`memory-profile-summary.json`、および `snapshots/*.json` を出力します（`-AnalyzePeOnly` を指定すると PE 静的および遅延インポートの推移的依存解析のみを単体実行できます）。

合格判定は `memory-profile-summary.json`（`track_gates.e2e_perf_01_mode_pass -eq $true`、欠測時は `$null` で判定不能扱い）の以下の全条件で行います（1 件の `nrd-test-cache.txt` で計測した場合は「ルート 3 軽量参考値」または「オフライン参考値」として区分記録します）。

- **600 秒アイドル必須基準（`-Mode idle`）**：`steady_window_60s_to_end.median_private_ws_mb <= 20.0`、`latest_private_ws_mb <= 20.0`、`AvgCpuPercent < 0.5%`、`spikes_ge_100mb_sampled_count == 0` かつ `os_peak_crossed_100mb_during_interval == false`、および定常後半（`330..600s`）と前半（`60..330s`）の `WorkingSet64` / `PrivateWorkingSetSize` 中央値差 `<= +1.0 MB`。
- **参考指標（`WorkingSet64` OS 共有ページ下限）**：Windows 11 環境では OS 共有ページ（`Shared == 1`）のみで約 `14.5 MB`（Stage 3 実測 `14.51–14.70 MB`）を占有するため、`WorkingSet64` の絶対値自体は参考値（`track_gates.legacy_reference_ws_le_20mb`）として記録し、リークおよび異常スパイクがないことを後半前半中央値差と 100 MB 未満維持で判定する（`決定記録 L-24`）。
- **60 秒高負荷基準（`-Mode load`）**：ブラウザ複数タブ閲覧と `cargo build --locked` の併用負荷下で `interval_peak_working_set_mb < 64.34`、`spikes_ge_100mb_sampled_count == 0` かつ `os_peak_crossed_100mb_during_interval == false`、かつ `AvgCpuPercent < 1.0%` であること（Stage 1 未改変ベースラインの 60 秒高負荷実測は `0.5475%`、Stage 3 実測は `0.5952%`）。

高負荷計測の直後（または併用中）に次のコマンドでダミー `Cookies` アクセスを走らせ、高優先度レーンのトースト応答が 1 秒以内に返ることを確認したあと、凍結したプロセスを終了してください。
負荷計測の出力をファイルへ保存する場合は、後続の `E2E-OPT-01` で上書きされないよう `perf_load_trackc.txt` のようにトラック名入りのファイル名で分けて保存してください。

```powershell
# ウィンドウ B（管理者 PowerShell）: 高負荷計測中の高優先度応答確認
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$perfSim = Start-Process -FilePath (Join-Path $repoRoot "target\debug\ledr-sim.exe") -ArgumentList "--scenario", "cookies-open", "--base-dir", "`"$(Join-Path $runDir 'canary_dir')`"", "--hold-ms", "30000", "--json" -PassThru
Start-Sleep -Seconds 2
(Get-Process -Id $perfSim.Id -ErrorAction SilentlyContinue).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
Stop-Process -Id $perfSim.Id -Force -ErrorAction SilentlyContinue
```

## 6. 専用環境向けの追加検証（検証専用 PC または VM 向け）

本章の 3 項目は日常利用中のホスト PC に影響を及ぼすか一時的な保護ディレクトリ配置を伴うため、検証専用 PC または VM 上で **第 5 章の直後かつ第 7 章の前** に実施してください。
開発ホスト PC で実施せず未完了の場合は、合否記録表へ「未実施（専用 VM 未用意）」または「未検証差異」として記録します。

### E2E-OPT-01：`--outbound-mode enforce` での一般パス未知プロセス初発凍結と負荷計測

検証専用 VM 上で、`--outbound-mode preemptive-only` を外した既定の `enforce` モードで動作と負荷を検証します。
先にウィンドウ A の稼働中デーモンを `Ctrl+C` で止め、`enforce` モードで起動してください。

```powershell
# ウィンドウ A（64 ビット版管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$env:RUST_LOG = "info,ledr_daemon=debug"
$stageBinDir = Join-Path $runDir "release-bin"
New-Item -ItemType Directory -Path $stageBinDir -Force | Out-Null
foreach ($exeName in @("ledr-daemon.exe", "ledr-auth-helper.exe", "ledr-ui.exe", "ledr-bridge-nm.exe", "ledr-sim.exe")) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "target\release\$exeName") -Destination (Join-Path $stageBinDir $exeName) -Force
}
& (Join-Path $stageBinDir "ledr-daemon.exe") --foreground --dev-bypass-auth --resume-suspended-on-shutdown --disable-nrd-refresh --db (Join-Path $runDir "enforce.db")
```

ウィンドウ B で一般パス（`Downloads` や `Temp` ではない `%LOCALAPPDATA%\LocalEDR-e2e-probe-<GUID>`）の排他ディレクトリを新規作成して `ledr-sim.exe` をコピーし、外部 TCP を実行して初発通信時の `NtSuspendProcess` と動的 WFP Block を確認してください。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$probeDir = Join-Path $env:LOCALAPPDATA ("LocalEDR-e2e-probe-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $probeDir -ErrorAction Stop | Out-Null
$probeExe = Join-Path $probeDir "ledr-probe.exe"
Copy-Item (Join-Path $repoRoot "target\debug\ledr-sim.exe") $probeExe -Force

$enfSim = Start-Process -FilePath $probeExe -ArgumentList "--scenario", "dns-tcp", "--domain", "example.com", "--port", "443", "--hold-ms", "120000", "--json" -PassThru
Start-Sleep -Seconds 2
(Get-Process -Id $enfSim.Id -ErrorAction SilentlyContinue).Threads | Select-Object Id, ThreadState, WaitReason | Format-Table -AutoSize
```

`E2E-UI-01` で `ledr-ui.exe` を閉じているため、ウィンドウ C で Release 版 `ledr-ui.exe` を起動して `View 1` を確認してください。

```powershell
# ウィンドウ C（通常ユーザー PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Start-Process -FilePath (Join-Path $runDir "release-bin\ledr-ui.exe") -WorkingDirectory (Join-Path $runDir "release-bin")
```

`dns-tcp` の TCP 接続自体は 100 ms 程度で完了して終了するため、非同期 ETW イベント配送と `NtSuspendProcess` の競合を避ける目的で `--hold-ms 120000` を指定し、ソケット切断後もプロセスを待機させて凍結状態を確認します。
`WaitReason: Suspended` になり、`ledr-ui` の `View 1` へ `LEDR-NET-UNKNOWN-OUTBOUND` が生成されて `Allow Once` または `Allow Permanent Rule` で再開できれば合格です（確認後に `ledr-ui.exe` を閉じてください）。
あわせて VM 上でこの `enforce` 稼働のまま `E2E-PERF-01` と同じ 60 秒計測を実施し、定常値に大きな乖離がないことを確認してから、今回作成した `$probeDir` のみを削除してください。
このときの計測ログを保存する場合は、Track C の証跡と衝突しないよう `perf_load_enforce.txt` など別ファイル名で出力してください。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell）
if ($enfSim) { Stop-Process -Id $enfSim.Id -Force -ErrorAction SilentlyContinue }
if ($probeDir -and (Test-Path -LiteralPath $probeDir)) {
    Remove-Item -Recurse -Force -LiteralPath $probeDir -ErrorAction SilentlyContinue
}
```

### E2E-OPT-02：`Program Files` 配置での本番 IPC 認可境界（`--dev-bypass-auth` なし）

`L-09` と `SEC_0002` と `SEC_0003` に基づき、`--dev-bypass-auth` を使わずに正規パスと SHA-256 による Named Pipe 認可が機能するかを検証します。
既存の `C:\Program Files\LocalEDR` がすでに存在する環境では上書きを防ぐため中止してください。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell）
if (Test-Path "C:\Program Files\LocalEDR") {
    throw "C:\Program Files\LocalEDR が既に存在するため上書き防止のため中止します。"
}
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
Set-Location $repoRoot
$pfDir = "C:\Program Files\LocalEDR"
New-Item -ItemType Directory -Path $pfDir -ErrorAction Stop | Out-Null
$pfItem = Get-Item -LiteralPath $pfDir -Force
if (-not $pfItem.PSIsContainer -or ($pfItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "C:\Program Files\LocalEDR がリパースポイントのため中止します。"
}
$pfOwnerSid = (Get-Acl -LiteralPath $pfDir).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($pfOwnerSid -notin @("S-1-5-32-544", "S-1-5-18")) {
    throw "C:\Program Files\LocalEDR の所有者が不正なため中止します: Owner=$pfOwnerSid"
}
icacls $pfDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "ACL 設定に失敗しました。" }

Copy-Item "target\release\ledr-daemon.exe" $pfDir -Force
Copy-Item "target\release\ledr-auth-helper.exe" $pfDir -Force
Copy-Item "target\release\ledr-ui.exe" $pfDir -Force
Copy-Item "target\release\ledr-bridge-nm.exe" $pfDir -Force

$uiHash = (Get-FileHash (Join-Path $pfDir "ledr-ui.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
$bridgeHash = (Get-FileHash (Join-Path $pfDir "ledr-bridge-nm.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText((Join-Path $adminDir "ui-sha256.txt"), $uiHash, [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText((Join-Path $adminDir "bridge-sha256.txt"), $bridgeHash, [System.Text.UTF8Encoding]::new($false))
Write-Output "保護配置と SHA-256 保存完了"
```

ウィンドウ A で稼働中のデーモンを止めたあと、`--dev-bypass-auth` なしで正規パスのデーモンを起動してください。

```powershell
# ウィンドウ A（64 ビット版管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$uiHash = (Get-Content -Encoding UTF8 (Join-Path $adminDir "ui-sha256.txt") -Raw).Trim()
$bridgeHash = (Get-Content -Encoding UTF8 (Join-Path $adminDir "bridge-sha256.txt") -Raw).Trim()
$env:RUST_LOG = "info,ledr_daemon=debug"
& "C:\Program Files\LocalEDR\ledr-daemon.exe" --foreground --ui-sha256 $uiHash --bridge-sha256 $bridgeHash --outbound-mode preemptive-only --resume-suspended-on-shutdown --disable-nrd-refresh --db (Join-Path $runDir "auth.db")
```

次の 3 点（およびルート 1・ルート 3 環境では任意の 4 点目）を順に確かめてください。

1. **正規 UI 許可（`SEC_0002` 受理）**：ウィンドウ C から `C:\Program Files\LocalEDR\ledr-ui.exe` を起動し、View 3 で `+ Add Rule` を開いて `Scope` に `NetworkBlock (WFP Deny)`、`Executable Path *` に `C:\Temp\ledr-auth-probe.exe` を入力し、`Save Rule` で追加して `Delete` で削除できることを確認したあと、`ledr-ui.exe` を閉じる。
2. **正規ブリッジのパイプサーバ検証（`SEC_0003`）**：ウィンドウ C から `& "C:\Program Files\LocalEDR\ledr-bridge-nm.exe" status --ping --json` を実行し、`ping` が成功することを確認する。
   この確認はブリッジ側の `GetNamedPipeServerProcessId` によるデーモンパス照合（`SEC_0003`）と IPC 疎通を検証するものであり、`Ping` は読み取り専用照会のためデーモン側の `--bridge-sha256` 検証（`SEC_0002`）は手順 4 で検証する。
3. **非認可 UI バイナリ拒否（`SEC_0002` 拒否）**：ウィンドウ C から `$repoRoot\target\debug\ledr-ui.exe` を起動し、View 3 で手順 1 と同じ入力（`Scope`: `NetworkBlock (WFP Deny)`、`Executable Path *`: `C:\Temp\ledr-auth-probe.exe`）で `+ Add Rule` と `Save Rule` を試みる。
   `NetworkBlock` ルールは `app.js` 側の `L-04` 入力検証を通過して IPC リクエストを発行するため、デーモン側の `GetNamedPipeClientProcessId` によるパスとハッシュ照合で拒否（IPC エラー表示）されることを確認したあと、`ledr-ui.exe` を閉じる。
4. **任意（ルート 1・ルート 3 向け）：実ブリッジ経由 `ReportBrowserEvent` での `--bridge-sha256` 許可・拒否（`SEC_0002`）**：
   ルート 2（Chrome を使用しない `FU-E2E-01` 単独）では本手順を省略し、`--bridge-sha256` の実中継は「未検証差異（単体テスト `daemon_p4_12` で検証済み）」として合否記録表へ記録してください。
   ルート 1 またはルート 3 で Chrome とローカル HTTP サーバを利用できる場合は、Track C の前に Chrome を閉じているため必要に応じて `E2E-P4-00` の手順でローカル HTTP サーバ（`127.0.0.1:8765/beacon`）と隔離プロファイル Chrome を再起動したうえで、ウィンドウ C で一時的に `Program Files` 配下のブリッジを登録して許可と拒否の両方を確認します。

```powershell
# ウィンドウ C（64 ビット版通常ユーザー PowerShell・ルート 1/3 で --bridge-sha256 実中継を検証する場合のみ）
& "C:\Program Files\LocalEDR\ledr-bridge-nm.exe" setup --scope user --browsers chrome --bridge-exe "C:\Program Files\LocalEDR\ledr-bridge-nm.exe" --skip-uri
if ($LASTEXITCODE -ne 0) { throw "Program Files ブリッジの一時登録に失敗しました。" }
```

   - **一致ハッシュ受理**：ウィンドウ A が一致する `--bridge-sha256 $bridgeHash` で稼働中の状態で、Chrome の検証ページ（`http://clickfix-sim.localedr.invalid:8765/phase4-browser-test.html` 等、30 秒重複抑止を避ける場合は `E2E-P4-00` で登録済みの別テストオリジン、または 30 秒以上待機）から ClickFix 操作を実行し、`C:\Program Files\LocalEDR\ledr-ui.exe` の `View 1` へ `LAYER_4_BROWSER` が新規記録されることを確認する。
   - **不一致ハッシュ拒否**：ウィンドウ A を `Ctrl+C` で止め、`--bridge-sha256 0000000000000000000000000000000000000000000000000000000000000000` を指定して `C:\Program Files\LocalEDR\ledr-daemon.exe` を再起動したうえで、再びブラウザイベントを送出する。
     デーモンを再起動しても拡張側（`chrome.storage.session`）の 30 秒重複抑止（`tabId`、オリジン、イベント種別の組）は残るため、同じタブとオリジンで 30 秒以内に再操作すると IPC 自体が送信されず拒否結果を確認できない。
     IPC 送信を確実に行うため、新しいタブで検証ページを開くか、`E2E-P4-00` で登録済みの別テストオリジン（例：`http://pastejack-sim.localedr.invalid:8765/phase4-browser-test.html`）を使うか、30 秒以上待ってから ClickFix 操作を実行する。
     デーモンの認可判定（`SEC_0002`）は標準出力ログではなく IPC 応答の `UNAUTHORIZED_CALLER` エラーを返し、拡張側の `native_bridge.js` が `chrome.storage.local` の `ledr_bridge_diagnostics.lastError` へ `[UNAUTHORIZED_CALLER] ...` を記録する（`Ping` を押すと `lastError` がクリアされ、ポップアップ自体は `daemonOnline: true` のままのため画面上には表示されない）。
     そのため、イベント送出直後（`Ping` を押す前）に `C:\Program Files\LocalEDR\ledr-ui.exe` の `View 1` へ新規記録されないことと、`chrome://extensions` の LocalEDR Browser Shield の Service Worker DevTools コンソールで `(await chrome.storage.local.get("ledr_bridge_diagnostics")).ledr_bridge_diagnostics.lastError` に `[UNAUTHORIZED_CALLER]` が記録されていることの両方を確認し、イベント未送信と認可拒否を区別する。
   - **一時登録解除**：確認後に Chrome と `ledr-ui.exe` を閉じ、ウィンドウ C で次を実行して一時登録を解除する（元の `HKCU` 設定の完全復元は第 7 章 `CLEAN-02` で行う）。

```powershell
# ウィンドウ C（64 ビット版通常ユーザー PowerShell）
& "C:\Program Files\LocalEDR\ledr-bridge-nm.exe" unregister --scope user --browsers chrome --keep-uri
```

`E2E-OPT-03` を連続して実施しない場合は、ウィンドウ A を `Ctrl+C` で停止したうえで `C:\Program Files\LocalEDR` と `C:\ProgramData\LocalEDR-e2e-admin` 配下のハッシュ一時ファイルを削除してください（`E2E-OPT-03` を続ける場合はそのまま残して次へ進みます）。

### E2E-OPT-03（`E2E-SVC-01`）：Session 0（`LocalSystem`）からのトースト起動代替確認

Windows Service SCM エントリポイントが未実装の段階でも、Sysinternals `PsExec64.exe` を用いて `LocalSystem` 権限（Session 0）からデーモンを起動し、`WTSQueryUserToken` と `CreateProcessAsUserW` による対話セッションへの `--notify` 起動を確認できます。
なお、デーモンは `SEC_0004` に基づき Session 0 で動作している間は `--foreground` が指定されていてもフォアグラウンド代替起動を拒否するため、本手順でトーストが表示されれば `WTSQueryUserToken` と `CreateProcessAsUserW` の実経路が通ったことを確認できます。
`E2E-OPT-02` で作成した `C:\Program Files\LocalEDR\` と `$adminDir\ui-sha256.txt` および `bridge-sha256.txt`（未作成の場合は `E2E-OPT-02` 前半で配置してください）が存在する状態で、ウィンドウ A を `Ctrl+C` で止めてからウィンドウ B で Session 0 起動を実行してください。
なお、`LocalSystem`（`S-1-5-18`）で `--dev-bypass-auth` を指定すると Named Pipe DACL が `SYSTEM` と `Administrators` のみ（`D:P(A;;GA;;;SY)(A;;GA;;;BA)`）へフェイルクローズされ、対話ユーザーの非昇格 `ledr-ui.exe` から IPC 接続できなくなるため、本手順では `--dev-bypass-auth` を付けず `--ui-sha256` と `--bridge-sha256` による本番 DACL（`SERVICE_PIPE_SDDL`）と `L-09` バイナリ検証で起動します。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell・PsExec64.exe が PATH または作業フォルダにある前提）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$uiHash = (Get-Content -Encoding UTF8 (Join-Path $adminDir "ui-sha256.txt") -Raw).Trim()
$bridgeHash = (Get-Content -Encoding UTF8 (Join-Path $adminDir "bridge-sha256.txt") -Raw).Trim()
$psexec = Get-Command PsExec64.exe -ErrorAction Stop
$svcDb = Join-Path $runDir "svc.db"
Start-Process -FilePath $psexec.Source -ArgumentList @(
    "-accepteula", "-s", "-i", "0", "-d",
    "`"C:\Program Files\LocalEDR\ledr-daemon.exe`"",
    "--foreground", "--ui-sha256", $uiHash, "--bridge-sha256", $bridgeHash,
    "--outbound-mode", "preemptive-only",
    "--resume-suspended-on-shutdown", "--disable-nrd-refresh",
    "--db", "`"$svcDb`""
)
Start-Sleep -Seconds 3
```

`PREP-03` で `HKCU\Software\Classes\ledr` 登録が済んでいる状態で、`ledr-sim.exe` の `cookies-open` を `Start-Process -PassThru` で別起動し、対話デスクトップ上へ通常ユーザー権限（非 `SYSTEM`）で `ledr-ui.exe --notify` のトースト通知が表示されることを確かめてください。
通知からの UI 起動は 2 段階の引き継ぎで動作し、まず Session 0 デーモンが `CreateProcessAsUserW` で対話ユーザー権限の `C:\Program Files\LocalEDR\ledr-ui.exe --notify <alert_id>` を起動してトーストを出し、ユーザーがトーストをクリックすると `PREP-03` で登録した `HKCU\Software\Classes\ledr` ハンドラ経由で `ledr://alert/<alert_id>` が開きます。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$svcSim = Start-Process -FilePath (Join-Path $repoRoot "target\debug\ledr-sim.exe") -ArgumentList "--scenario", "cookies-open", "--base-dir", "`"$(Join-Path $runDir 'canary_dir')`"", "--hold-ms", "30000", "--json" -PassThru
Start-Sleep -Seconds 3
```

通知の表示を確認したら、Session 0 の `ledr-daemon.exe` とテストプロセスを停止し、`C:\Program Files\LocalEDR` と一時ハッシュファイルを削除してください。
`Stop-Process -Force` による強制停止では SQLite WAL のチェックポイントが走らないため、`svc.db` のアラート記録を証跡として確認したい場合は停止前に `ledr-ui` や IPC 経由で照会するか、停止後に `svc.db` とあわせて `svc.db-wal` および `svc.db-shm` を同一フォルダへ保全してください。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell）
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
if ($svcSim) { Stop-Process -Id $svcSim.Id -Force -ErrorAction SilentlyContinue }
Get-Process ledr-daemon, ledr-sim, ledr-ui -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -Recurse -Force "C:\Program Files\LocalEDR" -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $adminDir "ui-sha256.txt"), (Join-Path $adminDir "bridge-sha256.txt") -ErrorAction SilentlyContinue
```

結果を記録する際は、Windows Service SCM によるサービス登録と自動復旧自体は未実装差異である旨を必ず切り分けて記載してください。

## 7. 共通後片付けと復元検証

管理者権限で起動した `--dev-bypass-auth` 付き `ledr-daemon.exe` が稼働したままだと、起動元と同じユーザーアカウントのプロセスがバイナリ認証なしで防御ルールを変更できる状態が残ります。
後片付けは必ずデーモンの停止から始めてください。

### CLEAN-01：デーモン停止と WFP 動的フィルタ残存 0 件確認（ウィンドウ A と B）

まずウィンドウ A の `ledr-daemon.exe` を `Ctrl+C` で正常終了し、ウィンドウ B で残存プロセスと WFP フィルタが 0 件であることを確認してください。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell）
Get-Process ledr-daemon, ledr-ui, ledr-sim, ledr-bridge-nm, localedr-e2e-sample, ledr-probe -ErrorAction SilentlyContinue | Stop-Process -Force
$rem = Get-Process ledr-daemon, ledr-ui -ErrorAction SilentlyContinue
if ($rem) { throw "LocalEDR プロセスが残留しています。" }

$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$cleanupXml = Join-Path $runDir "filters_cleanup.xml"
netsh wfp show filters "file=$cleanupXml"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $cleanupXml)) {
    throw "netsh wfp show filters に失敗しました。"
}
$hits = Select-String -Path $cleanupXml -Pattern "LocalEDR" -ErrorAction Stop
if ($hits) { throw "BFE に LocalEDR の WFP フィルタが残存しています。" }
Write-Output "CLEAN-01 完了: プロセス 0 件、WFP フィルタ 0 件"
```

### CLEAN-02：ローカルサーバ停止と HKCU 設定の削除および復元（ウィンドウ C）

`PREP-03` または Track B を実施した場合は（ルート 2 を含む全ルート）、ウィンドウ C（通常ユーザー 64 ビット）でローカル HTTP サーバを停止し、`unregister --scope user` のあとに本検証で追加された `HKCU` キーを掃除したうえで、退避ファイルが存在するキーだけを元の登録へ復元してください。
ルート 2（`FU-E2E-01` 単独）では `ledr-bridge-nm.exe setup` を未実行ですが、`unregister --scope user` は未登録の Native Messaging キーをそのまま無視して正常終了し、続くループで `PREP-03` の URI と AUMID キーを片付けて退避済み設定を復元します。
復元が途中で失敗した場合は退避フォルダを消さずに停止します。

```powershell
# ウィンドウ C（64 ビット版通常ユーザー PowerShell）
if (-not [Environment]::Is64BitProcess) {
    throw "64 ビット版 PowerShell で実行してください。"
}
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
Set-Location $repoRoot
$reg64 = "$env:SystemRoot\System32\reg.exe"

$serverPidFile = Join-Path $runDir "server-pid.txt"
if (Test-Path -LiteralPath $serverPidFile) {
    $srvPid = [int](Get-Content -Encoding UTF8 -LiteralPath $serverPidFile -Raw).Trim()
    Stop-Process -Id $srvPid -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $serverPidFile -ErrorAction SilentlyContinue
}

.\target\debug\ledr-bridge-nm.exe unregister --scope user --browsers chrome,edge

# unregister が参照しない場合の残留も防ぐため URI / AUMID キーを明示除去してから既存バックアップのみ復元する
foreach ($hkcuKey in @(
    "HKCU:\Software\Classes\ledr",
    "HKCU:\Software\Classes\AppUserModelId\LocalEDR.AlertUI"
)) {
    if (Test-Path $hkcuKey) {
        Remove-Item -Recurse -Force $hkcuKey -ErrorAction SilentlyContinue
    }
}

Get-ChildItem (Join-Path $runDir "backup\hkcu_*.reg") -ErrorAction SilentlyContinue | ForEach-Object {
    & $reg64 import $_.FullName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "HKCU レジストリ復元に失敗したため退避フォルダを削除せず中止します: $($_.FullName)"
    }
}
$userBackupManifest = Join-Path $runDir "backup\user-native-messaging"
if (Test-Path $userBackupManifest) {
    $userManifestDir = Join-Path $env:LOCALAPPDATA "LocalEDR\native-messaging"
    New-Item -ItemType Directory -Force -Path $userManifestDir | Out-Null
    Copy-Item -Recurse -Force -ErrorAction Stop (Join-Path $userBackupManifest "*") $userManifestDir
}
.\target\debug\ledr-bridge-nm.exe status --scope all
```

### CLEAN-03：HKLM 設定の復元（`--scope machine` を実施した場合のみ、ウィンドウ B）

`E2E-P4-00` で `--scope machine` を登録した場合のみ、ウィンドウ B（管理者 64 ビット）で解除、未退避キーの残留除去、および退避済み `HKLM` 両ビューとマニフェストの復元を行ってください。
`reg.exe import` の実行前に、退避フォルダが `$env:ProgramData\LocalEDR-e2e-admin-backup-*` 配下であること、リパースポイントでないこと、所有者が `Administrators` または `SYSTEM` であること、および非管理者の書き込み ACL が存在しないことを検証します。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell）
if (-not [Environment]::Is64BitProcess) {
    throw "64 ビット版 PowerShell で実行してください。"
}
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$repoRoot = (Get-Content -Encoding UTF8 (Join-Path $stateDir "repo.txt") -Raw).Trim()
Set-Location $repoRoot
.\target\debug\ledr-bridge-nm.exe unregister --scope machine --browsers chrome,edge
foreach ($hklmKey in @(
    "HKLM:\Software\Classes\ledr",
    "HKLM:\Software\Classes\AppUserModelId\LocalEDR.AlertUI"
)) {
    if (Test-Path $hklmKey) {
        Remove-Item -Recurse -Force $hklmKey -ErrorAction SilentlyContinue
    }
}

$adminBackupPtr = Join-Path $adminDir "admin-backup.txt"
if (Test-Path -LiteralPath $adminBackupPtr) {
    $adminBackupDir = (Get-Content -Encoding UTF8 -LiteralPath $adminBackupPtr -Raw).Trim()
    $reg64 = "$env:SystemRoot\System32\reg.exe"
    $reg32 = "$env:SystemRoot\SysWOW64\reg.exe"
    if ($adminBackupDir -and (Test-Path -LiteralPath $adminBackupDir)) {
        $allowedSids = @("S-1-5-32-544", "S-1-5-18")
        $expectedPrefix = [IO.Path]::GetFullPath((Join-Path $env:ProgramData "LocalEDR-e2e-admin-backup-"))
        $backupFull = [IO.Path]::GetFullPath($adminBackupDir)
        if (-not $backupFull.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "管理者専用退避フォルダのパスが期待プレフィックス外のため復元を中止します: $backupFull"
        }
        $backupItem = Get-Item -LiteralPath $backupFull -Force
        if (-not $backupItem.PSIsContainer -or ($backupItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "管理者専用退避フォルダがリパースポイントのため復元を中止します: $backupFull"
        }
        $backupAcl = Get-Acl -LiteralPath $backupFull
        $ownerSid = $backupAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($ownerSid -notin $allowedSids) {
            throw "管理者専用退避フォルダの所有者が不正なため復元を中止します: $backupFull (Owner=$ownerSid)"
        }
        $writeRights = [int][System.Security.AccessControl.FileSystemRights]::Write -bor
            [int][System.Security.AccessControl.FileSystemRights]::Delete -bor
            [int][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [int][System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
            0x40000000 -bor 0x10000000
        foreach ($ace in $backupAcl.Access) {
            if ($ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                if (($aceSid -notin $allowedSids) -and (([int]$ace.FileSystemRights -band $writeRights) -ne 0)) {
                    throw "管理者専用退避フォルダに非管理者の書き込み ACL があるため復元を中止します: $aceSid"
                }
            }
        }
        Get-ChildItem "$backupFull\hklm_*_64.reg" -ErrorAction SilentlyContinue | ForEach-Object {
            & $reg64 import $_.FullName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "HKLM 64 ビット復元失敗: $($_.FullName)" }
        }
        Get-ChildItem "$backupFull\hklm_*_32.reg" -ErrorAction SilentlyContinue | ForEach-Object {
            & $reg32 import $_.FullName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "HKLM 32 ビット復元失敗: $($_.FullName)" }
        }
        $machineManifestDir = "C:\ProgramData\LocalEDR\native-messaging"
        if (Test-Path "$backupFull\machine-native-messaging") {
            Remove-Item -Recurse -Force $machineManifestDir -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Force -Path $machineManifestDir | Out-Null
            Copy-Item -Recurse -Force -ErrorAction Stop "$backupFull\machine-native-messaging\*" $machineManifestDir
        }
        .\target\debug\ledr-bridge-nm.exe status --scope all
        Remove-Item -Recurse -Force -LiteralPath $backupFull
    }
    Remove-Item -LiteralPath $adminBackupPtr -ErrorAction SilentlyContinue
}
```

### CLEAN-04：新規おとり、レジストリプローブ、一時フォルダの整理（ウィンドウ B）

現行の `ledr-daemon.exe` は終了時におとりファイルを自動削除しないため、`PREP-02` で `C:\ProgramData\LocalEDR-e2e-admin\preexisting_honeypots.txt` へ記録した一覧に基づいて今回新規配置されたおとりファイルだけを削除してください。
あわせて、`E2E-P2-06` が途中失敗した場合に残る一時レジストリとダウンロード済みサンプルも片付けます。
テスト証跡（DB や WFP XML）を検証報告用に残す場合は、末尾の `$runDir` と状態ディレクトリ削除行を実行せず保持してください。

```powershell
# ウィンドウ B（64 ビット版管理者 PowerShell）
$stateDir = Join-Path $env:ProgramData "LocalEDR-e2e-state"
$adminDir = Join-Path $env:ProgramData "LocalEDR-e2e-admin"
$runDir = (Get-Content -Encoding UTF8 (Join-Path $stateDir "latest.txt") -Raw).Trim()
$preexistingFile = Join-Path $adminDir "preexisting_honeypots.txt"
if (Test-Path -LiteralPath $preexistingFile) {
    $preexisting = @([System.IO.File]::ReadAllLines($preexistingFile, [System.Text.UTF8Encoding]::new($false)))
    @(
        "$env:USERPROFILE\Documents\!00_LocalEDR_Canary_DoNotEdit.docx",
        "$env:USERPROFILE\Desktop\!00_LocalEDR_Canary_DoNotEdit.docx",
        "$env:USERPROFILE\Pictures\!00_LocalEDR_Canary_DoNotEdit.docx"
    ) | Where-Object { $_ -notin $preexisting } | ForEach-Object {
        Remove-Item -LiteralPath $_ -ErrorAction SilentlyContinue
    }
}
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LocalEdrE2eProbe" -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\LocalEdrE2eTmp" -Recurse -Force -ErrorAction SilentlyContinue
Get-Item "$env:USERPROFILE\Downloads\localedr-e2e-sample*.exe", "$env:USERPROFILE\Downloads\localedr-e2e-sample*.cmd" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# 証跡（DB や XML）が不要になった場合のみ次の 2 行のコメントを外して削除する
# Remove-Item -Recurse -Force -LiteralPath $runDir -ErrorAction SilentlyContinue
# Remove-Item -Recurse -Force -LiteralPath $stateDir, $adminDir -ErrorAction SilentlyContinue
```

## 8. トラブルシューティング、完了判定基準、合否記録テンプレート

### 典型的な障害の切り分け表

| 症状 | 主な原因 | 対処手順 |
| :--- | :--- | :--- |
| `WFP dynamic session could not be initialized` 等で起動失敗 | デーモン起動ウィンドウが管理者未昇格 | ウィンドウ A を右クリックの「管理者として実行」で開き直して起動する |
| `--notify` が `"suppressed_by_os_settings"` を返す | Windows の通知設定がオフ（`ToastEnabled=0`） | Windows の「設定」から「システム」の「通知」をオンにして再実行する |
| 64 ビットキーの退避や復元でパスが見つからない | 32 ビット版 PowerShell を起動している | `[Environment]::Is64BitProcess` が `True` になる 64 ビット版 PowerShell で実行する |
| Chrome 拡張の `Ping` が IPC 接続拒否で失敗する | Release デーモンと Debug ブリッジが混在している、または `Program Files` に別バイナリがある | 同じビルド種別の兄弟ペアを揃え、不要な `C:\Program Files\LocalEDR\ledr-daemon.exe` を退避する |
| 同じブラウザ操作を再試行しても View 1 に記録が増えない | `L-19` の 30 秒重複抑止（上限 256 件）が働いている | 30 秒以上待つか、別サブドメイン（`pastejack-sim` 等）で開き、`ledr-ui` 上部の `Refresh` を押す |
| View 2 に全体のダウンロード履歴が見えない | 左ペインで特定プロセスが選択されたままになっている | 左ペイン上部の `All` を押して `Scope: All Processes` へ戻し、`Canary & Downloads` タブを見る |
| 移動した `localedr-e2e-sample.exe` が WFP 遮断されない | 移動前に Chrome ダウンロード通知の SHA-256 算出と記録が終わっていない | 一度削除してダウンロードし直し、移動前に View 2 記録を確認してから移動する |
| `Microsoft-Windows-Kernel-Process` のイベントが 1 件も届かず新規プロセス登録や WFP ドロップ相関が機能しない | Windows の ETW 1 プロバイダ上限（8 セッション）に到達し、終了済みアプリの残留セッション等が配信枠を占有している | `logman query -ets` で一覧を確認したあと、各候補へ `logman query <セッション名> -ets` を実行して `Microsoft-Windows-Kernel-Process` 購読有無を特定し、終了済みアプリの不要な残留セッションだけを `logman stop <セッション名> -ets` で停止して `ledr-daemon.exe` を再起動する（`EventLog-System` や `DiagLog` など OS 標準セッションは停止しない） |
| Track B で `E2E-P4-03` または `E2E-P4-04` が発火しない、または検証ページが読み込み中のまま開かない | 前ステップのホスト名（`clickfix-sim` 等）のまま操作している、またはローカル HTTP サーバの `python.exe` が別インスタンス由来の WFP ドロップで凍結されている | ページ表示の `Hostname:` が対象ドメインであることを確認し、読み込み停止時は `View 1` で `python.exe` の凍結アラートを `Allow Once` で再開する。`local_server.py` を再起動する場合は、ポート `8765` の占有を残さないよう凍結中の旧 `python.exe` を先に終了してから再起動する |

### ルート別完了判定基準

[implementation-plan.md](implementation-plan.md) の未完了実機 E2E チェックリストを `[x]` へ更新できる条件を、PR の単位ごとに次のとおり定めます。

- **`FU-E2E-01`（Phase 2 と Phase 3 の実機検証 PR）の完了基準**：ルート 2（またはルート 1 の該当範囲）に含まれる `PREP-01` から `PREP-04`、Track A 全項目（`E2E-P2-01` から `E2E-P2-06`、`E2E-P3-01` から `E2E-P3-07`）、および Track C 全項目（`E2E-UI-01`、`E2E-PERF-01`）が `PASS` であること。
  オフライン環境での `E2E-P3-05` 省略、Windows Server SKU での代替実施、または専用 VM 不在による第 6 章（`E2E-OPT-01` から `E2E-OPT-03`）未実施がある場合は、残る未検証差異として [follow-up-notes.md](follow-up-notes.md) と PR 本文へ必ず切り分けて記録する。
  `E2E-P2-*`、`E2E-P3-*`（`P3-05` 除く）、`E2E-UI-01`、`E2E-PERF-01` のいずれかに `FAIL` または未解決 `BLOCKED` が残る場合は `[x]` へ更新しない。
- **`FU-E2E-02`（Phase 4 の実機 Chrome E2E 検証 PR）の完了基準**：ルート 3（またはルート 1 の該当範囲）に含まれる `PREP-01` から `PREP-03`、Track B 全項目（`E2E-P4-00` から `E2E-P4-07`）、および Track C 全項目（`E2E-UI-01` 必須、Phase 4 機能追加後の常駐性能回帰確認として `E2E-PERF-01` も実施）が `PASS` であること。
  Edge 実ブラウザ確認や `--scope machine`、第 6 章が未実施の場合は未実施箇所として PR 本文へ切り分け記録し、`E2E-P4-*` または `E2E-UI-01` に `FAIL` や未解決 `BLOCKED` が残る場合は `[x]` へ更新しない。

### 合否記録テンプレート

実機 E2E 実施時は実施環境の情報（OS ビルド、`ProductType`、Chrome バージョン、実行コミット SHA）とあわせて、次の表へ `PASS`、`FAIL`、`BLOCKED`、`未実施`、`未検証差異` のいずれかを記録し、PR または検証報告へ記載してください。

| ID | 区分 | 検証項目 | 判定 | 実測値、証跡メモ、差異 |
| :--- | :--- | :--- | :--- | :--- |
| `PREP-01` | 共通 | Debug と Release の両ビルド成功、`ProductType=1`、`BFE` Running | | |
| `PREP-02` | 共通 | `$runDir` 準備、`preexisting_honeypots.txt` 退避、`--prepare-dir` 排他拒否 | | |
| `PREP-03` | 共通 | `HKCU` 退避、`--register-uri`、`ToastEnabled` と `--notify` バナー表示 | | |
| `PREP-04` | 共通 | Debug デーモン起動と初期化ログ 7 項目 | | |
| `E2E-P2-01` | Track A | おとりファイル読み取り専用アクセス非発火 | | |
| `E2E-P2-02` | Track A | ダミー `Cookies` 単体凍結、1 秒以内通知、1,000 ms 以内 View 1、5 秒以内 `Allow Once` 再開 | | |
| `E2E-P2-03` | Track A | おとり書込ツリー凍結と `Terminate & Block` 親子 0 件完全終了 | | |
| `E2E-P2-04` | Track A | 60 秒未応答時の `EXPIRED_SUSPENDED (60s)` 遷移と凍結維持 | | |
| `E2E-P2-05` | Track A | 対話 `explorer.exe` による Never-Suspend ガード（`PENDING` 表示） | | |
| `E2E-P2-06` | Track A | ETW `Kernel-Registry` 自動起動キー検知と `CloseKey` キャッシュ無効化 | | |
| `E2E-P3-01` | Track A | BFE 動的 SubLayer、ループバック許可、単一 `SysWOW64` PowerShell 遮断と凍結 | | |
| `E2E-P3-02` | Track A | 複数 `SysWOW64` PowerShell 起動時の `App-Level (Ambiguous PID)` 非凍結 | | |
| `E2E-P3-03` | Track A | `ledr-sim` の LOTL と DNS TCP 相関（1 秒以内 View 2 描画と実 ETW 補完） | | |
| `E2E-P3-04` | Track A | View 1 許可保存、View 3 おとり状態、ドメイン `IP-resolved`、Deny 優先、削除連動 | | |
| `E2E-P3-05` | Track A | 実 WinHTTP NRD 取得と View 3 `NRD / Homograph Check` | | |
| `E2E-P3-06` | Track A | 未応答 UNC 共有での 3 秒停止予算、WAL トランケート先行、DB 永続化確認 | | |
| `E2E-P3-07` | Track A | `taskkill /F` 強制終了時の動的 WFP フィルタ 0 件消去と通信回復 | | |
| `E2E-P4-00` | Track B | `ledr-bridge-nm setup`、View 3 `.browser-detail-row` 混入なし、拡張 ID 一致と `Ping` | | |
| `E2E-P4-01` | Track B | ClickFix 警告、OS トースト非発火（`L-19`）、View 1 `ClickFixPastejacking` 記録 | | |
| `E2E-P4-02` | Track B | Pastejacking 警告発火（`pastejack-sim`）と通常コードコピー（領域 3）非発火（`L-15`） | | |
| `E2E-P4-03` | Track B | `nrd-sim.localedr.invalid` パスワード入力時の NRD 警告と `NrdPasswordWarning` | | |
| `E2E-P4-04` | Track B | `login-paypa1.localedr.invalid` パスワード入力時の `paypal` ホモグラフ警告 | | |
| `E2E-P4-05` | Track B | DNR 静的ルールによる `c2-sim` 遮断と `safe-sim` の `HTTP 200` 通過 | | |
| `E2E-P4-06` | Track B | `:Zone.Identifier` 確認、移動後 `dns-tcp` 事前 WFP 遮断（`L-18`）、MOTW 3 段階紐付け | | |
| `E2E-P4-07` | Track B | `LAYER_4_BROWSER` の `Allow Permanent Rule` 無効と `Acknowledge` 解決 | | |
| `E2E-UI-01` | Track C | Release 版 `ledr-ui` 閉鎖後の `ledr-ui` と WebView2 0 プロセス終了（`L-08`） | | |
| `E2E-PERF-01` | Track C | Release 版 `ledr-daemon` `PrivateWorkingSetSize <= 20.0 MB`（`WorkingSet64` 後半前半差 `<= +1.0 MB`、`>= 100.0 MB` スパイク 0 回、高負荷ピーク `< 64.34 MB`）、アイドル CPU `< 0.5%`（負荷 `< 1%`）、負荷時応答 | | |
| `E2E-OPT-01` | 専用（任意） | `--outbound-mode enforce` での一般パス未知プロセス初発通信凍結と負荷計測 | | |
| `E2E-OPT-02` | 専用（任意） | `Program Files` 配置＋ハッシュピン（`--dev-bypass-auth` なし）での IPC 認可境界 | | |
| `E2E-OPT-03` | 専用（任意） | Session 0（`LocalSystem`）からの `CreateProcessAsUserW` 起動と SCM 差異切り分け | | |
