[CmdletBinding()]
param(
    [string]$SourceDir = $PSScriptRoot,
    [string]$InstallDir = 'C:\Program Files\LocalEDR',
    [string]$DataDir = 'C:\ProgramData\LocalEDR',
    [switch]$UpdateMode,
    [int]$UiWaitSeconds = 10,
    [int]$ServiceWaitSeconds = 15,
    [int]$LockRetrySeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ServiceName = 'LocalEDR'
$script:BinaryNames = @(
    'ledr-daemon.exe',
    'ledr-ui.exe',
    'ledr-bridge-nm.exe',
    'ledr-auth-helper.exe'
)
$script:DistributedRuleNames = @(
    'lotl_core.json',
    'default_allowlist.json'
)
$script:LogWriter = $null
$script:LogBuffer = New-Object System.Collections.Generic.List[string]
$script:NativeHelperLoaded = $false

function Ensure-NativeHelper {
    if ($script:NativeHelperLoaded) {
        return
    }
    if (-not ('LocalEdrInstallerNative' -as [type])) {
        $code = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class LocalEdrInstallerNative
{
    private const uint FILE_READ_ATTRIBUTES = 0x0080;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out BY_HANDLE_FILE_INFORMATION lpFileInformation
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(
        string lpExistingFileName,
        string lpNewFileName,
        uint dwFlags
    );

    public static void GetFileInfoNoFollow(string path, out uint linkCount, out uint fileAttributes)
    {
        uint flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
        using (SafeFileHandle handle = CreateFileW(
            path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            flags,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW failed for " + path);
            }
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(handle, out info))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandle failed for " + path);
            }
            linkCount = info.NumberOfLinks;
            fileAttributes = info.FileAttributes;
        }
    }

    public static bool ScheduleDeleteOnReboot(string path)
    {
        return MoveFileExW(path, null, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}
'@
        Add-Type -TypeDefinition $code -Language CSharp
    }
    $script:NativeHelperLoaded = $true
}

function Write-InstallLog {
    param(
        [string]$Level,
        [string]$Message
    )
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "[$ts] [$Level] $Message"
    if ($null -ne $script:LogWriter) {
        $script:LogWriter.WriteLine($line)
    }
    else {
        $script:LogBuffer.Add($line)
    }
}

function Close-InstallLog {
    if ($null -ne $script:LogWriter) {
        try {
            $script:LogWriter.Flush()
            $script:LogWriter.Dispose()
        }
        finally {
            $script:LogWriter = $null
        }
    }
}

function Normalize-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.Length -gt $root.Length) {
        $full = $full.TrimEnd('\', '/')
    }
    return $full
}

function Assert-NoReparsePointComponent {
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][bool]$ExpectDirectoryIfExists
    )
    $full = Normalize-FullPath -Path $TargetPath
    $root = [System.IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "Path must be rooted: $TargetPath"
    }
    $rest = $full.Substring($root.Length)
    $segments = @()
    if (-not [string]::IsNullOrEmpty($rest)) {
        $segments = $rest -split '[\\/]+'
    }

    $current = $root
    if (Test-Path -LiteralPath $current) {
        $rootItem = Get-Item -LiteralPath $current -Force
        if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point detected on root path: $current"
        }
    }

    for ($i = 0; $i -lt $segments.Count; $i++) {
        $seg = $segments[$i]
        if ([string]::IsNullOrEmpty($seg)) {
            continue
        }
        $current = Join-Path $current $seg
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse point detected at path: $current"
            }
            $isLast = ($i -eq ($segments.Count - 1))
            $isDir = (($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0)
            if (-not $isLast) {
                if (-not $isDir) {
                    throw "Non-directory path component blocks directory tree: $current"
                }
            }
            else {
                if ($ExpectDirectoryIfExists -and (-not $isDir)) {
                    throw "Expected directory but found file: $current"
                }
                if ((-not $ExpectDirectoryIfExists) -and $isDir) {
                    throw "Expected file but found directory: $current"
                }
            }
        }
    }
}

function Assert-AdminOrSystemOwnerIfExists {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)
    if (-not (Test-Path -LiteralPath $DirectoryPath)) {
        return
    }
    $acl = Get-Acl -LiteralPath $DirectoryPath
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (($ownerSid -ne 'S-1-5-32-544') -and ($ownerSid -ne 'S-1-5-18')) {
        throw "Unsafe owner SID '$ownerSid' on existing directory '$DirectoryPath' (expected Administrators or SYSTEM)."
    }
}

function Invoke-IcaclsChecked {
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string[]]$GrantSpecs
    )
    $argsList = @($TargetPath, '/inheritance:r')
    foreach ($spec in $GrantSpecs) {
        $argsList += '/grant:r'
        $argsList += $spec
    }
    $output = & icacls.exe @argsList 2>&1
    if ($LASTEXITCODE -ne 0) {
        $detail = ($output | Out-String).Trim()
        throw "icacls failed for '$TargetPath' (exit $LASTEXITCODE): $detail"
    }
}

function Get-AncestorPidSet {
    param([int]$StartPid)
    $ancestors = New-Object 'System.Collections.Generic.HashSet[int]'
    $procs = Get-CimInstance -ClassName Win32_Process -Property ProcessId, ParentProcessId
    $parentMap = @{}
    foreach ($p in $procs) {
        $parentMap[[int]$p.ProcessId] = [int]$p.ParentProcessId
    }
    $cursor = $StartPid
    $depth = 0
    while ($parentMap.ContainsKey($cursor) -and ($depth -lt 64)) {
        $parentPid = $parentMap[$cursor]
        if ($parentPid -le 0) {
            break
        }
        if (-not $ancestors.Add($parentPid)) {
            break
        }
        $cursor = $parentPid
        $depth++
    }
    return $ancestors
}

function Wait-ForUiExit {
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedUiExePath,
        [Parameter(Mandatory = $true)][bool]$AllowUpdaterAncestor,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    $normalizedExpected = (Normalize-FullPath -Path $ExpectedUiExePath).ToLowerInvariant()
    $ancestorPids = New-Object 'System.Collections.Generic.HashSet[int]'
    if ($AllowUpdaterAncestor) {
        $ancestorPids = Get-AncestorPidSet -StartPid $PID
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $uiProcs = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='ledr-ui.exe'" -Property ProcessId, ExecutablePath, CommandLine)
        $blocking = New-Object System.Collections.Generic.List[object]
        foreach ($proc in $uiProcs) {
            $procPid = [int]$proc.ProcessId
            $isExcludedAncestor = $false
            if ($AllowUpdaterAncestor -and $ancestorPids.Contains($procPid)) {
                $exeRaw = $proc.ExecutablePath
                $cmdRaw = $proc.CommandLine
                if ((-not [string]::IsNullOrWhiteSpace($exeRaw)) -and (-not [string]::IsNullOrWhiteSpace($cmdRaw))) {
                    $exeNorm = (Normalize-FullPath -Path $exeRaw).ToLowerInvariant()
                    if (($exeNorm -eq $normalizedExpected) -and ($cmdRaw -match '(^|\s)--apply-verified-update(\s|$)')) {
                        $isExcludedAncestor = $true
                        Write-InstallLog -Level 'INFO' -Message "Excluding ancestor elevated updater ledr-ui.exe PID=$procPid from exit wait."
                    }
                }
            }
            if (-not $isExcludedAncestor) {
                $blocking.Add($proc)
            }
        }

        if ($blocking.Count -eq 0) {
            return
        }

        if ((Get-Date) -ge $deadline) {
            $pidSummary = (($blocking | ForEach-Object { $_.ProcessId }) -join ', ')
            throw "Timed out after ${TimeoutSeconds}s waiting for ledr-ui.exe to exit (remaining PIDs: $pidSummary)."
        }

        Start-Sleep -Milliseconds 200
    }
}

function Get-ServiceStateInfo {
    param([Parameter(Mandatory = $true)][string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        return @{
            Exists = $false
            Status = 'Missing'
        }
    }
    $svc.Refresh()
    return @{
        Exists = $true
        Status = $svc.Status.ToString()
    }
}

function Wait-ForServiceStopped {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    $info = Get-ServiceStateInfo -Name $Name
    if (-not $info.Exists) {
        return
    }
    if ($info.Status -eq 'Stopped') {
        return
    }

    if ($info.Status -ne 'StopPending') {
        Write-InstallLog -Level 'INFO' -Message "Stopping service '$Name' (current state: $($info.Status))."
        $stopOut = & sc.exe stop $Name 2>&1
        $rc = $LASTEXITCODE
        if (($rc -ne 0) -and ($rc -ne 1062)) {
            $detail = ($stopOut | Out-String).Trim()
            throw "sc.exe stop $Name failed (exit $rc): $detail"
        }
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $cur = Get-ServiceStateInfo -Name $Name
        if ((-not $cur.Exists) -or ($cur.Status -eq 'Stopped')) {
            return
        }
        if ((Get-Date) -ge $deadline) {
            throw "Timed out after ${TimeoutSeconds}s waiting for service '$Name' to reach STOPPED (last state: $($cur.Status))."
        }
        Start-Sleep -Milliseconds 250
    }
}

function Wait-ForServiceRunning {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $cur = Get-ServiceStateInfo -Name $Name
        if ($cur.Exists -and ($cur.Status -eq 'Running')) {
            return
        }
        if ((Get-Date) -ge $deadline) {
            throw "Timed out after ${TimeoutSeconds}s waiting for service '$Name' to reach RUNNING (last state: $($cur.Status))."
        }
        Start-Sleep -Milliseconds 250
    }
}

function Get-PreviousServiceConfig {
    param([Parameter(Mandatory = $true)][string]$Name)
    $qcOut = & sc.exe qc $Name 2>&1
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    $text = ($qcOut | Out-String)
    $binPath = $null
    $startType = 'auto'
    $displayName = 'LocalEDR Endpoint Detection & Response'
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^\s*BINARY_PATH_NAME\s*:\s*(.+)$') {
            $binPath = $Matches[1].Trim()
        }
        elseif ($line -match '^\s*START_TYPE\s*:\s*\d+\s+(\S+)') {
            $rawStart = $Matches[1].Trim().ToUpperInvariant()
            if ($rawStart -eq 'AUTO_START') { $startType = 'auto' }
            elseif ($rawStart -eq 'DEMAND_START') { $startType = 'demand' }
            elseif ($rawStart -eq 'DISABLED') { $startType = 'disabled' }
        }
        elseif ($line -match '^\s*DISPLAY_NAME\s*:\s*(.+)$') {
            $displayName = $Matches[1].Trim()
        }
    }
    return @{
        BinaryPathName = $binPath
        StartType = $startType
        DisplayName = $displayName
    }
}

function Invoke-WithFileLockRetry {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Operation,
        [Parameter(Mandatory = $true)][string]$Description,
        [int]$TimeoutSeconds = 5
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        try {
            & $Operation
            return
        }
        catch {
            $ex = $_.Exception
            $isSharingOrAccess = ($ex -is [System.IO.IOException]) -or ($ex -is [System.UnauthorizedAccessException])
            if ((-not $isSharingOrAccess) -or ((Get-Date) -ge $deadline)) {
                throw "Failed '$Description' within ${TimeoutSeconds}s lock retry budget: $($ex.Message)"
            }
            Start-Sleep -Milliseconds 200
        }
    }
}

function Copy-FileStrictNoHardlink {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestPath,
        [Parameter(Mandatory = $true)][int]$RetrySeconds
    )
    Invoke-WithFileLockRetry -TimeoutSeconds $RetrySeconds -Description "copy $SourcePath -> $DestPath" -Operation {
        [System.IO.File]::Copy($SourcePath, $DestPath, $true)
    }
}

function Assert-SingleLinkNonReparse {
    param([Parameter(Mandatory = $true)][string]$FilePath)
    Ensure-NativeHelper
    [uint32]$links = 0
    [uint32]$attrs = 0
    [LocalEdrInstallerNative]::GetFileInfoNoFollow($FilePath, [ref]$links, [ref]$attrs)
    if (($attrs -band 0x0400) -ne 0) {
        throw "File '$FilePath' is a reparse point (attributes=$attrs)."
    }
    if ($links -ne 1) {
        throw "File '$FilePath' must have nNumberOfLinks == 1, actual=$links (hardlinks are forbidden)."
    }
}

function Remove-BackupDirectoryBestEffort {
    param(
        [Parameter(Mandatory = $true)][string]$BackupDirPath,
        [Parameter(Mandatory = $true)][bool]$AllowRebootDelayForUi
    )
    if (-not (Test-Path -LiteralPath $BackupDirPath)) {
        return
    }
    try {
        Remove-Item -LiteralPath $BackupDirPath -Recurse -Force
    }
    catch {
        if ($AllowRebootDelayForUi) {
            $uiBak = Join-Path $BackupDirPath 'ledr-ui.exe'
            if (Test-Path -LiteralPath $uiBak) {
                Ensure-NativeHelper
                $okFile = [LocalEdrInstallerNative]::ScheduleDeleteOnReboot($uiBak)
                $okDir = [LocalEdrInstallerNative]::ScheduleDeleteOnReboot($BackupDirPath)
                Write-InstallLog -Level 'WARN' -Message "Backup cleanup deferred until reboot for '$uiBak' (scheduledFile=$okFile, scheduledDir=$okDir): $($_.Exception.Message)"
                return
            }
        }
        Write-InstallLog -Level 'WARN' -Message "Failed to remove backup directory '$BackupDirPath': $($_.Exception.Message)"
    }
}

$normSourceDir = Normalize-FullPath -Path $SourceDir
$normInstallDir = Normalize-FullPath -Path $InstallDir
$normDataDir = Normalize-FullPath -Path $DataDir
$normRulesDir = Join-Path $normDataDir 'rules'
$normLogsDir = Join-Path $normDataDir 'logs'
$normNmDir = Join-Path $normDataDir 'native-messaging'
$logFilePath = Join-Path $normLogsDir 'installer.log'

# Phase 1: Pre-flight checks before opening installer.log or mutating state
Write-InstallLog -Level 'INFO' -Message "Starting LocalEDR installation (SourceDir=$normSourceDir, InstallDir=$normInstallDir, DataDir=$normDataDir, UpdateMode=$($UpdateMode.IsPresent))."

Assert-NoReparsePointComponent -TargetPath $normSourceDir -ExpectDirectoryIfExists $true
Assert-NoReparsePointComponent -TargetPath $normInstallDir -ExpectDirectoryIfExists $true
Assert-NoReparsePointComponent -TargetPath $normDataDir -ExpectDirectoryIfExists $true
Assert-NoReparsePointComponent -TargetPath $normRulesDir -ExpectDirectoryIfExists $true
Assert-NoReparsePointComponent -TargetPath $normLogsDir -ExpectDirectoryIfExists $true
Assert-NoReparsePointComponent -TargetPath $normNmDir -ExpectDirectoryIfExists $true
Assert-NoReparsePointComponent -TargetPath $logFilePath -ExpectDirectoryIfExists $false

Assert-AdminOrSystemOwnerIfExists -DirectoryPath $normInstallDir
Assert-AdminOrSystemOwnerIfExists -DirectoryPath $normDataDir

foreach ($binName in $script:BinaryNames) {
    $srcBin = Join-Path $normSourceDir $binName
    if (-not (Test-Path -LiteralPath $srcBin -PathType Leaf)) {
        throw "Missing required source binary: $srcBin"
    }
    Assert-NoReparsePointComponent -TargetPath $srcBin -ExpectDirectoryIfExists $false
    $dstBin = Join-Path $normInstallDir $binName
    Assert-NoReparsePointComponent -TargetPath $dstBin -ExpectDirectoryIfExists $false
}

foreach ($ruleName in $script:DistributedRuleNames) {
    $srcRule = Join-Path (Join-Path $normSourceDir 'rules') $ruleName
    if (-not (Test-Path -LiteralPath $srcRule -PathType Leaf)) {
        throw "Missing required source rule file: $srcRule"
    }
    Assert-NoReparsePointComponent -TargetPath $srcRule -ExpectDirectoryIfExists $false
    $dstRule = Join-Path $normRulesDir $ruleName
    Assert-NoReparsePointComponent -TargetPath $dstRule -ExpectDirectoryIfExists $false
}

# Prepare DataDir and LogsDir safely so installer.log captures all runtime diagnostics
$createdDataDir = $false
if (-not (Test-Path -LiteralPath $normDataDir)) {
    [void](New-Item -ItemType Directory -Path $normDataDir -Force)
    $createdDataDir = $true
}
Invoke-IcaclsChecked -TargetPath $normDataDir -GrantSpecs @('*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F')

if (-not (Test-Path -LiteralPath $normLogsDir)) {
    [void](New-Item -ItemType Directory -Path $normLogsDir -Force)
}
Assert-NoReparsePointComponent -TargetPath $normLogsDir -ExpectDirectoryIfExists $true
Assert-NoReparsePointComponent -TargetPath $logFilePath -ExpectDirectoryIfExists $false

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:LogWriter = New-Object System.IO.StreamWriter($logFilePath, $true, $utf8NoBom)
$script:LogWriter.AutoFlush = $true
foreach ($bufferedLine in $script:LogBuffer) {
    $script:LogWriter.WriteLine($bufferedLine)
}
$script:LogBuffer.Clear()

$backupDir = $null
$createdInstallDir = $false
$createdRulesDir = $false
$backedUpBinaries = New-Object System.Collections.Generic.List[string]
$backedUpRules = New-Object System.Collections.Generic.List[string]
$newlyInstalledFiles = New-Object System.Collections.Generic.List[string]
$serviceCreated = $false
$serviceModified = $false
$prevServiceExists = $false
$prevServiceWasRunning = $false
$prevServiceConfig = $null
$startedServiceByInstaller = $false
$bridgeSetupDone = $false

try {
    # Phase 2: Wait for UI exit (10s, abort on timeout; exclude ancestor --apply-verified-update in -UpdateMode)
    $installedUiPath = Join-Path $normInstallDir 'ledr-ui.exe'
    Wait-ForUiExit -ExpectedUiExePath $installedUiPath -AllowUpdaterAncestor ($UpdateMode.IsPresent) -TimeoutSeconds $UiWaitSeconds

    # Phase 3: Query & wait for LocalEDR service stop (15s, abort on timeout)
    $svcState = Get-ServiceStateInfo -Name $script:ServiceName
    $prevServiceExists = $svcState.Exists
    if ($prevServiceExists) {
        $prevServiceWasRunning = ($svcState.Status -eq 'Running') -or ($svcState.Status -eq 'StartPending')
        $prevServiceConfig = Get-PreviousServiceConfig -Name $script:ServiceName
        Wait-ForServiceStopped -Name $script:ServiceName -TimeoutSeconds $ServiceWaitSeconds
    }

    # Phase 4: Create same-volume admin-only backup directory
    $installRoot = [System.IO.Path]::GetPathRoot($normInstallDir)
    $dataRoot = [System.IO.Path]::GetPathRoot($normDataDir)
    $backupName = '.installer-backup-' + [Guid]::NewGuid().ToString('N')
    if ($installRoot.Equals($dataRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        $backupDir = Join-Path $normDataDir $backupName
    }
    else {
        $parentOfInstall = [System.IO.Path]::GetDirectoryName($normInstallDir)
        $backupDir = Join-Path $parentOfInstall $backupName
    }
    [void](New-Item -ItemType Directory -Path $backupDir -Force)
    [void](New-Item -ItemType Directory -Path (Join-Path $backupDir 'rules') -Force)
    Invoke-IcaclsChecked -TargetPath $backupDir -GrantSpecs @('*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F')
    Write-InstallLog -Level 'INFO' -Message "Created backup directory: $backupDir"

    # Ensure InstallDir and DataDir\rules exist
    if (-not (Test-Path -LiteralPath $normInstallDir)) {
        [void](New-Item -ItemType Directory -Path $normInstallDir -Force)
        $createdInstallDir = $true
    }
    if (-not (Test-Path -LiteralPath $normRulesDir)) {
        [void](New-Item -ItemType Directory -Path $normRulesDir -Force)
        $createdRulesDir = $true
    }

    # Phase 5: Back up existing 4 binaries & 2 distributed rules (rename ledr-ui.exe into backup first)
    foreach ($binName in $script:BinaryNames) {
        $dstBin = Join-Path $normInstallDir $binName
        $bakBin = Join-Path $backupDir $binName
        if (Test-Path -LiteralPath $dstBin -PathType Leaf) {
            if ($binName -eq 'ledr-ui.exe') {
                Invoke-WithFileLockRetry -TimeoutSeconds $LockRetrySeconds -Description "move existing ledr-ui.exe to backup" -Operation {
                    [System.IO.File]::Move($dstBin, $bakBin)
                }
            }
            else {
                Copy-FileStrictNoHardlink -SourcePath $dstBin -DestPath $bakBin -RetrySeconds $LockRetrySeconds
            }
            $backedUpBinaries.Add($binName)
            Write-InstallLog -Level 'INFO' -Message "Backed up binary: $binName"
        }
        else {
            $newlyInstalledFiles.Add($dstBin)
        }
    }

    foreach ($ruleName in $script:DistributedRuleNames) {
        $dstRule = Join-Path $normRulesDir $ruleName
        $bakRule = Join-Path (Join-Path $backupDir 'rules') $ruleName
        if (Test-Path -LiteralPath $dstRule -PathType Leaf) {
            Copy-FileStrictNoHardlink -SourcePath $dstRule -DestPath $bakRule -RetrySeconds $LockRetrySeconds
            $backedUpRules.Add($ruleName)
            Write-InstallLog -Level 'INFO' -Message "Backed up rule: rules\$ruleName"
        }
        else {
            $newlyInstalledFiles.Add($dstRule)
        }
    }

    # Phase 6: Copy new 4 binaries into InstallDir (never hardlink) and 2 distributed rules into DataDir\rules
    foreach ($binName in $script:BinaryNames) {
        $srcBin = Join-Path $normSourceDir $binName
        $dstBin = Join-Path $normInstallDir $binName
        Copy-FileStrictNoHardlink -SourcePath $srcBin -DestPath $dstBin -RetrySeconds $LockRetrySeconds
        Write-InstallLog -Level 'INFO' -Message "Installed binary: $dstBin"
    }

    # Strictly enforce nNumberOfLinks == 1 and non-reparse on ledr-auth-helper.exe (L-23)
    $installedAuthHelper = Join-Path $normInstallDir 'ledr-auth-helper.exe'
    Assert-SingleLinkNonReparse -FilePath $installedAuthHelper
    Write-InstallLog -Level 'INFO' -Message "Verified ledr-auth-helper.exe nNumberOfLinks == 1 and non-reparse."

    # Copy uninstall.ps1 alongside binaries if bundled in SourceDir and not identical path
    $srcUninstallPs1 = Join-Path $normSourceDir 'uninstall.ps1'
    $dstUninstallPs1 = Join-Path $normInstallDir 'uninstall.ps1'
    if (Test-Path -LiteralPath $srcUninstallPs1 -PathType Leaf) {
        if (-not (Normalize-FullPath -Path $srcUninstallPs1).Equals((Normalize-FullPath -Path $dstUninstallPs1), [System.StringComparison]::OrdinalIgnoreCase)) {
            $hadUninstallPs1 = Test-Path -LiteralPath $dstUninstallPs1 -PathType Leaf
            if ($hadUninstallPs1) {
                Copy-FileStrictNoHardlink -SourcePath $dstUninstallPs1 -DestPath (Join-Path $backupDir 'uninstall.ps1') -RetrySeconds $LockRetrySeconds
                $backedUpBinaries.Add('uninstall.ps1')
            }
            else {
                $newlyInstalledFiles.Add($dstUninstallPs1)
            }
            Copy-FileStrictNoHardlink -SourcePath $srcUninstallPs1 -DestPath $dstUninstallPs1 -RetrySeconds $LockRetrySeconds
        }
    }

    foreach ($ruleName in $script:DistributedRuleNames) {
        $srcRule = Join-Path (Join-Path $normSourceDir 'rules') $ruleName
        $dstRule = Join-Path $normRulesDir $ruleName
        Copy-FileStrictNoHardlink -SourcePath $srcRule -DestPath $dstRule -RetrySeconds $LockRetrySeconds
        Write-InstallLog -Level 'INFO' -Message "Installed rule: $dstRule"
    }

    # Phase 7: Apply DACLs on InstallDir and DataDir
    Invoke-IcaclsChecked -TargetPath $normInstallDir -GrantSpecs @(
        '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-545:(OI)(CI)RX'
    )
    Invoke-IcaclsChecked -TargetPath $normDataDir -GrantSpecs @(
        '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-18:(OI)(CI)F'
    )
    Write-InstallLog -Level 'INFO' -Message "Applied icacls permissions to '$normInstallDir' and '$normDataDir'."

    # Phase 8: Register machine-scope Native Messaging manifests & apply RX ACL on native-messaging subdir
    $bridgeExe = Join-Path $normInstallDir 'ledr-bridge-nm.exe'
    $uiExe = Join-Path $normInstallDir 'ledr-ui.exe'
    $bridgeOut = & $bridgeExe setup --scope machine --bridge-exe $bridgeExe --ui-exe $uiExe 2>&1
    if ($LASTEXITCODE -ne 0) {
        $detail = ($bridgeOut | Out-String).Trim()
        throw "ledr-bridge-nm.exe setup --scope machine failed (exit $LASTEXITCODE): $detail"
    }
    $bridgeSetupDone = $true
    Write-InstallLog -Level 'INFO' -Message "Configured machine-scope Native Messaging hosts and URI scheme."

    Assert-NoReparsePointComponent -TargetPath $normNmDir -ExpectDirectoryIfExists $true
    if (Test-Path -LiteralPath $normNmDir -PathType Container) {
        Invoke-IcaclsChecked -TargetPath $normNmDir -GrantSpecs @(
            '*S-1-5-32-544:(OI)(CI)F',
            '*S-1-5-18:(OI)(CI)F',
            '*S-1-5-32-545:(OI)(CI)RX'
        )
        Write-InstallLog -Level 'INFO' -Message "Applied Users:RX icacls permission to '$normNmDir'."
    }

    # Phase 9: Create/configure LocalEDR Windows Service with 1s failure recovery (L-16) and start it
    $daemonExe = Join-Path $normInstallDir 'ledr-daemon.exe'
    $scBinPath = '\"' + $daemonExe + '\" --service'
    if ($prevServiceExists) {
        $cfgOut = & sc.exe config $script:ServiceName binPath= $scBinPath start= auto obj= LocalSystem DisplayName= "LocalEDR Endpoint Detection & Response" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe config $($script:ServiceName) failed (exit $LASTEXITCODE): $(($cfgOut | Out-String).Trim())"
        }
        $serviceModified = $true
    }
    else {
        $crtOut = & sc.exe create $script:ServiceName binPath= $scBinPath start= auto obj= LocalSystem DisplayName= "LocalEDR Endpoint Detection & Response" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe create $($script:ServiceName) failed (exit $LASTEXITCODE): $(($crtOut | Out-String).Trim())"
        }
        $serviceCreated = $true
    }

    $descOut = & sc.exe description $script:ServiceName "LocalEDR resident ETW/WFP/SQLite endpoint detection and response service" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe description $($script:ServiceName) failed (exit $LASTEXITCODE): $(($descOut | Out-String).Trim())"
    }

    $failOut = & sc.exe failure $script:ServiceName reset= 86400 actions= restart/1000/restart/1000/restart/1000 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failure $($script:ServiceName) failed (exit $LASTEXITCODE): $(($failOut | Out-String).Trim())"
    }

    $flagOut = & sc.exe failureflag $script:ServiceName 1 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failureflag $($script:ServiceName) failed (exit $LASTEXITCODE): $(($flagOut | Out-String).Trim())"
    }

    $startOut = & sc.exe start $script:ServiceName 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe start $($script:ServiceName) failed (exit $LASTEXITCODE): $(($startOut | Out-String).Trim())"
    }
    $startedServiceByInstaller = $true
    Wait-ForServiceRunning -Name $script:ServiceName -TimeoutSeconds $ServiceWaitSeconds
    Write-InstallLog -Level 'INFO' -Message "Service '$($script:ServiceName)' is RUNNING."

    # Phase 10: Cleanup backup directory
    Remove-BackupDirectoryBestEffort -BackupDirPath $backupDir -AllowRebootDelayForUi ($UpdateMode.IsPresent)
    Write-InstallLog -Level 'INFO' -Message "LocalEDR installation completed successfully."
}
catch {
    $errMsg = $_.Exception.Message
    Write-InstallLog -Level 'ERROR' -Message "Installation failed: $errMsg"
    Write-InstallLog -Level 'WARN' -Message "Starting step-by-step rollback..."

    try {
        if ($startedServiceByInstaller) {
            try {
                Wait-ForServiceStopped -Name $script:ServiceName -TimeoutSeconds $ServiceWaitSeconds
            }
            catch {
                Write-InstallLog -Level 'WARN' -Message "Rollback failed to stop newly started service: $($_.Exception.Message)"
            }
        }

        if ($bridgeSetupDone -and (-not $prevServiceExists) -and ($backedUpBinaries -notcontains 'ledr-bridge-nm.exe')) {
            $bridgeExe = Join-Path $normInstallDir 'ledr-bridge-nm.exe'
            if (Test-Path -LiteralPath $bridgeExe -PathType Leaf) {
                try {
                    $null = & $bridgeExe unregister --scope machine 2>&1
                }
                catch {
                    Write-InstallLog -Level 'WARN' -Message "Rollback unregister best-effort failed: $($_.Exception.Message)"
                }
            }
        }

        foreach ($newFile in $newlyInstalledFiles) {
            if (Test-Path -LiteralPath $newFile -PathType Leaf) {
                try {
                    Remove-Item -LiteralPath $newFile -Force
                }
                catch {
                    Write-InstallLog -Level 'WARN' -Message "Rollback failed removing new file '$newFile': $($_.Exception.Message)"
                }
            }
        }

        if ($null -ne $backupDir -and (Test-Path -LiteralPath $backupDir)) {
            foreach ($binName in $backedUpBinaries) {
                $bakPath = Join-Path $backupDir $binName
                $dstPath = Join-Path $normInstallDir $binName
                if (Test-Path -LiteralPath $bakPath -PathType Leaf) {
                    try {
                        if ($binName -eq 'ledr-ui.exe') {
                            if (Test-Path -LiteralPath $dstPath -PathType Leaf) {
                                $tmpKill = $dstPath + '.rollback-remove'
                                [System.IO.File]::Move($dstPath, $tmpKill)
                                try { Remove-Item -LiteralPath $tmpKill -Force } catch { }
                            }
                            [System.IO.File]::Move($bakPath, $dstPath)
                        }
                        else {
                            [System.IO.File]::Copy($bakPath, $dstPath, $true)
                        }
                        Write-InstallLog -Level 'INFO' -Message "Rollback restored binary: $binName"
                    }
                    catch {
                        Write-InstallLog -Level 'ERROR' -Message "Rollback failed restoring binary '$binName': $($_.Exception.Message)"
                    }
                }
            }

            foreach ($ruleName in $backedUpRules) {
                $bakRule = Join-Path (Join-Path $backupDir 'rules') $ruleName
                $dstRule = Join-Path $normRulesDir $ruleName
                if (Test-Path -LiteralPath $bakRule -PathType Leaf) {
                    try {
                        [System.IO.File]::Copy($bakRule, $dstRule, $true)
                        Write-InstallLog -Level 'INFO' -Message "Rollback restored rule: rules\$ruleName"
                    }
                    catch {
                        Write-InstallLog -Level 'ERROR' -Message "Rollback failed restoring rule 'rules\$ruleName': $($_.Exception.Message)"
                    }
                }
            }
        }

        if ($bridgeSetupDone -and ($backedUpBinaries -contains 'ledr-bridge-nm.exe')) {
            $restoredBridge = Join-Path $normInstallDir 'ledr-bridge-nm.exe'
            $restoredUi = Join-Path $normInstallDir 'ledr-ui.exe'
            if (Test-Path -LiteralPath $restoredBridge -PathType Leaf) {
                try {
                    $null = & $restoredBridge setup --scope machine --bridge-exe $restoredBridge --ui-exe $restoredUi 2>&1
                }
                catch {
                    Write-InstallLog -Level 'WARN' -Message "Rollback bridge re-setup best-effort failed: $($_.Exception.Message)"
                }
            }
        }

        if ($serviceCreated) {
            $null = & sc.exe delete $script:ServiceName 2>&1
            Write-InstallLog -Level 'INFO' -Message "Rollback deleted newly created service '$($script:ServiceName)'."
        }
        elseif ($serviceModified -and ($null -ne $prevServiceConfig) -and (-not [string]::IsNullOrWhiteSpace($prevServiceConfig.BinaryPathName))) {
            $null = & sc.exe config $script:ServiceName binPath= $prevServiceConfig.BinaryPathName start= $prevServiceConfig.StartType DisplayName= $prevServiceConfig.DisplayName 2>&1
            Write-InstallLog -Level 'INFO' -Message "Rollback restored previous service configuration."
        }

        if ($prevServiceWasRunning) {
            $null = & sc.exe start $script:ServiceName 2>&1
            if ($LASTEXITCODE -eq 0) {
                Wait-ForServiceRunning -Name $script:ServiceName -TimeoutSeconds $ServiceWaitSeconds
                Write-InstallLog -Level 'INFO' -Message "Rollback restarted previously running service '$($script:ServiceName)'."
            }
        }

        if ($createdRulesDir -and (Test-Path -LiteralPath $normRulesDir)) {
            $items = @(Get-ChildItem -LiteralPath $normRulesDir -Force)
            if ($items.Count -eq 0) { Remove-Item -LiteralPath $normRulesDir -Force }
        }
        if ($createdInstallDir -and (Test-Path -LiteralPath $normInstallDir)) {
            $items = @(Get-ChildItem -LiteralPath $normInstallDir -Force)
            if ($items.Count -eq 0) { Remove-Item -LiteralPath $normInstallDir -Force }
        }
    }
    finally {
        if ($null -ne $backupDir) {
            Remove-BackupDirectoryBestEffort -BackupDirPath $backupDir -AllowRebootDelayForUi ($UpdateMode.IsPresent)
        }
        Write-InstallLog -Level 'ERROR' -Message "Rollback finished; exiting with code 1."
        Close-InstallLog
    }

    exit 1
}
finally {
    Close-InstallLog
}
