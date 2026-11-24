[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\Program Files\LocalEDR',
    [string]$DataDir = 'C:\ProgramData\LocalEDR',
    [switch]$PurgeData,
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
$script:LogWriter = $null
$script:LogBuffer = New-Object System.Collections.Generic.List[string]

function Write-UninstallLog {
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

function Close-UninstallLog {
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

function Assert-NoReparsePointsInTree {
    param([Parameter(Mandatory = $true)][string]$RootDir)
    if (-not (Test-Path -LiteralPath $RootDir)) {
        return
    }
    Assert-NoReparsePointComponent -TargetPath $RootDir -ExpectDirectoryIfExists $true
    $entries = @(Get-ChildItem -LiteralPath $RootDir -Recurse -Force -ErrorAction Stop)
    foreach ($entry in $entries) {
        if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point detected inside data directory tree: $($entry.FullName)"
        }
    }
}

function Wait-ForUiExit {
    param([Parameter(Mandatory = $true)][int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $uiProcs = @(Get-Process -Name 'ledr-ui' -ErrorAction SilentlyContinue)
        if ($uiProcs.Count -eq 0) {
            return
        }
        if ((Get-Date) -ge $deadline) {
            $pids = (($uiProcs | ForEach-Object { $_.Id }) -join ', ')
            throw "Timed out after ${TimeoutSeconds}s waiting for ledr-ui.exe to exit (PIDs: $pids)."
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
        Write-UninstallLog -Level 'INFO' -Message "Stopping service '$Name' (current state: $($info.Status))."
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
            $isSharingOrAccess = $false
            $matchedEx = $null
            $cursor = $ex
            while ($null -ne $cursor) {
                if (($cursor -is [System.IO.IOException]) -or ($cursor -is [System.UnauthorizedAccessException])) {
                    $isSharingOrAccess = $true
                    $matchedEx = $cursor
                    break
                }
                $cursor = $cursor.InnerException
            }
            if ((-not $isSharingOrAccess) -or ((Get-Date) -ge $deadline)) {
                $detailMsg = if ($null -ne $matchedEx) { $matchedEx.Message } else { $ex.Message }
                throw "Failed '$Description' within ${TimeoutSeconds}s lock retry budget: $detailMsg"
            }
            Start-Sleep -Milliseconds 200
        }
    }
}

function Assert-NoUnresolvedSuspendedAlerts {
    param(
        [Parameter(Mandatory = $true)][string]$DaemonExePath,
        [Parameter(Mandatory = $true)][string]$DbPath
    )
    if (-not (Test-Path -LiteralPath $DaemonExePath -PathType Leaf)) {
        Write-UninstallLog -Level 'INFO' -Message "Daemon binary not found at '$DaemonExePath'; skipping unresolved suspended alert check."
        return
    }
    if (-not (Test-Path -LiteralPath $DbPath -PathType Leaf)) {
        Write-UninstallLog -Level 'INFO' -Message "Database not found at '$DbPath'; skipping unresolved suspended alert check."
        return
    }
    Assert-NoReparsePointComponent -TargetPath $DaemonExePath -ExpectDirectoryIfExists $false
    Assert-NoReparsePointComponent -TargetPath $DbPath -ExpectDirectoryIfExists $false

    $checkRc = -1
    $checkOut = @()
    $prevEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $checkOut = & $DaemonExePath '--check-unresolved-suspended' '--db' $DbPath 2>&1
        $checkRc = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevEap
    }

    $detail = (($checkOut | ForEach-Object { $_.ToString() }) -join "`n").Trim()
    if ($checkRc -eq 0) {
        Write-UninstallLog -Level 'INFO' -Message "Verified zero unresolved suspended alerts in '$DbPath'."
        return
    }
    if ($checkRc -eq 3) {
        throw "Unresolved suspended process alerts exist in '$DbPath'. Open ledr-ui.exe and resolve all suspended processes (Allow or Terminate) before uninstalling LocalEDR so contained processes do not remain permanently suspended. Detail: $detail"
    }
    throw "Unresolved suspended process check failed (exit $checkRc) for '$DbPath'; aborting uninstall to prevent orphaned suspended processes. Detail: $detail"
}

function Invoke-HoneypotCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$DaemonExePath,
        [Parameter(Mandatory = $true)][string]$DbPath,
        [int]$TimeoutSeconds = 5
    )
    if (-not (Test-Path -LiteralPath $DaemonExePath -PathType Leaf)) {
        Write-UninstallLog -Level 'WARN' -Message "Daemon binary not found at '$DaemonExePath'; skipping honeypot cleanup."
        return
    }
    Assert-NoReparsePointComponent -TargetPath $DaemonExePath -ExpectDirectoryIfExists $false
    if (Test-Path -LiteralPath $DbPath -PathType Leaf) {
        Assert-NoReparsePointComponent -TargetPath $DbPath -ExpectDirectoryIfExists $false
    }

    $deadline = (Get-Date).AddSeconds([Math]::Max(0, $TimeoutSeconds))
    while ($true) {
        $cleanupRc = -1
        $cleanupOut = @()
        $prevEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $cleanupOut = & $DaemonExePath '--cleanup-honeypots' '--db' $DbPath 2>&1
            $cleanupRc = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $prevEap
        }

        $detail = (($cleanupOut | ForEach-Object { $_.ToString() }) -join "`n").Trim()
        if ($cleanupRc -eq 0) {
            Write-UninstallLog -Level 'INFO' -Message "Honeypot cleanup completed: $detail"
            return
        }
        if ($cleanupRc -eq 4) {
            $hasRetryableLock = $detail -match '(?i)(sharing violation|used by another process|being used by another|access is denied|denied|locked|os error 32|os error 33|os error 5)'
            $onlyGuardRejection = ($detail -match '(?i)(reparse point|hardlinked target)') -and (-not $hasRetryableLock)
            if ($hasRetryableLock -and (-not $onlyGuardRejection) -and ((Get-Date) -lt $deadline)) {
                Start-Sleep -Milliseconds 250
                continue
            }
            Write-UninstallLog -Level 'WARN' -Message "Honeypot cleanup reported partial failure (exit 4); continuing uninstall: $detail"
            return
        }

        Write-UninstallLog -Level 'WARN' -Message "Honeypot cleanup failed (exit $cleanupRc); continuing uninstall: $detail"
        return
    }
}

function Remove-ArpRegistryKey64 {
    $baseKey = $null
    $uninstallKey = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        $uninstallKey = $baseKey.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', $true)
        if ($null -ne $uninstallKey) {
            $uninstallKey.DeleteSubKeyTree('LocalEDR', $false)
        }
    }
    finally {
        if ($null -ne $uninstallKey) { $uninstallKey.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
}

$normInstallDir = Normalize-FullPath -Path $InstallDir
$normDataDir = Normalize-FullPath -Path $DataDir
$normLogsDir = Join-Path $normDataDir 'logs'
$logFilePath = Join-Path $normLogsDir 'installer.log'

Write-UninstallLog -Level 'INFO' -Message "Starting LocalEDR uninstallation (InstallDir=$normInstallDir, DataDir=$normDataDir, PurgeData=$($PurgeData.IsPresent))."

Assert-NoReparsePointComponent -TargetPath $normInstallDir -ExpectDirectoryIfExists $true
Assert-NoReparsePointComponent -TargetPath $normDataDir -ExpectDirectoryIfExists $true
Assert-NoReparsePointComponent -TargetPath $normLogsDir -ExpectDirectoryIfExists $true
Assert-NoReparsePointComponent -TargetPath $logFilePath -ExpectDirectoryIfExists $false

if (Test-Path -LiteralPath $normDataDir -PathType Container) {
    if (-not (Test-Path -LiteralPath $normLogsDir)) {
        [void](New-Item -ItemType Directory -Path $normLogsDir -Force)
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $script:LogWriter = New-Object System.IO.StreamWriter($logFilePath, $true, $utf8NoBom)
    $script:LogWriter.AutoFlush = $true
    foreach ($line in $script:LogBuffer) {
        $script:LogWriter.WriteLine($line)
    }
    $script:LogBuffer.Clear()
}

try {
    # 0. Abort before stopping service, UI, or deleting DB if unresolved suspended processes exist (L-07)
    $daemonExe = Join-Path $normInstallDir 'ledr-daemon.exe'
    $dbPath = Join-Path $normDataDir 'localedr.db'
    Assert-NoUnresolvedSuspendedAlerts -DaemonExePath $daemonExe -DbPath $dbPath

    # 1. Wait up to 10s for ledr-ui.exe exit
    Wait-ForUiExit -TimeoutSeconds $UiWaitSeconds

    # 2. Wait up to 15s for LocalEDR service stop
    Wait-ForServiceStopped -Name $script:ServiceName -TimeoutSeconds $ServiceWaitSeconds

    # 2.5. Remove tracked and discovered honeypot canary files after service stop (L-06)
    Invoke-HoneypotCleanup -DaemonExePath $daemonExe -DbPath $dbPath -TimeoutSeconds $LockRetrySeconds

    # 3. Unregister machine-scope Native Messaging & URI handlers (5s lock retry)
    $bridgeExe = Join-Path $normInstallDir 'ledr-bridge-nm.exe'
    if (Test-Path -LiteralPath $bridgeExe -PathType Leaf) {
        Invoke-WithFileLockRetry -TimeoutSeconds $LockRetrySeconds -Description 'ledr-bridge-nm unregister' -Operation {
            $out = & $bridgeExe unregister --scope machine 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw [System.IO.IOException]("ledr-bridge-nm.exe unregister --scope machine failed (exit $LASTEXITCODE): $(($out | Out-String).Trim())")
            }
        }
        Write-UninstallLog -Level 'INFO' -Message 'Unregistered machine-scope Native Messaging hosts and URI scheme.'
    }
    else {
        Write-UninstallLog -Level 'WARN' -Message "Bridge binary not found at '$bridgeExe'; skipping unregister."
    }

    # 4. Delete LocalEDR service
    $svcInfo = Get-ServiceStateInfo -Name $script:ServiceName
    if ($svcInfo.Exists) {
        $delOut = & sc.exe delete $script:ServiceName 2>&1
        if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1060) -and ($LASTEXITCODE -ne 1072)) {
            throw "sc.exe delete $($script:ServiceName) failed (exit $LASTEXITCODE): $(($delOut | Out-String).Trim())"
        }
        $deadline = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $deadline) {
            $cur = Get-ServiceStateInfo -Name $script:ServiceName
            if (-not $cur.Exists) {
                break
            }
            Start-Sleep -Milliseconds 200
        }
        Write-UninstallLog -Level 'INFO' -Message "Deleted service '$($script:ServiceName)'."
    }

    # 5. Remove installed binaries and uninstall.ps1 with 5s lock retry
    $filesToDelete = @($script:BinaryNames) + @('uninstall.ps1')
    foreach ($fileName in $filesToDelete) {
        $target = Join-Path $normInstallDir $fileName
        if (Test-Path -LiteralPath $target -PathType Leaf) {
            Assert-NoReparsePointComponent -TargetPath $target -ExpectDirectoryIfExists $false
            Invoke-WithFileLockRetry -TimeoutSeconds $LockRetrySeconds -Description "remove $target" -Operation {
                Remove-Item -LiteralPath $target -Force
            }
            Write-UninstallLog -Level 'INFO' -Message "Removed file: $target"
        }
    }

    if (Test-Path -LiteralPath $normInstallDir -PathType Container) {
        $remaining = @(Get-ChildItem -LiteralPath $normInstallDir -Force)
        if ($remaining.Count -eq 0) {
            Remove-Item -LiteralPath $normInstallDir -Force
            Write-UninstallLog -Level 'INFO' -Message "Removed empty install directory: $normInstallDir"
        }
    }

    # 6. Remove 64-bit ARP Uninstall registry key
    Remove-ArpRegistryKey64
    Write-UninstallLog -Level 'INFO' -Message 'Removed ARP uninstall registry key.'

    # 7. Preserve ProgramData by default; delete ONLY when -PurgeData is passed
    if ($PurgeData.IsPresent) {
        Write-UninstallLog -Level 'INFO' -Message "PurgeData requested; closing installer.log and removing '$normDataDir'."
        Close-UninstallLog
        if (Test-Path -LiteralPath $normDataDir) {
            Assert-NoReparsePointsInTree -RootDir $normDataDir
            Invoke-WithFileLockRetry -TimeoutSeconds $LockRetrySeconds -Description "purge $normDataDir" -Operation {
                Remove-Item -LiteralPath $normDataDir -Recurse -Force
            }
        }
        $tempSummary = Join-Path $env:TEMP 'LocalEDR-uninstall.log'
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        [System.IO.File]::WriteAllText($tempSummary, "[$ts] [INFO] Uninstalled LocalEDR and purged '$normDataDir'.`r`n", $utf8NoBom)
    }
    else {
        Write-UninstallLog -Level 'INFO' -Message "Preserved data directory '$normDataDir' (default uninstall policy)."
    }
}
catch {
    Write-UninstallLog -Level 'ERROR' -Message "Uninstallation failed: $($_.Exception.Message)"
    Close-UninstallLog
    throw
}
finally {
    Close-UninstallLog
}
