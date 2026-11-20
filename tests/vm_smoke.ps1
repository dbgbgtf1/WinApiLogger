[CmdletBinding()]
param(
    [string]$Root = "C:\analysis\byppa_dump",
    [string]$DriverPath = "",
    [string]$CliPath = "",
    [string]$AnalysisPath = "",
    [string]$CertificatePath = "",
    [string]$ResultPath = "",
    [string]$ExpectedFileVersion = "10.0.26100.9974",
    [string]$ServiceName = "WinApiLogger"
)

$ErrorActionPreference = 'Stop'
if (-not $DriverPath) {
    $DriverPath = Join-Path $Root 'WinApiLogger.sys'
}
if (-not $CliPath) {
    $CliPath = Join-Path $Root 'WinApiLoggerCli.exe'
}
if (-not $AnalysisPath) {
    $AnalysisPath = Join-Path $Root 'analysis.json'
}
if (-not $CertificatePath) {
    $CertificatePath = Join-Path $Root 'WinApiLoggerTest.cer'
}
if (-not $ResultPath) {
    $ResultPath = Join-Path $Root 'WinApiLogger-smoke.json'
}

$serviceName = $ServiceName
$result = [ordered]@{
    success = $false
    started_at = (Get-Date).ToString('o')
    finished_at = $null
    target_pid = $null
    target_exit_code = $null
    stream_id = $null
    stream_state = $null
    stream_failure = $null
    loaded_module_mask = $null
    installed_module_mask = $null
    failure_source = $null
    failure_destination = $null
    record_count = 0
    first_record = $null
    delayed_read_exit_code = $null
    delayed_read_output = $null
    last_stage = "initialized"
    steps = @()
    error = $null
}
$target = $null

function Save-Result {
    $json = $script:result | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText(
        $ResultPath,
        $json,
        (New-Object Text.UTF8Encoding($false)))
}

function Set-Stage {
    param(
        [string]$Name
    )
    $script:result.last_stage = $Name
    $line = "{0} {1}`r`n" -f (Get-Date).ToString('o'), $Name
    [IO.File]::AppendAllText(
        "$ResultPath.stages",
        $line,
        (New-Object Text.UTF8Encoding($false)))
    Save-Result
}

function Add-Step {
    param(
        [string]$Name,
        [bool]$Success,
        [string]$Detail = ""
    )
    $script:result.steps += [ordered]@{
        name = $Name
        success = $Success
        detail = $Detail
    }
    Save-Result
}

function Invoke-GuestCommand {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = (& $FilePath @Arguments 2>&1 |
            ForEach-Object { $_.ToString() } |
            Out-String)
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
    return [pscustomobject]@{
        exit_code = $LASTEXITCODE
        output = $output.Trim()
    }
}

function Wait-ServiceState {
    param(
        [string]$ExpectedState,
        [int]$TimeoutSeconds = 15
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $query = Invoke-GuestCommand 'sc.exe' @('query', $serviceName)
        if ($query.exit_code -eq 0 -and
            $query.output -match "\b$ExpectedState\b") {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

try {
    Set-Stage "administrator-check"
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Guest process is not running as administrator'
    }
    Add-Step 'administrator' $true

    Set-Stage "windows-version-check"
    if ([Environment]::OSVersion.Version.Build -lt 26100) {
        throw "Expected Windows 11 24H2 or newer"
    }
    Add-Step 'windows-version' $true

    Set-Stage "target-dll-identity-check"
    $analysis = Get-Content -LiteralPath $AnalysisPath -Raw |
        ConvertFrom-Json
    foreach ($module in $analysis) {
        $path = Join-Path $env:SystemRoot "System32\$($module.name)"
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Missing system module: $path"
        }
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        if ($actualHash -ne $module.sha256) {
            throw "SHA-256 mismatch for $path"
        }
        $version = (Get-Item -LiteralPath $path).VersionInfo.FileVersion
        if ($version -notmatch [regex]::Escape($ExpectedFileVersion)) {
            throw "Unexpected file version for $path`: $version"
        }
    }
    Add-Step 'target-dll-identity' $true

    Set-Stage "certificate-import"
    foreach ($store in @('Root', 'TrustedPublisher')) {
        $import = Invoke-GuestCommand 'certutil.exe' @(
            '-addstore', '-f', $store, $CertificatePath)
        if ($import.exit_code -ne 0) {
            throw "certutil failed to import into $store`: $($import.output)"
        }
    }
    Add-Step 'certificate-import' $true

    Set-Stage "remove-existing-service"
    (Invoke-GuestCommand 'sc.exe' @('stop', $serviceName)) | Out-Null
    Start-Sleep -Milliseconds 500
    (Invoke-GuestCommand 'sc.exe' @('delete', $serviceName)) | Out-Null

    Set-Stage "create-service"
    $create = Invoke-GuestCommand 'sc.exe' @(
        'create',
        $serviceName,
        'type=', 'kernel',
        'start=', 'demand',
        'error=', 'normal',
        'binPath=', $DriverPath,
        'DisplayName=', 'WinApiLogger'
    )
    if ($create.exit_code -ne 0) {
        throw "Service creation failed: $($create.output)"
    }
    Set-Stage "start-driver"
    $start = Invoke-GuestCommand 'sc.exe' @('start', $serviceName)
    if ($start.exit_code -ne 0) {
        throw "Driver start failed: $($start.output)"
    }
    if (-not (Wait-ServiceState 'RUNNING')) {
        throw 'Driver service did not reach RUNNING state'
    }
    Add-Step 'driver-start' $true

    Set-Stage "filter-add"
    $addFilter = Invoke-GuestCommand $CliPath @(
        'filter', 'add', 'ping.exe')
    if ($addFilter.exit_code -ne 0) {
        throw "Adding filter failed: $($addFilter.output)"
    }
    Add-Step 'filter-add' $true

    Set-Stage "target-start"
    $target = Start-Process `
        -FilePath (Join-Path $env:SystemRoot 'System32\PING.EXE') `
        -ArgumentList @('-n', '20', '127.0.0.1') `
        -WindowStyle Hidden `
        -PassThru
    $result.target_pid = $target.Id
    Add-Step 'target-start' $true "PID=$($target.Id)"

    Set-Stage "stream-visible"
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline -and -not $result.stream_id) {
        $list = Invoke-GuestCommand $CliPath @('list')
        foreach ($line in ($list.output -split "\r?\n")) {
            $fields = @($line -split "`t")
            if ($fields.Count -ge 5 -and
                $fields[1] -eq [string]$target.Id) {
                $result.stream_id = [uint64]$fields[0]
                $result.stream_state = $fields[2]
                $result.stream_failure = $fields[3]
                if ($fields.Count -ge 7) {
                    $result.loaded_module_mask = $fields[5]
                    $result.installed_module_mask = $fields[6]
                }
                if ($fields.Count -ge 9) {
                    $result.failure_source = $fields[7]
                    $result.failure_destination = $fields[8]
                }
                break
            }
        }
        if (-not $result.stream_id) {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $result.stream_id) {
        throw 'Target stream did not appear in LIST_STREAMS'
    }
    if ($result.stream_state -ne 'active') {
        throw "Target stream state is $($result.stream_state): $($result.stream_failure)"
    }
    Add-Step 'stream-visible' $true "stream=$($result.stream_id)"

    Set-Stage "records-read"
    $deadline = (Get-Date).AddSeconds(15)
    $recordPattern = '^\d+\.\d+\s+(?:\S+:0x[0-9A-Fa-f]+|unknown-0x[0-9A-Fa-f]+)\s+called\s+\S+!\S+'
    while ((Get-Date) -lt $deadline -and $result.record_count -eq 0) {
        $read = Invoke-GuestCommand $CliPath @(
            'read', '--stream', [string]$result.stream_id)
        if ($read.exit_code -ne 0) {
            throw "READ_STREAM failed: $($read.output)"
        }
        $records = @(
            $read.output -split "\r?\n" |
                Where-Object { $_ -match $recordPattern }
        )
        if ($records.Count -gt 0) {
            $result.record_count = $records.Count
            $result.first_record = $records[0]
            break
        }
        $listAfterRead = Invoke-GuestCommand $CliPath @('list')
        foreach ($line in ($listAfterRead.output -split "\r?\n")) {
            $fields = @($line -split "`t")
            if ($fields.Count -ge 7 -and
                $fields[1] -eq [string]$target.Id) {
                $result.stream_state = $fields[2]
                $result.stream_failure = $fields[3]
                $result.loaded_module_mask = $fields[5]
                $result.installed_module_mask = $fields[6]
                if ($fields.Count -ge 9) {
                    $result.failure_source = $fields[7]
                    $result.failure_destination = $fields[8]
                }
                break
            }
        }
        Start-Sleep -Milliseconds 500
    }
    if ($result.record_count -eq 0) {
        throw 'No API records were returned for the target process'
    }
    Add-Step 'records-read' $true "count=$($result.record_count)"

    Set-Stage "wait-target-exit"
    if (-not $target.WaitForExit(30000)) {
        throw 'Target process did not exit within 30 seconds'
    }
    $result.target_exit_code = $target.ExitCode
    if ($target.ExitCode -ne 0) {
        throw "Target process exited unexpectedly with code $($target.ExitCode)"
    }
    Start-Sleep -Milliseconds 500

    Set-Stage "verify-stream-removed"
    $deadline = (Get-Date).AddSeconds(5)
    $stillListed = $true
    while ((Get-Date) -lt $deadline) {
        $list = Invoke-GuestCommand $CliPath @('list')
        $stillListed = $list.output -match "^\s*\d+\s+$($target.Id)\s+" -or
            $list.output -match "^\s*$($result.stream_id)\s+"
        if (-not $stillListed) {
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if ($stillListed) {
        throw 'Exited target stream remained in LIST_STREAMS'
    }
    Add-Step 'exit-removes-stream' $true

    Set-Stage "delayed-read"
    $delayed = Invoke-GuestCommand $CliPath @(
        'read', '--stream', [string]$result.stream_id)
    $result.delayed_read_exit_code = $delayed.exit_code
    $result.delayed_read_output = $delayed.output
    if ($delayed.exit_code -eq 0 -or
        $delayed.output -notmatch '1168|not found') {
        throw "Delayed READ_STREAM did not return not found: $($delayed.output)"
    }
    Add-Step 'delayed-read-not-found' $true

    Set-Stage "smoke-complete"
    $result.success = $true
}
catch {
    $result.error = $_.Exception.Message
    Add-Step 'failure' $false $result.error
}
finally {
    Set-Stage "cleanup-stop-target"
    if ($null -ne $target -and -not $target.HasExited) {
        Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue
        [void]$target.WaitForExit(5000)
    }
    Set-Stage "cleanup-stop-driver"
    (Invoke-GuestCommand 'sc.exe' @('stop', $serviceName)) | Out-Null
    if (Wait-ServiceState 'STOPPED' 10) {
        Add-Step 'driver-stop' $true
    }
    else {
        Add-Step 'driver-stop' $false 'Service did not reach STOPPED'
        if ($result.success) {
            $result.success = $false
            $result.error = 'Driver service did not stop'
        }
    }
    (Invoke-GuestCommand 'sc.exe' @('delete', $serviceName)) | Out-Null
    $result.finished_at = (Get-Date).ToString('o')
    Save-Result
}

if (-not $result.success) {
    exit 1
}
