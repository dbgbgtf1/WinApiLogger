[CmdletBinding()]
param(
    [switch]$EnableTestSigning,
    [string]$ResultPath = ""
)

$ErrorActionPreference = 'Stop'
if (-not $ResultPath) {
    $ResultPath = Join-Path $PSScriptRoot 'vm_preflight.json'
}

$result = [ordered]@{
    success = $false
    is_admin = $false
    os_build = $null
    secure_boot = $null
    testsigning_enabled = $false
    changed_testsigning = $false
    reboot_required = $false
    error = $null
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $result.is_admin = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $result.is_admin) {
        throw 'Guest process is not running with administrator privileges'
    }

    $result.os_build = [Environment]::OSVersion.Version.Build
    if ($result.os_build -lt 26100) {
        throw "Expected Windows 11 24H2 or newer, got build $($result.os_build)"
    }

    try {
        $result.secure_boot = Confirm-SecureBootUEFI
    }
    catch {
        $result.secure_boot = $false
    }
    if ($result.secure_boot) {
        throw 'Secure Boot is enabled and blocks test signing'
    }

    $bootOutput = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
    $bootOutput = $bootOutput -replace "`r", ""
    $result.testsigning_enabled =
        $bootOutput -match '(?im)^\s*testsigning\s+Yes\s*$'
    if (-not $result.testsigning_enabled -and $EnableTestSigning) {
        & bcdedit.exe /set '{current}' testsigning on | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "bcdedit testsigning failed with exit code $LASTEXITCODE"
        }
        $result.changed_testsigning = $true
        $result.reboot_required = $true
        $result.testsigning_enabled = $true
    }
    $result.success = $true
}
catch {
    $result.error = $_.Exception.Message
}
finally {
    $result |
        ConvertTo-Json |
        Set-Content -LiteralPath $ResultPath -Encoding UTF8
}

if (-not $result.success) {
    exit 1
}
