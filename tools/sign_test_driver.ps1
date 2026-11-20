[CmdletBinding()]
param(
    [string]$DriverPath = "",
    [string]$CertificatePath = ""
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $DriverPath) {
    $DriverPath = Join-Path $root 'build\WinApiLogger.sys'
}
if (-not $CertificatePath) {
    $CertificatePath = Join-Path $root 'build\vm\WinApiLoggerTest.cer'
}
$DriverPath = [IO.Path]::GetFullPath($DriverPath)
$CertificatePath = [IO.Path]::GetFullPath($CertificatePath)
$signTool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'

if (-not (Test-Path -LiteralPath $DriverPath)) {
    throw "Driver was not found: $DriverPath"
}
if (-not (Test-Path -LiteralPath $signTool)) {
    throw "signtool was not found: $signTool"
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $CertificatePath) |
    Out-Null
$subject = 'CN=WinApiLogger Test {0}' -f ([guid]::NewGuid().ToString('N'))
$certificate = $null
try {
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $subject `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddDays(2)
    Export-Certificate `
        -Cert $certificate `
        -FilePath $CertificatePath `
        -Type CERT |
        Out-Null

    & $signTool sign `
        /v `
        /fd SHA256 `
        /s My `
        /sha1 $certificate.Thumbprint `
        $DriverPath
    if ($LASTEXITCODE -ne 0) {
        throw "signtool sign failed with exit code $LASTEXITCODE"
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $DriverPath
    if ($null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne
            $certificate.Thumbprint) {
        throw 'Signed driver does not contain the expected test certificate'
    }

    [pscustomobject]@{
        driver = $DriverPath
        certificate = $CertificatePath
        thumbprint = $certificate.Thumbprint
        subject = $subject
    } | ConvertTo-Json | Write-Output
}
finally {
    if ($null -ne $certificate) {
        Remove-Item `
            -LiteralPath ("Cert:\CurrentUser\My\{0}" -f $certificate.Thumbprint) `
            -DeleteKey `
            -ErrorAction SilentlyContinue
    }
}
