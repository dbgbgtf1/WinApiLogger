[CmdletBinding()]
param(
    [switch]$Test,
    [switch]$SkipAnalyze
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $root 'build'
$windowsKitVersion = '10.0.26100.0'
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$llvm = 'C:\Program Files\LLVM\bin'
$clang = Join-Path $llvm 'clang.exe'
$clangCl = Join-Path $llvm 'clang-cl.exe'
$windowsKit = 'C:\Program Files (x86)\Windows Kits\10'
$kitInclude = Join-Path $windowsKit "Include\$windowsKitVersion"
$kitKmLib = Join-Path $windowsKit "Lib\$windowsKitVersion\km\x64"
$kitUcrtLib = Join-Path $windowsKit "Lib\$windowsKitVersion\ucrt\x64"
$infVerif = Join-Path $windowsKit "Tools\$windowsKitVersion\x64\infverif.exe"

foreach ($required in @($vswhere, $clang, $clangCl, $kitInclude, $kitKmLib, $infVerif)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required build component is missing: $required"
    }
}

$vsJson = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json
if ($LASTEXITCODE -ne 0) {
    throw 'vswhere failed'
}
$vsInfo = $vsJson | ConvertFrom-Json | Select-Object -First 1
if ($null -eq $vsInfo) {
    throw 'Visual Studio C++ tools were not found'
}
$vsDevCmd = Join-Path $vsInfo.installationPath 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path -LiteralPath $vsDevCmd)) {
    throw "VsDevCmd.bat is missing: $vsDevCmd"
}
$msvcRoot = Join-Path $vsInfo.installationPath 'VC\Tools\MSVC'
$msvcTools = Get-ChildItem -LiteralPath $msvcRoot -Directory |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1
if ($null -eq $msvcTools) {
    throw "MSVC tool directories are missing: $msvcRoot"
}
$msvcInclude = Join-Path $msvcTools.FullName 'include'
if (-not (Test-Path -LiteralPath $msvcInclude)) {
    throw "MSVC include directory is missing: $msvcInclude"
}

New-Item -ItemType Directory -Force -Path $build | Out-Null
Push-Location $root
try {
    & python '.\tools\generate_compile_commands.py' `
        --workspace $root `
        --clang $clang `
        --clang-cl $clangCl `
        --msvc-include $msvcInclude `
        --kit-include $kitInclude `
        --output (Join-Path $root 'compile_commands.json')
    if ($LASTEXITCODE -ne 0) {
        throw 'compile database generation failed'
    }

    if (-not $SkipAnalyze) {
        & python '.\tools\analyze_targets.py' `
            --targets '.\target_dlls' `
            --build '.\build' `
            --driver-include '.\driver\generated' `
            --reader-include '.\reader\generated'
        if ($LASTEXITCODE -ne 0) {
            throw 'target analysis failed'
        }
    }

    & $clang `
        -target x86_64-pc-windows-msvc `
        -O2 `
        -ffreestanding `
        -fno-stack-protector `
        -fno-builtin `
        -fno-exceptions `
        -fno-rtti `
        -D_LOGGER_FREESTANDING `
        -c '.\logger\logger.c' `
        -o '.\build\logger.obj'
    if ($LASTEXITCODE -ne 0) {
        throw 'logger compilation failed'
    }

    & python '.\tools\build_logger_payload.py' '.\build\logger.obj' `
        --binary '.\build\logger_payload.bin' `
        --header '.\driver\generated\generated_payload.h' `
        --report '.\build\logger_payload.txt'
    if ($LASTEXITCODE -ne 0) {
        throw 'logger payload generation failed'
    }

    $driverModules = @(
        'driver',
        'process',
        'image',
        'memory',
        'queue',
        'ioctl'
    )
    $driverCommands = foreach ($moduleName in $driverModules) {
        'cl.exe /nologo /c /kernel /GS- /GR- /EHs-c- /Zl /W4 /WX- ' +
            '/DUNICODE /D_UNICODE /D_AMD64_ /D_WIN64 /DAMD64 ' +
            ('/I"{0}\km" /I"{0}\shared" /I"{0}\ucrt" ' -f $kitInclude) +
            ('/Fo:build\{0}.obj driver\{0}.c' -f $moduleName)
    }
    $driverCompile = 'call "{0}" -arch=x64 -host_arch=x64 >nul && ' +
        ($driverCommands -join ' && ')
    $driverCompile = $driverCompile -f $vsDevCmd
    & cmd.exe /d /s /c $driverCompile
    if ($LASTEXITCODE -ne 0) {
        throw 'driver compilation failed'
    }

    $driverObjects = ($driverModules | ForEach-Object {
        "build\$_.obj"
    }) -join ' '
    $driverLink = 'call "{0}" -arch=x64 -host_arch=x64 >nul && ' +
        'link.exe /NOLOGO /DRIVER /NODEFAULTLIB /INTEGRITYCHECK ' +
        '/SUBSYSTEM:NATIVE ' +
        '/MACHINE:X64 /ENTRY:DriverEntry /OUT:build\WinApiLogger.sys ' +
        '/LIBPATH:"{1}" /LIBPATH:"{2}" {3} ' +
        'ntoskrnl.lib wdmsec.lib bufferoverflowk.lib'
    $driverLink = $driverLink -f `
        $vsDevCmd, $kitKmLib, $kitUcrtLib, $driverObjects
    & cmd.exe /d /s /c $driverLink
    if ($LASTEXITCODE -ne 0) {
        throw 'driver link failed'
    }

    & $infVerif /w '.\driver\WinApiLogger.inf'
    if ($LASTEXITCODE -ne 0) {
        throw 'driver INF validation failed'
    }

    $readerCompile = 'call "{0}" -arch=x64 -host_arch=x64 >nul && ' +
        'cl.exe /nologo /O2 /W4 /WX- /MT /DUNICODE /D_UNICODE ' +
        '/I. /Fo:build\reader.obj reader\reader.c ' +
        '/link /OUT:build\WinApiLoggerCli.exe /SUBSYSTEM:CONSOLE /MACHINE:X64'
    $readerCompile = $readerCompile -f $vsDevCmd
    & cmd.exe /d /s /c $readerCompile
    if ($LASTEXITCODE -ne 0) {
        throw 'reader build failed'
    }

    $runtimeCompile = 'call "{0}" -arch=x64 -host_arch=x64 >nul && ' +
        'ml64.exe /nologo /c /Fo"build\logger_register_check.obj" ' +
        'tests\logger_register_check.asm && ' +
        'cl.exe /nologo /O2 /W4 /MT /std:c11 /DUNICODE /D_UNICODE ' +
        '/Fo:build\logger_runtime_test.obj tests\logger_runtime_test.c ' +
        '/link /OUT:build\logger_runtime_test.exe /SUBSYSTEM:CONSOLE ' +
        '/MACHINE:X64 build\logger_register_check.obj'
    $runtimeCompile = $runtimeCompile -f $vsDevCmd
    & cmd.exe /d /s /c $runtimeCompile
    if ($LASTEXITCODE -ne 0) {
        throw 'logger runtime test build failed'
    }

    $readerTestCompile = 'call "{0}" -arch=x64 -host_arch=x64 >nul && ' +
        'cl.exe /nologo /O2 /W4 /MT /std:c11 /DUNICODE /D_UNICODE ' +
        '/I. /Fo:build\reader_format_test.obj tests\reader_format_test.c ' +
        '/link /OUT:build\reader_format_test.exe /SUBSYSTEM:CONSOLE ' +
        '/MACHINE:X64'
    $readerTestCompile = $readerTestCompile -f $vsDevCmd
    & cmd.exe /d /s /c $readerTestCompile
    if ($LASTEXITCODE -ne 0) {
        throw 'reader format test build failed'
    }

    if ($Test) {
        & python -m unittest discover -s '.\tests' -v
        if ($LASTEXITCODE -ne 0) {
            throw 'Python tests failed'
        }
        & '.\build\logger_runtime_test.exe'
        if ($LASTEXITCODE -ne 0) {
            throw 'logger runtime test failed'
        }
        & '.\build\reader_format_test.exe'
        if ($LASTEXITCODE -ne 0) {
            throw 'reader format test failed'
        }
    }
}
finally {
    Pop-Location
}

Write-Host 'Build completed:'
Get-Item `
    '.\build\WinApiLogger.sys', `
    '.\build\WinApiLoggerCli.exe', `
    '.\build\skipped_exports.csv', `
    '.\build\logger_payload.bin' |
    Select-Object Name, Length |
    Format-Table -AutoSize
