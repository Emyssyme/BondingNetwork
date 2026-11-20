$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "The MySpeedify executable must be built on Windows."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $pythonBits = python -c "import struct; print(struct.calcsize('P') * 8)"
    if ($LASTEXITCODE -ne 0 -or $pythonBits -ne "64") {
        throw "A 64-bit Python installation is required to build the Windows executable."
    }
    $pythonVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not determine the Python version."
    }
    if ([version]$pythonVersion -lt [version]"3.12" -or [version]$pythonVersion -gt [version]"3.14") {
        throw "Python 3.12 through 3.14 is supported for building the Windows executable."
    }

    $wintunHash = (Get-FileHash core\tun\wintun.dll -Algorithm SHA256).Hash
    if ($wintunHash -ne "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE") {
        throw "The bundled Wintun DLL does not match the pinned integrity hash."
    }

    $pyInstallerVersion = python -m PyInstaller --version
    if ($LASTEXITCODE -ne 0 -or $pyInstallerVersion -ne "6.22.3") {
        throw "Install PyInstaller 6.22.3 in this Python environment."
    }

    python -m PyInstaller --noconfirm --clean client\MySpeedify-onefile.spec
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE."
    }

    $executable = Join-Path $repoRoot "dist\MySpeedify.exe"
    if (-not (Test-Path $executable)) {
        throw "PyInstaller completed without producing '$executable'."
    }
    Write-Output "Executable created: $executable"
}
finally {
    Pop-Location
}
