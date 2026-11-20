$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "The MySpeedify installer must be built on Windows."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$iscc = Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) {
    throw "Inno Setup 6 was not found at '$iscc'. Install Inno Setup 6 and retry."
}

Push-Location $repoRoot
try {
    $pythonBits = python -c "import struct; print(struct.calcsize('P') * 8)"
    if ($LASTEXITCODE -ne 0 -or $pythonBits -ne "64") {
        throw "A 64-bit Python installation is required to build the Windows installer."
    }
    $pythonVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not determine the Python version."
    }
    if ([version]$pythonVersion -lt [version]"3.12" -or [version]$pythonVersion -gt [version]"3.14") {
        throw "Python 3.12 through 3.14 is supported for building the Windows installer."
    }

    $wintunHash = (Get-FileHash core\tun\wintun.dll -Algorithm SHA256).Hash
    if ($wintunHash -ne "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE") {
        throw "The bundled Wintun DLL does not match the pinned integrity hash."
    }

    $pyInstallerVersion = python -m PyInstaller --version
    if ($LASTEXITCODE -ne 0 -or $pyInstallerVersion -ne "6.22.3") {
        throw "Install PyInstaller 6.22.3 in this Python environment."
    }

    $appVersion = $env:MYSPEEDIFY_APP_VERSION
    if (-not $appVersion) {
        $appVersion = "0.1.0"
    }
    if ($appVersion -notmatch '^\d+(\.\d+){1,3}$') {
        throw "MYSPEEDIFY_APP_VERSION must be a numeric version such as 0.1.0."
    }

    python -m PyInstaller --noconfirm --clean client\MySpeedify.spec
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE."
    }

    New-Item -ItemType Directory -Force dist-installer | Out-Null
    & $iscc "/DAppVersion=$appVersion" client\installer.iss
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
