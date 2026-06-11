param(
    [switch]$InstallDependencies,
    [switch]$CreateInstaller
)

$root = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location $root

$pythonCmd = "python"
$pythonArgs = @()
if (-not (Get-Command python -ErrorAction SilentlyContinue) -and (Get-Command py -ErrorAction SilentlyContinue)) {
    $pythonCmd = "py"
    $pythonArgs = @("-3")
}

if ($InstallDependencies) {
    & $pythonCmd @pythonArgs -m pip install --upgrade pip
    & $pythonCmd @pythonArgs -m pip install -r requirements.txt
    & $pythonCmd @pythonArgs -m pip install -r requirements-dev.txt
}

if (-not (Test-Path "$root\\icon.ico")) {
    Write-Host "Generating icon file..."
    & $pythonCmd @pythonArgs make_icon.py
}

$pyiArgs = @(
    "--noconfirm",
    "--windowed",
    "--onefile",
    "--name",
    "SQLiToolkit"
)
if (Test-Path "$root\\icon.ico") {
    $pyiArgs += @("--icon", "icon.ico")
}
$pyiArgs += "sqli_toolkit_qt.py"

Write-Host "Building SQLi Toolkit executable with args: $pyiArgs"
& $pythonCmd @pythonArgs -m PyInstaller @pyiArgs

# Modify .spec file to include icon.ico in datas
if (Test-Path "$root\\SQLiToolkit.spec") {
    Write-Host "Updating SQLiToolkit.spec to include icon data..."
    $specContent = Get-Content "$root\\SQLiToolkit.spec" -Raw
    
    # Replace datas=[] with datas=[('icon.ico', '.')]
    if ($specContent -match "datas=\[\]") {
        $specContent = $specContent -replace "datas=\[\]", "datas=[('icon.ico', '.')]"
        Set-Content "$root\\SQLiToolkit.spec" $specContent
        
        # Rebuild with updated spec
        Write-Host "Rebuilding with updated spec file..."
        & python -m PyInstaller --noconfirm "$root\\SQLiToolkit.spec"
    }
}

if ($CreateInstaller) {
    $nsisCmd = (Get-Command makensis -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
    if (-not $nsisCmd) {
        $defaultPaths = @(
            "${env:ProgramFiles(x86)}\\NSIS\\Bin\\makensis.exe",
            "${env:ProgramFiles}\\NSIS\\Bin\\makensis.exe"
        )
        foreach ($path in $defaultPaths) {
            if (Test-Path $path) {
                $nsisCmd = $path
                break
            }
        }
    }
    if (-not $nsisCmd) {
        $whereResult = & where.exe makensis 2>$null
        if ($whereResult) {
            $nsisCmd = $whereResult.Trim()
        }
    }

    if (-not $nsisCmd) {
        Write-Host "NSIS compiler not found on PATH. Install NSIS and rerun with -CreateInstaller." -ForegroundColor Yellow
        exit 1
    }

    Write-Host "Creating NSIS installer..."
    & $nsisCmd installer.nsi
}
