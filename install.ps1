# AI Security Projects - one-command installer (Windows PowerShell)
# Usage: iex (iwr 'https://raw.githubusercontent.com/CyberEnthusiastic/<repo>/main/install.ps1').Content
#    or: .\install.ps1

$ErrorActionPreference = "Stop"

function Log  { param($m) Write-Host "[*] $m" -ForegroundColor Blue }
function Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail { param($m) Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

Write-Host @"
+--------------------------------------------------------------+
|     AI Security Projects - One-Command Installer            |
|     github.com/CyberEnthusiastic                             |
+--------------------------------------------------------------+
"@ -ForegroundColor Cyan

# 1. Python check
Log "Checking Python..."
try {
    $pyVersion = (python --version) 2>&1
    if ($pyVersion -notmatch "Python 3\.(\d+)") {
        Fail "Python 3.8+ required. Install from https://python.org"
    }
    $minor = [int]$matches[1]
    if ($minor -lt 8) {
        Fail "Python 3.8+ required, found $pyVersion"
    }
    Ok "Found $pyVersion"
} catch {
    Fail "Python not found. Install from https://python.org and add to PATH"
}

# 2. Virtual environment
Log "Creating virtual environment at .venv\"
python -m venv .venv
& .\.venv\Scripts\Activate.ps1
Ok "Virtual environment ready"

# 3. Install dependencies
if ((Test-Path requirements.txt) -and ((Get-Item requirements.txt).Length -gt 0)) {
    Log "Installing dependencies..."
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet -r requirements.txt
    Ok "Dependencies installed"
} else {
    Ok "No external dependencies (pure stdlib project)"
}

# 4. Self-test
Log "Running self-test..."
$mainFiles = @("scanner.py", "hunter.py", "analyzer.py", "proxy.py", "waf_lab.py")
foreach ($f in $mainFiles) {
    if (Test-Path $f) {
        if (Test-Path "samples") {
            python $f samples\ 2>&1 | Select-Object -Last 20
        }
        break
    }
}

Write-Host ""
Ok "Installation complete!"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Activate the venv:  .\.venv\Scripts\Activate.ps1"
Write-Host "  2. Read the README.md for the full usage guide"
Write-Host "  3. Open in VS Code:    code ."
Write-Host ""
