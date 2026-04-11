# AI Security Projects - Uninstaller (Windows PowerShell)
# Removes virtual environment, cached files, and reports.

$ErrorActionPreference = "SilentlyContinue"

function Ok { param($m) Write-Host "[+] $m" -ForegroundColor Green }

Write-Host "[*] Uninstalling..." -ForegroundColor Blue

# Remove virtual environment
if (Test-Path ".venv") { Remove-Item -Recurse -Force ".venv"; Ok "Removed .venv\" }

# Remove Python cache
Get-ChildItem -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Get-ChildItem -Recurse -Filter "*.pyc" | Remove-Item -Force
Ok "Removed Python cache"

# Remove generated reports
Remove-Item -Force "reports\*.json", "reports\*.html" 2>$null
Ok "Removed generated reports"

# Remove logs
Remove-Item -Force "logs\*.jsonl", "data\audit_log.jsonl", "data\scc.db" 2>$null
Ok "Removed logs and databases"

# Remove threat intel
Remove-Item -Force "threat_intel.json", "rules\threat_intel_ips.json" 2>$null
Ok "Removed auto-downloaded threat intel"

Write-Host ""
Ok "Uninstall complete."
Write-Host "[*] The project directory is still here." -ForegroundColor Yellow
Write-Host "    To fully remove: Remove-Item -Recurse -Force ." -ForegroundColor Gray
Write-Host "    To reinstall:    .\install.ps1" -ForegroundColor Gray
