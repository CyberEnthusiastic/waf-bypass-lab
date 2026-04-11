#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# AI Security Projects — Uninstaller (Linux / macOS / WSL / Git Bash)
# Removes the virtual environment, cached files, and reports.
# Does NOT delete the project directory itself (user's choice).
# ──────────────────────────────────────────────────────────────
set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}[*]${NC} Uninstalling..."

# Remove virtual environment
if [ -d ".venv" ]; then
  rm -rf .venv
  echo -e "${GREEN}[+]${NC} Removed .venv/"
fi

# Remove Python cache
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
echo -e "${GREEN}[+]${NC} Removed Python cache"

# Remove generated reports
rm -f reports/*.json reports/*.html 2>/dev/null || true
echo -e "${GREEN}[+]${NC} Removed generated reports"

# Remove logs
rm -f logs/*.jsonl data/audit_log.jsonl data/scc.db 2>/dev/null || true
echo -e "${GREEN}[+]${NC} Removed logs and databases"

# Remove threat intel (auto-downloaded)
rm -f threat_intel.json rules/threat_intel_ips.json 2>/dev/null || true
echo -e "${GREEN}[+]${NC} Removed auto-downloaded threat intel"

echo ""
echo -e "${GREEN}[+]${NC} Uninstall complete."
echo -e "${YELLOW}[*]${NC} The project directory is still here."
echo "    To fully remove: cd .. && rm -rf $(basename $PWD)"
echo "    To reinstall:     ./install.sh"
