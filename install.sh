#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# AI Security Projects — one-command installer (Linux / macOS / WSL / Git Bash)
# Usage:  curl -fsSL https://raw.githubusercontent.com/CyberEnthusiastic/<repo>/main/install.sh | bash
#    or:  ./install.sh
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; }

banner() {
cat <<'EOF'
╔══════════════════════════════════════════════════════════════╗
║       AI Security Projects — One-Command Installer          ║
║       github.com/CyberEnthusiastic                           ║
╚══════════════════════════════════════════════════════════════╝
EOF
}

# ---- 1. Python version check ----
check_python() {
  log "Checking Python..."
  if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    err "Python is not installed. Install Python 3.8+ from https://python.org and re-run this script."
    exit 1
  fi
  PYTHON=$(command -v python3 || command -v python)
  PY_VER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  PY_MAJOR=$("$PYTHON" -c 'import sys; print(sys.version_info.major)')
  PY_MINOR=$("$PYTHON" -c 'import sys; print(sys.version_info.minor)')
  if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    err "Python $PY_VER found — we require 3.8 or higher."
    exit 1
  fi
  ok "Python $PY_VER found at $PYTHON"
}

# ---- 2. Virtual environment ----
setup_venv() {
  log "Creating virtual environment at .venv/"
  "$PYTHON" -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate 2>/dev/null || source .venv/Scripts/activate
  ok "Virtual environment ready"
}

# ---- 3. Install dependencies ----
install_deps() {
  if [ -f requirements.txt ] && [ -s requirements.txt ]; then
    log "Installing dependencies from requirements.txt"
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    ok "Dependencies installed"
  else
    ok "No external dependencies (pure stdlib project)"
  fi
}

# ---- 4. Run the bundled self-test if present ----
self_test() {
  log "Running bundled self-test..."
  if [ -d samples ]; then
    MAIN_FILE=$(find . -maxdepth 1 -name "scanner.py" -o -name "hunter.py" -o -name "analyzer.py" -o -name "proxy.py" -o -name "waf_lab.py" | head -1)
    if [ -n "$MAIN_FILE" ]; then
      "$PYTHON" "$MAIN_FILE" samples/ 2>&1 | tail -20 || true
      ok "Self-test completed"
    fi
  fi
}

main() {
  banner
  check_python
  setup_venv
  install_deps
  self_test
  echo
  ok "Installation complete!"
  echo
  echo "Next steps:"
  echo "  1. Activate the venv:    source .venv/bin/activate   (Linux/Mac)"
  echo "                           source .venv/Scripts/activate (Git Bash on Windows)"
  echo "  2. Read the README.md for the full usage guide"
  echo "  3. Open in VS Code:      code ."
  echo
}

main "$@"
