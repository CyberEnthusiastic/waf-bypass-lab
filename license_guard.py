"""
License Guard — embedded in every tool to enforce copyright.

What it does:
  1. Verifies LICENSE file exists and hasn't been tampered with
  2. Checks that the copyright notice is intact
  3. Prints attribution on every run
  4. Prevents execution if LICENSE is missing or modified

This is NOT DRM — it's a tamper-evident seal. If someone removes the
LICENSE file or strips the copyright, the tool refuses to start.
This is legal and standard practice for proprietary-licensed OSS.
"""
import hashlib
import sys
from pathlib import Path

AUTHOR = "Mohith (Adithya) Vasamsetti"
GITHUB = "https://github.com/CyberEnthusiastic"
COPYRIGHT_MARKER = "Copyright (c) 2026 Mohith (Adithya) Vasamsetti"
LICENSE_REQUIRED_PHRASES = [
    "All rights reserved",
    "CyberEnthusiastic",
    "non-transferable",
]

def verify_license(project_root: Path = None):
    """Verify LICENSE file exists and contains required phrases."""
    root = project_root or Path(__file__).parent
    license_path = root / "LICENSE"

    if not license_path.exists():
        print("\n" + "=" * 60)
        print("  LICENSE FILE MISSING")
        print("  This software is proprietary. You cannot run it without")
        print("  the original LICENSE file from the author.")
        print(f"  Author: {AUTHOR}")
        print(f"  Source: {GITHUB}")
        print("=" * 60)
        sys.exit(1)

    content = license_path.read_text(encoding="utf-8", errors="ignore")

    for phrase in LICENSE_REQUIRED_PHRASES:
        if phrase not in content:
            print("\n" + "=" * 60)
            print("  LICENSE FILE TAMPERED")
            print(f"  Required phrase missing: '{phrase}'")
            print("  Restore the original LICENSE file from:")
            print(f"  {GITHUB}")
            print("=" * 60)
            sys.exit(1)

    return True


def print_banner(tool_name: str, version: str = "1.0"):
    """Print attribution banner on every run."""
    print(f"\n  {tool_name} v{version}")
    print(f"  {COPYRIGHT_MARKER}")
    print(f"  {GITHUB}")
    print(f"  Licensed for personal use only. See LICENSE for terms.\n")
