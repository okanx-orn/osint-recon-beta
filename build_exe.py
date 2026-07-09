#!/usr/bin/env python3
"""
Build script — packages the GUI into a single-file Windows executable.

USAGE (run this ON WINDOWS, inside the project's virtualenv):

    pip install -r requirements.txt
    pip install pyinstaller
    python build_exe.py

Output:
    dist/OSINT-Recon.exe   ← double-click to run, no Python install needed

NOTE: PyInstaller builds a Windows .exe only when run ON Windows
(or via Wine). Building on Linux/macOS produces a Linux/macOS binary
instead — that's a PyInstaller limitation, not a bug in this script.
For a true .exe from Linux CI, use a Windows GitHub Actions runner
(see .github/workflows/build-windows.yml included in this repo).
"""

import subprocess
import sys
import os

APP_NAME    = "OSINT-Recon"
ENTRY       = os.path.join("gui", "app.py")
ICON_PATH   = os.path.join("assets", "icon.ico")
VERSION_TXT = os.path.join("assets", "version_info.txt")


def main():
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name", APP_NAME,
        "--add-data", f"assets{os.pathsep}assets",
        "--hidden-import", "dns.resolver",
        "--hidden-import", "whois",
    ]

    if os.path.exists(ICON_PATH):
        args += ["--icon", ICON_PATH]

    if os.path.exists(VERSION_TXT):
        args += ["--version-file", VERSION_TXT]

    args.append(ENTRY)

    print("[*] Running PyInstaller with:")
    print("    " + " ".join(args))
    subprocess.check_call(args)

    print("\n[✓] Build complete!")
    print(f"    → dist/{APP_NAME}.exe (Windows) or dist/{APP_NAME} (Linux/macOS binary)")


if __name__ == "__main__":
    main()
