#!/usr/bin/env bash
# Build a standalone flagr binary for the current OS (macOS or Linux).
# Windows: use build.bat.
#
#   ./build.sh
#   PYTHON=python3.14 ./build.sh
#
# Output: dist/flagr (Linux) or dist/flagr.app (macOS).
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if ! "$PY" -c "import tkinter" >/dev/null 2>&1; then
  for candidate in python3.14 python3.13 python3.12 python3; do
    if command -v "$candidate" >/dev/null 2>&1 \
       && "$candidate" -c "import tkinter" >/dev/null 2>&1; then
      PY="$candidate"
      break
    fi
  done
fi
if ! "$PY" -c "import tkinter" >/dev/null 2>&1; then
  cat >&2 <<EOF
error: $PY has no tkinter, and no python3.x with tkinter was found.
  macOS:  brew install python-tk@3.14   (then PYTHON=python3.14 ./build.sh)
  Debian: sudo apt install python3-tk
EOF
  exit 1
fi
echo "using $("$PY" -c 'import sys;print(sys.executable, sys.version.split()[0])')"

VENV=".venv-build"
[ -d "$VENV" ] || "$PY" -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip pyinstaller

FLAGS=(--noconfirm --clean --name flagr)
if [ "$(uname -s)" = "Darwin" ]; then
  # .app bundles are directories; onedir inside the bundle is the supported layout.
  FLAGS+=(--windowed --osx-bundle-identifier id.siberlab.flagr)
else
  FLAGS+=(--onefile)
fi

"$VENV/bin/python" -m PyInstaller "${FLAGS[@]}" flagr.py

echo
if [ -d dist/flagr.app ]; then
  echo "built: dist/flagr.app"
  echo "open it:  open dist/flagr.app   (unsigned: right-click > Open first time)"
else
  echo "built: dist/flagr"
  echo "run it:   ./dist/flagr"
fi
