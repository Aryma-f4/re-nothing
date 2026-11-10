@echo off
rem Build a standalone flagr.exe on Windows.
rem Needs Python 3.10+ from python.org (includes tkinter).
rem Output: dist\flagr.exe
setlocal
cd /d "%~dp0"

set "PY=py -3"
%PY% -c "import tkinter" >nul 2>nul
if errorlevel 1 (
  echo error: tkinter missing in %PY%. Install Python from https://www.python.org/downloads/windows/ ^(tkinter is included^).
  exit /b 1
)

if not exist .venv-build (
  %PY% -m venv .venv-build || exit /b 1
)
.venv-build\Scripts\python -m pip install --quiet --upgrade pip pyinstaller || exit /b 1
.venv-build\Scripts\python -m PyInstaller --noconfirm --clean --onefile --windowed --name flagr flagr.py || exit /b 1

echo.
echo built: dist\flagr.exe
echo run it: dist\flagr.exe
