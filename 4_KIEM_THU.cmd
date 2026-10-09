@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Hay chay 0_CAI_DAT.cmd truoc.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m unittest discover -s tests -v
pause
