@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  set "RKE_PY=py -3"
) else (
  set "RKE_PY=python"
)
%RKE_PY% -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul
if errorlevel 1 (
  echo Can cai Python 3.10 tro len va bat Add Python to PATH.
  goto fail
)
if not exist ".venv\Scripts\python.exe" (
  %RKE_PY% -m venv .venv
  if errorlevel 1 goto fail
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto fail
".venv\Scripts\python.exe" setup_demo.py
if errorlevel 1 goto fail
echo.
echo CAI DAT XONG. Mo 1_ALICE.cmd va 2_BOB.cmd.
pause
exit /b 0
:fail
echo Cai dat chua thanh cong. Doc thong bao loi phia tren.
pause
exit /b 1
