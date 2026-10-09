@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title RKE Demo - ALICE
if not exist ".venv\Scripts\python.exe" (
  echo Hay chay 0_CAI_DAT.cmd truoc.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" alice.py
if errorlevel 1 pause
