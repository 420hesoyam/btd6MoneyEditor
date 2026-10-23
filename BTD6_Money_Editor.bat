@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%~dp0BTD6_Money_Editor.py" %*
) else (
    python "%~dp0BTD6_Money_Editor.py" %*
)

if errorlevel 1 pause
