@echo off
title Mirror App Launcher
color 0A

REM ===========================
REM  MIRROR.PY PORTABLE LAUNCHER (NO PIP)
REM ===========================

setlocal

REM Path to local Python
set PYTHON_DIR=%~dp0python
set PYTHON_EXE=%PYTHON_DIR%\python.exe

echo.
echo [*] Checking local Python in: %PYTHON_DIR%
if not exist "%PYTHON_EXE%" (
    echo [!] Local Python not found in %PYTHON_DIR%
    pause
    exit /b
)

echo.
echo [*] Launching Mirror App...
"%PYTHON_EXE%" "%~dp0mirror.py"

echo.
echo [*] Program finished. Press any key to exit.
pause >nul

endlocal
