@echo off
title MirrorPy Glass
cd /d "%~dp0"
python mirror_glass.py
if errorlevel 1 (
    echo.
    echo [!] Failed to start. Make sure Python 3.8+ is installed and in PATH.
    pause
)
