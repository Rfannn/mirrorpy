@echo off
title MirrorPy - Classic UI

REM ===========================================================
REM  Launches mirror.py using the embedded Python if it is
REM  present, otherwise the Python on PATH.
REM ===========================================================

setlocal
cd /d "%~dp0"

set PYTHON_EXE=%~dp0python\python.exe
if not exist "%PYTHON_EXE%" set PYTHON_EXE=python

"%PYTHON_EXE%" mirror.py
if errorlevel 1 (
    echo.
    echo [!] Failed to start.
    echo     Install Python 3.9+ and put it on PATH, or place an
    echo     embedded distribution in the python\ folder.
    pause
)

endlocal
