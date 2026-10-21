@echo off
title net-audit Desktop
rem Run from the repository root so relative paths resolve.
cd /d "%~dp0..\.."
if not exist build\release\net-audit.exe (
    echo net-audit.exe not found - building it with mingw32-make...
    mingw32-make
)
python frontends\desktop\gui.py
if errorlevel 1 pause
