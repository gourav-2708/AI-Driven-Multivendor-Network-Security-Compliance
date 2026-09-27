@echo off
title net-audit Desktop
cd /d "%~dp0.."
python desktop\gui.py
if errorlevel 1 pause
