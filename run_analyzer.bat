@echo off
title SOC Log Analyzer
cd /d "%~dp0"
cls
python log_analyzer.py
timeout /t 1 /nobreak >nul
exit
