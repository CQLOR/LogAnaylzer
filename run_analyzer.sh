#!/bin/bash
# Linux Launcher for SOC Log Analyzer

cd "$(dirname "$0")"

if command -v gnome-terminal >/dev/null 2>&1; then
    gnome-terminal -- bash -c "python3 log_analyzer.py; sleep 1"
elif command -v konsole >/dev/null 2>&1; then
    konsole -e bash -c "python3 log_analyzer.py; sleep 1"
elif command -v xfce4-terminal >/dev/null 2>&1; then
    xfce4-terminal -e "bash -c 'python3 log_analyzer.py; sleep 1'"
elif command -v xterm >/dev/null 2>&1; then
    xterm -e "bash -c 'python3 log_analyzer.py; sleep 1'"
else
    # Fallback to current terminal if graphical terminal emulator is unknown
    echo "Starting SOC Log Analyzer..."
    python3 log_analyzer.py
    sleep 1
fi
