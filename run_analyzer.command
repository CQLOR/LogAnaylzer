#!/bin/bash
# Get the directory where this script is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Run the analyzer
python3 log_analyzer.py sample_log.txt

# Wait exactly one second before tearing down the native window
sleep 1
osascript -e 'tell application "Terminal" to close front window'
