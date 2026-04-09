# Capstone Part I: Python Log Analyzer 

## Purpose
The Python Log Analyzer (`log_analyzer.py`) is a modular Command-Line Interface (CLI) application developed to ingest authentication and system log files to identify suspicious behavior. Acting as an automated Tier-1 SOC Analyst, the tool analyzes structured data sequentially to identify security incidents spanning across standard threshold checks to complex "Stretch Goal" detection modules.

## Features & Detection Modules

### Core Detections
- **Failed Logins Tracking**: Monitors the number of `AUTH_FAIL` events on a per-username and per-IP basis. A threshold trigger dynamically alerts analysts if an individual user or IP generates a significant amount of failures (default >5).
- **Suspicious IP Identification**: Any IP initiating more than 5 failed logins is flagged as `Suspicious`.
- **Privilege Escalation**: Assesses the logs to identify potential attempts to gain root or sudo permissions. Any log associated with a `PRIV_CHANGE` event or messages referencing `sudo`, `root`, `admin`, etc., are flagged as indicators of privilege escalation.

### Advanced "Stretch Goal" Detections
This script implements several advanced detection functions:
- **Interactive Prompt Processing**: Run the tool interactively to continually analyze different text files without stopping; exiting the loop correctly tears down the window.
- **Brute Force Followed by Success**: Monitors if an IP address or username hits the threshold limits with `AUTH_FAIL` and subsequently logs a successful login. 
- **One IP Targeting Many Users**: Discovers malicious actors rotating usernames across a single source. If a single IP targets 5 or more unique user accounts, it is flagged as password spraying.
- **Unusual Login Times**: Detects and flags any successful login occurring outside typical business hours. This is currently configured to flag logins strictly between midnight (00:00) and 5:00 AM UTC.
- **Configurable Thresholds**: Utilizes `argparse` to allow dynamic changes to the failure threshold limits via command-line arguments.
- **Colorized Output**: Incorporates an easy-to-read Summary Report formatted with custom ANSI escape codes mapping distinct issues to individual colors.
- **CSV Data Export**: Supports exporting all findings directly into a structured CSV file for cross-correlation in tools like Excel.

## Requirements
- Python 3.6+
- Basic Python modules: `argparse`, `re`, `csv`, `collections`, `datetime` (All standard library).

## How to Run The Script

### Method 1: The Interactive Pop-out Window (Cross-Platform)
This method executes the script natively in its own separate, dedicated Terminal instance.
- **For macOS**: Double-click the `run_analyzer.command` file located in your project directory via Finder. *(Alternatively in Terminal: `open run_analyzer.command`)*
- **For Windows**: Double-click the `run_analyzer.bat` file located in your folder via Explorer. *(Alternatively in CMD: `start run_analyzer.bat`)*
- **For Linux**: Run the `./run_analyzer.sh` executable. It automatically detects and spawns native GUI terminals (`gnome-terminal`, `xterm`, etc.).

Once the separate window opens, it analyzes `sample_log.txt` and then queries you for entirely new text files to analyze via an **Interactive Search Field**. 
When finished, simply type `exit` into the prompt. The script will wait 1 second and then forcefully close its separate window automatically!

### Method 2: Direct Command Line Setup (Standard Execution)
If you wish to pass strict arguments, export results to CSV, or skip the window pop-out, you can run the scanner straight from your current terminal:

```bash
# Basic Manual Analysis
python3 log_analyzer.py sample_log.txt

# Generating CSV Findings automatically to 'findings.csv'
python3 log_analyzer.py sample_log.txt --csv findings.csv

# Specifying a custom threshold limit (e.g., flag after 3 bad login attempts instead of 5)
python3 log_analyzer.py sample_log.txt --threshold 3

# Trigger Interactive Prompt immediately (No initial file passed)
python3 log_analyzer.py
```

## Included Dataset
To assist with testing, `sample_log.txt` operates as a curated mix of normal successful logins, background internet "noise", failed brute force authentications, advanced IP spoofing, and numerous `PRIV_CHANGE` activities.
