import argparse
import csv
import re
import shutil
from collections import defaultdict
from datetime import datetime

# Common ANSI Color Codes
LIME_GREEN = '\033[38;5;118m'    # Auth_Success
BRIGHT_PURPLE = '\033[38;5;135m' # Auth_Fail
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BOLD = '\033[1m'
RESET = '\033[0m'

# Suspicious keywords for privilege escalation
PRIVILEGE_KEYWORDS = [
    'sudo', 'admin', 'administrator', 'root', 'privilege', 'elevated', 'added to group'
]

def print_ascii_art():
    """Prints a cool ASCII design of a computer."""
    terminal_width = shutil.get_terminal_size((80, 20)).columns
    art = [
        r"      .---------------------------.      ",
        r"      | .-----------------------. |      ",
        r"      | |                       | |      ",
        r"      | |    SOC LOG ANALYZER   | |      ",
        r"      | |      SYSTEM ACTIVE    | |      ",
        r"      | |                       | |      ",
        r"      | '-----------------------' |      ",
        r"      '---------------------------'      ",
        r"           |                 |           ",
        r"     .-----'-----------------'-----.     ",
        r"     '-----------------------------'     "
    ]
    print("\n")
    for line in art:
        print(f"{CYAN}{BOLD}{line.center(terminal_width)}{RESET}")
    print("\n")

def print_centered_title(title):
    """Prints a centered title with spacing."""
    terminal_width = shutil.get_terminal_size((80, 20)).columns
    print("\n")
    print(f"{BOLD}{LIME_GREEN}{title.center(terminal_width)}{RESET}")
    print("\n")

def parse_log_line(line):
    """
    Parses a single log line using regex.
    Expects format:
    timestamp\tevent\tuser=username\tip=ip_address\tmessage=...
    """
    line = line.strip()
    if not line:
        return None
        
    pattern = r"^(?P<timestamp>\S+)\s+(?P<event>\S+)\s+user=(?P<username>\S+)\s+ip=(?P<ip>\S+)\s+message=(?P<message>.*)$"
    match = re.match(pattern, line)
    
    if match:
        return match.groupdict()
    
    parts = re.split(r'\s+', line, maxsplit=4)
    if len(parts) == 5:
        user_part = parts[2].split('=')[1] if '=' in parts[2] else parts[2]
        ip_part = parts[3].split('=')[1] if '=' in parts[3] else parts[3]
        msg_part = parts[4].split('=', 1)[1] if '=' in parts[4] else parts[4]
        return {
            'timestamp': parts[0],
            'event': parts[1],
            'username': user_part,
            'ip': ip_part,
            'message': msg_part
        }
    return None

def write_csv(filename, findings):
    """Exports the flagged events to a true CSV file, sorted by timestamp for spreadsheet viewing."""
    try:
        if not findings:
            return

        # Pre-sort findings chronologically based on timestamp (day/time)
        findings.sort(key=lambda x: x['timestamp'])

        with open(filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            headers = ['timestamp', 'username', 'ip_address', 'event_type', 'reason_flagged', 'message']
            writer.writerow(headers)
            
            # Data Lines
            for finding in findings:
                row = [
                    finding['timestamp'],
                    finding['username'],
                    finding['ip'],
                    finding['event'],
                    " | ".join(finding['reasons']),
                    finding['message']
                ]
                writer.writerow(row)

        print(f"{LIME_GREEN}[+] Findings successfully exported to {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error writing to CSV: {e}{RESET}")

def get_colored_reasons(reasons, width):
    """Assigns unique contrasting colors to specific reasons and ensures strict fixed-width mapping."""
    color_map = {
        "Privilege Escalation": '\033[38;5;196m',          # Red
        "Excessive failures for username": '\033[38;5;214m',# Light Orange
        "Excessive failures from IP": '\033[38;5;208m',     # Dark Orange
        "Brute Force": '\033[38;5;226m',                    # Yellow
        "IP targeting multiple users": '\033[38;5;205m',    # Hot Pink
        "Unusual Login Time": '\033[38;5;51m',              # Cyan
    }
    
    visible_str = ""
    colored_str = ""
    
    for i, r in enumerate(reasons):
        prefix = " | " if i > 0 else ""
        
        # Determine the color
        c = '\033[38;5;255m' # White default fallback
        for k, v in color_map.items():
            if k in r:
                c = v
                break
                
        avail = width - len(visible_str)
        if avail <= 0:
            break
            
        full_part = prefix + r
        if len(full_part) > avail:
            part_to_add = full_part[:avail]
            if len(prefix) >= avail:
                colored_str += part_to_add
            else:
                colored_str += prefix + f"{c}{part_to_add[len(prefix):]}{RESET}"
            visible_str += part_to_add
            break
        else:
            colored_str += prefix + f"{c}{r}{RESET}"
            visible_str += full_part
            
    padding = width - len(visible_str)
    colored_str += " " * padding
    return colored_str

def print_table(events):
    """Prints events in a formatted, user-friendly table without arbitrarily truncating reasons."""
    if not events:
        return

    # Calculate max width of the reason column to prevent cut-offs
    max_reason_len = max(len(" | ".join(e['reasons'])) for e in events)
    reason_width = max(10, max_reason_len, len('Reason'))

    header = f"| {'Time':<20} | {'User':<15} | {'IP':<15} | {'Event':<15} | {'Reason':<{reason_width}} |"
    sep = "-" * len(header)
    
    print(sep)
    print(f"{BOLD}{header}{RESET}")
    print(sep)
    
    for e in events:
        time_str = e['timestamp'][:20].ljust(20)
        user_str = e['username'][:15].ljust(15)
        ip_str = e['ip'][:15].ljust(15)
        event_raw = e['event'][:15].ljust(15)
        
        # Color Event based on success or fail
        if 'SUCCESS' in event_raw:
            event_colored = f"{LIME_GREEN}{event_raw}{RESET}"
        elif 'FAIL' in event_raw:
            event_colored = f"{BRIGHT_PURPLE}{event_raw}{RESET}"
        else:
            event_colored = f"{YELLOW}{event_raw}{RESET}"
            
        reason_colored = get_colored_reasons(e['reasons'], reason_width)
        
        print(f"| {time_str} | {user_str} | {ip_str} | {event_colored} | {reason_colored} |")
    
    print(sep)

def analyze_file(file_path, threshold, csv_export):
    print_centered_title(f"LOG ANALYZER OUTPUT RESULTS: {file_path}")

    # Trackers
    total_lines = 0
    failed_logins = 0
    
    failed_by_user = defaultdict(int)
    failed_by_ip = defaultdict(int)
    users_by_ip = defaultdict(set)
    events_timeline = defaultdict(list)
    flagged_events = []

    print(f"{CYAN}Analyzing {file_path}...{RESET}\n")

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                total_lines += 1
                parsed = parse_log_line(line)
                if not parsed:
                    continue
                
                events_timeline[parsed['username']].append(parsed)
                events_timeline[parsed['ip']].append(parsed)

                if parsed['event'] == 'AUTH_FAIL' or 'Invalid password' in parsed['message']:
                    failed_logins += 1
                    failed_by_user[parsed['username']] += 1
                    failed_by_ip[parsed['ip']] += 1
                
                if parsed['event'] in ('AUTH_FAIL', 'AUTH_SUCCESS'):
                    users_by_ip[parsed['ip']].add(parsed['username'])

    except FileNotFoundError:
        print(f"{RED}[!] Error: File '{file_path}' not found.{RESET}")
        return False
    except Exception as e:
        print(f"{RED}[!] Error reading file: {e}{RESET}")
        return False

    suspicious_ips_flagged = set()
    privilege_events_flagged = 0

    with open(file_path, 'r', encoding='utf-8') as file:
        current_failed_user = defaultdict(int)
        current_failed_ip = defaultdict(int)

        for line in file:
            parsed = parse_log_line(line)
            if not parsed:
                continue
            
            flag_reasons = []

            # Privilege Escalation Indicators
            msg_lower = parsed['message'].lower()
            if parsed['event'] == 'PRIV_CHANGE' or any(keyword in msg_lower for keyword in PRIVILEGE_KEYWORDS):
                flag_reasons.append("Privilege Escalation Indicator")
                privilege_events_flagged += 1
            
            if parsed['event'] == 'AUTH_FAIL' or 'Invalid password' in parsed['message']:
                current_failed_user[parsed['username']] += 1
                current_failed_ip[parsed['ip']] += 1
                
                if current_failed_user[parsed['username']] >= threshold:
                    flag_reasons.append(f"Excessive failures for username (>={threshold})")
                if current_failed_ip[parsed['ip']] >= threshold:
                    flag_reasons.append(f"Excessive failures from IP (>={threshold})")
                    suspicious_ips_flagged.add(parsed['ip'])

            elif parsed['event'] == 'AUTH_SUCCESS' or 'Login successful' in parsed['message']:
                if current_failed_user[parsed['username']] >= threshold:
                    flag_reasons.append("Brute Force Followed by Success (Username)")
                if current_failed_ip[parsed['ip']] >= threshold:
                    flag_reasons.append("Brute Force Followed by Success (IP)")
                    suspicious_ips_flagged.add(parsed['ip'])

                current_failed_user[parsed['username']] = 0
                current_failed_ip[parsed['ip']] = 0

                try:
                    dt = datetime.fromisoformat(parsed['timestamp'].replace('Z', '+00:00'))
                    if 0 <= dt.hour < 5:
                        flag_reasons.append("Unusual Login Time (00:00 - 05:00)")
                except ValueError:
                    pass
            
            # Detect One IP Targeting Many Users
            if len(users_by_ip[parsed['ip']]) >= threshold:
                if "Targeting Multiple Users" not in flag_reasons:
                    flag_reasons.append(f"IP targeting multiple users (>={threshold})")
                    suspicious_ips_flagged.add(parsed['ip'])

            if flag_reasons:
                flagged_events.append({
                    'timestamp': parsed['timestamp'],
                    'username': parsed['username'],
                    'ip': parsed['ip'],
                    'event': parsed['event'],
                    'message': parsed['message'],
                    'reasons': flag_reasons
                })

    # Summary Report
    print(f"{BOLD}{CYAN}=== Log Analyzer Summary Report ==={RESET}")
    print(f"Total log lines processed:       {BOLD}{total_lines}{RESET}")
    print(f"Total failed logins:             {BOLD}{failed_logins}{RESET}")
    print(f"Total suspicious IPs flagged:    {BOLD}{len(suspicious_ips_flagged)}{RESET} {YELLOW}{list(suspicious_ips_flagged)}{RESET}")
    print(f"Total privilege events flagged:  {BOLD}{privilege_events_flagged}{RESET}")
    print(f"Total flagged events:            {BOLD}{len(flagged_events)}{RESET}")
    print(f"{BOLD}{CYAN}==================================={RESET}\n")

    if flagged_events:
        print_centered_title("FLAGGED EVENTS TABLE")
        print_table(flagged_events)
        
        # Ask to download/save to CSV
        export_name = csv_export if csv_export else "findings.csv"
        print(f"\n{CYAN}Would you like to download/save these findings to CSV as '{export_name}'? (Y/n):{RESET}")
        ans = input(f"{BOLD}> {RESET}").strip().lower()
        if ans in ('y', 'yes', ''):
            write_csv(export_name, flagged_events)
        else:
            print(f"{YELLOW}Skipped CSV export.{RESET}")
    else:
        print(f"{LIME_GREEN}No suspicious events flagged.{RESET}")

    return True

def main():
    parser = argparse.ArgumentParser(description="Python Log Analyzer - Detects suspicious authentication and privilege events")
    parser.add_argument("log_file", nargs='?', help="Path to the log file to analyze", default=None)
    parser.add_argument("--csv", help="Optional path to output findings as CSV", default=None)
    parser.add_argument("--threshold", type=int, default=5, help="Threshold for repeated failed logins (default: 5)")
    args = parser.parse_args()

    print_ascii_art()
    
    files_to_process = [args.log_file] if args.log_file else []

    while True:
        if not files_to_process:
            print(f"{LIME_GREEN}================================================================={RESET}")
            print(f"{CYAN}Enter the path to a .txt log file to analyze (or type 'exit' to quit):{RESET}")
            user_input = input(f"{BOLD}> {RESET}").strip()
            
            if user_input.lower() == 'exit':
                print(f"{LIME_GREEN}Exiting SOC Log Analyzer. Goodbye!{RESET}")
                break
            if not user_input:
                continue
            current_file = user_input
        else:
            current_file = files_to_process.pop(0)

        analyze_file(current_file, args.threshold, args.csv)
        print("\n")

if __name__ == "__main__":
    main()
