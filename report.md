# SOC Analyst Report - Suspicious Log Activity

## 1. Overview
This report provides an analysis of recent authentication and system logs to identify signs of malicious behavior. The review highlights anomalous activities, specifically focusing on repeated failed logins, suspicious IP address behavior, anomalous login times, and privilege escalation indicators. A custom Python-based tool (`log_analyzer.py`) was developed and executed to flag these events.

## 2. Log Source
The dataset analyzed (`sample_log.txt`) is a simulated set of system and authentication logs spanning over several days. It contains 1,235 events structured with timestamps, event types, usernames, source IPs, and specific event messages. The events represent a mixture of routine daily traffic (`AUTH_SUCCESS`), background noise, and distinct indicators of compromise.

## 3. Detection Logic
Following SOC analyst best practices, the `log_analyzer.py` script identifies:
- **Repeated Failed Logins**: It tracks failure counts per unique username and source IP. Threshold-based alerting dynamically kicks in when consecutive failures reach or exceed a configurable limit (default 5, adjustable via `--threshold`), potentially indicating dictionary attacks or password spraying.
- **Suspicious IP Behavior**: The tool looks for specific behavior such as:
  - Excessive accumulated failures originating from a single IP.
  - "One IP Targeting Many Users" (often indicative of password spraying and credential stuffing). Any IP targeting concurrent unique user accounts at or above the configured threshold is flagged.
  - "Brute Force Followed by Success", where an IP or User has sustained excessive failures prior to a successful login.
- **Unusual Login Times**: The script filters and identifies `AUTH_SUCCESS` events that occur well outside of normal business hours. In our analysis, we classify 00:00 to 05:00 UTC as an anomalous window triggering a flag.
- **Privilege Escalation Indicators**: It flags any event marked with the type `PRIV_CHANGE`, or where the log message contains sensitive keywords (e.g., `sudo`, `admin`, `root`, `privilege`, `elevated`).

## 4. Findings
After execution, the tool flagged significant anomalous activity across the dataset:
- **Log lines processed**: 1,235
- **Total failed logins recorded**: 169
- **Suspicious IPs flagged**: 4 (Specifically: `192.168.1.15`, `192.168.1.17`, `51.185.130.223`, `10.0.2.87`)
- **Total privilege-related events flagged**: 95

### Key Threat Intelligence Observations:
1. **Password Spraying / Distributed Brute Force**: The four specific suspicious IP addresses (`192.168.1.15`, `192.168.1.17`, `51.185.130.223`, and `10.0.2.87`) engaged in heavy targeting of multiple accounts resulting in over 160 rejections. We successfully identified "Brute Force Followed by Success" originating from this campaign against the user `jdoe` from `100.108.103.43`.
2. **Abnormal Off-Hours Access**: A large volume of successful logins occurred during unusual times (between midnight and 5:00 AM UTC).
3. **Privilege Abuse Attempts**: Dozens of `PRIV_CHANGE` alerts were triggered, documenting failures in critical system commands (e.g., `chown`, `chmod`) by unprivileged users and the `root` user, as well as multiple users successfully being injected into the administrators group or granted sudo access (`hmulrooney1`, `hgaineofengland3`, `bphayre6`).

## 5. Recommendations
Based on the data collected, the following actions are recommended:
1. **Quarantine Source IPs**: Immediately block the flagged anomalous IPs (`192.168.1.15`, `192.168.1.17`, `51.185.130.223`, `10.0.2.87`) via the network intrusion prevention system (IPS) or edge firewall.
2. **Lock Compromised and Targeted Accounts**: Invalidate the credentials for `jdoe` and reset the password immediately, as we've noted a brute force attempt succeeded. Do the same for other heavily targeted accounts like `root` and `admin`.
3. **Audit Privilege Escalations**: Review all users newly added to the administrators group or granted sudo privileges. Revert any unauthorized permissions.
4. **Implement Stronger Authentication Limits**: Enforce Multi-Factor Authentication (MFA) across all authentication gateways and implement temporary lockouts (e.g., 15 minutes) after 5 failed login attempts per user/IP.
5. **Monitor Off-Hours Logins**: Verify with the relevant administrators why anomalous late-night traffic patterns exist. If they do not correspond with remote shifts, consider utilizing geo-blocking or time-restricted access hours. 

## 6. Reflection
- **What worked well**: Building dictionaries to track distinct IP-to-Username mapping dynamically helped immensely with discovering stealthy distributed password spraying techniques. Implementing Python's `datetime` package proved powerful for calculating unusual login windows.
- **What was challenging**: Log files are often messy; ensuring the log parser doesn't crash on slightly malformed inputs while still extracting necessary data fields using regular expressions required robust fallback checks.
- **Future Improvements**: We can improve the tool to ingest dynamic configuration files for tracking organizational business hours (instead of hardcoded 00:00 to 05:00), cross-reference source IPs against publicly available threat intelligence feeds (e.g., AbuseIPDB), and export logs immediately in a JSON format suitable for dashboards like Kibana.
