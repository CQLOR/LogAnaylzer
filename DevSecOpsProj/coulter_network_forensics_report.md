# Capstone Part II: Network Forensics Investigation (PCAP Analysis)
Author: Lenny Coulter

## 1. Executive Summary
A critical security incident occurred on 2026-01-28 involving an internal Windows system (`10.1.21.58`). Network traffic analysis indicates that the host was compromised and successfully established Command-and-Control (C2) communication with known malicious infrastructure (`whitepepper.su`). The attacker successfully executed automated botnet enrollment scripts masquerading as standard web browsers (Chrome and Edge) and likely exfiltrated log data or credentials. Due to the high probability of data exfiltration and control established by the attacker, this incident represents a **High Severity** threat with substantial potential business impact, including unauthorized data access, ransomware deployment potential, and lateral movement.

## 2. Environment Overview
Based on DHCP traffic and DNS queries within the PCAP, the environment is a corporate Microsoft Windows network:
* **Internal Network Structure:** Subnet `10.1.21.0/24` (IPs leased from gateway `10.1.21.1`).
* **Domain:** `win11office.com` and `mshome.net` 
* **Systems Present:** Enterprise Windows Endpoints (Windows 11 inferred from FQDN).

## 3. Host Identification
The primary internal system involved in all anomalous outbound communication has been definitively identified:
* **IP Address:** `10.1.21.58`
* **MAC Address:** `00:21:5d:c8:0e:f2`
* **Hostname:** `DESKTOP-ES9F3ML`
* **Associated User Environment:** Connected to the corporate Windows domain (`_ldap._tcp.dc._msdcs.DESKTOP-ES9F3ML.win11office.com` queries indicate AD integration).

*Evidence:* Analyzing DHCP `Discover` and `Request` frames (Options 12, 50, 61, 81) clearly linked MAC `00:21:5d:c8:0e:f2` to IP `10.1.21.58` and FQDN `DESKTOP-ES9F3ML.win11office.com`. This host was the source IP for the suspicious traffic.

## 4. Traffic Analysis Findings

### A. Suspicious Traffic Patterns
The host displayed automated, scripted communication patterns characteristic of malware beaconing. Shortly after reaching out to irregular file-hosting domains, it initiated rapid HTTP connections lacking standard browsing behavior (e.g., retrieving typical assets like CSS or JS alongside the `favicon.ico`).

### B. DNS Analysis
Multiple queries were made to highly suspicious domains with no business justification:
* `media.megafilehub4.lat` and `arch.filemegahab4.sbs` - These domains use irregular TLDs (`.lat`, `.sbs`) and naming conventions often associated with temporary malware payload hosting (Stage 1 drop sites).
* `whitepepper.su` - Registration under `.su` (Soviet Union) with automated DNS clustering, heavily indicative of C2 infrastructure.

### C. Command-and-Control (C2) Activity
Outbound HTTP GET requests were made to `whitepepper.su` on port 80 at IP `45.77.88.12`. The path `/api/set_agent` and URL parameters (`id`, `token`, `agent=Chrome`) represent a bot 'check-in', registering the compromised host with the attacker's centralized panel.

### D. Data Exfiltration Analysis
Data exfiltration is highly probable. Following the initial bot registration check-in, an identical request was sent with an appended parameter `&act=log` (`http://whitepepper.su/api/set_agent?...&act=log`). This specific URI structure reveals that localized logs, keylogger outputs, or stolen credentials were electronically uploaded to the C2 server within the GET request or underlying streams.

## 5. Indicators of Compromise (IOC)
* **Domains:**
  * `media.megafilehub4.lat` (Payload Server)
  * `arch.filemegahab4.sbs` (Payload Server)
  * `whitepepper.su` (C2 Server)
* **IP Addresses:**
  * `45.77.88.12` (Hosts `whitepepper.su`)
* **URLs:**
  * `http://whitepepper.su/api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C&token=842e2802df0f0a06b4ed51f12f4387e761523b&description=&agent=Chrome`
  * `http://whitepepper.su/api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C&token=842e2802df0f0a06b4ed51f12f4387e761523b&description=&agent=Edge&act=log`

*Justification:* These indicators directly correlate with the successful establishment of the C2 connection and active data transmission initiated by the malware.

## 6. Timeline of Activity
All timestamps are in UTC (2026-01-28):
* **00:04:49** - **Initial Suspicious Activity:** The compromised host `10.1.21.58` queries DNS for `media.megafilehub4.lat` and subsequently `arch.filemegahab4.sbs` mapping to payload delivery servers. This is likely the first stage execution of the malware loader downloading the C2 module.
* **00:05:36** - **Outbound C2 Resolution:** First DNS Request resolving the attacker's Command-and-Control domain `whitepepper.su`.
* **00:05:39** - **Evidence of Compromise (C2 Beacon):** The malware executes its first successful HTTP GET request to `whitepepper.su/api/set_agent`. It registers the system via token `842e28...` and masquerades via `agent=Chrome`.
* **00:05:40** - **Data Exfiltration:** A secondary HTTP GET request includes the parameter `&act=log`, indicating an electronic transmission or "logging" of local host data back to the attacker.
* **00:05:46 - 00:05:47** - **Follow-on Behavior:** The DNS querying loop repeats, followed by duplicated C2 beaconing explicitly shifting the parameter to `agent=Edge` and repeating the `act=log` exfiltration sequence.

## 7. Attack Narrative
During this incident, `DESKTOP-ES9F3ML` was compromised via a first-stage loader. Initially, at 00:04:49 UTC, the host communicated with `megafilehub4.lat` and `filemegahab4.sbs`, domains utilized to pivot and serve the secondary malicious payload. Just under a minute later, the fully executed payload began actively querying its hardcoded C2 infrastructure, `whitepepper.su`. 

Upon resolving the malicious domain, the malware issued HTTP GET requests to enroll the host in the attacker's botnet architecture on IP `45.77.88.12`. It passed specific hardware IDs and a static auth token (`3BF67EC...`). The attacker successfully acquired the host's logging parameters via repeated parameterized data droplets (noted by `act=log`). The malware then systematically iterated its perceived user-agents (switching from Chrome to Edge) likely to bypass rudimentary behavioral blocking technologies or feed different log types to the botmaster.

## 8. Impact Assessment
* **Systems Affected:** `DESKTOP-ES9F3ML` (IP: `10.1.21.58`).
* **Data at Risk:** Local system credentials, browsing data, operational log data, and potentially AD domain intelligence if the malware successfully mapped the `win11office.com` network topology.
* **Organizational Impact:** High risk of full Active Directory compromise if lateral movement occurred. Depending on the `act=log` content, proprietary corporate data could currently be exposed to threat actors.

## 9. Recommendations

**Immediate Actions:**
* **Isolate:** Disconnect `DESKTOP-ES9F3ML` (MAC: `00:21:5d:c8:0e:f2`) from the corporate network immediately to halt exfiltration and lateral movement.
* **Block:** Implementing perimeter blocklists firewalling outbound traffic to `whitepepper.su`, `*.megafilehub4.lat`, `*.filemegahab4.sbs`, and IP `45.77.88.12`.
* **Reset:** Reset all user credentials associated with the affected workstation, as well as any network service accounts operating on it.

**Short-Term Improvements:**
* **Scanning:** Run comprehensive full-disk endpoint antivirus and malware sweeps on all adjacent hosts on subnet `10.1.21.0/24`.
* **Patching & Triage:** Capture volatile memory (RAM) off the infected host before wiping and reimaging to discover the initial vector (e.g. phishing email payload vs software vulnerability).

**Long-Term Improvements:**
* **Deploy EDR:** Scale Endpoint Detection and Response tools across all fleet systems to detect process injection or unauthorized binaries communicating externally.
* **DNS Sinkholing:** Leverage active DNS filtering to block new domains ending in irregular high-risk TLDs like `.su` or `.sbs` globally across the corporate gateway.
* **Network Monitoring:** Enable deep packet inspection logging specifically alerting on cleartext credential passage or atypical URL query strings passing tokens outside authorized API architectures.

## 10. Reflection
* **Challenges:** Analyzing a 681MB JSON-formatted PCAP natively is memory-intensive and difficult without an ingestion pipeline (like Elastic/Kibana). Creating specialized filtering to rapidly extract relevant HTTP/DNS lines proved vital.
* **What Worker Best:** Using Python to iterate over the JSON data asynchronously based on string indices (`"dns.qry.name"`, `"http.request.full_uri"`) drastically circumvented memory issues and cleanly pulled required observables to reconstruct the timeline in seconds.
* **Improvements:** In a future production environment, automating PCAP processing through specialized libraries (like PyShark) or utilizing SIEM integrations would allow much deeper TCP-level contextual parsing (e.g. re-assembling the TCP stream to view payload responses from the server) rather than just header parsing.

---
**Filters/Scripts Used:**
- `python quick_analyzer.py` (Custom Python line-by-line Regex scanner extracting HTTP Uris and DNS Queries)
- RegEx matching (`"http.request.full_uri":\s*"([^"]+)"`)
- RegEx matching (`"dns.qry.name":\s*"([^"]+)"`)
- Filtering `ip.dst` correlation mapped directly against `.su` and `.lat` HTTP hosts.
