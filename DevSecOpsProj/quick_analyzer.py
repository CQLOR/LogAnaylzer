import sys
import re
from collections import Counter

dns_queries = Counter()
http_uris = Counter()
http_hosts = Counter()
http_user_agents = Counter()
ip_srcs = Counter()
ip_dsts = Counter()

with open("SecOps.json", "r", encoding="utf-8") as f:
    for line in f:
        if '"dns.qry.name":' in line:
            m = re.search(r'"dns.qry.name":\s*"([^"]+)"', line)
            if m: dns_queries[m.group(1)] += 1
        elif '"http.request.full_uri":' in line:
            m = re.search(r'"http.request.full_uri":\s*"([^"]+)"', line)
            if m: http_uris[m.group(1)] += 1
        elif '"http.host":' in line:
            m = re.search(r'"http.host":\s*"([^"]+)"', line)
            if m: http_hosts[m.group(1)] += 1
        elif '"http.user_agent":' in line:
            m = re.search(r'"http.user_agent":\s*"([^"]+)"', line)
            if m: http_user_agents[m.group(1)] += 1
        elif '"ip.src":' in line:
            m = re.search(r'"ip.src":\s*"([^"]+)"', line)
            if m: ip_srcs[m.group(1)] += 1
        elif '"ip.dst":' in line:
            m = re.search(r'"ip.dst":\s*"([^"]+)"', line)
            if m: ip_dsts[m.group(1)] += 1

with open("quick_stats.txt", "w") as out:
    out.write("DNS Queries:\n")
    for k, v in dns_queries.most_common(): out.write(f"{k}: {v}\n")
    out.write("\nHTTP URIs:\n")
    for k, v in http_uris.most_common(): out.write(f"{k}: {v}\n")
    out.write("\nHTTP Hosts:\n")
    for k, v in http_hosts.most_common(): out.write(f"{k}: {v}\n")
    out.write("\nHTTP User Agents:\n")
    for k, v in http_user_agents.most_common(): out.write(f"{k}: {v}\n")
    out.write("\nIP Srcs:\n")
    for k, v in ip_srcs.most_common(20): out.write(f"{k}: {v}\n")
    out.write("\nIP Dsts:\n")
    for k, v in ip_dsts.most_common(20): out.write(f"{k}: {v}\n")
