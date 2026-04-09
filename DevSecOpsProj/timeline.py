import re
with open("SecOps.json", "r", encoding="utf-8") as f:
    time = ""
    ip_dst = ""
    for line in f:
        if '"frame.time":' in line:
            m = re.search(r'"frame.time":\s*"([^"]+)"', line)
            if m: time = m.group(1)
        if '"ip.dst":' in line:
            m = re.search(r'"ip.dst":\s*"([^"]+)"', line)
            if m: ip_dst = m.group(1)
        if '"dns.qry.name":' in line:
            m = re.search(r'"dns.qry.name":\s*"([^"]+)"', line)
            if m:
                name = m.group(1)
                if "whitepepper" in name or "megafile" in name or "megahab" in name:
                    print(f"{time} - DNS Query: {name}")
        if '"http.request.full_uri":' in line:
            m = re.search(r'"http.request.full_uri":\s*"([^"]+)"', line)
            if m:
                uri = m.group(1)
                if "whitepepper" in uri:
                    print(f"{time} - HTTP Request: {uri} (Destination IP: {ip_dst})")
