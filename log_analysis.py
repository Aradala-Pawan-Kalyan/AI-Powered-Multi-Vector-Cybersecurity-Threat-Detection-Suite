"""
log_analysis.py
-----------------
Parses uploaded server/auth logs and flags patterns associated with
hacking attempts: SSH brute-force, SQL injection, XSS, path traversal,
known attack-tool user agents, and reconnaissance-style scanning
(one IP hitting many distinct paths / generating many 404s).

Supports:
 - Apache/Nginx "combined" access log format
 - Linux auth.log SSH authentication lines

This is offline log parsing only — nothing here reaches out to the
network or executes anything from the log file.
"""

import re
from collections import defaultdict

ACCESS_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)

SSH_FAILED_RE = re.compile(
    r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
)
SSH_ACCEPTED_RE = re.compile(
    r'Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
)

SQLI_PATTERNS = [
    r"'\s*or\s*'1'\s*=\s*'1", r"union(\s+all)?\s+select", r"drop\s+table",
    r"xp_cmdshell", r"--\s", r"/\*.*\*/", r"';--", r"benchmark\(",
    r"sleep\(\d+\)", r"waitfor\s+delay",
]
XSS_PATTERNS = [r"<script", r"onerror\s*=", r"javascript:", r"<img[^>]+onerror"]
TRAVERSAL_PATTERNS = [r"\.\./", r"%2e%2e%2f", r"\.\.\\", r"etc/passwd", r"boot\.ini"]

ATTACK_TOOL_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster",
    "acunetix", "nessus", "wpscan", "hydra", "metasploit", "zgrab",
]

SENSITIVE_PATH_PROBES = [
    "/.env", "/wp-login.php", "/wp-admin", "/.git/config", "/admin/config",
    "/phpmyadmin", "/.aws/credentials", "/server-status", "/xmlrpc.php",
]


def _match_any(patterns, text):
    text_l = text.lower()
    return any(re.search(p, text_l) for p in patterns)


def analyze_log(text: str) -> dict:
    lines = [l for l in text.splitlines() if l.strip()]
    events = []
    ip_failed_logins = defaultdict(int)
    ip_paths = defaultdict(set)
    ip_404s = defaultdict(int)
    ip_hits = defaultdict(int)

    for line in lines:
        m = SSH_FAILED_RE.search(line)
        if m:
            ip = m.group("ip")
            ip_failed_logins[ip] += 1
            ip_hits[ip] += 1
            continue

        m = SSH_ACCEPTED_RE.search(line)
        if m:
            ip = m.group("ip")
            if ip_failed_logins.get(ip, 0) >= 3:
                events.append({
                    "ip": ip, "type": "brute_force_success",
                    "severity": "critical",
                    "detail": f"Successful SSH login from {ip} after {ip_failed_logins[ip]} failed attempts",
                    "sample": line.strip()[:200],
                })
            continue

        m = ACCESS_LOG_RE.search(line)
        if m:
            ip = m.group("ip")
            path = m.group("path") or ""
            agent = m.group("agent") or ""
            status = m.group("status") or ""
            ip_hits[ip] += 1
            ip_paths[ip].add(path)
            if status == "404":
                ip_404s[ip] += 1

            if _match_any(SQLI_PATTERNS, path):
                events.append({
                    "ip": ip, "type": "sql_injection", "severity": "high",
                    "detail": "Possible SQL injection attempt in request path",
                    "sample": line.strip()[:200],
                })
            if _match_any(XSS_PATTERNS, path):
                events.append({
                    "ip": ip, "type": "xss_attempt", "severity": "high",
                    "detail": "Possible cross-site scripting (XSS) attempt in request path",
                    "sample": line.strip()[:200],
                })
            if _match_any(TRAVERSAL_PATTERNS, path):
                events.append({
                    "ip": ip, "type": "path_traversal", "severity": "high",
                    "detail": "Possible directory traversal attempt",
                    "sample": line.strip()[:200],
                })
            if any(p in path.lower() for p in SENSITIVE_PATH_PROBES):
                events.append({
                    "ip": ip, "type": "sensitive_path_probe", "severity": "medium",
                    "detail": f"Probed a sensitive/known-vulnerable path ({path})",
                    "sample": line.strip()[:200],
                })
            if any(tool in agent.lower() for tool in ATTACK_TOOL_AGENTS):
                events.append({
                    "ip": ip, "type": "attack_tool_agent", "severity": "high",
                    "detail": f"Request came from a known security/attack tool user agent ('{agent}')",
                    "sample": line.strip()[:200],
                })

    for ip, count in ip_failed_logins.items():
        if count >= 5:
            events.append({
                "ip": ip, "type": "ssh_brute_force", "severity": "critical",
                "detail": f"{count} failed SSH login attempts from {ip}",
                "sample": "",
            })

    for ip, paths in ip_paths.items():
        if len(paths) >= 15:
            events.append({
                "ip": ip, "type": "reconnaissance_scan", "severity": "medium",
                "detail": f"{ip} requested {len(paths)} distinct paths — possible directory enumeration/scanning",
                "sample": "",
            })
    for ip, count in ip_404s.items():
        if count >= 10:
            events.append({
                "ip": ip, "type": "404_flood", "severity": "medium",
                "detail": f"{ip} triggered {count} 'not found' responses — possible scanning behavior",
                "sample": "",
            })

    severity_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    events.sort(key=lambda e: severity_rank.get(e["severity"], 0), reverse=True)

    by_type = defaultdict(int)
    flagged_ips = set()
    for e in events:
        by_type[e["type"]] += 1
        flagged_ips.add(e["ip"])

    return {
        "total_lines": len(lines),
        "total_events": len(events),
        "flagged_ip_count": len(flagged_ips),
        "flagged_ips": sorted(flagged_ips),
        "by_type": dict(by_type),
        "events": events[:300],
    }
