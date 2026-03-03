#!/usr/bin/env python3
"""
Log Analyzer & Threat Detector
Author: Sanketh Subhas
Description: Parses Apache/Windows logs and detects threats using pattern matching.
"""

import re
import json
import argparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ─── THREAT DETECTION THRESHOLDS ────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5       # failed logins from same IP within log window
PORT_SCAN_THRESHOLD = 10        # unique ports hit by same IP
SUSPICIOUS_STATUS_CODES = {401, 403, 404, 500}
SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "python-requests", "curl/", "wget/", "dirbuster", "gobuster"
]
KNOWN_MALICIOUS_IPS = {
    "192.168.1.666",   # placeholder — replace with threat intel feeds
}

# ─── LOG PATTERNS ────────────────────────────────────────────────────────────

APACHE_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

WINDOWS_AUTH_PATTERN = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<event_id>4624|4625|4648|4719|4720|4726|4740)\s+'
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<user>\S+)\s+'
    r'(?P<result>Success|Failure)'
)

# ─── EVENT ID DESCRIPTIONS ───────────────────────────────────────────────────

WINDOWS_EVENT_DESCRIPTIONS = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4648": "Logon with Explicit Credentials",
    "4719": "System Audit Policy Changed",
    "4720": "User Account Created",
    "4726": "User Account Deleted",
    "4740": "User Account Locked Out",
}


# ─── PARSER FUNCTIONS ────────────────────────────────────────────────────────

def parse_apache_logs(filepath):
    entries = []
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            m = APACHE_PATTERN.match(line.strip())
            if m:
                entries.append({
                    "type": "apache",
                    "ip": m.group("ip"),
                    "time": m.group("time"),
                    "method": m.group("method"),
                    "path": m.group("path"),
                    "status": int(m.group("status")),
                    "agent": m.group("agent") or "",
                })
    return entries


def parse_windows_logs(filepath):
    entries = []
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            m = WINDOWS_AUTH_PATTERN.match(line.strip())
            if m:
                entries.append({
                    "type": "windows",
                    "ip": m.group("ip"),
                    "time": m.group("time"),
                    "event_id": m.group("event_id"),
                    "user": m.group("user"),
                    "result": m.group("result"),
                    "description": WINDOWS_EVENT_DESCRIPTIONS.get(m.group("event_id"), "Unknown Event"),
                })
    return entries


def auto_parse(filepath):
    """Auto-detect log type and parse accordingly."""
    with open(filepath, "r", errors="ignore") as f:
        sample = f.read(500)
    if re.search(r'\d+\.\d+\.\d+\.\d+.*\[.*\].*"(GET|POST|HEAD)', sample):
        return parse_apache_logs(filepath), "apache"
    elif re.search(r'\d{4}-\d{2}-\d{2}.*46(24|25|48)', sample):
        return parse_windows_logs(filepath), "windows"
    else:
        print(f"  [!] Could not detect log format for {filepath}")
        return [], "unknown"


# ─── THREAT DETECTION ────────────────────────────────────────────────────────

def detect_brute_force(entries):
    """Detect IPs with multiple failed login attempts."""
    alerts = []
    failed = defaultdict(list)

    for e in entries:
        if e["type"] == "apache" and e["status"] == 401:
            failed[e["ip"]].append(e)
        elif e["type"] == "windows" and e["result"] == "Failure":
            failed[e["ip"]].append(e)

    for ip, events in failed.items():
        if len(events) >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "severity": "HIGH",
                "type": "Brute Force Attack",
                "ip": ip,
                "count": len(events),
                "detail": f"{len(events)} failed login attempts detected from {ip}",
                "mitre": "T1110 - Brute Force",
            })
    return alerts


def detect_suspicious_agents(entries):
    """Detect known scanning/attack tool user agents."""
    alerts = []
    flagged = defaultdict(set)

    for e in entries:
        if e["type"] != "apache":
            continue
        agent_lower = e["agent"].lower()
        for tool in SUSPICIOUS_USER_AGENTS:
            if tool in agent_lower:
                flagged[e["ip"]].add(tool)

    for ip, tools in flagged.items():
        alerts.append({
            "severity": "MEDIUM",
            "type": "Suspicious User Agent",
            "ip": ip,
            "count": len(tools),
            "detail": f"Scanning tools detected from {ip}: {', '.join(tools)}",
            "mitre": "T1595 - Active Scanning",
        })
    return alerts


def detect_port_scanning(entries):
    """Detect IPs hitting many different endpoints rapidly (simulated port scan)."""
    alerts = []
    ip_paths = defaultdict(set)

    for e in entries:
        if e["type"] == "apache":
            ip_paths[e["ip"]].add(e["path"])

    for ip, paths in ip_paths.items():
        if len(paths) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "severity": "MEDIUM",
                "type": "Directory/Port Scan",
                "ip": ip,
                "count": len(paths),
                "detail": f"{ip} accessed {len(paths)} unique paths — possible enumeration",
                "mitre": "T1046 - Network Service Discovery",
            })
    return alerts


def detect_error_spikes(entries):
    """Detect IPs generating large volumes of 4xx/5xx errors."""
    alerts = []
    error_counts = defaultdict(int)

    for e in entries:
        if e["type"] == "apache" and e["status"] in SUSPICIOUS_STATUS_CODES:
            error_counts[e["ip"]] += 1

    for ip, count in error_counts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "severity": "LOW",
                "type": "Error Spike",
                "ip": ip,
                "count": count,
                "detail": f"{ip} triggered {count} HTTP error responses",
                "mitre": "T1595.002 - Vulnerability Scanning",
            })
    return alerts


def detect_known_malicious_ips(entries):
    """Flag entries from known malicious IPs."""
    alerts = []
    flagged = set()

    for e in entries:
        if e["ip"] in KNOWN_MALICIOUS_IPS and e["ip"] not in flagged:
            flagged.add(e["ip"])
            alerts.append({
                "severity": "CRITICAL",
                "type": "Known Malicious IP",
                "ip": e["ip"],
                "count": 1,
                "detail": f"Traffic detected from known malicious IP: {e['ip']}",
                "mitre": "T1071 - Application Layer Protocol",
            })
    return alerts


def detect_account_lockouts(entries):
    """Detect account lockout events from Windows logs."""
    alerts = []
    for e in entries:
        if e["type"] == "windows" and e["event_id"] == "4740":
            alerts.append({
                "severity": "HIGH",
                "type": "Account Lockout",
                "ip": e["ip"],
                "count": 1,
                "detail": f"Account '{e['user']}' locked out — originating from {e['ip']}",
                "mitre": "T1110.001 - Password Guessing",
            })
    return alerts


def run_all_detections(entries):
    all_alerts = []
    all_alerts += detect_brute_force(entries)
    all_alerts += detect_suspicious_agents(entries)
    all_alerts += detect_port_scanning(entries)
    all_alerts += detect_error_spikes(entries)
    all_alerts += detect_known_malicious_ips(entries)
    all_alerts += detect_account_lockouts(entries)
    return all_alerts


# ─── STATISTICS ──────────────────────────────────────────────────────────────

def generate_stats(entries):
    ip_counts = defaultdict(int)
    status_counts = defaultdict(int)
    top_paths = defaultdict(int)

    for e in entries:
        ip_counts[e["ip"]] += 1
        if e["type"] == "apache":
            status_counts[e["status"]] += 1
            top_paths[e["path"]] += 1

    return {
        "total_entries": len(entries),
        "unique_ips": len(ip_counts),
        "top_ips": sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5],
        "status_distribution": dict(sorted(status_counts.items())),
        "top_paths": sorted(top_paths.items(), key=lambda x: x[1], reverse=True)[:5],
    }


# ─── REPORT OUTPUT ───────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "LOW":      "\033[92m",  # green
}
RESET = "\033[0m"


def print_report(alerts, stats, log_file):
    print("\n" + "="*65)
    print("        LOG ANALYZER & THREAT DETECTOR — REPORT")
    print("="*65)
    print(f"  File     : {log_file}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Entries  : {stats['total_entries']} | Unique IPs: {stats['unique_ips']}")
    print("="*65)

    # Alerts
    sorted_alerts = sorted(alerts, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    print(f"\n  🚨 THREATS DETECTED: {len(alerts)}\n")

    if not alerts:
        print("  ✅ No threats detected.")
    else:
        for a in sorted_alerts:
            color = SEVERITY_COLORS.get(a["severity"], "")
            print(f"  {color}[{a['severity']}]{RESET} {a['type']}")
            print(f"         IP     : {a['ip']}")
            print(f"         Detail : {a['detail']}")
            print(f"         MITRE  : {a['mitre']}")
            print()

    # Stats
    print("-"*65)
    print("  📊 TOP IPs BY REQUEST VOLUME")
    for ip, count in stats["top_ips"]:
        print(f"     {ip:<20} {count} requests")

    if stats["status_distribution"]:
        print("\n  📊 HTTP STATUS CODE DISTRIBUTION")
        for code, count in stats["status_distribution"].items():
            print(f"     {code}  →  {count} responses")

    if stats["top_paths"]:
        print("\n  📊 TOP REQUESTED PATHS")
        for path, count in stats["top_paths"]:
            print(f"     {count:<6} {path}")

    print("\n" + "="*65 + "\n")


def save_json_report(alerts, stats, output_path):
    report = {
        "generated": datetime.now().isoformat(),
        "summary": {
            "total_entries": stats["total_entries"],
            "unique_ips": stats["unique_ips"],
            "total_alerts": len(alerts),
            "critical": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
            "high": sum(1 for a in alerts if a["severity"] == "HIGH"),
            "medium": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
            "low": sum(1 for a in alerts if a["severity"] == "LOW"),
        },
        "alerts": alerts,
        "statistics": {
            "top_ips": stats["top_ips"],
            "status_distribution": stats["status_distribution"],
            "top_paths": stats["top_paths"],
        }
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  💾 JSON report saved to: {output_path}")


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer & Threat Detector — by Sanketh Subhas",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py sample_logs/apache_access.log
  python log_analyzer.py sample_logs/windows_auth.log
  python log_analyzer.py sample_logs/apache_access.log --output report.json
        """
    )
    parser.add_argument("logfile", help="Path to log file (Apache or Windows auth log)")
    parser.add_argument("--output", "-o", help="Save JSON report to file", default=None)
    parser.add_argument("--format", "-f", choices=["apache", "windows", "auto"], default="auto",
                        help="Log format (default: auto-detect)")
    args = parser.parse_args()

    log_path = Path(args.logfile)
    if not log_path.exists():
        print(f"\n  [ERROR] File not found: {log_path}\n")
        return

    print(f"\n  🔍 Analyzing: {log_path.name} ...")

    if args.format == "apache":
        entries = parse_apache_logs(log_path)
        fmt = "apache"
    elif args.format == "windows":
        entries = parse_windows_logs(log_path)
        fmt = "windows"
    else:
        entries, fmt = auto_parse(log_path)

    print(f"  📄 Format detected: {fmt.upper()} | {len(entries)} entries parsed")

    alerts = run_all_detections(entries)
    stats = generate_stats(entries)
    print_report(alerts, stats, log_path.name)

    if args.output:
        save_json_report(alerts, stats, args.output)


if __name__ == "__main__":
    main()
