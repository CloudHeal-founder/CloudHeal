#!/usr/bin/env python3
"""
Cloud & API Vulnerability Scanner
--------------------------------
- Fast TCP port scanning with banner grabbing
- Service fingerprinting (HTTP, SSH, Redis, MongoDB, Elasticsearch, etc.)
- OWASP Top 10 API security checks (BOLA, excessive data, missing auth, etc.)
- Cloud misconfiguration detection (metadata endpoints, open S3 buckets)
- CVSS 4.0 base score assignment (Low/Medium/High/Critical)
- Beautiful coloured tabular output
"""

import socket
import argparse
import concurrent.futures
import sys
import re
import json
from typing import Dict, List, Tuple, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError
import ssl

try:
    from tabulate import tabulate
except ImportError:
    print("Install tabulate: pip install tabulate")
    sys.exit(1)

# ---------- Configuration ----------
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    5000: "Flask/API",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Known cloud metadata endpoints
CLOUD_METADATA = [
    "http://169.254.169.254/latest/meta-data/",   # AWS
    "http://169.254.169.254/metadata/instance?api-version=2017-08-01",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
]

# OWASP API Top 10 (2023) categories
OWASP_API_CATEGORIES = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

# ---------- CVSS 4.0 Base Score Mapping (simplified) ----------
def cvss_score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "INFO"

# ---------- Banner Grabbing ----------
def grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Attempt to read a banner from the service."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        # Send a probe for HTTP servers
        if port in (80, 443, 8080, 8443, 5000):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else None
    except Exception:
        return None

# ---------- Service Detection ----------
def detect_service(port: int, banner: Optional[str]) -> str:
    """Return a human‑readable service name based on port and banner."""
    base = COMMON_PORTS.get(port, "Unknown")
    if not banner:
        return base
    # Refine based on banner
    if "SSH" in banner.upper() or "OpenSSH" in banner:
        return "SSH"
    if "HTTP" in banner.upper() or "Server:" in banner:
        return "HTTP"
    if "Mongo" in banner or "MongoDB" in banner:
        return "MongoDB"
    if "Redis" in banner:
        return "Redis"
    if "Elasticsearch" in banner:
        return "Elasticsearch"
    if "MySQL" in banner:
        return "MySQL"
    if "PostgreSQL" in banner:
        return "PostgreSQL"
    if "FTP" in banner.upper():
        return "FTP"
    return base

# ---------- Vulnerability Checks ----------
def check_cloud_metadata(host: str) -> List[Tuple[str, str, float, str]]:
    """Check for exposed cloud metadata endpoints (cloud‑specific)."""
    findings = []
    for url in CLOUD_METADATA:
        try:
            req = Request(url, headers={"Metadata-Flavor": "Google"})  # GCP uses this
            with urlopen(req, timeout=2, context=ssl._create_unverified_context()) as resp:
                if resp.status == 200:
                    findings.append((
                        f"Exposed cloud metadata: {url}",
                        "Cloud Misconfiguration",
                        7.5,  # CVSS 4.0: High
                        "CRITICAL" if "169.254.169.254" in url else "HIGH"
                    ))
        except Exception:
            continue
    return findings

def check_s3_bucket(host: str) -> List[Tuple[str, str, float, str]]:
    """Check if host is an AWS S3 bucket and if it's publicly readable."""
    if not host.endswith(".s3.amazonaws.com"):
        return []
    findings = []
    try:
        # Try to list bucket (public read)
        url = f"https://{host}/?max-keys=1"
        req = Request(url)
        with urlopen(req, timeout=3, context=ssl._create_unverified_context()) as resp:
            if resp.status == 200:
                findings.append((
                    f"S3 bucket {host} is publicly readable",
                    "Cloud Misconfiguration (S3)",
                    7.0,
                    "HIGH"
                ))
    except Exception:
        pass
    return findings

def check_api_vulnerabilities(host: str, port: int, protocol: str) -> List[Tuple[str, str, float, str]]:
    """Simulate OWASP API Top 10 checks on HTTP endpoints."""
    findings = []
    if port not in (80, 443, 8080, 8443, 5000):
        return findings

    base_url = f"{protocol}://{host}:{port}"
    test_paths = [
        ("/api/users/1", "API1 - BOLA: Accessing another user's object"),
        ("/admin", "API5 - BFLA: Accessing admin functions"),
        ("/api/health", "API10 - Unsafe Consumption: Exposed internal info"),
        ("/api/v1/users", "API9 - Improper Inventory: Exposed API version"),
    ]

    for path, desc in test_paths:
        try:
            url = base_url + path
            req = Request(url)
            with urlopen(req, timeout=3, context=ssl._create_unverified_context()) as resp:
                if resp.status == 200:
                    # Check for excessive data (large response)
                    data = resp.read().decode(errors="ignore")
                    if len(data) > 10000:
                        findings.append((
                            f"{desc} - {url} (excessive data returned)",
                            "OWASP API",
                            5.5,
                            "MEDIUM"
                        ))
                    else:
                        findings.append((
                            f"{desc} - {url} (accessible)",
                            "OWASP API",
                            6.5,
                            "MEDIUM"
                        ))
        except Exception:
            pass
    return findings

def check_service_vulnerabilities(service: str, banner: str, host: str, port: int) -> List[Tuple[str, str, float, str]]:
    """Check for service‑specific vulnerabilities (e.g., default credentials, weak ciphers)."""
    findings = []
    if service == "Redis" and ("redis" in banner.lower() or "Redis" in banner):
        # Check for no authentication
        findings.append((
            f"Redis on port {port} may lack authentication (banner: {banner[:50]})",
            "Security Misconfiguration",
            7.5,
            "HIGH"
        ))
    if service == "MongoDB" and ("MongoDB" in banner):
        findings.append((
            f"MongoDB on port {port} – check for no auth (banner: {banner[:50]})",
            "Security Misconfiguration",
            7.0,
            "HIGH"
        ))
    if service == "Elasticsearch" and ("Elasticsearch" in banner):
        findings.append((
            f"Elasticsearch on port {port} – may be open (banner: {banner[:50]})",
            "Security Misconfiguration",
            6.5,
            "MEDIUM"
        ))
    if service == "SSH" and ("SSH" in banner):
        # Weak ciphers check (simulated)
        if "1.2.3" in banner or "draft" in banner:
            findings.append((
                f"SSH on port {port} may support weak ciphers (banner: {banner[:50]})",
                "Weak Cryptography",
                5.0,
                "MEDIUM"
            ))
    if service == "FTP" and ("FTP" in banner):
        if "anonymous" in banner.lower() or "vsftpd" in banner.lower():
            findings.append((
                f"FTP on port {port} allows anonymous login (banner: {banner[:50]})",
                "Broken Authentication",
                6.0,
                "MEDIUM"
            ))
    return findings

def scan_port(host: str, port: int) -> Tuple[int, Optional[str], Optional[str]]:
    """Scan a single port and return (port, service, banner)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            banner = grab_banner(host, port)
            service = detect_service(port, banner)
            return (port, service, banner)
    except Exception:
        pass
    return (port, None, None)

# ---------- Main Scanner ----------
def scan_host(host: str, ports: List[int], threads: int = 50) -> Dict[int, Tuple[str, str]]:
    """Parallel port scan, returns dict {port: (service, banner)}."""
    open_services = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port, service, banner = future.result()
            if service:
                open_services[port] = (service, banner)
    return open_services

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Cloud & API Vulnerability Scanner")
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range, e.g., 22,80,443 or 1-1024")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--api", action="store_true", help="Run OWASP API checks on HTTP services")
    args = parser.parse_args()

    # Parse ports
    ports = set()
    for part in args.ports.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end+1))
        else:
            ports.add(int(part))
    ports = sorted(ports)

    print(f"[*] Scanning {args.host} on ports: {len(ports)} ports...")
    open_services = scan_host(args.host, ports, args.threads)

    if not open_services:
        print("[!] No open ports found.")
        return

    # Gather all findings
    all_findings = []

    # Cloud metadata checks
    all_findings.extend(check_cloud_metadata(args.host))
    all_findings.extend(check_s3_bucket(args.host))

    # For each open service, run checks
    for port, (service, banner) in open_services.items():
        # Service vulnerabilities
        all_findings.extend(check_service_vulnerabilities(service, banner, args.host, port))
        # API checks if HTTP and flag
        if args.api and service in ("HTTP", "HTTPS"):
            protocol = "https" if port in (443, 8443) else "http"
            all_findings.extend(check_api_vulnerabilities(args.host, port, protocol))

    # Prepare table data
    table_data = []
    for port, (service, banner) in open_services.items():
        # Add open port info
        row = [
            port,
            service,
            banner[:60] if banner else "",
            "-",
            "-",
            "INFO"
        ]
        table_data.append(row)

    # Append findings (each finding as a separate row)
    for desc, category, score, severity in all_findings:
        # Try to associate finding with a port (if possible)
        port = "N/A"
        # Simple heuristic: look for port number in description
        match = re.search(r'port (\d+)', desc)
        if match:
            port = match.group(1)
        table_data.append([
            port,
            category,
            desc[:60],
            f"{score:.1f}",
            severity,
            "VULN"
        ])

    # Sort by severity (Critical > High > Medium > Low > Info)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "VULN": 5}
    table_data.sort(key=lambda x: severity_order.get(x[4], 99))

    # Print beautiful table with colours (ANSI)
    headers = ["Port", "Service/Check", "Details", "CVSS", "Severity", "Type"]
    print("\n" + "="*100)
    print(" VULNERABILITY SCAN REPORT".center(100))
    print("="*100)

    # Colour mapping
    colour_map = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[94m",    # Blue
        "LOW": "\033[92m",       # Green
        "INFO": "\033[37m",      # White
        "VULN": "\033[35m",      # Magenta
    }
    reset = "\033[0m"

    # Print table with colour
    for row in table_data:
        severity = row[4]
        colour = colour_map.get(severity, "")
        print(colour + tabulate([row], headers=headers, tablefmt="plain") + reset)

    # Summary
    print("\n" + "="*100)
    print(f"Total open ports: {len(open_services)}")
    print(f"Total findings:   {len(all_findings)}")
    print("="*100)

if __name__ == "__main__":
    main()















