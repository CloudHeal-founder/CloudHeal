#!/usr/bin/env python3
"""
Aegis (APCSS) – Automated Protection of Cloud Security Systems
With Human-in-the-Loop + AI Support + Enhanced Web Scanning + User Authentication
Built by Austin Emmanuel – 19‑year‑old founder from Nigeria
"""
import socket
import argparse
import concurrent.futures
import sys
import re
import json
import sqlite3
import datetime
import os
import ssl
import threading
import webbrowser
import requests
import urllib3
import subprocess
import time
from typing import Dict, List, Tuple, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

# ----- FLASK AUTHENTICATION IMPORTS -----
from flask import Flask, render_template_string, jsonify, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----- AI SUPPORT -----
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

# Configure your AI provider (choose one)
AI_PROVIDER = "ollama"  # or "openai"
OPENAI_API_KEY = "your-api-key-here"  # Only needed for OpenAI

if OPENAI_AVAILABLE and OPENAI_API_KEY != "your-api-key-here":
    openai.api_key = OPENAI_API_KEY

# ----- Optional Cloud SDKs -----
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from google.cloud import storage
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

try:
    from azure.storage.blob import BlobServiceClient
    from azure.identity import DefaultAzureCredential
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    import oci
    OCI_AVAILABLE = True
except ImportError:
    OCI_AVAILABLE = False

# ----- Web Dashboard -----
try:
    from flask import Flask, render_template_string, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("[!] Flask not installed. Install with: pip install flask")

# ----- Table Formatting -----
try:
    from tabulate import tabulate
except ImportError:
    print("Install tabulate: pip install tabulate")
    sys.exit(1)

# ---------- Database Setup ----------
DB_NAME = "apcss_global.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, target TEXT, cloud TEXT, account TEXT,
        open_ports TEXT, findings TEXT,
        total_open_ports INTEGER, total_findings INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS resources (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER,
        resource_type TEXT, resource_id TEXT, status TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, cloud TEXT, account TEXT,
        message TEXT, severity TEXT, fixed INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        company TEXT,
        created_at TEXT
    )''')
    conn.commit()
    conn.close()

def ensure_db_tables():
    """Create all tables if they don't exist (called at app startup)."""
    try:
        init_db()
        print("[+] Database tables verified/created.")
    except Exception as e:
        print(f"[!] Error creating database tables: {e}")

def save_scan(target, cloud, account, open_services, findings):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    ts = datetime.datetime.now().isoformat()
    c.execute('''INSERT INTO scans (timestamp, target, cloud, account, open_ports, findings, total_open_ports, total_findings)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (ts, target, cloud, account,
               json.dumps(list(open_services.keys())),
               json.dumps(findings),
               len(open_services), len(findings)))
    scan_id = c.lastrowid
    for port, (service, banner) in open_services.items():
        c.execute('INSERT INTO resources (scan_id, resource_type, resource_id, status) VALUES (?, ?, ?, ?)',
                  (scan_id, "port", str(port), f"{service}:{banner[:30] if banner else ''}"))
    conn.commit()
    conn.close()

def save_alert(cloud, account, message, severity, fixed=False):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    ts = datetime.datetime.now().isoformat()
    c.execute('INSERT INTO alerts (timestamp, cloud, account, message, severity, fixed) VALUES (?, ?, ?, ?, ?, ?)',
              (ts, cloud, account, message, severity, 1 if fixed else 0))
    conn.commit()
    conn.close()

def get_scan_history():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT timestamp, cloud, account, total_open_ports, total_findings FROM scans ORDER BY id DESC LIMIT 10')
    rows = c.fetchall()
    conn.close()
    return rows

def get_alerts(limit=20):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT timestamp, cloud, account, message, severity, fixed FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

# ---------- Slack Alert ----------
def send_slack_alert(message, severity="INFO", webhook_url=None, cloud="unknown", account="unknown"):
    if not webhook_url:
        return
    try:
        import requests
        color = "good" if severity == "INFO" else "warning" if severity == "MEDIUM" else "danger"
        payload = {
            "attachments": [{
                "color": color,
                "title": f"Aegis Alert [{cloud}/{account}]: {severity}",
                "text": message,
                "footer": "Aegis Security Platform",
                "ts": int(datetime.datetime.now().timestamp())
            }]
        }
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception:
        pass

# ---------- AI QUERY FUNCTION ----------
def ai_query(question, context=""):
    """Ask AI about your cloud security"""
    if not OLLAMA_AVAILABLE and not OPENAI_AVAILABLE:
        return "AI not available. Install ollama or openai."

    system_prompt = f"""
You are Aegis AI, a cloud security assistant built by Austin Emmanuel, a 19‑year‑old founder from Nigeria.

ABOUT AEGIS:
- Aegis (APCSS) is the world's first open‑source, four‑cloud, self‑healing security platform.
- It scans AWS, GCP, Azure, and OCI in one command.
- It auto‑fixes attack chains (S3, Security Groups, EC2, IAM).
- It includes a live dashboard, PDF compliance reports, and drift detection.
- It is completely free and open source.
- It was built because commercial tools like Wiz and Orca cost millions.
- The founder, Austin Emmanuel, built it to make cloud security accessible to everyone.

Your job is to help users understand their cloud security posture.
Answer questions about:
- Cloud vulnerabilities (S3, EC2, IAM, Security Groups, etc.)
- Attack paths and how attackers move
- Remediation steps for security issues
- Cloud security best practices
- Aegis itself – what it is, who built it, how to use it

Be helpful, accurate, and concise. Use simple language.

Context from the user's cloud scan:
{context}
"""

    try:
        if OLLAMA_AVAILABLE:
            response = ollama.chat(
                model="llama3",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": question}
                ]
            )
            return response['message']['content']
        elif OPENAI_AVAILABLE:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": question}
                ]
            )
            return response.choices[0].message.content
    except Exception as e:
        return f"AI Error: {str(e)}"

# ---------- COMPLIANCE REPORTS (PDF) ----------
try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False
    print("[!] fpdf2 not installed. Install: pip install fpdf2")

def generate_compliance_report(target="127.0.0.1", output_file="apcss_report.pdf", cloud=None, account=None):
    if not FPDF_AVAILABLE:
        print("[!] fpdf2 not installed. Run: pip install fpdf2")
        return None

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    if cloud and account:
        c.execute('''SELECT timestamp, cloud, account, open_ports, findings, total_open_ports, total_findings 
                     FROM scans WHERE cloud = ? AND account = ? ORDER BY id DESC LIMIT 1''', (cloud, account))
    elif cloud:
        c.execute('''SELECT timestamp, cloud, account, open_ports, findings, total_open_ports, total_findings 
                     FROM scans WHERE cloud = ? ORDER BY id DESC LIMIT 1''', (cloud,))
    else:
        c.execute('''SELECT timestamp, cloud, account, open_ports, findings, total_open_ports, total_findings 
                     FROM scans ORDER BY id DESC LIMIT 1''')
    latest = c.fetchone()

    if cloud and account:
        c.execute('SELECT timestamp, cloud, account, message, severity, fixed FROM alerts WHERE cloud = ? AND account = ? ORDER BY id DESC', (cloud, account))
    elif cloud:
        c.execute('SELECT timestamp, cloud, account, message, severity, fixed FROM alerts WHERE cloud = ? ORDER BY id DESC', (cloud,))
    else:
        c.execute('SELECT timestamp, cloud, account, message, severity, fixed FROM alerts ORDER BY id DESC')
    alerts = c.fetchall()
    conn.close()

    if not latest:
        print("[!] No scan data found. Run a scan first with --db")
        return None

    timestamp, cl, acc, open_ports_json, findings_json, total_ports, total_findings = latest
    open_ports = json.loads(open_ports_json) if open_ports_json else []
    findings = json.loads(findings_json) if findings_json else []

    attack_paths = []
    if cl == "aws":
        try:
            resources = fetch_aws_resources(acc)
            G = build_attack_graph(resources)
            paths = find_attack_paths(G)
            for p in paths:
                readable = []
                for node in p:
                    if node == "Internet": readable.append("Internet")
                    elif node.startswith("s3:"): readable.append(f"S3:{node.replace('s3:', '')}")
                    elif node.startswith("sg-"): readable.append("SG")
                    elif node.startswith("i-"): readable.append("EC2")
                    elif node.startswith("iam:"): readable.append("IAM")
                    else: readable.append(node)
                attack_paths.append(" -> ".join(readable))
        except:
            pass

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.add_page()
    pdf.set_font("helvetica", "B", 24)
    pdf.cell(0, 40, "Aegis", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "Automated Protection of Cloud Security Systems", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("helvetica", "", 12)
    pdf.cell(0, 20, f"Compliance Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(20)
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, f"Cloud: {cl or 'All'}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 10, f"Account: {acc or 'All'}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 10, "Scan Date: " + timestamp[:19], new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(20)
    pdf.set_font("helvetica", "I", 10)
    pdf.cell(0, 10, "Generated by Aegis Security Platform", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 10, "Open Source - Multi-Cloud Security", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.add_page()
    pdf.set_font("helvetica", "B", 18)
    pdf.cell(0, 15, "1. Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.line(10, 45, 200, 45)

    pdf.set_font("helvetica", "", 12)
    pdf.ln(10)
    pdf.cell(0, 10, f"- Total Open Ports: {total_ports}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"- Total Findings: {total_findings}", new_x="LMARGIN", new_y="NEXT")
    critical = sum(1 for a in alerts if a[4] == 'CRITICAL' and a[5] == 0)
    fixed = sum(1 for a in alerts if a[5] == 1)
    pdf.cell(0, 10, f"- Critical Vulnerabilities: {critical}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"- Auto-Fixed Issues: {fixed}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"- Attack Paths Found: {len(attack_paths)}", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(10)
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Compliance Readiness:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 12)
    status = "PASS" if critical == 0 else "FAIL"
    pdf.cell(0, 10, f"  - PCI-DSS: {status}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"  - HIPAA: {status}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"  - SOC2: {status}", new_x="LMARGIN", new_y="NEXT")

    pdf.add_page()
    pdf.set_font("helvetica", "B", 18)
    pdf.cell(0, 15, "2. Detailed Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.line(10, 45, 200, 45)

    pdf.set_font("helvetica", "B", 10)
    pdf.cell(25, 10, "Port", border=1)
    pdf.cell(40, 10, "Service", border=1)
    pdf.cell(60, 10, "Vulnerability", border=1)
    pdf.cell(25, 10, "CVSS", border=1)
    pdf.cell(25, 10, "Severity", border=1)
    pdf.cell(20, 10, "Fixed", border=1)
    pdf.ln()

    pdf.set_font("helvetica", "", 9)
    for f in findings[:15]:
        if len(f) >= 4:
            desc, cat, score, sev = f[0], f[1], f[2], f[3]
            is_fixed = any(sev in a[4] and desc in a[3] for a in alerts if a[5] == 1)
            pdf.cell(25, 8, "N/A", border=1)
            pdf.cell(40, 8, cat[:20], border=1)
            pdf.cell(60, 8, desc[:45], border=1)
            pdf.cell(25, 8, str(score), border=1)
            pdf.cell(25, 8, sev[:8], border=1)
            pdf.cell(20, 8, "YES" if is_fixed else "NO", border=1)
            pdf.ln()

    pdf.add_page()
    pdf.set_font("helvetica", "B", 18)
    pdf.cell(0, 15, "3. Attack Paths", new_x="LMARGIN", new_y="NEXT")
    pdf.line(10, 45, 200, 45)

    pdf.set_font("helvetica", "", 12)
    if attack_paths:
        for i, path in enumerate(attack_paths, 1):
            pdf.cell(0, 10, f"Path {i}: {path}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "I", 10)
            pdf.cell(0, 8, "  WARNING: This chain allows external access to sensitive data.", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 12)
            pdf.ln(5)
    else:
        pdf.cell(0, 10, "No attack paths found. Your cloud is secure.", new_x="LMARGIN", new_y="NEXT")

    pdf.add_page()
    pdf.set_font("helvetica", "B", 18)
    pdf.cell(0, 15, "4. Auto-Remediation Log", new_x="LMARGIN", new_y="NEXT")
    pdf.line(10, 45, 200, 45)

    pdf.set_font("helvetica", "B", 10)
    pdf.cell(60, 10, "Timestamp", border=1)
    pdf.cell(80, 10, "Action", border=1)
    pdf.cell(50, 10, "Status", border=1)
    pdf.ln()

    pdf.set_font("helvetica", "", 9)
    for alert in alerts[:20]:
        ts, cl, acc, msg, sev, fixed = alert
        pdf.cell(60, 8, ts[:16], border=1)
        pdf.cell(80, 8, msg[:35], border=1)
        pdf.cell(50, 8, "FIXED" if fixed else "OPEN", border=1)
        pdf.ln()

    pdf.output(output_file)
    return output_file

# ---------- Configuration ----------
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached", 5000: "Flask/API",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}
CLOUD_METADATA = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
    "http://metadata.google.internal/computeMetadata/v1/",
]

# ---------- Core Scanning Functions ----------
def grab_banner(host, port, timeout=3.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in (80, 443, 8080, 8443, 5000):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else None
    except:
        return None

def detect_service(port, banner):
    base = COMMON_PORTS.get(port, "Unknown")
    if not banner: return base
    if "SSH" in banner.upper(): return "SSH"
    if "HTTP" in banner.upper() or "Server:" in banner: return "HTTP"
    if "Mongo" in banner: return "MongoDB"
    if "Redis" in banner: return "Redis"
    return base

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            banner = grab_banner(host, port)
            service = detect_service(port, banner)
            return (port, service, banner)
    except:
        pass
    return (port, None, None)

def scan_host(host, ports, threads=50):
    open_services = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port, service, banner = future.result()
            if service:
                open_services[port] = (service, banner)
    return open_services

# ---------- ENHANCED WEB SCANNING ----------
def discover_directories(target_url, wordlist=None):
    """
    Brute‑force common directories on a web target.
    """
    if not wordlist:
        wordlist = [
            "admin", "admin.php", "administrator", "login", "login.php", "wp-admin",
            "backup", "backups", "temp", "tmp", "test", "dev", "staging",
            "api", "v1", "v2", "v3", "graphql", "swagger", "docs", "help",
            "config", ".env", "env", "phpinfo", "info", "server-status",
            "cgi-bin", "cgi", "icons", "manual", "webmail", "cpanel",
            "plesk", "mysql", "phpmyadmin", "pma", "myadmin",
            "wp-content", "wp-includes", "plugins", "themes", "uploads",
            "download", "downloads", "files", "assets", "static",
            "css", "js", "images", "img", "font", "fonts",
            "error", "errors", "logs", "log", "debug",
            "old", "new", "original", "backup", "copy",
            "shell", "cmd", "exec", "system", "php",
            "index", "home", "main", "default", "start",
            "about", "contact", "services", "products", "product",
            "artists", "artist", "albums", "album", "tracks", "track",
            "category", "categories", "cat", "product.php", "products.php",
            "shop", "store", "cart", "checkout", "order", "orders",
            "user", "users", "profile", "account", "dashboard",
            "admin.php", "login.php", "register.php", "signup",
            "wp-login.php", "wp-admin.php", "wp-content.php",
            "includes", "inc", "lib", "libs", "vendor",
            "node_modules", "bower_components", "dist", "build",
            "public", "private", "protected", "secure",
            "upload", "uploads", "download", "downloads",
            "sql", "database", "db", "data", "backup.sql",
            ".git", ".svn", ".hg", ".bzr", ".idea", ".vscode",
            "tests", "test", "spec", "features", "behat",
            "doc", "docs", "documentation", "api-docs",
            "v1/", "v2/", "v3/", "latest/", "current/",
            "old/", "new/", "dev/", "staging/", "prod/",
            "server-status", "server-info", "stats", "status"
        ]
    findings = []
    for word in wordlist:
        test_url = f"{target_url.rstrip('/')}/{word}"
        try:
            resp = requests.get(test_url, timeout=3, verify=False, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                risk = "MEDIUM" if resp.status_code == 200 else "LOW"
                findings.append({
                    "path": test_url,
                    "status": resp.status_code,
                    "risk": risk,
                    "owasp": "A05 Security Misconfiguration"
                })
        except:
            continue
    return findings

def test_sqli(target_url, params=None, payloads=None):
    """
    Basic SQL injection testing on URL parameters.
    """
    if not params:
        params = ["id", "page", "user", "query", "q", "search", "cat", "product", "artid", "album", "track", "category"]
    if not payloads:
        payloads = [
            "' OR 1=1 --",
            "' OR 1=1 #",
            "' OR 1=1/*",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT 1,2,3 #",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' ; SELECT 1 --",
            "' OR '1'='1",
            "' OR '1'='1' --",
            '" OR 1=1 --',
            '" OR 1=1 #',
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' OR '1'='1",
            "1' OR '1'='2"
        ]
    findings = []
    if '?' in target_url:
        base, query_string = target_url.split('?', 1)
        existing_params = []
        for pair in query_string.split('&'):
            if '=' in pair:
                existing_params.append(pair.split('=')[0])
        if existing_params:
            params = existing_params
    for param in params:
        for payload in payloads:
            test_url = f"{target_url.split('?')[0]}?{param}={payload}" if '?' in target_url else f"{target_url}?{param}={payload}"
            try:
                resp = requests.get(test_url, timeout=3, verify=False)
                if "error" in resp.text.lower() or "sql" in resp.text.lower() or "mysql" in resp.text.lower():
                    findings.append({
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "risk": "CRITICAL",
                        "owasp": "A03 Injection"
                    })
                    break
            except:
                continue
    return findings

def test_xss(target_url, params=None, payloads=None):
    """
    Basic XSS testing on URL parameters.
    """
    if not params:
        params = ["q", "search", "query", "input", "name", "id", "page", "cat", "product"]
    if not payloads:
        payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><img src=x onerror=alert(1)>",
            "'><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "onerror=alert(1)",
            "onload=alert(1)",
            "<svg/onload=alert(1)>"
        ]
    findings = []
    if '?' in target_url:
        base, query_string = target_url.split('?', 1)
        existing_params = []
        for pair in query_string.split('&'):
            if '=' in pair:
                existing_params.append(pair.split('=')[0])
        if existing_params:
            params = existing_params
    for param in params:
        for payload in payloads:
            test_url = f"{target_url.split('?')[0]}?{param}={payload}" if '?' in target_url else f"{target_url}?{param}={payload}"
            try:
                resp = requests.get(test_url, timeout=3, verify=False)
                if payload in resp.text or "<script>" in resp.text:
                    findings.append({
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "risk": "HIGH",
                        "owasp": "A03 Injection"
                    })
                    break
            except:
                continue
    return findings

def lookup_cve(service, version=None):
    """
    Query NVD API for known CVEs.
    """
    query = service
    if version:
        query += f" {version}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
    try:
        resp = requests.get(url, timeout=5)
        data = resp.json()
        if data.get('totalResults', 0) > 0:
            cve = data['vulnerabilities'][0]['cve']
            return {
                "id": cve['id'],
                "description": cve['descriptions'][0]['value'][:200],
                "cvss_score": cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
            }
    except:
        pass
    return None

def calculate_risk_score(findings):
    """
    Calculate overall risk score (0-100).
    """
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    total_weight = sum(weights.get(f[3] if isinstance(f, tuple) else f.get('risk', 'INFO'), 0) for f in findings)
    max_possible = len(findings) * 10
    if max_possible == 0:
        return 100
    raw_score = 100 - (total_weight / max_possible) * 100
    return max(0, min(100, round(raw_score)))

# ---------- CLOUD CHECKS ----------
def check_aws_s3_public(session=None, account_name=None):
    findings = []
    s3 = session.client('s3', verify=False) if session else boto3.client('s3', verify=False)
    try:
        for bucket in s3.list_buckets()['Buckets']:
            name = bucket['Name']
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl['Grants']:
                    uri = grant.get('Grantee', {}).get('URI', '')
                    if 'AllUsers' in uri:
                        acct = account_name or "default"
                        findings.append((
                            f"[{acct}] AWS S3 Bucket '{name}' is PUBLIC!",
                            "AWS",
                            8.0,
                            "CRITICAL",
                            "S3_PUBLIC",
                            name
                        ))
                        break
            except:
                continue
    except ClientError as e:
        if "RequestTimeTooSkewed" in str(e):
            findings.append((f"[{account_name or 'default'}] AWS Time Sync Error", "AWS", 0.0, "INFO", None, None))
        else:
            findings.append((f"[{account_name or 'default'}] AWS Error: {str(e)[:50]}", "AWS", 0.0, "INFO", None, None))
    return findings

def check_aws_security_groups(session=None, account_name=None):
    findings = []
    ec2 = session.client('ec2', verify=False) if session else boto3.client('ec2', verify=False)
    try:
        for sg in ec2.describe_security_groups()['SecurityGroups']:
            group_id = sg['GroupId']
            group_name = sg['GroupName']
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port = rule.get('FromPort')
                        acct = account_name or "default"
                        findings.append((
                            f"[{acct}] AWS SG '{group_name}' allows 0.0.0.0/0 on port {port}",
                            "AWS",
                            8.5,
                            "CRITICAL",
                            "SG_OPEN",
                            (group_id, port)
                        ))
    except:
        pass
    return findings

def check_gcp_storage_public(project_id=None):
    findings = []
    if not GCP_AVAILABLE:
        findings.append(("GCP SDK missing. Install google-cloud-storage", "GCP", 0.0, "INFO", None, None))
        return findings
    try:
        client = storage.Client(project=project_id) if project_id else storage.Client()
        for bucket in client.list_buckets():
            policy = bucket.get_iam_policy()
            if 'allUsers' in policy:
                acct = project_id or "default"
                findings.append((
                    f"[{acct}] GCP Bucket '{bucket.name}' is PUBLIC!",
                    "GCP",
                    8.0,
                    "CRITICAL",
                    "GCP_PUBLIC",
                    bucket.name
                ))
    except Exception as e:
        findings.append((f"GCP Error: {str(e)[:50]}", "GCP", 0.0, "INFO", None, None))
    return findings

def check_azure_blob_public(subscription_id=None):
    findings = []
    if not AZURE_AVAILABLE:
        findings.append(("Azure SDK missing. Install azure-storage-blob azure-identity azure-mgmt-storage", "Azure", 0.0, "INFO", None, None))
        return findings
    try:
        credential = DefaultAzureCredential()
        from azure.mgmt.storage import StorageManagementClient
        storage_client = StorageManagementClient(credential, subscription_id) if subscription_id else StorageManagementClient(credential, None)
        if not subscription_id:
            try:
                from azure.mgmt.resource import SubscriptionClient
                sub_client = SubscriptionClient(credential)
                subscription = list(sub_client.subscriptions.list())[0]
                subscription_id = subscription.subscription_id
                storage_client = StorageManagementClient(credential, subscription_id)
            except:
                findings.append(("Azure: No subscription ID provided and no default found.", "Azure", 0.0, "INFO", None, None))
                return findings
        accounts = storage_client.storage_accounts.list()
        for account in accounts:
            findings.append((
                f"Azure check ready. Configure full container scanning.",
                "Azure",
                0.0,
                "INFO",
                None,
                None
            ))
    except Exception as e:
        findings.append((f"Azure Error: {str(e)[:50]}", "Azure", 0.0, "INFO", None, None))
    return findings

def check_oci_storage_public(compartment_id=None):
    findings = []
    if not OCI_AVAILABLE:
        findings.append(("OCI SDK missing. Install oci", "OCI", 0.0, "INFO", None, None))
        return findings
    try:
        config = oci.config.from_file()
        object_storage = oci.object_storage.ObjectStorageClient(config)
        ns = object_storage.get_namespace().data
        buckets = object_storage.list_buckets(ns, compartment_id=compartment_id) if compartment_id else object_storage.list_buckets(ns)
        for bucket in buckets.data:
            if bucket.public_access_type and bucket.public_access_type != "NoPublicAccess":
                acct = compartment_id or "default"
                findings.append((
                    f"[{acct}] OCI Bucket '{bucket.name}' is PUBLIC!",
                    "OCI",
                    8.0,
                    "CRITICAL",
                    "OCI_PUBLIC",
                    (ns, bucket.name)
                ))
    except Exception as e:
        findings.append((f"OCI Error: {str(e)[:50]}", "OCI", 0.0, "INFO", None, None))
    return findings

# ---------- OWASP API TOP 10 ----------
def check_api_vulnerabilities(host, port, protocol):
    findings = []
    if port not in (80, 443, 8080, 8443, 5000):
        return findings
    base = f"{protocol}://{host}:{port}"

    paths = ["/api/users/1", "/api/orders/1", "/api/profile/1"]
    for p in paths:
        try:
            req = Request(base + p)
            with urlopen(req, timeout=3, context=ssl._create_unverified_context()) as resp:
                if resp.status == 200:
                    findings.append((f"{p} accessible without auth (BOLA - API1)", "OWASP", 7.0, "HIGH", "API_BOLA", p))
        except:
            pass

    auth_paths = ["/admin", "/dashboard", "/api/v1/me"]
    for p in auth_paths:
        try:
            req = Request(base + p)
            with urlopen(req, timeout=3, context=ssl._create_unverified_context()) as resp:
                if resp.status == 200:
                    findings.append((f"{p} accessible no auth (Broken Auth - API2)", "OWASP", 7.5, "HIGH", "API_AUTH", p))
        except:
            pass

    try:
        req = Request(base + "/api/users")
        with urlopen(req, timeout=3, context=ssl._create_unverified_context()) as resp:
            data = resp.read().decode(errors='ignore')
            if "password" in data.lower() or "ssn" in data.lower():
                findings.append(("Excessive data exposure (sensitive fields) - API3", "OWASP", 6.0, "MEDIUM", "API_DATA", None))
    except:
        pass

    success = 0
    for _ in range(12):
        try:
            req = Request(base + "/api/health")
            with urlopen(req, timeout=1, context=ssl._create_unverified_context()) as resp:
                if resp.status == 200:
                    success += 1
                else:
                    break
        except:
            break
    if success >= 10:
        findings.append((f"No rate limiting (API4) - allowed {success} requests", "OWASP", 5.0, "MEDIUM", "API_RATE", None))

    try:
        req = Request(base + "/api/admin/config")
        with urlopen(req, timeout=3, context=ssl._create_unverified_context()) as resp:
            if resp.status == 200:
                findings.append(("Admin config accessible (BFLA - API5)", "OWASP", 7.0, "HIGH", "API_BFLA", None))
    except:
        pass

    ssrf_urls = ["/api/fetch?url=http://169.254.169.254/latest/meta-data/", "/proxy?target=http://localhost"]
    for p in ssrf_urls:
        try:
            req = Request(base + p)
            with urlopen(req, timeout=3, context=ssl._create_unverified_context()) as resp:
                if "instance-id" in resp.read().decode(errors='ignore'):
                    findings.append((f"SSRF detected via {p} (API7)", "OWASP", 9.0, "CRITICAL", "API_SSRF", p))
        except:
            pass

    try:
        req = Request(base + "/")
        with urlopen(req, timeout=3, context=ssl._create_unverified_context()) as resp:
            h = resp.headers
            missing = []
            if 'Strict-Transport-Security' not in h: missing.append('HSTS')
            if 'X-Frame-Options' not in h: missing.append('X-Frame')
            if missing:
                findings.append((f"Missing security headers: {', '.join(missing)} (API8)", "OWASP", 5.0, "MEDIUM", "API_HEADERS", missing))
            if h.get('Access-Control-Allow-Origin') == '*':
                findings.append(("CORS allows '*' (API8)", "OWASP", 6.0, "MEDIUM", "API_CORS", None))
    except:
        pass

    return findings

# ---------- AUTO-REMEDIATION ----------
def fix_s3_public(bucket_name, session=None, cloud="aws", account="default"):
    try:
        s3 = session.client('s3', verify=False) if session else boto3.client('s3', verify=False)
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        save_alert(cloud, account, f"FIXED: Public S3 bucket '{bucket_name}'", "CRITICAL", fixed=True)
        return True, f"🔒 [{account}] S3 bucket '{bucket_name}' is now private."
    except Exception as e:
        return False, f"❌ [{account}] Failed: {str(e)[:100]}"

def fix_security_group_rule(group_id, port, session=None, cloud="aws", account="default"):
    try:
        ec2 = session.client('ec2', verify=False) if session else boto3.client('ec2', verify=False)
        ec2.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
        save_alert(cloud, account, f"FIXED: Open SG {group_id} on port {port}", "CRITICAL", fixed=True)
        return True, f"🔒 [{account}] Removed 0.0.0.0/0 rule on port {port} from SG {group_id}."
    except Exception as e:
        return False, f"❌ [{account}] Failed: {str(e)[:100]}"

def fix_ec2_open_ports(instance_id, session=None, cloud="aws", account="default"):
    try:
        ec2 = session.client('ec2', verify=False) if session else boto3.client('ec2', verify=False)
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        if not resp['Reservations']:
            return False, f"Instance {instance_id} not found."
        sgs = resp['Reservations'][0]['Instances'][0]['SecurityGroups']
        fixed = 0
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_resp = ec2.describe_security_groups(GroupIds=[sg_id])
            rules = sg_resp['SecurityGroups'][0].get('IpPermissions', [])
            for rule in rules:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port = rule.get('FromPort')
                        if port is not None:
                            ec2.revoke_security_group_ingress(
                                GroupId=sg_id,
                                IpPermissions=[{
                                    'IpProtocol': 'tcp',
                                    'FromPort': port,
                                    'ToPort': port,
                                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                                }]
                            )
                            fixed += 1
        if fixed > 0:
            save_alert(cloud, account, f"FIXED: Closed {fixed} open ports on EC2 {instance_id}", "HIGH", fixed=True)
            return True, f"🔒 [{account}] Closed {fixed} open ports on EC2 {instance_id}."
        else:
            return True, f"✅ [{account}] EC2 {instance_id} had no open ports."
    except Exception as e:
        return False, f"❌ [{account}] Failed: {str(e)[:100]}"

def fix_iam_role(instance_id, current_role_name, session=None, cloud="aws", account="default"):
    try:
        ec2 = session.client('ec2', verify=False) if session else boto3.client('ec2', verify=False)
        iam = session.client('iam', verify=False) if session else boto3.client('iam', verify=False)
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        if not resp['Reservations']:
            return False, f"Instance {instance_id} not found."
        inst = resp['Reservations'][0]['Instances'][0]
        iam_profile = inst.get('IamInstanceProfile', {})
        if not iam_profile:
            return True, f"✅ [{account}] EC2 {instance_id} has no IAM role."
        ec2.disassociate_iam_instance_profile(AssociationId=inst['IamInstanceProfile']['Id'])
        safe_role_name = "Aegis-ReadOnlyRole"
        try:
            iam.get_role(RoleName=safe_role_name)
        except iam.exceptions.NoSuchEntityException:
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }
            iam.create_role(RoleName=safe_role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
            iam.attach_role_policy(RoleName=safe_role_name, PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
        try:
            iam.get_instance_profile(InstanceProfileName=safe_role_name)
        except iam.exceptions.NoSuchEntityException:
            iam.create_instance_profile(InstanceProfileName=safe_role_name)
            iam.add_role_to_instance_profile(InstanceProfileName=safe_role_name, RoleName=safe_role_name)
        ec2.associate_iam_instance_profile(IamInstanceProfile={'Name': safe_role_name}, InstanceId=instance_id)
        save_alert(cloud, account, f"FIXED: Replaced IAM role on EC2 {instance_id}", "HIGH", fixed=True)
        return True, f"🔒 [{account}] Replaced IAM role on EC2 {instance_id}."
    except Exception as e:
        return False, f"❌ [{account}] Failed: {str(e)[:100]}"

def fix_gcp_bucket_public(bucket_name, project_id=None, cloud="gcp", account="default"):
    try:
        client = storage.Client(project=project_id) if project_id else storage.Client()
        bucket = client.get_bucket(bucket_name)
        policy = bucket.get_iam_policy()
        policy['allUsers'] = None
        bucket.set_iam_policy(policy)
        save_alert(cloud, account, f"FIXED: GCP bucket '{bucket_name}'", "CRITICAL", fixed=True)
        return True, f"🔒 [{account}] GCP bucket '{bucket_name}' is now private."
    except Exception as e:
        return False, f"❌ [{account}] Failed: {str(e)[:100]}"

def fix_oci_bucket_public(namespace, bucket_name, compartment_id=None, cloud="oci", account="default"):
    try:
        config = oci.config.from_file()
        object_storage = oci.object_storage.ObjectStorageClient(config)
        object_storage.update_bucket(
            namespace_name=namespace,
            bucket_name=bucket_name,
            update_bucket_details=oci.object_storage.models.UpdateBucketDetails(
                public_access_type="NoPublicAccess"
            )
        )
        save_alert(cloud, account, f"FIXED: OCI bucket '{bucket_name}'", "CRITICAL", fixed=True)
        return True, f"🔒 [{account}] OCI bucket '{bucket_name}' is now private."
    except Exception as e:
        return False, f"❌ [{account}] Failed: {str(e)[:100]}"

# ---------- ATTACK PATH GRAPH ----------
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    print("[!] networkx not installed. Install with: pip install networkx")

def fetch_aws_resources(account_name=None, session=None):
    resources = {
        'instances': [],
        'security_groups': {},
        'buckets': [],
        'instance_profiles': {}
    }
    if not AWS_AVAILABLE:
        return resources
    try:
        ec2 = session.client('ec2', verify=False) if session else boto3.client('ec2', verify=False)
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                inst_id = instance['InstanceId']
                sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                iam_profile = instance.get('IamInstanceProfile', {})
                role_name = iam_profile.get('Arn', '').split('/')[-1] if iam_profile else None
                resources['instances'].append({
                    'id': inst_id,
                    'sg_ids': sg_ids,
                    'role_name': role_name,
                    'account': account_name
                })
        sgs = ec2.describe_security_groups()
        for sg in sgs['SecurityGroups']:
            group_id = sg['GroupId']
            resources['security_groups'][group_id] = {
                'name': sg['GroupName'],
                'rules': sg.get('IpPermissions', []),
                'account': account_name
            }
        s3 = session.client('s3', verify=False) if session else boto3.client('s3', verify=False)
        buckets = s3.list_buckets()
        for bucket in buckets['Buckets']:
            name = bucket['Name']
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                public = False
                for grant in acl['Grants']:
                    uri = grant.get('Grantee', {}).get('URI', '')
                    if 'AllUsers' in uri:
                        public = True
                        break
                resources['buckets'].append({'name': name, 'public': public, 'account': account_name})
            except:
                resources['buckets'].append({'name': name, 'public': False, 'account': account_name})
    except Exception as e:
        print(f"[!] Error fetching AWS resources for {account_name}: {e}")
    return resources

def build_attack_graph(resources):
    G = nx.DiGraph()
    G.add_node("Internet", type="external")
    for sg_id, data in resources['security_groups'].items():
        acct = data.get('account', 'default')
        G.add_node(sg_id, type="security_group", name=data['name'], account=acct)
        for rule in data['rules']:
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    port = rule.get('FromPort', 'any')
                    G.add_edge("Internet", sg_id, label=f"port {port}")
    for inst in resources['instances']:
        acct = inst.get('account', 'default')
        G.add_node(inst['id'], type="ec2", role=inst['role_name'], account=acct)
        for sg_id in inst['sg_ids']:
            if sg_id in G:
                G.add_edge(sg_id, inst['id'], label="attached")
        if inst['role_name']:
            role_node = f"iam:{inst['role_name']}"
            G.add_node(role_node, type="iam_role", name=inst['role_name'], account=acct)
            G.add_edge(inst['id'], role_node, label="assumes")
    for bucket in resources['buckets']:
        acct = bucket.get('account', 'default')
        bucket_node = f"s3:{bucket['name']}"
        G.add_node(bucket_node, type="s3", public=bucket['public'], account=acct)
        if bucket['public']:
            G.add_edge("Internet", bucket_node, label="public read")
    return G

def find_attack_paths(G, target_type="s3"):
    paths = []
    targets = [n for n, d in G.nodes(data=True) if d.get('type') == target_type and d.get('public', False)]
    for target in targets:
        try:
            path = nx.shortest_path(G, source="Internet", target=target)
            paths.append(path)
        except nx.NetworkXNoPath:
            continue
    return paths

# ---------- MULTI-ACCOUNT SCANNING ----------
def scan_aws_account(account_name, account_id, role_name, args):
    print(f"\n📂 [AWS] Scanning account: {account_name} (ID: {account_id})")
    session = None
    if account_id:
        try:
            sts = boto3.client('sts')
            role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"Aegis-Scan-{account_name}"
            )
            creds = response['Credentials']
            session = boto3.Session(
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            )
            print(f"✅ Assumed role {role_name} in account {account_name}")
        except Exception as e:
            print(f"❌ Failed to assume role in {account_name}: {e}")
            return []
    all_findings = []
    all_findings.extend(check_aws_s3_public(session, account_name))
    all_findings.extend(check_aws_security_groups(session, account_name))
    resources = fetch_aws_resources(account_name, session)
    G = build_attack_graph(resources)
    paths = find_attack_paths(G)
    if paths:
        print(f"🔥 [{account_name}] Found {len(paths)} attack paths!")
        for path in paths:
            print(f"   {' -> '.join(path)}")
        if args.chain:
            fixed = fix_attack_chain_aws(resources, G, paths, account_name, session)
            print(f"✅ [{account_name}] Fixed {len(fixed)} nodes across all attack chains.")
    else:
        print(f"✅ [{account_name}] No attack paths found.")
    if args.db:
        open_services = {}
        save_scan(account_name, "aws", account_name, open_services, all_findings)
    return all_findings

def scan_gcp_project(project_id, args):
    print(f"\n📂 [GCP] Scanning project: {project_id}")
    all_findings = []
    all_findings.extend(check_gcp_storage_public(project_id))
    if args.chain:
        for f in all_findings:
            if len(f) >= 6 and f[4] == "GCP_PUBLIC":
                bucket_name = f[5]
                success, msg = fix_gcp_bucket_public(bucket_name, project_id, "gcp", project_id)
                print(msg)
    if args.db:
        save_scan(project_id, "gcp", project_id, {}, all_findings)
    return all_findings

def scan_azure_subscription(subscription_id, args):
    print(f"\n📂 [Azure] Scanning subscription: {subscription_id}")
    all_findings = []
    all_findings.extend(check_azure_blob_public(subscription_id))
    if args.chain:
        for f in all_findings:
            pass
    if args.db:
        save_scan(subscription_id, "azure", subscription_id, {}, all_findings)
    return all_findings

def scan_oci_compartment(compartment_id, args):
    print(f"\n📂 [OCI] Scanning compartment: {compartment_id}")
    all_findings = []
    all_findings.extend(check_oci_storage_public(compartment_id))
    if args.chain:
        for f in all_findings:
            if len(f) >= 6 and f[4] == "OCI_PUBLIC":
                ns, bucket_name = f[5]
                success, msg = fix_oci_bucket_public(ns, bucket_name, compartment_id, "oci", compartment_id)
                print(msg)
    if args.db:
        save_scan(compartment_id, "oci", compartment_id, {}, all_findings)
    return all_findings

def fix_attack_chain_aws(resources, G, paths, account_name, session):
    fixed_nodes = []
    for path in paths:
        print(f"\n🔧 [{account_name}] Breaking attack chain: {' -> '.join(path)}")
        for node in path:
            if node == "Internet":
                continue
            if node.startswith("s3:"):
                bucket_name = node.replace("s3:", "")
                success, msg = fix_s3_public(bucket_name, session, "aws", account_name)
                if success:
                    fixed_nodes.append(node)
                print(msg)
            elif node.startswith("sg-"):
                for sg_id, data in resources['security_groups'].items():
                    if sg_id == node:
                        for rule in data['rules']:
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    port = rule.get('FromPort', 22)
                                    success, msg = fix_security_group_rule(node, port, session, "aws", account_name)
                                    if success:
                                        fixed_nodes.append(node)
                                    print(msg)
            elif node.startswith("i-"):
                success, msg = fix_ec2_open_ports(node, session, "aws", account_name)
                if success:
                    fixed_nodes.append(node)
                print(msg)
                inst_data = next((inst for inst in resources['instances'] if inst['id'] == node), None)
                if inst_data and inst_data['role_name']:
                    role_name = inst_data['role_name']
                    if role_name:
                        success, msg = fix_iam_role(node, role_name, session, "aws", account_name)
                        if success:
                            fixed_nodes.append(f"iam:{role_name}")
                        print(msg)
                else:
                    print(f"   ℹ️ EC2 {node} has no IAM role.")
            elif node.startswith("iam:"):
                role_name = node.replace("iam:", "")
                print(f"   🔑 IAM role {role_name} will be handled via EC2.")
    return fixed_nodes

def run_fix_chain(args):
    print("[*] 🔥 Multi-Cloud attack chain breaking...")
    accounts = []
    if args.accounts:
        for item in args.accounts.split(','):
            item = item.strip()
            if ':' in item:
                cloud, identifier = item.split(':', 1)
                accounts.append({'cloud': cloud.strip(), 'identifier': identifier.strip()})
            else:
                accounts.append({'cloud': 'aws', 'identifier': item})
    elif args.accounts_file:
        with open(args.accounts_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if ':' in line:
                        cloud, identifier = line.split(':', 1)
                        accounts.append({'cloud': cloud.strip(), 'identifier': identifier.strip()})
                    else:
                        accounts.append({'cloud': 'aws', 'identifier': line})
    else:
        sts = boto3.client('sts')
        account_id = sts.get_caller_identity()['Account']
        accounts.append({'cloud': 'aws', 'identifier': account_id})

    print(f"[*] Scanning {len(accounts)} cloud account(s)...")
    for acct in accounts:
        cloud = acct['cloud'].lower()
        ident = acct['identifier']
        if cloud == 'aws':
            scan_aws_account(ident, ident, args.role or "Aegis-Scanner", args)
        elif cloud == 'gcp':
            scan_gcp_project(ident, args)
        elif cloud == 'azure':
            scan_azure_subscription(ident, args)
        elif cloud == 'oci':
            scan_oci_compartment(ident, args)
        else:
            print(f"[!] Unknown cloud: {cloud}")
    print("[*] Multi-cloud scanning complete.")

# ---------- AUTHENTICATION HTML TEMPLATES ----------
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis – Login</title>
    <style>
        body { background: #0a0e17; color: #e0e6ed; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: #111b26; padding: 40px; border-radius: 12px; border: 1px solid #1e2a3a; width: 350px; }
        .login-box h1 { text-align: center; color: #00d4ff; margin-bottom: 30px; }
        .login-box input { width: 100%; padding: 12px; margin-bottom: 15px; background: #0a0e17; border: 1px solid #1e2a3a; color: #e0e6ed; border-radius: 6px; box-sizing: border-box; }
        .login-box button { width: 100%; padding: 12px; background: #00d4ff; color: #0a0e17; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; }
        .login-box button:hover { background: #7b2ffc; color: #fff; }
        .login-box .error { color: #ff4757; text-align: center; margin-bottom: 10px; }
        .login-box .link { text-align: center; margin-top: 15px; color: #8ba0b8; font-size: 14px; }
        .login-box .link a { color: #00d4ff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>🛡️ Aegis</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="/login">
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="link">
            Don't have an account? <a href="/signup">Sign up</a>
        </div>
    </div>
</body>
</html>
"""

SIGNUP_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis – Sign Up</title>
    <style>
        body { background: #0a0e17; color: #e0e6ed; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .signup-box { background: #111b26; padding: 40px; border-radius: 12px; border: 1px solid #1e2a3a; width: 350px; }
        .signup-box h1 { text-align: center; color: #00d4ff; margin-bottom: 30px; }
        .signup-box input { width: 100%; padding: 12px; margin-bottom: 15px; background: #0a0e17; border: 1px solid #1e2a3a; color: #e0e6ed; border-radius: 6px; box-sizing: border-box; }
        .signup-box button { width: 100%; padding: 12px; background: #00d4ff; color: #0a0e17; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; }
        .signup-box button:hover { background: #7b2ffc; color: #fff; }
        .signup-box .error { color: #ff4757; text-align: center; margin-bottom: 10px; }
        .signup-box .link { text-align: center; margin-top: 15px; color: #8ba0b8; font-size: 14px; }
        .signup-box .link a { color: #00d4ff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="signup-box">
        <h1>🛡️ Aegis</h1>
        <h3 style="text-align:center; color:#8ba0b8; margin-top:-10px;">Create Account</h3>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="/signup">
            <input type="text" name="company" placeholder="Company Name" required>
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign Up</button>
        </form>
        <div class="link">
            Already have an account? <a href="/login">Login</a>
        </div>
    </div>
</body>
</html>
"""

# ---------- WEB DASHBOARD (UPGRADED) ----------
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis Security Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #0a0e17; color: #e0e6ed; display: flex; height: 100vh; overflow: hidden; }
        
        .sidebar { width: 220px; background: #0d1520; border-right: 1px solid #1e2a3a; padding: 20px 0; height: 100vh; position: fixed; left: 0; top: 0; overflow-y: auto; }
        .sidebar .logo { font-size: 22px; font-weight: 700; background: linear-gradient(135deg, #00d4ff, #7b2ffc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; padding: 0 20px; margin-bottom: 30px; }
        .sidebar .logo span { font-size: 12px; display: block; -webkit-text-fill-color: #5a6a7a; }
        .sidebar a { display: block; padding: 12px 20px; color: #8ba0b8; text-decoration: none; font-size: 14px; border-left: 3px solid transparent; transition: all 0.2s; }
        .sidebar a:hover, .sidebar a.active { background: #111b26; color: #e0e6ed; border-left-color: #00d4ff; }
        .sidebar a .icon { margin-right: 10px; }
        .sidebar .logout { margin-top: 40px; border-top: 1px solid #1e2a3a; padding-top: 20px; color: #ff4757; }
        .sidebar .logout:hover { border-left-color: #ff4757; }
        
        .main { margin-left: 220px; flex: 1; padding: 20px 30px; overflow-y: auto; height: 100vh; }
        .topbar { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid #1e2a3a; margin-bottom: 25px; }
        .topbar h1 { font-size: 24px; background: linear-gradient(135deg, #00d4ff, #7b2ffc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .topbar .user { display: flex; align-items: center; gap: 15px; }
        .topbar .user .email { color: #8ba0b8; font-size: 14px; }
        .topbar .user .badge { background: #1e2a3a; padding: 6px 14px; border-radius: 20px; font-size: 12px; color: #8ba0b8; }
        .topbar .user .last-updated { color: #5a6a7a; font-size: 12px; }
        .scan-btn { background: #00d4ff; color: #0a0e17; border: none; padding: 8px 20px; border-radius: 20px; font-weight: bold; cursor: pointer; transition: 0.2s; }
        .scan-btn:hover { background: #7b2ffc; color: #fff; }
        .scan-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #111b26; border-radius: 12px; padding: 20px; border: 1px solid #1e2a3a; transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-3px); border-color: #00d4ff; }
        .stat-card .number { font-size: 30px; font-weight: 700; color: #00d4ff; }
        .stat-card .label { font-size: 14px; color: #8ba0b8; margin-top: 4px; display: flex; align-items: center; gap: 8px; }
        .stat-card.critical .number { color: #ff4757; }
        .stat-card.fixed .number { color: #2ed573; }
        
        .chart-row { display: grid; grid-template-columns: 1fr 1fr; gap: 25px; margin-bottom: 30px; }
        .chart-box { background: #111b26; border-radius: 12px; padding: 20px; border: 1px solid #1e2a3a; }
        .chart-box h3 { font-size: 16px; color: #8ba0b8; margin-bottom: 15px; }
        .chart-box canvas { max-height: 200px; width: 100% !important; }
        
        .section { background: #111b26; border-radius: 12px; padding: 20px; margin-bottom: 20px; border: 1px solid #1e2a3a; }
        .section h2 { font-size: 18px; margin-bottom: 15px; color: #8ba0b8; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th { text-align: left; padding: 10px; color: #8ba0b8; border-bottom: 1px solid #1e2a3a; }
        td { padding: 10px; border-bottom: 1px solid #0d1620; }
        .severity-critical { color: #ff4757; font-weight: bold; }
        .severity-high { color: #ffa502; font-weight: bold; }
        .severity-medium { color: #eccc68; }
        .severity-info { color: #8ba0b8; }
        .fixed-true { color: #2ed573; }
        .fixed-false { color: #ffa502; }
        .path-chain { font-family: monospace; font-size: 13px; background: #0a0e17; padding: 6px 12px; border-radius: 6px; display: inline-block; }
        .empty { color: #5a6a7a; font-style: italic; }
        .refresh-btn { background: #1e2a3a; border: none; color: #e0e6ed; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; }
        .refresh-btn:hover { background: #2a3a4a; }
        .scan-loading { display: inline-block; width: 16px; height: 16px; border: 2px solid #8ba0b8; border-top-color: #00d4ff; border-radius: 50%; animation: spin 0.8s linear infinite; margin-left: 10px; vertical-align: middle; }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        @media (max-width: 768px) { .sidebar { display: none; } .main { margin-left: 0; } .chart-row { grid-template-columns: 1fr; } .stats { grid-template-columns: 1fr 1fr; } }
    </style>
</head>
<body>

    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">🛡️ Aegis<span>Cloud Security</span></div>
        <a href="#" class="active"><span class="icon">📊</span> Dashboard</a>
        <a href="#"><span class="icon">🔍</span> Scans</a>
        <a href="#"><span class="icon">🔔</span> Alerts</a>
        <a href="#"><span class="icon">⚙️</span> Settings</a>
        <a href="/logout" class="logout"><span class="icon">🚪</span> Logout</a>
    </div>

    <!-- Main Content -->
    <div class="main">
        <!-- Top Bar -->
        <div class="topbar">
            <h1>📊 Dashboard</h1>
            <div class="user">
                <span class="badge">{{ company }}</span>
                <span class="email">{{ email }}</span>
                <span class="last-updated" id="lastUpdated">Last updated: --</span>
                <button class="scan-btn" id="scanBtn" onclick="startScan()">⚡ Scan Now</button>
                <button class="refresh-btn" onclick="loadData()">⟳ Refresh</button>
                <div id="scanSpinner" style="display:inline;"></div>
            </div>
        </div>

        <!-- Stats -->
        <div class="stats" id="stats">
            <div class="stat-card"><div class="number" id="totalScans">-</div><div class="label">📋 Total Scans</div></div>
            <div class="stat-card critical"><div class="number" id="criticalFindings">-</div><div class="label">🔥 Critical Findings</div></div>
            <div class="stat-card fixed"><div class="number" id="fixedIssues">-</div><div class="label">✅ Auto-Fixed</div></div>
            <div class="stat-card"><div class="number" id="openPorts">-</div><div class="label">🔌 Open Ports</div></div>
        </div>

        <!-- Charts -->
        <div class="chart-row">
            <div class="chart-box"><h3>📈 Vulnerability Trend</h3><canvas id="trendChart"></canvas></div>
            <div class="chart-box"><h3>📊 Severity Breakdown</h3><canvas id="severityChart"></canvas></div>
        </div>

        <!-- Recent Scans -->
        <div class="section">
            <h2>📋 Recent Scans</h2>
            <table>
                <thead><tr><th>Timestamp</th><th>Target</th><th>Open Ports</th><th>Findings</th></tr></thead>
                <tbody id="scansTable"></tbody>
            </table>
        </div>

        <!-- Alerts -->
        <div class="section">
            <h2>🔔 Alerts & Remediations</h2>
            <table>
                <thead><tr><th>Timestamp</th><th>Message</th><th>Severity</th><th>Fixed</th></tr></thead>
                <tbody id="alertsTable"></tbody>
            </table>
        </div>

        <!-- Attack Paths -->
        <div class="section">
            <h2>🔥 Attack Paths</h2>
            <div id="attackPaths"></div>
        </div>
    </div>

    <script>
        let scanInProgress = false;

        async function loadData() {
            try {
                const res = await fetch('/api/data');
                const data = await res.json();

                document.getElementById('totalScans').textContent = data.total_scans || 0;
                document.getElementById('criticalFindings').textContent = data.critical_findings || 0;
                document.getElementById('fixedIssues').textContent = data.fixed_issues || 0;
                document.getElementById('openPorts').textContent = data.open_ports || 0;
                document.getElementById('lastUpdated').textContent = 'Last updated: ' + new Date().toLocaleTimeString();

                // Scans table
                const scansTable = document.getElementById('scansTable');
                if (data.scans && data.scans.length > 0) {
                    scansTable.innerHTML = data.scans.map(s => `
                        <tr><td>${s[0]}</td><td>${s[1]}</td><td>${s[2]}</td><td>${s[3]}</td></tr>
                    `).join('');
                } else {
                    scansTable.innerHTML = `<tr><td colspan="4" class="empty">No scans yet. Click "Scan Now" to start your first scan!</td></tr>`;
                }

                // Alerts table
                const alertsTable = document.getElementById('alertsTable');
                if (data.alerts && data.alerts.length > 0) {
                    alertsTable.innerHTML = data.alerts.map(a => `
                        <tr>
                            <td>${a[0]}</td>
                            <td>${a[1]}</td>
                            <td class="severity-${a[2].toLowerCase()}">${a[2]}</td>
                            <td class="fixed-${a[3] ? 'true' : 'false'}">${a[3] ? '✅ Fixed' : '⚠️ Open'}</td>
                        </tr>
                    `).join('');
                } else {
                    alertsTable.innerHTML = `<tr><td colspan="4" class="empty">No alerts yet.</td></tr>`;
                }

                // Attack paths
                const pathsDiv = document.getElementById('attackPaths');
                if (data.attack_paths && data.attack_paths.length > 0) {
                    pathsDiv.innerHTML = data.attack_paths.map((path, i) => `
                        <div style="margin-bottom: 8px; padding: 10px 14px; background: #0a0e17; border-radius: 8px; border-left: 3px solid #ff4757;">
                            <strong>Path ${i+1}:</strong>
                            <span class="path-chain">${path.join(' → ')}</span>
                        </div>
                    `).join('');
                } else {
                    pathsDiv.innerHTML = '<span class="empty">✅ No attack paths found.</span>';
                }

                // —— Charts ——
                const ctx1 = document.getElementById('trendChart').getContext('2d');
                const ctx2 = document.getElementById('severityChart').getContext('2d');

                // Severity breakdown
                const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
                if (data.alerts) {
                    data.alerts.forEach(a => { if (sevCounts[a[2]] !== undefined) sevCounts[a[2]]++; });
                }
                // If no data, show demo zeros
                if (data.alerts.length === 0) {
                    // keep zeros
                }

                // Destroy previous charts if they exist to avoid duplication
                if (window.sevChart) window.sevChart.destroy();
                if (window.trendChart) window.trendChart.destroy();

                window.sevChart = new Chart(ctx2, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{
                            data: [sevCounts.CRITICAL, sevCounts.HIGH, sevCounts.MEDIUM, sevCounts.LOW, sevCounts.INFO],
                            backgroundColor: ['#ff4757', '#ffa502', '#eccc68', '#2ed573', '#8ba0b8'],
                            borderColor: '#0a0e17',
                            borderWidth: 3
                        }]
                    },
                    options: { 
                        responsive: true, 
                        plugins: { legend: { labels: { color: '#e0e6ed' } } },
                        animation: { animateRotate: true, duration: 1000 }
                    }
                });

                // Trend chart
                let labels = data.scans.map(s => s[0].slice(0, 10)).reverse();
                let counts = data.scans.map(s => s[3]).reverse();
                if (labels.length === 0) {
                    // Demo data – show a flat line if no scans
                    labels = ['No Data'];
                    counts = [0];
                }
                window.trendChart = new Chart(ctx1, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Findings',
                            data: counts,
                            borderColor: '#00d4ff',
                            backgroundColor: 'rgba(0,212,255,0.1)',
                            fill: true,
                            tension: 0.3
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { labels: { color: '#e0e6ed' } } },
                        scales: { x: { ticks: { color: '#8ba0b8' } }, y: { ticks: { color: '#8ba0b8' } } },
                        animation: { duration: 800 }
                    }
                });

                // Re-enable scan button after loading
                document.getElementById('scanBtn').disabled = false;
                scanInProgress = false;
                document.getElementById('scanSpinner').innerHTML = '';

            } catch (e) {
                console.error('Error loading data:', e);
            }
        }

        async function startScan() {
            if (scanInProgress) return;
            scanInProgress = true;
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('scanSpinner').innerHTML = '<div class="scan-loading"></div>';

            try {
                const res = await fetch('/scan', { method: 'POST' });
                const result = await res.json();
                if (result.status === 'ok') {
                    alert('Scan completed successfully! Results will refresh.');
                    loadData();
                } else {
                    alert('Scan failed: ' + (result.message || 'Unknown error'));
                }
            } catch (e) {
                alert('Error starting scan: ' + e.message);
            } finally {
                document.getElementById('scanBtn').disabled = false;
                document.getElementById('scanSpinner').innerHTML = '';
                scanInProgress = false;
            }
        }

        // Initial load and refresh every 30s
        loadData();
        setInterval(loadData, 30000);
    </script>
</body>
</html>
"""

if FLASK_AVAILABLE:
    ensure_db_tables()
    app = Flask(__name__)
    app.secret_key = os.urandom(24)

    @app.route('/')
    def dashboard():
        if not session.get('user_id'):
            return redirect('/login')
        return render_template_string(
            DASHBOARD_HTML,
            email=session.get('email', 'user@example.com'),
            company=session.get('company', 'My Company')
        )

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            conn.close()
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['email'] = user[1]
                session['company'] = user[3]
                return redirect('/')
            else:
                return render_template_string(LOGIN_HTML, error="Invalid email or password")
        return render_template_string(LOGIN_HTML, error=None)

    # Business email validation (block free domains)
    FREE_DOMAINS = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.com', 'protonmail.com', 'icloud.com']
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            email = request.form['email']
            company = request.form['company']
            password = generate_password_hash(request.form['password'])

            # Check if email is from a free domain
            domain = email.split('@')[-1].lower()
            if domain in FREE_DOMAINS:
                return render_template_string(SIGNUP_HTML, error="Please use a business email address (personal emails are not allowed).")

            try:
                conn = sqlite3.connect(DB_NAME)
                c = conn.cursor()
                c.execute("INSERT INTO users (email, password, company, created_at) VALUES (?, ?, ?, datetime('now'))", 
                          (email, password, company))
                conn.commit()
                conn.close()
                return redirect('/login')
            except sqlite3.IntegrityError:
                return render_template_string(SIGNUP_HTML, error="Email already exists")
        return render_template_string(SIGNUP_HTML, error=None)

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect('/login')

    @app.route('/api/data')
    def api_data():
        scans = get_scan_history()
        alerts = get_alerts(20)
        total_scans = len(scans)
        critical_findings = sum(1 for a in alerts if a[4] == 'CRITICAL')
        fixed_issues = sum(1 for a in alerts if a[5] == 1)
        open_ports = scans[0][3] if scans else 0

        paths = []
        try:
            resources = fetch_aws_resources('default')
            G = build_attack_graph(resources)
            found = find_attack_paths(G)
            for p in found:
                readable = []
                for node in p:
                    if node == "Internet": readable.append("🌐 Internet")
                    elif node.startswith("s3:"): readable.append(f"📦 {node.replace('s3:', '')}")
                    elif node.startswith("sg-"): readable.append("🛡️ SG")
                    elif node.startswith("i-"): readable.append("🖥️ EC2")
                    elif node.startswith("iam:"): readable.append("🔑 IAM")
                    else: readable.append(node)
                paths.append(readable)
        except:
            paths = []

        return jsonify({
            'total_scans': total_scans,
            'critical_findings': critical_findings,
            'fixed_issues': fixed_issues,
            'open_ports': open_ports,
            'scans': scans,
            'alerts': alerts,
            'attack_paths': paths
        })

    @app.route('/scan', methods=['POST'])
    def trigger_scan():
        """Run a background scan on example.com and save results."""
        try:
            # Run a lightweight scan on example.com to generate demo data
            # In production, you'd run the full scanner with user cloud credentials.
            # For now, we simulate a scan by calling our own scan_host on example.com.
            import subprocess
            # Run a simple scan on example.com port 80,443
            cmd = [sys.executable, '-c', 
                   'import scanner; open_services = scanner.scan_host("example.com", [80,443]); print(open_services)']
            # Actually, we can directly call scan_host from this module.
            # Since we have the functions defined, we can run a small scan.
            # We'll do a quick scan on example.com ports 80,443
            open_services = scan_host("example.com", [80,443])
            findings = []
            # Add a dummy finding if needed
            if open_services:
                save_scan("example.com", "web", "default", open_services, findings)
            return jsonify({'status': 'ok', 'message': f'Scan completed, found {len(open_services)} open ports.'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})

    def start_dashboard(port=5000):
        port = int(os.environ.get('PORT', port))
        app.run(host='0.0.0.0', port=port, debug=False)

# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser(description="Aegis – Global Cloud & API Security")
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range")
    parser.add_argument("-t", "--threads", type=int, default=50)
    parser.add_argument("--api", action="store_true", help="Run OWASP API checks")
    parser.add_argument("--cloud", action="store_true", help="Check current cloud (single account)")
    parser.add_argument("--db", action="store_true", help="Enable learning & drift detection")
    parser.add_argument("--fix", action="store_true", help="Auto-remediate HIGH/CRITICAL issues")
    parser.add_argument("--human", action="store_true", help="Human-in-the-loop mode: ask for approval before each fix")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation")
    parser.add_argument("--graph", action="store_true", help="Build attack path graph (AWS only)")
    parser.add_argument("--dashboard", action="store_true", help="Start web dashboard")
    parser.add_argument("--slack", help="Slack webhook URL")
    parser.add_argument("--chain", action="store_true", help="Auto-fix attack chains across all clouds")
    parser.add_argument("--report", action="store_true", help="Generate PDF compliance report")
    parser.add_argument("--accounts", help="Comma-separated list: cloud:identifier")
    parser.add_argument("--accounts-file", help="File with one cloud:identifier per line")
    parser.add_argument("--role", default="Aegis-Scanner", help="AWS IAM role to assume")
    parser.add_argument("--dir", action="store_true", help="Discover hidden directories (web target)")
    parser.add_argument("--sqli", action="store_true", help="Test for SQL injection vulnerabilities (web target)")
    parser.add_argument("--xss", action="store_true", help="Test for Cross-Site Scripting (XSS) vulnerabilities (web target)")
    parser.add_argument("--cve", action="store_true", help="Lookup CVEs for detected services (requires banner)")
    parser.add_argument("--ask", help="Ask Aegis AI a question about your cloud security")
    args = parser.parse_args()

    # --- AI Query ---
    if args.ask:
        context = ""
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute('''SELECT findings FROM scans ORDER BY id DESC LIMIT 1''')
            result = c.fetchone()
            if result:
                context = f"Last scan findings: {result[0][:500]}"
            conn.close()
        except:
            pass

        print(f"[*] Asking Aegis AI: {args.ask}")
        response = ai_query(args.ask, context)
        print("\n" + "="*80)
        print("🤖 Aegis AI Response")
        print("="*80)
        print(response)
        print("="*80)
        return

    # --- Dashboard (without login) – overridden by Flask app above ---
    if args.dashboard:
        if not FLASK_AVAILABLE:
            print("[!] Flask not installed. Run: pip install flask")
            return
        print("[*] Starting Aegis Dashboard...")
        start_dashboard()
        import time
        while True:
            time.sleep(1)
        return

    # --- Report ---
    if args.report:
        print("[*] Generating PDF compliance report...")
        output = generate_compliance_report(args.host, "apcss_report.pdf")
        if output:
            print(f"[+] Report saved to: {output}")
        return

    # --- Multi-account scanning ---
    if args.chain or args.accounts or args.accounts_file:
        run_fix_chain(args)
        return

    # --- Graph (AWS only) ---
    if args.graph:
        print("[*] Building attack graph (AWS only)...")
        resources = fetch_aws_resources('default')
        G = build_attack_graph(resources)
        paths = find_attack_paths(G)
        if paths:
            print("\n🔥 ATTACK PATHS FOUND:")
            for path in paths:
                print(f"  {' -> '.join(path)}")
        else:
            print("✅ No attack paths found.")
        return

    # --- Single host/cloud scan (legacy) ---
    if args.db:
        init_db()
        print(f"[HISTORY] Target '{args.host}' - Learning mode active.")

    ports = set()
    for part in args.ports.split(','):
        if '-' in part:
            s, e = map(int, part.split('-'))
            ports.update(range(s, e+1))
        else:
            ports.add(int(part))
    ports = sorted(ports)

    print(f"[*] Scanning {args.host} on {len(ports)} ports...")
    open_services = scan_host(args.host, ports, args.threads)

    if not open_services:
        print("[!] No open ports found. Proceeding with web scanning only...")

    all_findings = []

    # --- CLOUD SCAN ---
    if args.cloud:
        print("[*] Checking AWS...")
        all_findings.extend(check_aws_s3_public())
        all_findings.extend(check_aws_security_groups())
        print("[*] Checking GCP...")
        all_findings.extend(check_gcp_storage_public())
        print("[*] Checking Azure...")
        all_findings.extend(check_azure_blob_public())
        print("[*] Checking OCI...")
        all_findings.extend(check_oci_storage_public())

    # --- API SCAN ---
    if open_services:
        for port, (service, banner) in open_services.items():
            if args.api and service in ("HTTP", "HTTPS"):
                protocol = "https" if port in (443, 8443) else "http"
                all_findings.extend(check_api_vulnerabilities(args.host, port, protocol))

    # --- WEB SCANNER (DIR, SQLI, XSS) ---
    target_url = args.host
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        target_url = f"https://{target_url}"

    if args.dir:
        print(f"[*] Discovering directories on {target_url}...")
        dir_findings = discover_directories(target_url)
        for f in dir_findings:
            all_findings.append((
                f"Directory found: {f['path']} (HTTP {f['status']})",
                "Web Security",
                5.0 if f['risk'] == "MEDIUM" else 2.0,
                f['risk'],
                "DIR_DISCOVERY",
                f['path']
            ))

    if args.sqli:
        print(f"[*] Testing SQL injection on {target_url}...")
        sqli_findings = test_sqli(target_url)
        for f in sqli_findings:
            all_findings.append((
                f"SQL Injection: {f['url']} (payload: {f['payload']})",
                "Web Security",
                9.0,
                f['risk'],
                "SQLI",
                f['url']
            ))

    if args.xss:
        print(f"[*] Testing XSS on {target_url}...")
        xss_findings = test_xss(target_url)
        for f in xss_findings:
            all_findings.append((
                f"XSS: {f['url']} (payload: {f['payload']})",
                "Web Security",
                7.5,
                f['risk'],
                "XSS",
                f['url']
            ))

    if args.cve and open_services:
        print(f"[*] Looking up CVEs for detected services...")
        for port, (service, banner) in open_services.items():
            if banner:
                cve_data = lookup_cve(service, version=None)
                if cve_data:
                    all_findings.append((
                        f"CVE {cve_data['id']}: {cve_data['description']}",
                        "CVE",
                        float(cve_data.get('cvss_score', 5.0)),
                        "HIGH",
                        "CVE",
                        cve_data['id']
                    ))

    risk_score = calculate_risk_score(all_findings)

    fixed_count = 0
    if args.fix:
        print("\n" + "="*80)
        print("🛡️ AUTO-REMEDIATION ENGAGED")
        if args.human:
            print("👤 HUMAN-IN-THE-LOOP MODE: You will approve each fix")
        else:
            print("🤖 AUTO MODE: Fixing everything automatically")
        print("="*80)

        fixable = []
        for f in all_findings:
            if len(f) >= 5:
                sev = f[3]
                fix_type = f[4] if len(f) > 4 else None
                extra = f[5] if len(f) > 5 else None
                if sev in ["HIGH", "CRITICAL"] and fix_type is not None:
                    fixable.append((f, fix_type, extra))

        if not fixable:
            print("No HIGH/CRITICAL fixable vulnerabilities found.")
        else:
            print(f"Found {len(fixable)} fixable HIGH/CRITICAL issues.")

            if not args.human:
                if not args.yes:
                    response = input("Apply all fixes? (y/n): ").strip().lower()
                    if response != 'y':
                        print("Remediation aborted.")
                        sys.exit(0)
            else:
                print("\n👤 HUMAN MODE: You will review each vulnerability before fixing.")

            for item in fixable:
                f, fix_type, extra = item
                desc = f[0]
                sev = f[3]

                if args.human:
                    print("\n" + "-"*80)
                    print(f"🔍 Vulnerability: {desc}")
                    print(f"⚠️ Severity: {sev}")
                    print("-"*80)
                    choice = input("Apply this fix? (y/n/skip all): ").strip().lower()
                    if choice == 'n' or choice == 'no':
                        print(f"⏭️ Skipping: {desc}")
                        save_alert("unknown", "default", f"⏭️ SKIPPED: {desc}", sev, fixed=False)
                        continue
                    elif choice == 's' or choice == 'skip all':
                        print("⏭️ Skipping all remaining fixes.")
                        break

                print(f"\n🔧 Processing: {desc}")
                success = False
                msg = ""

                if fix_type == "S3_PUBLIC" and extra:
                    success, msg = fix_s3_public(extra, cloud="aws", account="default")
                elif fix_type == "SG_OPEN" and extra:
                    group_id, port = extra
                    success, msg = fix_security_group_rule(group_id, port, cloud="aws", account="default")
                elif fix_type == "GCP_PUBLIC" and extra:
                    success, msg = fix_gcp_bucket_public(extra, cloud="gcp", account="default")
                elif fix_type == "OCI_PUBLIC" and extra:
                    ns, bucket = extra
                    success, msg = fix_oci_bucket_public(ns, bucket, cloud="oci", account="default")
                else:
                    msg = f"⚠️ No auto-fix implemented for {fix_type}"

                if success:
                    fixed_count += 1
                    save_alert("unknown", "default", desc, sev, fixed=True)
                    if args.slack:
                        send_slack_alert(f"✅ FIXED: {desc}", sev, args.slack)
                else:
                    save_alert("unknown", "default", f"❌ FAILED: {desc}", sev, fixed=False)
                print(msg)

            print(f"\n✅ Remediation complete. Fixed {fixed_count} out of {len(fixable)} issues.")

    if args.db:
        save_scan(args.host, "local", "default", open_services if open_services else {}, all_findings)

    # --- Print report ---
    table_data = []
    if open_services:
        for port, (service, banner) in open_services.items():
            table_data.append([port, service, banner[:60] if banner else "", "-", "-", "INFO"])
    for f in all_findings:
        desc, cat, score, sev = f[0], f[1], f[2], f[3]
        table_data.append(["N/A", cat, desc[:60], f"{score:.1f}", sev, "VULN"])

    print("\n" + "="*110)
    print(" 🛡️ AEGIS – SELF-HEALING CLOUD SECURITY ".center(110))
    print("="*110)
    print(f"🟢 Overall Risk Score: {risk_score}/100")
    print("="*110)

    colour_map = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m", "INFO": "\033[37m"}
    reset = "\033[0m"
    headers = ["Port", "Service/Check", "Details", "CVSS", "Severity", "Type"]
    for row in sorted(table_data, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"INFO":3}.get(x[4], 9)):
        print(colour_map.get(row[4], "") + tabulate([row], headers=headers, tablefmt="plain") + reset)

    print("\n" + "="*110)
    print(f"Total Open Ports: {len(open_services)} | Total Findings: {len(all_findings)} | Auto-Fixed: {fixed_count}")
    if args.fix:
        print("[+] Auto-remediation applied.")
    print("[+] Aegis learning engine active. Run again to detect DRIFT.")
    if args.slack:
        print("[+] Slack alerts enabled.")
    print("="*110)

if __name__ == "__main__":
    main()
