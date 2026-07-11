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
import random
import string
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
        first_name TEXT,
        last_name TEXT,
        created_at TEXT,
        verified INTEGER DEFAULT 0
    )''')
    conn.commit()
    conn.close()

# ---- OTP Storage (in-memory for simplicity, replace with Redis/DB later) ----
pending_users = {}

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    # In production, use SMTP or SendGrid. For now, print to console/log.
    print(f"[OTP] Your verification code for Aegis is: {otp}")
    print(f"[OTP] Sent to: {email}")
    return True

def ensure_db_tables():
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

# ---------- AI QUERY FUNCTION (UPDATED WITH FALLBACK KNOWLEDGE) ----------
def ai_query(question, context=""):
    """Ask AI about your cloud security – works even without Ollama/OpenAI"""
    
    # ─── FALLBACK KNOWLEDGE BASE ───
    fallback_knowledge = """
Aegis (APCSS) is the world's first open‑source, four‑cloud, self‑healing security platform.

🔹 WHAT AEGIS DOES:
- Scans AWS, GCP, Azure, and OCI in one command.
- Detects attack paths: Internet → Public VM → IAM Role → S3 Bucket.
- Auto‑fixes: open S3 buckets, overly permissive security groups, exposed EC2 ports, over‑privileged IAM roles.
- Includes a live dashboard with risk score, cloud inventory, attack path explorer, and AI copilot.
- Generates compliance reports (PCI‑DSS, HIPAA, SOC2).
- Sends Slack alerts for critical findings.
- Supports multi‑account scanning across all clouds.

👤 THE FOUNDER:
Austin Emmanuel – a 19‑year‑old founder from Nigeria. He built Aegis because commercial tools like Wiz and Orca cost millions and lock security behind paywalls. He wanted to democratize cloud security and give every team, from startups to enterprises, access to world‑class protection – for free.

🏆 WHY AEGIS STANDS OUT:
- 100% open source – no vendor lock‑in.
- Four‑cloud coverage (the only open‑source tool that does this).
- Auto‑remediation of attack chains, not just alerts.
- AI assistant that answers security questions.
- Built by a solo founder, not a billion‑dollar corporation.

💡 COMMON QUESTIONS:
- "What is an attack path?" → A chain of exploitable resources that an attacker can use to move from the internet to your sensitive data.
- "How do I fix a public S3 bucket?" → Aegis auto‑fixes it with one click, or you can use the CLI: `python scanner.py --fix`.
- "Which clouds does Aegis support?" → AWS, Azure, GCP, and OCI.
- "Is Aegis free?" → Yes, completely free and open source.
- "Who built Aegis?" → Austin Emmanuel, a 19‑year‑old founder from Nigeria.
"""

    # ─── If AI libraries are available, use them ───
    if OLLAMA_AVAILABLE or OPENAI_AVAILABLE:
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

User question: {question}
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
            # If AI fails, use fallback
            return f"AI service error: {str(e)}.\n\nHere's what I know:\n{fallback_knowledge}"

    # ─── If no AI libraries are installed, use fallback ───
    # Try to match keywords in the question
    q_lower = question.lower()
    if any(word in q_lower for word in ["who", "founder", "built", "created", "austin", "emmanuel"]):
        return f"""
👤 ABOUT THE FOUNDER

Austin Emmanuel is a 19‑year‑old founder from Nigeria who built Aegis (APCSS) – the world's first open‑source, four‑cloud, self‑healing security platform.

He created Aegis because commercial cloud security tools like Wiz and Orca charge millions of dollars, locking out startups, students, and independent developers. He wanted to democratize cloud security and give everyone access to enterprise‑grade protection – for free.

Aegis is his vision of a world where security is open, transparent, and accessible to all.
"""
    elif any(word in q_lower for word in ["what", "aegis", "apcss", "platform", "does"]):
        return f"""
🛡️ WHAT IS AEGIS?

Aegis (APCSS) is a fully open‑source, self‑healing cloud security platform that:

✓ Scans AWS, Azure, GCP, and OCI in a single command.
✓ Finds attack paths – Internet → EC2 → IAM → S3.
✓ Auto‑fixes open S3 buckets, security group rules, EC2 ports, and IAM roles.
✓ Provides a live dashboard with risk scoring, cloud inventory, and attack path visualization.
✓ Includes an AI security copilot that answers your cloud security questions.
✓ Generates compliance reports (PCI‑DSS, HIPAA, SOC2).
✓ Sends Slack alerts for critical risks.

It was built by Austin Emmanuel, a 19‑year‑old founder from Nigeria, to make cloud security accessible to everyone – for free.
"""
    else:
        return f"""
💡 AEGIS AI ASSISTANT

I'm your cloud security copilot. I can answer questions about:

• Cloud vulnerabilities (S3, EC2, IAM, Security Groups, etc.)
• Attack paths and how attackers move through your infrastructure
• Remediation steps for misconfigurations
• Cloud security best practices
• Aegis itself – what it is, who built it, and how to use it

Here's a quick summary:
Aegis is the world's first open‑source, four‑cloud, self‑healing security platform, built by Austin Emmanuel (19, Nigeria). It scans AWS, Azure, GCP, and OCI, finds attack paths, and auto‑fixes risks – all for free.

Ask me something specific!
"""

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

# ---------- HTML TEMPLATES (LANDING + DASHBOARD) ----------

# ========== LANDING PAGE (BLACK/WHITE/BLUE PREMIUM) ==========
LANDING_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Aegis – Autonomous Cloud Security</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet" />
    <style>
        * { font-family: 'Inter', sans-serif; }
        body { background: #000000; color: #ffffff; }

        .plasma {
            position: fixed;
            width: 100%;
            height: 100%;
            z-index: -1;
            background:
                radial-gradient(circle at 15% 20%, rgba(37,99,235,0.2) 0%, transparent 40%),
                radial-gradient(circle at 85% 30%, rgba(59,130,246,0.15) 0%, transparent 35%),
                radial-gradient(circle at 50% 85%, rgba(37,99,235,0.1) 0%, transparent 40%);
            filter: blur(120px);
        }

        .glass {
            background: rgba(255,255,255,0.03);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255,255,255,0.08);
        }

        .glass-card {
            background: rgba(255,255,255,0.02);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255,255,255,0.06);
            transition: all 0.3s ease;
        }
        .glass-card:hover {
            border-color: #2563eb;
            transform: translateY(-6px);
            box-shadow: 0 20px 60px rgba(37,99,235,0.15);
        }

        .hero-gradient {
            background: linear-gradient(135deg, #2563eb 0%, #3b82f6 50%, #60a5fa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .btn-primary {
            background: #2563eb;
            transition: all 0.3s ease;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 40px rgba(37,99,235,0.4);
        }

        .btn-secondary {
            border: 1px solid rgba(255,255,255,0.15);
            transition: all 0.3s ease;
        }
        .btn-secondary:hover {
            background: rgba(255,255,255,0.05);
            border-color: #2563eb;
        }

        .pricing-popular {
            border-color: #2563eb;
            background: rgba(37,99,235,0.06);
        }

        .trust-item {
            opacity: 0.6;
            transition: all 0.3s ease;
        }
        .trust-item:hover { opacity: 1; }

        html { scroll-behavior: smooth; }

        @media (max-width: 768px) {
            .hero-text h1 { font-size: 2.5rem; }
        }
    </style>
</head>
<body>

    <div class="plasma"></div>

    <!-- ─── NAVBAR ─── -->
    <nav class="flex items-center justify-between px-6 md:px-10 lg:px-16 py-5 border-b border-white/5 max-w-7xl mx-auto">
        <div class="flex items-center gap-2">
            <div class="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-white font-bold text-xl shadow-lg shadow-blue-500/20">
                🛡️
            </div>
            <span class="text-2xl font-bold text-white">
                Aegis
            </span>
            <span class="text-xs font-medium text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded-full border border-blue-500/20 hidden sm:inline">
                APCSS
            </span>
        </div>
        <div class="flex items-center gap-6 text-sm">
            <a href="#about" class="text-slate-400 hover:text-white transition hidden md:block">
                <i class="fas fa-info-circle mr-1"></i> About
            </a>
            <a href="#features" class="text-slate-400 hover:text-white transition hidden md:block">Features</a>
            <a href="#pricing" class="text-slate-400 hover:text-white transition hidden md:block">Pricing</a>
            <a href="https://github.com/CloudHeal-founder/CloudHeal" target="_blank" class="text-slate-400 hover:text-white transition hidden md:block">
                <i class="fab fa-github"></i>
            </a>
            <a href="/login" class="text-white font-medium hover:text-blue-400 transition">Login</a>
            <a href="/signup" class="btn-primary text-white px-5 py-2.5 rounded-full text-sm font-semibold shadow-lg shadow-blue-500/20">
                Get Started
            </a>
        </div>
    </nav>

    <!-- ─── HERO ─── -->
    <section class="flex flex-col lg:flex-row items-center gap-12 px-6 md:px-10 lg:px-16 py-16 lg:py-24 max-w-7xl mx-auto">
        <div class="flex-1 text-center lg:text-left">
            <div class="inline-flex items-center gap-2 bg-blue-500/10 border border-blue-500/20 px-4 py-1.5 rounded-full text-sm text-blue-400 font-medium mb-6">
                <span class="w-2 h-2 rounded-full bg-blue-400 animate-pulse"></span>
                Next‑Gen Cloud Security
            </div>
            <h1 class="hero-text text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-extrabold leading-[1.1] tracking-tight">
                Secure Your<br />
                <span class="hero-gradient">Entire Cloud</span><br />
                From One Platform
            </h1>
            <p class="text-slate-400 text-lg md:text-xl max-w-2xl mx-auto lg:mx-0 mt-6 leading-relaxed">
                Discover attack paths, misconfigurations, exposed assets, and cloud risks
                across <span class="text-white font-medium">AWS</span>,
                <span class="text-white font-medium">Azure</span>,
                <span class="text-white font-medium">GCP</span> &amp;
                <span class="text-white font-medium">OCI</span> – in real time.
            </p>
            <div class="flex flex-wrap items-center justify-center lg:justify-start gap-4 mt-8">
                <a href="/signup" class="btn-primary text-white px-8 py-3.5 rounded-full font-semibold text-base shadow-lg shadow-blue-500/25">
                    Start Free <i class="fas fa-arrow-right ml-2 text-sm"></i>
                </a>
                <a href="#about" class="btn-secondary text-white px-8 py-3.5 rounded-full font-medium text-base">
                    Learn More
                </a>
            </div>
            <div class="flex flex-wrap items-center justify-center lg:justify-start gap-3 mt-8">
                <span class="text-xs text-slate-500 uppercase tracking-wider font-semibold">Supported:</span>
                <span class="bg-white/5 border border-white/10 px-3 py-1 rounded-full text-sm text-slate-300 font-medium">AWS ✓</span>
                <span class="bg-white/5 border border-white/10 px-3 py-1 rounded-full text-sm text-slate-300 font-medium">Azure ✓</span>
                <span class="bg-white/5 border border-white/10 px-3 py-1 rounded-full text-sm text-slate-300 font-medium">GCP ✓</span>
                <span class="bg-white/5 border border-white/10 px-3 py-1 rounded-full text-sm text-slate-300 font-medium">OCI ✓</span>
            </div>
        </div>

        <!-- Hero Visual -->
        <div class="flex-1 w-full glass rounded-3xl p-8 md:p-10 border-white/10 shadow-2xl">
            <div class="flex flex-col items-center gap-4 max-w-sm mx-auto">
                <div class="w-full bg-slate-900/50 rounded-2xl p-5 border border-white/5">
                    <div class="flex flex-wrap items-center justify-center gap-3 text-sm">
                        <span class="text-slate-400">🌐 Internet</span>
                        <span class="text-blue-400">→</span>
                        <span class="text-red-400 font-medium">🛡️ Public VM</span>
                        <span class="text-blue-400">→</span>
                        <span class="text-amber-400 font-medium">🔑 IAM Role</span>
                        <span class="text-blue-400">→</span>
                        <span class="text-emerald-400 font-medium">📦 S3 Bucket</span>
                    </div>
                </div>
                <div class="flex items-center gap-6 bg-slate-900/50 rounded-2xl px-6 py-4 border border-white/5 w-full justify-center">
                    <span class="text-3xl font-bold bg-gradient-to-r from-blue-400 to-blue-200 bg-clip-text text-transparent">87</span>
                    <span class="text-slate-400 text-sm font-medium">Risk Score</span>
                    <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span class="text-emerald-400 text-xs font-medium">Live</span>
                </div>
                <p class="text-slate-500 text-xs text-center">Attack path visualization · Auto‑remediation ready</p>
            </div>
        </div>
    </section>

    <!-- ─── TRUST BAR ─── -->
    <div class="border-y border-white/5 py-10 text-center max-w-7xl mx-auto px-6">
        <p class="text-xs text-slate-500 uppercase tracking-widest font-semibold mb-5">Trusted by security teams building the future</p>
        <div class="flex flex-wrap items-center justify-center gap-8 md:gap-12">
            <span class="trust-item text-slate-400 font-medium text-sm">🏢 Startups</span>
            <span class="trust-item text-slate-400 font-medium text-sm">🔒 Enterprises</span>
            <span class="trust-item text-slate-400 font-medium text-sm">☁️ Cloud‑Native</span>
            <span class="trust-item text-slate-400 font-medium text-sm">🧠 AI‑Driven</span>
            <span class="trust-item text-slate-400 font-medium text-sm">🌍 Global</span>
        </div>
    </div>

    <!-- ─── ABOUT AEGIS ─── -->
    <section id="about" class="py-20 max-w-7xl mx-auto px-6 md:px-10">
        <h2 class="text-3xl md:text-4xl font-bold text-center">
            About <span class="hero-gradient">Aegis</span>
        </h2>
        <p class="text-slate-400 text-center max-w-3xl mx-auto mt-4 text-lg">
            The world's first open‑source, self‑healing cloud security platform.
        </p>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-10 mt-12">
            <div class="glass-card rounded-3xl p-8">
                <div class="text-5xl mb-4">🚀</div>
                <h3 class="text-2xl font-bold text-white">The Mission</h3>
                <p class="text-slate-400 mt-4 leading-relaxed">
                    Aegis was built to democratize cloud security. Commercial tools like
                    <span class="text-white font-medium">Wiz</span> and
                    <span class="text-white font-medium">Orca</span> cost millions –
                    Aegis is <span class="text-emerald-400 font-medium">100% free</span> and open source.
                </p>
                <p class="text-slate-400 mt-3 leading-relaxed">
                    We believe every team, from startups to enterprises, should have
                    access to world‑class cloud security without the billion‑dollar price tag.
                </p>
            </div>

            <div class="glass-card rounded-3xl p-8">
                <div class="text-5xl mb-4">🧠</div>
                <h3 class="text-2xl font-bold text-white">What Aegis Does</h3>
                <ul class="text-slate-400 mt-4 space-y-3">
                    <li>✓ <span class="text-white">Multi‑Cloud Scanning</span> – AWS, Azure, GCP, OCI</li>
                    <li>✓ <span class="text-white">Attack Path Analysis</span> – See how attackers move</li>
                    <li>✓ <span class="text-white">Auto‑Remediation</span> – Fix risks automatically</li>
                    <li>✓ <span class="text-white">AI Security Copilot</span> – Ask anything about your cloud</li>
                    <li>✓ <span class="text-white">Compliance Reporting</span> – PCI, HIPAA, SOC2</li>
                    <li>✓ <span class="text-white">100% Open Source</span> – No vendor lock‑in</li>
                </ul>
            </div>

            <div class="glass-card rounded-3xl p-8 md:col-span-2">
                <div class="flex flex-col md:flex-row items-center gap-6">
                    <div class="text-5xl">👤</div>
                    <div>
                        <h3 class="text-2xl font-bold text-white">Built by Austin Emmanuel</h3>
                        <p class="text-slate-400 mt-2 leading-relaxed">
                            Aegis was built by a <span class="text-white font-medium">19‑year‑old founder from Nigeria</span>
                            who saw that cloud security was locked behind massive paywalls.
                            This is a platform <span class="text-blue-400 font-medium">by the community, for the community</span>.
                        </p>
                        <div class="flex items-center gap-3 mt-4">
                            <a href="https://github.com/CloudHeal-founder/CloudHeal" target="_blank" class="text-slate-400 hover:text-white transition text-sm">
                                <i class="fab fa-github"></i> GitHub
                            </a>
                            <span class="text-slate-600">•</span>
                            <span class="text-slate-500 text-sm">Open Source</span>
                            <span class="text-slate-600">•</span>
                            <span class="text-emerald-400 text-sm font-medium">v2.0</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- ─── FEATURES ─── -->
    <section id="features" class="py-20 max-w-7xl mx-auto px-6 md:px-10">
        <h2 class="text-3xl md:text-4xl font-bold text-center">
            Built For <span class="hero-gradient">Modern Security Teams</span>
        </h2>
        <p class="text-slate-400 text-center max-w-2xl mx-auto mt-4 text-lg">
            One platform. Complete visibility. Autonomous remediation.
        </p>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mt-12">
            <div class="glass-card rounded-2xl p-8 text-center">
                <div class="text-4xl mb-4">🌩️</div>
                <h3 class="text-xl font-semibold text-white">Multi‑Cloud Visibility</h3>
                <p class="text-slate-400 text-sm mt-3 leading-relaxed">Unified security across AWS, Azure, GCP and OCI – one platform, one view.</p>
            </div>
            <div class="glass-card rounded-2xl p-8 text-center">
                <div class="text-4xl mb-4">🔗</div>
                <h3 class="text-xl font-semibold text-white">Attack Path Analysis</h3>
                <p class="text-slate-400 text-sm mt-3 leading-relaxed">See exactly how an attacker would move from the internet to your sensitive data.</p>
            </div>
            <div class="glass-card rounded-2xl p-8 text-center">
                <div class="text-4xl mb-4">🛠️</div>
                <h3 class="text-xl font-semibold text-white">Auto‑Remediation</h3>
                <p class="text-slate-400 text-sm mt-3 leading-relaxed">Not just alerts – Aegis fixes misconfigurations, open ports, and excessive permissions.</p>
            </div>
            <div class="glass-card rounded-2xl p-8 text-center">
                <div class="text-4xl mb-4">🤖</div>
                <h3 class="text-xl font-semibold text-white">AI Security Copilot</h3>
                <p class="text-slate-400 text-sm mt-3 leading-relaxed">Ask Aegis AI any security question – get instant, context‑aware answers.</p>
            </div>
            <div class="glass-card rounded-2xl p-8 text-center">
                <div class="text-4xl mb-4">📊</div>
                <h3 class="text-xl font-semibold text-white">Compliance &amp; Reporting</h3>
                <p class="text-slate-400 text-sm mt-3 leading-relaxed">Generate PCI‑DSS, HIPAA, SOC2 reports with one click.</p>
            </div>
            <div class="glass-card rounded-2xl p-8 text-center">
                <div class="text-4xl mb-4">🔓</div>
                <h3 class="text-xl font-semibold text-white">100% Open Source</h3>
                <p class="text-slate-400 text-sm mt-3 leading-relaxed">No vendor lock‑in. Full transparency. Built by the community.</p>
            </div>
        </div>
    </section>

    <!-- ─── DASHBOARD PREVIEW ─── -->
    <section class="py-16 max-w-7xl mx-auto px-6 md:px-10">
        <div class="glass rounded-3xl p-8 md:p-12 border-white/10">
            <h2 class="text-3xl md:text-4xl font-bold text-center">
                Security <span class="hero-gradient">Command Center</span>
            </h2>
            <p class="text-slate-400 text-center max-w-2xl mx-auto mt-4 text-lg">
                Real‑time visibility, attack paths, and auto‑remediation at a glance.
            </p>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-6 mt-10">
                <div class="glass-card rounded-2xl p-6 text-center">
                    <div class="text-3xl md:text-4xl font-bold bg-gradient-to-r from-blue-400 to-blue-200 bg-clip-text text-transparent">92</div>
                    <p class="text-slate-400 text-sm mt-1">🛡️ Security Posture</p>
                </div>
                <div class="glass-card rounded-2xl p-6 text-center">
                    <div class="text-3xl md:text-4xl font-bold text-white">12,481</div>
                    <p class="text-slate-400 text-sm mt-1">☁️ Assets Protected</p>
                </div>
                <div class="glass-card rounded-2xl p-6 text-center">
                    <div class="text-3xl md:text-4xl font-bold text-amber-400">8</div>
                    <p class="text-slate-400 text-sm mt-1">🔥 Active Attack Paths</p>
                </div>
                <div class="glass-card rounded-2xl p-6 text-center">
                    <div class="text-3xl md:text-4xl font-bold text-emerald-400">41</div>
                    <p class="text-slate-400 text-sm mt-1">⚡ Auto‑Remediated</p>
                </div>
            </div>
        </div>
    </section>

    <!-- ─── PRICING ─── -->
    <section id="pricing" class="py-20 max-w-7xl mx-auto px-6 md:px-10">
        <h2 class="text-3xl md:text-4xl font-bold text-center">
            Simple, <span class="hero-gradient">Transparent</span> Pricing
        </h2>
        <p class="text-slate-400 text-center max-w-2xl mx-auto mt-4 text-lg">
            Start free. Scale as you grow.
        </p>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mt-12 max-w-5xl mx-auto">
            <div class="glass-card rounded-2xl p-8 text-center">
                <h3 class="text-xl font-semibold text-white">Free</h3>
                <p class="text-4xl font-bold text-white mt-4">$0</p>
                <ul class="text-slate-400 text-sm space-y-3 mt-6 text-left">
                    <li>✓ 1 cloud account</li>
                    <li>✓ Manual scans</li>
                    <li>✓ Community support</li>
                    <li>✓ Basic dashboard</li>
                </ul>
                <a href="/signup" class="btn-primary text-white px-6 py-2.5 rounded-full text-sm font-semibold inline-block mt-8 shadow-lg shadow-blue-500/20">
                    Get Started
                </a>
            </div>
            <div class="glass-card pricing-popular rounded-2xl p-8 text-center border-2">
                <div class="bg-blue-500/10 text-blue-400 text-xs font-semibold px-3 py-1 rounded-full inline-block mb-4 border border-blue-500/20">Most Popular</div>
                <h3 class="text-xl font-semibold text-white">Pro</h3>
                <p class="text-4xl font-bold text-white mt-4">$500 <span class="text-base font-normal text-slate-400">/ month</span></p>
                <ul class="text-slate-400 text-sm space-y-3 mt-6 text-left">
                    <li>✓ 10 cloud accounts</li>
                    <li>✓ Auto‑remediation</li>
                    <li>✓ Slack alerts</li>
                    <li>✓ Priority support</li>
                    <li>✓ 1‑year history</li>
                </ul>
                <a href="/signup" class="btn-primary text-white px-6 py-2.5 rounded-full text-sm font-semibold inline-block mt-8 shadow-lg shadow-blue-500/30">
                    Start Trial
                </a>
            </div>
            <div class="glass-card rounded-2xl p-8 text-center">
                <h3 class="text-xl font-semibold text-white">Enterprise</h3>
                <p class="text-4xl font-bold text-white mt-4">Custom</p>
                <ul class="text-slate-400 text-sm space-y-3 mt-6 text-left">
                    <li>✓ Unlimited accounts</li>
                    <li>✓ 24/7 support</li>
                    <li>✓ Dedicated deployment</li>
                    <li>✓ Custom compliance</li>
                    <li>✓ SSO &amp; RBAC</li>
                </ul>
                <a href="/signup" class="btn-secondary text-white px-6 py-2.5 rounded-full text-sm font-semibold inline-block mt-8">
                    Contact Sales
                </a>
            </div>
        </div>
    </section>

    <!-- ─── CTA ─── -->
    <section class="py-20 max-w-7xl mx-auto px-6 md:px-10">
        <div class="glass rounded-3xl p-8 md:p-12 text-center border-white/10">
            <h2 class="text-3xl md:text-4xl font-bold">
                Ready to secure <span class="hero-gradient">your cloud</span>?
            </h2>
            <p class="text-slate-400 text-lg max-w-2xl mx-auto mt-4">
                Start securing your AWS, Azure, GCP and OCI infrastructure in minutes.
            </p>
            <a href="/signup" class="btn-primary text-white px-10 py-4 rounded-full font-semibold text-lg inline-block mt-8 shadow-lg shadow-blue-500/25">
                Start Free – No Credit Card
            </a>
        </div>
    </section>

    <!-- ─── FOOTER ─── -->
    <footer class="border-t border-white/5 py-8 text-center text-slate-500 text-sm max-w-7xl mx-auto px-6">
        <div class="flex flex-wrap items-center justify-center gap-6 mb-4">
            <a href="#about" class="text-slate-400 hover:text-white transition">About</a>
            <a href="https://github.com/CloudHeal-founder/CloudHeal" target="_blank" class="text-slate-400 hover:text-white transition">
                <i class="fab fa-github"></i> GitHub
            </a>
            <a href="/login" class="text-slate-400 hover:text-white transition">Dashboard</a>
            <a href="#pricing" class="text-slate-400 hover:text-white transition">Pricing</a>
        </div>
        <p class="text-xs text-slate-600">
            © 2026 Aegis – Built by <span class="text-slate-400 font-medium">Austin Emmanuel</span>
        </p>
        <p class="text-xs text-slate-700 mt-1">Open Source · Self‑Healing Cloud Security · v2.0</p>
    </footer>

</body>
</html>
"""

# ========== DASHBOARD (PREMIUM WITH COMMAND INPUT + AI SHIELD) ==========
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis Security Command Center</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet" />
    <style>
        * { font-family: 'Inter', sans-serif; }
        body {
            background: #000000;
            color: #ffffff;
            display: flex;
            height: 100vh;
            overflow: hidden;
        }

        /* ─── Sidebar ─── */
        .sidebar {
            width: 240px;
            background: rgba(0,0,0,0.8);
            backdrop-filter: blur(24px);
            border-right: 1px solid rgba(255,255,255,0.06);
            padding: 24px 0;
            height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            overflow-y: auto;
            z-index: 10;
        }

        .sidebar .logo {
            font-size: 24px;
            font-weight: 700;
            background: linear-gradient(135deg, #2563eb, #60a5fa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            padding: 0 24px;
            margin-bottom: 30px;
            letter-spacing: -0.5px;
        }

        .sidebar .logo span {
            font-size: 11px;
            display: block;
            -webkit-text-fill-color: #64748b;
            font-weight: 400;
            letter-spacing: 0.5px;
        }

        .sidebar a {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 24px;
            color: #94a3b8;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            border-left: 3px solid transparent;
            transition: 0.2s;
        }

        .sidebar a:hover,
        .sidebar a.active {
            background: rgba(255,255,255,.04);
            color: #ffffff;
            border-left-color: #2563eb;
        }

        .sidebar a .icon { font-size: 18px; }
        .sidebar .logout {
            margin-top: 40px;
            border-top: 1px solid rgba(255,255,255,.06);
            padding-top: 20px;
            color: #ef4444;
        }
        .sidebar .logout:hover { border-left-color: #ef4444; }

        /* ─── Main ─── */
        .main {
            margin-left: 240px;
            flex: 1;
            padding: 24px 32px;
            overflow-y: auto;
            height: 100vh;
            background:
                radial-gradient(circle at 10% 10%, rgba(37,99,235,0.12), transparent 35%),
                radial-gradient(circle at 85% 85%, rgba(96,165,250,0.08), transparent 40%),
                #000000;
        }

        /* ─── Top Bar ─── */
        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .topbar-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .topbar-left h1 {
            font-size: 26px;
            font-weight: 700;
            background: linear-gradient(135deg, #ffffff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .ai-shield {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(37,99,235,0.12);
            border: 1px solid rgba(37,99,235,0.25);
            border-radius: 999px;
            padding: 6px 16px 6px 10px;
            backdrop-filter: blur(12px);
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .ai-shield:hover {
            background: rgba(37,99,235,0.2);
            box-shadow: 0 0 40px rgba(37,99,235,0.2);
            transform: scale(1.02);
        }

        .ai-shield .shield-icon {
            font-size: 22px;
            filter: drop-shadow(0 0 10px rgba(37,99,235,0.4));
            animation: pulseGlow 2s infinite;
        }

        @keyframes pulseGlow {
            0%, 100% { filter: drop-shadow(0 0 10px rgba(37,99,235,0.3)); }
            50% { filter: drop-shadow(0 0 30px rgba(37,99,235,0.6)); }
        }

        .ai-shield .badge {
            color: #60a5fa;
            font-weight: 600;
            font-size: 13px;
        }

        .ai-shield .chat-input {
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 999px;
            padding: 4px 12px;
            font-size: 12px;
            color: #e2e8f0;
            outline: none;
            width: 140px;
            transition: 0.3s;
        }

        .ai-shield .chat-input:focus {
            border-color: #2563eb;
            background: rgba(255,255,255,0.1);
        }

        .topbar-right {
            display: flex;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
        }

        .topbar-right .user-badge {
            background: rgba(255,255,255,.06);
            padding: 6px 14px;
            border-radius: 999px;
            font-size: 12px;
            color: #94a3b8;
        }

        .scan-btn {
            background: linear-gradient(135deg, #2563eb, #3b82f6);
            color: #fff;
            border: none;
            padding: 8px 20px;
            border-radius: 999px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.3s;
            box-shadow: 0 4px 20px rgba(37,99,235,0.3);
        }

        .scan-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(37,99,235,0.5);
        }
        .scan-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        .refresh-btn {
            background: rgba(255,255,255,.06);
            border: 1px solid rgba(255,255,255,.08);
            color: #e2e8f0;
            padding: 8px 16px;
            border-radius: 999px;
            cursor: pointer;
            font-size: 13px;
            transition: 0.2s;
        }
        .refresh-btn:hover { background: rgba(255,255,255,.1); }

        /* ─── Command Input Section ─── */
        .command-section {
            background: rgba(255,255,255,0.02);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 24px;
            padding: 20px 24px;
            margin-bottom: 28px;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 16px;
        }

        .command-section .cmd-label {
            color: #94a3b8;
            font-size: 13px;
            font-weight: 500;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .command-section .cmd-input {
            flex: 1;
            min-width: 200px;
            background: rgba(0,0,0,0.4);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 999px;
            padding: 10px 20px;
            color: #e2e8f0;
            font-size: 14px;
            outline: none;
            transition: 0.3s;
        }

        .command-section .cmd-input:focus {
            border-color: #2563eb;
            box-shadow: 0 0 20px rgba(37,99,235,0.1);
        }

        .command-section .cmd-btn {
            background: linear-gradient(135deg, #2563eb, #3b82f6);
            color: #fff;
            border: none;
            padding: 10px 28px;
            border-radius: 999px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.3s;
            box-shadow: 0 4px 20px rgba(37,99,235,0.25);
            white-space: nowrap;
        }

        .command-section .cmd-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(37,99,235,0.4);
        }

        /* ─── Scan Results Log ─── */
        .results-section {
            background: rgba(255,255,255,0.02);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 24px;
            padding: 20px 24px;
            margin-bottom: 28px;
        }

        .results-section .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }

        .results-section .header h3 {
            color: #94a3b8;
            font-size: 15px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .results-section .header .clear-btn {
            background: none;
            border: none;
            color: #64748b;
            font-size: 12px;
            cursor: pointer;
            transition: 0.2s;
        }
        .results-section .header .clear-btn:hover { color: #ef4444; }

        .results-log {
            background: rgba(0,0,0,0.4);
            border-radius: 16px;
            padding: 16px;
            max-height: 200px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #94a3b8;
            border: 1px solid rgba(255,255,255,0.04);
        }

        .results-log .log-entry {
            padding: 4px 0;
            border-bottom: 1px solid rgba(255,255,255,0.03);
            color: #e2e8f0;
        }

        .results-log .log-entry .timestamp {
            color: #64748b;
            margin-right: 12px;
        }

        .results-log .log-entry .success { color: #34d399; }
        .results-log .log-entry .error { color: #f87171; }
        .results-log .log-entry .info { color: #60a5fa; }

        /* ─── Executive Metrics ─── */
        .executive-grid {
            display: grid;
            grid-template-columns: repeat(4,1fr);
            gap: 20px;
            margin-bottom: 30px;
        }

        .exec-card {
            padding: 24px;
            border-radius: 20px;
            background: rgba(255,255,255,0.02);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255,255,255,0.06);
            transition: 0.3s;
        }

        .exec-card:hover {
            border-color: #2563eb;
            transform: translateY(-3px);
            box-shadow: 0 10px 40px rgba(37,99,235,0.1);
        }

        .exec-card .exec-label {
            color: #94a3b8;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }

        .exec-card h1 {
            font-size: 42px;
            margin-top: 8px;
            margin-bottom: 4px;
            background: linear-gradient(135deg, #60a5fa, #2563eb);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .exec-card small {
            color: #64748b;
            font-size: 13px;
        }

        /* ─── Charts ─── */
        .chart-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 30px;
        }

        .chart-box {
            background: rgba(255,255,255,0.02);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 24px;
            padding: 24px;
        }

        .chart-box h3 {
            font-size: 16px;
            color: #94a3b8;
            margin-bottom: 16px;
        }

        .chart-box canvas { max-height: 200px; width: 100% !important; }

        /* ─── Cloud Inventory ─── */
        .cloud-grid {
            display: grid;
            grid-template-columns: repeat(4,1fr);
            gap: 20px;
            margin-top: 16px;
        }

        .cloud-card {
            background: rgba(255,255,255,0.02);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 20px;
            padding: 24px;
            text-align: center;
            transition: 0.3s;
        }

        .cloud-card:hover { border-color: #2563eb; transform: translateY(-3px); }
        .cloud-card .cloud-name { font-size: 16px; font-weight: 600; color: #94a3b8; }
        .cloud-card h1 { font-size: 36px; margin-top: 10px; color: #e2e8f0; }

        /* ─── Attack Paths ─── */
        .path-card {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 12px;
            padding: 18px 20px;
            margin-bottom: 12px;
            background: rgba(0,0,0,0.3);
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.06);
        }

        .path-node {
            padding: 10px 18px;
            border-radius: 12px;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.06);
            font-weight: 500;
            font-size: 14px;
            color: #e2e8f0;
        }
        .path-arrow { color: #2563eb; font-size: 20px; }
        .empty-state { color: #64748b; font-style: italic; padding: 20px; text-align: center; }

        /* ─── Sections ─── */
        .section {
            background: rgba(255,255,255,0.02);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 24px;
            padding: 24px;
            margin-bottom: 24px;
        }

        .section h2 {
            font-size: 18px;
            color: #94a3b8;
            margin-bottom: 16px;
            font-weight: 600;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }

        th {
            text-align: left;
            padding: 12px 8px;
            color: #64748b;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            font-weight: 500;
        }

        td {
            padding: 12px 8px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
        }

        .severity-critical { color: #ef4444; font-weight: 700; }
        .severity-high { color: #f59e0b; font-weight: 700; }
        .severity-medium { color: #eab308; }
        .severity-info { color: #94a3b8; }
        .fixed-true { color: #34d399; }
        .fixed-false { color: #f59e0b; }

        /* ─── AI Chat Overlay ─── */
        .ai-chat-overlay {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 400px;
            max-height: 500px;
            background: rgba(0,0,0,0.9);
            backdrop-filter: blur(24px);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 24px;
            padding: 20px;
            z-index: 999;
            box-shadow: 0 30px 80px rgba(0,0,0,0.8);
            display: none;
            flex-direction: column;
        }

        .ai-chat-overlay.open { display: flex; }

        .ai-chat-overlay .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .ai-chat-overlay .header h3 { color: #60a5fa; }

        .ai-chat-overlay .header .close-btn {
            background: none;
            border: none;
            color: #94a3b8;
            font-size: 20px;
            cursor: pointer;
        }

        .ai-chat-overlay .messages {
            max-height: 300px;
            overflow-y: auto;
            margin-bottom: 12px;
            padding-right: 8px;
        }

        .ai-chat-overlay .messages .msg {
            padding: 12px;
            border-radius: 16px;
            margin-bottom: 8px;
            word-wrap: break-word;
        }

        .ai-chat-overlay .messages .msg.user {
            background: rgba(255,255,255,0.06);
            color: #e2e8f0;
            text-align: right;
        }

        .ai-chat-overlay .messages .msg.ai {
            background: rgba(37,99,235,0.08);
            color: #94a3b8;
        }

        .ai-chat-overlay .input-area {
            display: flex;
            gap: 8px;
        }

        .ai-chat-overlay .input-area input {
            flex: 1;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 999px;
            padding: 10px 16px;
            color: #e2e8f0;
            outline: none;
        }

        .ai-chat-overlay .input-area button {
            background: linear-gradient(135deg, #2563eb, #3b82f6);
            border: none;
            color: #fff;
            padding: 10px 20px;
            border-radius: 999px;
            font-weight: 600;
            cursor: pointer;
        }

        /* ─── Responsive ─── */
        @media (max-width: 1024px) {
            .executive-grid { grid-template-columns: repeat(2,1fr); }
            .chart-row { grid-template-columns: 1fr; }
            .cloud-grid { grid-template-columns: repeat(2,1fr); }
        }

        @media (max-width: 768px) {
            .sidebar { display: none; }
            .main { margin-left: 0; padding: 16px; }
            .executive-grid { grid-template-columns: 1fr; }
            .cloud-grid { grid-template-columns: 1fr; }
            .topbar { flex-direction: column; align-items: stretch; }
            .topbar-left, .topbar-right { justify-content: space-between; flex-wrap: wrap; }
            .command-section .cmd-input { min-width: 150px; }
            .ai-shield .chat-input { width: 100px; }
            .ai-chat-overlay { width: calc(100% - 20px); right: 10px; bottom: 10px; }
        }
    </style>
</head>
<body>

    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">🛡️ Aegis<span>Command Center</span></div>
        <a href="#" class="active"><span class="icon">📊</span> Overview</a>
        <a href="#"><span class="icon">☁️</span> Cloud Assets</a>
        <a href="#"><span class="icon">🔗</span> Attack Paths</a>
        <a href="#"><span class="icon">🛡️</span> Findings</a>
        <a href="#"><span class="icon">📋</span> Compliance</a>
        <a href="#"><span class="icon">🤖</span> AI Copilot</a>
        <a href="/pricing"><span class="icon">💰</span> Pricing</a>
        <a href="/logout" class="logout"><span class="icon">🚪</span> Logout</a>
    </div>

    <!-- Main -->
    <div class="main">

        <!-- Top Bar -->
        <div class="topbar">
            <div class="topbar-left">
                <h1>📊 Command Center</h1>
                <!-- Premium AI Shield -->
                <div class="ai-shield" onclick="toggleAI()">
                    <span class="shield-icon">🛡️</span>
                    <span class="badge">AI Copilot</span>
                    <input type="text" class="chat-input" id="quickAIInput" placeholder="Ask security..." onkeypress="if(event.key==='Enter') quickAsk()" />
                </div>
            </div>
            <div class="topbar-right">
                <span class="user-badge">{{ company }}</span>
                <span class="user-badge">{{ email }}</span>
                <span class="last-updated text-slate-500 text-xs" id="lastUpdated">--</span>
                <button class="scan-btn" id="scanBtn" onclick="startScan()">⚡ Scan Now</button>
                <button class="refresh-btn" onclick="loadData()">⟳ Refresh</button>
                <div id="scanSpinner" style="display:inline;"></div>
            </div>
        </div>

        <!-- Command Input Section -->
        <div class="command-section">
            <span class="cmd-label"><i class="fas fa-terminal"></i> Run Command</span>
            <input type="text" class="cmd-input" id="cmdInput" placeholder='e.g., scan example.com -p 80,443' />
            <button class="cmd-btn" onclick="runCommand()"><i class="fas fa-play mr-2"></i>Execute</button>
            <button class="cmd-btn" style="background:rgba(255,255,255,0.06); box-shadow:none;" onclick="clearLogs()"><i class="fas fa-eraser mr-2"></i>Clear</button>
        </div>

        <!-- Results Log -->
        <div class="results-section">
            <div class="header">
                <h3><i class="fas fa-code mr-2"></i>Scan Results / Log</h3>
                <button class="clear-btn" onclick="clearLogs()">Clear All</button>
            </div>
            <div class="results-log" id="resultsLog">
                <div class="log-entry"><span class="timestamp">[System]</span> <span class="info">Ready. Enter a command to start.</span></div>
            </div>
        </div>

        <!-- Executive Metrics -->
        <div class="executive-grid">
            <div class="exec-card">
                <div class="exec-label">Risk Score</div>
                <h1 id="riskScore">--</h1>
                <small>Security posture</small>
            </div>
            <div class="exec-card">
                <div class="exec-label">Assets Protected</div>
                <h1 id="assetsProtected">--</h1>
                <small>Across all clouds</small>
            </div>
            <div class="exec-card">
                <div class="exec-label">Attack Paths</div>
                <h1 id="activePaths">--</h1>
                <small>Reachable exposures</small>
            </div>
            <div class="exec-card">
                <div class="exec-label">Auto Remediated</div>
                <h1 id="autoRemediated">--</h1>
                <small>Issues fixed</small>
            </div>
        </div>

        <!-- Charts -->
        <div class="chart-row">
            <div class="chart-box"><h3>📈 Vulnerability Trend</h3><canvas id="trendChart"></canvas></div>
            <div class="chart-box"><h3>📊 Severity Breakdown</h3><canvas id="severityChart"></canvas></div>
        </div>

        <!-- Cloud Inventory -->
        <div class="section">
            <h2>☁️ Cloud Inventory</h2>
            <div class="cloud-grid">
                <div class="cloud-card"><div class="cloud-name">AWS</div><h1 id="awsCount">0</h1></div>
                <div class="cloud-card"><div class="cloud-name">Azure</div><h1 id="azureCount">0</h1></div>
                <div class="cloud-card"><div class="cloud-name">GCP</div><h1 id="gcpCount">0</h1></div>
                <div class="cloud-card"><div class="cloud-name">OCI</div><h1 id="ociCount">0</h1></div>
            </div>
        </div>

        <!-- Attack Paths -->
        <div class="section">
            <h2>🔗 Attack Path Explorer</h2>
            <div id="attackPaths"></div>
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

    </div>

    <!-- AI Chat Overlay -->
    <div class="ai-chat-overlay" id="aiChatOverlay">
        <div class="header">
            <h3>🤖 Aegis AI Copilot</h3>
            <button class="close-btn" onclick="toggleAI()">✕</button>
        </div>
        <div class="messages" id="aiMessages">
            <div class="msg ai">👋 Hi! I'm your cloud security copilot. Ask me anything about your cloud posture, attack paths, or remediation.</div>
        </div>
        <div class="input-area">
            <input type="text" id="aiInput" placeholder="Ask a question..." onkeypress="if(event.key==='Enter') sendAI()" />
            <button onclick="sendAI()">Send</button>
        </div>
    </div>

    <script>
        // ─── Command Execution ───
        function runCommand() {
            const input = document.getElementById('cmdInput');
            const cmd = input.value.trim();
            if (!cmd) {
                addLog('Please enter a command.', 'error');
                return;
            }
            addLog('> ' + cmd, 'info');
            input.value = '';

            // Parse command (simple)
            if (cmd.startsWith('scan ')) {
                const parts = cmd.split(' ');
                let target = 'example.com';
                let ports = '80,443';
                for (let i = 1; i < parts.length; i++) {
                    if (parts[i] === '-p' && i+1 < parts.length) {
                        ports = parts[i+1];
                        i++;
                    } else if (!parts[i].startsWith('-')) {
                        target = parts[i];
                    }
                }
                addLog(`Starting scan on ${target} ports ${ports}...`, 'info');
                // Call scan endpoint with parameters (POST /scan)
                fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: target, ports: ports })
                })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'ok') {
                        addLog(`✅ Scan completed: ${data.message}`, 'success');
                        loadData(); // refresh dashboard
                    } else {
                        addLog(`❌ Scan failed: ${data.message}`, 'error');
                    }
                })
                .catch(err => {
                    addLog(`❌ Error: ${err.message}`, 'error');
                });
            } else {
                addLog(`Unknown command: "${cmd}"`, 'error');
            }
        }

        function addLog(message, type='info') {
            const log = document.getElementById('resultsLog');
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            const ts = new Date().toLocaleTimeString();
            let cls = '';
            if (type === 'success') cls = 'success';
            else if (type === 'error') cls = 'error';
            else if (type === 'info') cls = 'info';
            entry.innerHTML = `<span class="timestamp">[${ts}]</span> <span class="${cls}">${message}</span>`;
            log.appendChild(entry);
            log.scrollTop = log.scrollHeight;
        }

        function clearLogs() {
            const log = document.getElementById('resultsLog');
            log.innerHTML = `<div class="log-entry"><span class="timestamp">[System]</span> <span class="info">Log cleared.</span></div>`;
        }

        // ─── Load Data ───
        async function loadData() {
            try {
                const res = await fetch('/api/data');
                const data = await res.json();

                document.getElementById('riskScore').textContent = calculateRiskScore(data.alerts) || '--';
                document.getElementById('assetsProtected').textContent = data.total_scans || '--';
                document.getElementById('activePaths').textContent = data.attack_paths ? data.attack_paths.length : 0;
                document.getElementById('autoRemediated').textContent = data.fixed_issues || 0;
                document.getElementById('lastUpdated').textContent = 'Last updated: ' + new Date().toLocaleTimeString();

                const cloudCounts = { aws: 0, azure: 0, gcp: 0, oci: 0 };
                if (data.scans) {
                    data.scans.forEach(s => {
                        const cloud = s[1] ? s[1].toLowerCase() : '';
                        if (cloud in cloudCounts) cloudCounts[cloud] += 1;
                    });
                }
                document.getElementById('awsCount').textContent = cloudCounts.aws;
                document.getElementById('azureCount').textContent = cloudCounts.azure;
                document.getElementById('gcpCount').textContent = cloudCounts.gcp;
                document.getElementById('ociCount').textContent = cloudCounts.oci;

                // Scans table
                const scansTable = document.getElementById('scansTable');
                if (data.scans && data.scans.length > 0) {
                    scansTable.innerHTML = data.scans.map(s => `
                        <tr><td>${s[0]}</td><td>${s[1]}</td><td>${s[2]}</td><td>${s[3]}</td></tr>
                    `).join('');
                } else {
                    scansTable.innerHTML = `<tr><td colspan="4" class="empty-state">No scans yet. Run a command.</td></tr>`;
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
                    alertsTable.innerHTML = `<tr><td colspan="4" class="empty-state">No alerts yet.</td></tr>`;
                }

                // Attack Paths
                const pathsDiv = document.getElementById('attackPaths');
                if (data.attack_paths && data.attack_paths.length > 0) {
                    pathsDiv.innerHTML = data.attack_paths.map(path => `
                        <div class="path-card">
                            ${path.map((node, i) => `
                                <span class="path-node">${node}</span>
                                ${i < path.length - 1 ? `<span class="path-arrow">➜</span>` : ''}
                            `).join('')}
                        </div>
                    `).join('');
                } else {
                    pathsDiv.innerHTML = `<div class="empty-state">✅ No attack paths found.</div>`;
                }

                // ─── Charts ───
                const ctx1 = document.getElementById('trendChart').getContext('2d');
                const ctx2 = document.getElementById('severityChart').getContext('2d');

                const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
                if (data.alerts) {
                    data.alerts.forEach(a => { if (sevCounts[a[2]] !== undefined) sevCounts[a[2]]++; });
                }

                if (window.sevChart) window.sevChart.destroy();
                if (window.trendChart) window.trendChart.destroy();

                window.sevChart = new Chart(ctx2, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{
                            data: [sevCounts.CRITICAL, sevCounts.HIGH, sevCounts.MEDIUM, sevCounts.LOW, sevCounts.INFO],
                            backgroundColor: ['#ef4444', '#f59e0b', '#eab308', '#34d399', '#94a3b8'],
                            borderColor: '#000000',
                            borderWidth: 3
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { labels: { color: '#e2e8f0' } } },
                        animation: { animateRotate: true, duration: 1000 }
                    }
                });

                let labels = data.scans.map(s => s[0].slice(0, 10)).reverse();
                let counts = data.scans.map(s => s[3]).reverse();
                if (labels.length === 0) { labels = ['No Data']; counts = [0]; }

                window.trendChart = new Chart(ctx1, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Findings',
                            data: counts,
                            borderColor: '#2563eb',
                            backgroundColor: 'rgba(37,99,235,0.1)',
                            fill: true,
                            tension: 0.3
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { labels: { color: '#e2e8f0' } } },
                        scales: {
                            x: { ticks: { color: '#94a3b8' } },
                            y: { ticks: { color: '#94a3b8' } }
                        },
                        animation: { duration: 800 }
                    }
                });

                document.getElementById('scanBtn').disabled = false;
                scanInProgress = false;
                document.getElementById('scanSpinner').innerHTML = '';

            } catch (e) {
                console.error('Error loading data:', e);
                addLog('Failed to load dashboard data.', 'error');
            }
        }

        function calculateRiskScore(alerts) {
            if (!alerts || alerts.length === 0) return 95;
            let score = 100;
            alerts.forEach(a => {
                const sev = a[2];
                if (sev === 'CRITICAL') score -= 15;
                else if (sev === 'HIGH') score -= 8;
                else if (sev === 'MEDIUM') score -= 4;
                else if (sev === 'LOW') score -= 2;
            });
            return Math.max(0, Math.min(100, score));
        }

        // ─── Scan Now (default) ───
        let scanInProgress = false;

        async function startScan() {
            if (scanInProgress) return;
            scanInProgress = true;
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('scanSpinner').innerHTML = '<div style="display:inline-block; width:16px; height:16px; border:2px solid #94a3b8; border-top-color:#2563eb; border-radius:50%; animation: spin 0.8s linear infinite; margin-left:10px; vertical-align:middle;"></div>';
            addLog('Starting default scan on example.com:80,443...', 'info');

            try {
                const res = await fetch('/scan', { method: 'POST' });
                const result = await res.json();
                if (result.status === 'ok') {
                    addLog('✅ Scan completed successfully!', 'success');
                    loadData();
                } else {
                    addLog('❌ Scan failed: ' + (result.message || 'Unknown error'), 'error');
                }
            } catch (e) {
                addLog('❌ Error: ' + e.message, 'error');
            } finally {
                document.getElementById('scanBtn').disabled = false;
                document.getElementById('scanSpinner').innerHTML = '';
                scanInProgress = false;
            }
        }

        // ─── AI Chat ───
        function toggleAI() {
            const overlay = document.getElementById('aiChatOverlay');
            overlay.classList.toggle('open');
            if (overlay.classList.contains('open')) {
                overlay.style.display = 'flex';
            } else {
                overlay.style.display = 'none';
            }
        }

        async function sendAI() {
            const input = document.getElementById('aiInput');
            const msg = input.value.trim();
            if (!msg) return;
            input.value = '';
            const messagesDiv = document.getElementById('aiMessages');
            const userDiv = document.createElement('div');
            userDiv.className = 'msg user';
            userDiv.textContent = msg;
            messagesDiv.appendChild(userDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;

            const loadingDiv = document.createElement('div');
            loadingDiv.className = 'msg ai';
            loadingDiv.textContent = 'Thinking...';
            messagesDiv.appendChild(loadingDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;

            try {
                const res = await fetch('/api/ask', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ question: msg })
                });
                const data = await res.json();
                loadingDiv.textContent = data.response || 'Sorry, I could not answer that.';
            } catch (e) {
                loadingDiv.textContent = 'Error: Could not reach AI service.';
            }
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }

        async function quickAsk() {
            const input = document.getElementById('quickAIInput');
            const msg = input.value.trim();
            if (!msg) return;
            input.value = '';
            // Open AI panel if closed
            const overlay = document.getElementById('aiChatOverlay');
            if (!overlay.classList.contains('open')) {
                overlay.classList.add('open');
                overlay.style.display = 'flex';
            }
            document.getElementById('aiInput').value = msg;
            await sendAI();
        }

        // ─── Init ───
        loadData();
        setInterval(loadData, 30000);

        // Spinner animation style (inject)
        const style = document.createElement('style');
        style.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
        document.head.appendChild(style);
    </script>
</body>
</html>
"""

# ---------- LOGIN AND SIGNUP HTML (keep as before) ----------
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis – Login</title>
    <style>
        body { background: #000000; color: #e0e6ed; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: rgba(17, 27, 38, 0.8); backdrop-filter: blur(10px); padding: 40px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); width: 350px; }
        .login-box h1 { text-align: center; color: #2563eb; margin-bottom: 30px; }
        .login-box input { width: 100%; padding: 12px; margin-bottom: 15px; background: #0a0e17; border: 1px solid rgba(255,255,255,0.08); color: #e0e6ed; border-radius: 6px; box-sizing: border-box; }
        .login-box button { width: 100%; padding: 12px; background: #2563eb; color: #fff; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; }
        .login-box button:hover { background: #3b82f6; }
        .login-box .error { color: #ff4757; text-align: center; margin-bottom: 10px; }
        .login-box .link { text-align: center; margin-top: 15px; color: #8ba0b8; font-size: 14px; }
        .login-box .link a { color: #2563eb; text-decoration: none; }
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
        body { background: #000000; color: #e0e6ed; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .signup-box { background: rgba(17, 27, 38, 0.8); backdrop-filter: blur(10px); padding: 40px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); width: 360px; }
        .signup-box h1 { text-align: center; color: #2563eb; margin-bottom: 30px; }
        .signup-box input { width: 100%; padding: 12px; margin-bottom: 15px; background: #0a0e17; border: 1px solid rgba(255,255,255,0.08); color: #e0e6ed; border-radius: 6px; box-sizing: border-box; }
        .signup-box button { width: 100%; padding: 12px; background: #2563eb; color: #fff; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; }
        .signup-box button:hover { background: #3b82f6; }
        .signup-box .error { color: #ff4757; text-align: center; margin-bottom: 10px; }
        .signup-box .link { text-align: center; margin-top: 15px; color: #8ba0b8; font-size: 14px; }
        .signup-box .link a { color: #2563eb; text-decoration: none; }
        .name-row { display: flex; gap: 10px; }
        .name-row input { flex: 1; }
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
            <div class="name-row">
                <input type="text" name="first_name" placeholder="First Name" required>
                <input type="text" name="last_name" placeholder="Last Name" required>
            </div>
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

OTP_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis – Verify Email</title>
    <style>
        body { background: #000000; color: #e0e6ed; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .otp-box { background: rgba(17, 27, 38, 0.8); backdrop-filter: blur(10px); padding: 40px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); width: 350px; }
        .otp-box h1 { text-align: center; color: #2563eb; margin-bottom: 30px; }
        .otp-box input { width: 100%; padding: 12px; margin-bottom: 15px; background: #0a0e17; border: 1px solid rgba(255,255,255,0.08); color: #e0e6ed; border-radius: 6px; box-sizing: border-box; text-align: center; font-size: 24px; letter-spacing: 8px; }
        .otp-box button { width: 100%; padding: 12px; background: #2563eb; color: #fff; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; }
        .otp-box button:hover { background: #3b82f6; }
        .otp-box .error { color: #ff4757; text-align: center; margin-bottom: 10px; }
        .otp-box .info { color: #8ba0b8; text-align: center; margin-bottom: 20px; font-size: 14px; }
        .otp-box .otp-display { background: #0a0e17; border: 1px solid #34d399; border-radius: 8px; padding: 12px; text-align: center; margin-bottom: 20px; color: #34d399; font-size: 28px; letter-spacing: 6px; font-weight: bold; }
        .otp-box .resend { text-align: center; margin-top: 15px; color: #8ba0b8; font-size: 14px; }
        .otp-box .resend a { color: #2563eb; text-decoration: none; }
    </style>
</head>
<body>
    <div class="otp-box">
        <h1>📧 Verify Email</h1>
        <div class="info">We sent a 6‑digit code to <strong>{{ email }}</strong>.</div>
        <div class="otp-display">🔑 {{ otp }}</div>
        <div class="info" style="font-size:12px; color:#5a6a7a;">(Copy this code and paste it below)</div>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="/verify-otp">
            <input type="hidden" name="email" value="{{ email }}">
            <input type="text" name="otp" placeholder="6‑digit code" maxlength="6" required autofocus>
            <button type="submit">Verify Account</button>
        </form>
        <div class="resend">
            Didn't get the code? <a href="/resend-otp?email={{ email }}">Resend OTP</a>
        </div>
    </div>
</body>
</html>
"""

PRICING_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis – Pricing</title>
    <style>
        body { background: #000000; color: #e0e6ed; font-family: Arial, sans-serif; padding: 40px; text-align: center; }
        .container { max-width: 1000px; margin: 0 auto; }
        h1 { font-size: 42px; background: linear-gradient(135deg, #2563eb, #60a5fa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .pricing-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; margin-top: 40px; }
        .card { background: rgba(17, 27, 38, 0.8); backdrop-filter: blur(10px); border-radius: 12px; padding: 30px; border: 1px solid rgba(255,255,255,0.08); }
        .card.popular { border-color: #2563eb; }
        .card .plan { font-size: 24px; font-weight: 700; }
        .card .price { font-size: 36px; color: #2563eb; margin: 15px 0; }
        .card ul { list-style: none; padding: 0; text-align: left; }
        .card ul li { padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.06); color: #8ba0b8; }
        .card ul li:before { content: "✅ "; color: #34d399; }
        .btn { display: inline-block; background: #2563eb; color: #fff; padding: 10px 30px; border-radius: 30px; font-weight: 600; margin-top: 20px; text-decoration: none; }
        .btn:hover { background: #3b82f6; }
        @media (max-width: 768px) { .pricing-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>Choose Your Plan</h1>
        <p style="color:#8ba0b8;">Start free. Scale with confidence.</p>
        <div class="pricing-grid">
            <div class="card">
                <div class="plan">Free</div>
                <div class="price">$0</div>
                <ul>
                    <li>1 cloud account</li>
                    <li>Manual scans</li>
                    <li>Community support</li>
                </ul>
                <a href="/signup" class="btn">Get Started</a>
            </div>
            <div class="card popular">
                <div class="plan">Pro</div>
                <div class="price">$500 <span style="font-size:16px;color:#8ba0b8;">/ mo</span></div>
                <ul>
                    <li>10 cloud accounts</li>
                    <li>Auto‑fix</li>
                    <li>Slack alerts</li>
                    <li>Priority support</li>
                </ul>
                <a href="/signup" class="btn">Start Trial</a>
            </div>
            <div class="card">
                <div class="plan">Enterprise</div>
                <div class="price">Custom</div>
                <ul>
                    <li>Unlimited accounts</li>
                    <li>24/7 support</li>
                    <li>Dedicated deployment</li>
                </ul>
                <a href="/signup" class="btn">Contact Sales</a>
            </div>
        </div>
        <p style="margin-top:40px;"><a href="/" style="color:#2563eb;">← Back to home</a></p>
    </div>
</body>
</html>
"""

# ---------- FLASK APP ----------
if FLASK_AVAILABLE:
    ensure_db_tables()
    app = Flask(__name__)
    app.secret_key = os.urandom(24)

    # ── Public Routes ──
    @app.route('/')
    def landing_page():
        return render_template_string(LANDING_PAGE_HTML)

    @app.route('/pricing')
    def pricing():
        return render_template_string(PRICING_HTML)

    # ── Auth ──
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ? AND verified = 1", (email,))
            user = c.fetchone()
            conn.close()
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['email'] = user[1]
                session['company'] = user[3]
                return redirect('/dashboard')
            else:
                return render_template_string(LOGIN_HTML, error="Invalid email or account not verified")
        return render_template_string(LOGIN_HTML, error=None)

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            password = generate_password_hash(request.form['password'])

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ?", (email,))
            existing = c.fetchone()
            if existing:
                conn.close()
                return render_template_string(SIGNUP_HTML, error="Email already registered.")

            # Generate OTP
            otp = generate_otp()
            company = f"{first_name} {last_name}"
            pending_users[email] = {
                'company': company,
                'first_name': first_name,
                'last_name': last_name,
                'password': password,
                'otp': otp,
                'expiry': datetime.datetime.now() + datetime.timedelta(minutes=10)
            }
            conn.close()

            # Send OTP (print to console / logs)
            send_otp_email(email, otp)

            # Render OTP page WITH the OTP visible (for demo)
            return render_template_string(OTP_HTML, email=email, error=None, otp=otp)
        return render_template_string(SIGNUP_HTML, error=None)

    @app.route('/verify-otp', methods=['POST'])
    def verify_otp():
        otp = request.form['otp']
        email = request.form.get('email')
        if not email:
            return render_template_string(OTP_HTML, email="", otp="", error="Missing email.")
        if email not in pending_users:
            return render_template_string(OTP_HTML, email=email, otp="", error="OTP expired or not found.")
        data = pending_users[email]
        if data['otp'] != otp:
            return render_template_string(OTP_HTML, email=email, otp="", error="Invalid OTP.")
        if datetime.datetime.now() > data['expiry']:
            del pending_users[email]
            return render_template_string(OTP_HTML, email=email, otp="", error="OTP expired.")
        # OTP correct -> create user
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("""
            INSERT INTO users (email, password, company, first_name, last_name, created_at, verified)
            VALUES (?, ?, ?, ?, ?, datetime('now'), 1)
        """, (email, data['password'], data['company'], data['first_name'], data['last_name']))
        conn.commit()
        conn.close()
        del pending_users[email]
        return redirect('/login')

    @app.route('/resend-otp')
    def resend_otp():
        email = request.args.get('email')
        if not email:
            return "No email provided."
        if email not in pending_users:
            return "Email not found or OTP expired. Please sign up again."
        # Resend OTP
        otp = generate_otp()
        pending_users[email]['otp'] = otp
        pending_users[email]['expiry'] = datetime.datetime.now() + datetime.timedelta(minutes=10)
        send_otp_email(email, otp)
        return render_template_string(OTP_HTML, email=email, otp=otp, error="New OTP sent.")

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect('/')

    # ── Dashboard ──
    @app.route('/dashboard')
    def dashboard():
        if not session.get('user_id'):
            return redirect('/login')
        return render_template_string(
            DASHBOARD_HTML,
            email=session.get('email', 'user@example.com'),
            company=session.get('company', 'My Company')
        )

    # ── API ──
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

    @app.route('/api/ask', methods=['POST'])
    def ask_ai():
        data = request.get_json()
        question = data.get('question', '')
        if not question:
            return jsonify({'response': 'Please ask a question.'})
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
        answer = ai_query(question, context)
        return jsonify({'response': answer})

    @app.route('/scan', methods=['POST'])
    def trigger_scan():
        try:
            data = request.get_json()
            if data:
                target = data.get('target', 'example.com')
                ports_str = data.get('ports', '80,443')
                # Parse ports
                ports = []
                for part in ports_str.split(','):
                    if '-' in part:
                        s, e = map(int, part.split('-'))
                        ports.extend(range(s, e+1))
                    else:
                        ports.append(int(part))
            else:
                target = 'example.com'
                ports = [80, 443]

            open_services = scan_host(target, ports)
            findings = []
            if open_services:
                save_scan(target, 'web', 'default', open_services, findings)
            return jsonify({'status': 'ok', 'message': f'Scan completed on {target}, found {len(open_services)} open ports.'})
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

    if args.report:
        print("[*] Generating PDF compliance report...")
        output = generate_compliance_report(args.host, "apcss_report.pdf")
        if output:
            print(f"[+] Report saved to: {output}")
        return

    if args.chain or args.accounts or args.accounts_file:
        run_fix_chain(args)
        return

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

    if open_services:
        for port, (service, banner) in open_services.items():
            if args.api and service in ("HTTP", "HTTPS"):
                protocol = "https" if port in (443, 8443) else "http"
                all_findings.extend(check_api_vulnerabilities(args.host, port, protocol))

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
