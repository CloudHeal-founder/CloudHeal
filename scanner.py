#!/usr/bin/env python3
"""
Aegis – Full SaaS with Free & Premium tiers
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
import hashlib
from typing import Dict, List, Tuple, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

# ----- FLASK AUTHENTICATION IMPORTS -----
from flask import Flask, render_template_string, jsonify, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----- Optional Cloud SDKs (free tier doesn't need them) -----
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

# ----- Table Formatting -----
try:
    from tabulate import tabulate
except ImportError:
    print("Install tabulate: pip install tabulate")
    sys.exit(1)

# ----- AI (optional) -----
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

# ---------- Database Setup ----------
DB_NAME = "apcss_global.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Scans table
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        timestamp TEXT,
        target TEXT,
        cloud TEXT,
        account TEXT,
        open_ports TEXT,
        findings TEXT,
        total_open_ports INTEGER,
        total_findings INTEGER,
        status TEXT DEFAULT 'completed'
    )''')
    # Alerts table
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        timestamp TEXT,
        cloud TEXT,
        account TEXT,
        message TEXT,
        severity TEXT,
        fixed INTEGER DEFAULT 0
    )''')
    # Users table (with plan)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        company TEXT,
        first_name TEXT,
        last_name TEXT,
        created_at TEXT,
        verified INTEGER DEFAULT 0,
        plan TEXT DEFAULT 'free'   -- 'free' or 'premium'
    )''')
    conn.commit()
    conn.close()

def get_user_plan(user_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT plan FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else 'free'

def is_premium(user_id):
    return get_user_plan(user_id) == 'premium'

def save_scan(user_id, target, cloud, account, open_services, findings):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    ts = datetime.datetime.now().isoformat()
    c.execute('''INSERT INTO scans (user_id, timestamp, target, cloud, account, open_ports, findings, total_open_ports, total_findings)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (user_id, ts, target, cloud, account,
               json.dumps(list(open_services.keys())),
               json.dumps(findings),
               len(open_services), len(findings)))
    conn.commit()
    conn.close()

def save_alert(user_id, cloud, account, message, severity, fixed=False):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    ts = datetime.datetime.now().isoformat()
    c.execute('INSERT INTO alerts (user_id, timestamp, cloud, account, message, severity, fixed) VALUES (?, ?, ?, ?, ?, ?, ?)',
              (user_id, ts, cloud, account, message, severity, 1 if fixed else 0))
    conn.commit()
    conn.close()

def get_scan_history(user_id, limit=10):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT timestamp, target, cloud, total_open_ports, total_findings FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT ?', (user_id, limit))
    rows = c.fetchall()
    conn.close()
    return rows

def get_alerts(user_id, limit=20):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT timestamp, cloud, account, message, severity, fixed FROM alerts WHERE user_id = ? ORDER BY id DESC LIMIT ?', (user_id, limit))
    rows = c.fetchall()
    conn.close()
    return rows

def get_latest_scan_findings(user_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT findings FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 1', (user_id,))
    row = c.fetchone()
    conn.close()
    return json.loads(row[0]) if row and row[0] else []

# ---------- Core Scanning Functions ----------
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached", 5000: "Flask/API",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

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

# ---------- Web Security Checks (free) ----------
def discover_directories(target_url, wordlist=None):
    if not wordlist:
        wordlist = ["admin", "login", "wp-admin", "backup", ".env", "phpinfo", "server-status", "api", "docs", "config"]
    findings = []
    for word in wordlist:
        test_url = f"{target_url.rstrip('/')}/{word}"
        try:
            resp = requests.get(test_url, timeout=3, verify=False, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                findings.append({
                    "path": test_url,
                    "status": resp.status_code,
                    "risk": "MEDIUM" if resp.status_code == 200 else "LOW"
                })
        except:
            continue
    return findings

def test_sqli(target_url):
    payloads = ["' OR 1=1 --", "' OR 1=1 #", "' UNION SELECT 1,2,3 --"]
    findings = []
    if '?' in target_url:
        base, qs = target_url.split('?', 1)
        params = [p.split('=')[0] for p in qs.split('&') if '=' in p]
        for param in params:
            for payload in payloads:
                test_url = f"{base}?{param}={payload}"
                try:
                    resp = requests.get(test_url, timeout=3, verify=False)
                    if "error" in resp.text.lower() or "sql" in resp.text.lower():
                        findings.append({"url": test_url, "payload": payload, "risk": "CRITICAL"})
                        break
                except:
                    continue
    return findings

def test_xss(target_url):
    payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    findings = []
    if '?' in target_url:
        base, qs = target_url.split('?', 1)
        params = [p.split('=')[0] for p in qs.split('&') if '=' in p]
        for param in params:
            for payload in payloads:
                test_url = f"{base}?{param}={payload}"
                try:
                    resp = requests.get(test_url, timeout=3, verify=False)
                    if payload in resp.text:
                        findings.append({"url": test_url, "payload": payload, "risk": "HIGH"})
                        break
                except:
                    continue
    return findings

# ---------- Cloud Checks (premium) ----------
def check_aws_s3_public(account_name=None):
    findings = []
    if not AWS_AVAILABLE:
        findings.append(("AWS SDK missing. Install boto3", "AWS", 0.0, "INFO"))
        return findings
    try:
        s3 = boto3.client('s3', verify=False)
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            name = bucket['Name']
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl['Grants']:
                    uri = grant.get('Grantee', {}).get('URI', '')
                    if 'AllUsers' in uri:
                        findings.append((f"S3 bucket '{name}' is PUBLIC!", "AWS", 8.0, "CRITICAL"))
                        break
            except:
                continue
    except ClientError as e:
        findings.append((f"AWS Error: {str(e)[:50]}", "AWS", 0.0, "INFO"))
    return findings

def check_aws_security_groups(account_name=None):
    findings = []
    if not AWS_AVAILABLE:
        return findings
    try:
        ec2 = boto3.client('ec2', verify=False)
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            group_id = sg['GroupId']
            group_name = sg['GroupName']
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port = rule.get('FromPort')
                        findings.append((f"SG '{group_name}' allows 0.0.0.0/0 on port {port}", "AWS", 8.5, "CRITICAL"))
    except:
        pass
    return findings

def check_gcp_storage_public(project_id=None):
    findings = []
    if not GCP_AVAILABLE:
        findings.append(("GCP SDK missing. Install google-cloud-storage", "GCP", 0.0, "INFO"))
        return findings
    try:
        client = storage.Client(project=project_id) if project_id else storage.Client()
        for bucket in client.list_buckets():
            policy = bucket.get_iam_policy()
            if 'allUsers' in policy:
                findings.append((f"GCP bucket '{bucket.name}' is PUBLIC!", "GCP", 8.0, "CRITICAL"))
    except Exception as e:
        findings.append((f"GCP Error: {str(e)[:50]}", "GCP", 0.0, "INFO"))
    return findings

def check_azure_blob_public(subscription_id=None):
    findings = []
    if not AZURE_AVAILABLE:
        findings.append(("Azure SDK missing.", "Azure", 0.0, "INFO"))
        return findings
    # Placeholder – full implementation requires more setup
    findings.append(("Azure scanning requires additional configuration.", "Azure", 0.0, "INFO"))
    return findings

def check_oci_storage_public(compartment_id=None):
    findings = []
    if not OCI_AVAILABLE:
        findings.append(("OCI SDK missing. Install oci", "OCI", 0.0, "INFO"))
        return findings
    try:
        config = oci.config.from_file()
        object_storage = oci.object_storage.ObjectStorageClient(config)
        ns = object_storage.get_namespace().data
        buckets = object_storage.list_buckets(ns, compartment_id=compartment_id) if compartment_id else object_storage.list_buckets(ns)
        for bucket in buckets.data:
            if bucket.public_access_type and bucket.public_access_type != "NoPublicAccess":
                findings.append((f"OCI bucket '{bucket.name}' is PUBLIC!", "OCI", 8.0, "CRITICAL"))
    except Exception as e:
        findings.append((f"OCI Error: {str(e)[:50]}", "OCI", 0.0, "INFO"))
    return findings

# ---------- Auto-Fix (premium) ----------
def fix_s3_public(bucket_name, account="default"):
    try:
        s3 = boto3.client('s3', verify=False)
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        return True, f"🔒 S3 bucket '{bucket_name}' is now private."
    except Exception as e:
        return False, f"❌ Failed: {str(e)[:100]}"

def fix_security_group_rule(group_id, port):
    try:
        ec2 = boto3.client('ec2', verify=False)
        ec2.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )
        return True, f"🔒 Removed 0.0.0.0/0 rule on port {port} from SG {group_id}."
    except Exception as e:
        return False, f"❌ Failed: {str(e)[:100]}"

def fix_gcp_bucket_public(bucket_name, project_id=None):
    try:
        client = storage.Client(project=project_id) if project_id else storage.Client()
        bucket = client.get_bucket(bucket_name)
        policy = bucket.get_iam_policy()
        policy['allUsers'] = None
        bucket.set_iam_policy(policy)
        return True, f"🔒 GCP bucket '{bucket_name}' is now private."
    except Exception as e:
        return False, f"❌ Failed: {str(e)[:100]}"

def fix_oci_bucket_public(namespace, bucket_name):
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
        return True, f"🔒 OCI bucket '{bucket_name}' is now private."
    except Exception as e:
        return False, f"❌ Failed: {str(e)[:100]}"

# ---------- PDF Report (premium) ----------
try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

def generate_compliance_report(user_id, target, cloud, account, output_file="apcss_report.pdf"):
    if not FPDF_AVAILABLE:
        return None
    findings = get_latest_scan_findings(user_id)
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("helvetica", "B", 24)
    pdf.cell(0, 40, "Aegis Security Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("helvetica", "", 12)
    pdf.cell(0, 10, f"Target: {target}   Cloud: {cloud}   Account: {account}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Findings Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 10)
    for i, f in enumerate(findings[:20]):
        desc, cat, score, sev = f[0], f[1], f[2], f[3]
        pdf.cell(0, 8, f"{i+1}. [{sev}] {desc[:80]}", new_x="LMARGIN", new_y="NEXT")
    pdf.output(output_file)
    return output_file

# ---------- Flask App ----------
app = Flask(__name__)
app.secret_key = os.urandom(24)

# ---------- HTML Templates (with new beautiful background) ----------
# We'll embed the background CSS in the dashboard template below
# For brevity, I'll show the new dashboard with the background.

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis Security Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        /* ----- GLOBAL RESET & FONTS ----- */
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { 
            background: #0a0e17; 
            color: #e0e6ed; 
            overflow: hidden; 
            height: 100vh;
            position: relative;
        }

        /* ----- ANIMATED SHIELD & CLOUD BACKGROUND ----- */
        .bg-container {
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            z-index: 0;
            overflow: hidden;
            pointer-events: none;
        }
        .bg-container .cloud {
            position: absolute;
            background: radial-gradient(circle at 30% 30%, rgba(0,212,255,0.08), transparent 70%);
            border-radius: 50%;
            filter: blur(40px);
        }
        .bg-container .cloud:nth-child(1) { width: 600px; height: 300px; top: 10%; left: -100px; animation: floatCloud 20s infinite alternate; }
        .bg-container .cloud:nth-child(2) { width: 500px; height: 250px; bottom: 10%; right: -50px; animation: floatCloud 25s infinite alternate-reverse; }
        .bg-container .cloud:nth-child(3) { width: 300px; height: 200px; top: 40%; left: 50%; animation: floatCloud 18s infinite alternate; opacity: 0.5; }
        @keyframes floatCloud {
            0% { transform: translate(0, 0) scale(1); }
            100% { transform: translate(40px, -30px) scale(1.2); }
        }

        /* Shield SVG overlay (pulsing) */
        .shield-overlay {
            position: absolute;
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
            width: 800px;
            height: 800px;
            opacity: 0.06;
            background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><path d="M50 5L5 20v30c0 25 20 40 45 45 25-5 45-20 45-45V20L50 5z" fill="%2300d4ff" stroke="%237b2ffc" stroke-width="2"/><text x="50" y="55" font-size="20" text-anchor="middle" fill="white">🛡️</text></svg>') no-repeat center;
            background-size: contain;
            animation: pulseShield 4s infinite;
            pointer-events: none;
        }
        @keyframes pulseShield {
            0% { opacity: 0.04; transform: translate(-50%, -50%) scale(0.9); }
            50% { opacity: 0.1; transform: translate(-50%, -50%) scale(1.1); }
            100% { opacity: 0.04; transform: translate(-50%, -50%) scale(0.9); }
        }

        /* ----- SIDEBAR & MAIN (keep on top of background) ----- */
        .app-container {
            position: relative;
            z-index: 1;
            display: flex;
            height: 100vh;
        }
        .sidebar {
            width: 220px;
            background: rgba(13, 21, 32, 0.85);
            backdrop-filter: blur(10px);
            border-right: 1px solid #1e2a3a;
            padding: 20px 0;
            height: 100vh;
            overflow-y: auto;
            flex-shrink: 0;
        }
        .sidebar .logo { font-size: 22px; font-weight: 700; background: linear-gradient(135deg, #00d4ff, #7b2ffc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; padding: 0 20px; margin-bottom: 30px; }
        .sidebar a { display: block; padding: 12px 20px; color: #8ba0b8; text-decoration: none; font-size: 14px; border-left: 3px solid transparent; transition: 0.2s; }
        .sidebar a:hover, .sidebar a.active { background: #111b26; color: #e0e6ed; border-left-color: #00d4ff; }
        .sidebar .logout { margin-top: 40px; border-top: 1px solid #1e2a3a; padding-top: 20px; color: #ff4757; }
        .main {
            flex: 1;
            padding: 20px 30px;
            overflow-y: auto;
            height: 100vh;
            background: rgba(10, 14, 23, 0.7);
            backdrop-filter: blur(5px);
        }
        .topbar {
            display: flex; justify-content: space-between; align-items: center;
            padding-bottom: 20px; border-bottom: 1px solid #1e2a3a; margin-bottom: 25px;
            flex-wrap: wrap;
            gap: 10px;
        }
        .topbar h1 { font-size: 24px; background: linear-gradient(135deg, #00d4ff, #7b2ffc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .topbar .user { display: flex; align-items: center; gap: 15px; flex-wrap: wrap; }
        .topbar .user .badge { background: #1e2a3a; padding: 6px 14px; border-radius: 20px; font-size: 12px; color: #8ba0b8; }
        .topbar .user .plan { background: #00d4ff; color: #0a0e17; padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 12px; }
        .scan-btn, .refresh-btn { background: #00d4ff; color: #0a0e17; border: none; padding: 8px 20px; border-radius: 20px; font-weight: bold; cursor: pointer; transition: 0.2s; }
        .scan-btn:hover, .refresh-btn:hover { background: #7b2ffc; color: #fff; }
        .scan-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        /* Scan form */
        .scan-form { background: #111b26; border-radius: 12px; padding: 20px; margin-bottom: 25px; border: 1px solid #1e2a3a; display: flex; flex-wrap: wrap; gap: 15px; align-items: flex-end; }
        .scan-form .field { display: flex; flex-direction: column; gap: 4px; flex: 1 0 150px; }
        .scan-form .field label { font-size: 12px; color: #8ba0b8; }
        .scan-form .field input, .scan-form .field select { padding: 8px 12px; background: #0a0e17; border: 1px solid #1e2a3a; color: #e0e6ed; border-radius: 6px; }
        .scan-form .field input:focus { outline: none; border-color: #00d4ff; }
        .scan-form .submit-btn { background: #7b2ffc; color: #fff; border: none; padding: 10px 24px; border-radius: 20px; font-weight: bold; cursor: pointer; transition: 0.2s; }
        .scan-form .submit-btn:hover { background: #00d4ff; color: #0a0e17; }

        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: rgba(17,27,38,0.8); backdrop-filter: blur(5px); border-radius: 12px; padding: 20px; border: 1px solid #1e2a3a; transition: 0.2s; }
        .stat-card:hover { border-color: #00d4ff; transform: translateY(-3px); }
        .stat-card .number { font-size: 28px; font-weight: 700; color: #00d4ff; }
        .stat-card .label { font-size: 14px; color: #8ba0b8; }
        .stat-card.critical .number { color: #ff4757; }
        .stat-card.fixed .number { color: #2ed573; }

        .chart-row { display: grid; grid-template-columns: 1fr 1fr; gap: 25px; margin-bottom: 30px; }
        .chart-box { background: rgba(17,27,38,0.8); backdrop-filter: blur(5px); border-radius: 12px; padding: 20px; border: 1px solid #1e2a3a; }
        .chart-box h3 { font-size: 16px; color: #8ba0b8; margin-bottom: 15px; }

        .section { background: rgba(17,27,38,0.8); backdrop-filter: blur(5px); border-radius: 12px; padding: 20px; margin-bottom: 20px; border: 1px solid #1e2a3a; }
        .section h2 { font-size: 18px; margin-bottom: 15px; color: #8ba0b8; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th { text-align: left; padding: 10px; color: #8ba0b8; border-bottom: 1px solid #1e2a3a; }
        td { padding: 10px; border-bottom: 1px solid #0d1620; }
        .severity-critical { color: #ff4757; font-weight: bold; }
        .severity-high { color: #ffa502; }
        .severity-medium { color: #eccc68; }
        .severity-info { color: #8ba0b8; }
        .fixed-true { color: #2ed573; }
        .fixed-false { color: #ffa502; }
        .empty { color: #5a6a7a; font-style: italic; }

        .ai-bubble { position: fixed; bottom: 30px; right: 30px; z-index: 999; }
        .ai-bubble button { width: 60px; height: 60px; border-radius: 50%; background: linear-gradient(135deg, #00d4ff, #7b2ffc); border: none; color: #fff; font-size: 30px; cursor: pointer; box-shadow: 0 0 30px rgba(0,212,255,0.3); transition: 0.3s; }
        .ai-bubble button:hover { transform: scale(1.1); }

        @media (max-width: 768px) { .sidebar { display: none; } .chart-row { grid-template-columns: 1fr; } .scan-form { flex-direction: column; } }
    </style>
</head>
<body>
    <!-- Background -->
    <div class="bg-container">
        <div class="cloud"></div>
        <div class="cloud"></div>
        <div class="cloud"></div>
        <div class="shield-overlay"></div>
    </div>

    <!-- App -->
    <div class="app-container">
        <div class="sidebar">
            <div class="logo">🛡️ Aegis</div>
            <a href="#" class="active"><span>📊</span> Dashboard</a>
            <a href="#"><span>🔍</span> Scans</a>
            <a href="#"><span>🔔</span> Alerts</a>
            <a href="/logout" class="logout"><span>🚪</span> Logout</a>
        </div>

        <div class="main">
            <div class="topbar">
                <h1>📊 Dashboard</h1>
                <div class="user">
                    <span class="badge">{{ company }}</span>
                    <span class="plan">{{ plan|upper }}</span>
                    <span class="email">{{ email }}</span>
                    <button class="refresh-btn" onclick="loadData()">⟳ Refresh</button>
                </div>
            </div>

            <!-- Scan Form -->
            <div class="scan-form">
                <div class="field">
                    <label>Target (IP / Domain)</label>
                    <input type="text" id="scanTarget" placeholder="e.g. 192.168.1.1 or example.com" value="scanme.nmap.org">
                </div>
                <div class="field">
                    <label>Port Range</label>
                    <input type="text" id="scanPorts" placeholder="e.g. 1-1024, 80, 443" value="1-1024">
                </div>
                <div class="field">
                    <label>Cloud (premium only)</label>
                    <select id="scanCloud">
                        <option value="none">None</option>
                        <option value="aws">AWS</option>
                        <option value="gcp">GCP</option>
                        <option value="azure">Azure</option>
                        <option value="oci">OCI</option>
                    </select>
                </div>
                <div class="field">
                    <label>Account ID (optional)</label>
                    <input type="text" id="scanAccount" placeholder="e.g. 123456789012">
                </div>
                <button class="submit-btn" onclick="startScan()">🚀 Start Scan</button>
            </div>

            <!-- Stats -->
            <div class="stats" id="stats">
                <div class="stat-card"><div class="number" id="totalScans">-</div><div class="label">📋 Total Scans</div></div>
                <div class="stat-card critical"><div class="number" id="criticalFindings">-</div><div class="label">🔥 Critical</div></div>
                <div class="stat-card fixed"><div class="number" id="fixedIssues">-</div><div class="label">✅ Fixed</div></div>
                <div class="stat-card"><div class="number" id="openPorts">-</div><div class="label">🔌 Open Ports</div></div>
            </div>

            <!-- Charts -->
            <div class="chart-row">
                <div class="chart-box"><h3>📈 Vulnerability Trend</h3><canvas id="trendChart"></canvas></div>
                <div class="chart-box"><h3>📊 Severity Breakdown</h3><canvas id="severityChart"></canvas></div>
            </div>

            <!-- Tables -->
            <div class="section"><h2>📋 Recent Scans</h2><table><thead><tr><th>Timestamp</th><th>Target</th><th>Cloud</th><th>Open Ports</th><th>Findings</th></tr></thead><tbody id="scansTable"></tbody></table></div>
            <div class="section"><h2>🔔 Alerts</h2><table><thead><tr><th>Timestamp</th><th>Message</th><th>Severity</th><th>Fixed</th></tr></thead><tbody id="alertsTable"></tbody></table></div>
        </div>
    </div>

    <!-- AI Assistant -->
    <div class="ai-bubble"><button onclick="toggleAI()">🛡️</button></div>
    <div class="ai-chat" id="aiChat" style="display:none; position:fixed; bottom:100px; right:30px; width:350px; max-height:400px; background:#111b26; border:1px solid #1e2a3a; border-radius:16px; overflow:hidden; z-index:999; flex-direction:column; box-shadow:0 20px 60px rgba(0,0,0,0.8);">
        <div class="header" style="padding:15px 20px; background:#0d1520; border-bottom:1px solid #1e2a3a; display:flex; justify-content:space-between; align-items:center;">
            <h3 style="color:#00d4ff;">🤖 Aegis AI</h3>
            <button class="close" onclick="toggleAI()" style="background:none; border:none; color:#8ba0b8; font-size:20px; cursor:pointer;">✕</button>
        </div>
        <div class="messages" id="aiMessages" style="flex:1; padding:15px; overflow-y:auto; max-height:250px;"></div>
        <div class="input-area" style="display:flex; padding:10px; border-top:1px solid #1e2a3a; background:#0d1520;">
            <input type="text" id="aiInput" placeholder="Ask a question..." onkeypress="if(event.key==='Enter') sendAI()" style="flex:1; padding:10px; border:none; border-radius:8px; background:#0a0e17; color:#e0e6ed; outline:none;">
            <button onclick="sendAI()" style="margin-left:10px; padding:10px 16px; background:#00d4ff; color:#0a0e17; border:none; border-radius:8px; font-weight:bold; cursor:pointer;">Send</button>
        </div>
    </div>

    <script>
        function toggleAI() {
            var chat = document.getElementById('aiChat');
            chat.style.display = chat.style.display === 'none' ? 'flex' : 'none';
        }

        async function sendAI() {
            var input = document.getElementById('aiInput');
            var msg = input.value.trim();
            if (!msg) return;
            input.value = '';
            var container = document.getElementById('aiMessages');
            container.innerHTML += `<div class="msg user" style="text-align:right; margin:5px 0; color:#00d4ff;">${msg}</div>`;
            container.innerHTML += `<div class="msg ai" style="margin:5px 0; color:#8ba0b8;">Thinking...</div>`;
            try {
                var res = await fetch('/api/ask', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({question: msg})
                });
                var data = await res.json();
                var msgs = container.querySelectorAll('.msg');
                msgs[msgs.length-1].textContent = data.response || 'No response.';
            } catch(e) {
                var msgs = container.querySelectorAll('.msg');
                msgs[msgs.length-1].textContent = 'Error: ' + e.message;
            }
            container.scrollTop = container.scrollHeight;
        }

        async function startScan() {
            var target = document.getElementById('scanTarget').value;
            var ports = document.getElementById('scanPorts').value;
            var cloud = document.getElementById('scanCloud').value;
            var account = document.getElementById('scanAccount').value;

            var btn = document.querySelector('.submit-btn');
            btn.disabled = true;
            btn.textContent = '⏳ Scanning...';

            try {
                var res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, ports, cloud, account})
                });
                var data = await res.json();
                if (data.status === 'ok') {
                    alert('Scan started! Results will appear shortly.');
                    setTimeout(loadData, 3000);
                } else {
                    alert('Error: ' + data.message);
                }
            } catch(e) {
                alert('Network error: ' + e.message);
            }
            btn.disabled = false;
            btn.textContent = '🚀 Start Scan';
        }

        async function loadData() {
            try {
                var res = await fetch('/api/data');
                var data = await res.json();
                document.getElementById('totalScans').textContent = data.total_scans || 0;
                document.getElementById('criticalFindings').textContent = data.critical_findings || 0;
                document.getElementById('fixedIssues').textContent = data.fixed_issues || 0;
                document.getElementById('openPorts').textContent = data.open_ports || 0;

                var scansTable = document.getElementById('scansTable');
                if (data.scans && data.scans.length > 0) {
                    scansTable.innerHTML = data.scans.map(s => `<tr><td>${s[0]}</td><td>${s[1]}</td><td>${s[2] || '-'}</td><td>${s[3]}</td><td>${s[4]}</td></tr>`).join('');
                } else {
                    scansTable.innerHTML = `<tr><td colspan="5" class="empty">No scans yet. Use the form above.</td></tr>`;
                }

                var alertsTable = document.getElementById('alertsTable');
                if (data.alerts && data.alerts.length > 0) {
                    alertsTable.innerHTML = data.alerts.map(a => `<tr><td>${a[0]}</td><td>${a[1]}</td><td class="severity-${a[3].toLowerCase()}">${a[3]}</td><td class="fixed-${a[4] ? 'true' : 'false'}">${a[4] ? '✅ Fixed' : '⚠️ Open'}</td></tr>`).join('');
                } else {
                    alertsTable.innerHTML = `<tr><td colspan="4" class="empty">No alerts yet.</td></tr>`;
                }

                // Charts
                var sevCounts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0};
                if (data.alerts) data.alerts.forEach(a => { if (sevCounts[a[3]] !== undefined) sevCounts[a[3]]++; });
                var ctx2 = document.getElementById('severityChart').getContext('2d');
                if (window.sevChart) window.sevChart.destroy();
                window.sevChart = new Chart(ctx2, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical','High','Medium','Low','Info'],
                        datasets: [{
                            data: [sevCounts.CRITICAL, sevCounts.HIGH, sevCounts.MEDIUM, sevCounts.LOW, sevCounts.INFO],
                            backgroundColor: ['#ff4757','#ffa502','#eccc68','#2ed573','#8ba0b8'],
                            borderColor: '#0a0e17',
                            borderWidth: 3
                        }]
                    },
                    options: { responsive: true, plugins: { legend: { labels: { color: '#e0e6ed' } } } }
                });

                var labels = data.scans.map(s => s[0].slice(0, 10)).reverse();
                var counts = data.scans.map(s => s[4]).reverse();
                if (labels.length === 0) { labels = ['No Data']; counts = [0]; }
                var ctx1 = document.getElementById('trendChart').getContext('2d');
                if (window.trendChart) window.trendChart.destroy();
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
                    options: { responsive: true, plugins: { legend: { labels: { color: '#e0e6ed' } } }, scales: { x: { ticks: { color: '#8ba0b8' } }, y: { ticks: { color: '#8ba0b8' } } } }
                });
            } catch(e) {
                console.error('Error loading data:', e);
            }
        }

        loadData();
        setInterval(loadData, 15000);
    </script>
</body>
</html>
"""

# ---------- FLASK ROUTES ----------
@app.route('/')
def landing_page():
    # Return your existing landing page (or we can embed a simple one)
    return render_template_string("""
<!DOCTYPE html>
<html>
<head><title>Aegis – Self-Healing Cloud Security</title>
<style>
    body { background: #0a0e17; color: #e0e6ed; font-family: Arial; text-align: center; padding: 60px; }
    h1 { font-size: 48px; background: linear-gradient(135deg, #00d4ff, #7b2ffc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .btn { background: #00d4ff; color: #0a0e17; padding: 12px 30px; border-radius: 30px; text-decoration: none; font-weight: bold; display: inline-block; margin: 10px; }
    .btn:hover { background: #7b2ffc; color: #fff; }
</style>
</head>
<body>
    <div style="margin-top: 100px;">
        <h1>🛡️ Aegis</h1>
        <p style="font-size: 20px; color: #8ba0b8;">Self-Healing Cloud Security for Everyone</p>
        <a href="/login" class="btn">Login</a>
        <a href="/signup" class="btn">Sign Up</a>
        <br><br>
        <p style="font-size: 14px; color: #5a6a7a;">Free tier includes basic scanning • Premium unlocks cloud, auto-fix, PDF reports</p>
    </div>
</body>
</html>
""")

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
            session['plan'] = user[6]  # plan column
            return redirect('/dashboard')
        else:
            return render_template_string("""
            <html><body style="background:#0a0e17;color:#e0e6ed;text-align:center;padding:60px;">
            <h2>Login</h2>
            <form method="POST">
                <input type="email" name="email" placeholder="Email" required style="padding:10px;margin:10px;border-radius:6px;border:1px solid #1e2a3a;background:#111b26;color:white;"><br>
                <input type="password" name="password" placeholder="Password" required style="padding:10px;margin:10px;border-radius:6px;border:1px solid #1e2a3a;background:#111b26;color:white;"><br>
                <button type="submit" style="padding:10px 30px;background:#00d4ff;border:none;border-radius:30px;font-weight:bold;cursor:pointer;">Login</button>
            </form>
            <p style="color:#ff4757;">Invalid credentials or unverified account.</p>
            <a href="/signup" style="color:#00d4ff;">Sign Up</a>
            </body></html>
            """, error="Invalid credentials")
    return render_template_string("""
    <html><body style="background:#0a0e17;color:#e0e6ed;text-align:center;padding:60px;">
    <h2>Login</h2>
    <form method="POST">
        <input type="email" name="email" placeholder="Email" required style="padding:10px;margin:10px;border-radius:6px;border:1px solid #1e2a3a;background:#111b26;color:white;"><br>
        <input type="password" name="password" placeholder="Password" required style="padding:10px;margin:10px;border-radius:6px;border:1px solid #1e2a3a;background:#111b26;color:white;"><br>
        <button type="submit" style="padding:10px 30px;background:#00d4ff;border:none;border-radius:30px;font-weight:bold;cursor:pointer;">Login</button>
    </form>
    <p><a href="/signup" style="color:#00d4ff;">Create account</a></p>
    </body></html>
    """)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        plan = request.form.get('plan', 'free')  # default free

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            return "Email already registered. <a href='/login'>Login</a>"
        c.execute("INSERT INTO users (email, password, company, first_name, last_name, created_at, verified, plan) VALUES (?, ?, ?, ?, ?, datetime('now'), 1, ?)",
                  (email, password, f"{first_name} {last_name}", first_name, last_name, plan))
        conn.commit()
        conn.close()
        return redirect('/login')
    return render_template_string("""
    <html><body style="background:#0a0e17;color:#e0e6ed;text-align:center;padding:60px;">
    <h2>Sign Up</h2>
    <form method="POST">
        <input type="text" name="first_name" placeholder="First Name" required style="padding:10px;margin:5px;border-radius:6px;border:1px solid #1e2a3a;background:#111b26;color:white;">
        <input type="text" name="last_name" placeholder="Last Name" required style="padding:10px;margin:5px;border-radius:6px;border:1px solid #1e2a3a;background:#111b26;color:white;"><br>
        <input type="email" name="email" placeholder="Email" required style="padding:10px;margin:5px;border-radius:6px;border:1px solid #1e2a3a;background:#111b26;color:white;width:300px;"><br>
        <input type="password" name="password" placeholder="Password" required style="padding:10px;margin:5px;border-radius:6px;border:1px solid #1e2a3a;background:#111b26;color:white;width:300px;"><br>
        <select name="plan" style="padding:10px;margin:5px;border-radius:6px;background:#111b26;color:white;border:1px solid #1e2a3a;">
            <option value="free">Free</option>
            <option value="premium">Premium ($29/mo)</option>
        </select><br>
        <button type="submit" style="padding:10px 30px;background:#00d4ff;border:none;border-radius:30px;font-weight:bold;cursor:pointer;">Sign Up</button>
    </form>
    <p><a href="/login" style="color:#00d4ff;">Already have an account?</a></p>
    </body></html>
    """)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect('/login')
    user_id = session['user_id']
    plan = get_user_plan(user_id)
    return render_template_string(
        DASHBOARD_HTML,
        email=session.get('email', 'user@example.com'),
        company=session.get('company', 'My Company'),
        plan=plan
    )

# ---------- API ENDPOINTS ----------
@app.route('/api/data')
def api_data():
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    scans = get_scan_history(user_id)
    alerts = get_alerts(user_id)
    total_scans = len(scans)
    critical_findings = sum(1 for a in alerts if a[3] == 'CRITICAL')
    fixed_issues = sum(1 for a in alerts if a[4] == 1)
    open_ports = scans[0][3] if scans else 0
    return jsonify({
        'total_scans': total_scans,
        'critical_findings': critical_findings,
        'fixed_issues': fixed_issues,
        'open_ports': open_ports,
        'scans': scans,
        'alerts': alerts
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    if not session.get('user_id'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    data = request.get_json()
    target = data.get('target')
    ports_str = data.get('ports', '1-1024')
    cloud = data.get('cloud', 'none')
    account = data.get('account', 'default')
    user_id = session['user_id']
    is_prem = is_premium(user_id)

    if not target:
        return jsonify({'status': 'error', 'message': 'Target required'})

    # Parse ports
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            s, e = map(int, part.split('-'))
            ports.update(range(s, e+1))
        else:
            ports.add(int(part))
    ports = sorted(ports)

    # Run scan in background (thread)
    def run_scan():
        try:
            # Basic port scan
            open_services = scan_host(target, ports, threads=50)
            findings = []

            # Web checks (always free)
            if target.startswith('http://') or target.startswith('https://'):
                url = target
            else:
                url = f"https://{target}"
            # Simple directory checks (free)
            dirs = discover_directories(url)
            for d in dirs:
                findings.append((f"Directory: {d['path']} (HTTP {d['status']})", "Web", 5.0, "MEDIUM"))
            # SQLi & XSS (free)
            sqli = test_sqli(url)
            for s in sqli:
                findings.append((f"SQLi: {s['url']}", "Web", 9.0, "CRITICAL"))
            xss = test_xss(url)
            for x in xss:
                findings.append((f"XSS: {x['url']}", "Web", 7.5, "HIGH"))

            # Cloud checks (premium only)
            if is_prem and cloud != 'none':
                if cloud == 'aws':
                    findings.extend(check_aws_s3_public(account))
                    findings.extend(check_aws_security_groups(account))
                elif cloud == 'gcp':
                    findings.extend(check_gcp_storage_public(account))
                elif cloud == 'azure':
                    findings.extend(check_azure_blob_public(account))
                elif cloud == 'oci':
                    findings.extend(check_oci_storage_public(account))
                # Auto-fix for critical findings (premium)
                for f in findings:
                    if len(f) >= 4 and f[3] in ['CRITICAL', 'HIGH']:
                        # Try to auto-fix based on message
                        msg = f[0]
                        if 'S3 bucket' in msg and 'PUBLIC' in msg:
                            bucket_name = msg.split("'")[1]
                            success, res = fix_s3_public(bucket_name)
                            if success:
                                save_alert(user_id, cloud, account, f"Auto-fixed: {msg}", 'CRITICAL', fixed=True)
                            else:
                                save_alert(user_id, cloud, account, f"Failed to fix: {msg}", 'CRITICAL', fixed=False)
                        elif 'SG' in msg and 'allows' in msg:
                            # Parse SG ID and port from message (simplified)
                            # In real code, you'd extract from findings extra data
                            pass
                        # Add more fixers as needed

            # Save to DB
            save_scan(user_id, target, cloud, account, open_services, findings)
            # Save alerts for each finding (if not already saved)
            for f in findings:
                if len(f) >= 4:
                    # Check if already saved as alert (avoid duplicates)
                    # For simplicity, we save all findings as alerts
                    save_alert(user_id, cloud, account, f[0], f[3], fixed=False)
        except Exception as e:
            print(f"Scan error: {e}")

    threading.Thread(target=run_scan).start()
    return jsonify({'status': 'ok', 'message': 'Scan started'})

@app.route('/api/ask', methods=['POST'])
def ask_ai():
    if not session.get('user_id'):
        return jsonify({'response': 'Please login.'})
    data = request.get_json()
    question = data.get('question', '')
    if not question:
        return jsonify({'response': 'Ask a question.'})
    # Simple AI response (you can replace with Ollama or OpenAI)
    response = f"I received your question: '{question}'. This is a demo. In production, I'd use a real AI model."
    return jsonify({'response': response})

# ---------- STARTUP ----------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
