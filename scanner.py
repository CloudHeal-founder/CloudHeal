#!/usr/bin/env python3
"""
Aegis – Full SaaS with Blue/White BBCLEM-style Landing, Working Scan
Built by Austin Emmanuel – 19‑year‑old founder from Nigeria
"""
import socket
import argparse
import concurrent.futures
import sys
import json
import sqlite3
import datetime
import os
import threading
import requests
import urllib3
import random
import string
from urllib.request import urlopen, Request
from urllib.error import URLError

# ----- FLASK -----
from flask import Flask, render_template_string, jsonify, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----- Optional cloud SDKs (skip if not installed) -----
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

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

# ---------- Database Setup ----------
DB_NAME = "apcss_global.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
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
        total_findings INTEGER
    )''')
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
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        company TEXT,
        first_name TEXT,
        last_name TEXT,
        created_at TEXT,
        verified INTEGER DEFAULT 0,
        plan TEXT DEFAULT 'free'
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

# ---------- Scanner Functions ----------
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

def grab_banner(host, port, timeout=3.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in (80, 443, 8080, 8443):
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
    if "HTTP" in banner.upper(): return "HTTP"
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

# ----- Web checks (free) -----
def discover_directories(target_url):
    wordlist = ["admin", "login", "wp-admin", "backup", ".env", "phpinfo", "api", "docs"]
    findings = []
    for word in wordlist:
        test_url = f"{target_url.rstrip('/')}/{word}"
        try:
            resp = requests.get(test_url, timeout=3, verify=False, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                findings.append((f"Directory: {test_url} (HTTP {resp.status_code})", "Web", 5.0, "MEDIUM"))
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
                        findings.append((f"SQLi: {test_url}", "Web", 9.0, "CRITICAL"))
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
                        findings.append((f"XSS: {test_url}", "Web", 7.5, "HIGH"))
                        break
                except:
                    continue
    return findings

# ----- Cloud checks (premium) -----
def check_aws_s3_public(account_name=None):
    findings = []
    if not AWS_AVAILABLE:
        return [("AWS SDK missing", "AWS", 0, "INFO")]
    try:
        s3 = boto3.client('s3', verify=False)
        for bucket in s3.list_buckets()['Buckets']:
            name = bucket['Name']
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl['Grants']:
                    if 'AllUsers' in grant.get('Grantee', {}).get('URI', ''):
                        findings.append((f"S3 bucket '{name}' is PUBLIC", "AWS", 8.0, "CRITICAL"))
            except:
                continue
    except ClientError as e:
        findings.append((f"AWS error: {str(e)[:50]}", "AWS", 0, "INFO"))
    return findings

def check_aws_security_groups(account_name=None):
    findings = []
    if not AWS_AVAILABLE:
        return findings
    try:
        ec2 = boto3.client('ec2', verify=False)
        for sg in ec2.describe_security_groups()['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        findings.append((f"SG '{sg['GroupName']}' allows 0.0.0.0/0 on port {rule.get('FromPort')}", "AWS", 8.5, "CRITICAL"))
    except:
        pass
    return findings

def check_gcp_storage_public(project_id=None):
    findings = []
    if not GCP_AVAILABLE:
        return [("GCP SDK missing", "GCP", 0, "INFO")]
    try:
        client = storage.Client(project=project_id) if project_id else storage.Client()
        for bucket in client.list_buckets():
            policy = bucket.get_iam_policy()
            if 'allUsers' in policy:
                findings.append((f"GCP bucket '{bucket.name}' is PUBLIC", "GCP", 8.0, "CRITICAL"))
    except Exception as e:
        findings.append((f"GCP error: {str(e)[:50]}", "GCP", 0, "INFO"))
    return findings

def check_azure_blob_public(subscription_id=None):
    return [("Azure scan requires additional setup", "Azure", 0, "INFO")]

def check_oci_storage_public(compartment_id=None):
    if not OCI_AVAILABLE:
        return [("OCI SDK missing", "OCI", 0, "INFO")]
    try:
        config = oci.config.from_file()
        object_storage = oci.object_storage.ObjectStorageClient(config)
        ns = object_storage.get_namespace().data
        buckets = object_storage.list_buckets(ns, compartment_id=compartment_id) if compartment_id else object_storage.list_buckets(ns)
        findings = []
        for bucket in buckets.data:
            if bucket.public_access_type and bucket.public_access_type != "NoPublicAccess":
                findings.append((f"OCI bucket '{bucket.name}' is PUBLIC", "OCI", 8.0, "CRITICAL"))
        return findings
    except:
        return [("OCI error", "OCI", 0, "INFO")]

# ----- Auto-fix (premium) -----
def fix_s3_public(bucket_name):
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
        return True, f"Fixed S3 bucket '{bucket_name}'"
    except Exception as e:
        return False, str(e)

# ---------- Shared CSS (Blue/White Theme) ----------
SHARED_CSS = """
body {
    margin: 0;
    padding: 0;
    font-family: 'Segoe UI', Roboto, sans-serif;
    background: #0a0e1a;
    color: #e0f0ff;
    min-height: 100vh;
    position: relative;
}
.bg-layer {
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    z-index: 0;
    pointer-events: none;
    background: radial-gradient(circle at 20% 30%, #0a1a2a, #050a12 80%);
}
.bg-layer::before {
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: conic-gradient(from 0deg, #00a3ff, #0055ff, #00a3ff, #0055ff, #00a3ff);
    animation: rotateGlow 30s linear infinite;
    opacity: 0.08;
    filter: blur(80px);
}
@keyframes rotateGlow {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}
.shield {
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    width: 500px;
    height: 500px;
    opacity: 0.05;
    background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><path d="M50 5L5 20v30c0 25 20 40 45 45 25-5 45-20 45-45V20L50 5z" fill="%2300a3ff" stroke="%230055ff" stroke-width="3"/><text x="50" y="58" font-size="36" text-anchor="middle" fill="white">🛡️</text></svg>') no-repeat center;
    background-size: contain;
    animation: pulseShield 6s ease-in-out infinite;
    pointer-events: none;
}
@keyframes pulseShield {
    0% { opacity: 0.03; transform: translate(-50%, -50%) scale(0.9); }
    50% { opacity: 0.08; transform: translate(-50%, -50%) scale(1.1); }
    100% { opacity: 0.03; transform: translate(-50%, -50%) scale(0.9); }
}
.glass {
    background: rgba(10, 20, 40, 0.6);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(0, 163, 255, 0.2);
    border-radius: 16px;
    box-shadow: 0 8px 32px rgba(0, 100, 255, 0.15);
}
.content {
    position: relative;
    z-index: 1;
}
"""

# ===== LANDING PAGE (BBCLEM-style, blue/white) =====
LANDING_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis – Automated Cloud Security</title>
    <style>
        {{ SHARED_CSS }}
        .landing-container {
            display: flex;
            min-height: 100vh;
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
            align-items: center;
            gap: 60px;
        }
        .left {
            flex: 1.2;
        }
        .right {
            flex: 0.8;
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            border: 1px solid rgba(0, 163, 255, 0.3);
            box-shadow: 0 8px 32px rgba(0, 100, 255, 0.15);
        }
        .logo {
            font-size: 32px;
            font-weight: 700;
            color: #00a3ff;
            margin-bottom: 10px;
        }
        .tagline {
            font-size: 14px;
            color: #88bbdd;
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-bottom: 30px;
        }
        .left h1 {
            font-size: 42px;
            line-height: 1.2;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #00a3ff, #0055ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .left .desc {
            color: #aaccee;
            font-size: 18px;
            line-height: 1.6;
            margin-bottom: 30px;
            max-width: 600px;
        }
        .feature-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px 30px;
            margin-bottom: 30px;
        }
        .feature-grid .item {
            display: flex;
            align-items: center;
            gap: 10px;
            color: #cce0ff;
            font-size: 15px;
        }
        .feature-grid .item::before {
            content: "🛡️";
            color: #00a3ff;
            font-size: 18px;
        }
        .btn-primary {
            display: inline-block;
            background: #00a3ff;
            color: #fff;
            padding: 14px 36px;
            border-radius: 40px;
            font-weight: 600;
            text-decoration: none;
            transition: 0.3s;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        .btn-primary:hover {
            background: #0055ff;
            transform: scale(1.03);
        }
        .right h2 {
            color: #00a3ff;
            font-size: 26px;
            margin-bottom: 8px;
        }
        .right .welcome-sub {
            color: #88bbdd;
            font-size: 14px;
            margin-bottom: 25px;
        }
        .right input {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            background: #0a1a2a;
            border: 1px solid #2a4a6a;
            color: #e0f0ff;
            border-radius: 8px;
            box-sizing: border-box;
        }
        .right input:focus {
            border-color: #00a3ff;
            outline: none;
        }
        .right .login-btn {
            width: 100%;
            padding: 12px;
            background: #00a3ff;
            color: #fff;
            font-weight: bold;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: 0.3s;
            margin-top: 10px;
        }
        .right .login-btn:hover {
            background: #0055ff;
        }
        .right .links {
            display: flex;
            justify-content: space-between;
            margin-top: 15px;
            font-size: 14px;
        }
        .right .links a {
            color: #00a3ff;
            text-decoration: none;
        }
        .right .links a:hover {
            text-decoration: underline;
        }
        .trust-badges {
            display: flex;
            justify-content: space-around;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid rgba(0, 163, 255, 0.15);
        }
        .trust-badges .badge {
            text-align: center;
            color: #88bbdd;
            font-size: 13px;
        }
        .trust-badges .badge strong {
            display: block;
            color: #e0f0ff;
            font-size: 16px;
        }
        @media (max-width: 900px) {
            .landing-container {
                flex-direction: column;
                padding: 20px;
                gap: 30px;
            }
            .right {
                width: 100%;
                padding: 30px;
            }
            .feature-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="bg-layer"><div class="shield"></div></div>
    <div class="content landing-container">
        <div class="left">
            <div class="logo">🛡️ Aegis</div>
            <div class="tagline">Automated Protection of Cloud Security Systems</div>
            <h1>Comprehensive Security Testing Platform</h1>
            <div class="desc">
                Identify security vulnerabilities in web applications, APIs, networks, mobile apps and cloud infrastructure with our comprehensive security tools.
            </div>
            <div class="feature-grid">
                <div class="item">Comprehensive Security Scanning</div>
                <div class="item">API Security Testing</div>
                <div class="item">Web Application Testing</div>
                <div class="item">Network Penetration Testing</div>
                <div class="item">Mobile App Security</div>
                <div class="item">Cloud Infrastructure Testing</div>
                <div class="item">Advanced Vulnerability Detection</div>
                <div class="item">Professional Reporting</div>
                <div class="item">Expert Mentorship</div>
                <div class="item">Real-time Monitoring</div>
            </div>
            <a href="/signup" class="btn-primary">Get Started Free →</a>
        </div>
        <div class="right">
            <h2>Welcome to Aegis</h2>
            <div class="welcome-sub">Access your cybersecurity command center</div>
            <form method="POST" action="/login">
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit" class="login-btn">Sign In</button>
            </form>
            <div class="links">
                <a href="/signup">Create Account</a>
                <a href="#">Forgot Password?</a>
            </div>
            <div class="trust-badges">
                <div class="badge"><strong>🔒 Secure</strong>Enterprise-Grade</div>
                <div class="badge"><strong>🏆 Trusted</strong>by 500+ Professionals</div>
                <div class="badge"><strong>🕒 24/7</strong>Security Monitoring</div>
            </div>
        </div>
    </div>
</body>
</html>
"""

# ===== LOGIN =====
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Aegis – Login</title>
<style>
    {{ SHARED_CSS }}
    .login-box {
        max-width: 400px;
        margin: 80px auto;
        padding: 40px;
        text-align: center;
    }
    .login-box h2 {
        font-size: 28px;
        color: #00a3ff;
        margin-bottom: 10px;
    }
    .login-box input {
        width: 100%;
        padding: 12px;
        margin: 10px 0;
        background: #0a1a2a;
        border: 1px solid #2a4a6a;
        color: #e0f0ff;
        border-radius: 8px;
        box-sizing: border-box;
    }
    .login-box input:focus {
        border-color: #00a3ff;
        outline: none;
    }
    .login-box button {
        width: 100%;
        padding: 12px;
        background: #00a3ff;
        color: #fff;
        font-weight: bold;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        transition: 0.3s;
    }
    .login-box button:hover { background: #0055ff; }
    .login-box a { color: #00a3ff; text-decoration: none; }
    .error { color: #ff4757; margin-bottom: 10px; }
</style>
</head>
<body>
    <div class="bg-layer"><div class="shield"></div></div>
    <div class="content login-box glass">
        <h2>Welcome Back</h2>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST">
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <p style="margin-top:20px; color:#88bbdd;">Don't have an account? <a href="/signup">Create Account</a></p>
    </div>
</body>
</html>
"""

# ===== SIGNUP =====
SIGNUP_HTML = """
<!DOCTYPE html>
<html>
<head><title>Aegis – Sign Up</title>
<style>
    {{ SHARED_CSS }}
    .signup-box {
        max-width: 450px;
        margin: 60px auto;
        padding: 40px;
        text-align: center;
    }
    .signup-box h2 {
        font-size: 28px;
        color: #00a3ff;
        margin-bottom: 10px;
    }
    .signup-box input, .signup-box select {
        width: 100%;
        padding: 12px;
        margin: 8px 0;
        background: #0a1a2a;
        border: 1px solid #2a4a6a;
        color: #e0f0ff;
        border-radius: 8px;
        box-sizing: border-box;
    }
    .signup-box input:focus, .signup-box select:focus {
        border-color: #00a3ff;
        outline: none;
    }
    .signup-box button {
        width: 100%;
        padding: 12px;
        background: #00a3ff;
        color: #fff;
        font-weight: bold;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        transition: 0.3s;
    }
    .signup-box button:hover { background: #0055ff; }
    .signup-box a { color: #00a3ff; text-decoration: none; }
    .name-row { display: flex; gap: 10px; }
    .name-row input { flex: 1; }
</style>
</head>
<body>
    <div class="bg-layer"><div class="shield"></div></div>
    <div class="content signup-box glass">
        <h2>Create Account</h2>
        <form method="POST">
            <div class="name-row">
                <input type="text" name="first_name" placeholder="First Name" required>
                <input type="text" name="last_name" placeholder="Last Name" required>
            </div>
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <select name="plan">
                <option value="free">Free</option>
                <option value="premium">Premium ($500/mo)</option>
            </select>
            <button type="submit">Sign Up</button>
        </form>
        <p style="margin-top:20px; color:#88bbdd;">Already have an account? <a href="/login">Sign In</a></p>
    </div>
</body>
</html>
"""

# ===== OTP =====
OTP_HTML = """
<!DOCTYPE html>
<html>
<head><title>Aegis – Verify Email</title>
<style>
    {{ SHARED_CSS }}
    .otp-box {
        max-width: 400px;
        margin: 80px auto;
        padding: 40px;
        text-align: center;
    }
    .otp-box h2 {
        font-size: 28px;
        color: #00a3ff;
        margin-bottom: 10px;
    }
    .otp-box .info { color: #88bbdd; margin-bottom: 20px; }
    .otp-box .otp-display {
        background: #0a1a2a;
        border: 1px solid #00a3ff;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 20px;
        color: #00a3ff;
        font-size: 32px;
        letter-spacing: 8px;
        font-weight: bold;
        font-family: monospace;
    }
    .otp-box input {
        width: 100%;
        padding: 12px;
        margin: 10px 0;
        background: #0a1a2a;
        border: 1px solid #2a4a6a;
        color: #e0f0ff;
        border-radius: 8px;
        text-align: center;
        font-size: 20px;
        letter-spacing: 6px;
        box-sizing: border-box;
    }
    .otp-box input:focus {
        border-color: #00a3ff;
        outline: none;
    }
    .otp-box button {
        width: 100%;
        padding: 12px;
        background: #00a3ff;
        color: #fff;
        font-weight: bold;
        border: none;
        border-radius: 8px;
        cursor: pointer;
    }
    .otp-box button:hover { background: #0055ff; }
    .otp-box .resend { margin-top: 20px; color: #88bbdd; }
    .otp-box .resend a { color: #00a3ff; text-decoration: none; }
    .error { color: #ff4757; margin-bottom: 10px; }
</style>
</head>
<body>
    <div class="bg-layer"><div class="shield"></div></div>
    <div class="content otp-box glass">
        <h2>📧 Verify Email</h2>
        <div class="info">We sent a 6‑digit code to <strong>{{ email }}</strong></div>
        <div class="otp-display">🔑 {{ otp }}</div>
        <div class="info" style="font-size:12px; color:#5a7a9a;">(Copy this code and paste it below)</div>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST" action="/verify-otp">
            <input type="text" name="otp" placeholder="6‑digit code" maxlength="6" required autofocus>
            <button type="submit">Verify Account</button>
        </form>
        <div class="resend">Didn't get the code? <a href="/resend-otp">Resend OTP</a></div>
    </div>
</body>
</html>
"""

# ===== DASHBOARD (with scan form, stats, alerts, blue/white) =====
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis – Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        {{ SHARED_CSS }}
        .app-container {
            position: relative;
            z-index: 1;
            display: flex;
            height: 100vh;
        }
        .sidebar {
            width: 220px;
            background: rgba(10, 20, 40, 0.85);
            backdrop-filter: blur(10px);
            border-right: 1px solid rgba(0, 163, 255, 0.2);
            padding: 20px 0;
            height: 100vh;
            overflow-y: auto;
            flex-shrink: 0;
        }
        .sidebar .logo {
            font-size: 22px;
            font-weight: 700;
            color: #00a3ff;
            padding: 0 20px;
            margin-bottom: 30px;
        }
        .sidebar a {
            display: block;
            padding: 12px 20px;
            color: #88bbdd;
            text-decoration: none;
            font-size: 14px;
            border-left: 3px solid transparent;
            transition: 0.2s;
        }
        .sidebar a:hover, .sidebar a.active {
            background: rgba(0, 163, 255, 0.1);
            color: #fff;
            border-left-color: #00a3ff;
        }
        .sidebar .logout {
            margin-top: 40px;
            border-top: 1px solid rgba(0, 163, 255, 0.2);
            padding-top: 20px;
            color: #ff4757;
        }
        .main {
            flex: 1;
            padding: 20px 30px;
            overflow-y: auto;
            height: 100vh;
            background: rgba(10, 14, 26, 0.5);
            backdrop-filter: blur(5px);
        }
        .topbar {
            display: flex; justify-content: space-between; align-items: center;
            padding-bottom: 20px; border-bottom: 1px solid rgba(0, 163, 255, 0.2);
            margin-bottom: 25px;
            flex-wrap: wrap;
            gap: 10px;
        }
        .topbar h1 {
            font-size: 24px;
            color: #00a3ff;
        }
        .topbar .user {
            display: flex;
            align-items: center;
            gap: 15px;
            flex-wrap: wrap;
        }
        .topbar .user .badge {
            background: rgba(0, 163, 255, 0.2);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            color: #00a3ff;
        }
        .topbar .user .plan {
            background: #00a3ff;
            color: #fff;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 12px;
        }
        .topbar .user .email { color: #88bbdd; font-size: 14px; }
        .refresh-btn {
            background: rgba(0, 163, 255, 0.2);
            border: 1px solid rgba(0, 163, 255, 0.3);
            color: #e0f0ff;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
        }
        .refresh-btn:hover { background: rgba(0, 163, 255, 0.3); }

        .scan-form {
            background: rgba(10, 20, 40, 0.7);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
            border: 1px solid rgba(0, 163, 255, 0.2);
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: flex-end;
        }
        .scan-form .field {
            display: flex;
            flex-direction: column;
            gap: 4px;
            flex: 1 0 150px;
        }
        .scan-form .field label {
            font-size: 12px;
            color: #88bbdd;
        }
        .scan-form .field input, .scan-form .field select {
            padding: 8px 12px;
            background: #0a1a2a;
            border: 1px solid #2a4a6a;
            color: #e0f0ff;
            border-radius: 6px;
        }
        .scan-form .field input:focus, .scan-form .field select:focus {
            outline: none;
            border-color: #00a3ff;
        }
        .scan-form .submit-btn {
            background: #00a3ff;
            color: #fff;
            border: none;
            padding: 10px 24px;
            border-radius: 20px;
            font-weight: bold;
            cursor: pointer;
            transition: 0.2s;
        }
        .scan-form .submit-btn:hover { background: #0055ff; }
        .scan-form .submit-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(10, 20, 40, 0.6);
            backdrop-filter: blur(5px);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid rgba(0, 163, 255, 0.1);
            transition: 0.2s;
        }
        .stat-card:hover {
            border-color: rgba(0, 163, 255, 0.3);
            transform: translateY(-3px);
        }
        .stat-card .number {
            font-size: 28px;
            font-weight: 700;
            color: #00a3ff;
        }
        .stat-card .label {
            font-size: 14px;
            color: #88bbdd;
        }
        .stat-card.critical .number { color: #ff4757; }
        .stat-card.fixed .number { color: #2ed573; }

        .chart-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
            margin-bottom: 30px;
        }
        .chart-box {
            background: rgba(10, 20, 40, 0.6);
            backdrop-filter: blur(5px);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid rgba(0, 163, 255, 0.1);
        }
        .chart-box h3 {
            font-size: 16px;
            color: #88bbdd;
            margin-bottom: 15px;
        }

        .section {
            background: rgba(10, 20, 40, 0.6);
            backdrop-filter: blur(5px);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid rgba(0, 163, 255, 0.1);
        }
        .section h2 {
            font-size: 18px;
            margin-bottom: 15px;
            color: #88bbdd;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        th {
            text-align: left;
            padding: 10px;
            color: #88bbdd;
            border-bottom: 1px solid rgba(0, 163, 255, 0.2);
        }
        td {
            padding: 10px;
            border-bottom: 1px solid rgba(0, 163, 255, 0.05);
        }
        .severity-critical { color: #ff4757; font-weight: bold; }
        .severity-high { color: #ff6b81; }
        .severity-medium { color: #f9ca24; }
        .severity-info { color: #88bbdd; }
        .fixed-true { color: #2ed573; }
        .fixed-false { color: #f9ca24; }
        .empty { color: #5a7a9a; font-style: italic; }

        .ai-bubble {
            position: fixed;
            bottom: 30px;
            right: 30px;
            z-index: 999;
        }
        .ai-bubble button {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: #00a3ff;
            border: none;
            color: #fff;
            font-size: 30px;
            cursor: pointer;
            box-shadow: 0 0 30px rgba(0, 163, 255, 0.3);
            transition: 0.3s;
        }
        .ai-bubble button:hover { transform: scale(1.1); }
        .ai-chat {
            display: none;
            position: fixed;
            bottom: 100px;
            right: 30px;
            width: 380px;
            max-height: 500px;
            background: #0a1a2a;
            border: 1px solid rgba(0, 163, 255, 0.2);
            border-radius: 16px;
            overflow: hidden;
            z-index: 999;
            flex-direction: column;
            box-shadow: 0 20px 60px rgba(0,0,0,0.8);
        }
        .ai-chat.open { display: flex; }
        .ai-chat .header {
            padding: 15px 20px;
            background: #050a12;
            border-bottom: 1px solid rgba(0, 163, 255, 0.2);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .ai-chat .header h3 { color: #00a3ff; font-size: 16px; }
        .ai-chat .header .close {
            background: none;
            border: none;
            color: #88bbdd;
            font-size: 20px;
            cursor: pointer;
        }
        .ai-chat .messages {
            flex: 1;
            padding: 15px;
            overflow-y: auto;
            max-height: 300px;
        }
        .ai-chat .messages .msg {
            margin-bottom: 12px;
            padding: 10px 14px;
            border-radius: 10px;
            max-width: 80%;
            word-wrap: break-word;
        }
        .ai-chat .messages .msg.user {
            background: #1a3a5a;
            color: #e0f0ff;
            align-self: flex-end;
            margin-left: auto;
        }
        .ai-chat .messages .msg.ai {
            background: #0a1a2a;
            border: 1px solid rgba(0, 163, 255, 0.2);
            color: #88bbdd;
            align-self: flex-start;
        }
        .ai-chat .input-area {
            display: flex;
            padding: 10px;
            border-top: 1px solid rgba(0, 163, 255, 0.2);
            background: #050a12;
        }
        .ai-chat .input-area input {
            flex: 1;
            padding: 10px;
            border: none;
            border-radius: 8px;
            background: #0a1a2a;
            color: #e0f0ff;
            outline: none;
        }
        .ai-chat .input-area button {
            margin-left: 10px;
            padding: 10px 16px;
            background: #00a3ff;
            color: #fff;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
        }
        .ai-chat .input-area button:hover { background: #0055ff; }

        @media (max-width: 768px) {
            .sidebar { display: none; }
            .main { margin-left: 0; }
            .chart-row { grid-template-columns: 1fr; }
            .stats { grid-template-columns: 1fr 1fr; }
            .ai-chat { width: 300px; right: 10px; bottom: 90px; }
        }
    </style>
</head>
<body>
    <div class="bg-layer"><div class="shield"></div></div>

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
                <button class="submit-btn" id="scanBtn" onclick="startScan()">🚀 Start Scan</button>
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

            <!-- Recent Scans -->
            <div class="section"><h2>📋 Recent Scans</h2><table><thead><tr><th>Timestamp</th><th>Target</th><th>Cloud</th><th>Open Ports</th><th>Findings</th></tr></thead><tbody id="scansTable"></tbody></table></div>

            <!-- Alerts -->
            <div class="section"><h2>🔔 Alerts</h2><table><thead><tr><th>Timestamp</th><th>Message</th><th>Severity</th><th>Fixed</th></tr></thead><tbody id="alertsTable"></tbody></table></div>
        </div>
    </div>

    <!-- AI Assistant -->
    <div class="ai-bubble">
        <button id="aiToggle" onclick="toggleAI()">🛡️</button>
    </div>
    <div class="ai-chat" id="aiChat">
        <div class="header">
            <h3>🤖 Aegis AI</h3>
            <button class="close" onclick="toggleAI()">✕</button>
        </div>
        <div class="messages" id="aiMessages">
            <div class="msg ai">👋 Hi! I'm your security assistant. Ask me anything.</div>
        </div>
        <div class="input-area">
            <input type="text" id="aiInput" placeholder="Ask a question..." onkeypress="if(event.key==='Enter') sendAI()">
            <button onclick="sendAI()">Send</button>
        </div>
    </div>

    <script>
        function toggleAI() {
            const chat = document.getElementById('aiChat');
            chat.classList.toggle('open');
        }

        async function sendAI() {
            const input = document.getElementById('aiInput');
            const msg = input.value.trim();
            if (!msg) return;
            input.value = '';
            const container = document.getElementById('aiMessages');
            container.innerHTML += `<div class="msg user">${msg}</div>`;
            container.innerHTML += `<div class="msg ai">Thinking...</div>`;
            try {
                const res = await fetch('/api/ask', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({question: msg})
                });
                const data = await res.json();
                const msgs = container.querySelectorAll('.msg');
                msgs[msgs.length-1].textContent = data.response || 'No response.';
            } catch(e) {
                const msgs = container.querySelectorAll('.msg');
                msgs[msgs.length-1].textContent = 'Error: ' + e.message;
            }
            container.scrollTop = container.scrollHeight;
        }

        async function startScan() {
            const btn = document.getElementById('scanBtn');
            btn.disabled = true;
            btn.textContent = '⏳ Scanning...';

            const target = document.getElementById('scanTarget').value;
            const ports = document.getElementById('scanPorts').value;
            const cloud = document.getElementById('scanCloud').value;
            const account = document.getElementById('scanAccount').value;

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, ports, cloud, account})
                });
                const data = await res.json();
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
                const res = await fetch('/api/data');
                const data = await res.json();
                document.getElementById('totalScans').textContent = data.total_scans || 0;
                document.getElementById('criticalFindings').textContent = data.critical_findings || 0;
                document.getElementById('fixedIssues').textContent = data.fixed_issues || 0;
                document.getElementById('openPorts').textContent = data.open_ports || 0;

                const scansTable = document.getElementById('scansTable');
                if (data.scans && data.scans.length > 0) {
                    scansTable.innerHTML = data.scans.map(s => `<tr><td>${s[0]}</td><td>${s[1]}</td><td>${s[2] || '-'}</td><td>${s[3]}</td><td>${s[4]}</td></tr>`).join('');
                } else {
                    scansTable.innerHTML = `<tr><td colspan="5" class="empty">No scans yet. Use the form above.</td></tr>`;
                }

                const alertsTable = document.getElementById('alertsTable');
                if (data.alerts && data.alerts.length > 0) {
                    alertsTable.innerHTML = data.alerts.map(a => `<tr><td>${a[0]}</td><td>${a[1]}</td><td class="severity-${a[3].toLowerCase()}">${a[3]}</td><td class="fixed-${a[4] ? 'true' : 'false'}">${a[4] ? '✅ Fixed' : '⚠️ Open'}</td></tr>`).join('');
                } else {
                    alertsTable.innerHTML = `<tr><td colspan="4" class="empty">No alerts yet.</td></tr>`;
                }

                // Charts
                const sevCounts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0};
                if (data.alerts) data.alerts.forEach(a => { if (sevCounts[a[3]] !== undefined) sevCounts[a[3]]++; });
                const ctx2 = document.getElementById('severityChart').getContext('2d');
                if (window.sevChart) window.sevChart.destroy();
                window.sevChart = new Chart(ctx2, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical','High','Medium','Low','Info'],
                        datasets: [{
                            data: [sevCounts.CRITICAL, sevCounts.HIGH, sevCounts.MEDIUM, sevCounts.LOW, sevCounts.INFO],
                            backgroundColor: ['#ff4757','#ff6b81','#f9ca24','#2ed573','#88bbdd'],
                            borderColor: '#0a0e1a',
                            borderWidth: 3
                        }]
                    },
                    options: { responsive: true, plugins: { legend: { labels: { color: '#e0f0ff' } } } }
                });

                const labels = data.scans.map(s => s[0].slice(0, 10)).reverse();
                const counts = data.scans.map(s => s[4]).reverse();
                if (labels.length === 0) { labels = ['No Data']; counts = [0]; }
                const ctx1 = document.getElementById('trendChart').getContext('2d');
                if (window.trendChart) window.trendChart.destroy();
                window.trendChart = new Chart(ctx1, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Findings',
                            data: counts,
                            borderColor: '#00a3ff',
                            backgroundColor: 'rgba(0, 163, 255, 0.1)',
                            fill: true,
                            tension: 0.3
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { labels: { color: '#e0f0ff' } } },
                        scales: { x: { ticks: { color: '#88bbdd' } }, y: { ticks: { color: '#88bbdd' } } }
                    }
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

# ===== PRICING =====
PRICING_HTML = """
<!DOCTYPE html>
<html>
<head><title>Aegis – Pricing</title>
<style>
    {{ SHARED_CSS }}
    .pricing-box {
        max-width: 1000px;
        margin: 60px auto;
        padding: 40px;
        text-align: center;
    }
    .pricing-box h1 {
        font-size: 42px;
        color: #00a3ff;
        margin-bottom: 10px;
    }
    .pricing-box .sub { color: #88bbdd; font-size: 18px; margin-bottom: 40px; }
    .pricing-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 30px;
    }
    .card {
        background: rgba(10, 20, 40, 0.6);
        backdrop-filter: blur(10px);
        border-radius: 12px;
        padding: 30px;
        border: 1px solid rgba(0, 163, 255, 0.1);
        transition: 0.3s;
    }
    .card:hover { border-color: #00a3ff; transform: translateY(-5px); }
    .card.popular { border-color: #00a3ff; }
    .card .plan { font-size: 24px; font-weight: 700; }
    .card .price { font-size: 36px; color: #00a3ff; margin: 15px 0; }
    .card .price span { font-size: 16px; color: #88bbdd; }
    .card ul { list-style: none; padding: 0; text-align: left; margin: 20px 0; }
    .card ul li { padding: 8px 0; border-bottom: 1px solid rgba(0, 163, 255, 0.1); color: #88bbdd; }
    .card ul li:before { content: "✅ "; color: #2ed573; }
    .btn {
        display: inline-block;
        background: #00a3ff;
        color: #fff;
        padding: 10px 30px;
        border-radius: 30px;
        font-weight: 600;
        text-decoration: none;
        transition: 0.2s;
    }
    .btn:hover { background: #0055ff; }
    .back-link { display: inline-block; margin-top: 40px; color: #00a3ff; text-decoration: none; }
    .back-link:hover { text-decoration: underline; }
    @media (max-width: 768px) { .pricing-grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
    <div class="bg-layer"><div class="shield"></div></div>
    <div class="content pricing-box">
        <h1>Choose Your Plan</h1>
        <p class="sub">Start free. Scale with confidence.</p>
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
                <div class="price">$500 <span>/ month</span></div>
                <ul>
                    <li>10 cloud accounts</li>
                    <li>Auto‑fix</li>
                    <li>Slack alerts</li>
                    <li>Priority support</li>
                    <li>1‑year history</li>
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
                    <li>Custom compliance</li>
                    <li>SSO & RBAC</li>
                </ul>
                <a href="/signup" class="btn">Contact Sales</a>
            </div>
        </div>
        <a href="/" class="back-link">← Back to home</a>
    </div>
</body>
</html>
"""

# ---------- Flask App ----------
app = Flask(__name__)
app.secret_key = os.urandom(24)
pending_users = {}

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    print(f"[OTP] Your verification code: {otp}")
    print(f"[OTP] Sent to: {email}")
    return True

@app.route('/')
def landing():
    return render_template_string(LANDING_HTML, SHARED_CSS=SHARED_CSS)

@app.route('/pricing')
def pricing():
    return render_template_string(PRICING_HTML, SHARED_CSS=SHARED_CSS)

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
            session['plan'] = user[7]
            return redirect('/dashboard')
        else:
            return render_template_string(LOGIN_HTML, SHARED_CSS=SHARED_CSS, error="Invalid email or unverified account")
    return render_template_string(LOGIN_HTML, SHARED_CSS=SHARED_CSS, error=None)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        plan = request.form.get('plan', 'free')
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            return render_template_string(SIGNUP_HTML, SHARED_CSS=SHARED_CSS, error="Email already registered.")
        otp = generate_otp()
        company = f"{first_name} {last_name}"
        pending_users[email] = {
            'company': company,
            'first_name': first_name,
            'last_name': last_name,
            'password': password,
            'plan': plan,
            'otp': otp,
            'expiry': datetime.datetime.now() + datetime.timedelta(minutes=10)
        }
        conn.close()
        send_otp_email(email, otp)
        return render_template_string(OTP_HTML, SHARED_CSS=SHARED_CSS, email=email, otp=otp, error=None)
    return render_template_string(SIGNUP_HTML, SHARED_CSS=SHARED_CSS, error=None)

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    otp = request.form['otp']
    email = None
    for e, data in pending_users.items():
        if data['otp'] == otp and datetime.datetime.now() < data['expiry']:
            email = e
            break
    if email:
        data = pending_users.pop(email)
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("""
            INSERT INTO users (email, password, company, first_name, last_name, created_at, verified, plan)
            VALUES (?, ?, ?, ?, ?, datetime('now'), 1, ?)
        """, (email, data['password'], data['company'], data['first_name'], data['last_name'], data['plan']))
        conn.commit()
        conn.close()
        return redirect('/login')
    else:
        return render_template_string(OTP_HTML, SHARED_CSS=SHARED_CSS, email="your email", otp="", error="Invalid or expired OTP. Please try again.")

@app.route('/resend-otp')
def resend_otp():
    return redirect('/signup')

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
        SHARED_CSS=SHARED_CSS,
        email=session.get('email', 'user@example.com'),
        company=session.get('company', 'My Company'),
        plan=plan
    )

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
    premium = is_premium(user_id)

    if not target:
        return jsonify({'status': 'error', 'message': 'Target required'})

    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            s, e = map(int, part.split('-'))
            ports.update(range(s, e+1))
        else:
            ports.add(int(part))
    ports = sorted(ports)

    def run_scan():
        try:
            open_services = scan_host(target, ports, threads=50)
            findings = []
            if target.startswith(('http://', 'https://')):
                url = target
            else:
                url = f"https://{target}"
            dirs = discover_directories(url)
            for d in dirs:
                findings.append(d)
            sqli = test_sqli(url)
            for s in sqli:
                findings.append(s)
            xss = test_xss(url)
            for x in xss:
                findings.append(x)

            if premium and cloud != 'none':
                if cloud == 'aws':
                    findings.extend(check_aws_s3_public(account))
                    findings.extend(check_aws_security_groups(account))
                elif cloud == 'gcp':
                    findings.extend(check_gcp_storage_public(account))
                elif cloud == 'azure':
                    findings.extend(check_azure_blob_public(account))
                elif cloud == 'oci':
                    findings.extend(check_oci_storage_public(account))
                for f in findings:
                    if len(f) >= 4 and f[3] in ['CRITICAL', 'HIGH']:
                        msg = f[0]
                        if 'S3 bucket' in msg and 'PUBLIC' in msg:
                            bucket_name = msg.split("'")[1]
                            success, res = fix_s3_public(bucket_name)
                            if success:
                                save_alert(user_id, cloud, account, f"Auto-fixed: {msg}", 'CRITICAL', fixed=True)
                            else:
                                save_alert(user_id, cloud, account, f"Failed to fix: {msg}", 'CRITICAL', fixed=False)

            save_scan(user_id, target, cloud, account, open_services, findings)
            for f in findings:
                if len(f) >= 4:
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
    # Placeholder – you can replace with Ollama or OpenAI
    response = f"I received your question: '{question}'. This is a demo response."
    return jsonify({'response': response})

# ---------- Main ----------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
