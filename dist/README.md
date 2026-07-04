# 🛡️ APCSS – Automated Protection of Cloud Security System

**The world’s first open‑source, self‑healing cloud security platform.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![AWS](https://img.shields.io/badge/AWS-Supported-orange.svg)]()
[![GCP](https://img.shields.io/badge/GCP-Supported-blue.svg)]()
[![Azure](https://img.shields.io/badge/Azure-Supported-blueviolet.svg)]()
[![OCI](https://img.shields.io/badge/OCI-Supported-red.svg)]()

---

## 🚀 What is APCSS?

APCSS is a **multi-cloud, multi-account security scanner** that doesn't just *find* vulnerabilities – it **automatically fixes them**.

It scans **AWS, GCP, Azure, and OCI** across multiple accounts, builds an **attack path graph**, and **breaks the entire attack chain** (S3 buckets, Security Groups, EC2 open ports, and IAM roles) – all in one command.

---

## ✨ Features

| Feature | Description |
| :--- | :--- |
| ☁️ **4‑Cloud Coverage** | AWS · GCP · Azure · OCI |
| 🔗 **Attack Path Graph** | Visualises exactly how an attacker would move from the Internet to your sensitive data. |
| 🛡️ **Auto‑Fix the Chain** | Not just alerts – APCSS breaks the entire attack path by fixing S3, SGs, EC2, and IAM automatically. |
| 📊 **Live Dashboard** | Real‑time monitoring with alerts, scan history, and visual attack paths. |
| 📄 **Compliance Reports** | Generate PDF reports for PCI‑DSS, HIPAA, and SOC2 – auditor‑ready. |
| 🧠 **Drift Detection** | Learns your environment and alerts you when something changes (e.g., a new public bucket). |
| 📢 **Slack Alerts** | Get instant notifications when vulnerabilities are found or fixed. |

---

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/apcss.git
cd apcss

# Install dependencies
pip install -r requirements.txt