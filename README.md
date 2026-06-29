# 🤖 CloudHeal (CSPM Engine)

> **Autonomous Multi-Region Cloud Security Posture Management (CSPM) Continuous Self-Healing Daemon**

CloudHeal is an enterprise-grade automated security engine designed to scan global multi-region cloud infrastructure, discover exposed configurations, and apply instant mitigation policies with real-time telemetry alerts without human intervention.

---

## 🌍 Core Capabilities

* **Multi-Service Architecture**: Simultaneously monitors cloud data storage (Amazon S3) and network perimeter controls (EC2 Firewalls/Security Groups).
* **Multi-Region Orchestrator**: Sequentially audits and applies compliance controls across `us-east-1`, `us-west-2`, `eu-west-1`, and `ap-southeast-1`.
* **Autonomous Heartbeat Timer**: Runs continuously as a background daemon, triggering comprehensive global security sweeps every 60 seconds automatically.
* **Instant Remediation**: Automatically enforces strict bucket privacy headers (`BlockPublicAcls`, `IgnorePublicAcls`) and isolates exposed corporate network footprints from the inside out.
* **Real-Time Telemetry Pipeline**: Directly integrated with the Telegram Bot API to dispatch instant markdown security notifications and fix alerts straight to engineering communication channels.
* **Executive Compliance Auditing**: Automatically structures and appends complex multi-service security log states into clean, audit-ready CSV spreadsheet matrices (`cloud_heal_report.csv`).
* **Decoupled Architecture**: Runtime parameters, targeting definitions, bot tokens, and endpoint parameters are controlled completely outside the core engine using a modular `config.json` schema.

---

## 🛠️ Enterprise Architecture Layout

```text
├── config.json       # Central Product Configuration Matrix
├── heal.py           # Core Security Remediation & Logic Engine
├── render.yaml       # Web Infrastructure Blueprint Schema
├── requirements.txt  # Cloud Dependency Packages Manifest
└── README.md         # Documentation & Product Specifications
```

---

## 🚀 Quickstart Sandbox Installation

To audit and test your infrastructure configurations safely in a sandboxed offline Docker container layout, execute the following protocol:

### 1. Initialize the Infrastructure Sandbox
Spin up an isolated network environment using a local image instance pinned to version `3.8.0` to preserve data and telemetry boundaries:

```bash
docker run -d -p 4566:4566 -p 4510-4559:4510-4559 --name localstack_main localstack/localstack:3.8.0
```

### 2. Configure Local Settings Matrix
Ensure your `config.json` matrix targets your local isolation endpoint parameters and contains your telemetry credentials:

```json
{
    "target_regions": ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
    "sandbox_mode": true,
    "local_endpoint": "http://localhost:4566",
    "report_filename": "cloud_heal_report.csv",
    "telegram_token": "YOUR_BOT_TOKEN",
    "telegram_chat_id": "YOUR_CHAT_ID"
}
```

### 3. Deploy the Autonomous Security Scan
Initialize the runtime environment to execute the global scanning loop:

```bash
python heal.py
```

---

## 📈 Enterprise Production Deployment

To deploy CloudHeal across live enterprise infrastructure pools or the cloud web grid:

### 1. Standalone Compilation (.exe)
The codebase can be fully compiled into a single portable application layout for distribution on Windows environments without requiring local Python configurations:
```bash
pip install pyinstaller
python -m PyInstaller --onefile --name=CloudHeal heal.py
```

### 2. Cloud Web Grid Hosting (24/7 Worker)
The script is natively structured to run as a 24/7 cloud compute background process on modern PaaS platforms like **Railway**:
1. Connect this repository workspace directly to your cloud deployment dashboard.
2. Configure your environment variables (`TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`) securely inside your dashboard manager.
3. Apply the custom startup trigger setting to let it loop indefinitely:
   ```text
   python heal.py
   ```
ross all global subnets.
