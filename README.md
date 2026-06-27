# 🤖 CloudHeal (CSPM Engine)

> **Autonomous Multi-Region Cloud Security Posture Management (CSPM) Self-Healing Engine**

CloudHeal is an enterprise-grade automated security engine designed to scan global multi-region cloud infrastructure, discover exposed configurations, and apply instant mitigation policies without human intervention.

---

## 🌍 Core Capabilities

* **Multi-Service Architecture**: Simultaneously monitors cloud data storage (Amazon S3) and network perimeter controls (EC2 Firewalls/Security Groups).
* **Multi-Region Orchestrator**: Sequentially audits and applies compliance controls across `us-east-1`, `us-west-2`, `eu-west-1`, and `ap-southeast-1`.
* **Instant Remediation**: Automatically enforces strict bucket privacy headers (`BlockPublicAcls`, `IgnorePublicAcls`) and isolates exposed corporate network footprints from the inside out.
* **Executive Compliance Auditing**: Automatically structures and exports complex multi-service security log states into clean, audit-ready CSV spreadsheet matrices (`cloud_heal_report.csv`).
* **Decoupled Architecture**: Runtime parameters, targeting definitions, and endpoint parameters are controlled completely outside the core engine using a modular `config.json` schema.

---

## 🛠️ Enterprise Architecture Layout

```text
├── config.json       # Central Product Configuration Matrix
├── heal.py           # Core Security Remediation & Logic Engine
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
Ensure your `config.json` matrix targets your local isolation endpoint parameters:

```json
{
    "target_regions": ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
    "sandbox_mode": true,
    "local_endpoint": "http://localhost:4566",
    "report_filename": "cloud_heal_report.csv"
}
```

### 3. Deploy the Autonomous Security Scan
Initialize the runtime environment to execute the global scanning loop:

```bash
python heal.py
```

---

## 📈 Enterprise Production Deployment

To deploy CloudHeal across live enterprise infrastructure pools:
1. Provision the target machine environment with valid identity credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
2. Adjust the central settings block inside `config.json` to flip execution parameters to production:
   ```json
   "sandbox_mode": false
   ```
3. Execute `python heal.py` via a cron utility or continuous scheduler to enforce permanent boundary rules across all global subnets.
