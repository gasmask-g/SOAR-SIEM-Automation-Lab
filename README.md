# SILGAX: AI-Powered Security Orchestration, Automation, and Response (SOAR) Platform

## 📋 Table of Contents

1. [About The Project]
2. [System Architecture]
3. [Key Features]
4. [Technology Stack]
5. [Prerequisites]
6. [Installation & Deployment]

   * [1. Wazuh Deployment]
   * [2. n8n Deployment]
7. [Configuration & Integration]

   * [Step 1: Configuring Wazuh Manager]
   * [Step 2: Creating the Integration Script]
   * [Step 3: Setting up Google Gemini AI]
   * [Step 4: Building the n8n Workflow]
8. [Workflow Logic]
9. [Usage & Testing]
10. [Troubleshooting]
11. [Roadmap]
12. [Contributing]
13. [License]

---

## 🛡 About The Project

**SILGAX** is an advanced Security Orchestration, Automation, and Response (SOAR) platform designed to bridge the gap between detection and remediation. By integrating **Wazuh** (Open Source XDR/SIEM) with **n8n** (Workflow Automation), SILGAX automates the incident response lifecycle.

Crucially, SILGAX leverages **Google's Gemini AI** to act as a Level 1 Security Analyst. Instead of flooding security teams with raw logs, SILGAX intercepts alerts, analyzes them using Generative AI to determine context, severity, and potential mitigation steps, and then routes intelligent notifications via **Slack** and **Gmail**.

### Why SILGAX?

Traditional SIEMs generate thousands of alerts. SOC analysts often suffer from "alert fatigue," missing critical threats amidst the noise. SILGAX solves this by:

1. **Enriching Data:** Automatically gathering context around an IP or event.
2. **AI Analysis:** Using LLMs to interpret "fuzzy" threats that rule-based engines might misclassify.
3. **Instant Notification:** delivering formatted, actionable reports to communication channels.

---

## 🏗 System Architecture

The SILGAX architecture follows a modular, event-driven design:

1. **Data Collection:** Wazuh Agents installed on endpoints (Windows/Linux/macOS) collect logs (Syslog, Auth, Apache, etc.) and forward them to the Wazuh Manager.
2. **Detection:** Wazuh Manager analyzes logs against its ruleset. If a rule is triggered, an alert is generated.
3. **Orchestration Trigger:** The Wazuh Integrator daemon triggers a custom script/webhook based on alert level.
4. **Automation (The Brain):** **n8n** receives the alert JSON payload via a Webhook node.
5. **Cognitive Processing:** n8n passes the alert data to **Gemini AI** via API. The AI analyzes the payload for malicious intent and suggests remediation.
6. **Response & Notification:** Based on the AI's verdict:

   * **High Severity:** Alert sent to Slack #soc-critical and Email to Admin.
   * **Low Severity:** Logged for review, summary sent to Slack #soc-general.

---

## 🚀 Key Features

* **Real-time Threat Detection:** Leverages Wazuh's decoders and rules for immediate threat identification.
* **Generative AI Analysis:** Uses Google Gemini Pro to explain *why* an event is dangerous and recommend specific commands for remediation.
* **Multi-Channel Alerting:**

  * **Slack:** Interactive Block Kit messages with "Ban IP" or "Isolate Host" buttons (planned).
  * **Gmail:** Detailed HTML reports including raw logs and AI analysis.
* **No-Code/Low-Code Logic:** All orchestration logic is handled in n8n, allowing for easy modification of workflows without recompiling code.
* **Scalability:** containerized architecture (Docker) allows for easy scaling of the worker nodes.
* **Customizable Thresholds:** Define exactly which alerts (e.g., Severity > 10) trigger the AI analysis to save on API costs.

---

## 💻 Technology Stack

| Component          | Technology              | Description                                                   |
| :----------------- | :---------------------- | :------------------------------------------------------------ |
| **SIEM / XDR**     | Wazuh 4.7+              | Log analysis, file integrity monitoring, intrusion detection. |
| **Orchestrator**   | n8n                     | Workflow automation tool connecting disparate APIs.           |
| **Intelligence**   | Google Gemini AI        | LLM for natural language summary and threat scoring.          |
| **Notification**   | Slack API               | Real-time messaging and ChatOps.                              |
| **Notification**   | Gmail SMTP              | Formal incident reporting.                                    |
| **Infrastructure** | Docker & Docker Compose | Containerization and orchestration.                           |
| **Scripting**      | Python / Bash           | Custom integration scripts for Wazuh.                         |

---

## ⚙ Prerequisites

Before deploying SILGAX, ensure you have the following:

* **Hardware:**

  * Minimum 8GB RAM (16GB Recommended for smooth ELK/Wazuh performance).
  * 4 vCPUs.
  * 100GB Disk Space.
* **Software:**

  * Ubuntu 20.04/22.04 LTS (Recommended).
  * Docker & Docker Compose installed.
  * Python 3.9+.
* **API Keys:**

  * **Google Cloud Project** with Gemini API enabled.
  * **Slack App** webhook URL or Bot Token.
  * **Gmail** App Password (for SMTP) or OAuth Client ID.

---

## 📦 Installation & Deployment

### 1. Wazuh Deployment

We utilize the standard Docker single-node deployment for Wazuh.

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.2
cd wazuh-docker/single-node
docker-compose -f generate-indexer-certs.yml run --rm generator
docker-compose up -d
```

### 2. n8n Deployment

```yaml
version: "3"
services:
  n8n:
    image: n8nio/n8n
    ports:
      - "5678:5678"
    environment:
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=admin
      - N8N_BASIC_AUTH_PASSWORD=secure_password
      - WEBHOOK_URL=http://<YOUR_SERVER_IP>:5678/
    volumes:
      - ./n8n_data:/home/node/.n8n
    restart: always
```

```bash
docker-compose -f docker-compose.n8n.yml up -d
```

---

## 🔗 Configuration & Integration

### Step 1: Configuring Wazuh Manager

Add inside `ossec.conf`:

```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://<N8N_IP>:5678/webhook/wazuh-alert</hook_url>
  <level>10</level> <alert_format>json</alert_format>
</integration>
```

### Step 2: Creating the Integration Script

```python
#!/usr/bin/env python3
import sys, json, requests
alert_file = sys.argv[1]
with open(alert_file) as f:
    alert_json = json.load(f)
payload = {"title": "Wazuh Alert", "alert": alert_json}
requests.post(sys.argv[3], json=payload)
```

### Step 3: Setting up Google Gemini AI

Create API key → Add to n8n Credentials.

### Step 4: Building the n8n Workflow

Prompt example:

```
You are a Cyber Security Analyst. Analyze the following Wazuh SIEM alert.
...
Provide JSON with keys: summary, severity_score, recommendation.
```

---

## 🧠 Workflow Logic

1. Ingestion
2. Filter
3. Enrichment
4. AI Analysis
5. Route

---

## 📊 Usage & Testing

Simulate brute-force:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<AGENT_IP>
```

---

## 🔧 Troubleshooting

| Issue                | Cause             | Solution      |
| -------------------- | ----------------- | ------------- |
| Alerts not appearing | Integration error | Check logs    |
| Gemini 429           | Rate limit        | Add Wait node |
| Empty Slack message  | Parsing error     | Validate JSON |
| Docker networking    | Isolation         | Same network  |

---

## 🗺 Roadmap

* [ ] Phase 1
* [ ] Phase
