# SILGAX: AI-Powered SOAR Platform

## 📋 Table of Contents

1.  [About The Project](#-about-the-project)
2.  [System Architecture](#-system-architecture)
3.  [Key Features](#-key-features)
4.  [Technology Stack](#-technology-stack)
5.  [Prerequisites](#-prerequisites)
6.  [Installation & Deployment](#-installation--deployment)
    * [1. Wazuh Deployment](#1-wazuh-deployment)
    * [2. n8n Deployment](#2-n8n-deployment)
7.  [Configuration & Integration](#-configuration--integration)
    * [Step 1: Configuring Wazuh Manager](#step-1-configuring-wazuh-manager)
    * [Step 2: Creating the Integration Script](#step-2-creating-the-integration-script)
    * [Step 3: Setting up Google Gemini AI](#step-3-setting-up-google-gemini-ai)
    * [Step 4: Building the n8n Workflow](#step-4-building-the-n8n-workflow)
8.  [Workflow Logic](#-workflow-logic)
9.  [Usage & Testing](#-usage--testing)
10. [Troubleshooting](#-troubleshooting)
11. [Roadmap](#-roadmap)
12. [License](#-license)

---

## 🛡 About The Project

**SILGAX** is an advanced Security Orchestration, Automation, and Response (SOAR) platform designed to bridge the gap between detection and remediation. By integrating **Wazuh** (Open Source XDR/SIEM) with **n8n** (Workflow Automation), SILGAX automates the incident response lifecycle.

Crucially, SILGAX leverages **Google's Gemini AI** to act as a Level 1 Security Analyst. Instead of flooding security teams with raw logs, SILGAX intercepts alerts, analyzes them using Generative AI to determine context, severity, and potential mitigation steps, and then routes intelligent notifications via **Slack** and **Gmail**.

### Why SILGAX?

Traditional SIEMs generate thousands of alerts. SOC analysts often suffer from "alert fatigue," missing critical threats amidst the noise. SILGAX solves this by:

1. **Enriching Data:** Automatically gathering context around an IP or event.
2. **AI Analysis:** Using LLMs to interpret "fuzzy" threats that rule-based engines might misclassify.
3. **Instant Notification:** delivering formatted, actionable reports to communication channels.

> **Target Audience: MSMEs**

> SILGAX is specifically designed to support **Micro, Small and Medium Enterprises (MSMEs)**. Utilizing a completely **open-source** stack and **low-code/no-code** orchestration layer (n8n), SILGAX provides enterprise-grade security automation without the massive licensing costs or specialized coding skills. This makes advanced security accessible and affordable for smaller organizations.

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
   * **Medium Severity:** Logged for review, summary sent to Slack #soc-general.

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
| **SIEM / XDR**     | [Wazuh 4.14 (Current)](https://wazuh.com/)          | Log analysis, file integrity monitoring, intrusion detection. |
| **Orchestrator**   | [n8n](https://n8n.io/)                              | Workflow automation tool connecting disparate APIs.           |
| **Intelligence**   | [Google Gemini AI](https://aistudio.google.com/)    | LLM for natural language summary and threat scoring.          |
| **Notification**   | [Slack API](https://api.slack.com/)                 | Real-time messaging and ChatOps.                              |
| **Notification**   | [Gmail SMTP](https://console.cloud.google.com)      | Formal incident reporting.                                    |
| **Infrastructure** | [Docker](https://www.docker.com)                    | Containerization and orchestration.                           |
| **Scripting**      | Python / Bash                                       | Custom integration scripts for Wazuh.                         |

---

## ⚙ Prerequisites

Before deploying SILGAX, ensure you have the following:

* **Hardware:**

  * Minimum 8GB RAM (16GB Recommended for smooth Wazuh performance).
  * 4 vCPUs.
  * 100GB Disk Space.
* **Software:**

  * Ubuntu 20.04/22.04 LTS (Recommended).
  * Docker & Docker Compose installed.
  * Python 3.9+.
* **API Keys:**

  * **Google Cloud Project** with Gemini API enabled.
  * **Slack App** webhook URL or Bot Token.
  * **Gmail** API OAuth Client ID.

---

## 📦 Installation & Deployment

### 1. Wazuh Deployment

We utilize the standard Docker single-node deployment for Wazuh.

```bash
git clone https://github.com/wazuh/wazuh-docker.git
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
Wazuh needs a script to handle the "custom-n8n" integration name.
1. **Create the script** at `/var/ossec/integrations/`
2. **Permissions:** `chmod 750 /var/ossec/integrations/custom-n8n.py` & `chown root:wazuh`

Restart Wazuh Manager:
```bash
docker exec -it wazuh.manager systemctl restart wazuh-manager
```

### Step 3: Setting up Google Gemini AI

Create API key → Add to n8n Credentials.
1. Go to [Google AI Studio](https://aistudio.google.com/).
2. Create a new API Key.
3. In n8n, go to **Credentials** -\> **New** -\> **Google Gemini API**.
4. Paste your API Key.

### Step 4: Building the n8n Workflow

The n8n workflow is the heart of SILGAX.
**Workflow Nodes:**
1. **Webhook Node:**
   * Method: POST
   * Path: /wazuh-alert
   * Authentication: None (or Header Auth if configured).
3. **Edit Fields (Data Cleaning):**
   * Extract rule.description, agent.name, src_ip, full_log.
5. **Google Gemini Chat Model Node:**
   * **Sample Prompt:**

```
You are a Cyber Security Analyst. Analyze the following Wazuh SIEM alert.

1. Summarize the threat in plain English.
2. Assess the severity (Low/Medium/High/Critical).
3. Recommend immediate mitigation steps.
4. Provide a JSON formatted output with keys: "summary", "severity_score", "recommendation".
```

---

## 🧠 Workflow Logic

The logic flow ensures efficiency and accuracy:
1. **Ingestion:** Alert received.
2. **Filter:** Is the alert known false positive? (Checked against a local exclusion list in n8n Function node).
3. **Enrichment:** * *Optional:* Query VirusTotal API for src_ip reputation (if IP exists).
4. **AI Analysis:** Gemini receives the enriched data. * *Example Input:* "SSH Brute force detection from 192.168.1.50" * *Gemini Output:* "Potential unauthorized access attempt. The IP 192.168.1.50 has failed authentication 10 times in 2 minutes. Severity: High. Recommendation: Block IP in firewall."
5. **Route:** * **Critical:** Slack ping + Email + Create Ticket (Jira/ServiceNow - *Future*). * **Info:** Log to Google Sheets for weekly reporting.

---

## 📊 Usage & Testing

### Simulating an Attack
To verify SILGAX is working, simulate a brute-force attack on a monitored agent.
1. **Attack:** From a different machine:
```bash
    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<AGENT_IP>
```
2. **Observation:**
   * Wazuh Dashboard triggers "SSHD brute force attempt" (Rule ID 5710).
   * Check ossec.log: sending message to custom-n8n...
   * **n8n Interface:** See the execution flow light up.
   * **Slack:** Receive a message:
     > 🚨 **Critical Security Alert**

      > **Threat:** SSH Brute Force
      > **AI Analysis:** Multiple failed logins detected. Likely automated dictionary attack.
      > **Action:** Verify user identity or ban IP.

---

## 🔧 Troubleshooting

| Issue                | Cause             | Solution      |
| -------------------- | ----------------- | ------------- |
| Alerts not appearing | Integration error | Check `/var/ossec/logs/integrations.log` for Python script errors. Ensure permissions are 750 for custom script.    |
| Gemini API Error 429           | Rate limit        | Implement a "Wait" node or upgrade plan. |
| Empty Slack message  | Parsing error     | Ensure the Gemini output is strictly formatted. Use `JSON.parse()` in a Function node before sending to Slack. |
| Docker networking    | Isolation         | Ensure Wazuh and n8n are on the same Docker network or use the Host IP.  |

---

## 🗺 Roadmap

* [x] **Phase 1:** Basic Integration (Wazuh -\> n8n -\> Gmail)
* [x] **Phase 2:** AI Integration (Gemini Contextualization)
* [ ] **Phase 3:** Threat Intelligence Feed Integration (AbuseIPDB, VirusTotal)
* [ ] **Phase 4:** Automated Reporting (PDF Generation of Weekly Incidents)

---

## 📄 License

Distributed under the MIT License. See LICENSE for more information.

---
