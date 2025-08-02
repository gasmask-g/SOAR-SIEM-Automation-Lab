<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# Enhanced Security Incident Management with Wazuh \& SOAR Automation

A step-by-step guide to deploy a Security Information and Event Management (SIEM) solution using Wazuh, integrated with SOAR tools (Shuffle \& TheHive) for automated incident response.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Lab Setup](#lab-setup)
- [Installing Wazuh](#installing-wazuh)
- [Installing TheHive](#installing-thehive)
- [Deploying Wazuh Agent on Windows](#deploying-wazuh-agent-on-windows)
- [Configuring Sysmon Telemetry](#configuring-sysmon-telemetry)
- [Capturing Mimikatz \& Custom Rule](#capturing-mimikatz--custom-rule)
- [Integrating Shuffle for Automation](#integrating-shuffle-for-automation)
- [Enrichment with VirusTotal](#enrichment-with-virustotal)
- [Creating Alerts in TheHive](#creating-alerts-in-thehive)
- [Active Response Workflow](#active-response-workflow)
- [Cleanup \& Next Steps](#cleanup--next-steps)


## Overview

Implement a cloud-hosted Wazuh server to collect and analyze logs, a SOAR automation layer (Shuffle) to enrich and forward alerts, and TheHive for incident management. Upon detection (e.g., Mimikatz execution), alerts are automated through Shuffle workflows, enriched via VirusTotal, and pushed to TheHive. Final active-response actions can remove threats automatically.

## Architecture

```text
Windows10 VM (Sysmon + Wazuh Agent)
          │
          ▼
    Wazuh Manager (Cloud VM)
          │ —–> Shuffle (Webhook, HTTP, user-input, VirusTotal, Wazuh API)
          │
          ▼
      TheHive (Cloud VM)
```


## Prerequisites

- VMware or VirtualBox with a Windows 10 VM
- Cloud provider account (e.g., Google Cloud with \$300/90 days credit)
- Static public IPs, firewall rules restricted to your IP
- Domain knowledge: Linux shell, Windows PowerShell


## Lab Setup

1. **Windows 10 VM**
    - Install Sysmon with [sysmon-modular config](https://github.com/SwiftOnSecurity/sysmon-config).
    - Command:

```powershell
.\Sysmon64.exe -i .\sysmonconfig.xml
```

2. **Cloud VMs** for Wazuh \& TheHive:
    - Ubuntu 22.04 LTS x64
    - 8 GB RAM, 2 vCPUs, 160 GB disk
    - Static public IP
    - Firewall: allow only your IP on required ports

## Installing Wazuh

SSH into your Wazuh VM:

```bash
sudo apt-get update && sudo apt-get upgrade -y
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
sudo tar -xvf wazuh-install-files.tar  # extract credentials
```

Access: `https://<WAZUH_IP>`

## Installing TheHive

SSH into your TheHive VM:

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt install wget gnupg apt-transport-https git ca-certificates python3-pip lsb-release
# Java (Amazon Corretto 11)
wget -qO- https://apt.corretto.aws/corretto.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" \
  | sudo tee /etc/apt/sources.list.d/corretto.list
sudo apt update && sudo apt install java-11-amazon-corretto-jdk
# Cassandra
wget -qO- https://downloads.apache.org/cassandra/KEYS \
  | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" \
  | sudo tee /etc/apt/sources.list.d/cassandra.list
sudo apt update && sudo apt install cassandra
# Elasticsearch 7.x
wget -qO- https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update && sudo apt install elasticsearch
# TheHive
wget -O- https://archives.strangebee.com/keys/strangebee.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main" \
  | sudo tee /etc/apt/sources.list.d/strangebee.list
sudo apt update && sudo apt install -y thehive
```

Configure Cassandra (`/etc/cassandra/cassandra.yaml`), Elasticsearch (`/etc/elasticsearch/elasticsearch.yml`), and TheHive (`/etc/thehive/application.conf`) to use your VM’s public IP.
Start \& enable services:

```bash
sudo systemctl enable --now cassandra elasticsearch thehive
```

Access: `http://<THEHIVE_IP>:9000`
Default: `admin@thehive.local` / `secret`

## Deploying Wazuh Agent on Windows

1. In Wazuh UI → **Add Agent** → Windows package.
2. Fill Wazuh server IP, assign agent name.
3. Run generated PowerShell command as Administrator.
4. Start agent:

```powershell
NET START WazuhSvc
```

5. Verify in Wazuh UI → **Agents**

## Configuring Sysmon Telemetry

On Windows 10 agent, locate full channel name in Event Viewer:
`Microsoft-Windows-Sysmon/Operational`

Edit `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Remove other `<localfile>` entries under `<log_analysis>`. Restart Wazuh agent service.

## Capturing Mimikatz \& Custom Rule

1. Download `mimikatz_trunk.zip`; exclude from Defender.
2. Enable full logging in Wazuh manager (`/var/ossec/etc/ossec.conf`):

```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```

3. Restart Wazuh manager \& Filebeat (`/etc/filebeat/filebeat.yml`: `archives.enabled: true`).
4. In Wazuh UI → **Management** → **Rules** → **local_rules.xml**, add:

```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">
    (?i)mimikatz\.exe
  </field>
  <description>Mimikatz Execution Detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

5. Restart manager and test by renaming \& executing Mimikatz.

## Integrating Shuffle for Automation

1. Create an account at [shuffler.io](https://shuffler.io).
2. Workflows → **Create Workflow** → **Webhook** trigger.
3. Copy provided webhook URL and add to Wazuh (`/var/ossec/etc/ossec.conf`):

```xml
<integration>
  <name>shuffle</name>
  <hook_url>YOUR_WEBHOOK_URL</hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```

4. Restart Wazuh manager.
5. In Shuffle workflow:
    - **Webhook** → **SHA256 Regex** (extract `$..sha256$`).
    - **HTTP (GET_API)**:

```bash
curl -u API_USER:API_PASS -k \
  -X GET "https://<WAZUH_IP>:55000/security/user/authenticate?raw=true"
```

    - **VirusTotal** node (authenticate with API key).
    - **User Input** node (email to SOC Analyst).
    - **Wazuh** node: Run Command → `remove-threat` → agent ID.
    - **Email** node: notify threat neutralized.

Trigger on Mimikatz execution to test full flow.

## Enrichment with VirusTotal

- SHA256 Regex node extracts file hash.
- VirusTotal node scans hash across engines; returns malicious verdict.


## Creating Alerts in TheHive

1. Install TheHive app in Shuffle.
2. Authenticate using service account API key.
3. **Create Alert** action with JSON body:

```json
{
  "type": "alert",
  "description": "Mimikatz detected. Investigate immediately.",
  "summary": "Mimikatz execution on host $exec..computer",
  "tags": ["T1003"],
  "severity": "2",
  "source": "Wazuh",
  "flag": true,
  "status": "New"
}
```

4. Rerun workflow; verify alert in TheHive UI under your SOC user.

## Active Response Workflow

### Python Cleanup Script

```python
import os, hashlib, psutil

downloads_folder = r'C:\Users\<USER>\Downloads'
known_hashes = ["29efd64dd3c7fe1e2b022b7ad73a1ba5", "bb8bdb3e8c92e97e2f63626bc3b254c4"]

def calculate_file_hash(path):
    h = hashlib.md5()
    with open(path,'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def terminate_and_delete(path):
    for p in psutil.process_iter(['pid','exe']):
        if p.info['exe'] == path:
            p.terminate(); p.wait()
    os.remove(path)

for root,_,files in os.walk(downloads_folder):
    for name in files:
        path = os.path.join(root,name)
        if calculate_file_hash(path) in known_hashes:
            terminate_and_delete(path)
```

- Convert to EXE (`remove_threat.exe`).
- Add to `/var/ossec/etc/ossec.conf`:

```xml
<command>
  <name>remove-threat</name>
  <executable>remove_threat.exe</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
<active-response>
  <disabled>no</disabled>
  <command>remove-threat</command>
  <location>local</location>
  <rules_id>100092</rules_id>
</active-response>
```

- Restart Wazuh manager.


### Shuffle Adjustments

- **HTTP (GET_API)** for JWT
- **User Input** for SOC decision (True/False)
- **Wazuh** Run Command (remove-threat)
- **Email** notify completion


## Cleanup \& Next Steps

- Review firewall and logs.
- Extend Telemetry (Linux, network devices).
- Add additional SOAR playbooks in Shuffle (phishing, lateral movement).
- Integrate threat intelligence feeds.

---

*Happy Hunting!*

<div style="text-align: center">⁂</div>

