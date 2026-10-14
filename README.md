# HomeSOC

**HomeSOC** is a software-defined Security Operations Center project that ingests security telemetry from multiple sources, normalizes events, performs risk scoring and cross-source correlation, and presents correlated incidents through a Flask-based investigation dashboard.

> **Status:** Active Development  
> **Purpose:** Cybersecurity / SOC Engineering Portfolio Project

---

## Overview

Security tools often generate alerts independently. HomeSOC is designed to turn those isolated alerts into a unified incident view.

HomeSOC currently supports telemetry modeled after:

- **Suricata EVE JSON**
- **Zeek security notices**
- **Wazuh security alerts**

The system can:

- Normalize events from different security tools
- Assign event risk scores
- Correlate alerts by protected asset and time window
- Detect multi-stage attack activity
- Suppress duplicate detections
- Reward cross-tool corroboration
- Store incidents in SQLite
- Display incidents through a SOC dashboard
- Support analyst investigation states

---

## Architecture

```text
 Suricata ─┐
           │
 Zeek ─────┼──> Event Normalization
           │           │
 Wazuh ────┘           v
                  Risk Scoring
                       │
                       v
               Correlation Engine
                       │
          ┌────────────┼────────────┐
          │            │            │
     Time Window   Deduplication  Corroboration
          │            │            │
          └────────────┼────────────┘
                       │
                       v
                Incident Engine
                       │
                       v
                    SQLite
                       │
                       v
               Flask SOC Dashboard
```

---

## Current Features

### Multi-Source Event Ingestion

HomeSOC contains individual parsers for:

- Suricata
- Zeek
- Wazuh-style alerts

Each parser converts source-specific telemetry into the same internal event format.

### Event Normalization

Normalized events contain fields such as:

```text
timestamp
source
event_type
severity
risk_score
src_ip
dst_ip
asset_ip
description
```

This allows events from different security tools to pass through the same correlation engine.

---

## Risk Scoring

HomeSOC currently assigns risk values based on event type.

| Event Type | Score |
|---|---:|
| Failed Login | 15 |
| Network Scan | 25 |
| File Integrity Change | 30 |
| Multiple Failed Logins | 35 |
| Suspicious DNS | 40 |
| Privilege Escalation | 60 |
| Malware Alert | 70 |
| Command and Control | 80 |

Incident severity is calculated from the resulting correlated score.

---

## Cross-Source Correlation

HomeSOC correlates events affecting the same protected asset within a configurable time window.

Example:

```text
Suricata
Network Scan
    |
    v
Zeek
Password Guessing
    |
    v
Wazuh
Privilege Escalation
    |
    v
Suricata
Suspicious DNS
    |
    v
Zeek / Suricata
Command and Control
```

Instead of displaying these as unrelated alerts, HomeSOC can generate a single incident containing the complete attack sequence.

---

## Duplicate Alert Suppression

Multiple tools may detect the same underlying activity.

Without suppression:

```text
Suricata Network Scan    +25
Zeek Network Scan        +25
Suricata Network Scan    +25
                         ---
                          75
```

HomeSOC keeps all evidence but avoids blindly adding the full score for duplicate detections.

Example:

```text
Initial detection        25
Independent corroboration +6
Repeated duplicate        +0
                         ---
                          31
```

This prevents duplicate security alerts from artificially inflating incident risk.

---

## Cross-Tool Corroboration

HomeSOC differentiates between repeated alerts and independent confirmation.

```text
Same source + same activity
        ↓
Duplicate evidence

Different source + same activity
        ↓
Corroborating evidence
```

Corroborating detections increase confidence while contributing only a limited scoring bonus.

---

## Attack Progression

Security events are mapped to attack stages.

```text
Network Scan
     ↓
Reconnaissance

Multiple Failed Logins
     ↓
Credential Access

Privilege Escalation
     ↓
Privilege Escalation

File Integrity Change
     ↓
System Modification

Suspicious DNS / C2
     ↓
Command and Control
```

A correlated HomeSOC incident can therefore display progression such as:

```text
Reconnaissance
     ↓
Credential Access
     ↓
Privilege Escalation
     ↓
System Modification
     ↓
Command and Control
```

---

## Example Correlation

One current test scenario processes:

```text
Suricata events : 4
Zeek events     : 3
Wazuh events    : 3

Total normalized events: 10
Generated correlated incidents: 1
```

Example incident:

```text
Protected Asset : 192.168.1.20
Raw Events      : 10
Severity        : CRITICAL

Attack Progression:

Reconnaissance
-> Credential Access
-> Privilege Escalation
-> Command and Control
-> System Modification
```

---

## SOC Dashboard

HomeSOC includes a Flask-based investigation dashboard.

Current capabilities include:

- Incident summary statistics
- Critical incident count
- Protected asset count
- Average risk score
- Incident search
- Search by incident ID
- Search by IP address
- Severity filtering
- Individual investigation pages
- Attack progression visualization
- Event evidence timeline
- Analyst workflow status

Incident workflow states:

```text
NEW
INVESTIGATING
RESOLVED
```

---

## Project Structure

```text
HomeSOC/
│
├── attack-scenarios/
├── dashboard/
│   ├── static/
│   │   └── style.css
│   ├── templates/
│   │   ├── dashboard.html
│   │   └── incident.html
│   └── app.py
│
├── data/
├── detections/
├── docs/
│
├── sample-logs/
│   ├── security_events.json
│   ├── suricata_eve.jsonl
│   ├── zeek_notice.jsonl
│   └── wazuh_alerts.jsonl
│
├── scripts/
│   ├── parsers/
│   │   ├── suricata_parser.py
│   │   ├── zeek_parser.py
│   │   └── wazuh_parser.py
│   ├── correlation_engine.py
│   ├── database.py
│   ├── event_parser.py
│   ├── ingest_all.py
│   ├── ingest_suricata.py
│   ├── ingest_wazuh.py
│   ├── ingest_zeek.py
│   ├── log_ingest.py
│   └── risk_engine.py
│
├── .gitignore
├── README.md
└── requirements.txt
```

---

## Technology Stack

- Python
- Flask
- SQLite
- HTML
- CSS
- JSON / JSONL
- Git
- GitHub

Security telemetry represented:

- Suricata EVE JSON
- Zeek notices
- Wazuh-style alerts

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Abhiram-svg01/HomeSOC.git
cd HomeSOC
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

---

## Run Unified Ingestion

```powershell
python scripts\ingest_all.py
```

The unified ingestion pipeline:

1. Loads Suricata, Zeek, and Wazuh telemetry
2. Normalizes the events
3. Sorts events chronologically
4. Correlates events by protected asset
5. Applies duplicate suppression
6. Applies corroboration scoring
7. Builds attack progression
8. Generates incidents
9. Stores incidents in SQLite

---

## Run the Dashboard

```powershell
python dashboard\app.py
```

Then open:

```text
http://127.0.0.1:5000
```

---

## Development Roadmap

Planned improvements:

- Real Suricata sensor integration
- Real Zeek telemetry integration
- Real Wazuh manager integration
- MITRE ATT&CK technique mapping
- Improved confidence scoring
- Configurable detection rules
- Automated incident reports
- Unit and integration testing
- Dashboard source visualizations
- Unique-signal vs raw-alert metrics
- Incident export
- Virtualized SOC lab deployment

---

## Project Scope

HomeSOC is currently a **cybersecurity portfolio and lab project**.

The current repository includes sanitized sample telemetry so the detection and correlation pipeline can be demonstrated without exposing real security data.

The architecture is designed so these test inputs can later be replaced with telemetry generated by actual Suricata, Zeek, and Wazuh deployments.

---

## Author

**Abhiram Shelkar**

Master's in Cybersecurity  
Western Michigan University

GitHub: [Abhiram-svg01](https://github.com/Abhiram-svg01)

---

## Project Goal

HomeSOC demonstrates how isolated security alerts can be transformed into a unified SOC investigation workflow using:

**telemetry normalization, detection engineering, risk scoring, temporal correlation, cross-source correlation, alert deduplication, attack progression, incident persistence, and analyst investigation.**