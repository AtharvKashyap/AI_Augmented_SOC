# AI_Augmented_SOC

> Automated triage, enrichment, and incident reporting for Security Onion + Wazuh + Splunk environments.

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](#)

---

## What this does

Security teams running Security Onion, Wazuh, and Splunk deal with alert fatigue. This project adds an AI layer that:

- **Polls** Wazuh REST API and Security Onion Elasticsearch on a configurable interval
- **Normalizes** alerts from both sources into a common schema
- **Triages** each alert with an LLM: scores 1–10, classifies true/false positive likelihood, recommends an action
- **Enriches** with threat intel (VirusTotal, AbuseIPDB, Shodan) and asset context
- **Routes** alerts: page analyst now (8–10), queue for review (4–7), auto-close (1–3)
- **Drafts incident reports** from closed alert clusters: timeline, IOCs, affected assets, remediation steps
- **Delivers** reports via email or Splunk dashboard webhook

No SOAR platform required. Just Python, your existing stack, and an LLM API key.

---

## Stack

| Layer | Tool |
|---|---|
| Firewall / network | pfSense on OpenBSD |
| Network sensor | Security Onion (Suricata, Zeek) |
| Endpoint detection | Wazuh agents → Wazuh Manager |
| SIEM / dashboard | Splunk |
| AI triage | Claude API (Anthropic) |
| Threat intel | VirusTotal, AbuseIPDB, Shodan |

---

## Screenshots

> *(Add screenshots of your Splunk dashboard, triage output, and sample report here)*

---

## Requirements

- Python 3.11+
- Wazuh Manager (accessible REST API on port 55000)
- Security Onion with Elasticsearch (port 9200, internal network)
- Anthropic API key: https://console.anthropic.com
- Optional: VirusTotal, AbuseIPDB, Shodan API keys for enrichment
- Optional: Splunk HEC token for alert routing back to dashboard
- Optional: SMTP credentials for email report delivery

---

## Setup

### 1. Clone

```bash
git clone https://github.com/your-org/ai-soc.git
cd ai-soc
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in your credentials
```

Required `.env` values:

```text
WAZUH_HOST=https://your-wazuh-manager:55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=your-password

SECURITYONION_ES_HOST=https://your-securityonion:9200
SECURITYONION_ES_USER=elastic
SECURITYONION_ES_PASSWORD=your-password

ANTHROPIC_API_KEY=your-anthropic-api-key
```

Optional `.env` values:

```text
POLL_INTERVAL_SECONDS=120
ALERT_LOOKBACK_MINUTES=5
WAZUH_MIN_LEVEL=7
SO_MIN_SEVERITY=2

VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=

SPLUNK_HEC_URL=
SPLUNK_HEC_TOKEN=

EMAIL_ENABLED=false
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
EMAIL_FROM=
EMAIL_TO=
EMAIL_USE_TLS=true

OUTPUT_DIR=output
LOG_DIR=logs
DEDUP_STORE=sqlite   # sqlite or redis
REDIS_URL=redis://localhost:6379/0
```

### 5. Add your asset inventory

Create `assets.csv` with your known assets for context enrichment:

```csv
hostname,ip,owner,criticality,internet_facing,department
web-prod-01,203.0.113.10,Platform Team,Critical,Yes,Engineering
dc-01,10.0.0.5,Infra Team,Critical,No,IT
fin-ws-42,10.0.1.42,Endpoint Team,High,No,Finance
```

---

## Usage

### Run the triage daemon (continuous polling)

```bash
python3 run_triage.py
```

The daemon polls Wazuh and Security Onion every `POLL_INTERVAL_SECONDS`, triages new alerts, and routes them.

### Run a one-shot triage pass

```bash
python3 run_triage.py --once
```

### Draft an incident report from a closed alert cluster

```bash
python3 run_report.py --incident-id INC-20240610-001
```

Or pass a JSON file of alert IDs:

```bash
python3 run_report.py --alerts-file incidents/inc_001_alerts.json --notes "Analyst confirmed lateral movement via RDP."
```

Reports are written to `output/` as Markdown and optionally emailed.

### Command-line options

```bash
python3 run_triage.py --help
python3 run_report.py --help
```

---

## Project structure

```
ai-soc/
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # pytest on push
│   │   ├── lint.yml            # Ruff
│   │   └── secrets.yml         # Gitleaks
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
│
├── .env.example
├── .gitignore
├── README.md
├── PLAN.md
├── requirements.txt
│
├── assets.csv                  # Asset inventory with business context
│
├── run_triage.py               # Entry point: polling daemon
├── run_report.py               # Entry point: report drafting
│
├── soc/                        # Core package
│   ├── __init__.py
│   ├── config.py               # .env loading, constants
│   ├── wazuh_client.py         # Wazuh REST API polling and parsing
│   ├── seconion_client.py      # Security Onion Elasticsearch queries
│   ├── normalizer.py           # Merge and normalize to common alert schema
│   ├── dedup.py                # SQLite / Redis deduplication store
│   ├── enrichment.py           # VirusTotal, AbuseIPDB, Shodan lookups
│   ├── triage.py               # LLM triage call: score, classify, summarize
│   ├── router.py               # Route alert by score: page / queue / close
│   ├── report.py               # LLM report drafting from alert cluster
│   ├── notifier.py             # Email and Splunk HEC delivery
│   └── models.py               # Dataclasses: Alert, TriageResult, Incident, Report
│
├── prompts/
│   ├── triage_prompt.txt       # Triage system prompt (externalized)
│   └── report_prompt.txt       # Report drafting system prompt
│
├── output/                     # Generated reports
│   └── .gitkeep
│
├── logs/
│   └── .gitkeep
│
└── tests/
    ├── __init__.py
    ├── test_wazuh_client.py
    ├── test_seconion_client.py
    ├── test_normalizer.py
    ├── test_dedup.py
    ├── test_enrichment.py
    ├── test_triage.py
    ├── test_router.py
    ├── test_report.py
    └── fixtures/
        ├── sample_wazuh_alert.json
        └── sample_so_alert.json
```

---

## Triage scoring

Each alert is scored 1–10 by the LLM. The score determines routing:

| Score | Classification | Action |
|---|---|---|
| 8–10 | Critical / likely true positive | Page analyst immediately |
| 4–7 | Needs review | Queue for next analyst shift |
| 1–3 | Likely false positive | Auto-close and log |

Triage output per alert includes: score, false-positive likelihood, classification, recommended action, plain-English summary, extracted IOCs, and analyst reasoning.

---

## Incident report output

Reports are Markdown files containing:

1. Executive summary (non-technical, 3–4 sentences)
2. Incident timeline (chronological with timestamps)
3. Affected assets
4. Indicators of compromise (IOCs)
5. Attack narrative
6. Recommended remediation
7. Detection gaps and tuning recommendations

---

## Limitations

- Triage scoring is LLM-assisted and should be treated as analyst guidance, not ground truth. Human review of queued alerts is expected.
- Enrichment depends on third-party API rate limits (VirusTotal free tier: 4 req/min).
- Automated response actions (IP blocks, host isolation) are not included in this version — see `PLAN.md` Phase 4.
- Asset inventory is a static CSV. CMDB or EDR integration is a future milestone.

---

## Running tests

```bash
pytest tests/ -v
```

---

## License

MIT
