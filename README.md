# AI_Augmented_SOC

> AI-assisted triage, enrichment, and incident reporting for Wazuh + Security Onion environments, with Splunk and OpenBSD `pfctl` integrations planned for later phases.

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](#)

---

## What this does

Security teams running Wazuh and Security Onion often need a faster way to consolidate endpoint and network evidence, even when alert volume is low. This project adds an AI-assisted layer that:

- **Polls** Wazuh and Security Onion separately through their APIs/search backends on a configurable interval
- **Normalizes** endpoint and network alerts into a common schema
- **Generates testable incident candidates** from real alerts, sample fixtures, replay files, or manual test events so the system can be validated even in low-alert environments
- **Triages** alerts or alert clusters with an OpenRouter-hosted free model: scores 1–10, estimates true/false positive likelihood, recommends an action, and explains the evidence
- **Enriches** with optional threat intel (VirusTotal, AbuseIPDB, Shodan) and asset context
- **Routes** alerts: page analyst now (8–10), queue for review (4–7), mark likely benign (1–3)
- **Drafts incident reports** from alert clusters: timeline, IOCs, affected assets, remediation steps
- **Delivers** reports via email, Markdown output, or later Splunk dashboard/webhook integration

No SOAR platform required. Just Python, Wazuh, Security Onion, and an OpenRouter API key. Splunk and OpenBSD `pfctl` automation are planned later, but are not required for the MVP.

---

## Stack

| Layer | Tool |
|---|---|
| Firewall / network | OpenBSD `pfctl` / `pflog` planned for later phase |
| Network sensor | Security Onion (Suricata, Zeek) |
| Endpoint detection | Wazuh agents → Wazuh Manager |
| SIEM / dashboard | Splunk planned for later phase |
| AI triage | OpenRouter free model via OpenAI-compatible API |
| Threat intel | VirusTotal, AbuseIPDB, Shodan |

---

## Screenshots

> *(Add screenshots of Wazuh alerts, Security Onion alerts, triage output, and sample reports here. Splunk dashboard screenshots can be added after the Splunk phase.)*

---

## Requirements

- Python 3.11+
- Wazuh Manager accessible from the SOC automation host
- Security Onion accessible from the SOC automation host
- OpenRouter API key: https://openrouter.ai
- Optional: VirusTotal, AbuseIPDB, Shodan API keys for enrichment
- Optional: SMTP credentials for email report delivery
- Later phase: Splunk HEC token for alert routing back to dashboard
- Later phase: OpenBSD `pfctl` / `pflog` integration for firewall context and approved response actions

---

## Setup

### 1. Clone

```bash
git clone https://github.com/your-org/AI_Augmented_SOC.git
cd AI_Augmented_SOC
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

SECURITYONION_HOST=https://your-securityonion
SECURITYONION_USER=your-securityonion-user
SECURITYONION_PASSWORD=your-securityonion-password

OPENROUTER_API_KEY=your-openrouter-api-key
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=openrouter/free
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

# Testing in low-alert environments
ENABLE_SAMPLE_REPLAY=false
SAMPLE_REPLAY_FILE=tests/fixtures/sample_incident_replay.json
MANUAL_TEST_EVENTS_DIR=tests/fixtures/manual_events

# Later phase: Splunk output
SPLUNK_HEC_URL=
SPLUNK_HEC_TOKEN=

# Later phase: OpenBSD firewall integration
OPENBSD_PF_ENABLED=false
OPENBSD_PF_HOST=
OPENBSD_PF_USER=
OPENBSD_PFLOG_PATH=/var/log/pflog
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

The daemon polls Wazuh and Security Onion every `POLL_INTERVAL_SECONDS`, normalizes new alerts, optionally clusters related evidence, triages them through OpenRouter, and routes the result.

### Run a one-shot triage pass

```bash
python3 run_triage.py --once
```

### Replay sample alerts for testing

If your SOC does not generate many alerts, use replay fixtures to validate the pipeline without waiting for live incidents:

```bash
python3 run_triage.py --replay tests/fixtures/sample_incident_replay.json
```

You can also place manual test events in `tests/fixtures/manual_events/` and run a one-shot pass against those fixtures during development.

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
AI_Augmented_SOC/
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
├── run_triage.py               # Entry point: polling daemon, one-shot, or replay mode
├── run_report.py               # Entry point: report drafting
│
├── soc/                        # Core package
│   ├── __init__.py
│   ├── config.py               # .env loading, constants
│   ├── wazuh_client.py         # Wazuh API/index polling and parsing
│   ├── security_onion_client.py # Security Onion alert/log queries
│   ├── openrouter_client.py    # OpenRouter chat completion wrapper
│   ├── normalizer.py           # Merge and normalize to common alert schema
│   ├── clustering.py           # Group related alerts into incident candidates
│   ├── dedup.py                # SQLite / Redis deduplication store
│   ├── enrichment.py           # VirusTotal, AbuseIPDB, Shodan lookups
│   ├── triage.py               # LLM triage call: score, classify, summarize
│   ├── router.py               # Route alert by score: page / queue / likely-benign
│   ├── report.py               # LLM report drafting from alert cluster
│   ├── replay.py               # Sample/manual alert replay for testing low-alert SOCs
│   ├── notifier.py             # Email delivery; Splunk HEC later
│   └── models.py               # Dataclasses: Alert, IncidentCandidate, TriageResult, Incident, Report
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
    ├── test_security_onion_client.py
    ├── test_normalizer.py
    ├── test_dedup.py
    ├── test_enrichment.py
    ├── test_triage.py
    ├── test_router.py
    ├── test_report.py
    └── fixtures/
        ├── sample_wazuh_alert.json
        ├── sample_so_alert.json
        ├── sample_incident_replay.json
        └── manual_events/
            └── .gitkeep
```

---

## Triage scoring

Each alert or alert cluster is scored 1–10 by the OpenRouter-backed LLM. The score determines routing:

| Score | Classification | Action |
|---|---|---|
| 8–10 | Critical / likely true positive | Page analyst immediately |
| 4–7 | Needs review | Queue for next analyst shift |
| 1–3 | Likely benign / likely false positive | Mark likely benign and keep searchable |

Triage output per alert or cluster includes: score, false-positive likelihood, classification, recommended action, plain-English summary, extracted IOCs, analyst reasoning, and the evidence fields that support the decision.

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
- Low-alert SOC environments should use replay fixtures and manual test events to validate the pipeline before relying on live alerts.
- OpenRouter free models may have rate limits, availability limits, or model-quality variation. Use a paid or pinned model for production-like testing.
- Enrichment depends on third-party API rate limits (VirusTotal, AbuseIPDB, Shodan).
- Automated response actions such as OpenBSD `pfctl` blocks or Wazuh active response are not included in this version — see `PLAN.md` later phases.
- Splunk ingestion and dashboards are planned later and are not required for the MVP.
- Asset inventory is a static CSV. CMDB or EDR integration is a future milestone.

---

## Running tests

```bash
pytest tests/ -v
```