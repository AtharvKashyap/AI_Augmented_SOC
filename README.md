# AI_Augmented_SOC

> AI-assisted triage, enrichment, and incident reporting for Wazuh + Security Onion environments, with Splunk and OpenBSD `pfctl` integrations planned for later phases.

[![CI](https://github.com/your-org/AI_Augmented_SOC/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/AI_Augmented_SOC/actions/workflows/ci.yml)
[![CodeQL](https://github.com/your-org/AI_Augmented_SOC/actions/workflows/codeql.yml/badge.svg)](https://github.com/your-org/AI_Augmented_SOC/actions/workflows/codeql.yml)
[![Secret Scan](https://github.com/your-org/AI_Augmented_SOC/actions/workflows/secrets.yml/badge.svg)](https://github.com/your-org/AI_Augmented_SOC/actions/workflows/secrets.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](#)

---

## What this does

Security teams running Wazuh and Security Onion often need a faster way to consolidate endpoint and network evidence, even when alert volume is low. This project currently provides a tested replay-driven SOC pipeline and CLI, with live Wazuh ingestion as the next implementation phase.

The current MVP foundation:

- **Loads replay events** from JSON files or directories so the pipeline can be tested even when the SOC is quiet
- **Normalizes** Wazuh, Security Onion, and generic replay events into a common alert schema
- **Deduplicates** raw events and alerts using a persistent SQLite-backed deduplication store
- **Clusters** related alerts into incident candidates using shared hosts, users, source IPs, destination IPs, and rule groups
- **Enriches** alerts and candidates with local IOC/risk-factor extraction, with VirusTotal, AbuseIPDB, and Shodan planned as optional providers
- **Triages** alerts or incident candidates with deterministic local fallback and optional OpenRouter-backed LLM analysis
- **Routes** triage results: page analyst now, queue for review, or mark likely benign
- **Builds Markdown incident reports** from candidates, triage results, routing decisions, and enrichment evidence
- **Sends notifications** through dry-run mode, SMTP email, or Slack-compatible webhooks
- **Persists SOC objects** including raw events, alerts, incident candidates, triage results, routing decisions, and dedup keys

- **Runs from a real CLI** through `run_pipeline.py`, producing a JSON summary, SQLite database records, and Markdown incident reports

No SOAR platform required. The MVP is intentionally modular: each SOC stage is unit tested separately, and `soc/pipeline.py` coordinates the full workflow end-to-end.

Current live-ingestion status: replay/manual mode is working now. The next phase is real Wazuh integration using the Wazuh Manager API for agent context and the Wazuh Indexer API for alert search. Manual JSON replay is for testing, demos, and low-alert environments; it is not intended to replace live Wazuh polling.

---

## Stack

| Layer | Tool / Module |
|---|---|
| Replay / testing | JSON replay files and manual test fixtures |
| Endpoint detection | Wazuh agents → Wazuh Manager; Wazuh Indexer alert search planned next |
| Network sensor | Security Onion (Suricata, Zeek) |
| Normalization | `soc/normalizer.py` |
| Deduplication / persistence | SQLite via `soc/store.py` and `soc/dedup.py` |
| Incident clustering | `soc/clustering.py` |
| Local enrichment | `soc/enrichment.py` |
| AI triage | OpenRouter free model via OpenAI-compatible API, with deterministic fallback |
| Routing | `soc/router.py` |
| Reporting | Markdown reports via `soc/report.py` |
| Notifications | Dry-run, SMTP email, Slack-compatible webhook via `soc/notifier.py` |
| Pipeline orchestration | `soc/pipeline.py` |
| Firewall / network response | OpenBSD `pfctl` / `pflog` planned for later phase |
| SIEM / dashboard output | Splunk planned for later phase |

---

## Screenshots

> *(Add screenshots of Wazuh alerts, Security Onion alerts, triage output, and sample reports here. Splunk dashboard screenshots can be added after the Splunk phase.)*

---

## Requirements

- Python 3.11+
- `pip` and a virtual environment
- Optional: OpenRouter API key for LLM-assisted triage: https://openrouter.ai
- Optional next phase: Wazuh Manager API reachable from the SOC automation host, usually `https://<manager>:55000`
- Optional next phase: Wazuh Indexer API reachable from the SOC automation host, usually `https://<indexer>:9200`
- Optional later phase: Security Onion accessible from the SOC automation host
- Optional: SMTP credentials for email report delivery
- Optional: Slack-compatible webhook URL for notifications
- Optional later enrichment providers: VirusTotal, AbuseIPDB, Shodan
- Later phase: Splunk HEC token for dashboard/event output
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
OPENROUTER_API_KEY=your-openrouter-api-key
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=openrouter/free
OPENROUTER_REPORT_MODEL=

# Optional next phase: live Wazuh access
WAZUH_MANAGER_URL=https://your-wazuh-manager:55000
WAZUH_MANAGER_USER=wazuh-wui
WAZUH_MANAGER_PASSWORD=your-password
WAZUH_MANAGER_VERIFY_TLS=false

WAZUH_INDEXER_URL=https://your-wazuh-indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=your-password
WAZUH_INDEXER_VERIFY_TLS=false
WAZUH_ALERT_INDEX=wazuh-alerts-*
WAZUH_ALERT_LIMIT=100

# Optional live Security Onion access
SECURITYONION_HOST=https://your-securityonion
SECURITYONION_USER=your-securityonion-user
SECURITYONION_PASSWORD=your-securityonion-password
```

Optional `.env` values:

```text
POLL_INTERVAL_SECONDS=120
ALERT_LOOKBACK_MINUTES=5
WAZUH_MIN_LEVEL=7
WAZUH_ALERT_LOOKBACK_MINUTES=5
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
SQLITE_DB_PATH=data/soc.db
DEDUP_TTL_HOURS=24
DEDUP_STORE=sqlite
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

### 5. Add optional asset context

The current MVP does not require an asset inventory to run replay tests. Later enrichment can use a static inventory file for business context.

Create `assets.csv` if you want host ownership and criticality context:

```csv
hostname,ip,owner,criticality,internet_facing,department
web-prod-01,203.0.113.10,Platform Team,Critical,Yes,Engineering
dc-01,10.0.0.5,Infra Team,Critical,No,IT
fin-ws-42,10.0.1.42,Endpoint Team,High,No,Finance
```

---

## Usage

### Run the replay pipeline

Replay mode is the current safest end-to-end path. It loads JSON events, normalizes alerts, deduplicates, clusters, enriches, triages, routes, builds reports, and optionally sends notifications.

Python API example:

```python
from soc.pipeline import PipelineConfig, SOCPipeline

pipeline = SOCPipeline.with_sqlite_store(
    "data/soc.db",
    config=PipelineConfig(output_dir="output", send_notifications=False),
)

result = pipeline.run_replay_file("tests/fixtures/sample_incident_replay.json")
print(result.to_summary())
```

Replay directory example:

```python
from soc.pipeline import SOCPipeline

pipeline = SOCPipeline.with_sqlite_store("data/soc.db")
result = pipeline.run_replay_directory("tests/fixtures/manual_events")
print(result.to_summary())
```

### Run the CLI replay demo

The main runnable MVP command is:

```bash
python3 run_pipeline.py \
  --replay tests/fixtures/sample_incident_replay.json \
  --db data/soc.db \
  --output output \
  --pretty
```

This loads the sample replay file, stores processed SOC objects in SQLite, writes a Markdown incident report to `output/`, and prints a JSON run summary.

Example summary:

```json
{
  "raw_events": 3,
  "normalized_alerts": 3,
  "accepted_alerts": 3,
  "candidates": 1,
  "reports": 1,
  "errors": []
}
```

For repeat demos with the same replay file, disable deduplication:

```bash
python3 run_pipeline.py \
  --replay tests/fixtures/sample_incident_replay.json \
  --db data/soc.db \
  --output output \
  --no-dedup \
  --pretty
```

For a safe notification demo without sending real email or Slack messages:

```bash
python3 run_pipeline.py \
  --replay tests/fixtures/sample_incident_replay.json \
  --db data/soc.db \
  --output output \
  --notify \
  --dry-run \
  --no-dedup \
  --pretty
```

`run_pipeline.py` is intentionally thin and delegates the real workflow to `soc.pipeline.SOCPipeline`.

### Planned live Wazuh mode

The next implementation phase is live Wazuh ingestion. The intended command will be:

```bash
python3 run_pipeline.py \
  --wazuh \
  --db data/soc.db \
  --output output \
  --pretty
```

The planned Wazuh flow is:

```text
Wazuh Manager API :55000  -> authentication, manager status, agent inventory
Wazuh Indexer API :9200   -> query wazuh-alerts-* for recent alerts
soc/wazuh_client.py       -> convert alert hits into RawEvent objects
soc/pipeline.py           -> normalize, dedup, cluster, enrich, triage, route, report
```

Replay mode remains useful for repeatable tests and demos, but live Wazuh mode should remove the need to manually copy alerts into JSON files.

### Legacy planned entry points

These scripts are still useful names for later phases, but the current orchestration layer should drive them:

```bash
python3 run_triage.py --once
python3 run_report.py --incident-id INC-20240610-001
```

Reports are written to the configured `OUTPUT_DIR` as Markdown and can be delivered by dry-run, SMTP email, or Slack-compatible webhook notifications.

---

## Project structure

```
AI_Augmented_SOC/
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # Ruff, pytest, and replay CLI smoke test
│   │   ├── codeql.yml          # CodeQL static analysis
│   │   └── secrets.yml         # Gitleaks secret scanning
│   ├── dependabot.yml          # Weekly pip and GitHub Actions dependency updates
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
├── run_pipeline.py             # CLI wrapper for replay-driven pipeline runs
├── run_triage.py               # Planned live polling / one-shot triage entry point
├── run_report.py               # Planned standalone report drafting entry point
│
├── soc/                        # Core package
│   ├── __init__.py
│   ├── config.py               # .env loading, constants
│   ├── models.py               # Dataclasses: Alert, RawEvent, IncidentCandidate, TriageResult, Report
│   ├── store.py                # SQLite persistence for SOC objects and dedup keys
│   ├── pipeline.py             # End-to-end SOC workflow orchestration
│   ├── wazuh_client.py         # Planned Wazuh Manager + Indexer client
│   ├── security_onion_client.py # Security Onion alert/log queries
│   ├── openrouter_client.py    # OpenRouter chat completion wrapper
│   ├── normalizer.py           # Merge and normalize to common alert schema
│   ├── clustering.py           # Group related alerts into incident candidates
│   ├── dedup.py                # SQLite / Redis deduplication store
│   ├── enrichment.py           # Local IOC/risk-factor extraction; external TI providers later
│   ├── triage.py               # Local + OpenRouter triage: score, classify, summarize
│   ├── router.py               # Route by score/action: page / queue / likely-benign
│   ├── report.py               # Markdown incident report generation
│   ├── replay.py               # Sample/manual alert replay for testing low-alert SOCs
│   └── notifier.py             # Dry-run, SMTP email, Slack-compatible webhook delivery
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
    ├── test_models.py
    ├── test_config.py
    ├── test_store.py
    ├── test_dedup.py
    ├── test_replay.py
    ├── test_normalizer.py
    ├── test_clustering.py
    ├── test_enrichment.py
    ├── test_openrouter_client.py
    ├── test_triage.py
    ├── test_router.py
    ├── test_report.py
    ├── test_notifier.py
    ├── test_pipeline.py
    ├── test_wazuh_client.py              # planned / next phase
    ├── test_security_onion_client.py     # planned / next phase
    └── fixtures/
        ├── sample_wazuh_alert.json
        ├── sample_so_alert.json
        ├── sample_incident_replay.json
        └── manual_events/
            ├── .gitkeep
            └── sample_manual_incident.json
```

---

## Current tested modules

The current foundation is heavily unit tested. At this stage, the project validates the core SOC logic before adding live integrations:

| Module | Purpose |
|---|---|
| `soc/models.py` | Shared dataclasses and enums |
| `soc/config.py` | Environment loading and validation |
| `soc/store.py` | SQLite persistence |
| `soc/dedup.py` | Duplicate raw event / alert suppression |
| `soc/replay.py` | Replay file and directory loading |
| `soc/normalizer.py` | Wazuh, Security Onion, and generic alert normalization |
| `soc/clustering.py` | Alert grouping into incident candidates |
| `soc/enrichment.py` | Local IOC and risk-factor enrichment |
| `soc/openrouter_client.py` | OpenRouter-compatible chat completion wrapper |
| `soc/triage.py` | Local and LLM-assisted triage |
| `soc/router.py` | Triage-to-action routing |
| `soc/report.py` | Markdown incident report generation |
| `soc/notifier.py` | Dry-run, SMTP, and Slack-compatible notifications |
| `soc/pipeline.py` | End-to-end orchestration |
| `run_pipeline.py` | CLI wrapper for replay file and replay directory execution |
---

## Current phase status

| Area | Status |
|---|---|
| Replay/manual pipeline | Working |
| CLI replay demo | Working |
| SQLite persistence | Working |
| Deduplication | Working |
| Normalization | Working for replayed Wazuh/Security Onion-shaped events |
| Clustering | Working |
| Local enrichment | Working |
| Local/optional LLM triage | Working |
| Routing | Working |
| Markdown reports | Working |
| Dry-run/SMTP/Slack notification layer | Working |
| Live Wazuh Manager API client | Planned next |
| Live Wazuh Indexer alert search | Planned next |
| Live Security Onion client | Planned after Wazuh |
| PDF reports | Planned polish feature |
| Splunk/OpenBSD integrations | Later phase |

The project is currently a replay-driven MVP with a working end-to-end SOC workflow. The next build phase is `soc/wazuh_client.py` and `tests/test_wazuh_client.py`.

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


Reports are Markdown files generated from an incident candidate, triage result, routing decision, and enrichment evidence. They contain:

1. Executive summary (non-technical, 3–4 sentences)
2. Incident timeline (chronological with timestamps)
3. Affected assets
4. Indicators of compromise (IOCs)
5. Attack narrative
6. Recommended remediation
7. Detection gaps and tuning recommendations

Markdown is used as the source report format because it is easy to diff, test, review in GitHub/VS Code, and convert later. PDF export is a planned polish feature for manager/client-facing reports.

---

## Limitations

- Live Wazuh ingestion is planned next. The current tested path is replay-driven pipeline execution through `run_pipeline.py`.
- Triage scoring is LLM-assisted when configured and should be treated as analyst guidance, not ground truth. Human review of queued alerts is expected.
- Low-alert SOC environments should use replay fixtures and manual test events to validate the pipeline before relying on live alerts.
- OpenRouter free models may have rate limits, availability limits, or model-quality variation. Use a paid or pinned model for production-like testing.
- External enrichment providers such as VirusTotal, AbuseIPDB, and Shodan are planned as optional additions. Current enrichment is local and deterministic.
- Automated response actions such as OpenBSD `pfctl` blocks or Wazuh active response are not included in this version.
- Splunk ingestion and dashboards are planned later and are not required for the MVP.
- Asset inventory is optional and static. CMDB or EDR inventory integration is a future milestone.

---

## Running tests

```bash
pytest tests/ -v
```

Run a focused module test:

```bash
pytest tests/test_pipeline.py -v
```

Run Ruff linting:

```bash
ruff check soc tests run_pipeline.py
```

Run the replay CLI smoke test:

```bash
python3 run_pipeline.py \
  --replay tests/fixtures/sample_incident_replay.json \
  --db data/soc.db \
  --output output \
  --no-dedup \
  --pretty
```

Run the full cross-platform CI locally as closely as possible:

```bash
ruff check soc tests run_pipeline.py
pytest tests/ -v
python3 run_pipeline.py --replay tests/fixtures/sample_incident_replay.json --db data/soc.db --output output --no-dedup --pretty
```