# AI-SOC Build Plan

> Phased development plan for an AI-augmented SOC on top of Security Onion, Wazuh, and Splunk.

This document tracks what we're building, why, and in what order. Each phase is independently useful — you don't need Phase 4 to get value from Phase 1.

---

## Current stack

```
pfSense (OpenBSD) → Security Onion sensor → Wazuh Manager → Security Onion aggregation → Splunk
```

Wazuh agents run on endpoints and send to Wazuh Manager. Security Onion collects network data from the sensor. Both feeds land in Security Onion, which forwards everything to Splunk. Analysts currently watch Splunk dashboards manually.

---

## Goal

Replace manual alert review with an AI layer that:
1. Continuously polls both data sources
2. Triages every alert with an LLM (score, classify, summarize)
3. Routes alerts to the right destination (page / queue / close)
4. Enriches alerts with threat intel
5. Drafts incident reports automatically
6. Eventually triggers automated response for high-confidence detections

---

## Phases

---

### Phase 1 — Foundation and alert ingestion
**Goal:** Reliably pull alerts from Wazuh and Security Onion into a normalized Python schema.

#### Milestone 1.1 — Wazuh API client
- [ ] Implement JWT authentication against Wazuh Manager REST API (port 55000)
- [ ] Poll `GET /alerts` with configurable minimum severity level (`WAZUH_MIN_LEVEL`)
- [ ] Poll `GET /agents` to build local agent inventory (hostname, IP, OS)
- [ ] Parse alert fields: `rule.level`, `rule.description`, `rule.groups`, `agent.name`, `agent.ip`, `data.*`
- [ ] Handle token expiry and auto-refresh
- [ ] Handle rate limiting with exponential backoff

#### Milestone 1.2 — Security Onion Elasticsearch client
- [ ] Authenticate to Security Onion Elasticsearch (basic auth)
- [ ] Query `so-ids-*` index for Suricata IDS alerts by severity and time window
- [ ] Query `so-zeek-*` index for connection, DNS, and HTTP logs by source IP
- [ ] Query `so-wazuh-*` index as secondary Wazuh data mirror
- [ ] Parse alert fields: `@timestamp`, `rule.name`, `source.ip`, `destination.ip`, `event.severity`, `suricata.alert.signature`

#### Milestone 1.3 — Normalizer
- [ ] Define common `Alert` schema (dataclass): `id`, `source`, `timestamp`, `severity`, `rule_name`, `rule_groups`, `src_ip`, `dst_ip`, `hostname`, `agent_os`, `raw`
- [ ] Map Wazuh fields to common schema
- [ ] Map Security Onion fields to common schema
- [ ] Merge alerts from both sources into single stream

#### Milestone 1.4 — Deduplication store
- [ ] Implement SQLite-backed dedup store (default, zero dependencies)
- [ ] Implement Redis-backed dedup store (optional, for multi-process deploys)
- [ ] Store processed alert IDs with TTL (default 24h)
- [ ] Skip alerts already in store on next poll cycle

#### Milestone 1.5 — Polling daemon
- [ ] Implement main polling loop with configurable `POLL_INTERVAL_SECONDS`
- [ ] Wire Wazuh client + SO client + normalizer + dedup into loop
- [ ] Structured logging (JSON lines) to `logs/`
- [ ] Graceful shutdown on SIGINT / SIGTERM

**Exit criteria:** Daemon runs continuously, pulls new alerts from both sources every N seconds, deduplicates correctly, logs structured output. No LLM calls yet.

---

### Phase 2 — AI triage layer
**Goal:** Score and classify every alert with the LLM. Route alerts by score.

#### Milestone 2.1 — Triage prompt
- [ ] Write `prompts/triage_prompt.txt` system prompt
- [ ] Prompt accepts: rule name, severity, rule groups, agent hostname + OS, src/dst IP, raw event data
- [ ] Prompt returns structured JSON: `score` (1–10), `fp_likelihood` (low/medium/high), `classification`, `action` (page_now/queue_review/auto_close), `summary`, `iocs`, `reasoning`
- [ ] Validate JSON output; retry once on malformed response

#### Milestone 2.2 — Triage client
- [ ] Implement `triage.py` using Anthropic Python SDK (`claude-sonnet-4-6`)
- [ ] Build context block for each alert (alert fields + agent inventory lookup)
- [ ] Call LLM with triage prompt + alert context
- [ ] Parse and validate `TriageResult` dataclass from response
- [ ] Log token usage per call

#### Milestone 2.3 — Router
- [ ] Implement `router.py` routing logic based on `TriageResult.score`
- [ ] Score 8–10: emit `PAGE_NOW` event
- [ ] Score 4–7: emit `QUEUE_REVIEW` event
- [ ] Score 1–3: emit `AUTO_CLOSE` event
- [ ] Write all triage results to SQLite for audit trail

#### Milestone 2.4 — Analyst notification
- [ ] Implement `PAGE_NOW` path: send formatted Slack message or email with triage summary and raw alert link
- [ ] Implement `QUEUE_REVIEW` path: append to analyst review queue (SQLite table)
- [ ] Implement `AUTO_CLOSE` path: log and mark closed

**Exit criteria:** Every new alert is triaged within one poll cycle. High-score alerts generate analyst notifications. Triage results and routing decisions are persisted.

---

### Phase 3 — Enrichment
**Goal:** Attach threat intel and asset context to each alert before triage so the LLM has more signal.

#### Milestone 3.1 — Asset context lookup
- [ ] Load `assets.csv` into memory at startup
- [ ] Match alert `hostname` and `src_ip` to asset inventory
- [ ] Attach: `owner`, `criticality`, `internet_facing`, `department` to alert context
- [ ] Handle missing matches gracefully (unknown asset)

#### Milestone 3.2 — VirusTotal enrichment
- [ ] Implement VT IP reputation lookup (`/api/v3/ip_addresses/{ip}`)
- [ ] Implement VT domain lookup (`/api/v3/domains/{domain}`)
- [ ] Parse: malicious vote count, last analysis stats, known threat actor tags
- [ ] Rate limit to 4 req/min on free tier; skip enrichment on rate limit hit

#### Milestone 3.3 — AbuseIPDB enrichment
- [ ] Implement AbuseIPDB check endpoint (`/api/v2/check`)
- [ ] Parse: abuse confidence score, usage type, ISP, country, number of reports

#### Milestone 3.4 — Shodan enrichment
- [ ] Implement Shodan host lookup (`/shodan/host/{ip}`)
- [ ] Parse: open ports, detected services, CVEs flagged by Shodan, org name
- [ ] Cache Shodan results for 24h (results don't change minute to minute)

#### Milestone 3.5 — Wire enrichment into triage context
- [ ] Run enrichment for `src_ip` before each triage call
- [ ] Include enrichment summary in LLM prompt context block
- [ ] Mark enrichment source in `TriageResult` for audit

**Exit criteria:** Triage prompt includes VT/AbuseIPDB/Shodan context for known IPs. Analyst notifications include enrichment data alongside triage score.

---

### Phase 4 — Incident report drafting
**Goal:** Auto-draft structured incident reports from closed alert clusters.

#### Milestone 4.1 — Incident grouping
- [ ] Group related alerts by: common src IP, common agent, overlapping time window (configurable, default 2h)
- [ ] Assign incident ID (`INC-YYYYMMDD-NNN`)
- [ ] Store incident-to-alert mapping in SQLite

#### Milestone 4.2 — Report prompt
- [ ] Write `prompts/report_prompt.txt` system prompt
- [ ] Prompt accepts: alert timeline (JSON), triage results (JSON), analyst notes (free text)
- [ ] Prompt returns Markdown report with sections: Executive Summary, Timeline, Affected Assets, IOCs, Attack Narrative, Remediation, Detection Gaps

#### Milestone 4.3 — Report client
- [ ] Implement `report.py` using `claude-opus-4-6` (higher quality for final reports)
- [ ] Build full incident context from alert cluster + triage results + enrichment
- [ ] Call LLM with report prompt + incident context
- [ ] Write Markdown report to `output/INC-YYYYMMDD-NNN.md`

#### Milestone 4.4 — Report delivery
- [ ] Implement `run_report.py` CLI: `--incident-id`, `--alerts-file`, `--notes`
- [ ] Email delivery of Markdown report as attachment (reuse `notifier.py` SMTP)
- [ ] Optional: post report summary to Splunk via HEC webhook

**Exit criteria:** Analyst can run `python3 run_report.py --incident-id INC-20240610-001` and receive a fully drafted incident report in under 60 seconds.

---

### Phase 5 — Automated response (controlled)
**Goal:** For high-confidence detections matching pre-approved playbooks, trigger automated response actions without requiring analyst interaction.

> ⚠️ All automated response actions require explicit opt-in via `.env` flags. Nothing runs automatically on first deploy.

#### Milestone 5.1 — Playbook framework
- [ ] Define playbook schema: `trigger_conditions`, `required_confidence`, `action`, `requires_confirmation`
- [ ] Implement `playbooks/` directory with YAML playbook definitions
- [ ] Load and validate playbooks at startup

#### Milestone 5.2 — pfSense block action
- [ ] Implement pfSense API client (pfSense-API or fauxapi)
- [ ] Action: add IP to block alias on pfSense firewall
- [ ] Require `score >= 9` AND `fp_likelihood == low` to trigger without confirmation
- [ ] Log block action with justification; notify analyst

#### Milestone 5.3 — Wazuh active response
- [ ] Implement `PUT /active-response` Wazuh API call
- [ ] Action: trigger `firewall-drop` or `host-deny` on specific agent
- [ ] Require `score >= 9` AND analyst confirmation for host isolation
- [ ] Log response action with alert ID and triage result

#### Milestone 5.4 — Confirmation workflow
- [ ] Implement `requires_confirmation` flag in playbooks
- [ ] For confirmation-required actions: send analyst a Slack/email with one-click approve/deny link
- [ ] Timeout after 15 minutes with no response → no action, escalate
- [ ] Log all confirmation decisions

**Exit criteria:** Confirmed malicious IPs matching a playbook trigger are blocked on pfSense within one poll cycle. Host isolation requires analyst approval. All actions are logged and reversible.

---

### Phase 6 — Analyst assistant interface
**Goal:** Give analysts a conversational interface to query the SOC data, ask about alerts, and get AI-assisted investigation support.

#### Milestone 6.1 — CLI analyst assistant
- [ ] Implement `run_assistant.py` interactive CLI
- [ ] Context window includes: recent alerts, open incidents, triage queue, asset inventory
- [ ] Analyst can ask: "summarize today's high alerts", "what's the blast radius if 10.0.1.42 is compromised", "show all alerts from this IP in the last 24h"

#### Milestone 6.2 — Splunk integration
- [ ] Push triage results back to Splunk via HEC as custom sourcetype `ai_triage`
- [ ] Create Splunk saved search for triage score distribution
- [ ] Create Splunk dashboard panel showing auto-closed vs queued vs paged breakdown

---

## Technical decisions

| Decision | Choice | Rationale |
|---|---|---|
| LLM for triage | `claude-sonnet-4-6` | Fast, cheap per call, good instruction following |
| LLM for reports | `claude-opus-4-6` | Higher quality prose for final deliverables |
| Dedup store | SQLite default, Redis optional | Zero-dependency default; Redis for scaled deploys |
| Enrichment caching | SQLite with TTL | Avoid hammering free-tier APIs on repeated IPs |
| Alert schema | Python dataclasses | Lightweight, typed, no ORM overhead |
| Config | `.env` + `python-dotenv` | Standard pattern, easy to override in CI |

---

## Security notes

- `.env` is never committed. Real credentials live only in `.env` or a secrets manager.
- Wazuh API credentials should use a read-only API user, not the admin account.
- Security Onion ES should be accessed only from within the management network.
- LLM prompts include raw alert data — do not send PII-heavy logs to external LLM APIs without reviewing your data handling policy.
- Automated response actions (Phase 5) are disabled by default and require explicit `.env` opt-in.

---

## Out of scope (for now)

- Full CPE/version-aware vulnerability management (separate tool — see CVE scanner project)
- CMDB integration or EDR API integration
- SharePoint / Teams / Jira ticket creation (can be added to `notifier.py` in Phase 4)
- Multi-tenant or multi-organization deployments

---

## Open questions

- [ ] Do we need Redis for dedup, or is SQLite enough for our alert volume?
- [ ] Which Slack workspace / channel should receive `PAGE_NOW` notifications?
- [ ] What's the approved playbook list for Phase 5 automated response?
- [ ] Do we want Splunk HEC push in Phase 2 or can it wait for Phase 6?
