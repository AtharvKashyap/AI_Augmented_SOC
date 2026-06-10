# AI_Augmented_SOC Build Plan

> Phased development plan for an AI-augmented SOC on top of Wazuh and Security Onion, with Splunk and OpenBSD `pfctl` integrations planned for later phases.

This document tracks what we're building, why, and in what order. Each phase is independently useful — you don't need Phase 4 to get value from Phase 1.

---

## Current stack

```
Wazuh agents → Wazuh Manager
Security Onion sensor → Security Onion search/index backend
OpenBSD pfctl / pflog firewall context planned later
Splunk dashboarding planned later
```

Wazuh agents run on endpoints and send endpoint telemetry to Wazuh Manager. Security Onion collects network telemetry from the sensor using tools such as Suricata and Zeek. For the MVP, the automation layer pulls from Wazuh and Security Onion separately, normalizes the evidence itself, and uses an LLM only after the evidence has been collected and structured. Splunk forwarding and OpenBSD `pfctl`/`pflog` integration are planned later.

---

## Goal

Add an AI-assisted layer that:
1. Continuously polls Wazuh and Security Onion directly
2. Normalizes endpoint and network alerts into one internal schema
3. Supports replay/manual test events so the system can be validated even when the SOC has low alert volume
4. Groups related evidence into alert clusters or incident candidates when possible
5. Triages alerts or clusters with an OpenRouter-backed model (score, classify, summarize, recommend action)
6. Routes results to the right destination (page / queue / likely benign)
7. Enriches alerts with optional threat intel and asset context
8. Drafts incident reports and handoff summaries automatically
9. Later integrates Splunk dashboards and OpenBSD `pfctl` response actions

---

## Phases

---

### Phase 1 — Foundation, direct ingestion, and replay testing
**Goal:** Reliably pull alerts from Wazuh and Security Onion into a normalized Python schema, while also supporting fixture/replay input for low-alert SOC environments.

#### Milestone 1.1 — Wazuh API client
- [ ] Implement authentication against Wazuh Manager REST API (port 55000)
- [ ] Poll Wazuh agent inventory using the API to build local context (hostname, IP, OS, status)
- [ ] Pull Wazuh alert data from the configured Wazuh alert source available in the environment: Wazuh indexer/search backend, Wazuh alert JSON logs, or Wazuh data mirrored into Security Onion
- [ ] Support configurable minimum severity level (`WAZUH_MIN_LEVEL`)
- [ ] Parse alert fields when present: `rule.level`, `rule.description`, `rule.groups`, `agent.name`, `agent.ip`, `agent.id`, `data.*`, `full_log`
- [ ] Handle token expiry and auto-refresh
- [ ] Handle connection failures and rate limiting with exponential backoff

#### Milestone 1.2 — Security Onion client
- [ ] Authenticate to the Security Onion search/API endpoint available in the deployment
- [ ] Query Security Onion alert data for Suricata IDS alerts by severity and time window
- [ ] Query Zeek connection, DNS, and HTTP logs by source IP or destination IP when available
- [ ] Optionally query any Wazuh data mirrored into Security Onion as a secondary source
- [ ] Parse alert fields when present: `@timestamp`, `rule.name`, `source.ip`, `destination.ip`, `event.severity`, `suricata.alert.signature`, `network.protocol`, `dns.query`, `url.full`
- [ ] Keep Security Onion access restricted to the management/SOC network

#### Milestone 1.3 — Normalizer
- [ ] Define common `Alert` schema (dataclass): `id`, `source`, `timestamp`, `severity`, `rule_name`, `rule_groups`, `src_ip`, `dst_ip`, `hostname`, `agent_id`, `agent_os`, `user`, `process_name`, `command_line`, `raw`
- [ ] Map Wazuh fields to common schema
- [ ] Map Security Onion fields to common schema
- [ ] Merge alerts from both sources into single stream
- [ ] Preserve original raw event fields for auditability and later report generation

#### Milestone 1.4 — Deduplication store
- [ ] Implement SQLite-backed dedup store (default, zero dependencies)
- [ ] Implement Redis-backed dedup store (optional, for multi-process deploys)
- [ ] Store processed alert IDs with TTL (default 24h)
- [ ] Skip alerts already in store on next poll cycle

#### Milestone 1.5 — Replay and manual test events
- [ ] Implement `replay.py` to load alert sequences from `tests/fixtures/sample_incident_replay.json`
- [ ] Support `python3 run_triage.py --replay tests/fixtures/sample_incident_replay.json`
- [ ] Support manual JSON event files in `tests/fixtures/manual_events/`
- [ ] Allow replay mode to pass through the same normalizer, dedup, clustering, triage, and routing code as live mode
- [ ] Add fixtures for common scenarios: benign Wazuh alert, suspicious endpoint alert, Suricata IDS alert, suspicious DNS event, and combined endpoint + network incident

#### Milestone 1.6 — Polling daemon
- [ ] Implement main polling loop with configurable `POLL_INTERVAL_SECONDS`
- [ ] Wire Wazuh client + Security Onion client + normalizer + dedup into loop
- [ ] Structured logging (JSON lines) to `logs/`
- [ ] Graceful shutdown on SIGINT / SIGTERM

**Exit criteria:** Daemon runs continuously, pulls new alerts from Wazuh and Security Onion every N seconds, deduplicates correctly, supports replay/manual fixtures, and logs structured output. No LLM calls yet.

---

### Phase 2 — Clustering and OpenRouter AI triage layer
**Goal:** Score and classify alerts or alert clusters with an OpenRouter-backed LLM. Route results by score while keeping evidence auditable.

#### Milestone 2.0 — Alert clustering
- [ ] Implement `clustering.py` to group related alerts by host, agent, user, src IP, dst IP, and configurable time window
- [ ] Define `IncidentCandidate` dataclass with `id`, `first_seen`, `last_seen`, `primary_host`, `primary_user`, `src_ips`, `dst_ips`, `alerts`, `related_events`, `asset_context`, and `enrichment`
- [ ] Allow low-volume environments to triage single alerts when no meaningful cluster exists
- [ ] Assign local incident candidate IDs (`CAND-YYYYMMDD-NNN`)
- [ ] Store candidate-to-alert mappings in SQLite for audit and reporting

#### Milestone 2.1 — Triage prompt
- [ ] Write `prompts/triage_prompt.txt` system prompt
- [ ] Prompt accepts: normalized alert fields, optional cluster context, asset context, enrichment context, and selected raw event fields
- [ ] Prompt returns structured JSON: `score` (1–10), `fp_likelihood` (low/medium/high), `classification`, `action` (page_now/queue_review/mark_likely_benign), `summary`, `iocs`, `reasoning`, `evidence`
- [ ] Require the model to cite provided evidence fields for every important claim
- [ ] Require the model to say when evidence is insufficient instead of inventing context
- [ ] Validate JSON output; retry once on malformed response

#### Milestone 2.2 — Triage client
- [ ] Implement `openrouter_client.py` using OpenRouter's OpenAI-compatible chat completions API
- [ ] Implement `triage.py` on top of `openrouter_client.py`
- [ ] Configure `OPENROUTER_API_KEY`, `OPENROUTER_BASE_URL`, and `OPENROUTER_MODEL` in `.env`
- [ ] Build context block for each alert or incident candidate using normalized fields, agent inventory, and selected raw evidence
- [ ] Call the OpenRouter model with triage prompt + context
- [ ] Parse and validate `TriageResult` dataclass from response
- [ ] Log model name, latency, and token usage when available
- [ ] Handle OpenRouter free-model rate limits, unavailable models, and malformed responses gracefully

#### Milestone 2.3 — Router
- [ ] Implement `router.py` routing logic based on `TriageResult.score`
- [ ] Score 8–10: emit `PAGE_NOW` event
- [ ] Score 4–7: emit `QUEUE_REVIEW` event
- [ ] Score 1–3: emit `MARK_LIKELY_BENIGN` event
- [ ] Keep likely-benign events searchable instead of permanently closing or deleting them
- [ ] Write all triage results and routing decisions to SQLite for audit trail

#### Milestone 2.4 — Analyst notification
- [ ] Implement `PAGE_NOW` path: send formatted Slack message or email with triage summary and raw alert link
- [ ] Implement `QUEUE_REVIEW` path: append to analyst review queue (SQLite table)
- [ ] Implement `MARK_LIKELY_BENIGN` path: log, mark likely benign, and keep searchable

**Exit criteria:** New alerts or incident candidates are triaged within one poll cycle. High-score results generate analyst notifications. Triage results, evidence fields, and routing decisions are persisted.

---

### Phase 3 — Enrichment
**Goal:** Attach threat intel and asset context to each alert or incident candidate before triage so the LLM has more signal.

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
- [ ] Run enrichment for relevant `src_ip`, `dst_ip`, domain, or URL values before triage when API keys are configured
- [ ] Include enrichment summary in LLM prompt context block
- [ ] Mark enrichment source and lookup timestamp in `TriageResult` for audit
- [ ] Cache enrichment results in SQLite with TTL to avoid repeated third-party API calls

**Exit criteria:** Triage prompt includes configured VT/AbuseIPDB/Shodan context for known IOCs. Analyst notifications include enrichment data alongside triage score when available.

---

### Phase 4 — Incident report drafting
**Goal:** Auto-draft structured incident reports and shift handoff summaries from alert clusters or incident candidates.

#### Milestone 4.1 — Incident grouping
- [ ] Promote high-value `IncidentCandidate` objects into incidents
- [ ] Group related alerts by: common src IP, common dst IP, common agent, common user, overlapping time window (configurable, default 2h)
- [ ] Assign incident ID (`INC-YYYYMMDD-NNN`)
- [ ] Store incident-to-alert and incident-to-candidate mapping in SQLite

#### Milestone 4.2 — Report prompt
- [ ] Write `prompts/report_prompt.txt` system prompt
- [ ] Prompt accepts: alert timeline (JSON), triage results (JSON), analyst notes (free text)
- [ ] Prompt returns Markdown report with sections: Executive Summary, Timeline, Affected Assets, IOCs, Attack Narrative, Remediation, Detection Gaps

#### Milestone 4.3 — Report client
- [ ] Implement `report.py` using the configured OpenRouter report model
- [ ] Build full incident context from alert cluster + triage results + enrichment
- [ ] Call the OpenRouter model with report prompt + incident context
- [ ] Write Markdown report to `output/INC-YYYYMMDD-NNN.md`

#### Milestone 4.4 — Report delivery
- [ ] Implement `run_report.py` CLI: `--incident-id`, `--alerts-file`, `--notes`
- [ ] Email delivery of Markdown report as attachment (reuse `notifier.py` SMTP)
- [ ] Later phase: post report summary to Splunk via HEC webhook

**Exit criteria:** Analyst can run `python3 run_report.py --incident-id INC-20240610-001` and receive a drafted Markdown incident report. The same reporting logic can also summarize replay-generated incidents for testing.

---

### Phase 5 — Splunk and OpenBSD visibility integrations
**Goal:** Add Splunk output/dashboard support and OpenBSD `pflog` firewall visibility after the Wazuh + Security Onion MVP works.

#### Milestone 5.1 — Splunk output
- [ ] Push triage results back to Splunk via HEC as custom sourcetype `ai_triage`
- [ ] Push incident candidate summaries to Splunk for dashboarding
- [ ] Create saved searches for score distribution, page-now events, likely-benign volume, and repeated hosts/IPs
- [ ] Create dashboard panels showing queued vs paged vs likely-benign breakdown

#### Milestone 5.2 — Splunk input option
- [ ] Add optional Splunk search client as a later ingestion source
- [ ] Allow Splunk to become a unified read layer after forwarding is configured
- [ ] Keep direct Wazuh and Security Onion ingestion available even after Splunk is added

#### Milestone 5.3 — OpenBSD `pflog` visibility
- [ ] Add support for ingesting parsed `pflog` firewall events when available
- [ ] Normalize OpenBSD firewall events into the common alert/event schema
- [ ] Correlate firewall blocks with Wazuh endpoint alerts and Security Onion network alerts
- [ ] Include OpenBSD firewall evidence in triage summaries when available

**Exit criteria:** Triage and incident results can be pushed to Splunk for dashboards, and OpenBSD `pflog` events can be included as additional firewall context when configured.

---

### Phase 6 — Controlled response and analyst assistant interface
**Goal:** Add human-approved response actions and give analysts a conversational interface to query SOC data, ask about alerts, and get AI-assisted investigation support.

#### Milestone 6.0 — Controlled response framework
- [ ] Define playbook schema: `trigger_conditions`, `required_confidence`, `action`, `requires_confirmation`
- [ ] Implement `playbooks/` directory with YAML playbook definitions
- [ ] Load and validate playbooks at startup
- [ ] Require explicit `.env` opt-in for every response capability
- [ ] Log every suggested, approved, denied, and executed response action

#### Milestone 6.1 — CLI analyst assistant
- [ ] Implement `run_assistant.py` interactive CLI
- [ ] Context window includes: recent alerts, open incidents, triage queue, asset inventory
- [ ] Analyst can ask: "summarize today's high alerts", "what's the blast radius if 10.0.1.42 is compromised", "show all alerts from this IP in the last 24h"

#### Milestone 6.2 — OpenBSD `pfctl` approved response
- [ ] Implement an OpenBSD SSH-based response executor for approved `pfctl` changes
- [ ] Action: add a malicious IP to a controlled block table
- [ ] Require analyst confirmation for all firewall changes by default
- [ ] Log the exact command, target IP, reason, approving analyst, and rollback command
- [ ] Provide a rollback helper to remove IPs from the block table

#### Milestone 6.3 — Wazuh active response
- [ ] Implement Wazuh active response integration where supported
- [ ] Action: trigger configured endpoint response such as `firewall-drop` or `host-deny` on a specific agent
- [ ] Require `score >= 9` and analyst confirmation for endpoint-impacting actions
- [ ] Log response action with alert ID, incident ID, and triage result

**Exit criteria:** Analysts can query recent alerts/incidents from a CLI assistant. Any firewall or endpoint response requires explicit opt-in, analyst approval, audit logging, and rollback where possible.

---

## Technical decisions

| Decision | Choice | Rationale |
|---|---|---|
| LLM provider | OpenRouter | OpenAI-compatible API; supports free models for development/testing |
| LLM for triage | Configurable via `OPENROUTER_MODEL` | Avoid hardcoding model names; free models are acceptable for MVP testing |
| LLM for reports | Configurable via `OPENROUTER_REPORT_MODEL` or fallback to `OPENROUTER_MODEL` | Allows better report model later without changing code |
| Dedup store | SQLite default, Redis optional | Zero-dependency default; Redis for scaled deploys |
| Enrichment caching | SQLite with TTL | Avoid hammering free-tier APIs on repeated IPs |
| Alert schema | Python dataclasses | Lightweight, typed, no ORM overhead |
| Replay testing | JSON fixtures | Needed because the SOC may not generate enough live alerts for reliable testing |
| Config | `.env` + `python-dotenv` | Standard pattern, easy to override in CI |

---

## Security notes

- `.env` is never committed. Real credentials live only in `.env` or a secrets manager.
- Wazuh API credentials should use a read-only API user, not the admin account.
- Security Onion access should be allowed only from the management/SOC network.
- OpenRouter prompts may include raw alert data, hostnames, usernames, internal IPs, process names, file paths, URLs, and other sensitive telemetry. Review data handling before sending logs to external models.
- Use field allowlisting and raw-log truncation before sending context to the LLM.
- Automated response actions are disabled by default and require explicit `.env` opt-in plus analyst approval.
- OpenBSD `pfctl` response actions should log rollback commands and should never modify broad firewall rules automatically.

---

## Out of scope (for now)

- Full CPE/version-aware vulnerability management (separate tool — see CVE scanner project)
- Production Splunk-first architecture before forwarding is fully configured
- Automatic firewall blocking or endpoint isolation without analyst approval
- CMDB integration or EDR API integration
- SharePoint / Teams / Jira ticket creation (can be added to `notifier.py` later)
- Multi-tenant or multi-organization deployments

---

## Open questions

- [ ] Which Wazuh alert source is available first: Wazuh indexer/search backend, alert JSON logs, or mirrored Wazuh data in Security Onion?
- [ ] Which Security Onion query method will be used first in this environment?
- [ ] Which OpenRouter free model should be used for MVP testing?
- [ ] Do we need Redis for dedup, or is SQLite enough for our alert volume?
- [ ] Which email address or Slack workspace/channel should receive `PAGE_NOW` notifications?
- [ ] What replay fixtures should we include to prove the system works despite low alert volume?
- [ ] Which OpenBSD `pflog` format/parser should be supported first?
- [ ] What actions, if any, should be allowed in the future `pfctl` response playbook?
