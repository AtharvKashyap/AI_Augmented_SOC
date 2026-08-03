# AI_Augmented_SOC Build Plan

> Phased development plan for an AI-augmented SOC on top of Wazuh and Security Onion, with Splunk and OpenBSD `pfctl` integrations planned for later phases.

This document tracks what we're building, why, and in what order. Each phase is independently useful — you don't need Phase 4 to get value from Phase 1.

**Status legend:** `[x]` done and unit tested · `[~]` partially done, see note · `[ ]` not started

Status reflects the code as of the `defect-fixes` branch: 277 passing tests, `ruff` clean, replay and Wazuh-`alerts.json` ingestion working end to end. Nothing marked `[x]` has yet been exercised against a live Wazuh Manager or a live LLM call — every `[x]` means "implemented and unit tested against fakes."

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

## Immediate priorities

The phases below are all still in scope.

**Done** (branch `defect-fixes`): LLM triage is wired into the run path with `--no-llm` to force local; LLM context is allowlisted and truncated; analysis provenance is recorded, persisted, and displayed. See Known defects → Fixed.

**Next, and the one that changes what this project is:**

1. **Build the evaluation harness and labeled set** (Milestone 2.5). There is still no way to tell whether a triage score is any good, and therefore no way to tell whether a prompt or model change helped or hurt. Until this exists, every quality claim in this document is unfalsifiable.
2. **Get one real LLM run against real alerts.** `OPENROUTER_API_KEY` in `.env` is still the `replace-me` placeholder, so runs currently attempt an LLM call, fail auth, and fall back to local — visible as `triage_mode: llm` with `local_fallbacks > 0` in the summary. A real key plus a decision on model choice is the remaining blocker.
3. **Make `alerts.json` ingestion unattended-safe** (Milestone 1.1a) before attempting the daemon.

---

## Phases

---

### Phase 1 — Foundation, direct ingestion, and replay testing
**Goal:** Reliably pull alerts from Wazuh and Security Onion into a normalized Python schema, while also supporting fixture/replay input for low-alert SOC environments.

#### Milestone 1.1 — Wazuh API client
- [x] Implement authentication against Wazuh Manager REST API (port 55000)
- [x] Poll Wazuh agent inventory using the API to build local context (hostname, IP, OS, status)
- [~] Pull Wazuh alert data from the configured Wazuh alert source available in the environment: Wazuh indexer/search backend, Wazuh alert JSON logs, or Wazuh data mirrored into Security Onion — **`json_logs` only.** `WazuhClient.from_settings` rejects any other `WAZUH_ALERT_SOURCE`. Indexer settings exist in `Settings` with no client behind them.
- [x] Support configurable minimum severity level (`WAZUH_MIN_LEVEL`)
- [x] Parse alert fields when present: `rule.level`, `rule.description`, `rule.groups`, `agent.name`, `agent.ip`, `agent.id`, `data.*`, `full_log`
- [x] Handle token expiry and auto-refresh — re-authenticates once on 401/403 via `request(retry_auth=True)`
- [ ] Handle connection failures and rate limiting with exponential backoff — no backoff in the Wazuh client; `OpenRouterClient` has linear retry backoff, the Wazuh client has none

#### Milestone 1.1a — Make `alerts.json` ingestion unattended-safe *(new)*
Required before the daemon (1.6) can run against a real Manager. The current reader is correct for one-shot CLI use and unsafe for continuous use.
- [ ] Track a byte offset per file so each cycle reads only new lines instead of re-reading the whole file
- [ ] Track inode/device so log rotation is detected and the offset resets instead of silently skipping alerts
- [x] Skip and count malformed lines rather than raising — skipped lines are counted on `last_malformed_line_count` and logged as a warning; missing-file and not-a-file still raise
- [ ] Persist the cursor in SQLite alongside the dedup keys
- [ ] Decide and document a real transport: run on the Manager host, scheduled SFTP pull, or socket/Filebeat forwarding. "Copy the file manually" is not a deployment story.

#### Milestone 1.2 — Security Onion client
No Security Onion client module exists — the empty placeholder was deleted. Security Onion *normalization* is implemented and tested (1.3); only live retrieval is missing.
- [ ] Authenticate to the Security Onion search/API endpoint available in the deployment
- [ ] Query Security Onion alert data for Suricata IDS alerts by severity and time window
- [ ] Query Zeek connection, DNS, and HTTP logs by source IP or destination IP when available
- [ ] Optionally query any Wazuh data mirrored into Security Onion as a secondary source
- [ ] Parse alert fields when present: `@timestamp`, `rule.name`, `source.ip`, `destination.ip`, `event.severity`, `suricata.alert.signature`, `network.protocol`, `dns.query`, `url.full`
- [ ] Keep Security Onion access restricted to the management/SOC network

#### Milestone 1.3 — Normalizer
- [x] Define common `Alert` schema (dataclass): `id`, `source`, `timestamp`, `severity`, `rule_name`, `rule_groups`, `src_ip`, `dst_ip`, `hostname`, `agent_id`, `agent_os`, `user`, `process_name`, `command_line`, `raw`
- [x] Map Wazuh fields to common schema
- [x] Map Security Onion fields to common schema
- [x] Merge alerts from both sources into single stream — `Normalizer.normalize` dispatches on `EventSource`; the pipeline consumes one merged list
- [x] Preserve original raw event fields for auditability and later report generation

#### Milestone 1.4 — Deduplication store
- [x] Implement SQLite-backed dedup store (default, zero dependencies)
- [ ] ~~Implement Redis-backed dedup store (optional, for multi-process deploys)~~ — **deferred indefinitely.** See Answered questions: SQLite is sufficient at our volume, and `REDIS_URL` should be removed from `.env.example` rather than left implying support.
- [x] Store processed alert IDs with TTL (default 24h)
- [x] Skip alerts already in store on next poll cycle

#### Milestone 1.5 — Replay and manual test events
- [x] Implement `replay.py` to load alert sequences from `tests/fixtures/sample_incident_replay.json`
- [x] Support `python3 run_pipeline.py --replay tests/fixtures/sample_incident_replay.json` — the CLI is `run_pipeline.py`, not the originally planned `run_triage.py`, whose empty placeholder was deleted
- [x] Support manual JSON event files in `tests/fixtures/manual_events/` — via `--replay-dir` / `load_replay_directory`
- [x] Allow replay mode to pass through the same normalizer, dedup, clustering, triage, and routing code as live mode
- [~] Add fixtures for common scenarios: benign Wazuh alert, suspicious endpoint alert, Suricata IDS alert, suspicious DNS event, and combined endpoint + network incident — four fixtures exist (`sample_wazuh_alert`, `sample_so_alert`, `sample_incident_replay`, `manual_events/sample_manual_incident`); the benign and DNS scenarios are missing, and these five are the natural seed for the labeled set in 2.5

#### Milestone 1.6 — Polling daemon
Depends on 1.1a. Without a cursor, a polling loop re-reads the whole alert file every cycle.
- [ ] Implement main polling loop with configurable `POLL_INTERVAL_SECONDS`
- [ ] Wire Wazuh client + Security Onion client + normalizer + dedup into loop
- [ ] Structured logging (JSON lines) to `logs/`
- [ ] Graceful shutdown on SIGINT / SIGTERM

**Exit criteria:** Daemon runs continuously for 24h against a real Wazuh Manager without manual intervention, processes every new alert exactly once across at least one log rotation, survives malformed lines without aborting a cycle, and writes structured logs. Measured: zero duplicate `alert.id` values in the `alerts` table, and zero gaps when the cycle count is reconciled against the raw file. No LLM calls yet.

---

### Phase 2 — Clustering and OpenRouter AI triage layer
**Goal:** Score and classify alerts or alert clusters with an OpenRouter-backed LLM. Route results by score while keeping evidence auditable, and be able to *prove* the scores are usable.

#### Milestone 2.0 — Alert clustering
- [x] Implement `clustering.py` to group related alerts by host, agent, user, src IP, dst IP, and configurable time window
- [~] Define `IncidentCandidate` dataclass with `id`, `first_seen`, `last_seen`, `primary_host`, `primary_user`, `src_ips`, `dst_ips`, `alerts`, `related_events`, `asset_context`, and `enrichment` — all present except `asset_context`, which lands with Milestone 3.1
- [x] Allow low-volume environments to triage single alerts when no meaningful cluster exists
- [x] Assign local incident candidate IDs (`CAND-YYYYMMDD-NNN`) — actual format is `CAND-YYYYMMDD-NNN-<content hash>`; the hash makes reruns idempotent and is worth keeping
- [x] Store candidate-to-alert mappings in SQLite for audit and reporting

#### Milestone 2.1 — Triage prompt
- [x] Prompt lives in `TRIAGE_SYSTEM_PROMPT` in `soc/triage.py`, not in a text file — **decision recorded:** keeping it in Python makes it versionable and unit testable. The dead `prompts/*.txt` files were deleted.
- [x] Prompt accepts: normalized alert fields, cluster context, and selected raw event fields — via `build_alert_context` / `build_candidate_context` / `build_enrichment_context`. Asset context lands with Milestone 3.1.
- [x] **Allowlist context fields and truncate raw logs before the call** — `ALERT_CONTEXT_FIELDS` / `RAW_CONTEXT_FIELDS` / `CANDIDATE_CONTEXT_FIELDS` / `ENRICHMENT_CONTEXT_FIELDS`, `MAX_CONTEXT_FIELD_CHARS=512`, `MAX_CONTEXT_ALERTS=20`. `Alert.raw`, `related_events`, and enrichment provider raw responses are excluded entirely.
- [x] Prompt returns structured JSON: `score`, `fp_likelihood`, `classification`, `action`, `summary`, `iocs`, `reasoning`, `evidence`, `recommended_actions` — all requested and all parsed. Grouped and flat IOC shapes both accepted; malformed evidence entries are dropped rather than aborting triage.
- [x] Require the model to cite provided evidence fields for every important claim — required in the system prompt, parsed into `EvidenceItem` objects
- [x] Require the model to say when evidence is insufficient instead of inventing context — required in the system prompt, with an instruction to prefer `queue_review` over `page_now` when evidence is thin
- [~] Validate JSON output; retry once on malformed response — validation exists; **there is still no retry**, malformed output goes straight to local fallback
- [x] Version the prompt and record the version on every result — `TRIAGE_PROMPT_VERSION = "triage-v1"`, recorded on every LLM result and persisted
- [ ] Verify empirically that the model actually cites only provided fields — needs Milestone 2.5 plus a real key

#### Milestone 2.2 — Triage client
- [x] Implement `openrouter_client.py` using OpenRouter's OpenAI-compatible chat completions API
- [x] Implement `triage.py` on top of `openrouter_client.py`
- [x] Configure `OPENROUTER_API_KEY`, `OPENROUTER_BASE_URL`, and `OPENROUTER_MODEL` in `.env`
- [x] Build context block for each alert or incident candidate using normalized fields, agent inventory, and selected raw evidence — now allowlisted and truncated
- [x] **Call the OpenRouter model with triage prompt + context from the actual run path** — `run_pipeline.py` injects `TriageEngine(OpenRouterClient.from_settings(settings))` whenever `OPENROUTER_API_KEY` is set; `--no-llm` forces local. Not yet executed against a real key.
- [x] Parse and validate `TriageResult` dataclass from response
- [x] Log model name, latency, and token usage when available — `TriageEngine` prefers `chat_completion` so the provider-reported model and usage are captured; latency measured around the call
- [x] Handle OpenRouter free-model rate limits, unavailable models, and malformed responses gracefully — retryable-error detection with linear backoff, then local fallback

#### Milestone 2.3 — Router
- [x] Implement `router.py` routing logic based on `TriageResult.score`
- [x] Score 8–10: emit `PAGE_NOW` event
- [x] Score 4–7: emit `QUEUE_REVIEW` event
- [x] Score 1–3: emit `MARK_LIKELY_BENIGN` event
- [x] Keep likely-benign events searchable instead of permanently closing or deleting them
- [x] Write all triage results and routing decisions to SQLite for audit trail
- [x] **Collapse score→action to a single source of truth.** `respect_triage_action` is gone; the router always derives the action from the score via the configured thresholds, so tuning them now visibly changes routing. `TriageResult.action` is retained as a record of what was *suggested*, and disagreement between suggestion and score policy is surfaced in `RoutingDecision.message` — a useful signal for Milestone 2.5.

#### Milestone 2.4 — Analyst notification
- [x] Implement `PAGE_NOW` path: send formatted Slack message or email with triage summary and raw alert link
- [~] Implement `QUEUE_REVIEW` path: append to analyst review queue (SQLite table) — a `routing_decisions` row is written, but there is no queue table, no work-list, and no way to mark an item handled. Nothing can currently be *reviewed*.
- [x] Implement `MARK_LIKELY_BENIGN` path: log, mark likely benign, and keep searchable

#### Milestone 2.4a — Make the review queue real *(new)*
The human-in-the-loop is currently asserted but absent, and analyst disagreement is the only source of ground truth this project will ever get for free. Building this early feeds 2.5 continuously instead of requiring a one-off labeling session.
- [ ] Add an `analyst_queue` table: `triage_result_id`, `candidate_id`, `queued_at`, `reviewed_at`, `analyst_verdict` (agree / too_high / too_low / wrong_class), `analyst_score`, `notes`
- [ ] Minimal CLI to list open items, show the candidate and its evidence, and record a verdict — a short read-and-write loop, not the Phase 6 assistant
- [ ] Export recorded verdicts into the labeled set used by 2.5

#### Milestone 2.5 — Evaluation harness and labeled set *(new)*
The gap that matters most. Nothing today distinguishes good triage from bad, so no prompt or model change is currently measurable.
- [ ] Create `tests/fixtures/labeled/` with 40+ alerts and candidates: real where possible, replay fixtures otherwise, seeded from 1.5's scenarios
- [ ] Each entry carries an expected score band, expected action, expected classification, and a one-line rationale
- [ ] Implement an eval runner that scores the whole set through local triage and through LLM triage and reports: action agreement rate, mean absolute score error, and a confusion matrix over the three actions
- [ ] Report the two failure modes separately, because they are not symmetric: **missed true positives** (labeled malicious, scored ≤3) and **noise** (labeled benign, scored ≥8)
- [ ] Run the local-triage half in CI on every push; the LLM half stays manual/opt-in so CI needs no API key
- [ ] Record prompt version, model, and date on every eval run so results are comparable over time

#### Milestone 2.6 — Analysis provenance *(new)* — **complete**
- [x] Add `analysis_source` to `TriageResult`: `local` or `llm` — new `AnalysisSource` enum in `soc/models.py`
- [x] Populate `model`, `latency_ms`, `token_usage`, and prompt version on every LLM result
- [x] Persist all of the above in the `triage_results` table — as queryable columns plus an index on `analysis_source`; `SQLiteStore.initialize` migrates pre-existing databases via `_apply_column_migrations`
- [x] State the source plainly in Markdown reports and in notifications — reports carry an **Analysis source** line; notification bodies and metadata carry the source and model
- [x] Add a metric for fallback rate — the run summary reports `triage_mode`, `analysis_sources`, and `local_fallbacks` (counted only in LLM mode, since a local-mode run has not fallen back from anything)

**Exit criteria:** LLM triage runs from the CLI against a real OpenRouter key, and on the labeled set of Milestone 2.5: **no alert labeled malicious scores ≤3**, at least **60% of alerts labeled benign score ≤3**, and **action agreement ≥70%**. Every stored result names its analysis source and model. Fallback rate under normal operation is known and recorded. High-score results generate analyst notifications; queued results can actually be reviewed and a verdict recorded.

---

### Phase 3 — Enrichment
**Goal:** Attach threat intel and asset context to each alert or incident candidate before triage so the LLM has more signal.

Nothing in this phase is started. `LocalEnricher` provides deterministic local IOC extraction and IP classification today, which is what the pipeline currently feeds to triage; the external providers below are all unimplemented despite having keys in `.env.example`.

#### Milestone 3.1 — Asset context lookup
- [ ] Load `assets.csv` into memory at startup — no asset code exists anywhere in `soc/`
- [ ] Match alert `hostname` and `src_ip` to asset inventory
- [ ] Attach: `owner`, `criticality`, `internet_facing`, `department` to alert context
- [ ] Handle missing matches gracefully (unknown asset)
- [ ] Add the `asset_context` field to `IncidentCandidate` that Milestone 2.0 specified

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
- [x] Run enrichment for relevant `src_ip`, `dst_ip`, domain, or URL values before triage when API keys are configured — the wiring exists and runs; only local enrichment flows through it
- [x] Include enrichment summary in LLM prompt context block
- [ ] Mark enrichment source and lookup timestamp in `TriageResult` for audit — `EnrichmentResult` carries `provider` and `looked_up_at`, but neither is surfaced on the triage result
- [ ] Cache enrichment results in SQLite with TTL to avoid repeated third-party API calls — no enrichment cache table exists
- [ ] Do not send enrichment provider raw responses to the LLM unfiltered; they inherit the 2.1 allowlist rule

**Exit criteria:** Triage prompt includes configured VT/AbuseIPDB/Shodan context for known IOCs, and enrichment provider plus lookup timestamp appear on the stored triage result. Measured on the Milestone 2.5 labeled set: enabling enrichment does not regress action agreement, and improves score accuracy on the subset of entries with external IPs. Repeated runs over the same IOCs make zero additional third-party API calls within the TTL.

---

### Phase 4 — Incident report drafting
**Goal:** Auto-draft structured incident reports and shift handoff summaries from alert clusters or incident candidates.

Deterministic Markdown reporting already works and is tested — `MarkdownReportBuilder` renders candidate, triage, routing, and enrichment data into the seven planned sections without an LLM, and the pipeline writes `output/<candidate-id>.md` on every run. That is a better default than planned: reports exist even with no API key, and they are diffable in tests. The remaining work is `INC-*` promotion, LLM-assisted narrative, and delivery.

#### Milestone 4.1 — Incident grouping
- [ ] Promote high-value `IncidentCandidate` objects into incidents — only `CAND-*` exists today; there is no incident tier
- [ ] Group related alerts by: common src IP, common dst IP, common agent, common user, overlapping time window (configurable, default 2h)
- [ ] Assign incident ID (`INC-YYYYMMDD-NNN`)
- [ ] Store incident-to-alert and incident-to-candidate mapping in SQLite
- [ ] Define the promotion rule explicitly (score threshold, analyst action, or both) rather than leaving it implicit

#### Milestone 4.2 — Report prompt
- [ ] Write the report system prompt in Python alongside the triage prompt, matching the 2.1 decision — the dead `prompts/report_prompt.txt` was deleted; the current report is templated rather than generated
- [ ] Prompt accepts: alert timeline (JSON), triage results (JSON), analyst notes (free text)
- [ ] Prompt returns Markdown report with sections: Executive Summary, Timeline, Affected Assets, IOCs, Attack Narrative, Remediation, Detection Gaps
- [ ] Prompt context obeys the 2.1 allowlist and truncation rules

#### Milestone 4.3 — Report client
- [x] Implement `report.py` — done deterministically; all seven sections render from stored data
- [ ] Add LLM-assisted narrative using the configured OpenRouter report model, with the deterministic renderer as the permanent fallback rather than a stopgap
- [x] Build full incident context from alert cluster + triage results + enrichment
- [ ] Call the OpenRouter model with report prompt + incident context
- [x] Write Markdown report to `output/<id>.md` — currently `output/CAND-*.md`; becomes `output/INC-*.md` once 4.1 lands
- [ ] Mark LLM-drafted versus templated reports on the report itself, per Milestone 2.6

#### Milestone 4.4 — Report delivery
- [ ] Implement `run_report.py` CLI: `--incident-id`, `--alerts-file`, `--notes` — the empty placeholder was deleted; create it when implementing
- [ ] Email delivery of Markdown report as attachment (reuse `notifier.py` SMTP) — `EmailNotifier` sends report text in the body; there is no attachment support
- [ ] Later phase: post report summary to Splunk via HEC webhook

**Exit criteria:** Analyst can run `python3 run_report.py --incident-id INC-20240610-001` and receive a drafted Markdown incident report by email. Every report states whether it was LLM-drafted or templated. The same reporting logic summarizes replay-generated incidents for testing, and report generation still succeeds with no API key configured.

---

### Phase 5 — Splunk and OpenBSD visibility integrations
**Goal:** Add Splunk output/dashboard support and OpenBSD `pflog` firewall visibility after the Wazuh + Security Onion MVP works.

Not started. Milestone 5.2 in particular should not begin until someone has asked for it — it means maintaining two ingestion architectures, and the plan already commits to keeping direct ingestion regardless.

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

**Exit criteria:** Triage and incident results can be pushed to Splunk for dashboards, and OpenBSD `pflog` events can be included as additional firewall context when configured. Both are optional: with Splunk and pflog unconfigured, the pipeline runs unchanged and the test suite is unaffected.

---

### Phase 6 — Controlled response and analyst assistant interface
**Goal:** Add human-approved response actions and give analysts a conversational interface to query SOC data, ask about alerts, and get AI-assisted investigation support.

Not started, and correctly last. Note that the essential fragment of this phase — capturing analyst verdicts — has been pulled forward to Milestone 2.4a, because it is the only feedback signal the system will get and Phase 2 needs it. Nothing here should begin before Phase 2's exit criteria are met: response actions driven by unmeasured scores are the worst possible ordering.

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
- [ ] Require the score to come from a model result, not a local fallback — a regex heuristic must never be able to trigger an endpoint action

**Exit criteria:** Analysts can query recent alerts/incidents from a CLI assistant. Any firewall or endpoint response requires explicit opt-in, analyst approval, audit logging, and rollback where possible. No response path can be triggered by a locally-scored result, and the labeled-set metrics from 2.5 are recorded at the time any response capability is enabled.

---

## Known defects

### Fixed

All fixed under TDD on branch `defect-fixes`; suite grew from 240 to 277 tests.

| Defect | Fix |
|---|---|
| LLM triage never invoked from the CLI | `run_pipeline.py` builds `TriageEngine(OpenRouterClient.from_settings(settings))` when `OPENROUTER_API_KEY` is set; `--no-llm` forces local |
| Triage payload included full `Alert.raw` | Allowlisted context builders with per-field truncation and cluster cap; raw events, related events, and provider raw responses excluded |
| `model` / `latency_ms` / `token_usage` never set | Populated from the client; `TriageEngine` prefers `chat_completion` so the real model name and usage are recorded |
| LLM and local results indistinguishable | New `AnalysisSource` enum on `TriageResult` plus `prompt_version`; persisted as queryable columns; stated in reports and notifications; `local_fallbacks` in the run summary |
| `iocs`, `evidence`, `recommended_actions` never populated | Prompt requests them; parsers normalize grouped or flat IOCs and drop malformed evidence entries rather than aborting |
| Prompt never required evidence citation or admitted insufficiency | Both now required in `TRIAGE_SYSTEM_PROMPT`, versioned as `triage-v1` |
| One malformed line aborted the run | Malformed lines skipped, counted on `last_malformed_line_count`, and logged as a warning |
| `respect_triage_action` made router thresholds dead | Field removed; score is the sole routing authority; suggestion/policy disagreement surfaced in `RoutingDecision.message` |
| `prompts/*.txt` unread | Deleted; prompts live in Python so they can be versioned and unit tested |
| Empty placeholder files | `run_report.py`, `run_triage.py`, `soc/security_onion_client.py` and its empty test deleted |
| `pydantic` declared, unused | Removed from `requirements.txt` |

### Open

| Defect | Location | Effect |
|---|---|---|
| No read cursor; whole file re-read each run | `soc/wazuh_client.py` `read_recent_alerts` | Cost scales with file size; rotation unhandled. Blocks the daemon — see Milestone 1.1a |
| No retry on malformed LLM JSON | `soc/triage.py` `_triage_payload` | One bad response falls straight through to local scoring instead of retrying once (Milestone 2.1) |
| `REDIS_URL` / `DEDUP_STORE` still read by config | `soc/config.py` | Implies a Redis dedup option that does not exist; removing them is a config change, not cleanup |
| No enrichment provider or timestamp on `TriageResult` | `soc/triage.py` | Milestone 3.5 audit requirement still unmet |

---

## Technical decisions

| Decision | Choice | Rationale |
|---|---|---|
| LLM provider | OpenRouter | OpenAI-compatible API; supports free models for development/testing |
| LLM for triage | Configurable via `OPENROUTER_MODEL` | Avoid hardcoding model names; free models are acceptable for MVP testing |
| LLM for reports | Configurable via `OPENROUTER_REPORT_MODEL` or fallback to `OPENROUTER_MODEL` | Allows better report model later without changing code |
| Deterministic path is permanent, not a stopgap | Every stage works with no API key | Keeps CI offline and free, keeps the system usable during rate limits, and makes the LLM's contribution measurable by difference |
| Dedup store | SQLite only | Zero dependencies; Redis deferred indefinitely at our volume |
| Enrichment caching | SQLite with TTL | Avoid hammering free-tier APIs on repeated IPs |
| Alert schema | Python dataclasses | Lightweight, typed, no ORM overhead |
| Object IDs | Content-addressed (`CAND-YYYYMMDD-NNN-<hash>`) | Reruns are idempotent and overwrite rather than duplicate |
| Pipeline errors | Accumulated per run, `fail_fast` opt-in | One bad event should not lose a batch; check `summary["errors"]`, not just exit code |
| Replay testing | JSON fixtures | Needed because the SOC may not generate enough live alerts for reliable testing |
| Triage quality | Measured against a labeled set (2.5) | Unmeasured triage cannot be trusted to close alerts |
| Config | `.env` + `python-dotenv` | Standard pattern, easy to override in CI |

---

## Security notes

- `.env` is never committed. Real credentials live only in `.env` or a secrets manager.
- Wazuh API credentials should use a read-only API user, not the admin account.
- `WAZUH_MANAGER_VERIFY_TLS=false` in `.env.example` is a lab convenience. Any real deployment sets it to `true` with a trusted CA.
- Security Onion access should be allowed only from the management/SOC network.
- OpenRouter prompts may include raw alert data, hostnames, usernames, internal IPs, process names, file paths, URLs, and other sensitive telemetry. Review data handling before sending logs to external models.
- Field allowlisting and raw-log truncation before sending context to the LLM: **implemented** (Milestone 2.1). Only fields named in `ALERT_CONTEXT_FIELDS` / `RAW_CONTEXT_FIELDS` / `CANDIDATE_CONTEXT_FIELDS` / `ENRICHMENT_CONTEXT_FIELDS` leave the process, each truncated to 512 characters. Adding a field to a model does not add it to the prompt. Review the allowlist whenever those constants change, and note that `full_log` is allowlisted, so arbitrary log text — truncated — does still egress.
- Record an explicit decision about whether real client telemetry may be sent to free-tier OpenRouter models, whose terms differ from paid tiers on prompt retention and training.
- Automated response actions are disabled by default and require explicit `.env` opt-in plus analyst approval.
- OpenBSD `pfctl` response actions should log rollback commands and should never modify broad firewall rules automatically.
- No response action may be triggered by a locally-scored (non-model) triage result.

---

## Out of scope (for now)

- Full CPE/version-aware vulnerability management (separate tool — see CVE scanner project)
- Redis-backed dedup (SQLite is sufficient at our volume)
- Production Splunk-first architecture before forwarding is fully configured
- Automatic firewall blocking or endpoint isolation without analyst approval
- CMDB integration or EDR API integration
- SharePoint / Teams / Jira ticket creation (can be added to `notifier.py` later)
- Multi-tenant or multi-organization deployments
- Fine-tuning or self-hosting a triage model; prompt and context quality is the lever until the labeled set says otherwise

---

## Answered questions

- **Which Wazuh alert source is available first?** Manager `alerts.json` (`WAZUH_ALERT_SOURCE=json_logs`). The Manager REST API is used only for optional agent inventory context. Indexer ingestion is unbuilt and not currently needed.
- **Do we need Redis for dedup?** No. SQLite is sufficient at our alert volume. Removed from the plan; `REDIS_URL` should come out of `.env.example`.
- **Alert schema shape?** Settled in `soc/models.py` and stable across all nine stages.

## Open questions

- [ ] Which Security Onion query method will be used first in this environment?
- [ ] Which OpenRouter model for MVP testing — and is a paid pinned model warranted, given that free-tier rate limits push the system into local fallback and free-tier prompt-retention terms differ?
- [ ] Who labels the Milestone 2.5 evaluation set, and against what definition of "should have been paged"?
- [ ] Which email address or Slack workspace/channel should receive `PAGE_NOW` notifications?
- [ ] What transport delivers `alerts.json` in the target environment: run on the Manager, SFTP pull, or forwarding?
- [ ] Which OpenBSD `pflog` format/parser should be supported first?
- [ ] What actions, if any, should be allowed in the future `pfctl` response playbook?
