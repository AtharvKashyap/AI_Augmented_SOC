# AI_Augmented_SOC Build Plan

> Phased development plan for an AI-augmented SOC on top of Wazuh and Security Onion, with Splunk and OpenBSD `pfctl` integrations planned for later phases.

This document tracks what we're building, why, and in what order. Each phase is independently useful — you don't need Phase 4 to get value from Phase 1.

**Status legend:** `[x]` done and unit tested · `[~]` partially done, see note · `[ ]` not started

Status reflects the code as of the `defect-fixes` branch: 326 passing tests, `ruff` clean, replay and Wazuh-`alerts.json` ingestion working end to end. Nothing marked `[x]` has yet been exercised against a live Wazuh Manager or a live LLM call — every `[x]` means "implemented and unit tested against fakes."

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
2. **Confirm Security Onion Pro licensing.** The Connect API client is built and tested against a faked transport, but the API is a Pro-tier feature. If the deployment is not Pro, this path cannot authenticate and an index-level read path becomes a new milestone.
3. **Get one real LLM run against real alerts.** `OPENROUTER_API_KEY` in `.env` is still the `replace-me` placeholder, so runs currently attempt an LLM call, fail auth, and fall back to local — visible as `triage_mode: llm` with `local_fallbacks > 0` in the summary. A real key plus a decision on model choice is the remaining blocker.
4. **Run the daemon for 24h against a real Wazuh Manager.** The loop, cursor, rotation handling, and failure resilience are built and tested; only the long unattended run against real infrastructure is outstanding.

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
- [x] Handle connection failures and rate limiting with exponential backoff — bounded retry for connection errors, timeouts, 429, and 5xx via `WazuhManagerConfig.max_retries` / `retry_backoff_seconds`. Other 4xx are not retried, and the single 401/403 re-auth path is unchanged. Sleep is injectable so tests never wait.

#### Milestone 1.1a — Make `alerts.json` ingestion unattended-safe *(new)*
Prerequisite for the daemon (1.6), now met. A cursor store is used only in daemon mode; a one-shot CLI run still reads the whole file, as it always has.
- [x] Track a byte offset per file so each cycle reads only new lines instead of re-reading the whole file
- [x] Track inode/device so log rotation is detected and the offset resets instead of silently skipping alerts
- [x] Detect in-place rewrite via a content fingerprint of the file's leading bytes — inode and size are both unchanged when a log is truncated and refilled to a similar length, so size shrinkage alone silently dropped alerts
- [x] Skip and count malformed lines rather than raising — skipped lines are counted on `last_malformed_line_count` and logged as a warning; missing-file and not-a-file still raise
- [x] Persist the cursor in SQLite alongside the dedup keys — `ingest_cursors` table and `IngestCursor` model
- [ ] Decide and document a real transport: run on the Manager host, scheduled SFTP pull, or socket/Filebeat forwarding. "Copy the file manually" is not a deployment story.

#### Milestone 1.2 — Security Onion client
Implemented in `soc/security_onion_client.py` against the **Security Onion Connect API**, selected via `run_pipeline.py --security-onion`.

> **Licensing:** the Connect API is an enterprise feature and requires a **Security Onion Pro license**. Without one these settings will not authenticate. Replay fixtures remain the fallback, and an index-level read path would be a separate milestone.

- [x] Authenticate to the Security Onion search/API endpoint — OAuth2 client credentials: `POST /oauth2/token` with HTTP Basic auth and `grant_type=client_credentials`, returning a bearer token cached until shortly before `expires_in` elapses. Create the client under Administration → API Clients with the `events/read` permission.
- [x] Query Security Onion alert data by severity and time window — `GET /connect/query/data`. Severity is compared through `severity_from_security_onion` rather than numerically, because Suricata numbers severity *downwards*: with `SO_MIN_SEVERITY=2`, severities 1 and 2 are kept and 3+ dropped. Documents with no interpretable severity are kept rather than silently dropped.
- [~] Query Zeek connection, DNS, and HTTP logs by source or destination IP — reachable through the same endpoint by supplying a `query`, but no dedicated Zeek helper methods yet
- [~] Optionally query Wazuh data mirrored into Security Onion — possible via the `query` parameter; not wired as a distinct source
- [x] Parse alert fields when present — handled by the existing `normalize_security_onion_event`. A test asserts the full seam: a Connect API document becomes a `RawEvent` that normalizes to an `Alert` with the expected `src_ip`, `dst_ip`, `rule_name`, `hostname`, and severity.
- [x] Keep Security Onion access restricted to the management/SOC network — documented in `.env.example` and Security notes; `SECURITYONION_VERIFY_TLS` defaults to true
- [x] Tolerate undocumented response shapes — one extractor handles a top-level `events` list, a nested `data.events` list, and Elasticsearch-style `hits.hits[]._source`. An unrecognized shape returns nothing and logs a warning naming the keys actually received, so a real deployment is diagnosable from logs.
- [x] Bounded exponential retry for connection errors, timeouts, 429 and 5xx; other 4xx not retried; a persistent 401 re-authenticates exactly once
- [x] Re-apply severity and lookback filtering locally after the query, so a grid that ignores the inferred parameters below still returns correctly filtered results

**Parameters that are inferred, not documented.** The Security Onion docs do not publish the time-range, limit, timezone, or date-format parameter names for `/connect/query/data`; sibling endpoints use `range`, `zone`, and `format`. Every inferred name and value lives **only** as a `SecurityOnionConfig` field (`range_param`, `zone_param`, `format_param`, `limit_param` defaulting to `eventLimit`, plus `zone`, `date_format`, `range_datetime_format`, `range_separator`, and the deployment-specific `query` index pattern). None is hardcoded at a call site, so a real grid is corrected in exactly one place. Confirmed and hardcoded: the token endpoint and its auth, the bearer header, `/connect/query/data`, `query`, `gridId`, and `/connect/info`.

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
- [x] Implement main polling loop with configurable `POLL_INTERVAL_SECONDS` — `soc/daemon.py`, driven by `run_pipeline.py --daemon`, with `--poll-interval` and `--max-cycles` overrides
- [~] Wire Wazuh client + Security Onion client + normalizer + dedup into loop — Wazuh, normalizer, dedup, and the read cursor are wired; Security Onion waits on Milestone 1.2. Replay sources also work, mainly for testing the loop.
- [x] Structured logging (JSON lines) to `logs/` — one `cycle_completed` or `cycle_failed` record per cycle, plus start/stop records
- [x] Graceful shutdown on SIGINT / SIGTERM — signals set a flag and the loop exits at the next safe point, never mid-cycle; the wait between cycles is sliced so shutdown does not have to sit out a long poll interval
- [x] Survive a failing cycle — a cycle that raises is logged and the loop continues. A daemon that dies because one poll failed stops processing alerts silently, which is worse than a noisy failure.
- [x] Build the pipeline, Wazuh client, and cursor once and reuse across cycles, so state is not reset every poll

Verified end to end against a growing `alerts.json`: cycle 1 read 2 alerts and produced 1 candidate, cycle 2 read 0 (cursor held), cycle 3 read only the newly appended alert. Zero failed cycles.

**Exit criteria:** Daemon runs continuously for 24h against a real Wazuh Manager without manual intervention, processes every new alert exactly once across at least one log rotation, survives malformed lines without aborting a cycle, and writes structured logs. Measured: zero duplicate `alert.id` values in the `alerts` table, and zero gaps when the cycle count is reconciled against the raw file. No LLM calls yet.

**Status:** every mechanism is built and tested, including rotation, truncation, in-place rewrite, malformed lines, and failing cycles. The 24h run against a real Manager has **not** happened — that plus Milestone 1.2 is what remains for Phase 1.

---

### Phase 2 — Clustering and OpenRouter AI triage layer
**Goal:** Score and classify alerts or alert clusters with an OpenRouter-backed LLM. Route results by score while keeping evidence auditable, and be able to *prove* the scores are usable.

**Build order for the remaining work**, chosen for dependency direction and leverage:

1. ~~Retry unparseable LLM responses (2.1)~~ — **done.** Smallest change, and it reduces spurious fallbacks that would otherwise pollute every measurement taken later.
2. **Analyst review queue (2.4a)** — next. It defines the verdict schema that the evaluation set consumes, and it closes the human-in-the-loop gap. Independent of having a real API key.
3. **Evaluation harness (2.5)** — last, because it reads 2.4a's verdict schema and is the thing to run first once a real key exists.

**Verification status: this phase is being built without verification, by decision.** Every mechanism will be implemented and unit tested, but the exit criteria below are numeric thresholds that require a real LLM run against labeled data, and `OPENROUTER_API_KEY` is still a placeholder. Until that run happens:

- Phase 2 is **implementation-complete, verification-pending**. Do not read a checked box here as evidence that triage quality is acceptable.
- Any labeled entries authored without analyst review are **synthetic**: they record what we decided the scorer *should* say. Measuring against them demonstrates self-consistency, not accuracy. They must stay clearly separated from analyst-derived labels.

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
- [x] Validate JSON output; retry once on malformed response — `TriageEngine.max_json_retries` (default 1). Only unparseable responses are retried; transport failures are not, because `OpenRouterClient` already retries those with backoff and retrying twice would multiply the wait on a rate-limited model.
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
The human-in-the-loop was asserted but absent, and analyst disagreement is the only source of ground truth this project will ever get for free. Building this early feeds 2.5 continuously instead of requiring a one-off labeling session.
- [x] Add an `analyst_queue` table — keyed on `triage_result_id`, which is itself a deterministic content fingerprint, so re-running the pipeline cannot double-queue the same decision. Columns: `target_id`, `target_type`, `score`, `action`, `analysis_source`, `queued_at`, `reviewed_at`, `analyst_verdict`, `analyst_score`, `notes`.
- [x] New `AnalystVerdict` enum (`agree` / `too_high` / `too_low` / `wrong_class`) and `ReviewQueueItem` model. The verdict records *how* a score was wrong, not only whether, because over-scoring and misclassification call for different fixes.
- [x] The pipeline enqueues only `queue_review` results. Paged results are already in front of an analyst; likely-benign results stay searchable without demanding attention. An enqueue failure is recorded without discarding the run.
- [x] Minimal CLI (`run_review.py`) to list open items, show a queued decision with its evidence, and record a verdict
- [x] Export recorded verdicts with analyst provenance, so they can never be confused with synthetic labels
- [x] Feed those verdicts into the 2.5 labeled set — via Milestone 2.5a. `run_review.py promote` converts verdicts into loadable labeled cases, closing the loop that justified building 2.4a before 2.5.

#### Milestone 2.5 — Evaluation harness and labeled set *(new)*
The gap that mattered most: nothing distinguished good triage from bad, so no prompt or model change was measurable. `soc/evaluation.py` plus the `run_eval.py` CLI.
- [~] Create `tests/fixtures/labeled/` with 40+ alerts and candidates — **the harness is complete; the set holds 5 seed cases, not 40.** Growing it is a labeling task, not a coding task, and analyst-reviewed entries exported from 2.4a are the intended source. The seed exists to make the harness real and CI-enforceable.
- [x] Each entry carries an expected score band, acceptable actions, optional classification, and a required one-line rationale. A label without a stated reason is rejected at load time: a label nobody can review is a label nobody should trust. Bands accept **multiple** acceptable actions, because genuinely ambiguous alerts should not be labeled as though one answer were correct.
- [x] Eval runner scoring the whole set through local or LLM triage, reporting action agreement, in-band rate, score error, and an action confusion matrix. Score error is the distance *outside* the expected band, not from a midpoint: an in-band score is not an error.
- [x] Report the two failure modes separately — `missed_true_positives` (labeled serious, scored ≤3) and `noise_cases` (labeled benign, scored ≥8). Deliberately never averaged: `mark_likely_benign` means nobody looks again, so a missed detection is not interchangeable with a wasted page.
- [x] Local half runs in CI on every push via `run_eval.py --fail-under-thresholds`; the LLM half is opt-in through `--llm` so CI needs no API key. In LLM mode fallback is **disabled**, so a failed model call is a visible error rather than a local score quietly standing in for one and skewing the measurement.
- [x] Exit criteria are executable: `EvaluationThresholds` encodes them and `check()` returns one message per unmet criterion, so a build can be gated on triage quality.
- [x] Label provenance is tracked and surfaced. `is_analyst_validated` is false for any run containing a synthetic label, and the CLI prints the caveat to stderr on every such run, so a self-consistency run can never be quietly reported as an accuracy result.
- [ ] Record prompt version and model on every eval run so results are comparable over time — the triage result carries both; the eval summary does not yet copy them through

**First run found two real defects** in local scoring, which is the harness earning its place:

1. **`private_ip` was treated as a score-raising risk factor.** Local enrichment tags every internal address with it, so each internal IP added +1 — inflating every internal-only alert, which is most alerts in a SOC. A routine internal SSH login scored 4 and landed in the review queue. Fixed via `NON_ESCALATING_RISK_FACTORS`: the tag remains as context but no longer raises a score.
2. **Log filenames were extracted as domain IOCs.** `auth.log` parses as a domain because `.log` looks like a TLD, so a filename became an indicator, polluting reports and inviting the model to reason about a file as infrastructure. Fixed with `NON_DOMAIN_SUFFIXES`, deliberately excluding extensions that are also real TLDs (`.sh`, `.zip`, `.mov`).

#### Milestone 2.5a — Convert analyst verdicts into labeled cases *(new)* — **complete**
The missing link between the review queue and the evaluation set. Without it, analyst judgment could not reach the harness and the labeled set would stay synthetic forever.
- [x] Reconstruct a replayable fixture from a reviewed target, using the raw events already persisted for it (`SQLiteStore.list_raw_events_for_target`), so a labeled case is self-contained and committable rather than dependent on a live database whose rows age out
- [x] Derive an expected score band and acceptable actions from the verdict: `agree` narrows around the score triage gave, `too_high` and `too_low` open the band on the side the analyst indicated rather than inventing a number they never gave, and an explicit `analyst_score` takes precedence over any inference
- [x] Carry the analyst's notes through as the required rationale, synthesizing one when notes are absent, and mark provenance `analyst_reviewed`
- [x] Skip reviewed items whose source events are no longer recoverable, and report how many were skipped — a case that cannot be replayed cannot be scored
- [x] `run_review.py promote --labels PATH` does it in one command, and a test covers the seam between the two CLIs

Verified end to end with real components: pipeline run → item queued at score 4 → analyst records `too_high` with score 2 → promoted to a case with band `[1, 3]` and provenance `analyst_reviewed` → evaluation reports `is_analyst_validated: true` and flags the case out of band, because triage said 4 and the analyst said 3 or less. The disagreement is now a measurable signal rather than a lost opinion.

**Open finding, deliberately not "fixed":** the Suricata trojan-download-cradle case scores 6 against a labeled band of 7–10 — the local heuristic under-weights a network IDS malware signature. Its action still falls in the acceptable set. Tuning the scorer to hit a number we invented ourselves would be circular, so this is recorded as a finding for a real labeled set to confirm or refute.

#### Milestone 2.6 — Analysis provenance *(new)* — **complete**
- [x] Add `analysis_source` to `TriageResult`: `local` or `llm` — new `AnalysisSource` enum in `soc/models.py`
- [x] Populate `model`, `latency_ms`, `token_usage`, and prompt version on every LLM result
- [x] Persist all of the above in the `triage_results` table — as queryable columns plus an index on `analysis_source`; `SQLiteStore.initialize` migrates pre-existing databases via `_apply_column_migrations`
- [x] State the source plainly in Markdown reports and in notifications — reports carry an **Analysis source** line; notification bodies and metadata carry the source and model
- [x] Add a metric for fallback rate — the run summary reports `triage_mode`, `analysis_sources`, and `local_fallbacks` (counted only in LLM mode, since a local-mode run has not fallen back from anything)

**Exit criteria:** LLM triage runs from the CLI against a real OpenRouter key, and on the labeled set of Milestone 2.5: **no alert labeled malicious scores ≤3**, at least **60% of alerts labeled benign score ≤3**, and **action agreement ≥70%**. Every stored result names its analysis source and model. Fallback rate under normal operation is known and recorded. High-score results generate analyst notifications; queued results can actually be reviewed and a verdict recorded.

**Status: NOT MET, and not met by building more code.** The provenance, notification, and review-queue requirements are reachable without a key. The three numeric thresholds are not: they need a real key, a real model choice, and labels that came from a human looking at real alerts. This is the honest boundary of what implementation alone can deliver.

---

### Phase 3 — Enrichment
**Goal:** Attach threat intel and asset context to each alert or incident candidate before triage so the LLM has more signal.

Implemented. `soc/threat_intel.py` defines the provider layer; `soc/assets.py`, `soc/virustotal_client.py`, `soc/abuseipdb_client.py` and `soc/shodan_client.py` are the pieces behind it. `LocalEnricher` still runs first and external results are added to it, so enrichment degrades to local-only when no keys are configured.

**None of it has run against a live provider API.** Every provider is tested against a faked transport, exactly like the Wazuh and Security Onion clients.

Four rules are enforced by the layer rather than left to each provider:

- **Internal addresses are never sent upstream.** Querying `10.0.1.50` at a third party discloses internal addressing, returns nothing useful, and burns free-tier quota. Non-global addresses are dropped before any call. Note this also excludes RFC 5737 documentation ranges, so fixtures using `203.0.113.x` will not trigger lookups.
- **A provider failure is contained** — logged and skipped, so an outage costs one lookup rather than the run.
- **The verdict must live in the `summary`**, because the triage allowlist withholds enrichment `raw` from the model. A verdict recorded only in the details would never reach triage.
- **Risk factors are dropped for non-escalating verdicts** by `IntelLookup.to_enrichment_result`, not left to provider discipline. Local scoring boosts on any risk factor, so a provider reporting one alongside a clean verdict would silently inflate scores.

#### Milestone 3.1 — Asset context lookup
- [x] Load an asset CSV at startup — `soc/assets.py`, via `ASSET_INVENTORY_PATH`. Unknown extra columns are ignored, since a real CMDB export has more columns than we care about.
- [x] Match alert `hostname` and `src_ip` to asset inventory — hostname first, then IP. Matching is case-insensitive and resolves short name against FQDN in both directions, because alerts and CMDBs disagree about FQDNs constantly.
- [x] Attach `owner`, `criticality`, `internet_facing`, `department` to candidate context, and put `asset_context` in the triage allowlist: asset criticality is often what separates queueing from paging.
- [x] Handle missing matches gracefully — an unknown asset, an absent inventory, and an unrecognized criticality value all degrade rather than raise. A configured-but-unreadable inventory does fail loudly, because continuing would leave triage quietly blind while the run looked healthy.
- [x] Add the `asset_context` field to `IncidentCandidate` that Milestone 2.0 specified

#### Milestone 3.2 — VirusTotal enrichment
- [x] VT IP reputation lookup (`/api/v3/ip_addresses/{ip}`) and domain lookup (`/api/v3/domains/{domain}`)
- [x] Parse analysis counts, reputation and tags into a bounded subset. Verified at 235 bytes with a 50 KB `whois` blob correctly excluded — the payload is cached and persisted, so it must stay small.
- [x] Rate limit to 4 req/min via `min_seconds_between_calls = 15.0`, enforced by the enricher
- [x] **A single flagging engine is `SUSPICIOUS`, never `MALICIOUS`** (threshold 2). One engine hit is very often a false positive, and this is the difference between a useful signal and a page-generating machine. Thresholds live in the config so they are tunable.

#### Milestone 3.3 — AbuseIPDB enrichment
- [x] AbuseIPDB check endpoint (`/api/v2/check`) with a configurable `maxAgeInDays`
- [x] Parse confidence score, usage type, ISP, country, report count and allowlist flag into eight bounded keys
- [x] Verdict boundaries verified exactly: 75 malicious, 74 suspicious, 25 suspicious, 24 unknown, zero-score-zero-reports benign. `isWhitelisted` overrides even a score of 95, because an explicit allowlist is stronger evidence than an aggregate score.
- [x] A 429 raises with a message saying the daily quota is exhausted — an operational condition someone needs to recognize, not a generic failure

#### Milestone 3.4 — Shodan enrichment
- [x] Shodan host lookup (`/shodan/host/{ip}`)
- [x] Parse open ports, detected services, CVEs and org into a capped subset. The raw `data` banner array is never stored — a host record can be enormous and it gets cached.
- [x] Cached for 24h by the shared enrichment cache
- [x] **Shodan can never return `MALICIOUS`, and the enum member is never constructed in the module.** Shodan reports what a host *exposes*, not whether it is bad: an IP with 40 open ports is usually a load balancer. Known CVEs give `SUSPICIOUS`; everything else is `UNKNOWN` with a useful context summary that says so explicitly, so a bare exposure line cannot be misread as either a clean or a bad reputation result.
- [x] The API key is passed as a query parameter, so it is redacted from every exception and log line. Verified: a 401 names `SHODAN_API_KEY` without disclosing the key.

#### Milestone 3.5 — Wire enrichment into triage context
- [x] Run enrichment for relevant indicator values before triage when API keys are configured — external results are appended to local ones, and `--no-intel` forces a fully offline run
- [x] Include enrichment summary in the LLM prompt context block
- [x] Mark enrichment provider and lookup timestamp — both are on every `EnrichmentResult` and both are in the triage context allowlist, so the model sees which provider said what and when
- [x] Cache enrichment results in SQLite with TTL — `enrichment_cache`, keyed per provider *and* indicator type so two providers cannot read each other's answers. Failures are deliberately not cached: caching one would suppress retries for the whole TTL.
- [x] Never send provider raw responses to the model — they inherit the 2.1 allowlist, which excludes `raw` entirely. Verified end to end.
- [x] Duplicate indicators are collapsed so the same value is never paid for twice

**Exit criteria:** Triage prompt includes configured VT/AbuseIPDB/Shodan context for known IOCs, and enrichment provider plus lookup timestamp appear on the stored triage result. Measured on the Milestone 2.5 labeled set: enabling enrichment does not regress action agreement, and improves score accuracy on the subset of entries with external IPs. Repeated runs over the same IOCs make zero additional third-party API calls within the TTL.

**Status: mechanisms met, measurement not.** Verified end to end with real providers behind faked transports: asset context and both provider verdicts reached the model, provider raw stayed withheld, external intel escalated the candidate to `page_now`, and a second run over the same indicator made **zero** additional API calls. What is *not* done is the measured half — that needs real provider keys and the labeled set from 2.5, which is still 5 synthetic cases. Do not read this phase as evidence that enrichment improves triage quality; it is evidence that enrichment reaches triage.

---

### Phase 4 — Incident report drafting
**Goal:** Auto-draft structured incident reports and shift handoff summaries from alert clusters or incident candidates.

Deterministic Markdown reporting already works and is tested — `MarkdownReportBuilder` renders candidate, triage, routing, and enrichment data into the seven planned sections without an LLM, and the pipeline writes `output/<candidate-id>.md` on every run. That is a better default than planned: reports exist even with no API key, and they are diffable in tests. The remaining work is `INC-*` promotion, LLM-assisted narrative, and delivery.

#### Milestone 4.1 — Incident grouping
- [x] Promote high-value `IncidentCandidate` objects into incidents — `soc/incidents.py`, wired into the pipeline and disableable via `PipelineConfig.promote_incidents`
- [x] Group related candidates by common host, user, agent, src IP, dst IP and an overlapping time window (configurable, default 2h) — two views of the same activity become one incident, so an analyst does not investigate the same compromise twice from the endpoint and network sides
- [x] Assign incident ID `INC-YYYYMMDD-NNN-<hash>` — content-addressed like every other ID here, so a rerun updates rather than duplicating
- [x] Store incident-to-alert and incident-to-candidate mapping in SQLite — `incidents` plus `incident_candidate_links`. Named `_links` deliberately: `incident_candidates` already existed storing candidate rows, and reusing the name made `CREATE TABLE IF NOT EXISTS` a silent no-op against the wrong schema. Caught by a test.
- [x] **Promotion rule is explicit and follows the routing decision, not the triage suggestion.** A candidate is promoted when its score clears `min_score` (default 8) or when the router actually paged. `TriageResult.action` is only a suggestion; reading it instead of the routing decision would have made `RoutingConfig` thresholds invisible to the incident tier, recreating the dead-threshold bug removed from the router in Phase 2. Found while writing the pipeline tests.

#### Milestone 4.2 — Report prompt
- [x] Report system prompt in Python alongside the triage prompt — `REPORT_SYSTEM_PROMPT` and `REPORT_PROMPT_VERSION = "report-v1"`, matching the 2.1 decision
- [x] Prompt accepts incident scope, candidate context, triage results, routing decisions, enrichment summaries and analyst notes
- [x] Prompt requires all seven sections, requires every claim to be grounded in the supplied context naming the entity, forbids inventing hosts, users, addresses, hashes or timestamps, and requires saying when evidence is insufficient and what would settle it. An invented hostname in an incident report is worse than a missing one.
- [x] Prompt context reuses the 2.1 allowlist and truncation helpers rather than adding a second filtering scheme. Verified by planting a distinctive value in `Alert.raw` and asserting it never appears in the prompt.

#### Milestone 4.3 — Report client
- [x] Implement `report.py` — all seven sections render from stored data
- [x] LLM-assisted narrative with the deterministic renderer as the **permanent** fallback. Only the prose sections are model-drafted; Timeline, Affected Assets, IOCs, Triage Decisions and Enrichment Summary always come from stored data, so a report is produced with no API key. An unusable response is retried once, then templated; a transport failure is not retried, since the client already backs off.
- [x] Build full incident context from candidates, triage results, routing and enrichment
- [x] Call the model with the report prompt and incident context, preferring `OPENROUTER_REPORT_MODEL` over `OPENROUTER_MODEL` when set
- [x] Write Markdown reports to `output/INC-*.md` alongside the existing `output/CAND-*.md`
- [x] **Mark LLM-drafted versus templated on the report itself**, per Milestone 2.6. A `## Report Provenance` section names the model and prompt version, or states why it was templated. `generated_by_model` is set only for a genuine draft, and a **partial** model response is treated as unusable by design: a report labelled model-drafted is model-drafted throughout.

#### Milestone 4.4 — Report delivery
- [x] Implement `run_report.py` with `list`, `show` and `generate` subcommands; `generate` takes `--output`, `--notes`/`--notes-file`, `--no-llm` and `--email`
- [x] Email delivery of the Markdown report as a `text/markdown` attachment, with the summary still in the body so a client that cannot render the attachment is not left with nothing
- [ ] Later phase: post report summary to Splunk via HEC webhook (Milestone 5.1)

**Exit criteria:** Analyst can run `python3 run_report.py generate <incident-id>` and receive a drafted Markdown incident report, optionally by email. Every report states whether it was LLM-drafted or templated. The same reporting logic summarizes replay-generated incidents for testing, and report generation still succeeds with no API key configured.

**Status: met, except that no report has been drafted by a real model.** Verified end to end from replay input: candidates promoted to an incident, persisted with its mapping, and both candidate and incident reports written with all seven sections and a correct provenance line. Report generation with no API key works and is labelled templated. What has not happened is a real `--llm` draft against a live model, which is deferred with the rest of live testing.

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
| Read cursor unusable on Windows | `st_ino` there is a 128-bit file ID, which overflows SQLite's INTEGER, so every daemon cycle failed. Worse, a numeric string in an INTEGER-affinity column was silently coerced to a float and lost precision, which would have broken rotation detection rather than crashing. Replaced the two integer columns with one non-numeric `file_identity` TEXT token. Found only by the Windows CI jobs. |
| CI lint non-reproducible | Ruff was installed unpinned with no config, so the rule set was whatever the newest release defaulted to. `ruff.toml` now states the rule set and `requirements.txt` pins the version. |
| No read cursor; whole file re-read each run | `ingest_cursors` table plus rotation, truncation, and in-place-rewrite detection |
| Two shipped fixtures could not be loaded by `--replay` at all | `load_replay_file` now accepts a bare event object; a parametrized test asserts every shipped fixture loads |
| Read cursor consulted before the schema existed | The CLI initializes the store up front. Found by an end-to-end test with real components, not by any of the 324 unit tests — every one of them used a fake store. |
| Tests leaked `os.environ` between modules via `load_dotenv` | `tests/conftest.py` snapshots and restores the environment and settings cache around every test, so the suite is order-independent |

### Open

| Defect | Location | Effect |
|---|---|---|
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
