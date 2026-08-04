# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
source venv/bin/activate                      # local venv is checked out at ./venv (gitignored)
pip install -r requirements.txt

pytest tests/ -v                              # full suite
pytest tests/test_pipeline.py -v              # one module
pytest tests/test_pipeline.py::test_name -v   # one test

ruff check soc tests run_pipeline.py          # exactly what CI lints (no ruff config file; defaults apply)
```

Replay smoke test (this exact command is a CI step — keep it working):

```bash
python3 run_pipeline.py --replay tests/fixtures/sample_incident_replay.json \
  --db data/soc.db --output output --no-dedup --pretty
```

Live Wazuh mode (needs a readable `alerts.json`; see "Wazuh ingestion" below):

```bash
python3 run_pipeline.py --wazuh --db data/wazuh_test.db --output output --pretty
```

Add `--no-llm` to any run to force deterministic local triage regardless of `OPENROUTER_API_KEY`. Check `triage_mode` and `local_fallbacks` in the JSON summary to see which engine actually scored the run.

Security Onion mode (Connect API — **requires a Security Onion Pro licence**):

```bash
python3 run_pipeline.py --security-onion --output output --pretty
```

Continuous polling (Milestone 1.6):

```bash
python3 run_pipeline.py --wazuh --daemon --poll-interval 60           # runs until SIGINT/SIGTERM
python3 run_pipeline.py --wazuh --daemon --max-cycles 3 --no-llm      # bounded, for testing
```

Analyst review queue and triage evaluation:

```bash
python3 run_review.py list                      # open queue, oldest first
python3 run_review.py show <triage_result_id>   # the decision plus its evidence
python3 run_review.py verdict <id> --too-high --score 2 --notes "known backup job"
python3 run_review.py export --output verdicts.json    # raw verdict records
python3 run_review.py promote --labels labels.json     # verdicts -> loadable eval labels

python3 run_eval.py --pretty                    # local triage vs the labeled set
python3 run_eval.py --llm                       # model-assisted triage (needs a key)
python3 run_eval.py --fail-under-thresholds     # gate a build on triage quality
```

CI runs ruff + pytest + **the local half of the triage evaluation** + the replay smoke test on Linux/macOS/Windows × Python 3.11/3.12. It never touches live Wazuh, Security Onion, OpenRouter, SMTP, or Slack.

## Architecture

One linear pipeline, one module per stage, orchestrated by `soc/pipeline.py`:

```
RawEvent → Alert → IncidentCandidate → TriageResult → RoutingDecision → Markdown report → notification
 replay.py  normalizer.py  clustering.py   triage.py      router.py        report.py       notifier.py
 wazuh_client.py           (+ enrichment.py)
```

`soc/models.py` holds the data contracts for every arrow above (`RawEvent`, `Alert`, `IncidentCandidate`, `TriageResult`, `RoutingDecision`, `EnrichmentResult`, plus the `EventSource` / `AlertSeverity` / `TriageAction` / `RoutingStatus` / `AnalysisSource` enums). Stage modules must not invent their own shapes — extend `models.py` instead. Models are stdlib `@dataclass(slots=True)` — there is no pydantic or ORM anywhere in this project.

Things that only become clear after reading several files:

- **`SOCPipeline` is fully dependency-injected.** Every stage is a constructor kwarg with a working default (`SOCPipeline(triage_engine=..., store=..., notifier=...)`). `SOCPipeline.with_sqlite_store(db_path)` is the production wiring. Tests substitute fakes for individual stages rather than mocking internals.
- **Errors accumulate, they don't propagate.** Each `_stage(...)` helper in `pipeline.py` catches broadly and calls `_handle_error`, which appends to a `list[str]` — unless `PipelineConfig.fail_fast` is set, in which case it raises `PipelineError`. A run "succeeding" with a populated `errors` list in the JSON summary is normal, so check `summary["errors"]`, not just the exit code.
- **Each module also exposes module-level functions mirroring its class methods** (`soc.triage.triage_candidate`, `soc.report.build_candidate_report`, `soc.router.route_triage_result`, …). The classes carry config; the functions are the stateless entry points used heavily in tests.
- **Every stage has a deterministic path with no network dependency.** Triage falls back to `score_*_locally` when no LLM client is injected or when LLM output fails to parse (`TriageEngine.allow_fallback`); enrichment (`LocalEnricher`) is purely local regex/IOC extraction — VirusTotal/AbuseIPDB/Shodan keys exist in `.env` but no provider is implemented; notification defaults to `DryRunNotifier`.
- **LLM triage is opt-out, not opt-in.** `run_pipeline.py` builds `TriageEngine(OpenRouterClient.from_settings(settings))` whenever `OPENROUTER_API_KEY` is non-empty, and plain `TriageEngine()` otherwise. `--no-llm` forces local. CI has no `.env`, so CI runs stay offline and keyless.
- **Every `TriageResult` records what produced it.** `analysis_source` is `local` or `llm`; LLM results also carry `model`, `latency_ms`, `token_usage`, and `prompt_version`. A failed LLM call falls back to local scoring *and is relabelled `local`* — a heuristic score can never present itself as model output. Reports and notifications state the source in prose, and the run summary reports `triage_mode`, `analysis_sources`, and `local_fallbacks` so silent degradation under rate limits is visible.
- **The LLM never sees a raw event.** `build_alert_context` / `build_candidate_context` / `build_enrichment_context` in `soc/triage.py` emit only allowlisted fields (`ALERT_CONTEXT_FIELDS`, `RAW_CONTEXT_FIELDS`, …), truncate every string to `MAX_CONTEXT_FIELD_CHARS`, cap clusters at `MAX_CONTEXT_ALERTS`, and exclude `Alert.raw`, `IncidentCandidate.related_events`, and enrichment provider raw responses entirely. Adding a field to a model does **not** add it to the prompt — extend the allowlist deliberately.
- **The prompt lives in Python, not in a file.** `TRIAGE_SYSTEM_PROMPT` and `TRIAGE_PROMPT_VERSION` in `soc/triage.py`. Bump the version whenever the prompt changes; it is recorded on every result so eval runs stay attributable.
- **Score is the single source of truth for routing.** `soc/router.py` always derives the action from the score via `page_threshold=8` / `queue_threshold=4`. `TriageResult.action` records what the model or local scorer *suggested* but does not decide anything; when the two disagree, `RoutingDecision.message` says so.
- **IDs are deterministic content fingerprints**, not random: `CAND-YYYYMMDD-NNN-<hash>` from clustering, similar schemes in `normalizer._build_alert_id`, `triage._build_triage_id`, `router._build_routing_decision_id`. Report filenames are `{candidate.id}.md`. Reruns of the same input therefore produce the same IDs and overwrite the same reports.
- **Dedup is content-based and persistent.** `soc/dedup.py` builds keys (raw event, alert, source+source_id, payload fingerprint) stored with a TTL in the SQLite `dedup_keys` table. A second run over the same fixture is a no-op unless you pass `--no-dedup` or use a fresh `--db`.
- **Daemon mode changes ingestion semantics, not the pipeline.** `soc/daemon.py` is deliberately ignorant of Wazuh and the pipeline: it takes a `run_cycle` callable, so any source can drive it and it stays trivially testable. `--daemon` passes the pipeline's store to `WazuhClient.from_settings(cursor_store=...)`, which makes the reader resume from a persisted byte offset instead of rescanning the file; a one-shot run passes `None` and keeps the old whole-file behaviour. The pipeline, Wazuh client, and cursor are built **once** and reused across cycles — rebuilding per cycle would reset the cursor. A failing cycle is logged to `logs/daemon.jsonl` and the loop continues.
- **The CLI initializes the database before the first cycle.** The pipeline also initializes its store when it processes events, but the read cursor is consulted *before* that, so the schema must already exist. This bug passed 324 unit tests because every one of them used a fake store; only an end-to-end test with real components caught it. Prefer at least one real-component test per integration seam.
- **`SQLiteStore.initialize()` migrates before it creates.** `CREATE TABLE IF NOT EXISTS` leaves older databases on their original schema, so `_apply_column_migrations` runs first and `ALTER TABLE`s any column listed in `_ADDED_COLUMNS` that is missing. Order matters: indexes in `_SCHEMA_SQL` may reference columns that only exist after migration. When you add a column to an existing table, add it to both places.

### Triage quality is measured, not assumed

`soc/evaluation.py` is the only thing in this project that asks whether the answers are *right* rather than merely produced. Read it before touching scoring, prompts, or the router.

- **Label provenance is load-bearing.** `synthetic` labels record what we decided the scorer should say, so measuring against them shows self-consistency, not accuracy. Only `analyst_reviewed` labels — exported from the review queue via `run_review.py export` — support an accuracy claim. `EvaluationReport.is_analyst_validated` is false if *any* label in the run is synthetic, and the CLI prints that caveat to stderr. Do not remove either safeguard.
- **The two failure modes are never averaged.** `missed_true_positives` (labeled serious, scored ≤3) and `noise_cases` (labeled benign, scored ≥8) are reported separately, because `mark_likely_benign` means nobody looks again — a missed detection is not interchangeable with a wasted page.
- **Score error is distance outside the expected band**, not from a midpoint. An in-band score is not an error.
- **Labels accept multiple acceptable actions.** Genuinely ambiguous alerts must not be labeled as though one answer were correct.
- **Never write a label by running the scorer and recording what it said.** That makes the evaluation tautological. Labels come from security judgment or from analyst review; if the scorer disagrees, that is a finding to investigate, not a label to adjust.
- `EvaluationThresholds` encodes Phase 2's exit criteria as executable checks, and CI gates on them.
- The shipped set has 5 seed cases, far short of the 40+ the plan calls for. Growing it is a labeling task; the review queue is the intended source.
- **`export` and `promote` are different things.** `export` writes verdict records; `promote` writes *labeled cases*. A verdict records how a score was wrong, while a labeled case also needs a replayable fixture and an expected band, so `promote` reconstructs the fixture from the raw events the store kept. Only `promote` output is loadable by the harness.

### The analyst review queue

`queue_review` is the only routing action that creates queue work — paged results are already in front of someone, and likely-benign results stay searchable without demanding attention. The queue is keyed on `triage_result_id`, which is a deterministic content fingerprint, so re-running the pipeline over the same input cannot double-queue. `AnalystVerdict` records *how* a score was wrong (`too_high` / `too_low` / `wrong_class`), not just that it was, because those call for different fixes. `enqueue_for_review` is an optional part of the store protocol: the pipeline skips queueing rather than failing if a store predates it.

### Configuration

`soc/config.py` exposes a frozen `Settings` dataclass built from env vars via `get_settings(env_file, reload=False)`. Two things to know:

- **It caches in a module-level global `_cached_settings`.** Always pass `reload=True` when the environment may have changed — `run_pipeline.py` does, and tests do too.
- **Validation is opt-in per subsystem** (`validate_wazuh`, `validate_openrouter`, `validate_email`, …) rather than at load time, so replay mode works with an empty `.env`. Call the relevant validator when adding a live integration.

Several vars have legacy aliases (`WAZUH_MANAGER_URL` falls back to `WAZUH_HOST`, etc.) and `.env.example` documents every key, including ones for not-yet-built phases (Splunk HEC, OpenBSD pf, enrichment providers).

Config tests write a throwaway `.env.test` under `tmp_path` and `monkeypatch.delenv` the keys under test — real env vars leak into `get_settings` otherwise.

### Security Onion ingestion

`soc/security_onion_client.py` targets the **Connect API**, which is a Security Onion **Pro-licence** feature — without one it cannot authenticate.

- Auth is OAuth2 client credentials: `POST /oauth2/token` with HTTP Basic auth and `grant_type=client_credentials`, yielding a bearer token cached until shortly before `expires_in` elapses. Configured via `SECURITYONION_CLIENT_ID` / `SECURITYONION_CLIENT_SECRET`, **not** the console username and password (which remain in `Settings` unused by this client).
- Events come from `GET /connect/query/data`.
- **Several query parameters are inferred, not documented.** Security Onion does not publish the time-range, limit, timezone, or date-format parameter names for that endpoint. Every inferred name and value lives only as a `SecurityOnionConfig` field (`range_param`, `zone_param`, `format_param`, `limit_param` defaulting to `eventLimit`, plus `zone`, `date_format`, `range_datetime_format`, `range_separator`, and the `query` index pattern). Never hardcode one at a call site — when a real grid disagrees, it should be a one-line change in that dataclass.
- Because those params may be ignored by a real grid, severity and lookback filtering are **re-applied locally** after the query. Don't remove that as redundant.
- Severity is compared through `severity_from_security_onion`, not numerically, because Suricata numbers severity *downwards*. With `SO_MIN_SEVERITY=2`, severities 1–2 are kept and 3+ dropped; documents with no interpretable severity are kept rather than silently dropped.
- `extract_event_documents` tolerates three response shapes (`events`, `data.events`, Elasticsearch `hits.hits[]._source`) and returns nothing plus a warning naming the received keys for anything else.

### Wazuh ingestion

`WazuhClient` (`soc/wazuh_client.py`) is Manager-only and has two independent halves:

- `WazuhAlertJsonReader` — the actual alert source. Reads line-delimited `alerts.json` from `WAZUH_ALERT_JSON_PATH`, filters by lookback window and `WAZUH_MIN_LEVEL`, sorts, and keeps the newest `WAZUH_ALERT_LIMIT`. If not running on the Manager host, the file must be copied/mounted locally first.
- `WazuhManagerClient` — optional, HTTP API against `:55000`, used *only* for agent inventory context to enrich alerts. Absent credentials, `fetch_agent_inventory()` returns `{}` and ingestion still works.

`from_settings` hard-requires `WAZUH_ALERT_SOURCE=json_logs`; indexer-based ingestion settings exist in `Settings` but no indexer client does. `WazuhClient.fetch_recent_events` accepts `lookback_minutes`/`min_level`/`limit` for CLI compatibility and **ignores them** — the reader already holds those values from settings.

## Conventions

- Every module, class, and function carries a docstring with explicit `Inputs:` / `Outputs:` (and `Raises:` where relevant) sections. Match this style; it is uniform across all ~15k lines.
- `from __future__ import annotations` at the top of every module; modern generic syntax (`list[str]`, `X | None`), `JsonDict = dict[str, Any]` alias per module.
- Each module defines its own exception subclass (`NormalizationError`, `TriageError`, `WazuhError`, `PipelineError`, …) and raises only that from its public surface.
- Config-holding dataclasses are `frozen=True, slots=True` and validate in `__post_init__`.
- `soc/__init__.py` re-exports the stable foundation objects with an explicit `__all__` — keep it in sync when adding public models or loaders.
- One test module per `soc` module (`tests/test_<module>.py`), fixtures in `tests/fixtures/`. Live-integration tests fake the transport rather than hitting the network.
- `tests/conftest.py` snapshots and restores `os.environ` and the settings cache around every test. This is load-bearing: `get_settings` uses `load_dotenv`, which writes into `os.environ` permanently and does **not** override variables that are already set, so without isolation one test's `.env` silently wins over a later test's and the suite becomes order-dependent.
- Assert on score *bands*, never exact triage scores, so tuning the heuristic does not produce false failures.

## Not built yet

No placeholder files remain — if a module isn't there, it isn't written. Notably absent: a live Security Onion client (Security Onion *normalization* is implemented and tested; only retrieval is missing), a polling daemon, `INC-*` incident promotion, LLM-drafted report prose, and all external enrichment providers.

`WazuhAlertJsonReader` re-reads the whole `alerts.json` on every run and has no byte cursor or rotation handling, so it is correct for one-shot CLI use and not yet safe for a polling loop (PLAN.md Milestone 1.1a). It does tolerate malformed lines: they are skipped, counted on `last_malformed_line_count`, and logged.

`data/`, `output/`, and `logs/` are gitignored (`.gitkeep` only). `PLAN.md` holds the six-phase roadmap with per-milestone status, a **Known defects** table (verified issues with file locations), and the rationale for current scope — check it before assuming a feature works.
