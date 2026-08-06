# Splunk artifacts for AI triage output

These files are the Splunk-side half of PLAN.md Milestone 5.1. The Python side is
`soc/splunk_client.py`, which pushes triage results and incident summaries to an
HTTP Event Collector endpoint as sourcetype `ai_triage`.

**None of this has been tested against a live Splunk instance.** The searches and
the dashboard were written from the documented HEC event format and Simple XML
schema, not verified in a running deployment. Expect to adjust field names and
panel options on first install. The client itself is tested against a faked
transport, which proves what it sends, not that Splunk accepts it.

## Where the files go

Assuming a Splunk Enterprise install at `$SPLUNK_HOME` and an app named
`ai_augmented_soc` (create it, or substitute `search` to install into the default
app):

| File | Destination |
| --- | --- |
| `savedsearches.conf` | `$SPLUNK_HOME/etc/apps/ai_augmented_soc/local/savedsearches.conf` |
| `dashboard_ai_triage.xml` | `$SPLUNK_HOME/etc/apps/ai_augmented_soc/local/data/ui/views/dashboard_ai_triage.xml` |

Restart Splunk, or reload from the CLI:

```bash
$SPLUNK_HOME/bin/splunk restart
# or, without a restart:
curl -k -u admin https://localhost:8089/servicesNS/nobody/ai_augmented_soc/saved/searches/_reload
```

Every saved search ships with `enableSched = 0`. Turn scheduling on per search
once you have confirmed it returns what you expect, rather than scheduling six
untested searches at once.

## What has to exist first

- A HEC token with the target index in its allowed-index list, and HEC enabled
  globally (Settings → Data inputs → HTTP Event Collector).
- `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` set in `.env`. `SPLUNK_HEC_INDEX` is
  optional: leave it empty to use the token's default index.
- `SPLUNK_HEC_SOURCETYPE` left at `ai_triage`. Changing it means editing the
  `sourcetype=ai_triage` clause in every search here.

## What is in the index, and what deliberately is not

Only derived fields are forwarded. Triage events carry `target_id`,
`target_type`, `score`, `action`, `classification`, `fp_likelihood`,
`analysis_source`, `model`, `prompt_version`, and `summary`. Incident summaries
carry `id`, `candidate_count`, `alert_count`, `max_score`, `primary_host`,
`primary_user`, `first_seen`, and `last_seen`.

Raw source events, `Alert.raw`, and enrichment provider `raw` payloads are never
sent. That mirrors the triage context allowlist and keeps this index from
becoming an unmanaged second copy of the telemetry it summarizes. It also means
searches cannot pivot on raw fields — the `Repeated Addresses` search extracts
addresses from the triage `summary` for exactly that reason.

Both shapes share one sourcetype, so searches distinguish them by field: triage
events have `action`, incident summaries have `candidate_count`.

`analysis_source` is on every triage event on purpose. A local score and a model
score are not equivalent evidence, and a failed model call falls back to local
scoring, so a dashboard without that split would present heuristic output as
model output.
