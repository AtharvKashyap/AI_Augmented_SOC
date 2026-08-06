"""Tests for the optional Splunk search ingestion client.

Every test fakes the HTTP transport by injecting an `opener` callable, and every
test that would otherwise wait injects a `sleep` recorder, so no test performs
real network I/O and no test spends real time polling.

This client is an *additional* ingestion source. Nothing here touches the direct
Wazuh or Security Onion ingestion paths.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
from typing import Any

import pytest

from soc.models import EventSource
from soc.normalizer import Normalizer
from soc.splunk_search_client import (
    SplunkSearchAuthError,
    SplunkSearchClient,
    SplunkSearchConfig,
    SplunkSearchError,
    SplunkSearchRequestError,
    extract_result_rows,
    raw_event_from_splunk_result,
)

FAKE_TOKEN = "fake-splunk-token-do-not-report"
"""Low-entropy, self-describing sentinel. Not a credential."""


class FakeHTTPResponse:
    """Small context-manager response object for urllib fakes."""

    def __init__(self, body: str) -> None:
        """Initialize fake response.

        Inputs:
            body: Response body text.

        Outputs:
            None.
        """

        self.body = body.encode("utf-8")

    def __enter__(self) -> FakeHTTPResponse:
        """Enter context manager."""

        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Exit context manager."""

    def read(self) -> bytes:
        """Return response body bytes."""

        return self.body


class RecordingOpener:
    """Opener that records requests and replays a scripted list of responses."""

    def __init__(self, responses: list[Any]) -> None:
        """Initialize the opener.

        Inputs:
            responses: Bodies to return in order. A str is wrapped in a fake
                response; an Exception instance is raised instead.

        Outputs:
            None.
        """

        self.responses = list(responses)
        self.requests: list[Any] = []

    def __call__(self, request: Any, *, timeout: float, context: Any) -> Any:
        """Record the request and return or raise the next scripted response."""

        self.requests.append(request)
        if not self.responses:
            raise AssertionError("RecordingOpener ran out of scripted responses")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return FakeHTTPResponse(item)


class SleepRecorder:
    """Sleep replacement that records delays instead of waiting."""

    def __init__(self) -> None:
        """Initialize the recorder."""

        self.delays: list[float] = []

    def __call__(self, seconds: float) -> None:
        """Record one delay."""

        self.delays.append(seconds)


def _config(**overrides: Any) -> SplunkSearchConfig:
    """Return a test Splunk search config.

    Inputs:
        **overrides: Field overrides.

    Outputs:
        SplunkSearchConfig instance.
    """

    values: dict[str, Any] = {
        "base_url": "https://splunk.example:8089/",
        "token": FAKE_TOKEN,
        "search_query": "search index=main sourcetype=wazuh",
        "earliest_time": "-15m",
        "latest_time": "now",
        "max_results": 100,
        "retry_backoff_seconds": 0.0,
        "poll_interval_seconds": 0.0,
    }
    values.update(overrides)
    return SplunkSearchConfig(**values)


def _http_error(code: int, body: str = "") -> urllib.error.HTTPError:
    """Return an HTTPError with a readable body.

    Inputs:
        code: HTTP status code.
        body: Response body text.

    Outputs:
        HTTPError instance.
    """

    import io

    return urllib.error.HTTPError(
        "https://splunk.example:8089/services/search/jobs",
        code,
        "error",
        {},  # type: ignore[arg-type]
        io.BytesIO(body.encode("utf-8")),
    )


def _job_created(sid: str = "sid-1") -> str:
    """Return a job-creation response body."""

    return json.dumps({"sid": sid})


def _job_status(*, done: bool, state: str = "DONE") -> str:
    """Return a job-status response body."""

    return json.dumps({"entry": [{"content": {"isDone": done, "dispatchState": state}}]})


def _results(rows: list[Any]) -> str:
    """Return a results response body."""

    return json.dumps({"results": rows})


# --- Configuration -----------------------------------------------------------


def test_config_requires_base_url() -> None:
    """An empty base_url is rejected."""

    with pytest.raises(SplunkSearchError):
        _config(base_url="   ")


def test_config_requires_token() -> None:
    """An empty token is rejected."""

    with pytest.raises(SplunkSearchError):
        _config(token="")


def test_config_requires_search_query() -> None:
    """An empty search query is rejected."""

    with pytest.raises(SplunkSearchError):
        _config(search_query="")


def test_config_rejects_non_positive_poll_bounds() -> None:
    """max_poll_attempts must be at least one and max_results positive."""

    with pytest.raises(SplunkSearchError):
        _config(max_poll_attempts=0)
    with pytest.raises(SplunkSearchError):
        _config(max_results=0)


def test_config_defaults_are_a_bounded_recent_window() -> None:
    """The documented defaults are a 15-minute window capped at 100 results."""

    config = SplunkSearchConfig(base_url="https://splunk.example:8089", token=FAKE_TOKEN)
    assert config.earliest_time == "-15m"
    assert config.latest_time == "now"
    assert config.max_results == 100
    assert config.verify_tls is True
    assert config.search_query.strip() != ""


# --- Job creation ------------------------------------------------------------


def test_create_search_job_posts_query_time_range_and_json_output_mode() -> None:
    """Job creation POSTs search, earliest_time, latest_time and output_mode."""

    opener = RecordingOpener([_job_created("sid-abc")])
    client = SplunkSearchClient(_config(), opener=opener, sleep=SleepRecorder())

    sid = client.create_search_job()

    assert sid == "sid-abc"
    request = opener.requests[0]
    assert request.get_method() == "POST"
    assert request.full_url == "https://splunk.example:8089/services/search/jobs"
    body = urllib.parse.parse_qs(request.data.decode("utf-8"))
    assert body["search"] == ["search index=main sourcetype=wazuh"]
    assert body["earliest_time"] == ["-15m"]
    assert body["latest_time"] == ["now"]
    assert body["output_mode"] == ["json"]


def test_requests_send_a_bearer_authorization_header() -> None:
    """Every request authenticates with Authorization: Bearer <token>."""

    opener = RecordingOpener([_job_created()])
    client = SplunkSearchClient(_config(), opener=opener, sleep=SleepRecorder())

    client.create_search_job()

    header = opener.requests[0].get_header("Authorization")
    assert header == f"Bearer {FAKE_TOKEN}"


def test_create_search_job_without_a_sid_raises() -> None:
    """A creation response with no search ID is an error, not an empty run."""

    opener = RecordingOpener([json.dumps({"messages": []})])
    client = SplunkSearchClient(_config(), opener=opener, sleep=SleepRecorder())

    with pytest.raises(SplunkSearchRequestError, match="search ID"):
        client.create_search_job()


# --- Polling ----------------------------------------------------------------


def test_fetch_recent_events_polls_until_done_then_fetches_results() -> None:
    """The client polls the job, then reads results once the job reports done."""

    opener = RecordingOpener(
        [
            _job_created("sid-poll"),
            _job_status(done=False, state="RUNNING"),
            _job_status(done=True),
            _results([{"_time": "2026-01-01T00:00:00Z", "sourcetype": "wazuh"}]),
        ]
    )
    client = SplunkSearchClient(_config(), opener=opener, sleep=SleepRecorder())

    events = client.fetch_recent_events()

    assert len(events) == 1
    urls = [request.full_url for request in opener.requests]
    assert urls[1].startswith("https://splunk.example:8089/services/search/jobs/sid-poll?")
    assert "output_mode=json" in urls[1]
    assert urls[3].startswith("https://splunk.example:8089/services/search/jobs/sid-poll/results?")
    assert "count=100" in urls[3]
    assert "output_mode=json" in urls[3]


def test_polling_is_bounded_and_raises_rather_than_returning_partial_results() -> None:
    """Exceeding max_poll_attempts raises instead of returning what exists."""

    opener = RecordingOpener([_job_created("sid-slow")] + [_job_status(done=False, state="RUNNING")] * 3)
    client = SplunkSearchClient(_config(max_poll_attempts=3), opener=opener, sleep=SleepRecorder())

    with pytest.raises(SplunkSearchRequestError, match="did not finish"):
        client.fetch_recent_events()

    # Only the creation call plus exactly max_poll_attempts status calls happened;
    # no results request was made, so nothing partial could have been returned.
    assert len(opener.requests) == 4


def test_polling_uses_the_injected_sleep_and_never_waits() -> None:
    """Poll delays go to the injected sleep, so tests spend no real time."""

    sleeper = SleepRecorder()
    opener = RecordingOpener(
        [
            _job_created("sid-sleep"),
            _job_status(done=False, state="RUNNING"),
            _job_status(done=False, state="RUNNING"),
            _job_status(done=True),
            _results([]),
        ]
    )
    client = SplunkSearchClient(
        _config(poll_interval_seconds=5.0), opener=opener, sleep=sleeper
    )

    client.fetch_recent_events()

    assert sleeper.delays == [5.0, 5.0]


def test_failed_job_state_raises() -> None:
    """A job Splunk reports as FAILED raises rather than polling to the bound."""

    opener = RecordingOpener([_job_created("sid-bad"), _job_status(done=False, state="FAILED")])
    client = SplunkSearchClient(_config(), opener=opener, sleep=SleepRecorder())

    with pytest.raises(SplunkSearchRequestError, match="FAILED"):
        client.fetch_recent_events()


# --- Result rows to RawEvent --------------------------------------------------


def test_rows_become_raw_events_with_deterministic_content_addressed_ids() -> None:
    """Row IDs are content fingerprints, not positional or random."""

    row = {"_time": "2026-01-01T00:00:00Z", "index": "main", "host": "web01"}

    first = raw_event_from_splunk_result(dict(row))
    second = raw_event_from_splunk_result(dict(row))

    assert first.id == second.id
    assert first.id.startswith("splunk-search-")
    assert raw_event_from_splunk_result({**row, "host": "web02"}).id != first.id


def test_row_timestamp_is_parsed_into_utc() -> None:
    """A row's Splunk `_time` becomes a timezone-aware UTC RawEvent timestamp."""

    event = raw_event_from_splunk_result({"_time": "2026-01-01T12:00:00.000+00:00"})

    assert event.timestamp is not None
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.year == 2026


def test_wazuh_sourcetype_selects_the_wazuh_event_source() -> None:
    """A row that clearly says Wazuh is labelled EventSource.WAZUH."""

    event = raw_event_from_splunk_result({"sourcetype": "wazuh:alerts", "_time": "2026-01-01T00:00:00Z"})

    assert event.source == EventSource.WAZUH


def test_security_onion_sourcetype_selects_the_security_onion_event_source() -> None:
    """A row that clearly says Security Onion is labelled accordingly."""

    event = raw_event_from_splunk_result({"sourcetype": "suricata:alert", "index": "securityonion"})

    assert event.source == EventSource.SECURITY_ONION


def test_ambiguous_row_stays_a_splunk_event() -> None:
    """Without a clear signal the row keeps EventSource.SPLUNK."""

    event = raw_event_from_splunk_result({"sourcetype": "syslog", "index": "main"})

    assert event.source == EventSource.SPLUNK


def test_raw_json_string_becomes_the_payload_with_splunk_metadata_alongside() -> None:
    """A `_raw` JSON object is the payload so existing normalizers still work."""

    original = {"rule": {"level": 10, "description": "Failed password"}, "agent": {"id": "001"}}
    row = {
        "_raw": json.dumps(original),
        "_time": "2026-01-01T00:00:00Z",
        "sourcetype": "wazuh:alerts",
        "index": "main",
    }

    event = raw_event_from_splunk_result(row)

    assert event.payload["rule"] == original["rule"]
    assert event.payload["agent"] == original["agent"]
    assert "_raw" not in event.payload
    assert event.payload["splunk"]["sourcetype"] == "wazuh:alerts"
    assert event.payload["splunk"]["index"] == "main"


def test_non_json_raw_line_leaves_the_row_as_the_payload() -> None:
    """A plain syslog `_raw` line is not a JSON object, so the row is used."""

    row = {"_raw": "Jan  1 00:00:00 web01 sshd[1]: Failed password", "sourcetype": "syslog"}

    event = raw_event_from_splunk_result(row)

    assert event.payload["_raw"] == row["_raw"]
    assert "splunk" not in event.payload


def test_raw_event_from_a_splunk_row_normalizes_without_error() -> None:
    """A produced RawEvent goes through soc.normalizer.Normalizer cleanly."""

    row = {
        "_raw": json.dumps(
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "rule": {"level": 10, "description": "Multiple failed logins"},
                "agent": {"id": "001", "name": "web01"},
                "data": {"srcip": "8.8.8.8"},
            }
        ),
        "_time": "2026-01-01T00:00:00Z",
        "sourcetype": "wazuh:alerts",
    }

    event = raw_event_from_splunk_result(row)
    alert = Normalizer().normalize(event)

    assert alert.source == EventSource.WAZUH
    assert alert.rule_name == "Multiple failed logins"
    assert alert.hostname == "web01"


def test_generic_splunk_row_also_normalizes() -> None:
    """An ambiguous row normalizes through the generic path without raising."""

    event = raw_event_from_splunk_result({"sourcetype": "syslog", "message": "something happened"})

    alert = Normalizer().normalize(event)

    assert alert.source == EventSource.SPLUNK


# --- Tolerant result parsing --------------------------------------------------


def test_extract_result_rows_skips_and_counts_non_dict_rows() -> None:
    """A row that is not a dict is skipped and counted, never fatal."""

    rows, skipped = extract_result_rows({"results": [{"a": 1}, "not-a-row", None, {"b": 2}]})

    assert rows == [{"a": 1}, {"b": 2}]
    assert skipped == 2


def test_extract_result_rows_tolerates_a_missing_results_key() -> None:
    """An unrecognized response shape yields no rows rather than raising."""

    rows, skipped = extract_result_rows({"messages": [{"type": "INFO"}]})

    assert rows == []
    assert skipped == 0


def test_fetch_recent_events_exposes_the_skipped_row_count() -> None:
    """The client surfaces how many rows it had to skip."""

    opener = RecordingOpener(
        [
            _job_created("sid-skip"),
            _job_status(done=True),
            _results([{"_time": "2026-01-01T00:00:00Z"}, 42, "bad"]),
        ]
    )
    client = SplunkSearchClient(_config(), opener=opener, sleep=SleepRecorder())

    events = client.fetch_recent_events()

    assert len(events) == 1
    assert client.last_skipped_result_count == 2


# --- Errors -------------------------------------------------------------------


def test_401_raises_actionably_and_never_reveals_the_token() -> None:
    """An auth failure names the setting to fix and scrubs the token."""

    body = f"Unauthorized: token {FAKE_TOKEN} is not valid"
    opener = RecordingOpener([_http_error(401, body)])
    client = SplunkSearchClient(_config(), opener=opener, sleep=SleepRecorder())

    with pytest.raises(SplunkSearchAuthError) as excinfo:
        client.create_search_job()

    message = str(excinfo.value)
    assert "SPLUNK_SEARCH_TOKEN" in message
    assert FAKE_TOKEN not in message
    assert "***" in message


def test_401_is_not_retried() -> None:
    """A bad token cannot be fixed by retrying, so only one request is made."""

    opener = RecordingOpener([_http_error(401, "nope")])
    client = SplunkSearchClient(_config(max_retries=3), opener=opener, sleep=SleepRecorder())

    with pytest.raises(SplunkSearchAuthError):
        client.create_search_job()

    assert len(opener.requests) == 1


def test_500_is_retried_then_given_up_on() -> None:
    """A transient 5xx is retried max_retries times, then raises."""

    sleeper = SleepRecorder()
    opener = RecordingOpener([_http_error(500, "server error")] * 3)
    client = SplunkSearchClient(
        _config(max_retries=2, retry_backoff_seconds=1.0), opener=opener, sleep=sleeper
    )

    with pytest.raises(SplunkSearchRequestError, match="HTTP 500"):
        client.create_search_job()

    assert len(opener.requests) == 3
    assert sleeper.delays == [1.0, 2.0]


def test_500_body_containing_the_token_is_scrubbed() -> None:
    """Splunk error bodies are quoted into messages, so they are scrubbed too."""

    opener = RecordingOpener([_http_error(500, f"failed for token {FAKE_TOKEN}")])
    client = SplunkSearchClient(_config(max_retries=0), opener=opener, sleep=SleepRecorder())

    with pytest.raises(SplunkSearchRequestError) as excinfo:
        client.create_search_job()

    assert FAKE_TOKEN not in str(excinfo.value)


def test_network_error_is_retryable() -> None:
    """A connection failure is transient and gets retried."""

    opener = RecordingOpener(
        [
            urllib.error.URLError("connection refused"),
            _job_created("sid-after-retry"),
        ]
    )
    client = SplunkSearchClient(_config(max_retries=1), opener=opener, sleep=SleepRecorder())

    assert client.create_search_job() == "sid-after-retry"


# --- from_settings ------------------------------------------------------------


class FakeSettings:
    """Settings stand-in exposing only the Splunk search keys under test."""

    def __init__(self, **values: Any) -> None:
        """Store the provided attribute values."""

        for name, value in values.items():
            setattr(self, name, value)


def test_from_settings_reads_the_splunk_search_keys() -> None:
    """from_settings maps the documented settings onto the config."""

    client = SplunkSearchClient.from_settings(
        FakeSettings(
            splunk_search_url="https://splunk.example:8089",
            splunk_search_token=FAKE_TOKEN,
            splunk_search_query="search index=soc",
            splunk_search_earliest="-1h",
            splunk_search_latest="-5m",
            splunk_search_limit="250",
        )
    )

    assert client.config.base_url == "https://splunk.example:8089"
    assert client.config.search_query == "search index=soc"
    assert client.config.earliest_time == "-1h"
    assert client.config.latest_time == "-5m"
    assert client.config.max_results == 250


def test_from_settings_tolerates_a_settings_object_without_the_optional_keys() -> None:
    """Only the URL and token are required; the rest fall back to defaults."""

    client = SplunkSearchClient.from_settings(
        FakeSettings(splunk_search_url="https://splunk.example:8089", splunk_search_token=FAKE_TOKEN)
    )

    assert client.config.search_query.strip() != ""
    assert client.config.earliest_time == "-15m"
    assert client.config.max_results == 100


def test_from_settings_without_a_url_fails_loudly() -> None:
    """An unconfigured Splunk search source refuses rather than running empty."""

    with pytest.raises(SplunkSearchError, match="SPLUNK_SEARCH_URL"):
        SplunkSearchClient.from_settings(FakeSettings(splunk_search_token=FAKE_TOKEN))


def test_from_settings_without_a_token_fails_loudly() -> None:
    """A missing token names the setting to populate."""

    with pytest.raises(SplunkSearchError, match="SPLUNK_SEARCH_TOKEN"):
        SplunkSearchClient.from_settings(FakeSettings(splunk_search_url="https://splunk.example:8089"))
