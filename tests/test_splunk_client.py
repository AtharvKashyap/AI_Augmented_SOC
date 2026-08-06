
"""Tests for the Splunk HTTP Event Collector client.

Every test fakes the HTTP transport through the injected `opener`, so nothing
here touches a network or a live Splunk instance.
"""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from soc.incidents import Incident
from soc.models import (
    AnalysisSource,
    FalsePositiveLikelihood,
    TriageAction,
    TriageResult,
    utc_now,
)
from soc.splunk_client import (
    SplunkAuthError,
    SplunkClient,
    SplunkConfig,
    SplunkError,
    SplunkRequestError,
)

FAKE_TOKEN = "fake-splunk-token-do-not-report"
"""Low-entropy, self-describing sentinel so secret scanners cannot mistake it."""

SUCCESS_BODY = json.dumps({"text": "Success", "code": 0})


class FakeHTTPResponse:
    """Small context-manager response object for urllib fakes."""

    def __init__(self, body: str) -> None:
        """Initialize fake response."""

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
    """Opener that records every request and replays queued responses."""

    def __init__(self, responses: list[Any] | None = None) -> None:
        """Initialize recorder with optional queued responses or exceptions."""

        self.calls: list[dict[str, Any]] = []
        self.responses = list(responses or [])

    def __call__(self, request: Any, *, timeout: float, context: Any) -> Any:
        """Record one request and return or raise the next queued response."""

        self.calls.append(
            {
                "url": request.full_url,
                "method": request.get_method(),
                "headers": dict(request.header_items()),
                "body": (request.data or b"").decode("utf-8"),
                "timeout": timeout,
                "context": context,
            }
        )
        if self.responses:
            outcome = self.responses.pop(0)
        else:
            outcome = FakeHTTPResponse(SUCCESS_BODY)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    @property
    def bodies(self) -> list[str]:
        """Return the request body of every recorded call."""

        return [call["body"] for call in self.calls]


def _config(**overrides: Any) -> SplunkConfig:
    """Return a Splunk config with test defaults."""

    values: dict[str, Any] = {
        "hec_url": "https://splunk.example:8088",
        "token": FAKE_TOKEN,
        "timeout_seconds": 5,
        "retry_backoff_seconds": 0.0,
    }
    values.update(overrides)
    return SplunkConfig(**values)


def _triage_result(
    *,
    result_id: str = "TRI-0001",
    target_id: str = "ALERT-0001",
    score: int = 9,
    analysis_source: AnalysisSource = AnalysisSource.LLM,
) -> TriageResult:
    """Build a realistic triage result."""

    return TriageResult(
        id=result_id,
        target_id=target_id,
        target_type="alert",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="credential_access",
        action=TriageAction.PAGE_NOW,
        summary="Encoded PowerShell execution on endpoint-01",
        iocs={"ip": ["203.0.113.10"]},
        recommended_actions=["Isolate the host"],
        reasoning="Encoded command plus outbound connection",
        model="test/model",
        latency_ms=120,
        analysis_source=analysis_source,
        prompt_version="v3",
        created_at=utc_now(),
    )


def _incident(*, incident_id: str = "INC-20260101-001-abcdef") -> Incident:
    """Build a realistic incident."""

    now = utc_now()
    return Incident(
        id=incident_id,
        candidate_ids=["CAND-1", "CAND-2"],
        alert_ids=["ALERT-1", "ALERT-2", "ALERT-3"],
        triage_result_ids=["TRI-1"],
        first_seen=now,
        last_seen=now,
        primary_host="endpoint-01",
        primary_user="alice",
        src_ips=["10.0.1.42"],
        dst_ips=["203.0.113.10"],
        max_score=9,
    )


def test_config_rejects_missing_and_invalid_values():
    """Splunk config should validate its own fields."""

    with pytest.raises(SplunkError, match="hec_url"):
        SplunkConfig(hec_url="", token=FAKE_TOKEN)

    with pytest.raises(SplunkError, match="SPLUNK_HEC_TOKEN"):
        SplunkConfig(hec_url="https://splunk.example:8088", token="")

    with pytest.raises(SplunkError, match="max_batch_events"):
        _config(max_batch_events=0)

    with pytest.raises(SplunkError, match="max_retries"):
        _config(max_retries=-1)

    with pytest.raises(SplunkError, match="retry_backoff_seconds"):
        _config(retry_backoff_seconds=-1.0)

    with pytest.raises(SplunkError, match="timeout_seconds"):
        _config(timeout_seconds=0)


def test_bare_url_gets_collector_event_path_appended():
    """A bare HEC base URL should get /services/collector/event appended."""

    opener = RecordingOpener()
    client = SplunkClient(_config(hec_url="https://splunk.example:8088/"), opener=opener)

    client.send_triage_results([_triage_result()])

    assert opener.calls[0]["url"] == "https://splunk.example:8088/services/collector/event"


def test_collector_url_is_used_as_given():
    """A URL already ending in /services/collector must not be rewritten."""

    opener = RecordingOpener()
    client = SplunkClient(
        _config(hec_url="https://splunk.example:8088/services/collector"),
        opener=opener,
    )

    client.send_triage_results([_triage_result()])

    assert opener.calls[0]["url"] == "https://splunk.example:8088/services/collector"


def test_collector_event_url_is_used_as_given():
    """A URL already ending in /services/collector/event must not be doubled."""

    opener = RecordingOpener()
    client = SplunkClient(
        _config(hec_url="https://splunk.example:8088/services/collector/event"),
        opener=opener,
    )

    client.send_triage_results([_triage_result()])

    assert opener.calls[0]["url"] == "https://splunk.example:8088/services/collector/event"


def test_request_uses_splunk_authorization_header():
    """HEC requests must authenticate with the Splunk token scheme."""

    opener = RecordingOpener()
    client = SplunkClient(_config(), opener=opener)

    client.send_triage_results([_triage_result()])

    headers = opener.calls[0]["headers"]
    assert headers["Authorization"] == f"Splunk {FAKE_TOKEN}"
    assert opener.calls[0]["method"] == "POST"
    assert opener.calls[0]["timeout"] == 5


def test_events_are_newline_delimited_json_objects_not_an_array():
    """HEC needs concatenated JSON objects, so a batch must not be an array."""

    opener = RecordingOpener()
    client = SplunkClient(_config(max_batch_events=10), opener=opener)

    sent = client.send_triage_results(
        [_triage_result(result_id="TRI-1", target_id="A-1"), _triage_result(result_id="TRI-2", target_id="A-2")]
    )

    assert sent == 2
    assert len(opener.calls) == 1
    body = opener.bodies[0]
    assert not body.lstrip().startswith("[")
    lines = body.split("\n")
    assert len(lines) == 2
    targets = [json.loads(line)["event"]["target_id"] for line in lines]
    assert targets == ["A-1", "A-2"]


def test_sourcetype_index_and_host_are_included_when_configured():
    """Configured sourcetype, index and host must be stamped on every event."""

    opener = RecordingOpener()
    client = SplunkClient(
        _config(index="soc_ai", sourcetype="ai_triage", host="soc-automation-01"),
        opener=opener,
    )

    client.send_triage_results([_triage_result()])

    envelope = json.loads(opener.bodies[0])
    assert envelope["sourcetype"] == "ai_triage"
    assert envelope["index"] == "soc_ai"
    assert envelope["host"] == "soc-automation-01"
    assert isinstance(envelope["time"], (int, float))


def test_index_and_host_are_omitted_when_not_configured():
    """An unset index or host must be left out so token defaults apply."""

    opener = RecordingOpener()
    client = SplunkClient(_config(), opener=opener)

    client.send_triage_results([_triage_result()])

    envelope = json.loads(opener.bodies[0])
    assert "index" not in envelope
    assert "host" not in envelope
    assert envelope["sourcetype"] == "ai_triage"


def test_triage_event_carries_analysis_source_and_searchable_fields():
    """A dashboard must be able to tell a model score from a heuristic one."""

    opener = RecordingOpener()
    client = SplunkClient(_config(), opener=opener)

    client.send_triage_results([_triage_result(analysis_source=AnalysisSource.LOCAL)])

    event = json.loads(opener.bodies[0])["event"]
    assert event["analysis_source"] == "local"
    assert event["target_id"] == "ALERT-0001"
    assert event["target_type"] == "alert"
    assert event["score"] == 9
    assert event["action"] == "page_now"
    assert event["classification"] == "credential_access"
    assert event["fp_likelihood"] == "low"
    assert event["model"] == "test/model"
    assert event["prompt_version"] == "v3"
    assert event["summary"].startswith("Encoded PowerShell")


def test_triage_event_does_not_leak_raw_payloads():
    """Raw source data must never reach the Splunk index through this path."""

    opener = RecordingOpener()
    client = SplunkClient(_config(), opener=opener)
    result = _triage_result()
    result.iocs = {"raw": ["secret-raw-marker"]}
    result.token_usage = {"prompt_tokens": 11, "note": "secret-raw-marker"}
    result.reasoning = "secret-raw-marker"

    client.send_triage_results([result])

    body = opener.bodies[0]
    assert "secret-raw-marker" not in body
    event = json.loads(body)["event"]
    assert "iocs" not in event
    assert "token_usage" not in event
    assert "reasoning" not in event
    assert "evidence" not in event


def test_send_incidents_sends_summary_fields():
    """Incident events should summarize scale rather than repeat identifiers."""

    opener = RecordingOpener()
    client = SplunkClient(_config(), opener=opener)

    sent = client.send_incidents([_incident()])

    assert sent == 1
    event = json.loads(opener.bodies[0])["event"]
    assert event["id"] == "INC-20260101-001-abcdef"
    assert event["candidate_count"] == 2
    assert event["alert_count"] == 3
    assert event["max_score"] == 9
    assert event["primary_host"] == "endpoint-01"
    assert event["primary_user"] == "alice"
    assert isinstance(event["first_seen"], str)
    assert isinstance(event["last_seen"], str)
    assert "src_ips" not in event


def test_batches_at_the_configured_size():
    """Events must be batched, not sent one request per event."""

    opener = RecordingOpener()
    client = SplunkClient(_config(max_batch_events=2), opener=opener)

    results = [_triage_result(result_id=f"TRI-{index}", target_id=f"A-{index}") for index in range(5)]
    sent = client.send_triage_results(results)

    assert sent == 5
    assert len(opener.calls) == 3
    assert [len(body.split("\n")) for body in opener.bodies] == [2, 2, 1]


def test_empty_input_makes_no_request_and_returns_zero():
    """Nothing to send means no HTTP call at all."""

    opener = RecordingOpener()
    client = SplunkClient(_config(), opener=opener)

    assert client.send_triage_results([]) == 0
    assert client.send_incidents([]) == 0
    assert opener.calls == []


def test_non_zero_code_in_a_200_response_raises():
    """HEC reports some failures as a non-zero code inside HTTP 200."""

    opener = RecordingOpener(
        [FakeHTTPResponse(json.dumps({"text": "Incorrect index", "code": 7}))]
    )
    client = SplunkClient(_config(), opener=opener)

    with pytest.raises(SplunkRequestError, match="code 7"):
        client.send_triage_results([_triage_result()])


def test_auth_failure_names_the_token_setting_without_revealing_it():
    """A 401 must be actionable, not retried, and must not print the token."""

    opener = RecordingOpener(
        [
            urllib.error.HTTPError(
                "https://splunk.example:8088/services/collector/event",
                401,
                "Unauthorized",
                hdrs=None,
                fp=None,
            )
        ]
    )
    client = SplunkClient(_config(), opener=opener)

    with pytest.raises(SplunkAuthError) as excinfo:
        client.send_triage_results([_triage_result()])

    message = str(excinfo.value)
    assert "SPLUNK_HEC_TOKEN" in message
    assert FAKE_TOKEN not in message
    assert len(opener.calls) == 1


def test_token_never_appears_in_an_error_message_even_if_echoed(caplog):
    """A server echoing the token back must not leak it into an error or log."""

    class EchoingHTTPError(urllib.error.HTTPError):
        """HTTPError whose body echoes the credential it was sent."""

        def read(self) -> bytes:
            """Return an error body containing the token."""

            return f"token {FAKE_TOKEN} rejected".encode()

    opener = RecordingOpener(
        [
            EchoingHTTPError(
                "https://splunk.example:8088/services/collector/event",
                500,
                "Server Error",
                hdrs=None,
                fp=None,
            ),
            EchoingHTTPError(
                "https://splunk.example:8088/services/collector/event",
                500,
                "Server Error",
                hdrs=None,
                fp=None,
            ),
            EchoingHTTPError(
                "https://splunk.example:8088/services/collector/event",
                500,
                "Server Error",
                hdrs=None,
                fp=None,
            ),
        ]
    )
    slept: list[float] = []
    client = SplunkClient(_config(), opener=opener, sleep=slept.append)

    with caplog.at_level("WARNING"), pytest.raises(SplunkRequestError) as excinfo:
        client.send_triage_results([_triage_result()])

    assert FAKE_TOKEN not in str(excinfo.value)
    assert FAKE_TOKEN not in caplog.text


def test_server_error_is_retried_then_succeeds():
    """A transient 5xx should be retried with exponential backoff."""

    opener = RecordingOpener(
        [
            urllib.error.HTTPError(
                "https://splunk.example:8088/services/collector/event",
                503,
                "Service Unavailable",
                hdrs=None,
                fp=None,
            ),
            FakeHTTPResponse(SUCCESS_BODY),
        ]
    )
    slept: list[float] = []
    client = SplunkClient(_config(retry_backoff_seconds=0.5), opener=opener, sleep=slept.append)

    assert client.send_triage_results([_triage_result()]) == 1
    assert len(opener.calls) == 2
    assert slept == [0.5]


def test_persistent_server_error_gives_up_after_max_retries():
    """Retries are bounded; a permanent 500 must raise rather than loop."""

    errors = [
        urllib.error.HTTPError(
            "https://splunk.example:8088/services/collector/event",
            500,
            "Server Error",
            hdrs=None,
            fp=None,
        )
        for _ in range(5)
    ]
    opener = RecordingOpener(errors)
    slept: list[float] = []
    client = SplunkClient(
        _config(max_retries=2, retry_backoff_seconds=1.0),
        opener=opener,
        sleep=slept.append,
    )

    with pytest.raises(SplunkRequestError, match="HTTP 500"):
        client.send_triage_results([_triage_result()])

    assert len(opener.calls) == 3
    assert slept == [1.0, 2.0]


def test_client_error_is_not_retried():
    """A 400 is a client error no retry can fix."""

    opener = RecordingOpener(
        [
            urllib.error.HTTPError(
                "https://splunk.example:8088/services/collector/event",
                400,
                "Bad Request",
                hdrs=None,
                fp=None,
            )
        ]
    )
    client = SplunkClient(_config(), opener=opener)

    with pytest.raises(SplunkRequestError, match="HTTP 400"):
        client.send_triage_results([_triage_result()])

    assert len(opener.calls) == 1


def test_network_error_is_retried():
    """Connection failures are transient and must be retried."""

    opener = RecordingOpener(
        [urllib.error.URLError("connection refused"), FakeHTTPResponse(SUCCESS_BODY)]
    )
    slept: list[float] = []
    client = SplunkClient(_config(retry_backoff_seconds=0.25), opener=opener, sleep=slept.append)

    assert client.send_triage_results([_triage_result()]) == 1
    assert slept == [0.25]


def test_from_settings_reads_splunk_settings_defensively():
    """from_settings should read the four Splunk keys and default the sourcetype."""

    class BareSettings:
        """Settings object exposing only the two required Splunk keys."""

        splunk_hec_url = "https://splunk.example:8088"
        splunk_hec_token = FAKE_TOKEN

    client = SplunkClient.from_settings(BareSettings())

    assert client.config.sourcetype == "ai_triage"
    assert client.config.index == ""
    assert client.config.event_url == "https://splunk.example:8088/services/collector/event"


def test_from_settings_requires_url_and_token():
    """Missing Splunk configuration should fail with a named setting."""

    class NoSplunk:
        """Settings object with no Splunk configuration at all."""

    with pytest.raises(SplunkError, match="SPLUNK_HEC_URL"):
        SplunkClient.from_settings(NoSplunk())

    class UrlOnly:
        """Settings object with a URL but no token."""

        splunk_hec_url = "https://splunk.example:8088"

    with pytest.raises(SplunkError, match="SPLUNK_HEC_TOKEN"):
        SplunkClient.from_settings(UrlOnly())
