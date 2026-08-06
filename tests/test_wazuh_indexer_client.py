"""Tests for the Wazuh Indexer (OpenSearch) ingestion client.

Every test fakes the HTTP transport by injecting an `opener` callable and every
test that would otherwise wait injects a `sleep` recorder, so no test performs
real network I/O and no test spends real time on backoff.

The indexer is a *second* retrieval path for the same Wazuh alerts the
`alerts.json` reader returns. Tests here pin the two properties that keeps
honest: the generated event IDs must not collide with the other paths' IDs, and
selecting the indexer source without indexer credentials must fail loudly rather
than return an empty result set.
"""

from __future__ import annotations

import base64
import json
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from soc.config import get_settings
from soc.models import EventSource
from soc.normalizer import Normalizer
from soc.wazuh_client import WazuhClient, WazuhError
from soc.wazuh_indexer_client import (
    DEFAULT_INDEX_PATTERN,
    EVENT_ID_PREFIX,
    HIT_SOURCE_KEY,
    RULE_LEVEL_FIELD,
    TIMESTAMP_FIELD,
    URL_SETTING,
    WazuhIndexerAuthError,
    WazuhIndexerClient,
    WazuhIndexerConfig,
    WazuhIndexerError,
    WazuhIndexerRequestError,
    build_search_body,
    extract_hits,
    raw_event_from_indexer_hit,
)

FAKE_USER = "fake-indexer-user-do-not-report"
"""Low-entropy, self-describing sentinel. Not a credential."""

FAKE_PASSWORD = "fake-indexer-password-do-not-report"
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


def _config(**overrides: Any) -> WazuhIndexerConfig:
    """Return a test indexer config.

    Inputs:
        **overrides: Field overrides.

    Outputs:
        WazuhIndexerConfig instance.
    """

    values: dict[str, Any] = {
        "base_url": "https://indexer.example:9200/",
        "username": FAKE_USER,
        "password": FAKE_PASSWORD,
        "min_level": 7,
        "limit": 10,
        "lookback_minutes": 60,
        "retry_backoff_seconds": 0.5,
    }
    values.update(overrides)
    return WazuhIndexerConfig(**values)


def _alert(
    *,
    minutes_ago: int = 5,
    level: int = 10,
    rule_id: str = "5710",
    agent_id: str = "001",
) -> dict[str, Any]:
    """Return one Wazuh alert document body.

    Inputs:
        minutes_ago: Age of the alert.
        level: Wazuh rule level.
        rule_id: Wazuh rule ID.
        agent_id: Wazuh agent ID.

    Outputs:
        Alert document dictionary.
    """

    timestamp = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    return {
        "@timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "rule": {"id": rule_id, "level": level, "description": "sshd brute force"},
        "agent": {"id": agent_id, "name": "web-01", "ip": "10.0.1.42"},
        "data": {"srcip": "8.8.8.8"},
        "full_log": "Failed password for invalid user admin",
    }


def _hits_response(*alerts: dict[str, Any], extra_hits: list[Any] | None = None) -> str:
    """Return an OpenSearch search response body wrapping alert documents.

    Inputs:
        *alerts: Alert documents to wrap as hits.
        extra_hits: Optional raw hit entries appended verbatim.

    Outputs:
        JSON response body text.
    """

    hits: list[Any] = [
        {"_index": "wazuh-alerts-4.x-2026.08.05", "_id": f"hit-{index}", HIT_SOURCE_KEY: alert}
        for index, alert in enumerate(alerts)
    ]
    hits.extend(extra_hits or [])
    return json.dumps({"took": 3, "hits": {"total": {"value": len(hits)}, "hits": hits}})


def _request_body(request: Any) -> dict[str, Any]:
    """Return one recorded request's JSON body.

    Inputs:
        request: Recorded urllib Request object.

    Outputs:
        Parsed request body.
    """

    return json.loads(request.data.decode("utf-8"))


# --- Configuration ---------------------------------------------------------


def test_config_rejects_empty_credentials_and_bounds():
    """Config validation should refuse unusable values."""

    with pytest.raises(WazuhIndexerError, match=URL_SETTING):
        _config(base_url="   ")
    with pytest.raises(WazuhIndexerError):
        _config(username="")
    with pytest.raises(WazuhIndexerError):
        _config(password="")
    with pytest.raises(WazuhIndexerError):
        _config(index_pattern=" ")
    with pytest.raises(WazuhIndexerError):
        _config(limit=0)
    with pytest.raises(WazuhIndexerError):
        _config(lookback_minutes=0)
    with pytest.raises(WazuhIndexerError):
        _config(min_level=-1)
    with pytest.raises(WazuhIndexerError):
        _config(max_retries=-1)
    with pytest.raises(WazuhIndexerError):
        _config(retry_backoff_seconds=-1)
    with pytest.raises(WazuhIndexerError):
        _config(timeout_seconds=0)


def test_search_url_joins_base_index_and_search_path():
    """The search URL should be base + URL-encoded index pattern + _search."""

    config = _config()

    assert config.search_url == "https://indexer.example:9200/wazuh-alerts-%2A/_search"
    assert config.index_pattern == DEFAULT_INDEX_PATTERN


# --- Query body ------------------------------------------------------------


def test_build_search_body_bounds_time_level_and_size():
    """The query body should bound the window, the rule level, and the size."""

    since = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    body = build_search_body(since=since, min_level=7, limit=25)

    assert body["size"] == 25
    filters = body["query"]["bool"]["filter"]
    time_filter = next(item for item in filters if TIMESTAMP_FIELD in item.get("range", {}))
    assert time_filter["range"][TIMESTAMP_FIELD]["gte"] == "2026-08-05T12:00:00+00:00"
    level_filter = next(item for item in filters if RULE_LEVEL_FIELD in item.get("range", {}))
    assert level_filter["range"][RULE_LEVEL_FIELD]["gte"] == 7
    assert body["sort"] == [{TIMESTAMP_FIELD: {"order": "desc"}}]


def test_build_search_body_omits_level_filter_at_zero():
    """A minimum level of zero should not add a level filter at all."""

    body = build_search_body(since=datetime(2026, 8, 5, tzinfo=UTC), min_level=0, limit=5)
    filters = body["query"]["bool"]["filter"]

    assert all(RULE_LEVEL_FIELD not in item.get("range", {}) for item in filters)


# --- Retrieval -------------------------------------------------------------


def test_fetch_recent_alerts_posts_basic_auth_to_search_endpoint():
    """The client should POST the query with HTTP Basic auth."""

    opener = RecordingOpener([_hits_response(_alert())])
    client = WazuhIndexerClient(_config(), opener=opener, sleep=SleepRecorder())

    alerts = client.fetch_recent_alerts()

    assert len(alerts) == 1
    request = opener.requests[0]
    assert request.method == "POST"
    assert request.full_url == "https://indexer.example:9200/wazuh-alerts-%2A/_search"
    expected = base64.b64encode(f"{FAKE_USER}:{FAKE_PASSWORD}".encode()).decode("ascii")
    assert request.get_header("Authorization") == f"Basic {expected}"
    assert request.get_header("Content-type") == "application/json"
    assert _request_body(request)["size"] == 10


def test_fetch_recent_alerts_reapplies_level_and_window_filters_locally():
    """Local filtering must stand even if the indexer ignores the query bounds."""

    opener = RecordingOpener(
        [
            _hits_response(
                _alert(minutes_ago=5, level=10, rule_id="high"),
                _alert(minutes_ago=5, level=3, rule_id="low"),
                _alert(minutes_ago=600, level=12, rule_id="stale"),
            )
        ]
    )
    client = WazuhIndexerClient(_config(min_level=7, lookback_minutes=60), opener=opener)

    alerts = client.fetch_recent_alerts()

    assert [alert["rule"]["id"] for alert in alerts] == ["high"]


def test_fetch_recent_alerts_sorts_oldest_first_and_caps_at_limit():
    """Alerts should come back oldest to newest, capped at the limit."""

    opener = RecordingOpener(
        [
            _hits_response(
                _alert(minutes_ago=5, rule_id="newest"),
                _alert(minutes_ago=30, rule_id="middle"),
                _alert(minutes_ago=50, rule_id="oldest"),
            )
        ]
    )
    client = WazuhIndexerClient(_config(limit=2), opener=opener)

    alerts = client.fetch_recent_alerts()

    assert [alert["rule"]["id"] for alert in alerts] == ["middle", "newest"]


def test_unusable_hits_are_skipped_and_counted():
    """Non-dict hits and hits without a usable _source must be counted."""

    opener = RecordingOpener(
        [
            _hits_response(
                _alert(rule_id="good"),
                extra_hits=["not-a-dict", {"_id": "no-source"}, {"_source": ["list-not-dict"]}],
            )
        ]
    )
    client = WazuhIndexerClient(_config(), opener=opener)

    alerts = client.fetch_recent_alerts()

    assert [alert["rule"]["id"] for alert in alerts] == ["good"]
    assert client.last_skipped_hit_count == 3


def test_extract_hits_reports_unrecognized_shape_without_raising():
    """An unrecognized response envelope should yield no hits, not an exception."""

    documents, skipped = extract_hits({"error": {"type": "index_not_found_exception"}})

    assert documents == []
    assert skipped == 0


# --- Error handling --------------------------------------------------------


def _http_error(code: int, body: str = "failure") -> urllib.error.HTTPError:
    """Return an HTTPError with a readable body.

    Inputs:
        code: HTTP status code.
        body: Response body text.

    Outputs:
        HTTPError instance.
    """

    import io

    return urllib.error.HTTPError(
        url="https://indexer.example:9200/wazuh-alerts-%2A/_search",
        code=code,
        msg="error",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(body.encode("utf-8")),
    )


def test_auth_failure_is_not_retried():
    """A 401 is a credential problem, so it must fail on the first attempt."""

    opener = RecordingOpener([_http_error(401, "unauthorized")])
    sleeper = SleepRecorder()
    client = WazuhIndexerClient(_config(max_retries=2), opener=opener, sleep=sleeper)

    with pytest.raises(WazuhIndexerAuthError):
        client.fetch_recent_alerts()

    assert len(opener.requests) == 1
    assert sleeper.delays == []


def test_forbidden_is_treated_as_auth_failure():
    """A 403 means the account lacks read access, which a retry cannot fix."""

    opener = RecordingOpener([_http_error(403, "forbidden")])
    client = WazuhIndexerClient(_config(max_retries=2), opener=opener, sleep=SleepRecorder())

    with pytest.raises(WazuhIndexerAuthError):
        client.fetch_recent_alerts()

    assert len(opener.requests) == 1


def test_server_error_is_retried_with_bounded_backoff():
    """A 5xx should be retried up to max_retries times, then raise."""

    opener = RecordingOpener([_http_error(503), _http_error(503), _http_error(503)])
    sleeper = SleepRecorder()
    client = WazuhIndexerClient(
        _config(max_retries=2, retry_backoff_seconds=0.5), opener=opener, sleep=sleeper
    )

    with pytest.raises(WazuhIndexerRequestError):
        client.fetch_recent_alerts()

    assert len(opener.requests) == 3
    assert sleeper.delays == [0.5, 1.0]


def test_server_error_recovers_on_retry():
    """A transient 5xx followed by success should return alerts."""

    opener = RecordingOpener([_http_error(500), _hits_response(_alert())])
    client = WazuhIndexerClient(_config(), opener=opener, sleep=SleepRecorder())

    assert len(client.fetch_recent_alerts()) == 1


def test_client_error_is_not_retried():
    """A 404 index-missing error is a configuration problem, not a transient."""

    opener = RecordingOpener([_http_error(404, "index_not_found_exception")])
    client = WazuhIndexerClient(_config(max_retries=2), opener=opener, sleep=SleepRecorder())

    with pytest.raises(WazuhIndexerRequestError, match="404"):
        client.fetch_recent_alerts()

    assert len(opener.requests) == 1


def test_network_error_and_timeout_are_retryable():
    """Connection failures and timeouts should be retried."""

    opener = RecordingOpener([urllib.error.URLError("connection refused"), _hits_response(_alert())])
    client = WazuhIndexerClient(_config(), opener=opener, sleep=SleepRecorder())
    assert len(client.fetch_recent_alerts()) == 1

    opener = RecordingOpener([TimeoutError(), _hits_response(_alert())])
    client = WazuhIndexerClient(_config(), opener=opener, sleep=SleepRecorder())
    assert len(client.fetch_recent_alerts()) == 1


def test_malformed_json_body_raises_request_error():
    """A non-JSON body should raise rather than yield zero alerts silently."""

    opener = RecordingOpener(["<html>proxy error</html>"])
    client = WazuhIndexerClient(_config(), opener=opener, sleep=SleepRecorder())

    with pytest.raises(WazuhIndexerRequestError, match="malformed JSON"):
        client.fetch_recent_alerts()


def test_credentials_are_scrubbed_from_error_messages():
    """The indexer echoes request detail into errors, so scrub the password."""

    body = f"rejected credentials {FAKE_USER}:{FAKE_PASSWORD} for search"
    opener = RecordingOpener([_http_error(401, body)])
    client = WazuhIndexerClient(_config(), opener=opener, sleep=SleepRecorder())

    with pytest.raises(WazuhIndexerAuthError) as excinfo:
        client.fetch_recent_alerts()

    message = str(excinfo.value)
    assert FAKE_PASSWORD not in message
    assert "***" in message


def test_credentials_are_scrubbed_from_retry_exhaustion_message():
    """The final "gave up" message is built separately and must scrub too."""

    body = f"backend down, password={FAKE_PASSWORD}"
    opener = RecordingOpener([_http_error(503, body), _http_error(503, body)])
    client = WazuhIndexerClient(_config(max_retries=1), opener=opener, sleep=SleepRecorder())

    with pytest.raises(WazuhIndexerRequestError) as excinfo:
        client.fetch_recent_alerts()

    assert FAKE_PASSWORD not in str(excinfo.value)


# --- RawEvent construction -------------------------------------------------


def test_raw_event_ids_are_deterministic_and_path_scoped():
    """IDs must be content-addressed and must name this retrieval path."""

    alert = _alert()
    hit = {"_id": "opensearch-doc-1", HIT_SOURCE_KEY: alert}

    first = raw_event_from_indexer_hit(hit)
    second = raw_event_from_indexer_hit({"_id": "opensearch-doc-2", HIT_SOURCE_KEY: dict(alert)})

    assert first.id == second.id
    assert first.id.startswith(f"{EVENT_ID_PREFIX}-")
    assert first.source is EventSource.WAZUH
    assert first.payload["rule"]["id"] == "5710"


def test_raw_event_id_differs_from_the_other_wazuh_retrieval_paths():
    """The same alert read two ways must not share one audit row."""

    from soc.splunk_search_client import raw_event_from_splunk_result
    from soc.wazuh_client import raw_event_from_alert_json

    alert = _alert()

    indexer_event = raw_event_from_indexer_hit({HIT_SOURCE_KEY: dict(alert)})
    json_event = raw_event_from_alert_json(dict(alert))
    splunk_event = raw_event_from_splunk_result({"_raw": json.dumps(alert), "sourcetype": "wazuh"})

    assert len({indexer_event.id, json_event.id, splunk_event.id}) == 3


def test_raw_event_timestamp_comes_from_the_alert_document():
    """The event timestamp should be parsed out of the alert, not invented."""

    alert = _alert()
    alert["@timestamp"] = "2026-08-05T11:22:33.000Z"

    event = raw_event_from_indexer_hit({HIT_SOURCE_KEY: alert})

    assert event.timestamp == datetime(2026, 8, 5, 11, 22, 33, tzinfo=UTC)


def test_fetch_recent_events_produces_normalizable_events():
    """Events must be usable by the existing Wazuh normalizer unchanged."""

    opener = RecordingOpener([_hits_response(_alert())])
    client = WazuhIndexerClient(_config(), opener=opener, sleep=SleepRecorder())

    events = client.fetch_recent_events()
    alerts = Normalizer().normalize_many(events)

    assert len(alerts) == 1
    assert alerts[0].source is EventSource.WAZUH
    assert alerts[0].src_ip == "8.8.8.8"


def test_agent_inventory_is_attached_when_supplied():
    """Agent context should be merged in exactly as the alerts.json path does."""

    opener = RecordingOpener([_hits_response(_alert(agent_id="001"))])
    client = WazuhIndexerClient(_config(), opener=opener, sleep=SleepRecorder())

    events = client.fetch_recent_events(agent_inventory={"001": {"id": "001", "os": {"name": "Ubuntu"}}})

    assert events[0].payload["agent_context"]["os"]["name"] == "Ubuntu"


# --- from_settings ---------------------------------------------------------


def _env_file(tmp_path: Path, body: str, monkeypatch: Any) -> Path:
    """Write a throwaway .env file and clear the keys it sets.

    Inputs:
        tmp_path: Pytest temporary directory.
        body: Env file body.
        monkeypatch: Pytest monkeypatch fixture.

    Outputs:
        Path to the written env file.
    """

    for line in body.strip().splitlines():
        key = line.strip().split("=", 1)[0]
        if key:
            monkeypatch.delenv(key, raising=False)

    env_file = tmp_path / ".env.test"
    env_file.write_text("\n".join(line.strip() for line in body.strip().splitlines()), encoding="utf-8")
    return env_file


def test_from_settings_builds_config_from_wazuh_indexer_settings(tmp_path, monkeypatch):
    """from_settings should read the WAZUH_INDEXER_* and shared alert settings."""

    env_file = _env_file(
        tmp_path,
        f"""
        WAZUH_ALERT_SOURCE=indexer
        WAZUH_INDEXER_URL=https://indexer.example:9200
        WAZUH_INDEXER_USER={FAKE_USER}
        WAZUH_INDEXER_PASSWORD={FAKE_PASSWORD}
        WAZUH_INDEXER_VERIFY_TLS=false
        WAZUH_ALERT_INDEX=wazuh-alerts-4.x-*
        WAZUH_ALERT_LIMIT=33
        WAZUH_ALERT_LOOKBACK_MINUTES=90
        WAZUH_MIN_LEVEL=5
        """,
        monkeypatch,
    )
    settings = get_settings(env_file, reload=True)

    client = WazuhIndexerClient.from_settings(settings, opener=RecordingOpener([]), sleep=SleepRecorder())

    assert client.config.base_url == "https://indexer.example:9200"
    assert client.config.username == FAKE_USER
    assert client.config.index_pattern == "wazuh-alerts-4.x-*"
    assert client.config.limit == 33
    assert client.config.lookback_minutes == 90
    assert client.config.min_level == 5
    assert client.config.verify_tls is False


def test_from_settings_without_indexer_url_fails_loudly(tmp_path, monkeypatch):
    """Selecting the indexer with no URL must raise, never return zero results."""

    env_file = _env_file(
        tmp_path,
        """
        WAZUH_ALERT_SOURCE=indexer
        WAZUH_INDEXER_URL=
        WAZUH_INDEXER_USER=
        WAZUH_INDEXER_PASSWORD=
        """,
        monkeypatch,
    )
    settings = get_settings(env_file, reload=True)

    with pytest.raises(WazuhIndexerError, match=URL_SETTING):
        WazuhIndexerClient.from_settings(settings)


def test_from_settings_without_password_fails_loudly(tmp_path, monkeypatch):
    """A URL with no credentials must fail rather than send an anonymous query."""

    env_file = _env_file(
        tmp_path,
        f"""
        WAZUH_ALERT_SOURCE=indexer
        WAZUH_INDEXER_URL=https://indexer.example:9200
        WAZUH_INDEXER_USER={FAKE_USER}
        WAZUH_INDEXER_PASSWORD=
        """,
        monkeypatch,
    )
    settings = get_settings(env_file, reload=True)

    with pytest.raises(WazuhIndexerError, match="WAZUH_INDEXER_PASSWORD"):
        WazuhIndexerClient.from_settings(settings)


# --- Wiring into the Wazuh ingestion selection path ------------------------


def test_wazuh_client_from_settings_routes_indexer_source_to_the_indexer(tmp_path, monkeypatch):
    """WAZUH_ALERT_SOURCE=indexer must build an indexer-backed facade."""

    env_file = _env_file(
        tmp_path,
        f"""
        WAZUH_ALERT_SOURCE=indexer
        WAZUH_INDEXER_URL=https://indexer.example:9200
        WAZUH_INDEXER_USER={FAKE_USER}
        WAZUH_INDEXER_PASSWORD={FAKE_PASSWORD}
        WAZUH_MIN_LEVEL=7
        WAZUH_ALERT_LOOKBACK_MINUTES=60
        WAZUH_ALERT_LIMIT=10
        """,
        monkeypatch,
    )
    settings = get_settings(env_file, reload=True)

    opener = RecordingOpener([_hits_response(_alert())])
    client = WazuhClient.from_settings(settings, opener=opener, sleep=SleepRecorder())

    assert client.alert_reader is None
    assert isinstance(client.indexer, WazuhIndexerClient)

    events = client.fetch_recent_events()

    assert len(events) == 1
    assert events[0].id.startswith(f"{EVENT_ID_PREFIX}-")


def test_wazuh_client_from_settings_indexer_without_settings_is_actionable(tmp_path, monkeypatch):
    """Indexer source with no indexer settings must name what to set."""

    alert_path = tmp_path / "alerts.json"
    alert_path.write_text("", encoding="utf-8")
    env_file = _env_file(
        tmp_path,
        f"""
        WAZUH_ALERT_SOURCE=indexer
        WAZUH_ALERT_JSON_PATH={alert_path}
        WAZUH_INDEXER_URL=
        WAZUH_INDEXER_USER=
        WAZUH_INDEXER_PASSWORD=
        """,
        monkeypatch,
    )
    settings = get_settings(env_file, reload=True)

    with pytest.raises(WazuhError) as excinfo:
        WazuhClient.from_settings(settings)

    message = str(excinfo.value)
    assert "WAZUH_INDEXER_URL" in message
    assert "WAZUH_ALERT_SOURCE=json_logs" in message


def test_wazuh_client_from_settings_still_reads_json_logs(tmp_path, monkeypatch):
    """The json_logs path must be untouched by the indexer wiring."""

    alert_path = tmp_path / "alerts.json"
    alert_path.write_text(json.dumps(_alert()) + "\n", encoding="utf-8")
    env_file = _env_file(
        tmp_path,
        f"""
        WAZUH_ALERT_SOURCE=json_logs
        WAZUH_ALERT_JSON_PATH={alert_path}
        WAZUH_MIN_LEVEL=7
        WAZUH_ALERT_LOOKBACK_MINUTES=60
        WAZUH_ALERT_LIMIT=10
        """,
        monkeypatch,
    )
    settings = get_settings(env_file, reload=True)

    client = WazuhClient.from_settings(settings)

    assert client.indexer is None
    assert client.alert_reader is not None

    events = client.fetch_recent_events()

    assert len(events) == 1
    assert not events[0].id.startswith(f"{EVENT_ID_PREFIX}-")


def test_wazuh_client_from_settings_rejects_unknown_alert_source(tmp_path, monkeypatch):
    """An unknown source must name both supported values."""

    env_file = _env_file(
        tmp_path,
        """
        WAZUH_ALERT_SOURCE=elasticsearch
        """,
        monkeypatch,
    )
    settings = get_settings(env_file, reload=True)

    with pytest.raises(WazuhError) as excinfo:
        WazuhClient.from_settings(settings)

    message = str(excinfo.value)
    assert "json_logs" in message
    assert "indexer" in message
