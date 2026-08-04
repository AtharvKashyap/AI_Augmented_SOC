"""Tests for the Security Onion Connect API client.

Every test fakes the HTTP transport, either by monkeypatching
`urllib.request.urlopen` inside the module under test or by injecting an
`opener` callable. No test performs real network I/O.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
from datetime import timedelta
from typing import Any

import pytest

import soc.security_onion_client as so_client
from soc.models import AlertSeverity, EventSource, utc_now
from soc.normalizer import normalize_security_onion_event
from soc.security_onion_client import (
    SecurityOnionAuthError,
    SecurityOnionClient,
    SecurityOnionConfig,
    SecurityOnionError,
    SecurityOnionRequestError,
    extract_event_documents,
    raw_event_from_security_onion_document,
)


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


def _config(**overrides: Any) -> SecurityOnionConfig:
    """Return a test Security Onion config."""

    values: dict[str, Any] = {
        "host": "https://securityonion.example/",
        "client_id": "so-client",
        "client_secret": "so-secret",
        "verify_tls": False,
        "timeout_seconds": 5,
    }
    values.update(overrides)
    return SecurityOnionConfig(**values)


def _token_body(expires_in: int = 3599) -> str:
    """Return a Connect API OAuth2 token response body."""

    return json.dumps(
        {
            "access_token": "so-token-1",
            "expires_in": expires_in,
            "scope": "",
            "token_type": "bearer",
        }
    )


def _document(**overrides: Any) -> dict[str, Any]:
    """Return a Security Onion event document."""

    document: dict[str, Any] = {
        "_id": "doc-1",
        "@timestamp": utc_now().isoformat(),
        "event": {"severity": 1, "dataset": "alert"},
        "source": {"ip": "10.10.1.5"},
        "destination": {"ip": "203.0.113.9"},
        "suricata": {"alert": {"signature": "ET MALWARE Suspicious Beacon", "severity": 1}},
        "host": {"name": "sensor-01"},
    }
    document.update(overrides)
    return document


@pytest.fixture
def sleep_calls(monkeypatch):
    """Replace the module retry sleep so tests never wait for real time.

    Inputs:
        monkeypatch: Pytest monkeypatch fixture.

    Outputs:
        List that records every requested sleep duration in order.
    """

    recorded: list[float] = []
    monkeypatch.setattr(so_client.time, "sleep", recorded.append)
    return recorded


def test_config_rejects_missing_and_invalid_values():
    """Config validation should raise SecurityOnionError on bad input."""

    with pytest.raises(SecurityOnionError, match="host"):
        SecurityOnionConfig(host="", client_id="id", client_secret="secret")

    with pytest.raises(SecurityOnionError, match="client_id"):
        SecurityOnionConfig(host="https://so", client_id="", client_secret="secret")

    with pytest.raises(SecurityOnionError, match="client_secret"):
        SecurityOnionConfig(host="https://so", client_id="id", client_secret="")

    with pytest.raises(SecurityOnionError, match="max_retries"):
        SecurityOnionConfig(host="https://so", client_id="id", client_secret="s", max_retries=-1)

    with pytest.raises(SecurityOnionError, match="retry_backoff_seconds"):
        SecurityOnionConfig(
            host="https://so",
            client_id="id",
            client_secret="s",
            retry_backoff_seconds=-0.5,
        )

    with pytest.raises(SecurityOnionError, match="lookback"):
        SecurityOnionConfig(host="https://so", client_id="id", client_secret="s", lookback_minutes=0)

    with pytest.raises(SecurityOnionError, match="limit"):
        SecurityOnionConfig(host="https://so", client_id="id", client_secret="s", limit=0)

    with pytest.raises(SecurityOnionError, match="parameter name"):
        SecurityOnionConfig(host="https://so", client_id="id", client_secret="s", range_param="")


def test_config_exposes_inferred_parameter_names():
    """The inferred query parameter names must be overridable config fields."""

    config = _config()
    assert config.range_param == "range"
    assert config.zone_param == "zone"
    assert config.format_param == "format"
    assert config.limit_param == "eventLimit"

    overridden = _config(range_param="timeRange", limit_param="limit")
    assert overridden.range_param == "timeRange"
    assert overridden.limit_param == "limit"


def test_authenticate_uses_basic_auth_and_client_credentials_grant(monkeypatch):
    """The token request must use HTTP Basic auth and the client_credentials grant."""

    captured: dict[str, Any] = {}

    def fake_urlopen(request, *, timeout, context):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["headers"] = dict(request.header_items())
        captured["body"] = request.data.decode("utf-8") if request.data else None
        captured["timeout"] = timeout
        captured["context"] = context
        return FakeHTTPResponse(_token_body())

    monkeypatch.setattr(so_client.urllib.request, "urlopen", fake_urlopen)
    client = SecurityOnionClient(_config())

    token = client.authenticate()

    assert token == "so-token-1"
    assert client.token == "so-token-1"
    assert captured["url"] == "https://securityonion.example/oauth2/token"
    assert captured["method"] == "POST"
    assert captured["headers"]["Authorization"] == "Basic " + so_client.base64.b64encode(
        b"so-client:so-secret"
    ).decode("ascii")
    assert captured["headers"]["Content-type"] == "application/x-www-form-urlencoded"
    assert captured["body"] == "grant_type=client_credentials"
    assert captured["timeout"] == 5
    assert captured["context"] is not None


def test_authenticate_rejects_empty_token(monkeypatch):
    """A token response without an access_token must raise an auth error."""

    monkeypatch.setattr(
        so_client.urllib.request,
        "urlopen",
        lambda request, *, timeout, context: FakeHTTPResponse(json.dumps({"expires_in": 10})),
    )
    client = SecurityOnionClient(_config())

    with pytest.raises(SecurityOnionAuthError, match="access_token"):
        client.authenticate()


def test_get_info_sends_bearer_token(monkeypatch):
    """Connect API requests must carry the bearer token from the token endpoint."""

    calls: list[dict[str, Any]] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(
            {
                "url": request.full_url,
                "method": request.get_method(),
                "headers": dict(request.header_items()),
            }
        )
        if request.full_url.endswith("/oauth2/token"):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"version": "2.4.70"}))

    monkeypatch.setattr(so_client.urllib.request, "urlopen", fake_urlopen)
    client = SecurityOnionClient(_config())

    info = client.get_info()

    assert info == {"version": "2.4.70"}
    assert calls[1]["url"] == "https://securityonion.example/connect/info"
    assert calls[1]["method"] == "GET"
    assert calls[1]["headers"]["Authorization"] == "Bearer so-token-1"


def test_injected_opener_is_used_instead_of_urlopen():
    """An injected opener must receive every request, so no network is touched."""

    seen: list[str] = []

    def opener(request, *, timeout, context):
        seen.append(request.full_url)
        if request.full_url.endswith("/oauth2/token"):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"status": "ok"}))

    client = SecurityOnionClient(_config(), opener=opener)

    assert client.get_info() == {"status": "ok"}
    assert seen == [
        "https://securityonion.example/oauth2/token",
        "https://securityonion.example/connect/info",
    ]


def test_expired_token_triggers_exactly_one_reauthentication():
    """An expired cached token must be refreshed once, not on every request."""

    calls: list[str] = []

    def opener(request, *, timeout, context):
        calls.append(request.full_url)
        if request.full_url.endswith("/oauth2/token"):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"status": "ok"}))

    client = SecurityOnionClient(_config(), opener=opener)
    client._token = "stale-token"
    client._token_expires_at = utc_now() - timedelta(seconds=1)

    client.get_info()
    client.get_info()

    assert calls.count("https://securityonion.example/oauth2/token") == 1
    assert client.token == "so-token-1"


def test_valid_token_is_not_refreshed():
    """A cached, unexpired token must be reused without a token request."""

    calls: list[str] = []

    def opener(request, *, timeout, context):
        calls.append(request.full_url)
        return FakeHTTPResponse(json.dumps({"status": "ok"}))

    client = SecurityOnionClient(_config(), opener=opener)
    client._token = "fresh-token"
    client._token_expires_at = utc_now() + timedelta(hours=1)

    client.get_info()

    assert calls == ["https://securityonion.example/connect/info"]


def test_token_is_refreshed_early_before_exact_expiry():
    """A token inside the refresh skew window counts as expired."""

    calls: list[str] = []

    def opener(request, *, timeout, context):
        calls.append(request.full_url)
        if request.full_url.endswith("/oauth2/token"):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"status": "ok"}))

    client = SecurityOnionClient(_config(), opener=opener)
    client._token = "almost-stale"
    client._token_expires_at = utc_now() + timedelta(
        seconds=so_client.TOKEN_REFRESH_SKEW_SECONDS - 1
    )

    client.get_info()

    assert calls[0] == "https://securityonion.example/oauth2/token"


def test_authenticate_records_expiry_from_expires_in():
    """The cached expiry must be derived from the expires_in field."""

    client = SecurityOnionClient(
        _config(),
        opener=lambda request, *, timeout, context: FakeHTTPResponse(_token_body(expires_in=600)),
    )

    before = utc_now()
    client.authenticate()

    assert client.token_expires_at is not None
    delta = (client.token_expires_at - before).total_seconds()
    assert 590 <= delta <= 610


def test_from_settings_requires_host_and_credentials():
    """Missing host or credentials must raise an actionable SecurityOnionError."""

    class Settings:
        """Minimal settings stand-in."""

        securityonion_host = ""
        securityonion_client_id = "id"
        securityonion_client_secret = "secret"

    with pytest.raises(SecurityOnionError, match="SECURITYONION_HOST"):
        SecurityOnionClient.from_settings(Settings())

    class NoCredentials:
        """Settings with a host but no OAuth2 client credentials."""

        securityonion_host = "https://securityonion.example"
        securityonion_client_id = ""
        securityonion_client_secret = ""

    with pytest.raises(SecurityOnionError, match="SECURITYONION_CLIENT_ID"):
        SecurityOnionClient.from_settings(NoCredentials())

    class NoSecret:
        """Settings with a client ID but no client secret."""

        securityonion_host = "https://securityonion.example"
        securityonion_client_id = "id"
        securityonion_client_secret = ""

    with pytest.raises(SecurityOnionError, match="SECURITYONION_CLIENT_SECRET"):
        SecurityOnionClient.from_settings(NoSecret())


def test_from_settings_reads_optional_attributes_defensively():
    """from_settings must tolerate settings objects missing the optional keys."""

    class Settings:
        """Settings exposing only the required Security Onion keys."""

        securityonion_host = "https://securityonion.example"
        securityonion_client_id = "id"
        securityonion_client_secret = "secret"

    client = SecurityOnionClient.from_settings(Settings())

    assert client.config.host == "https://securityonion.example"
    assert client.config.verify_tls is True
    assert client.config.lookback_minutes > 0
    assert client.config.limit > 0
    assert client.config.grid_id is None


def test_from_settings_uses_supplied_optional_attributes():
    """Optional settings attributes must override the client defaults."""

    class Settings:
        """Settings exposing every Security Onion key."""

        securityonion_host = "https://securityonion.example"
        securityonion_client_id = "id"
        securityonion_client_secret = "secret"
        securityonion_verify_tls = False
        so_min_severity = 1
        securityonion_lookback_minutes = 15
        securityonion_alert_limit = 25
        securityonion_grid_id = "grid-7"

    client = SecurityOnionClient.from_settings(Settings())

    assert client.config.verify_tls is False
    assert client.config.min_severity == 1
    assert client.config.lookback_minutes == 15
    assert client.config.limit == 25
    assert client.config.grid_id == "grid-7"


def test_request_retries_after_rate_limit(monkeypatch, sleep_calls):
    """An HTTP 429 should be retried and then succeed."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.HTTPError(request.full_url, 429, "Too Many", hdrs=None, fp=None)
        return FakeHTTPResponse(json.dumps({"status": "ok"}))

    monkeypatch.setattr(so_client.urllib.request, "urlopen", fake_urlopen)
    client = SecurityOnionClient(_config())
    client._token = "so-token-1"
    client._token_expires_at = utc_now() + timedelta(hours=1)

    assert client.get_info() == {"status": "ok"}
    assert len(calls) == 2
    assert sleep_calls == [1.0]


def test_request_retries_network_errors(monkeypatch, sleep_calls):
    """A transient connection failure should be retried and then succeed."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.URLError("connection refused")
        return FakeHTTPResponse(json.dumps({"status": "ok"}))

    monkeypatch.setattr(so_client.urllib.request, "urlopen", fake_urlopen)
    client = SecurityOnionClient(_config())
    client._token = "so-token-1"
    client._token_expires_at = utc_now() + timedelta(hours=1)

    assert client.get_info() == {"status": "ok"}
    assert len(calls) == 2
    assert sleep_calls == [1.0]


def test_request_gives_up_after_configured_attempts(monkeypatch, sleep_calls):
    """A persistent HTTP 500 should stop after max_retries with exponential delays."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 500, "Server Error", hdrs=None, fp=None)

    monkeypatch.setattr(so_client.urllib.request, "urlopen", fake_urlopen)
    client = SecurityOnionClient(_config(max_retries=2, retry_backoff_seconds=0.5))
    client._token = "so-token-1"
    client._token_expires_at = utc_now() + timedelta(hours=1)

    with pytest.raises(SecurityOnionRequestError, match="HTTP 500"):
        client.request("GET", so_client.INFO_PATH, retry_auth=False)

    assert len(calls) == 3
    assert sleep_calls == [0.5, 1.0]


def test_request_does_not_retry_not_found(monkeypatch, sleep_calls):
    """An HTTP 404 is not transient and must not be retried."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", hdrs=None, fp=None)

    monkeypatch.setattr(so_client.urllib.request, "urlopen", fake_urlopen)
    client = SecurityOnionClient(_config())
    client._token = "so-token-1"
    client._token_expires_at = utc_now() + timedelta(hours=1)

    with pytest.raises(SecurityOnionRequestError, match="HTTP 404"):
        client.request("GET", so_client.INFO_PATH, retry_auth=False)

    assert len(calls) == 1
    assert sleep_calls == []


def test_persistent_unauthorized_does_not_retry_loop(monkeypatch, sleep_calls):
    """A persistent 401 must re-authenticate exactly once and never back off."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", hdrs=None, fp=None)

    monkeypatch.setattr(so_client.urllib.request, "urlopen", fake_urlopen)
    client = SecurityOnionClient(_config())
    client._token = "so-token-1"
    client._token_expires_at = utc_now() + timedelta(hours=1)

    with pytest.raises(SecurityOnionAuthError, match="authentication failed"):
        client.get_info()

    info_url = "https://securityonion.example/connect/info"
    assert calls.count(info_url) == 2
    assert calls.count("https://securityonion.example/oauth2/token") == 1
    assert sleep_calls == []


def test_query_sends_confirmed_and_inferred_parameters():
    """The event query must use the confirmed query param and configured names."""

    seen: list[str] = []

    def opener(request, *, timeout, context):
        seen.append(request.full_url)
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"events": []}))

    client = SecurityOnionClient(_config(grid_id="grid-7"), opener=opener)
    client.fetch_recent_alerts()

    query_url = seen[-1]
    assert query_url.startswith("https://securityonion.example/connect/query/data?")
    params = urllib.parse.parse_qs(urllib.parse.urlparse(query_url).query)
    assert params["query"] == ['_index:"*:so-*"']
    assert params["gridId"] == ["grid-7"]
    assert params["zone"] == ["UTC"]
    assert params["format"] == ["YYYY/MM/DD HH:mm:ss"]
    assert params["eventLimit"] == ["100"]
    assert " - " in params["range"][0]


def test_query_honours_overridden_parameter_names():
    """Renaming the inferred parameters must change the wire parameter names."""

    seen: list[str] = []

    def opener(request, *, timeout, context):
        seen.append(request.full_url)
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"events": []}))

    config = _config(
        range_param="timeRange",
        zone_param="tz",
        format_param="dateFormat",
        limit_param="limit",
    )
    SecurityOnionClient(config, opener=opener).fetch_recent_alerts()

    params = urllib.parse.parse_qs(urllib.parse.urlparse(seen[-1]).query)
    assert set(params) == {"query", "timeRange", "tz", "dateFormat", "limit"}


def test_query_without_grid_id_omits_the_parameter():
    """gridId is only meaningful for Manager-of-Managers and must be optional."""

    seen: list[str] = []

    def opener(request, *, timeout, context):
        seen.append(request.full_url)
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"events": []}))

    SecurityOnionClient(_config(), opener=opener).fetch_recent_alerts()

    assert "gridId" not in urllib.parse.parse_qs(urllib.parse.urlparse(seen[-1]).query)


def test_extract_event_documents_handles_top_level_events():
    """A top-level events list must be extracted."""

    document = _document()
    assert extract_event_documents({"events": [document]}) == [document]


def test_extract_event_documents_handles_nested_data_events():
    """A nested data.events list must be extracted."""

    document = _document()
    assert extract_event_documents({"data": {"events": [document]}}) == [document]


def test_extract_event_documents_handles_elasticsearch_hits():
    """Elasticsearch-style hits.hits[]._source documents must be extracted."""

    source = {"@timestamp": "2026-01-01T00:00:00Z", "source": {"ip": "10.0.0.1"}}
    response = {"hits": {"hits": [{"_id": "hit-1", "_index": "so-ids", "_source": source}]}}

    documents = extract_event_documents(response)

    assert len(documents) == 1
    assert documents[0]["source"] == {"ip": "10.0.0.1"}
    assert documents[0]["_id"] == "hit-1"
    assert documents[0]["_index"] == "so-ids"


def test_extract_event_documents_ignores_non_dict_entries():
    """Non-object entries in an events list must be skipped."""

    document = _document()
    assert extract_event_documents({"events": [document, "nope", 3, None]}) == [document]


def test_extract_event_documents_returns_empty_for_unknown_shape(caplog):
    """An unrecognized response must return no events and log the keys seen."""

    with caplog.at_level("WARNING"):
        documents = extract_event_documents({"totalEvents": 3, "metrics": {}})

    assert documents == []
    assert "totalEvents" in caplog.text
    assert "metrics" in caplog.text


def test_fetch_recent_alerts_filters_by_severity():
    """Documents less severe than min_severity must be dropped."""

    now = utc_now()
    high = _document(_id="high", event={"severity": 1}, **{"@timestamp": now.isoformat()})
    low = _document(_id="low", event={"severity": 3}, **{"@timestamp": now.isoformat()})
    low["suricata"] = {"alert": {"signature": "noise", "severity": 3}}

    def opener(request, *, timeout, context):
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"events": [high, low]}))

    client = SecurityOnionClient(_config(min_severity=2), opener=opener)

    documents = client.fetch_recent_alerts()

    assert [document["_id"] for document in documents] == ["high"]


def test_fetch_recent_alerts_keeps_documents_without_severity():
    """A document with no parseable severity must not be silently dropped."""

    document = _document(_id="no-severity", event={"dataset": "alert"})
    document.pop("suricata")

    def opener(request, *, timeout, context):
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"events": [document]}))

    client = SecurityOnionClient(_config(min_severity=2), opener=opener)

    assert [item["_id"] for item in client.fetch_recent_alerts()] == ["no-severity"]


def test_fetch_recent_alerts_filters_by_lookback_window():
    """Documents older than the lookback window must be dropped."""

    now = utc_now()
    recent = _document(_id="recent", **{"@timestamp": now.isoformat()})
    stale = _document(_id="stale", **{"@timestamp": (now - timedelta(minutes=180)).isoformat()})

    def opener(request, *, timeout, context):
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"events": [stale, recent]}))

    client = SecurityOnionClient(_config(lookback_minutes=60), opener=opener)

    assert [item["_id"] for item in client.fetch_recent_alerts()] == ["recent"]


def test_fetch_recent_alerts_sorts_and_applies_limit():
    """Results must be oldest-to-newest and capped at the configured limit."""

    now = utc_now()
    documents = [
        _document(_id=f"doc-{index}", **{"@timestamp": (now - timedelta(minutes=index)).isoformat()})
        for index in range(5)
    ]

    def opener(request, *, timeout, context):
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"events": documents}))

    client = SecurityOnionClient(_config(limit=2), opener=opener)

    assert [item["_id"] for item in client.fetch_recent_alerts()] == ["doc-1", "doc-0"]


def test_raw_event_from_document_is_deterministic_and_preserves_payload():
    """Conversion must yield a stable ID and keep the whole document."""

    document = _document()

    first = raw_event_from_security_onion_document(document)
    second = raw_event_from_security_onion_document(dict(document))

    assert first.source == EventSource.SECURITY_ONION
    assert first.id == second.id
    assert "doc-1" in first.id
    assert first.payload == document
    assert first.payload is not document


def test_raw_event_id_falls_back_to_content_hash():
    """A document with no ID field must get a deterministic content hash ID."""

    document = _document()
    document.pop("_id")

    first = raw_event_from_security_onion_document(document)
    second = raw_event_from_security_onion_document(dict(document))
    other = raw_event_from_security_onion_document({**document, "source": {"ip": "10.9.9.9"}})

    assert first.id == second.id
    assert first.id != other.id
    assert first.id.startswith("security_onion-")


def test_raw_event_timestamp_comes_from_the_document():
    """The RawEvent timestamp must be parsed from the document timestamp."""

    stamp = utc_now().replace(microsecond=0)
    event = raw_event_from_security_onion_document(_document(**{"@timestamp": stamp.isoformat()}))

    assert event.timestamp == stamp


def test_fetch_recent_events_returns_raw_events():
    """fetch_recent_events must return RawEvent objects for each document."""

    def opener(request, *, timeout, context):
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"events": [_document()]}))

    events = SecurityOnionClient(_config(), opener=opener).fetch_recent_events()

    assert len(events) == 1
    assert events[0].source == EventSource.SECURITY_ONION
    assert events[0].payload["_id"] == "doc-1"


def test_fetched_events_normalize_through_the_existing_normalizer():
    """The RawEvent payload shape must fit normalize_security_onion_event."""

    def opener(request, *, timeout, context):
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(json.dumps({"events": [_document()]}))

    events = SecurityOnionClient(_config(), opener=opener).fetch_recent_events()
    alert = normalize_security_onion_event(events[0])

    assert alert.source == EventSource.SECURITY_ONION
    assert alert.src_ip == "10.10.1.5"
    assert alert.dst_ip == "203.0.113.9"
    assert alert.rule_name == "ET MALWARE Suspicious Beacon"
    assert alert.hostname == "sensor-01"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.raw_event_id == events[0].id


def test_elasticsearch_hit_normalizes_through_the_existing_normalizer():
    """An Elasticsearch-shaped response must also survive normalization."""

    source = {
        "@timestamp": utc_now().isoformat(),
        "event": {"severity": 2},
        "source": {"ip": "192.168.10.20"},
        "destination": {"ip": "198.51.100.4"},
        "rule": {"name": "Zeek Notice"},
    }

    def opener(request, *, timeout, context):
        if request.full_url.endswith(so_client.TOKEN_PATH):
            return FakeHTTPResponse(_token_body())
        return FakeHTTPResponse(
            json.dumps({"hits": {"hits": [{"_id": "hit-9", "_source": source}]}})
        )

    events = SecurityOnionClient(_config(), opener=opener).fetch_recent_events()
    alert = normalize_security_onion_event(events[0])

    assert alert.src_ip == "192.168.10.20"
    assert alert.dst_ip == "198.51.100.4"
    assert alert.rule_name == "Zeek Notice"
    assert alert.severity == AlertSeverity.MEDIUM
