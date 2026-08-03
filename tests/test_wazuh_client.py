
"""Tests for the Wazuh Manager client and alerts.json reader."""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import soc.wazuh_client as wazuh_client
from soc.config import get_settings
from soc.models import EventSource, utc_now
from soc.wazuh_client import (
    WazuhAlertJsonConfig,
    WazuhAlertJsonReader,
    WazuhAuthError,
    WazuhClient,
    WazuhError,
    WazuhManagerClient,
    WazuhManagerConfig,
    WazuhRequestError,
    raw_event_from_alert_json,
)


class FakeHTTPResponse:
    """Small context-manager response object for urllib mocks."""

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


def _manager_config() -> WazuhManagerConfig:
    """Return test manager config."""

    return WazuhManagerConfig(
        url="https://wazuh-manager.example:55000/",
        username="api-user",
        password="api-pass",
        verify_tls=False,
        timeout_seconds=5,
    )


def _alert_json_config(path: Path) -> WazuhAlertJsonConfig:
    """Return test alerts.json config."""

    return WazuhAlertJsonConfig(
        path=path,
        lookback_minutes=1440,
        min_level=7,
        limit=100,
    )


def _alert(
    *,
    alert_id: str = "alert-001",
    timestamp: datetime | None = None,
    level: int = 12,
    agent_id: str = "001",
) -> dict[str, Any]:
    """Build a realistic Wazuh alerts.json object."""

    event_time = timestamp or utc_now()
    return {
        "id": alert_id,
        "timestamp": event_time.isoformat().replace("+00:00", "Z"),
        "rule": {
            "id": "92001",
            "level": level,
            "description": "Suspicious PowerShell encoded command execution",
            "groups": ["windows", "powershell"],
        },
        "agent": {
            "id": agent_id,
            "name": "endpoint-01",
            "ip": "10.0.1.42",
        },
        "data": {
            "win": {
                "eventdata": {
                    "targetUserName": "alice",
                    "newProcessName": "powershell.exe",
                    "commandLine": "powershell.exe -EncodedCommand ABC123",
                }
            }
        },
        "full_log": "Encoded PowerShell execution detected",
    }


def _write_alerts(path: Path, alerts: list[dict[str, Any]]) -> None:
    """Write line-delimited Wazuh alerts JSON."""

    path.write_text(
        "\n".join(json.dumps(alert) for alert in alerts) + "\n",
        encoding="utf-8",
    )


def test_manager_config_rejects_missing_values():
    """Manager config should reject missing required values."""

    with pytest.raises(WazuhError, match="manager URL"):
        WazuhManagerConfig(url="", username="user", password="pass")

    with pytest.raises(WazuhError, match="manager username"):
        WazuhManagerConfig(url="https://manager:55000", username="", password="pass")

    with pytest.raises(WazuhError, match="manager password"):
        WazuhManagerConfig(url="https://manager:55000", username="user", password="")


def test_alert_json_config_rejects_invalid_values(tmp_path):
    """alerts.json config should reject invalid filter values."""

    alert_path = tmp_path / "alerts.json"

    with pytest.raises(WazuhError, match="lookback"):
        WazuhAlertJsonConfig(path=alert_path, lookback_minutes=0)

    with pytest.raises(WazuhError, match="minimum rule level"):
        WazuhAlertJsonConfig(path=alert_path, min_level=-1)

    with pytest.raises(WazuhError, match="alert limit"):
        WazuhAlertJsonConfig(path=alert_path, limit=0)


def test_manager_authenticate_builds_basic_auth_request(monkeypatch):
    """Manager authentication should request a raw JWT token with basic auth."""

    captured: dict[str, Any] = {}

    def fake_urlopen(request, *, timeout, context):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["headers"] = dict(request.header_items())
        captured["timeout"] = timeout
        captured["context"] = context
        return FakeHTTPResponse("jwt-token-123")

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())

    token = client.authenticate()

    assert token == "jwt-token-123"
    assert client.token == "jwt-token-123"
    assert captured["url"] == (
        "https://wazuh-manager.example:55000/security/user/authenticate?raw=true"
    )
    assert captured["method"] == "POST"
    assert captured["headers"]["Authorization"].startswith("Basic ")
    assert captured["timeout"] == 5
    assert captured["context"] is not None


def test_manager_request_uses_bearer_token_and_parses_agents(monkeypatch):
    """Manager list_agents should authenticate and use bearer token."""

    calls: list[dict[str, Any]] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(
            {
                "url": request.full_url,
                "method": request.get_method(),
                "headers": dict(request.header_items()),
            }
        )
        if request.full_url.endswith("/security/user/authenticate?raw=true"):
            return FakeHTTPResponse("jwt-token-123")
        return FakeHTTPResponse(
            json.dumps(
                {
                    "data": {
                        "affected_items": [
                            {"id": "001", "name": "endpoint-01"},
                            {"id": "002", "name": "endpoint-02"},
                        ]
                    }
                }
            )
        )

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())

    agents = client.list_agents(status="active")

    assert agents == [
        {"id": "001", "name": "endpoint-01"},
        {"id": "002", "name": "endpoint-02"},
    ]
    assert calls[1]["url"] == "https://wazuh-manager.example:55000/agents?status=active"
    assert calls[1]["headers"]["Authorization"] == "Bearer jwt-token-123"


def test_manager_request_refreshes_token_on_auth_error(monkeypatch):
    """Manager request should retry once after a 401."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        if request.full_url.endswith("/security/user/authenticate?raw=true"):
            token_number = calls.count(request.full_url)
            return FakeHTTPResponse(f"jwt-token-{token_number}")
        if calls.count(request.full_url) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                401,
                "Unauthorized",
                hdrs=None,
                fp=None,
            )
        return FakeHTTPResponse(json.dumps({"data": {"affected_items": []}}))

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())

    agents = client.list_agents()

    assert agents == []
    assert client.token == "jwt-token-2"
    assert (
        calls.count("https://wazuh-manager.example:55000/security/user/authenticate?raw=true")
        == 2
    )
    assert calls.count("https://wazuh-manager.example:55000/agents") == 2


def test_manager_get_agent_returns_first_affected_item(monkeypatch):
    """get_agent should return the first affected item when present."""

    client = WazuhManagerClient(_manager_config())
    monkeypatch.setattr(
        client,
        "request",
        lambda method, path: {"data": {"affected_items": [{"id": "001"}]}},
    )

    assert client.get_agent("001") == {"id": "001"}


def test_manager_get_agent_rejects_empty_agent_id():
    """get_agent should reject an empty agent ID."""

    client = WazuhManagerClient(_manager_config())

    with pytest.raises(WazuhRequestError, match="agent_id"):
        client.get_agent("")


def test_alert_json_reader_reads_recent_alerts(tmp_path):
    """alerts.json reader should parse line-delimited JSON alerts."""

    alert_path = tmp_path / "alerts.json"
    alerts = [_alert(alert_id="alert-001"), _alert(alert_id="alert-002")]
    _write_alerts(alert_path, alerts)

    reader = WazuhAlertJsonReader(_alert_json_config(alert_path))

    assert reader.read_recent_alerts() == alerts


def test_alert_json_reader_filters_old_alerts(tmp_path):
    """alerts.json reader should filter alerts outside the lookback window."""

    alert_path = tmp_path / "alerts.json"
    old_alert = _alert(alert_id="old", timestamp=utc_now() - timedelta(days=3))
    recent_alert = _alert(alert_id="recent", timestamp=utc_now())
    _write_alerts(alert_path, [old_alert, recent_alert])
    config = WazuhAlertJsonConfig(
        path=alert_path,
        lookback_minutes=60,
        min_level=0,
        limit=100,
    )

    reader = WazuhAlertJsonReader(config)

    assert reader.read_recent_alerts() == [recent_alert]


def test_alert_json_reader_filters_low_rule_levels(tmp_path):
    """alerts.json reader should filter alerts below the minimum rule level."""

    alert_path = tmp_path / "alerts.json"
    low_alert = _alert(alert_id="low", level=3)
    high_alert = _alert(alert_id="high", level=10)
    _write_alerts(alert_path, [low_alert, high_alert])
    config = WazuhAlertJsonConfig(
        path=alert_path,
        lookback_minutes=1440,
        min_level=7,
        limit=100,
    )

    reader = WazuhAlertJsonReader(config)

    assert reader.read_recent_alerts() == [high_alert]


def test_alert_json_reader_respects_limit_and_sorts(tmp_path):
    """alerts.json reader should return newest alerts up to the configured limit."""

    alert_path = tmp_path / "alerts.json"
    oldest = _alert(alert_id="oldest", timestamp=utc_now() - timedelta(minutes=30))
    middle = _alert(alert_id="middle", timestamp=utc_now() - timedelta(minutes=20))
    newest = _alert(alert_id="newest", timestamp=utc_now() - timedelta(minutes=10))
    _write_alerts(alert_path, [newest, oldest, middle])
    config = WazuhAlertJsonConfig(
        path=alert_path,
        lookback_minutes=1440,
        min_level=0,
        limit=2,
    )

    reader = WazuhAlertJsonReader(config)

    assert [alert["id"] for alert in reader.read_recent_alerts()] == ["middle", "newest"]


def test_alert_json_reader_rejects_missing_file(tmp_path):
    """alerts.json reader should raise when the file does not exist."""

    reader = WazuhAlertJsonReader(_alert_json_config(tmp_path / "missing.json"))

    with pytest.raises(WazuhRequestError, match="does not exist"):
        reader.read_recent_alerts()


def test_alert_json_reader_rejects_path_that_is_not_a_file(tmp_path):
    """alerts.json reader should raise when the path is a directory."""

    directory = tmp_path / "alerts_dir"
    directory.mkdir()
    reader = WazuhAlertJsonReader(_alert_json_config(directory))

    with pytest.raises(WazuhRequestError, match="not a file"):
        reader.read_recent_alerts()


def test_alert_json_reader_skips_truncated_final_line(tmp_path):
    """A truncated final line should be skipped without losing valid alerts."""

    alert_path = tmp_path / "alerts.json"
    valid_alert = _alert(alert_id="alert-001")
    truncated = json.dumps(_alert(alert_id="alert-002"))[:40]
    alert_path.write_text(
        f"{json.dumps(valid_alert)}\n{truncated}",
        encoding="utf-8",
    )
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path))

    alerts = reader.read_recent_alerts()

    assert alerts == [valid_alert]
    assert reader.last_malformed_line_count == 1


def test_alert_json_reader_skips_all_malformed_lines(tmp_path):
    """All malformed lines should be skipped and counted."""

    alert_path = tmp_path / "alerts.json"
    valid_alert = _alert(alert_id="alert-001")
    alert_path.write_text(
        "\n".join(["not-json", json.dumps(valid_alert), "{broken", ""]),
        encoding="utf-8",
    )
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path))

    assert reader.read_recent_alerts() == [valid_alert]
    assert reader.last_malformed_line_count == 2


def test_alert_json_reader_resets_malformed_count_each_read(tmp_path):
    """The malformed line count should reset on every read_recent_alerts call."""

    alert_path = tmp_path / "alerts.json"
    valid_alert = _alert(alert_id="alert-001")
    alert_path.write_text("not-json\n", encoding="utf-8")
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path))

    assert reader.read_recent_alerts() == []
    assert reader.last_malformed_line_count == 1

    _write_alerts(alert_path, [valid_alert])

    assert reader.read_recent_alerts() == [valid_alert]
    assert reader.last_malformed_line_count == 0


def test_alert_json_reader_logs_warning_for_malformed_lines(tmp_path, caplog):
    """Skipped malformed lines should emit a logging warning naming the file."""

    alert_path = tmp_path / "alerts.json"
    alert_path.write_text(
        "\n".join([json.dumps(_alert(alert_id="alert-001")), "not-json"]),
        encoding="utf-8",
    )
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path))

    with caplog.at_level("WARNING", logger="soc.wazuh_client"):
        reader.read_recent_alerts()

    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert len(warnings) == 1
    assert str(alert_path) in warnings[0].getMessage()
    assert "1" in warnings[0].getMessage()


def test_alert_json_reader_does_not_log_when_all_lines_valid(tmp_path, caplog):
    """No warning should be emitted when every line parses."""

    alert_path = tmp_path / "alerts.json"
    _write_alerts(alert_path, [_alert(alert_id="alert-001")])
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path))

    with caplog.at_level("WARNING", logger="soc.wazuh_client"):
        reader.read_recent_alerts()

    assert reader.last_malformed_line_count == 0
    assert [record for record in caplog.records if record.levelname == "WARNING"] == []


def test_alert_json_reader_skips_non_dict_json_lines(tmp_path):
    """Lines that parse but are not objects should be skipped, not counted."""

    alert_path = tmp_path / "alerts.json"
    valid_alert = _alert(alert_id="alert-001")
    alert_path.write_text(
        "\n".join(["[]", '"text"', json.dumps(valid_alert)]),
        encoding="utf-8",
    )
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path))

    assert reader.read_recent_alerts() == [valid_alert]
    assert reader.last_malformed_line_count == 0


def test_raw_event_from_alert_json_maps_source_and_agent_context():
    """alerts.json alert should convert into RawEvent for the pipeline."""

    agent_inventory = {
        "001": {"id": "001", "os": {"name": "Windows 11"}, "status": "active"}
    }
    raw_event = raw_event_from_alert_json(_alert(), agent_inventory=agent_inventory)

    assert raw_event.id == "alert-001"
    assert raw_event.source == EventSource.WAZUH
    assert raw_event.payload["rule"]["level"] == 12
    assert raw_event.payload["agent_context"] == agent_inventory["001"]


def test_raw_event_from_alert_json_generates_fallback_id():
    """Raw event conversion should generate stable fallback ID when missing IDs."""

    alert = _alert()
    alert.pop("id")

    raw_event = raw_event_from_alert_json(alert)

    assert raw_event.id.startswith("wazuh-")
    assert "001" in raw_event.id
    assert "92001" in raw_event.id


def test_wazuh_client_fetch_recent_events_combines_alerts_and_inventory(tmp_path):
    """Facade should read alerts and attach manager inventory."""

    alert_path = tmp_path / "alerts.json"
    _write_alerts(alert_path, [_alert()])

    class FakeManager:
        def list_agents(self):
            return [{"id": "001", "name": "endpoint-01", "status": "active"}]

    reader = WazuhAlertJsonReader(_alert_json_config(alert_path))
    client = WazuhClient(manager=FakeManager(), alert_reader=reader)

    events = client.fetch_recent_events(lookback_minutes=5, min_level=7, limit=100)

    assert len(events) == 1
    assert events[0].id == "alert-001"
    assert events[0].payload["agent_context"] == {
        "id": "001",
        "name": "endpoint-01",
        "status": "active",
    }


def test_wazuh_client_can_skip_agent_inventory(tmp_path):
    """Facade should not call manager when inventory is disabled."""

    alert_path = tmp_path / "alerts.json"
    _write_alerts(alert_path, [_alert()])

    class FailingManager:
        def list_agents(self):
            raise AssertionError("manager should not be called")

    reader = WazuhAlertJsonReader(_alert_json_config(alert_path))
    client = WazuhClient(manager=FailingManager(), alert_reader=reader)

    events = client.fetch_recent_events(include_agent_inventory=False)

    assert len(events) == 1
    assert "agent_context" not in events[0].payload


def test_json_request_raises_for_malformed_json(monkeypatch):
    """Malformed JSON responses should raise WazuhRequestError."""

    def fake_urlopen(request, *, timeout, context):
        return FakeHTTPResponse("not-json")

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())
    client._token = "jwt-token-123"

    with pytest.raises(WazuhRequestError, match="malformed JSON"):
        client.request("GET", "/agents", retry_auth=False)


def test_json_request_raises_for_non_object_json(monkeypatch):
    """Non-object JSON responses should raise WazuhRequestError."""

    def fake_urlopen(request, *, timeout, context):
        return FakeHTTPResponse("[]")

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())
    client._token = "jwt-token-123"

    with pytest.raises(WazuhRequestError, match="non-object JSON"):
        client.request("GET", "/agents", retry_auth=False)


def test_http_401_raises_auth_error(monkeypatch):
    """HTTP 401 responses should raise WazuhAuthError."""

    def fake_urlopen(request, *, timeout, context):
        raise urllib.error.HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())
    client._token = "jwt-token-123"

    with pytest.raises(WazuhAuthError, match="authentication failed"):
        client.request("GET", "/agents", retry_auth=False)


def test_http_500_raises_request_error(monkeypatch):
    """HTTP 500 responses should raise WazuhRequestError."""

    def fake_urlopen(request, *, timeout, context):
        raise urllib.error.HTTPError(
            request.full_url,
            500,
            "Server Error",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())
    client._token = "jwt-token-123"

    with pytest.raises(WazuhRequestError, match="HTTP 500"):
        client.request("GET", "/agents", retry_auth=False)


def test_url_error_raises_request_error(monkeypatch):
    """Network failures should raise WazuhRequestError."""

    def fake_urlopen(request, *, timeout, context):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())
    client._token = "jwt-token-123"

    with pytest.raises(WazuhRequestError, match="connection refused"):
        client.request("GET", "/agents", retry_auth=False)


def test_wazuh_client_from_settings_builds_json_logs_client(tmp_path, monkeypatch):
    """from_settings should build a Manager + alerts.json client."""

    alert_path = tmp_path / "alerts.json"
    _write_alerts(alert_path, [_alert()])
    for key in [
        "WAZUH_HOST",
        "WAZUH_USER",
        "WAZUH_PASSWORD",
        "WAZUH_MANAGER_URL",
        "WAZUH_MANAGER_USER",
        "WAZUH_MANAGER_PASSWORD",
        "WAZUH_ALERT_SOURCE",
        "WAZUH_ALERT_JSON_PATH",
        "WAZUH_ALERT_LOOKBACK_MINUTES",
        "WAZUH_ALERT_LIMIT",
        "WAZUH_MIN_LEVEL",
    ]:
        monkeypatch.delenv(key, raising=False)

    env_file = tmp_path / ".env.test"
    env_file.write_text(
        "\n".join(
            [
                "WAZUH_ALERT_SOURCE=json_logs",
                f"WAZUH_ALERT_JSON_PATH={alert_path}",
                "WAZUH_ALERT_LOOKBACK_MINUTES=1440",
                "WAZUH_ALERT_LIMIT=20",
                "WAZUH_MIN_LEVEL=0",
            ]
        ),
        encoding="utf-8",
    )
    settings = get_settings(env_file, reload=True)

    client = WazuhClient.from_settings(settings)

    assert client.manager is None
    assert client.alert_reader.config.path == alert_path
    assert client.alert_reader.config.lookback_minutes == 1440
    assert client.alert_reader.config.limit == 20
    assert client.alert_reader.config.min_level == 0


def test_wazuh_client_from_settings_builds_manager_when_configured(tmp_path):
    """from_settings should include Manager client when Manager settings exist."""

    alert_path = tmp_path / "alerts.json"
    _write_alerts(alert_path, [_alert()])
    env_file = tmp_path / ".env.test"
    env_file.write_text(
        "\n".join(
            [
                "WAZUH_ALERT_SOURCE=json_logs",
                f"WAZUH_ALERT_JSON_PATH={alert_path}",
                "WAZUH_MANAGER_URL=https://manager.example:55000",
                "WAZUH_MANAGER_USER=manager-user",
                "WAZUH_MANAGER_PASSWORD=manager-pass",
                "WAZUH_MANAGER_VERIFY_TLS=false",
            ]
        ),
        encoding="utf-8",
    )
    settings = get_settings(env_file, reload=True)

    client = WazuhClient.from_settings(settings)

    assert client.manager is not None
    assert client.manager.config.url == "https://manager.example:55000"
    assert client.manager.config.username == "manager-user"
    assert client.manager.config.password == "manager-pass"
    assert client.manager.config.verify_tls is False


def test_wazuh_client_from_settings_requires_json_logs_source(tmp_path, monkeypatch):
    """Manager-only from_settings should require WAZUH_ALERT_SOURCE=json_logs."""

    alert_path = tmp_path / "alerts.json"
    _write_alerts(alert_path, [_alert()])
    for key in [
        "WAZUH_ALERT_SOURCE",
        "WAZUH_ALERT_JSON_PATH",
        "WAZUH_ALERT_LOOKBACK_MINUTES",
        "WAZUH_ALERT_LIMIT",
        "WAZUH_MIN_LEVEL",
    ]:
        monkeypatch.delenv(key, raising=False)
    env_file = tmp_path / ".env.test"
    env_file.write_text(
        "\n".join(
            [
                "WAZUH_ALERT_SOURCE=indexer",
                f"WAZUH_ALERT_JSON_PATH={alert_path}",
            ]
        ),
        encoding="utf-8",
    )
    settings = get_settings(env_file, reload=True)

    with pytest.raises(WazuhError, match="WAZUH_ALERT_SOURCE=json_logs"):
        WazuhClient.from_settings(settings)