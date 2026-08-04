
"""Tests for the Wazuh Manager client and alerts.json reader."""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from soc import wazuh_client
from soc.config import get_settings
from soc.models import EventSource, utc_now
from soc.store import SQLiteStore
from soc.wazuh_client import (
    WAZUH_ALERT_CURSOR_SOURCE,
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

def _cursor_store(tmp_path: Path) -> SQLiteStore:
    """Return an initialized SQLite store for ingestion cursor tests."""

    store = SQLiteStore(tmp_path / "cursor.db")
    store.initialize()
    return store


def test_alert_json_reader_without_cursor_store_rereads_whole_file(tmp_path):
    """With no cursor store the reader must keep re-reading the whole file."""

    alert_path = tmp_path / "alerts.json"
    first = _alert(alert_id="alert-001")
    _write_alerts(alert_path, [first])
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path))

    assert reader.read_recent_alerts() == [first]
    assert reader.read_recent_alerts() == [first]

    second = _alert(alert_id="alert-002")
    _write_alerts(alert_path, [first, second])

    assert reader.read_recent_alerts() == [first, second]


def test_alert_json_reader_with_cursor_store_returns_only_new_alerts(tmp_path):
    """A second read with a cursor store should return only appended alerts."""

    alert_path = tmp_path / "alerts.json"
    first = _alert(alert_id="alert-001")
    _write_alerts(alert_path, [first])
    store = _cursor_store(tmp_path)
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path), cursor_store=store)

    assert reader.read_recent_alerts() == [first]
    assert reader.read_recent_alerts() == []

    second = _alert(alert_id="alert-002")
    with alert_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(second) + "\n")

    assert reader.read_recent_alerts() == [second]
    assert reader.read_recent_alerts() == []


def test_alert_json_reader_persists_cursor_position(tmp_path):
    """The stored cursor should record the file end position, inode, and device."""

    alert_path = tmp_path / "alerts.json"
    _write_alerts(alert_path, [_alert(alert_id="alert-001")])
    store = _cursor_store(tmp_path)
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path), cursor_store=store)

    reader.read_recent_alerts()

    stat = alert_path.stat()
    cursor = store.get_ingest_cursor(WAZUH_ALERT_CURSOR_SOURCE, str(alert_path))

    assert cursor is not None
    assert cursor.byte_offset == stat.st_size
    assert cursor.file_identity == f"{stat.st_dev}-{stat.st_ino}"


def test_alert_json_reader_rereads_whole_file_after_rotation(tmp_path):
    """A rotated file (new inode) must be read from the beginning."""

    alert_path = tmp_path / "alerts.json"
    first = _alert(alert_id="alert-001")
    _write_alerts(alert_path, [first])
    store = _cursor_store(tmp_path)
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path), cursor_store=store)

    original_inode = alert_path.stat().st_ino
    assert reader.read_recent_alerts() == [first]

    rotated = _alert(alert_id="alert-rotated")
    alert_path.rename(tmp_path / "alerts.json.1")
    _write_alerts(alert_path, [rotated])
    assert alert_path.stat().st_ino != original_inode

    assert reader.read_recent_alerts() == [rotated]


def test_alert_json_reader_rereads_whole_file_after_truncation(tmp_path):
    """A truncated file smaller than the stored offset must be re-read fully."""

    alert_path = tmp_path / "alerts.json"
    _write_alerts(
        alert_path,
        [_alert(alert_id="alert-001"), _alert(alert_id="alert-002")],
    )
    store = _cursor_store(tmp_path)
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path), cursor_store=store)

    assert [alert["id"] for alert in reader.read_recent_alerts()] == ["alert-001", "alert-002"]

    replacement = _alert(alert_id="alert-003")
    _write_alerts(alert_path, [replacement])

    # Same file, so it is truncation and not rotation that must trigger the
    # full re-read. Asserting the identity is unchanged keeps this test honest
    # about which mechanism it is exercising.
    stat = alert_path.stat()
    assert store.get_ingest_cursor(
        WAZUH_ALERT_CURSOR_SOURCE, str(alert_path)
    ).file_identity == f"{stat.st_dev}-{stat.st_ino}"

    assert reader.read_recent_alerts() == [replacement]


def test_alert_json_reader_cursor_read_still_filters_and_limits(tmp_path):
    """Lookback, min_level, and limit must apply to incrementally read alerts."""

    alert_path = tmp_path / "alerts.json"
    _write_alerts(alert_path, [_alert(alert_id="seed")])
    store = _cursor_store(tmp_path)
    config = WazuhAlertJsonConfig(
        path=alert_path,
        lookback_minutes=60,
        min_level=7,
        limit=2,
    )
    reader = WazuhAlertJsonReader(config, cursor_store=store)

    assert [alert["id"] for alert in reader.read_recent_alerts()] == ["seed"]

    appended = [
        _alert(alert_id="too-old", timestamp=utc_now() - timedelta(days=2)),
        _alert(alert_id="too-quiet", level=3),
        _alert(alert_id="old-enough", timestamp=utc_now() - timedelta(minutes=30)),
        _alert(alert_id="newer", timestamp=utc_now() - timedelta(minutes=20)),
        _alert(alert_id="newest", timestamp=utc_now() - timedelta(minutes=10)),
    ]
    with alert_path.open("a", encoding="utf-8") as handle:
        for alert in appended:
            handle.write(json.dumps(alert) + "\n")

    assert [alert["id"] for alert in reader.read_recent_alerts()] == ["newer", "newest"]


def test_alert_json_reader_cursor_does_not_consume_partial_final_line(tmp_path):
    """A partially written final line must be re-read once it is complete."""

    alert_path = tmp_path / "alerts.json"
    complete = _alert(alert_id="alert-001")
    pending = _alert(alert_id="alert-002")
    partial = json.dumps(pending)[:40]
    alert_path.write_text(f"{json.dumps(complete)}\n{partial}", encoding="utf-8")
    store = _cursor_store(tmp_path)
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path), cursor_store=store)

    assert reader.read_recent_alerts() == [complete]
    assert reader.last_malformed_line_count == 1

    alert_path.write_text(
        f"{json.dumps(complete)}\n{json.dumps(pending)}\n",
        encoding="utf-8",
    )

    assert reader.read_recent_alerts() == [pending]
    assert reader.last_malformed_line_count == 0


@pytest.fixture(autouse=True)
def sleep_calls(monkeypatch):
    """Replace the Wazuh client retry sleep so tests never wait for real time.

    Inputs:
        monkeypatch: Pytest monkeypatch fixture.

    Outputs:
        List that records every requested sleep duration in order.
    """

    recorded: list[float] = []
    monkeypatch.setattr(wazuh_client.time, "sleep", recorded.append)
    return recorded


def test_manager_config_rejects_invalid_retry_values():
    """Manager config should reject negative retry settings."""

    with pytest.raises(WazuhError, match="max_retries"):
        WazuhManagerConfig(
            url="https://manager:55000",
            username="user",
            password="pass",
            max_retries=-1,
        )

    with pytest.raises(WazuhError, match="retry_backoff_seconds"):
        WazuhManagerConfig(
            url="https://manager:55000",
            username="user",
            password="pass",
            retry_backoff_seconds=-0.5,
        )


def test_manager_request_retries_after_rate_limit(monkeypatch, sleep_calls):
    """An HTTP 429 should be retried and then succeed."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                429,
                "Too Many Requests",
                hdrs=None,
                fp=None,
            )
        return FakeHTTPResponse(json.dumps({"data": {"affected_items": [{"id": "001"}]}}))

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())
    client._token = "jwt-token-123"

    assert client.list_agents() == [{"id": "001"}]
    assert len(calls) == 2
    assert sleep_calls == [1.0]


def test_manager_request_retries_network_errors(monkeypatch, sleep_calls):
    """A transient connection failure should be retried and then succeed."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.URLError("connection refused")
        return FakeHTTPResponse(json.dumps({"data": {"affected_items": []}}))

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())
    client._token = "jwt-token-123"

    assert client.list_agents() == []
    assert len(calls) == 2
    assert sleep_calls == [1.0]


def test_manager_request_gives_up_after_configured_attempts(monkeypatch, sleep_calls):
    """A persistent HTTP 500 should stop after max_retries with exponential delays."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        raise urllib.error.HTTPError(
            request.full_url,
            500,
            "Server Error",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    config = WazuhManagerConfig(
        url="https://wazuh-manager.example:55000/",
        username="api-user",
        password="api-pass",
        verify_tls=False,
        timeout_seconds=5,
        max_retries=2,
        retry_backoff_seconds=0.5,
    )
    client = WazuhManagerClient(config)
    client._token = "jwt-token-123"

    with pytest.raises(WazuhRequestError, match="HTTP 500"):
        client.request("GET", "/agents", retry_auth=False)

    assert len(calls) == 3
    assert sleep_calls == [0.5, 1.0]


def test_manager_request_does_not_retry_not_found(monkeypatch, sleep_calls):
    """An HTTP 404 is not transient and must not be retried."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        raise urllib.error.HTTPError(
            request.full_url,
            404,
            "Not Found",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config())
    client._token = "jwt-token-123"

    with pytest.raises(WazuhRequestError, match="HTTP 404"):
        client.request("GET", "/agents", retry_auth=False)

    assert len(calls) == 1
    assert sleep_calls == []


def test_manager_request_does_not_retry_auth_failures(monkeypatch, sleep_calls):
    """A persistent 401 must re-authenticate exactly once and not back off."""

    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        if request.full_url.endswith("/security/user/authenticate?raw=true"):
            return FakeHTTPResponse("jwt-token-123")
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
        client.request("GET", "/agents")

    assert calls.count("https://wazuh-manager.example:55000/agents") == 2
    assert sleep_calls == []


def test_manager_request_uses_injected_sleep(monkeypatch):
    """A caller-supplied sleep callable should be used for backoff."""

    injected: list[float] = []
    calls: list[str] = []

    def fake_urlopen(request, *, timeout, context):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "Service Unavailable",
                hdrs=None,
                fp=None,
            )
        return FakeHTTPResponse(json.dumps({"data": {"affected_items": []}}))

    monkeypatch.setattr(wazuh_client.urllib.request, "urlopen", fake_urlopen)
    client = WazuhManagerClient(_manager_config(), sleep=injected.append)
    client._token = "jwt-token-123"

    assert client.list_agents() == []
    assert injected == [1.0]


def test_wazuh_client_from_settings_accepts_cursor_store(tmp_path, monkeypatch):
    """from_settings should pass an optional cursor store to the alert reader."""

    alert_path = tmp_path / "alerts.json"
    _write_alerts(alert_path, [_alert()])
    monkeypatch.delenv("WAZUH_MANAGER_URL", raising=False)
    monkeypatch.delenv("WAZUH_HOST", raising=False)
    monkeypatch.delenv("WAZUH_MANAGER_USER", raising=False)
    monkeypatch.delenv("WAZUH_MANAGER_PASSWORD", raising=False)
    env_file = tmp_path / ".env.test"
    env_file.write_text(
        "\n".join(
            [
                "WAZUH_ALERT_SOURCE=json_logs",
                f"WAZUH_ALERT_JSON_PATH={alert_path}",
            ]
        ),
        encoding="utf-8",
    )
    settings = get_settings(env_file=env_file, reload=True)
    store = _cursor_store(tmp_path)

    client = WazuhClient.from_settings(settings, cursor_store=store)

    assert client.alert_reader.cursor_store is store


def test_alert_json_reader_detects_same_size_rewrite(tmp_path):
    """A copytruncate rotation that lands on a similar size must not skip alerts.

    Inode and size are both unchanged when a log is truncated in place and
    immediately refilled with a comparable amount of data. Size shrinkage alone
    cannot detect that, so the reader must fingerprint the file's leading bytes.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies the replacement alert is returned.
    """

    alert_path = tmp_path / "alerts.json"
    store = _cursor_store(tmp_path)
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path), cursor_store=store)

    first = _alert(alert_id="alert-001")
    _write_alerts(alert_path, [first])
    assert reader.read_recent_alerts() == [first]
    size_before = alert_path.stat().st_size

    # Truncate in place and refill. Compare the sizes directly rather than
    # computing an expected byte count: line-ending translation makes any
    # hardcoded arithmetic platform-specific, and the property under test is
    # simply that the size did not change, so size cannot detect the rewrite.
    replacement = _alert(alert_id="alert-002")
    _write_alerts(alert_path, [replacement])
    assert alert_path.stat().st_size == size_before

    assert reader.read_recent_alerts() == [replacement]


def test_alert_json_reader_counts_crlf_line_endings_correctly(tmp_path):
    """A file with Windows line endings must still yield exact byte offsets.

    An alerts.json copied to or written on Windows has CRLF endings. If the
    cursor counted bytes as though endings were one byte, every cycle would
    re-read or skip data.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify the offset matches the file size exactly and
        that only newly appended alerts are returned.
    """

    alert_path = tmp_path / "alerts.json"
    store = _cursor_store(tmp_path)
    first = _alert(alert_id="alert-001")
    with alert_path.open("w", encoding="utf-8", newline="\r\n") as handle:
        handle.write(json.dumps(first) + "\n")

    assert alert_path.read_bytes().endswith(b"\r\n")
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path), cursor_store=store)

    assert reader.read_recent_alerts() == [first]
    cursor = store.get_ingest_cursor(WAZUH_ALERT_CURSOR_SOURCE, str(alert_path))
    assert cursor.byte_offset == alert_path.stat().st_size
    assert reader.read_recent_alerts() == []

    second = _alert(alert_id="alert-002")
    with alert_path.open("a", encoding="utf-8", newline="\r\n") as handle:
        handle.write(json.dumps(second) + "\n")

    assert reader.read_recent_alerts() == [second]


def test_alert_json_reader_keeps_cursor_when_file_only_grows(tmp_path):
    """Fingerprinting must not cause a spurious re-read of an appended file.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies only the appended alert is returned.
    """

    alert_path = tmp_path / "alerts.json"
    store = _cursor_store(tmp_path)
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path), cursor_store=store)

    first = _alert(alert_id="alert-001")
    _write_alerts(alert_path, [first])
    assert reader.read_recent_alerts() == [first]

    second = _alert(alert_id="alert-002")
    with alert_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(second) + "\n")

    assert reader.read_recent_alerts() == [second]


def test_alert_json_reader_handles_windows_scale_file_identifiers(tmp_path, monkeypatch):
    """The reader must work where st_ino exceeds a 64-bit integer.

    This reproduces the Windows failure on any platform: a 128-bit file ID cannot
    be bound as a SQLite INTEGER, which broke every daemon cycle on Windows.

    Inputs:
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.

    Outputs:
        None. Assertions verify the cursor still advances across reads.
    """

    alert_path = tmp_path / "alerts.json"
    store = _cursor_store(tmp_path)
    first = _alert(alert_id="alert-001")
    _write_alerts(alert_path, [first])

    real_stat = Path.stat

    class _HugeIdStat:
        """Stat result reporting Windows-scale identity values."""

        def __init__(self, wrapped: Any) -> None:
            self._wrapped = wrapped
            self.st_ino = 2**80 + 999
            self.st_dev = 2**70 + 7

        def __getattr__(self, name: str) -> Any:
            return getattr(self._wrapped, name)

    def _fake_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        """Return a stat result with oversized identity fields."""

        result = real_stat(self, *args, **kwargs)
        if self == alert_path:
            return _HugeIdStat(result)
        return result

    monkeypatch.setattr(Path, "stat", _fake_stat)
    reader = WazuhAlertJsonReader(_alert_json_config(alert_path), cursor_store=store)

    assert reader.read_recent_alerts() == [first]
    assert reader.read_recent_alerts() == []

    second = _alert(alert_id="alert-002")
    with alert_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(second) + "\n")

    assert reader.read_recent_alerts() == [second]
