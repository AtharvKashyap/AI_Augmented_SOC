
"""Wazuh Manager client and alerts.json reader.

This module supports a Manager-only Wazuh deployment where this project can
access the Wazuh Manager API and a readable alerts.json file.

Wazuh Manager API, usually https://<manager>:55000:
- authenticate
- list agents
- fetch agent context

Wazuh alerts.json, usually /var/ossec/logs/alerts/alerts.json:
- read line-delimited JSON alerts
- filter by timestamp and rule.level
- convert alerts into RawEvent objects for SOCPipeline.run_events()
"""

from __future__ import annotations

import base64
import json
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from soc.models import EventSource, RawEvent, utc_now

if TYPE_CHECKING:
    from soc.config import Settings


logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]


class WazuhError(RuntimeError):
    """Base error for Wazuh client failures."""


class WazuhAuthError(WazuhError):
    """Raised when Wazuh authentication fails."""


class WazuhRequestError(WazuhError):
    """Raised when a Wazuh request fails."""


@dataclass(frozen=True, slots=True)
class WazuhManagerConfig:
    """Configuration for the Wazuh Manager API."""

    url: str
    username: str
    password: str
    verify_tls: bool = True
    timeout_seconds: int = 20

    def __post_init__(self) -> None:
        """Validate config."""

        if not self.url:
            raise WazuhError("Wazuh manager URL cannot be empty")
        if not self.username:
            raise WazuhError("Wazuh manager username cannot be empty")
        if not self.password:
            raise WazuhError("Wazuh manager password cannot be empty")


@dataclass(frozen=True, slots=True)
class WazuhAlertJsonConfig:
    """Configuration for reading Wazuh alerts.json."""

    path: Path
    lookback_minutes: int = 60
    min_level: int = 7
    limit: int = 100

    def __post_init__(self) -> None:
        """Validate config."""

        if not self.path:
            raise WazuhError("Wazuh alert JSON path cannot be empty")
        if self.lookback_minutes <= 0:
            raise WazuhError("Wazuh alert lookback must be greater than zero")
        if self.min_level < 0:
            raise WazuhError("Wazuh minimum rule level cannot be negative")
        if self.limit <= 0:
            raise WazuhError("Wazuh alert limit must be greater than zero")


class WazuhManagerClient:
    """Client for Wazuh Manager API operations."""

    def __init__(self, config: WazuhManagerConfig) -> None:
        """Initialize manager client."""

        self.config = config
        self._token: str | None = None
        self._ssl_context = _build_ssl_context(config.verify_tls)

    @property
    def token(self) -> str | None:
        """Return cached bearer token."""

        return self._token

    def authenticate(self) -> str:
        """Authenticate to Wazuh Manager and cache the bearer token."""

        token = self._request_token()
        self._token = token
        return token

    def list_agents(self, *, status: str | None = None) -> list[JsonDict]:
        """Return Wazuh agent inventory."""

        query: dict[str, str] = {}
        if status:
            query["status"] = status
        response = self.request("GET", "/agents", query=query)
        return _extract_wazuh_items(response)

    def get_agent(self, agent_id: str) -> JsonDict:
        """Return one Wazuh agent by ID."""

        if not agent_id:
            raise WazuhRequestError("agent_id cannot be empty")

        response = self.request("GET", f"/agents/{urllib.parse.quote(agent_id)}")
        data = response.get("data")
        if isinstance(data, dict):
            affected_items = data.get("affected_items")
            if isinstance(affected_items, list) and affected_items:
                item = affected_items[0]
                if isinstance(item, dict):
                    return item
            if data:
                return data
        return response

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        body: JsonDict | None = None,
        retry_auth: bool = True,
    ) -> JsonDict:
        """Send an authenticated request to Wazuh Manager."""

        if self._token is None:
            self.authenticate()

        headers = {"Authorization": f"Bearer {self._token}"}
        try:
            return _json_request(
                method,
                _build_url(self.config.url, path, query=query),
                body=body,
                headers=headers,
                timeout_seconds=self.config.timeout_seconds,
                ssl_context=self._ssl_context,
            )
        except WazuhAuthError:
            if not retry_auth:
                raise

            self.authenticate()
            headers = {"Authorization": f"Bearer {self._token}"}
            return _json_request(
                method,
                _build_url(self.config.url, path, query=query),
                body=body,
                headers=headers,
                timeout_seconds=self.config.timeout_seconds,
                ssl_context=self._ssl_context,
            )

    def _request_token(self) -> str:
        """Request a raw JWT token from Wazuh Manager."""

        credentials = f"{self.config.username}:{self.config.password}".encode("utf-8")
        encoded_credentials = base64.b64encode(credentials).decode("ascii")
        headers = {"Authorization": f"Basic {encoded_credentials}"}
        response = _text_request(
            "POST",
            _build_url(self.config.url, "/security/user/authenticate", query={"raw": "true"}),
            headers=headers,
            timeout_seconds=self.config.timeout_seconds,
            ssl_context=self._ssl_context,
        )
        token = response.strip().strip('"')
        if not token:
            raise WazuhAuthError("Wazuh Manager returned an empty token")
        return token


class WazuhAlertJsonReader:
    """Reader for Wazuh line-delimited alerts.json files."""

    def __init__(self, config: WazuhAlertJsonConfig) -> None:
        """Initialize alerts.json reader.

        Inputs:
            config: alerts.json location and filter configuration.

        Outputs:
            None.
        """

        self.config = config
        self.last_malformed_line_count = 0

    def read_recent_alerts(self) -> list[JsonDict]:
        """Read, parse, filter, and limit recent Wazuh alerts.

        Wazuh appends to alerts.json continuously, so a truncated or partially
        written line is expected. Malformed lines are skipped, counted in
        last_malformed_line_count, and reported once as a logged warning.

        Inputs:
            None.

        Outputs:
            Recent alert objects sorted oldest to newest, capped at the
            configured limit.

        Raises:
            WazuhRequestError: If the configured path is missing or not a file.
        """

        self.last_malformed_line_count = 0

        if not self.config.path.exists():
            raise WazuhRequestError(f"Wazuh alert JSON file does not exist: {self.config.path}")
        if not self.config.path.is_file():
            raise WazuhRequestError(f"Wazuh alert JSON path is not a file: {self.config.path}")

        since = utc_now() - timedelta(minutes=self.config.lookback_minutes)
        alerts: list[JsonDict] = []

        with self.config.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue

                try:
                    alert = json.loads(stripped)
                except json.JSONDecodeError:
                    self.last_malformed_line_count += 1
                    continue

                if not isinstance(alert, dict):
                    continue
                if not _alert_is_recent(alert, since):
                    continue
                if _rule_level(alert) < self.config.min_level:
                    continue

                alerts.append(alert)

        if self.last_malformed_line_count:
            logger.warning(
                "Skipped %d malformed JSON line(s) in Wazuh alert file %s",
                self.last_malformed_line_count,
                self.config.path,
            )

        alerts.sort(key=_alert_sort_key)
        return alerts[-self.config.limit :]

    def fetch_recent_events(
        self,
        *,
        agent_inventory: dict[str, JsonDict] | None = None,
    ) -> list[RawEvent]:
        """Read recent alerts and convert them into RawEvent objects."""

        return [
            raw_event_from_alert_json(alert, agent_inventory=agent_inventory)
            for alert in self.read_recent_alerts()
        ]


class WazuhClient:
    """Facade for Manager-only Wazuh ingestion into SOC RawEvent objects."""

    def __init__(
        self,
        *,
        manager: WazuhManagerClient | None = None,
        alert_reader: WazuhAlertJsonReader,
    ) -> None:
        """Initialize facade client."""

        self.manager = manager
        self.alert_reader = alert_reader

    @classmethod
    def from_settings(cls, settings: "Settings") -> "WazuhClient":
        """Build a Manager-only Wazuh client from application settings."""

        if settings.wazuh_alert_source != "json_logs":
            raise WazuhError("Manager-only Wazuh mode requires WAZUH_ALERT_SOURCE=json_logs")

        manager = None
        if _has_manager_settings(settings):
            settings.validate_wazuh_manager()
            manager = WazuhManagerClient(
                WazuhManagerConfig(
                    url=settings.wazuh_manager_url,
                    username=settings.wazuh_manager_user,
                    password=settings.wazuh_manager_password,
                    verify_tls=settings.wazuh_manager_verify_tls,
                )
            )

        alert_reader = WazuhAlertJsonReader(
            WazuhAlertJsonConfig(
                path=settings.wazuh_alert_json_path,
                lookback_minutes=settings.wazuh_alert_lookback_minutes,
                min_level=settings.wazuh_min_level,
                limit=settings.wazuh_alert_limit,
            )
        )
        return cls(manager=manager, alert_reader=alert_reader)

    def fetch_agent_inventory(self) -> dict[str, JsonDict]:
        """Fetch agent inventory keyed by agent ID."""

        if self.manager is None:
            return {}

        agents = self.manager.list_agents()
        inventory: dict[str, JsonDict] = {}
        for agent in agents:
            agent_id = str(agent.get("id", "")).strip()
            if agent_id:
                inventory[agent_id] = agent
        return inventory

    def fetch_recent_events(
        self,
        *,
        lookback_minutes: int | None = None,
        min_level: int | None = None,
        limit: int | None = None,
        include_agent_inventory: bool = True,
    ) -> list[RawEvent]:
        """Fetch recent Wazuh alerts and convert them to RawEvent objects.

        The optional lookback/min_level/limit parameters are accepted for
        compatibility with run_pipeline.py. The alert reader already has these
        values from settings, so this method does not need to rebuild it.
        """

        _ = lookback_minutes, min_level, limit
        agent_inventory = self.fetch_agent_inventory() if include_agent_inventory else {}
        return self.alert_reader.fetch_recent_events(agent_inventory=agent_inventory)


def raw_event_from_alert_json(
    alert: JsonDict,
    *,
    agent_inventory: dict[str, JsonDict] | None = None,
) -> RawEvent:
    """Convert one Wazuh alerts.json object into a RawEvent."""

    event_id = _event_id_from_alert(alert)
    timestamp = _parse_wazuh_timestamp(alert.get("@timestamp") or alert.get("timestamp"))
    payload = dict(alert)

    agent_id = _nested_str(payload, ["agent", "id"])
    if agent_id and agent_inventory and agent_id in agent_inventory:
        payload["agent_context"] = agent_inventory[agent_id]

    return RawEvent(
        id=event_id,
        source=EventSource.WAZUH,
        timestamp=timestamp,
        payload=payload,
        received_at=utc_now(),
    )


def _has_manager_settings(settings: "Settings") -> bool:
    """Return whether optional Wazuh Manager settings are configured."""

    return all(
        [
            settings.wazuh_manager_url.strip(),
            settings.wazuh_manager_user.strip(),
            settings.wazuh_manager_password.strip(),
        ]
    )


def _event_id_from_alert(alert: JsonDict) -> str:
    """Return stable event ID from a Wazuh alert object."""

    for value in (alert.get("id"), alert.get("event_id"), alert.get("_id")):
        if isinstance(value, str) and value.strip():
            return value.strip()

    timestamp = str(alert.get("@timestamp") or alert.get("timestamp") or "unknown-time")
    agent = _nested_str(alert, ["agent", "id"]) or _nested_str(alert, ["agent", "name"])
    rule = _nested_str(alert, ["rule", "id"]) or _nested_str(alert, ["rule", "description"])
    return f"wazuh-{timestamp}-{agent or 'unknown-agent'}-{rule or 'unknown-rule'}"


def _alert_is_recent(alert: JsonDict, since: datetime) -> bool:
    """Return whether alert is inside the configured lookback window."""

    alert_time = _parse_wazuh_timestamp(alert.get("@timestamp") or alert.get("timestamp"))
    return alert_time >= _ensure_utc(since)


def _alert_sort_key(alert: JsonDict) -> datetime:
    """Return alert timestamp for sorting."""

    return _parse_wazuh_timestamp(alert.get("@timestamp") or alert.get("timestamp"))


def _rule_level(alert: JsonDict) -> int:
    """Return Wazuh rule.level as an integer."""

    value: Any = alert
    for key in ["rule", "level"]:
        if not isinstance(value, dict):
            return 0
        value = value.get(key)

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_wazuh_timestamp(value: Any) -> datetime:
    """Parse Wazuh timestamp into timezone-aware UTC datetime."""

    if isinstance(value, datetime):
        return _ensure_utc(value)

    if isinstance(value, str) and value.strip():
        normalized = value.strip().replace("Z", "+00:00")
        try:
            return _ensure_utc(datetime.fromisoformat(normalized))
        except ValueError:
            return utc_now()

    return utc_now()


def _ensure_utc(value: datetime) -> datetime:
    """Return datetime as timezone-aware UTC."""

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _nested_str(payload: JsonDict, path: list[str]) -> str | None:
    """Return nested string value if present."""

    value: Any = payload
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)

    if value is None:
        return None

    text = str(value).strip()
    return text or None


def _extract_wazuh_items(response: JsonDict) -> list[JsonDict]:
    """Extract affected_items from Wazuh Manager responses."""

    data = response.get("data")
    if isinstance(data, dict):
        affected_items = data.get("affected_items")
        if isinstance(affected_items, list):
            return [item for item in affected_items if isinstance(item, dict)]

    affected_items = response.get("affected_items")
    if isinstance(affected_items, list):
        return [item for item in affected_items if isinstance(item, dict)]

    return []


def _build_url(base_url: str, path: str, *, query: dict[str, str] | None = None) -> str:
    """Build URL from base, path, and query."""

    normalized_base = base_url.rstrip("/")
    normalized_path = path if path.startswith("/") else f"/{path}"
    url = f"{normalized_base}{normalized_path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    return url


def _build_ssl_context(verify_tls: bool) -> ssl.SSLContext | None:
    """Return SSL context for urllib requests."""

    if verify_tls:
        return None
    return ssl._create_unverified_context()  # noqa: S323


def _json_request(
    method: str,
    url: str,
    *,
    body: JsonDict | None,
    headers: dict[str, str],
    timeout_seconds: int,
    ssl_context: ssl.SSLContext | None,
) -> JsonDict:
    """Send request and parse JSON response."""

    text = _text_request(
        method,
        url,
        body=body,
        headers={"Accept": "application/json", **headers},
        timeout_seconds=timeout_seconds,
        ssl_context=ssl_context,
    )

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise WazuhRequestError(f"Wazuh returned malformed JSON from {url}: {exc}") from exc

    if not isinstance(parsed, dict):
        raise WazuhRequestError(f"Wazuh returned non-object JSON from {url}")

    return parsed


def _text_request(
    method: str,
    url: str,
    *,
    body: JsonDict | None = None,
    headers: dict[str, str] | None = None,
    timeout_seconds: int,
    ssl_context: ssl.SSLContext | None,
) -> str:
    """Send HTTP request and return response text."""

    data = None
    request_headers = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=request_headers, method=method.upper())

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds, context=ssl_context) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        message = _read_http_error(exc)
        if exc.code in {401, 403}:
            raise WazuhAuthError(f"Wazuh authentication failed for {url}: {message}") from exc
        raise WazuhRequestError(f"Wazuh request failed for {url}: HTTP {exc.code}: {message}") from exc
    except urllib.error.URLError as exc:
        raise WazuhRequestError(f"Wazuh request failed for {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise WazuhRequestError(f"Wazuh request timed out for {url}") from exc


def _read_http_error(exc: urllib.error.HTTPError) -> str:
    """Read HTTP error body safely."""

    try:
        body = exc.read().decode("utf-8")
    except Exception:
        return str(exc)
    return body or str(exc)