
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

`WAZUH_ALERT_SOURCE` selects which of the two retrieval paths `WazuhClient`
carries, and exactly one is ever built:

- `json_logs` builds a `WazuhAlertJsonReader` over alerts.json. Unchanged.
- `indexer` builds a `soc.wazuh_indexer_client.WazuhIndexerClient` against the
  Wazuh Indexer (OpenSearch). Selecting it without indexer settings raises,
  because a silent downgrade to "no alerts" is indistinguishable from a quiet
  network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from soc.models import EventSource, RawEvent, utc_now
from soc.store import IngestCursor
from soc.wazuh_indexer_client import (
    INDEXER_ALERT_SOURCE,
    PASSWORD_SETTING,
    URL_SETTING,
    USER_SETTING,
    WazuhIndexerClient,
    WazuhIndexerError,
)

if TYPE_CHECKING:
    from soc.config import Settings


logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

JSON_LOGS_ALERT_SOURCE = "json_logs"
"""Value of WAZUH_ALERT_SOURCE that selects the alerts.json reader."""

WAZUH_ALERT_CURSOR_SOURCE = "wazuh_alerts_json"
"""Logical ingestion source name used for alerts.json read cursors."""

FINGERPRINT_BYTES = 256
"""Leading bytes sampled to detect a log file rewritten in place."""


class IngestCursorStore(Protocol):
    """Minimal persistence contract the alerts.json reader needs for cursors.

    `soc.store.SQLiteStore` satisfies this protocol. Tests may substitute any
    object with the same two methods.
    """

    def get_ingest_cursor(self, source: str, path: str) -> IngestCursor | None:
        """Return the stored cursor for one source and path, if any."""

    def upsert_ingest_cursor(self, cursor: IngestCursor) -> None:
        """Insert or update the stored cursor for one source and path."""


class WazuhError(RuntimeError):
    """Base error for Wazuh client failures."""


class WazuhAuthError(WazuhError):
    """Raised when Wazuh authentication fails."""


class WazuhRequestError(WazuhError):
    """Raised when a Wazuh request fails."""


@dataclass(frozen=True, slots=True)
class WazuhManagerConfig:
    """Configuration for the Wazuh Manager API.

    Attributes:
        url: Wazuh Manager base URL, usually https://<manager>:55000.
        username: API username.
        password: API password.
        verify_tls: Whether to verify the Manager TLS certificate.
        timeout_seconds: HTTP timeout in seconds.
        max_retries: Retry attempts after the first request for transient
            failures: connection errors, timeouts, HTTP 429, and HTTP 5xx.
        retry_backoff_seconds: Base delay for exponential backoff between
            retries. Attempt N waits base * 2 ** N seconds.
    """

    url: str
    username: str
    password: str
    verify_tls: bool = True
    timeout_seconds: int = 20
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0

    def __post_init__(self) -> None:
        """Validate config."""

        if not self.url:
            raise WazuhError("Wazuh manager URL cannot be empty")
        if not self.username:
            raise WazuhError("Wazuh manager username cannot be empty")
        if not self.password:
            raise WazuhError("Wazuh manager password cannot be empty")
        if self.max_retries < 0:
            raise WazuhError("Wazuh manager max_retries cannot be negative")
        if self.retry_backoff_seconds < 0:
            raise WazuhError("Wazuh manager retry_backoff_seconds cannot be negative")


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

    def __init__(
        self,
        config: WazuhManagerConfig,
        *,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Initialize manager client.

        Inputs:
            config: Wazuh Manager connection and retry configuration.
            sleep: Optional sleep callable used for retry backoff. Defaults to
                time.sleep; tests inject a recorder so no real time passes.

        Outputs:
            None.
        """

        self.config = config
        self._token: str | None = None
        self._sleep = sleep
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
        """Send an authenticated request to Wazuh Manager, retrying transients.

        Transient failures (connection errors, timeouts, HTTP 429, HTTP 5xx) are
        retried up to config.max_retries times with exponential backoff. Other
        failures, including every 4xx except 429, are raised immediately.
        Authentication failures are handled by the single re-authentication path
        in _request_once and are never retried here.

        Inputs:
            method: HTTP method.
            path: API path beginning with a slash.
            query: Optional query parameters.
            body: Optional JSON request body.
            retry_auth: Whether to re-authenticate once on 401/403.

        Outputs:
            Parsed JSON response object.

        Raises:
            WazuhAuthError: If authentication fails.
            WazuhRequestError: If the request keeps failing.
        """

        attempts = self.config.max_retries + 1
        last_error: WazuhError | None = None

        for attempt in range(attempts):
            try:
                return self._request_once(method, path, query=query, body=body, retry_auth=retry_auth)
            except WazuhError as exc:
                last_error = exc
                if attempt >= attempts - 1 or not _is_retryable_error(exc):
                    raise
                delay = self.config.retry_backoff_seconds * (2**attempt)
                logger.warning(
                    "Retrying Wazuh request %s %s in %.2fs after transient failure: %s",
                    method,
                    path,
                    delay,
                    exc,
                )
                self._sleep_for(delay)

        raise WazuhRequestError(f"Wazuh request failed after {attempts} attempt(s): {last_error}")

    def _request_once(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        body: JsonDict | None = None,
        retry_auth: bool = True,
    ) -> JsonDict:
        """Send one authenticated request, re-authenticating once on 401/403."""

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

    def _sleep_for(self, seconds: float) -> None:
        """Sleep between retries using the injected or default sleeper.

        Inputs:
            seconds: Delay in seconds.

        Outputs:
            None.
        """

        if self._sleep is not None:
            self._sleep(seconds)
            return
        time.sleep(seconds)

    def _request_token(self) -> str:
        """Request a raw JWT token from Wazuh Manager."""

        credentials = f"{self.config.username}:{self.config.password}".encode()
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

    def __init__(
        self,
        config: WazuhAlertJsonConfig,
        *,
        cursor_store: IngestCursorStore | None = None,
        cursor_source: str = WAZUH_ALERT_CURSOR_SOURCE,
    ) -> None:
        """Initialize alerts.json reader.

        Inputs:
            config: alerts.json location and filter configuration.
            cursor_store: Optional cursor persistence. When supplied, each read
                resumes from the stored byte offset instead of re-reading the
                whole file, which is what an unattended polling loop needs.
                When omitted, every read scans the whole file.
            cursor_source: Logical source name used to key the stored cursor.

        Outputs:
            None.
        """

        self.config = config
        self.cursor_store = cursor_store
        self.cursor_source = cursor_source
        self.last_malformed_line_count = 0

    def read_recent_alerts(self) -> list[JsonDict]:
        """Read, parse, filter, and limit recent Wazuh alerts.

        Wazuh appends to alerts.json continuously, so a truncated or partially
        written line is expected. Malformed lines are skipped, counted in
        last_malformed_line_count, and reported once as a logged warning.

        With a cursor store the read starts at the persisted byte offset and the
        offset advances past every newline-terminated line consumed, so a
        partially written final line is re-read on the next call. Rotation and
        truncation reset the offset to zero, meaning the whole current file is
        read. Without a cursor store the whole file is read every time.

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
        file_stat = self.config.path.stat()
        start_offset = self._start_offset(file_stat)
        offset = start_offset
        alerts: list[JsonDict] = []

        with self.config.path.open("rb") as handle:
            if start_offset:
                handle.seek(start_offset)

            for raw_line in handle:
                if raw_line.endswith(b"\n"):
                    offset += len(raw_line)

                stripped = raw_line.decode("utf-8", errors="replace").strip()
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

        self._save_offset(offset, file_stat)

        if self.last_malformed_line_count:
            logger.warning(
                "Skipped %d malformed JSON line(s) in Wazuh alert file %s",
                self.last_malformed_line_count,
                self.config.path,
            )

        alerts.sort(key=_alert_sort_key)
        return alerts[-self.config.limit :]

    def _start_offset(self, file_stat: os.stat_result) -> int:
        """Return the byte offset this read should start from.

        A stored cursor is only trusted when it still describes the same file.
        A changed device/inode identity means the path was rotated to a new file,
        and a file smaller than the stored offset means it was truncated. Both
        cases reset the offset to zero so no alert is silently skipped.

        Inputs:
            file_stat: Stat result for the configured alerts.json path.

        Outputs:
            Byte offset to seek to, zero when the whole file should be read.
        """

        if self.cursor_store is None:
            return 0

        cursor = self.cursor_store.get_ingest_cursor(self.cursor_source, str(self.config.path))
        if cursor is None:
            return 0

        current_identity = _file_identity(file_stat)
        if cursor.file_identity is not None and cursor.file_identity != current_identity:
            logger.warning(
                "Wazuh alert file %s is a different file than the cursor describes "
                "(%s -> %s); reading from the start",
                self.config.path,
                cursor.file_identity,
                current_identity,
            )
            return 0

        if file_stat.st_size < cursor.byte_offset:
            logger.warning(
                "Wazuh alert file %s was truncated (size %d < offset %d); reading from the start",
                self.config.path,
                file_stat.st_size,
                cursor.byte_offset,
            )
            return 0

        if cursor.content_fingerprint and not self._fingerprint_matches(cursor.content_fingerprint):
            logger.warning(
                "Wazuh alert file %s was rewritten in place; reading from the start",
                self.config.path,
            )
            return 0

        return cursor.byte_offset

    def _fingerprint_matches(self, stored: str) -> bool:
        """Return whether the file still starts with the fingerprinted bytes.

        A truncate-and-refill rotation can leave both the inode and the file size
        unchanged, so neither can detect it. Re-hashing the same leading window
        can. The stored window length is used rather than the current one, so a
        file that has merely grown past the window still matches.

        Inputs:
            stored: Fingerprint string of the form "<length>:<sha256 hex>".

        Outputs:
            True when the leading bytes are unchanged, False otherwise.
        """

        length_text, _, digest = stored.partition(":")
        if not digest:
            return True

        try:
            length = int(length_text)
        except ValueError:
            return True

        return _fingerprint_head(self.config.path, length) == stored

    @staticmethod
    def _build_fingerprint(path: Path) -> str | None:
        """Build a fingerprint of a file's leading bytes.

        Inputs:
            path: File to fingerprint.

        Outputs:
            Fingerprint string, or None when the file cannot be read.
        """

        return _fingerprint_head(path, FINGERPRINT_BYTES)

    def _save_offset(self, offset: int, file_stat: os.stat_result) -> None:
        """Persist the read position reached by this read.

        Inputs:
            offset: Byte offset just past the last fully consumed line.
            file_stat: Stat result taken before the read started.

        Outputs:
            None. Nothing is persisted when no cursor store is configured.
        """

        if self.cursor_store is None:
            return

        self.cursor_store.upsert_ingest_cursor(
            IngestCursor(
                source=self.cursor_source,
                path=str(self.config.path),
                byte_offset=offset,
                file_identity=_file_identity(file_stat),
                content_fingerprint=self._build_fingerprint(self.config.path),
                updated_at=utc_now(),
            )
        )

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
    """Facade for Wazuh ingestion into SOC RawEvent objects.

    Exactly one retrieval path is carried: an alerts.json reader or a Wazuh
    Indexer client. The Manager API half is optional either way and only supplies
    agent inventory context.
    """

    def __init__(
        self,
        *,
        manager: WazuhManagerClient | None = None,
        alert_reader: WazuhAlertJsonReader | None = None,
        indexer: WazuhIndexerClient | None = None,
    ) -> None:
        """Initialize facade client.

        Inputs:
            manager: Optional Manager API client used only for agent inventory.
            alert_reader: alerts.json reader, for the json_logs source.
            indexer: Wazuh Indexer client, for the indexer source.

        Outputs:
            None.

        Raises:
            WazuhError: If neither or both retrieval paths are supplied. Both
                would make it ambiguous which one produced a given event, and the
                event IDs of the two paths differ deliberately.
        """

        if alert_reader is None and indexer is None:
            raise WazuhError("WazuhClient requires either an alert_reader or an indexer")
        if alert_reader is not None and indexer is not None:
            raise WazuhError("WazuhClient accepts an alert_reader or an indexer, not both")

        self.manager = manager
        self.alert_reader = alert_reader
        self.indexer = indexer

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        cursor_store: IngestCursorStore | None = None,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> WazuhClient:
        """Build a Wazuh client for the configured alert source.

        Inputs:
            settings: Application settings object.
            cursor_store: Optional ingestion cursor persistence, used only by the
                json_logs source. Supply it for unattended polling so each cycle
                reads only new alert lines; omit it for one-shot CLI runs, which
                read the whole file.
            opener: Optional HTTP opener passed to the indexer client, so tests
                never touch the network. Ignored by the json_logs source.
            sleep: Optional sleep callable passed to the indexer client, so tests
                never wait on retry backoff. Ignored by the json_logs source.

        Outputs:
            WazuhClient instance.

        Raises:
            WazuhError: If WAZUH_ALERT_SOURCE is unknown, or is `indexer` while
                the indexer settings are missing. The second case fails loudly
                rather than yielding zero events, which would be indistinguishable
                from a quiet environment.
        """

        source = str(settings.wazuh_alert_source or "").strip()
        if source not in {JSON_LOGS_ALERT_SOURCE, INDEXER_ALERT_SOURCE}:
            raise WazuhError(
                f"Unsupported WAZUH_ALERT_SOURCE={source or '(empty)'}. Supported values: "
                f"{JSON_LOGS_ALERT_SOURCE}, {INDEXER_ALERT_SOURCE}"
            )

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

        if source == INDEXER_ALERT_SOURCE:
            return cls(
                manager=manager,
                indexer=_build_indexer_client(settings, opener=opener, sleep=sleep),
            )

        alert_reader = WazuhAlertJsonReader(
            WazuhAlertJsonConfig(
                path=settings.wazuh_alert_json_path,
                lookback_minutes=settings.wazuh_alert_lookback_minutes,
                min_level=settings.wazuh_min_level,
                limit=settings.wazuh_alert_limit,
            ),
            cursor_store=cursor_store,
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
        compatibility with run_pipeline.py. The configured retrieval path already
        has these values from settings, so this method does not need to rebuild it.

        Inputs:
            lookback_minutes: Accepted and ignored.
            min_level: Accepted and ignored.
            limit: Accepted and ignored.
            include_agent_inventory: Whether to enrich payloads with Manager
                agent context. Requires Manager credentials; without them the
                inventory is empty and ingestion still works.

        Outputs:
            RawEvent objects ready for SOCPipeline.run_events(). Their IDs differ
            per retrieval path, so the same alert read from the Indexer and from
            alerts.json does not overwrite one audit row.

        Raises:
            WazuhRequestError: If the alerts.json path is unusable.
            WazuhIndexerError: If an Indexer search fails.
        """

        _ = lookback_minutes, min_level, limit
        agent_inventory = self.fetch_agent_inventory() if include_agent_inventory else {}
        if self.indexer is not None:
            return self.indexer.fetch_recent_events(agent_inventory=agent_inventory)
        if self.alert_reader is not None:
            return self.alert_reader.fetch_recent_events(agent_inventory=agent_inventory)
        raise WazuhError("WazuhClient has no configured retrieval path")


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


def _build_indexer_client(
    settings: Settings,
    *,
    opener: Callable[..., Any] | None,
    sleep: Callable[[float], None] | None,
) -> WazuhIndexerClient:
    """Build the Wazuh Indexer client for WAZUH_ALERT_SOURCE=indexer.

    A missing or unusable indexer configuration is re-raised as a WazuhError, so
    every failure of `WazuhClient.from_settings` stays inside this module's error
    hierarchy, and the message names both the settings to populate and the
    alternative source. Returning an empty client instead would report "no
    alerts" for a deployment that is simply not configured.

    Inputs:
        settings: Application settings object.
        opener: Optional HTTP opener forwarded to the indexer client.
        sleep: Optional sleep callable forwarded to the indexer client.

    Outputs:
        WazuhIndexerClient instance.

    Raises:
        WazuhError: If the indexer settings are missing or unusable.
    """

    try:
        return WazuhIndexerClient.from_settings(settings, opener=opener, sleep=sleep)
    except WazuhIndexerError as exc:
        raise WazuhError(
            f"WAZUH_ALERT_SOURCE={INDEXER_ALERT_SOURCE} needs {URL_SETTING}, "
            f"{USER_SETTING} and {PASSWORD_SETTING} to be set; "
            f"set them, or use WAZUH_ALERT_SOURCE=json_logs to read alerts.json instead. "
            f"({exc})"
        ) from exc


def _has_manager_settings(settings: Settings) -> bool:
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
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


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
    return ssl._create_unverified_context()


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
        raise WazuhRequestError(f"Wazuh network error for {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise WazuhRequestError(f"Wazuh request timed out for {url}") from exc


def _is_retryable_error(exc: WazuhError) -> bool:
    """Return whether a Wazuh failure is transient and worth retrying.

    Retryable: connection errors, timeouts, HTTP 429, and HTTP 5xx. Every other
    4xx is a client error that a retry cannot fix, and authentication failures
    are handled by the separate single re-authentication path.

    Inputs:
        exc: WazuhError instance.

    Outputs:
        Boolean retry flag.
    """

    if isinstance(exc, WazuhAuthError):
        return False

    message = str(exc).lower()
    retryable_markers = (
        "http 408",
        "http 425",
        "http 429",
        "http 500",
        "http 502",
        "http 503",
        "http 504",
        "network error",
        "timed out",
    )
    return any(marker in message for marker in retryable_markers)


def _read_http_error(exc: urllib.error.HTTPError) -> str:
    """Read HTTP error body safely."""

    try:
        body = exc.read().decode("utf-8")
    except Exception:
        return str(exc)
    return body or str(exc)


def _fingerprint_head(path: Path, length: int) -> str | None:
    """Fingerprint the first `length` bytes of a file.

    Inputs:
        path: File to read.
        length: Number of leading bytes to sample.

    Outputs:
        String of the form "<bytes read>:<sha256 hex>", or None on read failure.
    """

    if length <= 0:
        return None

    try:
        with path.open("rb") as handle:
            head = handle.read(length)
    except OSError:
        return None

    if not head:
        return None

    return f"{len(head)}:{hashlib.sha256(head).hexdigest()}"


def _file_identity(file_stat: os.stat_result) -> str:
    """Build an opaque identity token for a file from its stat result.

    Device and inode are combined into one hyphenated string rather than stored
    as two integers. Windows file IDs are 128-bit and overflow SQLite's 64-bit
    INTEGER, and a numeric-looking string in a column with INTEGER affinity gets
    silently converted to a float, losing precision and quietly breaking
    rotation detection. A hyphenated token is never numeric, so it survives
    intact. Only equality is ever needed.

    Inputs:
        file_stat: Stat result for the file.

    Outputs:
        Identity string of the form "<device>-<inode>".
    """

    return f"{file_stat.st_dev}-{file_stat.st_ino}"
