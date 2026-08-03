"""Security Onion Connect API client.

This module retrieves Security Onion event documents over the Security Onion
**Connect API** and converts them into RawEvent objects for
SOCPipeline.run_events(). Normalization of those events already lives in
soc.normalizer.normalize_security_onion_event; this module only handles
authentication, retrieval, and RawEvent construction.

API surface, confirmed against the official Security Onion Connect API docs:
- OAuth2 client credentials: POST <host>/oauth2/token with HTTP Basic auth
  (client ID and client secret) and the form body grant_type=client_credentials.
- Token response fields: access_token, expires_in, scope, token_type. Tokens are
  valid for roughly two hours by default.
- Every subsequent request carries the header Authorization: Bearer <token>.
- Event query endpoint: GET <host>/connect/query/data with a `query` parameter
  holding an Elasticsearch-like query, for example `_index:"*:so-case"`.
- Optional `gridId` parameter, needed only for Manager-of-Managers deployments.
- Connectivity check: GET <host>/connect/info.
- Reading events requires the `events/read` permission scope on the client.

NOT CONFIRMED — inferred parameter names, change them in ONE place
--------------------------------------------------------------------
The parameter names for the time range, result limit, timezone, and date format
on /connect/query/data are **not published**. Sibling endpoints in the same API
use `range`, `zone`, and `format`, so those names are used here as *defaults*
and the limit parameter is guessed as `eventLimit`. They are configuration
fields, never hardcoded at a call site:

    SecurityOnionConfig.range_param   (default "range")     INFERRED
    SecurityOnionConfig.zone_param    (default "zone")      INFERRED
    SecurityOnionConfig.format_param  (default "format")    INFERRED
    SecurityOnionConfig.limit_param   (default "eventLimit") INFERRED
    SecurityOnionConfig.zone          (default "UTC")        INFERRED value
    SecurityOnionConfig.date_format   (default Connect UI style) INFERRED value
    SecurityOnionConfig.range_separator / range_datetime_format INFERRED values
    SecurityOnionConfig.query         (default `_index:"*:so-*"`) deployment
        specific; only the *form* of the filter is confirmed.

Anyone testing against a real grid corrects those defaults in
SecurityOnionConfig and nowhere else.

The shape of a returned event document is likewise undocumented, and Security
Onion proxies Elasticsearch, so extract_event_documents() accepts several known
shapes and returns an empty list (with a warning naming the received top-level
keys) for anything it does not recognize.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from soc.models import AlertSeverity, EventSource, RawEvent, utc_now
from soc.normalizer import severity_from_security_onion

if TYPE_CHECKING:
    from soc.config import Settings


logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

TOKEN_PATH = "/oauth2/token"
"""CONFIRMED. OAuth2 client-credentials token endpoint."""

QUERY_PATH = "/connect/query/data"
"""CONFIRMED. Event query endpoint."""

INFO_PATH = "/connect/info"
"""CONFIRMED. Connectivity and version endpoint."""

QUERY_PARAM = "query"
"""CONFIRMED. Name of the Elasticsearch-like query parameter."""

GRID_ID_PARAM = "gridId"
"""CONFIRMED. Optional Manager-of-Managers grid selector."""

DEFAULT_QUERY = '_index:"*:so-*"'
"""Default event filter. The *form* is confirmed, the index pattern is not."""

TOKEN_REFRESH_SKEW_SECONDS = 60
"""Refresh a cached token this many seconds before it actually expires."""


class SecurityOnionError(RuntimeError):
    """Base error for Security Onion client failures."""


class SecurityOnionAuthError(SecurityOnionError):
    """Raised when Security Onion authentication fails."""


class SecurityOnionRequestError(SecurityOnionError):
    """Raised when a Security Onion request fails."""


@dataclass(frozen=True, slots=True)
class SecurityOnionConfig:
    """Configuration for the Security Onion Connect API.

    Attributes:
        host: Connect API base URL, for example https://securityonion.example.
        client_id: OAuth2 client ID used for HTTP Basic auth on the token call.
        client_secret: OAuth2 client secret used for the same call.
        verify_tls: Whether to verify the Security Onion TLS certificate.
        timeout_seconds: HTTP timeout in seconds.
        max_retries: Retry attempts after the first request for transient
            failures: connection errors, timeouts, HTTP 429, and HTTP 5xx.
        retry_backoff_seconds: Base delay for exponential backoff between
            retries. Attempt N waits base * 2 ** N seconds.
        min_severity: Minimum Security Onion / Suricata severity to keep.
            Suricata numbers run *downwards* (1 is the most severe), so this is
            compared through soc.normalizer.severity_from_security_onion rather
            than numerically: a document is kept when its normalized severity is
            at least as high as the normalized severity of this value.
        lookback_minutes: Size of the query time window.
        limit: Maximum number of events kept per fetch.
        grid_id: Optional grid ID, only needed for Manager-of-Managers.
        query: Elasticsearch-like event filter. INFERRED index pattern.
        range_param: INFERRED name of the time-range parameter.
        zone_param: INFERRED name of the timezone parameter.
        format_param: INFERRED name of the date-format parameter.
        limit_param: INFERRED name of the result-limit parameter.
        zone: INFERRED timezone value sent with zone_param.
        date_format: INFERRED date-format value sent with format_param.
        range_datetime_format: INFERRED strftime pattern used to render the two
            endpoints of the time range.
        range_separator: INFERRED separator between the range endpoints.
    """

    host: str
    client_id: str
    client_secret: str
    verify_tls: bool = True
    timeout_seconds: int = 20
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0
    min_severity: int = 2
    lookback_minutes: int = 60
    limit: int = 100
    grid_id: str | None = None
    query: str = DEFAULT_QUERY

    # --- Inferred parameter names and values. See the module docstring. ---
    range_param: str = "range"
    zone_param: str = "zone"
    format_param: str = "format"
    limit_param: str = "eventLimit"
    zone: str = "UTC"
    date_format: str = "YYYY/MM/DD HH:mm:ss"
    range_datetime_format: str = "%Y/%m/%d %H:%M:%S"
    range_separator: str = " - "

    def __post_init__(self) -> None:
        """Validate config.

        Inputs:
            None. Reads the dataclass fields.

        Outputs:
            None.

        Raises:
            SecurityOnionError: If any field is empty, negative, or zero where a
                positive value is required.
        """

        if not self.host.strip():
            raise SecurityOnionError("Security Onion host cannot be empty")
        if not self.client_id.strip():
            raise SecurityOnionError("Security Onion client_id cannot be empty")
        if not self.client_secret.strip():
            raise SecurityOnionError("Security Onion client_secret cannot be empty")
        if self.timeout_seconds <= 0:
            raise SecurityOnionError("Security Onion timeout_seconds must be greater than zero")
        if self.max_retries < 0:
            raise SecurityOnionError("Security Onion max_retries cannot be negative")
        if self.retry_backoff_seconds < 0:
            raise SecurityOnionError("Security Onion retry_backoff_seconds cannot be negative")
        if self.min_severity < 0:
            raise SecurityOnionError("Security Onion min_severity cannot be negative")
        if self.lookback_minutes <= 0:
            raise SecurityOnionError("Security Onion lookback must be greater than zero")
        if self.limit <= 0:
            raise SecurityOnionError("Security Onion limit must be greater than zero")
        if not self.query.strip():
            raise SecurityOnionError("Security Onion query cannot be empty")

        for name, value in (
            ("range_param", self.range_param),
            ("zone_param", self.zone_param),
            ("format_param", self.format_param),
            ("limit_param", self.limit_param),
        ):
            if not value.strip():
                raise SecurityOnionError(f"Security Onion {name} parameter name cannot be empty")

    @property
    def base_url(self) -> str:
        """Return the Connect API base URL without a trailing slash.

        Inputs:
            None.

        Outputs:
            Normalized base URL string.
        """

        return self.host.rstrip("/")


class SecurityOnionClient:
    """Client for the Security Onion Connect API."""

    def __init__(
        self,
        config: SecurityOnionConfig,
        *,
        sleep: Callable[[float], None] | None = None,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        """Initialize Connect API client.

        Inputs:
            config: Connection, retry, and query configuration.
            sleep: Optional sleep callable used for retry backoff. Defaults to
                time.sleep; tests inject a recorder so no real time passes.
            opener: Optional urlopen-compatible callable invoked as
                opener(request, timeout=..., context=...). Defaults to
                urllib.request.urlopen; tests inject a fake so no network is
                touched.

        Outputs:
            None.
        """

        self.config = config
        self._sleep = sleep
        self._opener = opener
        self._token: str | None = None
        self._token_expires_at: datetime | None = None
        self._ssl_context = _build_ssl_context(config.verify_tls)

    @classmethod
    def from_settings(cls, settings: "Settings") -> "SecurityOnionClient":
        """Build a Connect API client from application settings.

        Optional attributes are read with getattr defaults so a Settings object
        that predates the Security Onion config keys still works.

        Inputs:
            settings: Application settings object exposing at least
                securityonion_host, securityonion_client_id, and
                securityonion_client_secret.

        Outputs:
            SecurityOnionClient instance.

        Raises:
            SecurityOnionError: If the host or the OAuth2 client credentials are
                missing.
        """

        host = str(getattr(settings, "securityonion_host", "") or "").strip()
        client_id = str(getattr(settings, "securityonion_client_id", "") or "").strip()
        client_secret = str(getattr(settings, "securityonion_client_secret", "") or "").strip()

        if not host:
            raise SecurityOnionError(
                "Security Onion ingestion requires SECURITYONION_HOST "
                "(the Connect API base URL, for example https://securityonion.example)"
            )
        if not client_id:
            raise SecurityOnionError(
                "Security Onion ingestion requires SECURITYONION_CLIENT_ID "
                "(an OAuth2 client with the events/read scope)"
            )
        if not client_secret:
            raise SecurityOnionError(
                "Security Onion ingestion requires SECURITYONION_CLIENT_SECRET "
                "for the configured OAuth2 client"
            )

        grid_id = str(getattr(settings, "securityonion_grid_id", "") or "").strip()

        config = SecurityOnionConfig(
            host=host,
            client_id=client_id,
            client_secret=client_secret,
            verify_tls=bool(getattr(settings, "securityonion_verify_tls", True)),
            min_severity=int(getattr(settings, "so_min_severity", 2)),
            lookback_minutes=int(getattr(settings, "securityonion_lookback_minutes", 60)),
            limit=int(getattr(settings, "securityonion_alert_limit", 100)),
            grid_id=grid_id or None,
        )
        return cls(config)

    @property
    def token(self) -> str | None:
        """Return the cached bearer token, if any.

        Inputs:
            None.

        Outputs:
            Cached access token or None.
        """

        return self._token

    @property
    def token_expires_at(self) -> datetime | None:
        """Return the cached token expiry timestamp, if any.

        Inputs:
            None.

        Outputs:
            Timezone-aware expiry datetime or None.
        """

        return self._token_expires_at

    def authenticate(self) -> str:
        """Obtain and cache an OAuth2 client-credentials bearer token.

        Inputs:
            None. Uses the configured client ID and secret.

        Outputs:
            The access token string.

        Raises:
            SecurityOnionAuthError: If the token endpoint rejects the
                credentials or returns no access_token.
            SecurityOnionRequestError: If the token request fails.
        """

        credentials = f"{self.config.client_id}:{self.config.client_secret}".encode("utf-8")
        encoded_credentials = base64.b64encode(credentials).decode("ascii")
        headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        response = _json_request(
            "POST",
            _build_url(self.config.base_url, TOKEN_PATH),
            data=urllib.parse.urlencode({"grant_type": "client_credentials"}).encode("utf-8"),
            headers=headers,
            timeout_seconds=self.config.timeout_seconds,
            ssl_context=self._ssl_context,
            opener=self._opener,
        )

        token = str(response.get("access_token") or "").strip()
        if not token:
            raise SecurityOnionAuthError(
                "Security Onion token response did not contain an access_token"
            )

        self._token = token
        self._token_expires_at = _expiry_from_expires_in(response.get("expires_in"))
        return token

    def get_info(self) -> JsonDict:
        """Return Connect API info, used as a connectivity check.

        Inputs:
            None.

        Outputs:
            Parsed JSON info object.

        Raises:
            SecurityOnionAuthError: If authentication fails.
            SecurityOnionRequestError: If the request keeps failing.
        """

        return self.request("GET", INFO_PATH)

    def fetch_recent_alerts(
        self,
        *,
        query: str | None = None,
        lookback_minutes: int | None = None,
        min_severity: int | None = None,
        limit: int | None = None,
    ) -> list[JsonDict]:
        """Query the Connect API and return recent event documents.

        Only the `query` and `gridId` parameter names are documented; the
        time-range, timezone, date-format, and limit parameter names come from
        the config fields described in the module docstring. Documents are then
        filtered locally by lookback window and severity, so a grid that ignores
        the inferred parameters still yields correctly filtered results.

        Inputs:
            query: Optional Elasticsearch-like filter overriding config.query.
            lookback_minutes: Optional window overriding config.lookback_minutes.
            min_severity: Optional minimum severity overriding config.min_severity.
            limit: Optional cap overriding config.limit.

        Outputs:
            Event documents sorted oldest to newest, capped at the limit.

        Raises:
            SecurityOnionAuthError: If authentication fails.
            SecurityOnionRequestError: If the query keeps failing.
        """

        window_minutes = lookback_minutes if lookback_minutes is not None else self.config.lookback_minutes
        severity_floor = min_severity if min_severity is not None else self.config.min_severity
        max_events = limit if limit is not None else self.config.limit
        since = utc_now() - timedelta(minutes=window_minutes)

        response = self.request(
            "GET",
            QUERY_PATH,
            query=self._build_query_params(
                query=query or self.config.query,
                since=since,
                limit=max_events,
            ),
        )

        documents = [
            document
            for document in extract_event_documents(response)
            if _document_is_recent(document, since) and _document_meets_severity(document, severity_floor)
        ]
        documents.sort(key=_document_sort_key)
        return documents[-max_events:]

    def fetch_recent_events(
        self,
        *,
        query: str | None = None,
        lookback_minutes: int | None = None,
        min_severity: int | None = None,
        limit: int | None = None,
    ) -> list[RawEvent]:
        """Fetch recent Security Onion events as RawEvent objects.

        Inputs:
            query: Optional Elasticsearch-like filter overriding config.query.
            lookback_minutes: Optional window overriding config.lookback_minutes.
            min_severity: Optional minimum severity overriding config.min_severity.
            limit: Optional cap overriding config.limit.

        Outputs:
            RawEvent objects ready for SOCPipeline.run_events().

        Raises:
            SecurityOnionAuthError: If authentication fails.
            SecurityOnionRequestError: If the query keeps failing.
        """

        documents = self.fetch_recent_alerts(
            query=query,
            lookback_minutes=lookback_minutes,
            min_severity=min_severity,
            limit=limit,
        )
        return [raw_event_from_security_onion_document(document) for document in documents]

    def _build_query_params(self, *, query: str, since: datetime, limit: int) -> dict[str, str]:
        """Build the /connect/query/data query parameters.

        Every inferred parameter name is read from the config, so a deployment
        that uses different names only needs its SecurityOnionConfig corrected.

        Inputs:
            query: Elasticsearch-like event filter.
            since: Start of the requested time window.
            limit: Maximum number of events requested.

        Outputs:
            Query parameter mapping.
        """

        config = self.config
        start = since.strftime(config.range_datetime_format)
        end = utc_now().strftime(config.range_datetime_format)

        params = {
            QUERY_PARAM: query,
            config.range_param: f"{start}{config.range_separator}{end}",
            config.zone_param: config.zone,
            config.format_param: config.date_format,
            config.limit_param: str(limit),
        }
        if config.grid_id:
            params[GRID_ID_PARAM] = config.grid_id
        return params

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        retry_auth: bool = True,
    ) -> JsonDict:
        """Send an authenticated Connect API request, retrying transients.

        Transient failures (connection errors, timeouts, HTTP 429, HTTP 5xx) are
        retried up to config.max_retries times with exponential backoff. Other
        failures, including every 4xx except 429, are raised immediately.
        Authentication failures are handled by the single re-authentication path
        in _request_once and are never retried here, so a persistent 401 cannot
        become a retry loop.

        Inputs:
            method: HTTP method.
            path: API path beginning with a slash.
            query: Optional query parameters.
            retry_auth: Whether to re-authenticate once on 401/403.

        Outputs:
            Parsed JSON response object.

        Raises:
            SecurityOnionAuthError: If authentication fails.
            SecurityOnionRequestError: If the request keeps failing.
        """

        attempts = self.config.max_retries + 1
        last_error: SecurityOnionError | None = None

        for attempt in range(attempts):
            try:
                return self._request_once(method, path, query=query, retry_auth=retry_auth)
            except SecurityOnionError as exc:
                last_error = exc
                if attempt >= attempts - 1 or not _is_retryable_error(exc):
                    raise
                delay = self.config.retry_backoff_seconds * (2**attempt)
                logger.warning(
                    "Retrying Security Onion request %s %s in %.2fs after transient failure: %s",
                    method,
                    path,
                    delay,
                    exc,
                )
                self._sleep_for(delay)

        raise SecurityOnionRequestError(
            f"Security Onion request failed after {attempts} attempt(s): {last_error}"
        )

    def _request_once(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        retry_auth: bool = True,
    ) -> JsonDict:
        """Send one authenticated request, re-authenticating once on 401/403.

        Inputs:
            method: HTTP method.
            path: API path beginning with a slash.
            query: Optional query parameters.
            retry_auth: Whether to re-authenticate once on 401/403.

        Outputs:
            Parsed JSON response object.

        Raises:
            SecurityOnionAuthError: If authentication fails.
            SecurityOnionRequestError: If the request fails.
        """

        self._ensure_token()
        url = _build_url(self.config.base_url, path, query=query)

        try:
            return _json_request(
                method,
                url,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout_seconds=self.config.timeout_seconds,
                ssl_context=self._ssl_context,
                opener=self._opener,
            )
        except SecurityOnionAuthError:
            if not retry_auth:
                raise

            self.authenticate()
            return _json_request(
                method,
                url,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout_seconds=self.config.timeout_seconds,
                ssl_context=self._ssl_context,
                opener=self._opener,
            )

    def _ensure_token(self) -> None:
        """Authenticate when no usable token is cached.

        A token is considered unusable when it is missing or inside the
        TOKEN_REFRESH_SKEW_SECONDS window before its expiry, so a request is
        never sent with a token that expires in flight.

        Inputs:
            None.

        Outputs:
            None.

        Raises:
            SecurityOnionAuthError: If authentication fails.
        """

        if self._token is None or self._token_is_expiring():
            self.authenticate()

    def _token_is_expiring(self) -> bool:
        """Return whether the cached token is expired or about to expire.

        Inputs:
            None.

        Outputs:
            True when the token should be refreshed, False otherwise.
        """

        if self._token_expires_at is None:
            return False
        return utc_now() >= self._token_expires_at - timedelta(seconds=TOKEN_REFRESH_SKEW_SECONDS)

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


def extract_event_documents(response: JsonDict) -> list[JsonDict]:
    """Extract event documents from a Connect API query response.

    The document envelope is not documented and Security Onion proxies
    Elasticsearch, so three shapes are accepted:
        1. {"events": [...]}
        2. {"data": {"events": [...]}}
        3. {"hits": {"hits": [{"_id": ..., "_source": {...}}]}}
    For the Elasticsearch shape the `_source` object is returned with the hit's
    own metadata keys (`_id`, `_index`, ...) merged in, so downstream ID
    derivation and normalization both see a flat document.

    An unrecognized shape returns an empty list rather than raising, and logs a
    warning naming the top-level keys actually received so a real deployment can
    be diagnosed from logs alone.

    Inputs:
        response: Parsed JSON response object.

    Outputs:
        List of event documents, empty when nothing recognizable is present.
    """

    events = response.get("events")
    if isinstance(events, list):
        return [document for document in events if isinstance(document, dict)]

    data = response.get("data")
    if isinstance(data, dict):
        nested_events = data.get("events")
        if isinstance(nested_events, list):
            return [document for document in nested_events if isinstance(document, dict)]

    hits = response.get("hits")
    if isinstance(hits, dict):
        inner_hits = hits.get("hits")
        if isinstance(inner_hits, list):
            return [
                document
                for document in (_flatten_elasticsearch_hit(hit) for hit in inner_hits)
                if document is not None
            ]

    logger.warning(
        "Unrecognized Security Onion query response shape; top-level keys: %s",
        ", ".join(sorted(str(key) for key in response)) or "(none)",
    )
    return []


def raw_event_from_security_onion_document(document: JsonDict) -> RawEvent:
    """Convert one Security Onion event document into a RawEvent.

    The whole document is preserved as the payload for auditability, and the ID
    is a deterministic function of the document content, so reprocessing the
    same event produces the same IDs downstream.

    Inputs:
        document: Security Onion event document.

    Outputs:
        RawEvent with source EventSource.SECURITY_ONION.
    """

    return RawEvent(
        id=_event_id_from_document(document),
        source=EventSource.SECURITY_ONION,
        timestamp=_parse_timestamp(_document_value(document, _TIMESTAMP_PATHS)),
        payload=dict(document),
        received_at=utc_now(),
    )


def _flatten_elasticsearch_hit(hit: Any) -> JsonDict | None:
    """Merge one Elasticsearch hit's metadata into its _source document.

    Inputs:
        hit: Candidate hit object.

    Outputs:
        Flattened document, or None when the hit is unusable.
    """

    if not isinstance(hit, dict):
        return None

    source = hit.get("_source")
    if not isinstance(source, dict):
        return None

    metadata = {key: value for key, value in hit.items() if key != "_source"}
    return {**source, **metadata}


def _event_id_from_document(document: JsonDict) -> str:
    """Return a stable, content-derived event ID for one document.

    Inputs:
        document: Security Onion event document.

    Outputs:
        Deterministic event ID string.
    """

    prefix = EventSource.SECURITY_ONION.value
    for path in ("_id", "event.id", "id", "log.id.uid", "uid"):
        value = _document_value(document, [path])
        if isinstance(value, str) and value.strip():
            return f"{prefix}-{value.strip()}"

    fingerprint = hashlib.sha256(
        json.dumps(document, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]
    return f"{prefix}-{fingerprint}"


_TIMESTAMP_PATHS = ["@timestamp", "timestamp", "event.created", "_source.@timestamp"]
"""Document paths inspected for an event timestamp, mirroring the normalizer."""

_SEVERITY_PATHS = [
    "event.severity",
    "severity",
    "suricata.alert.severity",
    "alert.severity",
    "_source.event.severity",
]
"""Document paths inspected for a severity value, mirroring the normalizer."""

_SEVERITY_RANK = {
    AlertSeverity.INFO: 0,
    AlertSeverity.LOW: 1,
    AlertSeverity.MEDIUM: 2,
    AlertSeverity.HIGH: 3,
    AlertSeverity.CRITICAL: 4,
}
"""Ordering used to compare normalized severities."""


def _document_meets_severity(document: JsonDict, min_severity: int) -> bool:
    """Return whether a document is at least as severe as the configured floor.

    Security Onion and Suricata number severity *downwards* (1 is the most
    severe), so the comparison goes through the normalizer's severity mapping
    rather than comparing raw numbers. A document whose severity cannot be
    interpreted is kept, so nothing is dropped silently.

    Inputs:
        document: Security Onion event document.
        min_severity: Minimum source severity value, in source units.

    Outputs:
        True when the document should be kept.
    """

    document_severity = severity_from_security_onion(_document_value(document, _SEVERITY_PATHS))
    if document_severity not in _SEVERITY_RANK:
        return True

    floor = severity_from_security_onion(min_severity)
    if floor not in _SEVERITY_RANK:
        return True

    return _SEVERITY_RANK[document_severity] >= _SEVERITY_RANK[floor]


def _document_is_recent(document: JsonDict, since: datetime) -> bool:
    """Return whether a document falls inside the lookback window.

    Inputs:
        document: Security Onion event document.
        since: Start of the lookback window.

    Outputs:
        True when the document timestamp is at or after `since`.
    """

    return _parse_timestamp(_document_value(document, _TIMESTAMP_PATHS)) >= _ensure_utc(since)


def _document_sort_key(document: JsonDict) -> datetime:
    """Return a document's timestamp for sorting.

    Inputs:
        document: Security Onion event document.

    Outputs:
        Timezone-aware timestamp.
    """

    return _parse_timestamp(_document_value(document, _TIMESTAMP_PATHS))


def _document_value(document: JsonDict, paths: list[str]) -> Any:
    """Return the first present value from dot-separated document paths.

    Flattened keys such as `event.severity` are supported as well as nested
    objects, because Security Onion documents appear in both forms.

    Inputs:
        document: Security Onion event document.
        paths: Candidate dot-separated paths.

    Outputs:
        First non-empty value, or None.
    """

    for path in paths:
        if path in document and document[path] not in (None, ""):
            return document[path]

        value: Any = document
        for key in path.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if value is not None and value != "":
            return value

    return None


def _parse_timestamp(value: Any) -> datetime:
    """Parse a Security Onion timestamp into a timezone-aware UTC datetime.

    Inputs:
        value: Datetime, ISO timestamp string, or None.

    Outputs:
        Parsed UTC datetime, or the current time when parsing fails.
    """

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
    """Return a datetime as timezone-aware UTC.

    Inputs:
        value: Naive or aware datetime.

    Outputs:
        Timezone-aware UTC datetime.
    """

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _expiry_from_expires_in(value: Any) -> datetime | None:
    """Convert an OAuth2 expires_in value into an absolute expiry time.

    Inputs:
        value: Seconds-until-expiry value from the token response.

    Outputs:
        Timezone-aware expiry datetime, or None when the value is unusable.
    """

    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None

    if seconds <= 0:
        return None

    return utc_now() + timedelta(seconds=seconds)


def _build_url(base_url: str, path: str, *, query: dict[str, str] | None = None) -> str:
    """Build a URL from base, path, and query parameters.

    Inputs:
        base_url: Base URL without a trailing slash.
        path: Path beginning with a slash.
        query: Optional query parameters.

    Outputs:
        Full URL string.
    """

    normalized_base = base_url.rstrip("/")
    normalized_path = path if path.startswith("/") else f"/{path}"
    url = f"{normalized_base}{normalized_path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    return url


def _build_ssl_context(verify_tls: bool) -> ssl.SSLContext | None:
    """Return the SSL context used for urllib requests.

    Inputs:
        verify_tls: Whether certificates should be verified.

    Outputs:
        None to use the default verifying context, or an unverified context.
    """

    if verify_tls:
        return None
    return ssl._create_unverified_context()  # noqa: S323


def _json_request(
    method: str,
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str],
    timeout_seconds: int,
    ssl_context: ssl.SSLContext | None,
    opener: Callable[..., Any] | None = None,
) -> JsonDict:
    """Send a request and parse the JSON response object.

    Inputs:
        method: HTTP method.
        url: Full request URL.
        data: Optional raw request body bytes.
        headers: Request headers.
        timeout_seconds: HTTP timeout.
        ssl_context: Optional SSL context.
        opener: Optional urlopen-compatible callable.

    Outputs:
        Parsed JSON object.

    Raises:
        SecurityOnionAuthError: On HTTP 401/403.
        SecurityOnionRequestError: On any other failure or non-object JSON.
    """

    text = _text_request(
        method,
        url,
        data=data,
        headers={"Accept": "application/json", **headers},
        timeout_seconds=timeout_seconds,
        ssl_context=ssl_context,
        opener=opener,
    )

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SecurityOnionRequestError(
            f"Security Onion returned malformed JSON from {url}: {exc}"
        ) from exc

    if not isinstance(parsed, dict):
        raise SecurityOnionRequestError(f"Security Onion returned non-object JSON from {url}")

    return parsed


def _text_request(
    method: str,
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout_seconds: int,
    ssl_context: ssl.SSLContext | None,
    opener: Callable[..., Any] | None = None,
) -> str:
    """Send an HTTP request and return the response text.

    Inputs:
        method: HTTP method.
        url: Full request URL.
        data: Optional raw request body bytes.
        headers: Optional request headers.
        timeout_seconds: HTTP timeout.
        ssl_context: Optional SSL context.
        opener: Optional urlopen-compatible callable, defaulting to
            urllib.request.urlopen.

    Outputs:
        Response body text.

    Raises:
        SecurityOnionAuthError: On HTTP 401/403.
        SecurityOnionRequestError: On any other HTTP, network, or timeout error.
    """

    request = urllib.request.Request(url, data=data, headers=dict(headers or {}), method=method.upper())
    send = opener if opener is not None else urllib.request.urlopen

    try:
        with send(request, timeout=timeout_seconds, context=ssl_context) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        message = _read_http_error(exc)
        if exc.code in {401, 403}:
            raise SecurityOnionAuthError(
                f"Security Onion authentication failed for {url}: {message}"
            ) from exc
        raise SecurityOnionRequestError(
            f"Security Onion request failed for {url}: HTTP {exc.code}: {message}"
        ) from exc
    except urllib.error.URLError as exc:
        raise SecurityOnionRequestError(
            f"Security Onion network error for {url}: {exc.reason}"
        ) from exc
    except TimeoutError as exc:
        raise SecurityOnionRequestError(f"Security Onion request timed out for {url}") from exc


def _is_retryable_error(exc: SecurityOnionError) -> bool:
    """Return whether a Security Onion failure is transient and worth retrying.

    Retryable: connection errors, timeouts, HTTP 429, and HTTP 5xx. Every other
    4xx is a client error that a retry cannot fix, and authentication failures
    are handled by the separate single re-authentication path.

    Inputs:
        exc: SecurityOnionError instance.

    Outputs:
        Boolean retry flag.
    """

    if isinstance(exc, SecurityOnionAuthError):
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
    """Read an HTTP error body safely.

    Inputs:
        exc: urllib HTTPError instance.

    Outputs:
        Error body text, or the string form of the error.
    """

    try:
        body = exc.read().decode("utf-8")
    except Exception:
        return str(exc)
    return body or str(exc)
