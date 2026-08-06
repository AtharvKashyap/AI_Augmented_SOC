"""Wazuh Indexer (OpenSearch) ingestion client.

This module retrieves Wazuh alert documents from the **Wazuh Indexer** — the
OpenSearch cluster Wazuh ships alerts into — and converts them into `RawEvent`
objects for `SOCPipeline.run_events()`. Normalization already lives in
`soc.normalizer`; this module only handles authentication, retrieval, filtering,
and `RawEvent` construction.

It is the second retrieval path for the same alerts `soc/wazuh_client.py` reads
out of `alerts.json`, and it is selected by `WAZUH_ALERT_SOURCE=indexer`. The
`json_logs` path is untouched by it.

Confirmed API surface (OpenSearch search API)
---------------------------------------------
- Search request: ``POST {base_url}/{index_pattern}/_search`` with a JSON body.
- Authentication is HTTP Basic (``Authorization: Basic <base64 user:pass>``);
  the Wazuh Indexer ships with the OpenSearch security plugin enabled.
- Body fields ``size``, ``query``, and ``sort`` are documented, as is the
  ``query.bool.filter`` / ``range`` construction used for the time window.
- Results arrive under ``hits.hits[]``, each hit carrying ``_index``, ``_id``,
  and the original document under ``_source``.

NEVER RUN AGAINST A LIVE WAZUH INDEXER — inferred names, change them in ONE place
--------------------------------------------------------------------------------
**No part of this module has been executed against a real Wazuh Indexer.** The
OpenSearch request and response *shapes* above come from the documented API, but
which Wazuh alert *fields* exist, what they are named, and how they are mapped
depend on the Wazuh index template of the deployment, and those are the parts most
likely to be wrong. Every one of them is isolated in a module constant so a real
deployment corrects it in one place — the same approach
`soc/security_onion_client.py` takes for the undocumented Connect API query
parameters:

    DEFAULT_INDEX_PATTERN  (default "wazuh-alerts-*")   INFERRED, deployment
        specific: Wazuh 4.x commonly indexes to ``wazuh-alerts-4.x-*`` with a
        ``wazuh-alerts-*`` alias, and a custom template may use neither.
    TIMESTAMP_FIELD        (default "@timestamp")        INFERRED
    FALLBACK_TIMESTAMP_FIELDS (default ("timestamp",))   INFERRED
    RULE_LEVEL_FIELD       (default "rule.level")        INFERRED
    HITS_KEY / HITS_INNER_KEY / HIT_SOURCE_KEY           INFERRED envelope path
    SORT_ORDER_DESCENDING                                INFERRED value

Never read one of those names at a call site.

Filtering is applied twice, deliberately
----------------------------------------
The query asks the indexer for the time window and the minimum ``rule.level``,
and then `WazuhIndexerClient.fetch_recent_alerts` re-applies both locally, the
same discipline `soc/security_onion_client.py` uses. A deployment whose template
maps ``rule.level`` as a keyword rather than a number will silently not honour
the range filter, and the local pass is what keeps the returned set correct.
The local pass is authoritative; the query bounds are an optimization.

Failure is loud, never quiet
----------------------------
An unparseable body, a missing index, or an exhausted retry budget raises. A
zero-result run and a broken query look identical to an operator, and reporting
"no alerts" for a failed search is the one outcome this module must not produce.
Unusable individual hits are the exception: they are skipped *and counted* on
`last_skipped_hit_count`, because one bad document must not cost the whole fetch.
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
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from soc.models import EventSource, RawEvent, utc_now

if TYPE_CHECKING:
    from soc.config import Settings

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

URL_SETTING = "WAZUH_INDEXER_URL"
"""Name of the setting an operator has to populate, quoted in error messages."""

USER_SETTING = "WAZUH_INDEXER_USER"
"""Name of the username setting, quoted in error messages."""

PASSWORD_SETTING = "WAZUH_INDEXER_PASSWORD"
"""Name of the password setting, quoted in error messages."""

ALERT_SOURCE_SETTING = "WAZUH_ALERT_SOURCE"
"""Name of the ingestion selector setting, quoted in error messages."""

INDEXER_ALERT_SOURCE = "indexer"
"""Value of WAZUH_ALERT_SOURCE that selects this client."""

SEARCH_PATH_SUFFIX = "/_search"
"""CONFIRMED. OpenSearch search endpoint suffix."""

SIZE_KEY = "size"
"""CONFIRMED. Body field capping the number of returned hits."""

QUERY_KEY = "query"
"""CONFIRMED. Body field holding the query."""

SORT_KEY = "sort"
"""CONFIRMED. Body field holding the sort specification."""

EVENT_ID_PREFIX = "wazuh-indexer"
"""Prefix on every generated RawEvent ID.

It names the *ingestion path*, not the chosen EventSource, deliberately: the same
Wazuh alert read from the Indexer, read from `alerts.json`, and read back out of
Splunk are three retrievals of one event, and giving them the same ID would let
one silently overwrite the other's audit row. `soc/splunk_search_client.py` uses
`splunk-search-<hash>` for exactly this reason.
"""

DEFAULT_INDEX_PATTERN = "wazuh-alerts-*"
"""INFERRED, deployment specific. Wazuh 4.x commonly writes wazuh-alerts-4.x-*."""

TIMESTAMP_FIELD = "@timestamp"
"""INFERRED. Alert field carrying the event time, used for range and sort."""

FALLBACK_TIMESTAMP_FIELDS: tuple[str, ...] = ("timestamp",)
"""INFERRED. Alert fields inspected when TIMESTAMP_FIELD is absent."""

RULE_LEVEL_FIELD = "rule.level"
"""INFERRED. Alert field carrying the Wazuh rule level."""

HITS_KEY = "hits"
"""INFERRED. Top-level response key holding the hits envelope."""

HITS_INNER_KEY = "hits"
"""INFERRED. Key inside the envelope holding the hit list."""

HIT_SOURCE_KEY = "_source"
"""INFERRED. Key on one hit holding the original alert document."""

SORT_ORDER_DESCENDING = "desc"
"""INFERRED. Sort direction requested so a capped query returns the newest hits."""

AGENT_CONTEXT_KEY = "agent_context"
"""Payload key holding Manager agent inventory, matching the alerts.json path."""

_REDACTED = "***"
"""Replacement for credentials in any message that could carry them."""

_RETRYABLE_STATUS_CODES = frozenset({408, 425, 429, 500, 502, 503, 504})
"""Statuses a retry can plausibly fix. Other 4xx client errors are not retried."""


class WazuhIndexerError(RuntimeError):
    """Base error for Wazuh Indexer ingestion failures.

    Attributes:
        retryable: Whether retrying the same request could plausibly succeed.
    """

    retryable = False


class WazuhIndexerAuthError(WazuhIndexerError):
    """Raised when the Indexer rejects the configured credentials.

    Never retryable: a 401 or 403 means the credentials are wrong or the account
    lacks read access on the index, and neither is fixed by asking again.
    """


class WazuhIndexerRequestError(WazuhIndexerError):
    """Raised when a search request fails or returns an unusable body."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        """Initialize the error.

        Inputs:
            message: Human-readable failure description.
            retryable: Whether the failure is transient.

        Outputs:
            None.
        """

        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class WazuhIndexerConfig:
    """Configuration for one Wazuh Indexer endpoint.

    Attributes:
        base_url: Indexer base URL, for example https://indexer.example:9200.
            Endpoint paths are appended to it.
        username: Indexer username, sent as HTTP Basic auth.
        password: Indexer password. Never appears in an exception or log line.
        index_pattern: Index or index pattern searched. INFERRED default.
        lookback_minutes: Size of the query time window.
        min_level: Minimum Wazuh rule.level kept. Zero means no level filter.
        limit: Maximum number of alerts kept per fetch.
        verify_tls: Whether to verify the Indexer TLS certificate.
        timeout_seconds: HTTP timeout in seconds.
        max_retries: Retry attempts after the first request, for transient
            failures only: connection errors, timeouts, HTTP 429, and HTTP 5xx.
        retry_backoff_seconds: Base delay for exponential backoff between
            retries. Attempt N waits base * 2 ** N seconds.
    """

    base_url: str
    username: str
    password: str
    index_pattern: str = DEFAULT_INDEX_PATTERN
    lookback_minutes: int = 60
    min_level: int = 7
    limit: int = 100
    verify_tls: bool = True
    timeout_seconds: int = 20
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0

    def __post_init__(self) -> None:
        """Validate config.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            WazuhIndexerError: If any field is unusable.
        """

        if not self.base_url.strip():
            raise WazuhIndexerError(f"Wazuh Indexer base_url cannot be empty; set {URL_SETTING}")
        if not self.username.strip():
            raise WazuhIndexerError(f"Wazuh Indexer username cannot be empty; set {USER_SETTING}")
        if not self.password.strip():
            raise WazuhIndexerError(f"Wazuh Indexer password cannot be empty; set {PASSWORD_SETTING}")
        if not self.index_pattern.strip():
            raise WazuhIndexerError("Wazuh Indexer index_pattern cannot be empty")
        if self.lookback_minutes <= 0:
            raise WazuhIndexerError("Wazuh Indexer lookback_minutes must be greater than zero")
        if self.min_level < 0:
            raise WazuhIndexerError("Wazuh Indexer min_level cannot be negative")
        if self.limit < 1:
            raise WazuhIndexerError("Wazuh Indexer limit must be at least one")
        if self.timeout_seconds <= 0:
            raise WazuhIndexerError("Wazuh Indexer timeout_seconds must be greater than zero")
        if self.max_retries < 0:
            raise WazuhIndexerError("Wazuh Indexer max_retries cannot be negative")
        if self.retry_backoff_seconds < 0:
            raise WazuhIndexerError("Wazuh Indexer retry_backoff_seconds cannot be negative")

    @property
    def search_url(self) -> str:
        """Return the search URL for the configured index pattern.

        The index pattern is URL-encoded rather than interpolated raw. It is
        operator-supplied configuration, but it lands in a URL path, and encoding
        it means a pattern containing `*`, `/`, or a space cannot silently change
        which endpoint is called.

        Inputs:
            None. Uses this object's base_url and index_pattern.

        Outputs:
            Fully qualified search URL.
        """

        index = urllib.parse.quote(self.index_pattern.strip(), safe="")
        return f"{self.base_url.strip().rstrip('/')}/{index}{SEARCH_PATH_SUFFIX}"


class WazuhIndexerClient:
    """Client that reads Wazuh alerts out of the Wazuh Indexer (OpenSearch)."""

    def __init__(
        self,
        config: WazuhIndexerConfig,
        *,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Initialize the client.

        Inputs:
            config: Endpoint, query, and retry configuration.
            opener: Optional callable invoked as opener(request, timeout=...,
                context=...). Defaults to urllib.request.urlopen; tests inject a
                fake so no test touches the network.
            sleep: Optional sleep callable used for retry backoff. Defaults to
                time.sleep; tests inject a recorder so no real time passes.

        Outputs:
            None.
        """

        self.config = config
        self._opener = opener or urllib.request.urlopen
        self._sleep = sleep or time.sleep
        self._ssl_context = _build_ssl_context(config.verify_tls)
        self.last_skipped_hit_count = 0

    @classmethod
    def from_settings(
        cls,
        settings: Settings | Any,
        *,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> WazuhIndexerClient:
        """Build a client from application settings.

        Every field is read with a `getattr` default so this works against a
        Settings object that predates any of these keys. The alert window, level
        floor, limit, and index pattern come from the shared `WAZUH_ALERT_*` and
        `WAZUH_MIN_LEVEL` settings, so switching retrieval path does not change
        what counts as an alert worth ingesting.

        Inputs:
            settings: Application settings exposing wazuh_indexer_url,
                wazuh_indexer_user, and wazuh_indexer_password, and optionally
                wazuh_indexer_verify_tls, wazuh_alert_index, wazuh_alert_limit,
                wazuh_alert_lookback_minutes, and wazuh_min_level.
            opener: Optional HTTP opener, as the constructor documents.
            sleep: Optional sleep callable, as the constructor documents.

        Outputs:
            WazuhIndexerClient instance.

        Raises:
            WazuhIndexerError: If the URL or the credentials are missing, or a
                configured value is unusable.
        """

        url = _coerce_text(getattr(settings, "wazuh_indexer_url", ""))
        username = _coerce_text(getattr(settings, "wazuh_indexer_user", ""))
        password = _coerce_text(getattr(settings, "wazuh_indexer_password", ""))

        if not url:
            raise WazuhIndexerError(
                f"Wazuh Indexer ingestion requires {URL_SETTING} to be set "
                "(the OpenSearch base URL, for example https://indexer.example:9200)"
            )
        if not username:
            raise WazuhIndexerError(f"Wazuh Indexer ingestion requires {USER_SETTING} to be set")
        if not password:
            raise WazuhIndexerError(f"Wazuh Indexer ingestion requires {PASSWORD_SETTING} to be set")

        config = WazuhIndexerConfig(
            base_url=url,
            username=username,
            password=password,
            index_pattern=(
                _coerce_text(getattr(settings, "wazuh_alert_index", "")) or DEFAULT_INDEX_PATTERN
            ),
            lookback_minutes=_coerce_int(getattr(settings, "wazuh_alert_lookback_minutes", None), 60),
            min_level=_coerce_int(getattr(settings, "wazuh_min_level", None), 7),
            limit=_coerce_int(getattr(settings, "wazuh_alert_limit", None), 100),
            verify_tls=bool(getattr(settings, "wazuh_indexer_verify_tls", True)),
        )
        return cls(config, opener=opener, sleep=sleep)

    def fetch_recent_alerts(self) -> list[JsonDict]:
        """Search the Indexer and return recent Wazuh alert documents.

        The time window and level floor are re-applied locally after the search,
        so a deployment whose index template does not support the range filters
        still yields a correctly filtered set. See the module docstring.

        Inputs:
            None. Uses the configured window, level floor, and limit.

        Outputs:
            Alert documents sorted oldest to newest, capped at the limit.

        Raises:
            WazuhIndexerAuthError: If the credentials are rejected.
            WazuhIndexerRequestError: If the search keeps failing or returns an
                unusable body.
        """

        since = utc_now() - timedelta(minutes=self.config.lookback_minutes)
        response = self._search(
            build_search_body(
                since=since,
                min_level=self.config.min_level,
                limit=self.config.limit,
            )
        )

        hits, skipped = extract_hits(response)
        self.last_skipped_hit_count = skipped
        if skipped:
            logger.warning(
                "Skipped %d unusable hit(s) in Wazuh Indexer response from %s",
                skipped,
                self.config.search_url,
            )

        alerts = [
            alert
            for alert in hits
            if _alert_is_recent(alert, since) and _rule_level(alert) >= self.config.min_level
        ]
        alerts.sort(key=_alert_sort_key)
        return alerts[-self.config.limit :]

    def fetch_recent_events(
        self,
        *,
        agent_inventory: dict[str, JsonDict] | None = None,
    ) -> list[RawEvent]:
        """Fetch recent Indexer alerts as RawEvent objects.

        Inputs:
            agent_inventory: Optional Wazuh Manager agent inventory keyed by
                agent ID, merged into each payload exactly as the alerts.json
                path does so downstream stages see one shape.

        Outputs:
            RawEvent objects ready for SOCPipeline.run_events().

        Raises:
            WazuhIndexerAuthError: If the credentials are rejected.
            WazuhIndexerRequestError: If the search keeps failing.
        """

        return [
            raw_event_from_indexer_alert(alert, agent_inventory=agent_inventory)
            for alert in self.fetch_recent_alerts()
        ]

    def _search(self, body: JsonDict) -> JsonDict:
        """Send one search request, retrying transient failures.

        Inputs:
            body: OpenSearch search body.

        Outputs:
            Parsed JSON response object.

        Raises:
            WazuhIndexerAuthError: If the credentials are rejected.
            WazuhIndexerRequestError: If the request keeps failing.
        """

        url = self.config.search_url
        payload = json.dumps(body).encode("utf-8")
        attempts = self.config.max_retries + 1
        last_error: WazuhIndexerError | None = None

        for attempt in range(attempts):
            try:
                return self._search_once(url, payload)
            except WazuhIndexerError as exc:
                last_error = exc
                if attempt >= attempts - 1 or not exc.retryable:
                    raise
                delay = self.config.retry_backoff_seconds * (2**attempt)
                logger.warning(
                    "Retrying Wazuh Indexer search %s in %.2fs after transient failure: %s",
                    url,
                    delay,
                    exc,
                )
                self._sleep(delay)

        raise WazuhIndexerRequestError(
            self._scrub(f"Wazuh Indexer search failed after {attempts} attempt(s): {last_error}")
        )

    def _search_once(self, url: str, payload: bytes) -> JsonDict:
        """Send one search request and parse its JSON object body.

        Inputs:
            url: Fully qualified search URL.
            payload: Encoded search body.

        Outputs:
            Parsed JSON response object.

        Raises:
            WazuhIndexerAuthError: If the credentials are rejected.
            WazuhIndexerRequestError: On any other failure or unusable body.
        """

        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Basic {self._basic_credentials()}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with self._opener(request, timeout=self.config.timeout_seconds, context=self._ssl_context) as response:
                text = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise self._http_error_to_exception(exc, url) from exc
        except urllib.error.URLError as exc:
            raise WazuhIndexerRequestError(
                self._scrub(f"Wazuh Indexer network error for {url}: {exc.reason}"),
                retryable=True,
            ) from exc
        except TimeoutError as exc:
            raise WazuhIndexerRequestError(
                self._scrub(f"Wazuh Indexer search timed out for {url}"),
                retryable=True,
            ) from exc

        try:
            parsed = json.loads(text or "{}")
        except json.JSONDecodeError as exc:
            raise WazuhIndexerRequestError(
                self._scrub(f"Wazuh Indexer returned malformed JSON from {url}: {exc}")
            ) from exc

        if not isinstance(parsed, dict):
            raise WazuhIndexerRequestError(
                self._scrub(f"Wazuh Indexer returned non-object JSON from {url}")
            )
        return parsed

    def _basic_credentials(self) -> str:
        """Return the base64 HTTP Basic credential blob.

        Inputs:
            None. Uses the configured username and password.

        Outputs:
            Base64-encoded "user:password" string.
        """

        raw = f"{self.config.username}:{self.config.password}".encode()
        return base64.b64encode(raw).decode("ascii")

    def _http_error_to_exception(self, exc: urllib.error.HTTPError, url: str) -> WazuhIndexerError:
        """Map an HTTPError onto the right module error.

        Inputs:
            exc: HTTPError raised by the opener.
            url: Endpoint URL, for the error message.

        Outputs:
            WazuhIndexerAuthError or WazuhIndexerRequestError, never raised here.
        """

        body = _read_http_error(exc)
        if exc.code in {401, 403}:
            return WazuhIndexerAuthError(
                self._scrub(
                    f"Wazuh Indexer rejected the configured credentials for {url} "
                    f"(HTTP {exc.code}); check {USER_SETTING} and {PASSWORD_SETTING} "
                    f"and the account's read access to the index: {body}"
                )
            )
        return WazuhIndexerRequestError(
            self._scrub(f"Wazuh Indexer search failed for {url}: HTTP {exc.code}: {body}"),
            retryable=exc.code in _RETRYABLE_STATUS_CODES,
        )

    def _scrub(self, message: str) -> str:
        """Remove the credentials from a message before it is raised or logged.

        OpenSearch security-plugin errors quote request detail back, and those
        bodies are quoted into exception messages, so both the password and the
        base64 blob that carries it are removed at the single point where
        messages are built. That makes "the credentials never leave this module"
        true by construction rather than by review.

        Inputs:
            message: Message text that may contain the credentials.

        Outputs:
            Message with every occurrence of a credential replaced.
        """

        scrubbed = message
        for secret in (self._basic_credentials(), self.config.password):
            if secret and secret in scrubbed:
                scrubbed = scrubbed.replace(secret, _REDACTED)
        return scrubbed


def build_search_body(*, since: datetime, min_level: int, limit: int) -> JsonDict:
    """Build the OpenSearch search body for a Wazuh alert query.

    Every field name is a module constant; see the module docstring for which of
    them are inferred. A `min_level` of zero adds no level filter at all, so
    "ingest everything" cannot be turned into "ingest nothing" by a deployment
    that maps `rule.level` as a keyword.

    Inputs:
        since: Start of the requested time window.
        min_level: Minimum Wazuh rule level, zero for no level filter.
        limit: Maximum number of hits requested.

    Outputs:
        Search body dictionary.
    """

    filters: list[JsonDict] = [{"range": {TIMESTAMP_FIELD: {"gte": _ensure_utc(since).isoformat()}}}]
    if min_level > 0:
        filters.append({"range": {RULE_LEVEL_FIELD: {"gte": min_level}}})

    return {
        SIZE_KEY: limit,
        QUERY_KEY: {"bool": {"filter": filters}},
        SORT_KEY: [{TIMESTAMP_FIELD: {"order": SORT_ORDER_DESCENDING}}],
    }


def extract_hits(response: JsonDict) -> tuple[list[JsonDict], int]:
    """Extract alert documents from a search response, tolerating bad hits.

    A hit that is not a dictionary, or whose `_source` is missing or is not a
    dictionary, is skipped and counted rather than raising — the same discipline
    the `alerts.json` reader applies to malformed lines. An unrecognized envelope
    yields no hits and logs a warning naming the top-level keys received, so a
    real deployment can be diagnosed from logs alone.

    Inputs:
        response: Parsed search response.

    Outputs:
        Tuple of (alert documents, skipped hit count).
    """

    envelope = response.get(HITS_KEY)
    inner = envelope.get(HITS_INNER_KEY) if isinstance(envelope, dict) else None
    if not isinstance(inner, list):
        logger.warning(
            "Unrecognized Wazuh Indexer response shape; top-level keys: %s",
            _key_list(response),
        )
        return [], 0

    alerts: list[JsonDict] = []
    skipped = 0
    for hit in inner:
        document = _hit_source(hit)
        if document is None:
            skipped += 1
            continue
        alerts.append(document)
    return alerts, skipped


def raw_event_from_indexer_alert(
    alert: JsonDict,
    *,
    agent_inventory: dict[str, JsonDict] | None = None,
) -> RawEvent:
    """Convert one Wazuh alert document from the Indexer into a RawEvent.

    The whole document is preserved as the payload for auditability, and the ID
    is a fingerprint of the document content, so re-running the same search over
    the same window yields the same IDs and dedup works. The hit's `_id` is
    deliberately *not* used: OpenSearch assigns it per indexed document, so a
    reindexed alert would arrive with a new one and be processed twice.

    Inputs:
        alert: Wazuh alert document, as taken from a hit's `_source`.
        agent_inventory: Optional Manager agent inventory keyed by agent ID.

    Outputs:
        RawEvent with source EventSource.WAZUH and an EVENT_ID_PREFIX ID.
    """

    payload = dict(alert)
    agent_id = _nested_str(payload, ["agent", "id"])
    if agent_id and agent_inventory and agent_id in agent_inventory:
        payload[AGENT_CONTEXT_KEY] = agent_inventory[agent_id]

    return RawEvent(
        id=_event_id_from_alert(alert),
        source=EventSource.WAZUH,
        timestamp=_parse_timestamp(_alert_timestamp_value(alert)),
        payload=payload,
        received_at=utc_now(),
    )


def raw_event_from_indexer_hit(
    hit: JsonDict,
    *,
    agent_inventory: dict[str, JsonDict] | None = None,
) -> RawEvent:
    """Convert one raw search hit into a RawEvent.

    Inputs:
        hit: One entry from `hits.hits[]`, or a bare alert document.
        agent_inventory: Optional Manager agent inventory keyed by agent ID.

    Outputs:
        RawEvent with source EventSource.WAZUH.

    Raises:
        WazuhIndexerRequestError: If the hit carries no usable `_source`. Callers
            reading a whole response should use extract_hits, which skips and
            counts unusable hits instead.
    """

    document = _hit_source(hit)
    if document is None:
        raise WazuhIndexerRequestError(
            f"Wazuh Indexer hit carries no usable {HIT_SOURCE_KEY} document; keys: {_key_list(hit)}"
        )
    return raw_event_from_indexer_alert(document, agent_inventory=agent_inventory)


def _hit_source(hit: Any) -> JsonDict | None:
    """Return one hit's alert document, or None when it is unusable.

    A bare alert document (no `_source` wrapper) is accepted so the same helper
    serves both a real response and a caller that already unwrapped a hit.

    Inputs:
        hit: Candidate hit object.

    Outputs:
        Alert document, or None.
    """

    if not isinstance(hit, dict):
        return None

    if HIT_SOURCE_KEY in hit:
        document = hit[HIT_SOURCE_KEY]
        return document if isinstance(document, dict) else None

    if any(key.startswith("_") for key in hit):
        return None
    return hit or None


def _event_id_from_alert(alert: JsonDict) -> str:
    """Return a stable, content-derived event ID for one alert document.

    Inputs:
        alert: Wazuh alert document.

    Outputs:
        Deterministic event ID string prefixed with EVENT_ID_PREFIX.
    """

    fingerprint = hashlib.sha256(
        json.dumps(alert, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]
    return f"{EVENT_ID_PREFIX}-{fingerprint}"


def _alert_timestamp_value(alert: JsonDict) -> Any:
    """Return the first usable timestamp value on an alert document.

    Inputs:
        alert: Wazuh alert document.

    Outputs:
        Timestamp value, or None when no known field carries one.
    """

    for field in (TIMESTAMP_FIELD, *FALLBACK_TIMESTAMP_FIELDS):
        value = alert.get(field)
        if value is not None and value != "":
            return value
    return None


def _alert_is_recent(alert: JsonDict, since: datetime) -> bool:
    """Return whether an alert falls inside the lookback window.

    Inputs:
        alert: Wazuh alert document.
        since: Start of the lookback window.

    Outputs:
        True when the alert timestamp is at or after `since`.
    """

    return _parse_timestamp(_alert_timestamp_value(alert)) >= _ensure_utc(since)


def _alert_sort_key(alert: JsonDict) -> datetime:
    """Return an alert's timestamp for sorting.

    Inputs:
        alert: Wazuh alert document.

    Outputs:
        Timezone-aware timestamp.
    """

    return _parse_timestamp(_alert_timestamp_value(alert))


def _rule_level(alert: JsonDict) -> int:
    """Return an alert's Wazuh rule level as an integer.

    A missing or uninterpretable level reads as zero, which keeps the alert only
    when no level floor is configured. Guessing a level upwards would let a
    document with a broken mapping page an analyst.

    Inputs:
        alert: Wazuh alert document.

    Outputs:
        Rule level, zero when absent or unparseable.
    """

    value: Any = alert
    for key in RULE_LEVEL_FIELD.split("."):
        if not isinstance(value, dict):
            return 0
        value = value.get(key)

    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _parse_timestamp(value: Any) -> datetime:
    """Parse an alert timestamp into a timezone-aware UTC datetime.

    Inputs:
        value: Datetime, ISO timestamp string, or None.

    Outputs:
        Parsed UTC datetime, or the current time when nothing usable is present.
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
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _nested_str(payload: JsonDict, path: list[str]) -> str | None:
    """Return a nested string value if present.

    Inputs:
        payload: Mapping to walk.
        path: Key path.

    Outputs:
        Stripped string value, or None.
    """

    value: Any = payload
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)

    if value is None:
        return None

    text = str(value).strip()
    return text or None


def _key_list(payload: JsonDict) -> str:
    """Return a payload's top-level keys as a readable string.

    Inputs:
        payload: Mapping to describe.

    Outputs:
        Comma-separated key names, or "(none)".
    """

    return ", ".join(sorted(str(key) for key in payload)) or "(none)"


def _coerce_text(value: Any) -> str:
    """Return a stripped string for any value, empty for None.

    Inputs:
        value: Any value.

    Outputs:
        Stripped string.
    """

    if value is None:
        return ""
    return str(value).strip()


def _coerce_int(value: Any, default: int) -> int:
    """Return an int for any value, falling back to a default.

    Inputs:
        value: Any value.
        default: Value used when conversion fails or the value is absent.

    Outputs:
        Integer value.
    """

    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _read_http_error(exc: urllib.error.HTTPError) -> str:
    """Read an HTTP error body safely.

    Inputs:
        exc: HTTPError raised by the opener.

    Outputs:
        Body text, or the exception's own string form.
    """

    try:
        body = exc.read().decode("utf-8")
    except Exception:
        return str(exc)
    return body or str(exc)


def _build_ssl_context(verify_tls: bool) -> ssl.SSLContext | None:
    """Return the SSL context for search requests.

    Inputs:
        verify_tls: Whether to verify the Indexer certificate.

    Outputs:
        None to use urllib's verifying default, or an unverified context.
    """

    if verify_tls:
        return None
    return ssl._create_unverified_context()
