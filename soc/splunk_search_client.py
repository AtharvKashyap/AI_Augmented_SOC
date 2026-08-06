"""Optional Splunk search client used as an *additional* ingestion source.

This module retrieves events from Splunk's REST search API and converts them
into `RawEvent` objects for `SOCPipeline.run_events()`. It is deliberately a
separate concern from `soc/splunk_client.py`, which is the HTTP Event Collector
*output* client: one pushes conclusions to Splunk, the other reads telemetry
back out, and nothing is shared between them but style.

Read this before wiring it anywhere
-----------------------------------
Splunk ingestion is **optional and additive**. Direct Wazuh ingestion
(`soc/wazuh_client.py`) and direct Security Onion ingestion
(`soc/security_onion_client.py`) keep working exactly as before and never route
through this module. If Splunk is not configured, nothing here runs.

Confirmed API surface (Splunk REST search)
------------------------------------------
- Create a search job: ``POST {base_url}/services/search/jobs`` with the form
  fields ``search``, ``earliest_time``, ``latest_time`` and
  ``output_mode=json``. The response carries a search ID.
- Poll job status: ``GET {base_url}/services/search/jobs/{sid}?output_mode=json``.
- Fetch results: ``GET {base_url}/services/search/jobs/{sid}/results``
  ``?output_mode=json&count={max_results}``, whose body carries a ``results``
  list of row objects.
- Authentication is ``Authorization: Bearer <token>``. A bearer token is used
  rather than a username and password so no console password has to be stored
  for ingestion.

NOT FULLY VERIFIED — inferred field names and paths, change them in ONE place
----------------------------------------------------------------------------
**This module has never been run against a live Splunk instance.** The request
shapes above come from the documented REST API, but the exact *field names and
paths inside the responses* differ between Splunk versions and between
``output_mode`` renderings, and those are the parts most likely to be wrong. Every
one of them is isolated in a module constant below so a real deployment corrects
it in one place, the same approach `soc/security_onion_client.py` takes for the
undocumented Connect API query parameters:

    SID_PATHS                (default ("sid", "entry.0.content.sid"))   INFERRED
    JOB_ENTRY_KEY            (default "entry")                          INFERRED
    JOB_CONTENT_KEY          (default "content")                        INFERRED
    JOB_DONE_FIELDS          (default ("isDone", "is_done", "done"))    INFERRED
    JOB_DISPATCH_STATE_FIELDS (default ("dispatchState", ...))          INFERRED
    JOB_DONE_STATES          (default {"DONE"})                         INFERRED
    JOB_FAILED_STATES        (default {"FAILED"})                       INFERRED
    RESULTS_KEY              (default "results")                        INFERRED
    RESULT_TIME_FIELDS       (default ("_time", ...))                   INFERRED
    RESULT_RAW_FIELD         (default "_raw")                           INFERRED
    SOURCE_HINT_FIELDS       (default ("sourcetype", "index", ...))     INFERRED

Never read one of those names at a call site.

Payload choice: `_raw` wins when it is a JSON object
----------------------------------------------------
A Splunk result row is a flat mapping of Splunk *fields*, and for forwarded
Wazuh or Security Onion data the original event is usually carried verbatim as a
JSON string in ``_raw``. When ``_raw`` parses as a JSON object it becomes the
`RawEvent.payload`, so the existing normalizers in `soc/normalizer.py` see the
same shape they see under direct ingestion instead of a Splunk-flattened
version. The Splunk field metadata is not discarded: it is kept alongside under
the `SPLUNK_METADATA_KEY` key, and only ever added where it would not overwrite
a key the original event already defines. When ``_raw`` is absent or is not a
JSON object, the row itself is the payload.
"""

from __future__ import annotations

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
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from soc.models import EventSource, RawEvent, utc_now

if TYPE_CHECKING:
    from soc.config import Settings

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

TOKEN_SETTING = "SPLUNK_SEARCH_TOKEN"
"""Name of the setting an operator has to populate, quoted in error messages."""

URL_SETTING = "SPLUNK_SEARCH_URL"
"""Name of the management-port URL setting, quoted in error messages."""

SEARCH_JOBS_PATH = "/services/search/jobs"
"""CONFIRMED. Search job collection endpoint."""

RESULTS_SUBPATH = "results"
"""CONFIRMED. Sub-resource holding a finished job's rows."""

SEARCH_PARAM = "search"
"""CONFIRMED. Form field carrying the SPL query."""

EARLIEST_PARAM = "earliest_time"
"""CONFIRMED. Form field carrying the start of the search window."""

LATEST_PARAM = "latest_time"
"""CONFIRMED. Form field carrying the end of the search window."""

OUTPUT_MODE_PARAM = "output_mode"
"""CONFIRMED. Response rendering selector."""

OUTPUT_MODE_JSON = "json"
"""CONFIRMED. The only rendering this module can parse."""

COUNT_PARAM = "count"
"""CONFIRMED. Result-count cap on the results sub-resource."""

DEFAULT_SEARCH_QUERY = "search index=main sourcetype=wazuh"
"""Default SPL query. Deployment specific: only the *form* is confirmed."""

DEFAULT_EARLIEST_TIME = "-15m"
"""Default start of the search window, in Splunk relative-time syntax."""

DEFAULT_LATEST_TIME = "now"
"""Default end of the search window."""

DEFAULT_MAX_RESULTS = 100
"""Default result cap, matching the other ingestion clients' `limit`."""

EVENT_ID_PREFIX = "splunk-search"
"""Prefix on every generated RawEvent ID.

It names the *ingestion path*, not the chosen EventSource, deliberately: a Wazuh
alert read through Splunk and the same alert read directly from `alerts.json`
are two retrievals of one event, and giving them the same ID would let one
silently overwrite the other's audit row.
"""

SPLUNK_METADATA_KEY = "splunk"
"""Payload key holding the Splunk field metadata when `_raw` supplies the body."""

# --- INFERRED response field names and paths. See the module docstring. ---

SID_PATHS: tuple[str, ...] = ("sid", "entry.0.content.sid")
"""INFERRED. Paths inspected for the search ID in a job-creation response."""

JOB_ENTRY_KEY = "entry"
"""INFERRED. Key holding the job entry list in a status response."""

JOB_CONTENT_KEY = "content"
"""INFERRED. Key holding one job entry's properties."""

JOB_DONE_FIELDS: tuple[str, ...] = ("isDone", "is_done", "done")
"""INFERRED. Boolean-ish job properties that indicate completion."""

JOB_DISPATCH_STATE_FIELDS: tuple[str, ...] = ("dispatchState", "dispatch_state", "state")
"""INFERRED. Job properties carrying the dispatch state string."""

JOB_DONE_STATES = frozenset({"DONE"})
"""INFERRED. Dispatch states that mean results can be read."""

JOB_FAILED_STATES = frozenset({"FAILED"})
"""INFERRED. Dispatch states that mean the job will never produce results."""

RESULTS_KEY = "results"
"""INFERRED. Key holding the row list in a results response."""

RESULT_TIME_FIELDS: tuple[str, ...] = ("_time", "_indextime", "@timestamp", "timestamp")
"""INFERRED. Row fields inspected for an event timestamp, in order."""

RESULT_RAW_FIELD = "_raw"
"""INFERRED. Row field carrying the original event text."""

SOURCE_HINT_FIELDS: tuple[str, ...] = ("sourcetype", "source", "index", "_sourcetype")
"""INFERRED. Row fields inspected to decide which EventSource a row came from."""

WAZUH_SOURCE_MARKERS: tuple[str, ...] = ("wazuh", "ossec")
"""Substrings in a source hint that clearly identify Wazuh data."""

SECURITY_ONION_SOURCE_MARKERS: tuple[str, ...] = (
    "securityonion",
    "security_onion",
    "security-onion",
    "suricata",
    "zeek",
    "so-",
)
"""Substrings in a source hint that clearly identify Security Onion data."""

_REDACTED = "***"
"""Replacement for the search token in any message that could carry it."""


class SplunkSearchError(RuntimeError):
    """Base error for Splunk search ingestion failures.

    Attributes:
        retryable: Whether retrying the same request could plausibly succeed.
    """

    retryable = False


class SplunkSearchAuthError(SplunkSearchError):
    """Raised when Splunk rejects the configured search token."""


class SplunkSearchRequestError(SplunkSearchError):
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
class SplunkSearchConfig:
    """Configuration for one Splunk REST search endpoint.

    Attributes:
        base_url: Splunk management URL, for example
            https://splunk.example:8089. Endpoint paths are appended to it.
        token: Splunk bearer token, sent as `Authorization: Bearer <token>`.
            Never appears in an exception message or log line.
        search_query: SPL query dispatched as the search job.
        earliest_time: Start of the search window, in Splunk time syntax.
        latest_time: End of the search window, in Splunk time syntax.
        max_results: Maximum rows requested from a finished job.
        verify_tls: Whether to verify the Splunk TLS certificate.
        timeout_seconds: HTTP timeout in seconds.
        max_retries: Retry attempts after the first request, for transient
            failures only: connection errors, timeouts, HTTP 429, and HTTP 5xx.
        retry_backoff_seconds: Base delay for exponential backoff between
            retries. Attempt N waits base * 2 ** N seconds.
        poll_interval_seconds: Delay between job status polls.
        max_poll_attempts: Maximum status polls before giving up. Exceeding it
            raises rather than reading a partially finished job.
    """

    base_url: str
    token: str
    search_query: str = DEFAULT_SEARCH_QUERY
    earliest_time: str = DEFAULT_EARLIEST_TIME
    latest_time: str = DEFAULT_LATEST_TIME
    max_results: int = DEFAULT_MAX_RESULTS
    verify_tls: bool = True
    timeout_seconds: int = 30
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0
    poll_interval_seconds: float = 1.0
    max_poll_attempts: int = 30

    def __post_init__(self) -> None:
        """Validate config.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            SplunkSearchError: If any field is unusable.
        """

        if not self.base_url.strip():
            raise SplunkSearchError(f"Splunk search base_url cannot be empty; set {URL_SETTING}")
        if not self.token.strip():
            raise SplunkSearchError(f"Splunk search token cannot be empty; set {TOKEN_SETTING}")
        if not self.search_query.strip():
            raise SplunkSearchError("Splunk search_query cannot be empty")
        if not self.earliest_time.strip():
            raise SplunkSearchError("Splunk search earliest_time cannot be empty")
        if not self.latest_time.strip():
            raise SplunkSearchError("Splunk search latest_time cannot be empty")
        if self.max_results < 1:
            raise SplunkSearchError("Splunk search max_results must be at least one")
        if self.timeout_seconds <= 0:
            raise SplunkSearchError("Splunk search timeout_seconds must be greater than zero")
        if self.max_retries < 0:
            raise SplunkSearchError("Splunk search max_retries cannot be negative")
        if self.retry_backoff_seconds < 0:
            raise SplunkSearchError("Splunk search retry_backoff_seconds cannot be negative")
        if self.poll_interval_seconds < 0:
            raise SplunkSearchError("Splunk search poll_interval_seconds cannot be negative")
        if self.max_poll_attempts < 1:
            raise SplunkSearchError("Splunk search max_poll_attempts must be at least one")

    @property
    def jobs_url(self) -> str:
        """Return the search job collection URL.

        Inputs:
            None. Uses this object's base_url.

        Outputs:
            Fully qualified search jobs URL.
        """

        return f"{self.base_url.strip().rstrip('/')}{SEARCH_JOBS_PATH}"

    def job_url(self, sid: str) -> str:
        """Return the status URL for one search job.

        Inputs:
            sid: Splunk search ID.

        Outputs:
            Fully qualified job status URL.
        """

        return f"{self.jobs_url}/{urllib.parse.quote(sid, safe='')}"

    def results_url(self, sid: str) -> str:
        """Return the results URL for one search job.

        Inputs:
            sid: Splunk search ID.

        Outputs:
            Fully qualified job results URL.
        """

        return f"{self.job_url(sid)}/{RESULTS_SUBPATH}"


class SplunkSearchClient:
    """Client that reads events out of Splunk via the REST search API."""

    def __init__(
        self,
        config: SplunkSearchConfig,
        *,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Initialize the client.

        Inputs:
            config: Endpoint, query, retry, and polling configuration.
            opener: Optional callable invoked as opener(request, timeout=...,
                context=...). Defaults to urllib.request.urlopen; tests inject a
                fake so no test touches the network.
            sleep: Optional sleep callable used for retry backoff and status
                polling. Defaults to time.sleep; tests inject a recorder so no
                real time passes.

        Outputs:
            None.
        """

        self.config = config
        self._opener = opener or urllib.request.urlopen
        self._sleep = sleep or time.sleep
        self._ssl_context = _build_ssl_context(config.verify_tls)
        self.last_skipped_result_count = 0

    @classmethod
    def from_settings(
        cls,
        settings: Settings | Any,
        *,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> SplunkSearchClient:
        """Build a client from application settings.

        Every field is read with a `getattr` default so this works against a
        Settings object that predates the Splunk search keys.

        Inputs:
            settings: Application settings exposing splunk_search_url and
                splunk_search_token, and optionally splunk_search_query,
                splunk_search_earliest, splunk_search_latest, and
                splunk_search_limit.
            opener: Optional HTTP opener, as the constructor documents.
            sleep: Optional sleep callable, as the constructor documents.

        Outputs:
            SplunkSearchClient instance.

        Raises:
            SplunkSearchError: If the URL or token is missing, or a value is
                unusable.
        """

        url = _coerce_text(getattr(settings, "splunk_search_url", ""))
        token = _coerce_text(getattr(settings, "splunk_search_token", ""))
        if not url:
            raise SplunkSearchError(
                f"Splunk search ingestion requires {URL_SETTING} to be set "
                "(the management URL, for example https://splunk.example:8089)"
            )
        if not token:
            raise SplunkSearchError(f"Splunk search ingestion requires {TOKEN_SETTING} to be set")

        config = SplunkSearchConfig(
            base_url=url,
            token=token,
            search_query=_coerce_text(getattr(settings, "splunk_search_query", "")) or DEFAULT_SEARCH_QUERY,
            earliest_time=_coerce_text(getattr(settings, "splunk_search_earliest", "")) or DEFAULT_EARLIEST_TIME,
            latest_time=_coerce_text(getattr(settings, "splunk_search_latest", "")) or DEFAULT_LATEST_TIME,
            max_results=_coerce_int(getattr(settings, "splunk_search_limit", None), DEFAULT_MAX_RESULTS),
            verify_tls=bool(getattr(settings, "splunk_search_verify_tls", True)),
        )
        return cls(config, opener=opener, sleep=sleep)

    def create_search_job(self) -> str:
        """Dispatch the configured search and return its search ID.

        Inputs:
            None. Uses the configured query and time window.

        Outputs:
            Splunk search ID string.

        Raises:
            SplunkSearchAuthError: If the token is rejected.
            SplunkSearchRequestError: If the request keeps failing or the
                response carries no search ID.
        """

        body = urllib.parse.urlencode(
            {
                SEARCH_PARAM: self.config.search_query,
                EARLIEST_PARAM: self.config.earliest_time,
                LATEST_PARAM: self.config.latest_time,
                OUTPUT_MODE_PARAM: OUTPUT_MODE_JSON,
            }
        ).encode("utf-8")

        response = self._request(
            "POST",
            self.config.jobs_url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        sid = extract_search_id(response)
        if not sid:
            raise SplunkSearchRequestError(
                self._scrub(
                    "Splunk did not return a search ID for the dispatched job; "
                    f"inspected {', '.join(SID_PATHS)} in keys: {_key_list(response)}"
                )
            )
        return sid

    def wait_for_job(self, sid: str) -> None:
        """Poll a search job until Splunk reports it finished.

        Polling is bounded by config.max_poll_attempts. Exhausting the bound
        raises rather than reading the job anyway: a partially dispatched search
        returns a partial result set that looks exactly like a quiet period, and
        silently under-reporting events is worse than failing the fetch.

        Inputs:
            sid: Splunk search ID.

        Outputs:
            None.

        Raises:
            SplunkSearchAuthError: If the token is rejected.
            SplunkSearchRequestError: If the job fails, or does not finish
                within config.max_poll_attempts polls.
        """

        for attempt in range(self.config.max_poll_attempts):
            response = self._request(
                "GET",
                _with_query(self.config.job_url(sid), {OUTPUT_MODE_PARAM: OUTPUT_MODE_JSON}),
            )
            content = extract_job_content(response)
            state = _dispatch_state(content)

            if state in JOB_FAILED_STATES:
                raise SplunkSearchRequestError(
                    self._scrub(f"Splunk search job {sid} reported dispatch state {state}")
                )
            if _job_is_done(content):
                return

            if attempt < self.config.max_poll_attempts - 1:
                self._sleep(self.config.poll_interval_seconds)

        raise SplunkSearchRequestError(
            self._scrub(
                f"Splunk search job {sid} did not finish within "
                f"{self.config.max_poll_attempts} status poll(s); no partial results were read"
            )
        )

    def fetch_results(self, sid: str) -> list[JsonDict]:
        """Fetch a finished job's result rows.

        Inputs:
            sid: Splunk search ID.

        Outputs:
            Result rows that are dictionaries. Rows of any other type are
            skipped and counted on last_skipped_result_count.

        Raises:
            SplunkSearchAuthError: If the token is rejected.
            SplunkSearchRequestError: If the request keeps failing.
        """

        response = self._request(
            "GET",
            _with_query(
                self.config.results_url(sid),
                {
                    OUTPUT_MODE_PARAM: OUTPUT_MODE_JSON,
                    COUNT_PARAM: str(self.config.max_results),
                },
            ),
        )

        rows, skipped = extract_result_rows(response)
        self.last_skipped_result_count = skipped
        if skipped:
            logger.warning(
                "Skipped %d non-object row(s) in Splunk results for search job %s",
                skipped,
                sid,
            )
        return rows[: self.config.max_results]

    def fetch_recent_events(self) -> list[RawEvent]:
        """Run the configured search and return its rows as RawEvent objects.

        Inputs:
            None. Uses the configured query, window, and result cap.

        Outputs:
            RawEvent objects ready for SOCPipeline.run_events().

        Raises:
            SplunkSearchAuthError: If the token is rejected.
            SplunkSearchRequestError: If any stage keeps failing or the job does
                not finish within the poll bound.
        """

        sid = self.create_search_job()
        self.wait_for_job(sid)
        return [raw_event_from_splunk_result(row) for row in self.fetch_results(sid)]

    def _request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> JsonDict:
        """Send one authenticated request, retrying transient failures.

        Inputs:
            method: HTTP method.
            url: Fully qualified request URL.
            data: Optional request body bytes.
            headers: Optional extra headers.

        Outputs:
            Parsed JSON response object.

        Raises:
            SplunkSearchAuthError: If the token is rejected.
            SplunkSearchRequestError: If the request keeps failing.
        """

        attempts = self.config.max_retries + 1
        last_error: SplunkSearchError | None = None

        for attempt in range(attempts):
            try:
                return self._request_once(method, url, data=data, headers=headers)
            except SplunkSearchError as exc:
                last_error = exc
                if attempt >= attempts - 1 or not exc.retryable:
                    raise
                delay = self.config.retry_backoff_seconds * (2**attempt)
                logger.warning(
                    "Retrying Splunk search request %s %s in %.2fs after transient failure: %s",
                    method,
                    url,
                    delay,
                    exc,
                )
                self._sleep(delay)

        raise SplunkSearchRequestError(
            self._scrub(f"Splunk search request failed after {attempts} attempt(s): {last_error}")
        )

    def _request_once(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> JsonDict:
        """Send one request and parse its JSON object body.

        Inputs:
            method: HTTP method.
            url: Fully qualified request URL.
            data: Optional request body bytes.
            headers: Optional extra headers.

        Outputs:
            Parsed JSON response object.

        Raises:
            SplunkSearchAuthError: If the token is rejected.
            SplunkSearchRequestError: On any other failure or unusable body.
        """

        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.config.token}",
                "Accept": "application/json",
                **(headers or {}),
            },
            method=method.upper(),
        )

        try:
            with self._opener(request, timeout=self.config.timeout_seconds, context=self._ssl_context) as response:
                text = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise self._http_error_to_exception(exc, url) from exc
        except urllib.error.URLError as exc:
            raise SplunkSearchRequestError(
                self._scrub(f"Splunk search network error for {url}: {exc.reason}"),
                retryable=True,
            ) from exc
        except TimeoutError as exc:
            raise SplunkSearchRequestError(
                self._scrub(f"Splunk search request timed out for {url}"),
                retryable=True,
            ) from exc

        try:
            parsed = json.loads(text or "{}")
        except json.JSONDecodeError as exc:
            raise SplunkSearchRequestError(
                self._scrub(f"Splunk returned malformed JSON from {url}: {exc}")
            ) from exc

        if not isinstance(parsed, dict):
            raise SplunkSearchRequestError(self._scrub(f"Splunk returned non-object JSON from {url}"))
        return parsed

    def _http_error_to_exception(self, exc: urllib.error.HTTPError, url: str) -> SplunkSearchError:
        """Map an HTTPError onto the right module error.

        Inputs:
            exc: HTTPError raised by the opener.
            url: Endpoint URL, for the error message.

        Outputs:
            SplunkSearchAuthError or SplunkSearchRequestError, never raised here.
        """

        body = _read_http_error(exc)
        if exc.code in {401, 403}:
            return SplunkSearchAuthError(
                self._scrub(
                    f"Splunk rejected the search token for {url} (HTTP {exc.code}); "
                    f"check {TOKEN_SETTING} and its search capability: {body}"
                )
            )
        return SplunkSearchRequestError(
            self._scrub(f"Splunk search request failed for {url}: HTTP {exc.code}: {body}"),
            retryable=exc.code in _RETRYABLE_STATUS_CODES,
        )

    def _scrub(self, message: str) -> str:
        """Remove the search token from a message before it is raised or logged.

        The token only ever goes into a request header, but Splunk quotes request
        detail back in error bodies and those bodies are quoted into exception
        messages. Scrubbing at the single point where messages are built makes
        "the token never leaves this module" true by construction.

        Inputs:
            message: Message text that may contain the token.

        Outputs:
            Message with every occurrence of the token replaced.
        """

        token = self.config.token
        if token and token in message:
            return message.replace(token, _REDACTED)
        return message


_RETRYABLE_STATUS_CODES = frozenset({408, 425, 429, 500, 502, 503, 504})
"""Statuses a retry can plausibly fix. Other 4xx client errors are not retried."""


def extract_search_id(response: JsonDict) -> str:
    """Extract the search ID from a job-creation response.

    Every candidate path is an INFERRED constant; see the module docstring.

    Inputs:
        response: Parsed job-creation response.

    Outputs:
        Search ID string, empty when none of the known paths carry one.
    """

    for path in SID_PATHS:
        value = _path_value(response, path)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
    return ""


def extract_job_content(response: JsonDict) -> JsonDict:
    """Extract one job's property object from a status response.

    Inputs:
        response: Parsed job-status response.

    Outputs:
        Job property mapping, empty when the response shape is unrecognized.
    """

    entries = response.get(JOB_ENTRY_KEY)
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                content = entry.get(JOB_CONTENT_KEY)
                if isinstance(content, dict):
                    return content
    content = response.get(JOB_CONTENT_KEY)
    if isinstance(content, dict):
        return content
    return {}


def extract_result_rows(response: JsonDict) -> tuple[list[JsonDict], int]:
    """Extract result rows from a results response, tolerating bad rows.

    A row that is not a dictionary is skipped and counted rather than raising,
    the same discipline the `alerts.json` reader applies to malformed lines: one
    unusable row must not cost the whole fetch.

    Inputs:
        response: Parsed results response.

    Outputs:
        Tuple of (usable rows, skipped row count).
    """

    rows = response.get(RESULTS_KEY)
    if not isinstance(rows, list):
        logger.warning(
            "Unrecognized Splunk results response shape; top-level keys: %s",
            _key_list(response),
        )
        return [], 0

    usable: list[JsonDict] = []
    skipped = 0
    for row in rows:
        if isinstance(row, dict):
            usable.append(row)
        else:
            skipped += 1
    return usable, skipped


def raw_event_from_splunk_result(row: JsonDict) -> RawEvent:
    """Convert one Splunk result row into a RawEvent.

    When the row's `_raw` field parses as a JSON object it becomes the payload,
    so the existing normalizers see the original Wazuh or Security Onion shape;
    the Splunk field metadata is kept alongside under SPLUNK_METADATA_KEY. See
    the module docstring for why.

    Inputs:
        row: One Splunk result row.

    Outputs:
        RawEvent whose source is WAZUH or SECURITY_ONION when the row clearly
        says so, and EventSource.SPLUNK otherwise.
    """

    return RawEvent(
        id=_event_id_from_row(row),
        source=event_source_from_row(row),
        timestamp=_parse_timestamp(_first_value(row, RESULT_TIME_FIELDS)),
        payload=_build_payload(row),
        received_at=utc_now(),
    )


def event_source_from_row(row: JsonDict) -> EventSource:
    """Decide which EventSource a Splunk row represents.

    Only a clear signal reclassifies a row: a sourcetype, source, or index
    naming Wazuh or Security Onion. Anything ambiguous stays
    EventSource.SPLUNK, which normalizes generically, because guessing wrong
    sends a payload through a normalizer expecting different field paths.

    Inputs:
        row: One Splunk result row.

    Outputs:
        EventSource.WAZUH, EventSource.SECURITY_ONION, or EventSource.SPLUNK.
    """

    hints = " ".join(
        str(row.get(field)).lower() for field in SOURCE_HINT_FIELDS if isinstance(row.get(field), str)
    )
    if any(marker in hints for marker in WAZUH_SOURCE_MARKERS):
        return EventSource.WAZUH
    if any(marker in hints for marker in SECURITY_ONION_SOURCE_MARKERS):
        return EventSource.SECURITY_ONION
    return EventSource.SPLUNK


def _build_payload(row: JsonDict) -> JsonDict:
    """Build the RawEvent payload for one Splunk row.

    Inputs:
        row: One Splunk result row.

    Outputs:
        Payload dictionary: the parsed `_raw` object with Splunk metadata
        attached, or a copy of the row itself.
    """

    parsed_raw = _parse_raw_field(row.get(RESULT_RAW_FIELD))
    if parsed_raw is None:
        return dict(row)

    payload = dict(parsed_raw)
    metadata = {key: value for key, value in row.items() if key != RESULT_RAW_FIELD}
    if metadata and SPLUNK_METADATA_KEY not in payload:
        payload[SPLUNK_METADATA_KEY] = metadata
    return payload


def _parse_raw_field(value: Any) -> JsonDict | None:
    """Parse a `_raw` field into a JSON object when possible.

    Inputs:
        value: Value of the row's `_raw` field.

    Outputs:
        Parsed object, or None when `_raw` is absent, unparseable, or not a
        JSON object (a plain syslog line, for instance).
    """

    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(parsed, dict):
        return parsed
    return None


def _event_id_from_row(row: JsonDict) -> str:
    """Return a stable, content-derived event ID for one Splunk row.

    The ID is a fingerprint of the row content only, so re-running the same
    search over the same window yields the same IDs and dedup works.

    Inputs:
        row: One Splunk result row.

    Outputs:
        Deterministic event ID string.
    """

    fingerprint = hashlib.sha256(
        json.dumps(row, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]
    return f"{EVENT_ID_PREFIX}-{fingerprint}"


def _first_value(row: JsonDict, fields: tuple[str, ...]) -> Any:
    """Return the first non-empty value among candidate row fields.

    Inputs:
        row: One Splunk result row.
        fields: Candidate field names in priority order.

    Outputs:
        First non-empty value, or None.
    """

    for field in fields:
        value = row.get(field)
        if value is not None and value != "":
            return value
    return None


def _path_value(payload: JsonDict, path: str) -> Any:
    """Return the value at a dot-separated path, supporting list indexes.

    Inputs:
        payload: Mapping to walk.
        path: Dot-separated path; a numeric segment indexes a list.

    Outputs:
        Value at the path, or None when any segment is missing.
    """

    if path in payload:
        return payload[path]

    value: Any = payload
    for segment in path.split("."):
        if isinstance(value, dict):
            value = value.get(segment)
        elif isinstance(value, list) and segment.isdigit():
            index = int(segment)
            value = value[index] if index < len(value) else None
        else:
            return None
    return value


def _dispatch_state(content: JsonDict) -> str:
    """Return the job's dispatch state, upper-cased.

    Inputs:
        content: Job property mapping.

    Outputs:
        Dispatch state string, empty when no known field carries one.
    """

    for field in JOB_DISPATCH_STATE_FIELDS:
        value = content.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    return ""


def _job_is_done(content: JsonDict) -> bool:
    """Return whether a job's properties report completion.

    Splunk renders booleans inconsistently across versions and output modes, so
    the string forms are accepted alongside real booleans, and the dispatch
    state is treated as a second, independent signal.

    Inputs:
        content: Job property mapping.

    Outputs:
        True when the job can be read.
    """

    if any(_is_truthy(content.get(field)) for field in JOB_DONE_FIELDS):
        return True

    return _dispatch_state(content) in JOB_DONE_STATES


def _is_truthy(value: Any) -> bool:
    """Return whether a Splunk boolean-ish property means "yes".

    Splunk renders booleans as real JSON booleans, as the integers 0 and 1, and
    as the strings "0"/"1"/"true", depending on version and output mode, so all
    three forms are accepted. Anything else — including a missing property — is
    "no", so an unrecognized rendering makes a job look unfinished rather than
    finished, and the poll bound then reports the problem.

    Inputs:
        value: Property value from a job's content mapping.

    Outputs:
        Boolean interpretation of the value.
    """

    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a Splunk row timestamp into a timezone-aware UTC datetime.

    Inputs:
        value: Datetime, ISO timestamp string, epoch number, or None.

    Outputs:
        Parsed UTC datetime, or None when nothing usable is present.
    """

    if isinstance(value, datetime):
        return _ensure_utc(value)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            return _ensure_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
        except ValueError:
            pass
        try:
            return datetime.fromtimestamp(float(text), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    return None


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


def _with_query(url: str, query: dict[str, str]) -> str:
    """Append query parameters to a URL.

    Inputs:
        url: Base URL without a query string.
        query: Query parameters.

    Outputs:
        URL with an encoded query string.
    """

    if not query:
        return url
    return f"{url}?{urllib.parse.urlencode(query)}"


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
        verify_tls: Whether to verify the Splunk certificate.

    Outputs:
        None to use urllib's verifying default, or an unverified context.
    """

    if verify_tls:
        return None
    return ssl._create_unverified_context()
