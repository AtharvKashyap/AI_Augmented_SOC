"""Splunk HTTP Event Collector client for triage and incident output.

This module pushes what the pipeline *concluded* into Splunk — never what it
read. Three decisions in here are worth knowing before changing anything:

    - **Only derived fields are sent.** The event bodies are built from explicit
      field lists, mirroring the triage context allowlist in `soc/triage.py`.
      `Alert.raw`, `IncidentCandidate.related_events`, and enrichment provider
      `raw` payloads are never forwarded. Without that rule a Splunk index
      slowly becomes a second, unmanaged copy of the raw telemetry it was
      supposed to summarize.
    - **`analysis_source` travels with every triage event.** A dashboard that
      cannot tell a model score from a heuristic one misrepresents how much of
      the picture a model actually produced, which is exactly the degradation
      the rest of this project works to keep visible.
    - **A configured URL is used as given.** An operator who pointed the config
      at `/services/collector` meant it, so the collector path is only appended
      when it is absent.

HEC accepts several event objects in one request as *concatenated* JSON objects
separated by newlines, not as a JSON array, so batching is a string join rather
than `json.dumps` of a list. It also reports some failures inside a 200 response
as a non-zero `code`, so the body is checked even on success.
"""

from __future__ import annotations

import json
import logging
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

from soc.models import utc_now

if TYPE_CHECKING:
    from soc.config import Settings
    from soc.incidents import Incident
    from soc.models import TriageResult

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

TOKEN_SETTING = "SPLUNK_HEC_TOKEN"
"""Name of the setting an operator has to populate, quoted in error messages."""

DEFAULT_SOURCETYPE = "ai_triage"
"""Sourcetype the Splunk saved searches and dashboard in `splunk/` expect."""

COLLECTOR_EVENT_PATH = "/services/collector/event"
"""Path appended to a bare HEC base URL."""

COLLECTOR_PATHS = ("/services/collector", COLLECTOR_EVENT_PATH)
"""Endpoint suffixes accepted as already complete, so they are not rewritten."""

DEFAULT_MAX_BATCH_EVENTS = 100
"""Events per request. Batching keeps a 500-alert run from making 500 requests."""

TRIAGE_EVENT_FIELDS = (
    "target_id",
    "target_type",
    "score",
    "action",
    "classification",
    "fp_likelihood",
    "analysis_source",
    "model",
    "prompt_version",
    "summary",
)
"""Triage fields forwarded to Splunk. Adding a field to TriageResult does not add
it here: this list is the allowlist, and `iocs`, `evidence`, and `reasoning` are
deliberately outside it."""

_RETRYABLE_STATUS_CODES = frozenset({408, 425, 500, 502, 503, 504})
"""Statuses a retry can plausibly fix. 4xx client errors are not retried."""

_REDACTED = "***"
"""Replacement for the HEC token in any message that could otherwise carry it."""


class HTTPOpener(Protocol):
    """Callable that performs one HTTP request, so tests can replace urllib."""

    def __call__(self, request: urllib.request.Request, *, timeout: float, context: Any) -> Any:
        """Send one request and return a context-manager response."""


class SplunkError(RuntimeError):
    """Base error for Splunk HEC failures.

    Attributes:
        retryable: Whether retrying the same request could plausibly succeed.
    """

    retryable = False


class SplunkAuthError(SplunkError):
    """Raised when Splunk rejects the configured HEC token."""


class SplunkRequestError(SplunkError):
    """Raised when a HEC request fails or returns an unusable body."""

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
class SplunkConfig:
    """Configuration for one Splunk HTTP Event Collector endpoint.

    Attributes:
        hec_url: HEC URL. Used as given when it already ends in
            /services/collector or /services/collector/event; otherwise
            /services/collector/event is appended.
        token: HEC token, sent as `Authorization: Splunk <token>`. Never appears
            in an exception message or log line.
        index: Target index. Omitted from the payload when empty, which lets the
            token's own default index apply.
        sourcetype: Sourcetype stamped on every event.
        host: Host field stamped on every event. Omitted when empty.
        verify_tls: Whether to verify the Splunk TLS certificate.
        timeout_seconds: HTTP timeout in seconds.
        max_retries: Retry attempts after the first request, for transient
            failures only: connection errors, timeouts, and HTTP 5xx.
        retry_backoff_seconds: Base delay for exponential backoff between
            retries. Attempt N waits base * 2 ** N seconds.
        max_batch_events: Maximum events per request.
    """

    hec_url: str
    token: str
    index: str = ""
    sourcetype: str = DEFAULT_SOURCETYPE
    host: str = ""
    verify_tls: bool = True
    timeout_seconds: int = 15
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0
    max_batch_events: int = DEFAULT_MAX_BATCH_EVENTS

    def __post_init__(self) -> None:
        """Validate config.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            SplunkError: If any field is unusable.
        """

        if not self.hec_url.strip():
            raise SplunkError("Splunk hec_url cannot be empty; set SPLUNK_HEC_URL")
        if not self.token.strip():
            raise SplunkError(f"Splunk token cannot be empty; set {TOKEN_SETTING}")
        if not self.sourcetype.strip():
            raise SplunkError("Splunk sourcetype cannot be empty")
        if self.timeout_seconds <= 0:
            raise SplunkError("Splunk timeout_seconds must be greater than zero")
        if self.max_retries < 0:
            raise SplunkError("Splunk max_retries cannot be negative")
        if self.retry_backoff_seconds < 0:
            raise SplunkError("Splunk retry_backoff_seconds cannot be negative")
        if self.max_batch_events < 1:
            raise SplunkError("Splunk max_batch_events must be at least one")

    @property
    def event_url(self) -> str:
        """Return the URL events are POSTed to.

        A URL an operator deliberately pointed at a collector endpoint is left
        alone; anything else gets the event endpoint appended.

        Inputs:
            None. Uses this object's hec_url.

        Outputs:
            Fully qualified HEC endpoint URL.
        """

        url = self.hec_url.strip().rstrip("/")
        if url.endswith(COLLECTOR_PATHS):
            return url
        return f"{url}{COLLECTOR_EVENT_PATH}"


class SplunkClient:
    """Client that pushes derived SOC results into Splunk over HEC."""

    def __init__(
        self,
        config: SplunkConfig,
        *,
        opener: HTTPOpener | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Initialize the client.

        Inputs:
            config: HEC endpoint, retry, and batching configuration.
            opener: Optional callable invoked as opener(request, timeout=...,
                context=...). Defaults to urllib.request.urlopen; tests inject a
                fake so no test touches the network.
            sleep: Optional sleep callable used for retry backoff. Defaults to
                time.sleep; tests inject a recorder so no real time passes.

        Outputs:
            None.
        """

        self.config = config
        self._opener: HTTPOpener = opener or urllib.request.urlopen
        self._sleep = sleep or time.sleep
        self._ssl_context = _build_ssl_context(config.verify_tls)

    @classmethod
    def from_settings(
        cls,
        settings: Settings | Any,
        *,
        opener: HTTPOpener | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> SplunkClient:
        """Build a client from application settings.

        Every field is read with a `getattr` default so this works against a
        Settings object that does not expose the optional tuning keys.

        Inputs:
            settings: Application settings exposing splunk_hec_url and
                splunk_hec_token, and optionally index/sourcetype.
            opener: Optional HTTP opener, as the constructor documents.
            sleep: Optional sleep callable, as the constructor documents.

        Outputs:
            SplunkClient instance.

        Raises:
            SplunkError: If the URL or token is missing, or a value is unusable.
        """

        url = _coerce_text(getattr(settings, "splunk_hec_url", ""))
        token = _coerce_text(getattr(settings, "splunk_hec_token", ""))
        if not url:
            raise SplunkError("Splunk output requires SPLUNK_HEC_URL to be set")
        if not token:
            raise SplunkError(f"Splunk output requires {TOKEN_SETTING} to be set")

        config = SplunkConfig(
            hec_url=url,
            token=token,
            index=_coerce_text(getattr(settings, "splunk_hec_index", "")),
            sourcetype=_coerce_text(getattr(settings, "splunk_hec_sourcetype", "")) or DEFAULT_SOURCETYPE,
            host=_coerce_text(getattr(settings, "splunk_hec_host", "")),
            verify_tls=bool(getattr(settings, "splunk_hec_verify_tls", True)),
        )
        return cls(config, opener=opener, sleep=sleep)

    def send_triage_results(self, results: Sequence[TriageResult]) -> int:
        """Push triage results to Splunk as sourcetype events.

        Only the fields in TRIAGE_EVENT_FIELDS are sent, so no raw alert payload
        or enrichment response can reach the index through this path.

        Inputs:
            results: Triage results to forward. An empty sequence makes no HTTP
                call at all.

        Outputs:
            Number of events sent.

        Raises:
            SplunkAuthError: If the HEC token is rejected.
            SplunkRequestError: If a request keeps failing or a 200 response
                reports a non-zero HEC code.
        """

        envelopes = [
            self._envelope(_triage_event(result), timestamp=getattr(result, "created_at", None))
            for result in results
        ]
        return self._send(envelopes)

    def send_incidents(self, incidents: Sequence[Incident]) -> int:
        """Push incident summaries to Splunk for dashboarding.

        Incidents are summarized, not reproduced: the candidate and alert lists
        become counts, because a dashboard needs the scale of an incident rather
        than every identifier inside it.

        Inputs:
            incidents: Incidents to forward. An empty sequence makes no HTTP
                call at all.

        Outputs:
            Number of events sent.

        Raises:
            SplunkAuthError: If the HEC token is rejected.
            SplunkRequestError: If a request keeps failing or a 200 response
                reports a non-zero HEC code.
        """

        envelopes = [
            self._envelope(
                _incident_event(incident),
                timestamp=getattr(incident, "last_seen", None) or getattr(incident, "created_at", None),
            )
            for incident in incidents
        ]
        return self._send(envelopes)

    def _envelope(self, event: JsonDict, *, timestamp: datetime | None) -> JsonDict:
        """Wrap one event body in a HEC envelope.

        Inputs:
            event: Derived event fields.
            timestamp: Event time, or None to use the current time.

        Outputs:
            HEC envelope dictionary.
        """

        envelope: JsonDict = {
            "event": event,
            "sourcetype": self.config.sourcetype,
            "time": _epoch_seconds(timestamp),
        }
        if self.config.index.strip():
            envelope["index"] = self.config.index.strip()
        if self.config.host.strip():
            envelope["host"] = self.config.host.strip()
        return envelope

    def _send(self, envelopes: Sequence[JsonDict]) -> int:
        """Send envelopes in batches and return how many were sent.

        Inputs:
            envelopes: HEC envelopes to send.

        Outputs:
            Number of events sent, zero when there was nothing to send.

        Raises:
            SplunkAuthError: If the HEC token is rejected.
            SplunkRequestError: If a request keeps failing.
        """

        if not envelopes:
            return 0

        sent = 0
        for batch in _chunked(envelopes, self.config.max_batch_events):
            self._post(_encode_batch(batch))
            sent += len(batch)
        return sent

    def _post(self, payload: str) -> None:
        """POST one batch, retrying transient failures with bounded backoff.

        Connection errors, timeouts, and HTTP 5xx are retried up to
        config.max_retries times with exponential backoff. Everything else,
        including 401/403 and a 200 response carrying a non-zero HEC code, is
        raised immediately: no retry fixes a bad token or a malformed event.

        Inputs:
            payload: Newline-delimited JSON envelopes.

        Outputs:
            None.

        Raises:
            SplunkAuthError: If the HEC token is rejected.
            SplunkRequestError: If the request keeps failing.
        """

        attempts = self.config.max_retries + 1
        last_error: SplunkError | None = None

        for attempt in range(attempts):
            try:
                self._post_once(payload)
            except SplunkError as exc:
                last_error = exc
                if attempt >= attempts - 1 or not exc.retryable:
                    raise
                delay = self.config.retry_backoff_seconds * (2**attempt)
                logger.warning(
                    "Retrying Splunk HEC request to %s in %.2fs after transient failure: %s",
                    self.config.event_url,
                    delay,
                    exc,
                )
                self._sleep(delay)
            else:
                return

        raise SplunkRequestError(
            f"Splunk HEC request failed after {attempts} attempt(s): {last_error}"
        )

    def _post_once(self, payload: str) -> None:
        """Send one HEC request and validate its response body.

        Inputs:
            payload: Newline-delimited JSON envelopes.

        Outputs:
            None.

        Raises:
            SplunkAuthError: If the HEC token is rejected.
            SplunkRequestError: On any other failure or unusable body.
        """

        url = self.config.event_url
        request = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={
                "Authorization": f"Splunk {self.config.token}",
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
            raise SplunkRequestError(
                self._scrub(f"Splunk HEC network error for {url}: {exc.reason}"),
                retryable=True,
            ) from exc
        except TimeoutError as exc:
            raise SplunkRequestError(
                self._scrub(f"Splunk HEC request timed out for {url}"),
                retryable=True,
            ) from exc

        self._check_response_body(text, url)

    def _check_response_body(self, text: str, url: str) -> None:
        """Reject a 200 response that reports a HEC failure.

        HEC answers `{"text": "Success", "code": 0}` on success and reports some
        errors — an invalid index, a malformed event — as a non-zero code inside
        an HTTP 200, so a status check alone would call those runs successful.

        Inputs:
            text: Response body.
            url: Endpoint URL, for the error message.

        Outputs:
            None.

        Raises:
            SplunkRequestError: If the body is unparseable or reports a non-zero
                code.
        """

        try:
            parsed = json.loads(text or "{}")
        except json.JSONDecodeError as exc:
            raise SplunkRequestError(
                self._scrub(f"Splunk HEC returned malformed JSON from {url}: {exc}")
            ) from exc

        if not isinstance(parsed, dict):
            raise SplunkRequestError(self._scrub(f"Splunk HEC returned non-object JSON from {url}"))

        code = parsed.get("code")
        if code in (None, 0):
            return

        detail = _coerce_text(parsed.get("text")) or "no detail"
        raise SplunkRequestError(
            self._scrub(f"Splunk HEC rejected the batch at {url}: code {code}: {detail}")
        )

    def _http_error_to_exception(self, exc: urllib.error.HTTPError, url: str) -> SplunkError:
        """Map an HTTPError onto the right module error.

        Inputs:
            exc: HTTPError raised by the opener.
            url: Endpoint URL, for the error message.

        Outputs:
            SplunkAuthError or SplunkRequestError, never raised here.
        """

        body = _read_http_error(exc)
        if exc.code in {401, 403}:
            return SplunkAuthError(
                self._scrub(
                    f"Splunk rejected the HEC token for {url} (HTTP {exc.code}); "
                    f"check {TOKEN_SETTING}: {body}"
                )
            )
        return SplunkRequestError(
            self._scrub(f"Splunk HEC request failed for {url}: HTTP {exc.code}: {body}"),
            retryable=exc.code in _RETRYABLE_STATUS_CODES,
        )

    def _scrub(self, message: str) -> str:
        """Remove the HEC token from a message before it is raised or logged.

        The token is only ever placed in a request header, but a server can echo
        a credential back in an error body, and an error body is quoted in the
        exception message. Scrubbing at the single point where messages are built
        makes "the token never leaves this module" true by construction rather
        than by review.

        Inputs:
            message: Message text that may contain the token.

        Outputs:
            Message with every occurrence of the token replaced.
        """

        token = self.config.token
        if token and token in message:
            return message.replace(token, _REDACTED)
        return message


def _triage_event(result: TriageResult) -> JsonDict:
    """Build the Splunk event body for one triage result.

    Inputs:
        result: Triage result to summarize.

    Outputs:
        Dictionary containing only TRIAGE_EVENT_FIELDS.
    """

    return {field: _json_safe(getattr(result, field, None)) for field in TRIAGE_EVENT_FIELDS}


def _incident_event(incident: Incident) -> JsonDict:
    """Build the Splunk event body for one incident.

    Inputs:
        incident: Incident to summarize.

    Outputs:
        Dictionary of dashboard-facing incident fields.
    """

    return {
        "id": incident.id,
        "candidate_count": len(incident.candidate_ids),
        "alert_count": len(incident.alert_ids),
        "max_score": incident.max_score,
        "primary_host": incident.primary_host,
        "primary_user": incident.primary_user,
        "first_seen": _json_safe(incident.first_seen),
        "last_seen": _json_safe(incident.last_seen),
    }


def _encode_batch(envelopes: Sequence[JsonDict]) -> str:
    """Encode envelopes as newline-delimited concatenated JSON objects.

    HEC expects concatenated objects, not a JSON array: an array is rejected as
    a single malformed event.

    Inputs:
        envelopes: HEC envelopes.

    Outputs:
        Newline-separated JSON text.
    """

    return "\n".join(json.dumps(envelope, sort_keys=True) for envelope in envelopes)


def _chunked(items: Sequence[JsonDict], size: int) -> Iterable[Sequence[JsonDict]]:
    """Yield consecutive slices of at most `size` items.

    Inputs:
        items: Sequence to split.
        size: Maximum slice length, at least one.

    Outputs:
        Iterator of slices.
    """

    for start in range(0, len(items), size):
        yield items[start : start + size]


def _epoch_seconds(value: datetime | None) -> float:
    """Return a HEC `time` value in epoch seconds.

    Inputs:
        value: Event time, or None to use the current time.

    Outputs:
        Epoch seconds as a float.
    """

    if value is None:
        return utc_now().timestamp()
    return value.timestamp()


def _json_safe(value: Any) -> Any:
    """Convert a model value into something json.dumps accepts.

    Inputs:
        value: Enum, datetime, or already-serializable value.

    Outputs:
        JSON-compatible value.
    """

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    return value


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
    """Return the SSL context for HEC requests.

    Inputs:
        verify_tls: Whether to verify the Splunk certificate.

    Outputs:
        None to use urllib's verifying default, or an unverified context.
    """

    if verify_tls:
        return None
    return ssl._create_unverified_context()
