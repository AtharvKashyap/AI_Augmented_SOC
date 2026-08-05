"""VirusTotal v3 reputation provider.

This module implements `soc.threat_intel.ThreatIntelProvider` against the
VirusTotal v3 API, covering IP addresses (`/api/v3/ip_addresses/{ip}`) and
domains (`/api/v3/domains/{domain}`).

Four decisions here exist for reasons that are not obvious from the API docs:

    - **One engine hit is not malicious.** VirusTotal aggregates ~70 engines and
      a single detection on an otherwise clean indicator is very often a false
      positive. `malicious == 1` is therefore reported as SUSPICIOUS, and the
      thresholds live in `VirusTotalConfig` so they can be tuned without editing
      the parser.
    - **The verdict must be in the summary.** `soc.triage` withholds enrichment
      `raw` payloads from the model, so a verdict recorded only in `details`
      would never reach triage. The summary states the verdict and the engine
      counts in plain analyst language.
    - **`details` is a bounded parsed subset.** A VirusTotal response carries
      whois text, per-engine results, and resolution history: kilobytes that get
      cached and persisted for no benefit. Only counts, capped tags, and
      reputation are kept.
    - **A 404 is a result, not a failure.** It means VirusTotal has never seen
      the indicator, which is UNKNOWN — not an error, and definitely not benign.

Every failure raises a `ThreatIntelError` subclass. `ThreatIntelEnricher` catches
and skips, so a missing or ambiguous answer must never be dressed up as a
verdict.
"""

from __future__ import annotations

import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from soc.threat_intel import IntelLookup, IntelVerdict, ThreatIntelError

if TYPE_CHECKING:
    from soc.config import Settings


logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

PROVIDER_NAME = "virustotal"
"""Provider name used for attribution and cache keys."""

DEFAULT_BASE_URL = "https://www.virustotal.com/api/v3"
"""VirusTotal v3 API root."""

IP_INDICATOR_TYPE = "ip"
DOMAIN_INDICATOR_TYPE = "domain"

SUPPORTED_INDICATOR_TYPES: tuple[str, ...] = (IP_INDICATOR_TYPE, DOMAIN_INDICATOR_TYPE)
"""Indicator types this provider can answer."""

_INDICATOR_PATHS = {
    IP_INDICATOR_TYPE: "ip_addresses",
    DOMAIN_INDICATOR_TYPE: "domains",
}

FREE_TIER_SECONDS_BETWEEN_CALLS = 15.0
"""Spacing needed to stay inside the free tier's 4 requests per minute."""

MAX_TAGS = 10
"""Tags kept in `details`; the rest are dropped as unbounded provider text."""

API_KEY_SETTING = "VIRUSTOTAL_API_KEY"
"""Setting named in authentication failures so the fix is actionable."""


class VirusTotalError(ThreatIntelError):
    """Base error for VirusTotal provider failures."""


class VirusTotalAuthError(VirusTotalError):
    """Raised when VirusTotal rejects the API key."""


class VirusTotalRequestError(VirusTotalError):
    """Raised when a VirusTotal request fails or returns an unusable body."""


class VirusTotalRateLimitError(VirusTotalError):
    """Raised when VirusTotal reports the request quota is exhausted."""


class _NotFound(VirusTotalError):
    """Internal signal that VirusTotal holds no record for an indicator.

    Not part of the public surface: `lookup` converts it into an UNKNOWN verdict,
    because "never seen" is an answer rather than a failure.
    """


class Opener(Protocol):
    """Transport contract used for requests, so tests never touch the network."""

    def __call__(self, request: Any, *, timeout: float, context: Any = None) -> Any:
        """Send one prepared request and return a readable response."""


@dataclass(frozen=True, slots=True)
class VirusTotalConfig:
    """Configuration for the VirusTotal v3 API.

    Attributes:
        api_key: VirusTotal API key, sent as the `x-apikey` header.
        base_url: API root, without a trailing slash.
        timeout_seconds: HTTP timeout in seconds.
        max_retries: Retry attempts after the first request, for transient
            failures only: connection errors, timeouts, and HTTP 5xx.
        retry_backoff_seconds: Base delay for exponential backoff between
            retries. Attempt N waits base * 2 ** N seconds.
        malicious_threshold: Malicious engine count at or above which the
            verdict is MALICIOUS. Two by default, because a lone detection on an
            otherwise clean indicator is usually a false positive.
        suspicious_threshold: Malicious or suspicious engine count at or above
            which the verdict is SUSPICIOUS.
        max_tags: Maximum tags retained in the parsed details.
        cache_ttl_hours: TTL the enricher should apply to cached answers. Held
            here so the wiring has one place to read it from.
    """

    api_key: str
    base_url: str = DEFAULT_BASE_URL
    timeout_seconds: int = 20
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0
    malicious_threshold: int = 2
    suspicious_threshold: int = 1
    max_tags: int = MAX_TAGS
    cache_ttl_hours: int = 24

    def __post_init__(self) -> None:
        """Validate config.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            VirusTotalError: If any field is unusable.
        """

        if not self.api_key.strip():
            raise VirusTotalError(f"VirusTotal API key cannot be empty; set {API_KEY_SETTING}")
        if not self.base_url.strip():
            raise VirusTotalError("VirusTotal base URL cannot be empty")
        if self.timeout_seconds <= 0:
            raise VirusTotalError("VirusTotal timeout_seconds must be greater than zero")
        if self.max_retries < 0:
            raise VirusTotalError("VirusTotal max_retries cannot be negative")
        if self.retry_backoff_seconds < 0:
            raise VirusTotalError("VirusTotal retry_backoff_seconds cannot be negative")
        if self.malicious_threshold < 1:
            raise VirusTotalError("VirusTotal malicious_threshold must be at least one")
        if self.suspicious_threshold < 1:
            raise VirusTotalError("VirusTotal suspicious_threshold must be at least one")
        if self.suspicious_threshold > self.malicious_threshold:
            raise VirusTotalError(
                "VirusTotal suspicious_threshold cannot exceed malicious_threshold"
            )
        if self.max_tags < 0:
            raise VirusTotalError("VirusTotal max_tags cannot be negative")
        if self.cache_ttl_hours <= 0:
            raise VirusTotalError("VirusTotal cache_ttl_hours must be greater than zero")


class VirusTotalClient:
    """VirusTotal v3 implementation of the threat-intel provider protocol."""

    name = PROVIDER_NAME
    supported_indicator_types = SUPPORTED_INDICATOR_TYPES

    def __init__(
        self,
        config: VirusTotalConfig,
        *,
        opener: Opener | None = None,
        sleep: Callable[[float], None] | None = None,
        min_seconds_between_calls: float = FREE_TIER_SECONDS_BETWEEN_CALLS,
    ) -> None:
        """Initialize the provider.

        Inputs:
            config: API key, endpoint, retry, and verdict-threshold config.
            opener: Optional transport called as opener(request, timeout=...,
                context=...). Defaults to urllib.request.urlopen; tests inject a
                fake so no request leaves the process.
            sleep: Optional sleep callable used for retry backoff. Defaults to
                time.sleep; tests inject a recorder so no real time passes.
            min_seconds_between_calls: Spacing the enricher enforces between
                calls. Defaults to the free tier's 4 requests per minute.

        Outputs:
            None.
        """

        self.config = config
        self.min_seconds_between_calls = float(min_seconds_between_calls)
        self._opener = opener or urllib.request.urlopen
        self._sleep = sleep or time.sleep
        # VirusTotal is public HTTPS with a valid certificate chain: there is no
        # reason to ever weaken verification here, so the default context stands.
        self._ssl_context: ssl.SSLContext | None = None

    @classmethod
    def from_settings(cls, settings: Settings | Any, **kwargs: Any) -> VirusTotalClient:
        """Build a client from application settings.

        Settings are read with `getattr` defaults so a settings object that
        predates a key still works rather than raising AttributeError.

        Inputs:
            settings: Settings object exposing virustotal_api_key and optionally
                enrichment_cache_ttl_hours.
            kwargs: Constructor overrides, for example opener or sleep.

        Outputs:
            VirusTotalClient instance.

        Raises:
            VirusTotalError: If no API key is configured.
        """

        api_key = str(getattr(settings, "virustotal_api_key", "") or "").strip()
        if not api_key:
            raise VirusTotalError(
                f"VirusTotal API key is not configured; set {API_KEY_SETTING} to enable this provider"
            )

        ttl_hours = getattr(settings, "enrichment_cache_ttl_hours", 24)
        try:
            cache_ttl_hours = int(ttl_hours)
        except (TypeError, ValueError):
            cache_ttl_hours = 24
        if cache_ttl_hours <= 0:
            cache_ttl_hours = 24

        return cls(VirusTotalConfig(api_key=api_key, cache_ttl_hours=cache_ttl_hours), **kwargs)

    def lookup(self, indicator_type: str, indicator: str) -> IntelLookup:
        """Return VirusTotal's verdict for one indicator.

        Inputs:
            indicator_type: Indicator type, "ip" or "domain".
            indicator: Indicator value.

        Outputs:
            IntelLookup carrying the verdict, an analyst-readable summary, short
            risk-factor tokens, and a bounded parsed subset of the response.

        Raises:
            VirusTotalError: If the indicator is unusable, the key is rejected,
                the quota is exhausted, or the request keeps failing. A 404 is
                not a failure: it yields an UNKNOWN verdict.
        """

        value = indicator.strip()
        if not value:
            raise VirusTotalError("VirusTotal indicator cannot be empty")

        path_segment = _INDICATOR_PATHS.get(indicator_type)
        if path_segment is None:
            raise VirusTotalError(
                f"VirusTotal does not support indicator type {indicator_type!r}; "
                f"supported types are {', '.join(SUPPORTED_INDICATOR_TYPES)}"
            )

        url = f"{self.config.base_url.rstrip('/')}/{path_segment}/{urllib.parse.quote(value, safe='')}"

        try:
            response = self._request_with_retries(url)
        except _NotFound:
            return self._unknown_lookup(
                indicator_type,
                value,
                summary=f"VirusTotal: unknown, no record of {value}",
                details={"found": False},
            )

        return self._build_lookup(indicator_type, value, response)

    def _request_with_retries(self, url: str) -> JsonDict:
        """Fetch and parse one URL, retrying transient failures.

        Connection errors, timeouts, and HTTP 5xx are retried up to
        config.max_retries times with exponential backoff. Everything else,
        including 401/403/404/429, is raised immediately: no retry can fix a
        rejected key, a missing record, or an exhausted daily quota.

        Inputs:
            url: Fully built request URL.

        Outputs:
            Parsed JSON response object.

        Raises:
            VirusTotalError: On any non-retryable failure, or once retries are
                exhausted.
        """

        attempts = self.config.max_retries + 1
        last_error: VirusTotalError | None = None

        for attempt in range(attempts):
            try:
                return self._request_once(url)
            except VirusTotalError as exc:
                last_error = exc
                if attempt >= attempts - 1 or not _is_retryable_error(exc):
                    raise
                delay = self.config.retry_backoff_seconds * (2**attempt)
                logger.warning(
                    "Retrying VirusTotal request %s in %.2fs after transient failure: %s",
                    url,
                    delay,
                    exc,
                )
                self._sleep(delay)

        raise VirusTotalRequestError(
            f"VirusTotal request failed after {attempts} attempt(s): {last_error}"
        )

    def _request_once(self, url: str) -> JsonDict:
        """Send one GET request and parse the JSON body.

        Inputs:
            url: Fully built request URL.

        Outputs:
            Parsed JSON response object.

        Raises:
            VirusTotalAuthError: On HTTP 401 or 403.
            VirusTotalRateLimitError: On HTTP 429.
            VirusTotalRequestError: On any other HTTP, network, or parse failure.
            _NotFound: On HTTP 404.
        """

        request = urllib.request.Request(
            url,
            headers={"x-apikey": self.config.api_key, "Accept": "application/json"},
            method="GET",
        )

        try:
            with self._opener(request, timeout=self.config.timeout_seconds, context=self._ssl_context) as response:
                text = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise _http_failure(exc, url) from exc
        except urllib.error.URLError as exc:
            raise VirusTotalRequestError(f"VirusTotal network error for {url}: {exc.reason}") from exc
        except TimeoutError as exc:
            raise VirusTotalRequestError(f"VirusTotal request timed out for {url}") from exc

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise VirusTotalRequestError(f"VirusTotal returned malformed JSON from {url}: {exc}") from exc

        if not isinstance(parsed, dict):
            raise VirusTotalRequestError(f"VirusTotal returned non-object JSON from {url}")

        return parsed

    def _build_lookup(self, indicator_type: str, indicator: str, response: JsonDict) -> IntelLookup:
        """Turn one parsed response into an IntelLookup.

        Inputs:
            indicator_type: Indicator type.
            indicator: Indicator value.
            response: Parsed VirusTotal response object.

        Outputs:
            IntelLookup instance.
        """

        attributes = _attributes(response)
        stats = _analysis_stats(attributes)

        if stats is None:
            return self._unknown_lookup(
                indicator_type,
                indicator,
                summary=f"VirusTotal: unknown, no analysis results for {indicator}",
                details=_base_details(attributes, self.config.max_tags),
            )

        verdict = self._verdict_for(stats)
        details = {**_base_details(attributes, self.config.max_tags), **stats}
        details["total_engines"] = _total_engines(stats)
        details["found"] = True

        return IntelLookup(
            provider=self.name,
            indicator_type=indicator_type,
            indicator=indicator,
            verdict=verdict,
            summary=_build_summary(verdict, indicator, stats),
            risk_factors=_risk_factors(verdict, stats, details.get("tags", ())),
            details=details,
        )

    def _unknown_lookup(
        self,
        indicator_type: str,
        indicator: str,
        *,
        summary: str,
        details: JsonDict,
    ) -> IntelLookup:
        """Build an UNKNOWN lookup, used when VirusTotal has nothing to say.

        Inputs:
            indicator_type: Indicator type.
            indicator: Indicator value.
            summary: Analyst-readable summary.
            details: Bounded parsed details.

        Outputs:
            IntelLookup with an UNKNOWN verdict and no risk factors.
        """

        return IntelLookup(
            provider=self.name,
            indicator_type=indicator_type,
            indicator=indicator,
            verdict=IntelVerdict.UNKNOWN,
            summary=summary,
            risk_factors=(),
            details=details,
        )

    def _verdict_for(self, stats: dict[str, int]) -> IntelVerdict:
        """Map analysis counts onto a verdict.

        Inputs:
            stats: Integer counts keyed malicious, suspicious, harmless,
                undetected.

        Outputs:
            IntelVerdict. Nothing conclusive maps to UNKNOWN rather than BENIGN,
            since "no data" and "clean" are different claims.
        """

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious >= self.config.malicious_threshold:
            return IntelVerdict.MALICIOUS
        if malicious >= self.config.suspicious_threshold or suspicious >= self.config.suspicious_threshold:
            return IntelVerdict.SUSPICIOUS
        if malicious == 0 and harmless > 0:
            return IntelVerdict.BENIGN
        return IntelVerdict.UNKNOWN


def _http_failure(exc: urllib.error.HTTPError, url: str) -> VirusTotalError:
    """Translate an HTTPError into the right provider error.

    Inputs:
        exc: HTTPError raised by the opener.
        url: Requested URL, for the message.

    Outputs:
        VirusTotalError subclass to raise, or _NotFound for a 404.
    """

    message = _read_http_error(exc)

    if exc.code in {401, 403}:
        return VirusTotalAuthError(
            f"VirusTotal rejected the API key for {url} (HTTP {exc.code}): {message}. "
            f"Check that {API_KEY_SETTING} is set to a valid key with quota remaining"
        )
    if exc.code == 404:
        return _NotFound(f"VirusTotal has no record for {url}")
    if exc.code == 429:
        return VirusTotalRateLimitError(
            f"VirusTotal quota exhausted for {url}: HTTP 429: {message}"
        )
    return VirusTotalRequestError(f"VirusTotal request failed for {url}: HTTP {exc.code}: {message}")


def _read_http_error(exc: urllib.error.HTTPError) -> str:
    """Read an HTTP error body safely.

    Inputs:
        exc: HTTPError instance.

    Outputs:
        Body text, or the exception's own string form.
    """

    try:
        body = exc.read().decode("utf-8")
    except Exception:
        return str(exc)
    return body or str(exc)


def _is_retryable_error(exc: VirusTotalError) -> bool:
    """Return whether a failure is transient and worth retrying.

    Retryable: connection errors, timeouts, and HTTP 5xx. A rejected key, a
    missing record, and an exhausted quota are not: the first two cannot be fixed
    by repeating the call, and the free tier's quota resets on a timescale no
    in-run retry can wait out.

    Inputs:
        exc: VirusTotalError instance.

    Outputs:
        Boolean retry flag.
    """

    if isinstance(exc, VirusTotalAuthError | VirusTotalRateLimitError | _NotFound):
        return False

    message = str(exc).lower()
    retryable_markers = (
        "http 500",
        "http 502",
        "http 503",
        "http 504",
        "network error",
        "timed out",
    )
    return any(marker in message for marker in retryable_markers)


def _attributes(response: JsonDict) -> JsonDict:
    """Return data.attributes from a VirusTotal response.

    Inputs:
        response: Parsed response object.

    Outputs:
        Attributes object, empty when absent or the wrong shape.
    """

    data = response.get("data")
    if not isinstance(data, dict):
        return {}
    attributes = data.get("attributes")
    return attributes if isinstance(attributes, dict) else {}


def _analysis_stats(attributes: JsonDict) -> dict[str, int] | None:
    """Return the four analysis counts, or None when they are absent.

    Non-integer values are dropped rather than coerced: a count we cannot read is
    not the same as zero, and treating it as zero would understate detections.

    Inputs:
        attributes: VirusTotal attributes object.

    Outputs:
        Counts keyed malicious, suspicious, harmless, undetected, or None.
    """

    raw_stats = attributes.get("last_analysis_stats")
    if not isinstance(raw_stats, dict):
        return None

    stats: dict[str, int] = {}
    for key in ("malicious", "suspicious", "harmless", "undetected"):
        value = raw_stats.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        stats[key] = value

    return stats or None


def _total_engines(stats: dict[str, int]) -> int:
    """Return how many engines reported anything.

    Inputs:
        stats: Analysis counts.

    Outputs:
        Sum of the counts.
    """

    return sum(stats.values())


def _base_details(attributes: JsonDict, max_tags: int) -> JsonDict:
    """Build the bounded, non-count portion of the parsed details.

    Only tags and reputation are kept. The rest of a VirusTotal response — whois
    text, per-engine verdicts, resolution history — is kilobytes that would be
    cached and persisted for no analytical benefit.

    Inputs:
        attributes: VirusTotal attributes object.
        max_tags: Maximum tags to retain.

    Outputs:
        Details dictionary.
    """

    details: JsonDict = {}

    raw_tags = attributes.get("tags")
    if isinstance(raw_tags, list):
        tags = [str(tag) for tag in raw_tags if isinstance(tag, str | int | float)]
        if tags:
            details["tags"] = tags[:max_tags]
            if len(tags) > max_tags:
                details["tags_truncated"] = True

    reputation = attributes.get("reputation")
    if isinstance(reputation, int) and not isinstance(reputation, bool):
        details["reputation"] = reputation

    return details


def _build_summary(verdict: IntelVerdict, indicator: str, stats: dict[str, int]) -> str:
    """Build the one-line summary that reaches triage.

    This is the only enrichment field the model sees, so the verdict and the
    engine counts belong here rather than in details.

    Inputs:
        verdict: Verdict for this indicator.
        indicator: Indicator value.
        stats: Analysis counts.

    Outputs:
        Summary string.
    """

    total = _total_engines(stats)
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if verdict is IntelVerdict.MALICIOUS or (verdict is IntelVerdict.SUSPICIOUS and malicious):
        detail = f"{malicious} of {total} engines flagged {indicator}"
    elif verdict is IntelVerdict.SUSPICIOUS:
        detail = f"{suspicious} of {total} engines rated {indicator} suspicious"
    elif verdict is IntelVerdict.BENIGN:
        detail = f"no engine flagged {indicator}, {stats.get('harmless', 0)} of {total} rated it harmless"
    else:
        detail = f"no engine has an opinion on {indicator} across {total} results"

    if suspicious and verdict is not IntelVerdict.SUSPICIOUS:
        detail = f"{detail}, {suspicious} rated it suspicious"

    return f"VirusTotal: {verdict.value}, {detail}"


def _risk_factors(
    verdict: IntelVerdict,
    stats: dict[str, int],
    tags: Any,
) -> tuple[str, ...]:
    """Build short machine-readable factors justifying an escalating verdict.

    Only escalating verdicts get factors: local scoring boosts on any factor, so
    emitting one alongside a clean verdict would inflate scores.

    Inputs:
        verdict: Verdict for this indicator.
        stats: Analysis counts.
        tags: Capped tag list from the parsed details, if any.

    Outputs:
        Tuple of short tokens, empty for non-escalating verdicts.
    """

    if verdict not in {IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS}:
        return ()

    factors: list[str] = [f"{PROVIDER_NAME}_{verdict.value}"]
    if stats.get("malicious", 0):
        factors.append(f"{PROVIDER_NAME}_malicious_engines_{stats['malicious']}")
    if stats.get("suspicious", 0):
        factors.append(f"{PROVIDER_NAME}_suspicious_engines_{stats['suspicious']}")
    if isinstance(tags, list):
        factors.extend(f"{PROVIDER_NAME}_tag_{_slug(str(tag))}" for tag in tags[:3])

    return tuple(factors)


def _slug(value: str) -> str:
    """Reduce a provider tag to a short token safe for a risk factor.

    Inputs:
        value: Raw tag text.

    Outputs:
        Lowercase token with non-alphanumeric runs collapsed to underscores.
    """

    cleaned = "".join(char if char.isalnum() else "_" for char in value.strip().lower())
    return "_".join(part for part in cleaned.split("_") if part)[:32]
