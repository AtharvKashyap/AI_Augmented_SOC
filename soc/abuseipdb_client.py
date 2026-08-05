
"""AbuseIPDB reputation provider for the threat-intel layer.

AbuseIPDB answers one question — how many people have reported this IP address,
and how confident is the aggregate — through `GET /api/v2/check`. That makes it a
cheap, high-signal second opinion on an external address, and a poor source of
anything else: it knows nothing about domains, hashes, or URLs.

Three decisions in here are worth knowing before changing anything:

    - **An explicit allowlist beats an aggregate score.** `isWhitelisted` wins
      outright, even against a 100% confidence score, because a whitelist entry is
      a human statement about a specific address while the score is a crowd
      average that a single mass-reporting campaign can move.
    - **Ambiguity is reported as UNKNOWN, never as MALICIOUS.** A missing or
      unparseable score means the provider had nothing to say. Guessing upwards
      would put a fabricated verdict into triage, which is worse than silence.
    - **Failures are raised, not smoothed over.** `ThreatIntelEnricher` catches and
      skips, so raising is how this provider declines to answer. Returning a
      neutral-looking verdict on an HTTP failure would make an outage
      indistinguishable from a clean result.

Thresholds live in `AbuseIPDBConfig` rather than as literals in the verdict
function, so tuning them is a config change instead of a code change.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from soc.threat_intel import IP_INDICATOR_TYPE, IntelLookup, IntelVerdict, ThreatIntelError

if TYPE_CHECKING:
    from soc.config import Settings

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

ABUSEIPDB_PROVIDER_NAME = "abuseipdb"
"""Provider name used for attribution and enrichment cache keys."""

DEFAULT_ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
"""Base URL of the AbuseIPDB v2 API."""

CHECK_PATH = "/check"
"""Endpoint path for a single-IP reputation check."""

DEFAULT_MAX_AGE_IN_DAYS = 90
"""Report window requested by default. AbuseIPDB allows 1-365."""

DEFAULT_MALICIOUS_SCORE = 75
"""Confidence score at or above which an address is called malicious."""

DEFAULT_SUSPICIOUS_SCORE = 25
"""Confidence score at or above which an address is called suspicious."""

DEFAULT_MIN_SECONDS_BETWEEN_CALLS = 1.0
"""Spacing between calls. The free tier is generous per day, not per second."""

MAX_DETAIL_TEXT_CHARS = 200
"""Cap on stored free-text fields, since details are cached and persisted."""

API_KEY_SETTING = "ABUSEIPDB_API_KEY"
"""Name of the setting an operator has to populate, quoted in error messages."""

RISK_FACTOR_HIGH_CONFIDENCE = "abuseipdb_high_confidence"
RISK_FACTOR_REPORTED_ABUSE = "abuseipdb_reported_abuse"

_RETRYABLE_STATUS_CODES = frozenset({408, 425, 500, 502, 503, 504})
"""Statuses a retry can plausibly fix. 429 is excluded on purpose: it means the
quota is gone, and hammering it wastes the remainder of the window."""


class HTTPOpener(Protocol):
    """Callable that performs one HTTP request, so tests can replace urllib."""

    def __call__(self, request: urllib.request.Request, *, timeout: float, context: Any) -> Any:
        """Send one request and return a context-manager response."""


class AbuseIPDBError(ThreatIntelError):
    """Base error for AbuseIPDB provider failures.

    Attributes:
        retryable: Whether retrying the same request could plausibly succeed.
    """

    retryable = False


class AbuseIPDBAuthError(AbuseIPDBError):
    """Raised when AbuseIPDB rejects the configured API key."""


class AbuseIPDBQuotaError(AbuseIPDBError):
    """Raised when the AbuseIPDB request quota has been exhausted."""


class AbuseIPDBRequestError(AbuseIPDBError):
    """Raised when an AbuseIPDB request fails or returns an unusable body."""

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
class AbuseIPDBConfig:
    """Configuration for the AbuseIPDB check endpoint.

    Attributes:
        api_key: AbuseIPDB API key, sent in the Key header.
        base_url: API base URL, without the endpoint path.
        max_age_in_days: Report window requested, 1-365.
        timeout_seconds: HTTP timeout in seconds.
        max_retries: Retry attempts after the first request, for transient
            failures only: connection errors, timeouts, and HTTP 5xx.
        retry_backoff_seconds: Base delay for exponential backoff. Attempt N
            waits base * 2 ** N seconds.
        malicious_score_threshold: Confidence score at or above which the verdict
            is malicious.
        suspicious_score_threshold: Confidence score at or above which the
            verdict is suspicious.
        min_seconds_between_calls: Minimum spacing the enricher enforces between
            calls to this provider.
    """

    api_key: str
    base_url: str = DEFAULT_ABUSEIPDB_BASE_URL
    max_age_in_days: int = DEFAULT_MAX_AGE_IN_DAYS
    timeout_seconds: int = 15
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0
    malicious_score_threshold: int = DEFAULT_MALICIOUS_SCORE
    suspicious_score_threshold: int = DEFAULT_SUSPICIOUS_SCORE
    min_seconds_between_calls: float = DEFAULT_MIN_SECONDS_BETWEEN_CALLS

    def __post_init__(self) -> None:
        """Validate config.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            AbuseIPDBError: If any field is unusable.
        """

        if not self.api_key.strip():
            raise AbuseIPDBError(f"AbuseIPDB api_key cannot be empty; set {API_KEY_SETTING}")
        if not self.base_url.strip():
            raise AbuseIPDBError("AbuseIPDB base_url cannot be empty")
        if self.timeout_seconds <= 0:
            raise AbuseIPDBError("AbuseIPDB timeout_seconds must be greater than zero")
        if self.max_retries < 0:
            raise AbuseIPDBError("AbuseIPDB max_retries cannot be negative")
        if self.retry_backoff_seconds < 0:
            raise AbuseIPDBError("AbuseIPDB retry_backoff_seconds cannot be negative")
        if not 1 <= self.max_age_in_days <= 365:
            raise AbuseIPDBError("AbuseIPDB max_age_in_days must be between 1 and 365")
        if not 1 <= self.malicious_score_threshold <= 100:
            raise AbuseIPDBError("AbuseIPDB malicious_score_threshold must be between 1 and 100")
        if not 1 <= self.suspicious_score_threshold <= 100:
            raise AbuseIPDBError("AbuseIPDB suspicious_score_threshold must be between 1 and 100")
        if self.suspicious_score_threshold > self.malicious_score_threshold:
            raise AbuseIPDBError(
                "AbuseIPDB suspicious_score_threshold cannot exceed malicious_score_threshold"
            )
        if self.min_seconds_between_calls < 0:
            raise AbuseIPDBError("AbuseIPDB min_seconds_between_calls cannot be negative")


class AbuseIPDBClient:
    """AbuseIPDB provider satisfying soc.threat_intel.ThreatIntelProvider.

    Attributes:
        name: Provider name used for attribution and caching.
        supported_indicator_types: Only ip; AbuseIPDB answers nothing else.
        min_seconds_between_calls: Spacing the enricher enforces, from config.
    """

    name = ABUSEIPDB_PROVIDER_NAME
    supported_indicator_types: tuple[str, ...] = (IP_INDICATOR_TYPE,)

    def __init__(
        self,
        config: AbuseIPDBConfig,
        *,
        opener: HTTPOpener | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Initialize the provider.

        Inputs:
            config: AbuseIPDB endpoint, retry, and threshold configuration.
            opener: Optional callable invoked as opener(request, timeout=...,
                context=...). Defaults to urllib.request.urlopen; tests inject a
                fake so no test touches the network.
            sleep: Optional sleep callable used for retry backoff. Defaults to
                time.sleep; tests inject a recorder so no real time passes.

        Outputs:
            None.
        """

        self.config = config
        self.min_seconds_between_calls = config.min_seconds_between_calls
        self._opener: HTTPOpener = opener or urllib.request.urlopen
        self._sleep = sleep or time.sleep

    @classmethod
    def from_settings(
        cls,
        settings: Settings | Any,
        *,
        opener: HTTPOpener | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> AbuseIPDBClient:
        """Build a provider from application settings.

        Every field except the API key is read with a `getattr` default, so this
        works against a Settings object that does not yet expose the optional
        tuning keys.

        Inputs:
            settings: Application settings exposing abuseipdb_api_key.
            opener: Optional HTTP opener, as the constructor documents.
            sleep: Optional sleep callable, as the constructor documents.

        Outputs:
            AbuseIPDBClient instance.

        Raises:
            AbuseIPDBError: If no API key is configured, or a configured value is
                unusable.
        """

        api_key = _coerce_text(getattr(settings, "abuseipdb_api_key", ""))
        if not api_key:
            raise AbuseIPDBError(f"AbuseIPDB enrichment requires {API_KEY_SETTING} to be set")

        config = AbuseIPDBConfig(
            api_key=api_key,
            base_url=_coerce_text(getattr(settings, "abuseipdb_base_url", "")) or DEFAULT_ABUSEIPDB_BASE_URL,
            max_age_in_days=_coerce_int(
                getattr(settings, "abuseipdb_max_age_in_days", None),
                DEFAULT_MAX_AGE_IN_DAYS,
            ),
            timeout_seconds=_coerce_int(getattr(settings, "abuseipdb_timeout_seconds", None), 15),
            max_retries=_coerce_int(getattr(settings, "abuseipdb_max_retries", None), 2),
            retry_backoff_seconds=_coerce_float(
                getattr(settings, "abuseipdb_retry_backoff_seconds", None),
                1.0,
            ),
            malicious_score_threshold=_coerce_int(
                getattr(settings, "abuseipdb_malicious_score", None),
                DEFAULT_MALICIOUS_SCORE,
            ),
            suspicious_score_threshold=_coerce_int(
                getattr(settings, "abuseipdb_suspicious_score", None),
                DEFAULT_SUSPICIOUS_SCORE,
            ),
            min_seconds_between_calls=_coerce_float(
                getattr(settings, "abuseipdb_min_seconds_between_calls", None),
                DEFAULT_MIN_SECONDS_BETWEEN_CALLS,
            ),
        )
        return cls(config, opener=opener, sleep=sleep)

    def lookup(self, indicator_type: str, indicator: str) -> IntelLookup:
        """Return the AbuseIPDB verdict for one indicator.

        Inputs:
            indicator_type: Must be "ip"; anything else is a programming error,
                since the enricher already filters by supported_indicator_types.
            indicator: IP address to check.

        Outputs:
            IntelLookup whose summary states the verdict, confidence score, and
            report count, because triage sees only the summary.

        Raises:
            AbuseIPDBError: If the indicator is unusable for this provider.
            AbuseIPDBAuthError: If the API key is rejected.
            AbuseIPDBQuotaError: If the request quota is exhausted.
            AbuseIPDBRequestError: If the request keeps failing or the response
                cannot be parsed.
        """

        ip_address = self._validate_indicator(indicator_type, indicator)
        data = self._check(ip_address)
        return self._build_lookup(ip_address, data)

    def _validate_indicator(self, indicator_type: str, indicator: str) -> str:
        """Validate and normalize one indicator before any request is sent.

        Inputs:
            indicator_type: Indicator type supplied by the caller.
            indicator: Indicator value supplied by the caller.

        Outputs:
            Normalized IP address string.

        Raises:
            AbuseIPDBError: If the type is unsupported or the value is not an IP.
        """

        normalized_type = indicator_type.strip().lower()
        if normalized_type != IP_INDICATOR_TYPE:
            raise AbuseIPDBError(
                f"AbuseIPDB supports only the 'ip' indicator type, got {indicator_type!r}"
            )

        candidate = indicator.strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise AbuseIPDBError(f"AbuseIPDB needs a valid IP address, got {indicator!r}") from exc

    def _check(self, ip_address: str) -> JsonDict:
        """Call the check endpoint, retrying transient failures.

        Connection errors, timeouts, and HTTP 5xx are retried up to
        config.max_retries times with exponential backoff. Everything else,
        including 401/403 and 429, is raised immediately: no retry fixes a bad
        key or an exhausted quota.

        Inputs:
            ip_address: Normalized IP address.

        Outputs:
            The response's `data` object.

        Raises:
            AbuseIPDBAuthError: If the API key is rejected.
            AbuseIPDBQuotaError: If the quota is exhausted.
            AbuseIPDBRequestError: If the request keeps failing.
        """

        url = self._build_check_url(ip_address)
        attempts = self.config.max_retries + 1
        last_error: AbuseIPDBError | None = None

        for attempt in range(attempts):
            try:
                return self._check_once(url)
            except AbuseIPDBError as exc:
                last_error = exc
                if attempt >= attempts - 1 or not exc.retryable:
                    raise
                delay = self.config.retry_backoff_seconds * (2**attempt)
                logger.warning(
                    "Retrying AbuseIPDB check for %s in %.2fs after transient failure: %s",
                    ip_address,
                    delay,
                    exc,
                )
                self._sleep(delay)

        raise AbuseIPDBRequestError(
            f"AbuseIPDB check failed after {attempts} attempt(s): {last_error}"
        )

    def _check_once(self, url: str) -> JsonDict:
        """Send one check request and return its parsed data object.

        Inputs:
            url: Fully built check URL.

        Outputs:
            The response's `data` object.

        Raises:
            AbuseIPDBAuthError: If the API key is rejected.
            AbuseIPDBQuotaError: If the quota is exhausted.
            AbuseIPDBRequestError: On any other failure or unusable body.
        """

        request = urllib.request.Request(
            url,
            headers={"Key": self.config.api_key, "Accept": "application/json"},
            method="GET",
        )

        try:
            with self._opener(request, timeout=self.config.timeout_seconds, context=None) as response:
                text = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise _http_error_to_exception(exc) from exc
        except urllib.error.URLError as exc:
            raise AbuseIPDBRequestError(
                f"AbuseIPDB network error for {CHECK_PATH}: {exc.reason}",
                retryable=True,
            ) from exc
        except TimeoutError as exc:
            raise AbuseIPDBRequestError(
                f"AbuseIPDB request timed out for {CHECK_PATH}",
                retryable=True,
            ) from exc

        return _parse_check_body(text)

    def _build_check_url(self, ip_address: str) -> str:
        """Build the check URL with both required query parameters.

        Inputs:
            ip_address: Normalized IP address.

        Outputs:
            Fully qualified URL.
        """

        query = urllib.parse.urlencode(
            {"ipAddress": ip_address, "maxAgeInDays": str(self.config.max_age_in_days)}
        )
        return f"{self.config.base_url.rstrip('/')}{CHECK_PATH}?{query}"

    def _build_lookup(self, ip_address: str, data: JsonDict) -> IntelLookup:
        """Turn one parsed data object into an IntelLookup.

        Inputs:
            ip_address: Normalized IP address that was checked.
            data: The response's `data` object.

        Outputs:
            IntelLookup instance.
        """

        score = _coerce_optional_int(data.get("abuseConfidenceScore"))
        reports = _coerce_int(data.get("totalReports"), 0)
        is_whitelisted = data.get("isWhitelisted") is True
        usage_type = _coerce_text(data.get("usageType"))
        isp = _coerce_text(data.get("isp"))
        country_code = _coerce_text(data.get("countryCode")).upper()
        domain = _coerce_text(data.get("domain"))

        verdict = self._decide_verdict(score=score, reports=reports, is_whitelisted=is_whitelisted)
        return IntelLookup(
            provider=self.name,
            indicator_type=IP_INDICATOR_TYPE,
            indicator=ip_address,
            verdict=verdict,
            summary=_build_summary(
                verdict=verdict,
                score=score,
                reports=reports,
                usage_type=usage_type,
                country_code=country_code,
                is_whitelisted=is_whitelisted,
            ),
            risk_factors=self._build_risk_factors(verdict=verdict, score=score),
            details={
                "abuse_confidence_score": score,
                "total_reports": reports,
                "usage_type": _truncate(usage_type),
                "isp": _truncate(isp),
                "country_code": country_code,
                "is_whitelisted": is_whitelisted,
                "domain": _truncate(domain),
                "max_age_in_days": self.config.max_age_in_days,
            },
        )

    def _decide_verdict(self, *, score: int | None, reports: int, is_whitelisted: bool) -> IntelVerdict:
        """Apply the verdict policy to one parsed response.

        An allowlist entry wins outright. Otherwise the confidence score decides,
        and a zero score with zero reports is the only positive statement of
        cleanliness AbuseIPDB can make. Everything else, including a missing
        score, is UNKNOWN: guessing upwards would fabricate evidence.

        Inputs:
            score: Abuse confidence score, or None when absent.
            reports: Total report count.
            is_whitelisted: Whether AbuseIPDB explicitly allowlists the address.

        Outputs:
            IntelVerdict value.
        """

        if is_whitelisted:
            return IntelVerdict.BENIGN
        if score is None:
            return IntelVerdict.UNKNOWN
        if score >= self.config.malicious_score_threshold:
            return IntelVerdict.MALICIOUS
        if score >= self.config.suspicious_score_threshold:
            return IntelVerdict.SUSPICIOUS
        if score == 0 and reports == 0:
            return IntelVerdict.BENIGN
        return IntelVerdict.UNKNOWN

    def _build_risk_factors(self, *, verdict: IntelVerdict, score: int | None) -> tuple[str, ...]:
        """Build the machine-readable factors that justify an escalation.

        Only escalating verdicts produce factors. Local scoring boosts on any
        risk factor, so emitting one alongside a clean verdict would inflate
        scores; the threat-intel layer strips them defensively as well.

        Inputs:
            verdict: Verdict already decided for this response.
            score: Abuse confidence score, or None.

        Outputs:
            Tuple of short factor tokens, possibly empty.
        """

        if score is None:
            return ()
        if verdict is IntelVerdict.MALICIOUS:
            return (RISK_FACTOR_HIGH_CONFIDENCE,)
        if verdict is IntelVerdict.SUSPICIOUS:
            return (RISK_FACTOR_REPORTED_ABUSE,)
        return ()


def _build_summary(
    *,
    verdict: IntelVerdict,
    score: int | None,
    reports: int,
    usage_type: str,
    country_code: str,
    is_whitelisted: bool,
) -> str:
    """Build the analyst-readable one-liner that reaches triage.

    `soc.triage` withholds enrichment raw payloads from the model, so this string
    is the only place the verdict, the score, and the report count can travel.

    Inputs:
        verdict: Decided verdict.
        score: Abuse confidence score, or None when absent.
        reports: Total report count.
        usage_type: AbuseIPDB usage type, possibly empty.
        country_code: Two-letter country code, possibly empty.
        is_whitelisted: Whether the address is explicitly allowlisted.

    Outputs:
        Summary string, for example
        "AbuseIPDB: malicious, 92% confidence from 140 reports, data center in DE".
    """

    parts = [f"AbuseIPDB: {verdict.value}"]
    if score is None:
        parts.append("no confidence score reported")
    else:
        parts.append(f"{score}% confidence from {reports} reports")
    if is_whitelisted:
        parts.append("explicitly whitelisted")

    context = _context_clause(usage_type, country_code)
    if context:
        parts.append(context)
    return ", ".join(parts)


def _context_clause(usage_type: str, country_code: str) -> str:
    """Describe where and what the address is, when AbuseIPDB says.

    Inputs:
        usage_type: AbuseIPDB usage type, possibly empty.
        country_code: Two-letter country code, possibly empty.

    Outputs:
        Clause such as "hosting provider in DE", or an empty string.
    """

    descriptor = _truncate(usage_type).lower()
    if descriptor and country_code:
        return f"{descriptor} in {country_code}"
    if descriptor:
        return descriptor
    if country_code:
        return f"in {country_code}"
    return ""


def _parse_check_body(text: str) -> JsonDict:
    """Parse a check response body into its data object.

    Inputs:
        text: Raw response body.

    Outputs:
        The `data` object.

    Raises:
        AbuseIPDBRequestError: If the body is not JSON or has no data object.
    """

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AbuseIPDBRequestError(f"AbuseIPDB returned malformed JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise AbuseIPDBRequestError("AbuseIPDB returned non-object JSON")

    data = parsed.get("data")
    if not isinstance(data, dict):
        raise AbuseIPDBRequestError("AbuseIPDB response contained no data object")

    return data


def _http_error_to_exception(exc: urllib.error.HTTPError) -> AbuseIPDBError:
    """Map an HTTP failure onto the right provider error.

    401/403 name the setting to fix, 429 says the quota is gone, and only 5xx and
    a few transient statuses are marked retryable.

    Inputs:
        exc: HTTPError raised by the opener.

    Outputs:
        AbuseIPDBError subclass instance, ready to raise.
    """

    message = _read_http_error(exc)
    if exc.code in {401, 403}:
        return AbuseIPDBAuthError(
            f"AbuseIPDB rejected the API key (HTTP {exc.code}); "
            f"check that {API_KEY_SETTING} is set to a valid key: {message}"
        )
    if exc.code == 429:
        return AbuseIPDBQuotaError(
            f"AbuseIPDB rate limit or daily quota exhausted (HTTP 429); "
            f"no further lookups will succeed until the quota resets: {message}"
        )
    return AbuseIPDBRequestError(
        f"AbuseIPDB request failed: HTTP {exc.code}: {message}",
        retryable=exc.code in _RETRYABLE_STATUS_CODES,
    )


def _read_http_error(exc: urllib.error.HTTPError) -> str:
    """Read an HTTP error body safely.

    Inputs:
        exc: HTTPError instance.

    Outputs:
        Body text, or the error's string form when the body cannot be read.
    """

    try:
        body = exc.read().decode("utf-8")
    except Exception:
        return str(exc)
    return body or str(exc)


def _truncate(value: str) -> str:
    """Cap one free-text field, since details are cached and persisted.

    Inputs:
        value: Text value.

    Outputs:
        Text no longer than MAX_DETAIL_TEXT_CHARS.
    """

    if len(value) <= MAX_DETAIL_TEXT_CHARS:
        return value
    return value[:MAX_DETAIL_TEXT_CHARS]


def _coerce_text(value: Any) -> str:
    """Coerce any value into a stripped string.

    Inputs:
        value: Value of any type, possibly None.

    Outputs:
        Stripped string, empty when the value was None.
    """

    if value is None:
        return ""
    return str(value).strip()


def _coerce_optional_int(value: Any) -> int | None:
    """Coerce a value into an int, or None when it is absent or unusable.

    Inputs:
        value: Value of any type.

    Outputs:
        Integer, or None.
    """

    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_int(value: Any, default: int) -> int:
    """Coerce a value into an int, falling back to a default.

    Inputs:
        value: Value of any type.
        default: Value used when coercion fails.

    Outputs:
        Integer.
    """

    coerced = _coerce_optional_int(value)
    return default if coerced is None else coerced


def _coerce_float(value: Any, default: float) -> float:
    """Coerce a value into a float, falling back to a default.

    Inputs:
        value: Value of any type.
        default: Value used when coercion fails.

    Outputs:
        Float.
    """

    if value is None or isinstance(value, bool):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
