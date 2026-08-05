"""Shodan host-exposure enrichment provider.

Shodan answers a different question than the reputation providers do. It reports
what an address *exposes* to the internet — open ports, banners, detected
products, and CVEs matched against those banners — and says nothing at all about
whether the host is malicious.

That difference is why this provider's verdict policy deliberately departs from
the others:

    - **`IntelVerdict.MALICIOUS` is never returned, under any circumstances.**
      A host with forty open ports is usually a cloud load balancer, not an
      attacker. Mapping exposure onto a reputation verdict would manufacture
      false positives at scale, and `mark_likely_benign` means nobody looks
      again, so the cost lands on real detections.
    - Known CVEs in `vulns` give `IntelVerdict.SUSPICIOUS`, because a matched
      vulnerability is at least a reason to look, even though a banner match is
      not proof of exploitability.
    - Everything else gives `IntelVerdict.UNKNOWN`, including a richly exposed
      host. UNKNOWN is the honest answer: Shodan has told us about exposure while
      saying nothing about maliciousness.
    - A 404 means Shodan has no record of the host. That is a normal result, not
      an error, so it is UNKNOWN rather than a raised exception.

Because the verdict carries so little, the *summary* carries the value here.
`soc.triage` withholds enrichment `raw` from the model, so the summary is the
only field that reaches triage: it is written as an analyst would write it, with
ports, organization, detected products, and CVEs enumerated up to a cap so it
stays one readable line.

Operational notes:

    - The API key travels as a query parameter, so any error text quoting the URL
      is redacted before it can reach an exception message or a log line.
    - `details` is a bounded parsed subset, never the raw host record. A Shodan
      host document can run to hundreds of kilobytes and this payload is cached
      and persisted.
    - Only connection errors, timeouts, and HTTP 5xx are retried. 429 is raised:
      the enricher's rate limiter, not a retry loop, is what respects quota.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from soc.threat_intel import IP_INDICATOR_TYPE, IntelLookup, IntelVerdict, ThreatIntelError

if TYPE_CHECKING:
    from soc.config import Settings

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

PROVIDER_NAME = "shodan"
"""Provider name used for caching, attribution, and rate limiting."""

DEFAULT_BASE_URL = "https://api.shodan.io"
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_RETRIES = 2
DEFAULT_RETRY_BACKOFF_SECONDS = 1.0
DEFAULT_MIN_SECONDS_BETWEEN_CALLS = 1.0
"""Shodan's free tier allows roughly one request per second."""

API_KEY_SETTING = "SHODAN_API_KEY"
"""Setting named in authentication failures so the fix is obvious."""

REDACTED = "[redacted]"

DEFAULT_MAX_PORTS = 20
DEFAULT_MAX_VULNS = 20
DEFAULT_MAX_HOSTNAMES = 10
DEFAULT_MAX_PRODUCTS = 10

SUMMARY_MAX_PORTS = 6
SUMMARY_MAX_VULNS = 3
SUMMARY_MAX_PRODUCTS = 3
SUMMARY_MAX_CHARS = 400
"""Kept under the 512-character truncation applied downstream."""

RISK_FACTOR_KNOWN_VULNS = "shodan_known_vulns"


class ShodanError(ThreatIntelError):
    """Base error for Shodan provider failures."""


class ShodanAuthError(ShodanError):
    """Raised when Shodan rejects the API key."""


class ShodanRequestError(ShodanError):
    """Raised when a Shodan request fails."""


@dataclass(frozen=True, slots=True)
class ShodanConfig:
    """Configuration for the Shodan host lookup API.

    Attributes:
        api_key: Shodan API key, sent as the `key` query parameter.
        base_url: API base URL, usually https://api.shodan.io.
        timeout_seconds: HTTP timeout in seconds.
        max_retries: Retry attempts after the first request, for transient
            failures only: connection errors, timeouts, and HTTP 5xx.
        retry_backoff_seconds: Base delay for exponential backoff between
            retries. Attempt N waits base * 2 ** N seconds.
        min_seconds_between_calls: Minimum spacing the enricher applies between
            calls to this provider.
        max_ports: Cap on ports kept in details.
        max_vulns: Cap on CVE identifiers kept in details.
        max_hostnames: Cap on hostnames kept in details.
        max_products: Cap on detected products kept in details.
    """

    api_key: str
    base_url: str = DEFAULT_BASE_URL
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES
    retry_backoff_seconds: float = DEFAULT_RETRY_BACKOFF_SECONDS
    min_seconds_between_calls: float = DEFAULT_MIN_SECONDS_BETWEEN_CALLS
    max_ports: int = DEFAULT_MAX_PORTS
    max_vulns: int = DEFAULT_MAX_VULNS
    max_hostnames: int = DEFAULT_MAX_HOSTNAMES
    max_products: int = DEFAULT_MAX_PRODUCTS

    def __post_init__(self) -> None:
        """Validate config.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            ShodanError: If any field is missing or out of range.
        """

        if not self.api_key.strip():
            raise ShodanError(f"Shodan API key cannot be empty; set {API_KEY_SETTING}")
        if not self.base_url.strip():
            raise ShodanError("Shodan base URL cannot be empty")
        if self.timeout_seconds <= 0:
            raise ShodanError("Shodan timeout_seconds must be greater than zero")
        if self.max_retries < 0:
            raise ShodanError("Shodan max_retries cannot be negative")
        if self.retry_backoff_seconds < 0:
            raise ShodanError("Shodan retry_backoff_seconds cannot be negative")
        if self.min_seconds_between_calls < 0:
            raise ShodanError("Shodan min_seconds_between_calls cannot be negative")
        for name in ("max_ports", "max_vulns", "max_hostnames", "max_products"):
            if getattr(self, name) <= 0:
                raise ShodanError(f"Shodan {name} must be greater than zero")

    @classmethod
    def from_settings(cls, settings: Settings) -> ShodanConfig:
        """Build config from application settings.

        Every field is read with getattr and a default so a Settings object that
        predates the Shodan keys still works.

        Inputs:
            settings: Application settings object exposing shodan_api_key.

        Outputs:
            ShodanConfig instance.

        Raises:
            ShodanError: If the API key is missing or a value is out of range.
        """

        return cls(
            api_key=str(getattr(settings, "shodan_api_key", "") or ""),
            base_url=str(getattr(settings, "shodan_base_url", DEFAULT_BASE_URL) or DEFAULT_BASE_URL),
            timeout_seconds=int(getattr(settings, "shodan_timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
            max_retries=int(getattr(settings, "shodan_max_retries", DEFAULT_MAX_RETRIES)),
            retry_backoff_seconds=float(
                getattr(settings, "shodan_retry_backoff_seconds", DEFAULT_RETRY_BACKOFF_SECONDS)
            ),
            min_seconds_between_calls=float(
                getattr(settings, "shodan_min_seconds_between_calls", DEFAULT_MIN_SECONDS_BETWEEN_CALLS)
            ),
        )


class ShodanClient:
    """Shodan host-exposure provider satisfying ThreatIntelProvider.

    Attributes:
        name: Provider name, shodan.
        supported_indicator_types: Only IP addresses; Shodan host lookups take
            no other indicator type.
        min_seconds_between_calls: Minimum spacing between calls, defaulting to
            one second to match the free tier.
    """

    name = PROVIDER_NAME
    supported_indicator_types = (IP_INDICATOR_TYPE,)
    min_seconds_between_calls = DEFAULT_MIN_SECONDS_BETWEEN_CALLS

    def __init__(
        self,
        config: ShodanConfig,
        *,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Initialize the provider.

        Inputs:
            config: Shodan connection, retry, and cap configuration.
            opener: Optional urlopen-compatible callable invoked as
                opener(request, timeout=..., context=...). Defaults to
                urllib.request.urlopen; tests inject a fake so no network is
                touched.
            sleep: Optional sleep callable used for retry backoff. Defaults to
                time.sleep; tests inject a recorder so no real time passes.

        Outputs:
            None.
        """

        self.config = config
        self.min_seconds_between_calls = config.min_seconds_between_calls
        self._opener = opener
        self._sleep = sleep
        # api.shodan.io is a public endpoint with a valid certificate, so TLS
        # verification is never configurable off: None means urllib's default
        # verifying context. The parameter is still passed so an injected opener
        # sees the same signature the other clients use.
        self._ssl_context = None

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> ShodanClient:
        """Build a provider from application settings.

        Inputs:
            settings: Application settings object exposing shodan_api_key.
            opener: Optional urlopen-compatible callable.
            sleep: Optional sleep callable for retry backoff.

        Outputs:
            ShodanClient instance.

        Raises:
            ShodanError: If the Shodan settings are unusable.
        """

        return cls(ShodanConfig.from_settings(settings), opener=opener, sleep=sleep)

    def lookup(self, indicator_type: str, indicator: str) -> IntelLookup:
        """Return Shodan's exposure context for one IP address.

        Inputs:
            indicator_type: Must be "ip".
            indicator: IP address to look up.

        Outputs:
            IntelLookup whose verdict is SUSPICIOUS when Shodan reports known
            CVEs and UNKNOWN otherwise. MALICIOUS is never returned.

        Raises:
            ShodanError: If the indicator type is unsupported, the indicator is
                empty, or the lookup fails.
        """

        if indicator_type != IP_INDICATOR_TYPE:
            raise ShodanError(
                f"Shodan supports only the {IP_INDICATOR_TYPE!r} indicator type, got {indicator_type!r}"
            )

        ip = indicator.strip()
        if not ip:
            raise ShodanError("Shodan lookup requires a non-empty IP address")

        host = self._fetch_host(ip)
        if host is None:
            return IntelLookup(
                provider=self.name,
                indicator_type=IP_INDICATOR_TYPE,
                indicator=ip,
                verdict=IntelVerdict.UNKNOWN,
                summary=f"Shodan: no exposure information for {ip}",
                details={"found": False},
            )

        return self._build_lookup(ip, host)

    def _build_lookup(self, ip: str, host: JsonDict) -> IntelLookup:
        """Turn one parsed host record into a lookup.

        Inputs:
            ip: IP address that was looked up.
            host: Shodan host response object.

        Outputs:
            IntelLookup instance.
        """

        details = self._parse_host(host)
        vulns = details["vulns"]

        if vulns:
            verdict = IntelVerdict.SUSPICIOUS
            risk_factors: tuple[str, ...] = (RISK_FACTOR_KNOWN_VULNS,)
        else:
            # Exposure alone is context, never a reputation judgment. See the
            # module docstring: a heavily exposed host stays UNKNOWN.
            verdict = IntelVerdict.UNKNOWN
            risk_factors = ()

        return IntelLookup(
            provider=self.name,
            indicator_type=IP_INDICATOR_TYPE,
            indicator=ip,
            verdict=verdict,
            summary=_build_summary(details),
            risk_factors=risk_factors,
            details=details,
        )

    def _parse_host(self, host: JsonDict) -> JsonDict:
        """Extract a bounded subset of one Shodan host record.

        A full host record can be hundreds of kilobytes and this payload is
        cached and persisted, so every list is capped.

        Inputs:
            host: Shodan host response object.

        Outputs:
            Bounded JSON-safe details dictionary.
        """

        ports = _int_list(host.get("ports"))
        vulns = _string_list(host.get("vulns"))
        hostnames = _string_list(host.get("hostnames"))
        products = _products(host.get("data"))

        return {
            "found": True,
            "ports": ports[: self.config.max_ports],
            "port_count": len(ports),
            "vulns": vulns[: self.config.max_vulns],
            "vuln_count": len(vulns),
            "hostnames": hostnames[: self.config.max_hostnames],
            "hostname_count": len(hostnames),
            "products": products[: self.config.max_products],
            "product_count": len(products),
            "org": _text(host.get("org")),
            "isp": _text(host.get("isp")),
            "os": _text(host.get("os")),
        }

    def _fetch_host(self, ip: str) -> JsonDict | None:
        """Fetch one Shodan host record, retrying transient failures.

        Inputs:
            ip: IP address to look up.

        Outputs:
            Parsed host object, or None when Shodan has no record (HTTP 404).

        Raises:
            ShodanAuthError: If the API key is rejected.
            ShodanRequestError: If the request keeps failing.
        """

        url = self._host_url(ip)
        attempts = self.config.max_retries + 1
        last_error: ShodanError | None = None

        for attempt in range(attempts):
            try:
                return self._request_once(url)
            except _HostNotFound:
                return None
            except ShodanError as exc:
                last_error = exc
                if attempt >= attempts - 1 or not _is_retryable_error(exc):
                    raise
                delay = self.config.retry_backoff_seconds * (2**attempt)
                logger.warning(
                    "Retrying Shodan host lookup for %s in %.2fs after transient failure: %s",
                    ip,
                    delay,
                    exc,
                )
                self._sleep_for(delay)

        raise ShodanRequestError(f"Shodan request failed after {attempts} attempt(s): {last_error}")

    def _request_once(self, url: str) -> JsonDict:
        """Send one host request and parse the JSON response.

        Inputs:
            url: Full request URL, including the key query parameter.

        Outputs:
            Parsed host object.

        Raises:
            _HostNotFound: On HTTP 404, meaning Shodan has no record.
            ShodanAuthError: On HTTP 401/403.
            ShodanRequestError: On any other HTTP, network, or parse failure.
        """

        safe_url = self._redact(url)
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json"},
            method="GET",
        )
        send = self._opener if self._opener is not None else urllib.request.urlopen

        try:
            with send(request, timeout=self.config.timeout_seconds, context=self._ssl_context) as response:
                text = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            self._raise_for_http_error(exc, safe_url)
        except urllib.error.URLError as exc:
            raise ShodanRequestError(
                f"Shodan network error for {safe_url}: {self._redact(str(exc.reason))}"
            ) from exc
        except TimeoutError as exc:
            raise ShodanRequestError(f"Shodan request timed out for {safe_url}") from exc

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ShodanRequestError(f"Shodan returned malformed JSON from {safe_url}: {exc}") from exc

        if not isinstance(parsed, dict):
            raise ShodanRequestError(f"Shodan returned non-object JSON from {safe_url}")

        return parsed

    def _raise_for_http_error(self, exc: urllib.error.HTTPError, safe_url: str) -> None:
        """Translate an HTTPError into the right Shodan failure.

        Inputs:
            exc: HTTPError raised by the opener.
            safe_url: Request URL with the API key already redacted.

        Outputs:
            None. This function always raises.

        Raises:
            _HostNotFound: On HTTP 404.
            ShodanAuthError: On HTTP 401/403.
            ShodanRequestError: On any other status.
        """

        message = self._redact(_read_http_error(exc))

        if exc.code == 404:
            # Shodan simply has nothing on this host. Normal, not a failure.
            raise _HostNotFound(safe_url)
        if exc.code in {401, 403}:
            raise ShodanAuthError(
                f"Shodan rejected the API key for {safe_url} (HTTP {exc.code}): {message}. "
                f"Check the {API_KEY_SETTING} setting."
            ) from exc
        if exc.code == 429:
            # Not retried: quota is the enricher's rate limiter to respect, and
            # hammering a throttled free tier only makes it worse.
            raise ShodanRequestError(
                f"Shodan rate limit exceeded for {safe_url} (HTTP 429): {message}"
            ) from exc

        raise ShodanRequestError(
            f"Shodan request failed for {safe_url}: HTTP {exc.code}: {message}"
        ) from exc

    def _host_url(self, ip: str) -> str:
        """Build the host endpoint URL for one IP address.

        Inputs:
            ip: IP address to look up.

        Outputs:
            Full URL including the key query parameter.
        """

        base = self.config.base_url.rstrip("/")
        query = urllib.parse.urlencode({"key": self.config.api_key})
        return f"{base}/shodan/host/{urllib.parse.quote(ip, safe='')}?{query}"

    def _redact(self, text: str) -> str:
        """Remove the API key from any text destined for a message or log.

        The key travels as a query parameter, so both the raw value and the
        `key=` parameter form are scrubbed. Anything that quotes the URL must go
        through this first.

        Inputs:
            text: Text that may contain the API key.

        Outputs:
            Text with the key replaced by a redaction marker.
        """

        return _redact_api_key(text, self.config.api_key)

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


class _HostNotFound(ShodanError):
    """Internal signal that Shodan has no record for the host (HTTP 404).

    Not part of the public surface: `lookup` converts it into an UNKNOWN
    verdict, because absence of a record is a normal answer.
    """


def lookup_ip(
    ip: str,
    config: ShodanConfig,
    *,
    opener: Callable[..., Any] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> IntelLookup:
    """Look up one IP address with a throwaway client.

    Inputs:
        ip: IP address to look up.
        config: Shodan configuration.
        opener: Optional urlopen-compatible callable.
        sleep: Optional sleep callable for retry backoff.

    Outputs:
        IntelLookup instance.

    Raises:
        ShodanError: If the lookup fails.
    """

    return ShodanClient(config, opener=opener, sleep=sleep).lookup(IP_INDICATOR_TYPE, ip)


def _build_summary(details: JsonDict) -> str:
    """Build the analyst-readable one-liner that reaches triage.

    This is the only enrichment field the model sees, and this provider's whole
    value is context rather than a verdict, so the ports, organization, detected
    products, and CVEs are all enumerated here — capped so the line stays
    readable and well inside the 512-character downstream truncation.

    Inputs:
        details: Bounded details produced by ShodanClient._parse_host.

    Outputs:
        Summary string.
    """

    parts: list[str] = []

    port_count = int(details.get("port_count", 0))
    if port_count:
        shown = details["ports"][:SUMMARY_MAX_PORTS]
        listed = ", ".join(str(port) for port in shown)
        if port_count > len(shown):
            listed = f"{listed}, +{port_count - len(shown)} more"
        parts.append(f"{port_count} open port{'s' if port_count != 1 else ''} ({listed})")
    else:
        parts.append("no open ports reported")

    # The organization reads as part of the exposure clause rather than as its
    # own comma-separated item: "3 open ports (22, 443) on Example Cloud".
    org = details.get("org") or details.get("isp")
    if org:
        parts[-1] = f"{parts[-1]} on {org}"

    products = details.get("products") or []
    if products:
        shown_products = products[:SUMMARY_MAX_PRODUCTS]
        listed_products = ", ".join(shown_products)
        product_count = int(details.get("product_count", len(products)))
        if product_count > len(shown_products):
            listed_products = f"{listed_products}, +{product_count - len(shown_products)} more"
        parts.append(f"services: {listed_products}")

    vuln_count = int(details.get("vuln_count", 0))
    if vuln_count:
        shown_vulns = details["vulns"][:SUMMARY_MAX_VULNS]
        listed_vulns = ", ".join(shown_vulns)
        if vuln_count > len(shown_vulns):
            listed_vulns = f"{listed_vulns}, +{vuln_count - len(shown_vulns)} more"
        parts.append(f"{vuln_count} known CVE{'s' if vuln_count != 1 else ''}: {listed_vulns}")
    else:
        # Said out loud so nobody reads a bare exposure summary as a clean
        # reputation result, and nobody reads it as a bad one either.
        parts.append("no known CVEs; exposure only, not a reputation verdict")

    summary = "Shodan: " + ", ".join(parts)
    if len(summary) > SUMMARY_MAX_CHARS:
        return summary[: SUMMARY_MAX_CHARS - 3].rstrip() + "..."
    return summary


def _products(data: Any) -> list[str]:
    """Extract detected product labels from a Shodan service list.

    Inputs:
        data: Value of the host record's `data` field.

    Outputs:
        Deduplicated "product (port)" labels in first-seen order.
    """

    if not isinstance(data, list):
        return []

    labels: list[str] = []
    seen: set[str] = set()
    for service in data:
        if not isinstance(service, dict):
            continue
        product = _text(service.get("product"))
        if not product:
            continue
        port = service.get("port")
        label = f"{product} ({port})" if isinstance(port, int) else product
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return labels


def _int_list(value: Any) -> list[int]:
    """Coerce a value into a sorted list of unique integers.

    Inputs:
        value: Candidate list of port numbers.

    Outputs:
        Sorted unique integers, empty when nothing is usable.
    """

    if not isinstance(value, list):
        return []

    numbers: set[int] = set()
    for item in value:
        if isinstance(item, bool):
            continue
        try:
            numbers.add(int(item))
        except (TypeError, ValueError):
            continue
    return sorted(numbers)


def _string_list(value: Any) -> list[str]:
    """Coerce a value into a sorted list of unique non-empty strings.

    Shodan sends `vulns` as either a list or a dictionary keyed by CVE, so both
    are accepted.

    Inputs:
        value: Candidate list or dictionary of strings.

    Outputs:
        Sorted unique strings, empty when nothing is usable.
    """

    if isinstance(value, dict):
        items: Any = list(value.keys())
    elif isinstance(value, list):
        items = value
    else:
        return []

    texts = {text for text in (_text(item) for item in items) if text}
    return sorted(texts)


def _text(value: Any) -> str:
    """Return a trimmed string for a scalar value.

    Inputs:
        value: Candidate value, possibly None.

    Outputs:
        Trimmed string, empty when the value is missing or not scalar.
    """

    if value is None or isinstance(value, (dict, list)):
        return ""
    return str(value).strip()


def _redact_api_key(text: str, api_key: str) -> str:
    """Replace an API key, and its query-parameter form, with a marker.

    Inputs:
        text: Text that may contain the key.
        api_key: Key to remove.

    Outputs:
        Redacted text.
    """

    if not api_key:
        return text

    redacted = text.replace(api_key, REDACTED)
    quoted = urllib.parse.quote(api_key, safe="")
    if quoted != api_key:
        redacted = redacted.replace(quoted, REDACTED)
    return redacted


def _is_retryable_error(exc: ShodanError) -> bool:
    """Return whether a Shodan failure is transient and worth retrying.

    Retryable: connection errors, timeouts, and HTTP 5xx. A rejected key cannot
    be fixed by retrying, and 429 deliberately is not retried either — quota is
    respected by spacing calls, not by hammering a throttled endpoint.

    Inputs:
        exc: ShodanError instance.

    Outputs:
        Boolean retry flag.
    """

    if isinstance(exc, ShodanAuthError):
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


def _read_http_error(exc: urllib.error.HTTPError) -> str:
    """Read an HTTP error body safely.

    Inputs:
        exc: HTTPError raised by the opener.

    Outputs:
        Body text, or the error's string form when the body is unreadable.
    """

    try:
        body = exc.read().decode("utf-8")
    except Exception:
        return str(exc)
    return body or str(exc)
