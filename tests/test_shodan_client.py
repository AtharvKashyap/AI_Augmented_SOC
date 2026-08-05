"""Tests for the Shodan host-exposure enrichment provider."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.parse
from typing import Any

import pytest

from soc.shodan_client import (
    ShodanClient,
    ShodanConfig,
    ShodanError,
)
from soc.threat_intel import IntelLookup, ThreatIntelEnricher

# Deliberately low-entropy and self-describing. A random-looking value here
# trips secret scanners on every commit, and this sentinel only needs to be
# distinctive enough to assert it never appears in an error or log line.
FAKE_KEY_SENTINEL = "fake-key-do-not-report"


class FakeHTTPResponse:
    """Small context-manager response object for urllib fakes."""

    def __init__(self, payload: Any) -> None:
        """Initialize fake response.

        Inputs:
            payload: JSON-serializable body, or a str/bytes body used verbatim.

        Outputs:
            None.
        """

        if isinstance(payload, bytes):
            self.body = payload
        elif isinstance(payload, str):
            self.body = payload.encode("utf-8")
        else:
            self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> FakeHTTPResponse:
        """Enter context manager."""

        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Exit context manager."""

    def read(self) -> bytes:
        """Return response body bytes."""

        return self.body


class FakeOpener:
    """Urlopen-compatible callable returning queued responses or errors."""

    def __init__(self, responses: list[Any]) -> None:
        """Initialize fake opener.

        Inputs:
            responses: Queue of payloads or exceptions, consumed in order.

        Outputs:
            None.
        """

        self.responses = list(responses)
        self.urls: list[str] = []
        self.timeouts: list[Any] = []

    def __call__(self, request: Any, *, timeout: Any = None, context: Any = None) -> Any:
        """Return the next queued response, raising queued exceptions.

        Inputs:
            request: urllib Request object.
            timeout: Request timeout.
            context: Optional SSL context.

        Outputs:
            FakeHTTPResponse instance.

        Raises:
            Exception: Whenever the queued item is an exception.
        """

        del context
        self.urls.append(request.full_url)
        self.timeouts.append(timeout)
        if not self.responses:
            raise AssertionError("FakeOpener ran out of queued responses")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return FakeHTTPResponse(item)


def _http_error(code: int, body: str = "") -> urllib.error.HTTPError:
    """Build an HTTPError with a readable body.

    Inputs:
        code: HTTP status code.
        body: Response body text.

    Outputs:
        urllib.error.HTTPError instance.
    """

    return urllib.error.HTTPError(
        url="https://api.shodan.io/shodan/host/203.0.113.10",
        code=code,
        msg=f"HTTP {code}",
        hdrs=None,
        fp=io.BytesIO(body.encode("utf-8")),
    )


def _config(**overrides: Any) -> ShodanConfig:
    """Return a test Shodan config.

    Inputs:
        overrides: Field overrides.

    Outputs:
        ShodanConfig instance.
    """

    values: dict[str, Any] = {"api_key": FAKE_KEY_SENTINEL, "timeout_seconds": 5, "retry_backoff_seconds": 0.0}
    values.update(overrides)
    return ShodanConfig(**values)


def _client(responses: list[Any], **overrides: Any) -> tuple[ShodanClient, FakeOpener, list[float]]:
    """Build a client wired to a fake opener and recording sleeper.

    Inputs:
        responses: Queue of payloads or exceptions for the fake opener.
        overrides: Config field overrides.

    Outputs:
        (client, opener, sleep_calls) tuple.
    """

    opener = FakeOpener(responses)
    sleeps: list[float] = []
    client = ShodanClient(_config(**overrides), opener=opener, sleep=sleeps.append)
    return client, opener, sleeps


def test_lookup_builds_host_url_with_key_query_parameter() -> None:
    """The request URL should be the host endpoint carrying the API key."""

    client, opener, _ = _client([{"ports": [443], "org": "Example Cloud"}])

    client.lookup("ip", "203.0.113.10")

    assert len(opener.urls) == 1
    parsed = urllib.parse.urlsplit(opener.urls[0])
    assert parsed.scheme == "https"
    assert parsed.netloc == "api.shodan.io"
    assert parsed.path == "/shodan/host/203.0.113.10"
    assert urllib.parse.parse_qs(parsed.query) == {"key": [FAKE_KEY_SENTINEL]}
    assert opener.timeouts == [5]


def test_provider_protocol_attributes() -> None:
    """The provider should advertise its name, types, and rate limit."""

    client, _, _ = _client([])

    assert client.name == "shodan"
    assert client.supported_indicator_types == ("ip",)
    assert client.min_seconds_between_calls == 1.0


def test_non_ip_indicator_type_raises() -> None:
    """A domain indicator is a programming error, not an UNKNOWN result."""

    client, opener, _ = _client([])

    with pytest.raises(ShodanError, match="ip"):
        client.lookup("domain", "evil.example")

    assert opener.urls == []


def _host(**overrides: Any) -> dict[str, Any]:
    """Return a representative Shodan host record.

    Inputs:
        overrides: Field overrides.

    Outputs:
        Host response dictionary.
    """

    host: dict[str, Any] = {
        "ip_str": "203.0.113.10",
        "ports": [22, 443, 8080],
        "org": "Example Cloud",
        "isp": "Example ISP",
        "hostnames": ["web01.example.com"],
        "os": None,
        "data": [
            {"port": 22, "product": "OpenSSH", "banner": "x" * 5000},
            {"port": 443, "product": "nginx"},
        ],
    }
    host.update(overrides)
    return host


def test_known_vulns_produce_suspicious_with_risk_factor() -> None:
    """CVEs reported by Shodan are worth looking at, so the verdict escalates."""

    host = _host(vulns=["CVE-2021-44228", "CVE-2022-22965"])
    client, _, _ = _client([host])

    lookup = client.lookup("ip", "203.0.113.10")

    assert lookup.verdict.value == "suspicious"
    assert "shodan_known_vulns" in lookup.risk_factors
    assert lookup.is_escalating is True
    assert "CVE-2021-44228" in lookup.summary
    assert "CVE-2022-22965" in lookup.summary
    assert lookup.details["vulns"] == ["CVE-2021-44228", "CVE-2022-22965"]


def test_no_vulns_produce_unknown_with_context_summary() -> None:
    """Exposure without CVEs is context, so the verdict stays UNKNOWN."""

    client, _, _ = _client([_host()])

    lookup = client.lookup("ip", "203.0.113.10")

    assert lookup.verdict.value == "unknown"
    assert lookup.risk_factors == ()
    assert lookup.is_escalating is False
    assert "22" in lookup.summary
    assert "443" in lookup.summary
    assert "8080" in lookup.summary
    assert "Example Cloud" in lookup.summary
    assert "OpenSSH" in lookup.summary
    assert lookup.details["port_count"] == 3
    assert lookup.details["org"] == "Example Cloud"


def test_heavily_exposed_host_without_vulns_is_not_escalated() -> None:
    """Forty open ports is a load balancer, not an attack. No escalation."""

    host = _host(
        ports=list(range(1, 41)),
        vulns=[],
        data=[{"port": port, "product": f"service-{port}"} for port in range(1, 41)],
    )
    client, _, _ = _client([host])

    lookup = client.lookup("ip", "203.0.113.10")

    assert lookup.verdict.value == "unknown"
    assert lookup.verdict.value != "malicious"
    assert lookup.verdict.value != "suspicious"
    assert lookup.risk_factors == ()
    assert lookup.is_escalating is False
    assert lookup.severity_hint == "info"


def test_malicious_is_never_returned_for_any_host_shape() -> None:
    """No host record, however alarming, may yield a MALICIOUS verdict."""

    shapes = [
        _host(vulns=["CVE-2021-44228"] * 5),
        _host(ports=list(range(1, 200)), vulns=[f"CVE-2024-{n:05d}" for n in range(50)]),
        _host(ports=[], vulns=["CVE-2019-0708"], org="", isp=""),
        {},
    ]
    client, _, _ = _client(shapes)

    for _ in shapes:
        lookup = client.lookup("ip", "203.0.113.10")
        assert lookup.verdict.value != "malicious"


def test_missing_host_returns_unknown_rather_than_raising() -> None:
    """HTTP 404 means Shodan has no record, which is a normal answer."""

    client, _, _ = _client([_http_error(404, "No information available for that IP.")])

    lookup = client.lookup("ip", "203.0.113.10")

    assert lookup.verdict.value == "unknown"
    assert lookup.risk_factors == ()
    assert lookup.details["found"] is False
    assert "203.0.113.10" in lookup.summary


@pytest.mark.parametrize("code", [401, 403])
def test_rejected_api_key_raises_actionably(code: int) -> None:
    """An auth failure must name the setting an operator has to fix."""

    client, _, sleeps = _client([_http_error(code, "Invalid API key")])

    with pytest.raises(ShodanError) as excinfo:
        client.lookup("ip", "203.0.113.10")

    message = str(excinfo.value)
    assert "SHODAN_API_KEY" in message
    assert str(code) in message
    assert sleeps == []


def test_rate_limited_lookup_raises() -> None:
    """HTTP 429 is raised so the enricher skips rather than hammering quota."""

    client, opener, sleeps = _client([_http_error(429, "Rate limit reached")])

    with pytest.raises(ShodanError, match="429"):
        client.lookup("ip", "203.0.113.10")

    assert len(opener.urls) == 1
    assert sleeps == []


def test_server_error_is_retried_then_succeeds() -> None:
    """A transient 5xx should be retried with backoff and then succeed."""

    client, opener, sleeps = _client(
        [_http_error(500, "upstream boom"), _host()],
        retry_backoff_seconds=0.5,
    )

    lookup = client.lookup("ip", "203.0.113.10")

    assert lookup.verdict.value == "unknown"
    assert len(opener.urls) == 2
    assert sleeps == [0.5]


def test_persistent_server_error_gives_up_after_bounded_retries() -> None:
    """Retries are bounded by max_retries; the failure is then raised."""

    client, opener, sleeps = _client(
        [_http_error(500, "boom") for _ in range(5)],
        max_retries=2,
        retry_backoff_seconds=0.25,
    )

    with pytest.raises(ShodanError, match="500"):
        client.lookup("ip", "203.0.113.10")

    assert len(opener.urls) == 3
    assert sleeps == [0.25, 0.5]


def test_network_error_is_retried() -> None:
    """Connection errors are transient and retried."""

    client, opener, _ = _client([urllib.error.URLError("connection refused"), _host()])

    client.lookup("ip", "203.0.113.10")

    assert len(opener.urls) == 2


def test_timeout_is_retried() -> None:
    """Timeouts are transient and retried."""

    client, opener, _ = _client([TimeoutError("read timed out"), _host()])

    client.lookup("ip", "203.0.113.10")

    assert len(opener.urls) == 2


def test_details_are_a_bounded_subset_of_the_host_record() -> None:
    """Details must be capped, not the whole host document."""

    host = _host(
        ports=list(range(1, 100)),
        vulns=[f"CVE-2024-{n:05d}" for n in range(60)],
        hostnames=[f"host{n}.example.com" for n in range(40)],
        data=[{"port": port, "product": f"service-{port:03d}"} for port in range(1, 100)],
    )
    client, _, _ = _client(
        [host],
        max_ports=5,
        max_vulns=4,
        max_hostnames=3,
        max_products=2,
    )

    details = client.lookup("ip", "203.0.113.10").details

    assert len(details["ports"]) == 5
    assert len(details["vulns"]) == 4
    assert len(details["hostnames"]) == 3
    assert len(details["products"]) == 2
    assert details["port_count"] == 99
    assert details["vuln_count"] == 60
    assert "data" not in details
    assert len(json.dumps(details)) < 2000


def test_summary_stays_short_for_a_huge_host_record() -> None:
    """The summary is one readable line even for an enormous host record."""

    host = _host(
        ports=list(range(1, 500)),
        vulns=[f"CVE-2024-{n:05d}" for n in range(200)],
        hostnames=[f"host{n}.example.com" for n in range(100)],
        data=[{"port": port, "product": f"service-with-a-long-name-{port:03d}"} for port in range(1, 500)],
    )
    client, _, _ = _client([host])

    summary = client.lookup("ip", "203.0.113.10").summary

    assert len(summary) <= 512
    assert "\n" not in summary
    assert summary.startswith("Shodan")


@pytest.mark.parametrize(
    "failure",
    [
        _http_error(401, "Invalid API key"),
        _http_error(403, "Access denied"),
        _http_error(429, "Rate limit reached"),
        _http_error(500, "boom"),
        urllib.error.URLError("connection refused"),
        TimeoutError("read timed out"),
        "not json at all",
        "[1, 2, 3]",
    ],
)
def test_api_key_never_appears_in_a_raised_exception(failure: Any) -> None:
    """The key travels in the URL, so no error text may ever leak it."""

    client, _, _ = _client([failure] * 4, max_retries=3, retry_backoff_seconds=0.0)

    with pytest.raises(ShodanError) as excinfo:
        client.lookup("ip", "203.0.113.10")

    rendered = f"{excinfo.value}{excinfo.value.args}{excinfo.value!r}"
    assert FAKE_KEY_SENTINEL not in rendered
    cause = excinfo.value.__cause__
    if cause is not None:
        assert FAKE_KEY_SENTINEL not in str(cause)


def test_api_key_never_appears_in_log_output(caplog: Any) -> None:
    """Retry logging quotes the failure, so it must be redacted too."""

    client, _, _ = _client([_http_error(500, "boom"), _host()])

    with caplog.at_level("DEBUG"):
        client.lookup("ip", "203.0.113.10")

    assert FAKE_KEY_SENTINEL not in caplog.text


def test_lookup_round_trips_through_payload() -> None:
    """The lookup must survive the cache serialization the enricher uses."""

    client, _, _ = _client([_host(vulns=["CVE-2021-44228"])])
    lookup = client.lookup("ip", "203.0.113.10")

    payload = lookup.to_payload()
    assert json.loads(json.dumps(payload)) == payload

    restored = IntelLookup.from_payload(payload)

    assert restored == lookup


def test_provider_fits_the_enricher_protocol() -> None:
    """Running through ThreatIntelEnricher proves the protocol actually fits."""

    client, _, _ = _client([_host(vulns=["CVE-2021-44228"])])
    enricher = ThreatIntelEnricher([client], sleep=lambda _seconds: None)

    results = enricher.enrich_indicators([("ip", "8.8.8.8")], target_id="alert-1")

    assert len(results) == 1
    assert results[0].provider == "shodan"
    assert results[0].indicator == "8.8.8.8"
    assert results[0].raw["verdict"] == "suspicious"
    assert results[0].raw["risk_factors"] == ["shodan_known_vulns"]
    assert "CVE-2021-44228" in results[0].summary


def test_vulns_reported_as_a_dictionary_are_understood() -> None:
    """Shodan sometimes keys vulns by CVE; both shapes must parse."""

    client, _, _ = _client([_host(vulns={"CVE-2021-44228": {"cvss": 10.0}})])

    lookup = client.lookup("ip", "203.0.113.10")

    assert lookup.verdict.value == "suspicious"
    assert lookup.details["vulns"] == ["CVE-2021-44228"]


def test_empty_indicator_raises() -> None:
    """A blank indicator is a programming error, not an empty lookup."""

    client, opener, _ = _client([])

    with pytest.raises(ShodanError):
        client.lookup("ip", "   ")

    assert opener.urls == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"api_key": ""},
        {"api_key": "   "},
        {"base_url": ""},
        {"timeout_seconds": 0},
        {"max_retries": -1},
        {"retry_backoff_seconds": -1.0},
        {"max_ports": 0},
        {"max_vulns": 0},
        {"max_hostnames": -1},
        {"max_products": 0},
    ],
)
def test_config_validation_rejects_bad_values(overrides: dict[str, Any]) -> None:
    """The config validates in __post_init__ rather than failing mid-request."""

    with pytest.raises(ShodanError):
        _config(**overrides)


def test_from_settings_is_defensive_about_missing_keys() -> None:
    """Only shodan_api_key is required; everything else falls back."""

    class BareSettings:
        """Settings object exposing nothing but the API key."""

        shodan_api_key = FAKE_KEY_SENTINEL

    client = ShodanClient.from_settings(BareSettings(), opener=FakeOpener([]))

    assert client.config.api_key == FAKE_KEY_SENTINEL
    assert client.config.base_url == "https://api.shodan.io"
    assert client.min_seconds_between_calls == 1.0


def test_from_settings_without_a_key_raises() -> None:
    """A missing key must fail loudly at construction, naming the setting."""

    class EmptySettings:
        """Settings object with a blank API key."""

        shodan_api_key = ""

    with pytest.raises(ShodanError, match="SHODAN_API_KEY"):
        ShodanClient.from_settings(EmptySettings())
