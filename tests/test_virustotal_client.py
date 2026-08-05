"""Tests for the VirusTotal threat-intel provider.

No test here performs a network call: every case injects a fake opener that
records the `urllib.request.Request` it was handed and returns a canned body,
mirroring the fake-transport style used for the Wazuh client.

Addresses used are genuinely routable (8.8.8.8) rather than RFC 5737
documentation ranges, because `ThreatIntelEnricher` withholds non-global
addresses from providers and a documentation range would make the end-to-end
test a no-op for the wrong reason.
"""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from soc.threat_intel import IntelLookup, IntelVerdict, ThreatIntelEnricher
from soc.virustotal_client import (
    VirusTotalClient,
    VirusTotalConfig,
    VirusTotalError,
    VirusTotalRequestError,
)


class FakeHTTPResponse:
    """Small context-manager response object for urllib fakes."""

    def __init__(self, body: str) -> None:
        """Initialize the fake response.

        Inputs:
            body: Response body text.

        Outputs:
            None.
        """

        self.body = body.encode("utf-8")

    def __enter__(self) -> FakeHTTPResponse:
        """Enter the context manager.

        Inputs:
            None.

        Outputs:
            This response object.
        """

        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Exit the context manager.

        Inputs:
            exc_type: Exception type, if any.
            exc: Exception instance, if any.
            traceback: Traceback, if any.

        Outputs:
            None.
        """

    def read(self) -> bytes:
        """Return the response body bytes.

        Inputs:
            None.

        Outputs:
            Body bytes.
        """

        return self.body


class RecordingOpener:
    """Fake opener returning queued responses and recording every request."""

    def __init__(self, responses: list[Any]) -> None:
        """Initialize the opener.

        Inputs:
            responses: Bodies or exceptions to return, in call order. A str is
                returned as a response body; an Exception is raised.

        Outputs:
            None.
        """

        self.responses = list(responses)
        self.requests: list[Any] = []

    def __call__(self, request: Any, *, timeout: float, context: Any = None) -> Any:
        """Record one request and return or raise the next queued response.

        Inputs:
            request: urllib Request object.
            timeout: Request timeout in seconds.
            context: Optional SSL context.

        Outputs:
            FakeHTTPResponse for the queued body.

        Raises:
            Exception: Whatever was queued for this call.
            AssertionError: If more calls were made than responses queued.
        """

        del timeout, context
        self.requests.append(request)
        assert self.responses, "opener called more times than responses queued"
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return FakeHTTPResponse(item)


def _http_error(code: int, body: str = "{}") -> urllib.error.HTTPError:
    """Build a urllib HTTPError with a readable body.

    Inputs:
        code: HTTP status code.
        body: Response body text.

    Outputs:
        HTTPError instance.
    """

    import io

    return urllib.error.HTTPError(
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        code,
        "error",
        {},
        io.BytesIO(body.encode("utf-8")),
    )


def _vt_body(
    *,
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 0,
    undetected: int = 0,
    tags: list[str] | None = None,
    reputation: int | None = None,
) -> str:
    """Build a VirusTotal v3 response body.

    Inputs:
        malicious: Engines calling the indicator malicious.
        suspicious: Engines calling it suspicious.
        harmless: Engines calling it harmless.
        undetected: Engines with no detection.
        tags: Optional VirusTotal tags.
        reputation: Optional community reputation score.

    Outputs:
        JSON body text.
    """

    attributes: dict[str, Any] = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        },
        "as_owner": "Example AS",
        "whois": "x" * 5000,
    }
    if tags is not None:
        attributes["tags"] = tags
    if reputation is not None:
        attributes["reputation"] = reputation
    return json.dumps({"data": {"id": "8.8.8.8", "type": "ip_address", "attributes": attributes}})


def _client(responses: list[Any], **overrides: Any) -> tuple[VirusTotalClient, RecordingOpener]:
    """Build a client wired to a recording opener.

    Inputs:
        responses: Bodies or exceptions the opener should yield.
        overrides: VirusTotalConfig field overrides.

    Outputs:
        (client, opener) pair.
    """

    config = VirusTotalConfig(api_key="vt-test-key", **overrides)
    opener = RecordingOpener(responses)
    sleeps: list[float] = []
    client = VirusTotalClient(config, opener=opener, sleep=sleeps.append)
    client.test_sleeps = sleeps  # type: ignore[attr-defined]
    return client, opener


def test_provider_attributes_match_protocol():
    """The client should expose the protocol attributes with free-tier spacing."""

    client, _ = _client([])

    assert client.name == "virustotal"
    assert client.supported_indicator_types == ("ip", "domain")
    assert client.min_seconds_between_calls == 15.0


def test_ip_lookup_builds_ip_addresses_url_and_sends_api_key_header():
    """An IP lookup should hit /ip_addresses/{ip} with the x-apikey header."""

    client, opener = _client([_vt_body(harmless=60)])

    client.lookup("ip", "8.8.8.8")

    request = opener.requests[0]
    assert request.full_url == "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    assert request.get_method() == "GET"
    assert request.get_header("X-apikey") == "vt-test-key"


def test_domain_lookup_builds_domains_url():
    """A domain lookup should hit /domains/{domain}."""

    client, opener = _client([_vt_body(harmless=60)])

    client.lookup("domain", "evil.example.com")

    assert opener.requests[0].full_url == "https://www.virustotal.com/api/v3/domains/evil.example.com"


def test_unsupported_indicator_type_raises():
    """An indicator type VirusTotal cannot answer should raise."""

    client, opener = _client([])

    with pytest.raises(VirusTotalError, match="indicator type"):
        client.lookup("hash", "deadbeef")

    assert opener.requests == []


def test_two_malicious_engines_is_malicious():
    """Two or more malicious engines should be reported as malicious."""

    client, _ = _client([_vt_body(malicious=5, harmless=63)])

    lookup = client.lookup("ip", "8.8.8.8")

    assert lookup.verdict is IntelVerdict.MALICIOUS
    assert lookup.risk_factors


def test_single_malicious_engine_is_suspicious_not_malicious():
    """One engine hit is usually a false positive, so it must be suspicious."""

    client, _ = _client([_vt_body(malicious=1, harmless=67)])

    lookup = client.lookup("ip", "8.8.8.8")

    assert lookup.verdict is IntelVerdict.SUSPICIOUS


def test_suspicious_engine_only_is_suspicious():
    """A suspicious-only hit should be suspicious."""

    client, _ = _client([_vt_body(malicious=0, suspicious=2, harmless=60)])

    lookup = client.lookup("ip", "8.8.8.8")

    assert lookup.verdict is IntelVerdict.SUSPICIOUS


def test_clean_stats_are_benign():
    """No malicious or suspicious hits with harmless votes should be benign."""

    client, _ = _client([_vt_body(harmless=68)])

    lookup = client.lookup("ip", "8.8.8.8")

    assert lookup.verdict is IntelVerdict.BENIGN


def test_all_zero_stats_are_unknown():
    """Stats with nothing at all in them should be unknown, never benign."""

    client, _ = _client([_vt_body(undetected=68)])

    lookup = client.lookup("ip", "8.8.8.8")

    assert lookup.verdict is IntelVerdict.UNKNOWN


def test_missing_analysis_stats_is_unknown():
    """A response without last_analysis_stats should be unknown."""

    body = json.dumps({"data": {"id": "8.8.8.8", "attributes": {"as_owner": "Example AS"}}})
    client, _ = _client([body])

    lookup = client.lookup("ip", "8.8.8.8")

    assert lookup.verdict is IntelVerdict.UNKNOWN
    assert lookup.risk_factors == ()


def test_verdict_thresholds_are_configurable():
    """Thresholds should live in config so they can be tuned."""

    client, _ = _client([_vt_body(malicious=1, harmless=67)], malicious_threshold=1)

    assert client.lookup("ip", "8.8.8.8").verdict is IntelVerdict.MALICIOUS


def test_config_rejects_invalid_values():
    """Config validation should reject unusable values."""

    with pytest.raises(VirusTotalError, match="API key"):
        VirusTotalConfig(api_key="")

    with pytest.raises(VirusTotalError, match="base URL"):
        VirusTotalConfig(api_key="k", base_url="")

    with pytest.raises(VirusTotalError, match="timeout"):
        VirusTotalConfig(api_key="k", timeout_seconds=0)

    with pytest.raises(VirusTotalError, match="max_retries"):
        VirusTotalConfig(api_key="k", max_retries=-1)

    with pytest.raises(VirusTotalError, match="malicious_threshold"):
        VirusTotalConfig(api_key="k", malicious_threshold=0)

    with pytest.raises(VirusTotalError, match="suspicious_threshold"):
        VirusTotalConfig(api_key="k", suspicious_threshold=0)


def test_summary_carries_verdict_and_engine_counts():
    """The summary is the only field triage sees, so it must state the verdict."""

    client, _ = _client([_vt_body(malicious=5, harmless=63)])

    summary = client.lookup("ip", "8.8.8.8").summary

    assert "malicious" in summary.lower()
    assert "5" in summary
    assert "68" in summary
    assert "8.8.8.8" in summary


def test_details_are_a_bounded_subset_with_capped_tags():
    """Details should hold parsed counts, capped tags, and no full response."""

    tags = [f"tag-{index}" for index in range(25)]
    client, _ = _client([_vt_body(malicious=3, harmless=60, tags=tags, reputation=-42)])

    details = client.lookup("ip", "8.8.8.8").details

    assert details["malicious"] == 3
    assert details["harmless"] == 60
    assert details["total_engines"] == 63
    assert details["reputation"] == -42
    assert details["tags"] == tags[:10]
    assert "whois" not in json.dumps(details)
    assert "data" not in details
    assert len(json.dumps(details)) < 1000


def test_lookup_round_trips_through_intel_lookup_payload():
    """The returned lookup must survive the cache serialization round trip."""

    client, _ = _client([_vt_body(malicious=4, harmless=60, tags=["malware"], reputation=-9)])

    lookup = client.lookup("ip", "8.8.8.8")
    restored = IntelLookup.from_payload(lookup.to_payload())

    assert restored == lookup


def test_http_404_is_unknown_rather_than_an_error():
    """A 404 means VirusTotal has no record: unknown, not an error, not benign."""

    client, _ = _client([_http_error(404, '{"error": {"code": "NotFoundError"}}')])

    lookup = client.lookup("ip", "8.8.8.8")

    assert lookup.verdict is IntelVerdict.UNKNOWN
    assert "no record" in lookup.summary.lower()


def test_http_401_raises_with_actionable_message():
    """A 401 should name the API key setting so the fix is obvious."""

    client, _ = _client([_http_error(401)])

    with pytest.raises(VirusTotalError, match="VIRUSTOTAL_API_KEY"):
        client.lookup("ip", "8.8.8.8")


def test_http_403_raises_with_actionable_message():
    """A 403 should also name the API key setting."""

    client, _ = _client([_http_error(403)])

    with pytest.raises(VirusTotalError, match="VIRUSTOTAL_API_KEY"):
        client.lookup("ip", "8.8.8.8")


def test_http_429_raises():
    """A quota exhaustion must raise so the enricher skips the indicator."""

    client, _ = _client([_http_error(429)])

    with pytest.raises(VirusTotalError, match="429"):
        client.lookup("ip", "8.8.8.8")


def test_http_429_is_not_retried():
    """The free-tier quota resets on a timescale no in-run retry can wait out."""

    client, opener = _client([_http_error(429), _vt_body(harmless=60)], max_retries=2)

    with pytest.raises(VirusTotalError):
        client.lookup("ip", "8.8.8.8")

    assert len(opener.requests) == 1


def test_transient_500_is_retried_then_succeeds():
    """A 5xx should be retried with backoff and the retry result used."""

    client, opener = _client([_http_error(500), _vt_body(malicious=3, harmless=60)], max_retries=2)

    lookup = client.lookup("ip", "8.8.8.8")

    assert lookup.verdict is IntelVerdict.MALICIOUS
    assert len(opener.requests) == 2
    assert client.test_sleeps == [1.0]


def test_connection_error_is_retried_then_succeeds():
    """A connection error should be retried, not surfaced immediately."""

    client, opener = _client([urllib.error.URLError("connection refused"), _vt_body(harmless=60)])

    assert client.lookup("ip", "8.8.8.8").verdict is IntelVerdict.BENIGN
    assert len(opener.requests) == 2


def test_persistent_500_gives_up_after_bounded_retries():
    """Retries are bounded: a persistent 5xx must raise rather than loop."""

    client, opener = _client([_http_error(500), _http_error(500), _http_error(500)], max_retries=2)

    with pytest.raises(VirusTotalRequestError, match="500"):
        client.lookup("ip", "8.8.8.8")

    assert len(opener.requests) == 3


def test_malformed_json_raises():
    """A non-JSON body must raise rather than be treated as no data."""

    client, _ = _client(["not json at all"])

    with pytest.raises(VirusTotalRequestError, match="malformed"):
        client.lookup("ip", "8.8.8.8")


def test_from_settings_reads_api_key_defensively():
    """from_settings should read settings with getattr defaults."""

    class Settings:
        """Minimal settings stand-in."""

        virustotal_api_key = "settings-key"
        enrichment_cache_ttl_hours = 12

    client = VirusTotalClient.from_settings(Settings())

    assert client.config.api_key == "settings-key"
    assert client.config.cache_ttl_hours == 12


def test_from_settings_requires_an_api_key():
    """A settings object with no key should raise rather than build a client."""

    class Settings:
        """Settings stand-in without a VirusTotal key."""

    with pytest.raises(VirusTotalError, match="API key"):
        VirusTotalClient.from_settings(Settings())


def test_provider_works_through_the_threat_intel_enricher():
    """The client must satisfy the provider protocol the enricher consumes."""

    client, _ = _client([_vt_body(malicious=6, harmless=60)])
    enricher = ThreatIntelEnricher([client], sleep=lambda _seconds: None)

    results = enricher.enrich_indicators([("ip", "8.8.8.8")], target_id="alert-1")

    assert len(results) == 1
    assert results[0].provider == "virustotal"
    assert results[0].indicator == "8.8.8.8"
    assert results[0].raw["verdict"] == "malicious"
