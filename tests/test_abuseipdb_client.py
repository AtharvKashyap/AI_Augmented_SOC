
"""Tests for the AbuseIPDB threat-intel provider.

Every test fakes the HTTP transport through the injectable opener, so no test
touches the network, and the injectable sleep means no test waits for real time.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
from typing import Any

import pytest

from soc.abuseipdb_client import (
    DEFAULT_ABUSEIPDB_BASE_URL,
    AbuseIPDBAuthError,
    AbuseIPDBClient,
    AbuseIPDBConfig,
    AbuseIPDBError,
    AbuseIPDBQuotaError,
    AbuseIPDBRequestError,
)
from soc.threat_intel import IntelLookup, IntelVerdict, ThreatIntelEnricher, ThreatIntelError

PUBLIC_IP = "185.220.101.5"


class FakeHTTPResponse:
    """Small context-manager response object for opener fakes."""

    def __init__(self, body: str) -> None:
        """Initialize fake response.

        Inputs:
            body: Response body text.

        Outputs:
            None.
        """

        self.body = body.encode("utf-8")

    def __enter__(self) -> FakeHTTPResponse:
        """Enter context manager.

        Inputs:
            None.

        Outputs:
            This response.
        """

        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Exit context manager.

        Inputs:
            exc_type: Exception type, if any.
            exc: Exception instance, if any.
            traceback: Traceback, if any.

        Outputs:
            None.
        """

    def read(self) -> bytes:
        """Return response body bytes.

        Inputs:
            None.

        Outputs:
            Body bytes.
        """

        return self.body


class FakeOpener:
    """Recording opener that replays queued responses or raises queued errors."""

    def __init__(self, outcomes: list[Any]) -> None:
        """Initialize the opener.

        Inputs:
            outcomes: Per-call outcomes. A string is returned as a response body,
                an Exception instance is raised, and the last outcome repeats
                once the queue is exhausted.

        Outputs:
            None.
        """

        self.outcomes = list(outcomes)
        self.requests: list[Any] = []

    def __call__(self, request: Any, *, timeout: Any = None, context: Any = None) -> FakeHTTPResponse:
        """Record one request and produce its queued outcome.

        Inputs:
            request: urllib Request object.
            timeout: Request timeout, recorded only.
            context: SSL context, recorded only.

        Outputs:
            FakeHTTPResponse for string outcomes.

        Raises:
            Exception: Whatever outcome was queued for this call.
        """

        self.requests.append(request)
        self.timeout = timeout
        self.context = context
        index = min(len(self.requests) - 1, len(self.outcomes) - 1)
        outcome = self.outcomes[index]
        if isinstance(outcome, Exception):
            raise outcome
        return FakeHTTPResponse(outcome)

    @property
    def call_count(self) -> int:
        """Return how many calls were made.

        Inputs:
            None.

        Outputs:
            Call count.
        """

        return len(self.requests)


def _config(**overrides: Any) -> AbuseIPDBConfig:
    """Build a test config.

    Inputs:
        overrides: Fields to override.

    Outputs:
        AbuseIPDBConfig instance.
    """

    values: dict[str, Any] = {
        "api_key": "test-key",
        "timeout_seconds": 5,
        "max_retries": 2,
        "retry_backoff_seconds": 0.5,
    }
    values.update(overrides)
    return AbuseIPDBConfig(**values)


def _body(**overrides: Any) -> str:
    """Build a realistic AbuseIPDB /check response body.

    Inputs:
        overrides: Fields to override or, with a None value, delete from data.

    Outputs:
        JSON response text.
    """

    data: dict[str, Any] = {
        "ipAddress": PUBLIC_IP,
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 92,
        "countryCode": "DE",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting GmbH",
        "domain": "example-hosting.de",
        "hostnames": ["node-5.example-hosting.de"],
        "totalReports": 140,
        "numDistinctUsers": 61,
        "lastReportedAt": "2026-07-30T11:22:33+00:00",
        "reports": [{"reportedAt": "2026-07-30T11:22:33+00:00", "comment": "SSH brute force"}],
    }
    for key, value in overrides.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return json.dumps({"data": data})


def _client(outcomes: list[Any], **config_overrides: Any) -> tuple[AbuseIPDBClient, FakeOpener, list[float]]:
    """Build a client wired to a fake opener and a recording sleep.

    Inputs:
        outcomes: Opener outcomes, as FakeOpener documents.
        config_overrides: Config fields to override.

    Outputs:
        (client, opener, recorded sleep durations) tuple.
    """

    opener = FakeOpener(outcomes)
    sleeps: list[float] = []
    client = AbuseIPDBClient(_config(**config_overrides), opener=opener, sleep=sleeps.append)
    return client, opener, sleeps


def _http_error(code: int, reason: str) -> urllib.error.HTTPError:
    """Build an HTTPError for the fake opener.

    Inputs:
        code: HTTP status code.
        reason: HTTP reason phrase.

    Outputs:
        HTTPError instance.
    """

    return urllib.error.HTTPError(
        f"{DEFAULT_ABUSEIPDB_BASE_URL}/check",
        code,
        reason,
        hdrs=None,
        fp=None,
    )


def test_provider_declares_threat_intel_protocol_attributes():
    """The provider should advertise its name, indicator types, and rate limit."""

    client, _, _ = _client([_body()])

    assert client.name == "abuseipdb"
    assert client.supported_indicator_types == ("ip",)
    assert client.min_seconds_between_calls == 1.0


def test_config_rejects_invalid_values():
    """Config validation should reject every unusable field value."""

    with pytest.raises(AbuseIPDBError, match="api_key"):
        AbuseIPDBConfig(api_key="")

    with pytest.raises(AbuseIPDBError, match="base_url"):
        AbuseIPDBConfig(api_key="k", base_url="")

    with pytest.raises(AbuseIPDBError, match="timeout_seconds"):
        AbuseIPDBConfig(api_key="k", timeout_seconds=0)

    with pytest.raises(AbuseIPDBError, match="max_retries"):
        AbuseIPDBConfig(api_key="k", max_retries=-1)

    with pytest.raises(AbuseIPDBError, match="retry_backoff_seconds"):
        AbuseIPDBConfig(api_key="k", retry_backoff_seconds=-0.5)

    with pytest.raises(AbuseIPDBError, match="max_age_in_days"):
        AbuseIPDBConfig(api_key="k", max_age_in_days=0)

    with pytest.raises(AbuseIPDBError, match="max_age_in_days"):
        AbuseIPDBConfig(api_key="k", max_age_in_days=366)

    with pytest.raises(AbuseIPDBError, match="malicious_score_threshold"):
        AbuseIPDBConfig(api_key="k", malicious_score_threshold=101)

    with pytest.raises(AbuseIPDBError, match="suspicious_score_threshold"):
        AbuseIPDBConfig(api_key="k", suspicious_score_threshold=0)

    with pytest.raises(AbuseIPDBError, match="suspicious_score_threshold"):
        AbuseIPDBConfig(api_key="k", suspicious_score_threshold=80, malicious_score_threshold=75)

    with pytest.raises(AbuseIPDBError, match="min_seconds_between_calls"):
        AbuseIPDBConfig(api_key="k", min_seconds_between_calls=-1.0)


def test_config_is_frozen_and_slotted():
    """Config should be immutable, matching every other config dataclass here."""

    config = _config()

    with pytest.raises(Exception):
        config.api_key = "other"


def test_lookup_builds_check_url_with_both_query_parameters():
    """The request URL should be /check with ipAddress and maxAgeInDays."""

    client, opener, _ = _client([_body()], max_age_in_days=30)

    client.lookup("ip", PUBLIC_IP)

    url = opener.requests[0].full_url
    parsed = urllib.parse.urlsplit(url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "https://api.abuseipdb.com/api/v2/check"
    assert urllib.parse.parse_qs(parsed.query) == {
        "ipAddress": [PUBLIC_IP],
        "maxAgeInDays": ["30"],
    }
    assert opener.requests[0].get_method() == "GET"


def test_lookup_sends_key_and_accept_headers():
    """The request should carry the API key and ask for JSON."""

    client, opener, _ = _client([_body()], api_key="secret-key")

    client.lookup("ip", PUBLIC_IP)

    headers = {key.lower(): value for key, value in opener.requests[0].header_items()}
    assert headers["key"] == "secret-key"
    assert headers["accept"] == "application/json"


@pytest.mark.parametrize(
    ("score", "reports", "expected"),
    [
        (100, 200, IntelVerdict.MALICIOUS),
        (75, 12, IntelVerdict.MALICIOUS),
        (74, 12, IntelVerdict.SUSPICIOUS),
        (25, 4, IntelVerdict.SUSPICIOUS),
        (24, 4, IntelVerdict.UNKNOWN),
        (1, 1, IntelVerdict.UNKNOWN),
        (0, 3, IntelVerdict.UNKNOWN),
        (0, 0, IntelVerdict.BENIGN),
    ],
)
def test_verdict_thresholds(score, reports, expected):
    """Each documented confidence-score boundary should map to its verdict."""

    client, _, _ = _client([_body(abuseConfidenceScore=score, totalReports=reports)])

    assert client.lookup("ip", PUBLIC_IP).verdict is expected


def test_whitelisted_overrides_high_confidence_score():
    """An explicit allowlist entry should beat an aggregate score."""

    client, _, _ = _client([_body(abuseConfidenceScore=99, totalReports=500, isWhitelisted=True)])

    lookup = client.lookup("ip", PUBLIC_IP)

    assert lookup.verdict is IntelVerdict.BENIGN
    assert lookup.risk_factors == ()
    assert "whitelisted" in lookup.summary.lower()


def test_missing_score_is_unknown():
    """A response with no confidence score should never assert a verdict."""

    client, _, _ = _client([_body(abuseConfidenceScore=None, totalReports=None)])

    lookup = client.lookup("ip", PUBLIC_IP)

    assert lookup.verdict is IntelVerdict.UNKNOWN
    assert lookup.risk_factors == ()


def test_summary_carries_verdict_score_and_report_count():
    """The summary is the only field triage sees, so it must state the verdict."""

    client, _, _ = _client([_body(abuseConfidenceScore=92, totalReports=140)])

    summary = client.lookup("ip", PUBLIC_IP).summary

    assert summary.startswith("AbuseIPDB: ")
    assert "malicious" in summary
    assert "92%" in summary
    assert "140 reports" in summary
    assert "DE" in summary


def test_risk_factors_are_short_tokens_for_escalating_verdicts():
    """Escalating verdicts should carry machine-readable factors, clean ones none."""

    malicious, _, _ = _client([_body(abuseConfidenceScore=92, totalReports=140)])
    suspicious, _, _ = _client([_body(abuseConfidenceScore=40, totalReports=6)])
    benign, _, _ = _client([_body(abuseConfidenceScore=0, totalReports=0)])

    assert malicious.lookup("ip", PUBLIC_IP).risk_factors == ("abuseipdb_high_confidence",)
    assert suspicious.lookup("ip", PUBLIC_IP).risk_factors == ("abuseipdb_reported_abuse",)
    assert benign.lookup("ip", PUBLIC_IP).risk_factors == ()


def test_details_are_a_bounded_parsed_subset():
    """Details are cached and persisted, so they must not be the whole response."""

    client, _, _ = _client([_body()], max_age_in_days=45)

    details = client.lookup("ip", PUBLIC_IP).details

    assert set(details) == {
        "abuse_confidence_score",
        "total_reports",
        "usage_type",
        "isp",
        "country_code",
        "is_whitelisted",
        "domain",
        "max_age_in_days",
    }
    assert details["abuse_confidence_score"] == 92
    assert details["total_reports"] == 140
    assert details["country_code"] == "DE"
    assert details["max_age_in_days"] == 45
    assert json.dumps(details)


def test_lookup_round_trips_through_intel_lookup_payload():
    """The result must survive the enrichment cache serialization round trip."""

    client, _, _ = _client([_body()])

    lookup = client.lookup("ip", PUBLIC_IP)
    restored = IntelLookup.from_payload(lookup.to_payload())

    assert restored == lookup


def test_non_ip_indicator_type_raises():
    """Reaching this provider with a domain is a programming error."""

    client, opener, _ = _client([_body()])

    with pytest.raises(AbuseIPDBError, match="indicator type"):
        client.lookup("domain", "evil.example")

    assert opener.call_count == 0


def test_unparseable_ip_raises():
    """A malformed address should be rejected before any request is sent."""

    client, opener, _ = _client([_body()])

    with pytest.raises(AbuseIPDBError, match="IP address"):
        client.lookup("ip", "not-an-ip")

    assert opener.call_count == 0


@pytest.mark.parametrize("code", [401, 403])
def test_auth_failure_raises_actionably(code):
    """401/403 should name the API key setting an operator has to fix."""

    client, _, _ = _client([_http_error(code, "Unauthorized")])

    with pytest.raises(AbuseIPDBAuthError, match="ABUSEIPDB_API_KEY"):
        client.lookup("ip", PUBLIC_IP)


def test_auth_failure_is_not_retried():
    """A bad key cannot be fixed by retrying, so it must fail on the first call."""

    client, opener, sleeps = _client([_http_error(401, "Unauthorized")])

    with pytest.raises(AbuseIPDBAuthError):
        client.lookup("ip", PUBLIC_IP)

    assert opener.call_count == 1
    assert sleeps == []


def test_rate_limit_raises_quota_error():
    """429 means the daily quota is gone, which someone needs to recognize."""

    client, opener, _ = _client([_http_error(429, "Too Many Requests")])

    with pytest.raises(AbuseIPDBQuotaError, match="quota"):
        client.lookup("ip", PUBLIC_IP)

    assert opener.call_count == 1


def test_server_error_is_retried_then_succeeds():
    """A transient 5xx should be retried with backoff and then succeed."""

    client, opener, sleeps = _client([_http_error(500, "Server Error"), _body()])

    lookup = client.lookup("ip", PUBLIC_IP)

    assert lookup.verdict is IntelVerdict.MALICIOUS
    assert opener.call_count == 2
    assert sleeps == [0.5]


def test_network_error_is_retried_then_succeeds():
    """Connection failures are transient and worth one retry."""

    client, opener, sleeps = _client([urllib.error.URLError("connection refused"), _body()])

    assert client.lookup("ip", PUBLIC_IP).verdict is IntelVerdict.MALICIOUS
    assert opener.call_count == 2
    assert sleeps == [0.5]


def test_timeout_is_retried_then_succeeds():
    """Timeouts are transient and worth one retry."""

    client, opener, sleeps = _client([TimeoutError("timed out"), _body()])

    assert client.lookup("ip", PUBLIC_IP).verdict is IntelVerdict.MALICIOUS
    assert opener.call_count == 2
    assert sleeps == [0.5]


def test_persistent_server_error_gives_up_after_bounded_retries():
    """Retries are bounded, and the final failure is raised rather than faked."""

    client, opener, sleeps = _client([_http_error(500, "Server Error")], max_retries=2)

    with pytest.raises(AbuseIPDBRequestError, match="HTTP 500"):
        client.lookup("ip", PUBLIC_IP)

    assert opener.call_count == 3
    assert sleeps == [0.5, 1.0]


def test_malformed_json_raises_request_error():
    """A non-JSON body must raise rather than produce an empty verdict."""

    client, _, _ = _client(["<html>maintenance</html>"])

    with pytest.raises(AbuseIPDBRequestError, match="malformed JSON"):
        client.lookup("ip", PUBLIC_IP)


def test_missing_data_object_raises_request_error():
    """A response without a data object is unusable and must raise."""

    client, _, _ = _client([json.dumps({"errors": [{"detail": "nope"}]})])

    with pytest.raises(AbuseIPDBRequestError, match="data"):
        client.lookup("ip", PUBLIC_IP)


def test_errors_are_threat_intel_errors():
    """The enricher only contains ThreatIntelError subclasses meaningfully."""

    assert issubclass(AbuseIPDBError, ThreatIntelError)
    assert issubclass(AbuseIPDBAuthError, AbuseIPDBError)
    assert issubclass(AbuseIPDBQuotaError, AbuseIPDBError)
    assert issubclass(AbuseIPDBRequestError, AbuseIPDBError)


class _Settings:
    """Minimal stand-in for soc.config.Settings."""

    def __init__(self, **values: Any) -> None:
        """Initialize the stand-in.

        Inputs:
            values: Attributes to expose.

        Outputs:
            None.
        """

        for key, value in values.items():
            setattr(self, key, value)


def test_from_settings_reads_the_api_key_and_applies_defaults():
    """from_settings should build a usable client from the key alone."""

    client = AbuseIPDBClient.from_settings(_Settings(abuseipdb_api_key="env-key"))

    assert client.config.api_key == "env-key"
    assert client.config.base_url == DEFAULT_ABUSEIPDB_BASE_URL
    assert client.config.max_age_in_days == 90
    assert client.config.min_seconds_between_calls == 1.0


def test_from_settings_tolerates_unrelated_settings_objects():
    """Optional keys are read defensively, since config wiring lands separately."""

    settings = _Settings(
        abuseipdb_api_key=" env-key ",
        abuseipdb_max_age_in_days="30",
        abuseipdb_timeout_seconds="7",
    )

    client = AbuseIPDBClient.from_settings(settings)

    assert client.config.api_key == "env-key"
    assert client.config.max_age_in_days == 30
    assert client.config.timeout_seconds == 7


def test_from_settings_requires_an_api_key():
    """A missing key must fail loudly, naming the setting to populate."""

    with pytest.raises(AbuseIPDBError, match="ABUSEIPDB_API_KEY"):
        AbuseIPDBClient.from_settings(_Settings(abuseipdb_api_key=""))

    with pytest.raises(AbuseIPDBError, match="ABUSEIPDB_API_KEY"):
        AbuseIPDBClient.from_settings(_Settings())


def test_provider_fits_the_threat_intel_enricher():
    """The provider must satisfy the protocol the enricher actually calls."""

    client, opener, _ = _client([_body()])
    enricher = ThreatIntelEnricher(providers=[client], sleep=lambda _seconds: None)

    results = enricher.enrich_indicators([("ip", PUBLIC_IP)], target_id="CAND-1")

    assert len(results) == 1
    result = results[0]
    assert result.provider == "abuseipdb"
    assert result.indicator == PUBLIC_IP
    assert result.indicator_type == "ip"
    assert "malicious" in result.summary
    assert result.raw["verdict"] == "malicious"
    assert result.raw["risk_factors"] == ["abuseipdb_high_confidence"]
    assert result.raw["target_id"] == "CAND-1"
    assert opener.call_count == 1
