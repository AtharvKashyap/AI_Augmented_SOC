

"""Tests for local enrichment.

These tests verify that `soc.enrichment` extracts useful observables from
alerts/candidates and creates local EnrichmentResult objects without calling
external threat-intelligence APIs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from soc.enrichment import (
    EnrichmentError,
    LocalEnricher,
    classify_ip,
    enrich_alert,
    enrich_candidate,
    enrich_indicator,
    extract_alert_indicators,
    extract_candidate_indicators,
    extract_iocs_from_text,
)
from soc.models import Alert, AlertSeverity, EnrichmentResult, EventSource, IncidentCandidate


BASE_TIME = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


def _alert() -> Alert:
    """Create a representative normalized alert for enrichment tests.

    Inputs:
        None.

    Outputs:
        Alert object.
    """

    return Alert(
        id="alert-001",
        source=EventSource.WAZUH,
        timestamp=BASE_TIME,
        severity=AlertSeverity.HIGH,
        source_severity=10,
        rule_name="Suspicious PowerShell to http://198.51.100.25/login",
        rule_groups=["windows", "powershell"],
        src_ip="10.0.1.10",
        dst_ip="198.51.100.25",
        hostname="endpoint-01",
        agent_id="001",
        agent_os="Windows",
        user="alice",
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand abc123",
        raw={
            "hash": "0123456789abcdef0123456789abcdef",
            "email": "analyst@example.com",
            "domain": "evil-example.xyz",
        },
    )


def _candidate() -> IncidentCandidate:
    """Create a representative incident candidate for enrichment tests.

    Inputs:
        None.

    Outputs:
        IncidentCandidate object.
    """

    alert = _alert()
    return IncidentCandidate(
        id="candidate-001",
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        alerts=[alert],
        primary_host="endpoint-01",
        primary_user="alice",
        src_ips=["10.0.1.10"],
        dst_ips=["198.51.100.25", "203.0.113.50"],
        related_events=[],
        enrichments=[],
        created_at=BASE_TIME,
    )


def _field(result: EnrichmentResult, *names: str) -> Any:
    """Read the first available field from an EnrichmentResult.

    Inputs:
        result: EnrichmentResult object.
        names: Candidate attribute names.

    Outputs:
        Field value.

    Raises:
        AssertionError: If none of the candidate fields exist.
    """

    for name in names:
        if hasattr(result, name):
            return getattr(result, name)
    raise AssertionError(f"Missing expected enrichment field. Tried: {names}")


def _details(result: EnrichmentResult) -> dict[str, Any]:
    """Read structured enrichment details from an EnrichmentResult.

    Inputs:
        result: EnrichmentResult object.

    Outputs:
        Details dictionary.
    """

    details = _field(result, "details", "metadata", "data", "raw")
    assert isinstance(details, dict)
    return details


def test_extract_iocs_from_text_finds_common_observables():
    """IOC extraction should find URLs, emails, IPs, hashes, and domains.

    Inputs:
        None.

    Outputs:
        None. Assertions verify extracted IOC pairs.
    """

    text = (
        "Visited http://198.51.100.25/login and evil-example.xyz, "
        "contact analyst@example.com, hash 0123456789abcdef0123456789abcdef, "
        "invalid IP 999.999.999.999, process powershell.exe."
    )

    indicators = extract_iocs_from_text(text)

    assert ("url", "http://198.51.100.25/login") in indicators
    assert ("email", "analyst@example.com") in indicators
    assert ("ip", "198.51.100.25") in indicators
    assert ("hash", "0123456789abcdef0123456789abcdef") in indicators
    assert ("domain", "evil-example.xyz") in indicators
    assert ("ip", "999.999.999.999") not in indicators
    assert ("domain", "powershell.exe") not in indicators


def test_extract_iocs_from_text_deduplicates_case_insensitively():
    """IOC extraction should deduplicate repeated values case-insensitively.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies deduplication behavior.
    """

    indicators = extract_iocs_from_text("evil-example.xyz EVIL-EXAMPLE.XYZ evil-example.xyz")

    assert indicators.count(("domain", "evil-example.xyz")) == 1


def test_extract_alert_indicators_includes_alert_fields_and_raw_iocs():
    """Alert indicator extraction should include normalized fields and raw IOCs.

    Inputs:
        None.

    Outputs:
        None. Assertions verify alert indicator extraction.
    """

    indicators = extract_alert_indicators(_alert())

    assert ("ip", "10.0.1.10") in indicators
    assert ("ip", "198.51.100.25") in indicators
    assert ("host", "endpoint-01") in indicators
    assert ("user", "alice") in indicators
    assert ("command", "powershell.exe -EncodedCommand abc123") in indicators
    assert ("process", "powershell.exe") in indicators
    assert ("hash", "0123456789abcdef0123456789abcdef") in indicators
    assert ("email", "analyst@example.com") in indicators
    assert ("domain", "evil-example.xyz") in indicators


def test_extract_candidate_indicators_includes_candidate_and_alert_values():
    """Candidate extraction should include candidate IPs plus alert indicators.

    Inputs:
        None.

    Outputs:
        None. Assertions verify candidate extraction.
    """

    indicators = extract_candidate_indicators(_candidate())

    assert ("ip", "10.0.1.10") in indicators
    assert ("ip", "198.51.100.25") in indicators
    assert ("ip", "203.0.113.50") in indicators
    assert ("host", "endpoint-01") in indicators
    assert ("user", "alice") in indicators
    assert ("command", "powershell.exe -EncodedCommand abc123") in indicators


def test_classify_ip_identifies_private_address():
    """IP classification should identify private/internal addresses.

    Inputs:
        None.

    Outputs:
        None. Assertions verify private IP classification.
    """

    result = classify_ip("10.0.1.10")

    assert result["ip_version"] == 4
    assert result["is_private"] is True
    assert "private_ip" in result["risk_factors"]


def test_classify_ip_identifies_public_address():
    """IP classification should identify public/global addresses.

    Inputs:
        None.

    Outputs:
        None. Assertions verify public IP classification.
    """

    result = classify_ip("8.8.8.8")

    assert result["ip_version"] == 4
    assert result["is_global"] is True
    assert "public_ip" in result["risk_factors"]


def test_classify_ip_rejects_invalid_ip():
    """Invalid IP classification input should raise EnrichmentError.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies invalid input behavior.
    """

    with pytest.raises(EnrichmentError, match="Invalid IP address"):
        classify_ip("999.999.999.999")


def test_enrich_indicator_creates_ip_enrichment_result():
    """enrich_indicator should create structured results for IPs.

    Inputs:
        None.

    Outputs:
        None. Assertions verify EnrichmentResult content.
    """

    result = enrich_indicator("ip", "8.8.8.8", target_id="alert-001")
    details = _details(result)

    assert isinstance(result, EnrichmentResult)
    assert details["enrichment_id"].startswith("enrich-")
    assert details["target_id"] == "alert-001"
    assert _field(result, "indicator_type", "ioc_type", "observable_type") == "ip"
    assert _field(result, "indicator", "ioc", "observable", "value") == "8.8.8.8"
    assert _field(result, "provider") == "local"
    assert "public/global IP" in _field(result, "summary")
    assert details["is_global"] is True
    assert "public_ip" in details["risk_factors"]


def test_enrich_indicator_flags_encoded_powershell():
    """Command enrichment should flag encoded PowerShell as high risk hint.

    Inputs:
        None.

    Outputs:
        None. Assertions verify command risk factors.
    """

    result = enrich_indicator("command", "powershell.exe -EncodedCommand abc123")
    details = _details(result)

    assert "encoded_powershell" in details["risk_factors"]
    assert details["severity_hint"] == "high"


def test_enrich_indicator_flags_suspicious_domain_tld():
    """Domain enrichment should flag suspicious TLDs.

    Inputs:
        None.

    Outputs:
        None. Assertions verify domain risk factors.
    """

    result = enrich_indicator("domain", "evil-example.xyz")
    details = _details(result)

    assert "suspicious_tld" in details["risk_factors"]
    assert details["severity_hint"] == "medium"


def test_enrich_indicator_flags_url_with_ip_and_cleartext_http():
    """URL enrichment should flag IP-based cleartext HTTP URLs.

    Inputs:
        None.

    Outputs:
        None. Assertions verify URL risk factors.
    """

    result = enrich_indicator("url", "http://198.51.100.25/login")
    details = _details(result)

    assert "url_with_ip" in details["risk_factors"]
    assert "cleartext_http" in details["risk_factors"]
    assert "credential_page_path" in details["risk_factors"]
    assert details["severity_hint"] == "medium"


def test_enrich_indicator_flags_hash_type():
    """Hash enrichment should identify common hash lengths.

    Inputs:
        None.

    Outputs:
        None. Assertions verify hash type detection.
    """

    result = enrich_indicator("hash", "0123456789abcdef0123456789abcdef")
    details = _details(result)

    assert details["hash_type"] == "md5"
    assert "hash_observable" in details["risk_factors"]


def test_enrich_indicator_rejects_empty_values():
    """Empty indicator inputs should raise EnrichmentError.

    Inputs:
        None.

    Outputs:
        None. Assertions verify validation behavior.
    """

    with pytest.raises(EnrichmentError, match="indicator_type and value"):
        enrich_indicator("", "8.8.8.8")

    with pytest.raises(EnrichmentError, match="indicator_type and value"):
        enrich_indicator("ip", "")


def test_enrich_alert_returns_enrichments_for_alert_indicators():
    """enrich_alert should return local enrichment results for alert indicators.

    Inputs:
        None.

    Outputs:
        None. Assertions verify alert enrichment behavior.
    """

    results = enrich_alert(_alert())
    observed = {
        (
            _field(result, "indicator_type", "ioc_type", "observable_type"),
            _field(result, "indicator", "ioc", "observable", "value"),
        )
        for result in results
    }

    assert ("ip", "10.0.1.10") in observed
    assert ("ip", "198.51.100.25") in observed
    assert ("host", "endpoint-01") in observed
    assert ("user", "alice") in observed
    assert ("command", "powershell.exe -EncodedCommand abc123") in observed
    assert all(_details(result)["target_id"] == "alert-001" for result in results)


def test_local_enricher_enrich_candidate_returns_candidate_scoped_results():
    """LocalEnricher should enrich candidates and preserve target ID.

    Inputs:
        None.

    Outputs:
        None. Assertions verify candidate enrichment behavior.
    """

    results = LocalEnricher().enrich_candidate(_candidate())
    observed = {
        (
            _field(result, "indicator_type", "ioc_type", "observable_type"),
            _field(result, "indicator", "ioc", "observable", "value"),
        )
        for result in results
    }

    assert ("ip", "10.0.1.10") in observed
    assert ("ip", "198.51.100.25") in observed
    assert ("ip", "203.0.113.50") in observed
    assert ("host", "endpoint-01") in observed
    assert ("user", "alice") in observed
    assert all(_details(result)["target_id"] == "candidate-001" for result in results)


def test_enrich_candidate_convenience_function():
    """enrich_candidate should expose a simple function interface.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies convenience wrapper behavior.
    """

    results = enrich_candidate(_candidate())

    assert results
    assert all(isinstance(result, EnrichmentResult) for result in results)