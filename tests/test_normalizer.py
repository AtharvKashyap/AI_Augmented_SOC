

"""Tests for source event normalization.

These tests verify that `soc.normalizer` converts Wazuh, Security Onion, and
replay RawEvent objects into the shared Alert model used by the rest of the SOC
pipeline.

The tests intentionally use realistic but compact event payloads so we can
validate field extraction without requiring live Wazuh or Security Onion.
"""

from __future__ import annotations

from datetime import datetime, timezone

from soc.models import AlertSeverity, EventSource, RawEvent
from soc.normalizer import (
    Normalizer,
    severity_from_security_onion,
    severity_from_text_or_number,
    severity_from_wazuh_level,
)


def test_normalize_wazuh_event_extracts_common_fields():
    """Wazuh events should normalize important endpoint alert fields.

    Inputs:
        None.

    Outputs:
        None. Assertions verify normalized Alert fields.
    """

    event = RawEvent(
        id="raw-wazuh-001",
        source=EventSource.WAZUH,
        timestamp=datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc),
        payload={
            "id": "1750000000.12345",
            "timestamp": "2026-06-10T12:01:00Z",
            "rule": {
                "level": 10,
                "description": "Suspicious PowerShell execution",
                "groups": ["windows", "powershell"],
            },
            "agent": {
                "id": "001",
                "name": "endpoint-01",
                "os": {"name": "Windows", "version": "11"},
            },
            "data": {
                "srcip": "10.0.1.10",
                "dstip": "198.51.100.25",
                "user": "alice",
                "command_line": "powershell.exe -EncodedCommand abc123",
            },
            "win": {
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                }
            },
        },
    )

    alert = Normalizer().normalize(event)

    assert alert.id == "wazuh:1750000000.12345"
    assert alert.source == EventSource.WAZUH
    assert alert.timestamp == datetime(2026, 6, 10, 12, 1, tzinfo=timezone.utc)
    assert alert.severity == AlertSeverity.HIGH
    assert alert.source_severity == 10
    assert alert.rule_name == "Suspicious PowerShell execution"
    assert alert.rule_groups == ["windows", "powershell"]
    assert alert.src_ip == "10.0.1.10"
    assert alert.dst_ip == "198.51.100.25"
    assert alert.hostname == "endpoint-01"
    assert alert.agent_id == "001"
    assert alert.agent_os == "Windows"
    assert alert.user == "alice"
    assert alert.process_name.endswith("powershell.exe")
    assert alert.command_line == "powershell.exe -EncodedCommand abc123"
    assert alert.raw_event_id == "raw-wazuh-001"
    assert alert.raw == event.payload


def test_normalize_wazuh_event_supports_flattened_fields():
    """Wazuh normalization should support flattened/indexer-like fields.

    Inputs:
        None.

    Outputs:
        None. Assertions verify flattened-field extraction.
    """

    event = RawEvent(
        id="raw-wazuh-flat-001",
        source=EventSource.WAZUH,
        timestamp=None,
        payload={
            "_id": "indexer-doc-001",
            "@timestamp": "2026-06-10T13:00:00+00:00",
            "rule_level": "12",
            "rule_description": "Possible credential dumping",
            "groups": ["windows", "credential_access"],
            "agent_id": "003",
            "hostname": "endpoint-03",
            "src_ip": "10.0.1.30",
            "dst_ip": "10.0.1.5",
            "user.name": "bob",
            "process.name": "rundll32.exe",
        },
    )

    alert = Normalizer().normalize(event)

    assert alert.id == "wazuh:indexer-doc-001"
    assert alert.timestamp == datetime(2026, 6, 10, 13, 0, tzinfo=timezone.utc)
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.source_severity == "12"
    assert alert.rule_name == "Possible credential dumping"
    assert alert.rule_groups == ["windows", "credential_access"]
    assert alert.agent_id == "003"
    assert alert.hostname == "endpoint-03"
    assert alert.src_ip == "10.0.1.30"
    assert alert.dst_ip == "10.0.1.5"
    assert alert.user == "bob"
    assert alert.process_name == "rundll32.exe"


def test_normalize_security_onion_suricata_event_extracts_common_fields():
    """Security Onion Suricata alerts should normalize network alert fields.

    Inputs:
        None.

    Outputs:
        None. Assertions verify normalized Alert fields.
    """

    event = RawEvent(
        id="raw-so-001",
        source=EventSource.SECURITY_ONION,
        timestamp=datetime(2026, 6, 10, 14, 0, tzinfo=timezone.utc),
        payload={
            "_id": "so-doc-001",
            "@timestamp": "2026-06-10T14:05:00Z",
            "suricata": {
                "alert": {
                    "signature": "ET TROJAN Possible C2 Traffic",
                    "severity": 1,
                    "category": "A Network Trojan was detected",
                }
            },
            "source": {"ip": "10.0.1.10"},
            "destination": {"ip": "198.51.100.25"},
            "host": {"name": "sensor-01", "os": {"name": "Security Onion"}},
            "agent": {"id": "so-agent-1"},
            "user": {"name": "alice"},
        },
    )

    alert = Normalizer().normalize(event)

    assert alert.id == "security_onion:so-doc-001"
    assert alert.source == EventSource.SECURITY_ONION
    assert alert.timestamp == datetime(2026, 6, 10, 14, 5, tzinfo=timezone.utc)
    assert alert.severity == AlertSeverity.HIGH
    assert alert.source_severity == 1
    assert alert.rule_name == "ET TROJAN Possible C2 Traffic"
    assert alert.rule_groups == ["A Network Trojan was detected"]
    assert alert.src_ip == "10.0.1.10"
    assert alert.dst_ip == "198.51.100.25"
    assert alert.hostname == "sensor-01"
    assert alert.agent_id == "so-agent-1"
    assert alert.agent_os == "Security Onion"
    assert alert.user == "alice"
    assert alert.raw_event_id == "raw-so-001"


def test_normalize_security_onion_zeek_like_event_extracts_ip_fields():
    """Security Onion Zeek-style fields should map source/destination IPs.

    Inputs:
        None.

    Outputs:
        None. Assertions verify Zeek-style field extraction.
    """

    event = RawEvent(
        id="raw-so-zeek-001",
        source=EventSource.SECURITY_ONION,
        timestamp=None,
        payload={
            "event": {"id": "zeek-event-001", "severity": 2, "category": ["network"]},
            "id": {"orig_h": "10.0.1.20", "resp_h": "203.0.113.10"},
            "message": "Suspicious outbound connection",
            "observer": {"hostname": "sensor-02"},
        },
    )

    alert = Normalizer().normalize(event)

    assert alert.id == "security_onion:zeek-event-001"
    assert alert.severity == AlertSeverity.MEDIUM
    assert alert.rule_name == "Suspicious outbound connection"
    assert alert.rule_groups == ["network"]
    assert alert.src_ip == "10.0.1.20"
    assert alert.dst_ip == "203.0.113.10"
    assert alert.hostname == "sensor-02"


def test_normalize_generic_replay_event_extracts_common_fields():
    """Replay events should normalize using generic field names.

    Inputs:
        None.

    Outputs:
        None. Assertions verify generic normalization.
    """

    event = RawEvent(
        id="manual-001",
        source=EventSource.REPLAY,
        timestamp=None,
        payload={
            "id": "manual-alert-001",
            "timestamp": "2026-06-10T15:00:00+00:00",
            "severity": "critical",
            "rule_name": "Manual critical test alert",
            "rule_groups": ["manual", "test"],
            "src_ip": "10.0.1.50",
            "dst_ip": "198.51.100.50",
            "hostname": "manual-host",
            "agent_id": "manual-agent",
            "agent_os": "Linux",
            "user": "charlie",
            "process_name": "bash",
            "command_line": "bash -c whoami",
        },
    )

    alert = Normalizer().normalize(event)

    assert alert.id == "replay:manual-alert-001"
    assert alert.source == EventSource.REPLAY
    assert alert.timestamp == datetime(2026, 6, 10, 15, 0, tzinfo=timezone.utc)
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.source_severity == "critical"
    assert alert.rule_name == "Manual critical test alert"
    assert alert.rule_groups == ["manual", "test"]
    assert alert.src_ip == "10.0.1.50"
    assert alert.dst_ip == "198.51.100.50"
    assert alert.hostname == "manual-host"
    assert alert.agent_id == "manual-agent"
    assert alert.agent_os == "Linux"
    assert alert.user == "charlie"
    assert alert.process_name == "bash"
    assert alert.command_line == "bash -c whoami"


def test_normalize_generic_event_uses_fallback_id_when_no_alert_id_exists():
    """Events without source alert IDs should get stable generated IDs.

    Inputs:
        None.

    Outputs:
        None. Assertions verify fallback ID behavior.
    """

    event = RawEvent(
        id="raw-unknown-001",
        source=EventSource.UNKNOWN,
        timestamp=None,
        payload={"message": "No source ID available"},
    )

    alert = Normalizer().normalize(event)

    assert alert.id.startswith("unknown:raw-unknown-001:")
    assert alert.rule_name == "No source ID available"
    assert alert.severity == AlertSeverity.UNKNOWN


def test_normalizer_normalize_many_returns_alerts_in_order():
    """normalize_many should normalize events and preserve input order.

    Inputs:
        None.

    Outputs:
        None. Assertions verify list behavior.
    """

    events = [
        RawEvent(
            id="raw-001",
            source=EventSource.REPLAY,
            timestamp=None,
            payload={"id": "alert-001", "payload_type": "first", "message": "First"},
        ),
        RawEvent(
            id="raw-002",
            source=EventSource.REPLAY,
            timestamp=None,
            payload={"id": "alert-002", "payload_type": "second", "message": "Second"},
        ),
    ]

    alerts = Normalizer().normalize_many(events)

    assert [alert.id for alert in alerts] == ["replay:alert-001", "replay:alert-002"]
    assert [alert.rule_name for alert in alerts] == ["First", "Second"]


def test_severity_from_wazuh_level_mapping():
    """Wazuh levels should map to expected normalized severities.

    Inputs:
        None.

    Outputs:
        None. Assertions verify severity mapping.
    """

    assert severity_from_wazuh_level(0) == AlertSeverity.INFO
    assert severity_from_wazuh_level(3) == AlertSeverity.LOW
    assert severity_from_wazuh_level(6) == AlertSeverity.MEDIUM
    assert severity_from_wazuh_level(9) == AlertSeverity.HIGH
    assert severity_from_wazuh_level(12) == AlertSeverity.CRITICAL
    assert severity_from_wazuh_level("12") == AlertSeverity.CRITICAL


def test_severity_from_security_onion_mapping():
    """Security Onion/Suricata severities should map as expected.

    Inputs:
        None.

    Outputs:
        None. Assertions verify severity mapping.
    """

    assert severity_from_security_onion(1) == AlertSeverity.HIGH
    assert severity_from_security_onion(2) == AlertSeverity.MEDIUM
    assert severity_from_security_onion(3) == AlertSeverity.LOW
    assert severity_from_security_onion(4) == AlertSeverity.INFO
    assert severity_from_security_onion("critical") == AlertSeverity.CRITICAL


def test_severity_from_text_or_number_mapping():
    """Generic text and numeric severities should map as expected.

    Inputs:
        None.

    Outputs:
        None. Assertions verify generic severity mapping.
    """

    assert severity_from_text_or_number("critical") == AlertSeverity.CRITICAL
    assert severity_from_text_or_number("high") == AlertSeverity.HIGH
    assert severity_from_text_or_number("warning") == AlertSeverity.MEDIUM
    assert severity_from_text_or_number("low") == AlertSeverity.LOW
    assert severity_from_text_or_number("info") == AlertSeverity.INFO
    assert severity_from_text_or_number(95) == AlertSeverity.CRITICAL
    assert severity_from_text_or_number(70) == AlertSeverity.HIGH
    assert severity_from_text_or_number(40) == AlertSeverity.MEDIUM
    assert severity_from_text_or_number(10) == AlertSeverity.LOW
    assert severity_from_text_or_number(0) == AlertSeverity.INFO
    assert severity_from_text_or_number("not-known") == AlertSeverity.UNKNOWN
    assert severity_from_text_or_number(None) == AlertSeverity.UNKNOWN


def test_timestamp_falls_back_to_raw_event_timestamp_when_payload_missing():
    """Normalizer should use RawEvent.timestamp when payload has no timestamp.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies timestamp fallback behavior.
    """

    raw_time = datetime(2026, 6, 10, 16, 0, tzinfo=timezone.utc)
    event = RawEvent(
        id="raw-001",
        source=EventSource.REPLAY,
        timestamp=raw_time,
        payload={"id": "alert-001", "message": "Timestamp fallback"},
    )

    alert = Normalizer().normalize(event)

    assert alert.timestamp == raw_time


def test_naive_timestamp_is_converted_to_utc():
    """Naive ISO timestamps should be treated as UTC.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies timezone normalization.
    """

    event = RawEvent(
        id="raw-001",
        source=EventSource.REPLAY,
        timestamp=None,
        payload={"id": "alert-001", "timestamp": "2026-06-10T17:00:00"},
    )

    alert = Normalizer().normalize(event)

    assert alert.timestamp == datetime(2026, 6, 10, 17, 0, tzinfo=timezone.utc)