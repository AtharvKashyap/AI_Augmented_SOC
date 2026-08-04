

"""Tests for deduplication helpers.

These tests verify that `soc.dedup` builds stable deduplication keys and uses
`SQLiteStore` correctly to avoid processing the same raw event or normalized
alert more than once.

The tests use a temporary SQLite database and do not require live Wazuh,
Security Onion, OpenRouter, Splunk, or OpenBSD services.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from soc.dedup import (
    DeduplicationError,
    DeduplicationService,
    build_alert_key,
    build_payload_fingerprint_key,
    build_raw_event_key,
    build_source_id_key,
)
from soc.models import Alert, AlertSeverity, EventSource, RawEvent
from soc.store import SQLiteStore


@pytest.fixture
def store(tmp_path):
    """Create an initialized SQLiteStore backed by a temporary database.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        Initialized SQLiteStore instance.
    """

    db_path = tmp_path / "test_dedup.db"
    sqlite_store = SQLiteStore(db_path)
    sqlite_store.initialize()
    return sqlite_store


@pytest.fixture
def dedup(store):
    """Create a DeduplicationService using the temporary store.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        DeduplicationService instance.
    """

    return DeduplicationService(store=store, ttl_hours=24)


def test_build_source_id_key_with_enum_source():
    """Source/id key generation should support EventSource enum values.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies key format.
    """

    key = build_source_id_key(EventSource.WAZUH, "alert-001")

    assert key == "wazuh:alert-001"


def test_build_source_id_key_with_string_source():
    """Source/id key generation should support plain string sources.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies key format.
    """

    key = build_source_id_key("security_onion", "event-abc")

    assert key == "security_onion:event-abc"


def test_build_source_id_key_rejects_empty_values():
    """Empty source or source ID values should raise DeduplicationError.

    Inputs:
        None.

    Outputs:
        None. Assertions verify validation behavior.
    """

    with pytest.raises(DeduplicationError):
        build_source_id_key("", "alert-001")

    with pytest.raises(DeduplicationError):
        build_source_id_key(EventSource.WAZUH, "   ")


def test_build_raw_event_key():
    """RawEvent keys should include raw prefix, source, and event ID.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies key format.
    """

    event = RawEvent(
        id="raw-001",
        source=EventSource.WAZUH,
        timestamp=datetime(2026, 6, 10, 12, 0, tzinfo=UTC),
        payload={"rule": {"level": 7}},
    )

    assert build_raw_event_key(event) == "raw:wazuh:raw-001"


def test_build_alert_key():
    """Alert keys should include alert prefix, source, and alert ID.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies key format.
    """

    alert = Alert(
        id="alert-001",
        source=EventSource.SECURITY_ONION,
        timestamp=datetime(2026, 6, 10, 12, 0, tzinfo=UTC),
        severity=AlertSeverity.HIGH,
        rule_name="ET TROJAN Possible C2 Traffic",
    )

    assert build_alert_key(alert) == "alert:security_onion:alert-001"


def test_payload_fingerprint_key_is_stable_for_same_payload():
    """Payload fingerprint keys should be stable for repeated input.

    Inputs:
        None.

    Outputs:
        None. Assertions verify stable fingerprint behavior.
    """

    payload = {"src_ip": "10.0.1.10", "dst_ip": "198.51.100.25"}

    first_key = build_payload_fingerprint_key(EventSource.SECURITY_ONION, payload)
    second_key = build_payload_fingerprint_key(EventSource.SECURITY_ONION, payload)

    assert first_key == second_key
    assert first_key.startswith("fingerprint:security_onion:")


def test_payload_fingerprint_key_changes_for_different_payloads():
    """Payload fingerprint keys should change when payload content changes.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies different payloads produce different keys.
    """

    first_payload = {"src_ip": "10.0.1.10"}
    second_payload = {"src_ip": "10.0.1.11"}

    first_key = build_payload_fingerprint_key(EventSource.SECURITY_ONION, first_payload)
    second_key = build_payload_fingerprint_key(EventSource.SECURITY_ONION, second_payload)

    assert first_key != second_key


def test_has_seen_and_mark_key_seen(dedup):
    """Raw keys should be unseen until marked as seen.

    Inputs:
        dedup: DeduplicationService fixture.

    Outputs:
        None. Assertions verify basic key behavior.
    """

    key = "wazuh:alert-001"

    assert dedup.has_seen_key(key) is False

    dedup.mark_key_seen(key)

    assert dedup.has_seen_key(key) is True


def test_mark_key_seen_rejects_empty_key(dedup):
    """Empty raw keys should raise DeduplicationError.

    Inputs:
        dedup: DeduplicationService fixture.

    Outputs:
        None. Assertions verify validation behavior.
    """

    with pytest.raises(DeduplicationError):
        dedup.mark_key_seen("   ")

    with pytest.raises(DeduplicationError):
        dedup.has_seen_key("")


def test_raw_event_dedup_flow(dedup):
    """Raw events should be deduplicated using their stable raw event key.

    Inputs:
        dedup: DeduplicationService fixture.

    Outputs:
        None. Assertions verify raw event dedup behavior.
    """

    event = RawEvent(
        id="raw-wazuh-001",
        source=EventSource.WAZUH,
        timestamp=datetime(2026, 6, 10, 12, 30, tzinfo=UTC),
        payload={"rule": {"description": "Suspicious PowerShell"}},
    )

    assert dedup.has_seen_raw_event(event) is False

    dedup.mark_raw_event_seen(event)

    assert dedup.has_seen_raw_event(event) is True


def test_alert_dedup_flow(dedup):
    """Alerts should be deduplicated using their stable alert key.

    Inputs:
        dedup: DeduplicationService fixture.

    Outputs:
        None. Assertions verify alert dedup behavior.
    """

    alert = Alert(
        id="alert-wazuh-001",
        source=EventSource.WAZUH,
        timestamp=datetime(2026, 6, 10, 12, 30, tzinfo=UTC),
        severity=AlertSeverity.HIGH,
        rule_name="Suspicious PowerShell",
    )

    assert dedup.has_seen_alert(alert) is False

    dedup.mark_alert_seen(alert)

    assert dedup.has_seen_alert(alert) is True


def test_source_id_dedup_flow(dedup):
    """Source/id pairs should be deduplicated without constructing full models.

    Inputs:
        dedup: DeduplicationService fixture.

    Outputs:
        None. Assertions verify source/id convenience methods.
    """

    assert dedup.has_seen_source_id(EventSource.SECURITY_ONION, "so-alert-001") is False

    dedup.mark_source_id_seen(EventSource.SECURITY_ONION, "so-alert-001")

    assert dedup.has_seen_source_id(EventSource.SECURITY_ONION, "so-alert-001") is True


def test_cleanup_expired_returns_zero_when_no_keys_expired(dedup):
    """Cleanup should return zero when no dedup keys have expired.

    Inputs:
        dedup: DeduplicationService fixture.

    Outputs:
        None. Assertion verifies cleanup return value.
    """

    dedup.mark_key_seen("wazuh:alert-001")

    assert dedup.cleanup_expired() == 0
    assert dedup.has_seen_key("wazuh:alert-001") is True