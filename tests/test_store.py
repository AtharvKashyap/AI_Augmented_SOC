

"""Tests for the SQLite persistence layer.

These tests verify that `soc.store.SQLiteStore` can create the local database
schema and persist the core SOC pipeline models without requiring any live
Wazuh, Security Onion, OpenRouter, Splunk, or OpenBSD services.

The store is intentionally tested with a temporary SQLite database so tests are
isolated, repeatable, and safe to run in CI.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from soc.models import (
    Alert,
    AlertSeverity,
    EventSource,
    EvidenceItem,
    FalsePositiveLikelihood,
    IncidentCandidate,
    RawEvent,
    RoutingDecision,
    RoutingStatus,
    TriageAction,
    TriageResult,
    WazuhAgent,
)
from soc.store import SQLiteStore, StoreStats


@pytest.fixture
def store(tmp_path):
    """Create an initialized SQLiteStore backed by a temporary database.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        Initialized SQLiteStore instance.
    """

    db_path = tmp_path / "test_ai_soc.db"
    sqlite_store = SQLiteStore(db_path)
    sqlite_store.initialize()
    return sqlite_store


def test_initialize_creates_empty_database(store):
    """Database initialization should create all tables with zero rows.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify table counts.
    """

    stats = store.stats()

    assert isinstance(stats, StoreStats)
    assert stats.wazuh_agents == 0
    assert stats.raw_events == 0
    assert stats.alerts == 0
    assert stats.incident_candidates == 0
    assert stats.triage_results == 0
    assert stats.routing_decisions == 0
    assert stats.dedup_keys == 0


def test_upsert_and_get_wazuh_agent(store):
    """Wazuh agents should be inserted, updated, and fetched by agent ID.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify upsert and retrieval behavior.
    """

    last_seen = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)
    agent = WazuhAgent(
        agent_id="001",
        hostname="endpoint-01",
        ip="10.0.1.10",
        os_name="Ubuntu",
        os_version="24.04",
        status="active",
        groups=["default", "linux"],
        labels={"role": "workstation"},
        last_seen=last_seen,
        raw={"id": "001", "name": "endpoint-01"},
    )

    store.upsert_wazuh_agent(agent)
    fetched = store.get_wazuh_agent("001")

    assert fetched is not None
    assert fetched.agent_id == "001"
    assert fetched.hostname == "endpoint-01"
    assert fetched.ip == "10.0.1.10"
    assert fetched.os_name == "Ubuntu"
    assert fetched.groups == ["default", "linux"]
    assert fetched.labels == {"role": "workstation"}
    assert fetched.last_seen == last_seen

    updated_agent = WazuhAgent(
        agent_id="001",
        hostname="endpoint-01-renamed",
        ip="10.0.1.11",
        status="disconnected",
    )
    store.upsert_wazuh_agent(updated_agent)
    updated = store.get_wazuh_agent("001")

    assert updated is not None
    assert updated.hostname == "endpoint-01-renamed"
    assert updated.ip == "10.0.1.11"
    assert updated.status == "disconnected"
    assert store.stats().wazuh_agents == 1


def test_save_raw_event_and_alert(store):
    """Raw events and normalized alerts should be persisted and retrievable.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify raw event and alert persistence.
    """

    event_time = datetime(2026, 6, 10, 12, 30, tzinfo=timezone.utc)
    raw_event = RawEvent(
        id="raw-wazuh-001",
        source=EventSource.WAZUH,
        timestamp=event_time,
        payload={"rule": {"level": 10, "description": "Suspicious PowerShell"}},
    )
    alert = Alert(
        id="alert-001",
        source=EventSource.WAZUH,
        timestamp=event_time,
        severity=AlertSeverity.HIGH,
        source_severity=10,
        rule_name="Suspicious PowerShell",
        rule_groups=["windows", "powershell"],
        hostname="endpoint-01",
        agent_id="001",
        user="alice",
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand abc123",
        raw_event_id="raw-wazuh-001",
        raw=raw_event.payload,
    )

    store.save_raw_event(raw_event)
    store.save_alert(alert)

    fetched_alert = store.get_alert("alert-001")
    recent_alerts = store.list_recent_alerts(limit=10)

    assert fetched_alert is not None
    assert fetched_alert["id"] == "alert-001"
    assert fetched_alert["source"] == "wazuh"
    assert fetched_alert["severity"] == "high"
    assert fetched_alert["hostname"] == "endpoint-01"
    assert fetched_alert["command_line"] == "powershell.exe -EncodedCommand abc123"
    assert len(recent_alerts) == 1
    assert recent_alerts[0]["id"] == "alert-001"
    assert store.stats().raw_events == 1
    assert store.stats().alerts == 1


def test_save_incident_candidate_links_alerts(store):
    """Incident candidates should persist candidate payload and alert links.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify candidate persistence.
    """

    event_time = datetime(2026, 6, 10, 13, 0, tzinfo=timezone.utc)
    alert = Alert(
        id="alert-002",
        source=EventSource.SECURITY_ONION,
        timestamp=event_time,
        severity=AlertSeverity.HIGH,
        source_severity=2,
        rule_name="ET TROJAN Possible C2 Traffic",
        src_ip="10.0.1.10",
        dst_ip="198.51.100.25",
        hostname="endpoint-01",
    )
    candidate = IncidentCandidate(
        id="CAND-20260610-001",
        first_seen=event_time,
        last_seen=event_time,
        alerts=[alert],
        primary_host="endpoint-01",
        primary_user="alice",
        src_ips=["10.0.1.10"],
        dst_ips=["198.51.100.25"],
    )

    store.save_alert(alert)
    store.save_incident_candidate(candidate)
    fetched_candidate = store.get_incident_candidate("CAND-20260610-001")

    assert fetched_candidate is not None
    assert fetched_candidate["id"] == "CAND-20260610-001"
    assert fetched_candidate["primary_host"] == "endpoint-01"
    assert fetched_candidate["src_ips"] == ["10.0.1.10"]
    assert fetched_candidate["dst_ips"] == ["198.51.100.25"]
    assert fetched_candidate["alerts"][0]["id"] == "alert-002"
    assert store.stats().incident_candidates == 1


def test_save_triage_result_and_routing_decision(store):
    """Triage results and routing decisions should be persisted.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify triage and routing counts.
    """

    evidence = EvidenceItem(
        source=EventSource.WAZUH,
        field="rule.description",
        value="Suspicious PowerShell",
        alert_id="alert-001",
    )
    result = TriageResult(
        id="triage-001",
        target_id="alert-001",
        target_type="alert",
        score=8,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="suspicious_endpoint_activity",
        action=TriageAction.PAGE_NOW,
        summary="Suspicious PowerShell activity observed on endpoint-01.",
        iocs={"hostnames": ["endpoint-01"], "users": ["alice"]},
        recommended_actions=["Review the endpoint process tree."],
        reasoning="High Wazuh severity and suspicious encoded command evidence.",
        evidence=[evidence],
        model="openrouter/free",
        latency_ms=1200,
        token_usage={"total_tokens": 500},
    )
    decision = RoutingDecision(
        id="route-001",
        triage_result_id="triage-001",
        target_id="alert-001",
        action=TriageAction.PAGE_NOW,
        status=RoutingStatus.QUEUED,
        destination="analyst_queue",
        message="Queued high-priority alert for analyst review.",
    )

    store.save_triage_result(result)
    store.save_routing_decision(decision)
    stats = store.stats()

    assert stats.triage_results == 1
    assert stats.routing_decisions == 1


def test_dedup_keys_are_added_checked_and_expired(store):
    """Deduplication keys should prevent repeated processing until expiry.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify dedup key behavior.
    """

    key = "wazuh:alert-001"

    assert store.has_dedup_key(key) is False

    store.add_dedup_key(key, ttl_hours=24)

    assert store.has_dedup_key(key) is True
    assert store.stats().dedup_keys == 1
    assert store.delete_expired_dedup_keys() == 0
    assert store.has_dedup_key(key) is True


def test_get_missing_records_returns_none(store):
    """Missing agent, alert, and candidate lookups should return None.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify missing-record behavior.
    """

    assert store.get_wazuh_agent("missing-agent") is None
    assert store.get_alert("missing-alert") is None
    assert store.get_incident_candidate("missing-candidate") is None


def test_triage_score_must_be_between_one_and_ten():
    """Invalid triage scores should fail fast at model creation time.

    Inputs:
        None.

    Outputs:
        None. Assertions verify validation behavior.
    """

    with pytest.raises(ValueError, match="score must be between 1 and 10"):
        TriageResult(
            id="triage-invalid",
            target_id="alert-001",
            target_type="alert",
            score=11,
            fp_likelihood=FalsePositiveLikelihood.UNKNOWN,
            classification="invalid",
            action=TriageAction.QUEUE_REVIEW,
            summary="Invalid score test.",
        )