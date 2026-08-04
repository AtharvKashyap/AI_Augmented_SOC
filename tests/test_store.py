

"""Tests for the SQLite persistence layer.

These tests verify that `soc.store.SQLiteStore` can create the local database
schema and persist the core SOC pipeline models without requiring any live
Wazuh, Security Onion, OpenRouter, Splunk, or OpenBSD services.

The store is intentionally tested with a temporary SQLite database so tests are
isolated, repeatable, and safe to run in CI.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from soc.models import (
    Alert,
    AlertSeverity,
    AnalysisSource,
    AnalystVerdict,
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
from soc.store import IngestCursor, SQLiteStore, StoreError, StoreStats


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

    last_seen = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
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

    event_time = datetime(2026, 6, 10, 12, 30, tzinfo=UTC)
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

    event_time = datetime(2026, 6, 10, 13, 0, tzinfo=UTC)
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

def test_save_triage_result_persists_analysis_provenance(store):
    """Analysis source and prompt version must be queryable, not buried in JSON."""

    result = TriageResult(
        id="triage-provenance-001",
        target_id="CAND-20260610-001",
        target_type="incident_candidate",
        score=9,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="likely_true_positive",
        action=TriageAction.PAGE_NOW,
        summary="Model scored this as an active compromise.",
        model="vendor/model-x",
        latency_ms=1234,
        analysis_source=AnalysisSource.LLM,
        prompt_version="triage-v1",
    )

    store.save_triage_result(result)

    with store._connect() as conn:
        row = conn.execute(
            "SELECT analysis_source, prompt_version, latency_ms FROM triage_results WHERE id = ?",
            (result.id,),
        ).fetchone()

    assert row["analysis_source"] == "llm"
    assert row["prompt_version"] == "triage-v1"
    assert row["latency_ms"] == 1234


def test_initialize_adds_provenance_columns_to_existing_database(tmp_path):
    """An existing database created before provenance existed must be upgraded."""

    db_path = tmp_path / "legacy.db"
    legacy_store = SQLiteStore(db_path)
    with legacy_store._connect() as conn:
        conn.execute(
            """
            CREATE TABLE triage_results (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                score INTEGER NOT NULL,
                fp_likelihood TEXT NOT NULL,
                classification TEXT NOT NULL,
                action TEXT NOT NULL,
                summary TEXT NOT NULL,
                model TEXT,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

    SQLiteStore(db_path).initialize()

    with legacy_store._connect() as conn:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(triage_results)")}

    assert {"analysis_source", "prompt_version", "latency_ms"} <= columns


def test_get_ingest_cursor_returns_none_when_absent(store):
    """An unknown source/path pair should have no stored ingestion cursor.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify the missing-cursor contract.
    """

    assert store.get_ingest_cursor("wazuh_alerts_json", "/var/ossec/logs/alerts/alerts.json") is None


def test_upsert_and_get_ingest_cursor(store):
    """An ingestion cursor should round-trip through SQLite.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify persisted cursor fields.
    """

    cursor = IngestCursor(
        source="wazuh_alerts_json",
        path="/var/ossec/logs/alerts/alerts.json",
        byte_offset=2048,
        inode=1234567,
        device=16777220,
    )

    store.upsert_ingest_cursor(cursor)
    loaded = store.get_ingest_cursor("wazuh_alerts_json", "/var/ossec/logs/alerts/alerts.json")

    assert loaded is not None
    assert loaded.source == "wazuh_alerts_json"
    assert loaded.path == "/var/ossec/logs/alerts/alerts.json"
    assert loaded.byte_offset == 2048
    assert loaded.inode == 1234567
    assert loaded.device == 16777220
    assert loaded.updated_at is not None


def test_upsert_ingest_cursor_updates_existing_row(store):
    """Re-upserting the same source/path pair should advance the offset in place.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify a single updated row.
    """

    store.upsert_ingest_cursor(
        IngestCursor(source="wazuh_alerts_json", path="/alerts.json", byte_offset=10, inode=1, device=2)
    )
    store.upsert_ingest_cursor(
        IngestCursor(source="wazuh_alerts_json", path="/alerts.json", byte_offset=99, inode=3, device=4)
    )

    loaded = store.get_ingest_cursor("wazuh_alerts_json", "/alerts.json")

    assert loaded is not None
    assert loaded.byte_offset == 99
    assert loaded.inode == 3
    assert loaded.device == 4

    with store._connect() as conn:
        count = conn.execute("SELECT COUNT(*) AS n FROM ingest_cursors").fetchone()["n"]

    assert count == 1


def test_ingest_cursors_are_scoped_by_source_and_path(store):
    """Cursors for different sources or paths must not collide.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify per-key isolation.
    """

    store.upsert_ingest_cursor(IngestCursor(source="wazuh_alerts_json", path="/a.json", byte_offset=1))
    store.upsert_ingest_cursor(IngestCursor(source="wazuh_alerts_json", path="/b.json", byte_offset=2))
    store.upsert_ingest_cursor(IngestCursor(source="other_source", path="/a.json", byte_offset=3))

    assert store.get_ingest_cursor("wazuh_alerts_json", "/a.json").byte_offset == 1
    assert store.get_ingest_cursor("wazuh_alerts_json", "/b.json").byte_offset == 2
    assert store.get_ingest_cursor("other_source", "/a.json").byte_offset == 3


def test_ingest_cursor_rejects_invalid_values():
    """IngestCursor should validate its own fields.

    Inputs:
        None.

    Outputs:
        None. Assertions verify validation errors.
    """

    with pytest.raises(StoreError, match="source"):
        IngestCursor(source="", path="/a.json", byte_offset=0)

    with pytest.raises(StoreError, match="path"):
        IngestCursor(source="wazuh_alerts_json", path="", byte_offset=0)

    with pytest.raises(StoreError, match="byte_offset"):
        IngestCursor(source="wazuh_alerts_json", path="/a.json", byte_offset=-1)


def _queued_triage(result_id: str = "triage-queue-001", score: int = 5) -> TriageResult:
    """Build a triage result of the kind that lands in the review queue."""

    return TriageResult(
        id=result_id,
        target_id="CAND-20260803-001",
        target_type="incident_candidate",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.MEDIUM,
        classification="needs_analyst_review",
        action=TriageAction.QUEUE_REVIEW,
        summary="Needs a human decision.",
    )


def test_enqueue_for_review_creates_an_open_queue_item(store):
    """Queued triage results must become reviewable work, not just a stored row."""

    triage = _queued_triage()
    store.save_triage_result(triage)

    store.enqueue_for_review(triage)
    open_items = store.list_open_queue_items()

    assert len(open_items) == 1
    assert open_items[0].triage_result_id == triage.id
    assert open_items[0].target_id == "CAND-20260803-001"
    assert open_items[0].score == 5
    assert open_items[0].reviewed_at is None
    assert open_items[0].analyst_verdict is None


def test_enqueue_for_review_is_idempotent(store):
    """Re-running the pipeline must not queue the same decision twice."""

    triage = _queued_triage()
    store.save_triage_result(triage)

    store.enqueue_for_review(triage)
    store.enqueue_for_review(triage)

    assert len(store.list_open_queue_items()) == 1


def test_record_analyst_verdict_closes_the_item(store):
    """A recorded verdict must remove the item from the open queue."""

    triage = _queued_triage()
    store.save_triage_result(triage)
    store.enqueue_for_review(triage)

    store.record_analyst_verdict(
        triage.id,
        verdict=AnalystVerdict.TOO_HIGH,
        analyst_score=2,
        notes="Known backup job.",
    )

    assert store.list_open_queue_items() == []
    reviewed = store.list_reviewed_queue_items()
    assert len(reviewed) == 1
    assert reviewed[0].analyst_verdict == AnalystVerdict.TOO_HIGH
    assert reviewed[0].analyst_score == 2
    assert reviewed[0].notes == "Known backup job."
    assert reviewed[0].reviewed_at is not None


def test_record_analyst_verdict_rejects_an_unknown_item(store):
    """Recording a verdict for something never queued must fail loudly."""

    with pytest.raises(StoreError, match="not in the review queue"):
        store.record_analyst_verdict("triage-does-not-exist", verdict=AnalystVerdict.AGREE)


def test_record_analyst_verdict_rejects_an_out_of_range_score(store):
    """An analyst score must obey the same 1-10 scale as triage."""

    triage = _queued_triage()
    store.save_triage_result(triage)
    store.enqueue_for_review(triage)

    with pytest.raises(StoreError, match="between 1 and 10"):
        store.record_analyst_verdict(triage.id, verdict=AnalystVerdict.TOO_LOW, analyst_score=42)


def test_open_queue_items_are_oldest_first(store):
    """Analysts should work the queue in arrival order."""

    for index in range(3):
        triage = _queued_triage(result_id=f"triage-{index}", score=4 + index)
        store.save_triage_result(triage)
        store.enqueue_for_review(triage)

    assert [item.triage_result_id for item in store.list_open_queue_items()] == [
        "triage-0",
        "triage-1",
        "triage-2",
    ]


def test_list_open_queue_items_honours_a_limit(store):
    """A long queue must be pageable."""

    for index in range(5):
        triage = _queued_triage(result_id=f"triage-{index}")
        store.save_triage_result(triage)
        store.enqueue_for_review(triage)

    assert len(store.list_open_queue_items(limit=2)) == 2


def test_get_triage_result_returns_the_full_stored_payload(store):
    """Reviewing an item needs the triage detail, not just its score."""

    triage = _queued_triage()
    triage.summary = "Encoded PowerShell reaching a public address."
    triage.recommended_actions = ["Isolate endpoint-01"]
    store.save_triage_result(triage)

    stored = store.get_triage_result(triage.id)

    assert stored is not None
    assert stored["summary"] == "Encoded PowerShell reaching a public address."
    assert stored["recommended_actions"] == ["Isolate endpoint-01"]
    assert stored["score"] == 5


def test_get_triage_result_returns_none_when_absent(store):
    """A missing triage result is not an error."""

    assert store.get_triage_result("nope") is None


def test_list_raw_events_for_a_candidate_returns_its_source_events(store):
    """Rebuilding a replayable fixture needs the original raw events."""

    raw = RawEvent(
        id="raw-777",
        source=EventSource.WAZUH,
        received_at=datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
        timestamp=datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
        payload={"rule": {"level": 10, "description": "Test rule"}},
    )
    alert = Alert(
        id="alert-777",
        source=EventSource.WAZUH,
        timestamp=raw.timestamp,
        severity=AlertSeverity.HIGH,
        rule_name="Test rule",
        raw_event_id=raw.id,
    )
    candidate = IncidentCandidate(
        id="CAND-777",
        first_seen=raw.timestamp,
        last_seen=raw.timestamp,
        alerts=[alert],
    )
    store.save_raw_event(raw)
    store.save_alert(alert)
    store.save_incident_candidate(candidate)

    events = store.list_raw_events_for_target("CAND-777", "incident_candidate")

    assert len(events) == 1
    assert events[0]["id"] == "raw-777"
    assert events[0]["payload"]["rule"]["description"] == "Test rule"
    assert events[0]["source"] == "wazuh"


def test_list_raw_events_for_an_alert_target(store):
    """A single-alert target resolves to its own raw event."""

    raw = RawEvent(
        id="raw-888",
        source=EventSource.SECURITY_ONION,
        received_at=datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
        timestamp=datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
        payload={"event": {"severity": 1}},
    )
    alert = Alert(
        id="alert-888",
        source=EventSource.SECURITY_ONION,
        timestamp=raw.timestamp,
        severity=AlertSeverity.HIGH,
        raw_event_id=raw.id,
    )
    store.save_raw_event(raw)
    store.save_alert(alert)

    events = store.list_raw_events_for_target("alert-888", "alert")

    assert [event["id"] for event in events] == ["raw-888"]


def test_list_raw_events_for_an_unknown_target_is_empty(store):
    """An unknown target is not an error."""

    assert store.list_raw_events_for_target("nope", "incident_candidate") == []
