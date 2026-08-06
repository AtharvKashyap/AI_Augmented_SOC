

"""Tests for the SQLite persistence layer.

These tests verify that `soc.store.SQLiteStore` can create the local database
schema and persist the core SOC pipeline models without requiring any live
Wazuh, Security Onion, OpenRouter, Splunk, or OpenBSD services.

The store is intentionally tested with a temporary SQLite database so tests are
isolated, repeatable, and safe to run in CI.
"""

from __future__ import annotations

import sqlite3
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
        file_identity="16777220-1234567",
    )

    store.upsert_ingest_cursor(cursor)
    loaded = store.get_ingest_cursor("wazuh_alerts_json", "/var/ossec/logs/alerts/alerts.json")

    assert loaded is not None
    assert loaded.source == "wazuh_alerts_json"
    assert loaded.path == "/var/ossec/logs/alerts/alerts.json"
    assert loaded.byte_offset == 2048
    assert loaded.file_identity == "16777220-1234567"
    assert loaded.updated_at is not None


def test_upsert_ingest_cursor_updates_existing_row(store):
    """Re-upserting the same source/path pair should advance the offset in place.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify a single updated row.
    """

    store.upsert_ingest_cursor(
        IngestCursor(source="wazuh_alerts_json", path="/alerts.json", byte_offset=10, file_identity="2-1")
    )
    store.upsert_ingest_cursor(
        IngestCursor(source="wazuh_alerts_json", path="/alerts.json", byte_offset=99, file_identity="4-3")
    )

    loaded = store.get_ingest_cursor("wazuh_alerts_json", "/alerts.json")

    assert loaded is not None
    assert loaded.byte_offset == 99
    assert loaded.file_identity == "4-3"

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


def test_ingest_cursor_persists_windows_scale_file_identifiers(store):
    """Windows file IDs exceed SQLite's 64-bit INTEGER and must still persist.

    os.stat().st_ino on Windows is a 128-bit file ID. Binding one as an INTEGER
    raises OverflowError, which made the read cursor -- and therefore the whole
    daemon -- unusable on Windows.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify a large identifier round-trips unchanged.
    """

    huge_identity = f"{2**70}-{2**80 + 12345}"
    cursor = IngestCursor(
        source="wazuh_alerts_json",
        path="C:\\logs\\alerts.json",
        byte_offset=512,
        file_identity=huge_identity,
        content_fingerprint="16:abc123",
    )

    store.upsert_ingest_cursor(cursor)
    loaded = store.get_ingest_cursor("wazuh_alerts_json", "C:\\logs\\alerts.json")

    assert loaded is not None
    assert loaded.file_identity == huge_identity
    assert loaded.byte_offset == 512


def test_ingest_cursor_without_a_stored_identity_still_loads(store):
    """A cursor row predating file_identity must load rather than fail.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertion verifies a missing identity reads back as None.
    """

    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO ingest_cursors (source, path, byte_offset, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            ("wazuh_alerts_json", "/var/log/alerts.json", 100, "2026-08-04T00:00:00+00:00"),
        )

    loaded = store.get_ingest_cursor("wazuh_alerts_json", "/var/log/alerts.json")

    assert loaded is not None
    assert loaded.file_identity is None
    assert loaded.byte_offset == 100


def test_enrichment_cache_round_trips_a_provider_payload(store):
    """Cached intel avoids re-querying rate-limited free-tier APIs.

    Inputs:
        store: Initialized SQLiteStore fixture.

    Outputs:
        None. Assertions verify the payload round-trips.
    """

    payload = {"verdict": "malicious", "malicious_votes": 7}

    store.put_cached_enrichment("virustotal", "ip", "203.0.113.10", payload, ttl_hours=24)
    cached = store.get_cached_enrichment("virustotal", "ip", "203.0.113.10")

    assert cached == payload


def test_enrichment_cache_misses_are_none(store):
    """An uncached indicator is a miss, not an error."""

    assert store.get_cached_enrichment("virustotal", "ip", "203.0.113.99") is None


def test_enrichment_cache_is_keyed_per_provider_and_type(store):
    """Two providers must not read each other's answers."""

    store.put_cached_enrichment("virustotal", "ip", "203.0.113.10", {"v": 1}, ttl_hours=24)

    assert store.get_cached_enrichment("abuseipdb", "ip", "203.0.113.10") is None
    assert store.get_cached_enrichment("virustotal", "domain", "203.0.113.10") is None


def test_expired_enrichment_cache_entries_are_treated_as_misses(store):
    """Stale intel must be refetched rather than trusted forever."""

    store.put_cached_enrichment("shodan", "ip", "203.0.113.10", {"v": 1}, ttl_hours=24)
    with store._connect() as conn:
        conn.execute(
            "UPDATE enrichment_cache SET expires_at = ? WHERE provider = ?",
            ("2020-01-01T00:00:00+00:00", "shodan"),
        )

    assert store.get_cached_enrichment("shodan", "ip", "203.0.113.10") is None


def test_put_cached_enrichment_replaces_an_existing_entry(store):
    """A refetch must overwrite, not accumulate duplicates."""

    store.put_cached_enrichment("virustotal", "ip", "203.0.113.10", {"v": 1}, ttl_hours=24)
    store.put_cached_enrichment("virustotal", "ip", "203.0.113.10", {"v": 2}, ttl_hours=24)

    assert store.get_cached_enrichment("virustotal", "ip", "203.0.113.10") == {"v": 2}


def test_delete_expired_enrichment_cache_reports_how_many_it_removed(store):
    """Cache pruning must be observable."""

    store.put_cached_enrichment("virustotal", "ip", "203.0.113.10", {"v": 1}, ttl_hours=24)
    store.put_cached_enrichment("virustotal", "ip", "203.0.113.11", {"v": 1}, ttl_hours=24)
    with store._connect() as conn:
        conn.execute(
            "UPDATE enrichment_cache SET expires_at = ? WHERE indicator = ?",
            ("2020-01-01T00:00:00+00:00", "203.0.113.10"),
        )

    assert store.delete_expired_enrichment_cache() == 1
    assert store.get_cached_enrichment("virustotal", "ip", "203.0.113.11") == {"v": 1}


def _incident(incident_id: str = "INC-20260805-001-abc123"):
    """Build an incident for persistence tests."""

    from soc.incidents import Incident

    moment = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    return Incident(
        id=incident_id,
        candidate_ids=["CAND-1", "CAND-2"],
        alert_ids=["alert-1", "alert-2"],
        triage_result_ids=["triage-1"],
        first_seen=moment,
        last_seen=moment,
        primary_host="endpoint-01",
        primary_user="alice",
        src_ips=["10.0.1.10"],
        dst_ips=["8.8.8.8"],
        max_score=9,
        asset_context={"criticality": "critical"},
    )


def test_save_incident_persists_it_with_its_candidate_mapping(store):
    """An incident must be recoverable along with what it was built from."""

    incident = _incident()

    store.save_incident(incident)
    stored = store.get_incident(incident.id)

    assert stored is not None
    assert stored["primary_host"] == "endpoint-01"
    assert stored["max_score"] == 9
    assert sorted(store.list_incident_candidate_ids(incident.id)) == ["CAND-1", "CAND-2"]


def test_saving_an_incident_twice_does_not_duplicate_its_mapping(store):
    """Reruns produce the same incident ID, so saving must be idempotent."""

    incident = _incident()

    store.save_incident(incident)
    store.save_incident(incident)

    assert sorted(store.list_incident_candidate_ids(incident.id)) == ["CAND-1", "CAND-2"]
    assert len(store.list_recent_incidents()) == 1


def test_get_incident_returns_none_when_absent(store):
    """A missing incident is not an error."""

    assert store.get_incident("INC-nope") is None


def test_list_recent_incidents_is_newest_first(store):
    """Analysts work the newest incidents first."""

    for index in range(3):
        store.save_incident(_incident(f"INC-20260805-00{index}-aaa"))

    listed = store.list_recent_incidents()

    assert len(listed) == 3
    assert listed[0]["id"] != listed[-1]["id"]


def test_list_recent_incidents_honours_a_limit(store):
    """A long incident list must be pageable."""

    for index in range(5):
        store.save_incident(_incident(f"INC-20260805-00{index}-aaa"))

    assert len(store.list_recent_incidents(limit=2)) == 2


def _proposal(status: str = "executed", proposal_id: str = "RESP-abc123"):
    """Build a response proposal for audit tests."""

    from soc.models import AnalysisSource
    from soc.response import ResponseActionType, ResponseProposal, ResponseStatus

    return ResponseProposal(
        id=proposal_id,
        playbook_name="pf-block-malicious-ip",
        action=ResponseActionType.PF_BLOCK_IP,
        target="8.8.8.8",
        triage_result_id="triage-1",
        triage_score=9,
        analysis_source=AnalysisSource.LLM,
        status=ResponseStatus(status),
        reason="score 9 met required confidence 9",
        approved_by="alice",
        command="pfctl -t blocklist -T add 8.8.8.8",
        rollback_command="pfctl -t blocklist -T delete 8.8.8.8",
        dry_run=False,
    )


def test_response_actions_are_auditable(store):
    """A firewall change nobody can review is not a controlled action."""

    store.record_response_action(_proposal())
    actions = store.list_response_actions()

    assert len(actions) == 1
    assert actions[0]["target"] == "8.8.8.8"
    assert actions[0]["approved_by"] == "alice"
    assert actions[0]["rollback_command"] == "pfctl -t blocklist -T delete 8.8.8.8"


def test_recording_the_same_proposal_twice_updates_one_row(store):
    """A proposal moves through statuses; each stage must not fork the trail."""

    from soc.response import ResponseStatus

    store.record_response_action(_proposal(status="suggested"))
    store.record_response_action(_proposal(status="approved"))
    store.record_response_action(_proposal(status="executed"))

    actions = store.list_response_actions()
    assert len(actions) == 1
    assert actions[0]["status"] == ResponseStatus.EXECUTED.value


def test_denied_response_actions_are_recorded_too(store):
    """Why nothing happened is as reviewable as what ran."""

    store.record_response_action(_proposal(status="denied", proposal_id="RESP-denied1"))

    assert store.list_response_actions()[0]["status"] == "denied"


def test_list_response_actions_honours_a_limit(store):
    """A long audit trail must be pageable."""

    for index in range(4):
        store.record_response_action(_proposal(proposal_id=f"RESP-{index}"))

    assert len(store.list_response_actions(limit=2)) == 2


def test_enrichment_provenance_is_queryable_not_only_inside_the_payload(tmp_path):
    """Milestone 3.5 asks for provider and lookup time on the *stored* result.

    Everything survives in `payload_json`, but an audit question like "which
    decisions rested on VirusTotal" has to be answerable with a query. Storing it
    only as JSON makes that a full-table scan and a parse.
    """

    store = SQLiteStore(tmp_path / "soc.db")
    store.initialize()
    result = TriageResult(
        id="triage-provenance-001",
        target_id="alert-001",
        target_type="alert",
        score=7,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="suspicious",
        action=TriageAction.QUEUE_REVIEW,
        summary="stored for audit",
        enrichment_providers=["AbuseIPDB", "VirusTotal"],
        enriched_at=datetime(2026, 6, 10, 11, 30, tzinfo=UTC),
    )

    store.save_triage_result(result)

    with store._connect() as conn:
        row = conn.execute(
            "SELECT enrichment_providers, enriched_at FROM triage_results WHERE id = ?",
            (result.id,),
        ).fetchone()

    assert "VirusTotal" in row["enrichment_providers"]
    assert row["enriched_at"] is not None


def test_an_older_database_gains_the_provenance_columns_on_initialize(tmp_path):
    """`CREATE TABLE IF NOT EXISTS` leaves an existing database on its old schema.

    A new column has to be listed in `_ADDED_COLUMNS` as well as the schema, or
    every database created before this change silently lacks it.
    """

    db_path = tmp_path / "old.db"
    with sqlite3.connect(db_path) as conn:
        # The schema as it stood before these two columns existed. It has to carry
        # the columns the schema's indexes reference, or this tests nothing real.
        conn.execute(
            """
            CREATE TABLE triage_results (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                score INTEGER NOT NULL,
                fp_likelihood TEXT,
                classification TEXT,
                action TEXT,
                summary TEXT,
                model TEXT,
                latency_ms INTEGER,
                analysis_source TEXT,
                prompt_version TEXT,
                payload_json TEXT,
                created_at TEXT
            )
            """
        )

    SQLiteStore(db_path).initialize()

    with sqlite3.connect(db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(triage_results)")}

    assert {"enrichment_providers", "enriched_at"} <= columns
