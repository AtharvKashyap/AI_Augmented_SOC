

"""Tests for the end-to-end SOC pipeline orchestration layer.

These tests use fake dependencies to verify that SOCPipeline calls each stage in
order without requiring real external services, LLM calls, SMTP, Slack, or live
Wazuh/Security Onion connections.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from soc.enrichment import enrich_indicator

from soc.models import (
    Alert,
    AlertSeverity,
    EnrichmentResult,
    EventSource,
    FalsePositiveLikelihood,
    IncidentCandidate,
    RawEvent,
    RoutingDecision,
    RoutingStatus,
    TriageAction,
    TriageResult,
)
from soc.notifier import NotificationResult
from soc.pipeline import (
    PipelineConfig,
    PipelineError,
    PipelineRunResult,
    SOCPipeline,
    run_replay_directory,
    run_replay_file,
)
from soc.router import RoutingConfig, TriageRouter


BASE_TIME = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


def _raw_event(event_id: str = "raw-001") -> RawEvent:
    """Create a representative raw event.

    Inputs:
        event_id: Raw event ID.

    Outputs:
        RawEvent object.
    """

    return RawEvent(
        id=event_id,
        source=EventSource.WAZUH,
        timestamp=BASE_TIME,
        payload={
            "id": event_id,
            "rule": {"level": 10, "description": "Suspicious PowerShell execution"},
            "agent": {"id": "001", "name": "endpoint-01"},
        },
        received_at=BASE_TIME,
    )


def _alert(alert_id: str = "alert-001") -> Alert:
    """Create a representative alert.

    Inputs:
        alert_id: Alert ID.

    Outputs:
        Alert object.
    """

    return Alert(
        id=alert_id,
        source=EventSource.WAZUH,
        timestamp=BASE_TIME,
        severity=AlertSeverity.HIGH,
        source_severity=10,
        rule_name="Suspicious PowerShell execution",
        rule_groups=["windows", "powershell"],
        src_ip="10.0.1.10",
        dst_ip="8.8.8.8",
        hostname="endpoint-01",
        agent_id="001",
        agent_os="Windows",
        user="alice",
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand abc123",
        raw={"raw_id": alert_id},
    )


def _candidate(alerts: list[Alert] | None = None) -> IncidentCandidate:
    """Create a representative incident candidate.

    Inputs:
        alerts: Optional alert list.

    Outputs:
        IncidentCandidate object.
    """

    alerts = alerts or [_alert()]
    return IncidentCandidate(
        id="candidate-001",
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        alerts=alerts,
        primary_host="endpoint-01",
        primary_user="alice",
        src_ips=["10.0.1.10"],
        dst_ips=["8.8.8.8"],
        related_events=[],
        enrichments=[],
        created_at=BASE_TIME,
    )


def _enrichment() -> EnrichmentResult:
    """Create a representative enrichment result.

    Inputs:
        None.

    Outputs:
        EnrichmentResult object.
    """

    return enrich_indicator(
        "command",
        "powershell.exe -EncodedCommand abc123",
        target_id="candidate-001",
    )


def _triage() -> TriageResult:
    """Create a representative triage result.

    Inputs:
        None.

    Outputs:
        TriageResult object.
    """

    return TriageResult(
        id="triage-001",
        target_id="candidate-001",
        target_type="incident_candidate",
        score=8,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="likely_true_positive_high_priority",
        action=TriageAction.PAGE_NOW,
        summary="Suspicious PowerShell activity requires review.",
    )


def _routing() -> RoutingDecision:
    """Create a representative routing decision.

    Inputs:
        None.

    Outputs:
        RoutingDecision object.
    """

    return RoutingDecision(
        id="route-001",
        triage_result_id="triage-001",
        target_id="candidate-001",
        action=TriageAction.PAGE_NOW,
        status=RoutingStatus.CREATED,
        destination="page_now",
        message="Page analyst immediately.",
        error=None,
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )


@dataclass(slots=True)
class FakeStore:
    """Fake store that records persisted objects."""

    initialized: bool = False
    raw_events: list[RawEvent] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    candidates: list[IncidentCandidate] = field(default_factory=list)
    triage_results: list[TriageResult] = field(default_factory=list)
    routing_decisions: list[RoutingDecision] = field(default_factory=list)
    queued_for_review: list[TriageResult] = field(default_factory=list)
    fail_on_initialize: bool = False
    fail_on_save_alert: bool = False
    fail_on_enqueue: bool = False

    def initialize(self) -> None:
        """Record initialization."""

        if self.fail_on_initialize:
            raise RuntimeError("store init failed")
        self.initialized = True

    def save_raw_event(self, event: RawEvent) -> None:
        """Record raw event save."""

        self.raw_events.append(event)

    def save_alert(self, alert: Alert) -> None:
        """Record alert save."""

        if self.fail_on_save_alert:
            raise RuntimeError("save alert failed")
        self.alerts.append(alert)

    def save_incident_candidate(self, candidate: IncidentCandidate) -> None:
        """Record candidate save."""

        self.candidates.append(candidate)

    def save_triage_result(self, result: TriageResult) -> None:
        """Record triage save."""

        self.triage_results.append(result)

    def save_routing_decision(self, decision: RoutingDecision) -> None:
        """Record routing save."""

        self.routing_decisions.append(decision)

    def enqueue_for_review(self, result: TriageResult) -> None:
        """Record review-queue enqueue."""

        if self.fail_on_enqueue:
            raise RuntimeError("enqueue failed")
        self.queued_for_review.append(result)


@dataclass(slots=True)
class FakeDedup:
    """Fake deduplication service."""

    seen_raw_event_ids: set[str] = field(default_factory=set)
    seen_alert_ids: set[str] = field(default_factory=set)
    marked_raw_event_ids: list[str] = field(default_factory=list)
    marked_alert_ids: list[str] = field(default_factory=list)

    def has_seen_raw_event(self, event: RawEvent) -> bool:
        """Return whether raw event should be treated as duplicate."""

        return event.id in self.seen_raw_event_ids

    def mark_raw_event_seen(self, event: RawEvent) -> None:
        """Record raw event mark."""

        self.marked_raw_event_ids.append(event.id)

    def has_seen_alert(self, alert: Alert) -> bool:
        """Return whether alert should be treated as duplicate."""

        return alert.id in self.seen_alert_ids

    def mark_alert_seen(self, alert: Alert) -> None:
        """Record alert mark."""

        self.marked_alert_ids.append(alert.id)


@dataclass(slots=True)
class FakeNormalizer:
    """Fake normalizer that maps raw events to alerts."""

    alerts_by_raw_id: dict[str, Alert]
    calls: list[str] = field(default_factory=list)
    fail_raw_ids: set[str] = field(default_factory=set)

    def normalize(self, event: RawEvent) -> Alert:
        """Return mapped alert or raise configured error."""

        self.calls.append(event.id)
        if event.id in self.fail_raw_ids:
            raise RuntimeError("normalization failed")
        return self.alerts_by_raw_id[event.id]


@dataclass(slots=True)
class FakeClusterer:
    """Fake clusterer that returns a fixed candidate list."""

    candidates: list[IncidentCandidate]
    received_alerts: list[Alert] = field(default_factory=list)
    should_fail: bool = False

    def cluster(self, alerts: list[Alert]) -> list[IncidentCandidate]:
        """Record alerts and return candidates."""

        if self.should_fail:
            raise RuntimeError("clustering failed")
        self.received_alerts = list(alerts)
        if not alerts:
            return []
        return self.candidates


@dataclass(slots=True)
class FakeEnricher:
    """Fake enricher that returns fixed enrichments."""

    enrichments: list[EnrichmentResult]
    calls: list[str] = field(default_factory=list)
    should_fail: bool = False

    def enrich_candidate(self, candidate: IncidentCandidate) -> list[EnrichmentResult]:
        """Record candidate and return enrichments."""

        self.calls.append(candidate.id)
        if self.should_fail:
            raise RuntimeError("enrichment failed")
        return self.enrichments


@dataclass(slots=True)
class FakeTriageEngine:
    """Fake triage engine that returns a fixed triage result."""

    triage_result: TriageResult
    calls: list[str] = field(default_factory=list)
    received_enrichments: list[list[EnrichmentResult]] = field(default_factory=list)
    should_fail: bool = False

    def triage_candidate(
        self,
        candidate: IncidentCandidate,
        enrichments: list[EnrichmentResult],
    ) -> TriageResult:
        """Record candidate and return triage result."""

        self.calls.append(candidate.id)
        self.received_enrichments.append(enrichments)
        if self.should_fail:
            raise RuntimeError("triage failed")
        return self.triage_result


@dataclass(slots=True)
class FakeRouter:
    """Fake router that returns a fixed routing decision."""

    routing: RoutingDecision
    calls: list[str] = field(default_factory=list)
    should_fail: bool = False

    def route(self, triage: TriageResult) -> RoutingDecision:
        """Record triage and return routing decision."""

        self.calls.append(triage.id)
        if self.should_fail:
            raise RuntimeError("routing failed")
        return self.routing


@dataclass(slots=True)
class FakeReporter:
    """Fake reporter that returns deterministic Markdown."""

    calls: list[str] = field(default_factory=list)
    received_enrichments: list[list[EnrichmentResult]] = field(default_factory=list)

    def build_candidate_report(
        self,
        candidate: IncidentCandidate,
        triage: TriageResult,
        *,
        routing: RoutingDecision,
        enrichments: list[EnrichmentResult],
    ) -> str:
        """Record report build and return Markdown text."""

        self.calls.append(candidate.id)
        self.received_enrichments.append(enrichments)
        return f"# Report for {candidate.id}\nScore: {triage.score}/10\nRoute: {routing.destination}\n"


@dataclass(slots=True)
class FakeNotifier:
    """Fake notifier that records notifications."""

    calls: list[str] = field(default_factory=list)
    should_fail: bool = False

    def notify_triage(
        self,
        triage: TriageResult,
        *,
        routing: RoutingDecision,
        report_text: str,
    ) -> list[NotificationResult]:
        """Record notification and return fake result."""

        self.calls.append(triage.id)
        if self.should_fail:
            raise RuntimeError("notification failed")
        return [
            NotificationResult(
                channel="dry_run",
                success=True,
                destination="local",
                message="recorded",
                error=None,
                sent_at=BASE_TIME,
            )
        ]


def _pipeline(
    tmp_path: Path,
    *,
    raw_events: list[RawEvent] | None = None,
    alerts: list[Alert] | None = None,
    candidates: list[IncidentCandidate] | None = None,
    dedup: FakeDedup | None = None,
    store: FakeStore | None = None,
    send_notifications: bool = True,
    write_reports: bool = True,
    fail_fast: bool = False,
) -> tuple[SOCPipeline, dict[str, Any]]:
    """Build pipeline with fake dependencies.

    Inputs:
        tmp_path: Pytest temp directory.
        raw_events: Optional raw events.
        alerts: Optional alerts.
        candidates: Optional candidates.
        dedup: Optional fake dedup.
        store: Optional fake store.
        send_notifications: Whether pipeline should send notifications.
        write_reports: Whether pipeline should write reports.
        fail_fast: Whether pipeline should fail fast.

    Outputs:
        Tuple of pipeline and dependency dictionary.
    """

    raw_events = raw_events or [_raw_event()]
    alerts = alerts or [_alert()]
    candidates = candidates or [_candidate(alerts)]
    normalizer = FakeNormalizer({event.id: alerts[index] for index, event in enumerate(raw_events)})
    clusterer = FakeClusterer(candidates)
    enricher = FakeEnricher([_enrichment()])
    triage_engine = FakeTriageEngine(_triage())
    router = FakeRouter(_routing())
    reporter = FakeReporter()
    notifier = FakeNotifier()
    config = PipelineConfig(
        output_dir=tmp_path / "reports",
        write_reports=write_reports,
        send_notifications=send_notifications,
        fail_fast=fail_fast,
    )
    pipeline = SOCPipeline(
        config=config,
        normalizer=normalizer,  # type: ignore[arg-type]
        dedup=dedup,
        store=store,
        clusterer=clusterer,  # type: ignore[arg-type]
        enricher=enricher,  # type: ignore[arg-type]
        triage_engine=triage_engine,  # type: ignore[arg-type]
        router=router,  # type: ignore[arg-type]
        reporter=reporter,  # type: ignore[arg-type]
        notifier=notifier,  # type: ignore[arg-type]
    )
    deps = {
        "raw_events": raw_events,
        "alerts": alerts,
        "candidates": candidates,
        "normalizer": normalizer,
        "clusterer": clusterer,
        "enricher": enricher,
        "triage_engine": triage_engine,
        "router": router,
        "reporter": reporter,
        "notifier": notifier,
        "store": store,
        "dedup": dedup,
    }
    return pipeline, deps


def test_pipeline_processes_events_end_to_end(tmp_path):
    """Pipeline should process raw events through all main stages."""

    store = FakeStore()
    dedup = FakeDedup()
    pipeline, deps = _pipeline(tmp_path, store=store, dedup=dedup)

    result = pipeline.run_events(deps["raw_events"])

    assert isinstance(result, PipelineRunResult)
    assert result.errors == []
    assert len(result.raw_events) == 1
    assert len(result.normalized_alerts) == 1
    assert len(result.accepted_alerts) == 1
    assert len(result.candidates) == 1
    assert len(result.item_results) == 1
    assert store.initialized is True
    assert store.raw_events == deps["raw_events"]
    assert store.alerts == deps["alerts"]
    assert store.candidates == deps["candidates"]
    assert [result.id for result in store.triage_results] == ["triage-001"]
    assert [decision.id for decision in store.routing_decisions] == ["route-001"]
    assert deps["normalizer"].calls == ["raw-001"]
    assert deps["clusterer"].received_alerts == deps["alerts"]
    assert deps["enricher"].calls == ["candidate-001"]
    assert deps["triage_engine"].calls == ["candidate-001"]
    assert deps["router"].calls == ["triage-001"]
    assert deps["reporter"].calls == ["candidate-001"]
    assert deps["notifier"].calls == ["triage-001"]


def test_pipeline_writes_report_file(tmp_path):
    """Pipeline should write Markdown report files when enabled."""

    pipeline, deps = _pipeline(tmp_path)

    result = pipeline.run_events(deps["raw_events"])

    assert len(result.report_paths) == 1
    report_path = result.report_paths[0]
    assert report_path == tmp_path / "reports" / "candidate-001.md"
    assert report_path.exists()
    assert "# Report for candidate-001" in report_path.read_text(encoding="utf-8")


def test_pipeline_can_disable_report_writing_and_notifications(tmp_path):
    """Pipeline should allow report writing and notifications to be disabled."""

    pipeline, deps = _pipeline(tmp_path, write_reports=False, send_notifications=False)

    result = pipeline.run_events(deps["raw_events"])

    assert result.item_results[0].report_path is None
    assert result.item_results[0].notifications == []
    assert deps["notifier"].calls == []
    assert result.report_paths == []


def test_pipeline_summary_counts_outputs(tmp_path):
    """PipelineRunResult.to_summary should count pipeline outputs."""

    pipeline, deps = _pipeline(tmp_path)

    result = pipeline.run_events(deps["raw_events"])
    summary = result.to_summary()

    assert summary["raw_events"] == 1
    assert summary["normalized_alerts"] == 1
    assert summary["accepted_alerts"] == 1
    assert summary["skipped_raw_events"] == 0
    assert summary["skipped_alerts"] == 0
    assert summary["candidates"] == 1
    assert summary["reports"] == 1
    assert summary["notifications"] == 1
    assert summary["errors"] == []
    assert "started_at" in summary
    assert "finished_at" in summary


def test_pipeline_skips_duplicate_raw_events(tmp_path):
    """Pipeline should skip raw events already seen by dedup service."""

    store = FakeStore()
    dedup = FakeDedup(seen_raw_event_ids={"raw-001"})
    pipeline, deps = _pipeline(tmp_path, store=store, dedup=dedup)

    result = pipeline.run_events(deps["raw_events"])

    assert result.skipped_raw_events == deps["raw_events"]
    assert result.normalized_alerts == []
    assert result.accepted_alerts == []
    assert result.candidates == []
    assert result.item_results == []
    assert store.raw_events == []
    assert deps["normalizer"].calls == []


def test_pipeline_skips_duplicate_alerts(tmp_path):
    """Pipeline should skip alerts already seen by dedup service."""

    store = FakeStore()
    dedup = FakeDedup(seen_alert_ids={"alert-001"})
    pipeline, deps = _pipeline(tmp_path, store=store, dedup=dedup)

    result = pipeline.run_events(deps["raw_events"])

    assert result.skipped_alerts == deps["alerts"]
    assert result.normalized_alerts == deps["alerts"]
    assert result.accepted_alerts == []
    assert result.candidates == []
    assert store.raw_events == deps["raw_events"]
    assert store.alerts == []


def test_pipeline_can_disable_deduplication(tmp_path):
    """Pipeline should ignore dedup service when deduplicate is false."""

    dedup = FakeDedup(seen_raw_event_ids={"raw-001"}, seen_alert_ids={"alert-001"})
    pipeline, deps = _pipeline(tmp_path, dedup=dedup)
    pipeline.config = PipelineConfig(
        output_dir=tmp_path / "reports",
        write_reports=False,
        send_notifications=False,
        deduplicate=False,
    )

    result = pipeline.run_events(deps["raw_events"])

    assert result.skipped_raw_events == []
    assert result.skipped_alerts == []
    assert result.accepted_alerts == deps["alerts"]


def test_pipeline_collects_non_fatal_normalization_errors(tmp_path):
    """Pipeline should collect normalization errors and continue."""

    pipeline, deps = _pipeline(tmp_path)
    deps["normalizer"].fail_raw_ids.add("raw-001")

    result = pipeline.run_events(deps["raw_events"])

    assert result.normalized_alerts == []
    assert result.accepted_alerts == []
    assert result.candidates == []
    assert result.item_results == []
    assert any("normalization failed for raw-001" in error for error in result.errors)


def test_pipeline_collects_store_errors_and_continues(tmp_path):
    """Pipeline should collect store save errors but continue processing."""

    store = FakeStore(fail_on_save_alert=True)
    pipeline, deps = _pipeline(tmp_path, store=store)

    result = pipeline.run_events(deps["raw_events"])

    assert len(result.accepted_alerts) == 1
    assert len(result.item_results) == 1
    assert any("save alert failed for alert-001" in error for error in result.errors)


def test_pipeline_collects_enrichment_error_and_uses_empty_enrichments(tmp_path):
    """Pipeline should continue with empty enrichments when enrichment fails."""

    pipeline, deps = _pipeline(tmp_path)
    deps["enricher"].should_fail = True

    result = pipeline.run_events(deps["raw_events"])

    assert len(result.item_results) == 1
    assert result.item_results[0].enrichments == []
    assert deps["triage_engine"].received_enrichments == [[]]
    assert any("enrichment failed for candidate-001" in error for error in result.errors)


def test_pipeline_skips_candidate_when_triage_fails(tmp_path):
    """Pipeline should skip item result when triage fails."""

    pipeline, deps = _pipeline(tmp_path)
    deps["triage_engine"].should_fail = True

    result = pipeline.run_events(deps["raw_events"])

    assert result.candidates == deps["candidates"]
    assert result.item_results == []
    assert any("triage failed for candidate-001" in error for error in result.errors)


def test_pipeline_skips_candidate_when_routing_fails(tmp_path):
    """Pipeline should skip item result when routing fails."""

    pipeline, deps = _pipeline(tmp_path)
    deps["router"].should_fail = True

    result = pipeline.run_events(deps["raw_events"])

    assert result.candidates == deps["candidates"]
    assert result.item_results == []
    assert any("routing failed for triage-001" in error for error in result.errors)


def test_pipeline_collects_notification_error_and_keeps_item_result(tmp_path):
    """Notification failures should not remove candidate item results."""

    pipeline, deps = _pipeline(tmp_path)
    deps["notifier"].should_fail = True

    result = pipeline.run_events(deps["raw_events"])

    assert len(result.item_results) == 1
    assert result.item_results[0].notifications == []
    assert any("notification failed for triage-001" in error for error in result.errors)


def test_pipeline_fail_fast_raises_pipeline_error(tmp_path):
    """Pipeline should raise immediately when fail_fast is enabled."""

    pipeline, deps = _pipeline(tmp_path, fail_fast=True)
    deps["normalizer"].fail_raw_ids.add("raw-001")

    with pytest.raises(PipelineError, match="normalization failed for raw-001"):
        pipeline.run_events(deps["raw_events"])


def test_pipeline_replay_file_convenience_function(tmp_path):
    """run_replay_file convenience wrapper should use provided pipeline."""

    replay_path = tmp_path / "events.json"
    replay_path.write_text(
        json.dumps(
            [
                {
                    "id": "raw-001",
                    "source": "wazuh",
                    "payload": {"id": "raw-001"},
                }
            ]
        ),
        encoding="utf-8",
    )
    pipeline, _deps = _pipeline(tmp_path)

    result = run_replay_file(replay_path, pipeline=pipeline)

    assert len(result.raw_events) == 1
    assert len(result.item_results) == 1


def test_pipeline_replay_directory_convenience_function(tmp_path):
    """run_replay_directory convenience wrapper should use provided pipeline."""

    replay_dir = tmp_path / "replay"
    replay_dir.mkdir()
    (replay_dir / "events.json").write_text(
        json.dumps(
            [
                {
                    "id": "raw-001",
                    "source": "wazuh",
                    "payload": {"id": "raw-001"},
                }
            ]
        ),
        encoding="utf-8",
    )
    pipeline, _deps = _pipeline(tmp_path)

    result = run_replay_directory(replay_dir, pipeline=pipeline)

    assert len(result.raw_events) == 1
    assert len(result.item_results) == 1


def test_pipeline_with_sqlite_store_factory(tmp_path):
    """SOCPipeline.with_sqlite_store should create store and dedup dependencies."""

    pipeline = SOCPipeline.with_sqlite_store(
        tmp_path / "soc.db",
        config=PipelineConfig(output_dir=tmp_path / "reports", write_reports=False),
    )

    assert pipeline.store is not None
    assert pipeline.dedup is not None


def test_pipeline_config_rejects_empty_output_dir():
    """PipelineConfig should reject empty output dir."""

    with pytest.raises(PipelineError, match="output_dir"):
        PipelineConfig(output_dir=Path(""))

def test_pipeline_queues_review_actions_for_an_analyst():
    """A queue_review routing decision must create reviewable analyst work.

    Writing a routing row without queueing anything an analyst can close makes
    "queued for review" a claim with nothing behind it.
    """

    store = FakeStore()
    pipeline = SOCPipeline(
        config=PipelineConfig(output_dir=Path("unused"), write_reports=False),
        store=store,
        router=TriageRouter(RoutingConfig(page_threshold=10, queue_threshold=1)),
    )

    result = pipeline.run_events([_raw_event()])

    assert result.item_results
    queued_actions = {item.routing.action for item in result.item_results}
    assert queued_actions == {TriageAction.QUEUE_REVIEW}
    assert [queued.id for queued in store.queued_for_review] == [
        item.triage.id for item in result.item_results
    ]


def test_pipeline_does_not_queue_paged_or_benign_actions():
    """Only review-bound results belong in the analyst queue."""

    store = FakeStore()
    pipeline = SOCPipeline(
        config=PipelineConfig(output_dir=Path("unused"), write_reports=False),
        store=store,
        router=TriageRouter(RoutingConfig(page_threshold=1, queue_threshold=1)),
    )

    result = pipeline.run_events([_raw_event()])

    assert {item.routing.action for item in result.item_results} == {TriageAction.PAGE_NOW}
    assert store.queued_for_review == []


def test_pipeline_records_an_enqueue_failure_without_losing_the_run():
    """A queue write failure must not discard an otherwise complete result."""

    store = FakeStore(fail_on_enqueue=True)
    pipeline = SOCPipeline(
        config=PipelineConfig(output_dir=Path("unused"), write_reports=False),
        store=store,
        router=TriageRouter(RoutingConfig(page_threshold=10, queue_threshold=1)),
    )

    result = pipeline.run_events([_raw_event()])

    assert result.item_results
    assert any("review queue" in error for error in result.errors)
