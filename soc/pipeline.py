

"""End-to-end SOC processing pipeline.

This module coordinates the individual SOC components:
    raw/replay events -> normalization -> dedup -> storage -> clustering ->
    enrichment -> triage -> routing -> report generation -> notification.

The individual modules stay focused on one job. The pipeline is the conductor
that calls them in the right order and returns a structured result object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from soc.clustering import AlertClusterer
from soc.dedup import DeduplicationService
from soc.enrichment import LocalEnricher
from soc.incidents import Incident, IncidentPromoter
from soc.models import (
    Alert,
    EnrichmentResult,
    IncidentCandidate,
    RawEvent,
    RoutingDecision,
    TriageAction,
    TriageResult,
    utc_now,
)
from soc.normalizer import Normalizer
from soc.notifier import NotificationDispatcher, NotificationResult
from soc.replay import load_replay_directory, load_replay_file
from soc.report import MarkdownReportBuilder, write_report_file
from soc.router import TriageRouter
from soc.store import SQLiteStore
from soc.triage import TriageEngine

JsonDict = dict[str, Any]


class PipelineError(RuntimeError):
    """Raised when the SOC pipeline cannot complete."""


class StoreProtocol(Protocol):
    """Minimal store interface required by the pipeline."""

    def initialize(self) -> None:
        """Initialize backing storage."""

    def save_raw_event(self, event: RawEvent) -> None:
        """Persist a raw event."""

    def save_alert(self, alert: Alert) -> None:
        """Persist a normalized alert."""

    def save_incident_candidate(self, candidate: IncidentCandidate) -> None:
        """Persist an incident candidate."""

    def save_triage_result(self, result: TriageResult) -> None:
        """Persist a triage result."""

    def save_routing_decision(self, decision: RoutingDecision) -> None:
        """Persist a routing decision."""

    def enqueue_for_review(self, result: TriageResult) -> None:
        """Add a triage result to the analyst review queue.

        Optional: stores predating the review queue may omit this, and the
        pipeline skips queueing rather than failing when it is absent.
        """


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    """Runtime configuration for the SOC pipeline.

    Attributes:
        output_dir: Directory where Markdown reports and notification JSON files
            should be written.
        write_reports: Whether to write Markdown reports to disk.
        send_notifications: Whether to call the configured notification
            dispatcher.
        initialize_store: Whether to initialize the store before processing.
        deduplicate: Whether to skip previously seen raw events and alerts.
        promote_incidents: Whether qualifying candidates are promoted into
            incidents. Environments that only want the candidate tier can
            disable it.
        fail_fast: Whether to raise on the first processing error.
    """

    output_dir: Path = Path("reports")
    write_reports: bool = True
    send_notifications: bool = False
    initialize_store: bool = True
    deduplicate: bool = True
    promote_incidents: bool = True
    fail_fast: bool = False

    def __post_init__(self) -> None:
        """Validate pipeline configuration."""

        if self.output_dir == Path(""):
            raise PipelineError("output_dir cannot be empty")


@dataclass(slots=True)
class PipelineItemResult:
    """Result for one processed incident candidate.

    Attributes:
        candidate: IncidentCandidate object.
        enrichments: Enrichment results used for triage/reporting.
        triage: TriageResult produced by triage engine.
        routing: RoutingDecision produced by router.
        report_text: Markdown report body.
        report_path: Optional path written to disk.
        notifications: Notification delivery results.
    """

    candidate: IncidentCandidate
    enrichments: list[EnrichmentResult]
    triage: TriageResult
    routing: RoutingDecision
    report_text: str
    report_path: Path | None = None
    notifications: list[NotificationResult] = field(default_factory=list)


@dataclass(slots=True)
class PipelineRunResult:
    """Result for one pipeline run.

    Attributes:
        raw_events: Raw events received by the pipeline.
        normalized_alerts: Alerts produced by the normalizer before dedup skips.
        accepted_alerts: Alerts accepted after deduplication.
        skipped_raw_events: Raw events skipped by deduplication.
        skipped_alerts: Alerts skipped by deduplication.
        candidates: Incident candidates produced by clustering.
        item_results: Per-candidate processing outputs.
        errors: Non-fatal error strings collected during processing.
        started_at: Run start timestamp.
        finished_at: Run finish timestamp.
    """

    raw_events: list[RawEvent]
    normalized_alerts: list[Alert]
    accepted_alerts: list[Alert]
    skipped_raw_events: list[RawEvent]
    skipped_alerts: list[Alert]
    candidates: list[IncidentCandidate]
    item_results: list[PipelineItemResult]
    errors: list[str]
    started_at: Any
    finished_at: Any
    incidents: list[Incident] = field(default_factory=list)

    @property
    def report_paths(self) -> list[Path]:
        """Return all written report paths.

        Inputs:
            None.

        Outputs:
            List of report paths.
        """

        return [item.report_path for item in self.item_results if item.report_path is not None]

    def to_summary(self) -> JsonDict:
        """Return JSON-safe run summary.

        Inputs:
            None.

        Outputs:
            Summary dictionary.
        """

        return {
            "raw_events": len(self.raw_events),
            "normalized_alerts": len(self.normalized_alerts),
            "accepted_alerts": len(self.accepted_alerts),
            "skipped_raw_events": len(self.skipped_raw_events),
            "skipped_alerts": len(self.skipped_alerts),
            "candidates": len(self.candidates),
            "incidents": len(self.incidents),
            "reports": len(self.report_paths),
            "notifications": sum(len(item.notifications) for item in self.item_results),
            "errors": list(self.errors),
            "started_at": _format_time(self.started_at),
            "finished_at": _format_time(self.finished_at),
        }


class SOCPipeline:
    """Coordinate the end-to-end SOC workflow."""

    def __init__(
        self,
        *,
        config: PipelineConfig | None = None,
        normalizer: Normalizer | None = None,
        dedup: DeduplicationService | None = None,
        store: StoreProtocol | None = None,
        clusterer: AlertClusterer | None = None,
        enricher: LocalEnricher | None = None,
        intel_enricher: Any | None = None,
        asset_inventory: Any | None = None,
        triage_engine: TriageEngine | None = None,
        router: TriageRouter | None = None,
        incident_promoter: IncidentPromoter | None = None,
        reporter: MarkdownReportBuilder | None = None,
        notifier: NotificationDispatcher | None = None,
    ) -> None:
        """Initialize pipeline.

        Inputs:
            config: Optional PipelineConfig.
            normalizer: Optional Normalizer.
            dedup: Optional DeduplicationService.
            store: Optional store object.
            clusterer: Optional AlertClusterer.
            enricher: Optional LocalEnricher.
            intel_enricher: Optional external threat-intel enricher. Omitted means
                local enrichment only, which needs no API keys.
            asset_inventory: Optional asset inventory used to attach asset
                context. Omitted means no asset context, which is normal.
            triage_engine: Optional TriageEngine.
            router: Optional TriageRouter.
            incident_promoter: Optional IncidentPromoter deciding what becomes an
                incident.
            reporter: Optional MarkdownReportBuilder.
            notifier: Optional NotificationDispatcher.

        Outputs:
            None.
        """

        self.config = config or PipelineConfig()
        self.normalizer = normalizer or Normalizer()
        self.dedup = dedup
        self.store = store
        self.clusterer = clusterer or AlertClusterer()
        self.enricher = enricher or LocalEnricher()
        self.intel_enricher = intel_enricher
        self.asset_inventory = asset_inventory
        self.triage_engine = triage_engine or TriageEngine()
        self.router = router or TriageRouter()
        self.incident_promoter = incident_promoter or IncidentPromoter()
        self.reporter = reporter or MarkdownReportBuilder()
        self.notifier = notifier or NotificationDispatcher(dry_run=True)

    @classmethod
    def with_sqlite_store(
        cls,
        db_path: str | Path,
        *,
        config: PipelineConfig | None = None,
        **kwargs: Any,
    ) -> SOCPipeline:
        """Create pipeline backed by SQLiteStore and DeduplicationService.

        Inputs:
            db_path: SQLite database path.
            config: Optional PipelineConfig.
            kwargs: Additional SOCPipeline dependency overrides.

        Outputs:
            SOCPipeline instance.
        """

        store = SQLiteStore(db_path)
        dedup = DeduplicationService(store)
        return cls(config=config, store=store, dedup=dedup, **kwargs)

    def run_replay_file(self, path: str | Path) -> PipelineRunResult:
        """Load replay events from a file and process them.

        Inputs:
            path: Replay JSON file path.

        Outputs:
            PipelineRunResult.
        """

        return self.run_events(load_replay_file(path))

    def run_replay_directory(self, path: str | Path) -> PipelineRunResult:
        """Load replay events from a directory and process them.

        Inputs:
            path: Directory containing replay JSON files.

        Outputs:
            PipelineRunResult.
        """

        load_result = load_replay_directory(path)
        return self.run_events(load_result.events)

    def run_events(self, raw_events: list[RawEvent]) -> PipelineRunResult:
        """Process raw events end-to-end.

        Inputs:
            raw_events: Raw events to process.

        Outputs:
            PipelineRunResult.
        """

        started_at = utc_now()
        errors: list[str] = []
        normalized_alerts: list[Alert] = []
        accepted_alerts: list[Alert] = []
        skipped_raw_events: list[RawEvent] = []
        skipped_alerts: list[Alert] = []
        item_results: list[PipelineItemResult] = []

        self._initialize_store(errors)

        for raw_event in raw_events:
            if self._should_skip_raw_event(raw_event, errors):
                skipped_raw_events.append(raw_event)
                continue

            self._save_raw_event(raw_event, errors)
            alert = self._normalize_raw_event(raw_event, errors)
            if alert is None:
                continue

            normalized_alerts.append(alert)
            if self._should_skip_alert(alert, errors):
                skipped_alerts.append(alert)
                continue

            self._save_alert(alert, errors)
            accepted_alerts.append(alert)

        candidates = self._cluster_alerts(accepted_alerts, errors)
        for candidate in candidates:
            item = self._process_candidate(candidate, errors)
            if item is not None:
                item_results.append(item)

        incidents = self._promote_incidents(item_results, errors)

        return PipelineRunResult(
            incidents=incidents,
            raw_events=raw_events,
            normalized_alerts=normalized_alerts,
            accepted_alerts=accepted_alerts,
            skipped_raw_events=skipped_raw_events,
            skipped_alerts=skipped_alerts,
            candidates=candidates,
            item_results=item_results,
            errors=errors,
            started_at=started_at,
            finished_at=utc_now(),
        )

    def _initialize_store(self, errors: list[str]) -> None:
        """Initialize storage if configured.

        Inputs:
            errors: Mutable error list.

        Outputs:
            None.
        """

        if self.store is None or not self.config.initialize_store:
            return
        try:
            self.store.initialize()
        except Exception as exc:
            self._handle_error(errors, f"store initialize failed: {exc}")

    def _should_skip_raw_event(self, raw_event: RawEvent, errors: list[str]) -> bool:
        """Return whether raw event should be skipped by dedup.

        Inputs:
            raw_event: RawEvent object.
            errors: Mutable error list.

        Outputs:
            True when event should be skipped.
        """

        if self.dedup is None or not self.config.deduplicate:
            return False
        try:
            if self.dedup.has_seen_raw_event(raw_event):
                return True
            self.dedup.mark_raw_event_seen(raw_event)
            return False
        except Exception as exc:
            self._handle_error(errors, f"raw event dedup failed for {raw_event.id}: {exc}")
            return False

    def _should_skip_alert(self, alert: Alert, errors: list[str]) -> bool:
        """Return whether alert should be skipped by dedup.

        Inputs:
            alert: Alert object.
            errors: Mutable error list.

        Outputs:
            True when alert should be skipped.
        """

        if self.dedup is None or not self.config.deduplicate:
            return False
        try:
            if self.dedup.has_seen_alert(alert):
                return True
            self.dedup.mark_alert_seen(alert)
            return False
        except Exception as exc:
            self._handle_error(errors, f"alert dedup failed for {alert.id}: {exc}")
            return False

    def _normalize_raw_event(self, raw_event: RawEvent, errors: list[str]) -> Alert | None:
        """Normalize raw event into alert.

        Inputs:
            raw_event: RawEvent object.
            errors: Mutable error list.

        Outputs:
            Alert or None if normalization failed.
        """

        try:
            return self.normalizer.normalize(raw_event)
        except Exception as exc:
            self._handle_error(errors, f"normalization failed for {raw_event.id}: {exc}")
            return None

    def _cluster_alerts(self, alerts: list[Alert], errors: list[str]) -> list[IncidentCandidate]:
        """Cluster alerts into incident candidates.

        Inputs:
            alerts: Accepted alerts.
            errors: Mutable error list.

        Outputs:
            IncidentCandidate list.
        """

        try:
            return self.clusterer.cluster(alerts)
        except Exception as exc:
            self._handle_error(errors, f"clustering failed: {exc}")
            return []

    def _process_candidate(
        self,
        candidate: IncidentCandidate,
        errors: list[str],
    ) -> PipelineItemResult | None:
        """Process one candidate through enrichment, triage, routing, report, notify.

        Inputs:
            candidate: IncidentCandidate object.
            errors: Mutable error list.

        Outputs:
            PipelineItemResult or None if required processing failed.
        """

        self._attach_asset_context(candidate, errors)
        self._save_candidate(candidate, errors)
        enrichments = self._enrich_candidate(candidate, errors)
        triage = self._triage_candidate(candidate, enrichments, errors)
        if triage is None:
            return None

        self._save_triage_result(triage, errors)
        routing = self._route_triage(triage, errors)
        if routing is None:
            return None

        self._save_routing_decision(routing, errors)
        self._enqueue_for_review(triage, routing, errors)
        report_text = self.reporter.build_candidate_report(
            candidate,
            triage,
            routing=routing,
            enrichments=enrichments,
        )
        report_path = self._write_report(candidate, report_text, errors)
        notifications = self._notify(triage, routing, report_text, errors)
        return PipelineItemResult(
            candidate=candidate,
            enrichments=enrichments,
            triage=triage,
            routing=routing,
            report_text=report_text,
            report_path=report_path,
            notifications=notifications,
        )

    def _enrich_candidate(
        self,
        candidate: IncidentCandidate,
        errors: list[str],
    ) -> list[EnrichmentResult]:
        """Enrich one candidate.

        Inputs:
            candidate: IncidentCandidate object.
            errors: Mutable error list.

        Outputs:
            EnrichmentResult list.
        """

        enrichments: list[EnrichmentResult] = []
        try:
            enrichments.extend(self.enricher.enrich_candidate(candidate))
        except Exception as exc:
            self._handle_error(errors, f"enrichment failed for {candidate.id}: {exc}")

        if self.intel_enricher is not None:
            try:
                enrichments.extend(self.intel_enricher.enrich_candidate(candidate))
            except Exception as exc:
                # A provider outage costs the lookup, never the run.
                self._handle_error(errors, f"threat intel enrichment failed for {candidate.id}: {exc}")
        return enrichments

    def _triage_candidate(
        self,
        candidate: IncidentCandidate,
        enrichments: list[EnrichmentResult],
        errors: list[str],
    ) -> TriageResult | None:
        """Triage one candidate.

        Inputs:
            candidate: IncidentCandidate object.
            enrichments: Enrichment results.
            errors: Mutable error list.

        Outputs:
            TriageResult or None.
        """

        try:
            return self.triage_engine.triage_candidate(candidate, enrichments)
        except Exception as exc:
            self._handle_error(errors, f"triage failed for {candidate.id}: {exc}")
            return None

    def _route_triage(self, triage: TriageResult, errors: list[str]) -> RoutingDecision | None:
        """Route a triage result.

        Inputs:
            triage: TriageResult object.
            errors: Mutable error list.

        Outputs:
            RoutingDecision or None.
        """

        try:
            return self.router.route(triage)
        except Exception as exc:
            self._handle_error(errors, f"routing failed for {triage.id}: {exc}")
            return None

    def _write_report(
        self,
        candidate: IncidentCandidate,
        report_text: str,
        errors: list[str],
    ) -> Path | None:
        """Write candidate report if enabled.

        Inputs:
            candidate: IncidentCandidate object.
            report_text: Markdown report text.
            errors: Mutable error list.

        Outputs:
            Written path or None.
        """

        if not self.config.write_reports:
            return None
        try:
            report_path = self.config.output_dir / f"{candidate.id}.md"
            return write_report_file(report_text, report_path)
        except Exception as exc:
            self._handle_error(errors, f"report write failed for {candidate.id}: {exc}")
            return None

    def _notify(
        self,
        triage: TriageResult,
        routing: RoutingDecision,
        report_text: str,
        errors: list[str],
    ) -> list[NotificationResult]:
        """Send notifications if enabled.

        Inputs:
            triage: TriageResult object.
            routing: RoutingDecision object.
            report_text: Markdown report text.
            errors: Mutable error list.

        Outputs:
            NotificationResult list.
        """

        if not self.config.send_notifications:
            return []
        try:
            return self.notifier.notify_triage(triage, routing=routing, report_text=report_text)
        except Exception as exc:
            self._handle_error(errors, f"notification failed for {triage.id}: {exc}")
            return []

    def _save_raw_event(self, event: RawEvent, errors: list[str]) -> None:
        """Persist raw event when store exists.

        Inputs:
            event: RawEvent object.
            errors: Mutable error list.

        Outputs:
            None.
        """

        if self.store is None:
            return
        try:
            self.store.save_raw_event(event)
        except Exception as exc:
            self._handle_error(errors, f"save raw event failed for {event.id}: {exc}")

    def _save_alert(self, alert: Alert, errors: list[str]) -> None:
        """Persist alert when store exists.

        Inputs:
            alert: Alert object.
            errors: Mutable error list.

        Outputs:
            None.
        """

        if self.store is None:
            return
        try:
            self.store.save_alert(alert)
        except Exception as exc:
            self._handle_error(errors, f"save alert failed for {alert.id}: {exc}")

    def _save_candidate(self, candidate: IncidentCandidate, errors: list[str]) -> None:
        """Persist candidate when store exists.

        Inputs:
            candidate: IncidentCandidate object.
            errors: Mutable error list.

        Outputs:
            None.
        """

        if self.store is None:
            return
        try:
            self.store.save_incident_candidate(candidate)
        except Exception as exc:
            self._handle_error(errors, f"save candidate failed for {candidate.id}: {exc}")

    def _save_triage_result(self, triage: TriageResult, errors: list[str]) -> None:
        """Persist triage result when store exists.

        Inputs:
            triage: TriageResult object.
            errors: Mutable error list.

        Outputs:
            None.
        """

        if self.store is None:
            return
        try:
            self.store.save_triage_result(triage)
        except Exception as exc:
            self._handle_error(errors, f"save triage failed for {triage.id}: {exc}")

    def _save_routing_decision(self, routing: RoutingDecision, errors: list[str]) -> None:
        """Persist routing decision when store exists.

        Inputs:
            routing: RoutingDecision object.
            errors: Mutable error list.

        Outputs:
            None.
        """

        if self.store is None:
            return
        try:
            self.store.save_routing_decision(routing)
        except Exception as exc:
            self._handle_error(errors, f"save routing failed for {routing.id}: {exc}")

    def _promote_incidents(
        self,
        item_results: list[PipelineItemResult],
        errors: list[str],
    ) -> list[Incident]:
        """Promote qualifying candidates into incidents, persist and report them.

        The incident tier is deliberately narrower than the candidate tier: only
        candidates clearing the promotion bar become incidents, so an incident
        still means something to an analyst. Failures here are recorded rather
        than raised, because losing already-processed candidates to a problem in
        a later stage would be a worse outcome than a missing incident.

        Inputs:
            item_results: Processed candidate results.
            errors: Mutable error list.

        Outputs:
            Promoted incidents.
        """

        if not self.config.promote_incidents or not item_results:
            return []

        try:
            incidents = self.incident_promoter.promote(
                [(item.candidate, item.triage) for item in item_results],
                routing_decisions={item.candidate.id: item.routing for item in item_results},
            )
        except Exception as exc:
            self._handle_error(errors, f"incident promotion failed: {exc}")
            return []

        for incident in incidents:
            self._save_incident(incident, errors)
            self._write_incident_report(incident, item_results, errors)
        return incidents

    def _save_incident(self, incident: Incident, errors: list[str]) -> None:
        """Persist one incident when the store supports it.

        Inputs:
            incident: Incident to save.
            errors: Mutable error list.

        Outputs:
            None.
        """

        if self.store is None:
            return
        save = getattr(self.store, "save_incident", None)
        if save is None:
            return
        try:
            save(incident)
        except Exception as exc:
            self._handle_error(errors, f"save incident failed for {incident.id}: {exc}")

    def _write_incident_report(
        self,
        incident: Incident,
        item_results: list[PipelineItemResult],
        errors: list[str],
    ) -> None:
        """Write the Markdown report for one incident.

        Inputs:
            incident: Incident to report on.
            item_results: Processed candidate results, used to gather context.
            errors: Mutable error list.

        Outputs:
            None.
        """

        if not self.config.write_reports:
            return

        members = [item for item in item_results if item.candidate.id in set(incident.candidate_ids)]
        enrichments: list[EnrichmentResult] = []
        for item in members:
            enrichments.extend(item.enrichments)

        try:
            report_text = self.reporter.build_incident_report(
                incident,
                candidates=[item.candidate for item in members],
                triage_results=[item.triage for item in members],
                routing_decisions=[item.routing for item in members],
                enrichments=enrichments,
            )
            write_report_file(report_text, self.config.output_dir / f"{incident.id}.md")
        except Exception as exc:
            self._handle_error(errors, f"incident report failed for {incident.id}: {exc}")

    def _attach_asset_context(self, candidate: IncidentCandidate, errors: list[str]) -> None:
        """Attach inventory context for the candidate's primary asset.

        Asset criticality is often what separates queueing from paging, so this
        runs before enrichment and triage. A missing or broken inventory is
        recorded and skipped: unknown asset context is normal, and losing the
        alert over it would not be.

        Inputs:
            candidate: IncidentCandidate to annotate.
            errors: Mutable error list.

        Outputs:
            None. The candidate's asset_context is set when a match is found.
        """

        if self.asset_inventory is None:
            return

        first_src_ip = candidate.src_ips[0] if candidate.src_ips else None
        try:
            context = self.asset_inventory.lookup(
                hostname=candidate.primary_host,
                ip=first_src_ip,
            )
        except Exception as exc:
            self._handle_error(errors, f"asset lookup failed for {candidate.id}: {exc}")
            return

        if context is None:
            return
        to_dict = getattr(context, "to_dict", None)
        candidate.asset_context = to_dict() if callable(to_dict) else dict(context)

    def _enqueue_for_review(
        self,
        triage: TriageResult,
        routing: RoutingDecision,
        errors: list[str],
    ) -> None:
        """Add review-bound results to the analyst queue.

        Only `queue_review` results are queued. Paged results are already in
        front of an analyst, and likely-benign results stay searchable without
        demanding attention.

        Inputs:
            triage: TriageResult under review.
            routing: RoutingDecision produced for it.
            errors: Mutable error list.

        Outputs:
            None.
        """

        if self.store is None or routing.action != TriageAction.QUEUE_REVIEW:
            return

        enqueue = getattr(self.store, "enqueue_for_review", None)
        if enqueue is None:
            return

        try:
            enqueue(triage)
        except Exception as exc:
            self._handle_error(errors, f"review queue enqueue failed for {triage.id}: {exc}")

    def _handle_error(self, errors: list[str], message: str) -> None:
        """Collect or raise pipeline error.

        Inputs:
            errors: Mutable error list.
            message: Error message.

        Outputs:
            None.
        """

        if self.config.fail_fast:
            raise PipelineError(message)
        errors.append(message)


def run_replay_file(
    path: str | Path,
    *,
    pipeline: SOCPipeline | None = None,
) -> PipelineRunResult:
    """Convenience function to run one replay file.

    Inputs:
        path: Replay JSON file path.
        pipeline: Optional SOCPipeline instance.

    Outputs:
        PipelineRunResult.
    """

    active_pipeline = pipeline or SOCPipeline()
    return active_pipeline.run_replay_file(path)


def run_replay_directory(
    path: str | Path,
    *,
    pipeline: SOCPipeline | None = None,
) -> PipelineRunResult:
    """Convenience function to run one replay directory.

    Inputs:
        path: Replay directory path.
        pipeline: Optional SOCPipeline instance.

    Outputs:
        PipelineRunResult.
    """

    active_pipeline = pipeline or SOCPipeline()
    return active_pipeline.run_replay_directory(path)


def _format_time(value: Any) -> str:
    """Format timestamp for summaries.

    Inputs:
        value: Any timestamp-like object.

    Outputs:
        String timestamp.
    """

    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)