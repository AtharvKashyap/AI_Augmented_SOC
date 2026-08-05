

"""Tests for Markdown report generation.

These tests verify that report generation produces analyst-readable Markdown,
can write reports to disk, and can create report/evidence dataclasses while
remaining tolerant of small model field-name changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from soc.enrichment import enrich_indicator
from soc.incidents import Incident
from soc.models import (
    Alert,
    AlertSeverity,
    AnalysisSource,
    EnrichmentResult,
    EventSource,
    EvidenceItem,
    FalsePositiveLikelihood,
    IncidentCandidate,
    IncidentReport,
    RoutingDecision,
    RoutingStatus,
    TriageAction,
    TriageResult,
)
from soc.openrouter_client import OpenRouterError
from soc.report import (
    REPORT_PROMPT_VERSION,
    REPORT_SYSTEM_PROMPT,
    MarkdownReportBuilder,
    build_alert_report,
    build_candidate_evidence,
    build_candidate_report,
    build_incident_report,
    create_incident_report,
    write_report_file,
)

BASE_TIME = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _alert(alert_id: str = "alert-001") -> Alert:
    """Create a representative alert for report tests.

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
        raw={"rule": {"level": 10, "description": "Suspicious PowerShell execution"}},
    )


def _candidate() -> IncidentCandidate:
    """Create a representative incident candidate for report tests.

    Inputs:
        None.

    Outputs:
        IncidentCandidate object.
    """

    return IncidentCandidate(
        id="candidate-001",
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        alerts=[_alert("alert-001"), _alert("alert-002")],
        primary_host="endpoint-01",
        primary_user="alice",
        src_ips=["10.0.1.10"],
        dst_ips=["8.8.8.8", "1.1.1.1"],
        related_events=[],
        enrichments=[],
        created_at=BASE_TIME,
    )


def _triage(target_id: str = "candidate-001", target_type: str = "incident_candidate") -> TriageResult:
    """Create a representative triage result.

    Inputs:
        target_id: Triage target ID.
        target_type: Triage target type.

    Outputs:
        TriageResult object.
    """

    return TriageResult(
        id="triage-001",
        target_id=target_id,
        target_type=target_type,
        score=8,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="likely_true_positive_high_priority",
        action=TriageAction.PAGE_NOW,
        summary="PowerShell activity with public destination IP looks suspicious.",
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


def _enrichments() -> list[EnrichmentResult]:
    """Create representative enrichment results.

    Inputs:
        None.

    Outputs:
        EnrichmentResult list.
    """

    return [
        enrich_indicator("ip", "8.8.8.8", target_id="candidate-001"),
        enrich_indicator("command", "powershell.exe -EncodedCommand abc123", target_id="candidate-001"),
    ]


def _field(value: Any, *names: str, default: Any = None) -> Any:
    """Read first available field from a model object.

    Inputs:
        value: Object to inspect.
        names: Candidate attribute names.
        default: Fallback value.

    Outputs:
        Attribute value or default.
    """

    for name in names:
        if hasattr(value, name):
            return getattr(value, name)
    return default


def test_build_candidate_report_contains_core_sections():
    """Candidate report should include core Markdown sections.

    Inputs:
        None.

    Outputs:
        None. Assertions verify report content.
    """

    report = build_candidate_report(_candidate(), _triage(), routing=_routing(), enrichments=_enrichments())

    assert report.startswith("# Incident Candidate Report: candidate-001")
    assert "## Executive Summary" in report
    assert "## Triage Decision" in report
    assert "## Routing" in report
    assert "## Candidate Scope" in report
    assert "## Alerts" in report
    assert "## Enrichment Summary" in report
    assert "## Recommended Analyst Actions" in report
    assert "## Evidence" in report
    assert "Generated by AI_Augmented_SOC" in report


def test_build_candidate_report_contains_candidate_details():
    """Candidate report should include important candidate details.

    Inputs:
        None.

    Outputs:
        None. Assertions verify candidate detail content.
    """

    report = build_candidate_report(_candidate(), _triage(), enrichments=_enrichments())

    assert "candidate-001" in report
    assert "endpoint-01" in report
    assert "alice" in report
    assert "10.0.1.10" in report
    assert "8.8.8.8" in report
    assert "1.1.1.1" in report
    assert "alert-001" in report
    assert "alert-002" in report
    assert "Suspicious PowerShell execution" in report


def test_build_candidate_report_contains_triage_and_action_details():
    """Candidate report should include triage score and page-now action.

    Inputs:
        None.

    Outputs:
        None. Assertions verify triage/action content.
    """

    report = build_candidate_report(_candidate(), _triage(), routing=_routing())

    assert "8/10" in report
    assert "likely_true_positive_high_priority" in report
    assert "page_now" in report
    assert "False-positive likelihood" in report
    assert "Page or notify the responsible analyst immediately." in report
    assert "Page analyst immediately." in report


def test_build_candidate_report_contains_enrichment_table():
    """Candidate report should include enrichment indicators and risk hints.

    Inputs:
        None.

    Outputs:
        None. Assertions verify enrichment content.
    """

    report = build_candidate_report(_candidate(), _triage(), enrichments=_enrichments())

    assert "| Indicator | Type | Provider | Summary | Risk hints |" in report
    assert "8.8.8.8" in report
    assert "powershell.exe -EncodedCommand abc123" in report
    assert "encoded_powershell" in report


def test_build_candidate_report_without_optional_context_still_renders():
    """Candidate report should render without routing or enrichment context.

    Inputs:
        None.

    Outputs:
        None. Assertions verify optional context handling.
    """

    report = build_candidate_report(_candidate(), _triage())

    assert "## Routing" not in report
    assert "No enrichment results available." in report
    assert "No enrichment evidence available." in report


def test_build_alert_report_contains_alert_sections_and_details():
    """Alert report should include alert-focused sections and details.

    Inputs:
        None.

    Outputs:
        None. Assertions verify alert report content.
    """

    alert = _alert()
    triage = _triage(target_id="alert-001", target_type="alert")
    report = build_alert_report(alert, triage, routing=_routing(), enrichments=_enrichments())

    assert report.startswith("# Alert Report: alert-001")
    assert "## Executive Summary" in report
    assert "## Alert Details" in report
    assert "## Enrichment Summary" in report
    assert "alert-001" in report
    assert "Suspicious PowerShell execution" in report
    assert "powershell.exe -EncodedCommand abc123" in report
    assert "page_now" in report


def test_markdown_report_builder_methods_match_convenience_functions():
    """Builder methods should produce the same text as convenience functions.

    Inputs:
        None.

    Outputs:
        None. Assertions verify wrapper behavior.
    """

    builder = MarkdownReportBuilder()
    candidate = _candidate()
    triage = _triage()
    alert = _alert()
    alert_triage = _triage(target_id="alert-001", target_type="alert")

    assert builder.build_candidate_report(candidate, triage) == build_candidate_report(candidate, triage)
    assert builder.build_alert_report(alert, alert_triage) == build_alert_report(alert, alert_triage)


def test_build_candidate_evidence_creates_alert_and_enrichment_evidence():
    """Candidate evidence should include alert and enrichment evidence items.

    Inputs:
        None.

    Outputs:
        None. Assertions verify evidence generation.
    """

    evidence = build_candidate_evidence(_candidate(), _enrichments())

    assert len(evidence) == 4
    assert all(isinstance(item, EvidenceItem) for item in evidence)
    titles = [
        _field(item, "title", "field", "description", "content", "text", "value", default="")
        for item in evidence
    ]
    values = [_field(item, "value", "content", "text", "description", default="") for item in evidence]
    assert any("Suspicious PowerShell execution" in str(title) for title in titles)
    assert any("8.8.8.8" in str(title) for title in titles)
    assert any("Alert ID" in str(value) for value in values)


def test_create_incident_report_returns_model_with_report_content():
    """create_incident_report should return an IncidentReport dataclass.

    Inputs:
        None.

    Outputs:
        None. Assertions verify IncidentReport content.
    """

    report = create_incident_report(
        _candidate(),
        _triage(),
        routing=_routing(),
        enrichments=_enrichments(),
    )

    assert isinstance(report, IncidentReport)
    title = _field(report, "title", default="")
    body = _field(report, "body", "markdown", "content", "body_markdown", default="")
    report_id = _field(report, "id", "report_id", default="")

    assert str(report_id).startswith("report-")
    assert "candidate-001" in title
    assert "8/10" in body
    assert "## Executive Summary" in body
    assert "## Evidence" in body


def test_write_report_file_writes_markdown(tmp_path):
    """write_report_file should create parent directories and write text.

    Inputs:
        tmp_path: Pytest temporary path fixture.

    Outputs:
        None. Assertions verify file output.
    """

    report_text = build_candidate_report(_candidate(), _triage())
    output_path = tmp_path / "reports" / "candidate-001.md"

    written_path = write_report_file(report_text, output_path)

    assert written_path == output_path
    assert output_path.exists()
    assert output_path.read_text(encoding="utf-8") == report_text


def test_report_escapes_markdown_table_pipes_in_alert_rule():
    """Alert table should escape pipe characters in rule names.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies Markdown table escaping.
    """

    alert = _alert()
    alert.rule_name = "Suspicious | PowerShell"
    candidate = _candidate()
    candidate.alerts = [alert]

    report = build_candidate_report(candidate, _triage())

    assert "Suspicious \\| PowerShell" in report


def test_queue_review_report_has_queue_specific_recommendations():
    """QUEUE_REVIEW triage should produce queue-specific recommended actions.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies action-specific recommendations.
    """

    triage = TriageResult(
        id="triage-queue",
        target_id="candidate-001",
        target_type="incident_candidate",
        score=5,
        fp_likelihood=FalsePositiveLikelihood.MEDIUM,
        classification="needs_analyst_review",
        action=TriageAction.QUEUE_REVIEW,
        summary="Needs review.",
    )

    report = build_candidate_report(_candidate(), triage)

    assert "Queue for analyst review." in report
    assert "Check whether similar alerts occurred on the same host or user." in report


def test_likely_benign_report_has_low_priority_recommendations():
    """MARK_LIKELY_BENIGN triage should produce low-priority recommendations.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies action-specific recommendations.
    """

    triage = TriageResult(
        id="triage-benign",
        target_id="candidate-001",
        target_type="incident_candidate",
        score=2,
        fp_likelihood=FalsePositiveLikelihood.HIGH,
        classification="likely_false_positive_or_low_priority",
        action=TriageAction.MARK_LIKELY_BENIGN,
        summary="Likely benign.",
    )

    report = build_candidate_report(_candidate(), triage)

    assert "Mark as likely benign or low priority." in report
    assert "Monitor for recurrence or escalation." in report

def test_candidate_report_labels_local_scoring_as_local():
    """A deterministically scored report must not imply a model produced it."""

    report = MarkdownReportBuilder().build_candidate_report(_candidate(), _triage())

    assert "deterministic local scoring" in report.lower()
    assert "Analysis source" in report


def test_candidate_report_names_the_model_that_scored_it():
    """An LLM-scored report must name the model and prompt version."""

    triage = _triage()
    triage.analysis_source = AnalysisSource.LLM
    triage.model = "vendor/model-x"
    triage.prompt_version = "triage-v1"

    report = MarkdownReportBuilder().build_candidate_report(_candidate(), triage)

    assert "vendor/model-x" in report
    assert "triage-v1" in report
    assert "deterministic local scoring" not in report.lower()


# --- Incident-level reporting (Milestones 4.2 and 4.3) -----------------------

LEAKY_RAW_MARKER = "raw-payload-must-not-leak"
LEAKY_ENRICHMENT_MARKER = "enrichment-raw-must-not-leak"


def _incident_alert(
    alert_id: str,
    *,
    hostname: str = "endpoint-01",
    minutes: int = 0,
    rule_name: str = "Suspicious PowerShell execution",
    dst_ip: str = "203.0.113.10",
) -> Alert:
    """Create an alert for incident-level report tests.

    Inputs:
        alert_id: Alert ID.
        hostname: Affected host.
        minutes: Offset from BASE_TIME in minutes.
        rule_name: Detection rule name.
        dst_ip: Destination address.

    Outputs:
        Alert object whose raw payload carries a marker that must never leak.
    """

    return Alert(
        id=alert_id,
        source=EventSource.WAZUH,
        timestamp=BASE_TIME + timedelta(minutes=minutes),
        severity=AlertSeverity.HIGH,
        source_severity=10,
        rule_name=rule_name,
        rule_groups=["windows", "powershell"],
        src_ip="10.0.1.10",
        dst_ip=dst_ip,
        hostname=hostname,
        agent_id="001",
        agent_os="Windows",
        user="alice",
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand abc123",
        raw={"rule": {"level": 10}, "session_secret": LEAKY_RAW_MARKER},
    )


def _incident_candidates() -> list[IncidentCandidate]:
    """Create two candidates belonging to one incident.

    Inputs:
        None.

    Outputs:
        IncidentCandidate list.
    """

    first = IncidentCandidate(
        id="CAND-20260610-001-aaa",
        first_seen=BASE_TIME,
        last_seen=BASE_TIME + timedelta(minutes=5),
        alerts=[_incident_alert("alert-001"), _incident_alert("alert-002", minutes=5)],
        primary_host="endpoint-01",
        primary_user="alice",
        src_ips=["10.0.1.10"],
        dst_ips=["203.0.113.10"],
        created_at=BASE_TIME,
    )
    second = IncidentCandidate(
        id="CAND-20260610-002-bbb",
        first_seen=BASE_TIME + timedelta(minutes=20),
        last_seen=BASE_TIME + timedelta(minutes=25),
        alerts=[
            _incident_alert(
                "alert-003",
                hostname="fileserver-02",
                minutes=20,
                rule_name="Credential dumping detected",
            )
        ],
        primary_host="fileserver-02",
        primary_user="bob",
        src_ips=["10.0.1.11"],
        dst_ips=["198.51.100.9"],
        created_at=BASE_TIME,
    )
    return [first, second]


def _incident_triages(candidates: list[IncidentCandidate]) -> list[TriageResult]:
    """Create triage results for incident candidates.

    Inputs:
        candidates: Candidates in the incident.

    Outputs:
        TriageResult list, one per candidate.
    """

    scores = [8, 9]
    results = []
    for candidate, score in zip(candidates, scores, strict=False):
        results.append(
            TriageResult(
                id=f"triage-{candidate.id}",
                target_id=candidate.id,
                target_type="incident_candidate",
                score=score,
                fp_likelihood=FalsePositiveLikelihood.LOW,
                classification="likely_true_positive_high_priority",
                action=TriageAction.PAGE_NOW,
                summary=f"Malicious activity on {candidate.primary_host}.",
                iocs={"ips": ["203.0.113.10"], "hashes": ["deadbeef"]},
                recommended_actions=["Isolate the host"],
            )
        )
    return results


def _incident(
    candidates: list[IncidentCandidate] | None = None,
    triages: list[TriageResult] | None = None,
    *,
    asset_context: dict[str, Any] | None = None,
) -> Incident:
    """Create an incident spanning the given candidates.

    Inputs:
        candidates: Candidates in the incident.
        triages: Triage results for those candidates.
        asset_context: Optional asset context for the primary host.

    Outputs:
        Incident object.
    """

    candidates = candidates if candidates is not None else _incident_candidates()
    triages = triages if triages is not None else _incident_triages(candidates)
    alert_ids = [alert.id for candidate in candidates for alert in candidate.alerts]
    return Incident(
        id="INC-20260610-001-abc123",
        candidate_ids=[candidate.id for candidate in candidates],
        alert_ids=alert_ids,
        triage_result_ids=[triage.id for triage in triages],
        first_seen=BASE_TIME,
        last_seen=BASE_TIME + timedelta(minutes=25),
        primary_host="endpoint-01",
        primary_user="alice",
        src_ips=["10.0.1.10", "10.0.1.11"],
        dst_ips=["203.0.113.10", "198.51.100.9"],
        max_score=max((triage.score for triage in triages), default=0),
        asset_context=asset_context or {},
        created_at=BASE_TIME,
    )


def _leaky_enrichments() -> list[EnrichmentResult]:
    """Create enrichment results whose raw payloads must never leak.

    Inputs:
        None.

    Outputs:
        EnrichmentResult list.
    """

    return [
        EnrichmentResult(
            indicator="203.0.113.10",
            indicator_type="ip",
            provider="local",
            summary="Public destination address.",
            raw={"provider_response": LEAKY_ENRICHMENT_MARKER},
            looked_up_at=BASE_TIME,
        )
    ]


def test_incident_report_contains_all_seven_sections():
    """A deterministic incident report must render all seven planned sections."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)

    report = MarkdownReportBuilder().build_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
    )

    assert report.startswith("# Incident Report: INC-20260610-001-abc123")
    for heading in (
        "## Executive Summary",
        "## Timeline",
        "## Affected Assets",
        "## IOCs",
        "## Attack Narrative",
        "## Remediation",
        "## Detection Gaps",
    ):
        assert heading in report
    assert "Generated by AI_Augmented_SOC" in report


def test_incident_report_aggregates_every_candidate():
    """The report must aggregate alerts, assets, and scores across candidates."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)

    report = build_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
    )

    for expected in (
        "CAND-20260610-001-aaa",
        "CAND-20260610-002-bbb",
        "alert-001",
        "alert-002",
        "alert-003",
        "endpoint-01",
        "fileserver-02",
        "203.0.113.10",
        "198.51.100.9",
        "Credential dumping detected",
    ):
        assert expected in report
    assert "9/10" in report
    assert "2026-06-10T12:00:00+00:00" in report
    assert "2026-06-10T12:25:00+00:00" in report


def test_incident_report_includes_asset_context_when_present():
    """Asset criticality must reach the report when the incident carries it."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)
    incident = _incident(
        candidates,
        triages,
        asset_context={"criticality": "high", "owner": "payments-team"},
    )

    report = build_incident_report(incident, candidates=candidates, triage_results=triages)

    assert "criticality" in report
    assert "high" in report
    assert "payments-team" in report


def test_incident_report_without_narrative_client_is_labelled_templated():
    """With no narrative client the report must declare itself templated."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)

    report = build_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
    )

    assert "## Report Provenance" in report
    assert "templated" in report.lower()
    assert "model-drafted" not in report.lower()


def test_create_incident_report_leaves_generated_by_model_unset_when_templated():
    """A templated report must never look model-drafted on the model object."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)

    report = create_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
    )

    assert isinstance(report, IncidentReport)
    assert report.incident_id == "INC-20260610-001-abc123"
    assert report.generated_by_model is None
    assert "templated" in report.markdown.lower()


def test_incident_report_includes_analyst_notes_when_supplied():
    """Analyst notes are first-hand context and must appear in the report."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)

    report = build_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
        analyst_notes="Confirmed with the asset owner that no change window was open.",
    )

    assert "## Analyst Notes" in report
    assert "no change window was open" in report


def test_incident_report_with_no_candidates_still_renders():
    """An incident with no candidate detail must render, not raise."""

    incident = Incident(id="INC-20260610-009-empty", first_seen=None, last_seen=None)

    report = build_incident_report(incident, candidates=[], triage_results=[])

    assert "# Incident Report: INC-20260610-009-empty" in report
    assert "## Timeline" in report
    assert "No alerts" in report
    assert "unknown" in report.lower()


def test_module_level_build_incident_report_matches_builder():
    """The module-level function must mirror the builder method."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)
    incident = _incident(candidates, triages)

    assert build_incident_report(
        incident, candidates=candidates, triage_results=triages
    ) == MarkdownReportBuilder().build_incident_report(
        incident, candidates=candidates, triage_results=triages
    )


@dataclass(slots=True)
class FakeNarrativeClient:
    """Fake narrative client recording prompts and returning fixed text."""

    response_text: str = ""
    raise_error: Exception | None = None
    calls: list[dict[str, object]] = field(default_factory=list)

    def complete_text(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 800,
    ) -> str:
        """Record a fake narrative call and return the configured response."""

        self.calls.append({"prompt": prompt, "system_prompt": system_prompt, "model": model})
        del temperature, max_tokens
        if self.raise_error is not None:
            raise self.raise_error
        return self.response_text


@dataclass(slots=True)
class FakeSequenceNarrativeClient:
    """Fake narrative client returning a scripted sequence of responses."""

    responses: list[Any]
    calls: int = 0

    def complete_text(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 800,
    ) -> str:
        """Return the next scripted response, repeating the last one."""

        del prompt, system_prompt, model, temperature, max_tokens
        index = min(self.calls, len(self.responses) - 1)
        self.calls += 1
        response = self.responses[index]
        if isinstance(response, Exception):
            raise response
        return response


_VALID_NARRATIVE_JSON = (
    '{"executive_summary": "Credential theft on endpoint-01 spread to fileserver-02.",'
    ' "attack_narrative": "The operator ran encoded PowerShell, then dumped credentials.",'
    ' "remediation": "Isolate both hosts and reset alice.",'
    ' "detection_gaps": "No EDR coverage on fileserver-02."}'
)


def test_incident_report_with_narrative_client_is_model_drafted():
    """A working narrative client must produce a labelled model-drafted report."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)
    client = FakeNarrativeClient(response_text=_VALID_NARRATIVE_JSON)
    builder = MarkdownReportBuilder(client, model="vendor/model-x")

    report = builder.build_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
    )

    assert "model-drafted" in report.lower()
    assert "vendor/model-x" in report
    assert REPORT_PROMPT_VERSION in report
    assert "The operator ran encoded PowerShell" in report
    assert "No EDR coverage on fileserver-02." in report
    for heading in ("## Timeline", "## Affected Assets", "## IOCs", "## Detection Gaps"):
        assert heading in report
    assert "alert-003" in report


def test_create_incident_report_sets_generated_by_model_for_a_real_draft():
    """generated_by_model must be set only when a model actually drafted prose."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)
    client = FakeNarrativeClient(response_text=_VALID_NARRATIVE_JSON)

    report = create_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
        narrative_client=client,
        model="vendor/model-x",
    )

    assert report.generated_by_model == "vendor/model-x"
    assert REPORT_PROMPT_VERSION in report.markdown


def test_incident_report_falls_back_to_templated_when_the_client_fails():
    """A transport failure must degrade to a templated report, labelled as such."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)
    client = FakeNarrativeClient(raise_error=OpenRouterError("rate limited"))

    report = create_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
        narrative_client=client,
    )

    assert report.generated_by_model is None
    assert "templated" in report.markdown.lower()
    assert "model-drafted" not in report.markdown.lower()
    assert len(client.calls) == 1


def test_incident_narrative_retries_one_unusable_response():
    """One unusable narrative response deserves a retry, not an instant fallback."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)
    client = FakeSequenceNarrativeClient(responses=["not json at all", _VALID_NARRATIVE_JSON])

    report = build_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
        narrative_client=client,
    )

    assert client.calls == 2
    assert "model-drafted" in report.lower()


def test_incident_narrative_falls_back_when_the_retry_is_also_unusable():
    """Two unusable responses must end in a templated report."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)
    client = FakeSequenceNarrativeClient(responses=["not json", "still not json"])

    report = build_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
        narrative_client=client,
    )

    assert client.calls == 2
    assert "templated" in report.lower()
    assert "model-drafted" not in report.lower()


def test_incident_narrative_does_not_retry_transport_failures():
    """The client already retries transport failures; doubling the wait is wrong."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)
    client = FakeSequenceNarrativeClient(responses=[OpenRouterError("rate limited")])

    report = build_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
        narrative_client=client,
    )

    assert client.calls == 1
    assert "templated" in report.lower()


def test_narrative_prompt_never_contains_raw_alert_or_enrichment_payloads():
    """Raw source and provider payloads must not reach a third party."""

    candidates = _incident_candidates()
    triages = _incident_triages(candidates)
    client = FakeNarrativeClient(response_text=_VALID_NARRATIVE_JSON)

    build_incident_report(
        _incident(candidates, triages),
        candidates=candidates,
        triage_results=triages,
        enrichments=_leaky_enrichments(),
        narrative_client=client,
        analyst_notes="Owner confirmed no change window.",
    )

    assert len(client.calls) == 1
    prompt = str(client.calls[0]["prompt"])
    assert LEAKY_RAW_MARKER not in prompt
    assert LEAKY_ENRICHMENT_MARKER not in prompt
    assert "session_secret" not in prompt
    assert "provider_response" not in prompt
    assert "Suspicious PowerShell execution" in prompt
    assert "Owner confirmed no change window." in prompt


def test_report_system_prompt_requires_sections_grounding_and_honesty():
    """The prompt must demand the seven sections, grounding, and admitted gaps."""

    lowered = REPORT_SYSTEM_PROMPT.lower()

    for section in (
        "executive summary",
        "timeline",
        "affected assets",
        "iocs",
        "attack narrative",
        "remediation",
        "detection gaps",
    ):
        assert section in lowered
    assert "ground" in lowered
    assert "insufficient" in lowered
    assert "invent" in lowered
