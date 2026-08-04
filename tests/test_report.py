

"""Tests for Markdown report generation.

These tests verify that report generation produces analyst-readable Markdown,
can write reports to disk, and can create report/evidence dataclasses while
remaining tolerant of small model field-name changes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from soc.enrichment import enrich_indicator
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
from soc.report import (
    MarkdownReportBuilder,
    build_alert_report,
    build_candidate_evidence,
    build_candidate_report,
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
