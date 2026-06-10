

"""Incident report generation for AI_Augmented_SOC.

This module converts alerts, incident candidates, triage results, routing
choices, and enrichment context into analyst-readable incident reports.

The report layer is deterministic and does not call an LLM. A future module may
add LLM-assisted prose, but the MVP report builder should always be able to
produce useful Markdown from local data alone.
"""

from __future__ import annotations

import hashlib
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc.models import (
    Alert,
    EnrichmentResult,
    EvidenceItem,
    IncidentCandidate,
    IncidentReport,
    RoutingDecision,
    TriageResult,
    utc_now,
)


JsonDict = dict[str, Any]


class ReportError(ValueError):
    """Raised when report generation cannot continue."""


class MarkdownReportBuilder:
    """Build Markdown reports from SOC triage objects."""

    def build_candidate_report(
        self,
        candidate: IncidentCandidate,
        triage: TriageResult,
        *,
        routing: RoutingDecision | None = None,
        enrichments: list[EnrichmentResult] | None = None,
        title: str | None = None,
    ) -> str:
        """Build a Markdown report for an incident candidate.

        Inputs:
            candidate: IncidentCandidate being reported.
            triage: TriageResult for the candidate.
            routing: Optional RoutingDecision.
            enrichments: Optional enrichment results.
            title: Optional report title override.

        Outputs:
            Markdown report text.
        """

        enrichments = enrichments or candidate.enrichments or []
        report_title = title or f"Incident Candidate Report: {candidate.id}"
        lines = [
            f"# {report_title}",
            "",
            "## Executive Summary",
            _candidate_executive_summary(candidate, triage),
            "",
            "## Triage Decision",
            _triage_markdown(triage),
            "",
        ]

        if routing is not None:
            lines.extend(["## Routing", _routing_markdown(routing), ""])

        lines.extend(
            [
                "## Candidate Scope",
                _candidate_scope_markdown(candidate),
                "",
                "## Alerts",
                _alerts_markdown(candidate.alerts),
                "",
                "## Enrichment Summary",
                _enrichments_markdown(enrichments),
                "",
                "## Recommended Analyst Actions",
                _recommended_actions_markdown(triage),
                "",
                "## Evidence",
                _candidate_evidence_markdown(candidate, enrichments),
                "",
                _generated_footer(),
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    def build_alert_report(
        self,
        alert: Alert,
        triage: TriageResult,
        *,
        routing: RoutingDecision | None = None,
        enrichments: list[EnrichmentResult] | None = None,
        title: str | None = None,
    ) -> str:
        """Build a Markdown report for a single alert.

        Inputs:
            alert: Alert being reported.
            triage: TriageResult for the alert.
            routing: Optional RoutingDecision.
            enrichments: Optional enrichment results.
            title: Optional report title override.

        Outputs:
            Markdown report text.
        """

        enrichments = enrichments or []
        report_title = title or f"Alert Report: {alert.id}"
        lines = [
            f"# {report_title}",
            "",
            "## Executive Summary",
            _alert_executive_summary(alert, triage),
            "",
            "## Triage Decision",
            _triage_markdown(triage),
            "",
        ]

        if routing is not None:
            lines.extend(["## Routing", _routing_markdown(routing), ""])

        lines.extend(
            [
                "## Alert Details",
                _alert_detail_markdown(alert),
                "",
                "## Enrichment Summary",
                _enrichments_markdown(enrichments),
                "",
                "## Recommended Analyst Actions",
                _recommended_actions_markdown(triage),
                "",
                "## Evidence",
                _alert_evidence_markdown(alert, enrichments),
                "",
                _generated_footer(),
            ]
        )
        return "\n".join(lines).rstrip() + "\n"


def build_candidate_report(
    candidate: IncidentCandidate,
    triage: TriageResult,
    *,
    routing: RoutingDecision | None = None,
    enrichments: list[EnrichmentResult] | None = None,
    title: str | None = None,
) -> str:
    """Convenience function for candidate Markdown report generation.

    Inputs:
        candidate: IncidentCandidate being reported.
        triage: TriageResult for the candidate.
        routing: Optional RoutingDecision.
        enrichments: Optional enrichment results.
        title: Optional report title override.

    Outputs:
        Markdown report text.
    """

    return MarkdownReportBuilder().build_candidate_report(
        candidate,
        triage,
        routing=routing,
        enrichments=enrichments,
        title=title,
    )


def build_alert_report(
    alert: Alert,
    triage: TriageResult,
    *,
    routing: RoutingDecision | None = None,
    enrichments: list[EnrichmentResult] | None = None,
    title: str | None = None,
) -> str:
    """Convenience function for alert Markdown report generation.

    Inputs:
        alert: Alert being reported.
        triage: TriageResult for the alert.
        routing: Optional RoutingDecision.
        enrichments: Optional enrichment results.
        title: Optional report title override.

    Outputs:
        Markdown report text.
    """

    return MarkdownReportBuilder().build_alert_report(
        alert,
        triage,
        routing=routing,
        enrichments=enrichments,
        title=title,
    )


def create_incident_report(
    candidate: IncidentCandidate,
    triage: TriageResult,
    *,
    routing: RoutingDecision | None = None,
    enrichments: list[EnrichmentResult] | None = None,
    title: str | None = None,
) -> IncidentReport:
    """Create an IncidentReport dataclass for a candidate.

    Inputs:
        candidate: IncidentCandidate being reported.
        triage: TriageResult for the candidate.
        routing: Optional RoutingDecision.
        enrichments: Optional enrichment results.
        title: Optional report title override.

    Outputs:
        IncidentReport instance.
    """

    report_title = title or f"Incident Candidate Report: {candidate.id}"
    body = build_candidate_report(
        candidate,
        triage,
        routing=routing,
        enrichments=enrichments,
        title=report_title,
    )
    payload = {
        "id": _build_report_id(candidate.id, triage.id),
        "candidate_id": candidate.id,
        "triage_result_id": triage.id,
        "title": report_title,
        "summary": _candidate_executive_summary(candidate, triage),
        "body": body,
        "markdown": body,
        "content": body,
        "severity_score": triage.score,
        "action": triage.action,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "evidence": build_candidate_evidence(candidate, enrichments or candidate.enrichments or []),
        "metadata": {
            "alert_count": len(candidate.alerts),
            "primary_host": candidate.primary_host,
            "primary_user": candidate.primary_user,
            "src_ips": list(candidate.src_ips),
            "dst_ips": list(candidate.dst_ips),
        },
    }
    return _make_incident_report(payload)


def write_report_file(report_text: str, output_path: str | Path) -> Path:
    """Write a Markdown report to disk.

    Inputs:
        report_text: Markdown report body.
        output_path: Destination file path.

    Outputs:
        Path that was written.
    """

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_text, encoding="utf-8")
    return path


def build_candidate_evidence(
    candidate: IncidentCandidate,
    enrichments: list[EnrichmentResult] | None = None,
) -> list[EvidenceItem]:
    """Build EvidenceItem objects for a candidate.

    Inputs:
        candidate: IncidentCandidate object.
        enrichments: Optional enrichment results.

    Outputs:
        EvidenceItem list. If the project EvidenceItem dataclass has different
        fields than expected, unavailable fields are skipped.
    """

    evidence: list[EvidenceItem] = []
    for alert in candidate.alerts:
        evidence.append(
            _make_evidence_item(
                {
                    "id": _build_evidence_id(candidate.id, alert.id, "alert"),
                    "source": str(alert.source.value if hasattr(alert.source, "value") else alert.source),
                    "kind": "alert",
                    "title": alert.rule_name or alert.id,
                    "description": _alert_brief(alert),
                    "content": _alert_detail_markdown(alert),
                    "timestamp": alert.timestamp,
                    "metadata": _alert_metadata(alert),
                    "raw": alert.raw,
                }
            )
        )

    for enrichment in enrichments or []:
        indicator = _field(enrichment, "indicator", "ioc", "observable", "value", default="unknown")
        evidence.append(
            _make_evidence_item(
                {
                    "id": _build_evidence_id(candidate.id, str(indicator), "enrichment"),
                    "source": _field(enrichment, "provider", "source", default="local"),
                    "kind": "enrichment",
                    "title": f"Enrichment: {indicator}",
                    "description": _field(enrichment, "summary", default="No enrichment summary."),
                    "content": _enrichment_markdown(enrichment),
                    "timestamp": _field(enrichment, "looked_up_at", "created_at", "timestamp", default=utc_now()),
                    "metadata": _details(enrichment),
                    "raw": _details(enrichment),
                }
            )
        )
    return evidence


def _candidate_executive_summary(candidate: IncidentCandidate, triage: TriageResult) -> str:
    """Build candidate executive summary.

    Inputs:
        candidate: IncidentCandidate object.
        triage: TriageResult object.

    Outputs:
        Summary string.
    """

    host = candidate.primary_host or "unknown host"
    user = candidate.primary_user or "unknown user"
    return (
        f"Candidate `{candidate.id}` contains {len(candidate.alerts)} alert(s), centered on `{host}` "
        f"and user `{user}`. Triage scored it **{triage.score}/10** with action "
        f"`{triage.action.value}` and classification `{triage.classification}`. {triage.summary}"
    )


def _alert_executive_summary(alert: Alert, triage: TriageResult) -> str:
    """Build alert executive summary.

    Inputs:
        alert: Alert object.
        triage: TriageResult object.

    Outputs:
        Summary string.
    """

    host = alert.hostname or "unknown host"
    rule_name = alert.rule_name or "Unknown rule"
    return (
        f"Alert `{alert.id}` fired rule `{rule_name}` on `{host}`. Triage scored it "
        f"**{triage.score}/10** with action `{triage.action.value}` and classification "
        f"`{triage.classification}`. {triage.summary}"
    )


def _triage_markdown(triage: TriageResult) -> str:
    """Build Markdown for triage result.

    Inputs:
        triage: TriageResult object.

    Outputs:
        Markdown string.
    """

    fp_value = triage.fp_likelihood.value if hasattr(triage.fp_likelihood, "value") else triage.fp_likelihood
    return "\n".join(
        [
            f"- **Target:** `{triage.target_type}` / `{triage.target_id}`",
            f"- **Score:** {triage.score}/10",
            f"- **False-positive likelihood:** `{fp_value}`",
            f"- **Classification:** `{triage.classification}`",
            f"- **Recommended action:** `{triage.action.value}`",
            f"- **Summary:** {triage.summary}",
        ]
    )


def _routing_markdown(routing: RoutingDecision) -> str:
    """Build Markdown for routing decision.

    Inputs:
        routing: RoutingDecision object.

    Outputs:
        Markdown string.
    """

    status = _field(routing, "status", default="unknown")
    action = _field(routing, "action", default="unknown")
    if hasattr(status, "value"):
        status = status.value
    if hasattr(action, "value"):
        action = action.value
    return "\n".join(
        [
            f"- **Routing ID:** `{_field(routing, 'id', default='unknown')}`",
            f"- **Action:** `{action}`",
            f"- **Status:** `{status}`",
            f"- **Destination:** `{_field(routing, 'destination', default='unknown')}`",
            f"- **Message:** {_field(routing, 'message', default='No routing message.')}",
        ]
    )


def _candidate_scope_markdown(candidate: IncidentCandidate) -> str:
    """Build Markdown for candidate scope.

    Inputs:
        candidate: IncidentCandidate object.

    Outputs:
        Markdown string.
    """

    return "\n".join(
        [
            f"- **First seen:** {_format_time(candidate.first_seen)}",
            f"- **Last seen:** {_format_time(candidate.last_seen)}",
            f"- **Primary host:** `{candidate.primary_host or 'unknown'}`",
            f"- **Primary user:** `{candidate.primary_user or 'unknown'}`",
            f"- **Source IPs:** {_comma_code(candidate.src_ips)}",
            f"- **Destination IPs:** {_comma_code(candidate.dst_ips)}",
            f"- **Alert count:** {len(candidate.alerts)}",
        ]
    )


def _alerts_markdown(alerts: list[Alert]) -> str:
    """Build Markdown table for alerts.

    Inputs:
        alerts: Alert objects.

    Outputs:
        Markdown string.
    """

    if not alerts:
        return "No alerts attached to this candidate."

    lines = [
        "| Time | Alert ID | Severity | Rule | Host | User | Src | Dst |",
        "|---|---|---:|---|---|---|---|---|",
    ]
    for alert in alerts:
        lines.append(
            "| "
            f"{_format_time(alert.timestamp)} | `{alert.id}` | `{alert.severity.value}` | "
            f"{_escape_table(alert.rule_name or 'Unknown rule')} | `{alert.hostname or ''}` | "
            f"`{alert.user or ''}` | `{alert.src_ip or ''}` | `{alert.dst_ip or ''}` |"
        )
    return "\n".join(lines)


def _alert_detail_markdown(alert: Alert) -> str:
    """Build Markdown details for one alert.

    Inputs:
        alert: Alert object.

    Outputs:
        Markdown string.
    """

    return "\n".join(
        [
            f"- **Alert ID:** `{alert.id}`",
            f"- **Source:** `{alert.source.value}`",
            f"- **Time:** {_format_time(alert.timestamp)}",
            f"- **Severity:** `{alert.severity.value}`",
            f"- **Source severity:** `{alert.source_severity}`",
            f"- **Rule:** {alert.rule_name or 'Unknown rule'}",
            f"- **Rule groups:** {_comma_code(alert.rule_groups)}",
            f"- **Host:** `{alert.hostname or 'unknown'}`",
            f"- **Agent ID:** `{alert.agent_id or 'unknown'}`",
            f"- **Agent OS:** `{alert.agent_os or 'unknown'}`",
            f"- **User:** `{alert.user or 'unknown'}`",
            f"- **Process:** `{alert.process_name or 'unknown'}`",
            f"- **Command line:** `{alert.command_line or 'unknown'}`",
            f"- **Source IP:** `{alert.src_ip or 'unknown'}`",
            f"- **Destination IP:** `{alert.dst_ip or 'unknown'}`",
        ]
    )


def _enrichments_markdown(enrichments: list[EnrichmentResult]) -> str:
    """Build Markdown for enrichment results.

    Inputs:
        enrichments: Enrichment results.

    Outputs:
        Markdown string.
    """

    if not enrichments:
        return "No enrichment results available."

    lines = ["| Indicator | Type | Provider | Summary | Risk hints |", "|---|---|---|---|---|"]
    for enrichment in enrichments:
        details = _details(enrichment)
        risk_factors = details.get("risk_factors", []) if isinstance(details, dict) else []
        lines.append(
            "| "
            f"`{_field(enrichment, 'indicator', 'ioc', 'observable', 'value', default='unknown')}` | "
            f"`{_field(enrichment, 'indicator_type', 'ioc_type', 'observable_type', default='unknown')}` | "
            f"`{_field(enrichment, 'provider', 'source', default='unknown')}` | "
            f"{_escape_table(_field(enrichment, 'summary', default='No summary.'))} | "
            f"{_comma_code(risk_factors)} |"
        )
    return "\n".join(lines)


def _recommended_actions_markdown(triage: TriageResult) -> str:
    """Build recommended analyst action list.

    Inputs:
        triage: TriageResult object.

    Outputs:
        Markdown string.
    """

    if triage.action.value == "page_now":
        actions = [
            "Page or notify the responsible analyst immediately.",
            "Validate whether the affected host/user is actively compromised.",
            "Preserve relevant logs before they rotate.",
            "Consider containment only after human approval.",
        ]
    elif triage.action.value == "queue_review":
        actions = [
            "Queue for analyst review.",
            "Validate source and destination context.",
            "Check whether similar alerts occurred on the same host or user.",
            "Decide whether this should become a confirmed incident or false positive.",
        ]
    else:
        actions = [
            "Mark as likely benign or low priority.",
            "Document why it was considered low risk.",
            "Monitor for recurrence or escalation.",
        ]
    return "\n".join(f"- {action}" for action in actions)


def _candidate_evidence_markdown(candidate: IncidentCandidate, enrichments: list[EnrichmentResult]) -> str:
    """Build candidate evidence Markdown.

    Inputs:
        candidate: IncidentCandidate object.
        enrichments: Enrichment results.

    Outputs:
        Markdown string.
    """

    parts = ["### Alert Evidence"]
    for alert in candidate.alerts:
        parts.extend([f"#### `{alert.id}`", _alert_detail_markdown(alert), ""])

    parts.append("### Enrichment Evidence")
    if not enrichments:
        parts.append("No enrichment evidence available.")
    for enrichment in enrichments:
        parts.extend([_enrichment_markdown(enrichment), ""])
    return "\n".join(parts).rstrip()


def _alert_evidence_markdown(alert: Alert, enrichments: list[EnrichmentResult]) -> str:
    """Build alert evidence Markdown.

    Inputs:
        alert: Alert object.
        enrichments: Enrichment results.

    Outputs:
        Markdown string.
    """

    parts = ["### Alert Evidence", _alert_detail_markdown(alert), "", "### Enrichment Evidence"]
    if not enrichments:
        parts.append("No enrichment evidence available.")
    for enrichment in enrichments:
        parts.extend([_enrichment_markdown(enrichment), ""])
    return "\n".join(parts).rstrip()


def _enrichment_markdown(enrichment: EnrichmentResult) -> str:
    """Build Markdown for one enrichment result.

    Inputs:
        enrichment: EnrichmentResult object.

    Outputs:
        Markdown string.
    """

    details = _details(enrichment)
    return "\n".join(
        [
            f"- **Indicator:** `{_field(enrichment, 'indicator', 'ioc', 'observable', 'value', default='unknown')}`",
            f"- **Type:** `{_field(enrichment, 'indicator_type', 'ioc_type', 'observable_type', default='unknown')}`",
            f"- **Provider:** `{_field(enrichment, 'provider', 'source', default='unknown')}`",
            f"- **Summary:** {_field(enrichment, 'summary', default='No summary.')}",
            f"- **Details:** `{_compact_dict(details)}`",
        ]
    )


def _make_incident_report(payload: JsonDict) -> IncidentReport:
    """Create IncidentReport while tolerating model field evolution.

    Inputs:
        payload: Candidate field values.

    Outputs:
        IncidentReport instance.
    """

    if not is_dataclass(IncidentReport):
        raise ReportError("IncidentReport must be a dataclass")

    kwargs: JsonDict = {}
    for field in fields(IncidentReport):
        if field.name in payload:
            kwargs[field.name] = payload[field.name]
        elif field.name == "report_id":
            kwargs[field.name] = payload["id"]
        elif field.name == "incident_id":
            kwargs[field.name] = payload["candidate_id"]
        elif field.name == "body_markdown":
            kwargs[field.name] = payload["body"]
        elif field.name == "generated_at":
            kwargs[field.name] = payload["created_at"]

    try:
        return IncidentReport(**kwargs)
    except TypeError as exc:
        raise ReportError(f"Could not create IncidentReport: {exc}") from exc


def _make_evidence_item(payload: JsonDict) -> EvidenceItem:
    """Create EvidenceItem while tolerating model field evolution.

    Inputs:
        payload: Candidate field values.

    Outputs:
        EvidenceItem instance.
    """

    if not is_dataclass(EvidenceItem):
        raise ReportError("EvidenceItem must be a dataclass")

    kwargs: JsonDict = {}
    for field in fields(EvidenceItem):
        if field.name in payload:
            kwargs[field.name] = payload[field.name]
        elif field.name == "evidence_id":
            kwargs[field.name] = payload["id"]
        elif field.name == "field":
            kwargs[field.name] = payload["title"]
        elif field.name == "value":
            kwargs[field.name] = payload["content"]
        elif field.name == "type":
            kwargs[field.name] = payload["kind"]
        elif field.name == "text":
            kwargs[field.name] = payload["content"]

    try:
        return EvidenceItem(**kwargs)
    except TypeError as exc:
        raise ReportError(f"Could not create EvidenceItem: {exc}") from exc


def _alert_brief(alert: Alert) -> str:
    """Build one-line alert description.

    Inputs:
        alert: Alert object.

    Outputs:
        Description string.
    """

    return f"{alert.rule_name or 'Unknown rule'} on {alert.hostname or 'unknown host'} at {_format_time(alert.timestamp)}"


def _alert_metadata(alert: Alert) -> JsonDict:
    """Build alert metadata dictionary.

    Inputs:
        alert: Alert object.

    Outputs:
        Metadata dictionary.
    """

    return {
        "alert_id": alert.id,
        "severity": alert.severity.value,
        "source": alert.source.value,
        "host": alert.hostname,
        "user": alert.user,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
    }


def _build_report_id(candidate_id: str, triage_id: str) -> str:
    """Build stable report ID.

    Inputs:
        candidate_id: Candidate ID.
        triage_id: Triage result ID.

    Outputs:
        Report ID string.
    """

    fingerprint = hashlib.sha256(f"{candidate_id}:{triage_id}".encode("utf-8")).hexdigest()[:12]
    return f"report-{fingerprint}"


def _build_evidence_id(scope_id: str, item_id: str, kind: str) -> str:
    """Build stable evidence ID.

    Inputs:
        scope_id: Report or candidate scope ID.
        item_id: Evidence source item ID.
        kind: Evidence kind.

    Outputs:
        Evidence ID string.
    """

    fingerprint = hashlib.sha256(f"{scope_id}:{kind}:{item_id}".encode("utf-8")).hexdigest()[:12]
    return f"evidence-{fingerprint}"


def _field(value: Any, *names: str, default: Any = None) -> Any:
    """Return first available attribute from an object.

    Inputs:
        value: Object to inspect.
        names: Candidate field names.
        default: Fallback value.

    Outputs:
        Attribute value or default.
    """

    for name in names:
        if hasattr(value, name):
            return getattr(value, name)
    return default


def _details(enrichment: EnrichmentResult) -> JsonDict:
    """Read enrichment details regardless of field name.

    Inputs:
        enrichment: EnrichmentResult object.

    Outputs:
        Details dictionary.
    """

    for name in ("details", "metadata", "data", "raw"):
        value = getattr(enrichment, name, None)
        if isinstance(value, dict):
            return value
    return {}


def _format_time(value: Any) -> str:
    """Format timestamps for reports.

    Inputs:
        value: datetime-like value.

    Outputs:
        ISO timestamp string.
    """

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if value is None:
        return "unknown"
    return str(value)


def _comma_code(values: Any) -> str:
    """Format iterable values as comma-separated inline code.

    Inputs:
        values: Iterable or scalar value.

    Outputs:
        Markdown string.
    """

    if values is None:
        return "`none`"
    if isinstance(values, str):
        return f"`{values}`" if values else "`none`"
    try:
        items = list(values)
    except TypeError:
        return f"`{values}`"
    if not items:
        return "`none`"
    return ", ".join(f"`{item}`" for item in items)


def _compact_dict(value: JsonDict) -> str:
    """Compact dictionary for Markdown display.

    Inputs:
        value: Dictionary.

    Outputs:
        Compact string.
    """

    if not value:
        return "{}"
    parts = []
    for key, item in value.items():
        if isinstance(item, list):
            item_text = ",".join(str(element) for element in item)
        else:
            item_text = str(item)
        parts.append(f"{key}={item_text}")
    return "; ".join(parts)


def _escape_table(value: Any) -> str:
    """Escape Markdown table separators.

    Inputs:
        value: Cell value.

    Outputs:
        Escaped text.
    """

    return str(value).replace("|", "\\|").replace("\n", " ")


def _generated_footer() -> str:
    """Build generated-by footer.

    Inputs:
        None.

    Outputs:
        Footer string.
    """

    return "---\nGenerated by AI_Augmented_SOC."