

"""Incident report generation for AI_Augmented_SOC.

This module converts alerts, incident candidates, triage results, routing
choices, and enrichment context into analyst-readable incident reports.

The deterministic renderer is permanent, not a stopgap: every report must be
producible from stored data alone, with no API key and no network. An optional
narrative client only *adds* prose. When it is absent, fails, or returns
something unusable, the deterministic text stands in and the report says so.

Provenance is stated in the report body and on the returned IncidentReport:
`generated_by_model` is set only when a model genuinely drafted the prose, and
the "Report Provenance" section says either `model-drafted` or `templated`. A
templated report must never be mistakable for a drafted one — the same rule
`AnalysisSource` enforces for triage scores.

Only allowlisted, truncated context is sent to the model. Raw source payloads
(`Alert.raw` beyond the triage allowlist), related raw events, and enrichment
provider responses are withheld, reusing the context builders in `soc.triage`
rather than inventing a second filtering scheme.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc.incidents import Incident
from soc.models import (
    Alert,
    AnalysisSource,
    EnrichmentResult,
    EvidenceItem,
    IncidentCandidate,
    IncidentReport,
    RoutingDecision,
    TriageResult,
    utc_now,
)
from soc.openrouter_client import OpenRouterError, parse_json_response_text

# The context allowlist, the truncation limits, and the cluster cap are defined
# once, in soc.triage. Importing them (including the two module-private helpers)
# keeps one filtering scheme for everything this project sends to a model; a
# second copy here would drift and eventually leak a field.
from soc.triage import (
    MAX_CONTEXT_ALERTS,
    TRUNCATION_MARKER,
    TextCompletionClient,
    _json_safe,
    _truncate_value,
    build_candidate_context,
    build_enrichment_context,
)

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]


class ReportError(ValueError):
    """Raised when report generation cannot continue."""


REPORT_PROMPT_VERSION = "report-v1"

REPORT_SYSTEM_PROMPT = """You are a careful SOC incident reporter writing for on-call analysts.
Return only valid JSON with these keys, each holding Markdown prose:
- executive_summary: what happened, why it matters, and how confident the evidence makes you.
- attack_narrative: the likely sequence of attacker activity, in order.
- remediation: concrete containment, eradication, and recovery steps.
- detection_gaps: what the current detections missed or could not confirm.

Your prose is combined with deterministic sections the system renders itself:
Executive Summary, Timeline, Affected Assets, IOCs, Attack Narrative,
Remediation, and Detection Gaps. Do not emit headings; the report adds them.
Do not restate the Timeline, Affected Assets, or IOCs tables.

Grounding rules, which matter more than fluency:
- Ground every claim in the supplied context and name the incident, candidate,
  alert, host, user, or indicator it came from.
- Never invent hostnames, usernames, IP addresses, domains, hashes, process
  names, timestamps, or log content. An invented asset in an incident report is
  worse than a missing one, because someone will act on it.
- Where the evidence is insufficient to support a conclusion, say plainly that
  it is insufficient and state what evidence would settle it. Do not guess at
  attacker intent, initial access, or scope that the context does not show.
- The context is already filtered and truncated. Treat absent fields as unknown
  rather than assuming a value, and do not ask for raw log payloads.
"""

NARRATIVE_SECTION_KEYS: tuple[str, ...] = (
    "executive_summary",
    "attack_narrative",
    "remediation",
    "detection_gaps",
)
"""Prose sections a model may draft. Everything else is rendered locally."""

INCIDENT_CONTEXT_FIELDS: tuple[str, ...] = (
    "id",
    "first_seen",
    "last_seen",
    "primary_host",
    "primary_user",
    "src_ips",
    "dst_ips",
    "max_score",
    "asset_context",
    "candidate_ids",
)

TRIAGE_CONTEXT_FIELDS: tuple[str, ...] = (
    "id",
    "target_id",
    "target_type",
    "score",
    "fp_likelihood",
    "classification",
    "action",
    "summary",
    "analysis_source",
    "model",
    "prompt_version",
)

ROUTING_CONTEXT_FIELDS: tuple[str, ...] = (
    "id",
    "target_id",
    "action",
    "status",
    "destination",
    "message",
)

MAX_ANALYST_NOTES_CHARS = 4000
"""Analyst notes are free text, so they get their own, larger cap."""

MAX_CONTEXT_CANDIDATES = MAX_CONTEXT_ALERTS
"""Reuse the cluster cap: an incident's candidate list is bounded the same way."""

MAX_NARRATIVE_TIMELINE_LINES = 12


@dataclass(frozen=True, slots=True)
class IncidentNarrative:
    """Prose sections of an incident report plus their provenance.

    Attributes:
        sections: Narrative text keyed by NARRATIVE_SECTION_KEYS.
        source: Whether a model or local templating produced the prose.
        model: Model that drafted the prose, when one did.
        prompt_version: Report prompt version used for a model draft.
        fallback_reason: Why a model draft was not used, when it was attempted.
    """

    sections: dict[str, str]
    source: AnalysisSource
    model: str | None = None
    prompt_version: str | None = None
    fallback_reason: str | None = None

    @property
    def is_model_drafted(self) -> bool:
        """Return whether a model actually drafted this narrative.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            True only for a genuine model draft.
        """

        return self.source is AnalysisSource.LLM


class MarkdownReportBuilder:
    """Build Markdown reports from SOC triage objects.

    Args:
        narrative_client: Optional client with complete_text() used to draft the
            prose sections of an incident report. Without one, reports are fully
            templated, which is a supported permanent mode rather than a
            degraded one.
        model: Optional model override passed to the narrative client.
        max_tokens: Maximum narrative output tokens.
        temperature: Narrative sampling temperature.
        max_json_retries: Extra attempts when a narrative response cannot be
            used. Transport failures are not retried here; the client already
            retries those with backoff.
    """

    def __init__(
        self,
        narrative_client: TextCompletionClient | None = None,
        *,
        model: str | None = None,
        max_tokens: int = 1600,
        temperature: float = 0.2,
        max_json_retries: int = 1,
    ) -> None:
        """Initialize the report builder.

        Inputs:
            narrative_client: Optional OpenRouter-like client.
            model: Optional model override.
            max_tokens: Maximum narrative output tokens.
            temperature: Narrative sampling temperature.
            max_json_retries: Extra attempts on an unusable narrative response.

        Outputs:
            None.

        Raises:
            ReportError: If a configuration value is invalid.
        """

        if max_tokens <= 0:
            raise ReportError("max_tokens must be greater than zero")
        if temperature < 0:
            raise ReportError("temperature cannot be negative")
        if max_json_retries < 0:
            raise ReportError("max_json_retries cannot be negative")

        self.narrative_client = narrative_client
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.max_json_retries = max_json_retries

    def build_incident_report(
        self,
        incident: Incident,
        *,
        candidates: list[IncidentCandidate],
        triage_results: list[TriageResult],
        routing_decisions: list[RoutingDecision] | None = None,
        enrichments: list[EnrichmentResult] | None = None,
        analyst_notes: str | None = None,
        title: str | None = None,
    ) -> str:
        """Build a Markdown incident report with all seven planned sections.

        Inputs:
            incident: Incident being reported.
            candidates: Candidates the incident was promoted from.
            triage_results: Triage results for those candidates.
            routing_decisions: Optional routing decisions.
            enrichments: Optional enrichment results.
            analyst_notes: Optional free-text analyst notes.
            title: Optional report title override.

        Outputs:
            Markdown report text.
        """

        markdown, _ = self.render_incident_report(
            incident,
            candidates=candidates,
            triage_results=triage_results,
            routing_decisions=routing_decisions,
            enrichments=enrichments,
            analyst_notes=analyst_notes,
            title=title,
        )
        return markdown

    def render_incident_report(
        self,
        incident: Incident,
        *,
        candidates: list[IncidentCandidate],
        triage_results: list[TriageResult],
        routing_decisions: list[RoutingDecision] | None = None,
        enrichments: list[EnrichmentResult] | None = None,
        analyst_notes: str | None = None,
        title: str | None = None,
    ) -> tuple[str, IncidentNarrative]:
        """Render an incident report and report how its prose was produced.

        Callers that persist an IncidentReport need the provenance as data, not
        only as prose, so this returns both.

        Inputs:
            incident: Incident being reported.
            candidates: Candidates the incident was promoted from.
            triage_results: Triage results for those candidates.
            routing_decisions: Optional routing decisions.
            enrichments: Optional enrichment results.
            analyst_notes: Optional free-text analyst notes.
            title: Optional report title override.

        Outputs:
            Tuple of Markdown text and the narrative that produced its prose.
        """

        candidates = list(candidates or [])
        triage_results = list(triage_results or [])
        routing_decisions = list(routing_decisions or [])
        enrichments = list(enrichments or _collected_enrichments(candidates))

        templated = _templated_narrative(incident, candidates, triage_results, enrichments)
        narrative = templated
        if self.narrative_client is not None:
            drafted = self._draft_narrative(
                incident,
                candidates=candidates,
                triage_results=triage_results,
                routing_decisions=routing_decisions,
                enrichments=enrichments,
                analyst_notes=analyst_notes,
                fallback=templated,
            )
            narrative = drafted

        report_title = title or f"Incident Report: {incident.id}"
        alert_pairs = _incident_alert_pairs(candidates)
        lines = [
            f"# {report_title}",
            "",
            "## Report Provenance",
            _provenance_markdown(narrative),
            "",
            "## Executive Summary",
            narrative.sections["executive_summary"],
            "",
            "## Timeline",
            _timeline_markdown(alert_pairs),
            "",
            "## Affected Assets",
            _affected_assets_markdown(incident, candidates),
            "",
            "## IOCs",
            _incident_iocs_markdown(incident, triage_results, enrichments),
            "",
            "## Attack Narrative",
            narrative.sections["attack_narrative"],
            "",
            "## Remediation",
            narrative.sections["remediation"],
            "",
            "## Detection Gaps",
            narrative.sections["detection_gaps"],
            "",
        ]

        if analyst_notes and analyst_notes.strip():
            lines.extend(["## Analyst Notes", analyst_notes.strip(), ""])

        lines.extend(["## Triage Decisions", _triage_summary_markdown(triage_results), ""])

        if routing_decisions:
            lines.append("## Routing")
            for routing in routing_decisions:
                lines.extend([_routing_markdown(routing), ""])

        lines.extend(["## Enrichment Summary", _enrichments_markdown(enrichments), "", _generated_footer()])
        return "\n".join(lines).rstrip() + "\n", narrative

    def _draft_narrative(
        self,
        incident: Incident,
        *,
        candidates: list[IncidentCandidate],
        triage_results: list[TriageResult],
        routing_decisions: list[RoutingDecision],
        enrichments: list[EnrichmentResult],
        analyst_notes: str | None,
        fallback: IncidentNarrative,
    ) -> IncidentNarrative:
        """Ask the narrative client for prose, falling back when it cannot.

        Inputs:
            incident: Incident being reported.
            candidates: Candidates in the incident.
            triage_results: Triage results for those candidates.
            routing_decisions: Routing decisions, if any.
            enrichments: Enrichment results, if any.
            analyst_notes: Optional analyst notes.
            fallback: Deterministic narrative used when drafting fails.

        Outputs:
            A model-drafted narrative, or the deterministic fallback.
        """

        context = build_incident_narrative_context(
            incident,
            candidates=candidates,
            triage_results=triage_results,
            routing_decisions=routing_decisions,
            enrichments=enrichments,
            analyst_notes=analyst_notes,
        )
        prompt = build_incident_narrative_prompt(context)
        attempts = self.max_json_retries + 1

        for attempt in range(1, attempts + 1):
            try:
                response_text, model_name = self._invoke_narrative_client(prompt)
            except OpenRouterError as exc:
                # Transport failures are already retried inside the client with
                # backoff. Retrying here would multiply the wait on a
                # rate-limited model for no extra chance of success.
                logger.warning("Report narrative call failed for %s: %s", incident.id, exc)
                return _with_fallback_reason(fallback, str(exc))

            try:
                sections = parse_narrative_sections(parse_json_response_text(response_text))
            except (OpenRouterError, ReportError, KeyError, TypeError, ValueError) as exc:
                # One unusable response is worth another try: models often wrap
                # or truncate JSON, and dropping straight to the template
                # discards their judgment entirely.
                if attempt < attempts:
                    logger.warning(
                        "Report narrative was unusable for %s (attempt %d of %d): %s",
                        incident.id,
                        attempt,
                        attempts,
                        exc,
                    )
                    continue
                logger.warning("Falling back to a templated narrative for %s: %s", incident.id, exc)
                return _with_fallback_reason(fallback, str(exc))

            return IncidentNarrative(
                sections=sections,
                source=AnalysisSource.LLM,
                model=model_name,
                prompt_version=REPORT_PROMPT_VERSION,
            )

        return fallback

    def _invoke_narrative_client(self, prompt: str) -> tuple[str, str | None]:
        """Call the narrative client and report which model answered.

        Inputs:
            prompt: User prompt for the narrative call.

        Outputs:
            Tuple of response text and model name when reported.

        Raises:
            ReportError: If no narrative client is configured.
        """

        client = self.narrative_client
        if client is None:
            raise ReportError("no narrative client configured")

        if hasattr(client, "chat_completion"):
            messages = [
                {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ]
            result = client.chat_completion(
                messages,
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return result.content, result.model

        response_text = client.complete_text(
            prompt,
            system_prompt=REPORT_SYSTEM_PROMPT,
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        return response_text, self.model

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
    target: Incident | IncidentCandidate,
    triage: TriageResult | None = None,
    *,
    candidates: list[IncidentCandidate] | None = None,
    triage_results: list[TriageResult] | None = None,
    routing: RoutingDecision | None = None,
    routing_decisions: list[RoutingDecision] | None = None,
    enrichments: list[EnrichmentResult] | None = None,
    analyst_notes: str | None = None,
    title: str | None = None,
    narrative_client: TextCompletionClient | None = None,
    model: str | None = None,
) -> IncidentReport:
    """Create an IncidentReport for an incident or a single candidate.

    Passing an Incident produces the incident-level report (Milestone 4.3);
    passing an IncidentCandidate keeps the original candidate-level behaviour.
    `generated_by_model` is populated only when a model genuinely drafted the
    narrative, so a templated report can never look model-drafted.

    Inputs:
        target: Incident or IncidentCandidate being reported.
        triage: TriageResult, required for the candidate form.
        candidates: Candidates in the incident, for the incident form.
        triage_results: Triage results for those candidates.
        routing: Optional single RoutingDecision, for the candidate form.
        routing_decisions: Optional routing decisions, for the incident form.
        enrichments: Optional enrichment results.
        analyst_notes: Optional free-text analyst notes, for the incident form.
        title: Optional report title override.
        narrative_client: Optional client used to draft the prose sections.
        model: Optional model override for the narrative client.

    Outputs:
        IncidentReport instance.

    Raises:
        ReportError: If the candidate form is used without a triage result.
    """

    if isinstance(target, Incident):
        return _create_report_for_incident(
            target,
            candidates=list(candidates or []),
            triage_results=list(triage_results or []),
            routing_decisions=list(routing_decisions or ([routing] if routing else [])),
            enrichments=enrichments,
            analyst_notes=analyst_notes,
            title=title,
            narrative_client=narrative_client,
            model=model,
        )

    candidate = target
    if triage is None:
        raise ReportError("a candidate report requires a triage result")

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


def _create_report_for_incident(
    incident: Incident,
    *,
    candidates: list[IncidentCandidate],
    triage_results: list[TriageResult],
    routing_decisions: list[RoutingDecision],
    enrichments: list[EnrichmentResult] | None,
    analyst_notes: str | None,
    title: str | None,
    narrative_client: TextCompletionClient | None,
    model: str | None,
) -> IncidentReport:
    """Create an IncidentReport for a promoted incident.

    Inputs:
        incident: Incident being reported.
        candidates: Candidates in the incident.
        triage_results: Triage results for those candidates.
        routing_decisions: Routing decisions, if any.
        enrichments: Optional enrichment results.
        analyst_notes: Optional free-text analyst notes.
        title: Optional report title override.
        narrative_client: Optional client used to draft the prose sections.
        model: Optional model override for the narrative client.

    Outputs:
        IncidentReport instance whose generated_by_model is set only for a
        genuine model draft.
    """

    report_title = title or f"Incident Report: {incident.id}"
    builder = MarkdownReportBuilder(narrative_client, model=model)
    body, narrative = builder.render_incident_report(
        incident,
        candidates=candidates,
        triage_results=triage_results,
        routing_decisions=routing_decisions,
        enrichments=enrichments,
        analyst_notes=analyst_notes,
        title=report_title,
    )
    payload = {
        "id": _build_report_id(incident.id, "|".join(incident.triage_result_ids)),
        "incident_id": incident.id,
        "candidate_id": incident.candidate_ids[0] if incident.candidate_ids else incident.id,
        "triage_result_id": incident.triage_result_ids[0] if incident.triage_result_ids else "",
        "title": report_title,
        "summary": narrative.sections["executive_summary"],
        "body": body,
        "markdown": body,
        "content": body,
        "severity_score": incident.max_score,
        "generated_by_model": narrative.model if narrative.is_model_drafted else None,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "metadata": {
            "candidate_count": len(candidates),
            "alert_count": len(incident.alert_ids),
            "narrative_source": narrative.source.value,
            "report_prompt_version": narrative.prompt_version,
        },
    }
    return _make_incident_report(payload)


def build_incident_narrative_context(
    incident: Incident,
    *,
    candidates: list[IncidentCandidate],
    triage_results: list[TriageResult],
    routing_decisions: list[RoutingDecision] | None = None,
    enrichments: list[EnrichmentResult] | None = None,
    analyst_notes: str | None = None,
) -> JsonDict:
    """Build the allowlisted, truncated model context for an incident report.

    Every nested object goes through the `soc.triage` context builders, so raw
    source payloads, related raw events, and enrichment provider responses are
    excluded here for the same reasons they are excluded from triage.

    Inputs:
        incident: Incident being reported.
        candidates: Candidates in the incident.
        triage_results: Triage results for those candidates.
        routing_decisions: Optional routing decisions.
        enrichments: Optional enrichment results.
        analyst_notes: Optional free-text analyst notes.

    Outputs:
        JSON-safe dictionary containing allowlisted fields only.
    """

    candidate_list = list(candidates or [])
    context: JsonDict = {
        "incident": {
            name: _truncate_value(_json_safe(getattr(incident, name, None)))
            for name in INCIDENT_CONTEXT_FIELDS
        },
        "candidate_count": len(candidate_list),
        "candidates_truncated": len(candidate_list) > MAX_CONTEXT_CANDIDATES,
        "candidates": [build_candidate_context(item) for item in candidate_list[:MAX_CONTEXT_CANDIDATES]],
        "triage_results": [
            {
                name: _truncate_value(_json_safe(getattr(triage, name, None)))
                for name in TRIAGE_CONTEXT_FIELDS
            }
            for triage in triage_results or []
        ],
        "routing_decisions": [
            {
                name: _truncate_value(_json_safe(getattr(routing, name, None)))
                for name in ROUTING_CONTEXT_FIELDS
            }
            for routing in routing_decisions or []
        ],
        "enrichments": [build_enrichment_context(item) for item in enrichments or []],
    }

    notes = (analyst_notes or "").strip()
    if notes:
        context["analyst_notes"] = _truncate_notes(notes)
    return context


def build_incident_narrative_prompt(context: JsonDict) -> str:
    """Build the user prompt for the incident narrative call.

    Inputs:
        context: Allowlisted incident context from build_incident_narrative_context.

    Outputs:
        Prompt string.
    """

    return (
        "Draft the narrative sections of a SOC incident report from the context "
        "below. Return only JSON with the keys executive_summary, "
        "attack_narrative, remediation, and detection_gaps. Each value must be "
        "Markdown prose without headings.\n"
        "Ground every statement in the context, name the incident, candidate, "
        "alert, host, user, or indicator it rests on, and state plainly where "
        "the evidence is insufficient rather than filling the gap.\n\n"
        f"Incident context:\n{json.dumps(_json_safe(context), indent=2, sort_keys=True)}"
    )


def parse_narrative_sections(payload: JsonDict) -> dict[str, str]:
    """Validate a model narrative response into usable prose sections.

    A partially answered response is treated as unusable rather than merged with
    templated text: a report labelled model-drafted must be model-drafted
    throughout, or the label stops meaning anything.

    Inputs:
        payload: Parsed model JSON.

    Outputs:
        Narrative text keyed by NARRATIVE_SECTION_KEYS.

    Raises:
        ReportError: If any required section is missing or empty.
    """

    if not isinstance(payload, dict):
        raise ReportError("narrative response must be a JSON object")

    sections: dict[str, str] = {}
    for key in NARRATIVE_SECTION_KEYS:
        value = payload.get(key)
        text = "" if value is None else str(value).strip()
        if not text:
            raise ReportError(f"narrative response is missing section '{key}'")
        sections[key] = text
    return sections


def _templated_narrative(
    incident: Incident,
    candidates: list[IncidentCandidate],
    triage_results: list[TriageResult],
    enrichments: list[EnrichmentResult],
) -> IncidentNarrative:
    """Build the deterministic narrative used with no model.

    Inputs:
        incident: Incident being reported.
        candidates: Candidates in the incident.
        triage_results: Triage results for those candidates.
        enrichments: Enrichment results, if any.

    Outputs:
        IncidentNarrative labelled as locally produced.
    """

    return IncidentNarrative(
        sections={
            "executive_summary": _templated_executive_summary(incident, candidates, triage_results),
            "attack_narrative": _templated_attack_narrative(candidates),
            "remediation": _templated_remediation(triage_results),
            "detection_gaps": _templated_detection_gaps(incident, candidates, triage_results, enrichments),
        },
        source=AnalysisSource.LOCAL,
    )


def _with_fallback_reason(narrative: IncidentNarrative, reason: str) -> IncidentNarrative:
    """Return the templated narrative annotated with why drafting failed.

    Inputs:
        narrative: Deterministic narrative.
        reason: Error text from the failed narrative attempt.

    Outputs:
        IncidentNarrative carrying the fallback reason.
    """

    return IncidentNarrative(
        sections=narrative.sections,
        source=narrative.source,
        model=None,
        prompt_version=None,
        fallback_reason=reason,
    )


def _templated_executive_summary(
    incident: Incident,
    candidates: list[IncidentCandidate],
    triage_results: list[TriageResult],
) -> str:
    """Build the deterministic executive summary for an incident.

    Inputs:
        incident: Incident being reported.
        candidates: Candidates in the incident.
        triage_results: Triage results for those candidates.

    Outputs:
        Markdown text.
    """

    max_score = max((triage.score for triage in triage_results), default=incident.max_score)
    alert_count = len(incident.alert_ids) or sum(len(candidate.alerts) for candidate in candidates)
    hosts = _incident_hosts(incident, candidates)
    lines = [
        f"Incident `{incident.id}` covers {len(incident.candidate_ids) or len(candidates)} candidate(s) "
        f"and {alert_count} alert(s) between {_format_time(incident.first_seen)} and "
        f"{_format_time(incident.last_seen)}.",
        "",
        f"- **Maximum triage score:** {max_score}/10",
        f"- **Primary host:** `{incident.primary_host or 'unknown'}`",
        f"- **Primary user:** `{incident.primary_user or 'unknown'}`",
        f"- **Hosts involved:** {_comma_code(hosts)}",
        f"- **Candidates:** {_comma_code(incident.candidate_ids or [c.id for c in candidates])}",
    ]
    if incident.asset_context:
        lines.append(f"- **Asset context:** {_compact_dict(dict(incident.asset_context))}")
    if triage_results:
        lines.append("")
        lines.append("Triage summaries:")
        lines.extend(f"- `{triage.target_id}`: {triage.summary}" for triage in triage_results)
    return "\n".join(lines)


def _templated_attack_narrative(candidates: list[IncidentCandidate]) -> str:
    """Build the deterministic attack narrative for an incident.

    This is an ordered restatement of what fired, not an interpretation. Saying
    so keeps a reader from mistaking a chronology for an analyst's judgement.

    Inputs:
        candidates: Candidates in the incident.

    Outputs:
        Markdown text.
    """

    pairs = _incident_alert_pairs(candidates)
    if not pairs:
        return (
            "No alert detail is attached to this incident, so no sequence of activity can be "
            "reconstructed. The evidence available is insufficient to describe an attack path."
        )

    lines = [
        "Templated chronology of the detections in this incident. No model or analyst "
        "interpretation has been applied, so treat causal links as unproven:",
        "",
    ]
    for candidate, alert in pairs[:MAX_NARRATIVE_TIMELINE_LINES]:
        lines.append(
            f"- {_format_time(alert.timestamp)} — `{alert.rule_name or 'Unknown rule'}` fired on "
            f"`{alert.hostname or 'unknown host'}` for user `{alert.user or 'unknown'}` "
            f"(candidate `{candidate.id}`, alert `{alert.id}`)."
        )
    if len(pairs) > MAX_NARRATIVE_TIMELINE_LINES:
        lines.append(f"- ...and {len(pairs) - MAX_NARRATIVE_TIMELINE_LINES} further alert(s); see the Timeline.")
    return "\n".join(lines)


def _templated_remediation(triage_results: list[TriageResult]) -> str:
    """Build the deterministic remediation section.

    Inputs:
        triage_results: Triage results for the incident.

    Outputs:
        Markdown text.
    """

    suggested: list[str] = []
    for triage in triage_results:
        for action in triage.recommended_actions:
            text = str(action).strip()
            if text and text not in suggested:
                suggested.append(text)

    if suggested:
        return "\n".join(f"- {action}" for action in suggested)

    if not triage_results:
        return (
            "- No triage result is attached to this incident, so no remediation can be "
            "recommended from the stored evidence.\n"
            "- Confirm the incident scope before taking any containment action."
        )

    strongest = max(triage_results, key=lambda triage: triage.score)
    return _recommended_actions_markdown(strongest)


def _templated_detection_gaps(
    incident: Incident,
    candidates: list[IncidentCandidate],
    triage_results: list[TriageResult],
    enrichments: list[EnrichmentResult],
) -> str:
    """Build the deterministic detection-gaps section.

    Inputs:
        incident: Incident being reported.
        candidates: Candidates in the incident.
        triage_results: Triage results for those candidates.
        enrichments: Enrichment results, if any.

    Outputs:
        Markdown text.
    """

    pairs = _incident_alert_pairs(candidates)
    sources = sorted({alert.source.value for _, alert in pairs})
    lines = ["Templated observations about coverage. These are gaps in the recorded evidence, not an audit:"]

    if sources:
        lines.append(f"- Detection coverage in this incident came only from: {_comma_code(sources)}.")
    else:
        lines.append("- No alert detail is attached, so detection coverage cannot be assessed.")
    if not enrichments:
        lines.append("- No enrichment results are attached, so indicator reputation was never checked.")
    if not any(triage.analysis_source is AnalysisSource.LLM for triage in triage_results):
        lines.append("- Every triage score here came from local heuristics; no model reviewed the activity.")
    hosts_without_agent = sorted(
        {alert.hostname for _, alert in pairs if alert.hostname and not alert.agent_id}
    )
    if hosts_without_agent:
        lines.append(f"- No agent ID was recorded for: {_comma_code(hosts_without_agent)}.")
    if not incident.asset_context:
        lines.append("- No asset context is available for the affected hosts, so business impact is unknown.")
    return "\n".join(lines)


def _provenance_markdown(narrative: IncidentNarrative) -> str:
    """State plainly whether the narrative was model-drafted or templated.

    Inputs:
        narrative: Narrative used in the report.

    Outputs:
        Markdown text.
    """

    lines = []
    if narrative.is_model_drafted:
        model_text = f"`{narrative.model}`" if narrative.model else "an unreported model"
        lines.append(f"- **Narrative:** model-drafted by LLM {model_text}")
        lines.append(f"- **Report prompt version:** `{narrative.prompt_version or REPORT_PROMPT_VERSION}`")
    else:
        lines.append("- **Narrative:** templated deterministically from stored data")
        lines.append("- **Report prompt version:** none; no model was consulted")
        if narrative.fallback_reason:
            lines.append(
                "- **Why templated:** the narrative call did not produce usable prose "
                f"({narrative.fallback_reason})"
            )
    lines.append(
        "- **Deterministic sections:** Timeline, Affected Assets, IOCs, Triage Decisions, and "
        "Enrichment Summary are always rendered from stored data."
    )
    return "\n".join(lines)


def _timeline_markdown(pairs: list[tuple[IncidentCandidate, Alert]]) -> str:
    """Build the incident timeline table.

    Inputs:
        pairs: (candidate, alert) pairs in chronological order.

    Outputs:
        Markdown text.
    """

    if not pairs:
        return "No alerts are attached to this incident."

    lines = [
        "| Time | Alert ID | Candidate | Severity | Rule | Host | User | Src | Dst |",
        "|---|---|---|---:|---|---|---|---|---|",
    ]
    for candidate, alert in pairs:
        lines.append(
            "| "
            f"{_format_time(alert.timestamp)} | `{alert.id}` | `{candidate.id}` | "
            f"`{alert.severity.value}` | {_escape_table(alert.rule_name or 'Unknown rule')} | "
            f"`{alert.hostname or ''}` | `{alert.user or ''}` | `{alert.src_ip or ''}` | "
            f"`{alert.dst_ip or ''}` |"
        )
    return "\n".join(lines)


def _affected_assets_markdown(incident: Incident, candidates: list[IncidentCandidate]) -> str:
    """Build the affected-assets section.

    Inputs:
        incident: Incident being reported.
        candidates: Candidates in the incident.

    Outputs:
        Markdown text.
    """

    pairs = _incident_alert_pairs(candidates)
    users = sorted({alert.user for _, alert in pairs if alert.user} | _optional_set(incident.primary_user))
    agents = sorted({alert.agent_id for _, alert in pairs if alert.agent_id})
    lines = [
        f"- **Primary host:** `{incident.primary_host or 'unknown'}`",
        f"- **Primary user:** `{incident.primary_user or 'unknown'}`",
        f"- **Hosts:** {_comma_code(_incident_hosts(incident, candidates))}",
        f"- **Users:** {_comma_code(users)}",
        f"- **Agent IDs:** {_comma_code(agents)}",
        f"- **First seen:** {_format_time(incident.first_seen)}",
        f"- **Last seen:** {_format_time(incident.last_seen)}",
    ]

    if incident.asset_context:
        lines.append("- **Asset context:**")
        lines.extend(f"  - **{key}:** `{value}`" for key, value in sorted(incident.asset_context.items()))
    else:
        lines.append("- **Asset context:** `none recorded`")
    return "\n".join(lines)


def _incident_iocs_markdown(
    incident: Incident,
    triage_results: list[TriageResult],
    enrichments: list[EnrichmentResult],
) -> str:
    """Build the IOC section, aggregating every source of indicators.

    Inputs:
        incident: Incident being reported.
        triage_results: Triage results for the incident.
        enrichments: Enrichment results, if any.

    Outputs:
        Markdown text.
    """

    grouped: dict[str, list[str]] = {}
    _add_iocs(grouped, "source_ips", incident.src_ips)
    _add_iocs(grouped, "destination_ips", incident.dst_ips)
    for triage in triage_results:
        for kind, values in (triage.iocs or {}).items():
            _add_iocs(grouped, str(kind), values if isinstance(values, list) else [values])
    for enrichment in enrichments:
        indicator = _field(enrichment, "indicator", "ioc", "observable", "value", default=None)
        if indicator:
            _add_iocs(grouped, str(_field(enrichment, "indicator_type", default="unknown")), [indicator])

    if not grouped:
        return "No indicators of compromise were extracted for this incident."

    lines = ["| Type | Indicators |", "|---|---|"]
    for kind in sorted(grouped):
        lines.append(f"| `{kind}` | {_comma_code(grouped[kind])} |")
    return "\n".join(lines)


def _triage_summary_markdown(triage_results: list[TriageResult]) -> str:
    """Build the per-candidate triage table.

    Inputs:
        triage_results: Triage results for the incident.

    Outputs:
        Markdown text.
    """

    if not triage_results:
        return "No triage results are attached to this incident."

    lines = ["| Target | Score | Action | Classification | Analysis source |", "|---|---:|---|---|---|"]
    for triage in triage_results:
        lines.append(
            f"| `{triage.target_id}` | {triage.score}/10 | `{triage.action.value}` | "
            f"`{triage.classification}` | {_escape_table(_analysis_source_description(triage))} |"
        )
    return "\n".join(lines)


def _add_iocs(grouped: dict[str, list[str]], kind: str, values: Any) -> None:
    """Add indicator values to a grouped IOC mapping, de-duplicated.

    Inputs:
        grouped: Mapping being built.
        kind: Indicator type label.
        values: Indicator values.

    Outputs:
        None. Updates grouped in place.
    """

    for value in values or []:
        text = str(value).strip()
        if not text:
            continue
        bucket = grouped.setdefault(kind, [])
        if text not in bucket:
            bucket.append(text)


def _incident_alert_pairs(candidates: list[IncidentCandidate]) -> list[tuple[IncidentCandidate, Alert]]:
    """Return every alert across candidates in chronological order.

    Inputs:
        candidates: Candidates in the incident.

    Outputs:
        List of (candidate, alert) pairs.
    """

    pairs = [(candidate, alert) for candidate in candidates or [] for alert in candidate.alerts]
    return sorted(pairs, key=lambda pair: (_sort_timestamp(pair[1].timestamp), pair[1].id))


def _sort_timestamp(value: Any) -> float:
    """Return a sortable timestamp for an alert.

    Inputs:
        value: datetime-like value.

    Outputs:
        POSIX timestamp, or 0.0 when unavailable.
    """

    if isinstance(value, datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return moment.timestamp()
    return 0.0


def _incident_hosts(incident: Incident, candidates: list[IncidentCandidate]) -> list[str]:
    """Return every host named by the incident or its candidates.

    Inputs:
        incident: Incident being reported.
        candidates: Candidates in the incident.

    Outputs:
        Sorted host list.
    """

    hosts = _optional_set(incident.primary_host)
    for candidate in candidates or []:
        hosts |= _optional_set(candidate.primary_host)
        hosts |= {alert.hostname for alert in candidate.alerts if alert.hostname}
    return sorted(hosts)


def _optional_set(value: str | None) -> set[str]:
    """Return a one-element set for a value, or an empty set.

    Inputs:
        value: Optional string.

    Outputs:
        Set containing the value when it is non-empty.
    """

    return {value} if value else set()


def _collected_enrichments(candidates: list[IncidentCandidate]) -> list[EnrichmentResult]:
    """Collect enrichment results already attached to candidates.

    Inputs:
        candidates: Candidates in the incident.

    Outputs:
        Enrichment result list.
    """

    return [enrichment for candidate in candidates or [] for enrichment in candidate.enrichments or []]


def _truncate_notes(notes: str) -> str:
    """Truncate analyst notes using the shared truncation marker.

    Inputs:
        notes: Analyst notes text.

    Outputs:
        Notes truncated to MAX_ANALYST_NOTES_CHARS.
    """

    if len(notes) <= MAX_ANALYST_NOTES_CHARS:
        return notes
    return notes[:MAX_ANALYST_NOTES_CHARS] + TRUNCATION_MARKER


def build_incident_report(
    incident: Incident,
    *,
    candidates: list[IncidentCandidate],
    triage_results: list[TriageResult],
    routing_decisions: list[RoutingDecision] | None = None,
    enrichments: list[EnrichmentResult] | None = None,
    analyst_notes: str | None = None,
    title: str | None = None,
    narrative_client: TextCompletionClient | None = None,
    model: str | None = None,
) -> str:
    """Convenience function for incident Markdown report generation.

    Inputs:
        incident: Incident being reported.
        candidates: Candidates the incident was promoted from.
        triage_results: Triage results for those candidates.
        routing_decisions: Optional routing decisions.
        enrichments: Optional enrichment results.
        analyst_notes: Optional free-text analyst notes.
        title: Optional report title override.
        narrative_client: Optional client used to draft the prose sections.
        model: Optional model override for the narrative client.

    Outputs:
        Markdown report text.
    """

    return MarkdownReportBuilder(narrative_client, model=model).build_incident_report(
        incident,
        candidates=candidates,
        triage_results=triage_results,
        routing_decisions=routing_decisions,
        enrichments=enrichments,
        analyst_notes=analyst_notes,
        title=title,
    )


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
            f"- **Analysis source:** {_analysis_source_description(triage)}",
            f"- **Summary:** {triage.summary}",
        ]
    )


def _analysis_source_description(triage: TriageResult) -> str:
    """Describe what actually produced a triage score.

    A reader deciding whether to trust a score needs to know whether a model
    produced it or whether local heuristics did, including when an LLM call
    failed and fell back. Never let one present itself as the other.

    Inputs:
        triage: TriageResult object.

    Outputs:
        Human-readable provenance description.
    """

    if triage.analysis_source != AnalysisSource.LLM:
        return "Deterministic local scoring (no model was consulted)"

    parts = [f"LLM `{triage.model}`" if triage.model else "LLM (model not reported)"]
    if triage.prompt_version:
        parts.append(f"prompt `{triage.prompt_version}`")
    if triage.latency_ms is not None:
        parts.append(f"{triage.latency_ms} ms")
    return ", ".join(parts)


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

    fingerprint = hashlib.sha256(f"{candidate_id}:{triage_id}".encode()).hexdigest()[:12]
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

    fingerprint = hashlib.sha256(f"{scope_id}:{kind}:{item_id}".encode()).hexdigest()[:12]
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
            value = value.replace(tzinfo=UTC)
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