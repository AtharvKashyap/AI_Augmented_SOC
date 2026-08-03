

"""Core data models for AI_Augmented_SOC.

This module defines the shared data contracts used across the SOC pipeline.
The rest of the project should pass these models between clients, the
normalizer, the database layer, the triage engine, routing, and reporting.

Design goals:
    - Keep models lightweight and dependency-free.
    - Preserve raw source data for auditability.
    - Make objects easy to serialize into JSON or SQLite.
    - Avoid tool-specific assumptions leaking through the whole codebase.

The main flow is:
    Wazuh/Security Onion raw event
        -> RawEvent
        -> Alert
        -> IncidentCandidate
        -> TriageResult
        -> RoutingDecision / IncidentReport
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


JsonDict = dict[str, Any]


def utc_now() -> datetime:
    """Return the current UTC time with timezone information.

    Returns:
        A timezone-aware UTC datetime.
    """

    return datetime.now(timezone.utc)


class EventSource(str, Enum):
    """Supported sources of SOC telemetry.

    Values:
        WAZUH: Endpoint/security alerts from Wazuh.
        SECURITY_ONION: Network/security alerts from Security Onion.
        OPENBSD_PF: Future firewall telemetry from OpenBSD pflog/pfctl.
        SPLUNK: Future Splunk-originated or Splunk-forwarded events.
        REPLAY: Local fixture/manual replay events for testing.
        UNKNOWN: Fallback when a source cannot be identified.
    """

    WAZUH = "wazuh"
    SECURITY_ONION = "security_onion"
    OPENBSD_PF = "openbsd_pf"
    SPLUNK = "splunk"
    REPLAY = "replay"
    UNKNOWN = "unknown"


class AlertSeverity(str, Enum):
    """Normalized alert severity values.

    Not every tool uses the same severity scale. This enum gives the rest of
    the project a common vocabulary while preserving original severity in raw
    event data.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class TriageAction(str, Enum):
    """Valid routing actions returned by AI triage.

    Values:
        PAGE_NOW: Notify an analyst immediately.
        QUEUE_REVIEW: Store for analyst review.
        MARK_LIKELY_BENIGN: Keep searchable, but do not page.
    """

    PAGE_NOW = "page_now"
    QUEUE_REVIEW = "queue_review"
    MARK_LIKELY_BENIGN = "mark_likely_benign"


class FalsePositiveLikelihood(str, Enum):
    """Likelihood that an alert or incident candidate is a false positive."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class RoutingStatus(str, Enum):
    """Status of a routing decision after triage."""

    CREATED = "created"
    SENT = "sent"
    QUEUED = "queued"
    MARKED_LIKELY_BENIGN = "marked_likely_benign"
    FAILED = "failed"


class AnalysisSource(str, Enum):
    """What actually produced a triage score.

    A deterministic local score and a model score are not equivalent evidence,
    and a local score produced by LLM fallback must never be presented as model
    output. Every TriageResult records which one it is.

    Values:
        LOCAL: Deterministic local scoring rules.
        LLM: Language model response, parsed and validated.
    """

    LOCAL = "local"
    LLM = "llm"


@dataclass(slots=True)
class WazuhAgent:
    """Endpoint inventory record from Wazuh.

    Wazuh identifies which endpoint generated an alert. This model stores the
    endpoint metadata that can be joined with alerts during normalization,
    triage, and reporting.

    Attributes:
        agent_id: Wazuh agent ID.
        hostname: Endpoint hostname reported by Wazuh.
        ip: Endpoint IP address, if known.
        os_name: Operating system name, if known.
        os_version: Operating system version, if known.
        status: Wazuh agent status, such as active/disconnected.
        groups: Wazuh groups assigned to the agent.
        labels: Optional Wazuh labels or custom metadata.
        last_seen: Last time Wazuh saw the agent.
        raw: Original Wazuh agent payload for audit/debugging.
    """

    agent_id: str
    hostname: str | None = None
    ip: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    status: str | None = None
    groups: list[str] = field(default_factory=list)
    labels: JsonDict = field(default_factory=dict)
    last_seen: datetime | None = None
    raw: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        """Serialize the agent into a JSON-compatible dictionary.

        Returns:
            Dictionary representation of the Wazuh agent.
        """

        return _serialize_dataclass(self)


@dataclass(slots=True)
class RawEvent:
    """Raw event collected from a telemetry source before normalization.

    Raw events are stored before parsing so the system keeps an audit trail and
    can re-run normalization later if field mappings improve.

    Attributes:
        id: Stable local or source event identifier.
        source: Tool/source that produced the event.
        timestamp: Event timestamp.
        received_at: Time the automation system received the event.
        payload: Original event body.
    """

    id: str
    source: EventSource
    timestamp: datetime | None
    payload: JsonDict
    received_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> JsonDict:
        """Serialize the raw event into a JSON-compatible dictionary.

        Returns:
            Dictionary representation of the raw event.
        """

        return _serialize_dataclass(self)


@dataclass(slots=True)
class Alert:
    """Normalized alert used by the SOC pipeline.

    This model hides source-specific differences between Wazuh and Security
    Onion. Source-specific fields should remain in `raw` while common fields
    are promoted to top-level attributes.

    Attributes:
        id: Stable alert identifier.
        source: Source tool that produced the alert.
        timestamp: When the alert occurred.
        severity: Normalized severity.
        source_severity: Original severity value from the source tool.
        rule_name: Rule/signature name.
        rule_groups: Rule groups/categories from the source tool.
        src_ip: Source IP, if present.
        dst_ip: Destination IP, if present.
        hostname: Hostname involved in the alert, if known.
        agent_id: Wazuh agent ID, if applicable.
        agent_os: Endpoint operating system, if known.
        user: User involved in the event, if known.
        process_name: Process name involved in the alert, if known.
        command_line: Command line involved in the alert, if known.
        raw_event_id: ID of the stored RawEvent this alert came from.
        raw: Original source payload or selected source fields.
    """

    id: str
    source: EventSource
    timestamp: datetime | None
    severity: AlertSeverity = AlertSeverity.UNKNOWN
    source_severity: str | int | None = None
    rule_name: str | None = None
    rule_groups: list[str] = field(default_factory=list)
    src_ip: str | None = None
    dst_ip: str | None = None
    hostname: str | None = None
    agent_id: str | None = None
    agent_os: str | None = None
    user: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    raw_event_id: str | None = None
    raw: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        """Serialize the alert into a JSON-compatible dictionary.

        Returns:
            Dictionary representation of the alert.
        """

        return _serialize_dataclass(self)


@dataclass(slots=True)
class EnrichmentResult:
    """Threat-intelligence or context enrichment attached to an IOC.

    Attributes:
        indicator: IP, domain, URL, hash, or other IOC that was enriched.
        indicator_type: Type of indicator, such as ip/domain/url/hash.
        provider: Enrichment provider name, such as VirusTotal or AbuseIPDB.
        summary: Short human-readable enrichment summary.
        raw: Original provider response or selected fields.
        looked_up_at: Time the enrichment lookup was performed.
    """

    indicator: str
    indicator_type: str
    provider: str
    summary: str | None = None
    raw: JsonDict = field(default_factory=dict)
    looked_up_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> JsonDict:
        """Serialize the enrichment result into a JSON-compatible dictionary.

        Returns:
            Dictionary representation of the enrichment result.
        """

        return _serialize_dataclass(self)


@dataclass(slots=True)
class IncidentCandidate:
    """Group of related alerts that may represent one incident.

    Low-alert environments may produce single-alert candidates. Higher-volume
    environments can group related endpoint and network evidence by host, user,
    source IP, destination IP, and time window.

    Attributes:
        id: Local candidate ID, such as CAND-YYYYMMDD-NNN.
        first_seen: Earliest event time in the candidate.
        last_seen: Latest event time in the candidate.
        alerts: Normalized alerts included in the candidate.
        primary_host: Main affected host, if known.
        primary_user: Main affected user, if known.
        src_ips: Source IPs involved.
        dst_ips: Destination IPs involved.
        related_events: Additional raw/normalized context events.
        enrichments: Threat-intel/context enrichment results.
        created_at: Time the candidate was created locally.
    """

    id: str
    first_seen: datetime | None
    last_seen: datetime | None
    alerts: list[Alert] = field(default_factory=list)
    primary_host: str | None = None
    primary_user: str | None = None
    src_ips: list[str] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)
    related_events: list[RawEvent] = field(default_factory=list)
    enrichments: list[EnrichmentResult] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> JsonDict:
        """Serialize the candidate into a JSON-compatible dictionary.

        Returns:
            Dictionary representation of the incident candidate.
        """

        return _serialize_dataclass(self)


@dataclass(slots=True)
class EvidenceItem:
    """Specific evidence supporting an AI triage or report claim.

    Attributes:
        source: Source tool where the evidence came from.
        field: Field name used as evidence.
        value: Field value used as evidence.
        timestamp: Event timestamp, if available.
        alert_id: Related normalized alert ID, if available.
        raw_event_id: Related raw event ID, if available.
    """

    source: EventSource
    field: str
    value: Any
    timestamp: datetime | None = None
    alert_id: str | None = None
    raw_event_id: str | None = None

    def to_dict(self) -> JsonDict:
        """Serialize the evidence item into a JSON-compatible dictionary.

        Returns:
            Dictionary representation of the evidence item.
        """

        return _serialize_dataclass(self)


@dataclass(slots=True)
class TriageResult:
    """Structured AI triage output for an alert or incident candidate.

    Attributes:
        id: Local triage result ID.
        target_id: Alert ID or incident candidate ID being triaged.
        target_type: Type of target, usually alert or incident_candidate.
        score: Integer score from 1 to 10.
        fp_likelihood: Estimated false-positive likelihood.
        classification: Short classification label.
        action: Recommended routing action.
        summary: Plain-English summary of the activity.
        iocs: Extracted indicators of compromise grouped by type.
        recommended_actions: Analyst next steps.
        reasoning: Brief explanation of the score and action.
        evidence: Evidence items supporting important claims.
        model: LLM model used for triage.
        latency_ms: LLM call latency, if recorded.
        token_usage: Token usage metadata, if available.
        created_at: Local creation time.
    """

    id: str
    target_id: str
    target_type: str
    score: int
    fp_likelihood: FalsePositiveLikelihood
    classification: str
    action: TriageAction
    summary: str
    iocs: JsonDict = field(default_factory=dict)
    recommended_actions: list[str] = field(default_factory=list)
    reasoning: str | None = None
    evidence: list[EvidenceItem] = field(default_factory=list)
    model: str | None = None
    latency_ms: int | None = None
    token_usage: JsonDict = field(default_factory=dict)
    analysis_source: AnalysisSource = AnalysisSource.LOCAL
    prompt_version: str | None = None
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        """Validate score range immediately after object creation.

        Raises:
            ValueError: If score is outside the inclusive range 1-10.
        """

        if not 1 <= self.score <= 10:
            raise ValueError("TriageResult.score must be between 1 and 10")

    def to_dict(self) -> JsonDict:
        """Serialize the triage result into a JSON-compatible dictionary.

        Returns:
            Dictionary representation of the triage result.
        """

        return _serialize_dataclass(self)


@dataclass(slots=True)
class RoutingDecision:
    """Decision made after triage about where an alert/candidate should go.

    Attributes:
        id: Local routing decision ID.
        triage_result_id: Associated triage result ID.
        target_id: Alert ID or incident candidate ID.
        action: Routing action selected by triage/router.
        status: Delivery or queueing status.
        destination: Notification destination, queue name, or local marker.
        message: Human-readable routing message.
        error: Error message if routing failed.
        created_at: Local creation time.
        updated_at: Last update time.
    """

    id: str
    triage_result_id: str
    target_id: str
    action: TriageAction
    status: RoutingStatus = RoutingStatus.CREATED
    destination: str | None = None
    message: str | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> JsonDict:
        """Serialize the routing decision into a JSON-compatible dictionary.

        Returns:
            Dictionary representation of the routing decision.
        """

        return _serialize_dataclass(self)


@dataclass(slots=True)
class IncidentReport:
    """Markdown report generated for an incident or incident candidate.

    Attributes:
        id: Local report ID.
        incident_id: Incident or candidate ID being reported on.
        title: Report title.
        markdown: Full Markdown report body.
        generated_by_model: LLM model used to generate the report.
        output_path: Local file path if written to disk.
        created_at: Local creation time.
    """

    id: str
    incident_id: str
    title: str
    markdown: str
    generated_by_model: str | None = None
    output_path: str | None = None
    created_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> JsonDict:
        """Serialize the incident report into a JSON-compatible dictionary.

        Returns:
            Dictionary representation of the incident report.
        """

        return _serialize_dataclass(self)


def _serialize_dataclass(instance: Any) -> JsonDict:
    """Convert a dataclass instance into a JSON-compatible dictionary.

    Dataclasses may contain nested dataclasses, enums, datetimes, lists, and
    dictionaries. This helper normalizes those values so the result can be
    written to JSON logs, stored in SQLite as JSON text, or sent to an LLM.

    Args:
        instance: Dataclass instance to serialize.

    Returns:
        JSON-compatible dictionary.
    """

    return _serialize_value(asdict(instance))


def _serialize_value(value: Any) -> Any:
    """Recursively serialize common Python values into JSON-compatible values.

    Args:
        value: Any Python value.

    Returns:
        JSON-compatible value.
    """

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [_serialize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _serialize_value(item) for key, item in value.items()}
    return value