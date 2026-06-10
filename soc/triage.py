

"""AI-assisted triage for alerts and incident candidates.

This module turns normalized Alert or IncidentCandidate objects into
TriageResult objects. It uses OpenRouter when a client is provided, but keeps a
safe deterministic fallback so replay/testing can run without live LLM access.

Expected LLM JSON shape:
    {
      "score": 8,
      "fp_likelihood": "low",
      "classification": "likely_true_positive",
      "action": "page_now",
      "summary": "Concise analyst summary",
      "reasoning": ["short reason 1", "short reason 2"]
    }
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from typing import Any, Protocol

from soc.models import (
    Alert,
    AlertSeverity,
    EnrichmentResult,
    FalsePositiveLikelihood,
    IncidentCandidate,
    TriageAction,
    TriageResult,
)
from soc.openrouter_client import OpenRouterError, parse_json_response_text


JsonDict = dict[str, Any]


class TriageError(ValueError):
    """Raised when triage input or output is invalid."""


class TextCompletionClient(Protocol):
    """Protocol for LLM clients used by the triage engine."""

    def complete_text(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 800,
    ) -> str:
        """Return text completion for a prompt."""


class TriageEngine:
    """Create triage results for alerts and incident candidates.

    Args:
        llm_client: Optional client with complete_text(). If omitted, triage is
            deterministic and local only.
        model: Optional model override passed to the LLM client.
        max_tokens: Maximum LLM output tokens.
        temperature: LLM sampling temperature.
        allow_fallback: If True, malformed/failed LLM output falls back to local
            deterministic triage instead of raising.
    """

    def __init__(
        self,
        llm_client: TextCompletionClient | None = None,
        *,
        model: str | None = None,
        max_tokens: int = 800,
        temperature: float = 0.1,
        allow_fallback: bool = True,
    ) -> None:
        """Initialize the triage engine.

        Inputs:
            llm_client: Optional OpenRouter-like client.
            model: Optional model override.
            max_tokens: Maximum LLM output tokens.
            temperature: LLM sampling temperature.
            allow_fallback: Whether local fallback is allowed on LLM failure.

        Outputs:
            None.
        """

        if max_tokens <= 0:
            raise TriageError("max_tokens must be greater than zero")
        if temperature < 0:
            raise TriageError("temperature cannot be negative")

        self.llm_client = llm_client
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.allow_fallback = allow_fallback

    def triage_alert(self, alert: Alert, enrichments: list[EnrichmentResult] | None = None) -> TriageResult:
        """Triage one normalized alert.

        Inputs:
            alert: Alert to analyze.
            enrichments: Optional local or external enrichment results.

        Outputs:
            TriageResult object.
        """

        target_payload = build_alert_triage_payload(alert, enrichments or [])
        return self._triage_payload(
            target_id=alert.id,
            target_type="alert",
            target_payload=target_payload,
            fallback_result=local_triage_alert(alert, enrichments or []),
        )

    def triage_candidate(
        self,
        candidate: IncidentCandidate,
        enrichments: list[EnrichmentResult] | None = None,
    ) -> TriageResult:
        """Triage one incident candidate.

        Inputs:
            candidate: IncidentCandidate to analyze.
            enrichments: Optional local or external enrichment results.

        Outputs:
            TriageResult object.
        """

        target_payload = build_candidate_triage_payload(candidate, enrichments or [])
        return self._triage_payload(
            target_id=candidate.id,
            target_type="incident_candidate",
            target_payload=target_payload,
            fallback_result=local_triage_candidate(candidate, enrichments or []),
        )

    def triage_candidates(
        self,
        candidates: list[IncidentCandidate],
        enrichments_by_candidate_id: dict[str, list[EnrichmentResult]] | None = None,
    ) -> list[TriageResult]:
        """Triage multiple incident candidates.

        Inputs:
            candidates: Incident candidates to analyze.
            enrichments_by_candidate_id: Optional enrichment lookup by candidate ID.

        Outputs:
            TriageResult objects in the same order.
        """

        enrichment_lookup = enrichments_by_candidate_id or {}
        return [self.triage_candidate(candidate, enrichment_lookup.get(candidate.id, [])) for candidate in candidates]

    def _triage_payload(
        self,
        *,
        target_id: str,
        target_type: str,
        target_payload: JsonDict,
        fallback_result: TriageResult,
    ) -> TriageResult:
        """Triage a serialized payload with optional LLM assistance.

        Inputs:
            target_id: Alert or candidate ID.
            target_type: Target type label.
            target_payload: JSON-serializable target payload.
            fallback_result: Deterministic fallback result.

        Outputs:
            TriageResult object.
        """

        if self.llm_client is None:
            return fallback_result

        prompt = build_triage_prompt(target_payload)
        try:
            response_text = self.llm_client.complete_text(
                prompt,
                system_prompt=TRIAGE_SYSTEM_PROMPT,
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            parsed = parse_json_response_text(response_text)
            return triage_result_from_llm_json(parsed, target_id=target_id, target_type=target_type)
        except (OpenRouterError, TriageError, KeyError, TypeError, ValueError) as exc:
            if not self.allow_fallback:
                raise TriageError(f"LLM triage failed: {exc}") from exc
            return fallback_result


TRIAGE_SYSTEM_PROMPT = """You are a careful SOC triage assistant.
Return only valid JSON. Do not include markdown.
Score from 1 to 10, where 10 is urgent confirmed compromise.
Choose action from: page_now, queue_review, mark_likely_benign.
Choose fp_likelihood from: low, medium, high, unknown.
Be conservative: page only for credible high-impact or active compromise.
"""


def triage_alert(
    alert: Alert,
    enrichments: list[EnrichmentResult] | None = None,
    *,
    llm_client: TextCompletionClient | None = None,
) -> TriageResult:
    """Convenience function for triaging one alert.

    Inputs:
        alert: Alert to analyze.
        enrichments: Optional enrichment results.
        llm_client: Optional OpenRouter-like client.

    Outputs:
        TriageResult object.
    """

    return TriageEngine(llm_client).triage_alert(alert, enrichments or [])


def triage_candidate(
    candidate: IncidentCandidate,
    enrichments: list[EnrichmentResult] | None = None,
    *,
    llm_client: TextCompletionClient | None = None,
) -> TriageResult:
    """Convenience function for triaging one incident candidate.

    Inputs:
        candidate: IncidentCandidate to analyze.
        enrichments: Optional enrichment results.
        llm_client: Optional OpenRouter-like client.

    Outputs:
        TriageResult object.
    """

    return TriageEngine(llm_client).triage_candidate(candidate, enrichments or [])


def local_triage_alert(alert: Alert, enrichments: list[EnrichmentResult] | None = None) -> TriageResult:
    """Create deterministic local triage result for one alert.

    Inputs:
        alert: Alert to analyze.
        enrichments: Optional enrichment results.

    Outputs:
        TriageResult object.
    """

    enrichments = enrichments or []
    score = score_alert_locally(alert, enrichments)
    fp_likelihood = _fp_likelihood_from_score(score)
    action = _action_from_score(score)
    classification = _classification_from_score(score)
    summary = _local_alert_summary(alert, score, action)

    return TriageResult(
        id=_build_triage_id(alert.id, "alert", score, classification),
        target_id=alert.id,
        target_type="alert",
        score=score,
        fp_likelihood=fp_likelihood,
        classification=classification,
        action=action,
        summary=summary,
    )


def local_triage_candidate(
    candidate: IncidentCandidate,
    enrichments: list[EnrichmentResult] | None = None,
) -> TriageResult:
    """Create deterministic local triage result for one incident candidate.

    Inputs:
        candidate: IncidentCandidate to analyze.
        enrichments: Optional enrichment results.

    Outputs:
        TriageResult object.
    """

    enrichments = enrichments or []
    score = score_candidate_locally(candidate, enrichments)
    fp_likelihood = _fp_likelihood_from_score(score)
    action = _action_from_score(score)
    classification = _classification_from_score(score)
    summary = _local_candidate_summary(candidate, score, action)

    return TriageResult(
        id=_build_triage_id(candidate.id, "incident_candidate", score, classification),
        target_id=candidate.id,
        target_type="incident_candidate",
        score=score,
        fp_likelihood=fp_likelihood,
        classification=classification,
        action=action,
        summary=summary,
    )


def score_alert_locally(alert: Alert, enrichments: list[EnrichmentResult] | None = None) -> int:
    """Score an alert using deterministic local rules.

    Inputs:
        alert: Alert to score.
        enrichments: Optional enrichment results.

    Outputs:
        Integer score from 1 to 10.
    """

    score = _base_score_for_severity(alert.severity)
    searchable = " ".join(
        str(value or "")
        for value in [alert.rule_name, alert.command_line, alert.process_name, alert.user, alert.src_ip, alert.dst_ip]
    ).lower()

    high_risk_terms = ("mimikatz", "sekurlsa", "lsass", "credential", "c2", "trojan", "ransom")
    medium_risk_terms = ("powershell", "encodedcommand", "-enc", "rundll32", "regsvr32", "mshta")

    if any(term in searchable for term in high_risk_terms):
        score += 2
    if any(term in searchable for term in medium_risk_terms):
        score += 1
    if alert.dst_ip and not _is_private_ip(alert.dst_ip):
        score += 1

    score += _enrichment_score_boost(enrichments or [])
    return _clamp_score(score)


def score_candidate_locally(
    candidate: IncidentCandidate,
    enrichments: list[EnrichmentResult] | None = None,
) -> int:
    """Score an incident candidate using deterministic local rules.

    Inputs:
        candidate: IncidentCandidate to score.
        enrichments: Optional enrichment results.

    Outputs:
        Integer score from 1 to 10.
    """

    if not candidate.alerts:
        return 1

    alert_scores = [score_alert_locally(alert, []) for alert in candidate.alerts]
    score = max(alert_scores)

    if len(candidate.alerts) >= 3:
        score += 1
    if len(candidate.src_ips) >= 2 or len(candidate.dst_ips) >= 2:
        score += 1
    if candidate.primary_user:
        score += 1

    score += _enrichment_score_boost(enrichments or [])
    return _clamp_score(score)


def triage_result_from_llm_json(payload: JsonDict, *, target_id: str, target_type: str) -> TriageResult:
    """Convert parsed LLM JSON into a validated TriageResult.

    Inputs:
        payload: Parsed LLM JSON object.
        target_id: Alert or candidate ID.
        target_type: Target type label.

    Outputs:
        TriageResult object.
    """

    score = _parse_score(payload.get("score"))
    fp_likelihood = _parse_fp_likelihood(payload.get("fp_likelihood"))
    action = _parse_action(payload.get("action"), score=score)
    classification = _clean_optional_text(payload.get("classification")) or _classification_from_score(score)
    summary = _clean_optional_text(payload.get("summary")) or "LLM triage completed without summary."

    reasoning = payload.get("reasoning")
    if isinstance(reasoning, list) and reasoning:
        summary = f"{summary} Reasons: {'; '.join(str(item) for item in reasoning[:3])}"

    return TriageResult(
        id=_build_triage_id(target_id, target_type, score, classification),
        target_id=target_id,
        target_type=target_type,
        score=score,
        fp_likelihood=fp_likelihood,
        classification=classification,
        action=action,
        summary=summary,
    )


def build_alert_triage_payload(alert: Alert, enrichments: list[EnrichmentResult] | None = None) -> JsonDict:
    """Build compact JSON payload for alert triage.

    Inputs:
        alert: Alert to serialize.
        enrichments: Optional enrichment results.

    Outputs:
        JSON-serializable dictionary.
    """

    return {
        "target_type": "alert",
        "alert": _safe_model_dict(alert),
        "enrichments": [_safe_model_dict(enrichment) for enrichment in enrichments or []],
    }


def build_candidate_triage_payload(
    candidate: IncidentCandidate,
    enrichments: list[EnrichmentResult] | None = None,
) -> JsonDict:
    """Build compact JSON payload for incident candidate triage.

    Inputs:
        candidate: IncidentCandidate to serialize.
        enrichments: Optional enrichment results.

    Outputs:
        JSON-serializable dictionary.
    """

    return {
        "target_type": "incident_candidate",
        "candidate": _safe_model_dict(candidate),
        "enrichments": [_safe_model_dict(enrichment) for enrichment in enrichments or []],
    }


def build_triage_prompt(payload: JsonDict) -> str:
    """Build the user prompt for LLM triage.

    Inputs:
        payload: Serialized alert or candidate payload.

    Outputs:
        Prompt string.
    """

    return (
        "Analyze this SOC alert/candidate and return only JSON with keys: "
        "score, fp_likelihood, classification, action, summary, reasoning.\n\n"
        f"Payload:\n{json.dumps(_json_safe(payload), indent=2, sort_keys=True)}"
    )


def _safe_model_dict(value: Any) -> JsonDict:
    """Convert a dataclass/model object into a JSON-safe dictionary.

    Inputs:
        value: Dataclass or dictionary-like object.

    Outputs:
        JSON-safe dictionary.
    """

    if is_dataclass(value):
        return _json_safe(asdict(value))
    if isinstance(value, dict):
        return _json_safe(value)
    raise TriageError(f"Cannot serialize value for triage: {type(value).__name__}")


def _json_safe(value: Any) -> Any:
    """Convert common Python objects into JSON-safe values.

    Inputs:
        value: Any Python value.

    Outputs:
        JSON-safe equivalent.
    """

    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [_json_safe(item) for item in value]
    if hasattr(value, "value") and value.__class__.__module__ == "enum":
        return value.value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _parse_score(value: Any) -> int:
    """Parse and validate score from LLM output.

    Inputs:
        value: Candidate score value.

    Outputs:
        Integer score from 1 to 10.
    """

    try:
        score = int(value)
    except (TypeError, ValueError) as exc:
        raise TriageError("LLM score must be an integer from 1 to 10") from exc
    return _clamp_score(score)


def _parse_fp_likelihood(value: Any) -> FalsePositiveLikelihood:
    """Parse false-positive likelihood from text.

    Inputs:
        value: Candidate false-positive likelihood.

    Outputs:
        FalsePositiveLikelihood enum.
    """

    text = _clean_optional_text(value).lower()
    if text == "low":
        return FalsePositiveLikelihood.LOW
    if text == "medium":
        return FalsePositiveLikelihood.MEDIUM
    if text == "high":
        return FalsePositiveLikelihood.HIGH
    return FalsePositiveLikelihood.UNKNOWN


def _parse_action(value: Any, *, score: int) -> TriageAction:
    """Parse triage action from text, with score fallback.

    Inputs:
        value: Candidate action value.
        score: Triage score for fallback action.

    Outputs:
        TriageAction enum.
    """

    text = _clean_optional_text(value).lower()
    if text in {"page_now", "page", "urgent", "notify"}:
        return TriageAction.PAGE_NOW
    if text in {"queue_review", "queue", "review", "analyst_review"}:
        return TriageAction.QUEUE_REVIEW
    if text in {"mark_likely_benign", "likely_benign", "benign", "close"}:
        return TriageAction.MARK_LIKELY_BENIGN
    return _action_from_score(score)


def _action_from_score(score: int) -> TriageAction:
    """Map score to action.

    Inputs:
        score: Score from 1 to 10.

    Outputs:
        TriageAction enum.
    """

    if score >= 8:
        return TriageAction.PAGE_NOW
    if score >= 4:
        return TriageAction.QUEUE_REVIEW
    return TriageAction.MARK_LIKELY_BENIGN


def _fp_likelihood_from_score(score: int) -> FalsePositiveLikelihood:
    """Map local score to false-positive likelihood.

    Inputs:
        score: Score from 1 to 10.

    Outputs:
        FalsePositiveLikelihood enum.
    """

    if score >= 8:
        return FalsePositiveLikelihood.LOW
    if score >= 4:
        return FalsePositiveLikelihood.MEDIUM
    return FalsePositiveLikelihood.HIGH


def _classification_from_score(score: int) -> str:
    """Map score to classification label.

    Inputs:
        score: Score from 1 to 10.

    Outputs:
        Classification string.
    """

    if score >= 8:
        return "likely_true_positive_high_priority"
    if score >= 4:
        return "needs_analyst_review"
    return "likely_false_positive_or_low_priority"


def _base_score_for_severity(severity: AlertSeverity) -> int:
    """Map normalized alert severity to base triage score.

    Inputs:
        severity: AlertSeverity enum.

    Outputs:
        Base score from 1 to 8.
    """

    mapping = {
        AlertSeverity.CRITICAL: 8,
        AlertSeverity.HIGH: 6,
        AlertSeverity.MEDIUM: 4,
        AlertSeverity.LOW: 2,
        AlertSeverity.INFO: 1,
        AlertSeverity.UNKNOWN: 3,
    }
    return mapping.get(severity, 3)


def _enrichment_score_boost(enrichments: list[EnrichmentResult]) -> int:
    """Calculate score boost from enrichment details.

    Inputs:
        enrichments: Enrichment results.

    Outputs:
        Score boost integer.
    """

    boost = 0
    for enrichment in enrichments:
        details = _enrichment_details(enrichment)
        details_text = json.dumps(_json_safe(details), sort_keys=True).lower()
        summary_text = str(getattr(enrichment, "summary", "")).lower()
        indicator_text = str(getattr(enrichment, "indicator", "")).lower()
        searchable = " ".join([details_text, summary_text, indicator_text])

        severity_hint = str(details.get("severity_hint", "")).lower()
        risk_factors = {str(item).lower() for item in details.get("risk_factors", [])}

        if (
            severity_hint == "high"
            or risk_factors & {"encoded_powershell", "credential_dumping_hint"}
            or "encoded_powershell" in searchable
            or "credential_dumping_hint" in searchable
            or "encodedcommand" in searchable
        ):
            boost += 2
        elif severity_hint == "medium" or risk_factors:
            boost += 1
    return min(boost, 3)


def _enrichment_details(enrichment: EnrichmentResult) -> JsonDict:
    """Return enrichment details regardless of exact model field name.

    Inputs:
        enrichment: EnrichmentResult object.

    Outputs:
        Details dictionary, or empty dictionary if unavailable.
    """

    for field_name in ("details", "metadata", "data", "raw"):
        value = getattr(enrichment, field_name, None)
        if isinstance(value, dict):
            return value
    return {}


def _local_alert_summary(alert: Alert, score: int, action: TriageAction) -> str:
    """Build deterministic local alert summary.

    Inputs:
        alert: Alert being triaged.
        score: Local score.
        action: Selected action.

    Outputs:
        Summary string.
    """

    rule_name = alert.rule_name or "Unknown rule"
    host = alert.hostname or "unknown host"
    return f"Local triage scored alert {alert.id} as {score}/10 ({action.value}): {rule_name} on {host}."


def _local_candidate_summary(candidate: IncidentCandidate, score: int, action: TriageAction) -> str:
    """Build deterministic local candidate summary.

    Inputs:
        candidate: Candidate being triaged.
        score: Local score.
        action: Selected action.

    Outputs:
        Summary string.
    """

    host = candidate.primary_host or "unknown host"
    return (
        f"Local triage scored candidate {candidate.id} as {score}/10 ({action.value}) "
        f"with {len(candidate.alerts)} alert(s) on {host}."
    )


def _build_triage_id(target_id: str, target_type: str, score: int, classification: str) -> str:
    """Build stable triage result ID.

    Inputs:
        target_id: Alert or candidate ID.
        target_type: Target type label.
        score: Triage score.
        classification: Classification label.

    Outputs:
        Stable triage ID string.
    """

    raw = f"{target_type}:{target_id}:{score}:{classification}"
    fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"triage-{fingerprint}"


def _is_private_ip(value: str) -> bool:
    """Return True if an IP address is private/internal.

    Inputs:
        value: IP address string.

    Outputs:
        Boolean flag. Invalid values return False.
    """

    import ipaddress

    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _clamp_score(score: int) -> int:
    """Clamp score to 1-10.

    Inputs:
        score: Candidate score.

    Outputs:
        Clamped score.
    """

    return max(1, min(10, score))


def _clean_optional_text(value: Any) -> str:
    """Convert optional value to stripped text.

    Inputs:
        value: Any value.

    Outputs:
        Stripped string or empty string.
    """

    if value is None:
        return ""
    return str(value).strip()