

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
      "reasoning": ["short reason 1", "short reason 2"],
      "iocs": {"ips": ["203.0.113.10"], "domains": ["evil.example"]},
      "recommended_actions": ["Isolate web-01"],
      "evidence": [{"field": "command_line", "value": "...", "source": "wazuh"}]
    }

Only allowlisted, truncated fields are sent to the model: see
ALERT_CONTEXT_FIELDS and RAW_CONTEXT_FIELDS. Raw source payloads, related raw
events, and enrichment provider responses are deliberately withheld.

Every TriageResult records whether a model or the local rules produced it. A
failed or malformed LLM call falls back to local scoring and is labelled
`AnalysisSource.LOCAL`, so a heuristic score can never be mistaken for model
output.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, is_dataclass
from typing import Any, Protocol

from soc.models import (
    Alert,
    AlertSeverity,
    AnalysisSource,
    EnrichmentResult,
    EventSource,
    EvidenceItem,
    FalsePositiveLikelihood,
    IncidentCandidate,
    TriageAction,
    TriageResult,
)
from soc.openrouter_client import OpenRouterError, parse_json_response_text


logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]


class TriageError(ValueError):
    """Raised when triage input or output is invalid."""


MAX_CONTEXT_FIELD_CHARS = 512
MAX_CONTEXT_ALERTS = 20
TRUNCATION_MARKER = "...[truncated]"

ALERT_CONTEXT_FIELDS: tuple[str, ...] = (
    "id",
    "source",
    "timestamp",
    "severity",
    "source_severity",
    "rule_name",
    "rule_groups",
    "src_ip",
    "dst_ip",
    "hostname",
    "agent_id",
    "agent_os",
    "user",
    "process_name",
    "command_line",
)

RAW_CONTEXT_FIELDS: tuple[str, ...] = ("full_log",)

CANDIDATE_CONTEXT_FIELDS: tuple[str, ...] = (
    "id",
    "first_seen",
    "last_seen",
    "primary_host",
    "primary_user",
    "src_ips",
    "dst_ips",
)

ENRICHMENT_CONTEXT_FIELDS: tuple[str, ...] = (
    "indicator",
    "indicator_type",
    "provider",
    "summary",
    "looked_up_at",
)


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
        max_json_retries: Extra attempts when a response cannot be parsed into a
            TriageResult. Transport failures are not retried here; the client
            already retries those with backoff.
    """

    def __init__(
        self,
        llm_client: TextCompletionClient | None = None,
        *,
        model: str | None = None,
        max_tokens: int = 800,
        temperature: float = 0.1,
        allow_fallback: bool = True,
        max_json_retries: int = 1,
    ) -> None:
        """Initialize the triage engine.

        Inputs:
            llm_client: Optional OpenRouter-like client.
            model: Optional model override.
            max_tokens: Maximum LLM output tokens.
            temperature: LLM sampling temperature.
            allow_fallback: Whether local fallback is allowed on LLM failure.
            max_json_retries: Extra attempts on an unparseable response.

        Outputs:
            None.
        """

        if max_tokens <= 0:
            raise TriageError("max_tokens must be greater than zero")
        if temperature < 0:
            raise TriageError("temperature cannot be negative")
        if max_json_retries < 0:
            raise TriageError("max_json_retries cannot be negative")

        self.llm_client = llm_client
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.allow_fallback = allow_fallback
        self.max_json_retries = max_json_retries

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
        attempts = self.max_json_retries + 1

        for attempt in range(1, attempts + 1):
            started_at = time.perf_counter()
            try:
                response_text, model_name, token_usage = self._invoke_llm(prompt)
            except OpenRouterError as exc:
                # Transport failures are already retried inside the client with
                # backoff. Retrying here as well would multiply the wait on a
                # rate-limited model for no extra chance of success.
                return self._fallback_or_raise(fallback_result, exc)

            latency_ms = int((time.perf_counter() - started_at) * 1000)
            try:
                parsed = parse_json_response_text(response_text)
                return triage_result_from_llm_json(
                    parsed,
                    target_id=target_id,
                    target_type=target_type,
                    model=model_name,
                    latency_ms=latency_ms,
                    token_usage=token_usage,
                    prompt_version=TRIAGE_PROMPT_VERSION,
                )
            except (OpenRouterError, TriageError, KeyError, TypeError, ValueError) as exc:
                # An unparseable response is worth one more try: free models
                # often wrap or truncate JSON, and dropping straight to local
                # scoring discards the model's judgment entirely.
                if attempt < attempts:
                    logger.warning(
                        "LLM triage response was unusable for %s (attempt %d of %d): %s",
                        target_id,
                        attempt,
                        attempts,
                        exc,
                    )
                    continue
                return self._fallback_or_raise(fallback_result, exc)

        return fallback_result

    def _fallback_or_raise(self, fallback_result: TriageResult, exc: Exception) -> TriageResult:
        """Return the local fallback, or raise when fallback is disabled.

        Inputs:
            fallback_result: Deterministic local result.
            exc: Error that ended the LLM attempt.

        Outputs:
            The fallback TriageResult, labelled as locally scored.

        Raises:
            TriageError: If fallback is not allowed.
        """

        if not self.allow_fallback:
            raise TriageError(f"LLM triage failed: {exc}") from exc
        logger.warning("Falling back to local triage: %s", exc)
        return fallback_result

    def _invoke_llm(self, prompt: str) -> tuple[str, str | None, JsonDict]:
        """Call the configured LLM client and collect provenance metadata.

        Clients exposing `chat_completion` also report the model actually used
        and token usage, which the caller records on the TriageResult. Clients
        exposing only `complete_text` still work, with less provenance.

        Inputs:
            prompt: User prompt for the triage call.

        Outputs:
            Tuple of response text, model name if reported, and token usage.

        Raises:
            TriageError: If no LLM client is configured.
        """

        client = self.llm_client
        if client is None:
            raise TriageError("no LLM client configured")

        if hasattr(client, "chat_completion"):
            messages = [
                {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ]
            result = client.chat_completion(
                messages,
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return result.content, result.model, dict(result.usage or {})

        response_text = client.complete_text(
            prompt,
            system_prompt=TRIAGE_SYSTEM_PROMPT,
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        return response_text, self.model, {}


TRIAGE_PROMPT_VERSION = "triage-v1"

TRIAGE_SYSTEM_PROMPT = """You are a careful SOC triage assistant.
Return only valid JSON. Do not include markdown.
Score from 1 to 10, where 10 is urgent confirmed compromise.
Choose action from: page_now, queue_review, mark_likely_benign.
Choose fp_likelihood from: low, medium, high, unknown.
Be conservative: page only for credible high-impact or active compromise.

Evidence rules:
- Cite the specific payload fields that support every important claim, using the
  evidence array. Each entry must name a field present in the payload and the
  value you relied on. Do not cite fields that were not provided.
- If the provided evidence is insufficient to judge the activity, say so in the
  summary, score conservatively, and prefer queue_review over page_now. Never
  invent hostnames, users, processes, addresses, or log content that is absent
  from the payload.
- List only indicators that appear in the payload. Do not speculate.
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


def triage_result_from_llm_json(
    payload: JsonDict,
    *,
    target_id: str,
    target_type: str,
    model: str | None = None,
    latency_ms: int | None = None,
    token_usage: JsonDict | None = None,
    prompt_version: str | None = None,
) -> TriageResult:
    """Convert parsed LLM JSON into a validated TriageResult.

    Inputs:
        payload: Parsed LLM JSON object.
        target_id: Alert or candidate ID.
        target_type: Target type label.
        model: Model name reported by the client, when available.
        latency_ms: Measured call latency in milliseconds.
        token_usage: Token usage reported by the provider, when available.
        prompt_version: Version of the triage prompt used for this call.

    Outputs:
        TriageResult object marked as LLM-sourced.
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
        iocs=_parse_iocs(payload.get("iocs")),
        recommended_actions=_parse_recommended_actions(payload.get("recommended_actions")),
        evidence=_parse_evidence(
            payload.get("evidence"),
            target_id=target_id,
            target_type=target_type,
        ),
        model=model,
        latency_ms=latency_ms,
        token_usage=dict(token_usage or {}),
        analysis_source=AnalysisSource.LLM,
        prompt_version=prompt_version,
    )


def _parse_iocs(value: Any) -> JsonDict:
    """Parse indicators of compromise from LLM output.

    Models return either an object grouping indicators by type or a bare list.
    Both are accepted; anything else yields no indicators rather than an error.

    Inputs:
        value: Candidate IOC structure.

    Outputs:
        Dictionary mapping indicator type to a list of indicator strings.
    """

    if isinstance(value, dict):
        parsed: JsonDict = {}
        for key, items in value.items():
            values = _string_list(items)
            if values:
                parsed[str(key)] = values
        return parsed
    values = _string_list(value)
    return {"unclassified": values} if values else {}


def _parse_recommended_actions(value: Any) -> list[str]:
    """Parse analyst next steps from LLM output.

    Inputs:
        value: Candidate recommended-actions structure.

    Outputs:
        List of non-empty action strings.
    """

    return _string_list(value)


def _parse_evidence(value: Any, *, target_id: str, target_type: str) -> list[EvidenceItem]:
    """Parse cited evidence from LLM output.

    Entries that do not name a field are dropped: an uncitable claim is worse
    than no citation, and a malformed entry must not abort an otherwise usable
    triage result.

    Inputs:
        value: Candidate evidence structure.
        target_id: Alert or candidate ID being triaged.
        target_type: Target type label.

    Outputs:
        List of EvidenceItem objects.
    """

    if not isinstance(value, list):
        return []

    items: list[EvidenceItem] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        field_name = _clean_optional_text(entry.get("field"))
        if not field_name:
            continue
        items.append(
            EvidenceItem(
                source=_parse_event_source(entry.get("source")),
                field=field_name,
                value=entry.get("value"),
                alert_id=target_id if target_type == "alert" else None,
            )
        )
    return items


def _parse_event_source(value: Any) -> EventSource:
    """Parse an event source label, defaulting to unknown.

    Inputs:
        value: Candidate source label.

    Outputs:
        EventSource enum.
    """

    text = _clean_optional_text(value).lower()
    for source in EventSource:
        if source.value == text:
            return source
    return EventSource.UNKNOWN


def _string_list(value: Any) -> list[str]:
    """Coerce a value into a list of non-empty strings.

    Inputs:
        value: Any value.

    Outputs:
        List of cleaned strings.
    """

    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list | tuple | set):
        candidates = list(value)
    else:
        return []

    results = []
    for item in candidates:
        text = _clean_optional_text(item)
        if text:
            results.append(text)
    return results


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
        "alert": build_alert_context(alert),
        "enrichments": [build_enrichment_context(item) for item in enrichments or []],
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
        "candidate": build_candidate_context(candidate),
        "enrichments": [build_enrichment_context(item) for item in enrichments or []],
    }


def build_alert_context(alert: Alert) -> JsonDict:
    """Build the allowlisted, truncated LLM context for one alert.

    Alert payloads carry the complete original source event, which can include
    credentials, command lines, internal hostnames, and arbitrary log text. Only
    explicitly named fields leave this process, and every string is truncated.

    Inputs:
        alert: Alert to describe.

    Outputs:
        JSON-safe dictionary containing allowlisted fields only.
    """

    context: JsonDict = {}
    for name in ALERT_CONTEXT_FIELDS:
        context[name] = _truncate_value(_json_safe(getattr(alert, name, None)))

    raw = alert.raw if isinstance(alert.raw, dict) else {}
    excerpt = {
        name: _truncate_value(_json_safe(raw[name]))
        for name in RAW_CONTEXT_FIELDS
        if raw.get(name) not in (None, "")
    }
    if excerpt:
        context["raw_excerpt"] = excerpt
    return context


def build_candidate_context(candidate: IncidentCandidate) -> JsonDict:
    """Build the allowlisted, truncated LLM context for one incident candidate.

    Related raw events are excluded entirely: they hold unfiltered source
    payloads and duplicate the evidence already summarized by the alerts.

    Inputs:
        candidate: IncidentCandidate to describe.

    Outputs:
        JSON-safe dictionary containing allowlisted fields only.
    """

    context: JsonDict = {}
    for name in CANDIDATE_CONTEXT_FIELDS:
        context[name] = _truncate_value(_json_safe(getattr(candidate, name, None)))

    alerts = list(candidate.alerts or [])
    context["alert_count"] = len(alerts)
    context["alerts_truncated"] = len(alerts) > MAX_CONTEXT_ALERTS
    context["alerts"] = [build_alert_context(alert) for alert in alerts[:MAX_CONTEXT_ALERTS]]
    return context


def build_enrichment_context(enrichment: EnrichmentResult) -> JsonDict:
    """Build the allowlisted LLM context for one enrichment result.

    Provider raw responses are excluded; only the derived summary is shared.

    Inputs:
        enrichment: EnrichmentResult to describe.

    Outputs:
        JSON-safe dictionary containing allowlisted fields only.
    """

    return {
        name: _truncate_value(_json_safe(getattr(enrichment, name, None)))
        for name in ENRICHMENT_CONTEXT_FIELDS
    }


def _truncate_value(value: Any) -> Any:
    """Truncate long strings so one field cannot dominate the prompt.

    Inputs:
        value: Any JSON-safe value.

    Outputs:
        The value with long strings truncated and marked.
    """

    if isinstance(value, str) and len(value) > MAX_CONTEXT_FIELD_CHARS:
        return value[:MAX_CONTEXT_FIELD_CHARS] + TRUNCATION_MARKER
    if isinstance(value, list):
        return [_truncate_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _truncate_value(item) for key, item in value.items()}
    return value


def build_triage_prompt(payload: JsonDict) -> str:
    """Build the user prompt for LLM triage.

    Inputs:
        payload: Serialized alert or candidate payload.

    Outputs:
        Prompt string.
    """

    return (
        "Analyze this SOC alert/candidate and return only JSON with keys: "
        "score, fp_likelihood, classification, action, summary, reasoning, "
        "iocs, recommended_actions, evidence.\n"
        "iocs must be an object grouping indicator values by type, for example "
        '{"ips": [], "domains": [], "hashes": []}.\n'
        "recommended_actions must be an array of short analyst next steps.\n"
        "evidence must be an array of objects with keys field, value, and "
        "optionally source, citing payload fields that justify the score.\n\n"
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