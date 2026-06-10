

"""Tests for AI-assisted and local SOC triage.

These tests verify deterministic local triage, LLM JSON parsing, prompt payload
creation, and fallback behavior without making real OpenRouter calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest

from soc.enrichment import enrich_indicator
from soc.models import (
    Alert,
    AlertSeverity,
    EnrichmentResult,
    EventSource,
    FalsePositiveLikelihood,
    IncidentCandidate,
    TriageAction,
    TriageResult,
)
from soc.openrouter_client import OpenRouterError
from soc.triage import (
    TriageEngine,
    TriageError,
    build_alert_triage_payload,
    build_candidate_triage_payload,
    build_triage_prompt,
    local_triage_alert,
    local_triage_candidate,
    score_alert_locally,
    score_candidate_locally,
    triage_alert,
    triage_candidate,
    triage_result_from_llm_json,
)


BASE_TIME = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


@dataclass(slots=True)
class FakeLLMClient:
    """Fake LLM client that records prompts and returns configured text."""

    response_text: str
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
        """Record a fake LLM call and return configured response text."""

        self.calls.append(
            {
                "prompt": prompt,
                "system_prompt": system_prompt,
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
        )
        if self.raise_error is not None:
            raise self.raise_error
        return self.response_text


def _alert(
    *,
    alert_id: str = "alert-001",
    severity: AlertSeverity = AlertSeverity.HIGH,
    rule_name: str = "Suspicious PowerShell execution",
    command_line: str | None = "powershell.exe -EncodedCommand abc123",
    process_name: str | None = "powershell.exe",
    dst_ip: str | None = "8.8.8.8",
) -> Alert:
    """Create a representative Alert for triage tests."""

    return Alert(
        id=alert_id,
        source=EventSource.WAZUH,
        timestamp=BASE_TIME,
        severity=severity,
        source_severity=10,
        rule_name=rule_name,
        rule_groups=["windows", "powershell"],
        src_ip="10.0.1.10",
        dst_ip=dst_ip,
        hostname="endpoint-01",
        agent_id="001",
        agent_os="Windows",
        user="alice",
        process_name=process_name,
        command_line=command_line,
        raw={"rule": {"level": 10, "description": rule_name}},
    )


def _candidate(alerts: list[Alert] | None = None) -> IncidentCandidate:
    """Create a representative IncidentCandidate for triage tests."""

    if alerts is None:
        alerts = [_alert()]
    return IncidentCandidate(
        id="candidate-001",
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        alerts=alerts,
        primary_host="endpoint-01",
        primary_user="alice",
        src_ips=["10.0.1.10"],
        dst_ips=["8.8.8.8", "1.1.1.1"],
        related_events=[],
        enrichments=[],
        created_at=BASE_TIME,
    )


def _high_risk_enrichment() -> EnrichmentResult:
    """Create high-risk enrichment for score boost tests."""

    return enrich_indicator("command", "powershell.exe -EncodedCommand abc123", target_id="alert-001")


def test_local_triage_alert_scores_high_powershell_alert():
    """Local triage should score suspicious PowerShell alerts high enough for review/page."""

    result = local_triage_alert(_alert())

    assert isinstance(result, TriageResult)
    assert result.target_id == "alert-001"
    assert result.target_type == "alert"
    assert result.score >= 8
    assert result.fp_likelihood == FalsePositiveLikelihood.LOW
    assert result.action == TriageAction.PAGE_NOW
    assert result.classification == "likely_true_positive_high_priority"
    assert "Suspicious PowerShell execution" in result.summary
    assert result.id.startswith("triage-")


def test_local_triage_alert_scores_low_info_alert_as_likely_benign():
    """Low-information alerts should stay low priority under local triage."""

    alert = _alert(
        severity=AlertSeverity.INFO,
        rule_name="Informational login event",
        command_line=None,
        process_name=None,
        dst_ip="10.0.1.20",
    )

    result = local_triage_alert(alert)

    assert result.score <= 3
    assert result.fp_likelihood == FalsePositiveLikelihood.HIGH
    assert result.action == TriageAction.MARK_LIKELY_BENIGN
    assert result.classification == "likely_false_positive_or_low_priority"


def test_score_alert_locally_uses_enrichment_boost():
    """High-risk enrichment should increase local alert score."""

    alert = _alert(
        severity=AlertSeverity.MEDIUM,
        rule_name="Generic script alert",
        command_line=None,
        process_name=None,
        dst_ip="10.0.1.20",
    )

    without_enrichment = score_alert_locally(alert, [])
    with_enrichment = score_alert_locally(alert, [_high_risk_enrichment()])

    assert with_enrichment > without_enrichment
    assert with_enrichment <= 10


def test_local_triage_candidate_scores_multiple_related_alerts():
    """Candidate triage should consider alert count, entities, and max alert severity."""

    alerts = [
        _alert(alert_id="alert-001"),
        _alert(alert_id="alert-002", rule_name="Possible C2 traffic", command_line=None),
        _alert(alert_id="alert-003", severity=AlertSeverity.MEDIUM, rule_name="Network anomaly"),
    ]
    candidate = _candidate(alerts)

    result = local_triage_candidate(candidate)

    assert result.target_id == "candidate-001"
    assert result.target_type == "incident_candidate"
    assert result.score >= 8
    assert result.action == TriageAction.PAGE_NOW
    assert "3 alert(s)" in result.summary


def test_score_candidate_locally_returns_one_for_empty_candidate():
    """Candidates with no alerts should receive the minimum local score."""

    candidate = _candidate([])

    assert score_candidate_locally(candidate, []) == 1


def test_triage_result_from_llm_json_parses_valid_payload():
    """LLM JSON should be converted into a validated TriageResult."""

    result = triage_result_from_llm_json(
        {
            "score": 7,
            "fp_likelihood": "medium",
            "classification": "needs_review_custom",
            "action": "queue_review",
            "summary": "Suspicious but not confirmed.",
            "reasoning": ["PowerShell observed", "Needs analyst confirmation"],
        },
        target_id="alert-001",
        target_type="alert",
    )

    assert result.score == 7
    assert result.fp_likelihood == FalsePositiveLikelihood.MEDIUM
    assert result.classification == "needs_review_custom"
    assert result.action == TriageAction.QUEUE_REVIEW
    assert "Suspicious but not confirmed" in result.summary
    assert "PowerShell observed" in result.summary


def test_triage_result_from_llm_json_clamps_score_and_falls_back_action():
    """LLM score should be clamped and missing action should fall back from score."""

    result = triage_result_from_llm_json(
        {
            "score": 99,
            "fp_likelihood": "low",
            "summary": "Very suspicious.",
        },
        target_id="alert-001",
        target_type="alert",
    )

    assert result.score == 10
    assert result.action == TriageAction.PAGE_NOW
    assert result.classification == "likely_true_positive_high_priority"


def test_triage_result_from_llm_json_rejects_missing_score():
    """Missing score should raise TriageError."""

    with pytest.raises(TriageError, match="score"):
        triage_result_from_llm_json({"summary": "missing score"}, target_id="alert-001", target_type="alert")


def test_build_alert_triage_payload_is_json_serializable():
    """Alert triage payload should contain JSON-safe alert and enrichment data."""

    payload = build_alert_triage_payload(_alert(), [_high_risk_enrichment()])

    assert payload["target_type"] == "alert"
    assert payload["alert"]["id"] == "alert-001"
    assert payload["alert"]["severity"] == "high"
    assert payload["alert"]["timestamp"] == BASE_TIME.isoformat()
    assert payload["enrichments"]


def test_build_candidate_triage_payload_is_json_serializable():
    """Candidate triage payload should contain JSON-safe candidate data."""

    payload = build_candidate_triage_payload(_candidate(), [_high_risk_enrichment()])

    assert payload["target_type"] == "incident_candidate"
    assert payload["candidate"]["id"] == "candidate-001"
    assert payload["candidate"]["alerts"][0]["id"] == "alert-001"
    assert payload["enrichments"]


def test_build_triage_prompt_contains_payload_and_required_keys():
    """Triage prompt should instruct the LLM to return strict JSON keys."""

    prompt = build_triage_prompt({"target_type": "alert", "alert": {"id": "alert-001"}})

    assert "return only JSON" in prompt
    assert "score" in prompt
    assert "fp_likelihood" in prompt
    assert "classification" in prompt
    assert "action" in prompt
    assert "alert-001" in prompt


def test_triage_engine_uses_llm_client_when_available():
    """TriageEngine should call the LLM client and parse JSON response."""

    llm = FakeLLMClient(
        response_text=(
            '{"score": 8, "fp_likelihood": "low", "classification": "likely_true_positive", '
            '"action": "page_now", "summary": "Credible C2 behavior", "reasoning": ["C2 keyword"]}'
        )
    )
    engine = TriageEngine(llm, model="test-model", max_tokens=300, temperature=0)

    result = engine.triage_alert(_alert())

    assert result.score == 8
    assert result.action == TriageAction.PAGE_NOW
    assert result.fp_likelihood == FalsePositiveLikelihood.LOW
    assert result.classification == "likely_true_positive"
    assert "Credible C2 behavior" in result.summary
    assert len(llm.calls) == 1
    assert llm.calls[0]["model"] == "test-model"
    assert llm.calls[0]["temperature"] == 0
    assert llm.calls[0]["max_tokens"] == 300
    assert "Payload" in llm.calls[0]["prompt"]


def test_triage_engine_accepts_fenced_json_response():
    """TriageEngine should parse fenced JSON returned by an LLM."""

    llm = FakeLLMClient(
        response_text='```json\n{"score": 5, "fp_likelihood": "medium", "action": "queue_review", "summary": "Review"}\n```'
    )

    result = TriageEngine(llm).triage_alert(_alert())

    assert result.score == 5
    assert result.action == TriageAction.QUEUE_REVIEW
    assert result.fp_likelihood == FalsePositiveLikelihood.MEDIUM


def test_triage_engine_falls_back_when_llm_returns_bad_json():
    """Malformed LLM output should fall back to local triage when allowed."""

    llm = FakeLLMClient(response_text="not json")
    engine = TriageEngine(llm, allow_fallback=True)

    result = engine.triage_alert(_alert())

    assert result.target_id == "alert-001"
    assert result.summary.startswith("Local triage scored alert")


def test_triage_engine_falls_back_when_llm_raises_error():
    """LLM client errors should fall back to local triage when allowed."""

    llm = FakeLLMClient(response_text="", raise_error=OpenRouterError("network failed"))
    engine = TriageEngine(llm, allow_fallback=True)

    result = engine.triage_alert(_alert())

    assert result.target_id == "alert-001"
    assert result.summary.startswith("Local triage scored alert")


def test_triage_engine_raises_when_fallback_disabled():
    """Malformed LLM output should raise TriageError when fallback is disabled."""

    llm = FakeLLMClient(response_text="not json")
    engine = TriageEngine(llm, allow_fallback=False)

    with pytest.raises(TriageError, match="LLM triage failed"):
        engine.triage_alert(_alert())


def test_triage_engine_triages_candidates_with_enrichment_lookup():
    """triage_candidates should preserve order and use enrichment lookup."""

    candidates = [_candidate(), _candidate([_alert(alert_id="alert-002", severity=AlertSeverity.LOW)])]
    candidates[1].id = "candidate-002"
    engine = TriageEngine()

    results = engine.triage_candidates(
        candidates,
        enrichments_by_candidate_id={"candidate-001": [_high_risk_enrichment()]},
    )

    assert [result.target_id for result in results] == ["candidate-001", "candidate-002"]
    assert all(result.target_type == "incident_candidate" for result in results)


def test_convenience_triage_alert_and_candidate_functions():
    """Convenience triage functions should return TriageResult objects."""

    alert_result = triage_alert(_alert())
    candidate_result = triage_candidate(_candidate())

    assert isinstance(alert_result, TriageResult)
    assert isinstance(candidate_result, TriageResult)
    assert alert_result.target_type == "alert"
    assert candidate_result.target_type == "incident_candidate"


def test_triage_engine_rejects_invalid_config():
    """TriageEngine should reject invalid generation settings."""

    with pytest.raises(TriageError, match="max_tokens"):
        TriageEngine(max_tokens=0)

    with pytest.raises(TriageError, match="temperature"):
        TriageEngine(temperature=-1)