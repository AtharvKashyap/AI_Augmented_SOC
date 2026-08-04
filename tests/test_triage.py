

"""Tests for AI-assisted and local SOC triage.

These tests verify deterministic local triage, LLM JSON parsing, prompt payload
creation, and fallback behavior without making real OpenRouter calls.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from soc.enrichment import LocalEnricher, enrich_indicator
from soc.models import (
    Alert,
    AlertSeverity,
    AnalysisSource,
    EnrichmentResult,
    EventSource,
    FalsePositiveLikelihood,
    IncidentCandidate,
    RawEvent,
    TriageAction,
    TriageResult,
)
from soc.openrouter_client import ChatCompletionResult, OpenRouterError
from soc.triage import (
    MAX_CONTEXT_ALERTS,
    MAX_CONTEXT_FIELD_CHARS,
    TRIAGE_PROMPT_VERSION,
    TRIAGE_SYSTEM_PROMPT,
    TRUNCATION_MARKER,
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

BASE_TIME = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


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

@dataclass(slots=True)
class FakeChatClient:
    """Fake client exposing chat_completion so provenance metadata is available."""

    response_text: str
    model_name: str = "vendor/model-x"
    usage: dict[str, object] = field(default_factory=lambda: {"total_tokens": 123})
    calls: list[dict[str, object]] = field(default_factory=list)

    def chat_completion(
        self,
        messages: list[dict[str, object]],
        *,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 800,
    ) -> ChatCompletionResult:
        """Record a fake chat call and return a parsed completion result."""

        self.calls.append(
            {
                "messages": messages,
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
        )
        return ChatCompletionResult(
            content=self.response_text,
            model=self.model_name,
            usage=dict(self.usage),
            raw={},
        )


def test_local_triage_records_local_analysis_source():
    """Deterministic triage must identify itself as local, not model output."""

    assert local_triage_alert(_alert()).analysis_source == AnalysisSource.LOCAL
    assert local_triage_candidate(_candidate()).analysis_source == AnalysisSource.LOCAL


def test_llm_triage_records_llm_analysis_source_and_prompt_version():
    """LLM-scored results must be distinguishable from local fallback results."""

    llm = FakeLLMClient(
        response_text='{"score": 7, "fp_likelihood": "medium", "action": "queue_review", "summary": "Review"}'
    )

    result = TriageEngine(llm).triage_alert(_alert())

    assert result.analysis_source == AnalysisSource.LLM
    assert result.prompt_version == TRIAGE_PROMPT_VERSION
    assert result.latency_ms is not None
    assert result.latency_ms >= 0


def test_llm_fallback_records_local_analysis_source():
    """A failed LLM call must not let the local fallback masquerade as model output."""

    llm = FakeLLMClient(response_text="", raise_error=OpenRouterError("rate limited"))

    result = TriageEngine(llm).triage_alert(_alert())

    assert result.analysis_source == AnalysisSource.LOCAL
    assert result.model is None
    assert result.prompt_version is None


def test_llm_triage_records_model_and_token_usage_from_chat_client():
    """When the client reports model and usage, both must land on the result."""

    client = FakeChatClient(
        response_text='{"score": 9, "fp_likelihood": "low", "action": "page_now", "summary": "Active compromise"}'
    )

    result = TriageEngine(client).triage_candidate(_candidate())

    assert result.analysis_source == AnalysisSource.LLM
    assert result.model == "vendor/model-x"
    assert result.token_usage == {"total_tokens": 123}
    assert len(client.calls) == 1


def _alert_with_raw(raw: dict[str, object], **overrides: object) -> Alert:
    """Create an Alert carrying a raw source payload, for context-filter tests."""

    fields: dict[str, object] = {
        "id": "alert-raw-001",
        "source": EventSource.WAZUH,
        "timestamp": BASE_TIME,
        "severity": AlertSeverity.HIGH,
        "rule_name": "Suspicious process",
        "hostname": "web-01",
        "raw": raw,
    }
    fields.update(overrides)
    return Alert(**fields)


def test_alert_triage_payload_excludes_unallowlisted_raw_fields():
    """The raw source event must not be dumped wholesale into the LLM prompt."""

    alert = _alert_with_raw(
        {
            "full_log": "kernel: something happened",
            "data": {"win": {"eventdata": {"targetUserName": "svc_backup"}}},
            "predecoder": {"hostname": "internal-dc-01.corp.local"},
        }
    )

    payload = build_alert_triage_payload(alert)
    serialized = json.dumps(payload)

    assert "svc_backup" not in serialized
    assert "internal-dc-01.corp.local" not in serialized
    assert "raw" not in payload["alert"]


def test_alert_triage_payload_includes_allowlisted_raw_excerpt():
    """Explicitly allowlisted raw fields are still useful context and are kept."""

    alert = _alert_with_raw({"full_log": "sshd: Failed password for root"})

    payload = build_alert_triage_payload(alert)

    assert payload["alert"]["raw_excerpt"]["full_log"] == "sshd: Failed password for root"


def test_alert_triage_payload_truncates_long_values():
    """Long fields must be truncated so one alert cannot blow the context window."""

    alert = _alert_with_raw({"full_log": "A" * 5000}, command_line="B" * 5000)

    payload = build_alert_triage_payload(alert)

    assert len(payload["alert"]["command_line"]) <= MAX_CONTEXT_FIELD_CHARS + len(TRUNCATION_MARKER)
    assert payload["alert"]["command_line"].endswith(TRUNCATION_MARKER)
    assert len(payload["alert"]["raw_excerpt"]["full_log"]) <= MAX_CONTEXT_FIELD_CHARS + len(TRUNCATION_MARKER)


def test_candidate_triage_payload_caps_alert_count_and_reports_the_cap():
    """A large cluster must be capped, and the caller must be told it was."""

    alerts = [_alert_with_raw({}, id=f"alert-{index:03d}") for index in range(MAX_CONTEXT_ALERTS + 5)]
    candidate = IncidentCandidate(
        id="candidate-large",
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        alerts=alerts,
    )

    payload = build_candidate_triage_payload(candidate)

    assert len(payload["candidate"]["alerts"]) == MAX_CONTEXT_ALERTS
    assert payload["candidate"]["alert_count"] == MAX_CONTEXT_ALERTS + 5
    assert payload["candidate"]["alerts_truncated"] is True


def test_candidate_triage_payload_excludes_related_raw_events():
    """Related raw events carry whole source payloads and must stay out of context."""

    candidate = _candidate()
    candidate.related_events = [
        RawEvent(
            id="raw-001",
            source=EventSource.WAZUH,
            received_at=BASE_TIME,
            timestamp=BASE_TIME,
            payload={"secret_token": "leak-me-please"},
        )
    ]

    serialized = json.dumps(build_candidate_triage_payload(candidate))

    assert "leak-me-please" not in serialized
    assert "related_events" not in serialized


def test_enrichment_payload_excludes_provider_raw_response():
    """Third-party provider responses must not be forwarded to the LLM verbatim."""

    enrichment = EnrichmentResult(
        indicator="8.8.8.8",
        indicator_type="ip",
        provider="local",
        summary="Public IP",
        raw={"internal_note": "do-not-forward"},
    )

    serialized = json.dumps(build_alert_triage_payload(_alert(), [enrichment]))

    assert "do-not-forward" not in serialized
    assert "Public IP" in serialized


def test_triage_result_from_llm_json_parses_iocs_and_recommended_actions():
    """IOCs and recommended actions returned by the model must reach the result."""

    payload = {
        "score": 8,
        "fp_likelihood": "low",
        "action": "page_now",
        "summary": "Credential theft attempt",
        "iocs": {"ips": ["203.0.113.10"], "domains": ["evil.example"]},
        "recommended_actions": ["Isolate web-01", "Reset svc_backup credentials"],
    }

    result = triage_result_from_llm_json(payload, target_id="alert-001", target_type="alert")

    assert result.iocs == {"ips": ["203.0.113.10"], "domains": ["evil.example"]}
    assert result.recommended_actions == ["Isolate web-01", "Reset svc_backup credentials"]


def test_triage_result_from_llm_json_normalizes_flat_ioc_list():
    """A model returning a bare IOC list must still produce usable grouped IOCs."""

    payload = {
        "score": 5,
        "fp_likelihood": "medium",
        "action": "queue_review",
        "summary": "Review",
        "iocs": ["203.0.113.10", "evil.example"],
    }

    result = triage_result_from_llm_json(payload, target_id="alert-001", target_type="alert")

    assert result.iocs == {"unclassified": ["203.0.113.10", "evil.example"]}


def test_triage_result_from_llm_json_parses_evidence_items():
    """Cited evidence must be parsed into EvidenceItem objects for the report."""

    payload = {
        "score": 9,
        "fp_likelihood": "low",
        "action": "page_now",
        "summary": "Active compromise",
        "evidence": [
            {"field": "command_line", "value": "powershell -enc ...", "source": "wazuh"},
            {"field": "dst_ip", "value": "203.0.113.10"},
        ],
    }

    result = triage_result_from_llm_json(payload, target_id="alert-001", target_type="alert")

    assert [item.field for item in result.evidence] == ["command_line", "dst_ip"]
    assert result.evidence[0].source == EventSource.WAZUH
    assert result.evidence[1].source == EventSource.UNKNOWN
    assert result.evidence[0].alert_id == "alert-001"


def test_triage_result_from_llm_json_ignores_malformed_evidence_entries():
    """Malformed evidence entries must be dropped rather than aborting triage."""

    payload = {
        "score": 4,
        "fp_likelihood": "medium",
        "action": "queue_review",
        "summary": "Review",
        "evidence": ["not-an-object", {"value": "missing field"}, {"field": "user", "value": "root"}],
    }

    result = triage_result_from_llm_json(payload, target_id="alert-001", target_type="alert")

    assert [item.field for item in result.evidence] == ["user"]


def test_triage_prompt_requests_iocs_and_evidence():
    """The prompt must ask for the fields the report and audit trail depend on."""

    prompt = build_triage_prompt(build_alert_triage_payload(_alert()))

    assert "iocs" in prompt
    assert "evidence" in prompt
    assert "recommended_actions" in prompt


def test_triage_system_prompt_requires_citation_and_admits_insufficiency():
    """The model must be told to cite evidence and to admit missing evidence."""

    assert "cite" in TRIAGE_SYSTEM_PROMPT.lower()
    assert "insufficient" in TRIAGE_SYSTEM_PROMPT.lower()


@dataclass(slots=True)
class FakeSequenceLLMClient:
    """Fake LLM client returning a scripted sequence of responses."""

    responses: list[str]
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


_VALID_LLM_JSON = (
    '{"score": 8, "fp_likelihood": "low", "action": "page_now", "summary": "Confirmed compromise"}'
)


def test_triage_engine_retries_once_on_malformed_json():
    """A single malformed response should be retried, not dropped to fallback.

    Falling straight back to local scoring on one bad response silently wastes
    the model's judgment, and free-tier models return unparseable text often.
    """

    llm = FakeSequenceLLMClient(responses=["not json at all", _VALID_LLM_JSON])

    result = TriageEngine(llm).triage_alert(_alert())

    assert llm.calls == 2
    assert result.analysis_source == AnalysisSource.LLM
    assert result.score == 8


def test_triage_engine_falls_back_when_the_retry_also_fails():
    """Two malformed responses must end in labelled local scoring."""

    llm = FakeSequenceLLMClient(responses=["not json", "still not json"])

    result = TriageEngine(llm).triage_alert(_alert())

    assert llm.calls == 2
    assert result.analysis_source == AnalysisSource.LOCAL


def test_triage_engine_does_not_retry_transport_errors():
    """The OpenRouter client already retries transport failures itself.

    Retrying here as well would multiply the wait on a rate-limited free model.
    """

    llm = FakeSequenceLLMClient(responses=[OpenRouterError("rate limited")])

    result = TriageEngine(llm).triage_alert(_alert())

    assert llm.calls == 1
    assert result.analysis_source == AnalysisSource.LOCAL


def test_triage_engine_json_retries_are_configurable():
    """Retries must be tunable, including off."""

    llm = FakeSequenceLLMClient(responses=["not json", _VALID_LLM_JSON])

    result = TriageEngine(llm, max_json_retries=0).triage_alert(_alert())

    assert llm.calls == 1
    assert result.analysis_source == AnalysisSource.LOCAL


def test_triage_engine_rejects_negative_json_retries():
    """Invalid retry configuration must fail loudly."""

    with pytest.raises(TriageError, match="max_json_retries"):
        TriageEngine(max_json_retries=-1)


def test_private_ip_enrichment_does_not_inflate_the_score():
    """Being on an internal network is not a risk signal.

    Local enrichment marks every private address with a `private_ip` risk
    factor. Counting that as a score boost inflates every internal-only alert,
    which is most alerts in a SOC, and manufactures review-queue noise.
    """

    alert = Alert(
        id="alert-internal-001",
        source=EventSource.WAZUH,
        timestamp=BASE_TIME,
        severity=AlertSeverity.LOW,
        rule_name="sshd: authentication success.",
        src_ip="10.0.1.55",
        dst_ip="10.0.1.10",
        hostname="linux-app-01",
        user="deploy",
    )
    enrichments = LocalEnricher().enrich_alert(alert)

    assert enrichments, "expected local enrichment to produce indicators"
    assert score_alert_locally(alert, enrichments) == score_alert_locally(alert, [])


def test_high_risk_enrichment_still_boosts_the_score():
    """Suppressing private-IP noise must not suppress genuine risk factors."""

    alert = _alert()

    boosted = score_alert_locally(alert, [_high_risk_enrichment()])

    assert boosted > score_alert_locally(
        _alert(
            severity=AlertSeverity.MEDIUM,
            rule_name="Generic script alert",
            command_line=None,
            process_name=None,
            dst_ip="10.0.1.20",
        ),
        [],
    )
