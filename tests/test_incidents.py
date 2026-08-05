

"""Tests for promoting incident candidates into incidents."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from soc.incidents import (
    IncidentError,
    IncidentPromoter,
    PromotionConfig,
    build_incident_id,
    promote_candidates,
)
from soc.models import (
    Alert,
    AlertSeverity,
    EventSource,
    FalsePositiveLikelihood,
    IncidentCandidate,
    TriageAction,
    TriageResult,
)

BASE_TIME = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _alert(alert_id: str, *, host: str = "endpoint-01", src: str = "10.0.1.10", dst: str = "8.8.8.8") -> Alert:
    """Build an alert with controllable entities."""

    return Alert(
        id=alert_id,
        source=EventSource.WAZUH,
        timestamp=BASE_TIME,
        severity=AlertSeverity.HIGH,
        rule_name="Suspicious activity",
        src_ip=src,
        dst_ip=dst,
        hostname=host,
    )


def _candidate(
    candidate_id: str,
    *,
    host: str = "endpoint-01",
    user: str | None = "alice",
    src: str = "10.0.1.10",
    dst: str = "8.8.8.8",
    offset_minutes: int = 0,
    alerts: list[Alert] | None = None,
) -> IncidentCandidate:
    """Build a candidate with controllable entities and timing."""

    moment = BASE_TIME + timedelta(minutes=offset_minutes)
    return IncidentCandidate(
        id=candidate_id,
        first_seen=moment,
        last_seen=moment,
        alerts=alerts if alerts is not None else [_alert(f"{candidate_id}-a1", host=host, src=src, dst=dst)],
        primary_host=host,
        primary_user=user,
        src_ips=[src],
        dst_ips=[dst],
    )


def _triage(candidate_id: str, score: int, action: TriageAction | None = None) -> TriageResult:
    """Build a triage result for a candidate."""

    if action is None:
        action = TriageAction.PAGE_NOW if score >= 8 else TriageAction.QUEUE_REVIEW
    return TriageResult(
        id=f"triage-{candidate_id}",
        target_id=candidate_id,
        target_type="incident_candidate",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="likely_true_positive",
        action=action,
        summary="Summary",
    )


def test_only_high_scoring_candidates_are_promoted():
    """A candidate becomes an incident when it clears the promotion bar.

    Promoting everything would make the incident tier meaningless, since it
    would just mirror the candidate tier.
    """

    pairs = [
        (_candidate("CAND-1"), _triage("CAND-1", 9)),
        (_candidate("CAND-2", host="other-host", src="10.0.2.2", dst="1.1.1.1", user="bob"), _triage("CAND-2", 4)),
    ]

    incidents = promote_candidates(pairs)

    assert len(incidents) == 1
    assert incidents[0].candidate_ids == ["CAND-1"]


def test_promotion_threshold_is_configurable():
    """Different environments tolerate different volumes of incidents."""

    pairs = [(_candidate("CAND-1"), _triage("CAND-1", 5))]

    promoter = IncidentPromoter(PromotionConfig(min_score=5))

    assert promoter.promote(pairs)
    assert IncidentPromoter(PromotionConfig(min_score=6)).promote(pairs) == []


def test_a_paged_candidate_is_promoted_even_below_the_score_bar():
    """If it was urgent enough to page, it is urgent enough to be an incident."""

    pairs = [(_candidate("CAND-1"), _triage("CAND-1", 4, action=TriageAction.PAGE_NOW))]

    assert promote_candidates(pairs)


def test_candidates_sharing_an_entity_in_window_merge_into_one_incident():
    """Two views of the same activity are one incident, not two.

    Splitting them would make an analyst investigate the same compromise twice.
    """

    pairs = [
        (_candidate("CAND-1"), _triage("CAND-1", 9)),
        (_candidate("CAND-2", offset_minutes=30), _triage("CAND-2", 8)),
    ]

    incidents = promote_candidates(pairs)

    assert len(incidents) == 1
    assert sorted(incidents[0].candidate_ids) == ["CAND-1", "CAND-2"]


def test_candidates_sharing_nothing_stay_separate():
    """Unrelated activity must not be merged just because it scored high."""

    pairs = [
        (_candidate("CAND-1"), _triage("CAND-1", 9)),
        (
            _candidate("CAND-2", host="db-01", user="svc", src="10.9.9.9", dst="9.9.9.9"),
            _triage("CAND-2", 9),
        ),
    ]

    assert len(promote_candidates(pairs)) == 2


def test_candidates_outside_the_time_window_stay_separate():
    """Shared infrastructure months apart is not one incident."""

    pairs = [
        (_candidate("CAND-1"), _triage("CAND-1", 9)),
        (_candidate("CAND-2", offset_minutes=60 * 6), _triage("CAND-2", 9)),
    ]

    assert len(promote_candidates(pairs)) == 2


def test_time_window_is_configurable():
    """The correlation window depends on the environment."""

    pairs = [
        (_candidate("CAND-1"), _triage("CAND-1", 9)),
        (_candidate("CAND-2", offset_minutes=60 * 6), _triage("CAND-2", 9)),
    ]

    promoter = IncidentPromoter(PromotionConfig(time_window_minutes=60 * 8))

    assert len(promoter.promote(pairs)) == 1


def test_incident_records_its_alerts_and_entities():
    """An incident must carry enough to investigate without re-deriving it."""

    pairs = [
        (_candidate("CAND-1"), _triage("CAND-1", 9)),
        (_candidate("CAND-2", offset_minutes=10), _triage("CAND-2", 10)),
    ]

    incident = promote_candidates(pairs)[0]

    assert sorted(incident.alert_ids) == ["CAND-1-a1", "CAND-2-a1"]
    assert incident.primary_host == "endpoint-01"
    assert "10.0.1.10" in incident.src_ips
    assert "8.8.8.8" in incident.dst_ips
    assert incident.max_score == 10


def test_incident_time_span_covers_every_candidate():
    """The incident window is the union of what it contains."""

    pairs = [
        (_candidate("CAND-1"), _triage("CAND-1", 9)),
        (_candidate("CAND-2", offset_minutes=45), _triage("CAND-2", 9)),
    ]

    incident = promote_candidates(pairs)[0]

    assert incident.first_seen == BASE_TIME
    assert incident.last_seen == BASE_TIME + timedelta(minutes=45)


def test_incident_ids_are_deterministic_and_dated():
    """Reruns over the same input must not create duplicate incidents."""

    pairs = [(_candidate("CAND-1"), _triage("CAND-1", 9))]

    first = promote_candidates(pairs)[0].id
    second = promote_candidates(pairs)[0].id

    assert first == second
    assert first.startswith("INC-20260805-001-")


def test_different_incidents_get_different_ids():
    """Distinct activity must not collide onto one identifier."""

    pairs = [
        (_candidate("CAND-1"), _triage("CAND-1", 9)),
        (
            _candidate("CAND-2", host="db-01", user="svc", src="10.9.9.9", dst="9.9.9.9"),
            _triage("CAND-2", 9),
        ),
    ]

    incidents = promote_candidates(pairs)

    assert incidents[0].id != incidents[1].id


def test_incident_carries_the_triage_results_that_justified_it():
    """An incident must be able to show why it was opened."""

    pairs = [(_candidate("CAND-1"), _triage("CAND-1", 9))]

    incident = promote_candidates(pairs)[0]

    assert incident.triage_result_ids == ["triage-CAND-1"]


def test_promotion_rejects_a_mismatched_triage_result():
    """Pairing a candidate with someone else's triage is a caller bug."""

    with pytest.raises(IncidentError, match="does not describe"):
        promote_candidates([(_candidate("CAND-1"), _triage("CAND-OTHER", 9))])


def test_promotion_config_rejects_invalid_values():
    """Invalid promotion settings must fail loudly."""

    with pytest.raises(IncidentError, match="min_score"):
        PromotionConfig(min_score=0)

    with pytest.raises(IncidentError, match="time_window_minutes"):
        PromotionConfig(time_window_minutes=0)


def test_no_candidates_promotes_nothing():
    """An empty run is not an error."""

    assert promote_candidates([]) == []


def test_incident_is_json_safe():
    """Incidents are persisted and reported, so they must serialize."""

    incident = promote_candidates([(_candidate("CAND-1"), _triage("CAND-1", 9))])[0]

    payload = incident.to_dict()

    assert payload["id"] == incident.id
    assert payload["max_score"] == 9


def test_build_incident_id_is_stable_regardless_of_candidate_order():
    """The same set of candidates is the same incident, however it is ordered."""

    assert build_incident_id(["CAND-2", "CAND-1"], BASE_TIME, 1) == build_incident_id(
        ["CAND-1", "CAND-2"], BASE_TIME, 1
    )


def test_routing_decision_decides_what_counts_as_paged():
    """The router is what actually paged, so promotion must follow it.

    Reading only the triage suggestion would make RoutingConfig thresholds
    invisible to the incident tier, recreating the dead-threshold problem that
    was removed from the router in Phase 2.
    """

    from soc.models import RoutingDecision, RoutingStatus

    candidate = _candidate("CAND-1")
    triage = _triage("CAND-1", 5, action=TriageAction.QUEUE_REVIEW)
    routing = RoutingDecision(
        id="route-1",
        triage_result_id=triage.id,
        target_id=candidate.id,
        action=TriageAction.PAGE_NOW,
        status=RoutingStatus.CREATED,
        destination="page_now",
        message="Paged by a tuned threshold.",
        error=None,
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )

    assert promote_candidates([(candidate, triage)]) == []
    assert promote_candidates(
        [(candidate, triage)], routing_decisions={candidate.id: routing}
    )
