

"""Tests for triage routing decisions.

These tests verify that `soc.router` converts TriageResult objects into
RoutingDecision objects using deterministic routing policy and configured
routing destinations.

The router does not send notifications. It only decides where a triage result
should go next.
"""

from __future__ import annotations

import pytest

from soc.models import (
    FalsePositiveLikelihood,
    RoutingStatus,
    TriageAction,
    TriageResult,
)
from soc.router import (
    RoutingConfig,
    RoutingError,
    TriageRouter,
    action_from_score,
    route_triage_result,
)


def _triage_result(
    score: int,
    action: TriageAction,
    *,
    result_id: str = "triage-001",
    target_id: str = "alert-001",
) -> TriageResult:
    """Create a compact TriageResult for router tests.

    Inputs:
        score: Triage score from 1 to 10.
        action: Recommended triage action.
        result_id: Triage result ID.
        target_id: Alert or candidate target ID.

    Outputs:
        TriageResult object.
    """

    return TriageResult(
        id=result_id,
        target_id=target_id,
        target_type="alert",
        score=score,
        fp_likelihood=FalsePositiveLikelihood.LOW,
        classification="test_classification",
        action=action,
        summary="Test triage summary.",
    )


def test_action_from_score_default_thresholds():
    """Default thresholds should map scores to expected actions.

    Inputs:
        None.

    Outputs:
        None. Assertions verify score-to-action mapping.
    """

    assert action_from_score(10) == TriageAction.PAGE_NOW
    assert action_from_score(8) == TriageAction.PAGE_NOW
    assert action_from_score(7) == TriageAction.QUEUE_REVIEW
    assert action_from_score(4) == TriageAction.QUEUE_REVIEW
    assert action_from_score(3) == TriageAction.MARK_LIKELY_BENIGN
    assert action_from_score(1) == TriageAction.MARK_LIKELY_BENIGN


def test_action_from_score_custom_thresholds():
    """Custom thresholds should override the default score policy.

    Inputs:
        None.

    Outputs:
        None. Assertions verify custom threshold behavior.
    """

    assert action_from_score(9, page_threshold=9, queue_threshold=5) == TriageAction.PAGE_NOW
    assert action_from_score(8, page_threshold=9, queue_threshold=5) == TriageAction.QUEUE_REVIEW
    assert action_from_score(4, page_threshold=9, queue_threshold=5) == TriageAction.MARK_LIKELY_BENIGN


def test_action_from_score_rejects_invalid_score():
    """Invalid scores should raise RoutingError.

    Inputs:
        None.

    Outputs:
        None. Assertions verify validation behavior.
    """

    with pytest.raises(RoutingError, match="score"):
        action_from_score(0)

    with pytest.raises(RoutingError, match="score"):
        action_from_score(11)


def test_action_from_score_rejects_invalid_thresholds():
    """Invalid thresholds should raise RoutingError.

    Inputs:
        None.

    Outputs:
        None. Assertions verify threshold validation.
    """

    with pytest.raises(RoutingError, match="queue_threshold"):
        action_from_score(5, queue_threshold=0)

    with pytest.raises(RoutingError, match="page_threshold"):
        action_from_score(5, page_threshold=0)

    with pytest.raises(RoutingError, match="page_threshold"):
        action_from_score(5, page_threshold=3, queue_threshold=4)


def test_router_respects_triage_action_by_default():
    """Router should use TriageResult.action when respect_triage_action is True.

    Inputs:
        None.

    Outputs:
        None. Assertions verify default routing behavior.
    """

    result = _triage_result(score=9, action=TriageAction.QUEUE_REVIEW)

    decision = TriageRouter().route(result)

    assert decision.triage_result_id == "triage-001"
    assert decision.target_id == "alert-001"
    assert decision.action == TriageAction.QUEUE_REVIEW
    assert decision.status == RoutingStatus.QUEUED
    assert decision.destination == "analyst_queue"
    assert "score 9/10" in decision.message
    assert "queue_review" in decision.message
    assert decision.error is None
    assert decision.id.startswith("route-")


def test_router_can_force_score_based_action():
    """Router should derive action from score when respect_triage_action is False.

    Inputs:
        None.

    Outputs:
        None. Assertions verify deterministic score-based routing.
    """

    result = _triage_result(score=9, action=TriageAction.QUEUE_REVIEW)
    router = TriageRouter(RoutingConfig(respect_triage_action=False))

    decision = router.route(result)

    assert decision.action == TriageAction.PAGE_NOW
    assert decision.status == RoutingStatus.CREATED
    assert decision.destination == "page_now"


def test_router_maps_page_now_to_page_destination():
    """PAGE_NOW decisions should use page destination and CREATED status.

    Inputs:
        None.

    Outputs:
        None. Assertions verify PAGE_NOW destination/status.
    """

    result = _triage_result(score=10, action=TriageAction.PAGE_NOW)
    router = TriageRouter(RoutingConfig(page_destination="email_pager"))

    decision = router.route(result)

    assert decision.action == TriageAction.PAGE_NOW
    assert decision.status == RoutingStatus.CREATED
    assert decision.destination == "email_pager"


def test_router_maps_queue_review_to_queue_destination():
    """QUEUE_REVIEW decisions should use queue destination and QUEUED status.

    Inputs:
        None.

    Outputs:
        None. Assertions verify QUEUE_REVIEW destination/status.
    """

    result = _triage_result(score=5, action=TriageAction.QUEUE_REVIEW)
    router = TriageRouter(RoutingConfig(queue_destination="tier1_queue"))

    decision = router.route(result)

    assert decision.action == TriageAction.QUEUE_REVIEW
    assert decision.status == RoutingStatus.QUEUED
    assert decision.destination == "tier1_queue"


def test_router_maps_likely_benign_to_benign_destination():
    """MARK_LIKELY_BENIGN decisions should use benign destination/status.

    Inputs:
        None.

    Outputs:
        None. Assertions verify likely-benign destination/status.
    """

    result = _triage_result(score=2, action=TriageAction.MARK_LIKELY_BENIGN)
    router = TriageRouter(RoutingConfig(benign_destination="benign_archive"))

    decision = router.route(result)

    assert decision.action == TriageAction.MARK_LIKELY_BENIGN
    assert decision.status == RoutingStatus.MARKED_LIKELY_BENIGN
    assert decision.destination == "benign_archive"


def test_route_many_preserves_order():
    """route_many should return decisions in the same order as inputs.

    Inputs:
        None.

    Outputs:
        None. Assertions verify batch routing behavior.
    """

    results = [
        _triage_result(9, TriageAction.PAGE_NOW, result_id="triage-001", target_id="alert-001"),
        _triage_result(5, TriageAction.QUEUE_REVIEW, result_id="triage-002", target_id="alert-002"),
        _triage_result(2, TriageAction.MARK_LIKELY_BENIGN, result_id="triage-003", target_id="alert-003"),
    ]

    decisions = TriageRouter().route_many(results)

    assert [decision.target_id for decision in decisions] == ["alert-001", "alert-002", "alert-003"]
    assert [decision.action for decision in decisions] == [
        TriageAction.PAGE_NOW,
        TriageAction.QUEUE_REVIEW,
        TriageAction.MARK_LIKELY_BENIGN,
    ]


def test_route_triage_result_convenience_function():
    """route_triage_result should expose a simple function interface.

    Inputs:
        None.

    Outputs:
        None. Assertions verify convenience wrapper behavior.
    """

    result = _triage_result(score=8, action=TriageAction.QUEUE_REVIEW)

    decision = route_triage_result(result, respect_triage_action=False)

    assert decision.action == TriageAction.PAGE_NOW
    assert decision.destination == "page_now"


def test_routing_decision_id_is_stable_for_same_input():
    """Routing decision IDs should be stable for the same result/action.

    Inputs:
        None.

    Outputs:
        None. Assertions verify stable ID behavior.
    """

    result = _triage_result(score=8, action=TriageAction.PAGE_NOW)
    router = TriageRouter()

    first = router.route(result)
    second = router.route(result)

    assert first.id == second.id


def test_routing_decision_id_changes_for_different_action_when_score_based():
    """Routing decision IDs should change when selected action changes.

    Inputs:
        None.

    Outputs:
        None. Assertions verify ID input sensitivity.
    """

    result = _triage_result(score=8, action=TriageAction.QUEUE_REVIEW)

    respected = TriageRouter(RoutingConfig(respect_triage_action=True)).route(result)
    score_based = TriageRouter(RoutingConfig(respect_triage_action=False)).route(result)

    assert respected.id != score_based.id
    assert respected.action == TriageAction.QUEUE_REVIEW
    assert score_based.action == TriageAction.PAGE_NOW


def test_routing_config_rejects_invalid_thresholds():
    """RoutingConfig should reject invalid threshold values.

    Inputs:
        None.

    Outputs:
        None. Assertions verify config validation.
    """

    with pytest.raises(RoutingError, match="queue_threshold"):
        RoutingConfig(queue_threshold=0)

    with pytest.raises(RoutingError, match="page_threshold"):
        RoutingConfig(page_threshold=0)

    with pytest.raises(RoutingError, match="page_threshold"):
        RoutingConfig(page_threshold=3, queue_threshold=4)


def test_routing_config_rejects_empty_destinations():
    """RoutingConfig should reject empty destination strings.

    Inputs:
        None.

    Outputs:
        None. Assertions verify destination validation.
    """

    with pytest.raises(RoutingError, match="page_destination"):
        RoutingConfig(page_destination="")

    with pytest.raises(RoutingError, match="queue_destination"):
        RoutingConfig(queue_destination="   ")

    with pytest.raises(RoutingError, match="benign_destination"):
        RoutingConfig(benign_destination="")