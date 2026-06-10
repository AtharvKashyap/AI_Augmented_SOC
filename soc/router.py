

"""Routing logic for AI_Augmented_SOC triage results.

This module converts TriageResult objects into RoutingDecision objects.

Routing is intentionally separated from notification delivery:
    - router.py decides what should happen.
    - notifier.py later delivers email, Slack, console, or file notifications.

Default routing policy:
    - score 8-10: PAGE_NOW
    - score 4-7: QUEUE_REVIEW
    - score 1-3: MARK_LIKELY_BENIGN

If the TriageResult already contains a specific action, the router respects it
by default. This lets the LLM recommend an action while still allowing the app
to apply deterministic validation and destination mapping.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from soc.models import RoutingDecision, RoutingStatus, TriageAction, TriageResult, utc_now


class RoutingError(ValueError):
    """Raised when routing cannot produce a valid decision."""


@dataclass(frozen=True, slots=True)
class RoutingConfig:
    """Configuration for converting triage results into routing decisions.

    Attributes:
        page_threshold: Minimum score that should page immediately.
        queue_threshold: Minimum score that should enter analyst review queue.
        page_destination: Destination name for immediate analyst paging.
        queue_destination: Destination name for analyst review queue.
        benign_destination: Destination name for likely-benign records.
        respect_triage_action: If True, use TriageResult.action directly. If
            False, derive action only from score thresholds.
    """

    page_threshold: int = 8
    queue_threshold: int = 4
    page_destination: str = "page_now"
    queue_destination: str = "analyst_queue"
    benign_destination: str = "likely_benign"
    respect_triage_action: bool = True

    def __post_init__(self) -> None:
        """Validate routing thresholds and destinations.

        Raises:
            RoutingError: If thresholds or destinations are invalid.
        """

        if not 1 <= self.queue_threshold <= 10:
            raise RoutingError("queue_threshold must be between 1 and 10")
        if not 1 <= self.page_threshold <= 10:
            raise RoutingError("page_threshold must be between 1 and 10")
        if self.page_threshold < self.queue_threshold:
            raise RoutingError("page_threshold must be greater than or equal to queue_threshold")
        _require_destination("page_destination", self.page_destination)
        _require_destination("queue_destination", self.queue_destination)
        _require_destination("benign_destination", self.benign_destination)


class TriageRouter:
    """Create RoutingDecision objects from TriageResult objects.

    Args:
        config: Optional RoutingConfig. Defaults are suitable for MVP usage.
    """

    def __init__(self, config: RoutingConfig | None = None) -> None:
        """Initialize the router.

        Inputs:
            config: Optional routing configuration.

        Outputs:
            None.
        """

        self.config = config or RoutingConfig()

    def route(self, result: TriageResult) -> RoutingDecision:
        """Convert one triage result into one routing decision.

        Inputs:
            result: TriageResult produced by AI or deterministic triage.

        Outputs:
            RoutingDecision describing what should happen next.
        """

        action = self._select_action(result)
        destination = self._destination_for_action(action)
        status = self._status_for_action(action)
        now = utc_now()

        return RoutingDecision(
            id=_build_routing_decision_id(result, action),
            triage_result_id=result.id,
            target_id=result.target_id,
            action=action,
            status=status,
            destination=destination,
            message=_build_routing_message(result, action, destination),
            error=None,
            created_at=now,
            updated_at=now,
        )

    def route_many(self, results: list[TriageResult]) -> list[RoutingDecision]:
        """Route multiple triage results.

        Inputs:
            results: TriageResult objects to route.

        Outputs:
            RoutingDecision objects in the same order.
        """

        return [self.route(result) for result in results]

    def _select_action(self, result: TriageResult) -> TriageAction:
        """Select the routing action for a triage result.

        Inputs:
            result: TriageResult being routed.

        Outputs:
            TriageAction selected by policy.
        """

        if self.config.respect_triage_action:
            return result.action
        return action_from_score(
            result.score,
            page_threshold=self.config.page_threshold,
            queue_threshold=self.config.queue_threshold,
        )

    def _destination_for_action(self, action: TriageAction) -> str:
        """Map a routing action to a destination.

        Inputs:
            action: Selected TriageAction.

        Outputs:
            Destination string.
        """

        if action == TriageAction.PAGE_NOW:
            return self.config.page_destination
        if action == TriageAction.QUEUE_REVIEW:
            return self.config.queue_destination
        if action == TriageAction.MARK_LIKELY_BENIGN:
            return self.config.benign_destination
        raise RoutingError(f"Unsupported triage action: {action}")

    @staticmethod
    def _status_for_action(action: TriageAction) -> RoutingStatus:
        """Map a routing action to an initial routing status.

        Inputs:
            action: Selected TriageAction.

        Outputs:
            Initial RoutingStatus.
        """

        if action == TriageAction.PAGE_NOW:
            return RoutingStatus.CREATED
        if action == TriageAction.QUEUE_REVIEW:
            return RoutingStatus.QUEUED
        if action == TriageAction.MARK_LIKELY_BENIGN:
            return RoutingStatus.MARKED_LIKELY_BENIGN
        raise RoutingError(f"Unsupported triage action: {action}")


def route_triage_result(
    result: TriageResult,
    *,
    page_threshold: int = 8,
    queue_threshold: int = 4,
    page_destination: str = "page_now",
    queue_destination: str = "analyst_queue",
    benign_destination: str = "likely_benign",
    respect_triage_action: bool = True,
) -> RoutingDecision:
    """Convenience function for routing a single triage result.

    Inputs:
        result: TriageResult to route.
        page_threshold: Minimum score for PAGE_NOW when deriving from score.
        queue_threshold: Minimum score for QUEUE_REVIEW when deriving from score.
        page_destination: Destination for PAGE_NOW.
        queue_destination: Destination for QUEUE_REVIEW.
        benign_destination: Destination for MARK_LIKELY_BENIGN.
        respect_triage_action: Whether to use result.action directly.

    Outputs:
        RoutingDecision object.
    """

    config = RoutingConfig(
        page_threshold=page_threshold,
        queue_threshold=queue_threshold,
        page_destination=page_destination,
        queue_destination=queue_destination,
        benign_destination=benign_destination,
        respect_triage_action=respect_triage_action,
    )
    return TriageRouter(config).route(result)


def action_from_score(
    score: int,
    *,
    page_threshold: int = 8,
    queue_threshold: int = 4,
) -> TriageAction:
    """Derive a routing action from a triage score.

    Inputs:
        score: Triage score from 1 to 10.
        page_threshold: Minimum score for PAGE_NOW.
        queue_threshold: Minimum score for QUEUE_REVIEW.

    Outputs:
        TriageAction selected by deterministic thresholds.

    Raises:
        RoutingError: If score or thresholds are invalid.
    """

    if not 1 <= score <= 10:
        raise RoutingError("score must be between 1 and 10")
    if not 1 <= queue_threshold <= 10:
        raise RoutingError("queue_threshold must be between 1 and 10")
    if not 1 <= page_threshold <= 10:
        raise RoutingError("page_threshold must be between 1 and 10")
    if page_threshold < queue_threshold:
        raise RoutingError("page_threshold must be greater than or equal to queue_threshold")

    if score >= page_threshold:
        return TriageAction.PAGE_NOW
    if score >= queue_threshold:
        return TriageAction.QUEUE_REVIEW
    return TriageAction.MARK_LIKELY_BENIGN


def _build_routing_decision_id(result: TriageResult, action: TriageAction) -> str:
    """Build a stable routing decision ID.

    Inputs:
        result: TriageResult being routed.
        action: Selected action.

    Outputs:
        Routing decision ID string.
    """

    raw = f"{result.id}:{result.target_id}:{action.value}"
    fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"route-{fingerprint}"


def _build_routing_message(
    result: TriageResult,
    action: TriageAction,
    destination: str,
) -> str:
    """Build a human-readable routing message.

    Inputs:
        result: TriageResult being routed.
        action: Selected routing action.
        destination: Selected destination.

    Outputs:
        Routing message string.
    """

    return (
        f"Routed target {result.target_id} with score {result.score}/10 "
        f"as {action.value} to {destination}: {result.summary}"
    )


def _require_destination(name: str, value: str) -> None:
    """Validate that a destination string is non-empty.

    Inputs:
        name: Destination field name.
        value: Destination value.

    Outputs:
        None.

    Raises:
        RoutingError: If destination is empty.
    """

    if value.strip() == "":
        raise RoutingError(f"{name} cannot be empty")