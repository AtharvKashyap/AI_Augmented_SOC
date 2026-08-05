
"""Promotion of incident candidates into incidents.

A candidate is a cluster of alerts the system built. An incident is something a
human would open a case for. Keeping the tiers separate matters: promoting every
candidate would make the incident tier a second name for the candidate tier and
tell an analyst nothing.

Two decisions define this module, and both are deliberate:

    - **The promotion bar is explicit.** A candidate is promoted when its triage
      score clears `min_score`, or when routing already paged someone — if it was
      urgent enough to wake an analyst, it is urgent enough to be an incident.
      The rule lives in config so it can be tuned per environment rather than
      being buried in a conditional.
    - **Candidates that share an entity inside the window merge.** Two views of
      the same activity are one incident. Splitting them would make an analyst
      investigate the same compromise twice, once from the endpoint side and once
      from the network side.

Incident IDs are content-addressed like the rest of the project's identifiers, so
re-running over the same input produces the same incident instead of a duplicate.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from soc.models import IncidentCandidate, TriageAction, TriageResult, utc_now

JsonDict = dict[str, Any]

DEFAULT_MIN_SCORE = 8
DEFAULT_TIME_WINDOW_MINUTES = 120


class IncidentError(ValueError):
    """Raised when incident promotion input or configuration is invalid."""


@dataclass(frozen=True, slots=True)
class PromotionConfig:
    """Rules deciding what becomes an incident.

    Attributes:
        min_score: Lowest triage score that promotes a candidate on its own.
        promote_paged: Whether a paged candidate is promoted regardless of score.
            The routing decision is authoritative here when one is supplied,
            because the router is what actually decided to page. Reading only
            the triage suggestion would make RoutingConfig thresholds
            unobservable from the incident tier.
        time_window_minutes: How far apart two candidates can be and still be
            treated as the same incident.
        require_shared_entity: Whether candidates must share a host, user, or
            address to merge. Disabling this would merge unrelated activity that
            merely happened at the same time.
    """

    min_score: int = DEFAULT_MIN_SCORE
    promote_paged: bool = True
    time_window_minutes: int = DEFAULT_TIME_WINDOW_MINUTES
    require_shared_entity: bool = True

    def __post_init__(self) -> None:
        """Validate the configuration.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            IncidentError: If a threshold or window is invalid.
        """

        if not 1 <= self.min_score <= 10:
            raise IncidentError("min_score must be between 1 and 10")
        if self.time_window_minutes <= 0:
            raise IncidentError("time_window_minutes must be greater than zero")


@dataclass(slots=True)
class Incident:
    """A promoted incident, spanning one or more candidates.

    Attributes:
        id: Incident ID of the form INC-YYYYMMDD-NNN-<hash>.
        candidate_ids: Candidates this incident was built from.
        alert_ids: Every alert across those candidates.
        triage_result_ids: Triage results that justified promotion, so the
            incident can always show why it was opened.
        first_seen: Earliest activity across the candidates.
        last_seen: Latest activity across the candidates.
        primary_host: Most common host across the candidates.
        primary_user: Most common user across the candidates.
        src_ips: Distinct source addresses.
        dst_ips: Distinct destination addresses.
        max_score: Highest triage score in the incident, which is the score an
            analyst should be judged against rather than an average.
        asset_context: Asset context of the primary host, when known.
        created_at: Local creation time.
    """

    id: str
    candidate_ids: list[str] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    triage_result_ids: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    primary_host: str | None = None
    primary_user: str | None = None
    src_ips: list[str] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)
    max_score: int = 0
    asset_context: JsonDict = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> JsonDict:
        """Return a JSON-safe representation.

        Inputs:
            None.

        Outputs:
            Dictionary representation of the incident.
        """

        return {
            "id": self.id,
            "candidate_ids": list(self.candidate_ids),
            "alert_ids": list(self.alert_ids),
            "triage_result_ids": list(self.triage_result_ids),
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "primary_host": self.primary_host,
            "primary_user": self.primary_user,
            "src_ips": list(self.src_ips),
            "dst_ips": list(self.dst_ips),
            "max_score": self.max_score,
            "asset_context": dict(self.asset_context),
            "created_at": _iso(self.created_at),
        }


@dataclass(slots=True)
class _WorkingIncident:
    """Mutable accumulator used while grouping candidates."""

    candidates: list[IncidentCandidate] = field(default_factory=list)
    triages: list[TriageResult] = field(default_factory=list)
    entities: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class IncidentPromoter:
    """Promote qualifying candidates into incidents."""

    def __init__(self, config: PromotionConfig | None = None) -> None:
        """Initialize the promoter.

        Inputs:
            config: Optional PromotionConfig.

        Outputs:
            None.
        """

        self.config = config or PromotionConfig()

    def promote(
        self,
        pairs: Iterable[tuple[IncidentCandidate, TriageResult]],
        *,
        asset_contexts: dict[str, JsonDict] | None = None,
        routing_decisions: dict[str, Any] | None = None,
    ) -> list[Incident]:
        """Promote and group qualifying candidates.

        Inputs:
            pairs: (candidate, triage result) pairs to consider.
            asset_contexts: Optional asset context by candidate ID.
            routing_decisions: Optional routing decision by candidate ID. When
                given, its action is what "was this paged" means, since the
                router is the component that decided.

        Outputs:
            Incidents, ordered by first activity.

        Raises:
            IncidentError: If a triage result does not describe its candidate.
        """

        routing = routing_decisions or {}
        qualifying: list[tuple[IncidentCandidate, TriageResult]] = []
        for candidate, triage in pairs:
            if triage.target_id != candidate.id:
                raise IncidentError(
                    f"triage result {triage.id} does not describe candidate {candidate.id}"
                )
            if self._qualifies(triage, routing.get(candidate.id)):
                qualifying.append((candidate, triage))

        if not qualifying:
            return []

        contexts = asset_contexts or {}
        return [
            self._build_incident(group, index=index, asset_contexts=contexts)
            for index, group in enumerate(self._group(qualifying), start=1)
        ]

    def _qualifies(self, triage: TriageResult, routing: Any | None = None) -> bool:
        """Return whether one candidate clears the promotion bar.

        The effective action is the routing decision when one exists, falling
        back to the triage suggestion otherwise. The router is what actually
        decided to page, so reading the suggestion instead would leave
        RoutingConfig thresholds invisible to the incident tier.

        Inputs:
            triage: TriageResult for a candidate.
            routing: Optional RoutingDecision applied to that result.

        Outputs:
            True when the candidate should become an incident.
        """

        if triage.score >= self.config.min_score:
            return True
        if not self.config.promote_paged:
            return False
        effective_action = routing.action if routing is not None else triage.action
        return effective_action is TriageAction.PAGE_NOW

    def _group(
        self,
        pairs: Sequence[tuple[IncidentCandidate, TriageResult]],
    ) -> list[_WorkingIncident]:
        """Group qualifying candidates that describe the same activity.

        Inputs:
            pairs: Qualifying (candidate, triage) pairs.

        Outputs:
            Working incident groups.
        """

        ordered = sorted(pairs, key=lambda pair: _sort_key(pair[0]))
        groups: list[_WorkingIncident] = []

        for candidate, triage in ordered:
            entities = candidate_entities(candidate)
            target = self._find_group(candidate, entities, groups)
            if target is None:
                target = _WorkingIncident()
                groups.append(target)
            target.candidates.append(candidate)
            target.triages.append(triage)
            target.entities |= entities
            target.first_seen = _earliest(target.first_seen, candidate.first_seen)
            target.last_seen = _latest(target.last_seen, candidate.last_seen)

        return groups

    def _find_group(
        self,
        candidate: IncidentCandidate,
        entities: set[str],
        groups: list[_WorkingIncident],
    ) -> _WorkingIncident | None:
        """Find an existing group this candidate belongs to.

        Inputs:
            candidate: Candidate being placed.
            entities: Entities extracted from the candidate.
            groups: Existing groups.

        Outputs:
            Matching group, or None when a new one is needed.
        """

        window = timedelta(minutes=self.config.time_window_minutes)
        for group in reversed(groups):
            if self.config.require_shared_entity and entities.isdisjoint(group.entities):
                continue
            if not _within_window(candidate, group, window):
                continue
            return group
        return None

    def _build_incident(
        self,
        group: _WorkingIncident,
        *,
        index: int,
        asset_contexts: dict[str, JsonDict],
    ) -> Incident:
        """Build one incident from a group.

        Inputs:
            group: Working group of candidates.
            index: One-based index used in the incident ID.
            asset_contexts: Asset context by candidate ID.

        Outputs:
            Incident instance.
        """

        candidate_ids = [candidate.id for candidate in group.candidates]
        alert_ids: list[str] = []
        src_ips: list[str] = []
        dst_ips: list[str] = []
        for candidate in group.candidates:
            alert_ids.extend(alert.id for alert in candidate.alerts)
            src_ips.extend(candidate.src_ips)
            dst_ips.extend(candidate.dst_ips)

        asset_context: JsonDict = {}
        for candidate in group.candidates:
            context = asset_contexts.get(candidate.id) or candidate.asset_context
            if context:
                asset_context = dict(context)
                break

        return Incident(
            id=build_incident_id(candidate_ids, group.first_seen, index),
            candidate_ids=candidate_ids,
            alert_ids=_unique(alert_ids),
            triage_result_ids=[triage.id for triage in group.triages],
            first_seen=group.first_seen,
            last_seen=group.last_seen,
            primary_host=_most_common(candidate.primary_host for candidate in group.candidates),
            primary_user=_most_common(candidate.primary_user for candidate in group.candidates),
            src_ips=_unique(src_ips),
            dst_ips=_unique(dst_ips),
            max_score=max(triage.score for triage in group.triages),
            asset_context=asset_context,
        )


def promote_candidates(
    pairs: Iterable[tuple[IncidentCandidate, TriageResult]],
    *,
    config: PromotionConfig | None = None,
    asset_contexts: dict[str, JsonDict] | None = None,
    routing_decisions: dict[str, Any] | None = None,
) -> list[Incident]:
    """Convenience function promoting candidates with default rules.

    Inputs:
        pairs: (candidate, triage result) pairs to consider.
        config: Optional PromotionConfig.
        asset_contexts: Optional asset context by candidate ID.

    Outputs:
        Incidents.
    """

    return IncidentPromoter(config).promote(
        pairs,
        asset_contexts=asset_contexts,
        routing_decisions=routing_decisions,
    )


def candidate_entities(candidate: IncidentCandidate) -> set[str]:
    """Extract the entities used to decide whether candidates are related.

    Inputs:
        candidate: IncidentCandidate to inspect.

    Outputs:
        Set of typed entity strings.
    """

    entities: set[str] = set()
    if candidate.primary_host:
        entities.add(f"host:{candidate.primary_host.lower()}")
    if candidate.primary_user:
        entities.add(f"user:{candidate.primary_user.lower()}")
    entities.update(f"src:{value}" for value in candidate.src_ips if value)
    entities.update(f"dst:{value}" for value in candidate.dst_ips if value)
    for alert in candidate.alerts:
        if alert.agent_id:
            entities.add(f"agent:{alert.agent_id}")
    return entities


def build_incident_id(candidate_ids: Sequence[str], first_seen: datetime | None, index: int) -> str:
    """Build a deterministic incident ID.

    The fingerprint is taken over the sorted candidate IDs, so the same set of
    candidates always yields the same incident regardless of the order they were
    processed in, and a rerun updates rather than duplicates.

    Inputs:
        candidate_ids: Candidates in the incident.
        first_seen: Earliest activity, used for the date part.
        index: One-based index within the run.

    Outputs:
        Incident ID string.
    """

    moment = first_seen or utc_now()
    date_part = moment.strftime("%Y%m%d")
    fingerprint = hashlib.sha256("|".join(sorted(candidate_ids)).encode("utf-8")).hexdigest()[:10]
    return f"INC-{date_part}-{index:03d}-{fingerprint}"


def _within_window(
    candidate: IncidentCandidate,
    group: _WorkingIncident,
    window: timedelta,
) -> bool:
    """Return whether a candidate falls inside a group's time window.

    Inputs:
        candidate: Candidate being placed.
        group: Existing group.
        window: Maximum separation.

    Outputs:
        True when the candidate is close enough in time.
    """

    moment = candidate.first_seen or candidate.last_seen
    if moment is None or group.first_seen is None or group.last_seen is None:
        return True
    return group.first_seen - window <= moment <= group.last_seen + window


def _sort_key(candidate: IncidentCandidate) -> tuple[float, str]:
    """Return a stable sort key for a candidate.

    Inputs:
        candidate: Candidate to sort.

    Outputs:
        Tuple of timestamp and ID.
    """

    moment = candidate.first_seen or candidate.last_seen
    return (moment.timestamp() if moment is not None else 0.0, candidate.id)


def _earliest(current: datetime | None, value: datetime | None) -> datetime | None:
    """Return the earlier of two optional timestamps."""

    if value is None:
        return current
    if current is None:
        return value
    return min(current, value)


def _latest(current: datetime | None, value: datetime | None) -> datetime | None:
    """Return the later of two optional timestamps."""

    if value is None:
        return current
    if current is None:
        return value
    return max(current, value)


def _unique(values: Iterable[str]) -> list[str]:
    """Return unique values in first-seen order."""

    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _most_common(values: Iterable[str | None]) -> str | None:
    """Return the most frequent non-empty value, or None."""

    counts: dict[str, int] = {}
    for value in values:
        if value:
            counts[value] = counts.get(value, 0) + 1
    if not counts:
        return None
    return max(sorted(counts), key=lambda key: counts[key])


def _iso(value: datetime | None) -> str | None:
    """Format an optional timestamp as ISO-8601."""

    return None if value is None else value.isoformat()
