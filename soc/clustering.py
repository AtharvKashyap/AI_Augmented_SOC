

"""Alert clustering for AI_Augmented_SOC.

This module groups normalized Alert objects into IncidentCandidate objects.

The MVP clustering logic is intentionally deterministic and explainable:
    - Sort alerts by timestamp.
    - Group alerts that occur within a configurable time window.
    - Join alerts when they share meaningful entities such as host, agent ID,
      user, source IP, or destination IP.
    - Produce one IncidentCandidate per cluster.

This is not meant to be perfect correlation logic. It is the first practical
step so replay/manual events, Wazuh alerts, and Security Onion alerts can flow
into triage as incident-shaped groups instead of isolated records.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from soc.models import Alert, IncidentCandidate, utc_now


class ClusteringError(ValueError):
    """Raised when alert clustering receives invalid input."""


@dataclass(frozen=True, slots=True)
class ClusteringConfig:
    """Configuration for deterministic alert clustering.

    Attributes:
        time_window_minutes: Maximum time gap between related alerts.
        require_shared_entity: If True, alerts must share at least one entity to
            join an existing cluster. If False, time proximity alone may group
            alerts.
        max_alerts_per_candidate: Safety limit for the number of alerts in one
            candidate.
    """

    time_window_minutes: int = 30
    require_shared_entity: bool = True
    max_alerts_per_candidate: int = 50

    def __post_init__(self) -> None:
        """Validate clustering configuration.

        Raises:
            ClusteringError: If numeric settings are invalid.
        """

        if self.time_window_minutes <= 0:
            raise ClusteringError("time_window_minutes must be greater than zero")
        if self.max_alerts_per_candidate <= 0:
            raise ClusteringError("max_alerts_per_candidate must be greater than zero")


@dataclass(slots=True)
class _WorkingCluster:
    """Mutable internal cluster used while grouping alerts."""

    alerts: list[Alert]
    entities: set[str]
    first_seen: datetime | None
    last_seen: datetime | None


class AlertClusterer:
    """Group normalized alerts into incident candidates.

    Args:
        config: Optional ClusteringConfig. Defaults are suitable for MVP usage.
    """

    def __init__(self, config: ClusteringConfig | None = None) -> None:
        """Initialize the clusterer.

        Inputs:
            config: Optional clustering configuration.

        Outputs:
            None.
        """

        self.config = config or ClusteringConfig()

    def cluster(self, alerts: list[Alert]) -> list[IncidentCandidate]:
        """Cluster alerts into incident candidates.

        Inputs:
            alerts: Normalized alerts to group.

        Outputs:
            Incident candidates created from the input alerts.
        """

        if not alerts:
            return []

        sorted_alerts = sorted(alerts, key=_alert_sort_key)
        clusters: list[_WorkingCluster] = []

        for alert in sorted_alerts:
            target_cluster = self._find_cluster_for_alert(alert, clusters)
            if target_cluster is None:
                clusters.append(_new_cluster(alert))
            else:
                _add_alert_to_cluster(alert, target_cluster)

        return [_cluster_to_candidate(cluster, index=index) for index, cluster in enumerate(clusters, start=1)]

    def _find_cluster_for_alert(
        self,
        alert: Alert,
        clusters: list[_WorkingCluster],
    ) -> _WorkingCluster | None:
        """Find the best existing cluster for an alert.

        Inputs:
            alert: Alert being placed.
            clusters: Existing working clusters.

        Outputs:
            Matching _WorkingCluster, or None if a new cluster should be made.
        """

        alert_entities = extract_alert_entities(alert)

        for cluster in reversed(clusters):
            if len(cluster.alerts) >= self.config.max_alerts_per_candidate:
                continue
            if not _within_time_window(alert, cluster, self.config.time_window_minutes):
                continue
            if self.config.require_shared_entity and alert_entities.isdisjoint(cluster.entities):
                continue
            return cluster

        return None


def cluster_alerts(
    alerts: list[Alert],
    *,
    time_window_minutes: int = 30,
    require_shared_entity: bool = True,
    max_alerts_per_candidate: int = 50,
) -> list[IncidentCandidate]:
    """Convenience function for clustering alerts without instantiating a class.

    Inputs:
        alerts: Normalized alerts to group.
        time_window_minutes: Maximum time gap between related alerts.
        require_shared_entity: Whether alerts must share host/user/IP/etc.
        max_alerts_per_candidate: Maximum alerts allowed in one candidate.

    Outputs:
        Incident candidates created from the input alerts.
    """

    config = ClusteringConfig(
        time_window_minutes=time_window_minutes,
        require_shared_entity=require_shared_entity,
        max_alerts_per_candidate=max_alerts_per_candidate,
    )
    return AlertClusterer(config).cluster(alerts)


def extract_alert_entities(alert: Alert) -> set[str]:
    """Extract clustering entities from an alert.

    Inputs:
        alert: Alert to inspect.

    Outputs:
        Set of normalized entity strings.
    """

    entities: set[str] = set()
    _add_entity(entities, "agent", alert.agent_id)
    _add_entity(entities, "host", alert.hostname)
    _add_entity(entities, "user", alert.user)
    _add_entity(entities, "src", alert.src_ip)
    _add_entity(entities, "dst", alert.dst_ip)

    for group in alert.rule_groups:
        _add_entity(entities, "rule_group", group)

    return entities


def _new_cluster(alert: Alert) -> _WorkingCluster:
    """Create a new working cluster from one alert.

    Inputs:
        alert: First alert in the cluster.

    Outputs:
        _WorkingCluster instance.
    """

    timestamp = _alert_time(alert)
    return _WorkingCluster(
        alerts=[alert],
        entities=extract_alert_entities(alert),
        first_seen=timestamp,
        last_seen=timestamp,
    )


def _add_alert_to_cluster(alert: Alert, cluster: _WorkingCluster) -> None:
    """Add an alert to an existing working cluster.

    Inputs:
        alert: Alert to add.
        cluster: Working cluster to update.

    Outputs:
        None. The cluster is mutated.
    """

    alert_time = _alert_time(alert)
    cluster.alerts.append(alert)
    cluster.entities.update(extract_alert_entities(alert))
    cluster.first_seen = _min_datetime(cluster.first_seen, alert_time)
    cluster.last_seen = _max_datetime(cluster.last_seen, alert_time)


def _cluster_to_candidate(cluster: _WorkingCluster, index: int) -> IncidentCandidate:
    """Convert an internal working cluster into an IncidentCandidate.

    Inputs:
        cluster: Working cluster to convert.
        index: 1-based cluster index for stable-ish candidate IDs.

    Outputs:
        IncidentCandidate instance.
    """

    alerts = sorted(cluster.alerts, key=_alert_sort_key)
    first_seen = cluster.first_seen
    last_seen = cluster.last_seen
    primary_host = _first_non_empty(alert.hostname for alert in alerts)
    primary_user = _first_non_empty(alert.user for alert in alerts)

    return IncidentCandidate(
        id=_build_candidate_id(alerts, index),
        first_seen=first_seen,
        last_seen=last_seen,
        alerts=alerts,
        primary_host=primary_host,
        primary_user=primary_user,
        src_ips=_unique_non_empty(alert.src_ip for alert in alerts),
        dst_ips=_unique_non_empty(alert.dst_ip for alert in alerts),
        related_events=[],
        enrichments=[],
        created_at=utc_now(),
    )


def _within_time_window(alert: Alert, cluster: _WorkingCluster, minutes: int) -> bool:
    """Return whether an alert is close enough in time to a cluster.

    Inputs:
        alert: Alert being placed.
        cluster: Existing cluster.
        minutes: Time window in minutes.

    Outputs:
        True if alert falls within the window, otherwise False.
    """

    alert_time = _alert_time(alert)
    if alert_time is None or cluster.last_seen is None:
        return True

    return abs(alert_time - cluster.last_seen) <= timedelta(minutes=minutes)


def _alert_time(alert: Alert) -> datetime | None:
    """Return alert timestamp normalized to a timezone-aware datetime.

    Inputs:
        alert: Alert to inspect.

    Outputs:
        Timezone-aware datetime or None.
    """

    if alert.timestamp is None:
        return None
    if alert.timestamp.tzinfo is None:
        return alert.timestamp.replace(tzinfo=timezone.utc)
    return alert.timestamp


def _alert_sort_key(alert: Alert) -> tuple[datetime, str]:
    """Return stable sort key for alerts.

    Inputs:
        alert: Alert to sort.

    Outputs:
        Tuple of timestamp and alert ID.
    """

    timestamp = _alert_time(alert) or datetime.min.replace(tzinfo=timezone.utc)
    return timestamp, alert.id


def _build_candidate_id(alerts: list[Alert], index: int) -> str:
    """Build a deterministic candidate ID from alert IDs.

    Inputs:
        alerts: Alerts included in the candidate.
        index: 1-based cluster index.

    Outputs:
        Candidate ID string.
    """

    alert_ids = ":".join(sorted(alert.id for alert in alerts))
    fingerprint = hashlib.sha256(alert_ids.encode("utf-8")).hexdigest()[:10]
    first_time = _alert_time(alerts[0])
    date_part = first_time.strftime("%Y%m%d") if first_time is not None else "unknown"
    return f"CAND-{date_part}-{index:03d}-{fingerprint}"


def _add_entity(entities: set[str], prefix: str, value: Any) -> None:
    """Add a normalized entity value to a set.

    Inputs:
        entities: Entity set to update.
        prefix: Entity type prefix.
        value: Raw entity value.

    Outputs:
        None. The set is mutated when value is non-empty.
    """

    if value is None:
        return
    text = str(value).strip().lower()
    if text == "":
        return
    entities.add(f"{prefix}:{text}")


def _min_datetime(left: datetime | None, right: datetime | None) -> datetime | None:
    """Return the earlier of two optional datetimes.

    Inputs:
        left: First datetime or None.
        right: Second datetime or None.

    Outputs:
        Earlier datetime, or whichever value is not None.
    """

    if left is None:
        return right
    if right is None:
        return left
    return min(left, right)


def _max_datetime(left: datetime | None, right: datetime | None) -> datetime | None:
    """Return the later of two optional datetimes.

    Inputs:
        left: First datetime or None.
        right: Second datetime or None.

    Outputs:
        Later datetime, or whichever value is not None.
    """

    if left is None:
        return right
    if right is None:
        return left
    return max(left, right)


def _first_non_empty(values: Any) -> str | None:
    """Return the first non-empty value from an iterable.

    Inputs:
        values: Iterable of values.

    Outputs:
        First non-empty string or None.
    """

    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _unique_non_empty(values: Any) -> list[str]:
    """Return unique non-empty values while preserving first-seen order.

    Inputs:
        values: Iterable of values.

    Outputs:
        List of unique strings.
    """

    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result