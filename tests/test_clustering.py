

"""Tests for deterministic alert clustering.

These tests verify that normalized Alert objects are grouped into
IncidentCandidate objects using the simple MVP clustering rules in
`soc.clustering`.

The clusterer should be deterministic, explainable, and safe for low-volume SOC
labs where alerts may be sparse.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from soc.clustering import (
    AlertClusterer,
    ClusteringConfig,
    ClusteringError,
    cluster_alerts,
    extract_alert_entities,
)
from soc.models import Alert, AlertSeverity, EventSource


BASE_TIME = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


def _alert(
    alert_id: str,
    *,
    minutes: int = 0,
    source: EventSource = EventSource.WAZUH,
    hostname: str | None = None,
    agent_id: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    rule_groups: list[str] | None = None,
) -> Alert:
    """Create a compact Alert for clustering tests.

    Inputs:
        alert_id: Alert ID.
        minutes: Minutes after BASE_TIME for the alert timestamp.
        source: Alert source.
        hostname: Optional hostname.
        agent_id: Optional Wazuh agent ID.
        user: Optional username.
        src_ip: Optional source IP.
        dst_ip: Optional destination IP.
        rule_groups: Optional rule groups.

    Outputs:
        Alert object.
    """

    return Alert(
        id=alert_id,
        source=source,
        timestamp=BASE_TIME + timedelta(minutes=minutes),
        severity=AlertSeverity.HIGH,
        rule_name="Test alert",
        rule_groups=rule_groups or [],
        hostname=hostname,
        agent_id=agent_id,
        user=user,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )


def test_cluster_empty_alert_list_returns_empty_list():
    """Clustering an empty list should return an empty list.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies empty input behavior.
    """

    assert AlertClusterer().cluster([]) == []


def test_alerts_with_same_host_inside_time_window_cluster_together():
    """Alerts sharing a host within the time window should form one candidate.

    Inputs:
        None.

    Outputs:
        None. Assertions verify same-host clustering behavior.
    """

    alerts = [
        _alert("alert-001", minutes=0, hostname="endpoint-01"),
        _alert("alert-002", minutes=5, hostname="endpoint-01"),
    ]

    candidates = AlertClusterer().cluster(alerts)

    assert len(candidates) == 1
    assert candidates[0].alerts == alerts
    assert candidates[0].primary_host == "endpoint-01"
    assert candidates[0].first_seen == BASE_TIME
    assert candidates[0].last_seen == BASE_TIME + timedelta(minutes=5)


def test_alerts_with_same_user_inside_time_window_cluster_together():
    """Alerts sharing a user within the time window should form one candidate.

    Inputs:
        None.

    Outputs:
        None. Assertions verify same-user clustering behavior.
    """

    alerts = [
        _alert("alert-001", minutes=0, hostname="endpoint-01", user="alice"),
        _alert("alert-002", minutes=10, hostname="endpoint-02", user="alice"),
    ]

    candidates = AlertClusterer().cluster(alerts)

    assert len(candidates) == 1
    assert [alert.id for alert in candidates[0].alerts] == ["alert-001", "alert-002"]
    assert candidates[0].primary_user == "alice"


def test_alerts_with_same_ip_inside_time_window_cluster_together():
    """Alerts sharing IP entities should form one candidate.

    Inputs:
        None.

    Outputs:
        None. Assertions verify IP-based clustering behavior.
    """

    alerts = [
        _alert("alert-001", minutes=0, src_ip="10.0.1.10", dst_ip="198.51.100.25"),
        _alert("alert-002", minutes=15, src_ip="10.0.1.10", dst_ip="203.0.113.50"),
    ]

    candidates = AlertClusterer().cluster(alerts)

    assert len(candidates) == 1
    assert candidates[0].src_ips == ["10.0.1.10"]
    assert candidates[0].dst_ips == ["198.51.100.25", "203.0.113.50"]


def test_alerts_with_different_entities_create_separate_candidates():
    """Alerts with no shared entity should not cluster by default.

    Inputs:
        None.

    Outputs:
        None. Assertions verify separate cluster behavior.
    """

    alerts = [
        _alert("alert-001", minutes=0, hostname="endpoint-01"),
        _alert("alert-002", minutes=5, hostname="endpoint-02"),
    ]

    candidates = AlertClusterer().cluster(alerts)

    assert len(candidates) == 2
    assert [candidate.alerts[0].id for candidate in candidates] == ["alert-001", "alert-002"]


def test_alerts_outside_time_window_create_separate_candidates():
    """Alerts sharing an entity but outside the time window should split.

    Inputs:
        None.

    Outputs:
        None. Assertions verify time-window behavior.
    """

    alerts = [
        _alert("alert-001", minutes=0, hostname="endpoint-01"),
        _alert("alert-002", minutes=45, hostname="endpoint-01"),
    ]
    clusterer = AlertClusterer(ClusteringConfig(time_window_minutes=30))

    candidates = clusterer.cluster(alerts)

    assert len(candidates) == 2


def test_require_shared_entity_false_allows_time_only_grouping():
    """When shared entities are not required, time proximity may group alerts.

    Inputs:
        None.

    Outputs:
        None. Assertions verify require_shared_entity behavior.
    """

    alerts = [
        _alert("alert-001", minutes=0, hostname="endpoint-01"),
        _alert("alert-002", minutes=5, hostname="endpoint-02"),
    ]
    clusterer = AlertClusterer(
        ClusteringConfig(time_window_minutes=30, require_shared_entity=False)
    )

    candidates = clusterer.cluster(alerts)

    assert len(candidates) == 1
    assert [alert.id for alert in candidates[0].alerts] == ["alert-001", "alert-002"]


def test_clusterer_sorts_alerts_before_clustering():
    """Clusterer should sort alerts by timestamp before grouping them.

    Inputs:
        None.

    Outputs:
        None. Assertions verify deterministic ordering.
    """

    later = _alert("alert-later", minutes=10, hostname="endpoint-01")
    earlier = _alert("alert-earlier", minutes=0, hostname="endpoint-01")

    candidates = AlertClusterer().cluster([later, earlier])

    assert len(candidates) == 1
    assert [alert.id for alert in candidates[0].alerts] == ["alert-earlier", "alert-later"]
    assert candidates[0].first_seen == BASE_TIME
    assert candidates[0].last_seen == BASE_TIME + timedelta(minutes=10)


def test_candidate_metadata_uses_first_host_user_and_unique_ips():
    """Candidates should contain useful primary host/user and unique IP lists.

    Inputs:
        None.

    Outputs:
        None. Assertions verify candidate metadata.
    """

    alerts = [
        _alert(
            "alert-001",
            minutes=0,
            hostname="endpoint-01",
            user="alice",
            src_ip="10.0.1.10",
            dst_ip="198.51.100.25",
        ),
        _alert(
            "alert-002",
            minutes=5,
            hostname="endpoint-01",
            user="alice",
            src_ip="10.0.1.10",
            dst_ip="203.0.113.25",
        ),
    ]

    candidate = AlertClusterer().cluster(alerts)[0]

    assert candidate.primary_host == "endpoint-01"
    assert candidate.primary_user == "alice"
    assert candidate.src_ips == ["10.0.1.10"]
    assert candidate.dst_ips == ["198.51.100.25", "203.0.113.25"]
    assert candidate.id.startswith("CAND-20260610-001-")


def test_max_alerts_per_candidate_splits_large_cluster():
    """max_alerts_per_candidate should cap cluster size.

    Inputs:
        None.

    Outputs:
        None. Assertions verify max size behavior.
    """

    alerts = [
        _alert("alert-001", minutes=0, hostname="endpoint-01"),
        _alert("alert-002", minutes=1, hostname="endpoint-01"),
        _alert("alert-003", minutes=2, hostname="endpoint-01"),
    ]
    clusterer = AlertClusterer(ClusteringConfig(max_alerts_per_candidate=2))

    candidates = clusterer.cluster(alerts)

    assert len(candidates) == 2
    assert [alert.id for alert in candidates[0].alerts] == ["alert-001", "alert-002"]
    assert [alert.id for alert in candidates[1].alerts] == ["alert-003"]


def test_cluster_alerts_convenience_function():
    """cluster_alerts should expose a simple function interface.

    Inputs:
        None.

    Outputs:
        None. Assertions verify convenience wrapper behavior.
    """

    alerts = [
        _alert("alert-001", minutes=0, hostname="endpoint-01"),
        _alert("alert-002", minutes=5, hostname="endpoint-01"),
    ]

    candidates = cluster_alerts(alerts, time_window_minutes=30)

    assert len(candidates) == 1
    assert [alert.id for alert in candidates[0].alerts] == ["alert-001", "alert-002"]


def test_extract_alert_entities_includes_expected_values():
    """extract_alert_entities should return normalized clustering entities.

    Inputs:
        None.

    Outputs:
        None. Assertions verify extracted entity set.
    """

    alert = _alert(
        "alert-001",
        hostname="Endpoint-01",
        agent_id="001",
        user="Alice",
        src_ip="10.0.1.10",
        dst_ip="198.51.100.25",
        rule_groups=["Windows", "PowerShell"],
    )

    entities = extract_alert_entities(alert)

    assert entities == {
        "agent:001",
        "host:endpoint-01",
        "user:alice",
        "src:10.0.1.10",
        "dst:198.51.100.25",
        "rule_group:windows",
        "rule_group:powershell",
    }


def test_config_rejects_invalid_time_window():
    """ClusteringConfig should reject non-positive time windows.

    Inputs:
        None.

    Outputs:
        None. Assertions verify validation behavior.
    """

    with pytest.raises(ClusteringError, match="time_window_minutes"):
        ClusteringConfig(time_window_minutes=0)


def test_config_rejects_invalid_max_alerts():
    """ClusteringConfig should reject non-positive max alert counts.

    Inputs:
        None.

    Outputs:
        None. Assertions verify validation behavior.
    """

    with pytest.raises(ClusteringError, match="max_alerts_per_candidate"):
        ClusteringConfig(max_alerts_per_candidate=0)


def test_alerts_without_timestamps_can_cluster_when_entity_matches():
    """Alerts without timestamps should still cluster if entities match.

    Inputs:
        None.

    Outputs:
        None. Assertions verify missing timestamp behavior.
    """

    first = _alert("alert-001", hostname="endpoint-01")
    second = _alert("alert-002", hostname="endpoint-01")
    first.timestamp = None
    second.timestamp = None

    candidates = AlertClusterer().cluster([first, second])

    assert len(candidates) == 1
    assert candidates[0].first_seen is None
    assert candidates[0].last_seen is None
    assert [alert.id for alert in candidates[0].alerts] == ["alert-001", "alert-002"]