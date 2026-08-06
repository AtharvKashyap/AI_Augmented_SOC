"""Normalize source-specific SOC events into shared Alert models.

This module converts RawEvent objects from Wazuh, Security Onion, and replay
fixtures into the common `Alert` model used by the rest of the pipeline.

Normalization goals:
    - Promote common searchable fields to top-level Alert attributes.
    - Preserve the original raw event payload for audit/debugging.
    - Handle common Wazuh and Security Onion JSON shapes defensively.
    - Never fail the whole polling cycle because one event is oddly shaped.

Supported inputs:
    - Wazuh alert JSON / indexer-like payloads.
    - Security Onion / Suricata / Zeek-like payloads.
    - Replay/manual test payloads.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from soc.models import Alert, AlertSeverity, EventSource, RawEvent

JsonDict = dict[str, Any]


class NormalizationError(ValueError):
    """Raised when a raw event cannot be normalized into an Alert."""


class Normalizer:
    """Convert RawEvent objects into normalized Alert objects.

    This class is stateless. A class wrapper is used so polling code can depend
    on one simple object instead of a group of module-level functions.
    """

    def normalize(self, event: RawEvent) -> Alert:
        """Normalize one RawEvent into one Alert.

        Inputs:
            event: RawEvent collected from Wazuh, Security Onion, or replay.

        Outputs:
            Alert object with normalized fields.

        Raises:
            NormalizationError: If the event source is unsupported or the event
            payload is not a dictionary.
        """

        if not isinstance(event.payload, dict):
            raise NormalizationError("RawEvent.payload must be a dictionary")

        if event.source == EventSource.WAZUH:
            return normalize_wazuh_event(event)
        if event.source == EventSource.SECURITY_ONION:
            return normalize_security_onion_event(event)
        if event.source == EventSource.OPENBSD_PF:
            return normalize_openbsd_pf_event(event)
        if event.source in {
            EventSource.REPLAY,
            EventSource.SPLUNK,
            EventSource.UNKNOWN,
        }:
            return normalize_generic_event(event)

        raise NormalizationError(f"Unsupported event source: {event.source}")

    def normalize_many(self, events: list[RawEvent]) -> list[Alert]:
        """Normalize multiple RawEvent objects.

        Inputs:
            events: RawEvent objects to normalize.

        Outputs:
            List of normalized Alert objects.
        """

        return [self.normalize(event) for event in events]


def normalize_wazuh_event(event: RawEvent) -> Alert:
    """Normalize a Wazuh RawEvent into an Alert.

    Wazuh payloads can come from several places: API responses, alerts.json, or
    indexer documents. This function checks common nested and flattened field
    paths instead of assuming one exact shape.

    Inputs:
        event: RawEvent with source EventSource.WAZUH.

    Outputs:
        Normalized Alert object.
    """

    payload = event.payload
    source_severity = _first_present(
        payload,
        [
            "rule.level",
            "rule_level",
            "data.rule.level",
            "_source.rule.level",
        ],
    )
    timestamp = _extract_timestamp(event, ["timestamp", "@timestamp", "_source.@timestamp"])
    rule_name = _first_string(
        payload,
        [
            "rule.description",
            "rule.name",
            "rule_description",
            "description",
            "_source.rule.description",
        ],
    )
    rule_groups = _first_list(
        payload,
        [
            "rule.groups",
            "rule.groups_json",
            "groups",
            "_source.rule.groups",
        ],
    )
    agent_id = _first_string(payload, ["agent.id", "agent_id", "_source.agent.id"])
    hostname = _first_string(
        payload,
        [
            "agent.name",
            "agent.hostname",
            "hostname",
            "host.name",
            "_source.agent.name",
        ],
    )
    agent_os = _first_string(
        payload,
        [
            "agent.os.name",
            "agent.os.full",
            "host.os.name",
            "os.name",
            "_source.agent.os.name",
        ],
    )

    return Alert(
        id=_build_alert_id(event, preferred_id=_first_string(payload, ["id", "alert.id", "_id"])),
        source=EventSource.WAZUH,
        timestamp=timestamp,
        severity=severity_from_wazuh_level(source_severity),
        source_severity=source_severity,
        rule_name=rule_name,
        rule_groups=rule_groups,
        src_ip=_first_string(
            payload,
            [
                "data.srcip",
                "data.src_ip",
                "srcip",
                "src_ip",
                "source.ip",
                "_source.data.srcip",
            ],
        ),
        dst_ip=_first_string(
            payload,
            [
                "data.dstip",
                "data.dst_ip",
                "dstip",
                "dst_ip",
                "destination.ip",
                "_source.data.dstip",
            ],
        ),
        hostname=hostname,
        agent_id=agent_id,
        agent_os=agent_os,
        user=_first_string(
            payload,
            [
                "data.dstuser",
                "data.srcuser",
                "data.user",
                "user.name",
                # Real Wazuh alerts nest Windows eventdata under `data.`. The
                # unprefixed paths are kept for pre-flattened documents.
                "data.win.eventdata.targetUserName",
                "data.win.eventdata.subjectUserName",
                "win.eventdata.targetUserName",
                "win.eventdata.subjectUserName",
                "_source.data.user",
            ],
        ),
        process_name=_first_string(
            payload,
            [
                "data.process.name",
                "process.name",
                "data.win.eventdata.image",
                "data.win.eventdata.newProcessName",
                "win.eventdata.image",
                "win.eventdata.newProcessName",
                "syscheck.path",
            ],
        ),
        command_line=_first_string(
            payload,
            [
                "data.command",
                "data.command_line",
                "process.command_line",
                "data.win.eventdata.commandLine",
                "win.eventdata.commandLine",
            ],
        ),
        logon_type=_first_string(
            payload,
            [
                "data.win.eventdata.logonType",
                "win.eventdata.logonType",
                "data.logon_type",
            ],
        ),
        fired_times=_first_int(payload, ["rule.firedtimes", "_source.rule.firedtimes"]),
        bytes_transferred=_first_int(
            payload,
            ["network.bytes", "data.bytes", "zeek.conn.orig_bytes", "source.bytes"],
        ),
        raw_event_id=event.id,
        raw=payload,
    )


def normalize_security_onion_event(event: RawEvent) -> Alert:
    """Normalize a Security Onion RawEvent into an Alert.

    Security Onion events may contain Suricata, Zeek, Elastic Common Schema, or
    OpenSearch-style fields. This function checks common paths used by those
    formats and falls back safely when fields are absent.

    Inputs:
        event: RawEvent with source EventSource.SECURITY_ONION.

    Outputs:
        Normalized Alert object.
    """

    payload = event.payload
    source_severity = _first_present(
        payload,
        [
            "event.severity",
            "severity",
            # A real Suricata EVE document nests alert fields under
            # `suricata.eve.alert.*`; the shorter paths suit flattened documents.
            "suricata.eve.alert.severity",
            "suricata.alert.severity",
            "alert.severity",
            "_source.event.severity",
        ],
    )
    timestamp = _extract_timestamp(event, ["@timestamp", "timestamp", "event.created", "_source.@timestamp"])
    rule_name = _first_string(
        payload,
        [
            "suricata.eve.alert.signature",
            "suricata.alert.signature",
            "alert.signature",
            "rule.name",
            "event.reason",
            "message",
            "_source.suricata.alert.signature",
        ],
    )
    rule_groups = _first_list(
        payload,
        [
            "suricata.eve.alert.category",
            "suricata.alert.category",
            "alert.category",
            "event.category",
            "event.type",
            "tags",
            "_source.event.category",
        ],
    )

    return Alert(
        id=_build_alert_id(event, preferred_id=_first_string(payload, ["event.id", "_id", "id"])),
        source=EventSource.SECURITY_ONION,
        timestamp=timestamp,
        severity=severity_from_security_onion(source_severity),
        source_severity=source_severity,
        rule_name=rule_name,
        rule_groups=rule_groups,
        src_ip=_first_string(
            payload,
            [
                "source.ip",
                "src_ip",
                "srcip",
                "id.orig_h",
                "zeek.id.orig_h",
                "_source.source.ip",
            ],
        ),
        dst_ip=_first_string(
            payload,
            [
                "destination.ip",
                "dst_ip",
                "dstip",
                "id.resp_h",
                "zeek.id.resp_h",
                "_source.destination.ip",
            ],
        ),
        hostname=_first_string(
            payload,
            [
                "host.name",
                "hostname",
                "observer.hostname",
                "agent.name",
                "_source.host.name",
            ],
        ),
        agent_id=_first_string(payload, ["agent.id", "_source.agent.id"]),
        agent_os=_first_string(payload, ["host.os.name", "host.os.full", "_source.host.os.name"]),
        user=_first_string(payload, ["user.name", "source.user.name", "destination.user.name"]),
        process_name=_first_string(payload, ["process.name", "process.executable"]),
        command_line=_first_string(payload, ["process.command_line"]),
        # Zeek conn logs carry the volume; `network.bytes` is the ECS total and
        # `orig_bytes` the outbound half, which is the direction that matters for
        # exfiltration.
        bytes_transferred=_first_int(
            payload,
            [
                "network.bytes",
                "zeek.conn.orig_bytes",
                "source.bytes",
                "_source.network.bytes",
            ],
        ),
        raw_event_id=event.id,
        raw=payload,
    )


def normalize_openbsd_pf_event(event: RawEvent) -> Alert:
    """Normalize an OpenBSD pf RawEvent into an Alert.

    The payload is the parsed pflog dictionary produced by
    soc.pflog.PflogEvent.to_payload(), so field names are already flat and
    known. The whole payload is kept in Alert.raw, including ports and the
    original log line, because the Alert model has no port fields and a firewall
    decision is only auditable with the line it came from.

    Severity is deliberately capped: a `block` normalizes to LOW and a `pass` to
    INFO, and nothing here can produce HIGH. A blocked packet is the firewall
    doing exactly what it was configured to do, and a busy internet-facing
    firewall blocks thousands of packets an hour. Mapping that to HIGH would
    flood triage and the routing thresholds with firewall noise and bury the
    endpoint and network detections an analyst actually needs to see. Firewall
    events are context for other alerts, not detections in their own right;
    correlation is what makes them interesting, not their own severity.

    Inputs:
        event: RawEvent with source EventSource.OPENBSD_PF.

    Outputs:
        Normalized Alert object.
    """

    payload = event.payload
    action = _first_string(payload, ["action"])
    direction = _first_string(payload, ["direction"])
    interface = _first_string(payload, ["interface"])
    timestamp = _extract_timestamp(event, ["timestamp", "@timestamp"])

    return Alert(
        id=_build_alert_id(event, preferred_id=_first_string(payload, ["id", "event_id"])),
        source=EventSource.OPENBSD_PF,
        timestamp=timestamp,
        severity=severity_from_pf_action(action),
        source_severity=action,
        rule_name=_build_pf_rule_name(action, direction, interface),
        rule_groups=_build_pf_rule_groups(action),
        src_ip=_first_string(payload, ["src_ip", "source.ip", "srcip"]),
        dst_ip=_first_string(payload, ["dst_ip", "destination.ip", "dstip"]),
        hostname=_first_string(payload, ["hostname", "host.name", "firewall_hostname"]),
        agent_id=_first_string(payload, ["agent_id", "agent.id"]),
        agent_os=_first_string(payload, ["agent_os", "host.os.name"]),
        user=None,
        process_name=None,
        command_line=None,
        raw_event_id=event.id,
        raw=payload,
    )


def normalize_generic_event(event: RawEvent) -> Alert:
    """Normalize a replay, unknown, or future-source event into an Alert.

    Generic normalization is used for manual tests and future integrations such
    as OpenBSD pf or Splunk until dedicated normalizers are implemented.

    Inputs:
        event: RawEvent from replay or a future/unknown source.

    Outputs:
        Best-effort Alert object.
    """

    payload = event.payload
    source_severity = _first_present(payload, ["severity", "level", "event.severity"])
    timestamp = _extract_timestamp(event, ["timestamp", "@timestamp", "event.timestamp"])

    return Alert(
        id=_build_alert_id(event, preferred_id=_first_string(payload, ["id", "alert_id", "event.id"])),
        source=event.source,
        timestamp=timestamp,
        severity=severity_from_text_or_number(source_severity),
        source_severity=source_severity,
        rule_name=_first_string(payload, ["rule_name", "rule.name", "signature", "message", "description"]),
        rule_groups=_first_list(payload, ["rule_groups", "groups", "tags", "event.category"]),
        src_ip=_first_string(payload, ["src_ip", "srcip", "source.ip"]),
        dst_ip=_first_string(payload, ["dst_ip", "dstip", "destination.ip"]),
        hostname=_first_string(payload, ["hostname", "host.name", "agent.name"]),
        agent_id=_first_string(payload, ["agent_id", "agent.id"]),
        agent_os=_first_string(payload, ["agent_os", "host.os.name", "os.name"]),
        user=_first_string(payload, ["user", "user.name"]),
        process_name=_first_string(payload, ["process_name", "process.name"]),
        command_line=_first_string(payload, ["command_line", "process.command_line", "command"]),
        raw_event_id=event.id,
        raw=payload,
    )


def severity_from_wazuh_level(value: Any) -> AlertSeverity:
    """Map Wazuh numeric rule levels to normalized severity.

    Wazuh rule levels commonly range from 0 to 15. This project uses a simple
    practical mapping for triage:
        0-2: info
        3-5: low
        6-8: medium
        9-11: high
        12+: critical

    Inputs:
        value: Wazuh rule level value.

    Outputs:
        AlertSeverity enum value.
    """

    level = _to_int(value)
    if level is None:
        return severity_from_text_or_number(value)
    if level <= 2:
        return AlertSeverity.INFO
    if level <= 5:
        return AlertSeverity.LOW
    if level <= 8:
        return AlertSeverity.MEDIUM
    if level <= 11:
        return AlertSeverity.HIGH
    return AlertSeverity.CRITICAL


def severity_from_security_onion(value: Any) -> AlertSeverity:
    """Map Security Onion/Suricata severity values to normalized severity.

    Suricata commonly uses lower numbers for more severe alerts. A common
    mapping is:
        1: high
        2: medium
        3: low
        4+: info

    Inputs:
        value: Security Onion, Suricata, or ECS severity value.

    Outputs:
        AlertSeverity enum value.
    """

    severity = _to_int(value)
    if severity is None:
        return severity_from_text_or_number(value)
    if severity <= 1:
        return AlertSeverity.HIGH
    if severity == 2:
        return AlertSeverity.MEDIUM
    if severity == 3:
        return AlertSeverity.LOW
    return AlertSeverity.INFO


def severity_from_pf_action(value: Any) -> AlertSeverity:
    """Map an OpenBSD pf action to a normalized severity.

    Firewall activity is context, not detection, so this mapping has a hard
    ceiling of LOW:
        block: low
        anything else, including pass and match: info

    A firewall that blocks a packet has already handled it. Escalating that would
    make every scan against an internet-facing interface look like an incident.

    Inputs:
        value: pf action text such as "block" or "pass".

    Outputs:
        AlertSeverity.LOW for a block, AlertSeverity.INFO otherwise.
    """

    if value is None:
        return AlertSeverity.INFO
    if str(value).strip().lower() == "block":
        return AlertSeverity.LOW
    return AlertSeverity.INFO


def severity_from_text_or_number(value: Any) -> AlertSeverity:
    """Best-effort severity mapping from common text or numeric values.

    Inputs:
        value: Severity value as text or number.

    Outputs:
        AlertSeverity enum value.
    """

    if value is None:
        return AlertSeverity.UNKNOWN

    numeric = _to_int(value)
    if numeric is not None:
        if numeric >= 90:
            return AlertSeverity.CRITICAL
        if numeric >= 70:
            return AlertSeverity.HIGH
        if numeric >= 40:
            return AlertSeverity.MEDIUM
        if numeric >= 10:
            return AlertSeverity.LOW
        return AlertSeverity.INFO

    text = str(value).strip().lower()
    if text in {"critical", "crit", "fatal", "emergency"}:
        return AlertSeverity.CRITICAL
    if text in {"high", "error", "err", "major"}:
        return AlertSeverity.HIGH
    if text in {"medium", "med", "moderate", "warning", "warn"}:
        return AlertSeverity.MEDIUM
    if text in {"low", "minor", "notice"}:
        return AlertSeverity.LOW
    if text in {"info", "informational", "debug", "trace"}:
        return AlertSeverity.INFO
    return AlertSeverity.UNKNOWN


def _build_pf_rule_name(action: str | None, direction: str | None, interface: str | None) -> str:
    """Build a readable rule name for an OpenBSD pf event.

    pf has no rule descriptions, only rule numbers, so the human-readable name
    has to be composed from the decision itself.

    Inputs:
        action: pf action such as "block" or "pass".
        direction: Packet direction, "in" or "out".
        interface: Interface name the rule matched on.

    Outputs:
        Rule name such as "pf block in on em0", degrading as fields are missing.
    """

    parts = ["pf"]
    if action:
        parts.append(action.lower())
    if direction:
        parts.append(direction.lower())
    if interface:
        parts.extend(["on", interface])

    if len(parts) == 1:
        return "pf firewall event"
    return " ".join(parts)


def _build_pf_rule_groups(action: str | None) -> list[str]:
    """Build rule groups for an OpenBSD pf event.

    Inputs:
        action: pf action such as "block" or "pass".

    Outputs:
        Groups list, always starting with "firewall" and "pf" so firewall
        context is selectable regardless of the action.
    """

    groups = ["firewall", "pf"]
    if action:
        groups.append(action.strip().lower())
    return groups


def _extract_timestamp(event: RawEvent, paths: list[str]) -> datetime | None:
    """Extract event timestamp from payload paths or fall back to RawEvent time.

    Inputs:
        event: RawEvent being normalized.
        paths: Candidate payload field paths to inspect.

    Outputs:
        Parsed datetime if available, otherwise RawEvent.timestamp.
    """

    raw_timestamp = _first_present(event.payload, paths)
    parsed = _parse_datetime(raw_timestamp)
    return parsed or event.timestamp


def _parse_datetime(value: Any) -> datetime | None:
    """Parse a datetime value from common timestamp representations.

    Inputs:
        value: Datetime, ISO timestamp string, Unix seconds, or None.

    Outputs:
        Timezone-aware datetime, or None when parsing fails.
    """

    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)

    text = str(value).strip()
    if text == "":
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _build_alert_id(event: RawEvent, preferred_id: str | None = None) -> str:
    """Build a stable normalized alert ID.

    Inputs:
        event: Source RawEvent.
        preferred_id: Optional alert ID extracted from source payload.

    Outputs:
        Stable alert ID string.
    """

    if preferred_id is not None and preferred_id.strip() != "":
        return f"{event.source.value}:{preferred_id.strip()}"

    fingerprint = hashlib.sha256(repr(event.payload).encode("utf-8")).hexdigest()[:16]
    return f"{event.source.value}:{event.id}:{fingerprint}"


def _first_string(payload: JsonDict, paths: list[str]) -> str | None:
    """Return the first non-empty string-like value from candidate paths.

    Inputs:
        payload: Source event payload.
        paths: Dot-separated field paths.

    Outputs:
        String value or None.
    """

    value = _first_present(payload, paths)
    if value is None:
        return None
    if isinstance(value, dict):
        return None
    if isinstance(value, list):
        value = ",".join(str(item) for item in value if str(item).strip() != "")
    text = str(value).strip()
    return text if text else None


def _first_int(payload: JsonDict, paths: list[str]) -> int | None:
    """Return the first path whose value reads as a non-negative integer.

    Sources are inconsistent about whether counts arrive as numbers or as
    strings, so both are accepted. An unparseable value is skipped rather than
    raising: a malformed count must not cost the whole alert.

    Inputs:
        payload: Source payload.
        paths: Dotted paths to try in order.

    Outputs:
        Integer value, or None when no path yields one.
    """

    for path in paths:
        value = _get_path(payload, path)
        if isinstance(value, bool):
            continue
        try:
            number = int(str(value).strip())
        except (TypeError, ValueError):
            continue
        if number >= 0:
            return number
    return None


def _first_list(payload: JsonDict, paths: list[str]) -> list[str]:
    """Return the first list-like value from candidate paths.

    Inputs:
        payload: Source event payload.
        paths: Dot-separated field paths.

    Outputs:
        List of strings. Empty list if no value is found.
    """

    value = _first_present(payload, paths)
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip() != ""]
    if isinstance(value, tuple | set):
        return [str(item).strip() for item in value if str(item).strip() != ""]
    text = str(value).strip()
    return [text] if text else []


def _first_present(payload: JsonDict, paths: list[str]) -> Any:
    """Return first present value from a list of dot-separated paths.

    Inputs:
        payload: Source event payload.
        paths: Dot-separated candidate paths.

    Outputs:
        First non-empty value or None.
    """

    for path in paths:
        value = _get_path(payload, path)
        if value is not None and value != "":
            return value
    return None


def _get_path(payload: JsonDict, path: str) -> Any:
    """Read a nested dictionary value using dot-separated paths.

    This helper also supports payloads that already contain flattened keys such
    as `source.ip`.

    Inputs:
        payload: Source event payload.
        path: Dot-separated path.

    Outputs:
        Value if found, otherwise None.
    """

    if path in payload:
        return payload[path]

    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        if part not in current:
            return None
        current = current[part]
    return current


def _to_int(value: Any) -> int | None:
    """Convert a value to int when possible.

    Inputs:
        value: Candidate integer value.

    Outputs:
        Integer or None when conversion fails.
    """

    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if text == "":
        return None
    try:
        return int(text)
    except ValueError:
        return None
