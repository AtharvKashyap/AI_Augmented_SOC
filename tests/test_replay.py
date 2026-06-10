"""Tests for replay fixture loading.

These tests verify that `soc.replay` can load sample/manual JSON events from
files and directories, convert them into RawEvent objects, and reject malformed
replay input cleanly.

Replay support is important because the SOC may not generate enough live Wazuh
or Security Onion alerts to test the pipeline reliably.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from soc.models import EventSource, RawEvent
from soc.replay import (
    ReplayError,
    ReplayLoadResult,
    load_replay_directory,
    load_replay_file,
    parse_event_source,
    parse_timestamp,
    raw_event_from_dict,
)


def _write_json(path, payload) -> None:
    """Write JSON test data to disk.

    Inputs:
        path: Path to write.
        payload: JSON-serializable payload.

    Outputs:
        None. File is written to disk.
    """

    path.write_text(json.dumps(payload), encoding="utf-8")


def test_load_replay_file_list_format(tmp_path):
    """Replay files may be a list of event objects.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify loaded RawEvent objects.
    """

    replay_file = tmp_path / "events.json"
    _write_json(
        replay_file,
        [
            {
                "id": "raw-wazuh-001",
                "source": "wazuh",
                "timestamp": "2026-06-10T12:00:00+00:00",
                "payload": {"rule": {"level": 10}},
            },
            {
                "id": "raw-so-001",
                "source": "security_onion",
                "timestamp": "2026-06-10T12:01:00Z",
                "payload": {"suricata": {"alert": {"signature": "Possible C2"}}},
            },
        ],
    )

    events = load_replay_file(replay_file)

    assert len(events) == 2
    assert all(isinstance(event, RawEvent) for event in events)
    assert events[0].id == "raw-wazuh-001"
    assert events[0].source == EventSource.WAZUH
    assert events[0].timestamp == datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)
    assert events[0].payload == {"rule": {"level": 10}}
    assert events[1].id == "raw-so-001"
    assert events[1].source == EventSource.SECURITY_ONION
    assert events[1].timestamp == datetime(2026, 6, 10, 12, 1, tzinfo=timezone.utc)


def test_load_replay_file_object_format(tmp_path):
    """Replay files may be an object with an `events` list.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify object-format loading.
    """

    replay_file = tmp_path / "incident.json"
    _write_json(
        replay_file,
        {
            "name": "sample incident",
            "events": [
                {
                    "id": "raw-so-002",
                    "source": "so",
                    "timestamp": "2026-06-10T12:05:00+00:00",
                    "payload": {"source": {"ip": "10.0.1.10"}},
                }
            ],
        },
    )

    events = load_replay_file(replay_file)

    assert len(events) == 1
    assert events[0].id == "raw-so-002"
    assert events[0].source == EventSource.SECURITY_ONION
    assert events[0].payload == {"source": {"ip": "10.0.1.10"}}


def test_load_replay_directory_loads_json_and_skips_non_json(tmp_path):
    """Replay directories should load JSON files and skip other files.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify directory loading behavior.
    """

    first_file = tmp_path / "01_wazuh.json"
    second_file = tmp_path / "02_so.json"
    skipped_file = tmp_path / "notes.txt"

    _write_json(
        first_file,
        [
            {
                "id": "raw-wazuh-001",
                "source": "wazuh",
                "payload": {"rule": {"description": "Suspicious PowerShell"}},
            }
        ],
    )
    _write_json(
        second_file,
        [
            {
                "id": "raw-so-001",
                "source": "security_onion",
                "payload": {"event": {"kind": "alert"}},
            }
        ],
    )
    skipped_file.write_text("not json", encoding="utf-8")

    result = load_replay_directory(tmp_path)

    assert isinstance(result, ReplayLoadResult)
    assert len(result.events) == 2
    assert result.files_loaded == [first_file, second_file]
    assert result.files_skipped == [skipped_file]
    assert result.events[0].id == "raw-wazuh-001"
    assert result.events[1].id == "raw-so-001"


def test_raw_event_from_dict_generates_fallback_id(tmp_path):
    """Replay events without IDs should receive deterministic fallback IDs.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies fallback ID format.
    """

    replay_file = tmp_path / "manual_test.json"
    event = raw_event_from_dict(
        {
            "source": "wazuh",
            "timestamp": "2026-06-10T12:00:00+00:00",
            "payload": {"rule": {"level": 7}},
        },
        index=2,
        file_path=replay_file,
    )

    assert event.id == "replay-wazuh-manual_test-0003"
    assert event.source == EventSource.WAZUH


def test_raw_event_from_dict_defaults_source_to_replay():
    """Replay events without a source should default to EventSource.REPLAY.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies default source behavior.
    """

    event = raw_event_from_dict({"id": "manual-001", "payload": {"message": "test"}})

    assert event.id == "manual-001"
    assert event.source == EventSource.REPLAY


def test_raw_event_from_dict_rejects_missing_payload():
    """Replay events must include a JSON object payload.

    Inputs:
        None.

    Outputs:
        None. Assertions verify validation behavior.
    """

    with pytest.raises(ReplayError, match="payload"):
        raw_event_from_dict({"id": "bad-001", "source": "wazuh"})

    with pytest.raises(ReplayError, match="payload"):
        raw_event_from_dict({"id": "bad-002", "source": "wazuh", "payload": []})


def test_parse_event_source_accepts_aliases():
    """Source parser should accept common source aliases.

    Inputs:
        None.

    Outputs:
        None. Assertions verify alias mapping.
    """

    assert parse_event_source("wazuh") == EventSource.WAZUH
    assert parse_event_source("security_onion") == EventSource.SECURITY_ONION
    assert parse_event_source("security-onion") == EventSource.SECURITY_ONION
    assert parse_event_source("so") == EventSource.SECURITY_ONION
    assert parse_event_source("pf") == EventSource.OPENBSD_PF
    assert parse_event_source("splunk") == EventSource.SPLUNK
    assert parse_event_source("replay") == EventSource.REPLAY


def test_parse_event_source_rejects_unknown_source():
    """Unsupported source values should raise ReplayError.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies invalid source behavior.
    """

    with pytest.raises(ReplayError, match="Unsupported replay source"):
        parse_event_source("unknown_tool_name")


def test_parse_timestamp_handles_none_empty_z_and_naive_values():
    """Timestamp parser should handle optional and common ISO formats.

    Inputs:
        None.

    Outputs:
        None. Assertions verify timestamp parsing behavior.
    """

    assert parse_timestamp(None) is None
    assert parse_timestamp("") is None
    assert parse_timestamp("2026-06-10T12:00:00Z") == datetime(
        2026,
        6,
        10,
        12,
        0,
        tzinfo=timezone.utc,
    )
    assert parse_timestamp("2026-06-10T12:00:00") == datetime(
        2026,
        6,
        10,
        12,
        0,
        tzinfo=timezone.utc,
    )


def test_parse_timestamp_rejects_invalid_timestamp():
    """Invalid timestamp strings should raise ReplayError.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies invalid timestamp behavior.
    """

    with pytest.raises(ReplayError, match="Invalid replay timestamp"):
        parse_timestamp("not-a-real-time")


def test_load_replay_file_rejects_missing_file(tmp_path):
    """Missing replay files should raise ReplayError.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies missing-file behavior.
    """

    with pytest.raises(ReplayError, match="does not exist"):
        load_replay_file(tmp_path / "missing.json")


def test_load_replay_file_rejects_invalid_json(tmp_path):
    """Invalid JSON replay files should raise ReplayError.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies invalid JSON behavior.
    """

    replay_file = tmp_path / "bad.json"
    replay_file.write_text("{not json", encoding="utf-8")

    with pytest.raises(ReplayError, match="Invalid JSON"):
        load_replay_file(replay_file)


def test_load_replay_file_rejects_unsupported_shape(tmp_path):
    """Replay files must be a list or object with an events list.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies unsupported shape handling.
    """

    replay_file = tmp_path / "bad_shape.json"
    _write_json(replay_file, {"not_events": []})

    with pytest.raises(ReplayError, match="events"):
        load_replay_file(replay_file)


def test_load_replay_directory_rejects_missing_directory(tmp_path):
    """Missing replay directories should raise ReplayError.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies missing-directory behavior.
    """

    with pytest.raises(ReplayError, match="does not exist"):
        load_replay_directory(tmp_path / "missing_dir")
