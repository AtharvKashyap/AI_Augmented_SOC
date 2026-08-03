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
from pathlib import Path

import pytest

from soc.models import AlertSeverity, EventSource, RawEvent, TriageAction
from soc.normalizer import Normalizer
from soc.replay import (
    ReplayError,
    ReplayLoadResult,
    load_replay_directory,
    load_replay_file,
    parse_event_source,
    parse_timestamp,
    raw_event_from_dict,
)
from soc.triage import local_triage_alert


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


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
    """Replay files must be an event object, a list, or an events wrapper.

    A JSON scalar is none of those and cannot be interpreted as an event.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies unsupported shape handling.
    """

    replay_file = tmp_path / "bad_shape.json"
    _write_json(replay_file, "not an event")

    with pytest.raises(ReplayError, match="must be an event object"):
        load_replay_file(replay_file)


def test_load_replay_file_reports_the_real_problem_for_an_objectless_event(tmp_path):
    """An object with no recognizable event fields fails on its missing payload.

    Since a bare object is now read as a single event, a mistyped wrapper key
    surfaces as the more precise "missing payload" error rather than a shape
    error. That is the accurate diagnosis: the object is not a valid event.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies the error names the payload.
    """

    replay_file = tmp_path / "no_payload.json"
    _write_json(replay_file, {"not_events": []})

    with pytest.raises(ReplayError, match="payload"):
        load_replay_file(replay_file)


def test_benign_wazuh_fixture_triages_as_likely_benign():
    """The benign Wazuh replay fixture must score in the likely-benign band.

    Expected labeled verdict (Milestone 2.5 eval seed): BENIGN. A routine sshd
    authentication success (Wazuh rule level 3, internal source and destination,
    no process or command line) must normalize to a low-severity Alert and be
    marked likely benign by deterministic local triage.

    The score is asserted as a band, not an exact value, so heuristic weight
    tuning in `soc.triage` does not break this test.

    Inputs:
        None. Reads `tests/fixtures/sample_wazuh_benign_alert.json`.

    Outputs:
        None. Assertions verify severity, score band, and triage action.
    """

    events = load_replay_file(FIXTURES_DIR / "sample_wazuh_benign_alert.json")

    assert len(events) == 1
    assert events[0].source == EventSource.WAZUH

    alert = Normalizer().normalize(events[0])

    assert alert.severity == AlertSeverity.LOW
    assert alert.source_severity == 3
    assert alert.rule_name == "sshd: authentication success."
    assert alert.hostname == "linux-app-01"
    assert alert.agent_id == "004"
    assert alert.user == "deploy"
    assert alert.src_ip == "10.0.1.55"
    assert alert.dst_ip == "10.0.1.10"
    assert alert.process_name is None
    assert alert.command_line is None

    result = local_triage_alert(alert)

    assert result.score <= 3
    assert result.action == TriageAction.MARK_LIKELY_BENIGN


def test_suspicious_dns_fixture_preserves_query_and_addresses():
    """The suspicious DNS replay fixture must normalize with its DNS context.

    Expected labeled verdict (Milestone 2.5 eval seed): SUSPICIOUS, worth analyst
    review but not a page. A Zeek DNS lookup of an algorithmically generated
    domain that returns NXDOMAIN is real beaconing evidence, so the queried
    domain and both endpoints must survive normalization for triage and
    enrichment to use them.

    Inputs:
        None. Reads `tests/fixtures/sample_dns_suspicious_alert.json`.

    Outputs:
        None. Assertions verify the queried domain and endpoint addresses.
    """

    events = load_replay_file(FIXTURES_DIR / "sample_dns_suspicious_alert.json")

    assert len(events) == 1
    assert events[0].source == EventSource.SECURITY_ONION

    alert = Normalizer().normalize(events[0])
    queried_domain = "z7q4k9v2m8x1p3w6.example.net"

    assert alert.src_ip == "10.0.1.42"
    assert alert.dst_ip == "10.0.1.10"
    assert alert.hostname == "securityonion-sensor-01"
    assert alert.severity == AlertSeverity.MEDIUM
    assert alert.rule_name == "Possible DGA domain lookup from workstation"
    assert "dns" in alert.rule_groups
    assert alert.raw["dns"]["question"]["name"] == queried_domain
    assert alert.raw["zeek"]["dns"]["query"] == queried_domain
    assert queried_domain in alert.raw["message"]

    result = local_triage_alert(alert)

    assert result.score >= 4
    assert result.action != TriageAction.MARK_LIKELY_BENIGN


def test_load_replay_directory_rejects_missing_directory(tmp_path):
    """Missing replay directories should raise ReplayError.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies missing-directory behavior.
    """

    with pytest.raises(ReplayError, match="does not exist"):
        load_replay_directory(tmp_path / "missing_dir")


def test_load_replay_file_accepts_a_single_event_object(tmp_path):
    """A hand-written file holding one event object is valid replay input.

    Manual test events are written by hand, and requiring a one-element list
    wrapper is friction with no benefit. A bare JSON object is one event.

    Inputs:
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies single-object files load.
    """

    replay_file = tmp_path / "single_event.json"
    _write_json(
        replay_file,
        {
            "id": "manual-001",
            "source": "wazuh",
            "payload": {"rule": {"level": 5, "description": "Test rule"}},
        },
    )

    events = load_replay_file(replay_file)

    assert len(events) == 1
    assert events[0].id == "manual-001"


@pytest.mark.parametrize(
    "fixture_name",
    [
        "sample_wazuh_alert.json",
        "sample_so_alert.json",
        "sample_wazuh_benign_alert.json",
        "sample_dns_suspicious_alert.json",
        "sample_incident_replay.json",
    ],
)
def test_every_repo_fixture_loads_through_the_replay_loader(fixture_name):
    """Every shipped fixture must be replayable from the CLI.

    A fixture the documented `--replay` path cannot open is not usable evidence,
    however well it is shaped for direct unit-test use.

    Inputs:
        fixture_name: Fixture file name under tests/fixtures.

    Outputs:
        None. Assertion verifies the fixture loads and yields events.
    """

    events = load_replay_file(Path("tests/fixtures") / fixture_name)

    assert events
