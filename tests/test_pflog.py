"""Tests for OpenBSD pflog text parsing.

These tests exercise `soc.pflog`, which turns `tcpdump`-rendered pflog output
into PflogEvent objects and RawEvent objects for the pipeline. The parser is
deliberately tolerant: a line it cannot read is skipped and counted rather than
failing the read, because a firewall log is a continuously appended file that a
deployment may render with slightly different tcpdump flags.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

from soc.models import EventSource
from soc.pflog import (
    PflogError,
    PflogEvent,
    PflogReader,
    parse_pflog_line,
    raw_event_from_pflog,
    read_pflog_file,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_pflog.txt"

BLOCK_LINE = (
    "Aug 05 12:00:00.123456 rule 12/(match) block in on em0: "
    "203.0.113.5.4444 > 10.0.1.5.22: S 12345:12345(0) win 65535"
)
PASS_LINE = (
    "Aug 05 12:00:01.456789 rule 5/(match) pass out on em0: 10.0.1.5.51000 > 8.8.8.8.53: udp 40"
)
ICMP_LINE = (
    "Aug 05 12:00:02.222333 rule 12/(match) block in on em0: 198.51.100.7 > 10.0.1.5: icmp: echo request"
)


def test_parse_pflog_block_line_extracts_every_field():
    """A blocked TCP packet line should yield every parsed field.

    Inputs:
        None.

    Outputs:
        None. Assertions verify each PflogEvent attribute.
    """

    event = parse_pflog_line(BLOCK_LINE, year=2026)

    assert isinstance(event, PflogEvent)
    assert event.timestamp == datetime(2026, 8, 5, 12, 0, 0, 123456, tzinfo=UTC)
    assert event.action == "block"
    assert event.direction == "in"
    assert event.interface == "em0"
    assert event.rule_number == 12
    assert event.protocol == "tcp"
    assert event.src_ip == "203.0.113.5"
    assert event.src_port == 4444
    assert event.dst_ip == "10.0.1.5"
    assert event.dst_port == 22
    assert event.raw_line == BLOCK_LINE


def test_parse_pflog_pass_line_extracts_every_field():
    """A passed UDP packet line should yield every parsed field.

    Inputs:
        None.

    Outputs:
        None. Assertions verify each PflogEvent attribute.
    """

    event = parse_pflog_line(PASS_LINE, year=2026)

    assert event is not None
    assert event.timestamp == datetime(2026, 8, 5, 12, 0, 1, 456789, tzinfo=UTC)
    assert event.action == "pass"
    assert event.direction == "out"
    assert event.interface == "em0"
    assert event.rule_number == 5
    assert event.protocol == "udp"
    assert event.src_ip == "10.0.1.5"
    assert event.src_port == 51000
    assert event.dst_ip == "8.8.8.8"
    assert event.dst_port == 53
    assert event.raw_line == PASS_LINE


def test_parse_pflog_line_without_ports_still_parses():
    """An ICMP line carries no ports and must still parse.

    Inputs:
        None.

    Outputs:
        None. Assertions verify addresses parse and ports stay None.
    """

    event = parse_pflog_line(ICMP_LINE, year=2026)

    assert event is not None
    assert event.action == "block"
    assert event.protocol == "icmp"
    assert event.src_ip == "198.51.100.7"
    assert event.src_port is None
    assert event.dst_ip == "10.0.1.5"
    assert event.dst_port is None


def test_parse_pflog_line_returns_none_for_unparseable_line():
    """A line that does not match the expected format returns None, not an error.

    Inputs:
        None.

    Outputs:
        None. Assertions verify None is returned for junk input.
    """

    assert parse_pflog_line("not-pflog-output: something else entirely") is None
    assert parse_pflog_line("") is None
    assert parse_pflog_line("   ") is None


def test_parse_pflog_line_defaults_to_current_year():
    """pflog lines carry no year, so the current UTC year is assumed.

    Inputs:
        None.

    Outputs:
        None. Assertion verifies the default year behavior.
    """

    event = parse_pflog_line(BLOCK_LINE)

    assert event is not None
    assert event.timestamp is not None
    assert event.timestamp.year == datetime.now(UTC).year


def test_pflog_event_to_payload_preserves_parsed_fields():
    """to_payload should expose every parsed field for the normalizer.

    Inputs:
        None.

    Outputs:
        None. Assertions verify payload keys and values.
    """

    event = parse_pflog_line(BLOCK_LINE, year=2026)

    assert event is not None
    payload = event.to_payload()

    assert payload["action"] == "block"
    assert payload["direction"] == "in"
    assert payload["interface"] == "em0"
    assert payload["rule_number"] == 12
    assert payload["protocol"] == "tcp"
    assert payload["src_ip"] == "203.0.113.5"
    assert payload["src_port"] == 4444
    assert payload["dst_ip"] == "10.0.1.5"
    assert payload["dst_port"] == 22
    assert payload["raw_line"] == BLOCK_LINE
    assert payload["timestamp"] == "2026-08-05T12:00:00.123456+00:00"


def test_read_pflog_file_skips_malformed_lines_and_reports_the_count():
    """The fixture's one junk line is skipped and counted, not fatal.

    Inputs:
        None.

    Outputs:
        None. Assertions verify parsed events and the skipped count.
    """

    reader = PflogReader()
    events = reader.read_pflog_file(FIXTURE_PATH, year=2026)

    assert len(events) == 4
    assert reader.last_malformed_line_count == 1
    assert [event.action for event in events] == ["block", "pass", "block", "block"]
    assert [event.interface for event in events] == ["em0", "em0", "em0", "vio0"]


def test_read_pflog_file_module_function_matches_reader():
    """The module-level function mirrors the reader method.

    Inputs:
        None.

    Outputs:
        None. Assertions verify the module function parses the fixture.
    """

    events = read_pflog_file(FIXTURE_PATH, year=2026)

    assert [event.action for event in events] == ["block", "pass", "block", "block"]


def test_read_pflog_file_logs_warning_naming_file_and_count(caplog):
    """Skipped lines are reported once as a warning naming file and count.

    Inputs:
        caplog: pytest log capture fixture.

    Outputs:
        None. Assertions verify the warning content.
    """

    with caplog.at_level(logging.WARNING, logger="soc.pflog"):
        read_pflog_file(FIXTURE_PATH, year=2026)

    warnings = [record.getMessage() for record in caplog.records if record.levelno >= logging.WARNING]
    assert any("1" in message and str(FIXTURE_PATH) in message for message in warnings)


def test_read_pflog_file_raises_for_missing_file(tmp_path):
    """A missing pflog file must raise PflogError.

    Inputs:
        tmp_path: pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies the raised error.
    """

    with pytest.raises(PflogError):
        read_pflog_file(tmp_path / "no-such-pflog.txt")


def test_read_pflog_file_raises_for_directory(tmp_path):
    """A directory in place of a pflog file must raise PflogError.

    Inputs:
        tmp_path: pytest temporary directory fixture.

    Outputs:
        None. Assertion verifies the raised error.
    """

    with pytest.raises(PflogError):
        read_pflog_file(tmp_path)


def test_raw_event_from_pflog_builds_openbsd_pf_raw_event():
    """raw_event_from_pflog should produce an OPENBSD_PF RawEvent.

    Inputs:
        None.

    Outputs:
        None. Assertions verify source, timestamp, and payload.
    """

    event = parse_pflog_line(BLOCK_LINE, year=2026)
    assert event is not None

    raw_event = raw_event_from_pflog(event)

    assert raw_event.source == EventSource.OPENBSD_PF
    assert raw_event.timestamp == datetime(2026, 8, 5, 12, 0, 0, 123456, tzinfo=UTC)
    assert raw_event.payload["action"] == "block"
    assert raw_event.payload["raw_line"] == BLOCK_LINE


def test_raw_event_from_pflog_id_is_deterministic_and_content_addressed():
    """The same line must produce the same ID, a different line a different one.

    Inputs:
        None.

    Outputs:
        None. Assertions verify ID determinism and content addressing.
    """

    first = raw_event_from_pflog(parse_pflog_line(BLOCK_LINE, year=2026))
    second = raw_event_from_pflog(parse_pflog_line(BLOCK_LINE, year=2026))
    other = raw_event_from_pflog(parse_pflog_line(PASS_LINE, year=2026))

    assert first.id == second.id
    assert first.id != other.id
    assert first.id.startswith(f"{EventSource.OPENBSD_PF.value}-")


def test_raw_event_from_pflog_accepts_extra_payload_context():
    """A caller may attach the firewall hostname to the payload.

    Inputs:
        None.

    Outputs:
        None. Assertions verify extra context reaches the payload and
        participates in the content-addressed ID, so the same packet logged by
        two firewalls does not collide.
    """

    event = parse_pflog_line(BLOCK_LINE, year=2026)
    assert event is not None

    plain = raw_event_from_pflog(event)
    with_host = raw_event_from_pflog(event, hostname="fw-01")

    assert with_host.payload["hostname"] == "fw-01"
    assert plain.id != with_host.id
    assert with_host.id == raw_event_from_pflog(event, hostname="fw-01").id
