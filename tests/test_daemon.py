

"""Tests for the polling daemon.

These tests verify the daemon's loop control, resilience, structured logging,
and shutdown behavior without sleeping for real time or installing process-wide
signal handlers except where explicitly under test.
"""

from __future__ import annotations

import json
import signal
from pathlib import Path
from typing import Any

import pytest

from soc.daemon import DaemonConfig, DaemonError, PollingDaemon


class FakeRunResult:
    """Minimal stand-in for PipelineRunResult."""

    def __init__(self, **summary: Any) -> None:
        """Store the summary this result should report."""

        self._summary = summary

    def to_summary(self) -> dict[str, Any]:
        """Return the configured summary."""

        return dict(self._summary)


def _recording_sleep(calls: list[float]):
    """Build a sleep callable that records durations instead of waiting."""

    def _sleep(seconds: float) -> None:
        calls.append(seconds)

    return _sleep


def _config(tmp_path: Path, **overrides: Any) -> DaemonConfig:
    """Build a daemon config writing logs under a temporary directory."""

    values: dict[str, Any] = {
        "poll_interval_seconds": 10,
        "max_cycles": 3,
        "log_dir": tmp_path / "logs",
    }
    values.update(overrides)
    return DaemonConfig(**values)


def test_daemon_runs_exactly_the_configured_number_of_cycles(tmp_path):
    """max_cycles must bound the loop so runs are testable and scriptable."""

    cycles: list[int] = []

    def run_cycle() -> FakeRunResult:
        """Record one cycle."""

        cycles.append(1)
        return FakeRunResult(raw_events=2, candidates=1, errors=[])

    daemon = PollingDaemon(run_cycle=run_cycle, config=_config(tmp_path), sleep=lambda _: None)

    summary = daemon.run()

    assert len(cycles) == 3
    assert summary.cycles_completed == 3
    assert summary.stopped_reason == "max_cycles_reached"


def test_daemon_does_not_sleep_after_the_final_cycle(tmp_path):
    """A daemon about to exit must not wait out one more poll interval."""

    sleeps: list[float] = []
    daemon = PollingDaemon(
        run_cycle=lambda: FakeRunResult(raw_events=0),
        config=_config(tmp_path, max_cycles=3),
        sleep=_recording_sleep(sleeps),
    )

    daemon.run()

    assert sum(sleeps) == pytest.approx(20.0)


def test_daemon_continues_after_a_failing_cycle(tmp_path):
    """One bad cycle must not kill an unattended daemon."""

    attempts: list[int] = []

    def run_cycle() -> FakeRunResult:
        """Fail on the second cycle only."""

        attempts.append(len(attempts) + 1)
        if len(attempts) == 2:
            raise RuntimeError("wazuh unreachable")
        return FakeRunResult(raw_events=1)

    daemon = PollingDaemon(
        run_cycle=run_cycle,
        config=_config(tmp_path, max_cycles=3),
        sleep=lambda _: None,
    )

    summary = daemon.run()

    assert len(attempts) == 3
    assert summary.cycles_completed == 3
    assert summary.cycles_failed == 1
    assert "wazuh unreachable" in summary.errors[0]


def test_daemon_writes_one_structured_log_line_per_cycle(tmp_path):
    """Structured JSON lines are the daemon's only operational record."""

    config = _config(tmp_path, max_cycles=2)
    daemon = PollingDaemon(
        run_cycle=lambda: FakeRunResult(raw_events=4, candidates=2, errors=[]),
        config=config,
        sleep=lambda _: None,
    )

    daemon.run()

    log_lines = [
        json.loads(line)
        for line in (config.log_dir / "daemon.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    cycle_records = [record for record in log_lines if record.get("event") == "cycle_completed"]

    assert len(cycle_records) == 2
    assert cycle_records[0]["cycle"] == 1
    assert cycle_records[0]["raw_events"] == 4
    assert cycle_records[0]["candidates"] == 2
    assert "timestamp" in cycle_records[0]


def test_daemon_logs_a_failing_cycle_with_its_error(tmp_path):
    """A failed cycle must be diagnosable from the log alone."""

    config = _config(tmp_path, max_cycles=1)

    def run_cycle() -> FakeRunResult:
        """Always fail."""

        raise RuntimeError("alerts.json missing")

    daemon = PollingDaemon(run_cycle=run_cycle, config=config, sleep=lambda _: None)

    daemon.run()

    records = [
        json.loads(line)
        for line in (config.log_dir / "daemon.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    failures = [record for record in records if record.get("event") == "cycle_failed"]

    assert len(failures) == 1
    assert "alerts.json missing" in failures[0]["error"]
    assert failures[0]["error_type"] == "RuntimeError"


def test_daemon_stops_when_stop_is_requested_mid_run(tmp_path):
    """A stop request must end the loop at the next safe point."""

    def run_cycle() -> FakeRunResult:
        """Request shutdown from inside the first cycle."""

        daemon.request_stop("test_signal")
        return FakeRunResult(raw_events=1)

    daemon = PollingDaemon(
        run_cycle=run_cycle,
        config=_config(tmp_path, max_cycles=None),
        sleep=lambda _: None,
    )

    summary = daemon.run()

    assert summary.cycles_completed == 1
    assert summary.stopped_reason == "test_signal"


def test_daemon_stops_promptly_while_waiting_between_cycles(tmp_path):
    """Shutdown must not have to wait out a long poll interval."""

    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        """Record the sleep slice and request shutdown on the first one."""

        sleeps.append(seconds)
        daemon.request_stop("sigterm")

    daemon = PollingDaemon(
        run_cycle=lambda: FakeRunResult(raw_events=0),
        config=_config(tmp_path, poll_interval_seconds=600, max_cycles=None),
        sleep=sleep,
    )

    summary = daemon.run()

    assert sum(sleeps) < 600
    assert summary.stopped_reason == "sigterm"


def test_daemon_signal_handler_requests_stop_without_killing_the_process(tmp_path):
    """SIGTERM must trigger graceful shutdown, not an abrupt exit."""

    daemon = PollingDaemon(
        run_cycle=lambda: FakeRunResult(raw_events=0),
        config=_config(tmp_path, max_cycles=None),
        sleep=lambda _: None,
    )

    daemon.handle_shutdown_signal(signal.SIGTERM, None)

    assert daemon.stop_requested is True
    assert daemon.run().cycles_completed == 0


def test_daemon_config_rejects_invalid_values(tmp_path):
    """Invalid daemon settings must fail loudly at construction."""

    with pytest.raises(DaemonError, match="poll_interval_seconds"):
        DaemonConfig(poll_interval_seconds=0, log_dir=tmp_path)

    with pytest.raises(DaemonError, match="max_cycles"):
        DaemonConfig(poll_interval_seconds=10, max_cycles=0, log_dir=tmp_path)


def test_daemon_summary_is_json_safe(tmp_path):
    """The run summary must serialize for the CLI to print."""

    daemon = PollingDaemon(
        run_cycle=lambda: FakeRunResult(raw_events=1),
        config=_config(tmp_path, max_cycles=1),
        sleep=lambda _: None,
    )

    summary = daemon.run().to_summary()

    assert json.loads(json.dumps(summary))["cycles_completed"] == 1
