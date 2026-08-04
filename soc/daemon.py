

"""Polling daemon for continuous SOC ingestion.

This module runs one pipeline cycle repeatedly on a fixed interval, which is
what turns the one-shot CLI into an unattended service.

Design notes:
    - The daemon knows nothing about Wazuh, Security Onion, or the pipeline. It
      is given a callable that performs one cycle, so it stays trivially
      testable and any event source can drive it.
    - A failing cycle is recorded and the loop continues. An unattended daemon
      that dies because one poll failed is worse than useless: alerts stop being
      processed and nothing says so.
    - Shutdown is cooperative. SIGINT and SIGTERM set a flag, and the loop exits
      at the next safe point rather than mid-cycle, so a run is never left half
      persisted.
    - Waiting between cycles happens in short slices so shutdown does not have
      to wait out a long poll interval.
    - Every cycle appends one JSON line to the log, which is the only
      operational record an unattended process leaves behind.

Reading only new alerts across cycles is the ingestion layer's job, via the
persistent read cursor in `soc.wazuh_client`. Without a cursor store the daemon
would re-read the whole alert file every cycle and rely on deduplication.
"""

from __future__ import annotations

import json
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import FrameType
from typing import Any

from soc.models import utc_now

JsonDict = dict[str, Any]

SHUTDOWN_SIGNALS: tuple[signal.Signals, ...] = (signal.SIGINT, signal.SIGTERM)

SLEEP_SLICE_SECONDS = 1.0
"""Maximum single wait, so a stop request is noticed promptly."""

DAEMON_LOG_FILENAME = "daemon.jsonl"


class DaemonError(ValueError):
    """Raised when daemon configuration or execution is invalid."""


@dataclass(frozen=True, slots=True)
class DaemonConfig:
    """Runtime configuration for the polling daemon.

    Attributes:
        poll_interval_seconds: Seconds to wait between cycles.
        max_cycles: Stop after this many cycles. None runs until stopped, which
            is the normal service mode; a bound makes runs scriptable and
            testable.
        log_dir: Directory receiving the structured JSON-lines log.
    """

    poll_interval_seconds: int = 120
    max_cycles: int | None = None
    log_dir: Path = Path("logs")

    def __post_init__(self) -> None:
        """Validate daemon configuration.

        Inputs:
            None. Uses this object's fields.

        Outputs:
            None.

        Raises:
            DaemonError: If an interval or cycle bound is invalid.
        """

        if self.poll_interval_seconds <= 0:
            raise DaemonError("poll_interval_seconds must be greater than zero")
        if self.max_cycles is not None and self.max_cycles <= 0:
            raise DaemonError("max_cycles must be greater than zero when set")


@dataclass(slots=True)
class DaemonRunSummary:
    """Outcome of one daemon run.

    Attributes:
        cycles_completed: Cycles attempted, including failed ones.
        cycles_failed: Cycles that raised.
        events_processed: Total raw events seen across cycles.
        candidates_created: Total incident candidates produced across cycles.
        errors: Error strings from failed cycles.
        stopped_reason: Why the loop ended.
        started_at: Run start time.
        finished_at: Run end time.
    """

    cycles_completed: int = 0
    cycles_failed: int = 0
    events_processed: int = 0
    candidates_created: int = 0
    errors: list[str] = field(default_factory=list)
    stopped_reason: str = "not_started"
    started_at: datetime | None = None
    finished_at: datetime | None = None

    def to_summary(self) -> JsonDict:
        """Return a JSON-safe summary of the run.

        Inputs:
            None.

        Outputs:
            Summary dictionary suitable for printing or logging.
        """

        return {
            "cycles_completed": self.cycles_completed,
            "cycles_failed": self.cycles_failed,
            "events_processed": self.events_processed,
            "candidates_created": self.candidates_created,
            "errors": list(self.errors),
            "stopped_reason": self.stopped_reason,
            "started_at": _format_time(self.started_at),
            "finished_at": _format_time(self.finished_at),
        }


class PollingDaemon:
    """Run one pipeline cycle repeatedly until stopped."""

    def __init__(
        self,
        *,
        run_cycle: Callable[[], Any],
        config: DaemonConfig | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Initialize the daemon.

        Inputs:
            run_cycle: Callable performing one cycle. Its return value is used
                only for reporting, via `to_summary()` when available.
            config: Optional DaemonConfig.
            sleep: Optional sleep callable. Defaults to time.sleep; tests inject
                a recorder so no real time passes.

        Outputs:
            None.
        """

        self.run_cycle = run_cycle
        self.config = config or DaemonConfig()
        self._sleep = sleep or time.sleep
        self._stop_requested = False
        self._stop_reason: str | None = None

    @property
    def stop_requested(self) -> bool:
        """Return whether shutdown has been requested."""

        return self._stop_requested

    def request_stop(self, reason: str = "stop_requested") -> None:
        """Ask the loop to finish at the next safe point.

        Inputs:
            reason: Short reason recorded in the run summary and log.

        Outputs:
            None.
        """

        self._stop_requested = True
        if self._stop_reason is None:
            self._stop_reason = reason

    def install_signal_handlers(self) -> None:
        """Install cooperative SIGINT/SIGTERM handlers.

        Only the main thread of the main interpreter may install handlers, so
        failures are ignored: a daemon that cannot register a handler should
        still run, it just will not shut down gracefully on a signal.

        Inputs:
            None.

        Outputs:
            None.
        """

        for sig in SHUTDOWN_SIGNALS:
            try:
                signal.signal(sig, self.handle_shutdown_signal)
            except (ValueError, OSError):
                self._log({"event": "signal_handler_unavailable", "signal": sig.name})

    def handle_shutdown_signal(self, signum: int, frame: FrameType | None) -> None:
        """Record a shutdown signal without terminating the process.

        Inputs:
            signum: Signal number received.
            frame: Current stack frame, unused.

        Outputs:
            None.
        """

        del frame
        try:
            name = signal.Signals(signum).name.lower()
        except ValueError:
            name = f"signal_{signum}"
        self.request_stop(name)
        self._log({"event": "shutdown_requested", "signal": name})

    def run(self) -> DaemonRunSummary:
        """Run cycles until stopped, bounded, or interrupted.

        Inputs:
            None.

        Outputs:
            DaemonRunSummary describing the run.
        """

        summary = DaemonRunSummary(started_at=utc_now(), stopped_reason="running")
        self._log(
            {
                "event": "daemon_started",
                "poll_interval_seconds": self.config.poll_interval_seconds,
                "max_cycles": self.config.max_cycles,
            }
        )

        while not self._stop_requested and not self._cycle_limit_reached(summary):
            self._run_one_cycle(summary)

            if self._stop_requested or self._cycle_limit_reached(summary):
                break
            self._wait_between_cycles()

        summary.stopped_reason = self._final_reason(summary)
        summary.finished_at = utc_now()
        self._log({"event": "daemon_stopped", **summary.to_summary()})
        return summary

    def _run_one_cycle(self, summary: DaemonRunSummary) -> None:
        """Execute one cycle and record its outcome.

        Inputs:
            summary: Mutable run summary.

        Outputs:
            None.
        """

        summary.cycles_completed += 1
        cycle_number = summary.cycles_completed

        try:
            result = self.run_cycle()
        except Exception as exc:
            summary.cycles_failed += 1
            summary.errors.append(f"cycle {cycle_number} failed: {exc}")
            self._log(
                {
                    "event": "cycle_failed",
                    "cycle": cycle_number,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                }
            )
            return

        cycle_summary = _result_summary(result)
        summary.events_processed += int(cycle_summary.get("raw_events", 0) or 0)
        summary.candidates_created += int(cycle_summary.get("candidates", 0) or 0)
        self._log({"event": "cycle_completed", "cycle": cycle_number, **cycle_summary})

    def _wait_between_cycles(self) -> None:
        """Wait one poll interval, in slices, so shutdown stays responsive.

        Inputs:
            None.

        Outputs:
            None.
        """

        remaining = float(self.config.poll_interval_seconds)
        while remaining > 0 and not self._stop_requested:
            slice_seconds = min(SLEEP_SLICE_SECONDS, remaining)
            self._sleep(slice_seconds)
            remaining -= slice_seconds

    def _cycle_limit_reached(self, summary: DaemonRunSummary) -> bool:
        """Return whether the configured cycle bound has been reached.

        Inputs:
            summary: Current run summary.

        Outputs:
            True when no further cycles should run.
        """

        return self.config.max_cycles is not None and summary.cycles_completed >= self.config.max_cycles

    def _final_reason(self, summary: DaemonRunSummary) -> str:
        """Determine why the loop ended.

        Inputs:
            summary: Current run summary.

        Outputs:
            Short reason string.
        """

        if self._stop_reason is not None:
            return self._stop_reason
        if self._cycle_limit_reached(summary):
            return "max_cycles_reached"
        return "stopped"

    def _log(self, record: JsonDict) -> None:
        """Append one structured JSON line to the daemon log.

        Logging must never take down the daemon, so write failures are
        swallowed: losing a log line is strictly better than losing ingestion.

        Inputs:
            record: JSON-safe fields to record.

        Outputs:
            None.
        """

        payload = {"timestamp": utc_now().isoformat(), **record}
        try:
            self.config.log_dir.mkdir(parents=True, exist_ok=True)
            with (self.config.log_dir / DAEMON_LOG_FILENAME).open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, default=str, sort_keys=True) + "\n")
        except OSError:
            return


def _result_summary(result: Any) -> JsonDict:
    """Extract a JSON-safe summary from a cycle result.

    Inputs:
        result: Whatever the cycle callable returned.

    Outputs:
        Summary dictionary, empty when the result cannot describe itself.
    """

    to_summary = getattr(result, "to_summary", None)
    if callable(to_summary):
        summary = to_summary()
        if isinstance(summary, dict):
            return summary
    return {}


def _format_time(value: datetime | None) -> str | None:
    """Format a timestamp for summaries.

    Inputs:
        value: Optional timestamp.

    Outputs:
        ISO-8601 string, or None.
    """

    return None if value is None else value.isoformat()
