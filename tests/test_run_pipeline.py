"""Tests for the run_pipeline CLI wrapper.

The CLI should stay thin: parse arguments, construct the pipeline, run a selected
event source, and print a JSON summary. These tests mock settings, pipeline
construction, and Wazuh clients so no real database, LLM, SMTP, Slack, or Wazuh
calls are required.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import run_pipeline
from run_pipeline import CliError, build_parser, main, run_from_args
from soc.config import ConfigError
from soc.pipeline import PipelineError
from soc.wazuh_client import WazuhError


@dataclass(slots=True)
class FakeSettings:
    """Minimal settings object needed by run_pipeline."""

    sqlite_db_path: Path
    output_dir: Path
    email_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    email_from: str = ""
    email_to: str = ""
    email_use_tls: bool = True
    slack_webhook_url: str = ""
    wazuh_alert_lookback_minutes: int = 5
    wazuh_min_level: int = 7
    wazuh_alert_limit: int = 100


@dataclass(slots=True)
class FakePipelineConfig:
    """Fake pipeline config that records CLI-derived values."""

    output_dir: Path
    write_reports: bool = True
    send_notifications: bool = False
    deduplicate: bool = True
    fail_fast: bool = False


@dataclass(slots=True)
class FakeRunResult:
    """Fake pipeline run result."""

    source_type: str
    source_path: Path | None
    report_paths: list[Path]

    def to_summary(self) -> dict[str, Any]:
        """Return deterministic summary."""

        return {
            "raw_events": 1,
            "normalized_alerts": 1,
            "accepted_alerts": 1,
            "candidates": 1,
            "reports": len(self.report_paths),
            "errors": [],
            "source_type": self.source_type,
            "source_path": str(self.source_path) if self.source_path is not None else None,
        }


class FakeNotifierDispatcher:
    """Fake NotificationDispatcher factory target."""

    calls: list[dict[str, Any]] = []

    @classmethod
    def from_settings(cls, settings: FakeSettings, *, dry_run: bool = False) -> FakeNotifierDispatcher:
        """Record notifier construction."""

        cls.calls.append({"settings": settings, "dry_run": dry_run})
        return cls()


class FakeSOCPipeline:
    """Fake SOCPipeline factory target."""

    created: list[dict[str, Any]] = []
    last_instance: FakeSOCPipeline | None = None

    def __init__(self, db_path: Path, config: FakePipelineConfig, notifier: FakeNotifierDispatcher) -> None:
        """Initialize fake pipeline."""

        self.db_path = db_path
        self.config = config
        self.notifier = notifier
        self.replay_file_calls: list[Path] = []
        self.replay_directory_calls: list[Path] = []
        self.run_events_calls: list[list[Any]] = []
        FakeSOCPipeline.last_instance = self

    @classmethod
    def with_sqlite_store(
        cls,
        db_path: Path,
        *,
        config: FakePipelineConfig,
        notifier: FakeNotifierDispatcher,
    ) -> FakeSOCPipeline:
        """Record pipeline construction and return fake instance."""

        cls.created.append({"db_path": db_path, "config": config, "notifier": notifier})
        return cls(db_path, config, notifier)

    def run_replay_file(self, path: Path) -> FakeRunResult:
        """Record replay file call."""

        self.replay_file_calls.append(path)
        return FakeRunResult("file", path, [self.config.output_dir / "candidate-001.md"])

    def run_replay_directory(self, path: Path) -> FakeRunResult:
        """Record replay directory call."""

        self.replay_directory_calls.append(path)
        return FakeRunResult("directory", path, [self.config.output_dir / "candidate-001.md"])

    def run_events(self, events: list[Any]) -> FakeRunResult:
        """Record direct event execution call."""

        self.run_events_calls.append(events)
        return FakeRunResult("wazuh", None, [self.config.output_dir / "candidate-001.md"])


class FakeWazuhClient:
    """Fake WazuhClient factory target."""

    settings_calls: list[FakeSettings] = []
    last_instance: FakeWazuhClient | None = None
    events_to_return: list[Any] = [{"id": "wazuh-event-001"}]

    def __init__(self) -> None:
        """Initialize fake Wazuh client."""

        self.fetch_calls: list[dict[str, int]] = []
        FakeWazuhClient.last_instance = self

    @classmethod
    def from_settings(cls, settings: FakeSettings) -> FakeWazuhClient:
        """Record settings used to build Wazuh client."""

        cls.settings_calls.append(settings)
        return cls()

    def fetch_recent_events(
        self,
        *,
        lookback_minutes: int,
        min_level: int,
        limit: int,
    ) -> list[Any]:
        """Return fake Wazuh events."""

        self.fetch_calls.append(
            {
                "lookback_minutes": lookback_minutes,
                "min_level": min_level,
                "limit": limit,
            }
        )
        return self.events_to_return


def _reset_fakes() -> None:
    """Reset fake class call history."""

    FakeNotifierDispatcher.calls.clear()
    FakeSOCPipeline.created.clear()
    FakeSOCPipeline.last_instance = None
    FakeWazuhClient.settings_calls.clear()
    FakeWazuhClient.last_instance = None
    FakeWazuhClient.events_to_return = [{"id": "wazuh-event-001"}]


def _settings(tmp_path: Path) -> FakeSettings:
    """Build fake settings."""

    return FakeSettings(
        sqlite_db_path=tmp_path / "data" / "soc.db",
        output_dir=tmp_path / "output",
    )


def _patch_cli_dependencies(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeSettings:
    """Patch run_pipeline dependencies with fakes."""

    _reset_fakes()
    settings = _settings(tmp_path)
    monkeypatch.setattr(run_pipeline, "PipelineConfig", FakePipelineConfig)
    monkeypatch.setattr(run_pipeline, "NotificationDispatcher", FakeNotifierDispatcher)
    monkeypatch.setattr(run_pipeline, "SOCPipeline", FakeSOCPipeline)
    monkeypatch.setattr(run_pipeline, "WazuhClient", FakeWazuhClient)
    monkeypatch.setattr(run_pipeline, "get_settings", lambda env_file, reload: settings)
    return settings


def _args(**overrides: Any) -> argparse.Namespace:
    """Build default argparse namespace for run_from_args tests."""

    values = {
        "replay": None,
        "replay_dir": None,
        "wazuh": False,
        "env_file": Path(".env"),
        "db": None,
        "output": None,
        "notify": False,
        "dry_run": False,
        "no_reports": False,
        "no_dedup": False,
        "fail_fast": False,
        "pretty": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_build_parser_accepts_replay_file(tmp_path):
    """Parser should accept replay file mode."""

    replay_path = tmp_path / "replay.json"
    args = build_parser().parse_args(["--replay", str(replay_path)])

    assert args.replay == replay_path
    assert args.replay_dir is None
    assert args.wazuh is False
    assert args.env_file == Path(".env")
    assert args.notify is False
    assert args.dry_run is False


def test_build_parser_accepts_replay_directory(tmp_path):
    """Parser should accept replay directory mode."""

    replay_dir = tmp_path / "replay"
    args = build_parser().parse_args(["--replay-dir", str(replay_dir), "--notify", "--dry-run"])

    assert args.replay is None
    assert args.replay_dir == replay_dir
    assert args.wazuh is False
    assert args.notify is True
    assert args.dry_run is True


def test_build_parser_accepts_wazuh_mode():
    """Parser should accept Wazuh mode."""

    args = build_parser().parse_args(["--wazuh"])

    assert args.replay is None
    assert args.replay_dir is None
    assert args.wazuh is True


def test_build_parser_requires_one_source():
    """Parser should require exactly one source."""

    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_build_parser_rejects_multiple_sources(tmp_path):
    """Parser should reject multiple source modes together."""

    with pytest.raises(SystemExit):
        build_parser().parse_args(
            [
                "--replay",
                str(tmp_path / "replay.json"),
                "--replay-dir",
                str(tmp_path / "replay"),
            ]
        )
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            [
                "--replay",
                str(tmp_path / "replay.json"),
                "--wazuh",
            ]
        )


def test_run_from_args_runs_replay_file_with_defaults(monkeypatch, tmp_path):
    """run_from_args should construct pipeline and run replay file."""

    settings = _patch_cli_dependencies(monkeypatch, tmp_path)
    replay_path = tmp_path / "replay.json"
    replay_path.write_text("[]", encoding="utf-8")

    summary = run_from_args(_args(replay=replay_path))

    assert summary["source_type"] == "file"
    assert summary["source_mode"] == "replay"
    assert summary["source_path"] == str(replay_path)
    assert summary["db_path"] == str(settings.sqlite_db_path)
    assert summary["output_dir"] == str(settings.output_dir)
    assert summary["reports_written"] == [str(settings.output_dir / "candidate-001.md")]
    assert summary["notifications_enabled"] is False
    assert summary["dry_run"] is False
    assert FakeNotifierDispatcher.calls == [{"settings": settings, "dry_run": False}]
    created = FakeSOCPipeline.created[0]
    assert created["db_path"] == settings.sqlite_db_path
    assert created["config"].output_dir == settings.output_dir
    assert created["config"].write_reports is True
    assert created["config"].send_notifications is False
    assert created["config"].deduplicate is True
    assert created["config"].fail_fast is False
    assert FakeSOCPipeline.last_instance is not None
    assert FakeSOCPipeline.last_instance.replay_file_calls == [replay_path]


def test_run_from_args_runs_replay_directory(monkeypatch, tmp_path):
    """run_from_args should run replay directory mode."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    replay_dir = tmp_path / "replay"
    replay_dir.mkdir()

    summary = run_from_args(_args(replay_dir=replay_dir))

    assert summary["source_type"] == "directory"
    assert summary["source_mode"] == "replay_dir"
    assert summary["source_path"] == str(replay_dir)
    assert FakeSOCPipeline.last_instance is not None
    assert FakeSOCPipeline.last_instance.replay_directory_calls == [replay_dir]


def test_run_from_args_runs_wazuh_mode(monkeypatch, tmp_path):
    """run_from_args should fetch Wazuh events and run them through the pipeline."""

    settings = _patch_cli_dependencies(monkeypatch, tmp_path)
    settings.wazuh_alert_lookback_minutes = 15
    settings.wazuh_min_level = 10
    settings.wazuh_alert_limit = 250
    FakeWazuhClient.events_to_return = [{"id": "wazuh-event-001"}]

    summary = run_from_args(_args(wazuh=True))

    assert summary["source_type"] == "wazuh"
    assert summary["source_mode"] == "wazuh"
    assert summary["source_path"] is None
    assert summary["reports_written"] == [str(settings.output_dir / "candidate-001.md")]
    assert FakeWazuhClient.settings_calls == [settings]
    assert FakeWazuhClient.last_instance is not None
    assert FakeWazuhClient.last_instance.fetch_calls == [
        {
            "lookback_minutes": 15,
            "min_level": 10,
            "limit": 250,
        }
    ]
    assert FakeSOCPipeline.last_instance is not None
    assert FakeSOCPipeline.last_instance.run_events_calls == [[{"id": "wazuh-event-001"}]]


def test_run_from_args_honors_cli_overrides(monkeypatch, tmp_path):
    """run_from_args should honor db/output/report/dedup/fail-fast flags."""

    settings = _patch_cli_dependencies(monkeypatch, tmp_path)
    replay_path = tmp_path / "replay.json"
    replay_path.write_text("[]", encoding="utf-8")
    custom_db = tmp_path / "custom" / "custom.db"
    custom_output = tmp_path / "custom-output"

    summary = run_from_args(
        _args(
            replay=replay_path,
            db=custom_db,
            output=custom_output,
            notify=True,
            dry_run=True,
            no_reports=True,
            no_dedup=True,
            fail_fast=True,
        )
    )

    assert summary["db_path"] == str(custom_db)
    assert summary["output_dir"] == str(custom_output)
    assert summary["notifications_enabled"] is True
    assert summary["dry_run"] is True
    assert custom_db.parent.exists()
    assert custom_output.exists()
    assert FakeNotifierDispatcher.calls == [{"settings": settings, "dry_run": True}]
    created = FakeSOCPipeline.created[0]
    assert created["config"].output_dir == custom_output
    assert created["config"].write_reports is False
    assert created["config"].send_notifications is True
    assert created["config"].deduplicate is False
    assert created["config"].fail_fast is True


def test_run_from_args_rejects_missing_replay_file(monkeypatch, tmp_path):
    """run_from_args should reject missing replay files."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    missing_path = tmp_path / "missing.json"

    with pytest.raises(CliError, match="replay file does not exist"):
        run_from_args(_args(replay=missing_path))


def test_run_from_args_rejects_replay_path_that_is_directory(monkeypatch, tmp_path):
    """run_from_args should reject --replay when path is a directory."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    replay_path = tmp_path / "not-file"
    replay_path.mkdir()

    with pytest.raises(CliError, match="replay path is not a file"):
        run_from_args(_args(replay=replay_path))


def test_run_from_args_rejects_missing_replay_directory(monkeypatch, tmp_path):
    """run_from_args should reject missing replay directories."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    missing_dir = tmp_path / "missing-dir"

    with pytest.raises(CliError, match="replay directory does not exist"):
        run_from_args(_args(replay_dir=missing_dir))


def test_run_from_args_rejects_replay_dir_that_is_file(monkeypatch, tmp_path):
    """run_from_args should reject --replay-dir when path is a file."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    replay_dir = tmp_path / "not-dir.json"
    replay_dir.write_text("[]", encoding="utf-8")

    with pytest.raises(CliError, match="replay path is not a directory"):
        run_from_args(_args(replay_dir=replay_dir))


def test_main_prints_json_summary(monkeypatch, tmp_path, capsys):
    """main should print compact JSON summary and return zero."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    replay_path = tmp_path / "replay.json"
    replay_path.write_text("[]", encoding="utf-8")

    exit_code = main(["--replay", str(replay_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    summary = json.loads(captured.out)
    assert summary["source_type"] == "file"
    assert captured.err == ""


def test_main_pretty_prints_json_summary(monkeypatch, tmp_path, capsys):
    """main should pretty-print JSON when --pretty is passed."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    replay_path = tmp_path / "replay.json"
    replay_path.write_text("[]", encoding="utf-8")

    exit_code = main(["--replay", str(replay_path), "--pretty"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "\n  \"" in captured.out
    assert json.loads(captured.out)["source_type"] == "file"


def test_main_returns_one_for_cli_error(monkeypatch, tmp_path, capsys):
    """main should return one and write stderr for CliError."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    missing_path = tmp_path / "missing.json"

    exit_code = main(["--replay", str(missing_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error: replay file does not exist" in captured.err
    assert captured.out == ""


def test_main_returns_one_for_config_error(monkeypatch, tmp_path, capsys):
    """main should return one for ConfigError."""

    replay_path = tmp_path / "replay.json"
    replay_path.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        run_pipeline,
        "get_settings",
        lambda env_file, reload: (_ for _ in ()).throw(ConfigError("bad config")),
    )

    exit_code = main(["--replay", str(replay_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error: bad config" in captured.err


def test_main_returns_one_for_pipeline_error(monkeypatch, tmp_path, capsys):
    """main should return one for PipelineError."""

    replay_path = tmp_path / "replay.json"
    replay_path.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        run_pipeline,
        "run_from_args",
        lambda args: (_ for _ in ()).throw(PipelineError("pipeline failed")),
    )

    exit_code = main(["--replay", str(replay_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error: pipeline failed" in captured.err


def test_main_returns_one_for_wazuh_error(monkeypatch, tmp_path, capsys):
    """main should return one for WazuhError."""

    monkeypatch.setattr(
        run_pipeline,
        "run_from_args",
        lambda args: (_ for _ in ()).throw(WazuhError("wazuh failed")),
    )

    exit_code = main(["--wazuh"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error: wazuh failed" in captured.err


def test_main_returns_130_for_keyboard_interrupt(monkeypatch, tmp_path, capsys):
    """main should return 130 for KeyboardInterrupt."""

    replay_path = tmp_path / "replay.json"
    replay_path.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        run_pipeline,
        "run_from_args",
        lambda args: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    exit_code = main(["--replay", str(replay_path)])

    captured = capsys.readouterr()
    assert exit_code == 130
    assert "error: interrupted" in captured.err