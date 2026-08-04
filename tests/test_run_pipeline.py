"""Tests for the run_pipeline CLI wrapper.

The CLI should stay thin: parse arguments, construct the pipeline, run a selected
event source, and print a JSON summary. These tests mock settings, pipeline
construction, and Wazuh clients so no real database, LLM, SMTP, Slack, or Wazuh
calls are required.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path
from typing import Any

import pytest

import run_pipeline
from run_pipeline import CliError, build_parser, main, run_from_args
from soc.config import ConfigError
from soc.models import AnalysisSource, FalsePositiveLikelihood, TriageAction, TriageResult
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
    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "vendor/model-x"
    openrouter_site_url: str = ""
    openrouter_app_name: str = "AI_Augmented_SOC"
    poll_interval_seconds: int = 120
    log_dir: Path = Path("logs")


@dataclass(slots=True)
class FakeStore:
    """Fake store recording schema initialization."""

    db_path: Path
    initialize_calls: int = 0

    def initialize(self) -> None:
        """Record a schema initialization call."""

        self.initialize_calls += 1


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
    item_results: list[Any] = field(default_factory=list)

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

    def __init__(
        self,
        db_path: Path,
        config: FakePipelineConfig,
        notifier: FakeNotifierDispatcher,
        triage_engine: Any = None,
    ) -> None:
        """Initialize fake pipeline."""

        self.db_path = db_path
        self.config = config
        self.notifier = notifier
        self.triage_engine = triage_engine
        self.store = FakeStore(db_path)
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
        triage_engine: Any = None,
    ) -> FakeSOCPipeline:
        """Record pipeline construction and return fake instance."""

        cls.created.append(
            {
                "db_path": db_path,
                "config": config,
                "notifier": notifier,
                "triage_engine": triage_engine,
            }
        )
        return cls(db_path, config, notifier, triage_engine)

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


class FakeSecurityOnionClient:
    """Fake SecurityOnionClient factory target."""

    settings_calls: list[FakeSettings] = []
    last_instance: FakeSecurityOnionClient | None = None
    events_to_return: list[Any] = [{"id": "so-event-001"}]

    def __init__(self) -> None:
        """Initialize fake Security Onion client."""

        self.fetch_calls = 0
        FakeSecurityOnionClient.last_instance = self

    @classmethod
    def from_settings(cls, settings: FakeSettings) -> FakeSecurityOnionClient:
        """Record settings used to build the client."""

        cls.settings_calls.append(settings)
        return cls()

    def fetch_recent_events(self) -> list[Any]:
        """Return fake Security Onion events."""

        self.fetch_calls += 1
        return list(FakeSecurityOnionClient.events_to_return)


class FakeWazuhClient:
    """Fake WazuhClient factory target."""

    settings_calls: list[FakeSettings] = []
    last_instance: FakeWazuhClient | None = None
    events_to_return: list[Any] = [{"id": "wazuh-event-001"}]

    def __init__(self) -> None:
        """Initialize fake Wazuh client."""

        self.fetch_calls: list[dict[str, int]] = []
        FakeWazuhClient.last_instance = self

    cursor_stores: list[Any] = []

    @classmethod
    def from_settings(cls, settings: FakeSettings, *, cursor_store: Any = None) -> FakeWazuhClient:
        """Record settings and cursor store used to build Wazuh client."""

        cls.settings_calls.append(settings)
        cls.cursor_stores.append(cursor_store)
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

    FakeSecurityOnionClient.settings_calls.clear()
    FakeSecurityOnionClient.last_instance = None

    FakeNotifierDispatcher.calls.clear()
    FakeSOCPipeline.created.clear()
    FakeSOCPipeline.last_instance = None
    FakeWazuhClient.settings_calls.clear()
    FakeWazuhClient.cursor_stores.clear()
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
    settings.log_dir = tmp_path / "logs"
    monkeypatch.setattr(run_pipeline, "PipelineConfig", FakePipelineConfig)
    monkeypatch.setattr(run_pipeline, "NotificationDispatcher", FakeNotifierDispatcher)
    monkeypatch.setattr(run_pipeline, "SOCPipeline", FakeSOCPipeline)
    monkeypatch.setattr(run_pipeline, "WazuhClient", FakeWazuhClient)
    monkeypatch.setattr(run_pipeline, "SecurityOnionClient", FakeSecurityOnionClient)
    monkeypatch.setattr(run_pipeline, "get_settings", lambda env_file, reload: settings)
    # Daemon cycles must not spend real wall-clock time in CI.
    monkeypatch.setattr("soc.daemon.time.sleep", lambda _seconds: None)
    return settings


def _args(**overrides: Any) -> argparse.Namespace:
    """Build default argparse namespace for run_from_args tests."""

    values = {
        "replay": None,
        "replay_dir": None,
        "wazuh": False,
        "security_onion": False,
        "env_file": Path(".env"),
        "db": None,
        "output": None,
        "notify": False,
        "dry_run": False,
        "no_reports": False,
        "no_dedup": False,
        "fail_fast": False,
        "no_llm": False,
        "daemon": False,
        "poll_interval": None,
        "max_cycles": None,
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

@dataclass(slots=True)
class FakeOpenRouterClient:
    """Fake OpenRouter client factory target."""

    settings: Any

    @classmethod
    def from_settings(cls, settings: Any, *, model: str | None = None) -> FakeOpenRouterClient:
        """Record settings used to build the client."""

        return cls(settings=settings)


def _triage_result(analysis_source: AnalysisSource) -> TriageResult:
    """Build a triage result with a chosen analysis source."""

    return TriageResult(
        id=f"triage-{analysis_source.value}",
        target_id="candidate-001",
        target_type="incident_candidate",
        score=5,
        fp_likelihood=FalsePositiveLikelihood.MEDIUM,
        classification="needs_analyst_review",
        action=TriageAction.QUEUE_REVIEW,
        summary="Review",
        analysis_source=analysis_source,
    )


def test_build_parser_accepts_no_llm_flag(tmp_path):
    """The CLI must be able to force deterministic local triage."""

    replay_file = tmp_path / "replay.json"
    replay_file.write_text("[]", encoding="utf-8")

    args = build_parser().parse_args(["--replay", str(replay_file), "--no-llm"])

    assert args.no_llm is True


def test_run_from_args_uses_llm_triage_when_api_key_is_configured(monkeypatch, tmp_path):
    """A configured OpenRouter key must actually reach the triage engine."""

    settings = _patch_cli_dependencies(monkeypatch, tmp_path)
    settings.openrouter_api_key = "test-key"
    monkeypatch.setattr(run_pipeline, "OpenRouterClient", FakeOpenRouterClient)
    replay_file = tmp_path / "replay.json"
    replay_file.write_text("[]", encoding="utf-8")

    summary = run_from_args(_args(replay=replay_file))

    engine = FakeSOCPipeline.created[0]["triage_engine"]
    assert isinstance(engine.llm_client, FakeOpenRouterClient)
    assert summary["triage_mode"] == "llm"


def test_run_from_args_falls_back_to_local_triage_without_api_key(monkeypatch, tmp_path):
    """With no key configured, triage must be local and must say so."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    replay_file = tmp_path / "replay.json"
    replay_file.write_text("[]", encoding="utf-8")

    summary = run_from_args(_args(replay=replay_file))

    engine = FakeSOCPipeline.created[0]["triage_engine"]
    assert engine.llm_client is None
    assert summary["triage_mode"] == "local"


def test_run_from_args_no_llm_flag_overrides_configured_api_key(monkeypatch, tmp_path):
    """--no-llm must win over a configured key so runs can be forced offline."""

    settings = _patch_cli_dependencies(monkeypatch, tmp_path)
    settings.openrouter_api_key = "test-key"
    monkeypatch.setattr(run_pipeline, "OpenRouterClient", FakeOpenRouterClient)
    replay_file = tmp_path / "replay.json"
    replay_file.write_text("[]", encoding="utf-8")

    summary = run_from_args(_args(replay=replay_file, no_llm=True))

    assert FakeSOCPipeline.created[0]["triage_engine"].llm_client is None
    assert summary["triage_mode"] == "local"


def test_run_from_args_summary_counts_analysis_sources(monkeypatch, tmp_path):
    """Silent degradation to local scoring must be visible in the summary."""

    settings = _patch_cli_dependencies(monkeypatch, tmp_path)
    settings.openrouter_api_key = "test-key"
    monkeypatch.setattr(run_pipeline, "OpenRouterClient", FakeOpenRouterClient)

    class _MixedPipeline(FakeSOCPipeline):
        """Fake pipeline returning one LLM-scored and two local-scored items."""

        def run_replay_file(self, path: Path) -> FakeRunResult:
            """Return a run result with mixed triage provenance."""

            items = [
                _Item(_triage_result(AnalysisSource.LLM)),
                _Item(_triage_result(AnalysisSource.LOCAL)),
                _Item(_triage_result(AnalysisSource.LOCAL)),
            ]
            return FakeRunResult("file", path, [], items)

    monkeypatch.setattr(run_pipeline, "SOCPipeline", _MixedPipeline)
    replay_file = tmp_path / "replay.json"
    replay_file.write_text("[]", encoding="utf-8")

    summary = run_from_args(_args(replay=replay_file))

    assert summary["analysis_sources"] == {"llm": 1, "local": 2}
    assert summary["local_fallbacks"] == 2


@dataclass(slots=True)
class _Item:
    """Minimal stand-in for PipelineItemResult carrying only triage."""

    triage: TriageResult


def test_run_from_args_reports_no_fallbacks_when_llm_was_never_used(monkeypatch, tmp_path):
    """A run that never intended to use an LLM has not "fallen back" to anything."""

    _patch_cli_dependencies(monkeypatch, tmp_path)

    class _LocalOnlyPipeline(FakeSOCPipeline):
        """Fake pipeline returning locally scored items."""

        def run_replay_file(self, path: Path) -> FakeRunResult:
            """Return a run result with local triage provenance."""

            return FakeRunResult("file", path, [], [_Item(_triage_result(AnalysisSource.LOCAL))])

    monkeypatch.setattr(run_pipeline, "SOCPipeline", _LocalOnlyPipeline)
    replay_file = tmp_path / "replay.json"
    replay_file.write_text("[]", encoding="utf-8")

    summary = run_from_args(_args(replay=replay_file))

    assert summary["triage_mode"] == "local"
    assert summary["analysis_sources"] == {"local": 1}
    assert summary["local_fallbacks"] == 0


def test_build_parser_accepts_daemon_flags(tmp_path):
    """The CLI must expose the polling loop and a way to bound it."""

    args = build_parser().parse_args(
        ["--wazuh", "--daemon", "--poll-interval", "30", "--max-cycles", "2"]
    )

    assert args.daemon is True
    assert args.poll_interval == 30
    assert args.max_cycles == 2


def test_run_from_args_daemon_mode_runs_bounded_cycles(monkeypatch, tmp_path):
    """Daemon mode must run the pipeline once per cycle and report the loop."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    replay_file = tmp_path / "replay.json"
    replay_file.write_text("[]", encoding="utf-8")

    summary = run_from_args(
        _args(replay=replay_file, daemon=True, poll_interval=1, max_cycles=2)
    )

    assert summary["cycles_completed"] == 2
    assert summary["stopped_reason"] == "max_cycles_reached"
    assert len(FakeSOCPipeline.last_instance.replay_file_calls) == 2
    assert summary["source_mode"] == "replay"


def test_run_from_args_daemon_mode_builds_pipeline_only_once(monkeypatch, tmp_path):
    """Rebuilding the pipeline per cycle would discard dedup and cursor state."""

    _patch_cli_dependencies(monkeypatch, tmp_path)
    replay_file = tmp_path / "replay.json"
    replay_file.write_text("[]", encoding="utf-8")

    run_from_args(_args(replay=replay_file, daemon=True, poll_interval=1, max_cycles=3))

    assert len(FakeSOCPipeline.created) == 1


def test_run_from_args_daemon_wazuh_mode_threads_the_cursor_store(monkeypatch, tmp_path):
    """Without a cursor store the daemon would rescan the whole alert file."""

    _patch_cli_dependencies(monkeypatch, tmp_path)

    run_from_args(_args(wazuh=True, daemon=True, poll_interval=1, max_cycles=2))

    assert FakeWazuhClient.cursor_stores
    assert FakeWazuhClient.cursor_stores[0] == FakeSOCPipeline.last_instance.store


def test_run_from_args_single_run_wazuh_mode_uses_no_cursor_store(monkeypatch, tmp_path):
    """A one-shot run must keep reading the whole file, as before."""

    _patch_cli_dependencies(monkeypatch, tmp_path)

    run_from_args(_args(wazuh=True))

    assert FakeWazuhClient.cursor_stores == [None]


def test_run_from_args_daemon_uses_settings_poll_interval_by_default(monkeypatch, tmp_path):
    """The documented POLL_INTERVAL_SECONDS setting must actually be used."""

    settings = _patch_cli_dependencies(monkeypatch, tmp_path)
    settings.poll_interval_seconds = 77
    captured: dict[str, Any] = {}

    real_daemon_config = run_pipeline.DaemonConfig

    def _capture(**kwargs: Any) -> Any:
        """Record the daemon config the CLI built."""

        captured.update(kwargs)
        return real_daemon_config(**kwargs)

    monkeypatch.setattr(run_pipeline, "DaemonConfig", _capture)
    replay_file = tmp_path / "replay.json"
    replay_file.write_text("[]", encoding="utf-8")

    run_from_args(_args(replay=replay_file, daemon=True, max_cycles=1))

    assert captured["poll_interval_seconds"] == 77


def _write_env_file(tmp_path: Path, alerts_path: Path) -> Path:
    """Write a real .env file for end-to-end CLI tests."""

    env_file = tmp_path / ".env.test"
    env_file.write_text(
        "\n".join(
            [
                "WAZUH_ALERT_SOURCE=json_logs",
                f"WAZUH_ALERT_JSON_PATH={alerts_path}",
                "WAZUH_ALERT_LOOKBACK_MINUTES=60",
                "WAZUH_MIN_LEVEL=0",
                "WAZUH_ALERT_LIMIT=50",
                f"SQLITE_DB_PATH={tmp_path / 'soc.db'}",
                f"OUTPUT_DIR={tmp_path / 'out'}",
                f"LOG_DIR={tmp_path / 'logs'}",
                "POLL_INTERVAL_SECONDS=1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return env_file


def _write_live_alert(alerts_path: Path, alert_id: str, *, append: bool = False) -> None:
    """Append or write one realistic Wazuh alert line."""

    from datetime import datetime

    record = {
        "id": alert_id,
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        "rule": {"level": 10, "description": "Suspicious authentication", "groups": ["sshd"]},
        "agent": {"id": "001", "name": "endpoint-01", "ip": "10.0.1.42"},
        "data": {"srcip": "203.0.113.10", "dstuser": "root"},
        "full_log": "sshd: Failed password for root from 203.0.113.10",
    }
    mode = "a" if append else "w"
    with alerts_path.open(mode, encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def test_wazuh_daemon_mode_runs_end_to_end_with_real_components(monkeypatch, tmp_path):
    """Daemon + cursor must work against a real store, not just against fakes.

    This exercises the real SQLiteStore, alerts.json reader, cursor, pipeline,
    and report writer. A fake store cannot catch ordering bugs such as reading
    the cursor table before the schema exists.

    Inputs:
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify a clean cycle that processed the alert.
    """

    monkeypatch.setattr("soc.daemon.time.sleep", lambda _seconds: None)
    alerts_path = tmp_path / "alerts.json"
    _write_live_alert(alerts_path, "live-001")
    env_file = _write_env_file(tmp_path, alerts_path)

    summary = run_from_args(
        _args(wazuh=True, daemon=True, env_file=env_file, poll_interval=1, max_cycles=1, no_llm=True)
    )

    assert summary["errors"] == []
    assert summary["cycles_failed"] == 0
    assert summary["events_processed"] == 1
    assert summary["candidates_created"] == 1


def test_wazuh_daemon_mode_processes_each_alert_exactly_once(monkeypatch, tmp_path):
    """The read cursor must stop the daemon reprocessing the whole file.

    Inputs:
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory fixture.

    Outputs:
        None. Assertions verify two cycles see two distinct alerts.
    """

    monkeypatch.setattr("soc.daemon.time.sleep", lambda _seconds: None)
    alerts_path = tmp_path / "alerts.json"
    _write_live_alert(alerts_path, "live-001")
    env_file = _write_env_file(tmp_path, alerts_path)

    first = run_from_args(
        _args(wazuh=True, daemon=True, env_file=env_file, poll_interval=1, max_cycles=1, no_llm=True)
    )
    _write_live_alert(alerts_path, "live-002", append=True)
    second = run_from_args(
        _args(wazuh=True, daemon=True, env_file=env_file, poll_interval=1, max_cycles=1, no_llm=True)
    )

    assert first["events_processed"] == 1
    assert second["events_processed"] == 1
    assert second["cycles_failed"] == 0


def test_build_parser_accepts_security_onion_source():
    """Security Onion must be selectable as an ingestion source."""

    args = build_parser().parse_args(["--security-onion"])

    assert args.security_onion is True


def test_build_parser_rejects_security_onion_combined_with_wazuh():
    """Sources stay mutually exclusive so one run has one provenance."""

    with pytest.raises(SystemExit):
        build_parser().parse_args(["--wazuh", "--security-onion"])


def test_run_from_args_runs_security_onion_mode(monkeypatch, tmp_path):
    """Security Onion mode must fetch events and run them through the pipeline."""

    settings = _patch_cli_dependencies(monkeypatch, tmp_path)

    summary = run_from_args(_args(security_onion=True))

    assert FakeSecurityOnionClient.settings_calls == [settings]
    assert FakeSecurityOnionClient.last_instance.fetch_calls == 1
    assert FakeSOCPipeline.last_instance.run_events_calls == [[{"id": "so-event-001"}]]
    assert summary["source_mode"] == "security_onion"


def test_run_from_args_security_onion_daemon_builds_client_once(monkeypatch, tmp_path):
    """The client is reused across cycles so its bearer token survives."""

    _patch_cli_dependencies(monkeypatch, tmp_path)

    run_from_args(_args(security_onion=True, daemon=True, poll_interval=1, max_cycles=3))

    assert len(FakeSecurityOnionClient.settings_calls) == 1
    assert FakeSecurityOnionClient.last_instance.fetch_calls == 3
