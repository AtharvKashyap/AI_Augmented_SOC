"""Command-line runner for the AI_Augmented_SOC pipeline.

This file is intentionally thin. The real workflow lives in `soc.pipeline`.
The CLI only parses arguments, loads settings, constructs the pipeline, runs a
selected event source, and prints a JSON summary.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from soc.config import ConfigError, get_settings
from soc.models import AnalysisSource
from soc.notifier import NotificationDispatcher
from soc.openrouter_client import OpenRouterClient, OpenRouterError
from soc.pipeline import PipelineConfig, PipelineError, SOCPipeline
from soc.triage import TriageEngine
from soc.wazuh_client import WazuhClient, WazuhError


JsonDict = dict[str, Any]


class CliError(RuntimeError):
    """Raised when CLI input or execution is invalid."""


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Inputs:
        None.

    Outputs:
        Configured ArgumentParser.
    """

    parser = argparse.ArgumentParser(
        description="Run the AI_Augmented_SOC pipeline.",
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--replay",
        type=Path,
        help="Path to a replay JSON file.",
    )
    source_group.add_argument(
        "--replay-dir",
        type=Path,
        help="Path to a directory containing replay JSON files.",
    )
    source_group.add_argument(
        "--wazuh",
        action="store_true",
        help="Fetch recent alerts from Wazuh Indexer and process them.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Path to .env file. Defaults to .env.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="SQLite database path. Defaults to SQLITE_DB_PATH from .env.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Report output directory. Defaults to OUTPUT_DIR from .env.",
    )
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Send notifications using configured channels.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use dry-run notifications instead of real delivery.",
    )
    parser.add_argument(
        "--no-reports",
        action="store_true",
        help="Do not write Markdown report files.",
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable deduplication for this run.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Raise immediately on the first pipeline error.",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Force deterministic local triage even when an OpenRouter key is configured.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON summary.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the pipeline CLI.

    Inputs:
        argv: Optional argument list. Defaults to sys.argv.

    Outputs:
        Process exit code.
    """

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        summary = run_from_args(args)
    except (CliError, ConfigError, PipelineError, WazuhError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130

    indent = 2 if args.pretty else None
    print(json.dumps(summary, indent=indent, sort_keys=True))
    return 0


def run_from_args(args: argparse.Namespace) -> JsonDict:
    """Create and run pipeline from parsed CLI args.

    Inputs:
        args: Parsed argparse namespace.

    Outputs:
        JSON-safe summary dictionary.
    """

    settings = get_settings(args.env_file, reload=True)
    db_path = Path(args.db or settings.sqlite_db_path)
    output_dir = Path(args.output or settings.output_dir)
    _validate_source_args(args)

    output_dir.mkdir(parents=True, exist_ok=True)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    config = PipelineConfig(
        output_dir=output_dir,
        write_reports=not args.no_reports,
        send_notifications=args.notify,
        deduplicate=not args.no_dedup,
        fail_fast=args.fail_fast,
    )
    notifier = NotificationDispatcher.from_settings(settings, dry_run=args.dry_run)
    triage_engine = _build_triage_engine(settings, use_llm=not args.no_llm)
    pipeline = SOCPipeline.with_sqlite_store(
        db_path,
        config=config,
        notifier=notifier,
        triage_engine=triage_engine,
    )

    source_mode = _source_mode(args)
    if args.replay is not None:
        result = pipeline.run_replay_file(args.replay)
    elif args.replay_dir is not None:
        result = pipeline.run_replay_directory(args.replay_dir)
    elif args.wazuh:
        wazuh = WazuhClient.from_settings(settings)
        events = wazuh.fetch_recent_events(
            lookback_minutes=settings.wazuh_alert_lookback_minutes,
            min_level=settings.wazuh_min_level,
            limit=settings.wazuh_alert_limit,
        )
        result = pipeline.run_events(events)
    else:
        raise CliError("one source is required: --replay, --replay-dir, or --wazuh")

    summary = result.to_summary()
    summary["source_mode"] = source_mode
    summary["db_path"] = str(db_path)
    summary["output_dir"] = str(output_dir)
    summary["reports_written"] = [str(path) for path in result.report_paths]
    summary["notifications_enabled"] = args.notify
    summary["dry_run"] = args.dry_run
    triage_mode = "llm" if triage_engine.llm_client is not None else "local"
    summary["triage_mode"] = triage_mode
    summary["analysis_sources"] = _count_analysis_sources(result)
    # Only an LLM-mode run can fall back; a local-mode run scored locally by design.
    summary["local_fallbacks"] = (
        summary["analysis_sources"].get(AnalysisSource.LOCAL.value, 0) if triage_mode == "llm" else 0
    )
    return summary


def _build_triage_engine(settings: Any, *, use_llm: bool) -> TriageEngine:
    """Build the triage engine the pipeline should use.

    LLM triage is used only when it is both requested and configured. A missing
    API key is a normal operating mode, not an error: the deterministic local
    engine still produces scores, and the run summary reports which one ran.

    Inputs:
        settings: Application settings object.
        use_llm: Whether LLM-assisted triage is permitted for this run.

    Outputs:
        TriageEngine, with an OpenRouter client attached when available.

    Raises:
        CliError: If LLM triage is configured but the client cannot be built.
    """

    if not use_llm or not str(getattr(settings, "openrouter_api_key", "") or "").strip():
        return TriageEngine()

    try:
        client = OpenRouterClient.from_settings(settings)
    except OpenRouterError as exc:
        raise CliError(f"cannot build OpenRouter client: {exc}") from exc
    return TriageEngine(client, model=getattr(settings, "openrouter_model", None))


def _count_analysis_sources(result: Any) -> JsonDict:
    """Count triage results by what produced them.

    A run configured for LLM triage that quietly degrades to local scoring under
    rate limits looks identical to a healthy run without this count.

    Inputs:
        result: PipelineRunResult from the pipeline.

    Outputs:
        Mapping of analysis source value to count.
    """

    counts: JsonDict = {}
    for item in result.item_results:
        source = item.triage.analysis_source
        key = source.value if hasattr(source, "value") else str(source)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _validate_source_args(args: argparse.Namespace) -> None:
    """Validate source path arguments.

    Inputs:
        args: Parsed argparse namespace.

    Outputs:
        None.

    Raises:
        CliError: If source arguments are invalid.
    """

    if args.replay is not None:
        if not args.replay.exists():
            raise CliError(f"replay file does not exist: {args.replay}")
        if not args.replay.is_file():
            raise CliError(f"replay path is not a file: {args.replay}")
    if args.replay_dir is not None:
        if not args.replay_dir.exists():
            raise CliError(f"replay directory does not exist: {args.replay_dir}")
        if not args.replay_dir.is_dir():
            raise CliError(f"replay path is not a directory: {args.replay_dir}")


def _source_mode(args: argparse.Namespace) -> str:
    """Return the selected source mode name."""

    if args.replay is not None:
        return "replay"
    if args.replay_dir is not None:
        return "replay_dir"
    if args.wazuh:
        return "wazuh"
    raise CliError("one source is required: --replay, --replay-dir, or --wazuh")


if __name__ == "__main__":
    raise SystemExit(main())