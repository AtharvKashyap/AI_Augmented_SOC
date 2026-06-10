

"""Command-line runner for the AI_Augmented_SOC pipeline.

This file is intentionally thin. The real workflow lives in `soc.pipeline`.
The CLI only parses arguments, loads settings, constructs the pipeline, runs a
replay source, and prints a JSON summary.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from soc.config import ConfigError, get_settings
from soc.notifier import NotificationDispatcher
from soc.pipeline import PipelineConfig, PipelineError, SOCPipeline


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
        description="Run the AI_Augmented_SOC replay pipeline.",
    )
    replay_group = parser.add_mutually_exclusive_group(required=True)
    replay_group.add_argument(
        "--replay",
        type=Path,
        help="Path to a replay JSON file.",
    )
    replay_group.add_argument(
        "--replay-dir",
        type=Path,
        help="Path to a directory containing replay JSON files.",
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
    except (CliError, ConfigError, PipelineError) as exc:
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
    db_path = args.db or settings.sqlite_db_path
    output_dir = args.output or settings.output_dir
    _validate_replay_args(args)

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
    pipeline = SOCPipeline.with_sqlite_store(
        db_path,
        config=config,
        notifier=notifier,
    )

    if args.replay is not None:
        result = pipeline.run_replay_file(args.replay)
    elif args.replay_dir is not None:
        result = pipeline.run_replay_directory(args.replay_dir)
    else:
        raise CliError("either --replay or --replay-dir is required")

    summary = result.to_summary()
    summary["db_path"] = str(db_path)
    summary["output_dir"] = str(output_dir)
    summary["reports_written"] = [str(path) for path in result.report_paths]
    summary["notifications_enabled"] = args.notify
    summary["dry_run"] = args.dry_run
    return summary


def _validate_replay_args(args: argparse.Namespace) -> None:
    """Validate replay path arguments.

    Inputs:
        args: Parsed argparse namespace.

    Outputs:
        None.

    Raises:
        CliError: If replay path is invalid.
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


if __name__ == "__main__":
    raise SystemExit(main())