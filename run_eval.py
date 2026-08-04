"""Command-line runner for the triage evaluation harness.

Scores the labeled set and reports quality metrics. The local half needs no API
key, so it can run in CI on every push; pass --llm to evaluate model-assisted
triage instead, which does need a key.

Exit code 1 when a threshold is unmet, so this can gate a build.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from soc.config import ConfigError, get_settings
from soc.evaluation import (
    LABELED_SET_DIR,
    EvaluationError,
    EvaluationThresholds,
    evaluate_cases,
    load_labeled_cases,
)
from soc.openrouter_client import OpenRouterClient, OpenRouterError
from soc.triage import TriageEngine

JsonDict = dict[str, Any]


class EvalCliError(RuntimeError):
    """Raised when evaluation CLI input or execution is invalid."""


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Inputs:
        None.

    Outputs:
        Configured ArgumentParser.
    """

    parser = argparse.ArgumentParser(description="Evaluate SOC triage against a labeled set.")
    parser.add_argument(
        "--labels",
        type=Path,
        default=LABELED_SET_DIR,
        help=f"Labeled set file or directory. Defaults to {LABELED_SET_DIR}.",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Evaluate LLM-assisted triage instead of local triage. Requires an API key.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Path to .env file. Defaults to .env.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write the JSON report to.",
    )
    parser.add_argument(
        "--fail-under-thresholds",
        action="store_true",
        help="Exit non-zero when an exit-criteria threshold is unmet.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON report.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the evaluation CLI.

    Inputs:
        argv: Optional argument list. Defaults to sys.argv.

    Outputs:
        Process exit code.
    """

    args = build_parser().parse_args(argv)

    try:
        summary, failures = run_from_args(args)
    except (EvalCliError, ConfigError, EvaluationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130

    print(json.dumps(summary, indent=2 if args.pretty else None, sort_keys=True))

    if not summary["is_analyst_validated"]:
        print(
            "note: this run contains synthetic labels, so it measures self-consistency, "
            "not accuracy. Only analyst-reviewed labels support an accuracy claim.",
            file=sys.stderr,
        )
    for failure in failures:
        print(f"threshold unmet: {failure}", file=sys.stderr)

    return 1 if failures and args.fail_under_thresholds else 0


def run_from_args(args: argparse.Namespace) -> tuple[JsonDict, list[str]]:
    """Load labels, evaluate them, and return the summary and threshold failures.

    Inputs:
        args: Parsed argparse namespace.

    Outputs:
        Tuple of JSON-safe summary and unmet-threshold messages.

    Raises:
        EvalCliError: If an LLM run is requested without a usable API key.
    """

    cases = load_labeled_cases(args.labels)
    engine = _build_engine(args)
    report = evaluate_cases(cases, triage_engine=engine)

    summary = report.to_summary()
    summary["triage_mode"] = "llm" if engine.llm_client is not None else "local"
    summary["labels_path"] = str(args.labels)

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return summary, EvaluationThresholds().check(report)


def _build_engine(args: argparse.Namespace) -> TriageEngine:
    """Build the triage engine to evaluate.

    Inputs:
        args: Parsed argparse namespace.

    Outputs:
        TriageEngine, LLM-backed only when explicitly requested.

    Raises:
        EvalCliError: If an LLM run is requested but no key is configured.
    """

    if not args.llm:
        return TriageEngine()

    settings = get_settings(args.env_file, reload=True)
    if not str(getattr(settings, "openrouter_api_key", "") or "").strip():
        raise EvalCliError("--llm requires OPENROUTER_API_KEY to be configured")

    try:
        client = OpenRouterClient.from_settings(settings)
    except OpenRouterError as exc:
        raise EvalCliError(f"cannot build OpenRouter client: {exc}") from exc

    # Fallback is disabled so a failed model call is a visible error rather than
    # a local score quietly standing in for one and skewing the measurement.
    return TriageEngine(client, model=settings.openrouter_model, allow_fallback=False)


if __name__ == "__main__":
    raise SystemExit(main())
