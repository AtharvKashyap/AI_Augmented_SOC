"""Command-line analyst review tool for the AI_Augmented_SOC review queue.

The pipeline routes mid-scoring triage results to `queue_review`. This CLI is
what makes that routing mean something: it lists queued items, shows the full
triage detail behind one of them, records an analyst verdict, and exports
recorded verdicts as a labeled set.

Analyst verdicts are the only ground truth this project gets for free, so the
export command matters as much as the review command, and every exported record
is stamped with `analyst_reviewed` provenance so it can never be confused with a
synthetic label.

This file is intentionally thin, like `run_pipeline.py`: it parses arguments,
loads settings, opens the store, and formats output. All persistence lives in
`soc.store`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc.config import ConfigError, get_settings
from soc.evaluation import promote_reviews_to_labels
from soc.models import AnalystVerdict, ReviewQueueItem
from soc.store import SQLiteStore, StoreError


JsonDict = dict[str, Any]

#: Marks every exported record as analyst-derived rather than synthetic.
LABEL_PROVENANCE = "analyst_reviewed"

#: Command-line flag name to verdict enum member.
VERDICT_FLAGS: dict[str, AnalystVerdict] = {
    "agree": AnalystVerdict.AGREE,
    "too_high": AnalystVerdict.TOO_HIGH,
    "too_low": AnalystVerdict.TOO_LOW,
    "wrong_class": AnalystVerdict.WRONG_CLASS,
}


class CliError(RuntimeError):
    """Raised when CLI input or execution is invalid."""


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Four distinct verbs read better as subcommands than as mutually exclusive
    flags, so `list`, `show`, `verdict`, and `export` are subparsers that each
    carry the shared `--db` / `--env-file` arguments.

    Inputs:
        None.

    Outputs:
        Configured ArgumentParser.
    """

    parser = argparse.ArgumentParser(
        description="Review queued AI triage results and record analyst verdicts.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser(
        "list",
        help="List review queue items.",
    )
    list_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of items to list. Defaults to all.",
    )
    list_parser.add_argument(
        "--reviewed",
        action="store_true",
        help="List items an analyst has already judged instead of open ones.",
    )
    _add_shared_arguments(list_parser)

    show_parser = subparsers.add_parser(
        "show",
        help="Show one queue item with its full triage detail.",
    )
    show_parser.add_argument(
        "triage_result_id",
        help="Triage result ID identifying the queue item.",
    )
    _add_shared_arguments(show_parser)

    verdict_parser = subparsers.add_parser(
        "verdict",
        help="Record an analyst verdict for one queue item.",
    )
    verdict_parser.add_argument(
        "triage_result_id",
        help="Triage result ID identifying the queue item.",
    )
    verdict_group = verdict_parser.add_mutually_exclusive_group(required=True)
    for flag, verdict in VERDICT_FLAGS.items():
        verdict_group.add_argument(
            f"--{flag.replace('_', '-')}",
            dest="verdict",
            action="store_const",
            const=verdict.value,
            help=f"Record the {verdict.value} verdict.",
        )
    verdict_parser.add_argument(
        "--score",
        type=int,
        default=None,
        help="Score from 1 to 10 the analyst would have given.",
    )
    verdict_parser.add_argument(
        "--notes",
        default=None,
        help="Free-text analyst notes.",
    )
    _add_shared_arguments(verdict_parser)

    export_parser = subparsers.add_parser(
        "export",
        help="Export recorded analyst verdicts as a labeled JSON set.",
    )
    export_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path of the JSON file to write.",
    )
    export_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of reviewed items to export. Defaults to all.",
    )
    export_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the exported JSON.",
    )
    _add_shared_arguments(export_parser)

    promote_parser = subparsers.add_parser(
        "promote",
        help="Promote recorded verdicts into a loadable evaluation labeled set.",
    )
    promote_parser.add_argument(
        "--labels",
        type=Path,
        required=True,
        help="Path of the labeled-set JSON file to write.",
    )
    promote_parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=None,
        help="Directory for reconstructed replay fixtures. Defaults to <labels dir>/fixtures.",
    )
    _add_shared_arguments(promote_parser)

    return parser


def _add_shared_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the arguments every subcommand accepts.

    Inputs:
        parser: Subcommand parser to extend.

    Outputs:
        None. Arguments are added in place.
    """

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


def main(argv: Sequence[str] | None = None) -> int:
    """Run the analyst review CLI.

    Human-readable output is printed by the command handlers themselves, because
    a review loop is read by a person rather than piped into a tool. The summary
    returned by `run_from_args` exists for tests and future callers.

    Inputs:
        argv: Optional argument list. Defaults to sys.argv.

    Outputs:
        Process exit code: 0 on success, 1 on handled errors, 130 on interrupt.
    """

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        run_from_args(args)
    except (CliError, ConfigError, StoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130

    return 0


def run_from_args(args: argparse.Namespace) -> JsonDict:
    """Dispatch one review subcommand.

    Inputs:
        args: Parsed argparse namespace.

    Outputs:
        JSON-safe summary dictionary describing what the command did.

    Raises:
        CliError: If the command is unknown or its input is invalid.
        ConfigError: If settings cannot be loaded.
        StoreError: If the store rejects the operation.
    """

    store, db_path = _build_store(args)
    summary: JsonDict = {"command": args.command, "db_path": str(db_path)}

    if args.command == "list":
        summary.update(_run_list(store, args))
    elif args.command == "show":
        summary.update(_run_show(store, args))
    elif args.command == "verdict":
        summary.update(_run_verdict(store, args))
    elif args.command == "promote":
        summary.update(_run_promote(store, args))
    elif args.command == "export":
        summary.update(_run_export(store, args))
    else:
        raise CliError(f"unknown command: {args.command}")

    return summary


def _build_store(args: argparse.Namespace) -> tuple[SQLiteStore, Path]:
    """Open and initialize the store the command should read.

    Inputs:
        args: Parsed argparse namespace carrying --db and --env-file.

    Outputs:
        Tuple of initialized store and the resolved database path.

    Raises:
        CliError: If the database cannot be opened or initialized.
    """

    settings = get_settings(args.env_file, reload=True)
    db_path = Path(args.db or settings.sqlite_db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(db_path)
    try:
        store.initialize()
    except Exception as exc:
        raise CliError(f"cannot initialize database: {exc}") from exc
    return store, db_path


def _run_list(store: SQLiteStore, args: argparse.Namespace) -> JsonDict:
    """List open or reviewed queue items as a compact table.

    Inputs:
        store: Initialized store.
        args: Parsed argparse namespace carrying --limit and --reviewed.

    Outputs:
        Summary dictionary with the listing mode and row count.

    Raises:
        CliError: If --limit is not positive.
    """

    limit = _validate_limit(args.limit)
    reviewed = bool(args.reviewed)
    items = (
        store.list_reviewed_queue_items(limit)
        if reviewed
        else store.list_open_queue_items(limit)
    )

    if not items:
        print("No reviewed queue items." if reviewed else "No open review queue items.")
        return {"mode": "reviewed" if reviewed else "open", "count": 0}

    print(_format_table(items, reviewed=reviewed))
    return {"mode": "reviewed" if reviewed else "open", "count": len(items)}


def _run_show(store: SQLiteStore, args: argparse.Namespace) -> JsonDict:
    """Print one queue item with the full triage detail behind it.

    A verdict recorded from a score alone is guesswork, so this prints the
    summary, reasoning, IOCs, evidence, recommended actions and the target the
    triage engine actually looked at.

    Inputs:
        store: Initialized store.
        args: Parsed argparse namespace carrying triage_result_id.

    Outputs:
        Summary dictionary naming the item shown.

    Raises:
        CliError: If the ID is not in the review queue.
    """

    triage_result_id = args.triage_result_id
    item = store.get_queue_item(triage_result_id)
    if item is None:
        raise CliError(f"{triage_result_id} is not in the review queue")

    triage = store.get_triage_result(triage_result_id) or {}
    target = _load_target(store, item)

    lines: list[str] = [
        f"Triage result:   {item.triage_result_id}",
        f"Target:          {item.target_id} ({item.target_type})",
        f"Triage score:    {item.score}",
        f"Routed action:   {_enum_value(item.action)}",
        f"Analysis source: {_enum_value(item.analysis_source)}",
        f"Model:           {triage.get('model') or '-'}",
        f"Prompt version:  {triage.get('prompt_version') or '-'}",
        f"Classification:  {triage.get('classification') or '-'}",
        f"FP likelihood:   {triage.get('fp_likelihood') or '-'}",
        f"Queued at:       {_format_timestamp(item.queued_at)}",
        f"Status:          {'open' if item.is_open else 'reviewed'}",
    ]
    if not item.is_open:
        lines += [
            f"Analyst verdict: {_enum_value(item.analyst_verdict) or '-'}",
            f"Analyst score:   {'-' if item.analyst_score is None else item.analyst_score}",
            f"Reviewed at:     {_format_timestamp(item.reviewed_at)}",
            f"Notes:           {item.notes or '-'}",
        ]

    lines += ["", "Summary:", _indent(triage.get("summary") or "(none recorded)")]
    lines += ["", "Reasoning:", _indent(triage.get("reasoning") or "(none recorded)")]
    lines += ["", "IOCs:", *_format_iocs(triage.get("iocs"))]
    lines += ["", "Evidence:", *_format_evidence(triage.get("evidence"))]
    lines += ["", "Recommended actions:", *_format_bullets(triage.get("recommended_actions"))]
    lines += ["", f"Target detail ({item.target_type}):", *_format_mapping(target)]

    print("\n".join(lines))
    return {"triage_result_id": item.triage_result_id, "is_open": item.is_open}


def _run_verdict(store: SQLiteStore, args: argparse.Namespace) -> JsonDict:
    """Record one analyst verdict against a queued triage result.

    Inputs:
        store: Initialized store.
        args: Parsed argparse namespace carrying the ID, verdict, score and notes.

    Outputs:
        Summary dictionary describing the recorded verdict.

    Raises:
        CliError: If no verdict was selected or the verdict name is unknown.
        StoreError: If the item is not queued or the score is out of range.
    """

    triage_result_id = args.triage_result_id
    if not args.verdict:
        raise CliError("one verdict is required: --agree, --too-high, --too-low, or --wrong-class")
    try:
        verdict = AnalystVerdict(args.verdict)
    except ValueError as exc:
        raise CliError(f"unknown verdict: {args.verdict}") from exc

    store.record_analyst_verdict(
        triage_result_id,
        verdict=verdict,
        analyst_score=args.score,
        notes=args.notes,
    )

    score_text = "not given" if args.score is None else str(args.score)
    print(f"Recorded verdict {verdict.value} for {triage_result_id} (analyst score: {score_text}).")
    return {
        "triage_result_id": triage_result_id,
        "analyst_verdict": verdict.value,
        "analyst_score": args.score,
        "notes": args.notes,
    }


def _run_promote(store: SQLiteStore, args: argparse.Namespace) -> JsonDict:
    """Promote recorded verdicts into a labeled set the eval harness can load.

    `export` writes verdicts; this writes *labeled cases*. The difference matters:
    a verdict records how a score was wrong, while a labeled case also needs a
    replayable fixture and an expected score band, so this reconstructs the
    fixture from the raw events the store kept. This is the step that lets
    analyst judgment actually reach the evaluation harness.

    Inputs:
        store: Initialized store.
        args: Parsed argparse namespace carrying --labels and --fixtures-dir.

    Outputs:
        Summary dictionary describing what was written.
    """

    labels_path = args.labels
    fixtures_dir = args.fixtures_dir or labels_path.parent / "fixtures"
    records = promote_reviews_to_labels(
        store,
        labels_path=labels_path,
        fixtures_dir=fixtures_dir,
    )

    reviewed = len(store.list_reviewed_queue_items())
    skipped = reviewed - len(records)
    print(f"Promoted {len(records)} analyst-reviewed label(s) to {labels_path}")
    if skipped > 0:
        print(
            f"Skipped {skipped} reviewed item(s) whose source events are no longer "
            "recoverable and therefore cannot be replayed."
        )

    return {
        "labels_path": str(labels_path),
        "fixtures_dir": str(fixtures_dir),
        "labels_written": len(records),
        "reviewed_items": reviewed,
        "skipped_unrecoverable": skipped,
    }


def _run_export(store: SQLiteStore, args: argparse.Namespace) -> JsonDict:
    """Export recorded verdicts as the analyst-derived labeled set.

    Every record carries `label_provenance = analyst_reviewed`, because a label a
    human produced and a label we invented are not the same evidence and must
    never be mixed silently. An empty result still writes an empty array: a
    missing file would be indistinguishable from a failed export.

    Inputs:
        store: Initialized store.
        args: Parsed argparse namespace carrying --output, --limit and --pretty.

    Outputs:
        Summary dictionary with the record count and output path.

    Raises:
        CliError: If --limit is invalid or the file cannot be written.
    """

    limit = _validate_limit(args.limit)
    items = store.list_reviewed_queue_items(limit)
    records = [_export_record(item) for item in items]

    output = Path(args.output)
    indent = 2 if args.pretty else None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(records, indent=indent, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise CliError(f"cannot write export file {output}: {exc}") from exc

    print(f"Wrote {len(records)} analyst-reviewed record(s) to {output}.")
    return {"records": len(records), "output": str(output)}


def _export_record(item: ReviewQueueItem) -> JsonDict:
    """Build one exported label record from a reviewed queue item.

    Inputs:
        item: Reviewed queue item.

    Outputs:
        JSON-safe record dictionary.
    """

    return {
        # Both keys carry the same value: `label_provenance` names it
        # unambiguously in a standalone file, and `provenance` is the key the
        # Milestone 2.5 labeled-set loader reads.
        "label_provenance": LABEL_PROVENANCE,
        "provenance": LABEL_PROVENANCE,
        "triage_result_id": item.triage_result_id,
        "target_id": item.target_id,
        "target_type": item.target_type,
        "triage_score": item.score,
        "triage_action": _enum_value(item.action),
        "analysis_source": _enum_value(item.analysis_source),
        "analyst_verdict": _enum_value(item.analyst_verdict),
        "analyst_score": item.analyst_score,
        "notes": item.notes,
        "queued_at": _dt_text(item.queued_at),
        "reviewed_at": _dt_text(item.reviewed_at),
    }


def _dt_text(value: datetime | None) -> str | None:
    """Render a datetime as ISO-8601 text for JSON export.

    Inputs:
        value: Datetime or None.

    Outputs:
        ISO-8601 string, or None.
    """

    return None if value is None else value.isoformat()


def _load_target(store: SQLiteStore, item: ReviewQueueItem) -> JsonDict | None:
    """Load the alert or incident candidate a queue item points at.

    Inputs:
        store: Initialized store.
        item: Queue item whose target should be loaded.

    Outputs:
        Target payload dictionary, or None when it is not stored.
    """

    if item.target_type == "alert":
        return store.get_alert(item.target_id)
    return store.get_incident_candidate(item.target_id) or store.get_alert(item.target_id)


def _format_timestamp(value: datetime | None) -> str:
    """Render a timestamp for human reading.

    Inputs:
        value: Datetime or None.

    Outputs:
        ISO-8601 string, or "-" when absent.
    """

    return _dt_text(value) or "-"


def _indent(text: str, prefix: str = "  ") -> str:
    """Indent every line of a block of text.

    Inputs:
        text: Text to indent.
        prefix: Indentation prefix.

    Outputs:
        Indented text.
    """

    return "\n".join(f"{prefix}{line}" for line in str(text).splitlines() or [""])


def _format_bullets(values: Any) -> list[str]:
    """Render a list of strings as indented bullets.

    Inputs:
        values: List of values, or None.

    Outputs:
        List of output lines.
    """

    if not values:
        return ["  (none recorded)"]
    if not isinstance(values, list):
        return [f"  - {values}"]
    return [f"  - {value}" for value in values]


def _format_iocs(iocs: Any) -> list[str]:
    """Render grouped IOCs as indented lines.

    Inputs:
        iocs: Mapping of IOC type to values, or None.

    Outputs:
        List of output lines.
    """

    if not iocs:
        return ["  (none recorded)"]
    if not isinstance(iocs, dict):
        return [f"  {iocs}"]
    lines: list[str] = []
    for ioc_type, values in sorted(iocs.items()):
        rendered = ", ".join(str(value) for value in values) if isinstance(values, list) else str(values)
        lines.append(f"  {ioc_type}: {rendered}")
    return lines


def _format_evidence(evidence: Any) -> list[str]:
    """Render evidence items as indented lines.

    Inputs:
        evidence: List of evidence dictionaries, or None.

    Outputs:
        List of output lines.
    """

    if not evidence or not isinstance(evidence, list):
        return ["  (none recorded)"]
    lines: list[str] = []
    for entry in evidence:
        if not isinstance(entry, dict):
            lines.append(f"  - {entry}")
            continue
        source = entry.get("source") or "unknown"
        field = entry.get("field") or "unknown"
        value = entry.get("value")
        alert_id = entry.get("alert_id")
        suffix = f" [alert {alert_id}]" if alert_id else ""
        lines.append(f"  - {source}: {field} = {value}{suffix}")
    return lines


def _format_mapping(payload: JsonDict | None) -> list[str]:
    """Render a stored payload as sorted key/value lines.

    Nested structures are printed as compact JSON so nothing an analyst may need
    is silently dropped.

    Inputs:
        payload: Payload dictionary, or None when not stored.

    Outputs:
        List of output lines.
    """

    if not payload:
        return ["  (not stored)"]
    lines: list[str] = []
    for key, value in sorted(payload.items()):
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value, sort_keys=True)
        else:
            rendered = str(value)
        lines.append(f"  {key}: {rendered}")
    return lines


def _format_table(items: list[ReviewQueueItem], *, reviewed: bool) -> str:
    """Render queue items as an aligned text table.

    The analysis source is printed on every row: an analyst must always be able
    to tell a model score from a heuristic one.

    Inputs:
        items: Queue items to render, in the order the store returned them.
        reviewed: Whether to render verdict columns instead of age.

    Outputs:
        Table text without a trailing newline.
    """

    headers = ["#", "TRIAGE RESULT ID", "TARGET", "SCORE", "ACTION", "SOURCE"]
    headers += ["VERDICT", "ANALYST", "REVIEWED"] if reviewed else ["AGE"]

    rows: list[list[str]] = []
    for position, item in enumerate(items, start=1):
        row = [
            str(position),
            item.triage_result_id,
            f"{item.target_id} ({item.target_type})",
            str(item.score),
            _enum_value(item.action),
            _enum_value(item.analysis_source),
        ]
        if reviewed:
            row += [
                _enum_value(item.analyst_verdict) or "-",
                "-" if item.analyst_score is None else str(item.analyst_score),
                _format_age(item.reviewed_at),
            ]
        else:
            row.append(_format_age(item.queued_at))
        rows.append(row)

    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]
    lines = ["  ".join(value.ljust(widths[index]) for index, value in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.append("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())
    return "\n".join(lines)


def _format_age(value: datetime | None) -> str:
    """Render how long ago a timestamp was, compactly.

    Inputs:
        value: Timezone-aware datetime, or None.

    Outputs:
        Age string such as "3h" or "12d", or "-" when unknown.
    """

    if value is None:
        return "-"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    seconds = int((datetime.now(timezone.utc) - value).total_seconds())
    if seconds < 0:
        return "0m"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def _enum_value(value: Any) -> Any:
    """Return the value of an enum member, or the input unchanged.

    Inputs:
        value: Enum member, plain value, or None.

    Outputs:
        Plain JSON-safe value.
    """

    return value.value if hasattr(value, "value") else value


def _validate_limit(limit: int | None) -> int | None:
    """Validate an optional row limit.

    Inputs:
        limit: Requested limit, or None for no limit.

    Outputs:
        The validated limit, or None.

    Raises:
        CliError: If the limit is not positive.
    """

    if limit is not None and limit < 1:
        raise CliError("--limit must be a positive integer")
    return limit


if __name__ == "__main__":
    raise SystemExit(main())
